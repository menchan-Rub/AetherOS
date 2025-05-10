// AetherOS ミューテックス実装
//
// このモジュールはスケーラブルなミューテックスを実装します。
// スピンロックと違い、長時間のブロックに最適化されています。
// スレッドがブロックされると、カーネルスケジューラと連携して
// 効率的なスレッド切り替えを行います。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::fmt;

use crate::core::task::scheduler::{schedule_out, schedule_in, current_thread_id};
use crate::core::sync::waitqueue::WaitQueue;
use super::{SyncPrimitive, SyncOptions, LockStrategy, LockResult, SyncDebugInfo};
use super::{record_primitive_created, record_primitive_destroyed, record_contention, record_deadlock, record_wait_time};
use super::{current_time_ns, cpu_pause};

/// ミューテックス状態定数
const UNLOCKED: u32 = 0;
const LOCKED: u32 = 1;
const CONTENDED: u32 = 2;

/// スピン試行回数の上限（長時間のスピンを防ぐ）
const MAX_SPIN_ATTEMPTS: u32 = 100;

/// ミューテックスの実装
#[repr(align(64))]  // キャッシュライン境界にアライン
pub struct Mutex<T: ?Sized> {
    /// ロック状態 (0=解放, 1=ロック, 2=競合)
    state: AtomicU32,
    /// 所有スレッドID
    owner: AtomicU64,
    /// 取得回数
    acquisition_count: AtomicUsize,
    /// 解放回数
    release_count: AtomicUsize,
    /// 競合回数
    contention_count: AtomicUsize,
    /// ブロック回数
    block_count: AtomicUsize,
    /// 最後のロック時刻
    lock_time: AtomicU64,
    /// ロック待ちキュー
    waiters: WaitQueue,
    /// ロックオプション
    options: SyncOptions,
    /// 保護対象データ
    data: UnsafeCell<T>,
    /// パディング（キャッシュライン境界調整用）
    _padding: [u8; 16],
}

// ミューテックスはスレッド間で安全に共有できる
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

/// ミューテックスガード実装
pub struct MutexGuard<'a, T: ?Sized + 'a> {
    /// ロック参照
    lock: &'a Mutex<T>,
    /// スレッドID
    thread_id: u64,
}

// ミューテックスガードはスレッド間で移動できない
impl<T: ?Sized> !Send for MutexGuard<'_, T> {}

impl<T> Mutex<T> {
    /// 新しいミューテックスを作成
    pub fn new(data: T) -> Self {
        record_primitive_created();
        
        Self {
            state: AtomicU32::new(UNLOCKED),
            owner: AtomicU64::new(0),
            acquisition_count: AtomicUsize::new(0),
            release_count: AtomicUsize::new(0),
            contention_count: AtomicUsize::new(0),
            block_count: AtomicUsize::new(0),
            lock_time: AtomicU64::new(0),
            waiters: WaitQueue::new(),
            options: SyncOptions::default(),
            data: UnsafeCell::new(data),
            _padding: [0; 16],
        }
    }
    
    /// 設定オプション付きで新しいミューテックスを作成
    pub fn with_options(data: T, options: SyncOptions) -> Self {
        record_primitive_created();
        
        Self {
            state: AtomicU32::new(UNLOCKED),
            owner: AtomicU64::new(0),
            acquisition_count: AtomicUsize::new(0),
            release_count: AtomicUsize::new(0),
            contention_count: AtomicUsize::new(0),
            block_count: AtomicUsize::new(0),
            lock_time: AtomicU64::new(0),
            waiters: WaitQueue::new(),
            options,
            data: UnsafeCell::new(data),
            _padding: [0; 16],
        }
    }
    
    /// ミューテックスを消費して内部値を取得
    pub fn into_inner(self) -> T {
        // 他のスレッドがロックを保持していないことを確認
        assert_eq!(self.state.load(Ordering::Relaxed), UNLOCKED, 
                  "ミューテックスがロックされている状態で消費しようとしました");
        
        record_primitive_destroyed();
        self.data.into_inner()
    }
}

impl<T: ?Sized> Mutex<T> {
    /// ミューテックスを取得し、ガードを返す
    pub fn lock(&self) -> MutexGuard<T> {
        let start_time = current_time_ns();
        let current_id = current_thread_id();
        
        // 自分が既に所有しているか確認（再帰的ロックはサポートしない）
        if self.owner.load(Ordering::Relaxed) == current_id {
            // デッドロック検出
            record_deadlock();
            panic!("デッドロック検出: スレッド {} がすでに所有しているミューテックスを再度ロックしようとしました", current_id);
        }
        
        // 高速パス：アンロック状態からロック状態へのアトミックな変更を試みる
        if let Ok(_) = self.state.compare_exchange(UNLOCKED, LOCKED, 
                                                 Ordering::Acquire, 
                                                 Ordering::Relaxed) {
            // 競合なしでロック取得成功
            self.owner.store(current_id, Ordering::Relaxed);
            self.lock_time.store(current_time_ns(), Ordering::Relaxed);
            self.acquisition_count.fetch_add(1, Ordering::Relaxed);
            
            return MutexGuard {
                lock: self,
                thread_id: current_id,
            };
        }
        
        // 競合発生：スピン後にブロック
        self.lock_contended(current_id, start_time)
    }
    
    /// 競合発生時のロック取得処理（スピン→ブロック）
    fn lock_contended(&self, current_id: u64, start_time: u64) -> MutexGuard<T> {
        // 競合カウント更新
        self.contention_count.fetch_add(1, Ordering::Relaxed);
        record_contention();
        
        // 短時間のスピンを試みる
        for i in 0..MAX_SPIN_ATTEMPTS {
            // スピン待機（指数バックオフ）
            for j in 0..(1 << core::cmp::min(i, 6)) {
                cpu_pause();
            }
            
            // ロック取得再試行
            if let Ok(_) = self.state.compare_exchange(UNLOCKED, LOCKED, 
                                                     Ordering::Acquire, 
                                                     Ordering::Relaxed) {
                // スピン中にロック取得成功
                self.owner.store(current_id, Ordering::Relaxed);
                self.lock_time.store(current_time_ns(), Ordering::Relaxed);
                self.acquisition_count.fetch_add(1, Ordering::Relaxed);
                
                let elapsed = current_time_ns().saturating_sub(start_time);
                record_wait_time(elapsed);
                
                return MutexGuard {
                    lock: self,
                    thread_id: current_id,
                };
            }
        }
        
        // スピン失敗：スレッドをブロック
        
        // 非ブロッキング戦略の場合は失敗を返す
        if let LockStrategy::TryOnce = self.options.strategy {
            return MutexGuard {
                lock: self,
                thread_id: 0, // 無効なガード
            };
        }
        
        // ブロック前に競合フラグを設定
        self.state.compare_exchange(LOCKED, CONTENDED, 
                                   Ordering::Relaxed, 
                                   Ordering::Relaxed)
            .ok();
        
        // タイムアウト付きロック取得
        if let LockStrategy::TimedBlocking(timeout_ns) = self.options.strategy {
            let result = self.waiters.wait_timeout(timeout_ns);
            
            if !result {
                // タイムアウト発生
                return MutexGuard {
                    lock: self,
                    thread_id: 0, // 無効なガード
                };
            }
        } else {
            // 通常のブロッキングロック取得
            self.block_count.fetch_add(1, Ordering::Relaxed);
            self.waiters.wait();
        }
        
        // ブロックから復帰後、再度ロック取得を試みる
        loop {
            if let Ok(_) = self.state.compare_exchange(UNLOCKED, LOCKED, 
                                                     Ordering::Acquire, 
                                                     Ordering::Relaxed) {
                // ロック取得成功
                self.owner.store(current_id, Ordering::Relaxed);
                self.lock_time.store(current_time_ns(), Ordering::Relaxed);
                self.acquisition_count.fetch_add(1, Ordering::Relaxed);
                
                let elapsed = current_time_ns().saturating_sub(start_time);
                record_wait_time(elapsed);
                
                return MutexGuard {
                    lock: self,
                    thread_id: current_id,
                };
            }
            
            // まだロックが取得できない場合は再度ブロック
            self.state.compare_exchange(LOCKED, CONTENDED, 
                                       Ordering::Relaxed, 
                                       Ordering::Relaxed)
                .ok();
                
            self.block_count.fetch_add(1, Ordering::Relaxed);
            self.waiters.wait();
        }
    }
    
    /// ミューテックスの取得を試みる（失敗時に即座に返る）
    pub fn try_lock(&self) -> Option<MutexGuard<T>> {
        let current_id = current_thread_id();
        
        // 自分が既に所有しているか確認
        if self.owner.load(Ordering::Relaxed) == current_id {
            record_deadlock();
            return None;
        }
        
        // ロック取得を一度だけ試みる
        if let Ok(_) = self.state.compare_exchange(UNLOCKED, LOCKED, 
                                                 Ordering::Acquire, 
                                                 Ordering::Relaxed) {
            // ロック取得成功
            self.owner.store(current_id, Ordering::Relaxed);
            self.lock_time.store(current_time_ns(), Ordering::Relaxed);
            self.acquisition_count.fetch_add(1, Ordering::Relaxed);
            
            return Some(MutexGuard {
                lock: self,
                thread_id: current_id,
            });
        }
        
        // ロック取得失敗
        None
    }
    
    /// ロックされているかを確認
    pub fn is_locked(&self) -> bool {
        self.state.load(Ordering::Relaxed) != UNLOCKED
    }
    
    /// このスレッドが所有しているかを確認
    pub fn is_owned_by_current_thread(&self) -> bool {
        self.owner.load(Ordering::Relaxed) == current_thread_id()
    }
    
    /// 所有者のスレッドIDを取得
    pub fn get_owner(&self) -> u64 {
        self.owner.load(Ordering::Relaxed)
    }
    
    /// 統計情報を取得
    pub fn get_stats(&self) -> (usize, usize, usize, usize) {
        // (取得数, 解放数, 競合数, ブロック数)
        (
            self.acquisition_count.load(Ordering::Relaxed),
            self.release_count.load(Ordering::Relaxed),
            self.contention_count.load(Ordering::Relaxed),
            self.block_count.load(Ordering::Relaxed)
        )
    }
    
    /// ミューテックスを強制的に解放（危険な操作、所有者でない場合）
    /// デバッグや回復操作にのみ使用
    pub unsafe fn force_unlock(&self) {
        let old_state = self.state.swap(UNLOCKED, Ordering::Release);
        self.owner.store(0, Ordering::Relaxed);
        self.release_count.fetch_add(1, Ordering::Relaxed);
        
        // 待機中のスレッドがあれば1つだけ起こす
        if old_state == CONTENDED {
            self.waiters.wake_one();
        }
    }
    
    /// ガードなしで内部データへの参照を取得（安全でない操作）
    pub unsafe fn get_mut_unchecked(&self) -> &mut T {
        &mut *self.data.get()
    }
    
    /// デバッグ情報を取得
    pub fn debug_info(&self) -> SyncDebugInfo {
        SyncDebugInfo {
            name: "Mutex",
            acquisition_count: self.acquisition_count.load(Ordering::Relaxed),
            release_count: self.release_count.load(Ordering::Relaxed),
            contention_count: self.contention_count.load(Ordering::Relaxed),
            total_wait_time_ns: 0, // このレベルでは追跡していない
            max_wait_time_ns: 0,   // このレベルでは追跡していない
            current_owner: Some(self.owner.load(Ordering::Relaxed)),
            lock_time: Some(self.lock_time.load(Ordering::Relaxed)),
        }
    }
}

impl<T: ?Sized + Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.try_lock() {
            Some(guard) => f.debug_struct("Mutex")
                .field("data", &*guard)
                .field("locked", &true)
                .field("owner", &self.owner.load(Ordering::Relaxed))
                .finish(),
            None => f.debug_struct("Mutex")
                .field("data", &"<locked>")
                .field("locked", &true)
                .field("owner", &self.owner.load(Ordering::Relaxed))
                .finish(),
        }
    }
}

impl<'a, T: ?Sized> Deref for MutexGuard<'a, T> {
    type Target = T;
    
    fn deref(&self) -> &T {
        // 有効なガードかチェック
        if self.thread_id == 0 {
            panic!("無効なミューテックスガードを使用しようとしました");
        }
        
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T: ?Sized> DerefMut for MutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        // 有効なガードかチェック
        if self.thread_id == 0 {
            panic!("無効なミューテックスガードを使用しようとしました");
        }
        
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T: ?Sized> Drop for MutexGuard<'a, T> {
    fn drop(&mut self) {
        // 無効なガードの場合は何もしない
        if self.thread_id == 0 {
            return;
        }
        
        // ミューテックスのロックを解放
        
        // 所有者をクリア
        self.lock.owner.store(0, Ordering::Relaxed);
        self.lock.release_count.fetch_add(1, Ordering::Relaxed);
        
        // 競合状態から非ロック状態へ変更し、結果を確認
        let old_state = self.lock.state.swap(UNLOCKED, Ordering::Release);
        
        // 待機中のスレッドがあれば1つだけ起こす
        if old_state == CONTENDED {
            self.lock.waiters.wake_one();
        }
    }
}

impl<T: ?Sized> SyncPrimitive for Mutex<T> {
    fn lock(&self) -> bool {
        let guard = Mutex::lock(self);
        guard.thread_id != 0
    }
    
    fn unlock(&self) -> bool {
        if self.owner.load(Ordering::Relaxed) == current_thread_id() {
            // 正当な所有者による解放
            let old_state = self.state.swap(UNLOCKED, Ordering::Release);
            self.owner.store(0, Ordering::Relaxed);
            self.release_count.fetch_add(1, Ordering::Relaxed);
            
            // 待機中のスレッドを起こす
            if old_state == CONTENDED {
                self.waiters.wake_one();
            }
            
            true
        } else {
            // 不正な解放
            false
        }
    }
    
    fn is_locked(&self) -> bool {
        self.state.load(Ordering::Relaxed) != UNLOCKED
    }
    
    fn is_owned_by_current_thread(&self) -> bool {
        self.owner.load(Ordering::Relaxed) == current_thread_id()
    }
} 