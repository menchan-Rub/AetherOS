// AetherOS スピンロック実装
//
// このモジュールは高性能なスピンロックを実装します。
// 短時間のクリティカルセクション向けに最適化されており、
// ハードウェアのアトミック命令を効率的に利用します。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::fmt;

use super::{SyncPrimitive, SyncOptions, LockStrategy, LockResult, SyncDebugInfo};
use super::{record_primitive_created, record_primitive_destroyed, record_contention, record_deadlock, record_wait_time};
use super::{current_thread_id, cpu_pause, current_time_ns};

/// スピン試行の最大回数
const MAX_SPIN_ATTEMPTS: usize = 1000;

/// 最大バックオフ時間（ナノ秒）
const MAX_BACKOFF_NS: u64 = 1_000_000; // 1ミリ秒

/// ロックステータス値
const UNLOCKED: u32 = 0;
const LOCKED: u32 = 1;

/// 指数バックオフ計算のためのヘルパー構造体
struct ExponentialBackoff {
    /// 現在の待機回数
    attempt: u32,
    /// 最大待機回数
    max_attempts: u32,
    /// 基本待機時間（ナノ秒）
    base_wait_ns: u64,
    /// 最大待機時間（ナノ秒）
    max_wait_ns: u64,
}

impl ExponentialBackoff {
    /// 新しいバックオフインスタンスを作成
    fn new() -> Self {
        Self {
            attempt: 0,
            max_attempts: 20,
            base_wait_ns: 1000, // 1マイクロ秒
            max_wait_ns: MAX_BACKOFF_NS,
        }
    }
    
    /// 次の待機時間を計算し、待機する
    fn spin_once(&mut self) {
        self.attempt += 1;
        
        if self.attempt <= 10 {
            // 最初の数回はCPU_PAUSEを使用（高速）
            for _ in 0..self.attempt {
                cpu_pause();
            }
            return;
        }
        
        // 指数バックオフを計算
        let mut wait_time = self.base_wait_ns;
        for _ in 10..self.attempt {
            wait_time = core::cmp::min(wait_time * 2, self.max_wait_ns);
        }
        
        // ナノ秒単位で待機（アーキテクチャ依存の実装）
        let start = current_time_ns();
        while current_time_ns() - start < wait_time {
            cpu_pause();
        }
    }
    
    /// バックオフをリセット
    fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// スピンロック実装
#[repr(align(64))]  // キャッシュライン境界にアライン
pub struct SpinLock<T: ?Sized> {
    /// ロック状態
    lock: AtomicU32,
    /// 所有スレッドID
    owner: AtomicU64,
    /// 取得回数
    acquisition_count: AtomicUsize,
    /// 解放回数
    release_count: AtomicUsize,
    /// 競合回数
    contention_count: AtomicUsize,
    /// 設定オプション
    options: SyncOptions,
    /// データ値
    data: UnsafeCell<T>,
    /// 最後のロック時刻
    lock_time: AtomicU64,
    /// パディング（キャッシュライン境界調整用）
    _padding: [u8; 8],
}

// スピンロックはスレッド間で安全に共有できる
unsafe impl<T: ?Sized + Send> Send for SpinLock<T> {}
unsafe impl<T: ?Sized + Send> Sync for SpinLock<T> {}

/// スピンロックガード実装
pub struct SpinLockGuard<'a, T: ?Sized + 'a> {
    /// ロック参照
    lock: &'a SpinLock<T>,
    /// スレッドID
    thread_id: u64,
}

// SpinLockGuardのSendトレイト実装を防止（ロックが別スレッドで解放されることを防ぐ）
impl<T: ?Sized> !Send for SpinLockGuard<'_, T> {}

impl<T> SpinLock<T> {
    /// 新しいスピンロックを作成
    pub fn new(data: T) -> Self {
        record_primitive_created();
        
        Self {
            lock: AtomicU32::new(UNLOCKED),
            owner: AtomicU64::new(0),
            acquisition_count: AtomicUsize::new(0),
            release_count: AtomicUsize::new(0),
            contention_count: AtomicUsize::new(0),
            options: SyncOptions::default(),
            data: UnsafeCell::new(data),
            lock_time: AtomicU64::new(0),
            _padding: [0; 8],
        }
    }
    
    /// 設定オプション付きで新しいスピンロックを作成
    pub fn with_options(data: T, options: SyncOptions) -> Self {
        record_primitive_created();
        
        Self {
            lock: AtomicU32::new(UNLOCKED),
            owner: AtomicU64::new(0),
            acquisition_count: AtomicUsize::new(0),
            release_count: AtomicUsize::new(0),
            contention_count: AtomicUsize::new(0),
            options,
            data: UnsafeCell::new(data),
            lock_time: AtomicU64::new(0),
            _padding: [0; 8],
        }
    }
    
    /// スピンロックを消費して内部値を取得
    pub fn into_inner(self) -> T {
        // スピンロックを消費し、内部値を返す
        self.data.into_inner()
    }
}

impl<T: ?Sized> SpinLock<T> {
    /// スピンロックを取得し、ガードを返す
    pub fn lock(&self) -> SpinLockGuard<T> {
        let start_time = current_time_ns();
        let current_id = current_thread_id();
        
        // 自分が既に所有しているか確認（再帰ロックはサポートしない）
        if self.owner.load(Ordering::Relaxed) == current_id {
            // デッドロック検出（自分自身を再ロックしようとしている）
            record_deadlock();
            panic!("Deadlock detected: thread {} attempted to recursively lock a spinlock", current_id);
        }
        
        // 最初の数回は単純なスピンを試みる
        for _ in 0..10 {
            if let Ok(_) = self.lock.compare_exchange_weak(
                UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed
            ) {
                // ロック取得成功
                self.owner.store(current_id, Ordering::Relaxed);
                self.lock_time.store(current_time_ns(), Ordering::Relaxed);
                self.acquisition_count.fetch_add(1, Ordering::Relaxed);
                
                let elapsed = current_time_ns().saturating_sub(start_time);
                if elapsed > 0 {
                    record_wait_time(elapsed);
                }
                
                return SpinLockGuard {
                    lock: self,
                    thread_id: current_id,
                };
            }
            
            // 少し待機
            cpu_pause();
        }
        
        // 指数バックオフでスピンする
        let mut backoff = ExponentialBackoff::new();
        loop {
            // ロック取得を試みる
            if let Ok(_) = self.lock.compare_exchange_weak(
                UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed
            ) {
                // ロック取得成功
                self.owner.store(current_id, Ordering::Relaxed);
                self.lock_time.store(current_time_ns(), Ordering::Relaxed);
                self.acquisition_count.fetch_add(1, Ordering::Relaxed);
                
                let elapsed = current_time_ns().saturating_sub(start_time);
                record_wait_time(elapsed);
                
                return SpinLockGuard {
                    lock: self,
                    thread_id: current_id,
                };
            }
            
            // スピン回数をインクリメント
            if backoff.attempt == 0 {
                // 競合を記録（最初の競合時のみ）
                self.contention_count.fetch_add(1, Ordering::Relaxed);
                record_contention();
            }
            
            // 非ブロッキング戦略の場合は失敗を返す
            if let LockStrategy::TryOnce = self.options.strategy {
                if backoff.attempt >= 10 {
                    return SpinLockGuard {
                        lock: self,
                        thread_id: 0, // 無効なガード
                    };
                }
            }
            
            // タイムアウト確認
            if let LockStrategy::TimedBlocking(timeout_ns) = self.options.strategy {
                let now = current_time_ns();
                if now > start_time + timeout_ns {
                    // タイムアウト
                    return SpinLockGuard {
                        lock: self,
                        thread_id: 0, // 無効なガード
                    };
                }
            }
            
            // バックオフ待機
            backoff.spin_once();
        }
    }
    
    /// スピンロックの取得を試みる（失敗時に即座に返る）
    pub fn try_lock(&self) -> Option<SpinLockGuard<T>> {
        let current_id = current_thread_id();
        
        // 自分が既に所有しているか確認
        if self.owner.load(Ordering::Relaxed) == current_id {
            // デッドロック検出（自分自身を再ロックしようとしている）
            record_deadlock();
            return None;
        }
        
        // ロック取得を一度だけ試みる
        if let Ok(_) = self.lock.compare_exchange(
            UNLOCKED, LOCKED, Ordering::Acquire, Ordering::Relaxed
        ) {
            // ロック取得成功
            self.owner.store(current_id, Ordering::Relaxed);
            self.lock_time.store(current_time_ns(), Ordering::Relaxed);
            self.acquisition_count.fetch_add(1, Ordering::Relaxed);
            
            return Some(SpinLockGuard {
                lock: self,
                thread_id: current_id,
            });
        }
        
        // ロック取得失敗
        None
    }
    
    /// ロックされているかを確認
    pub fn is_locked(&self) -> bool {
        self.lock.load(Ordering::Relaxed) == LOCKED
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
    pub fn get_stats(&self) -> (usize, usize, usize) {
        // (取得数, 解放数, 競合数)
        (
            self.acquisition_count.load(Ordering::Relaxed),
            self.release_count.load(Ordering::Relaxed),
            self.contention_count.load(Ordering::Relaxed)
        )
    }
    
    /// スピンロックを強制的に解放（危険な操作、所有者でない場合）
    /// デバッグや回復操作にのみ使用
    pub unsafe fn force_unlock(&self) {
        self.owner.store(0, Ordering::Relaxed);
        self.lock.store(UNLOCKED, Ordering::Release);
        self.release_count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// デバッグ情報を取得
    pub fn debug_info(&self) -> SyncDebugInfo {
        SyncDebugInfo {
            name: "SpinLock",
            acquisition_count: self.acquisition_count.load(Ordering::Relaxed),
            release_count: self.release_count.load(Ordering::Relaxed),
            contention_count: self.contention_count.load(Ordering::Relaxed),
            total_wait_time_ns: 0, // このレベルでは追跡していない
            max_wait_time_ns: 0,   // このレベルでは追跡していない
            current_owner: Some(self.owner.load(Ordering::Relaxed)),
            lock_time: Some(self.lock_time.load(Ordering::Relaxed)),
        }
    }
    
    /// ガードなしで内部データへの参照を取得（安全でない操作）
    pub unsafe fn get_mut_unchecked(&self) -> &mut T {
        &mut *self.data.get()
    }
}

impl<T: ?Sized + Default> Default for SpinLock<T> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for SpinLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.try_lock() {
            Some(guard) => f.debug_struct("SpinLock")
                .field("data", &*guard)
                .field("locked", &true)
                .field("owner", &self.owner.load(Ordering::Relaxed))
                .finish(),
            None => f.debug_struct("SpinLock")
                .field("data", &"<locked>")
                .field("locked", &true)
                .field("owner", &self.owner.load(Ordering::Relaxed))
                .finish(),
        }
    }
}

impl<'a, T: ?Sized> Deref for SpinLockGuard<'a, T> {
    type Target = T;
    
    fn deref(&self) -> &T {
        // 有効なガードかチェック
        if self.thread_id == 0 {
            panic!("Attempted to use an invalid SpinLockGuard");
        }
        
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T: ?Sized> DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        // 有効なガードかチェック
        if self.thread_id == 0 {
            panic!("Attempted to use an invalid SpinLockGuard");
        }
        
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T: ?Sized> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        // 無効なガードの場合は何もしない
        if self.thread_id == 0 {
            return;
        }
        
        // 所有者をクリア
        self.lock.owner.store(0, Ordering::Relaxed);
        
        // ロックを解放
        self.lock.lock.store(UNLOCKED, Ordering::Release);
        self.lock.release_count.fetch_add(1, Ordering::Relaxed);
    }
}

impl<T: ?Sized> SyncPrimitive for SpinLock<T> {
    fn lock(&self) -> bool {
        let guard = SpinLock::lock(self);
        guard.thread_id != 0
    }
    
    fn unlock(&self) -> bool {
        if self.owner.load(Ordering::Relaxed) == current_thread_id() {
            // 正当な所有者による解放
            self.owner.store(0, Ordering::Relaxed);
            self.lock.store(UNLOCKED, Ordering::Release);
            self.release_count.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            // 不正な解放
            false
        }
    }
    
    fn is_locked(&self) -> bool {
        self.lock.load(Ordering::Relaxed) == LOCKED
    }
    
    fn is_owned_by_current_thread(&self) -> bool {
        self.owner.load(Ordering::Relaxed) == current_thread_id()
    }
} 