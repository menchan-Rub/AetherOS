// AetherOS セマフォ実装
//
// このモジュールはカウンティングセマフォを実装します。
// 複数のスレッド間での同期とリソース管理のための
// 効率的なプリミティブを提供します。

use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::{SyncPrimitive, SyncOptions, LockStrategy, LockResult, SyncDebugInfo};
use super::{record_primitive_created, record_primitive_destroyed, record_contention, record_deadlock, record_wait_time};
use super::{current_thread_id, cpu_pause, current_time_ns};
use crate::core::process::scheduler;

/// スピン試行の最大回数
const MAX_SPIN_ATTEMPTS: usize = 100;

/// 待機スレッド情報
#[derive(Debug)]
struct Waiter {
    /// スレッドID
    thread_id: u64,
    /// 待機開始時刻
    wait_start: u64,
    /// タイムアウト（ナノ秒、0=無限）
    timeout_ns: u64,
    /// 待機状態
    signaled: AtomicBool,
}

/// セマフォ実装
#[repr(align(64))]  // キャッシュライン境界にアライン
pub struct Semaphore {
    /// 現在の値
    count: AtomicI64,
    /// 最大値（負の値は無制限）
    max_count: i64,
    /// 取得回数
    acquisition_count: AtomicUsize,
    /// 解放回数
    release_count: AtomicUsize,
    /// 競合回数
    contention_count: AtomicUsize,
    /// 設定オプション
    options: SyncOptions,
    /// 待機スレッド数
    waiters_count: AtomicUsize,
    /// 待機キュー（ポインタ格納用）
    waiters_ptr: AtomicUsize,
    /// パディング（キャッシュライン境界調整用）
    _padding: [u8; 8],
}

// セマフォはスレッド間で安全に共有できる
unsafe impl Send for Semaphore {}
unsafe impl Sync for Semaphore {}

impl Semaphore {
    /// 新しいセマフォを作成
    ///
    /// * `initial_count` - 初期カウント値
    /// * `max_count` - 最大カウント値（負の値は無制限）
    pub fn new(initial_count: i64, max_count: i64) -> Self {
        record_primitive_created();
        
        // 初期値は最大値を超えないように
        let initial = if max_count >= 0 && initial_count > max_count {
            max_count
        } else {
            initial_count
        };
        
        Self {
            count: AtomicI64::new(initial),
            max_count,
            acquisition_count: AtomicUsize::new(0),
            release_count: AtomicUsize::new(0),
            contention_count: AtomicUsize::new(0),
            options: SyncOptions::default(),
            waiters_count: AtomicUsize::new(0),
            waiters_ptr: AtomicUsize::new(0),
            _padding: [0; 8],
        }
    }
    
    /// 設定オプション付きで新しいセマフォを作成
    pub fn with_options(initial_count: i64, max_count: i64, options: SyncOptions) -> Self {
        record_primitive_created();
        
        // 初期値は最大値を超えないように
        let initial = if max_count >= 0 && initial_count > max_count {
            max_count
        } else {
            initial_count
        };
        
        Self {
            count: AtomicI64::new(initial),
            max_count,
            acquisition_count: AtomicUsize::new(0),
            release_count: AtomicUsize::new(0),
            contention_count: AtomicUsize::new(0),
            options,
            waiters_count: AtomicUsize::new(0),
            waiters_ptr: AtomicUsize::new(0),
            _padding: [0; 8],
        }
    }
    
    /// バイナリセマフォ（0または1の値）を作成
    pub fn binary() -> Self {
        Self::new(1, 1)
    }
    
    /// セマフォを取得 (P操作/wait)
    pub fn acquire(&self) -> bool {
        self.acquire_n(1)
    }
    
    /// 指定した数のセマフォを取得
    pub fn acquire_n(&self, n: i64) -> bool {
        if n <= 0 {
            return true; // 無効な要求数
        }
        
        let start_time = current_time_ns();
        let current_id = current_thread_id();
        
        // スピンフェーズでの取得試行
        for _ in 0..MAX_SPIN_ATTEMPTS {
            let current = self.count.load(Ordering::Relaxed);
            
            // 十分なカウントがあるか確認
            if current >= n {
                let new_count = current - n;
                if let Ok(_) = self.count.compare_exchange_weak(
                    current, new_count, Ordering::Acquire, Ordering::Relaxed
                ) {
                    // 取得成功
                    self.acquisition_count.fetch_add(1, Ordering::Relaxed);
                    
                    let elapsed = current_time_ns().saturating_sub(start_time);
                    if elapsed > 0 {
                        record_wait_time(elapsed);
                    }
                    
                    return true;
                }
            } else if let LockStrategy::TryOnce = self.options.strategy {
                // 即時失敗戦略の場合はここで終了
                return false;
            }
            
            // 少し待機
            cpu_pause();
        }
        
        // スピンでの取得に失敗した場合、ブロッキング戦略に移行
        self.contention_count.fetch_add(1, Ordering::Relaxed);
        record_contention();
        
        // 非ブロッキング戦略の場合は失敗を返す
        if let LockStrategy::TryOnce = self.options.strategy {
            return false;
        }
        
        // 待機情報を準備
        let timeout_ns = if let LockStrategy::TimedBlocking(timeout) = self.options.strategy {
            timeout
        } else {
            0 // 無限
        };
        
        let waiter = Waiter {
            thread_id: current_id,
            wait_start: start_time,
            timeout_ns,
            signaled: AtomicBool::new(false),
        };
        
        // 待機キューを確保
        let waiters_ptr = self.ensure_waiters_queue();
        
        // 待機カウンタを更新
        self.waiters_count.fetch_add(1, Ordering::Relaxed);
        
        // 待機キューに追加
        unsafe {
            let waiters = &mut *(waiters_ptr as *mut VecDeque<Waiter>);
            waiters.push_back(waiter);
        }
        
        // 待機状態に入る前にもう一度試行（レースコンディション回避）
        let mut acquired = false;
        let current = self.count.load(Ordering::Relaxed);
        if current >= n {
            let new_count = current - n;
            if let Ok(_) = self.count.compare_exchange(
                current, new_count, Ordering::Acquire, Ordering::Relaxed
            ) {
                acquired = true;
            }
        }
        
        if !acquired {
            // 待機状態に入る
            scheduler::thread_wait(current_id);
            
            // 条件：シグナルを受けたか、タイムアウト
            let mut timed_out = false;
            let mut signaled = false;
            
            // 待機キューから自分の状態を確認
            unsafe {
                let waiters = &mut *(waiters_ptr as *mut VecDeque<Waiter>);
                for waiter in waiters.iter() {
                    if waiter.thread_id == current_id {
                        signaled = waiter.signaled.load(Ordering::Relaxed);
                        
                        // タイムアウト確認
                        if timeout_ns > 0 && !signaled {
                            let now = current_time_ns();
                            if now > start_time + timeout_ns {
                                timed_out = true;
                            }
                        }
                        
                        break;
                    }
                }
            }
            
            if timed_out {
                // タイムアウト時は取得成功せず
                return false;
            }
            
            if !signaled {
                // スレッドが再開されたがシグナルを受けていない場合
                // （他の理由でスレッドが起動された場合）
                // カウントを再度確認して取得を試みる
                acquired = false;
                for _ in 0..1000 {  // 限定的な再試行
                    let current = self.count.load(Ordering::Relaxed);
                    if current >= n {
                        let new_count = current - n;
                        if let Ok(_) = self.count.compare_exchange(
                            current, new_count, Ordering::Acquire, Ordering::Relaxed
                        ) {
                            acquired = true;
                            break;
                        }
                    }
                    cpu_pause();
                }
            } else {
                // シグナルされた場合は取得成功
                acquired = true;
            }
        }
        
        // 待機カウンタを更新
        self.waiters_count.fetch_sub(1, Ordering::Relaxed);
        
        // 待機キューから自分を削除
        unsafe {
            let waiters = &mut *(waiters_ptr as *mut VecDeque<Waiter>);
            let mut idx = None;
            
            // 自分のエントリを探す
            for (i, w) in waiters.iter().enumerate() {
                if w.thread_id == current_id {
                    idx = Some(i);
                    break;
                }
            }
            
            // エントリを削除
            if let Some(i) = idx {
                waiters.remove(i);
            }
        }
        
        if acquired {
            self.acquisition_count.fetch_add(1, Ordering::Relaxed);
            
            let elapsed = current_time_ns().saturating_sub(start_time);
            record_wait_time(elapsed);
            
            true
        } else {
            false
        }
    }
    
    /// セマフォの取得を試みる（失敗時に即座に返る）
    pub fn try_acquire(&self) -> bool {
        self.try_acquire_n(1)
    }
    
    /// 指定した数のセマフォ取得を試みる（失敗時に即座に返る）
    pub fn try_acquire_n(&self, n: i64) -> bool {
        if n <= 0 {
            return true; // 無効な要求数
        }
        
        let current = self.count.load(Ordering::Relaxed);
        
        // 十分なカウントがあるか確認
        if current >= n {
            let new_count = current - n;
            if let Ok(_) = self.count.compare_exchange(
                current, new_count, Ordering::Acquire, Ordering::Relaxed
            ) {
                // 取得成功
                self.acquisition_count.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        
        // 取得失敗
        false
    }
    
    /// セマフォを解放 (V操作/signal)
    pub fn release(&self) -> bool {
        self.release_n(1)
    }
    
    /// 指定した数のセマフォを解放
    pub fn release_n(&self, n: i64) -> bool {
        if n <= 0 {
            return false; // 無効な解放数
        }
        
        // セマフォカウントを増加
        let mut success = false;
        let mut new_count = 0;
        
        loop {
            let current = self.count.load(Ordering::Relaxed);
            
            // 最大値を超えないか確認
            if self.max_count >= 0 && current + n > self.max_count {
                // 最大値制限あり
                new_count = self.max_count;
            } else {
                // 無制限または制限内
                new_count = current + n;
            }
            
            if let Ok(_) = self.count.compare_exchange_weak(
                current, new_count, Ordering::Release, Ordering::Relaxed
            ) {
                success = true;
                break;
            }
            
            // 少し待機
            cpu_pause();
        }
        
        if success {
            self.release_count.fetch_add(1, Ordering::Relaxed);
            
            // 待機スレッドがあれば一部を起こす
            if self.waiters_count.load(Ordering::Relaxed) > 0 {
                self.wake_waiters();
            }
            
            true
        } else {
            false
        }
    }
    
    /// 待機キューを確保する
    fn ensure_waiters_queue(&self) -> usize {
        let ptr = self.waiters_ptr.load(Ordering::Relaxed);
        if ptr != 0 {
            return ptr;
        }
        
        // 新しい待機キューを作成
        let waiters = Box::new(VecDeque::<Waiter>::with_capacity(4));
        let waiters_ptr = Box::into_raw(waiters) as usize;
        
        // アトミックに待機キューポインタを設定
        let result = self.waiters_ptr.compare_exchange(
            0,
            waiters_ptr,
            Ordering::Release,
            Ordering::Relaxed
        );
        
        match result {
            Ok(_) => waiters_ptr,
            Err(actual) => {
                // 別スレッドが同時に作成した場合
                unsafe {
                    // 作成したキューを破棄
                    drop(Box::from_raw(waiters_ptr as *mut VecDeque<Waiter>));
                }
                actual
            }
        }
    }
    
    /// 待機中のスレッドを起こす
    fn wake_waiters(&self) {
        let waiters_ptr = self.waiters_ptr.load(Ordering::Relaxed);
        if waiters_ptr == 0 {
            return;
        }
        
        unsafe {
            let waiters = &mut *(waiters_ptr as *mut VecDeque<Waiter>);
            if waiters.is_empty() {
                return;
            }
            
            // カウント値を読み込む
            let mut count = self.count.load(Ordering::Relaxed);
            let mut threads_to_wake = Vec::new();
            
            // 起こせるスレッドを探す
            for waiter in waiters.iter() {
                if !waiter.signaled.load(Ordering::Relaxed) {
                    if count > 0 {
                        // このスレッドを起こせる
                        threads_to_wake.push(waiter.thread_id);
                        waiter.signaled.store(true, Ordering::Relaxed);
                        count -= 1; // 概算
                    } else {
                        // もうカウントがない
                        break;
                    }
                }
            }
            
            // 待機スレッドを起こす
            for thread_id in threads_to_wake {
                scheduler::thread_wake(thread_id);
            }
        }
    }
    
    /// 現在の値を取得
    pub fn get_count(&self) -> i64 {
        self.count.load(Ordering::Relaxed)
    }
    
    /// 最大値を取得
    pub fn get_max_count(&self) -> i64 {
        self.max_count
    }
    
    /// 待機数を取得
    pub fn get_waiters_count(&self) -> usize {
        self.waiters_count.load(Ordering::Relaxed)
    }
    
    /// 統計情報を取得
    pub fn get_stats(&self) -> (usize, usize, usize, usize) {
        // (取得数, 解放数, 競合数, 待機数)
        (
            self.acquisition_count.load(Ordering::Relaxed),
            self.release_count.load(Ordering::Relaxed),
            self.contention_count.load(Ordering::Relaxed),
            self.waiters_count.load(Ordering::Relaxed)
        )
    }
    
    /// デバッグ情報を取得
    pub fn debug_info(&self) -> SyncDebugInfo {
        SyncDebugInfo {
            name: "Semaphore",
            acquisition_count: self.acquisition_count.load(Ordering::Relaxed),
            release_count: self.release_count.load(Ordering::Relaxed),
            contention_count: self.contention_count.load(Ordering::Relaxed),
            total_wait_time_ns: 0, // このレベルでは追跡していない
            max_wait_time_ns: 0,   // このレベルでは追跡していない
            current_owner: None,   // セマフォには所有者の概念がない
            lock_time: None,       // セマフォにはロック時刻の概念がない
        }
    }
}

impl Drop for Semaphore {
    fn drop(&mut self) {
        record_primitive_destroyed();
        
        // 待機キューがあれば解放
        let waiters_ptr = self.waiters_ptr.load(Ordering::Relaxed);
        if waiters_ptr != 0 {
            unsafe {
                let waiters = Box::from_raw(waiters_ptr as *mut VecDeque<Waiter>);
                
                // 待機中のスレッドを全て起こす
                for waiter in waiters.iter() {
                    if !waiter.signaled.load(Ordering::Relaxed) {
                        scheduler::thread_wake(waiter.thread_id);
                    }
                }
                
                // VecDequeは自動的にドロップされる
            }
        }
    }
}

impl SyncPrimitive for Semaphore {
    fn lock(&self) -> bool {
        self.acquire()
    }
    
    fn unlock(&self) -> bool {
        self.release()
    }
    
    fn is_locked(&self) -> bool {
        self.count.load(Ordering::Relaxed) == 0
    }
    
    fn is_owned_by_current_thread(&self) -> bool {
        false // セマフォには所有権の概念がない
    }
} 