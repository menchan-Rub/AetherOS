// AetherOS 読み取り/書き込みロック実装
//
// このモジュールは読み取り/書き込みロック（RWLock）を実装します。
// 複数の同時読み取りと排他的な書き込みアクセスを管理し、
// 効率的な並行処理を可能にします。

use core::cell::UnsafeCell;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use alloc::collections::VecDeque;
use alloc::sync::Arc;

use super::{SyncPrimitive, SyncOptions, LockStrategy, LockResult, SyncDebugInfo};
use super::{record_primitive_created, record_primitive_destroyed, record_contention, record_deadlock, record_wait_time};
use super::{current_thread_id, cpu_pause, current_time_ns, memory_barrier};
use crate::core::process::scheduler;

/// ロックステータスのビット定義
const WRITER_BIT: usize = 1 << 31;      // 最上位ビット = 書き込みロック
const READER_MASK: usize = !WRITER_BIT; // 読み取りカウンタマスク

/// スピン試行の最大回数
const MAX_SPIN_ATTEMPTS: usize = 100;

/// 待機リクエストタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaiterType {
    /// 読み取りロック待機
    Reader,
    /// 書き込みロック待機
    Writer,
}

/// 待機状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaiterState {
    /// 待機中
    Waiting,
    /// シグナル受信済み
    Signaled,
    /// キャンセル
    Canceled,
    /// タイムアウト
    TimedOut,
}

/// 待機スレッド情報
#[derive(Debug)]
struct Waiter {
    /// スレッドID
    thread_id: u64,
    /// 待機タイプ
    waiter_type: WaiterType,
    /// 現在の状態
    state: WaiterState,
    /// 待機開始時刻
    wait_start: u64,
    /// タイムアウト（ナノ秒、0=無限）
    timeout_ns: u64,
}

/// 読み取り/書き込みロック実装
#[repr(align(64))]  // キャッシュライン境界にアライン
pub struct RwLock<T: ?Sized> {
    /// ロック状態（最上位ビット=書き込みロック、残りビット=読み取りカウント）
    state: AtomicUsize,
    /// 書き込み所有者スレッドID（0=なし）
    writer: AtomicU64,
    /// 書き込みロック取得時刻
    write_lock_time: AtomicU64,
    /// 読み取り取得回数
    read_count: AtomicUsize,
    /// 書き込み取得回数
    write_count: AtomicUsize,
    /// 競合回数
    contention_count: AtomicUsize,
    /// 読み取り待機数
    pending_readers: AtomicUsize,
    /// 書き込み待機数
    pending_writers: AtomicUsize,
    /// 設定オプション
    options: SyncOptions,
    /// 待機キュー（ポインタ格納用）
    waiters_ptr: AtomicUsize,
    /// 保護対象データ
    data: UnsafeCell<T>,
    /// パディング（キャッシュライン境界調整用）
    _padding: [u8; 8],
}

// RwLockはスレッド間で安全に共有できる
unsafe impl<T: ?Sized + Send + Sync> Send for RwLock<T> {}
unsafe impl<T: ?Sized + Send + Sync> Sync for RwLock<T> {}

/// 読み取りロックガード
pub struct RwLockReadGuard<'a, T: ?Sized> {
    /// ロック参照
    lock: &'a RwLock<T>,
    /// 所有者スレッドID
    owner_id: u64,
}

/// 書き込みロックガード
pub struct RwLockWriteGuard<'a, T: ?Sized> {
    /// ロック参照
    lock: &'a RwLock<T>,
    /// 所有者スレッドID
    owner_id: u64,
}

// ロックガードはスレッド間で移動できない
impl<T: ?Sized> !Send for RwLockReadGuard<'_, T> {}
impl<T: ?Sized> !Send for RwLockWriteGuard<'_, T> {}

impl<T> RwLock<T> {
    /// 新しい読み取り/書き込みロックを作成
    pub fn new(data: T) -> Self {
        record_primitive_created();
        
        Self {
            state: AtomicUsize::new(0),
            writer: AtomicU64::new(0),
            write_lock_time: AtomicU64::new(0),
            read_count: AtomicUsize::new(0),
            write_count: AtomicUsize::new(0),
            contention_count: AtomicUsize::new(0),
            pending_readers: AtomicUsize::new(0),
            pending_writers: AtomicUsize::new(0),
            options: SyncOptions::default(),
            waiters_ptr: AtomicUsize::new(0),
            data: UnsafeCell::new(data),
            _padding: [0; 8],
        }
    }
    
    /// 設定オプション付きで新しい読み取り/書き込みロックを作成
    pub fn with_options(data: T, options: SyncOptions) -> Self {
        record_primitive_created();
        
        Self {
            state: AtomicUsize::new(0),
            writer: AtomicU64::new(0),
            write_lock_time: AtomicU64::new(0),
            read_count: AtomicUsize::new(0),
            write_count: AtomicUsize::new(0),
            contention_count: AtomicUsize::new(0),
            pending_readers: AtomicUsize::new(0),
            pending_writers: AtomicUsize::new(0),
            options,
            waiters_ptr: AtomicUsize::new(0),
            data: UnsafeCell::new(data),
            _padding: [0; 8],
        }
    }
    
    /// データを消費して取り出す
    pub fn into_inner(self) -> T {
        record_primitive_destroyed();
        
        // ロックが解放されていることを確認
        debug_assert_eq!(self.state.load(Ordering::Relaxed), 0, 
                      "RWロックが解放されていない状態で消費しようとしました");
        
        // 待機キューがあれば解放
        let waiters_ptr = self.waiters_ptr.load(Ordering::Relaxed);
        if waiters_ptr != 0 {
            unsafe {
                // Box<VecDeque<Waiter>>をドロップ
                let _ = Box::from_raw(waiters_ptr as *mut VecDeque<Waiter>);
            }
        }
        
        self.data.into_inner()
    }
}

impl<T: ?Sized> RwLock<T> {
    /// 読み取りロックを取得する
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        let start_time = current_time_ns();
        let current_id = current_thread_id();
        
        // 現在のスレッドが書き込みロックを保持しているかチェック（デッドロック防止）
        if self.writer.load(Ordering::Relaxed) == current_id {
            if self.options.debug_logging {
                log::warn!("RWロックのデッドロック回避: 書き込みロック所有者が読み取りロックを取得しようとしています");
            }
            
            // 書き込みロックを保持している場合は自動的に読み取りロックも取得できる
            return RwLockReadGuard {
                lock: self,
                owner_id: current_id,
            };
        }
        
        // 読み取りロック取得を試みる（スピンフェーズ）
        for _ in 0..MAX_SPIN_ATTEMPTS {
            let state = self.state.load(Ordering::Relaxed);
            
            // 書き込みロックが保持されていなければ読み取りカウントを増加
            if state & WRITER_BIT == 0 {
                let new_state = state + 1;
                if let Ok(_) = self.state.compare_exchange_weak(
                    state, new_state, Ordering::Acquire, Ordering::Relaxed
                ) {
                    // 読み取りロック取得成功
                    self.read_count.fetch_add(1, Ordering::Relaxed);
                    
                    let elapsed = current_time_ns().saturating_sub(start_time);
                    if elapsed > 0 {
                        record_wait_time(elapsed);
                    }
                    
                    return RwLockReadGuard {
                        lock: self,
                        owner_id: current_id,
                    };
                }
            }
            
            // 少し待機
            cpu_pause();
        }
        
        // スピンでのロック取得に失敗した場合、ブロッキング戦略に移行
        self.contention_count.fetch_add(1, Ordering::Relaxed);
        record_contention();
        
        // ロック戦略が即時失敗の場合はパニック
        if let LockStrategy::TryOnce = self.options.strategy {
            panic!("読み取りロックの取得に失敗しました（TryOnce戦略）");
        }
        
        // 待機キューに追加
        let waiter = Waiter {
            thread_id: current_id,
            waiter_type: WaiterType::Reader,
            state: WaiterState::Waiting,
            wait_start: start_time,
            timeout_ns: if let LockStrategy::TimedBlocking(timeout) = self.options.strategy {
                timeout
            } else {
                0 // 無限
            },
        };
        
        let timeout_ns = waiter.timeout_ns;
        
        // 待機キューを取得または作成
        let waiters_ptr = self.ensure_waiters_queue();
        
        // 待機カウンタを更新
        self.pending_readers.fetch_add(1, Ordering::Relaxed);
        
        unsafe {
            let waiters = &mut *(waiters_ptr as *mut VecDeque<Waiter>);
            
            // 待機者を追加
            waiters.push_back(waiter);
        }
        
        // 待機状態に入る
        scheduler::thread_wait(current_id);
        
        // 待機終了（スレッドが再開された）
        let mut wait_result = WaiterState::Signaled;
        
        // タイムアウトチェック
        if timeout_ns > 0 {
            let now = current_time_ns();
            if now > start_time + timeout_ns {
                wait_result = WaiterState::TimedOut;
            }
        }
        
        // 待機カウンタを更新
        self.pending_readers.fetch_sub(1, Ordering::Relaxed);
        
        // 待機キューから自分を削除
        unsafe {
            let waiters = &mut *(waiters_ptr as *mut VecDeque<Waiter>);
            let mut idx = None;
            
            // 自分のエントリを探す
            for (i, w) in waiters.iter().enumerate() {
                if w.thread_id == current_id {
                    idx = Some(i);
                    // 状態を確認
                    wait_result = w.state;
                    break;
                }
            }
            
            // エントリを削除
            if let Some(i) = idx {
                waiters.remove(i);
            }
        }
        
        // 待機結果に応じた処理
        match wait_result {
            WaiterState::Signaled => {
                // 読み取りロックを実際に取得
                let mut acquired = false;
                for _ in 0..1000 {  // 限定的な再試行
                    let state = self.state.load(Ordering::Relaxed);
                    if state & WRITER_BIT == 0 {
                        let new_state = state + 1;
                        if let Ok(_) = self.state.compare_exchange(
                            state, new_state, Ordering::Acquire, Ordering::Relaxed
                        ) {
                            acquired = true;
                            break;
                        }
                    }
                    cpu_pause();
                }
                
                if !acquired {
                    panic!("シグナル後の読み取りロック取得に失敗しました");
                }
                
                self.read_count.fetch_add(1, Ordering::Relaxed);
                
                let elapsed = current_time_ns().saturating_sub(start_time);
                record_wait_time(elapsed);
                
                RwLockReadGuard {
                    lock: self,
                    owner_id: current_id,
                }
            },
            WaiterState::TimedOut => {
                // タイムアウト時にはロックを取得せずエラー
                panic!("読み取りロックの取得がタイムアウトしました");
            },
            WaiterState::Canceled => {
                // キャンセル時にはロックを取得せずエラー
                panic!("読み取りロックの取得がキャンセルされました");
            },
            _ => {
                // その他の状態は不正
                panic!("読み取りロックの待機で不正な状態が発生しました");
            }
        }
    }
    
    /// 書き込みロックを取得する
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        let start_time = current_time_ns();
        let current_id = current_thread_id();
        
        // 現在のスレッドが既に書き込みロックを保持しているかチェック
        if self.writer.load(Ordering::Relaxed) == current_id {
            // 既に所有している場合は再度返す
            return RwLockWriteGuard {
                lock: self,
                owner_id: current_id,
            };
        }
        
        // 書き込みロック取得を試みる（スピンフェーズ）
        for _ in 0..MAX_SPIN_ATTEMPTS {
            // ロック状態が0（ロックなし）であれば書き込みビットを設定
            if let Ok(_) = self.state.compare_exchange_weak(
                0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed
            ) {
                // 書き込みロック取得成功
                self.write_count.fetch_add(1, Ordering::Relaxed);
                self.writer.store(current_id, Ordering::Relaxed);
                self.write_lock_time.store(current_time_ns(), Ordering::Relaxed);
                
                let elapsed = current_time_ns().saturating_sub(start_time);
                if elapsed > 0 {
                    record_wait_time(elapsed);
                }
                
                return RwLockWriteGuard {
                    lock: self,
                    owner_id: current_id,
                };
            }
            
            // 少し待機
            cpu_pause();
        }
        
        // スピンでのロック取得に失敗した場合、ブロッキング戦略に移行
        self.contention_count.fetch_add(1, Ordering::Relaxed);
        record_contention();
        
        // ロック戦略が即時失敗の場合はパニック
        if let LockStrategy::TryOnce = self.options.strategy {
            panic!("書き込みロックの取得に失敗しました（TryOnce戦略）");
        }
        
        // 待機キューに追加
        let waiter = Waiter {
            thread_id: current_id,
            waiter_type: WaiterType::Writer,
            state: WaiterState::Waiting,
            wait_start: start_time,
            timeout_ns: if let LockStrategy::TimedBlocking(timeout) = self.options.strategy {
                timeout
            } else {
                0 // 無限
            },
        };
        
        let timeout_ns = waiter.timeout_ns;
        
        // 待機キューを取得または作成
        let waiters_ptr = self.ensure_waiters_queue();
        
        // 待機カウンタを更新
        self.pending_writers.fetch_add(1, Ordering::Relaxed);
        
        unsafe {
            let waiters = &mut *(waiters_ptr as *mut VecDeque<Waiter>);
            
            // 待機者を追加（書き込み待機は先頭に挿入して優先）
            waiters.push_front(waiter);
        }
        
        // 待機状態に入る
        scheduler::thread_wait(current_id);
        
        // 待機終了（スレッドが再開された）
        let mut wait_result = WaiterState::Signaled;
        
        // タイムアウトチェック
        if timeout_ns > 0 {
            let now = current_time_ns();
            if now > start_time + timeout_ns {
                wait_result = WaiterState::TimedOut;
            }
        }
        
        // 待機カウンタを更新
        self.pending_writers.fetch_sub(1, Ordering::Relaxed);
        
        // 待機キューから自分を削除
        unsafe {
            let waiters = &mut *(waiters_ptr as *mut VecDeque<Waiter>);
            let mut idx = None;
            
            // 自分のエントリを探す
            for (i, w) in waiters.iter().enumerate() {
                if w.thread_id == current_id {
                    idx = Some(i);
                    // 状態を確認
                    wait_result = w.state;
                    break;
                }
            }
            
            // エントリを削除
            if let Some(i) = idx {
                waiters.remove(i);
            }
        }
        
        // 待機結果に応じた処理
        match wait_result {
            WaiterState::Signaled => {
                // 書き込みロックが実際に取得されているか確認
                let state = self.state.load(Ordering::Relaxed);
                let writer_id = self.writer.load(Ordering::Relaxed);
                
                if state != WRITER_BIT || writer_id != current_id {
                    // 書き込みロックが期待通りに設定されていない
                    panic!("シグナル後の書き込みロック状態が不正です: state={}, writer={}",
                           state, writer_id);
                }
                
                let elapsed = current_time_ns().saturating_sub(start_time);
                record_wait_time(elapsed);
                
                RwLockWriteGuard {
                    lock: self,
                    owner_id: current_id,
                }
            },
            WaiterState::TimedOut => {
                // タイムアウト時にはロックを取得せずエラー
                panic!("書き込みロックの取得がタイムアウトしました");
            },
            WaiterState::Canceled => {
                // キャンセル時にはロックを取得せずエラー
                panic!("書き込みロックの取得がキャンセルされました");
            },
            _ => {
                // その他の状態は不正
                panic!("書き込みロックの待機で不正な状態が発生しました");
            }
        }
    }
    
    /// 読み取りロック取得を試みる（失敗時に即座に返る）
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        let current_id = current_thread_id();
        
        // 現在のスレッドが書き込みロックを保持しているか
        if self.writer.load(Ordering::Relaxed) == current_id {
            return Some(RwLockReadGuard {
                lock: self,
                owner_id: current_id,
            });
        }
        
        // 読み取りロック取得を試みる
        let state = self.state.load(Ordering::Relaxed);
        if state & WRITER_BIT == 0 {
            let new_state = state + 1;
            if let Ok(_) = self.state.compare_exchange(
                state, new_state, Ordering::Acquire, Ordering::Relaxed
            ) {
                // 読み取りロック取得成功
                self.read_count.fetch_add(1, Ordering::Relaxed);
                
                return Some(RwLockReadGuard {
                    lock: self,
                    owner_id: current_id,
                });
            }
        }
        
        // 取得失敗
        None
    }
    
    /// 書き込みロック取得を試みる（失敗時に即座に返る）
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        let current_id = current_thread_id();
        
        // 現在のスレッドが既に書き込みロックを保持しているか
        if self.writer.load(Ordering::Relaxed) == current_id {
            return Some(RwLockWriteGuard {
                lock: self,
                owner_id: current_id,
            });
        }
        
        // 書き込みロック取得を試みる
        if let Ok(_) = self.state.compare_exchange(
            0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed
        ) {
            // 書き込みロック取得成功
            self.write_count.fetch_add(1, Ordering::Relaxed);
            self.writer.store(current_id, Ordering::Relaxed);
            self.write_lock_time.store(current_time_ns(), Ordering::Relaxed);
            
            return Some(RwLockWriteGuard {
                lock: self,
                owner_id: current_id,
            });
        }
        
        // 取得失敗
        None
    }
    
    /// 内部データへの可変参照を取得（アンセーフ）
    ///
    /// # Safety
    /// 呼び出し元は、このスレッドが唯一データにアクセスしていることを保証する必要があります。
    pub unsafe fn get_mut_unchecked(&self) -> &mut T {
        &mut *self.data.get()
    }
    
    /// 読み取りロックが取得されているかを確認
    pub fn has_readers(&self) -> bool {
        (self.state.load(Ordering::Relaxed) & READER_MASK) > 0
    }
    
    /// 書き込みロックが取得されているかを確認
    pub fn has_writer(&self) -> bool {
        (self.state.load(Ordering::Relaxed) & WRITER_BIT) != 0
    }
    
    /// 現在のスレッドが書き込みロックを保持しているかを確認
    pub fn is_owned_by_current_thread(&self) -> bool {
        let current_id = current_thread_id();
        let writer_id = self.writer.load(Ordering::Relaxed);
        writer_id != 0 && writer_id == current_id
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
    
    /// 読み取りロックを解放
    fn release_read(&self) {
        // 読み取りカウンタを減少
        loop {
            let state = self.state.load(Ordering::Relaxed);
            
            // 読み取りカウントがゼロまたは書き込みビットが立っている場合はエラー
            assert!(state & READER_MASK > 0, "読み取りロックが取得されていません");
            assert!(state & WRITER_BIT == 0, "書き込みロックと読み取りロックが同時に取得されています");
            
            let new_state = state - 1;
            if let Ok(_) = self.state.compare_exchange_weak(
                state, new_state, Ordering::Release, Ordering::Relaxed
            ) {
                break;
            }
        }
        
        // 読み取りが完全に解放された場合は待機中の書き込みロック要求を処理
        if self.state.load(Ordering::Relaxed) == 0 && self.pending_writers.load(Ordering::Relaxed) > 0 {
            self.wake_waiters(WaiterType::Writer);
        }
    }
    
    /// 書き込みロックを解放
    fn release_write(&self) {
        let current_id = current_thread_id();
        
        // 書き込み所有者をチェック
        let writer_id = self.writer.load(Ordering::Relaxed);
        assert_eq!(writer_id, current_id, "現在のスレッドは書き込みロックの所有者ではありません");
        
        // 書き込みビットをクリア
        let state = self.state.load(Ordering::Relaxed);
        assert_eq!(state, WRITER_BIT, "書き込みロック状態が不正です");
        
        self.writer.store(0, Ordering::Relaxed);
        memory_barrier();
        self.state.store(0, Ordering::Release);
        
        // 待機者を起こす（書き込みロックが解放されたので）
        // 書き込み待機者を優先
        if self.pending_writers.load(Ordering::Relaxed) > 0 {
            self.wake_waiters(WaiterType::Writer);
        } else if self.pending_readers.load(Ordering::Relaxed) > 0 {
            self.wake_waiters(WaiterType::Reader);
        }
    }
    
    /// 待機中のスレッドを起こす
    fn wake_waiters(&self, priority_type: WaiterType) {
        let waiters_ptr = self.waiters_ptr.load(Ordering::Relaxed);
        if waiters_ptr == 0 {
            return;
        }
        
        unsafe {
            let waiters = &mut *(waiters_ptr as *mut VecDeque<Waiter>);
            
            if priority_type == WaiterType::Writer {
                // 書き込み待機者を探す
                for waiter in waiters.iter_mut() {
                    if waiter.waiter_type == WaiterType::Writer && waiter.state == WaiterState::Waiting {
                        // 書き込みロックを割り当て
                        waiter.state = WaiterState::Signaled;
                        let thread_id = waiter.thread_id;
                        
                        // 書き込みビットを設定
                        self.state.store(WRITER_BIT, Ordering::Release);
                        self.writer.store(thread_id, Ordering::Release);
                        self.write_lock_time.store(current_time_ns(), Ordering::Relaxed);
                        
                        // 待機スレッドを再開
                        scheduler::thread_wake(thread_id);
                        return; // 一度に一つの書き込みだけ
                    }
                }
            }
            
            // 書き込み待機者がいないか、読み取り優先の場合は読み取り待機者を全て起こす
            if priority_type == WaiterType::Reader {
                let mut readers_to_wake = Vec::new();
                
                for waiter in waiters.iter_mut() {
                    if waiter.waiter_type == WaiterType::Reader && waiter.state == WaiterState::Waiting {
                        waiter.state = WaiterState::Signaled;
                        readers_to_wake.push(waiter.thread_id);
                    }
                }
                
                if !readers_to_wake.is_empty() {
                    // 読み取りカウントを増加
                    let reader_count = readers_to_wake.len();
                    self.state.fetch_add(reader_count, Ordering::Release);
                    
                    // 読み取り待機者を再開
                    for thread_id in readers_to_wake {
                        scheduler::thread_wake(thread_id);
                    }
                }
            }
        }
    }
    
    /// 統計情報を取得
    pub fn get_stats(&self) -> (usize, usize, usize, usize) {
        // (読み取り数, 書き込み数, 読み取り待機数, 書き込み待機数)
        (
            self.read_count.load(Ordering::Relaxed),
            self.write_count.load(Ordering::Relaxed),
            self.pending_readers.load(Ordering::Relaxed),
            self.pending_writers.load(Ordering::Relaxed)
        )
    }
    
    /// デバッグ情報を取得
    pub fn debug_info(&self) -> SyncDebugInfo {
        let writer_id = self.writer.load(Ordering::Relaxed);
        let lock_time = self.write_lock_time.load(Ordering::Relaxed);
        
        SyncDebugInfo {
            name: "RwLock",
            acquisition_count: self.read_count.load(Ordering::Relaxed) + self.write_count.load(Ordering::Relaxed),
            release_count: self.read_count.load(Ordering::Relaxed) + self.write_count.load(Ordering::Relaxed),
            contention_count: self.contention_count.load(Ordering::Relaxed),
            total_wait_time_ns: 0, // このレベルでは追跡していない
            max_wait_time_ns: 0,   // このレベルでは追跡していない
            current_owner: if writer_id != 0 { Some(writer_id) } else { None },
            lock_time: if lock_time != 0 { Some(lock_time) } else { None },
        }
    }
}

impl<'a, T: ?Sized> Deref for RwLockReadGuard<'a, T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T: ?Sized> Drop for RwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        // ガードがドロップされるときに読み取りロックを解放
        self.lock.release_read();
    }
}

impl<'a, T: ?Sized> Deref for RwLockWriteGuard<'a, T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T: ?Sized> DerefMut for RwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T: ?Sized> Drop for RwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        // ガードがドロップされるときに書き込みロックを解放
        self.lock.release_write();
    }
}

impl<T: ?Sized> SyncPrimitive for RwLock<T> {
    fn lock(&self) -> bool {
        // 書き込みロックを取得する場合と同等
        let state = self.state.load(Ordering::Relaxed);
        state == WRITER_BIT
    }
    
    fn unlock(&self) -> bool {
        // 書き込みロックを解放する場合と同等
        let state = self.state.load(Ordering::Relaxed);
        if state == WRITER_BIT {
            self.writer.store(0, Ordering::Relaxed);
            self.state.store(0, Ordering::Release);
            true
        } else {
            false
        }
    }
    
    fn is_locked(&self) -> bool {
        self.state.load(Ordering::Relaxed) != 0
    }
    
    fn is_owned_by_current_thread(&self) -> bool {
        self.is_owned_by_current_thread()
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for RwLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.try_read() {
            Some(guard) => f.debug_struct("RwLock")
                            .field("locked", &"read")
                            .field("data", &&*guard)
                            .finish(),
            None => match self.try_write() {
                Some(guard) => f.debug_struct("RwLock")
                                .field("locked", &"write")
                                .field("data", &&*guard)
                                .finish(),
                None => f.debug_struct("RwLock")
                         .field("locked", &"locked")
                         .field("data", &"<locked>")
                         .finish(),
            }
        }
    }
}

impl<T: Default> Default for RwLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
} 