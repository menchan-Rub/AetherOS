// AetherOS 同期プリミティブモジュール
//
// このモジュールはカーネル内で使用される同期プリミティブを提供します。
// 高性能で拡張性のある同期機能を実装し、マルチコアシステムでの
// 効率的な並行処理を可能にします。

mod mutex;
mod rwlock;
mod spinlock;
mod semaphore;
mod barrier;
mod event;
mod condvar;
mod once;
mod atomic;
mod lockfree;

pub use mutex::{Mutex, MutexGuard};
pub use rwlock::{RwLock, RwLockReadGuard, RwLockWriteGuard};
pub use spinlock::{SpinLock, SpinLockGuard};
pub use semaphore::{Semaphore, SemaphoreGuard};
pub use barrier::{Barrier, BarrierToken, BarrierOptions, CentralBarrier, PhaseBarrier};
pub use event::Event;
pub use condvar::CondVar;
pub use once::Once;
pub use atomic::{AtomicExt, AtomicPtr, AtomicRef};
pub use lockfree::{LockFreeStack, LockFreeQueue, LockFreeHashMap, HardwareTransaction, TransactionError};

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut, Drop};
use core::fmt;
use crate::arch;

/// 同期プリミティブの通常操作とパニック時の動作を定義するトレイト
pub trait SyncPrimitive: Sized {
    /// プリミティブのロックを取得
    fn lock(&self) -> bool;
    
    /// プリミティブのロックを解放
    fn unlock(&self) -> bool;
    
    /// プリミティブがロックされているかをチェック
    fn is_locked(&self) -> bool;
    
    /// 現在のスレッドがこのプリミティブを所有しているかをチェック
    fn is_owned_by_current_thread(&self) -> bool;
}

/// ロック取得戦略を定義する列挙型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockStrategy {
    /// 即時失敗（ロックが取得できない場合即座に失敗）
    TryOnce,
    /// スピンロック（ロックが取得できるまでCPUをスピン）
    Spin,
    /// ブロッキング（ロックが取得できるまでスレッドをブロック）
    Blocking,
    /// タイムアウト付きブロッキング（指定時間待機後に失敗）
    TimedBlocking(u64), // タイムアウト（ナノ秒）
}

/// ロック取得結果を定義する列挙型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockResult {
    /// 成功
    Success,
    /// 失敗（ロック取得できず）
    Failed,
    /// タイムアウト
    Timeout,
    /// 再帰的ロック
    Recursive,
    /// デッドロック検出
    Deadlock,
}

/// 並行性のレベルを示す列挙型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcurrencyLevel {
    /// 低（最大2-4スレッド）
    Low,
    /// 中（5-16スレッド）
    Medium,
    /// 高（17-64スレッド）
    High,
    /// 超高（65スレッド以上）
    VeryHigh,
    /// 動的（実行時に決定）
    Dynamic,
}

/// 同期プリミティブのデバッグ情報
#[derive(Debug)]
pub struct SyncDebugInfo {
    /// プリミティブの名前
    pub name: &'static str,
    /// ロック取得回数
    pub acquisition_count: usize,
    /// ロック解放回数
    pub release_count: usize,
    /// 競合回数
    pub contention_count: usize,
    /// 待機時間の合計（ナノ秒）
    pub total_wait_time_ns: u64,
    /// 最長待機時間（ナノ秒）
    pub max_wait_time_ns: u64,
    /// 現在の所有者スレッドID（存在する場合）
    pub current_owner: Option<u64>,
    /// ロック取得時刻（ティック）
    pub lock_time: Option<u64>,
}

/// 同期プリミティブのオプション
#[derive(Debug, Clone)]
pub struct SyncOptions {
    /// ロック取得戦略
    pub strategy: LockStrategy,
    /// デッドロック検出を有効にするか
    pub deadlock_detection: bool,
    /// 優先継承を有効にするか（リアルタイムシステム用）
    pub priority_inheritance: bool,
    /// デバッグログを有効にするか
    pub debug_logging: bool,
    /// 再帰的ロックを許可するか
    pub recursive: bool,
    /// ロック取得の最大試行回数
    pub max_attempts: Option<usize>,
    /// CPUコアをバインドするか（特定のコアでのみ使用される場合）
    pub cpu_affinity: Option<usize>,
    /// 並行性レベル（並行アクセス数の予測）
    pub concurrency_level: ConcurrencyLevel,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            strategy: LockStrategy::Spin,
            deadlock_detection: false,
            priority_inheritance: false,
            debug_logging: false,
            recursive: false,
            max_attempts: None,
            cpu_affinity: None,
            concurrency_level: ConcurrencyLevel::Medium,
        }
    }
}

/// グローバル同期統計
#[derive(Debug)]
pub struct SyncStats {
    /// 作成された同期プリミティブの総数
    primitives_created: AtomicUsize,
    /// アクティブな同期プリミティブ数
    active_primitives: AtomicUsize,
    /// ロック競合の総数
    total_contentions: AtomicUsize,
    /// デッドロック検出回数
    deadlocks_detected: AtomicUsize,
    /// 総待機時間（ナノ秒）
    total_wait_time_ns: AtomicUsize,
}

/// グローバル同期統計のインスタンス
static SYNC_STATS: SyncStats = SyncStats {
    primitives_created: AtomicUsize::new(0),
    active_primitives: AtomicUsize::new(0),
    total_contentions: AtomicUsize::new(0),
    deadlocks_detected: AtomicUsize::new(0),
    total_wait_time_ns: AtomicUsize::new(0),
};

/// 同期サブシステムを初期化
pub fn init() {
    // アーキテクチャ固有の初期化（必要な場合）
    arch_init();
    
    log::info!("同期プリミティブサブシステム初期化完了");
}

/// アーキテクチャ固有の初期化
#[cfg(target_arch = "x86_64")]
fn arch_init() {
    // x86_64固有の最適化（例：PAUSE命令の調整など）
}

#[cfg(target_arch = "aarch64")]
fn arch_init() {
    // aarch64固有の最適化
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn arch_init() {
    // デフォルトの初期化
}

/// グローバル同期統計を取得
pub fn get_stats() -> (usize, usize, usize, usize, usize) {
    (
        SYNC_STATS.primitives_created.load(Ordering::Relaxed),
        SYNC_STATS.active_primitives.load(Ordering::Relaxed),
        SYNC_STATS.total_contentions.load(Ordering::Relaxed),
        SYNC_STATS.deadlocks_detected.load(Ordering::Relaxed),
        SYNC_STATS.total_wait_time_ns.load(Ordering::Relaxed),
    )
}

/// 同期プリミティブの作成を記録
#[inline]
pub(crate) fn record_primitive_created() {
    SYNC_STATS.primitives_created.fetch_add(1, Ordering::Relaxed);
    SYNC_STATS.active_primitives.fetch_add(1, Ordering::Relaxed);
}

/// 同期プリミティブの破棄を記録
#[inline]
pub(crate) fn record_primitive_destroyed() {
    SYNC_STATS.active_primitives.fetch_sub(1, Ordering::Relaxed);
}

/// ロック競合を記録
#[inline]
pub(crate) fn record_contention() {
    SYNC_STATS.total_contentions.fetch_add(1, Ordering::Relaxed);
}

/// デッドロック検出を記録
#[inline]
pub(crate) fn record_deadlock() {
    SYNC_STATS.deadlocks_detected.fetch_add(1, Ordering::Relaxed);
}

/// 待機時間を記録
#[inline]
pub(crate) fn record_wait_time(time_ns: u64) {
    if time_ns > 0 {
        SYNC_STATS.total_wait_time_ns.fetch_add(time_ns as usize, Ordering::Relaxed);
    }
}

/// 現在の実行スレッドのIDを取得
pub fn current_thread_id() -> u64 {
    // スケジューラからスレッドIDを取得の完全実装
    #[cfg(target_arch = "x86_64")]
    {
        // x86_64: GS段セレクタからPCBのスレッドIDを取得
        unsafe {
            let thread_id: u64;
            core::arch::asm!(
                "mov rax, gs:[0x00]",  // PCBのthread_idオフセット
                out("rax") thread_id,
                options(nostack)
            );
            thread_id
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        // AArch64: TPIDR_EL1からスレッドIDを取得
        unsafe {
            let thread_id: u64;
            core::arch::asm!(
                "mrs {}, TPIDR_EL1",
                out(reg) thread_id,
                options(nostack)
            );
            thread_id
        }
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        // RISC-V: sscratchレジスタからスレッドIDを取得
        unsafe {
            let thread_id: u64;
            core::arch::asm!(
                "csrr {}, sscratch",
                out(reg) thread_id,
                options(nostack)
            );
            thread_id
        }
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
    {
        // フォールバック: カーネルスタック内のスレッド情報から取得
        use crate::core::process;
        if let Some(current_thread) = process::current_thread() {
            current_thread.get_id()
        } else {
            0  // カーネル初期化中またはアイドルスレッド
        }
    }
}

/// CPUをスピンさせるためのユーティリティ関数
#[inline]
pub fn cpu_pause() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_pause();
    }
    
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::aarch64::__yield();
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        core::hint::spin_loop();
    }
}

/// メモリバリア
#[inline]
pub fn memory_barrier() {
    core::sync::atomic::fence(Ordering::SeqCst);
}

/// 現在時刻を取得（ナノ秒）
pub fn current_time_ns() -> u64 {
    // 高精度タイマーから時刻を取得の完全実装
    #[cfg(target_arch = "x86_64")]
    {
        use crate::arch::x86_64::timer;
        
        // TSC (Time Stamp Counter) を使用
        let tsc_freq = timer::get_tsc_frequency();
        if tsc_freq > 0 {
            unsafe {
                let tsc: u64;
                core::arch::asm!(
                    "rdtsc",
                    "shl rdx, 32",
                    "or rax, rdx",
                    out("rax") tsc,
                    out("rdx") _,
                    options(nostack)
                );
                
                // TSCを時刻に変換 (ナノ秒)
                (tsc * 1_000_000_000) / tsc_freq
            }
        } else {
            // TSCが利用できない場合はHPETを使用
            timer::read_hpet_counter()
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::timer;
        
        // Generic Timer のカウンタを読み取り
        unsafe {
            let counter: u64;
            core::arch::asm!(
                "mrs {}, CNTVCT_EL0",
                out(reg) counter,
                options(nostack)
            );
            
            // カウンタ頻度を取得
            let freq: u64;
            core::arch::asm!(
                "mrs {}, CNTFRQ_EL0",
                out(reg) freq,
                options(nostack)
            );
            
            // カウンタを時刻に変換 (ナノ秒)
            if freq > 0 {
                (counter * 1_000_000_000) / freq
            } else {
                timer::read_system_timer()
            }
        }
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        use crate::arch::riscv64::timer;
        
        // Machine Time レジスタを読み取り
        unsafe {
            let time: u64;
            core::arch::asm!(
                "csrr {}, time",
                out(reg) time,
                options(nostack)
            );
            
            // タイムベースを取得（通常は10MHz）
            let timebase = timer::get_timebase_frequency();
            
            // タイムカウンタを時刻に変換 (ナノ秒)
            (time * 1_000_000_000) / timebase
        }
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
    {
        // フォールバック実装: アトミックカウンタベース
        static MONOTONIC_COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        
        // カウンタを増加させて時間の単調性を保証
        let count = MONOTONIC_COUNTER.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        
        // 仮想時刻を計算（1マイクロ秒間隔）
        count * 1000
    }
}

// スピンロック
pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// スピンロックのガード
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

unsafe impl<T: Send> Send for SpinLock<T> {}
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }
    
    pub fn lock(&self) -> SpinLockGuard<T> {
        // アトミックにロック取得を試みる
        while self.locked.compare_exchange_weak(
            false, 
            true, 
            Ordering::Acquire,
            Ordering::Relaxed
        ).is_err() {
            // スピンウェイト（ハードウェアのpause命令を使用）
            arch::cpu::spin_hint();
        }
        
        SpinLockGuard { lock: self }
    }
    
    pub fn try_lock(&self) -> Option<SpinLockGuard<T>> {
        // ロックを試み、すでに取得されていれば失敗
        let result = self.locked.compare_exchange(
            false,
            true,
            Ordering::Acquire,
            Ordering::Relaxed
        );
        
        if result.is_ok() {
            Some(SpinLockGuard { lock: self })
        } else {
            None
        }
    }
}

impl<'a, T> Deref for SpinLockGuard<'a, T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        // ロック解放
        self.lock.locked.store(false, Ordering::Release);
    }
}

// 読み書きロック
pub struct RwLock<T> {
    // 負の値は書き込みロック、正の値は読み込みロックの数
    state: AtomicUsize,
    data: UnsafeCell<T>,
}

// 読み込みロックのガード
pub struct RwLockReadGuard<'a, T> {
    lock: &'a RwLock<T>,
}

// 書き込みロックのガード
pub struct RwLockWriteGuard<'a, T> {
    lock: &'a RwLock<T>,
}

unsafe impl<T: Send> Send for RwLock<T> {}
unsafe impl<T: Send + Sync> Sync for RwLock<T> {}

const WRITER_BIT: usize = usize::MAX / 2 + 1;

impl<T> RwLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            state: AtomicUsize::new(0),
            data: UnsafeCell::new(data),
        }
    }
    
    pub fn read(&self) -> RwLockReadGuard<T> {
        // 書き込みロックがかかっていない場合のみ読み込みカウントを増やす
        loop {
            let state = self.state.load(Ordering::Relaxed);
            
            // 書き込みロックがかかっている場合
            if state & WRITER_BIT != 0 {
                // スピンウェイト
                arch::cpu::spin_hint();
                continue;
            }
            
            // 読み込みカウントを増やす
            if self.state.compare_exchange_weak(
                state,
                state + 1,
                Ordering::Acquire,
                Ordering::Relaxed
            ).is_ok() {
                break;
            }
        }
        
        RwLockReadGuard { lock: self }
    }
    
    pub fn write(&self) -> RwLockWriteGuard<T> {
        // 他のロックがかかっていない場合のみ書き込みビットを設定
        loop {
            // 状態が0の場合のみ書き込みロックを取得できる
            if self.state.compare_exchange_weak(
                0,
                WRITER_BIT,
                Ordering::Acquire,
                Ordering::Relaxed
            ).is_ok() {
                break;
            }
            
            // スピンウェイト
            arch::cpu::spin_hint();
        }
        
        RwLockWriteGuard { lock: self }
    }
    
    pub fn try_read(&self) -> Option<RwLockReadGuard<T>> {
        let state = self.state.load(Ordering::Relaxed);
        
        // 書き込みロックがかかっている場合
        if state & WRITER_BIT != 0 {
            return None;
        }
        
        // 読み込みカウントを増やす
        if self.state.compare_exchange(
            state,
            state + 1,
            Ordering::Acquire,
            Ordering::Relaxed
        ).is_ok() {
            Some(RwLockReadGuard { lock: self })
        } else {
            None
        }
    }
    
    pub fn try_write(&self) -> Option<RwLockWriteGuard<T>> {
        // 状態が0の場合のみ書き込みロックを取得できる
        if self.state.compare_exchange(
            0,
            WRITER_BIT,
            Ordering::Acquire,
            Ordering::Relaxed
        ).is_ok() {
            Some(RwLockWriteGuard { lock: self })
        } else {
            None
        }
    }
}

impl<'a, T> Deref for RwLockReadGuard<'a, T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> Drop for RwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        // 読み込みカウントを減らす
        self.lock.state.fetch_sub(1, Ordering::Release);
    }
}

impl<'a, T> Deref for RwLockWriteGuard<'a, T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for RwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for RwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        // 書き込みビットをクリア
        self.lock.state.fetch_and(!WRITER_BIT, Ordering::Release);
    }
}

// セマフォ
pub struct Semaphore {
    count: AtomicUsize,
}

impl Semaphore {
    pub const fn new(count: usize) -> Self {
        Self {
            count: AtomicUsize::new(count),
        }
    }
    
    pub fn acquire(&self) {
        loop {
            // カウントが1以上ならデクリメント
            let count = self.count.load(Ordering::Relaxed);
            
            if count == 0 {
                // カウントが0なら待機
                arch::cpu::spin_hint();
                continue;
            }
            
            // カウントをデクリメント
            if self.count.compare_exchange_weak(
                count,
                count - 1,
                Ordering::Acquire,
                Ordering::Relaxed
            ).is_ok() {
                break;
            }
        }
    }
    
    pub fn release(&self) {
        // カウントをインクリメント
        self.count.fetch_add(1, Ordering::Release);
    }
    
    pub fn try_acquire(&self) -> bool {
        // カウントが1以上ならデクリメント
        let count = self.count.load(Ordering::Relaxed);
        
        if count == 0 {
            return false;
        }
        
        // カウントをデクリメント
        self.count.compare_exchange(
            count,
            count - 1,
            Ordering::Acquire,
            Ordering::Relaxed
        ).is_ok()
    }
}

// 相互排他ロック（Mutex）
pub struct Mutex<T> {
    // ロック獲得待ちのキュー管理のデータ構造を想定
    // 実際のウェイトキュー実装はOSによるスレッド休止を伴うため複雑
    // ここではスピンロックをベースにシンプルな実装としている
    inner: SpinLock<T>,
}

pub type MutexGuard<'a, T> = SpinLockGuard<'a, T>;

impl<T> Mutex<T> {
    pub const fn new(data: T) -> Self {
        Self {
            inner: SpinLock::new(data),
        }
    }
    
    pub fn lock(&self) -> MutexGuard<T> {
        self.inner.lock()
    }
    
    pub fn try_lock(&self) -> Option<MutexGuard<T>> {
        self.inner.try_lock()
    }
}