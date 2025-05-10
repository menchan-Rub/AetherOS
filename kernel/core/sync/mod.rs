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

pub use mutex::{Mutex, MutexGuard};
pub use rwlock::{RwLock, RwLockReadGuard, RwLockWriteGuard};
pub use spinlock::{SpinLock, SpinLockGuard};
pub use semaphore::{Semaphore, SemaphoreGuard};
pub use barrier::Barrier;
pub use event::Event;
pub use condvar::CondVar;
pub use once::Once;
pub use atomic::{AtomicExt, AtomicPtr, AtomicRef};

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut, Drop};
use core::fmt;

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
#[inline]
pub fn current_thread_id() -> u64 {
    // 実際の実装ではスケジューラからスレッドIDを取得
    // この実装はダミー
    crate::arch::current_cpu_id() as u64
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
        // 他のアーキテクチャ用の汎用的な実装
        core::hint::spin_loop();
    }
}

/// メモリバリア実行のユーティリティ関数
#[inline]
pub fn memory_barrier() {
    core::sync::atomic::fence(Ordering::SeqCst);
}

/// 現在時刻を取得（ナノ秒）
#[inline]
pub fn current_time_ns() -> u64 {
    // 実際の実装ではシステムクロックから時間を取得
    // この実装はダミー
    crate::arch::read_timestamp_counter() as u64
} 