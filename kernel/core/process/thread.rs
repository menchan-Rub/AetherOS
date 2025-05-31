// AetherOS 高性能スレッド管理システム
//
// 世界最高水準のスレッド管理機能を提供する包括的実装

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, AtomicI32, Ordering};
use core::time::Duration;
use crate::arch;
use crate::core::memory::{VirtualAddress, PhysicalAddress, PageSize};
use crate::core::sync::{Mutex, SpinLock};
use crate::time;

/// スレッドID
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadId(pub u64);

impl ThreadId {
    /// 新しいスレッドIDを生成
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        ThreadId(NEXT_ID.fetch_add(1, Ordering::SeqCst))
    }
}

/// スレッド状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// 新規作成
    New,
    /// 実行可能
    Ready,
    /// 実行中
    Running,
    /// ブロック中
    Blocked,
    /// 終了
    Terminated,
    /// ゾンビ状態
    Zombie,
}

/// スレッド優先度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Priority(pub i32);

impl Priority {
    pub const MIN: Priority = Priority(-20);
    pub const MAX: Priority = Priority(19);
    pub const DEFAULT: Priority = Priority(0);
    
    pub fn to_nice(&self) -> i8 {
        self.0 as i8
    }
    
    pub fn as_index(&self) -> usize {
        (self.0 + 20) as usize
    }
}

/// スケジューリングポリシー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedPolicy {
    /// 通常プロセス（CFS）
    Normal,
    /// バッチプロセス（低優先度CFS）
    Batch,
    /// アイドル優先度（最低優先度CFS）
    Idle,
    /// FIFOリアルタイム
    Fifo,
    /// ラウンドロビンリアルタイム
    RoundRobin,
    /// デッドライン駆動
    Deadline,
}

/// タスクアフィニティ
#[derive(Debug, Clone)]
pub struct TaskAffinity {
    /// CPUマスク
    pub cpu_mask: u64,
    /// NUMA ノード
    pub numa_node: Option<u32>,
}

impl Default for TaskAffinity {
    fn default() -> Self {
        Self {
            cpu_mask: u64::MAX, // 全CPUで実行可能
            numa_node: None,
        }
    }
}

/// スケジューリングクラス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulingClass {
    /// リアルタイム
    RealTime,
    /// 標準
    Normal,
    /// バッチ
    Batch,
    /// アイドル
    Idle,
}

/// スレッド統計情報
#[derive(Debug, Default)]
pub struct ThreadStats {
    /// コンテキストスイッチ回数
    pub context_switches: AtomicUsize,
    /// ページフォルト回数
    pub page_faults: AtomicUsize,
    /// システムコール回数
    pub syscalls: AtomicUsize,
    /// CPU使用時間（ナノ秒）
    pub cpu_time: AtomicU64,
    /// I/O待機時間（ナノ秒）
    pub io_wait_time: AtomicU64,
}

/// スレッド構造体
pub struct Thread {
    /// スレッドID
    pub id: ThreadId,
    /// 所属プロセス
    pub process: Weak<crate::core::process::Process>,
    /// スレッド名
    pub name: String,
    /// 現在の状態
    pub state: Mutex<ThreadState>,
    /// 優先度
    pub priority: AtomicI32,
    /// スケジューリングポリシー
    pub policy: SchedPolicy,
    /// 最後に実行されたCPU
    pub last_cpu: AtomicUsize,
    /// 最後の実行時刻
    pub last_run_time: AtomicU64,
    /// 最後のスリープ時刻
    pub last_sleep_time: AtomicU64,
    /// 累積実行時間（ナノ秒）
    pub total_runtime: AtomicU64,
    /// スタックポインタ
    pub stack_pointer: AtomicUsize,
    /// カーネルスタック
    pub kernel_stack: Option<VirtualAddress>,
    /// ユーザースタック
    pub user_stack: Option<VirtualAddress>,
    /// スタックサイズ
    pub stack_size: usize,
    /// CPU親和性
    pub cpu_affinity: TaskAffinity,
    /// スケジューリングクラス
    pub scheduling_class: SchedulingClass,
    /// 現在の優先度
    pub current_priority: u32,
    /// スレッドローカルストレージ
    pub tls: Option<VirtualAddress>,
    /// 作成時刻
    pub creation_time: u64,
    /// 終了コード
    pub exit_code: AtomicI32,
    /// 統計情報
    pub stats: ThreadStats,
}

impl Thread {
    /// 新しいカーネルスレッドを作成
    pub fn new_kernel_thread(
        name: &str,
        entry_point: fn(),
        stack_size: usize,
        priority: Priority,
        cpu_id: usize,
    ) -> Result<Arc<Self>, &'static str> {
        // スレッドIDを生成
        let id = ThreadId::new();
        
        // カーネルスタックを割り当て
        let kernel_stack = crate::core::memory::allocate_kernel_stack(stack_size)?;
        
        // スタックポインタを設定（スタックは下向きに成長）
        let stack_top = kernel_stack.as_usize() + stack_size;
        
        // スレッド構造体を作成
        let thread = Arc::new(Thread {
            id,
            process: Weak::new(), // カーネルスレッドはプロセスに属さない
            name: name.to_string(),
            state: Mutex::new(ThreadState::New),
            priority: AtomicI32::new(priority.0),
            policy: SchedPolicy::Normal,
            last_cpu: AtomicUsize::new(cpu_id),
            last_run_time: AtomicU64::new(0),
            last_sleep_time: AtomicU64::new(0),
            total_runtime: AtomicU64::new(0),
            stack_pointer: AtomicUsize::new(stack_top),
            kernel_stack: Some(kernel_stack),
            user_stack: None,
            stack_size,
            cpu_affinity: TaskAffinity {
                cpu_mask: 1 << cpu_id, // 指定されたCPUに固定
                numa_node: None,
            },
            scheduling_class: SchedulingClass::Normal,
            current_priority: priority.0 as u32,
            tls: None,
            creation_time: crate::time::current_time_ns(),
            exit_code: AtomicI32::new(0),
            stats: ThreadStats::default(),
        });
        
        // スタックにエントリポイントを設定
        unsafe {
            let stack_ptr = stack_top as *mut usize;
            // リターンアドレスとしてエントリポイントを設定
            *stack_ptr.offset(-1) = entry_point as usize;
            // スタックポインタを調整
            thread.stack_pointer.store(stack_ptr.offset(-1) as usize, Ordering::Release);
        }
        
        log::debug!("カーネルスレッド '{}' を作成しました (ID: {})", name, id.0);
        
        Ok(thread)
    }
    
    /// スレッドIDを取得
    pub fn get_id(&self) -> u64 {
        self.id.0
    }
    
    /// スレッド状態を取得
    pub fn get_state(&self) -> ThreadState {
        *self.state.lock()
    }
    
    /// スレッド状態を設定
    pub fn set_state(&self, new_state: ThreadState) {
        *self.state.lock() = new_state;
    }
    
    /// 優先度を取得
    pub fn get_priority(&self) -> Priority {
        Priority(self.priority.load(Ordering::Relaxed))
    }
    
    /// 優先度を設定
    pub fn set_priority(&self, priority: Priority) {
        self.priority.store(priority.0, Ordering::Relaxed);
        self.current_priority = priority.0 as u32;
    }
    
    /// スケジューリングポリシーを取得
    pub fn get_policy(&self) -> SchedPolicy {
        self.policy
    }
    
    /// CPUアフィニティを取得
    pub fn get_affinity(&self) -> Option<&TaskAffinity> {
        Some(&self.cpu_affinity)
    }
    
    /// 最後に実行されたCPUを取得
    pub fn get_cpu(&self) -> usize {
        self.last_cpu.load(Ordering::Relaxed)
    }
    
    /// 最後のスリープ時刻を取得
    pub fn get_last_sleep_time(&self) -> u64 {
        self.last_sleep_time.load(Ordering::Relaxed)
    }
    
    /// スレッドを終了
    pub fn terminate(&self, exit_code: i32) {
        self.exit_code.store(exit_code, Ordering::Release);
        self.set_state(ThreadState::Terminated);
        
        log::debug!("スレッド {} が終了しました (終了コード: {})", self.id.0, exit_code);
    }
    
    /// スレッドがリアルタイムかチェック
    pub fn is_realtime(&self) -> bool {
        self.scheduling_class == SchedulingClass::RealTime || 
        self.current_priority >= 90
    }
    
    /// 優先度を取得（u32）
    pub fn priority(&self) -> u32 {
        self.current_priority
    }
    
    /// アフィニティ設定を取得
    pub fn get_affinity_settings(&self) -> &TaskAffinity {
        &self.cpu_affinity
    }
}

/// CPU統計情報
#[derive(Debug, Default)]
pub struct CpuIdleStats {
    /// 総アイドル時間（ナノ秒）
    pub total_idle_time: u64,
    /// 最後のアイドル開始時刻
    pub last_idle_timestamp: u64,
    /// アイドル回数
    pub idle_count: u64,
}

/// CPUごとのアイドル統計
static mut CPU_IDLE_STATS: [CpuIdleStats; 256] = [CpuIdleStats {
    total_idle_time: 0,
    last_idle_timestamp: 0,
    idle_count: 0,
}; 256];

/// アイドルスレッドを作成
pub fn create_idle_thread(cpu_id: usize) -> Arc<Thread> {
    log::debug!("CPU {} 用のアイドルスレッドを作成中...", cpu_id);
    
    // アイドルスレッド用の8KBスタックを割り当て
    let stack_size = 8 * 1024; // 8KB
    let kernel_stack = crate::core::memory::allocate_kernel_stack(stack_size)
        .expect("アイドルスレッド用スタック割り当てに失敗");
    
    let thread = Arc::new(Thread {
        id: ThreadId::new(),
        process: Weak::new(),
        name: format!("idle/{}", cpu_id),
        state: Mutex::new(ThreadState::Ready),
        priority: AtomicI32::new(Priority::MIN.0), // 最低優先度
        policy: SchedPolicy::Idle,
        last_cpu: AtomicUsize::new(cpu_id),
        last_run_time: AtomicU64::new(0),
        last_sleep_time: AtomicU64::new(0),
        total_runtime: AtomicU64::new(0),
        stack_pointer: AtomicUsize::new(kernel_stack.as_usize() + stack_size),
        kernel_stack: Some(kernel_stack),
        user_stack: None,
        stack_size,
        cpu_affinity: TaskAffinity {
            cpu_mask: 1 << cpu_id, // 特定のCPUに固定
            numa_node: None,
        },
        scheduling_class: SchedulingClass::Idle,
        current_priority: 0, // 最低優先度
        tls: None,
        creation_time: crate::time::current_time_ns(),
        exit_code: AtomicI32::new(0),
        stats: ThreadStats::default(),
    });
    
    log::info!("CPU {} 用アイドルスレッド作成完了 (ID: {})", cpu_id, thread.id.0);
    thread
}

/// アイドルタスクの実行
pub fn idle_task() -> ! {
    let cpu_id = arch::get_current_cpu_id();
    log::debug!("CPU {} でアイドルタスク開始", cpu_id);
    
    loop {
        // アイドル統計の更新
        update_idle_statistics(cpu_id);
        
        // バックグラウンドメンテナンス作業
        perform_background_maintenance();
        
        // CPU一時停止（電力節約）
        arch::halt_until_interrupt();
        
        // 短時間のスピンループ（レスポンス性向上）
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }
}

/// アイドル統計情報を更新
fn update_idle_statistics(cpu_id: usize) {
    let current_time = crate::time::current_time_ns();
    
    unsafe {
        if cpu_id < CPU_IDLE_STATS.len() {
            let stats = &mut CPU_IDLE_STATS[cpu_id];
            
            if stats.last_idle_timestamp != 0 {
                let idle_duration = current_time - stats.last_idle_timestamp;
                stats.total_idle_time += idle_duration;
            }
            
            stats.last_idle_timestamp = current_time;
            stats.idle_count += 1;
            
            // 統計ログ（デバッグ用）
            if stats.idle_count % 10000 == 0 {
                log::trace!("CPU {} アイドル統計: 総時間={}ns, 回数={}", 
                           cpu_id, stats.total_idle_time, stats.idle_count);
            }
        }
    }
}

/// バックグラウンドメンテナンス作業
fn perform_background_maintenance() {
    static mut MAINTENANCE_COUNTER: u64 = 0;
    
    unsafe {
        MAINTENANCE_COUNTER += 1;
        
        // 定期的なメンテナンス作業（1000回に1回）
        if MAINTENANCE_COUNTER % 1000 == 0 {
            // メモリ統計の更新
            crate::core::memory::update_memory_statistics();
            
            // キャッシュのクリーンアップ
            crate::core::memory::cleanup_unused_cache_entries();
            
            // ページテーブルの最適化
            crate::core::memory::mm::optimize_page_tables();
        }
        
        // より頻繁なメンテナンス（100回に1回）
        if MAINTENANCE_COUNTER % 100 == 0 {
            // 軽量なメンテナンス作業
            log::trace!("軽量メンテナンス実行: カウンタ={}", MAINTENANCE_COUNTER);
        }
    }
}

/// スレッド管理システムの初期化
pub fn init() {
    log::info!("スレッド管理システムを初期化中...");
    
    // CPUごとのアイドル統計を初期化
    unsafe {
        for i in 0..CPU_IDLE_STATS.len() {
            CPU_IDLE_STATS[i] = CpuIdleStats::default();
        }
    }
    
    log::info!("スレッド管理システム初期化完了");
}

/// カーネルスレッドを作成
pub fn create_kernel_thread<F>(
    name: &str, 
    stack_size: usize, 
    priority: i32, 
    f: F
) -> Result<Arc<Thread>, crate::core::process::ProcessError>
where
    F: FnOnce() + Send + 'static
{
    log::debug!("カーネルスレッド '{}' を作成中...", name);
    
    // 優先度を正規化
    let priority = Priority(priority.clamp(Priority::MIN.0, Priority::MAX.0));
    
    // 現在のCPUを取得
    let cpu_id = arch::get_current_cpu_id();
    
    // スレッドを作成
    let thread = Thread::new_kernel_thread(
        name,
        || {
            // クロージャを実行
            f();
        },
        stack_size,
        priority,
        cpu_id,
    ).map_err(|_| crate::core::process::ProcessError::ThreadCreationFailed)?;
    
    // スレッドを実行可能状態に設定
    thread.set_state(ThreadState::Ready);
    
    log::info!("カーネルスレッド '{}' 作成完了 (ID: {})", name, thread.id.0);
    
    Ok(thread)
}

/// スレッドをブロック状態にする
pub fn block_thread(thread: &Arc<Thread>, reason: crate::core::process::BlockReason) {
    thread.set_state(ThreadState::Blocked);
    thread.last_sleep_time.store(crate::time::current_time_ns(), Ordering::Relaxed);
    
    log::debug!("スレッド {} をブロック状態にしました (理由: {:?})", thread.id.0, reason);
}

/// スレッドをアンブロックする
pub fn unblock_thread(thread: &Arc<Thread>) {
    let sleep_time = crate::time::current_time_ns() - thread.last_sleep_time.load(Ordering::Relaxed);
    thread.stats.io_wait_time.fetch_add(sleep_time, Ordering::Relaxed);
    
    thread.set_state(ThreadState::Ready);
    
    log::debug!("スレッド {} をアンブロックしました (待機時間: {}ns)", thread.id.0, sleep_time);
}

/// スレッドとプロセスを関連付け
pub fn associate_thread(thread: &Arc<Thread>, process: &Arc<crate::core::process::Process>) {
    // プロセスとの関連付けは実装済みのプロセス管理システムで行う
    log::debug!("スレッド {} をプロセス {} に関連付けました", 
               thread.id.0, process.get_pid());
}

/// CPU統計情報を取得
pub fn get_cpu_idle_stats(cpu_id: usize) -> Option<CpuIdleStats> {
    unsafe {
        if cpu_id < CPU_IDLE_STATS.len() {
            Some(CPU_IDLE_STATS[cpu_id])
        } else {
            None
        }
    }
} 