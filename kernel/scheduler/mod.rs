// AetherOS スケジューラ
//
// 最先端の高効率マルチコアスケジューリングシステム
// - 省電力性と応答性を両立
// - 公平性と効率性を両立
// - リアルタイム対応
// - 負荷予測機能

mod cfs;       // 完全公平スケジューラ
mod realtime;  // リアルタイムスケジューラ
mod idle;      // アイドルスケジューラ
mod affinity;  // CPUアフィニティ
mod groups;    // スケジューリンググループ
mod policy;    // スケジューリングポリシー
mod deadline;  // デッドラインスケジューラ
mod energy;    // 省電力スケジューリング
mod load;      // 負荷予測
mod smt;       // 同時マルチスレッディング管理

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use crate::core::sync::{Mutex, RwLock, SpinLock};
use crate::core::process::{Process, Thread, ThreadState, Priority};
use crate::arch::cpu::{CpuId, get_current_cpu, enable_preemption, disable_preemption};
use crate::time::{Timespec, get_current_time, set_timer_interrupt};

/// スケジューラタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerType {
    /// 完全公平スケジューラ
    CFS,
    /// FIFOリアルタイムスケジューラ
    FIFO,
    /// ラウンドロビンリアルタイムスケジューラ
    RoundRobin,
    /// デッドラインスケジューラ
    Deadline,
    /// アイドルスケジューラ
    Idle,
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
    FIFO,
    /// ラウンドロビンリアルタイム
    RR,
    /// デッドライン駆動
    Deadline,
}

/// CPUランキュー（実行キュー）
pub struct RunQueue {
    /// CFS実行キュー
    cfs_rq: cfs::CFSRunQueue,
    /// リアルタイム実行キュー
    rt_rq: realtime::RTRunQueue,
    /// デッドライン実行キュー
    dl_rq: deadline::DLRunQueue,
    /// アイドルスレッド
    idle_thread: Option<Arc<Thread>>,
    /// 現在実行中のスレッド
    current: SpinLock<Option<Arc<Thread>>>,
    /// 実行中のスレッドの種類
    current_type: AtomicU32,
    /// このキューが所属するCPU
    cpu_id: CpuId,
    /// キュー内のスレッド数
    nr_running: AtomicUsize,
    /// プリエンプション無効カウンタ
    preempt_count: AtomicUsize,
    /// クロック周波数（ティック数/秒）
    clock_tick_rate: u64,
    /// このCPUの負荷平均
    load_avg: AtomicU64,
    /// シングルレイヤーランキュー（高速パス用）
    fast_path: SpinLock<VecDeque<Arc<Thread>>>,
    /// スケジューリング統計情報
    stats: SchedulerStats,
}

/// スケジューラ統計情報
#[derive(Debug, Default)]
pub struct SchedulerStats {
    /// コンテキストスイッチ回数
    context_switches: AtomicUsize,
    /// 割り込み回数
    interrupts: AtomicUsize,
    /// プリエンプション回数
    preemptions: AtomicUsize,
    /// ミス回数（適切なスレッドがない）
    misses: AtomicUsize,
    /// スケジューリング決定に要した平均時間（ナノ秒）
    avg_decision_time_ns: AtomicU64,
    /// 最長実行時間（マイクロ秒）
    max_exec_time_us: AtomicU64,
    /// 最長待機時間（マイクロ秒）
    max_wait_time_us: AtomicU64,
}

/// CPU統計情報
#[derive(Debug, Default)]
pub struct CpuIdleStats {
    /// 総アイドル時間（ナノ秒）
    pub total_idle_time_ns: AtomicU64,
    /// 最後のアイドル開始時刻
    pub last_idle_start: AtomicU64,
    /// アイドル回数
    pub idle_count: AtomicU64,
    /// 最大連続アイドル時間
    pub max_idle_duration_ns: AtomicU64,
    /// 平均アイドル時間
    pub avg_idle_duration_ns: AtomicU64,
}

/// バックグラウンドメンテナンス統計
#[derive(Debug, Default)]
pub struct MaintenanceStats {
    /// メモリ統計更新回数
    pub memory_stats_updates: AtomicU64,
    /// キャッシュクリーンアップ回数
    pub cache_cleanups: AtomicU64,
    /// ページテーブル最適化回数
    pub page_table_optimizations: AtomicU64,
    /// 最後のメンテナンス実行時刻
    pub last_maintenance_time: AtomicU64,
}

/// グローバルCPU統計
static CPU_IDLE_STATS: CpuIdleStats = CpuIdleStats {
    total_idle_time_ns: AtomicU64::new(0),
    last_idle_start: AtomicU64::new(0),
    idle_count: AtomicU64::new(0),
    max_idle_duration_ns: AtomicU64::new(0),
    avg_idle_duration_ns: AtomicU64::new(0),
};

/// グローバルメンテナンス統計
static MAINTENANCE_STATS: MaintenanceStats = MaintenanceStats {
    memory_stats_updates: AtomicU64::new(0),
    cache_cleanups: AtomicU64::new(0),
    page_table_optimizations: AtomicU64::new(0),
    last_maintenance_time: AtomicU64::new(0),
};

/// 各CPUのランキュー
static mut RUN_QUEUES: Vec<RunQueue> = Vec::new();

/// スケジューラの初期化状態
static SCHEDULER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// 最後にスケジュールされた時間
static LAST_SCHEDULE: AtomicU64 = AtomicU64::new(0);

/// スケジューラをセットアップ
pub fn init(num_cpus: usize) {
    if SCHEDULER_INITIALIZED.load(Ordering::SeqCst) {
        return;
    }
    
    // 各CPUのランキューを初期化
    unsafe {
        RUN_QUEUES = Vec::with_capacity(num_cpus);
        
        for cpu_id in 0..num_cpus {
            RUN_QUEUES.push(RunQueue::new(cpu_id));
        }
    }
    
    // アイドルスレッドを作成
    for cpu_id in 0..num_cpus {
        let idle_thread = create_idle_thread(cpu_id);
        unsafe {
            RUN_QUEUES[cpu_id].idle_thread = Some(idle_thread);
        }
    }
    
    // 初期化完了
    SCHEDULER_INITIALIZED.store(true, Ordering::SeqCst);
    
    // 初期時間を設定
    LAST_SCHEDULE.store(get_current_time().as_nanos(), Ordering::SeqCst);
    
    // タイマー割り込みを設定
    set_timer_interrupt(sched_tick);
    
    log::info!("スケジューラ初期化完了: {} CPUs", num_cpus);
}

/// スケジューラのシャットダウン
pub fn shutdown() {
    if !SCHEDULER_INITIALIZED.load(Ordering::SeqCst) {
        return;
    }
    
    // タイマー割り込みを無効化
    // タスクをクリーンアップ
    // ...
    
    SCHEDULER_INITIALIZED.store(false, Ordering::SeqCst);
    
    log::info!("スケジューラシャットダウン完了");
}

/// アイドルスレッドを作成
fn create_idle_thread(cpu_id: CpuId) -> Arc<Thread> {
    // アイドルスレッドのスタックサイズ（8KB）
    const IDLE_STACK_SIZE: usize = 8192;
    
    log::debug!("CPU {} 用のアイドルスレッドを作成中", cpu_id);
    
    // アイドルスレッドを作成
    let idle_thread = Thread::new_kernel_thread(
        &format!("idle/{}", cpu_id),
        idle_task,
        IDLE_STACK_SIZE,
        Priority::MIN, // 最低優先度
        cpu_id,
    ).expect("アイドルスレッド作成に失敗");
    
    // アイドルスレッドの特別な設定
    idle_thread.set_state(ThreadState::Ready);
    idle_thread.scheduling_class = SchedulingClass::Idle;
    
    // CPU親和性を特定のCPUに固定
    idle_thread.cpu_affinity = TaskAffinity {
        cpu_mask: 1 << cpu_id,
        numa_node: None,
    };
    
    log::info!("CPU {} 用のアイドルスレッド '{}' を作成しました (ID: {})", 
               cpu_id, idle_thread.name, idle_thread.get_id());
    
    idle_thread
}

/// アイドルタスク - CPUが他に実行するタスクがない時に実行される
pub fn idle_task() -> ! {
    log::info!("アイドルタスクを開始");
    
    let mut maintenance_counter = 0u64;
    const MAINTENANCE_INTERVAL: u64 = 1000; // 1000回のアイドルループごとにメンテナンス実行
    
    loop {
        // アイドル開始時刻を記録
        let idle_start = crate::time::current_time_ns();
        CPU_IDLE_STATS.last_idle_start.store(idle_start, Ordering::SeqCst);
        
        // 電力管理: CPU一時停止
        halt_until_interrupt();
        
        // アイドル終了時刻を記録
        let idle_end = crate::time::current_time_ns();
        let idle_duration = idle_end - idle_start;
        
        // 統計情報を更新
        update_idle_statistics(idle_duration);
        
        // 定期的なバックグラウンドメンテナンス
        maintenance_counter += 1;
        if maintenance_counter >= MAINTENANCE_INTERVAL {
            perform_background_maintenance();
            maintenance_counter = 0;
        }
        
        // 短時間のスピンループ（割り込み処理の機会を提供）
        for _ in 0..100 {
            core::hint::spin_loop();
        }
    }
}

/// CPU一時停止（割り込みまで待機）
fn halt_until_interrupt() {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            // HLT命令でCPUを一時停止（割り込みで復帰）
            core::arch::asm!("hlt", options(nostack, preserves_flags));
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            // WFI（Wait For Interrupt）命令
            core::arch::asm!("wfi", options(nostack, preserves_flags));
        }
        
        #[cfg(target_arch = "riscv64")]
        {
            // WFI（Wait For Interrupt）命令
            core::arch::asm!("wfi", options(nostack, preserves_flags));
        }
    }
}

/// アイドル統計情報を更新
fn update_idle_statistics(idle_duration: u64) {
    // 総アイドル時間を更新
    CPU_IDLE_STATS.total_idle_time_ns.fetch_add(idle_duration, Ordering::SeqCst);
    
    // アイドル回数を増加
    let idle_count = CPU_IDLE_STATS.idle_count.fetch_add(1, Ordering::SeqCst) + 1;
    
    // 最大アイドル時間を更新
    let current_max = CPU_IDLE_STATS.max_idle_duration_ns.load(Ordering::Relaxed);
    if idle_duration > current_max {
        CPU_IDLE_STATS.max_idle_duration_ns.store(idle_duration, Ordering::SeqCst);
    }
    
    // 平均アイドル時間を更新（移動平均）
    let current_avg = CPU_IDLE_STATS.avg_idle_duration_ns.load(Ordering::Relaxed);
    let new_avg = if current_avg == 0 {
        idle_duration
    } else {
        // 指数移動平均（α = 1/16）
        (current_avg * 15 + idle_duration) / 16
    };
    CPU_IDLE_STATS.avg_idle_duration_ns.store(new_avg, Ordering::SeqCst);
    
    // 統計ログ（デバッグ用、頻度を制限）
    if idle_count % 10000 == 0 {
        log::trace!("アイドル統計: 回数={}, 総時間={}ms, 平均時間={}μs, 最大時間={}μs",
                   idle_count,
                   CPU_IDLE_STATS.total_idle_time_ns.load(Ordering::Relaxed) / 1_000_000,
                   new_avg / 1000,
                   current_max / 1000);
    }
}

/// バックグラウンドメンテナンスを実行
fn perform_background_maintenance() {
    let current_time = crate::time::current_time_ns();
    let last_maintenance = MAINTENANCE_STATS.last_maintenance_time.load(Ordering::Relaxed);
    
    // 最低間隔チェック（1秒以上経過している場合のみ実行）
    if current_time - last_maintenance < 1_000_000_000 {
        return;
    }
    
    log::trace!("バックグラウンドメンテナンスを開始");
    
    // 1. メモリ統計更新
    if let Err(e) = crate::core::memory::mm::update_memory_statistics() {
        log::warn!("メモリ統計更新失敗: {}", e);
    } else {
        MAINTENANCE_STATS.memory_stats_updates.fetch_add(1, Ordering::SeqCst);
    }
    
    // 2. キャッシュクリーンアップ（低頻度）
    let cleanup_count = MAINTENANCE_STATS.cache_cleanups.load(Ordering::Relaxed);
    if cleanup_count % 10 == 0 { // 10回に1回実行
        if let Err(e) = crate::core::memory::mm::cleanup_caches() {
            log::warn!("キャッシュクリーンアップ失敗: {}", e);
        } else {
            MAINTENANCE_STATS.cache_cleanups.fetch_add(1, Ordering::SeqCst);
        }
    }
    
    // 3. ページテーブル最適化（さらに低頻度）
    let optimization_count = MAINTENANCE_STATS.page_table_optimizations.load(Ordering::Relaxed);
    if optimization_count % 100 == 0 { // 100回に1回実行
        if let Err(e) = crate::core::memory::mm::optimize_page_tables() {
            log::warn!("ページテーブル最適化失敗: {}", e);
        } else {
            MAINTENANCE_STATS.page_table_optimizations.fetch_add(1, Ordering::SeqCst);
        }
    }
    
    // 4. ガベージコレクション（必要に応じて）
    perform_garbage_collection();
    
    // 5. システム健全性チェック
    perform_system_health_check();
    
    // 最後のメンテナンス時刻を更新
    MAINTENANCE_STATS.last_maintenance_time.store(current_time, Ordering::SeqCst);
    
    log::trace!("バックグラウンドメンテナンス完了");
}

/// ガベージコレクションを実行
fn perform_garbage_collection() {
    log::trace!("ガベージコレクション開始");
    
    let start_time = crate::time::current_time_ns();
    let mut collected_objects = 0;
    let mut freed_memory = 0;
    
    // 1. 未使用のカーネルオブジェクトを解放
    collected_objects += collect_unused_kernel_objects();
    
    // 2. 孤立したリソースを特定・解放
    collected_objects += collect_orphaned_resources();
    
    // 3. メモリリークの検出と対処
    let leaked_memory = detect_and_fix_memory_leaks();
    freed_memory += leaked_memory;
    
    // 4. 未使用のページテーブルエントリを解放
    freed_memory += cleanup_unused_page_tables();
    
    // 5. 古いキャッシュエントリを解放
    freed_memory += cleanup_old_cache_entries();
    
    // 6. 未使用のファイルディスクリプタを解放
    collected_objects += cleanup_unused_file_descriptors();
    
    // 7. 古いネットワーク接続を解放
    collected_objects += cleanup_stale_network_connections();
    
    let end_time = crate::time::current_time_ns();
    let duration_us = (end_time - start_time) / 1000;
    
    log::debug!("ガベージコレクション完了: {}オブジェクト解放, {}KB回収, {}μs", 
               collected_objects, freed_memory / 1024, duration_us);
    
    // 統計情報を更新
    MAINTENANCE_STATS.cache_cleanups.fetch_add(1, Ordering::Relaxed);
}

/// 未使用のカーネルオブジェクトを収集
fn collect_unused_kernel_objects() -> usize {
    let mut collected = 0;
    
    // プロセス管理オブジェクトの清理
    collected += cleanup_zombie_processes();
    
    // スレッドオブジェクトの清理
    collected += cleanup_dead_threads();
    
    // ミューテックスとセマフォの清理
    collected += cleanup_unused_sync_objects();
    
    // タイマーオブジェクトの清理
    collected += cleanup_expired_timers();
    
    collected
}

/// ゾンビプロセスを清理
fn cleanup_zombie_processes() -> usize {
    let mut cleaned = 0;
    
    // プロセス管理システムからゾンビプロセスを取得
    if let Ok(process_manager) = crate::core::process::get_process_manager() {
        let zombie_pids = process_manager.get_zombie_processes();
        
        for pid in zombie_pids {
            if let Ok(_) = process_manager.cleanup_zombie_process(pid) {
                cleaned += 1;
                log::trace!("ゾンビプロセス清理: PID={}", pid);
            }
        }
    }
    
    cleaned
}

/// 死んだスレッドを清理
fn cleanup_dead_threads() -> usize {
    let mut cleaned = 0;
    
    // 各CPUのランキューから死んだスレッドを削除
    for cpu_id in 0..crate::arch::cpu::get_cpu_count() {
        let rq = unsafe { &RUN_QUEUES[cpu_id] };
        
        // CFSキューから清理
        cleaned += rq.cfs_rq.cleanup_dead_threads();
        
        // リアルタイムキューから清理
        cleaned += rq.rt_rq.cleanup_dead_threads();
        
        // デッドラインキューから清理
        cleaned += rq.dl_rq.cleanup_dead_threads();
    }
    
    cleaned
}

/// 未使用の同期オブジェクトを清理
fn cleanup_unused_sync_objects() -> usize {
    let mut cleaned = 0;
    
    // 未使用のミューテックスを清理
    if let Ok(sync_manager) = crate::core::sync::get_sync_manager() {
        cleaned += sync_manager.cleanup_unused_mutexes();
        cleaned += sync_manager.cleanup_unused_semaphores();
        cleaned += sync_manager.cleanup_unused_condition_variables();
    }
    
    cleaned
}

/// 期限切れタイマーを清理
fn cleanup_expired_timers() -> usize {
    let mut cleaned = 0;
    
    if let Ok(timer_manager) = crate::time::get_timer_manager() {
        cleaned += timer_manager.cleanup_expired_timers();
    }
    
    cleaned
}

/// 孤立したリソースを収集
fn collect_orphaned_resources() -> usize {
    let mut collected = 0;
    
    // 孤立したメモリ領域を検出
    collected += detect_orphaned_memory_regions();
    
    // 孤立したファイルハンドルを検出
    collected += detect_orphaned_file_handles();
    
    // 孤立したネットワークソケットを検出
    collected += detect_orphaned_network_sockets();
    
    collected
}

/// 孤立したメモリ領域を検出
fn detect_orphaned_memory_regions() -> usize {
    let mut detected = 0;
    
    // メモリマネージャーから孤立した領域を取得
    if let Ok(memory_manager) = crate::core::memory::get_memory_manager() {
        let orphaned_regions = memory_manager.detect_orphaned_regions();
        
        for region in orphaned_regions {
            if memory_manager.free_orphaned_region(region).is_ok() {
                detected += 1;
                log::trace!("孤立メモリ領域解放: アドレス=0x{:x}", region.start_address);
            }
        }
    }
    
    detected
}

/// 孤立したファイルハンドルを検出
fn detect_orphaned_file_handles() -> usize {
    let mut detected = 0;
    
    if let Ok(fs_manager) = crate::core::fs::get_filesystem_manager() {
        let orphaned_handles = fs_manager.detect_orphaned_handles();
        
        for handle in orphaned_handles {
            if fs_manager.close_orphaned_handle(handle).is_ok() {
                detected += 1;
                log::trace!("孤立ファイルハンドル解放: ハンドル={}", handle);
            }
        }
    }
    
    detected
}

/// 孤立したネットワークソケットを検出
fn detect_orphaned_network_sockets() -> usize {
    let mut detected = 0;
    
    if let Ok(network_manager) = crate::core::network::get_network_manager() {
        let orphaned_sockets = network_manager.detect_orphaned_sockets();
        
        for socket in orphaned_sockets {
            if network_manager.close_orphaned_socket(socket).is_ok() {
                detected += 1;
                log::trace!("孤立ネットワークソケット解放: ソケット={}", socket);
            }
        }
    }
    
    detected
}

/// メモリリークを検出して修正
fn detect_and_fix_memory_leaks() -> usize {
    let mut fixed_memory = 0;
    
    // メモリアロケータの統計を確認
    if let Ok(allocator_stats) = crate::core::memory::get_allocator_stats() {
        let potential_leaks = allocator_stats.allocation_count - allocator_stats.deallocation_count;
        
        if potential_leaks > 1000 {
            log::warn!("潜在的メモリリーク検出: {}個の未解放オブジェクト", potential_leaks);
            
            // リーク検出アルゴリズムを実行
            let leaked_blocks = run_leak_detection_algorithm();
            
            for block in leaked_blocks {
                if let Ok(size) = free_leaked_memory_block(block) {
                    fixed_memory += size;
                    log::trace!("リークメモリ解放: アドレス=0x{:x}, サイズ={}バイト", block.address, size);
                }
            }
        }
    }
    
    fixed_memory
}

/// リーク検出アルゴリズムを実行
fn run_leak_detection_algorithm() -> Vec<MemoryBlock> {
    let mut leaked_blocks = Vec::new();
    
    // マーク・アンド・スイープアルゴリズムを使用
    let reachable_blocks = mark_reachable_memory_blocks();
    let all_allocated_blocks = get_all_allocated_memory_blocks();
    
    for block in all_allocated_blocks {
        if !reachable_blocks.contains(&block) {
            // 到達不可能なブロック = リーク
            leaked_blocks.push(block);
        }
    }
    
    leaked_blocks
}

/// 到達可能なメモリブロックをマーク
fn mark_reachable_memory_blocks() -> HashSet<MemoryBlock> {
    let mut reachable = HashSet::new();
    let mut work_queue = VecDeque::new();
    
    // ルートセットから開始（スタック、レジスタ、グローバル変数）
    let root_pointers = collect_root_pointers();
    
    for pointer in root_pointers {
        if let Some(block) = find_memory_block_for_pointer(pointer) {
            work_queue.push_back(block);
        }
    }
    
    // 幅優先探索で到達可能なブロックを探索
    while let Some(block) = work_queue.pop_front() {
        if reachable.insert(block) {
            // 新しく発見されたブロック内のポインタを探索
            let pointers_in_block = scan_block_for_pointers(block);
            
            for pointer in pointers_in_block {
                if let Some(target_block) = find_memory_block_for_pointer(pointer) {
                    if !reachable.contains(&target_block) {
                        work_queue.push_back(target_block);
                    }
                }
            }
        }
    }
    
    reachable
}

/// ルートポインタを収集
fn collect_root_pointers() -> Vec<usize> {
    let mut root_pointers = Vec::new();
    
    // スタックポインタを収集
    root_pointers.extend(scan_stack_for_pointers());
    
    // グローバル変数を収集
    root_pointers.extend(scan_global_variables_for_pointers());
    
    // レジスタを収集
    root_pointers.extend(scan_registers_for_pointers());
    
    root_pointers
}

/// スタックからポインタをスキャン
fn scan_stack_for_pointers() -> Vec<usize> {
    let mut pointers = Vec::new();
    
    // 現在のスタックフレームから開始
    let stack_start = get_current_stack_start();
    let stack_end = get_current_stack_end();
    
    let mut addr = stack_start;
    while addr < stack_end {
        unsafe {
            let potential_pointer = *(addr as *const usize);
            if is_valid_heap_pointer(potential_pointer) {
                pointers.push(potential_pointer);
            }
        }
        addr += core::mem::size_of::<usize>();
    }
    
    pointers
}

/// グローバル変数からポインタをスキャン
fn scan_global_variables_for_pointers() -> Vec<usize> {
    let mut pointers = Vec::new();
    
    // データセクションとBSSセクションをスキャン
    extern "C" {
        static __data_start: u8;
        static __data_end: u8;
        static __bss_start: u8;
        static __bss_end: u8;
    }
    
    unsafe {
        // データセクション
        let data_start = &__data_start as *const u8 as usize;
        let data_end = &__data_end as *const u8 as usize;
        pointers.extend(scan_memory_range_for_pointers(data_start, data_end));
        
        // BSSセクション
        let bss_start = &__bss_start as *const u8 as usize;
        let bss_end = &__bss_end as *const u8 as usize;
        pointers.extend(scan_memory_range_for_pointers(bss_start, bss_end));
    }
    
    pointers
}

/// レジスタからポインタをスキャン
fn scan_registers_for_pointers() -> Vec<usize> {
    let mut pointers = Vec::new();
    
    // アーキテクチャ固有のレジスタスキャン
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            let mut rax: usize;
            let mut rbx: usize;
            let mut rcx: usize;
            let mut rdx: usize;
            let mut rsi: usize;
            let mut rdi: usize;
            let mut r8: usize;
            let mut r9: usize;
            let mut r10: usize;
            let mut r11: usize;
            let mut r12: usize;
            let mut r13: usize;
            let mut r14: usize;
            let mut r15: usize;
            
            core::arch::asm!(
                "mov {}, rax",
                "mov {}, rbx",
                "mov {}, rcx",
                "mov {}, rdx",
                "mov {}, rsi",
                "mov {}, rdi",
                "mov {}, r8",
                "mov {}, r9",
                "mov {}, r10",
                "mov {}, r11",
                "mov {}, r12",
                "mov {}, r13",
                "mov {}, r14",
                "mov {}, r15",
                out(reg) rax,
                out(reg) rbx,
                out(reg) rcx,
                out(reg) rdx,
                out(reg) rsi,
                out(reg) rdi,
                out(reg) r8,
                out(reg) r9,
                out(reg) r10,
                out(reg) r11,
                out(reg) r12,
                out(reg) r13,
                out(reg) r14,
                out(reg) r15,
            );
            
            let registers = [rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15];
            
            for &reg_value in &registers {
                if is_valid_heap_pointer(reg_value) {
                    pointers.push(reg_value);
                }
            }
        }
    }
    
    pointers
}

/// メモリ範囲からポインタをスキャン
fn scan_memory_range_for_pointers(start: usize, end: usize) -> Vec<usize> {
    let mut pointers = Vec::new();
    
    let mut addr = start;
    while addr + core::mem::size_of::<usize>() <= end {
        unsafe {
            let potential_pointer = *(addr as *const usize);
            if is_valid_heap_pointer(potential_pointer) {
                pointers.push(potential_pointer);
            }
        }
        addr += core::mem::size_of::<usize>();
    }
    
    pointers
}

/// ブロック内のポインタをスキャン
fn scan_block_for_pointers(block: MemoryBlock) -> Vec<usize> {
    scan_memory_range_for_pointers(block.address, block.address + block.size)
}

/// 有効なヒープポインタかチェック
fn is_valid_heap_pointer(addr: usize) -> bool {
    // ヒープ領域の範囲内かチェック
    if let Ok(heap_info) = crate::core::memory::get_heap_info() {
        addr >= heap_info.start && addr < heap_info.end && addr % core::mem::size_of::<usize>() == 0
    } else {
        false
    }
}

/// 未使用のページテーブルを清理
fn cleanup_unused_page_tables() -> usize {
    let mut freed_memory = 0;
    
    if let Ok(page_table_manager) = crate::core::memory::mm::get_page_table_manager() {
        let unused_tables = page_table_manager.find_unused_page_tables();
        
        for table in unused_tables {
            if let Ok(size) = page_table_manager.free_page_table(table) {
                freed_memory += size;
                log::trace!("未使用ページテーブル解放: アドレス=0x{:x}, サイズ={}バイト", table.address, size);
            }
        }
    }
    
    freed_memory
}

/// 古いキャッシュエントリを清理
fn cleanup_old_cache_entries() -> usize {
    let mut freed_memory = 0;
    
    // ページキャッシュの清理
    if let Ok(page_cache) = crate::core::fs::get_page_cache() {
        freed_memory += page_cache.cleanup_old_entries();
    }
    
    // SLUBキャッシュの清理
    if let Ok(slub_cache) = crate::core::memory::slub::get_global_cache() {
        freed_memory += slub_cache.cleanup_old_entries();
    }
    
    // バッファキャッシュの清理
    if let Ok(buffer_cache) = crate::core::fs::get_buffer_cache() {
        freed_memory += buffer_cache.cleanup_old_entries();
    }
    
    freed_memory
}

/// 未使用のファイルディスクリプタを清理
fn cleanup_unused_file_descriptors() -> usize {
    let mut cleaned = 0;
    
    if let Ok(fd_manager) = crate::core::fs::get_fd_manager() {
        let unused_fds = fd_manager.find_unused_descriptors();
        
        for fd in unused_fds {
            if fd_manager.close_descriptor(fd).is_ok() {
                cleaned += 1;
                log::trace!("未使用ファイルディスクリプタ解放: FD={}", fd);
            }
        }
    }
    
    cleaned
}

/// 古いネットワーク接続を清理
fn cleanup_stale_network_connections() -> usize {
    let mut cleaned = 0;
    
    if let Ok(network_manager) = crate::core::network::get_network_manager() {
        let stale_connections = network_manager.find_stale_connections();
        
        for connection in stale_connections {
            if network_manager.close_stale_connection(connection).is_ok() {
                cleaned += 1;
                log::trace!("古いネットワーク接続解放: 接続ID={}", connection.id);
            }
        }
    }
    
    cleaned
}

/// システム健全性チェックを実行
fn perform_system_health_check() {
    log::trace!("システム健全性チェック開始");
    
    let start_time = crate::time::current_time_ns();
    let mut issues_found = 0;
    
    // 1. メモリ使用率の監視
    issues_found += check_memory_health();
    
    // 2. CPU使用率の監視
    issues_found += check_cpu_health();
    
    // 3. I/O待機時間の監視
    issues_found += check_io_health();
    
    // 4. デッドロックの検出
    issues_found += check_deadlock_detection();
    
    // 5. ファイルシステムの健全性チェック
    issues_found += check_filesystem_health();
    
    // 6. ネットワークの健全性チェック
    issues_found += check_network_health();
    
    // 7. 温度監視
    issues_found += check_thermal_health();
    
    // 8. 電力管理チェック
    issues_found += check_power_management_health();
    
    let end_time = crate::time::current_time_ns();
    let duration_us = (end_time - start_time) / 1000;
    
    if issues_found > 0 {
        log::warn!("システム健全性チェック完了: {}個の問題を検出, {}μs", issues_found, duration_us);
    } else {
        log::debug!("システム健全性チェック完了: 問題なし, {}μs", duration_us);
    }
}

/// メモリ健全性をチェック
fn check_memory_health() -> usize {
    let mut issues = 0;
    
    // メモリ使用率チェック
    if let Ok(memory_stats) = crate::core::memory::get_memory_stats() {
        let total_memory = memory_stats.total_bytes;
        let used_memory = memory_stats.used_bytes;
    
    if total_memory > 0 {
        let usage_percent = (used_memory * 100) / total_memory;
        
        if usage_percent > 95 {
            log::error!("メモリ使用率が危険レベル: {}%", usage_percent);
                issues += 1;
                
                // 緊急メモリ回収を実行
                emergency_memory_reclaim();
        } else if usage_percent > 85 {
            log::warn!("メモリ使用率が高い: {}%", usage_percent);
                issues += 1;
            }
        }
        
        // メモリ断片化チェック
        let fragmentation_percent = calculate_memory_fragmentation();
        if fragmentation_percent > 80 {
            log::warn!("メモリ断片化が深刻: {}%", fragmentation_percent);
            issues += 1;
            
            // メモリコンパクションを実行
            perform_memory_compaction();
        }
        
        // スワップ使用率チェック
        if memory_stats.total_swap_bytes > 0 {
            let swap_usage_percent = (memory_stats.used_swap_bytes * 100) / memory_stats.total_swap_bytes;
            if swap_usage_percent > 90 {
                log::error!("スワップ使用率が危険レベル: {}%", swap_usage_percent);
                issues += 1;
            }
        }
    }
    
    issues
}

/// CPU健全性をチェック
fn check_cpu_health() -> usize {
    let mut issues = 0;
    
    // CPU使用率チェック
    let cpu_usage = calculate_cpu_usage();
    if cpu_usage > 95.0 {
        log::error!("CPU使用率が危険レベル: {:.1}%", cpu_usage);
        issues += 1;
        
        // 高負荷対策を実行
        handle_high_cpu_load();
    } else if cpu_usage > 85.0 {
        log::warn!("CPU使用率が高い: {:.1}%", cpu_usage);
        issues += 1;
    }
    
    // 負荷平均チェック
    let (load_1, load_5, load_15) = calculate_load_average();
    let cpu_count = crate::arch::cpu::get_cpu_count() as f32;
    
    if load_1 > cpu_count * 2.0 {
        log::error!("1分負荷平均が異常に高い: {:.2} (CPU数: {})", load_1, cpu_count);
        issues += 1;
    }
    
    if load_15 > cpu_count * 1.5 {
        log::warn!("15分負荷平均が高い: {:.2} (CPU数: {})", load_15, cpu_count);
        issues += 1;
    }
    
    // コンテキストスイッチ頻度チェック
    let context_switch_rate = calculate_context_switch_rate();
    if context_switch_rate > 100000 {
        log::warn!("コンテキストスイッチ頻度が高い: {}回/秒", context_switch_rate);
        issues += 1;
    }
    
    issues
}

/// I/O健全性をチェック
fn check_io_health() -> usize {
    let mut issues = 0;
    
    // ディスクI/O待機時間チェック
    if let Ok(io_stats) = crate::core::fs::get_io_stats() {
        let avg_wait_time_ms = io_stats.avg_wait_time_ns / 1_000_000;
        
        if avg_wait_time_ms > 1000 {
            log::error!("ディスクI/O待機時間が異常に長い: {}ms", avg_wait_time_ms);
            issues += 1;
        } else if avg_wait_time_ms > 500 {
            log::warn!("ディスクI/O待機時間が長い: {}ms", avg_wait_time_ms);
            issues += 1;
        }
        
        // I/Oキューの深さチェック
        if io_stats.queue_depth > 128 {
            log::warn!("I/Oキューが深い: {}", io_stats.queue_depth);
            issues += 1;
        }
        
        // エラー率チェック
        let error_rate = (io_stats.error_count * 100) / io_stats.total_operations.max(1);
        if error_rate > 5 {
            log::error!("I/Oエラー率が高い: {}%", error_rate);
            issues += 1;
        }
    }
    
    issues
}

/// デッドロック検出
fn check_deadlock_detection() -> usize {
    let mut issues = 0;
    
    if let Ok(deadlock_detector) = crate::core::sync::get_deadlock_detector() {
        let deadlocks = deadlock_detector.detect_deadlocks();
        
        if !deadlocks.is_empty() {
            log::error!("デッドロック検出: {}個のデッドロック", deadlocks.len());
            issues += deadlocks.len();
            
            // デッドロック解決を試行
            for deadlock in deadlocks {
                if let Err(e) = deadlock_detector.resolve_deadlock(deadlock) {
                    log::error!("デッドロック解決失敗: {:?}", e);
                } else {
                    log::info!("デッドロック解決成功: ID={}", deadlock.id);
                }
            }
        }
    }
    
    issues
}

/// ファイルシステム健全性をチェック
fn check_filesystem_health() -> usize {
    let mut issues = 0;
    
    if let Ok(fs_manager) = crate::core::fs::get_filesystem_manager() {
        // ディスク容量チェック
        let filesystems = fs_manager.get_mounted_filesystems();
        
        for fs in filesystems {
            let usage_percent = fs.get_usage_percentage();
            
            if usage_percent > 95 {
                log::error!("ファイルシステム容量が危険レベル: {}% ({})", usage_percent, fs.mount_point);
                issues += 1;
            } else if usage_percent > 85 {
                log::warn!("ファイルシステム容量が高い: {}% ({})", usage_percent, fs.mount_point);
                issues += 1;
            }
            
            // inode使用率チェック
            let inode_usage_percent = fs.get_inode_usage_percentage();
            if inode_usage_percent > 90 {
                log::warn!("inode使用率が高い: {}% ({})", inode_usage_percent, fs.mount_point);
                issues += 1;
            }
        }
        
        // ファイルシステムエラーチェック
        let fs_errors = fs_manager.get_filesystem_errors();
        if !fs_errors.is_empty() {
            log::error!("ファイルシステムエラー検出: {}個", fs_errors.len());
            issues += fs_errors.len();
        }
    }
    
    issues
}

/// ネットワーク健全性をチェック
fn check_network_health() -> usize {
    let mut issues = 0;
    
    if let Ok(network_manager) = crate::core::network::get_network_manager() {
        // ネットワークインターフェースの状態チェック
        let interfaces = network_manager.get_network_interfaces();
        
        for interface in interfaces {
            if !interface.is_up() {
                log::warn!("ネットワークインターフェースがダウン: {}", interface.name);
                issues += 1;
            }
            
            // パケットロス率チェック
            let packet_loss_rate = interface.get_packet_loss_rate();
            if packet_loss_rate > 5.0 {
                log::warn!("パケットロス率が高い: {:.1}% ({})", packet_loss_rate, interface.name);
                issues += 1;
            }
            
            // エラー率チェック
            let error_rate = interface.get_error_rate();
            if error_rate > 1.0 {
                log::warn!("ネットワークエラー率が高い: {:.1}% ({})", error_rate, interface.name);
                issues += 1;
            }
        }
        
        // 接続数チェック
        let active_connections = network_manager.get_active_connection_count();
        let max_connections = network_manager.get_max_connections();
        
        if active_connections > max_connections * 90 / 100 {
            log::warn!("アクティブ接続数が上限に近い: {}/{}", active_connections, max_connections);
            issues += 1;
        }
    }
    
    issues
}

/// 温度監視
fn check_thermal_health() -> usize {
    let mut issues = 0;
    
    // CPU温度チェック
    #[cfg(target_arch = "x86_64")]
    {
        if let Ok(thermal_manager) = crate::arch::x86_64::thermal::get_thermal_manager() {
            let cpu_temps = thermal_manager.get_cpu_temperatures();
            
            for (cpu_id, temp) in cpu_temps.iter().enumerate() {
                if *temp > 90.0 {
                    log::error!("CPU{}温度が危険レベル: {:.1}°C", cpu_id, temp);
                    issues += 1;
                    
                    // 緊急冷却措置
                    emergency_thermal_throttling(cpu_id);
                } else if *temp > 80.0 {
                    log::warn!("CPU{}温度が高い: {:.1}°C", cpu_id, temp);
                    issues += 1;
                }
            }
        }
    }
    
    issues
}

/// 電力管理健全性をチェック
fn check_power_management_health() -> usize {
    let mut issues = 0;
    
    if let Ok(power_manager) = crate::arch::power::get_power_manager() {
        // バッテリー残量チェック（ノートPCの場合）
        if let Some(battery_level) = power_manager.get_battery_level() {
            if battery_level < 10 {
                log::error!("バッテリー残量が危険レベル: {}%", battery_level);
                issues += 1;
                
                // 省電力モードに切り替え
                set_power_management_mode(PowerManagementMode::PowerSaver);
            } else if battery_level < 20 {
                log::warn!("バッテリー残量が低い: {}%", battery_level);
                issues += 1;
            }
        }
        
        // 電力消費チェック
        let power_consumption = power_manager.get_current_power_consumption();
        let max_power = power_manager.get_max_power_rating();
        
        if power_consumption > max_power * 95 / 100 {
            log::warn!("電力消費が上限に近い: {}W/{}W", power_consumption, max_power);
            issues += 1;
        }
    }
    
    issues
}

/// システム負荷平均を計算（完全実装）
pub fn calculate_load_average() -> (f32, f32, f32) {
    // 1分、5分、15分の負荷平均を計算
    static LOAD_1MIN: AtomicU64 = AtomicU64::new(0);
    static LOAD_5MIN: AtomicU64 = AtomicU64::new(0);
    static LOAD_15MIN: AtomicU64 = AtomicU64::new(0);
    static LAST_UPDATE: AtomicU64 = AtomicU64::new(0);
    
    let current_time = crate::time::current_time_ns();
    let last_update = LAST_UPDATE.load(Ordering::Relaxed);
    
    // 5秒間隔で更新（Linuxと同様）
    if current_time - last_update < 5_000_000_000 {
        // キャッシュされた値を返す
        return (
            f64::from_bits(LOAD_1MIN.load(Ordering::Relaxed)) as f32,
            f64::from_bits(LOAD_5MIN.load(Ordering::Relaxed)) as f32,
            f64::from_bits(LOAD_15MIN.load(Ordering::Relaxed)) as f32,
        );
    }
    
    // 現在の実行可能プロセス数を取得
    let runnable_count = get_runnable_process_count();
    let running_count = get_running_process_count();
    let io_wait_count = get_io_wait_runnable_count();
    
    // 総負荷 = 実行中 + 実行可能 + I/O待機（実行可能）
    let current_load = (running_count + runnable_count + io_wait_count) as f64;
    
    // 指数移動平均の係数（Linuxカーネルと同じ値）
    // exp(-5/60) ≈ 0.9200444146293232 (1分)
    // exp(-5/300) ≈ 0.9834714538216174 (5分)  
    // exp(-5/900) ≈ 0.9944598480048967 (15分)
    let exp_1 = 0.9200444146293232;
    let exp_5 = 0.9834714538216174;
    let exp_15 = 0.9944598480048967;
    
    // 現在の負荷平均を取得
    let load_1 = f64::from_bits(LOAD_1MIN.load(Ordering::Relaxed));
    let load_5 = f64::from_bits(LOAD_5MIN.load(Ordering::Relaxed));
    let load_15 = f64::from_bits(LOAD_15MIN.load(Ordering::Relaxed));
    
    // 指数移動平均で更新
    let new_load_1 = load_1 * exp_1 + current_load * (1.0 - exp_1);
    let new_load_5 = load_5 * exp_5 + current_load * (1.0 - exp_5);
    let new_load_15 = load_15 * exp_15 + current_load * (1.0 - exp_15);
    
    // 更新された値を保存
    LOAD_1MIN.store(new_load_1.to_bits(), Ordering::Relaxed);
    LOAD_5MIN.store(new_load_5.to_bits(), Ordering::Relaxed);
    LOAD_15MIN.store(new_load_15.to_bits(), Ordering::Relaxed);
    LAST_UPDATE.store(current_time, Ordering::Relaxed);
    
    // 詳細ログ出力（デバッグ時）
    log::trace!("負荷平均更新: 現在負荷={:.2}, 実行中={}, 実行可能={}, I/O待機={}",
               current_load, running_count, runnable_count, io_wait_count);
    
    (new_load_1 as f32, new_load_5 as f32, new_load_15 as f32)
}

/// 実行可能プロセス数を取得
fn get_runnable_process_count() -> usize {
    let mut count = 0;
    
    // 全CPUコアの実行キューを調査
    let cpu_count = crate::arch::cpu::get_cpu_count();
    
    for cpu_id in 0..cpu_count {
        // 各CPUの実行キューサイズを取得
        if let Ok(queue_size) = get_cpu_runqueue_size(cpu_id) {
            count += queue_size;
        }
    }
    
    // 現在実行中のプロセス数も含める
    count += get_running_process_count();
    
    // I/O待機中だが実行可能なプロセス数も含める
    count += get_io_wait_runnable_count();
    
    count
}

/// 指定CPUの実行キューサイズを取得
fn get_cpu_runqueue_size(cpu_id: usize) -> Result<usize, &'static str> {
    // CPUごとの実行キューにアクセス
    if let Some(scheduler) = get_cpu_scheduler(cpu_id) {
        Ok(scheduler.get_runqueue_size())
    } else {
        Err("CPUスケジューラーが見つかりません")
    }
}

/// 現在実行中のプロセス数を取得
fn get_running_process_count() -> usize {
    let cpu_count = crate::arch::cpu::get_cpu_count();
    let mut running_count = 0;
    
    for cpu_id in 0..cpu_count {
        if let Some(current_task) = get_current_task_on_cpu(cpu_id) {
            if current_task.state == TaskState::Running {
                running_count += 1;
            }
        }
    }
    
    running_count
}

/// I/O待機中だが実行可能なプロセス数を取得
fn get_io_wait_runnable_count() -> usize {
    // I/O完了待ちキューから実行可能なタスクをカウント
    let mut count = 0;
    
    // ブロックI/O待ちキュー
    if let Ok(block_io_queue) = get_block_io_wait_queue() {
        for task in block_io_queue.iter() {
            if task.io_operation.is_completed() && task.state == TaskState::Blocked {
                count += 1;
            }
        }
    }
    
    // ネットワークI/O待ちキュー
    if let Ok(network_io_queue) = get_network_io_wait_queue() {
        for task in network_io_queue.iter() {
            if task.io_operation.is_completed() && task.state == TaskState::Blocked {
                count += 1;
            }
        }
    }
    
    // タイマー待ちキュー（期限切れ）
    if let Ok(timer_queue) = get_timer_wait_queue() {
        let current_time = crate::time::current_time_ms();
        for task in timer_queue.iter() {
            if task.wake_time <= current_time && task.state == TaskState::Sleeping {
                count += 1;
            }
        }
    }
    
    count
}

/// CPUスケジューラーを取得
fn get_cpu_scheduler(cpu_id: usize) -> Option<&'static CpuScheduler> {
    static CPU_SCHEDULERS: [Option<CpuScheduler>; MAX_CPUS] = [None; MAX_CPUS];
    
    if cpu_id < MAX_CPUS {
        CPU_SCHEDULERS[cpu_id].as_ref()
    } else {
        None
    }
}

/// 指定CPUで現在実行中のタスクを取得
fn get_current_task_on_cpu(cpu_id: usize) -> Option<&'static Task> {
    if let Some(scheduler) = get_cpu_scheduler(cpu_id) {
        scheduler.get_current_task()
    } else {
        None
    }
}

/// ブロックI/O待ちキューを取得
fn get_block_io_wait_queue() -> Result<&'static Vec<Task>, &'static str> {
    static BLOCK_IO_WAIT_QUEUE: SpinLock<Vec<Task>> = SpinLock::new(Vec::new());
    
    // 実装では適切なロック機構を使用
    Ok(unsafe { &*(BLOCK_IO_WAIT_QUEUE.lock().as_ptr()) })
}

/// ネットワークI/O待ちキューを取得
fn get_network_io_wait_queue() -> Result<&'static Vec<Task>, &'static str> {
    static NETWORK_IO_WAIT_QUEUE: SpinLock<Vec<Task>> = SpinLock::new(Vec::new());
    
    // 実装では適切なロック機構を使用
    Ok(unsafe { &*(NETWORK_IO_WAIT_QUEUE.lock().as_ptr()) })
}

/// タイマー待ちキューを取得
fn get_timer_wait_queue() -> Result<&'static Vec<Task>, &'static str> {
    static TIMER_WAIT_QUEUE: SpinLock<Vec<Task>> = SpinLock::new(Vec::new());
    
    // 実装では適切なロック機構を使用
    Ok(unsafe { &*(TIMER_WAIT_QUEUE.lock().as_ptr()) })
}

const MAX_CPUS: usize = 256;

/// CPUスケジューラー構造体
struct CpuScheduler {
    cpu_id: usize,
    runqueue: SpinLock<Vec<Task>>,
    current_task: Option<&'static Task>,
}

impl CpuScheduler {
    /// 実行キューサイズを取得
    fn get_runqueue_size(&self) -> usize {
        self.runqueue.lock().len()
    }
    
    /// 現在のタスクを取得
    fn get_current_task(&self) -> Option<&'static Task> {
        self.current_task
    }
}

/// タスク構造体
struct Task {
    id: usize,
    state: TaskState,
    io_operation: IoOperation,
    wake_time: u64,
}

/// タスク状態
#[derive(PartialEq)]
enum TaskState {
    Running,
    Runnable,
    Blocked,
    Sleeping,
    Zombie,
}

/// I/O操作
struct IoOperation {
    operation_type: IoType,
    completed: bool,
}

impl IoOperation {
    fn is_completed(&self) -> bool {
        self.completed
    }
}

/// I/Oタイプ
enum IoType {
    BlockRead,
    BlockWrite,
    NetworkSend,
    NetworkReceive,
    Timer,
}

/// CPU統計情報を取得
pub fn get_cpu_idle_stats() -> CpuIdleStats {
    CpuIdleStats {
        total_idle_time_ns: AtomicU64::new(CPU_IDLE_STATS.total_idle_time_ns.load(Ordering::Relaxed)),
        last_idle_start: AtomicU64::new(CPU_IDLE_STATS.last_idle_start.load(Ordering::Relaxed)),
        idle_count: AtomicU64::new(CPU_IDLE_STATS.idle_count.load(Ordering::Relaxed)),
        max_idle_duration_ns: AtomicU64::new(CPU_IDLE_STATS.max_idle_duration_ns.load(Ordering::Relaxed)),
        avg_idle_duration_ns: AtomicU64::new(CPU_IDLE_STATS.avg_idle_duration_ns.load(Ordering::Relaxed)),
    }
}

/// メンテナンス統計情報を取得
pub fn get_maintenance_stats() -> MaintenanceStats {
    MaintenanceStats {
        memory_stats_updates: AtomicU64::new(MAINTENANCE_STATS.memory_stats_updates.load(Ordering::Relaxed)),
        cache_cleanups: AtomicU64::new(MAINTENANCE_STATS.cache_cleanups.load(Ordering::Relaxed)),
        page_table_optimizations: AtomicU64::new(MAINTENANCE_STATS.page_table_optimizations.load(Ordering::Relaxed)),
        last_maintenance_time: AtomicU64::new(MAINTENANCE_STATS.last_maintenance_time.load(Ordering::Relaxed)),
    }
}

/// CPU使用率を計算
pub fn calculate_cpu_usage() -> f32 {
    let uptime = crate::time::get_uptime_ns();
    let idle_time = CPU_IDLE_STATS.total_idle_time_ns.load(Ordering::Relaxed);
    
    if uptime == 0 {
        return 0.0;
    }
    
    let busy_time = uptime.saturating_sub(idle_time);
    let usage_percent = (busy_time as f32 / uptime as f32) * 100.0;
    
    usage_percent.min(100.0).max(0.0)
}

/// システム負荷平均を計算（簡易版）
pub fn calculate_load_average() -> (f32, f32, f32) {
    // 実際の実装では、1分、5分、15分の負荷平均を計算
    // ここでは簡易的な実装
    
    let cpu_usage = calculate_cpu_usage();
    let load_1min = cpu_usage / 100.0;
    let load_5min = load_1min * 0.9; // 簡略化
    let load_15min = load_1min * 0.8; // 簡略化
    
    (load_1min, load_5min, load_15min)
}

/// スケジューラー診断情報を出力
pub fn diagnose_scheduler() {
    let idle_stats = get_cpu_idle_stats();
    let maintenance_stats = get_maintenance_stats();
    let cpu_usage = calculate_cpu_usage();
    let (load_1, load_5, load_15) = calculate_load_average();
    
    log::info!("=== スケジューラー診断 ===");
    log::info!("CPU使用率: {:.1}%", cpu_usage);
    log::info!("負荷平均: {:.2}, {:.2}, {:.2}", load_1, load_5, load_15);
    
    log::info!("=== アイドル統計 ===");
    log::info!("アイドル回数: {}", idle_stats.idle_count.load(Ordering::Relaxed));
    log::info!("総アイドル時間: {}秒", idle_stats.total_idle_time_ns.load(Ordering::Relaxed) / 1_000_000_000);
    log::info!("平均アイドル時間: {}μs", idle_stats.avg_idle_duration_ns.load(Ordering::Relaxed) / 1000);
    log::info!("最大アイドル時間: {}μs", idle_stats.max_idle_duration_ns.load(Ordering::Relaxed) / 1000);
    
    log::info!("=== メンテナンス統計 ===");
    log::info!("メモリ統計更新: {}回", maintenance_stats.memory_stats_updates.load(Ordering::Relaxed));
    log::info!("キャッシュクリーンアップ: {}回", maintenance_stats.cache_cleanups.load(Ordering::Relaxed));
    log::info!("ページテーブル最適化: {}回", maintenance_stats.page_table_optimizations.load(Ordering::Relaxed));
    
    let last_maintenance = maintenance_stats.last_maintenance_time.load(Ordering::Relaxed);
    if last_maintenance > 0 {
        let current_time = crate::time::current_time_ns();
        let time_since_maintenance = (current_time - last_maintenance) / 1_000_000_000;
        log::info!("最後のメンテナンス: {}秒前", time_since_maintenance);
    }
}

/// アイドル統計をリセット
pub fn reset_idle_stats() {
    CPU_IDLE_STATS.total_idle_time_ns.store(0, Ordering::SeqCst);
    CPU_IDLE_STATS.last_idle_start.store(0, Ordering::SeqCst);
    CPU_IDLE_STATS.idle_count.store(0, Ordering::SeqCst);
    CPU_IDLE_STATS.max_idle_duration_ns.store(0, Ordering::SeqCst);
    CPU_IDLE_STATS.avg_idle_duration_ns.store(0, Ordering::SeqCst);
    
    log::info!("アイドル統計をリセットしました");
}

/// 電力管理モード設定
pub fn set_power_management_mode(mode: PowerManagementMode) {
    match mode {
        PowerManagementMode::Performance => {
            log::info!("電力管理モード: パフォーマンス");
            // CPU周波数を最大に設定
        }
        PowerManagementMode::Balanced => {
            log::info!("電力管理モード: バランス");
            // 負荷に応じてCPU周波数を調整
        }
        PowerManagementMode::PowerSaver => {
            log::info!("電力管理モード: 省電力");
            // CPU周波数を最小に設定
        }
    }
}

/// 電力管理モード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerManagementMode {
    /// パフォーマンス優先
    Performance,
    /// バランス
    Balanced,
    /// 省電力優先
    PowerSaver,
}

/// タイマー割り込みハンドラ
fn sched_tick() {
    let cpu_id = get_current_cpu();
    
    // 現在のランキューを取得
    let rq = unsafe {
        &RUN_QUEUES[cpu_id]
    };
    
    // 統計情報を更新
    rq.stats.interrupts.fetch_add(1, Ordering::Relaxed);
    
    // 各スケジューラのティック処理を呼び出す
    rq.cfs_rq.tick();
    rq.rt_rq.tick();
    rq.dl_rq.tick();
    
    // 負荷統計情報を更新
    update_load_stats(cpu_id);
    
    // 必要に応じてプリエンプション
    if need_resched(cpu_id) {
        schedule();
    }
}

/// 負荷統計情報を更新
fn update_load_stats(cpu_id: CpuId) {
    let rq = unsafe {
        &RUN_QUEUES[cpu_id]
    };
    
    // 実行中のスレッド数に基づいて負荷を計算
    let nr_running = rq.nr_running.load(Ordering::Relaxed);
    
    // 指数移動平均を使用して負荷を更新
    let current_load = rq.load_avg.load(Ordering::Relaxed);
    let new_load = (current_load * 7 + (nr_running as u64) * 8) / 8;
    
    rq.load_avg.store(new_load, Ordering::Relaxed);
}

/// 再スケジューリングが必要かチェック
pub fn need_resched(cpu_id: CpuId) -> bool {
    let rq = unsafe {
        &RUN_QUEUES[cpu_id]
    };
    
    // 現在実行中のスレッドを取得
    let current = rq.current.lock();
    
    // 現在のスレッドがない場合はスケジューリングが必要
    if current.is_none() {
        return true;
    }
    
    // 現在のスケジューラタイプに基づいてチェック
    match rq.current_type.load(Ordering::Relaxed) {
        x if x == SchedulerType::CFS as u32 => {
            // CFSの場合、より高い優先度のスレッドがあるか
            // または実行時間が長すぎる場合にプリエンプション
            rq.cfs_rq.need_resched(&current)
        },
        x if x == SchedulerType::FIFO as u32 => {
            // FIFOの場合、より高い優先度のスレッドがあれば
            // プリエンプション
            rq.rt_rq.need_resched(&current)
        },
        x if x == SchedulerType::RoundRobin as u32 => {
            // ラウンドロビンの場合、タイムスライスが終了したか
            // より高い優先度のスレッドがあればプリエンプション
            rq.rt_rq.need_resched(&current)
        },
        x if x == SchedulerType::Deadline as u32 => {
            // デッドラインの場合、より緊急のスレッドがあれば
            // プリエンプション
            rq.dl_rq.need_resched(&current)
        },
        _ => {
            // アイドルスレッドの場合、他のスレッドがあれば
            // プリエンプション
            rq.nr_running.load(Ordering::Relaxed) > 0
        }
    }
}

/// スレッドを実行可能キューに追加
pub fn enqueue_thread(thread: Arc<Thread>) {
    // プリエンプションを無効にして競合を防止
    disable_preemption();
    
    // スレッドのCPUアフィニティに基づいて適切なCPUを選択
    let cpu_id = select_cpu_for_thread(&thread);
    
    // 対応するランキューを取得
    let rq = unsafe {
        &RUN_QUEUES[cpu_id]
    };
    
    // スケジューリングポリシーに基づいて適切なキューに追加
    match thread.get_policy() {
        SchedPolicy::Normal | SchedPolicy::Batch | SchedPolicy::Idle => {
            // 通常スレッド（CFS）
            rq.cfs_rq.enqueue(Arc::clone(&thread));
        },
        SchedPolicy::FIFO | SchedPolicy::RR => {
            // リアルタイムスレッド
            rq.rt_rq.enqueue(Arc::clone(&thread));
        },
        SchedPolicy::Deadline => {
            // デッドラインスレッド
            rq.dl_rq.enqueue(Arc::clone(&thread));
        },
    }
    
    // 実行中スレッド数を増加
    rq.nr_running.fetch_add(1, Ordering::SeqCst);
    
    // 高速パスキューにも追加（オプション）
    if enable_fast_path() {
        rq.fast_path.lock().push_back(Arc::clone(&thread));
    }
    
    // プリエンプションを再度有効化
    enable_preemption();
    
    // 必要に応じてプリエンプション
    if need_resched(get_current_cpu()) {
        schedule();
    }
}

/// スレッドを実行可能キューから削除
pub fn dequeue_thread(thread: &Arc<Thread>) {
    // プリエンプションを無効にして競合を防止
    disable_preemption();
    
    // スレッドが存在するCPUを特定
    let cpu_id = thread.get_cpu();
    
    // 対応するランキューを取得
    let rq = unsafe {
        &RUN_QUEUES[cpu_id]
    };
    
    // スケジューリングポリシーに基づいて適切なキューから削除
    match thread.get_policy() {
        SchedPolicy::Normal | SchedPolicy::Batch | SchedPolicy::Idle => {
            // 通常スレッド（CFS）
            rq.cfs_rq.dequeue(thread);
        },
        SchedPolicy::FIFO | SchedPolicy::RR => {
            // リアルタイムスレッド
            rq.rt_rq.dequeue(thread);
        },
        SchedPolicy::Deadline => {
            // デッドラインスレッド
            rq.dl_rq.dequeue(thread);
        },
    }
    
    // 実行中スレッド数を減少
    let count = rq.nr_running.load(Ordering::Relaxed);
    if count > 0 {
        rq.nr_running.fetch_sub(1, Ordering::SeqCst);
    }
    
    // 高速パスキューからも削除
    let mut fast_path = rq.fast_path.lock();
    fast_path.retain(|t| !Arc::ptr_eq(t, thread));
    
    // プリエンプションを再度有効化
    enable_preemption();
}

/// CPUを選択（ロードバランシング）
fn select_cpu_for_thread(thread: &Arc<Thread>) -> CpuId {
    // スレッドがCPUアフィニティを持つ場合はそれを尊重
    if let Some(affinity) = thread.get_affinity() {
        // アフィニティマスクから適切なCPUを選択
        return affinity::select_cpu_from_affinity(affinity);
    }
    
    // ロードバランシング：最も負荷の低いCPUを選択
    let mut min_load = u64::MAX;
    let mut selected_cpu = 0;
    
    unsafe {
        for (i, rq) in RUN_QUEUES.iter().enumerate() {
            let load = rq.load_avg.load(Ordering::Relaxed);
            if load < min_load {
                min_load = load;
                selected_cpu = i;
            }
        }
    }
    
    selected_cpu
}

/// メインスケジューリング関数
pub fn schedule() {
    // 既にプリエンプションが無効化されている場合は戻る
    if is_preemption_disabled() {
        return;
    }
    
    // プリエンプションを無効化
    disable_preemption();
    
    // 現在のCPU ID
    let cpu_id = get_current_cpu();
    
    // 対応するランキューを取得
    let rq = unsafe {
        &RUN_QUEUES[cpu_id]
    };
    
    let start_time = get_current_time().as_nanos();
    
    // 各スケジューラから次のスレッドを選択
    let next_thread = pick_next_thread(cpu_id);
    
    match next_thread {
        Some(next) => {
            // 現在のスレッドを取得
            let mut current = rq.current.lock();
            
            if let Some(current_thread) = current.take() {
                // 自分自身を選択した場合は何もしない
                if Arc::ptr_eq(&current_thread, &next) {
                    *current = Some(current_thread);
                    enable_preemption();
                    return;
                }
                
                // 現在のスレッドを実行キューに戻す（必要な場合）
                if current_thread.get_state() == ThreadState::Running {
                    current_thread.set_state(ThreadState::Runnable);
                    enqueue_thread(Arc::clone(&current_thread));
                }
                
                // コンテキストスイッチ
                rq.stats.context_switches.fetch_add(1, Ordering::Relaxed);
                
                // 次のスレッドを実行状態に設定
                next.set_state(ThreadState::Running);
                
                // 現在のスレッドを更新
                *current = Some(Arc::clone(&next));
                
                // スケジューラタイプを更新
                match next.get_policy() {
                    SchedPolicy::Normal | SchedPolicy::Batch | SchedPolicy::Idle => {
                        rq.current_type.store(SchedulerType::CFS as u32, Ordering::Relaxed);
                    },
                    SchedPolicy::FIFO => {
                        rq.current_type.store(SchedulerType::FIFO as u32, Ordering::Relaxed);
                    },
                    SchedPolicy::RR => {
                        rq.current_type.store(SchedulerType::RoundRobin as u32, Ordering::Relaxed);
                    },
                    SchedPolicy::Deadline => {
                        rq.current_type.store(SchedulerType::Deadline as u32, Ordering::Relaxed);
                    },
                }
                
                // アーキテクチャ固有のコンテキストスイッチ
                let current_thread_id = current_thread.get_id();
                let next_thread_id = next.get_id();
                
                drop(current); // ロックを解放
                
                // コンテキストスイッチを実行
                unsafe {
                    crate::arch::task::context_switch(current_thread_id, next_thread_id);
                }
            } else {
                // 現在のスレッドがない場合（初回起動時など）
                next.set_state(ThreadState::Running);
                *current = Some(Arc::clone(&next));
                
                // スケジューラタイプを更新
                match next.get_policy() {
                    SchedPolicy::Normal | SchedPolicy::Batch | SchedPolicy::Idle => {
                        rq.current_type.store(SchedulerType::CFS as u32, Ordering::Relaxed);
                    },
                    SchedPolicy::FIFO => {
                        rq.current_type.store(SchedulerType::FIFO as u32, Ordering::Relaxed);
                    },
                    SchedPolicy::RR => {
                        rq.current_type.store(SchedulerType::RoundRobin as u32, Ordering::Relaxed);
                    },
                    SchedPolicy::Deadline => {
                        rq.current_type.store(SchedulerType::Deadline as u32, Ordering::Relaxed);
                    },
                }
                
                // 最初のスレッドを実行
                drop(current); // ロックを解放
                
                // 初回起動
                unsafe {
                    crate::arch::task::start_first_thread(next.get_id());
                }
            }
            
        } None => {
            // 実行可能なスレッドがない場合はアイドルスレッドを実行
            rq.stats.misses.fetch_add(1, Ordering::Relaxed);
            
            let mut current = rq.current.lock();
            
            // アイドルスレッドを取得
            if let Some(idle) = &rq.idle_thread {
                // 現在のスレッドがアイドルでない場合のみ切り替え
                if let Some(current_thread) = current.take() {
                    if !Arc::ptr_eq(&current_thread, idle) {
                        // 現在のスレッドを実行キューに戻す（必要な場合）
                        if current_thread.get_state() == ThreadState::Running {
                            current_thread.set_state(ThreadState::Runnable);
                            enqueue_thread(Arc::clone(&current_thread));
                        }
                        
                        // アイドルスレッドに切り替え
                        rq.stats.context_switches.fetch_add(1, Ordering::Relaxed);
                        *current = Some(Arc::clone(idle));
                        rq.current_type.store(SchedulerType::Idle as u32, Ordering::Relaxed);
                        
                        // コンテキストスイッチ
                        let current_thread_id = current_thread.get_id();
                        let idle_thread_id = idle.get_id();
                        
                        drop(current); // ロックを解放
                        
                        // コンテキストスイッチを実行
                        unsafe {
                            crate::arch::task::context_switch(current_thread_id, idle_thread_id);
                        }
                    }
                } else {
                    // 初回起動時
                    *current = Some(Arc::clone(idle));
                    rq.current_type.store(SchedulerType::Idle as u32, Ordering::Relaxed);
                    
                    drop(current); // ロックを解放
                    
                    // アイドルスレッドを起動
                    unsafe {
                        crate::arch::task::start_first_thread(idle.get_id());
                    }
                }
            }
        }
    }
    
    // スケジューリング決定にかかった時間を記録
    let end_time = get_current_time().as_nanos();
    let decision_time = end_time - start_time;
    
    // 移動平均で決定時間を更新
    let current_avg = rq.stats.avg_decision_time_ns.load(Ordering::Relaxed);
    let new_avg = (current_avg * 15 + decision_time) / 16;
    rq.stats.avg_decision_time_ns.store(new_avg, Ordering::Relaxed);
    
    // 最後のスケジュール時間を更新
    LAST_SCHEDULE.store(end_time, Ordering::SeqCst);
    
    // プリエンプションを再度有効化
    enable_preemption();
}

/// 次に実行するスレッドを選択
fn pick_next_thread(cpu_id: CpuId) -> Option<Arc<Thread>> {
    let rq = unsafe {
        &RUN_QUEUES[cpu_id]
    };
    
    // 完全なマルチレベルスケジューリング実装
    
    // 1. デッドラインスケジューラ（最高優先度）
    if let Some(dl_thread) = rq.dl_rq.pick_next() {
        let current_time = crate::arch::time::current_time_ns();
        if dl_thread.get_deadline() > current_time {
            log::trace!("デッドライン選択: スレッド={}", dl_thread.get_id());
            rq.stats.deadline_hits.fetch_add(1, Ordering::Relaxed);
            return Some(dl_thread);
        } else {
            // デッドライン逸脱処理
            let miss_time = current_time - dl_thread.get_deadline();
            log::warn!("デッドライン逸脱: スレッド={}, 逸脱={}μs", 
                      dl_thread.get_id(), miss_time / 1000);
            
            handle_deadline_miss(&dl_thread, current_time);
            rq.dl_rq.dequeue(&dl_thread);
            
            // ペナルティとしてCFSキューに移動
            let mut cfs_thread = Arc::clone(&dl_thread);
            cfs_thread.set_penalty_vruntime(miss_time / 1000);
            rq.cfs_rq.enqueue(cfs_thread);
        }
    }
    
    // 2. リアルタイムスケジューラ（高優先度）
    if let Some(rt_thread) = rq.rt_rq.pick_next() {
        let rt_usage = rq.rt_rq.get_bandwidth_usage();
        
        // RTスロットリング制御（95%制限）
        if rt_usage < 95.0 {
            log::trace!("リアルタイム選択: スレッド={}, RT使用率={}%", 
                       rt_thread.get_id(), rt_usage);
            
            rq.rt_rq.update_bandwidth_usage(&rt_thread);
            rq.stats.rt_hits.fetch_add(1, Ordering::Relaxed);
            return Some(rt_thread);
        } else {
            log::debug!("RTスロットリング発動: 使用率={}%", rt_usage);
            rq.rt_rq.enable_throttling(Duration::from_millis(5));
        }
    }
    
    // 3. 完全公平スケジューラ（通常優先度）
    if let Some(cfs_thread) = rq.cfs_rq.pick_next() {
        let vruntime = cfs_thread.get_vruntime();
        let min_vruntime = rq.cfs_rq.get_min_vruntime();
        let spread = vruntime - min_vruntime;
        
        // 仮想時間制限チェック（18ms制限）
        if spread <= Duration::from_millis(18).as_nanos() as u64 {
            log::trace!("CFS選択: スレッド={}, vruntime={}, spread={}μs", 
                       cfs_thread.get_id(), vruntime, spread / 1000);
            
            // 動的タイムスライス計算
            let nr_running = rq.nr_running.load(Ordering::Relaxed);
            let timeslice = calculate_cfs_timeslice(&cfs_thread, nr_running);
            cfs_thread.set_timeslice(timeslice);
            
            rq.stats.cfs_hits.fetch_add(1, Ordering::Relaxed);
            return Some(cfs_thread);
        } else {
            log::debug!("CFS spread制限: スレッド={}, spread={}ms", 
                       cfs_thread.get_id(), spread / 1_000_000);
        }
    }
    
    // 4. 高速パス（低レイテンシ）
    if enable_fast_path() {
        let mut fast_path = rq.fast_path.lock();
        if let Some(fast_thread) = fast_path.pop_front() {
            log::trace!("高速パス選択: スレッド={}", fast_thread.get_id());
            rq.stats.fast_path_hits.fetch_add(1, Ordering::Relaxed);
            
            // 高速パス用短いタイムスライス
            fast_thread.set_timeslice(Duration::from_micros(1000));
            return Some(fast_thread);
        }
    }
    
    // 5. アイドルスレッド（最低優先度）
    if let Some(idle_thread) = &rq.idle_thread {
        log::trace!("アイドル選択: CPU={}", cpu_id);
        
        // 省電力準備
        prepare_cpu_idle_state(cpu_id);
        rq.stats.idle_hits.fetch_add(1, Ordering::Relaxed);
        
        return Some(Arc::clone(idle_thread));
    }
    
    // 6. ワークスチール（緊急時）
    if let Some(stolen_thread) = attempt_work_stealing(cpu_id) {
        log::info!("ワークスチール成功: CPU={} <- 他CPU", cpu_id);
        rq.stats.work_steal_hits.fetch_add(1, Ordering::Relaxed);
        return Some(stolen_thread);
    }
    
    // 7. 完全に実行可能スレッドが無い
    log::warn!("実行可能スレッド無し: CPU={}", cpu_id);
    rq.stats.no_thread_available.fetch_add(1, Ordering::Relaxed);
    None
}

/// デッドラインミス処理
fn handle_deadline_miss(thread: &Arc<Thread>, current_time: u64) {
    // 1. デッドラインミス統計更新
    thread.increment_deadline_misses();
    
    // 2. システム全体のデッドラインミス率更新
    GLOBAL_SCHEDULER_STATS.deadline_misses.fetch_add(1, Ordering::Relaxed);
    
    // 3. ミス原因の分析
    let miss_reason = analyze_deadline_miss_cause(thread, current_time);
    
    // 4. 適応的対応
    match miss_reason {
        DeadlineMissReason::SystemOverload => {
            // システム過負荷：低優先度タスクを一時停止
            suspend_low_priority_tasks();
        },
        DeadlineMissReason::ResourceContention => {
            // リソース競合：リソース予約を調整
            adjust_resource_reservations(thread);
        },
        DeadlineMissReason::EstimationError => {
            // 実行時間予測エラー：予測モデルを更新
            update_execution_time_model(thread, current_time);
        },
        DeadlineMissReason::InterruptOverhead => {
            // 割り込みオーバーヘッド：割り込み処理を最適化
            optimize_interrupt_handling();
        },
    }
    
    // 5. ログ出力
    log::warn!("デッドラインミス詳細: スレッド={}, 原因={:?}, 逸脱時間={}μs",
              thread.get_id(), miss_reason, (current_time - thread.get_deadline()) / 1000);
}

/// CFSタイムスライス計算
fn calculate_cfs_timeslice(thread: &Arc<Thread>, nr_running: usize) -> Duration {
    // 基本タイムスライス
    let base_timeslice = Duration::from_millis(CFS_BASE_TIMESLICE_MS);
    
    // 実行可能スレッド数による調整
    let load_factor = if nr_running > 1 {
        base_timeslice.as_nanos() as f64 / nr_running as f64
    } else {
        base_timeslice.as_nanos() as f64
    };
    
    // nice値による重み調整
    let nice_value = thread.get_nice();
    let weight = nice_to_weight(nice_value);
    let weighted_timeslice = (load_factor * weight) as u64;
    
    // 最小・最大制限
    let min_timeslice = Duration::from_micros(CFS_MIN_GRANULARITY_US).as_nanos() as u64;
    let max_timeslice = Duration::from_millis(CFS_MAX_TIMESLICE_MS).as_nanos() as u64;
    
    let final_timeslice = weighted_timeslice.clamp(min_timeslice, max_timeslice);
    
    Duration::from_nanos(final_timeslice)
}

/// nice値から重みを計算
fn nice_to_weight(nice: i8) -> f64 {
    // Linux CFSと同様の重み計算
    const NICE_0_LOAD: f64 = 1024.0;
    const NICE_TO_PRIO_FACTOR: f64 = 1.25;
    
    if nice == 0 {
        1.0
    } else if nice > 0 {
        // 正のnice値（低優先度）
        1.0 / NICE_TO_PRIO_FACTOR.powi(nice as i32)
    } else {
        // 負のnice値（高優先度）
        NICE_TO_PRIO_FACTOR.powi((-nice) as i32)
    }
}

/// CPU省電力状態準備
fn prepare_cpu_idle_state(cpu_id: CpuId) {
    // 1. CPU頻度調整
    let optimal_frequency = calculate_optimal_cpu_frequency(cpu_id);
    crate::arch::cpu::set_cpu_frequency(cpu_id, optimal_frequency);
    
    // 2. 不要な機能停止
    crate::arch::cpu::disable_unnecessary_features(cpu_id);
    
    // 3. キャッシュフラッシュ（必要に応じて）
    if should_flush_cache_on_idle(cpu_id) {
        crate::arch::cpu::flush_cache(cpu_id);
    }
    
    // 4. 省電力状態選択
    let idle_state = select_optimal_idle_state(cpu_id);
    crate::arch::cpu::prepare_idle_state(cpu_id, idle_state);
}

/// 最適CPU周波数計算
fn calculate_optimal_cpu_frequency(cpu_id: CpuId) -> u32 {
    let rq = unsafe { &RUN_QUEUES[cpu_id] };
    
    // 負荷に基づく周波数調整
    let load_percent = rq.load_avg.load(Ordering::Relaxed);
    let max_frequency = crate::arch::cpu::get_max_frequency(cpu_id);
    
    // 負荷が低い場合は周波数を下げる
    if load_percent < 30 {
        max_frequency / 4  // 25%
    } else if load_percent < 60 {
        max_frequency / 2  // 50%
    } else if load_percent < 90 {
        (max_frequency * 3) / 4  // 75%
    } else {
        max_frequency  // 100%
    }
}

/// ワークスチール試行
fn attempt_work_stealing(target_cpu: CpuId) -> Option<Arc<Thread>> {
    let num_cpus = get_cpu_count();
    
    // 他のCPUから負荷の高いものを見つける
    for source_cpu in 0..num_cpus {
        if source_cpu == target_cpu {
            continue;
        }
        
        let source_rq = unsafe { &RUN_QUEUES[source_cpu] };
        let target_rq = unsafe { &RUN_QUEUES[target_cpu] };
        
        // 負荷差の確認
        let source_load = source_rq.nr_running.load(Ordering::Relaxed);
        let target_load = target_rq.nr_running.load(Ordering::Relaxed);
        
        if source_load > target_load + WORK_STEAL_THRESHOLD {
            // CFSキューからスチール試行
            if let Some(stolen_thread) = source_rq.cfs_rq.steal_thread() {
                // CPU親和性の確認
                if stolen_thread.can_run_on_cpu(target_cpu) {
                    // スレッドのCPU移行
                    stolen_thread.set_cpu(target_cpu);
                    
                    // 統計更新
                    source_rq.stats.work_steals_out.fetch_add(1, Ordering::Relaxed);
                    target_rq.stats.work_steals_in.fetch_add(1, Ordering::Relaxed);
                    
                    log::debug!("ワークスチール: CPU{} <- CPU{}, スレッド={}", 
                               target_cpu, source_cpu, stolen_thread.get_id());
                    
                    return Some(stolen_thread);
                } else {
                    // 親和性に合わない場合は元に戻す
                    source_rq.cfs_rq.enqueue(stolen_thread);
                }
            }
        }
    }
    
    None
}

/// デッドラインミス原因分析
fn analyze_deadline_miss_cause(thread: &Arc<Thread>, current_time: u64) -> DeadlineMissReason {
    let start_time = crate::arch::time::current_time_ns();
    
    // 1. システム負荷分析
    let system_load = get_system_load_average() as f64;
    if system_load > 4.0 { // CPUコア数の4倍を過負荷とする
        log::debug!("システム過負荷検出: 負荷={:.2}", system_load);
        return DeadlineMissReason::SystemOverload;
    }
    
    // 2. リソース競合分析
    let resource_contention = measure_resource_contention(thread) as f64;
    if resource_contention > 0.8 { // 80%以上の競合
        log::debug!("リソース競合検出: 競合率={:.2}%", resource_contention * 100.0);
        return DeadlineMissReason::ResourceContention;
    }
    
    // 3. 実行時間予測精度分析
    let predicted_time = thread.get_predicted_execution_time();
    let actual_time = current_time - thread.get_start_time();
    
    if predicted_time > 0 {
        let prediction_error = ((actual_time as f64 - predicted_time as f64) / predicted_time as f64).abs();
        if prediction_error > 0.5 { // 50%以上の予測誤差
            log::debug!("実行時間予測誤差: 予測={}μs, 実際={}μs, 誤差={:.1}%",
                       predicted_time / 1000, actual_time / 1000, prediction_error * 100.0);
            return DeadlineMissReason::EstimationError;
        }
    }
    
    // 4. 割り込みオーバーヘッド分析
    let interrupt_overhead = measure_interrupt_overhead() as f64;
    if interrupt_overhead > 1000.0 { // 1000割り込み/秒以上
        log::debug!("割り込み過多検出: {}回/秒", interrupt_overhead);
        return DeadlineMissReason::InterruptOverhead;
    }
    
    // 5. メモリ圧迫チェック
    let memory_pressure = crate::core::memory::get_memory_pressure() as f64;
    if memory_pressure > 0.9 { // 90%以上のメモリ使用
        log::debug!("メモリ圧迫検出: 使用率={:.1}%", memory_pressure * 100.0);
        return DeadlineMissReason::MemoryPressure;
    }
    
    // 6. I/O待機時間チェック
    let io_wait_time = thread.get_io_wait_time();
    let total_time = current_time - thread.get_creation_time();
    let io_ratio = if total_time > 0 { io_wait_time as f64 / total_time as f64 } else { 0.0 };
    
    if io_ratio > 0.3 { // 30%以上がI/O待機
        log::debug!("I/O待機過多検出: I/O率={:.1}%", io_ratio * 100.0);
        return DeadlineMissReason::IoBottleneck;
    }
    
    let analysis_time = crate::arch::time::current_time_ns() - start_time;
    log::trace!("デッドラインミス原因分析完了: 時間={}μs", analysis_time / 1000);
    
    DeadlineMissReason::Unknown
}

/// システム負荷平均取得
fn get_system_load_average() -> f64 {
    let num_cpus = crate::arch::cpu::get_cpu_count();
    let mut total_load = 0.0;
    let mut active_cpus = 0;
    
    for cpu_id in 0..num_cpus {
        if crate::arch::cpu::is_cpu_online(cpu_id) {
            let rq = unsafe { &RUN_QUEUES[cpu_id] };
            
            // CPU負荷計算（実行可能タスク数 + 1分間の負荷平均）
            let current_load = rq.nr_running.load(Ordering::Relaxed) as f64;
            let historical_load = rq.load_avg.load(Ordering::Relaxed) as f64 / 100.0;
            
            // 指数平滑化平均（α=0.2）
            let combined_load = 0.8 * historical_load + 0.2 * current_load;
            total_load += combined_load;
            active_cpus += 1;
        }
    }
    
    if active_cpus > 0 {
        total_load / active_cpus as f64
    } else {
        0.0
    }
}

/// リソース競合測定
fn measure_resource_contention(thread: &Arc<Thread>) -> f64 {
    let mut contention_factors = Vec::new();
    
    // 1. メモリ競合測定
    let memory_bandwidth_used = crate::arch::memory::get_memory_bandwidth_usage();
    let memory_bandwidth_max = crate::arch::memory::get_memory_bandwidth_max();
    let memory_contention = if memory_bandwidth_max > 0 {
        memory_bandwidth_used as f64 / memory_bandwidth_max as f64
    } else {
        0.0
    };
    contention_factors.push(memory_contention);
    
    // 2. キャッシュミス率測定
    let l3_miss_rate = crate::arch::cpu::get_l3_cache_miss_rate(thread.get_cpu());
    contention_factors.push(l3_miss_rate as f64);
    
    // 3. ロック競合測定
    let lock_wait_time = thread.get_lock_wait_time();
    let total_execution_time = thread.get_total_execution_time();
    let lock_contention = if total_execution_time > 0 {
        lock_wait_time as f64 / total_execution_time as f64
    } else {
        0.0
    };
    contention_factors.push(lock_contention.min(1.0));
    
    // 4. I/Oキュー深度
    let io_queue_depth = crate::drivers::block::get_average_queue_depth();
    let io_contention = (io_queue_depth as f64 / 32.0).min(1.0); // 32を最大深度とする
    contention_factors.push(io_contention);
    
    // 5. ネットワーク競合
    let network_utilization = crate::core::network::get_network_utilization();
    contention_factors.push(network_utilization as f64);
    
    // 加重平均（メモリとキャッシュを重視）
    let weights = [0.3, 0.3, 0.2, 0.1, 0.1];
    let mut weighted_sum = 0.0;
    
    for (i, &factor) in contention_factors.iter().enumerate() {
        weighted_sum += factor * weights[i];
    }
    
    weighted_sum.min(1.0)
}

/// 割り込みオーバーヘッド測定
fn measure_interrupt_overhead() -> f64 {
    let current_time = crate::arch::time::current_time_ns();
    static LAST_MEASUREMENT: AtomicU64 = AtomicU64::new(0);
    static LAST_INTERRUPT_COUNT: AtomicUsize = AtomicUsize::new(0);
    
    let last_time = LAST_MEASUREMENT.swap(current_time, Ordering::Relaxed);
    let current_interrupt_count = GLOBAL_SCHEDULER_STATS.interrupts.load(Ordering::Relaxed);
    let last_interrupt_count = LAST_INTERRUPT_COUNT.swap(current_interrupt_count, Ordering::Relaxed);
    
    if last_time > 0 && current_time > last_time {
        let time_delta = current_time - last_time;
        let interrupt_delta = current_interrupt_count.saturating_sub(last_interrupt_count);
        
        // 割り込み/秒を計算
        let interrupts_per_second = (interrupt_delta as f64 * 1_000_000_000.0) / time_delta as f64;
        
        // CPU使用率ベースの補正
        let cpu_count = crate::arch::cpu::get_cpu_count();
        let mut total_cpu_usage = 0.0;
        
        for cpu_id in 0..cpu_count {
            total_cpu_usage += crate::arch::cpu::get_cpu_usage(cpu_id) as f64;
        }
        
        let avg_cpu_usage = total_cpu_usage / cpu_count as f64;
        
        // 高CPU使用率時は割り込みオーバーヘッドを重み付け
        interrupts_per_second * (1.0 + avg_cpu_usage / 100.0)
    } else {
        // 初回測定またはタイムスタンプ不正
        0.0
    }
}

/// 低優先度タスク一時停止
fn suspend_low_priority_tasks() {
    let num_cpus = crate::arch::cpu::get_cpu_count();
    let mut suspended_count = 0;
    
    for cpu_id in 0..num_cpus {
        let rq = unsafe { &RUN_QUEUES[cpu_id] };
        
        // nice値が10以上（低優先度）のタスクを一時停止
        let cfs_tasks = rq.cfs_rq.get_tasks_by_nice_range(10, 19);
        
        for task in cfs_tasks {
            if task.get_state() == TaskState::Running || task.get_state() == TaskState::Ready {
                task.set_state(TaskState::Suspended);
                task.set_suspension_reason(SuspensionReason::SystemOverload);
                
                // CFSキューから除去
                rq.cfs_rq.dequeue(&task);
                
                log::debug!("低優先度タスク一時停止: スレッド={}, nice={}, CPU={}", 
                           task.get_id(), task.get_nice(), cpu_id);
                suspended_count += 1;
                
                // 最大10タスクまで停止
                if suspended_count >= 10 {
                    break;
                }
            }
        }
        
        if suspended_count >= 10 {
            break;
        }
    }
    
    if suspended_count > 0 {
        log::info!("システム過負荷対応: {}個の低優先度タスクを一時停止", suspended_count);
        
        // 停止タスクの復帰タイマー設定（5秒後）
        crate::core::timer::set_timer(Duration::from_secs(5), || {
            resume_suspended_tasks();
        });
    }
}

/// 一時停止タスクの復帰
fn resume_suspended_tasks() {
    let num_cpus = crate::arch::cpu::get_cpu_count();
    let mut resumed_count = 0;
    
    // システム負荷を再確認
    let current_load = get_system_load_average();
    if current_load > 3.0 {
        log::debug!("システム負荷依然高負荷: {:.2}、復帰延期", current_load);
        
        // さらに5秒後に再試行
        crate::core::timer::set_timer(Duration::from_secs(5), || {
            resume_suspended_tasks();
        });
        return;
    }
    
    for cpu_id in 0..num_cpus {
        let suspended_tasks = crate::core::process::get_suspended_tasks_for_cpu(cpu_id);
        
        for task in suspended_tasks {
            if task.get_suspension_reason() == SuspensionReason::SystemOverload {
                task.set_state(TaskState::Ready);
                
                // CFSキューに復帰
                let rq = unsafe { &RUN_QUEUES[cpu_id] };
                rq.cfs_rq.enqueue(task.clone());
                
                log::debug!("低優先度タスク復帰: スレッド={}, CPU={}", 
                           task.get_id(), cpu_id);
                resumed_count += 1;
            }
        }
    }
    
    if resumed_count > 0 {
        log::info!("システム負荷軽減: {}個のタスクを復帰", resumed_count);
    }
}

/// リソース予約調整
fn adjust_resource_reservations(thread: &Arc<Thread>) {
    // 1. CPU予約調整
    let current_cpu_reservation = thread.get_cpu_reservation();
    let cpu_usage_history = thread.get_cpu_usage_history();
    
    // 過去10回の実行における平均CPU使用率
    let avg_cpu_usage = if !cpu_usage_history.is_empty() {
        cpu_usage_history.iter().sum::<f64>() / cpu_usage_history.len() as f64
    } else {
        current_cpu_reservation as f64
    };
    
    // 実使用率+20%のマージンで予約調整
    let adjusted_cpu_reservation = ((avg_cpu_usage * 1.2) as u32).min(100);
    thread.set_cpu_reservation(adjusted_cpu_reservation);
    
    // 2. メモリ予約調整
    let current_memory_reservation = thread.get_memory_reservation();
    let memory_usage_peak = thread.get_memory_usage_peak();
    
    // ピーク使用量+25%のマージンで調整
    let adjusted_memory_reservation = ((memory_usage_peak as f64 * 1.25) as usize)
        .max(current_memory_reservation)
        .min(crate::core::memory::get_available_memory());
    thread.set_memory_reservation(adjusted_memory_reservation);
    
    // 3. I/O帯域幅予約調整
    let io_bandwidth_usage = thread.get_io_bandwidth_usage();
    let adjusted_io_reservation = (io_bandwidth_usage as f64 * 1.15) as u64; // 15%マージン
    thread.set_io_bandwidth_reservation(adjusted_io_reservation);
    
    // 4. ネットワーク帯域幅予約調整
    let network_bandwidth_usage = thread.get_network_bandwidth_usage();
    let adjusted_network_reservation = (network_bandwidth_usage as f64 * 1.1) as u64; // 10%マージン
    thread.set_network_bandwidth_reservation(adjusted_network_reservation);
    
    log::info!("リソース予約調整完了: スレッド={}, CPU={}%->{}, メモリ={}MB->{}MB, I/O={}MB/s->{}MB/s, NET={}Mbps->{}Mbps",
              thread.get_id(),
              current_cpu_reservation, adjusted_cpu_reservation,
              current_memory_reservation / 1024 / 1024, adjusted_memory_reservation / 1024 / 1024,
              thread.get_io_bandwidth_reservation() / 1024 / 1024, adjusted_io_reservation / 1024 / 1024,
              thread.get_network_bandwidth_reservation(), adjusted_network_reservation);
}

/// 実行時間予測モデル更新
fn update_execution_time_model(thread: &Arc<Thread>, current_time: u64) {
    let actual_execution_time = current_time - thread.get_start_time();
    let predicted_time = thread.get_predicted_execution_time();
    
    // 予測誤差の計算
    let prediction_error = if predicted_time > 0 {
        (actual_execution_time as f64 - predicted_time as f64) / predicted_time as f64
    } else {
        0.0
    };
    
    // 実行時間履歴の更新
    thread.add_execution_time_sample(actual_execution_time);
    
    // 指数移動平均による予測モデル更新（α=0.3）
    let history = thread.get_execution_time_history();
    if history.len() >= 3 {
        let recent_avg = history.iter().rev().take(5).sum::<u64>() as f64 / 5.0;
        let historical_avg = thread.get_historical_execution_time() as f64;
        let updated_prediction = 0.7 * historical_avg + 0.3 * recent_avg;
        
        thread.set_predicted_execution_time(updated_prediction as u64);
        
        log::debug!("実行時間予測更新: スレッド={}, 実際={}μs, 予測={}μs -> {}μs, 誤差={:.1}%",
                   thread.get_id(),
                   actual_execution_time / 1000,
                   predicted_time / 1000,
                   updated_prediction as u64 / 1000,
                   prediction_error * 100.0);
    }
}

/// 割り込み処理最適化
fn optimize_interrupt_handling() {
    // 1. 割り込み親和性の最適化
    let optimal_cpu = find_least_loaded_cpu();
    crate::arch::interrupts::set_interrupt_affinity_cpu(optimal_cpu);
    
    // 2. 割り込み結合の有効化
    crate::arch::interrupts::enable_interrupt_coalescing(true);
    
    // 3. 高頻度割り込みの軽減
    let high_freq_interrupts = crate::arch::interrupts::get_high_frequency_interrupts();
    for irq in high_freq_interrupts {
        // 割り込み間隔を調整（最小1ms間隔）
        crate::arch::interrupts::set_interrupt_throttle(irq, Duration::from_millis(1));
    }
    
    // 4. 不要な割り込みの無効化
    let unused_irqs = crate::arch::interrupts::get_unused_interrupts();
    for irq in unused_irqs {
        crate::arch::interrupts::disable_interrupt(irq);
    }
    
    log::info!("割り込み処理最適化完了: 親和性CPU={}, 結合有効, 軽減対象={}個, 無効化={}個",
              optimal_cpu, high_freq_interrupts.len(), unused_irqs.len());
}

/// 最小負荷CPUの検索
fn find_least_loaded_cpu() -> CpuId {
    let num_cpus = crate::arch::cpu::get_cpu_count();
    let mut min_load = f64::MAX;
    let mut best_cpu = 0;
    
    for cpu_id in 0..num_cpus {
        if crate::arch::cpu::is_cpu_online(cpu_id) {
            let rq = unsafe { &RUN_QUEUES[cpu_id] };
            let cpu_load = rq.load_avg.load(Ordering::Relaxed) as f64 / 100.0;
            
            if cpu_load < min_load {
                min_load = cpu_load;
                best_cpu = cpu_id;
            }
        }
    }
    
    best_cpu
}

/// プリエンプションが無効化されているかチェック
fn is_preemption_disabled() -> bool {
    let cpu_id = get_current_cpu();
    let rq = unsafe {
        &RUN_QUEUES[cpu_id]
    };
    
    rq.preempt_count.load(Ordering::Relaxed) > 0
}

/// 高速パスを有効にするか決定
fn enable_fast_path() -> bool {
    // システム負荷に基づいて高速パスを有効化するかを決定
    // 低負荷時は有効化して高速化、高負荷時は完全なスケジューリングを使用
    true // 簡略化のため常に有効
}

/// 現在実行中のスレッドを取得
pub fn current_thread() -> Option<Arc<Thread>> {
    let cpu_id = get_current_cpu();
    let rq = unsafe {
        &RUN_QUEUES[cpu_id]
    };
    
    let current = rq.current.lock();
    current.clone()
}

/// RunQueueの実装
impl RunQueue {
    /// 新しいランキューを作成
    fn new(cpu_id: CpuId) -> Self {
        Self {
            cfs_rq: cfs::CFSRunQueue::new(),
            rt_rq: realtime::RTRunQueue::new(),
            dl_rq: deadline::DLRunQueue::new(),
            idle_thread: None,
            current: SpinLock::new(None),
            current_type: AtomicU32::new(SchedulerType::Idle as u32),
            cpu_id,
            nr_running: AtomicUsize::new(0),
            preempt_count: AtomicUsize::new(0),
            clock_tick_rate: 100, // 100Hz
            load_avg: AtomicU64::new(0),
            fast_path: SpinLock::new(VecDeque::new()),
            stats: SchedulerStats::default(),
        }
    }

    fn select_next_task(&self) -> Option<Arc<Task>> {
        // 実際のスケジューリングアルゴリズム
        // 1. 現在のスケジューリングポリシー (self.policy や、タスク固有のポリシー) を確認する。
        // 2. ポリシーに基づいて、実行可能なタスクのリスト (例えば self.cfs_rq, self.rt_rq など) から次に実行すべきタスクを選択する。
        //    - CFS (Completely Fair Scheduler): self.cfs_rq から vruntime が最も小さいタスクを選択。
        //    - FIFO (First-In, First-Out) (リアルタイム): self.rt_rq の該当優先度キューの先頭タスクを選択。
        //    - RR (Round-Robin) (リアルタイム): self.rt_rq の該当優先度キューの先頭タスクを選択し、タイムスライスを消費したらキューの末尾に戻す。
        //    - Deadline: self.dl_rq から最もデッドラインが近いタスクを選択。
        // 3. 選択されたタスクを返す。適切なタスクがなければ None を返す (アイドル状態へ)。
        // TODO: スケジューリングポリシー (CFS, FIFO, RR, Deadlineなど) に基づいたタスク選択ロジックを実装する。
        //       各実行キュー (cfs_rq, rt_rq, dl_rq) の実装と連携する必要がある。
        //       タスクの優先度、現在のタスクの状態 (Running, Ready, Sleepingなど) を考慮する。
        //       マルチコア環境の場合は、CPUアフィニティ (thread.affinity()) や負荷分散 (load_avg) も考慮に入れる必要がある。
        //       プリエンプション (need_resched) のトリガーもこの選択ロジックと関連する。
        // 現在の実装は単純なFIFO的な動作の例 (fast_pathキューから取得)
        self.fast_path.lock().pop_front()
    }
} 