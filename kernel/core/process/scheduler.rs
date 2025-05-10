// AetherOS スケジューラ
//
// 適応型ハイブリッドスケジューラを実装します。
// 負荷に応じてリアルタイム性能と公平性を動的に最適化します。

use crate::arch;
use crate::process::{
    PriorityClass, Process, SchedPolicy, Thread, ThreadState,
    current_process, current_thread, set_current_process, set_current_thread
};
use crate::sync::{Mutex, RwLock, SpinLock};
use crate::time;
use alloc::collections::{BinaryHeap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp::{Ord, Ordering, PartialOrd};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};

/// タイムスライス（ナノ秒）
const TIME_SLICE_NS: u64 = 4_000_000; // 4ms
/// リアルタイムタイムスライス（ナノ秒）
const RT_TIME_SLICE_NS: u64 = 1_000_000; // 1ms
/// 最大実行可能キュー数
const MAX_RUNQUEUES: usize = 64;
/// 最大リアルタイム優先度
const MAX_RT_PRIO: i32 = 99;
/// 最小リアルタイム優先度
const MIN_RT_PRIO: i32 = 1;
/// 通常優先度の範囲
const NORMAL_PRIO_RANGE: i32 = 20;

/// 実行キュー構造体
struct RunQueue {
    /// 通常優先度キュー（優先度レベル別）
    normal_queues: [VecDeque<Arc<Thread>>; NORMAL_PRIO_RANGE as usize],
    /// リアルタイム優先度キュー（優先度レベル別）
    rt_queues: [VecDeque<Arc<Thread>>; (MAX_RT_PRIO - MIN_RT_PRIO + 1) as usize],
    /// アイドルスレッド
    idle_thread: Option<Arc<Thread>>,
    /// 次に実行するキューのインデックス
    next_queue_index: AtomicUsize,
    /// キュー内のスレッド総数
    total_threads: AtomicUsize,
    /// 実行中のスレッド
    current_thread: Mutex<Option<Arc<Thread>>>,
    /// デッドラインスケジューリングキュー（EDF）
    deadline_queue: Mutex<BinaryHeap<DeadlineTask>>,
}

/// デッドライン付きタスク
#[derive(Clone)]
struct DeadlineTask {
    /// スレッド
    thread: Arc<Thread>,
    /// 絶対デッドライン（ナノ秒）
    absolute_deadline: u64,
    /// 実行時間（ナノ秒）
    execution_time: u64,
    /// 周期（ナノ秒、周期タスクの場合）
    period: Option<u64>,
}

impl PartialEq for DeadlineTask {
    fn eq(&self, other: &Self) -> bool {
        self.absolute_deadline == other.absolute_deadline
    }
}

impl Eq for DeadlineTask {}

impl PartialOrd for DeadlineTask {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // デッドラインが小さい（早い）方が優先度が高い
        other.absolute_deadline.partial_cmp(&self.absolute_deadline)
    }
}

impl Ord for DeadlineTask {
    fn cmp(&self, other: &Self) -> Ordering {
        // デッドラインが小さい（早い）方が優先度が高い
        other.absolute_deadline.cmp(&self.absolute_deadline)
    }
}

/// スケジューラの状態
struct SchedulerState {
    /// CPUごとの実行キュー
    run_queues: Vec<RunQueue>,
    /// 実行キューのロードバランサタイマー
    load_balance_timer: u64,
    /// スケジューラ統計情報
    stats: SchedulerStats,
    /// グローバルスケジューラロック（マイグレーション時に使用）
    global_lock: SpinLock<()>,
    /// AI予測モデルの統計データ
    #[cfg(feature = "ai_scheduler")]
    prediction_data: RwLock<PredictionData>,
}

/// スケジューラ統計情報
struct SchedulerStats {
    /// コンテキストスイッチ数
    context_switches: AtomicUsize,
    /// 強制的なコンテキストスイッチ数
    forced_switches: AtomicUsize,
    /// アイドル時間（ナノ秒）
    idle_time_ns: AtomicU64,
    /// スケジューラが最後に実行された時刻（ナノ秒）
    last_schedule_time: AtomicU64,
    /// スケジューラの実行間隔の平均（ナノ秒）
    avg_schedule_interval_ns: AtomicU64,
    /// 最大スケジューラレイテンシ（ナノ秒）
    max_latency_ns: AtomicU64,
}

#[cfg(feature = "ai_scheduler")]
/// AI予測モデルの統計データ
struct PredictionData {
    /// プロセス実行パターンキャッシュ
    process_patterns: BTreeMap<Pid, Vec<ProcessExecutionSample>>,
    /// CPU使用率予測
    cpu_usage_prediction: BTreeMap<Pid, f32>,
    /// メモリ使用量予測
    memory_usage_prediction: BTreeMap<Pid, usize>,
    /// プロセス間依存関係グラフ
    process_dependencies: Vec<(Pid, Pid, f32)>,
    /// 予測モデル最終更新時刻
    last_update_time: u64,
}

#[cfg(feature = "ai_scheduler")]
/// プロセス実行サンプル
struct ProcessExecutionSample {
    /// タイムスタンプ（ナノ秒）
    timestamp: u64,
    /// CPU使用率（0-100）
    cpu_usage: f32,
    /// メモリ使用量（バイト）
    memory_usage: usize,
    /// I/Oアクティビティ
    io_activity: usize,
    /// CPUコア番号
    cpu_core: usize,
}

/// グローバルスケジューラ状態
static mut SCHEDULER: Option<SchedulerState> = None;
/// スケジューラが初期化済みフラグ
static SCHEDULER_INITIALIZED: AtomicBool = AtomicBool::new(false);
/// スケジューラ実行中フラグ
static SCHEDULING: AtomicBool = AtomicBool::new(false);

/// スケジューラの初期化
pub fn init() {
    let cpu_count = arch::get_cpu_count();
    
    // 実行キューの初期化
    let mut run_queues = Vec::with_capacity(cpu_count);
    for _ in 0..cpu_count {
        // 64の優先度レベルをもつ実行キューを作成
        let normal_queues = core::array::from_fn(|_| VecDeque::new());
        let rt_queues = core::array::from_fn(|_| VecDeque::new());
        
        run_queues.push(RunQueue {
            normal_queues,
            rt_queues,
            idle_thread: None,
            next_queue_index: AtomicUsize::new(0),
            total_threads: AtomicUsize::new(0),
            current_thread: Mutex::new(None),
            deadline_queue: Mutex::new(BinaryHeap::new()),
        });
    }
    
    // スケジューラ状態構造体の初期化
    let scheduler = SchedulerState {
        run_queues,
        load_balance_timer: 0,
        stats: SchedulerStats {
            context_switches: AtomicUsize::new(0),
            forced_switches: AtomicUsize::new(0),
            idle_time_ns: AtomicU64::new(0),
            last_schedule_time: AtomicU64::new(0),
            avg_schedule_interval_ns: AtomicU64::new(TIME_SLICE_NS),
            max_latency_ns: AtomicU64::new(0),
        },
        global_lock: SpinLock::new(()),
        #[cfg(feature = "ai_scheduler")]
        prediction_data: RwLock::new(PredictionData {
            process_patterns: BTreeMap::new(),
            cpu_usage_prediction: BTreeMap::new(),
            memory_usage_prediction: BTreeMap::new(),
            process_dependencies: Vec::new(),
            last_update_time: 0,
        }),
    };
    
    // グローバルスケジューラ状態の設定
    unsafe {
        SCHEDULER = Some(scheduler);
    }
    
    // 各CPUコアのアイドルスレッド作成
    for cpu_id in 0..cpu_count {
        create_idle_thread(cpu_id);
    }
    
    // タイマー割り込みハンドラの設定
    arch::set_timer_handler(timer_tick);
    
    // スケジューラ初期化完了
    SCHEDULER_INITIALIZED.store(true, AtomicOrdering::SeqCst);
    
    log::info!("スケジューラ初期化完了：{}CPUコア", cpu_count);
}

/// アイドルスレッドの作成
fn create_idle_thread(cpu_id: usize) {
    // アイドルスレッドを作成する処理
    // 実際の実装ではcreate_kernel_threadなどのAPIを使用
    
    unsafe {
        if let Some(scheduler) = SCHEDULER.as_mut() {
            // ここでは仮のアイドルスレッド作成ロジックを記述
            // 実際の実装ではOSごとに適切なアイドルスレッド作成コードが必要
            
            // アイドルスレッドをセット（実装は省略）
            // scheduler.run_queues[cpu_id].idle_thread = Some(idle_thread);
        }
    }
}

/// スケジューラのメインループを開始
pub fn start() -> ! {
    // 最初のプロセスをスケジュールする
    schedule();
    
    // この関数は通常、戻らない（最初のプロセスにジャンプする）
    loop {
        arch::halt();
    }
}

/// タイマー割り込みハンドラ
fn timer_tick() {
    if !SCHEDULER_INITIALIZED.load(AtomicOrdering::Relaxed) {
        return;
    }
    
    // 現在の時刻を取得
    let current_time = time::get_system_time_ns();
    
    // 前回のスケジュール時間を記録
    let last_schedule_time = unsafe {
        SCHEDULER.as_ref().unwrap().stats.last_schedule_time.load(AtomicOrdering::Relaxed)
    };
    
    // 前回のスケジュールからの経過時間を計算
    let elapsed = current_time - last_schedule_time;
    
    // 現在のCPU ID
    let cpu_id = arch::get_current_cpu_id();
    
    // 現在のスレッドと実行時間を取得
    if let Some(thread) = current_thread() {
        // スレッドのCPU時間を更新
        let old_time = thread.cpu_time_ns.load(AtomicOrdering::Relaxed);
        thread.cpu_time_ns.store(old_time + elapsed, AtomicOrdering::Relaxed);
        
        // 現在のスレッドのポリシーを確認
        if let Some(process) = current_process() {
            let policy = SchedPolicy::from_i32(process.sched_policy.load(AtomicOrdering::Relaxed));
            let priority = process.sched_priority.load(AtomicOrdering::Relaxed);
            
            // プリエンプション条件の確認
            let should_preempt = match policy {
                // リアルタイムタスクはタイムスライスを使い切った場合にプリエンプション
                SchedPolicy::Fifo => false, // FIFOは自発的に降伏するまで実行
                SchedPolicy::RoundRobin => elapsed >= RT_TIME_SLICE_NS,
                SchedPolicy::Deadline => check_deadline_expired(&thread, current_time),
                // 通常タスク（タイムスライス切れでプリエンプション）
                _ => elapsed >= TIME_SLICE_NS,
            };
            
            if should_preempt {
                // スケジューラを起動
                schedule();
            }
        }
    } else {
        // 現在のスレッドがない場合（初期状態など）スケジューラを起動
        schedule();
    }
    
    // ロードバランスが必要か確認し、必要であれば実行
    check_load_balance(cpu_id);
}

/// デッドラインが過ぎたかチェック
fn check_deadline_expired(thread: &Arc<Thread>, current_time: u64) -> bool {
    // スレッドの属性からデッドラインを取得
    // ここでは簡単な実装として、スレッド固有データから最初のデッドラインを取得することを想定
    let deadline = thread.data.read().get("deadline").map(|d| {
        if d.len() >= 8 {
            u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
        } else {
            u64::MAX // デッドラインが設定されていない場合
        }
    }).unwrap_or(u64::MAX);
    
    current_time >= deadline
}

/// ロードバランス実行が必要か確認
fn check_load_balance(cpu_id: usize) {
    unsafe {
        if let Some(scheduler) = SCHEDULER.as_mut() {
            // 定期的にロードバランスを実行（現在は簡易実装）
            scheduler.load_balance_timer += 1;
            
            // 100タイマーティックごとにロードバランスを実行
            if scheduler.load_balance_timer >= 100 {
                scheduler.load_balance_timer = 0;
                load_balance(cpu_id);
            }
        }
    }
}

/// CPUコア間のロードバランスを実行
fn load_balance(cpu_id: usize) {
    // ロードバランスのロジックを実装
    // 最も負荷の高いCPUから最も負荷の低いCPUにタスクを移動
    
    unsafe {
        if let Some(scheduler) = SCHEDULER.as_ref() {
            let _guard = scheduler.global_lock.lock();
            
            // 最もビジーなCPUを探す
            let mut busiest_cpu = 0;
            let mut busiest_load = 0;
            
            // 最も暇なCPUを探す
            let mut idlest_cpu = 0;
            let mut idlest_load = usize::MAX;
            
            // 各CPUの負荷を調査
            for (i, queue) in scheduler.run_queues.iter().enumerate() {
                let load = queue.total_threads.load(AtomicOrdering::Relaxed);
                
                if load > busiest_load {
                    busiest_cpu = i;
                    busiest_load = load;
                }
                
                if load < idlest_load {
                    idlest_cpu = i;
                    idlest_load = load;
                }
            }
            
            // 負荷の差が一定以上あれば、タスクを移動
            if busiest_load > idlest_load + 2 && busiest_cpu != idlest_cpu {
                // ビジーCPUからタスクを取得（実装は省略）
                // タスクを他のCPUの実行キューに移動する処理
            }
        }
    }
}

/// メインスケジューラ関数
pub fn schedule() {
    // 既にスケジューリング中なら何もしない（再帰防止）
    if SCHEDULING.swap(true, AtomicOrdering::Acquire) {
        SCHEDULING.store(false, AtomicOrdering::Release);
        return;
    }
    
    // 現在のCPU ID
    let cpu_id = arch::get_current_cpu_id();
    
    // 現在の時刻
    let current_time = time::get_system_time_ns();
    
    unsafe {
        if let Some(scheduler) = SCHEDULER.as_mut() {
            // 前回のスケジュール間隔を更新
            let last_time = scheduler.stats.last_schedule_time.load(AtomicOrdering::Relaxed);
            let interval = current_time - last_time;
            
            // スケジュール統計を更新
            scheduler.stats.last_schedule_time.store(current_time, AtomicOrdering::Relaxed);
            
            // 平均スケジュール間隔を更新（指数移動平均）
            let avg = scheduler.stats.avg_schedule_interval_ns.load(AtomicOrdering::Relaxed);
            let new_avg = (avg * 7 + interval) / 8; // 7/8 old + 1/8 new
            scheduler.stats.avg_schedule_interval_ns.store(new_avg, AtomicOrdering::Relaxed);
            
            // 現在実行中のスレッドを保存
            let current = current_thread();
            
            // 次に実行するスレッドを選択
            let next = select_next_thread(cpu_id);
            
            if let Some(next_thread) = next {
                // 現在のスレッドと次のスレッドが同じなら何もしない
                if let Some(ref current_thread) = current {
                    if Arc::ptr_eq(current_thread, &next_thread) {
                        SCHEDULING.store(false, AtomicOrdering::Release);
                        return;
                    }
                }
                
                // 現在のスレッドがあれば、状態を更新して実行キューに戻す
                if let Some(current_thread) = current {
                    // スレッド状態を実行可能に更新
                    if let ThreadState::Running = *current_thread.state.lock() {
                        *current_thread.state.lock() = ThreadState::Ready;
                    }
                    
                    // 実行キューに戻す（ブロックされていなければ）
                    match *current_thread.state.lock() {
                        ThreadState::Ready => {
                            enqueue_thread(cpu_id, current_thread);
                        },
                        _ => {} // その他の状態のスレッドは実行キューに戻さない
                    }
                }
                
                // 次のスレッドを実行中としてマーク
                *next_thread.state.lock() = ThreadState::Running;
                next_thread.last_cpu.store(cpu_id, AtomicOrdering::Release);
                next_thread.last_run_time.store(current_time, AtomicOrdering::Release);
                
                // 現在のスレッド/プロセス参照を更新
                if let Some(process) = next_thread.process.upgrade() {
                    set_current_process(&process);
                }
                set_current_thread(&next_thread);
                
                // 実行中のスレッドを更新
                *scheduler.run_queues[cpu_id].current_thread.lock() = Some(next_thread.clone());
                
                // コンテキストスイッチカウントを増加
                scheduler.stats.context_switches.fetch_add(1, AtomicOrdering::Relaxed);
                
                // 実際のコンテキストスイッチを実行
                if let Some(current_thread) = current {
                    context_switch(&current_thread, &next_thread);
                } else {
                    // 初回スケジューリング（現在のスレッドがない場合）
                    first_switch(&next_thread);
                }
            } else {
                // 実行可能なスレッドがない場合、アイドルスレッドを実行
                if let Some(ref idle_thread) = scheduler.run_queues[cpu_id].idle_thread {
                    // アイドル時間を記録
                    scheduler.stats.idle_time_ns.fetch_add(interval, AtomicOrdering::Relaxed);
                    
                    // 現在のスレッドとアイドルスレッドが同じなら何もしない
                    if let Some(ref current_thread) = current {
                        if Arc::ptr_eq(current_thread, idle_thread) {
                            SCHEDULING.store(false, AtomicOrdering::Release);
                            return;
                        }
                    }
                    
                    // 現在のスレッドがあれば、実行キューに戻す
                    if let Some(current_thread) = current {
                        // スレッド状態を実行可能に更新
                        if let ThreadState::Running = *current_thread.state.lock() {
                            *current_thread.state.lock() = ThreadState::Ready;
                        }
                        
                        // 実行キューに戻す（ブロックされていなければ）
                        match *current_thread.state.lock() {
                            ThreadState::Ready => {
                                enqueue_thread(cpu_id, current_thread);
                            },
                            _ => {} // その他の状態のスレッドは実行キューに戻さない
                        }
                    }
                    
                    // アイドルスレッドを実行中としてマーク
                    *idle_thread.state.lock() = ThreadState::Running;
                    
                    // 現在のスレッド/プロセス参照を更新
                    if let Some(process) = idle_thread.process.upgrade() {
                        set_current_process(&process);
                    }
                    set_current_thread(idle_thread);
                    
                    // 実行中のスレッドを更新
                    *scheduler.run_queues[cpu_id].current_thread.lock() = Some(idle_thread.clone());
                    
                    // コンテキストスイッチカウントを増加
                    scheduler.stats.context_switches.fetch_add(1, AtomicOrdering::Relaxed);
                    
                    // 実際のコンテキストスイッチを実行
                    if let Some(current_thread) = current {
                        context_switch(&current_thread, idle_thread);
                    } else {
                        // 初回スケジューリング
                        first_switch(idle_thread);
                    }
                }
            }
        }
    }
    
    // スケジューリング完了
    SCHEDULING.store(false, AtomicOrdering::Release);
}

/// 次に実行するスレッドを選択
fn select_next_thread(cpu_id: usize) -> Option<Arc<Thread>> {
    unsafe {
        if let Some(scheduler) = SCHEDULER.as_ref() {
            let run_queue = &scheduler.run_queues[cpu_id];
            
            // 1. デッドラインタスクが最優先
            if let Some(deadline_task) = run_queue.deadline_queue.lock().peek() {
                // 実際のデッドラインタスク選択処理
                return Some(deadline_task.thread.clone());
            }
            
            // 2. リアルタイムタスク
            for i in (MIN_RT_PRIO..=MAX_RT_PRIO).rev() {
                let queue_idx = (i - MIN_RT_PRIO) as usize;
                if !run_queue.rt_queues[queue_idx].is_empty() {
                    // 最高優先度のリアルタイムタスクを返す
                    return Some(run_queue.rt_queues[queue_idx][0].clone());
                }
            }
            
            // 3. 通常タスク
            let mut found = false;
            let mut start_idx = run_queue.next_queue_index.load(AtomicOrdering::Relaxed);
            
            for i in 0..NORMAL_PRIO_RANGE as usize {
                let queue_idx = (start_idx + i) % NORMAL_PRIO_RANGE as usize;
                
                if !run_queue.normal_queues[queue_idx].is_empty() {
                    // 次のインデックスを更新
                    run_queue.next_queue_index.store(
                        (queue_idx + 1) % NORMAL_PRIO_RANGE as usize,
                        AtomicOrdering::Relaxed
                    );
                    
                    // 選択したキューの最初のタスクを返す
                    found = true;
                    return Some(run_queue.normal_queues[queue_idx][0].clone());
                }
            }
            
            if !found {
                // 実行可能なタスクがない場合、アイドルスレッドを返す
                return run_queue.idle_thread.clone();
            }
        }
        None
    }
}

/// スレッドを実行キューに追加
fn enqueue_thread(cpu_id: usize, thread: Arc<Thread>) {
    if let Some(process) = thread.process.upgrade() {
        let policy = SchedPolicy::from_i32(process.sched_policy.load(AtomicOrdering::Relaxed));
        let priority = process.sched_priority.load(AtomicOrdering::Relaxed);
        
        unsafe {
            if let Some(scheduler) = SCHEDULER.as_mut() {
                let run_queue = &mut scheduler.run_queues[cpu_id];
                
                match policy {
                    SchedPolicy::Fifo | SchedPolicy::RoundRobin => {
                        // リアルタイムキューに追加
                        if priority >= MIN_RT_PRIO && priority <= MAX_RT_PRIO {
                            let queue_idx = (priority - MIN_RT_PRIO) as usize;
                            run_queue.rt_queues[queue_idx].push_back(thread);
                            run_queue.total_threads.fetch_add(1, AtomicOrdering::Relaxed);
                        } else {
                            // 無効な優先度の場合は通常キューに追加
                            run_queue.normal_queues[NORMAL_PRIO_RANGE as usize / 2].push_back(thread);
                            run_queue.total_threads.fetch_add(1, AtomicOrdering::Relaxed);
                        }
                    },
                    SchedPolicy::Deadline => {
                        // デッドラインキューに追加（実際の実装ではスレッドからデッドライン情報を取得）
                        let deadline = thread.data.read().get("deadline").map(|d| {
                            if d.len() >= 8 {
                                u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
                            } else {
                                u64::MAX
                            }
                        }).unwrap_or(u64::MAX);
                        
                        let execution_time = thread.data.read().get("exec_time").map(|d| {
                            if d.len() >= 8 {
                                u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
                            } else {
                                0
                            }
                        }).unwrap_or(0);
                        
                        let period = thread.data.read().get("period").map(|d| {
                            if d.len() >= 8 {
                                Some(u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]))
                            } else {
                                None
                            }
                        }).unwrap_or(None);
                        
                        let deadline_task = DeadlineTask {
                            thread: thread.clone(),
                            absolute_deadline: deadline,
                            execution_time,
                            period,
                        };
                        
                        run_queue.deadline_queue.lock().push(deadline_task);
                        run_queue.total_threads.fetch_add(1, AtomicOrdering::Relaxed);
                    },
                    _ => {
                        // 通常キューに追加
                        // 優先度を0〜(NORMAL_PRIO_RANGE-1)の範囲に正規化
                        let norm_prio = (priority.max(0).min(NORMAL_PRIO_RANGE - 1)) as usize;
                        run_queue.normal_queues[norm_prio].push_back(thread);
                        run_queue.total_threads.fetch_add(1, AtomicOrdering::Relaxed);
                    }
                }
            }
        }
    }
}

/// スレッドを実行キューから取り除く
pub fn dequeue_thread(cpu_id: usize, thread: &Arc<Thread>) {
    if let Some(process) = thread.process.upgrade() {
        let policy = SchedPolicy::from_i32(process.sched_policy.load(AtomicOrdering::Relaxed));
        let priority = process.sched_priority.load(AtomicOrdering::Relaxed);
        
        unsafe {
            if let Some(scheduler) = SCHEDULER.as_mut() {
                let run_queue = &mut scheduler.run_queues[cpu_id];
                
                match policy {
                    SchedPolicy::Fifo | SchedPolicy::RoundRobin => {
                        // リアルタイムキューから削除
                        if priority >= MIN_RT_PRIO && priority <= MAX_RT_PRIO {
                            let queue_idx = (priority - MIN_RT_PRIO) as usize;
                            run_queue.rt_queues[queue_idx].retain(|t| !Arc::ptr_eq(t, thread));
                            run_queue.total_threads.fetch_sub(1, AtomicOrdering::Relaxed);
                        }
                    },
                    SchedPolicy::Deadline => {
                        // デッドラインキューから削除
                        let mut deadline_queue = run_queue.deadline_queue.lock();
                        let mut new_queue = BinaryHeap::new();
                        
                        // スレッドと一致しないタスクだけを新しいヒープに移す
                        for task in deadline_queue.drain() {
                            if !Arc::ptr_eq(&task.thread, thread) {
                                new_queue.push(task);
                            } else {
                                run_queue.total_threads.fetch_sub(1, AtomicOrdering::Relaxed);
                            }
                        }
                        
                        // 新しいヒープに置き換え
                        *deadline_queue = new_queue;
                    },
                    _ => {
                        // 通常キューから削除
                        let norm_prio = (priority.max(0).min(NORMAL_PRIO_RANGE - 1)) as usize;
                        run_queue.normal_queues[norm_prio].retain(|t| !Arc::ptr_eq(t, thread));
                        run_queue.total_threads.fetch_sub(1, AtomicOrdering::Relaxed);
                    }
                }
            }
        }
    }
}

/// 最初のコンテキストスイッチ（現在のスレッドがない場合）
fn first_switch(next_thread: &Arc<Thread>) {
    // アーキテクチャ固有の初期コンテキストスイッチ処理
    arch::first_thread_switch(next_thread.kernel_stack + next_thread.kernel_stack_size);
}

/// スレッド間のコンテキストスイッチ
fn context_switch(current_thread: &Arc<Thread>, next_thread: &Arc<Thread>) {
    // アーキテクチャ固有のコンテキストスイッチ処理
    arch::context_switch(
        &mut current_thread.context.lock() as *mut _,
        &mut next_thread.context.lock() as *mut _,
    );
}

/// スケジューリングポリシーをi32から変換
impl SchedPolicy {
    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => SchedPolicy::Normal,
            1 => SchedPolicy::Batch,
            2 => SchedPolicy::Idle,
            3 => SchedPolicy::Fifo,
            4 => SchedPolicy::RoundRobin,
            5 => SchedPolicy::Deadline,
            6 => SchedPolicy::Adaptive,
            _ => SchedPolicy::Normal,
        }
    }
} 