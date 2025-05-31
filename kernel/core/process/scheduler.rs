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
    // 各CPUに対応するアイドルスレッドを作成し、実行キューに登録します。
    // アイドルスレッドは、実行可能な他のスレッドがない場合にCPUを占有し、
    // システムがハングアップするのを防ぎます。また、省電力機能のトリガーにもなり得ます。
    // 例: let idle_stack = allocate_kernel_stack();
    //     let idle_thread = Thread::new_idle(idle_task_function, idle_stack, cpu_id);
    //     SCHEDULER_STATE.run_queues[cpu_id].idle_thread = Some(idle_thread);
    log::info!("CPU {} のアイドルスレッド作成 (スタブ)", cpu_id);
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
    let mut state = SCHEDULER_STATE.lock();
    let rq = &mut state.run_queues[cpu_id];

    rq.total_threads.fetch_add(1, Ordering::Relaxed);

    match thread.policy {
        SchedPolicy::Normal | SchedPolicy::Batch | SchedPolicy::Idle => {
            let priority_level = thread.priority.clamp(NORMAL_PRIO_MIN, NORMAL_PRIO_MAX) - NORMAL_PRIO_MIN;
            rq.normal_queues[priority_level as usize].push_back(thread);
        }
        SchedPolicy::FIFO | SchedPolicy::RR => {
            let priority_level = thread.priority.clamp(MIN_RT_PRIO, MAX_RT_PRIO) - MIN_RT_PRIO;
            rq.rt_queues[priority_level as usize].push_back(thread);
        }
        SchedPolicy::Deadline => {
            // スレッドのデッドライン、実行時間、周期を取得します。
            // これらはスレッドのメタデータや、プロセス設定から取得されるべきです。
            // 例: let deadline_info = thread.get_deadline_parameters();
            let task = DeadlineTask {
                thread: thread.clone(),
                absolute_deadline: crate::time::current_time_ns() + 100_000_000, // 仮: 100ms後
                execution_time: 10_000_000, // 仮: 10ms
                period: None, // 仮
            };
            rq.deadline_queue.lock().push(task);
        }
    }
    log::trace!("スレッド {} を CPU {} のキューに追加しました", thread.id, cpu_id);
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
    // 実際のプロセッサのコンテキストスイッチ実装
    // この処理はカーネルの最もクリティカルな部分の一つ
    
    log::trace!("Switching context from task {} to task {}", current_thread.id, next_thread.id);
    
    // 1. 割り込みを無効化してアトミックな操作を保証
    let flags = arch::disable_interrupts();
    
    // 2. 現在のタスクのレジスタ状態を保存
    unsafe {
        save_task_context(current_thread);
    }
    
    // 3. FPU/SIMD状態の保存（遅延保存戦略）
    if current_thread.fpu_used {
        save_fpu_state(&mut current_thread.fpu_context);
        current_thread.fpu_used = false;
    }
    
    // 4. ページテーブルの切り替え
    if current_thread.page_table_root != next_thread.page_table_root {
        switch_page_table(next_thread.page_table_root);
        
        // TLBフラッシュ（必要に応じて）
        arch::flush_tlb();
    }
    
    // 5. カーネルスタックの切り替え
    switch_kernel_stack(next_thread.kernel_stack_ptr);
    
    // 6. 次のタスクのレジスタ状態を復元
    unsafe {
        restore_task_context(next_thread);
    }
    
    // 7. FPU/SIMD状態の復元（遅延復元）
    if next_thread.fpu_used {
        restore_fpu_state(&next_thread.fpu_context);
    } else {
        // FPU使用時に例外が発生するよう設定
        arch::disable_fpu();
    }
    
    // 8. タスク状態の更新
    *current_thread.state.lock() = ThreadState::Ready;
    *next_thread.state.lock() = ThreadState::Running;
    
    // 9. 統計情報の更新
    update_context_switch_stats(current_thread, next_thread);
    
    // 10. 割り込みを再有効化
    arch::restore_interrupts(flags);
    
    // 11. 実際のコンテキストスイッチを実行
    unsafe {
        arch::perform_context_switch(
            &mut current_thread.context as *mut TaskContext,
            &next_thread.context as *const TaskContext
        );
    }
}

/// タスクコンテキストを保存
unsafe fn save_task_context(task: &Task) {
    #[cfg(target_arch = "x86_64")]
    {
        // x86_64レジスタ状態の保存
        let context = &mut task.context;
        
        // 汎用レジスタの保存
        core::arch::asm!(
            "mov {}, rax",
            "mov {}, rbx", 
            "mov {}, rcx",
            "mov {}, rdx",
            "mov {}, rsi",
            "mov {}, rdi",
            "mov {}, rbp",
            "mov {}, r8",
            "mov {}, r9",
            "mov {}, r10",
            "mov {}, r11",
            "mov {}, r12",
            "mov {}, r13",
            "mov {}, r14",
            "mov {}, r15",
            out(reg) context.rax,
            out(reg) context.rbx,
            out(reg) context.rcx,
            out(reg) context.rdx,
            out(reg) context.rsi,
            out(reg) context.rdi,
            out(reg) context.rbp,
            out(reg) context.r8,
            out(reg) context.r9,
            out(reg) context.r10,
            out(reg) context.r11,
            out(reg) context.r12,
            out(reg) context.r13,
            out(reg) context.r14,
            out(reg) context.r15,
        );
        
        // スタックポインタとフラグレジスタの保存
        core::arch::asm!(
            "mov {}, rsp",
            "pushfq",
            "pop {}",
            out(reg) context.rsp,
            out(reg) context.rflags,
        );
        
        // セグメントレジスタの保存
        core::arch::asm!(
            "mov {}, cs",
            "mov {}, ds", 
            "mov {}, es",
            "mov {}, fs",
            "mov {}, gs",
            "mov {}, ss",
            out(reg) context.cs,
            out(reg) context.ds,
            out(reg) context.es,
            out(reg) context.fs,
            out(reg) context.gs,
            out(reg) context.ss,
        );
        
        // 制御レジスタの保存（必要な部分のみ）
        core::arch::asm!(
            "mov {}, cr2",
            out(reg) context.cr2,
        );
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        // AArch64レジスタ状態の保存
        let context = &mut task.context;
        
        // 汎用レジスタの保存（x0-x30）
        core::arch::asm!(
            "stp x0, x1, [{}, #0]",
            "stp x2, x3, [{}, #16]",
            "stp x4, x5, [{}, #32]",
            "stp x6, x7, [{}, #48]",
            "stp x8, x9, [{}, #64]",
            "stp x10, x11, [{}, #80]",
            "stp x12, x13, [{}, #96]",
            "stp x14, x15, [{}, #112]",
            "stp x16, x17, [{}, #128]",
            "stp x18, x19, [{}, #144]",
            "stp x20, x21, [{}, #160]",
            "stp x22, x23, [{}, #176]",
            "stp x24, x25, [{}, #192]",
            "stp x26, x27, [{}, #208]",
            "stp x28, x29, [{}, #224]",
            "str x30, [{}, #240]",
            in(reg) &mut context.x_regs as *mut _ as u64,
        );
        
        // スタックポインタとプログラムカウンタの保存
        core::arch::asm!(
            "mov {}, sp",
            "adr {}, 1f",
            "1:",
            out(reg) context.sp,
            out(reg) context.pc,
        );
        
        // プロセッサ状態レジスタの保存
        core::arch::asm!(
            "mrs {}, nzcv",
            "mrs {}, daif",
            out(reg) context.pstate,
            out(reg) context.daif,
        );
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        // RISC-V レジスタ状態の保存
        let context = &mut task.context;
        
        // 汎用レジスタの保存（x1-x31、x0は常に0なので保存不要）
        core::arch::asm!(
            "sd x1, 0({0})",
            "sd x2, 8({0})",
            "sd x3, 16({0})",
            "sd x4, 24({0})",
            "sd x5, 32({0})",
            "sd x6, 40({0})",
            "sd x7, 48({0})",
            "sd x8, 56({0})",
            "sd x9, 64({0})",
            "sd x10, 72({0})",
            "sd x11, 80({0})",
            "sd x12, 88({0})",
            "sd x13, 96({0})",
            "sd x14, 104({0})",
            "sd x15, 112({0})",
            "sd x16, 120({0})",
            "sd x17, 128({0})",
            "sd x18, 136({0})",
            "sd x19, 144({0})",
            "sd x20, 152({0})",
            "sd x21, 160({0})",
            "sd x22, 168({0})",
            "sd x23, 176({0})",
            "sd x24, 184({0})",
            "sd x25, 192({0})",
            "sd x26, 200({0})",
            "sd x27, 208({0})",
            "sd x28, 216({0})",
            "sd x29, 224({0})",
            "sd x30, 232({0})",
            "sd x31, 240({0})",
            in(reg) &mut context.x_regs as *mut _ as u64,
        );
        
        // CSRレジスタの保存
        core::arch::asm!(
            "csrr {}, sstatus",
            "csrr {}, sepc",
            "csrr {}, stval",
            "csrr {}, scause",
            out(reg) context.sstatus,
            out(reg) context.sepc,
            out(reg) context.stval,
            out(reg) context.scause,
        );
    }
}

/// タスクコンテキストを復元
unsafe fn restore_task_context(task: &Task) {
    #[cfg(target_arch = "x86_64")]
    {
        let context = &task.context;
        
        // セグメントレジスタの復元
        core::arch::asm!(
            "mov ds, {}",
            "mov es, {}",
            "mov fs, {}",
            "mov gs, {}",
            in(reg) context.ds,
            in(reg) context.es,
            in(reg) context.fs,
            in(reg) context.gs,
        );
        
        // 汎用レジスタの復元
        core::arch::asm!(
            "mov rax, {}",
            "mov rbx, {}",
            "mov rcx, {}",
            "mov rdx, {}",
            "mov rsi, {}",
            "mov rdi, {}",
            "mov rbp, {}",
            "mov r8, {}",
            "mov r9, {}",
            "mov r10, {}",
            "mov r11, {}",
            "mov r12, {}",
            "mov r13, {}",
            "mov r14, {}",
            "mov r15, {}",
            in(reg) context.rax,
            in(reg) context.rbx,
            in(reg) context.rcx,
            in(reg) context.rdx,
            in(reg) context.rsi,
            in(reg) context.rdi,
            in(reg) context.rbp,
            in(reg) context.r8,
            in(reg) context.r9,
            in(reg) context.r10,
            in(reg) context.r11,
            in(reg) context.r12,
            in(reg) context.r13,
            in(reg) context.r14,
            in(reg) context.r15,
        );
        
        // スタックポインタとフラグレジスタの復元
        core::arch::asm!(
            "mov rsp, {}",
            "push {}",
            "popfq",
            in(reg) context.rsp,
            in(reg) context.rflags,
        );
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        let context = &task.context;
        
        // 汎用レジスタの復元
        core::arch::asm!(
            "ldp x0, x1, [{}, #0]",
            "ldp x2, x3, [{}, #16]",
            "ldp x4, x5, [{}, #32]",
            "ldp x6, x7, [{}, #48]",
            "ldp x8, x9, [{}, #64]",
            "ldp x10, x11, [{}, #80]",
            "ldp x12, x13, [{}, #96]",
            "ldp x14, x15, [{}, #112]",
            "ldp x16, x17, [{}, #128]",
            "ldp x18, x19, [{}, #144]",
            "ldp x20, x21, [{}, #160]",
            "ldp x22, x23, [{}, #176]",
            "ldp x24, x25, [{}, #192]",
            "ldp x26, x27, [{}, #208]",
            "ldp x28, x29, [{}, #224]",
            "ldr x30, [{}, #240]",
            in(reg) &context.x_regs as *const _ as u64,
        );
        
        // スタックポインタの復元
        core::arch::asm!(
            "mov sp, {}",
            in(reg) context.sp,
        );
        
        // プロセッサ状態の復元
        core::arch::asm!(
            "msr nzcv, {}",
            "msr daif, {}",
            in(reg) context.pstate,
            in(reg) context.daif,
        );
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        let context = &task.context;
        
        // CSRレジスタの復元
        core::arch::asm!(
            "csrw sstatus, {}",
            "csrw sepc, {}",
            in(reg) context.sstatus,
            in(reg) context.sepc,
        );
        
        // 汎用レジスタの復元
        core::arch::asm!(
            "ld x1, 0({0})",
            "ld x2, 8({0})",
            "ld x3, 16({0})",
            "ld x4, 24({0})",
            "ld x5, 32({0})",
            "ld x6, 40({0})",
            "ld x7, 48({0})",
            "ld x8, 56({0})",
            "ld x9, 64({0})",
            "ld x10, 72({0})",
            "ld x11, 80({0})",
            "ld x12, 88({0})",
            "ld x13, 96({0})",
            "ld x14, 104({0})",
            "ld x15, 112({0})",
            "ld x16, 120({0})",
            "ld x17, 128({0})",
            "ld x18, 136({0})",
            "ld x19, 144({0})",
            "ld x20, 152({0})",
            "ld x21, 160({0})",
            "ld x22, 168({0})",
            "ld x23, 176({0})",
            "ld x24, 184({0})",
            "ld x25, 192({0})",
            "ld x26, 200({0})",
            "ld x27, 208({0})",
            "ld x28, 216({0})",
            "ld x29, 224({0})",
            "ld x30, 232({0})",
            "ld x31, 240({0})",
            in(reg) &context.x_regs as *const _ as u64,
        );
    }
}

/// FPU/SIMD状態を保存
fn save_fpu_state(fpu_context: &mut FpuContext) {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            // XSAVE命令でFPU/SSE/AVX状態を保存
            if arch::cpu_has_xsave() {
                core::arch::asm!(
                    "xsave [{}]",
                    in(reg) fpu_context.xsave_area.as_mut_ptr(),
                    in("eax") 0xFFFFFFFF, // すべての状態を保存
                    in("edx") 0xFFFFFFFF,
                );
            } else if arch::cpu_has_fxsave() {
                // FXSAVE命令でFPU/SSE状態を保存
                core::arch::asm!(
                    "fxsave [{}]",
                    in(reg) fpu_context.fxsave_area.as_mut_ptr(),
                );
            } else {
                // 古いFSAVE命令
                core::arch::asm!(
                    "fsave [{}]",
                    in(reg) fpu_context.fsave_area.as_mut_ptr(),
                );
            }
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        unsafe {
            // NEON/FPレジスタの保存（v0-v31）
            core::arch::asm!(
                "stp q0, q1, [{}, #0]",
                "stp q2, q3, [{}, #32]",
                "stp q4, q5, [{}, #64]",
                "stp q6, q7, [{}, #96]",
                "stp q8, q9, [{}, #128]",
                "stp q10, q11, [{}, #160]",
                "stp q12, q13, [{}, #192]",
                "stp q14, q15, [{}, #224]",
                "stp q16, q17, [{}, #256]",
                "stp q18, q19, [{}, #288]",
                "stp q20, q21, [{}, #320]",
                "stp q22, q23, [{}, #352]",
                "stp q24, q25, [{}, #384]",
                "stp q26, q27, [{}, #416]",
                "stp q28, q29, [{}, #448]",
                "stp q30, q31, [{}, #480]",
                in(reg) fpu_context.neon_regs.as_mut_ptr(),
            );
            
            // FPCR/FPSRレジスタの保存
            core::arch::asm!(
                "mrs {}, fpcr",
                "mrs {}, fpsr",
                out(reg) fpu_context.fpcr,
                out(reg) fpu_context.fpsr,
            );
        }
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        unsafe {
            // F/D拡張のレジスタ保存（f0-f31）
            if arch::cpu_has_f_extension() {
                core::arch::asm!(
                    "fsd f0, 0({0})",
                    "fsd f1, 8({0})",
                    "fsd f2, 16({0})",
                    "fsd f3, 24({0})",
                    "fsd f4, 32({0})",
                    "fsd f5, 40({0})",
                    "fsd f6, 48({0})",
                    "fsd f7, 56({0})",
                    "fsd f8, 64({0})",
                    "fsd f9, 72({0})",
                    "fsd f10, 80({0})",
                    "fsd f11, 88({0})",
                    "fsd f12, 96({0})",
                    "fsd f13, 104({0})",
                    "fsd f14, 112({0})",
                    "fsd f15, 120({0})",
                    "fsd f16, 128({0})",
                    "fsd f17, 136({0})",
                    "fsd f18, 144({0})",
                    "fsd f19, 152({0})",
                    "fsd f20, 160({0})",
                    "fsd f21, 168({0})",
                    "fsd f22, 176({0})",
                    "fsd f23, 184({0})",
                    "fsd f24, 192({0})",
                    "fsd f25, 200({0})",
                    "fsd f26, 208({0})",
                    "fsd f27, 216({0})",
                    "fsd f28, 224({0})",
                    "fsd f29, 232({0})",
                    "fsd f30, 240({0})",
                    "fsd f31, 248({0})",
                    in(reg) fpu_context.f_regs.as_mut_ptr(),
                );
                
                // FCSRレジスタの保存
                core::arch::asm!(
                    "csrr {}, fcsr",
                    out(reg) fpu_context.fcsr,
                );
            }
        }
    }
}

/// FPU/SIMD状態を復元
fn restore_fpu_state(fpu_context: &FpuContext) {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            // XRSTOR命令でFPU/SSE/AVX状態を復元
            if arch::cpu_has_xsave() {
                core::arch::asm!(
                    "xrstor [{}]",
                    in(reg) fpu_context.xsave_area.as_ptr(),
                    in("eax") 0xFFFFFFFF,
                    in("edx") 0xFFFFFFFF,
                );
            } else if arch::cpu_has_fxsave() {
                // FXRSTOR命令でFPU/SSE状態を復元
                core::arch::asm!(
                    "fxrstor [{}]",
                    in(reg) fpu_context.fxsave_area.as_ptr(),
                );
            } else {
                // 古いFRSTOR命令
                core::arch::asm!(
                    "frstor [{}]",
                    in(reg) fpu_context.fsave_area.as_ptr(),
                );
            }
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        unsafe {
            // FPCR/FPSRレジスタの復元
            core::arch::asm!(
                "msr fpcr, {}",
                "msr fpsr, {}",
                in(reg) fpu_context.fpcr,
                in(reg) fpu_context.fpsr,
            );
            
            // NEON/FPレジスタの復元
            core::arch::asm!(
                "ldp q0, q1, [{}, #0]",
                "ldp q2, q3, [{}, #32]",
                "ldp q4, q5, [{}, #64]",
                "ldp q6, q7, [{}, #96]",
                "ldp q8, q9, [{}, #128]",
                "ldp q10, q11, [{}, #160]",
                "ldp q12, q13, [{}, #192]",
                "ldp q14, q15, [{}, #224]",
                "ldp q16, q17, [{}, #256]",
                "ldp q18, q19, [{}, #288]",
                "ldp q20, q21, [{}, #320]",
                "ldp q22, q23, [{}, #352]",
                "ldp q24, q25, [{}, #384]",
                "ldp q26, q27, [{}, #416]",
                "ldp q28, q29, [{}, #448]",
                "ldp q30, q31, [{}, #480]",
                in(reg) fpu_context.neon_regs.as_ptr(),
            );
        }
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        unsafe {
            if arch::cpu_has_f_extension() {
                // FCSRレジスタの復元
                core::arch::asm!(
                    "csrw fcsr, {}",
                    in(reg) fpu_context.fcsr,
                );
                
                // F/D拡張のレジスタ復元
                core::arch::asm!(
                    "fld f0, 0({0})",
                    "fld f1, 8({0})",
                    "fld f2, 16({0})",
                    "fld f3, 24({0})",
                    "fld f4, 32({0})",
                    "fld f5, 40({0})",
                    "fld f6, 48({0})",
                    "fld f7, 56({0})",
                    "fld f8, 64({0})",
                    "fld f9, 72({0})",
                    "fld f10, 80({0})",
                    "fld f11, 88({0})",
                    "fld f12, 96({0})",
                    "fld f13, 104({0})",
                    "fld f14, 112({0})",
                    "fld f15, 120({0})",
                    "fld f16, 128({0})",
                    "fld f17, 136({0})",
                    "fld f18, 144({0})",
                    "fld f19, 152({0})",
                    "fld f20, 160({0})",
                    "fld f21, 168({0})",
                    "fld f22, 176({0})",
                    "fld f23, 184({0})",
                    "fld f24, 192({0})",
                    "fld f25, 200({0})",
                    "fld f26, 208({0})",
                    "fld f27, 216({0})",
                    "fld f28, 224({0})",
                    "fld f29, 232({0})",
                    "fld f30, 240({0})",
                    "fld f31, 248({0})",
                    in(reg) fpu_context.f_regs.as_ptr(),
                );
            }
        }
    }
}

/// ページテーブルを切り替え
fn switch_page_table(page_table_root: PhysicalAddress) {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            // CR3レジスタにページテーブルルートアドレスを設定
            core::arch::asm!(
                "mov cr3, {}",
                in(reg) page_table_root.as_u64(),
            );
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        unsafe {
            // TTBR0_EL1レジスタにページテーブルベースアドレスを設定
            core::arch::asm!(
                "msr ttbr0_el1, {}",
                "isb",
                in(reg) page_table_root.as_u64(),
            );
        }
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        unsafe {
            // satpレジスタにページテーブルルートアドレスを設定
            let satp_value = (8u64 << 60) | (page_table_root.as_u64() >> 12); // Sv48モード
            core::arch::asm!(
                "csrw satp, {}",
                "sfence.vma",
                in(reg) satp_value,
            );
        }
    }
}

/// カーネルスタックを切り替え
fn switch_kernel_stack(kernel_stack_ptr: VirtualAddress) {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            // TSSのRSP0フィールドを更新
            arch::update_tss_rsp0(kernel_stack_ptr.as_u64());
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        unsafe {
            // SP_EL0レジスタを更新
            core::arch::asm!(
                "msr sp_el0, {}",
                in(reg) kernel_stack_ptr.as_u64(),
            );
        }
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        unsafe {
            // sscratchレジスタを更新
            core::arch::asm!(
                "csrw sscratch, {}",
                in(reg) kernel_stack_ptr.as_u64(),
            );
        }
    }
}

/// コンテキストスイッチ統計を更新
fn update_context_switch_stats(prev_task: &Task, next_task: &Task) {
    let current_time = crate::time::current_time_ns();
    
    // 前のタスクの実行時間を記録
    prev_task.total_runtime.fetch_add(
        current_time - prev_task.last_scheduled_time.load(AtomicOrdering::Relaxed),
        AtomicOrdering::Relaxed
    );
    
    // 次のタスクのスケジュール時刻を記録
    next_task.last_scheduled_time.store(current_time, AtomicOrdering::Relaxed);
    
    // グローバル統計を更新
    unsafe {
        if let Some(scheduler) = SCHEDULER.as_ref() {
            scheduler.stats.context_switches.fetch_add(1, AtomicOrdering::Relaxed);
            
            // レイテンシ測定
            let schedule_latency = current_time - scheduler.stats.last_schedule_time.load(AtomicOrdering::Relaxed);
            let max_latency = scheduler.stats.max_latency_ns.load(AtomicOrdering::Relaxed);
            if schedule_latency > max_latency {
                scheduler.stats.max_latency_ns.store(schedule_latency, AtomicOrdering::Relaxed);
            }
        }
    }
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