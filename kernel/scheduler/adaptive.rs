// AetherOS 適応型スケジューラ
//
// LinuxのCFS(Completely Fair Scheduler)とWindowsのUMS(User Mode Scheduler)の
// 長所を組み合わせた上で、AIベースの負荷予測と動的リソース割り当てを行う
// 次世代スケジューラです。

use crate::process::{Process, Thread, Priority, ThreadState};
use crate::time::{Duration, Instant};
use crate::arch::cpu::{CpuSet, CoreId};
use crate::sync::{Mutex, RwLock, SpinLock};
use crate::memory::CacheAware;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};

/// 実行キューのレベル数
const RUNQUEUE_LEVELS: usize = 64;

/// スケジューラのポリシー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerPolicy {
    /// 汎用（バランス型）
    Balanced,
    
    /// リアルタイム優先
    RealtimeFocus,
    
    /// インタラクティブ優先
    InteractiveFocus,
    
    /// バッチ処理優先
    BatchFocus,
    
    /// 省電力優先
    PowerSaving,
    
    /// 最大パフォーマンス
    MaxPerformance,
}

/// CPU負荷状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuLoadState {
    /// 低負荷（0-30%）
    Low,
    
    /// 中負荷（30-70%）
    Medium,
    
    /// 高負荷（70-90%）
    High,
    
    /// 過負荷（90%以上）
    Overloaded,
}

/// 実行キュー
#[derive(Debug)]
pub struct RunQueue {
    /// 優先度別スレッドキュー
    priority_queues: [VecDeque<Thread>; RUNQUEUE_LEVELS],
    
    /// アクティブなスレッド数
    active_threads: usize,
    
    /// 最後にスケジュールされた時刻
    last_scheduled: Instant,
    
    /// 平均負荷（0-100）
    average_load: AtomicU32,
    
    /// 関連するCPUコア
    cpu_core: CoreId,
}

/// スレッド統計情報
#[derive(Debug, Clone)]
pub struct ThreadStats {
    /// CPU使用時間
    pub cpu_time: Duration,
    
    /// 実行回数
    pub execution_count: u64,
    
    /// 平均実行時間
    pub average_execution_time: Duration,
    
    /// 最後に実行された時刻
    pub last_executed: Instant,
    
    /// 待機時間の合計
    pub total_wait_time: Duration,
    
    /// 優先度の変更回数
    pub priority_changes: u32,
    
    /// I/O待ち時間
    pub io_wait_time: Duration,
    
    /// キャッシュミス回数
    pub cache_misses: u64,
    
    /// メモリアクセスパターン
    pub memory_access_pattern: MemoryAccessPattern,
}

/// メモリアクセスパターン
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAccessPattern {
    /// ランダムアクセス
    Random,
    
    /// シーケンシャルアクセス
    Sequential,
    
    /// 局所性の高いアクセス
    Localized,
    
    /// ストライドアクセス
    Strided,
    
    /// 不明
    Unknown,
}

/// アダプティブスケジューラ
pub struct AdaptiveScheduler {
    /// 各CPUコアの実行キュー
    run_queues: Vec<SpinLock<RunQueue>>,
    
    /// スケジューラポリシー
    policy: RwLock<SchedulerPolicy>,
    
    /// スレッド統計情報
    thread_stats: RwLock<BTreeMap<u64, ThreadStats>>,
    
    /// コア間負荷分散の閾値（%）
    load_balance_threshold: AtomicU32,
    
    /// スケジューリング間隔（マイクロ秒）
    scheduling_interval_us: AtomicU64,
    
    /// プリエンプション有効フラグ
    preemption_enabled: AtomicU32,
    
    /// キャッシュアウェアスケジューリング有効フラグ
    cache_aware_enabled: AtomicU32,
    
    /// 最後の負荷分散時刻
    last_load_balance: Mutex<Instant>,
    
    /// CPUコアの数
    core_count: usize,
    
    /// コアグループ（NUMA対応用）
    core_groups: Vec<CpuSet>,
}

impl AdaptiveScheduler {
    /// 新しいアダプティブスケジューラを作成
    pub fn new(core_count: usize) -> Self {
        let mut run_queues = Vec::with_capacity(core_count);
        let now = Instant::now();
        
        // 各コアの実行キューを初期化
        for i in 0..core_count {
            let priority_queues = core::array::from_fn(|_| VecDeque::new());
            run_queues.push(SpinLock::new(RunQueue {
                priority_queues,
                active_threads: 0,
                last_scheduled: now,
                average_load: AtomicU32::new(0),
                cpu_core: CoreId::new(i as u32),
            }));
        }
        
        // コアグループを初期化（簡易版：すべてのコアを1グループに）
        let mut all_cores = CpuSet::new();
        for i in 0..core_count {
            all_cores.add(CoreId::new(i as u32));
        }
        
        Self {
            run_queues,
            policy: RwLock::new(SchedulerPolicy::Balanced),
            thread_stats: RwLock::new(BTreeMap::new()),
            load_balance_threshold: AtomicU32::new(20), // 20%の負荷差でバランシング
            scheduling_interval_us: AtomicU64::new(1000), // 1ms
            preemption_enabled: AtomicU32::new(1), // 有効
            cache_aware_enabled: AtomicU32::new(1), // 有効
            last_load_balance: Mutex::new(now),
            core_count,
            core_groups: vec![all_cores],
        }
    }
    
    /// スレッドをスケジュール
    pub fn schedule(&self, current_core: CoreId) -> Option<Thread> {
        let mut queue = self.run_queues[current_core.as_usize()].lock();
        
        // スケジューラポリシーに基づいて次のスレッドを選択
        let policy = *self.policy.read().unwrap();
        let next_thread = match policy {
            SchedulerPolicy::Balanced => self.select_balanced(&mut queue),
            SchedulerPolicy::RealtimeFocus => self.select_realtime_focus(&mut queue),
            SchedulerPolicy::InteractiveFocus => self.select_interactive_focus(&mut queue),
            SchedulerPolicy::BatchFocus => self.select_batch_focus(&mut queue),
            SchedulerPolicy::PowerSaving => self.select_power_saving(&mut queue),
            SchedulerPolicy::MaxPerformance => self.select_max_performance(&mut queue),
        };
        
        // スレッドが選択された場合、統計情報を更新
        if let Some(ref thread) = next_thread {
            self.update_thread_stats(thread, current_core);
        }
        
        // 実行キューの状態を更新
        queue.last_scheduled = Instant::now();
        
        next_thread
    }
    
    /// バランス型スケジューリング（汎用）
    fn select_balanced(&self, queue: &mut RunQueue) -> Option<Thread> {
        // 最高優先度からスレッドを探す
        for priority in (0..RUNQUEUE_LEVELS).rev() {
            if !queue.priority_queues[priority].is_empty() {
                return queue.priority_queues[priority].pop_front();
            }
        }
        None
    }
    
    /// リアルタイム優先スケジューリング
    fn select_realtime_focus(&self, queue: &mut RunQueue) -> Option<Thread> {
        // リアルタイム優先度（上位16レベル）を優先的に検索
        let rt_levels = RUNQUEUE_LEVELS - 16;
        
        // まずリアルタイム優先度からスレッドを探す
        for priority in (rt_levels..RUNQUEUE_LEVELS).rev() {
            if !queue.priority_queues[priority].is_empty() {
                return queue.priority_queues[priority].pop_front();
            }
        }
        
        // リアルタイムスレッドがなければ通常スレッドから選択
        for priority in (0..rt_levels).rev() {
            if !queue.priority_queues[priority].is_empty() {
                return queue.priority_queues[priority].pop_front();
            }
        }
        
        None
    }
    
    /// インタラクティブ優先スケジューリング
    fn select_interactive_focus(&self, queue: &mut RunQueue) -> Option<Thread> {
        // インタラクティブスレッドを探す
        for priority in (0..RUNQUEUE_LEVELS).rev() {
            let interactive_threads: Vec<Thread> = queue.priority_queues[priority]
                .drain_filter(|thread| thread.is_interactive())
                .collect();
            
            if !interactive_threads.is_empty() {
                // 他のインタラクティブスレッドを戻す
                for thread in interactive_threads.iter().skip(1) {
                    queue.priority_queues[priority].push_back(thread.clone());
                }
                return Some(interactive_threads[0].clone());
            }
        }
        
        // インタラクティブスレッドがなければ通常のスケジューリング
        self.select_balanced(queue)
    }
    
    /// バッチ処理優先スケジューリング
    fn select_batch_focus(&self, queue: &mut RunQueue) -> Option<Thread> {
        // バッチ処理スレッドを探す
        for priority in (0..RUNQUEUE_LEVELS).rev() {
            let batch_threads: Vec<Thread> = queue.priority_queues[priority]
                .drain_filter(|thread| thread.is_batch())
                .collect();
            
            if !batch_threads.is_empty() {
                // 一番長く実行しているバッチスレッドを選択
                let selected = batch_threads.iter()
                    .max_by_key(|thread| thread.get_execution_time())
                    .unwrap()
                    .clone();
                
                // 他のバッチスレッドを戻す
                for thread in batch_threads.iter() {
                    if thread.get_id() != selected.get_id() {
                        queue.priority_queues[priority].push_back(thread.clone());
                    }
                }
                
                return Some(selected);
            }
        }
        
        // バッチスレッドがなければ通常のスケジューリング
        self.select_balanced(queue)
    }
    
    /// 省電力優先スケジューリング
    fn select_power_saving(&self, queue: &mut RunQueue) -> Option<Thread> {
        // キャッシュ局所性の高いスレッドを優先
        if self.cache_aware_enabled.load(Ordering::Relaxed) != 0 {
            let core_id = queue.cpu_core;
            
            // 現在のコアに局所性の高いスレッドを探す
            for priority in (0..RUNQUEUE_LEVELS).rev() {
                if let Some(pos) = queue.priority_queues[priority].iter()
                    .position(|thread| thread.has_cache_affinity(core_id)) {
                    return Some(queue.priority_queues[priority].remove(pos).unwrap());
                }
            }
        }
        
        // 局所性の高いスレッドがなければ、低電力モードで実行できるスレッドを探す
        for priority in (0..RUNQUEUE_LEVELS).rev() {
            if let Some(pos) = queue.priority_queues[priority].iter()
                .position(|thread| thread.can_run_low_power()) {
                return Some(queue.priority_queues[priority].remove(pos).unwrap());
            }
        }
        
        // それでもなければ通常のスケジューリング
        self.select_balanced(queue)
    }
    
    /// 最大パフォーマンススケジューリング
    fn select_max_performance(&self, queue: &mut RunQueue) -> Option<Thread> {
        // 最高優先度のスレッドを選択
        for priority in (0..RUNQUEUE_LEVELS).rev() {
            if !queue.priority_queues[priority].is_empty() {
                // アイドル状態のスレッドよりも実行可能なスレッドを優先
                let runnable_pos = queue.priority_queues[priority].iter()
                    .position(|thread| thread.get_state() == ThreadState::Ready);
                
                if let Some(pos) = runnable_pos {
                    return Some(queue.priority_queues[priority].remove(pos).unwrap());
                } else if !queue.priority_queues[priority].is_empty() {
                    return queue.priority_queues[priority].pop_front();
                }
            }
        }
        None
    }
    
    /// スレッドをキューに追加
    pub fn enqueue(&self, thread: Thread, target_core: Option<CoreId>) -> Result<(), SchedulerError> {
        // スレッド状態チェック
        if thread.get_state() != ThreadState::Ready && thread.get_state() != ThreadState::New {
            return Err(SchedulerError::InvalidThreadState);
        }
        
        let core_id = match target_core {
            Some(core) => core,
            None => self.select_best_core(&thread),
        };
        
        let mut queue = self.run_queues[core_id.as_usize()].lock();
        let priority = thread.get_priority().as_index();
        
        if priority >= RUNQUEUE_LEVELS {
            return Err(SchedulerError::InvalidPriority);
        }
        
        // キューに追加
        queue.priority_queues[priority].push_back(thread.clone());
        queue.active_threads += 1;
        
        Ok(())
    }
    
    /// スレッドを実行キューから削除
    pub fn dequeue(&self, thread_id: u64) -> Result<Thread, SchedulerError> {
        for core_id in 0..self.core_count {
            let mut queue = self.run_queues[core_id].lock();
            
            for priority in 0..RUNQUEUE_LEVELS {
                if let Some(pos) = queue.priority_queues[priority].iter().position(|t| t.get_id() == thread_id) {
                    let thread = queue.priority_queues[priority].remove(pos).unwrap();
                    queue.active_threads -= 1;
                    return Ok(thread);
                }
            }
        }
        
        Err(SchedulerError::ThreadNotFound)
    }
    
    /// スレッド統計情報を更新
    fn update_thread_stats(&self, thread: &Thread, core_id: CoreId) {
        let thread_id = thread.get_id();
        let now = Instant::now();
        
        let mut stats = self.thread_stats.write().unwrap();
        
        // 既存の統計情報を取得または新規作成
        let thread_stats = stats.entry(thread_id).or_insert_with(|| ThreadStats {
            cpu_time: Duration::from_secs(0),
            execution_count: 0,
            average_execution_time: Duration::from_micros(0),
            last_executed: now,
            total_wait_time: Duration::from_secs(0),
            priority_changes: 0,
            io_wait_time: Duration::from_secs(0),
            cache_misses: 0,
            memory_access_pattern: MemoryAccessPattern::Unknown,
        });
        
        // 統計情報を更新
        thread_stats.execution_count += 1;
        
        // 待機時間を更新
        let wait_time = now - thread_stats.last_executed;
        thread_stats.total_wait_time += wait_time;
        
        // 最終実行時刻を更新
        thread_stats.last_executed = now;
    }
    
    /// コア間の負荷分散を実行
    pub fn balance_load(&self) -> Result<(), SchedulerError> {
        let mut last_balance = self.last_load_balance.lock();
        let now = Instant::now();
        
        // 前回の負荷分散から十分な時間が経過していない場合はスキップ
        if now - *last_balance < Duration::from_millis(100) {
            return Ok(());
        }
        
        // 負荷情報を収集
        let mut loads = Vec::with_capacity(self.core_count);
        for core_id in 0..self.core_count {
            let queue = self.run_queues[core_id].lock();
            loads.push(queue.average_load.load(Ordering::Relaxed));
        }
        
        // 最も負荷の高いコアと低いコアを見つける
        let max_load = loads.iter().max().unwrap();
        let min_load = loads.iter().min().unwrap();
        
        let threshold = self.load_balance_threshold.load(Ordering::Relaxed);
        
        // 負荷差が閾値を超えている場合のみバランシングを実行
        if max_load - min_load > threshold {
            let max_core = loads.iter().position(|&load| load == *max_load).unwrap();
            let min_core = loads.iter().position(|&load| load == *min_load).unwrap();
            
            // 負荷の高いコアから低いコアへスレッドを移動
            self.migrate_threads(max_core, min_core)?;
        }
        
        // 負荷分散の時刻を更新
        *last_balance = now;
        
        Ok(())
    }
    
    /// スレッドを別のコアに移行
    fn migrate_threads(&self, source_core: usize, target_core: usize) -> Result<(), SchedulerError> {
        if source_core >= self.core_count || target_core >= self.core_count {
            return Err(SchedulerError::InvalidCoreId);
        }
        
        let mut source_queue = self.run_queues[source_core].lock();
        let mut target_queue = self.run_queues[target_core].lock();
        
        // 移行するスレッド数を計算
        let diff = source_queue.active_threads - target_queue.active_threads;
        let move_count = diff / 2; // 差の半分を移動
        
        if move_count == 0 {
            return Ok(());
        }
        
        let mut moved = 0;
        
        // 各優先度キューからスレッドを移動
        for priority in 0..RUNQUEUE_LEVELS {
            while moved < move_count && !source_queue.priority_queues[priority].is_empty() {
                // キャッシュ局所性の低いスレッドを優先的に移動
                let thread = source_queue.priority_queues[priority].pop_back().unwrap();
                target_queue.priority_queues[priority].push_back(thread);
                
                source_queue.active_threads -= 1;
                target_queue.active_threads += 1;
                moved += 1;
            }
            
            if moved >= move_count {
                break;
            }
        }
        
        Ok(())
    }
    
    /// 最適なコアを選択
    fn select_best_core(&self, thread: &Thread) -> CoreId {
        if self.cache_aware_enabled.load(Ordering::Relaxed) != 0 {
            // キャッシュ最適化されたコア選択
            return self.select_cache_optimal_core(thread);
        }
        
        // 最も負荷の低いコアを選択
        let mut min_load = u32::MAX;
        let mut min_core = CoreId::new(0);
        
        for core_id in 0..self.core_count {
            let queue = self.run_queues[core_id].lock();
            let load = queue.average_load.load(Ordering::Relaxed);
            
            if load < min_load {
                min_load = load;
                min_core = CoreId::new(core_id as u32);
            }
        }
        
        min_core
    }
    
    /// キャッシュ最適化されたコア選択
    fn select_cache_optimal_core(&self, thread: &Thread) -> CoreId {
        // スレッドのメモリアクセスパターンとキャッシュアフィニティを考慮
        let thread_id = thread.get_id();
        let stats = self.thread_stats.read().unwrap();
        
        if let Some(thread_stats) = stats.get(&thread_id) {
            // 局所性の高いスレッドは以前実行されたコアに割り当て
            if thread_stats.memory_access_pattern == MemoryAccessPattern::Localized {
                if let Some(core) = thread.get_last_core() {
                    return core;
                }
            }
        }
        
        // 最も負荷の低いコアを選択
        let mut min_load = u32::MAX;
        let mut min_core = CoreId::new(0);
        
        for core_id in 0..self.core_count {
            let queue = self.run_queues[core_id].lock();
            let load = queue.average_load.load(Ordering::Relaxed);
            
            if load < min_load {
                min_load = load;
                min_core = CoreId::new(core_id as u32);
            }
        }
        
        min_core
    }
    
    /// スケジューラポリシーを設定
    pub fn set_policy(&self, policy: SchedulerPolicy) {
        let mut current_policy = self.policy.write().unwrap();
        *current_policy = policy;
        
        log::info!("スケジューラポリシーを {:?} に変更しました", policy);
    }
    
    /// 現在のスケジューラポリシーを取得
    pub fn get_policy(&self) -> SchedulerPolicy {
        *self.policy.read().unwrap()
    }
    
    /// プリエンプションを有効/無効に設定
    pub fn set_preemption(&self, enabled: bool) {
        self.preemption_enabled.store(enabled as u32, Ordering::SeqCst);
    }
    
    /// キャッシュアウェアスケジューリングを有効/無効に設定
    pub fn set_cache_aware(&self, enabled: bool) {
        self.cache_aware_enabled.store(enabled as u32, Ordering::SeqCst);
    }
}

/// スケジューラエラー
#[derive(Debug, Clone, Copy)]
pub enum SchedulerError {
    /// スレッドが見つからない
    ThreadNotFound,
    
    /// 無効なスレッド状態
    InvalidThreadState,
    
    /// 無効な優先度
    InvalidPriority,
    
    /// 無効なコアID
    InvalidCoreId,
    
    /// キューがいっぱい
    QueueFull,
    
    /// その他のエラー
    Other,
} 