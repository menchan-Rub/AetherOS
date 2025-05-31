// AetherOS ネットワークキュー管理システム
//
// このモジュールはネットワークパケットの効率的なキュー管理を提供します。
// 優先度ベースのキュー、バッチ処理、動的負荷分散機能を実装しています。

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use crate::core::sync::{Mutex, RwLock, Condvar};
use crate::core::network::protocol::{TransportError, TransferPriority};
use crate::core::memory::telepage::NodeId;

/// キューの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueState {
    /// アイドル
    Idle,
    /// アクティブ
    Active,
    /// 一時停止
    Paused,
    /// シャットダウン
    Shutdown,
}

/// キュー統計情報
#[derive(Debug, Default, Clone)]
pub struct QueueStats {
    /// エンキューされた項目数
    pub enqueued: u64,
    /// デキューされた項目数
    pub dequeued: u64,
    /// 現在のキューの深さ
    pub current_depth: usize,
    /// 最大キュー深度
    pub max_depth: usize,
    /// 破棄された項目数
    pub dropped: u64,
    /// バッチ処理数
    pub batches: u64,
    /// 合計待機時間（マイクロ秒）
    pub total_wait_time_us: u64,
    /// 平均待機時間（マイクロ秒）
    pub avg_wait_time_us: u64,
}

/// キュータイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueType {
    /// 送信キュー
    Transmit,
    /// 受信キュー
    Receive,
    /// 処理キュー
    Processing,
    /// コマンドキュー
    Command,
}

/// 優先度付きキューマネージャ
pub struct PriorityQueueManager<T> {
    /// キュータイプ
    queue_type: QueueType,
    /// 優先度ごとのキュー
    queues: RwLock<BTreeMap<TransferPriority, NetworkQueue<T>>>,
    /// 状態
    state: AtomicQueueState,
    /// 統計情報
    stats: QueueManagerStats,
    /// 最大キューサイズ
    max_queue_size: usize,
    /// コンディション変数（通知用）
    condvar: Condvar,
    /// ロック（条件変数用）
    mutex: Mutex<()>,
}

/// ネットワークキュー
struct NetworkQueue<T> {
    /// キューデータ
    data: Mutex<VecDeque<QueueItem<T>>>,
    /// 優先度
    priority: TransferPriority,
    /// 統計情報
    stats: QueueStats,
    /// 最大サイズ
    max_size: usize,
}

/// キュー項目
struct QueueItem<T> {
    /// データ
    data: T,
    /// エンキュー時刻
    enqueue_time: u64,
    /// 優先度
    priority: TransferPriority,
    /// タイムアウト（ミリ秒、0=無限）
    timeout_ms: u64,
}

/// キューマネージャ統計情報
#[derive(Debug, Default)]
struct QueueManagerStats {
    /// 総エンキュー数
    total_enqueued: AtomicU64,
    /// 総デキュー数
    total_dequeued: AtomicU64,
    /// 総バッチ数
    total_batches: AtomicU64,
    /// 総ドロップ数
    total_dropped: AtomicU64,
    /// 現在の総アイテム数
    current_items: AtomicUsize,
}

/// アトミックキュー状態
struct AtomicQueueState(AtomicUsize);

impl AtomicQueueState {
    /// 新しい状態を作成
    fn new(state: QueueState) -> Self {
        Self(AtomicUsize::new(state as usize))
    }
    
    /// 状態を設定
    fn set(&self, state: QueueState) {
        self.0.store(state as usize, Ordering::SeqCst);
    }
    
    /// 状態を取得
    fn get(&self) -> QueueState {
        match self.0.load(Ordering::SeqCst) {
            0 => QueueState::Idle,
            1 => QueueState::Active,
            2 => QueueState::Paused,
            _ => QueueState::Shutdown,
        }
    }
}

impl<T: Clone + Send + Sync + 'static> PriorityQueueManager<T> {
    /// 新しいキューマネージャを作成
    pub fn new(queue_type: QueueType, max_queue_size: usize) -> Self {
        Self {
            queue_type,
            queues: RwLock::new(BTreeMap::new()),
            state: AtomicQueueState::new(QueueState::Idle),
            stats: QueueManagerStats::default(),
            max_queue_size,
            condvar: Condvar::new(),
            mutex: Mutex::new(()),
        }
    }
    
    /// 初期化
    pub fn init(&self) -> Result<(), TransportError> {
        let mut queues = self.queues.write().unwrap();
        
        // 各優先度のキューを作成
        for priority in &[
            TransferPriority::Critical,
            TransferPriority::High,
            TransferPriority::Normal,
            TransferPriority::Low,
        ] {
            let queue = NetworkQueue {
                data: Mutex::new(VecDeque::with_capacity(self.max_queue_size)),
                priority: *priority,
                stats: QueueStats::default(),
                max_size: self.max_queue_size,
            };
            
            queues.insert(*priority, queue);
        }
        
        // 状態をアクティブに設定
        self.state.set(QueueState::Active);
        
        Ok(())
    }
    
    /// キューにアイテムを追加
    pub fn enqueue(&self, item: T, priority: TransferPriority, timeout_ms: u64) -> Result<(), TransportError> {
        // 状態チェック
        if self.state.get() == QueueState::Shutdown {
            return Err(TransportError::InternalError("キューはシャットダウン済み".to_string()));
        }
        
        // 現在時刻を取得
        let now = crate::core::time::current_timestamp();
        
        // キュー項目を作成
        let queue_item = QueueItem {
            data: item,
            enqueue_time: now,
            priority,
            timeout_ms,
        };
        
        // 適切なキューを取得
        let queues = self.queues.read().unwrap();
        let queue = queues.get(&priority).ok_or_else(|| {
            TransportError::InternalError(format!("優先度 {:?} のキューが見つかりません", priority))
        })?;
        
        // キューに追加
        let mut data = queue.data.lock().unwrap();
        
        // キューがいっぱいかチェック
        if data.len() >= queue.max_size {
            // 優先度に基づいて処理
            match priority {
                TransferPriority::Critical => {
                    // 重要なアイテムは常に受け入れる（必要なら最も古いアイテムを削除）
                    if !data.is_empty() {
                        data.pop_front(); // 最も古いアイテムを削除
                        queue.stats.dropped += 1;
                        self.stats.total_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                },
                _ => {
                    // 低優先度のアイテムはドロップ
                    queue.stats.dropped += 1;
                    self.stats.total_dropped.fetch_add(1, Ordering::Relaxed);
                    return Err(TransportError::ResourceExhausted(format!(
                        "{:?} キューがいっぱいです (サイズ: {})",
                        self.queue_type, queue.max_size
                    )));
                }
            }
        }
        
        // キューに追加
        data.push_back(queue_item);
        
        // 統計情報を更新
        queue.stats.enqueued += 1;
        queue.stats.current_depth = data.len();
        queue.stats.max_depth = queue.stats.max_depth.max(data.len());
        
        self.stats.total_enqueued.fetch_add(1, Ordering::Relaxed);
        self.stats.current_items.fetch_add(1, Ordering::Relaxed);
        
        // 待機中のデキュースレッドに通知
        self.notify_dequeue();
        
        Ok(())
    }
    
    /// キューからアイテムを取得（単一）
    pub fn dequeue(&self) -> Result<Option<T>, TransportError> {
        let result = self.dequeue_batch(1)?;
        Ok(result.into_iter().next())
    }
    
    /// キューからアイテムをバッチ取得
    pub fn dequeue_batch(&self, max_items: usize) -> Result<Vec<T>, TransportError> {
        if max_items == 0 {
            return Ok(Vec::new());
        }
        
        // 状態チェック
        if self.state.get() == QueueState::Shutdown {
            return Err(TransportError::InternalError("キューはシャットダウン済み".to_string()));
        }
        
        // 一時停止中はエラー
        if self.state.get() == QueueState::Paused {
            return Err(TransportError::InternalError("キューは一時停止中".to_string()));
        }
        
        let mut result = Vec::with_capacity(max_items);
        let queues = self.queues.read().unwrap();
        
        // 優先度順にキューを処理
        for priority in &[
            TransferPriority::Critical,
            TransferPriority::High,
            TransferPriority::Normal,
            TransferPriority::Low,
        ] {
            if result.len() >= max_items {
                break;
            }
            
            let queue = match queues.get(priority) {
                Some(q) => q,
                None => continue,
            };
            
            let mut data = queue.data.lock().unwrap();
            let current_time = crate::core::time::current_timestamp();
            
            // タイムアウトしたアイテムを削除
            let mut i = 0;
            while i < data.len() {
                let item = &data[i];
                if item.timeout_ms > 0 && current_time - item.enqueue_time > item.timeout_ms {
                    data.remove(i);
                    queue.stats.dropped += 1;
                    self.stats.total_dropped.fetch_add(1, Ordering::Relaxed);
                    self.stats.current_items.fetch_sub(1, Ordering::Relaxed);
                } else {
                    i += 1;
                }
            }
            
            // 残りのスペースを計算
            let remaining = max_items - result.len();
            
            // このキューから取得できるアイテム数
            let items_to_take = remaining.min(data.len());
            
            // アイテムを取得
            for _ in 0..items_to_take {
                if let Some(item) = data.pop_front() {
                    // 待機時間を計算
                    let wait_time = current_time - item.enqueue_time;
                    
                    // 統計情報を更新
                    queue.stats.dequeued += 1;
                    queue.stats.current_depth = data.len();
                    queue.stats.total_wait_time_us += wait_time * 1000; // ミリ秒→マイクロ秒
                    
                    if queue.stats.dequeued > 0 {
                        queue.stats.avg_wait_time_us = 
                            queue.stats.total_wait_time_us / queue.stats.dequeued;
                    }
                    
                    self.stats.total_dequeued.fetch_add(1, Ordering::Relaxed);
                    self.stats.current_items.fetch_sub(1, Ordering::Relaxed);
                    
                    // 結果に追加
                    result.push(item.data);
                }
            }
        }
        
        // バッチ統計を更新
        if !result.is_empty() {
            self.stats.total_batches.fetch_add(1, Ordering::Relaxed);
        }
        
        Ok(result)
    }
    
    /// キューが空かどうかをチェック
    pub fn is_empty(&self) -> bool {
        let queues = self.queues.read().unwrap();
        
        for queue in queues.values() {
            let data = queue.data.lock().unwrap();
            if !data.is_empty() {
                return false;
            }
        }
        
        true
    }
    
    /// キュー内のアイテム数を取得
    pub fn len(&self) -> usize {
        self.stats.current_items.load(Ordering::Relaxed)
    }
    
    /// キューの状態を設定
    pub fn set_state(&self, state: QueueState) {
        self.state.set(state);
        
        // アクティブになった場合は待機中のスレッドに通知
        if state == QueueState::Active {
            self.notify_dequeue();
        }
    }
    
    /// キューの状態を取得
    pub fn get_state(&self) -> QueueState {
        self.state.get()
    }
    
    /// 統計情報を取得
    pub fn get_stats(&self) -> BTreeMap<TransferPriority, QueueStats> {
        let queues = self.queues.read().unwrap();
        let mut result = BTreeMap::new();
        
        for (priority, queue) in queues.iter() {
            result.insert(*priority, queue.stats.clone());
        }
        
        result
    }
    
    /// 全体の統計情報を取得
    pub fn get_total_stats(&self) -> QueueStats {
        // 合計統計情報を計算
        QueueStats {
            enqueued: self.stats.total_enqueued.load(Ordering::Relaxed),
            dequeued: self.stats.total_dequeued.load(Ordering::Relaxed),
            current_depth: self.stats.current_items.load(Ordering::Relaxed),
            max_depth: self.get_max_depth(),
            dropped: self.stats.total_dropped.load(Ordering::Relaxed),
            batches: self.stats.total_batches.load(Ordering::Relaxed),
            total_wait_time_us: self.get_total_wait_time(),
            avg_wait_time_us: self.get_avg_wait_time(),
        }
    }
    
    /// キューをクリア
    pub fn clear(&self) {
        let queues = self.queues.read().unwrap();
        
        for queue in queues.values() {
            let mut data = queue.data.lock().unwrap();
            let dropped = data.len() as u64;
            data.clear();
            
            // 統計情報を更新
            queue.stats.dropped += dropped;
            queue.stats.current_depth = 0;
            
            self.stats.total_dropped.fetch_add(dropped, Ordering::Relaxed);
            self.stats.current_items.store(0, Ordering::Relaxed);
        }
    }
    
    /// キューが空になるまで待機
    pub fn wait_until_empty(&self, timeout_ms: u64) -> Result<bool, TransportError> {
        let start_time = crate::core::time::current_timestamp();
        
        while !self.is_empty() {
            // タイムアウトチェック
            if timeout_ms > 0 {
                let current_time = crate::core::time::current_timestamp();
                if current_time - start_time >= timeout_ms {
                    return Ok(false);
                }
            }
            
            // 少し待機
            let mut lock = self.mutex.lock().unwrap();
            let _ = self.condvar.wait_timeout(&mut lock, 10); // 10ms待機
        }
        
        Ok(true)
    }
    
    /// アイテムが利用可能になるまで待機
    pub fn wait_for_item(&self, timeout_ms: u64) -> Result<bool, TransportError> {
        if !self.is_empty() {
            return Ok(true);
        }
        
        let start_time = crate::core::time::current_timestamp();
        
        loop {
            // 状態チェック
            if self.state.get() == QueueState::Shutdown {
                return Err(TransportError::InternalError("キューはシャットダウン済み".to_string()));
            }
            
            // タイムアウトチェック
            if timeout_ms > 0 {
                let current_time = crate::core::time::current_timestamp();
                if current_time - start_time >= timeout_ms {
                    return Ok(false);
                }
            }
            
            // 条件変数で待機
            let mut lock = self.mutex.lock().unwrap();
            let remaining_ms = if timeout_ms > 0 {
                let current_time = crate::core::time::current_timestamp();
                let elapsed = current_time - start_time;
                if elapsed >= timeout_ms {
                    return Ok(false);
                }
                timeout_ms - elapsed
            } else {
                // タイムアウトなし
                u64::MAX
            };
            
            let _ = self.condvar.wait_timeout(&mut lock, remaining_ms);
            
            // 再チェック
            if !self.is_empty() {
                return Ok(true);
            }
        }
    }
    
    /// デキュースレッドに通知
    fn notify_dequeue(&self) {
        let _lock = self.mutex.lock().unwrap();
        self.condvar.notify_all();
    }
    
    /// 最大深度を取得
    fn get_max_depth(&self) -> usize {
        let queues = self.queues.read().unwrap();
        let mut max_depth = 0;
        
        for queue in queues.values() {
            max_depth = max_depth.max(queue.stats.max_depth);
        }
        
        max_depth
    }
    
    /// 合計待機時間を取得
    fn get_total_wait_time(&self) -> u64 {
        let queues = self.queues.read().unwrap();
        let mut total_wait_time = 0;
        
        for queue in queues.values() {
            total_wait_time += queue.stats.total_wait_time_us;
        }
        
        total_wait_time
    }
    
    /// 平均待機時間を取得
    fn get_avg_wait_time(&self) -> u64 {
        let dequeued = self.stats.total_dequeued.load(Ordering::Relaxed);
        let total_wait_time = self.get_total_wait_time();
        
        if dequeued > 0 {
            total_wait_time / dequeued
        } else {
            0
        }
    }
}

/// マルチキューマネージャ
/// 
/// 複数のキューを管理し、それらの間でロードバランシングを行います。
/// これは複数のCPUコアやネットワークカードキューに対応するために使用されます。
pub struct MultiQueueManager<T> {
    /// キュータイプ
    queue_type: QueueType,
    /// キューマネージャ群
    queues: Vec<Arc<PriorityQueueManager<T>>>,
    /// 状態
    state: AtomicQueueState,
    /// ラウンドロビンインデックス
    rr_index: AtomicUsize,
    /// 最小負荷ポリシー使用フラグ
    use_least_loaded: bool,
}

impl<T: Clone + Send + Sync + 'static> MultiQueueManager<T> {
    /// 新しいマルチキューマネージャを作成
    pub fn new(queue_type: QueueType, queue_count: usize, max_queue_size: usize, use_least_loaded: bool) -> Self {
        let mut queues = Vec::with_capacity(queue_count);
        
        for _ in 0..queue_count {
            let queue = Arc::new(PriorityQueueManager::new(queue_type, max_queue_size));
            queues.push(queue);
        }
        
        Self {
            queue_type,
            queues,
            state: AtomicQueueState::new(QueueState::Idle),
            rr_index: AtomicUsize::new(0),
            use_least_loaded,
        }
    }
    
    /// 初期化
    pub fn init(&self) -> Result<(), TransportError> {
        for queue in &self.queues {
            queue.init()?;
        }
        
        self.state.set(QueueState::Active);
        Ok(())
    }
    
    /// キューにアイテムを追加
    pub fn enqueue(&self, item: T, priority: TransferPriority, timeout_ms: u64) -> Result<(), TransportError> {
        // 状態チェック
        if self.state.get() == QueueState::Shutdown {
            return Err(TransportError::InternalError("キューはシャットダウン済み".to_string()));
        }
        
        // キューを選択
        let queue = self.select_queue_for_enqueue()?;
        
        // 選択したキューにエンキュー
        queue.enqueue(item, priority, timeout_ms)
    }
    
    /// キューからアイテムを取得
    pub fn dequeue(&self) -> Result<Option<T>, TransportError> {
        let result = self.dequeue_batch(1)?;
        Ok(result.into_iter().next())
    }
    
    /// キューからアイテムをバッチ取得
    pub fn dequeue_batch(&self, max_items: usize) -> Result<Vec<T>, TransportError> {
        if max_items == 0 {
            return Ok(Vec::new());
        }
        
        // 状態チェック
        if self.state.get() == QueueState::Shutdown {
            return Err(TransportError::InternalError("キューはシャットダウン済み".to_string()));
        }
        
        // 一時停止中はエラー
        if self.state.get() == QueueState::Paused {
            return Err(TransportError::InternalError("キューは一時停止中".to_string()));
        }
        
        // キューを選択
        let queue = self.select_queue_for_dequeue()?;
        
        // 選択したキューからデキュー
        queue.dequeue_batch(max_items)
    }
    
    /// すべてのキューが空かどうかをチェック
    pub fn is_empty(&self) -> bool {
        for queue in &self.queues {
            if !queue.is_empty() {
                return false;
            }
        }
        
        true
    }
    
    /// キュー内のアイテム数を取得
    pub fn len(&self) -> usize {
        let mut total = 0;
        
        for queue in &self.queues {
            total += queue.len();
        }
        
        total
    }
    
    /// すべてのキューの状態を設定
    pub fn set_state(&self, state: QueueState) {
        self.state.set(state);
        
        for queue in &self.queues {
            queue.set_state(state);
        }
    }
    
    /// 全体の状態を取得
    pub fn get_state(&self) -> QueueState {
        self.state.get()
    }
    
    /// 統計情報を取得
    pub fn get_stats(&self) -> Vec<BTreeMap<TransferPriority, QueueStats>> {
        let mut result = Vec::with_capacity(self.queues.len());
        
        for queue in &self.queues {
            result.push(queue.get_stats());
        }
        
        result
    }
    
    /// すべてのキューをクリア
    pub fn clear(&self) {
        for queue in &self.queues {
            queue.clear();
        }
    }
    
    /// エンキュー用のキューを選択
    fn select_queue_for_enqueue(&self) -> Result<&Arc<PriorityQueueManager<T>>, TransportError> {
        if self.queues.is_empty() {
            return Err(TransportError::InternalError("利用可能なキューがありません".to_string()));
        }
        
        if self.use_least_loaded {
            // 最小負荷のキューを選択
            let mut min_load = usize::MAX;
            let mut min_index = 0;
            
            for (i, queue) in self.queues.iter().enumerate() {
                let load = queue.len();
                if load < min_load {
                    min_load = load;
                    min_index = i;
                }
            }
            
            Ok(&self.queues[min_index])
        } else {
            // ラウンドロビン方式
            let index = self.rr_index.fetch_add(1, Ordering::Relaxed) % self.queues.len();
            Ok(&self.queues[index])
        }
    }
    
    /// デキュー用のキューを選択
    fn select_queue_for_dequeue(&self) -> Result<&Arc<PriorityQueueManager<T>>, TransportError> {
        if self.queues.is_empty() {
            return Err(TransportError::InternalError("利用可能なキューがありません".to_string()));
        }
        
        // 空でないキューを探す
        for queue in &self.queues {
            if !queue.is_empty() {
                return Ok(queue);
            }
        }
        
        // すべてのキューが空なら最初のものを返す
        Ok(&self.queues[0])
    }
} 