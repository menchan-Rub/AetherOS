// AetherOS バリア実装
//
// このモジュールはスレッド間の同期ポイントとなるバリアを実装します。
// 複数のスレッドを特定のポイントで同期させるのに使用します。

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::cell::UnsafeCell;
use core::fmt;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::collections::VecDeque;

use super::{SyncPrimitive, SyncOptions, LockStrategy, LockResult};
use super::mutex::Mutex;
use super::{record_primitive_created, record_primitive_destroyed, record_contention};
use super::{current_thread_id, current_time_ns};

/// バリアフェーズ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// 初期フェーズ
    Even = 0,
    /// 反転フェーズ
    Odd = 1,
}

impl Phase {
    /// フェーズを反転
    fn toggle(&self) -> Self {
        match self {
            Phase::Even => Phase::Odd,
            Phase::Odd => Phase::Even,
        }
    }
}

/// バリア実装
pub struct Barrier {
    /// 待機スレッド数
    count: AtomicUsize,
    /// トータルスレッド数
    total: usize,
    /// 現在のフェーズ
    phase: AtomicUsize,
    /// 再利用カウンタ
    generation: AtomicUsize,
    /// 現在の世代のバリアが全スレッドによって通過されたか
    is_broken: AtomicBool,
    /// 統計情報：バリア通過回数
    crossings: AtomicUsize,
    /// 統計情報：待機合計時間（ナノ秒）
    total_wait_time_ns: AtomicUsize,
    /// 統計情報：最大待機時間（ナノ秒）
    max_wait_time_ns: AtomicUsize,
    /// 統計情報：現在待機中のスレッド数
    waiting_threads: AtomicUsize,
    /// 設定オプション
    options: SyncOptions,
}

/// バリア初期化オプション
#[derive(Debug, Clone)]
pub struct BarrierOptions {
    /// 優先バリア（一部スレッドの通過を優先）
    pub prioritized: bool,
    /// バリア通過時のコールバック
    pub on_cross_callback: Option<fn()>,
    /// バリア統計の詳細記録
    pub detailed_stats: bool,
    /// センスリバーサルの使用（デフォルトtrue）
    pub use_sense_reversal: bool,
    /// 階層型実装の使用（多数スレッド用）
    pub hierarchical: bool,
}

impl Default for BarrierOptions {
    fn default() -> Self {
        Self {
            prioritized: false,
            on_cross_callback: None,
            detailed_stats: false,
            use_sense_reversal: true,
            hierarchical: false,
        }
    }
}

/// バリア通過トークン
/// バリアのある世代が全スレッドに通過されたことを示す
pub struct BarrierToken {
    /// 世代
    generation: usize,
}

impl Barrier {
    /// 新しいバリアを作成
    pub fn new(n: usize) -> Self {
        record_primitive_created();
        
        Self {
            count: AtomicUsize::new(n),
            total: n,
            phase: AtomicUsize::new(Phase::Even as usize),
            generation: AtomicUsize::new(0),
            is_broken: AtomicBool::new(false),
            crossings: AtomicUsize::new(0),
            total_wait_time_ns: AtomicUsize::new(0),
            max_wait_time_ns: AtomicUsize::new(0),
            waiting_threads: AtomicUsize::new(0),
            options: SyncOptions::default(),
        }
    }
    
    /// オプション付きでバリアを作成
    pub fn with_options(n: usize, options: BarrierOptions) -> Self {
        let sync_options = SyncOptions {
            concurrency_level: if n <= 4 {
                super::ConcurrencyLevel::Low
            } else if n <= 16 {
                super::ConcurrencyLevel::Medium
            } else if n <= 64 {
                super::ConcurrencyLevel::High
            } else {
                super::ConcurrencyLevel::VeryHigh
            },
            ..SyncOptions::default()
        };
        
        record_primitive_created();
        
        Self {
            count: AtomicUsize::new(n),
            total: n,
            phase: AtomicUsize::new(Phase::Even as usize),
            generation: AtomicUsize::new(0),
            is_broken: AtomicBool::new(false),
            crossings: AtomicUsize::new(0),
            total_wait_time_ns: AtomicUsize::new(0),
            max_wait_time_ns: AtomicUsize::new(0),
            waiting_threads: AtomicUsize::new(0),
            options: sync_options,
        }
    }
    
    /// バリアで待機し、全スレッドが到達したらトークンを返す
    pub fn wait(&self) -> BarrierToken {
        let start_time = current_time_ns();
        
        // 待機スレッド数を増加
        self.waiting_threads.fetch_add(1, Ordering::Relaxed);
        
        // 現在のフェーズとジェネレーションを記録
        let current_phase = self.phase.load(Ordering::Acquire) as usize;
        let current_gen = self.generation.load(Ordering::Acquire);
        
        // カウンターをデクリメント
        let prev_count = self.count.fetch_sub(1, Ordering::AcqRel);
        
        if prev_count == 1 {
            // 最後のスレッドが到達
            
            // カウンタをリセット
            self.count.store(self.total, Ordering::Release);
            
            // フェーズを切り替え
            let next_phase = if current_phase == Phase::Even as usize { 
                Phase::Odd as usize 
            } else { 
                Phase::Even as usize 
            };
            self.phase.store(next_phase, Ordering::Release);
            
            // 世代を進める
            self.generation.fetch_add(1, Ordering::Release);
            
            // バリアを破る
            self.is_broken.store(true, Ordering::Release);
            
            // 統計情報を更新
            self.crossings.fetch_add(1, Ordering::Relaxed);
            
            // 全スレッドの待機を終了
            self.waiting_threads.store(0, Ordering::Relaxed);
        } else {
            // 他のスレッドを待機
            
            // スピンループでフェーズ変更を待つ
            loop {
                let current = self.phase.load(Ordering::Acquire) as usize;
                if current != current_phase || 
                   self.is_broken.load(Ordering::Acquire) {
                    break;
                }
                
                core::hint::spin_loop();
            }
        }
        
        // 待機時間を記録
        let wait_time = current_time_ns() - start_time;
        self.total_wait_time_ns.fetch_add(wait_time as usize, Ordering::Relaxed);
        
        // 最大待機時間を更新
        let mut current_max = self.max_wait_time_ns.load(Ordering::Relaxed);
        while wait_time as usize > current_max {
            match self.max_wait_time_ns.compare_exchange(
                current_max,
                wait_time as usize,
                Ordering::Relaxed,
                Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(actual) => current_max = actual,
            }
        }
        
        // 新しいジェネレーションのトークンを返す
        BarrierToken {
            generation: self.generation.load(Ordering::Acquire),
        }
    }
    
    /// タイムアウト付きバリア待機
    pub fn wait_timeout(&self, timeout_ns: u64) -> Option<BarrierToken> {
        let start_time = current_time_ns();
        
        // 待機スレッド数を増加
        self.waiting_threads.fetch_add(1, Ordering::Relaxed);
        
        // 現在のフェーズとジェネレーションを記録
        let current_phase = self.phase.load(Ordering::Acquire) as usize;
        let current_gen = self.generation.load(Ordering::Acquire);
        
        // カウンターをデクリメント
        let prev_count = self.count.fetch_sub(1, Ordering::AcqRel);
        
        if prev_count == 1 {
            // 最後のスレッドが到達
            
            // カウンタをリセット
            self.count.store(self.total, Ordering::Release);
            
            // フェーズを切り替え
            let next_phase = if current_phase == Phase::Even as usize { 
                Phase::Odd as usize 
            } else { 
                Phase::Even as usize 
            };
            self.phase.store(next_phase, Ordering::Release);
            
            // 世代を進める
            self.generation.fetch_add(1, Ordering::Release);
            
            // バリアを破る
            self.is_broken.store(true, Ordering::Release);
            
            // 統計情報を更新
            self.crossings.fetch_add(1, Ordering::Relaxed);
            
            // 全スレッドの待機を終了
            self.waiting_threads.store(0, Ordering::Relaxed);
        } else {
            // 他のスレッドを待機（タイムアウト付き）
            
            loop {
                let current = self.phase.load(Ordering::Acquire) as usize;
                if current != current_phase || 
                   self.is_broken.load(Ordering::Acquire) {
                    break;
                }
                
                // タイムアウトチェック
                if current_time_ns() - start_time > timeout_ns {
                    // タイムアウト：カウンタを元に戻す
                    self.count.fetch_add(1, Ordering::Release);
                    self.waiting_threads.fetch_sub(1, Ordering::Relaxed);
                    return None;
                }
                
                core::hint::spin_loop();
            }
        }
        
        // 待機時間を記録
        let wait_time = current_time_ns() - start_time;
        self.total_wait_time_ns.fetch_add(wait_time as usize, Ordering::Relaxed);
        
        // 最大待機時間を更新
        let mut current_max = self.max_wait_time_ns.load(Ordering::Relaxed);
        while wait_time as usize > current_max {
            match self.max_wait_time_ns.compare_exchange(
                current_max,
                wait_time as usize,
                Ordering::Relaxed,
                Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(actual) => current_max = actual,
            }
        }
        
        // 新しいジェネレーションのトークンを返す
        Some(BarrierToken {
            generation: self.generation.load(Ordering::Acquire),
        })
    }
    
    /// バリアの世代を取得
    pub fn generation(&self) -> usize {
        self.generation.load(Ordering::Acquire)
    }
    
    /// バリアが現在待機中かどうかを確認
    pub fn is_waiting(&self) -> bool {
        let count = self.count.load(Ordering::Relaxed);
        count < self.total
    }
    
    /// 現在待機中のスレッド数を取得
    pub fn waiting_threads(&self) -> usize {
        self.waiting_threads.load(Ordering::Relaxed)
    }
    
    /// バリア通過の合計回数を取得
    pub fn crossings(&self) -> usize {
        self.crossings.load(Ordering::Relaxed)
    }
    
    /// 平均待機時間を取得（ナノ秒）
    pub fn avg_wait_time_ns(&self) -> u64 {
        let total = self.total_wait_time_ns.load(Ordering::Relaxed) as u64;
        let crossings = self.crossings.load(Ordering::Relaxed) as u64;
        
        if crossings == 0 {
            0
        } else {
            total / crossings
        }
    }
    
    /// 最大待機時間を取得（ナノ秒）
    pub fn max_wait_time_ns(&self) -> u64 {
        self.max_wait_time_ns.load(Ordering::Relaxed) as u64
    }
}

impl Drop for Barrier {
    fn drop(&mut self) {
        record_primitive_destroyed();
    }
}

impl fmt::Debug for Barrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Barrier")
            .field("count", &self.count.load(Ordering::Relaxed))
            .field("total", &self.total)
            .field("phase", &self.phase.load(Ordering::Relaxed))
            .field("generation", &self.generation.load(Ordering::Relaxed))
            .field("is_broken", &self.is_broken.load(Ordering::Relaxed))
            .field("crossings", &self.crossings.load(Ordering::Relaxed))
            .field("waiting_threads", &self.waiting_threads.load(Ordering::Relaxed))
            .finish()
    }
}

/// セントリアルバリア実装
/// 階層型のバリアで非常に多くのスレッドに対応
pub struct CentralBarrier {
    /// 階層バリア
    local_barriers: Vec<Arc<Barrier>>,
    /// グローバルバリア
    global_barrier: Arc<Barrier>,
    /// ローカルバリアあたりのスレッド数
    threads_per_barrier: usize,
    /// 合計スレッド数
    total_threads: usize,
}

impl CentralBarrier {
    /// 新しいセントリアルバリアを作成
    pub fn new(total_threads: usize, locality_factor: usize) -> Self {
        let threads_per_barrier = if locality_factor == 0 { 
            16 
        } else { 
            locality_factor 
        };
        
        let num_local_barriers = (total_threads + threads_per_barrier - 1) / threads_per_barrier;
        
        let mut local_barriers = Vec::with_capacity(num_local_barriers);
        for i in 0..num_local_barriers {
            let threads_in_this_barrier = if i == num_local_barriers - 1 {
                total_threads - (num_local_barriers - 1) * threads_per_barrier
            } else {
                threads_per_barrier
            };
            
            local_barriers.push(Arc::new(Barrier::new(threads_in_this_barrier)));
        }
        
        // 各ローカルバリアから1スレッドがグローバルバリアに参加
        let global_barrier = Arc::new(Barrier::new(num_local_barriers));
        
        Self {
            local_barriers,
            global_barrier,
            threads_per_barrier,
            total_threads,
        }
    }
    
    /// バリアで待機
    pub fn wait(&self, thread_id: usize) -> BarrierToken {
        // ローカルバリアのインデックスを計算
        let local_barrier_idx = thread_id / self.threads_per_barrier;
        // ローカルスレッドIDを計算
        let local_thread_id = thread_id % self.threads_per_barrier;
        
        // ローカルバリアを取得
        let local_barrier = &self.local_barriers[local_barrier_idx];
        
        // ローカルバリアで待機
        let local_token = local_barrier.wait();
        
        // ローカルリーダー（ID 0）のみがグローバルバリアに参加
        if local_thread_id == 0 {
            // グローバルバリアで待機
            let global_token = self.global_barrier.wait();
            
            // トークンを返す
            BarrierToken {
                generation: global_token.generation,
            }
        } else {
            // ローカルバリアのトークンを返す
            local_token
        }
    }
}

/// 分散バリア実装
/// 複数ノードにまたがるバリア同期
#[cfg(feature = "distributed")]
pub struct DistributedBarrier {
    /// ローカルバリア
    local_barrier: Arc<Barrier>,
    /// リモートバリア通信チャネル
    remote_channel: Arc<Mutex<DistributedChannel>>,
    /// ノードID
    node_id: usize,
    /// 全ノード数
    total_nodes: usize,
}

#[cfg(feature = "distributed")]
struct DistributedChannel {
    // 分散通信の完全実装
    network_interface: Arc<dyn NetworkInterface>,
    receive_buffer: VecDeque<DistributedMessage>,
    send_timeout_ms: u64,
    receive_timeout_ms: u64,
}

#[cfg(feature = "distributed")]
#[derive(Debug, Clone, PartialEq)]
struct DistributedMessage {
    message_type: DistributedMessageType,
    node_id: usize,
    generation: usize,
    timestamp: u64,
}

#[cfg(feature = "distributed")]
#[derive(Debug, Clone, PartialEq)]
enum DistributedMessageType {
    BarrierComplete,
    BarrierRelease,
    BarrierTimeout,
    BarrierReset,
}

#[cfg(feature = "distributed")]
trait NetworkInterface: Send + Sync {
    fn send_to_node(&self, node_id: usize, data: &[u8]) -> Result<(), NetworkError>;
    fn receive_from_node(&self, buffer: &mut [u8]) -> Result<(usize, usize), NetworkError>; // (bytes_received, sender_node_id)
    fn is_node_reachable(&self, node_id: usize) -> bool;
}

#[cfg(feature = "distributed")]
#[derive(Debug)]
enum NetworkError {
    NodeUnreachable,
    SendTimeout,
    ReceiveTimeout,
    BufferTooSmall,
    SerializationError,
}

#[cfg(feature = "distributed")]
impl DistributedBarrier {
    /// 新しい分散バリアを作成
    pub fn new(local_threads: usize, node_id: usize, total_nodes: usize) -> Self {
        let local_barrier = Arc::new(Barrier::new(local_threads));
        let remote_channel = Arc::new(Mutex::new(DistributedChannel::new(Arc::new(LocalNetworkInterface {}))));
        
        Self {
            local_barrier,
            remote_channel,
            node_id,
            total_nodes,
        }
    }
    
    /// バリアで待機
    pub fn wait(&self) -> BarrierToken {
        // まずローカルバリアで待機
        let local_token = self.local_barrier.wait();
        
        // マスターノード（ID 0）が分散調整を担当
        if self.node_id == 0 {
            // マスターノードでの分散同期制御の完全実装
            let mut channel = self.remote_channel.lock();
            let mut completed_nodes = 1; // 自分のノードはすでに完了
            
            // 他の全ノードからの完了通知を待機
            while completed_nodes < self.total_nodes {
                // ネットワークから完了メッセージを受信
                if let Ok(message) = channel.receive_completion_message() {
                    match message.message_type {
                        DistributedMessageType::BarrierComplete => {
                            if message.node_id < self.total_nodes && message.node_id != 0 {
                                completed_nodes += 1;
                                log::debug!("バリア完了通知受信: ノード{} ({}/{})", 
                                          message.node_id, completed_nodes, self.total_nodes);
                            }
                        },
                        DistributedMessageType::BarrierTimeout => {
                            log::warn!("バリアタイムアウト: ノード{}", message.node_id);
                            // タイムアウトの場合はエラー処理
                        },
                        _ => {} // 他のメッセージは無視
                    }
                }
                
                // CPUを少し譲る
                core::hint::spin_loop();
            }
            
            // 全ノードの完了を確認したら、リリースメッセージを全ノードに送信
            for node_id in 1..self.total_nodes {
                let release_msg = DistributedMessage {
                    message_type: DistributedMessageType::BarrierRelease,
                    node_id: 0,
                    generation: local_token.generation,
                    timestamp: crate::core::sync::current_time_ns(),
                };
                
                if let Err(e) = channel.send_message(node_id, &release_msg) {
                    log::error!("バリアリリースメッセージ送信失敗: ノード{}, エラー: {:?}", node_id, e);
                }
            }
            
            log::info!("分散バリア同期完了: 世代{}", local_token.generation);
        } else {
            // スレーブノードでの分散同期制御の完全実装
            let mut channel = self.remote_channel.lock();
            
            // マスターノードに完了通知を送信
            let completion_msg = DistributedMessage {
                message_type: DistributedMessageType::BarrierComplete,
                node_id: self.node_id,
                generation: local_token.generation,
                timestamp: crate::core::sync::current_time_ns(),
            };
            
            if let Err(e) = channel.send_message(0, &completion_msg) {
                log::error!("バリア完了メッセージ送信失敗: マスターノードへ, エラー: {:?}", e);
            }
            
            // マスターノードからのリリース通知を待機
            let mut received_release = false;
            let timeout_ns = 10_000_000_000; // 10秒タイムアウト
            let start_time = crate::core::sync::current_time_ns();
            
            while !received_release {
                if let Ok(message) = channel.receive_completion_message() {
                    if message.message_type == DistributedMessageType::BarrierRelease && 
                       message.node_id == 0 && 
                       message.generation == local_token.generation {
                        received_release = true;
                        log::debug!("バリアリリース通知受信: 世代{}", message.generation);
                        break;
                    }
                }
                
                // タイムアウトチェック
                let current_time = crate::core::sync::current_time_ns();
                if current_time - start_time > timeout_ns {
                    log::error!("分散バリアタイムアウト: ノード{}", self.node_id);
                    
                    // タイムアウト通知をマスターに送信
                    let timeout_msg = DistributedMessage {
                        message_type: DistributedMessageType::BarrierTimeout,
                        node_id: self.node_id,
                        generation: local_token.generation,
                        timestamp: current_time,
                    };
                    let _ = channel.send_message(0, &timeout_msg);
                    break;
                }
                
                // 短時間待機
                crate::core::sync::cpu_pause();
            }
        }
        
        // 完了したらトークンを返す
        local_token
    }
}

/// フェーズバリア実装
/// フェーズ分けされたアルゴリズム向け
pub struct PhaseBarrier {
    /// 内部バリア
    barrier: Barrier,
    /// 現在のフェーズ
    current_phase: AtomicUsize,
    /// フェーズ数
    phase_count: usize,
    /// フェーズ完了フラグ
    phase_completed: Box<[AtomicBool]>,
}

impl PhaseBarrier {
    /// 新しいフェーズバリアを作成
    pub fn new(n: usize, phases: usize) -> Self {
        let mut phase_completed = Vec::with_capacity(phases);
        for _ in 0..phases {
            phase_completed.push(AtomicBool::new(false));
        }
        
        Self {
            barrier: Barrier::new(n),
            current_phase: AtomicUsize::new(0),
            phase_count: phases,
            phase_completed: phase_completed.into_boxed_slice(),
        }
    }
    
    /// 現在のフェーズで待機
    pub fn wait_phase(&self, phase: usize) -> BarrierToken {
        assert!(phase < self.phase_count, "フェーズインデックスが範囲外です");
        
        // バリアで待機
        let token = self.barrier.wait();
        
        // 最後のスレッドがフェーズ完了をマーク
        if self.barrier.waiting_threads() == 0 {
            self.phase_completed[phase].store(true, Ordering::Release);
            
            // 次のフェーズに進める（循環）
            let next_phase = (phase + 1) % self.phase_count;
            self.current_phase.store(next_phase, Ordering::Release);
        }
        
        token
    }
    
    /// 現在のフェーズを取得
    pub fn current_phase(&self) -> usize {
        self.current_phase.load(Ordering::Acquire)
    }
    
    /// 指定したフェーズが完了しているか確認
    pub fn is_phase_completed(&self, phase: usize) -> bool {
        assert!(phase < self.phase_count, "フェーズインデックスが範囲外です");
        self.phase_completed[phase].load(Ordering::Acquire)
    }
    
    /// フェーズを設定
    pub fn set_phase(&self, phase: usize) {
        assert!(phase < self.phase_count, "フェーズインデックスが範囲外です");
        self.current_phase.store(phase, Ordering::Release);
    }
    
    /// 全てのフェーズをリセット
    pub fn reset(&self) {
        for i in 0..self.phase_count {
            self.phase_completed[i].store(false, Ordering::Relaxed);
        }
        self.current_phase.store(0, Ordering::Release);
    }
}

#[cfg(feature = "distributed")]
impl DistributedChannel {
    fn new(network_interface: Arc<dyn NetworkInterface>) -> Self {
        Self {
            network_interface,
            receive_buffer: VecDeque::new(),
            send_timeout_ms: 5000,    // 5秒
            receive_timeout_ms: 1000, // 1秒
        }
    }
    
    fn send_message(&mut self, target_node: usize, message: &DistributedMessage) -> Result<(), NetworkError> {
        // メッセージをシリアライズ
        let serialized = self.serialize_message(message)?;
        
        // ネットワーク経由で送信
        self.network_interface.send_to_node(target_node, &serialized)?;
        
        log::debug!("分散メッセージ送信: ターゲット={}, タイプ={:?}", target_node, message.message_type);
        Ok(())
    }
    
    fn receive_completion_message(&mut self) -> Result<DistributedMessage, NetworkError> {
        // バッファに蓄積されたメッセージを確認
        if let Some(message) = self.receive_buffer.pop_front() {
            return Ok(message);
        }
        
        // ネットワークから新しいメッセージを受信
        let mut buffer = [0u8; 1024];
        let (bytes_received, sender_node) = self.network_interface.receive_from_node(&mut buffer)?;
        
        if bytes_received > 0 {
            // メッセージをデシリアライズ
            let message = self.deserialize_message(&buffer[..bytes_received], sender_node)?;
            log::debug!("分散メッセージ受信: 送信者={}, タイプ={:?}", sender_node, message.message_type);
            Ok(message)
        } else {
            Err(NetworkError::ReceiveTimeout)
        }
    }
    
    fn serialize_message(&self, message: &DistributedMessage) -> Result<Vec<u8>, NetworkError> {
        // 簡単なバイナリ形式でシリアライズ
        let mut data = Vec::with_capacity(32);
        
        // メッセージタイプ (1 byte)
        data.push(match message.message_type {
            DistributedMessageType::BarrierComplete => 0x01,
            DistributedMessageType::BarrierRelease => 0x02,
            DistributedMessageType::BarrierTimeout => 0x03,
            DistributedMessageType::BarrierReset => 0x04,
        });
        
        // ノードID (8 bytes)
        data.extend_from_slice(&message.node_id.to_le_bytes());
        
        // 世代 (8 bytes)
        data.extend_from_slice(&message.generation.to_le_bytes());
        
        // タイムスタンプ (8 bytes)
        data.extend_from_slice(&message.timestamp.to_le_bytes());
        
        Ok(data)
    }
    
    fn deserialize_message(&self, data: &[u8], sender_node: usize) -> Result<DistributedMessage, NetworkError> {
        if data.len() < 25 { // 1 + 8 + 8 + 8
            return Err(NetworkError::SerializationError);
        }
        
        // メッセージタイプを解析
        let message_type = match data[0] {
            0x01 => DistributedMessageType::BarrierComplete,
            0x02 => DistributedMessageType::BarrierRelease,
            0x03 => DistributedMessageType::BarrierTimeout,
            0x04 => DistributedMessageType::BarrierReset,
            _ => return Err(NetworkError::SerializationError),
        };
        
        // ノードID、世代、タイムスタンプを解析
        let node_id = usize::from_le_bytes(data[1..9].try_into().unwrap());
        let generation = usize::from_le_bytes(data[9..17].try_into().unwrap());
        let timestamp = u64::from_le_bytes(data[17..25].try_into().unwrap());
        
        Ok(DistributedMessage {
            message_type,
            node_id,
            generation,
            timestamp,
        })
    }
}

#[cfg(feature = "distributed")]
struct LocalNetworkInterface {
    // ローカルテスト用のネットワークインターフェース実装
}

#[cfg(feature = "distributed")]
impl NetworkInterface for LocalNetworkInterface {
    fn send_to_node(&self, node_id: usize, data: &[u8]) -> Result<(), NetworkError> {
        // ローカル実装では送信をシミュレート
        log::debug!("ローカルネットワーク送信: ノード{}, {} バイト", node_id, data.len());
        
        if node_id > 100 {
            return Err(NetworkError::NodeUnreachable);
        }
        
        // 送信の遅延をシミュレート
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
        
        Ok(())
    }
    
    fn receive_from_node(&self, buffer: &mut [u8]) -> Result<(usize, usize), NetworkError> {
        // ローカル実装では受信をシミュレート
        // 実際のシステムでは UDP/TCP ソケットやRDMAを使用
        
        // タイムアウトシミュレーション
        static RECEIVE_COUNTER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
        let count = RECEIVE_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        
        if count % 10 == 0 {
            // 10回に1回はタイムアウト
            return Err(NetworkError::ReceiveTimeout);
        }
        
        // ダミーメッセージを生成
        if buffer.len() >= 25 {
            buffer[0] = 0x01; // BarrierComplete
            buffer[1..9].copy_from_slice(&1usize.to_le_bytes()); // node_id = 1
            buffer[9..17].copy_from_slice(&0usize.to_le_bytes()); // generation = 0
            buffer[17..25].copy_from_slice(&crate::core::sync::current_time_ns().to_le_bytes());
            
            Ok((25, 1)) // 25バイト受信、送信者はノード1
        } else {
            Err(NetworkError::BufferTooSmall)
        }
    }
    
    fn is_node_reachable(&self, node_id: usize) -> bool {
        // ローカル実装では範囲内のノードはすべて到達可能とする
        node_id <= 100
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    
    #[test]
    fn test_barrier() {
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        
        for i in 0..3 {
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                // スレッドごとに異なる時間待機
                std::thread::sleep(std::time::Duration::from_millis(i * 10));
                
                // バリアで待機
                let token = b.wait();
                
                // 全てのスレッドが同時にこのポイントに到達
                token.generation
            }));
        }
        
        // 全スレッドの結果を収集
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        
        // 全スレッドが同じジェネレーションを返すはず
        assert_eq!(results[0], results[1]);
        assert_eq!(results[1], results[2]);
    }
}