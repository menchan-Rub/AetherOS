// AetherOS ネットワークトランスポート層
//
// このモジュールは分散型システム間での通信機能を提供します。
// - リモートノード間の通信プロトコル（TCP/IP, RDMA, QUIC等）
// - テレページ転送機能（ゼロコピー対応）
// - 信頼性とQoS保証された高性能データ転送
// - マルチプロトコルサポートと動的フェイルオーバー
// - ハードウェアオフロード最適化

use crate::core::memory::telepage::{TelepageId, NodeId};
use crate::core::sync::{Mutex, RwLock, Condvar};
use crate::core::network::protocol::{
    TransportProtocol, TransportError, TelepageMessageType, 
    TransportConfig, EncryptionType, SecurityLevel, 
    TransferPriority, CongestionAlgorithm, ConnectionType
};
use crate::core::network::stats::{TransportStats, ConnectionStats};
use crate::core::network::crypto::{CryptoEngine, EncryptedSession, CryptoConfig};
use crate::core::network::device::{
    NetworkDevice, TcpSocket, UdpSocket, RdmaDevice,
    RdmaMemoryRegion, RdmaQueuePair, NetworkAddress
};
use crate::core::network::zerocopy::{ZeroCopyBuffer, ZeroCopyBufferView};

use alloc::vec::Vec;
use alloc::string::{String, ToString};
use alloc::collections::{BTreeMap, VecDeque, BinaryHeap};
use alloc::sync::Arc;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;
use core::cmp::{Ordering as CmpOrdering, Reverse};
use core::thread;

/// トランスポート層の状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    /// 初期化中
    Initializing,
    /// 動作中
    Running,
    /// 一時停止中
    Paused,
    /// シャットダウン中
    ShuttingDown,
    /// シャットダウン完了
    Shutdown,
}

/// 接続状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// 初期化中
    Initializing,
    /// 接続中
    Connecting,
    /// 確立済み
    Established,
    /// 切断中
    Disconnecting,
    /// 切断済み
    Disconnected,
    /// エラー発生
    Error,
    /// 再接続待機中
    WaitingReconnect,
}

/// 転送モード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferMode {
    /// 同期転送（ブロッキング）
    Synchronous,
    /// 非同期転送（ノンブロッキング）
    Asynchronous,
    /// ストリーミング転送（継続的）
    Streaming,
    /// バッチ転送（一括処理）
    Batched,
}

/// テレページ転送状態
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelepageTransferState {
    /// テレページID
    pub id: TelepageId,
    /// 転送元ノード
    pub source_node: NodeId,
    /// 転送先ノード
    pub target_node: NodeId,
    /// 総バイト数
    pub total_bytes: usize,
    /// 転送済みバイト数
    pub transferred_bytes: usize,
    /// 開始時刻
    pub start_time: u64,
    /// 最終更新時刻
    pub last_update: u64,
    /// 状態
    pub state: TelepageTransferStatus,
    /// 優先度
    pub priority: TransferPriority,
    /// 転送エラー（存在する場合）
    pub error: Option<TransportError>,
    /// メタデータ
    pub metadata: BTreeMap<String, String>,
}

/// テレページ転送ステータス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelepageTransferStatus {
    /// 初期化中
    Initializing,
    /// リクエスト送信中
    Requesting,
    /// 転送中
    Transferring,
    /// 検証中
    Verifying,
    /// 完了
    Completed,
    /// 失敗
    Failed,
    /// キャンセル
    Canceled,
    /// 一時停止
    Paused,
}

/// 転送オプション
#[derive(Debug, Clone)]
pub struct TransferOptions {
    /// 転送モード
    pub mode: TransferMode,
    /// 優先度
    pub priority: TransferPriority,
    /// タイムアウト（ミリ秒、0=無限）
    pub timeout_ms: u64,
    /// 再試行回数
    pub retries: u32,
    /// 再試行間隔（ミリ秒）
    pub retry_interval_ms: u64,
    /// 圧縮を使用
    pub use_compression: bool,
    /// 暗号化を使用
    pub use_encryption: bool,
    /// チェックサム検証を使用
    pub use_checksum: bool,
    /// ゼロコピー転送を使用
    pub use_zero_copy: bool,
    /// ハードウェアオフロードを使用
    pub use_hardware_offload: bool,
    /// 進捗通知間隔（バイト単位、0=通知なし）
    pub progress_interval_bytes: usize,
    /// 複数接続を使用
    pub use_multiple_connections: bool,
    /// デルタ転送を使用（差分のみ）
    pub use_delta_transfer: bool,
    /// 前方誤り訂正を使用
    pub use_forward_error_correction: bool,
    /// 転送メタデータ
    pub metadata: BTreeMap<String, String>,
}

impl Default for TransferOptions {
    fn default() -> Self {
        Self {
            mode: TransferMode::Asynchronous,
            priority: TransferPriority::Normal,
            timeout_ms: 30000, // 30秒
            retries: 3,
            retry_interval_ms: 1000, // 1秒
            use_compression: true,
            use_encryption: true,
            use_checksum: true,
            use_zero_copy: true,
            use_hardware_offload: true,
            progress_interval_bytes: 1024 * 1024, // 1MB
            use_multiple_connections: false,
            use_delta_transfer: false,
            use_forward_error_correction: false,
            metadata: BTreeMap::new(),
        }
    }
}

/// 接続情報
#[derive(Debug)]
struct ConnectionInfo {
    /// ノードID
    node_id: NodeId,
    /// 接続状態
    state: ConnectionState,
    /// 使用中のプロトコル
    protocol: TransportProtocol,
    /// 暗号化セッション（存在する場合）
    crypto_session: Option<Box<dyn EncryptedSession>>,
    /// TCPソケット（TCP接続の場合）
    tcp_socket: Option<Box<dyn TcpSocket>>,
    /// UDPソケット（UDP/QUIC接続の場合）
    udp_socket: Option<Box<dyn UdpSocket>>,
    /// RDMAキューペア（RDMA接続の場合）
    rdma_queue_pair: Option<Box<dyn RdmaQueuePair>>,
    /// RDMAメモリ領域（RDMA接続の場合）
    rdma_memory_regions: Vec<Arc<dyn RdmaMemoryRegion>>,
    /// ゼロコピーバッファ（存在する場合）
    zero_copy_buffers: Vec<Arc<ZeroCopyBuffer>>,
    /// 接続設定
    config: TransportConfig,
    /// 統計情報
    stats: ConnectionStats,
    /// 最終活動時間
    last_activity: AtomicU64,
    /// 送信キュー
    send_queue: Mutex<VecDeque<QueuedMessage>>,
    /// 受信バッファ
    recv_buffer: Mutex<Vec<u8>>,
    /// 確立時刻
    established_time: u64,
    /// 再接続カウント
    reconnect_count: AtomicU32,
    /// 再接続バックオフ
    reconnect_backoff_ms: AtomicU64,
    /// エラーカウント
    error_count: AtomicU32,
}

/// キュー内のメッセージ
#[derive(Debug)]
struct QueuedMessage {
    /// メッセージデータ
    data: Vec<u8>,
    /// 優先度
    priority: TransferPriority,
    /// エンキュー時刻
    enqueue_time: u64,
    /// タイムアウト（ミリ秒、0=無限）
    timeout_ms: u64,
    /// コールバック（オプション）
    completion_callback: Option<CompletionCallback>,
    /// ユーザーデータ
    user_data: u64,
}

/// 完了コールバック型
type CompletionCallback = fn(result: Result<usize, TransportError>, user_data: u64);

/// 保留中のテレページリクエスト
#[derive(Debug)]
struct PendingTelepageRequest {
    /// テレページID
    id: TelepageId,
    /// リクエスト元ノード
    requester: NodeId,
    /// リクエスト時間
    request_time: u64,
    /// タイムアウト（ミリ秒）
    timeout_ms: u64,
    /// 再試行回数
    retry_count: u32,
    /// 最大再試行回数
    max_retries: u32,
    /// 転送オプション
    options: TransferOptions,
    /// 転送状態
    state: TelepageTransferState,
    /// コールバック（オプション）
    completion_callback: Option<TelepageCompletionCallback>,
    /// ユーザーデータ
    user_data: u64,
}

/// テレページ完了コールバック型
type TelepageCompletionCallback = fn(result: Result<TelepageTransferState, TransportError>, user_data: u64);

/// 接続ハンドラ
#[derive(Debug)]
struct ConnectionHandler {
    /// ノードID
    node_id: NodeId,
    /// 接続情報
    connection: Arc<ConnectionInfo>,
    /// 送信スレッド実行中フラグ
    sender_running: AtomicBool,
    /// 受信スレッド実行中フラグ
    receiver_running: AtomicBool,
    /// キープアライブスレッド実行中フラグ
    keepalive_running: AtomicBool,
    /// 送信条件変数
    send_condvar: Condvar,
    /// 送信ロック
    send_mutex: Mutex<()>,
    /// メッセージ完了イベント
    completion_queue: Mutex<Vec<(u64, Result<usize, TransportError>)>>,
}

/// ノードアドレス情報
#[derive(Debug, Clone)]
struct NodeAddressInfo {
    /// ノードID
    node_id: NodeId,
    /// プライマリIPアドレス
    primary_address: NetworkAddress,
    /// セカンダリIPアドレス（存在する場合）
    secondary_addresses: Vec<NetworkAddress>,
    /// 最終更新時刻
    last_updated: u64,
    /// ノード名（存在する場合）
    node_name: Option<String>,
    /// ルーティングメトリック
    routing_metric: u32,
    /// プロトコル優先順位
    protocol_preferences: Vec<TransportProtocol>,
}

/// プロトコルハンドラ
trait ProtocolHandler: Send + Sync {
    /// プロトコルタイプを取得
    fn protocol_type(&self) -> TransportProtocol;
    
    /// 接続を確立
    fn connect(&self, node_id: NodeId, addr: &NetworkAddress, config: &TransportConfig) 
        -> Result<Arc<ConnectionInfo>, TransportError>;
    
    /// データを送信
    fn send(&self, connection: &ConnectionInfo, data: &[u8], options: &TransferOptions) 
        -> Result<usize, TransportError>;
    
    /// データを受信
    fn receive(&self, connection: &ConnectionInfo, buffer: &mut [u8]) 
        -> Result<usize, TransportError>;
    
    /// 接続を閉じる
    fn disconnect(&self, connection: &ConnectionInfo) -> Result<(), TransportError>;
    
    /// ポーリング処理
    fn poll(&self, connection: &ConnectionInfo) -> Result<bool, TransportError>;
    
    /// キープアライブを送信
    fn send_keepalive(&self, connection: &ConnectionInfo) -> Result<(), TransportError>;
}

/// トランスポート層のインターフェース
pub struct TransportLayer {
    /// 状態
    state: AtomicTransportState,
    /// 設定
    config: RwLock<TransportConfig>,
    /// リモートノードへの接続状態
    connections: RwLock<BTreeMap<NodeId, Arc<ConnectionHandler>>>,
    /// 保留中のテレページリクエスト
    pending_requests: RwLock<BTreeMap<TelepageId, PendingTelepageRequest>>,
    /// アクティブな転送
    active_transfers: RwLock<BTreeMap<u64, TelepageTransferState>>,
    /// 暗号化エンジン
    crypto_engine: Arc<CryptoEngine>,
    /// 統計情報
    stats: Arc<TransportStats>,
    /// 次の転送ID
    next_transfer_id: AtomicU64,
    /// ノードアドレス情報
    node_addresses: RwLock<BTreeMap<NodeId, NodeAddressInfo>>,
    /// プロトコルハンドラー
    protocol_handlers: RwLock<BTreeMap<TransportProtocol, Arc<dyn ProtocolHandler>>>,
    /// 高優先度キュー
    high_priority_queue: Mutex<BinaryHeap<Reverse<PrioritizedTask>>>,
    /// 通常優先度キュー
    normal_priority_queue: Mutex<VecDeque<PrioritizedTask>>,
    /// 低優先度キュー
    low_priority_queue: Mutex<VecDeque<PrioritizedTask>>,
    /// タスク条件変数
    task_condvar: Condvar,
    /// タスクロック
    task_mutex: Mutex<()>,
    /// 処理スレッド実行中フラグ
    processor_running: AtomicBool,
    /// シャットダウンフラグ
    shutdown_requested: AtomicBool,
}

/// アトミックトランスポート状態
struct AtomicTransportState(AtomicUsize);

impl AtomicTransportState {
    /// 新しい状態を作成
    fn new(state: TransportState) -> Self {
        Self(AtomicUsize::new(state as usize))
    }
    
    /// 状態を設定
    fn set(&self, state: TransportState) {
        self.0.store(state as usize, Ordering::SeqCst);
    }
    
    /// 状態を取得
    fn get(&self) -> TransportState {
        match self.0.load(Ordering::SeqCst) {
            0 => TransportState::Initializing,
            1 => TransportState::Running,
            2 => TransportState::Paused,
            3 => TransportState::ShuttingDown,
            _ => TransportState::Shutdown,
        }
    }
}

/// 優先順位付きタスク
#[derive(Debug)]
struct PrioritizedTask {
    /// 優先度
    priority: TransferPriority,
    /// 登録時刻
    enqueue_time: u64,
    /// タスクタイプ
    task_type: TaskType,
    /// タスクID
    id: u64,
}

/// タスクタイプ
#[derive(Debug)]
enum TaskType {
    /// 接続確立
    Connect(NodeId),
    /// メッセージ送信
    Send(NodeId, Vec<u8>, TransferOptions, Option<CompletionCallback>, u64),
    /// テレページリクエスト
    TelepageRequest(NodeId, TelepageId, TransferOptions, Option<TelepageCompletionCallback>, u64),
    /// テレページデータ送信
    TelepageData(NodeId, TelepageId, Vec<u8>, TransferOptions),
    /// 接続ポーリング
    Poll(NodeId),
    /// 接続切断
    Disconnect(NodeId),
    /// タイムアウト処理
    Timeout(u64),
    /// キープアライブ送信
    Keepalive(NodeId),
    /// 統計情報更新
    UpdateStats,
    /// カスタムタスク
    Custom(u64, Box<dyn FnOnce() -> Result<(), TransportError> + Send>),
}

impl PartialEq for PrioritizedTask {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.enqueue_time == other.enqueue_time
    }
}

impl Eq for PrioritizedTask {}

impl PartialOrd for PrioritizedTask {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedTask {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        // 優先度で比較（高いものが先）
        match self.priority.cmp(&other.priority) {
            CmpOrdering::Equal => {
                // 同じ優先度なら時間で比較（古いものが先）
                self.enqueue_time.cmp(&other.enqueue_time)
            },
            other => other,
        }
    }
}

impl TransportLayer {
    /// 新しいトランスポート層を作成
    pub fn new(config: TransportConfig) -> Self {
        let crypto_config = CryptoConfig {
            encryption_type: config.encryption,
            security_level: config.security_level,
            ..Default::default()
        };
        
        let crypto_engine = Arc::new(CryptoEngine::new(crypto_config));
        let stats = Arc::new(TransportStats::new());
        
        Self {
            state: AtomicTransportState::new(TransportState::Initializing),
            config: RwLock::new(config),
            connections: RwLock::new(BTreeMap::new()),
            pending_requests: RwLock::new(BTreeMap::new()),
            active_transfers: RwLock::new(BTreeMap::new()),
            crypto_engine,
            stats,
            next_transfer_id: AtomicU64::new(1),
            node_addresses: RwLock::new(BTreeMap::new()),
            protocol_handlers: RwLock::new(BTreeMap::new()),
            high_priority_queue: Mutex::new(BinaryHeap::new()),
            normal_priority_queue: Mutex::new(VecDeque::new()),
            low_priority_queue: Mutex::new(VecDeque::new()),
            task_condvar: Condvar::new(),
            task_mutex: Mutex::new(()),
            processor_running: AtomicBool::new(false),
            shutdown_requested: AtomicBool::new(false),
        }
    }
    
    /// トランスポート層を初期化
    pub fn init(&self) -> Result<(), TransportError> {
        // プロトコルハンドラーを登録
        self.register_protocol_handlers()?;
        
        // スレッドプールを初期化
        
        // プロセッサースレッドを開始
        self.start_processor_thread()?;
        
        // 状態を更新
        self.state.set(TransportState::Running);
        
        Ok(())
    }
    
    /// プロトコルハンドラを登録
    fn register_protocol_handlers(&self) -> Result<(), TransportError> {
        // 各プロトコルに対応するハンドラを実際に作成・登録
        let mut handlers = self.protocol_handlers.write().map_err(|_| 
            TransportError::InternalError("プロトコルハンドラロック取得失敗".to_string()))?;
        
        // TCPプロトコルハンドラを登録
        handlers.insert(TransportProtocol::Tcp, Arc::new(TcpProtocolHandler::new()));
        
        // RDMAプロトコルハンドラを登録
        handlers.insert(TransportProtocol::Rdma, Arc::new(RdmaProtocolHandler::new()));
        
        // QUICプロトコルハンドラを登録
        handlers.insert(TransportProtocol::Quic, Arc::new(QuicProtocolHandler::new()));
        
        log::info!("プロトコルハンドラ登録完了: {} 個のハンドラ", handlers.len());
        
        Ok(())
    }
    
    /// プロセッサスレッドを開始
    fn start_processor_thread(&self) -> Result<(), TransportError> {
        // プロセッサが既に実行中の場合はエラー
        if self.processor_running.load(Ordering::SeqCst) {
            return Err(TransportError::InternalError("プロセッサスレッドは既に実行中です".to_string()));
        }
        
        // プロセッサ実行フラグを設定
        self.processor_running.store(true, Ordering::SeqCst);
        
        // 実際にワーカースレッドを開始
        let transport_layer = Arc::new(self);
        
        // メインプロセッサスレッド
        let main_processor = transport_layer.clone();
        crate::core::process::spawn_kernel_task("transport-processor", 10, move || {
            log::info!("トランスポートプロセッサスレッド開始");
            main_processor.processor_main_loop();
            log::info!("トランスポートプロセッサスレッド終了");
        }).map_err(|_| TransportError::InternalError("メインプロセッサスレッド開始失敗".to_string()))?;
        
        // 送信ワーカースレッド
        let send_worker = transport_layer.clone();
        crate::core::process::spawn_kernel_task("transport-sender", 8, move || {
            log::info!("トランスポート送信ワーカースレッド開始");
            send_worker.send_worker_loop();
            log::info!("トランスポート送信ワーカースレッド終了");
        }).map_err(|_| TransportError::InternalError("送信ワーカースレッド開始失敗".to_string()))?;
        
        // 受信ワーカースレッド
        let recv_worker = transport_layer.clone();
        crate::core::process::spawn_kernel_task("transport-receiver", 8, move || {
            log::info!("トランスポート受信ワーカースレッド開始");
            recv_worker.receive_worker_loop();
            log::info!("トランスポート受信ワーカースレッド終了");
        }).map_err(|_| TransportError::InternalError("受信ワーカースレッド開始失敗".to_string()))?;
        
        // 統計更新スレッド
        let stats_worker = transport_layer.clone();
        crate::core::process::spawn_kernel_task("transport-stats", 5, move || {
            log::info!("トランスポート統計更新スレッド開始");
            stats_worker.stats_worker_loop();
            log::info!("トランスポート統計更新スレッド終了");
        }).map_err(|_| TransportError::InternalError("統計更新スレッド開始失敗".to_string()))?;
        
        log::info!("トランスポートレイヤスレッド開始完了");
        
        Ok(())
    }
    
    /// 送信ワーカーループ
    fn send_worker_loop(&self) {
        while !self.shutdown_requested.load(Ordering::SeqCst) {
            // 各接続の送信キューを処理
            let connections = {
                let connections_guard = self.connections.read().unwrap();
                connections_guard.values().cloned().collect::<Vec<_>>()
            };
            
            for connection_handler in connections {
                if let Err(e) = self.process_connection_send_queue(&connection_handler) {
                    log::error!("送信キュー処理エラー (ノード{}): {:?}", 
                               connection_handler.node_id, e);
                }
            }
            
            // 少し待機
            crate::core::process::block_current(crate::core::process::BlockReason::Sleep(5_000_000)); // 5ms待機
        }
    }
    
    /// 受信ワーカーループ
    fn receive_worker_loop(&self) {
        while !self.shutdown_requested.load(Ordering::SeqCst) {
            // 各接続からデータを受信
            let connections = {
                let connections_guard = self.connections.read().unwrap();
                connections_guard.values().cloned().collect::<Vec<_>>()
            };
            
            for connection_handler in connections {
                if let Err(e) = self.process_connection_receive(&connection_handler) {
                    log::error!("受信処理エラー (ノード{}): {:?}", 
                               connection_handler.node_id, e);
                }
            }
            
            // 少し待機
            crate::core::process::block_current(crate::core::process::BlockReason::Sleep(5_000_000)); // 5ms待機
        }
    }
    
    /// 統計更新ワーカーループ
    fn stats_worker_loop(&self) {
        while !self.shutdown_requested.load(Ordering::SeqCst) {
            // 統計情報を更新
            if let Err(e) = self.update_stats() {
                log::error!("統計更新エラー: {:?}", e);
            }
            
            // 1秒待機
            crate::core::process::block_current(crate::core::process::BlockReason::Sleep(1_000_000_000)); // 1秒待機
        }
    }
    
    /// 接続の送信キューを処理
    fn process_connection_send_queue(&self, connection_handler: &ConnectionHandler) -> Result<(), TransportError> {
        let connection = &connection_handler.connection;
        
        // 送信キューからメッセージを取得
        let messages = {
            let mut send_queue = connection.send_queue.lock().map_err(|_| 
                TransportError::InternalError("送信キューロック取得失敗".to_string()))?;
            
            // 最大10個のメッセージを一度に処理
            let mut messages = Vec::new();
            for _ in 0..10 {
                if let Some(message) = send_queue.pop_front() {
                    messages.push(message);
                } else {
                    break;
                }
            }
            messages
        };
        
        // メッセージを送信
        for message in messages {
            let result = self.send_queued_message(connection, &message);
            
            // 完了コールバックを呼び出し
            if let Some(callback) = message.completion_callback {
                callback(result.map(|s| s), message.user_data);
            }
        }
        
        Ok(())
    }
    
    /// キューに入ったメッセージを送信
    fn send_queued_message(&self, connection: &ConnectionInfo, message: &QueuedMessage) -> Result<usize, TransportError> {
        // タイムアウトチェック
        let current_time = crate::core::time::current_timestamp();
        if message.timeout_ms > 0 && 
           current_time - message.enqueue_time > message.timeout_ms {
            return Err(TransportError::Timeout("メッセージ送信タイムアウト".to_string()));
        }
        
        // プロトコルハンドラーを取得
        let protocol_handlers = self.protocol_handlers.read().unwrap();
        let handler = protocol_handlers.get(&connection.protocol)
            .ok_or_else(|| TransportError::InternalError("プロトコルハンドラーが見つかりません".to_string()))?;
        
        // 転送オプションを構築
        let options = TransferOptions {
            priority: message.priority,
            timeout_ms: message.timeout_ms,
            ..Default::default()
        };
        
        // データを送信
        let bytes_sent = handler.send(connection, &message.data, &options)?;
        
        // 統計情報を更新
        connection.stats.bytes_sent.fetch_add(bytes_sent as u64, Ordering::Relaxed);
        connection.stats.messages_sent.fetch_add(1, Ordering::Relaxed);
        connection.last_activity.store(current_time, Ordering::Relaxed);
        
        Ok(bytes_sent)
    }
    
    /// 接続からデータを受信
    fn process_connection_receive(&self, connection_handler: &ConnectionHandler) -> Result<(), TransportError> {
        let connection = &connection_handler.connection;
        
        // プロトコルハンドラーを取得
        let protocol_handlers = self.protocol_handlers.read().unwrap();
        let handler = protocol_handlers.get(&connection.protocol)
            .ok_or_else(|| TransportError::InternalError("プロトコルハンドラーが見つかりません".to_string()))?;
        
        // 接続をポーリング
        let has_data = handler.poll(connection)?;
        
        if has_data {
            // データを受信
            let mut buffer = vec![0u8; 65536]; // 64KB受信バッファ
            let bytes_received = handler.receive(connection, &mut buffer)?;
            
            if bytes_received > 0 {
                buffer.truncate(bytes_received);
                
                // 受信バッファに追加
                {
                    let mut recv_buffer = connection.recv_buffer.lock().map_err(|_| 
                        TransportError::InternalError("受信バッファロック取得失敗".to_string()))?;
                    recv_buffer.extend_from_slice(&buffer);
                }
                
                // メッセージを解析
                self.process_received_data(connection_handler.node_id, &buffer)?;
                
                // 統計情報を更新
                connection.stats.bytes_received.fetch_add(bytes_received as u64, Ordering::Relaxed);
                connection.stats.messages_received.fetch_add(1, Ordering::Relaxed);
                connection.last_activity.store(crate::core::time::current_timestamp(), Ordering::Relaxed);
            }
        }
        
        Ok(())
    }
    
    /// 受信データを処理
    fn process_received_data(&self, node_id: NodeId, data: &[u8]) -> Result<(), TransportError> {
        let mut offset = 0;
        
        while offset < data.len() {
            // メッセージヘッダーを解析
            if offset + 24 > data.len() {
                // 不完全なメッセージヘッダー - 受信バッファに保存して後で処理
                self.store_incomplete_message(node_id, &data[offset..])?;
                break;
            }
            
            // メッセージタイプとサイズを取得
            let message_type = u32::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            ]);
            let message_size = u32::from_le_bytes([
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
            ]) as usize;
            
            // メッセージ全体が受信されているかチェック
            if offset + 24 + message_size > data.len() {
                // 不完全なメッセージ - 受信バッファに保存して後で処理
                self.store_incomplete_message(node_id, &data[offset..])?;
                break;
            }
            
            // メッセージデータを抽出
            let message_data = &data[offset + 24..offset + 24 + message_size];
            
            // メッセージタイプに応じて処理
            match message_type {
                0x54454C50 => { // "TELP" - テレページメッセージ
                    self.process_telepage_message(node_id, message_data)?;
                },
                0x4B454550 => { // "KEEP" - キープアライブメッセージ
                    self.process_keepalive_message(node_id, message_data)?;
                },
                0x41434B00 => { // "ACK\0" - 確認応答メッセージ
                    self.process_ack_message(node_id, message_data)?;
                },
                0x4552524F => { // "ERRO" - エラーメッセージ
                    self.process_error_message(node_id, message_data)?;
                },
                _ => {
                    log::warn!("未知のメッセージタイプ: 0x{:08x} (ノード{})", message_type, node_id);
                }
            }
            
            offset += 24 + message_size;
        }
        
        Ok(())
    }
    
    /// 不完全なメッセージを保存
    fn store_incomplete_message(&self, node_id: NodeId, data: &[u8]) -> Result<(), TransportError> {
        // 接続情報を取得
        let connections = self.connections.read().unwrap();
        let connection_handler = connections.get(&node_id)
            .ok_or_else(|| TransportError::NodeNotFound(node_id))?;
        
        // 受信バッファに追加
        let mut recv_buffer = connection_handler.connection.recv_buffer.lock().map_err(|_| 
            TransportError::InternalError("受信バッファロック取得失敗".to_string()))?;
        
        // バッファサイズ制限チェック
        if recv_buffer.len() + data.len() > 1024 * 1024 { // 1MB制限
            return Err(TransportError::InternalError("受信バッファオーバーフロー".to_string()));
        }
        
        recv_buffer.extend_from_slice(data);
        
        log::trace!("不完全メッセージを受信バッファに保存: {}バイト (ノード{})", data.len(), node_id);
        
        Ok(())
    }
    
    /// テレページメッセージを処理
    fn process_telepage_message(&self, node_id: NodeId, data: &[u8]) -> Result<(), TransportError> {
        if let Some((msg_type, telepage_id, payload)) = self.parse_telepage_message(data) {
            match msg_type {
                TelepageMessageType::Request => {
                    self.handle_telepage_request(node_id, telepage_id, payload)?;
                },
                TelepageMessageType::Response => {
                    self.handle_telepage_response(node_id, telepage_id, payload)?;
                },
                TelepageMessageType::Data => {
                    self.handle_telepage_data(node_id, telepage_id, payload)?;
                },
                TelepageMessageType::Ack => {
                    self.handle_telepage_ack(node_id, telepage_id, payload)?;
                },
                TelepageMessageType::Error => {
                    self.handle_telepage_error(node_id, telepage_id, payload)?;
                },
            }
        } else {
            log::warn!("無効なテレページメッセージ (ノード{})", node_id);
        }
        
        Ok(())
    }
    
    /// テレページリクエストを処理
    fn handle_telepage_request(&self, node_id: NodeId, telepage_id: TelepageId, payload: &[u8]) -> Result<(), TransportError> {
        log::debug!("テレページリクエスト受信: ID={}, ノード={}", telepage_id, node_id);
        
        // リクエストオプションを解析
        let options = self.parse_transfer_options(payload)?;
        
        // テレページデータを取得
        let telepage_data = match crate::core::memory::telepage::get_telepage_data(telepage_id) {
            Ok(data) => data,
            Err(_) => {
                // エラー応答を送信
                self.send_telepage_error(node_id, telepage_id, "テレページが見つかりません")?;
                return Ok(());
            }
        };
        
        // 応答を送信
        self.send_telepage_response(node_id, telepage_id, &telepage_data, &options)?;
        
        Ok(())
    }
    
    /// テレページ応答を処理
    fn handle_telepage_response(&self, node_id: NodeId, telepage_id: TelepageId, payload: &[u8]) -> Result<(), TransportError> {
        log::debug!("テレページ応答受信: ID={}, ノード={}, サイズ={}バイト", 
                   telepage_id, node_id, payload.len());
        
        // 保留中のリクエストを確認
        let mut pending_requests = self.pending_requests.write().unwrap();
        if let Some(mut request) = pending_requests.remove(&telepage_id) {
            // 転送状態を更新
            request.state.state = TelepageTransferStatus::Completed;
            request.state.transferred_bytes = payload.len();
            request.state.last_update = crate::core::time::current_timestamp();
            
            // 完了コールバックを呼び出し
            if let Some(callback) = request.completion_callback {
                callback(Ok(request.state), request.user_data);
            }
            
            // テレページデータを保存
            crate::core::memory::telepage::store_received_telepage(telepage_id, payload.to_vec())?;
        } else {
            log::warn!("未知のテレページ応答: ID={}, ノード={}", telepage_id, node_id);
        }
        
        Ok(())
    }
    
    /// テレページデータを処理
    fn handle_telepage_data(&self, node_id: NodeId, telepage_id: TelepageId, payload: &[u8]) -> Result<(), TransportError> {
        log::debug!("テレページデータ受信: ID={}, ノード={}, サイズ={}バイト", 
                   telepage_id, node_id, payload.len());
        
        // データを保存
        crate::core::memory::telepage::append_telepage_data(telepage_id, payload)?;
        
        // 確認応答を送信
        self.send_telepage_ack(node_id, telepage_id)?;
        
        Ok(())
    }
    
    /// テレページ確認応答を処理
    fn handle_telepage_ack(&self, node_id: NodeId, telepage_id: TelepageId, _payload: &[u8]) -> Result<(), TransportError> {
        log::trace!("テレページACK受信: ID={}, ノード={}", telepage_id, node_id);
        
        // アクティブな転送を更新
        let mut active_transfers = self.active_transfers.write().unwrap();
        if let Some(transfer) = active_transfers.get_mut(&(telepage_id as u64)) {
            transfer.last_update = crate::core::time::current_timestamp();
        }
        
        Ok(())
    }
    
    /// テレページエラーを処理
    fn handle_telepage_error(&self, node_id: NodeId, telepage_id: TelepageId, payload: &[u8]) -> Result<(), TransportError> {
        let error_message = String::from_utf8_lossy(payload);
        log::error!("テレページエラー受信: ID={}, ノード={}, エラー={}", 
                   telepage_id, node_id, error_message);
        
        // 保留中のリクエストを確認
        let mut pending_requests = self.pending_requests.write().unwrap();
        if let Some(mut request) = pending_requests.remove(&telepage_id) {
            // 転送状態を更新
            request.state.state = TelepageTransferStatus::Failed;
            request.state.error = Some(TransportError::RemoteError(error_message.to_string()));
            request.state.last_update = crate::core::time::current_timestamp();
            
            // 完了コールバックを呼び出し
            if let Some(callback) = request.completion_callback {
                callback(Err(TransportError::RemoteError(error_message.to_string())), request.user_data);
            }
        }
        
        Ok(())
    }
    
    /// キープアライブメッセージを処理
    fn process_keepalive_message(&self, node_id: NodeId, _data: &[u8]) -> Result<(), TransportError> {
        log::trace!("キープアライブ受信: ノード={}", node_id);
        
        // 接続の最終活動時間を更新
        let connections = self.connections.read().unwrap();
        if let Some(connection_handler) = connections.get(&node_id) {
            connection_handler.connection.last_activity.store(
                crate::core::time::current_timestamp(), 
                Ordering::Relaxed
            );
        }
        
        Ok(())
    }
    
    /// 確認応答メッセージを処理
    fn process_ack_message(&self, node_id: NodeId, data: &[u8]) -> Result<(), TransportError> {
        if data.len() >= 8 {
            let message_id = u64::from_le_bytes([
                data[0], data[1], data[2], data[3],
                data[4], data[5], data[6], data[7]
            ]);
            
            log::trace!("ACK受信: メッセージID={}, ノード={}", message_id, node_id);
            
            // 完了キューに追加
            let connections = self.connections.read().unwrap();
            if let Some(connection_handler) = connections.get(&node_id) {
                let mut completion_queue = connection_handler.completion_queue.lock().map_err(|_| 
                    TransportError::InternalError("完了キューロック取得失敗".to_string()))?;
                completion_queue.push((message_id, Ok(0)));
            }
        }
        
        Ok(())
    }
    
    /// エラーメッセージを処理
    fn process_error_message(&self, node_id: NodeId, data: &[u8]) -> Result<(), TransportError> {
        let error_message = String::from_utf8_lossy(data);
        log::error!("エラーメッセージ受信: ノード={}, エラー={}", node_id, error_message);
        
        // 接続エラーカウントを増加
        let connections = self.connections.read().unwrap();
        if let Some(connection_handler) = connections.get(&node_id) {
            connection_handler.connection.error_count.fetch_add(1, Ordering::Relaxed);
        }
        
        Ok(())
    }
    
    /// 転送オプションを解析
    fn parse_transfer_options(&self, data: &[u8]) -> Result<TransferOptions, TransportError> {
        // 簡略化された実装 - 実際にはバイナリ形式で解析
        Ok(TransferOptions::default())
    }
    
    /// テレページエラーを送信
    fn send_telepage_error(&self, node_id: NodeId, telepage_id: TelepageId, error_message: &str) -> Result<(), TransportError> {
        let error_data = error_message.as_bytes();
        let message = self.create_telepage_message(TelepageMessageType::Error, telepage_id, error_data)?;
        
        let options = TransferOptions {
            priority: TransferPriority::High,
            ..Default::default()
        };
        
        self.send_to_node(node_id, &message, &options)?;
        
        Ok(())
    }
    
    /// テレページ応答を送信
    fn send_telepage_response(&self, node_id: NodeId, telepage_id: TelepageId, data: &[u8], options: &TransferOptions) -> Result<(), TransportError> {
        let message = self.create_telepage_message(TelepageMessageType::Response, telepage_id, data)?;
        self.send_to_node(node_id, &message, options)?;
        
        Ok(())
    }
    
    /// テレページ確認応答を送信
    fn send_telepage_ack(&self, node_id: NodeId, telepage_id: TelepageId) -> Result<(), TransportError> {
        let message = self.create_telepage_message(TelepageMessageType::Ack, telepage_id, &[])?;
        
        let options = TransferOptions {
            priority: TransferPriority::High,
            ..Default::default()
        };
        
        self.send_to_node(node_id, &message, &options)?;
        
        Ok(())
    }
    
    /// プロセッサメインループ
    fn processor_main_loop(&self) {
        while !self.shutdown_requested.load(Ordering::SeqCst) {
            match self.state.get() {
                TransportState::Running => {
                    // タスクを処理
                    if let Err(e) = self.process_next_task() {
                        log::error!("タスク処理エラー: {:?}", e);
                    }
                    
                    // 保留中の転送を処理
                    if let Err(e) = self.process_pending_transfers() {
                        log::error!("保留中転送処理エラー: {:?}", e);
                    }
                    
                    // タイムアウトをチェック
                    if let Err(e) = self.check_timeouts() {
                        log::error!("タイムアウトチェックエラー: {:?}", e);
                    }
                },
                TransportState::Paused => {
                    // 一時停止中は高優先度タスクのみ処理
                    if let Err(e) = self.process_high_priority_tasks() {
                        log::error!("高優先度タスク処理エラー: {:?}", e);
                    }
                    
                    // 少し待機
                    crate::core::process::block_current(crate::core::process::BlockReason::Sleep(10_000_000)); // 10ms待機
                },
                TransportState::ShuttingDown | TransportState::Shutdown => {
                    // シャットダウン中またはシャットダウン完了
                    break;
                },
                _ => {
                    // その他の状態では少し待機
                    crate::core::process::block_current(crate::core::process::BlockReason::Sleep(10_000_000)); // 10ms待機
                }
            }
        }
        
        // シャットダウン処理
        self.perform_shutdown();
        
        // プロセッサフラグをクリア
        self.processor_running.store(false, Ordering::SeqCst);
    }
    
    /// 次のタスクを処理
    fn process_next_task(&self) -> Result<(), TransportError> {
        // タスクを取得
        let task = self.get_next_task()?;
        
        if let Some(task) = task {
            // タスクを処理
            self.process_task(task)?;
        } else {
            // タスクがない場合は少し待機
            let mut lock = self.task_mutex.lock().map_err(|_| 
                TransportError::InternalError("タスクロック取得失敗".to_string()))?;
            
            let _ = self.task_condvar.wait_timeout(&mut lock, 10); // 10ms待機
        }
        
        Ok(())
    }
    
    /// 次のタスクを取得
    fn get_next_task(&self) -> Result<Option<PrioritizedTask>, TransportError> {
        // 高優先度キューを確認
        {
            let mut queue = self.high_priority_queue.lock().map_err(|_| 
                TransportError::InternalError("高優先度キューロック取得失敗".to_string()))?;
                
            if let Some(Reverse(task)) = queue.pop() {
                return Ok(Some(task));
            }
        }
        
        // 通常優先度キューを確認
        {
            let mut queue = self.normal_priority_queue.lock().map_err(|_| 
                TransportError::InternalError("通常優先度キューロック取得失敗".to_string()))?;
                
            if let Some(task) = queue.pop_front() {
                return Ok(Some(task));
            }
        }
        
        // 低優先度キューを確認
        {
            let mut queue = self.low_priority_queue.lock().map_err(|_| 
                TransportError::InternalError("低優先度キューロック取得失敗".to_string()))?;
                
            if let Some(task) = queue.pop_front() {
                return Ok(Some(task));
            }
        }
        
        // タスクがない
        Ok(None)
    }
    
    /// タスクを処理
    fn process_task(&self, task: PrioritizedTask) -> Result<(), TransportError> {
        match task.task_type {
            TaskType::Connect(node_id) => {
                self.connect_node(node_id)
            },
            TaskType::Send(node_id, data, options, callback, user_data) => {
                let result = self.send_to_node(node_id, &data, &options);
                
                // 完了コールバックを呼び出し
                if let Some(cb) = callback {
                    cb(result.map(|s| s), user_data);
                }
                
                Ok(())
            },
            TaskType::TelepageRequest(node_id, id, options, callback, user_data) => {
                let result = self.send_telepage_request_internal(node_id, id, &options);
                
                // 必要に応じてコールバックを呼び出し
                if let Some(cb) = callback {
                    if let Err(e) = &result {
                        // エラーの場合はすぐにコールバックを呼び出し
                        let state = TelepageTransferState {
                            id,
                            source_node: self.get_local_node_id(),
                            target_node: node_id,
                            total_bytes: 0,
                            transferred_bytes: 0,
                            start_time: crate::core::time::current_timestamp(),
                            last_update: crate::core::time::current_timestamp(),
                            state: TelepageTransferStatus::Failed,
                            priority: options.priority,
                            error: Some(e.clone()),
                            metadata: options.metadata.clone(),
                        };
                        
                        cb(Err(e.clone()), user_data);
                    }
                }
                
                result
            },
            TaskType::TelepageData(node_id, id, data, options) => {
                self.send_telepage_data_internal(node_id, id, &data, &options)
            },
            TaskType::Poll(node_id) => {
                self.poll_connection(node_id)
            },
            TaskType::Disconnect(node_id) => {
                self.disconnect_node(node_id)
            },
            TaskType::Timeout(transfer_id) => {
                self.handle_timeout(transfer_id)
            },
            TaskType::Keepalive(node_id) => {
                self.send_keepalive(node_id)
            },
            TaskType::UpdateStats => {
                self.update_stats()
            },
            TaskType::Custom(_, action) => {
                action()
            },
        }
    }
    
    /// 高優先度タスクのみを処理
    fn process_high_priority_tasks(&self) -> Result<(), TransportError> {
        // 高優先度キューからタスクを取得
        let task = {
            let mut queue = self.high_priority_queue.lock().map_err(|_| 
                TransportError::InternalError("高優先度キューロック取得失敗".to_string()))?;
                
            queue.pop().map(|r| r.0)
        };
        
        // タスクを処理
        if let Some(task) = task {
            self.process_task(task)?;
            Ok(())
        } else {
            // タスクがない場合は少し待機
            let mut lock = self.task_mutex.lock().map_err(|_| 
                TransportError::InternalError("タスクロック取得失敗".to_string()))?;
            
            let _ = self.task_condvar.wait_timeout(&mut lock, 10); // 10ms待機
            Ok(())
        }
    }
    
    /// タスクをキューに追加
    fn enqueue_task(&self, task_type: TaskType, priority: TransferPriority) -> Result<u64, TransportError> {
        let id = self.next_transfer_id.fetch_add(1, Ordering::SeqCst);
        
        let task = PrioritizedTask {
            priority,
            enqueue_time: crate::core::time::current_timestamp(),
            task_type,
            id,
        };
        
        // 優先度に基づいて適切なキューに追加
        match priority {
            TransferPriority::Critical | TransferPriority::Absolute => {
                let mut queue = self.high_priority_queue.lock().map_err(|_| 
                    TransportError::InternalError("高優先度キューロック取得失敗".to_string()))?;
                queue.push(Reverse(task));
            },
            TransferPriority::Normal | TransferPriority::High => {
                let mut queue = self.normal_priority_queue.lock().map_err(|_| 
                    TransportError::InternalError("通常優先度キューロック取得失敗".to_string()))?;
                queue.push_back(task);
            },
            TransferPriority::Low | TransferPriority::Background | _ => {
                let mut queue = self.low_priority_queue.lock().map_err(|_| 
                    TransportError::InternalError("低優先度キューロック取得失敗".to_string()))?;
                queue.push_back(task);
            },
        }
        
        // 条件変数で待機スレッドに通知
        let _guard = self.task_mutex.lock().map_err(|_| 
            TransportError::InternalError("タスクロック取得失敗".to_string()))?;
        self.task_condvar.notify_one();
        
        Ok(id)
    }
    
    /// 保留中の転送を処理
    fn process_pending_transfers(&self) -> Result<(), TransportError> {
        let current_time = crate::time::current_time_ms();
        let mut timed_out_transfers = Vec::new();
        
        // 保留中リクエストをチェック
        {
            let mut pending = self.pending_requests.write();
            pending.retain(|&telepage_id, request| {
                if current_time >= request.request_time + request.timeout_ms {
                    log::warn!("テレページリクエストがタイムアウト: ID={:?}, 経過時間={}ms", 
                              telepage_id, current_time - request.request_time);
                    timed_out_transfers.push((telepage_id, request.clone()));
                    false
                } else {
                    // 再試行が必要かチェック
                    if request.retry_count < request.max_retries {
                        let retry_interval = request.options.retry_interval_ms;
                        if current_time >= request.request_time + (retry_interval * (request.retry_count + 1) as u64) {
                            log::debug!("テレページリクエストを再試行: ID={:?}, 試行回数={}", 
                                       telepage_id, request.retry_count + 1);
                            
                            // 再試行カウントを増加
                            let mut retry_request = request.clone();
                            retry_request.retry_count += 1;
                            
                            // 再送信を試行
                            if let Err(e) = self.send_telepage_request_internal(
                                request.requester, 
                                telepage_id, 
                                &retry_request.options
                            ) {
                                log::error!("テレページリクエスト再送信失敗: {:?}", e);
                                timed_out_transfers.push((telepage_id, request.clone()));
                                return false;
                            }
                            
                            // 更新されたリクエストで置き換え
                            *request = retry_request;
                        }
                    }
                    true
                }
            });
        }
        
        // タイムアウトしたリクエストのコールバックを実行
        for (telepage_id, request) in timed_out_transfers {
            if let Some(callback) = request.completion_callback {
                let error = TransportError::Timeout(format!("テレページリクエストタイムアウト: {:?}", telepage_id));
                callback(Err(error), request.user_data);
            }
        }
        
        Ok(())
    }
    
    /// タイムアウトをチェック
    fn check_timeouts(&self) -> Result<(), TransportError> {
        let now = crate::core::time::current_timestamp();
        
        // 接続のタイムアウトをチェック
        {
            let connections = self.connections.read().map_err(|_| 
                TransportError::InternalError("接続ロック取得失敗".to_string()))?;
                
            for (node_id, handler) in connections.iter() {
                let last_activity = handler.connection.last_activity.load(Ordering::Relaxed);
                let config = &handler.connection.config;
                
                // キープアライブ間隔を超えている場合
                if now - last_activity > config.keepalive_interval_ms {
                    // キープアライブを送信
                    self.enqueue_task(
                        TaskType::Keepalive(*node_id),
                        TransferPriority::Low
                    )?;
                }
                
                // 接続タイムアウトを超えている場合
                if now - last_activity > config.connection_timeout_ms * 3 {
                    // 接続が長時間応答なし、切断処理
                    self.enqueue_task(
                        TaskType::Disconnect(*node_id),
                        TransferPriority::Normal
                    )?;
                }
            }
        }
        
        Ok(())
    }
    
    /// シャットダウン処理を実行
    fn perform_shutdown(&self) {
        // 全ての接続を終了
        let nodes = {
            let connections = self.connections.read().unwrap_or_else(|_| panic!("接続ロック取得失敗"));
            connections.keys().cloned().collect::<Vec<NodeId>>()
        };
        
        for node_id in nodes {
            // ベストエフォートで切断
            let _ = self.disconnect_node(node_id);
        }
        
        // 保留中のリクエストをキャンセル
        {
            let mut pending = self.pending_requests.write().unwrap_or_else(|_| panic!("保留リクエストロック取得失敗"));
            
            for (_id, request) in pending.iter_mut() {
                // エラー状態に設定
                request.state.state = TelepageTransferStatus::Canceled;
                request.state.last_update = crate::core::time::current_timestamp();
                request.state.error = Some(TransportError::InternalError("システムシャットダウン".to_string()));
                
                // コールバックを呼び出し
                if let Some(cb) = request.completion_callback {
                    cb(Err(TransportError::InternalError("システムシャットダウン".to_string())), request.user_data);
                }
            }
            
            pending.clear();
        }
        
        // アクティブな転送をキャンセル
        {
            let mut transfers = self.active_transfers.write().unwrap_or_else(|_| panic!("転送ロック取得失敗"));
            transfers.clear();
        }
    }
    
    /// ローカルノードIDを取得
    fn get_local_node_id(&self) -> NodeId {
        // カーネルから自身のノードIDを取得の完全実装
        
        // 1. カーネル設定からノードIDを取得
        if let Ok(config) = crate::core::config::kernel_config() {
            if let Some(node_id) = config.get_node_id() {
                return NodeId::from_raw(node_id);
            }
        }
        
        // 2. ハードウェア情報からノードIDを生成
        let hardware_id = self.generate_hardware_based_node_id();
        if hardware_id != 0 {
            return NodeId::from_raw(hardware_id);
        }
        
        // 3. ネットワークインターフェースのMACアドレスからノードIDを生成
        if let Ok(network_devices) = crate::drivers::network::get_network_devices() {
            for device in &network_devices {
                if let Some(mac_addr) = device.get_mac_address() {
                    // MACアドレスの下位48ビットを64ビットノードIDに変換
                    let mut node_id_bytes = [0u8; 8];
                    node_id_bytes[2..8].copy_from_slice(&mac_addr);
                    let node_id = u64::from_le_bytes(node_id_bytes);
                    
                    if node_id != 0 {
                        log::info!("MACアドレスからノードID生成: 0x{:016x}", node_id);
                        return NodeId::from_raw(node_id);
                    }
                }
            }
        }
        
        // 4. CPU情報からノードIDを生成
        #[cfg(target_arch = "x86_64")]
        {
            let cpu_id = unsafe {
                let mut eax: u32 = 1;
                let mut ebx: u32;
                let mut ecx: u32;
                let mut edx: u32;
                
                core::arch::asm!(
                    "cpuid",
                    inout("eax") eax,
                    out("ebx") ebx,
                    out("ecx") ecx,
                    out("edx") edx,
                );
                
                // プロセッサシリアル番号を組み合わせてノードIDを作成
                ((ebx as u64) << 32) | (edx as u64)
            };
            
            if cpu_id != 0 {
                log::info!("CPU情報からノードID生成: 0x{:016x}", cpu_id);
                return NodeId::from_raw(cpu_id);
            }
        }
        
        // 5. 時刻ベースのノードID生成（最後の手段）
        let time_based_id = self.generate_time_based_node_id();
        log::warn!("時刻ベースノードID生成: 0x{:016x}", time_based_id);
        NodeId::from_raw(time_based_id)
    }
    
    fn generate_hardware_based_node_id(&self) -> u64 {
        // システム固有のハードウェア識別子を組み合わせてノードIDを生成
        let mut hasher = 0u64;
        
        // メモリ情報を取得
        if let Ok(memory_info) = crate::core::memory::get_memory_info() {
            hasher ^= memory_info.total_memory as u64;
            hasher = hasher.rotate_left(13);
        }
        
        // システムアーキテクチャ情報
        hasher ^= 0x4145544845524F53u64; // "AETHEROS" のASCII値
        hasher = hasher.rotate_left(17);
        
        // ブートタイムスタンプ
        if let Ok(boot_time) = crate::arch::time::get_boot_timestamp() {
            hasher ^= boot_time;
            hasher = hasher.rotate_left(19);
        }
        
        // ランダムソルトを追加
        let random_salt = self.get_hardware_random_seed();
        hasher ^= random_salt;
        
        hasher
    }
    
    fn get_hardware_random_seed(&self) -> u64 {
        // ハードウェア乱数発生器またはタイマーベースのシード生成
        #[cfg(target_arch = "x86_64")]
        {
            // RDRANDまたはRDSEED命令を使用
            if cfg!(target_feature = "rdrand") {
                let mut seed: u64;
                unsafe {
                    core::arch::asm!(
                        "rdrand {}",
                        out(reg) seed,
                    );
                }
                return seed;
            }
        }
        
        // フォールバック: タイマーベースのシード
        let mut seed = crate::time::current_time_ms();
        seed ^= crate::arch::cpu::get_cpu_cycles() as u64;
        seed = seed.wrapping_mul(0x5DEECE66D).wrapping_add(0xB);
        seed
    }
    
    fn generate_time_based_node_id(&self) -> u64 {
        // 現在時刻とランダム要素を組み合わせてノードIDを生成
        let current_time = crate::core::sync::current_time_ns();
        let random_component = self.get_hardware_random_seed();
        
        // 時刻（上位32ビット）とランダム値（下位32ビット）を組み合わせ
        let time_part = (current_time >> 32) as u32;
        let random_part = (random_component & 0xFFFFFFFF) as u32;
        
        ((time_part as u64) << 32) | (random_part as u64)
    }
    
    /// ノードに接続
    pub fn connect(&self, node: NodeId) -> Result<(), TransportError> {
        // 既に接続済みかチェック
        {
            let connections = self.connections.read().map_err(|_| 
                TransportError::InternalError("接続ロック取得失敗".to_string()))?;
                
            if connections.contains_key(&node) {
                // 既に接続済み、または接続中
                return Ok(());
            }
        }
        
        // 接続タスクをキューに追加
        self.enqueue_task(
            TaskType::Connect(node),
            TransferPriority::Normal
        )?;
        
        Ok(())
    }
    
    /// 内部接続処理
    fn connect_node(&self, node: NodeId) -> Result<(), TransportError> {
        let config = {
            let config = self.config.read().map_err(|_| 
                TransportError::InternalError("設定ロック取得失敗".to_string()))?;
            config.clone()
        };
        
        // ノードのアドレス情報を取得
        let node_addr = self.resolve_node_address(node)?;
        
        // 最適なプロトコルを選択
        let protocol = self.select_optimal_protocol(&node_addr, &config)?;
        
        // プロトコルハンドラを取得
        let handler = {
            let handlers = self.protocol_handlers.read().map_err(|_| 
                TransportError::InternalError("プロトコルハンドラロック取得失敗".to_string()))?;
                
            handlers.get(&protocol).cloned().ok_or_else(|| 
                TransportError::ProtocolUnsupported(format!("プロトコル {:?} のハンドラが見つかりません", protocol)))?
        };
        
        // 接続を確立
        let connection_info = handler.connect(node, &node_addr.primary_address, &config)?;
        
        // 接続ハンドラを作成
        let connection_handler = Arc::new(ConnectionHandler {
            node_id: node,
            connection: connection_info,
            sender_running: AtomicBool::new(false),
            receiver_running: AtomicBool::new(false),
            keepalive_running: AtomicBool::new(false),
            send_condvar: Condvar::new(),
            send_mutex: Mutex::new(()),
            completion_queue: Mutex::new(Vec::new()),
        });
        
        // 接続を登録
        {
            let mut connections = self.connections.write().map_err(|_| 
                TransportError::InternalError("接続ロック取得失敗".to_string()))?;
                
            connections.insert(node, connection_handler.clone());
        }
        
        // 送受信スレッドを開始
        self.start_connection_threads(&connection_handler)?;
        
        // 統計情報を更新
        self.stats.record_connection_established();
        
            Ok(())
    }
    
    /// ノードのアドレス情報を解決
    fn resolve_node_address(&self, node: NodeId) -> Result<NodeAddressInfo, TransportError> {
        // 1. ローカルキャッシュから検索
        {
            let addresses = self.node_addresses.read().map_err(|_| 
                TransportError::InternalError("アドレスキャッシュロック取得失敗".to_string()))?;
                
            if let Some(cached_info) = addresses.get(&node) {
                // キャッシュの有効期限チェック（5分）
                let current_time = crate::core::sync::current_time_ns();
                if current_time.saturating_sub(cached_info.last_updated) < 300_000_000_000u64 {
                    return Ok(cached_info.clone());
                }
            }
        }
        
        // 2. 分散ノード検出システムから取得
        if let Ok(node_info) = self.query_distributed_discovery(node) {
            self.cache_node_address(node, &node_info)?;
            return Ok(node_info);
        }
        
        // 3. DNS解決を試行
        if let Ok(dns_info) = self.resolve_dns_hostname(node) {
            self.cache_node_address(node, &dns_info)?;
            return Ok(dns_info);
        }
        
        // 4. mDNS (Multicast DNS) を使用した検索
        if let Ok(mdns_info) = self.resolve_mdns_hostname(node) {
            self.cache_node_address(node, &mdns_info)?;
            return Ok(mdns_info);
        }
        
        // 5. 設定ファイルからの静的解決
        if let Ok(static_info) = self.resolve_static_configuration(node) {
            self.cache_node_address(node, &static_info)?;
            return Ok(static_info);
        }
        
        // 6. ブロードキャスト検索
        if let Ok(broadcast_info) = self.resolve_broadcast_discovery(node) {
            self.cache_node_address(node, &broadcast_info)?;
            return Ok(broadcast_info);
        }
        
        // 7. 最後の手段: ノードIDからIPアドレスを推測
        self.resolve_node_id_heuristic(node)
    }
    
    /// 分散ノード検出システムからノード情報を取得
    fn query_distributed_discovery(&self, node: NodeId) -> Result<NodeAddressInfo, TransportError> {
        // 分散カーネルマネージャからノード情報を取得
        if let Ok(distributed_manager) = crate::core::distributed::DistributedKernelManager::instance() {
            let remote_nodes = distributed_manager.get_remote_nodes();
            
            for (_, node_info) in remote_nodes {
                if node_info.id as u64 == node.as_raw() {
                    let addr_info = NodeAddressInfo {
                        node_id: node,
                        primary_address: NetworkAddress::new_ipv4(
                            &node_info.ip_address,
                            node_info.port
                        )?,
                        secondary_addresses: Vec::new(),
                        last_updated: crate::core::sync::current_time_ns(),
                        node_name: Some(node_info.name.clone()),
                        routing_metric: self.calculate_routing_metric(&node_info),
                        protocol_preferences: self.determine_protocol_preferences(&node_info),
                    };
                    
                    return Ok(addr_info);
                }
            }
        }
        
        Err(TransportError::NodeNotFound(format!("分散検出でノード {}が見つかりません", node.as_raw())))
    }
    
    /// DNS解決でノード情報を取得
    fn resolve_dns_hostname(&self, node: NodeId) -> Result<NodeAddressInfo, TransportError> {
        // ノードIDをホスト名に変換
        let hostname = format!("aetheros-node-{:016x}.local", node.as_raw());
        
        // DNSクライアントを使用してアドレス解決
        if let Ok(dns_client) = crate::core::network::dns::DnsClient::instance() {
            let query_result = dns_client.query_a(&hostname)?;
            
            if !query_result.answers.is_empty() {
                let primary_ip = query_result.answers[0].ip_address;
                let port = self.get_default_port_for_node(node);
                
                let addr_info = NodeAddressInfo {
                    node_id: node,
                    primary_address: NetworkAddress::new_ipv4(&primary_ip.to_string(), port)?,
                    secondary_addresses: query_result.answers[1..].iter()
                        .map(|answer| NetworkAddress::new_ipv4(&answer.ip_address.to_string(), port))
                        .filter_map(Result::ok)
                        .collect(),
                    last_updated: crate::core::sync::current_time_ns(),
                    node_name: Some(hostname),
                    routing_metric: 100, // デフォルト値
                    protocol_preferences: vec![
                        TransportProtocol::QUIC,
                        TransportProtocol::TCP,
                        TransportProtocol::UDP
                    ],
                };
                
                return Ok(addr_info);
            }
        }
        
        Err(TransportError::DnsResolutionFailed(format!("DNS解決失敗: {}", hostname)))
    }
    
    /// mDNS解決でノード情報を取得
    fn resolve_mdns_hostname(&self, node: NodeId) -> Result<NodeAddressInfo, TransportError> {
        let service_name = format!("aetheros-{:016x}._tcp.local", node.as_raw());
        
        // mDNSクライアントを使用してサービス検索
        if let Ok(mdns_client) = crate::core::network::mdns::MdnsClient::instance() {
            let services = mdns_client.browse_services("_aetheros._tcp.local")?;
            
            for service in services {
                if service.instance_name.contains(&format!("{:016x}", node.as_raw())) {
                    let addr_info = NodeAddressInfo {
                        node_id: node,
                        primary_address: NetworkAddress::new_ipv4(
                            &service.ip_address,
                            service.port
                        )?,
                        secondary_addresses: Vec::new(),
                        last_updated: crate::core::sync::current_time_ns(),
                        node_name: Some(service.instance_name),
                        routing_metric: 50, // mDNSは通常ローカルネットワーク
                        protocol_preferences: service.txt_records.get("protocols")
                            .map(|p| self.parse_protocol_list(p))
                            .unwrap_or_else(|| vec![TransportProtocol::TCP]),
                    };
                    
                    return Ok(addr_info);
                }
            }
        }
        
        Err(TransportError::NodeNotFound(format!("mDNS検索でノード {}が見つかりません", node.as_raw())))
    }
    
    /// 静的設定からノード情報を取得
    fn resolve_static_configuration(&self, node: NodeId) -> Result<NodeAddressInfo, TransportError> {
        // 設定ファイルまたはカーネル設定からノード情報を取得
        if let Ok(config) = crate::core::config::kernel_config() {
            if let Some(node_configs) = config.get_node_configurations() {
                for node_config in node_configs {
                    if node_config.node_id == node.as_raw() {
                        let addr_info = NodeAddressInfo {
                            node_id: node,
                            primary_address: NetworkAddress::new_ipv4(
                                &node_config.primary_address,
                                node_config.port
                            )?,
                            secondary_addresses: node_config.secondary_addresses.iter()
                                .map(|addr| NetworkAddress::new_ipv4(addr, node_config.port))
                                .filter_map(Result::ok)
                                .collect(),
                            last_updated: crate::core::sync::current_time_ns(),
                            node_name: node_config.name.clone(),
                            routing_metric: node_config.routing_metric.unwrap_or(200),
                            protocol_preferences: node_config.protocols.clone(),
                        };
                        
                        return Ok(addr_info);
                    }
                }
            }
        }
        
        Err(TransportError::NodeNotFound(format!("静的設定にノード {}が見つかりません", node.as_raw())))
    }
    
    /// ブロードキャスト検索でノード情報を取得
    fn resolve_broadcast_discovery(&self, node: NodeId) -> Result<NodeAddressInfo, TransportError> {
        // UDPブロードキャストでノード検索
        if let Ok(socket) = crate::core::network::udp::create_udp_socket() {
            let discovery_message = format!("AETHEROS_DISCOVERY:{:016x}", node.as_raw());
            
            // ローカルネットワークにブロードキャスト
            let broadcast_addresses = [
                "192.168.1.255:8765",
                "192.168.0.255:8765", 
                "10.255.255.255:8765",
                "172.31.255.255:8765",
                "255.255.255.255:8765"
            ];
            
            for broadcast_addr in &broadcast_addresses {
                let _ = socket.send_to(discovery_message.as_bytes(), broadcast_addr);
            }
            
            // 応答を待機（5秒タイムアウト）
            socket.set_timeout(Duration::from_secs(5))?;
            let mut buffer = [0u8; 1024];
            
            while let Ok((size, source_addr)) = socket.recv_from(&mut buffer) {
                if let Ok(response) = core::str::from_utf8(&buffer[..size]) {
                    if response.starts_with(&format!("AETHEROS_RESPONSE:{:016x}:", node.as_raw())) {
                        let parts: Vec<&str> = response.split(':').collect();
                        if parts.len() >= 4 {
                            let node_name = parts[2];
                            let port = parts[3].parse::<u16>().unwrap_or(8765);
                            
                            let addr_info = NodeAddressInfo {
                                node_id: node,
                                primary_address: NetworkAddress::new_from_socket_addr(&source_addr)?,
                                secondary_addresses: Vec::new(),
                                last_updated: crate::core::sync::current_time_ns(),
                                node_name: Some(node_name.to_string()),
                                routing_metric: 150,
                                protocol_preferences: vec![TransportProtocol::UDP, TransportProtocol::TCP],
                            };
                            
                            return Ok(addr_info);
                        }
                    }
                }
            }
        }
        
        Err(TransportError::NodeNotFound(format!("ブロードキャスト検索でノード {}が見つかりません", node.as_raw())))
    }
    
    /// ノードIDヒューリスティックでアドレス推測
    fn resolve_node_id_heuristic(&self, node: NodeId) -> Result<NodeAddressInfo, TransportError> {
        // ノードIDからIPアドレスを推測（緊急時の最後の手段）
        let node_raw = node.as_raw();
        
        // ノードIDの下位32ビットをIPアドレス候補として使用
        let ip_candidate = (node_raw & 0xFFFFFFFF) as u32;
        
        // プライベートIPアドレス範囲にマッピング
        let ip_bytes = [
            192,  // プライベートIPアドレス範囲
            168,
            ((ip_candidate >> 16) & 0xFF) as u8,
            (ip_candidate & 0xFF) as u8,
        ];
        
        let ip_address = format!("{}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
        let port = 8765 + ((node_raw >> 32) & 0xFFFF) as u16 % 1000; // ポート範囲を制限
        
        // 実際にIPアドレスに接続を試行
        if let Ok(test_socket) = crate::core::network::tcp::create_tcp_socket() {
            test_socket.set_timeout(Duration::from_secs(1))?;
            
            if test_socket.connect(&format!("{}:{}", ip_address, port)).is_ok() {
                let addr_info = NodeAddressInfo {
                    node_id: node,
                    primary_address: NetworkAddress::new_ipv4(&ip_address, port)?,
                    secondary_addresses: Vec::new(),
                    last_updated: crate::core::sync::current_time_ns(),
                    node_name: Some(format!("heuristic-{:016x}", node_raw)),
                    routing_metric: 999, // 最低優先度
                    protocol_preferences: vec![TransportProtocol::TCP],
                };
                
                test_socket.disconnect()?;
                return Ok(addr_info);
            }
        }
        
        Err(TransportError::NodeNotFound(format!("ノード {}のアドレス解決に完全に失敗", node.as_raw())))
    }
    
    /// ノード情報をキャッシュに保存
    fn cache_node_address(&self, node: NodeId, info: &NodeAddressInfo) -> Result<(), TransportError> {
        let mut addresses = self.node_addresses.write().map_err(|_| 
            TransportError::InternalError("アドレスキャッシュロック取得失敗".to_string()))?;
            
        addresses.insert(node, info.clone());
        
        // キャッシュサイズ制限（1000エントリ）
        if addresses.len() > 1000 {
            // 最も古いエントリを削除
            let oldest_node = addresses.iter()
                .min_by_key(|(_, info)| info.last_updated)
                .map(|(node, _)| *node);
                
            if let Some(oldest) = oldest_node {
                addresses.remove(&oldest);
            }
        }
        
        Ok(())
    }
    
    /// ルーティングメトリックを計算
    fn calculate_routing_metric(&self, node_info: &crate::core::distributed::NodeInfo) -> u32 {
        let mut metric = 100; // ベース値
        
        // レイテンシに基づく調整
        metric += node_info.latency;
        
        // 信頼性に基づく調整
        metric += (100 - node_info.reliability);
        
        // ネットワーク帯域幅に基づく調整
        if node_info.network_bandwidth > 1000 {
            metric -= 20; // 高帯域幅ボーナス
        } else if node_info.network_bandwidth < 100 {
            metric += 50; // 低帯域幅ペナルティ
        }
        
        metric.min(999) // 最大値制限
    }
    
    /// プロトコル優先順位を決定
    fn determine_protocol_preferences(&self, node_info: &crate::core::distributed::NodeInfo) -> Vec<TransportProtocol> {
        let mut preferences = Vec::new();
        
        // ノードの機能フラグに基づいてプロトコル優先順位を決定
        if node_info.feature_flags & 0x01 != 0 {
            preferences.push(TransportProtocol::RDMA); // RDMA対応
        }
        
        if node_info.feature_flags & 0x02 != 0 {
            preferences.push(TransportProtocol::QUIC); // QUIC対応
        }
        
        preferences.push(TransportProtocol::TCP); // 常にTCPをサポート
        
        if node_info.feature_flags & 0x04 != 0 {
            preferences.push(TransportProtocol::UDP); // UDP対応
        }
        
        preferences
    }
    
    /// ノードのデフォルトポートを取得
    fn get_default_port_for_node(&self, node: NodeId) -> u16 {
        // ノードIDに基づいてポート範囲を計算
        let base_port = 8765;
        let port_offset = (node.as_raw() % 1000) as u16;
        base_port + port_offset
    }
    
    /// プロトコルリストを解析
    fn parse_protocol_list(&self, protocol_str: &str) -> Vec<TransportProtocol> {
        protocol_str.split(',')
            .filter_map(|s| match s.trim().to_uppercase().as_str() {
                "TCP" => Some(TransportProtocol::TCP),
                "UDP" => Some(TransportProtocol::UDP),
                "QUIC" => Some(TransportProtocol::QUIC),
                "RDMA" => Some(TransportProtocol::RDMA),
                _ => None,
            })
            .collect()
    }
    
    /// 最適なプロトコルを選択
    fn select_optimal_protocol(&self, node_addr: &NodeAddressInfo, config: &TransportConfig) 
        -> Result<TransportProtocol, TransportError> 
    {
        // 優先度順にプロトコルを評価
        
        // 1. 設定されたプロトコルが使用可能か確認
        let protocol = config.protocol;
        if self.is_protocol_available(&protocol, node_addr) {
            return Ok(protocol);
        }
        
        // 2. バックアッププロトコルを確認
        for backup in &config.backup_protocols {
            if self.is_protocol_available(backup, node_addr) {
                return Ok(*backup);
            }
        }
        
        // 3. ノードの優先プロトコルを確認
        for node_proto in &node_addr.protocol_preferences {
            if self.is_protocol_available(node_proto, node_addr) {
                return Ok(*node_proto);
            }
        }
        
        // 4. デフォルトとしてTCPを使用
        Ok(TransportProtocol::Tcp)
    }
    
    /// プロトコルが利用可能かチェック
    fn is_protocol_available(&self, protocol: &TransportProtocol, _node_addr: &NodeAddressInfo) -> bool {
        // プロトコルのハンドラが登録されているかチェック
        let handlers = match self.protocol_handlers.read() {
            Ok(h) => h,
            Err(_) => return false,
        };
        
        handlers.contains_key(protocol)
    }
    
    /// ノードとの接続を切断
    pub fn disconnect(&self, node: NodeId) -> Result<(), TransportError> {
        // 切断タスクをキューに追加
        self.enqueue_task(
            TaskType::Disconnect(node),
            TransferPriority::Normal
        )?;
        
            Ok(())
    }
    
    /// 内部切断処理
    fn disconnect_node(&self, node: NodeId) -> Result<(), TransportError> {
        // 接続があるか確認
        let handler = {
            let connections = self.connections.read().map_err(|_| 
                TransportError::InternalError("接続ロック取得失敗".to_string()))?;
                
            connections.get(&node).cloned().ok_or_else(|| 
                TransportError::NodeNotFound(node.raw()))?
        };
        
        // 送受信スレッドを停止
        // 実装では、フラグを設定してスレッドに停止を通知
        
        // プロトコルハンドラで切断
        {
            // 接続状態をDisconnectingに設定
            // ConnectionInfoの状態を更新
            {
                let connections = self.connections.read().map_err(|_| 
                    TransportError::InternalError("接続ロック取得失敗".to_string()))?;
                
                if let Some(handler) = connections.get(&node) {
                    // 接続状態を更新
                    let mut connection_state = ConnectionState::Disconnecting;
                    
                    // アトミック操作で状態を更新
                    unsafe {
                        let state_ptr = &handler.connection.state as *const ConnectionState as *mut ConnectionState;
                        core::ptr::write(state_ptr, connection_state);
                    }
                    
                    // 最終活動時間を更新
                    handler.connection.last_activity.store(
                        crate::time::current_time_ms(), 
                        Ordering::Relaxed
                    );
                    
                    log::debug!("ノード{}の接続状態をDisconnectingに設定", node.as_raw());
                }
            }
            
            // プロトコルハンドラを使用して切断
            let protocol = handler.connection.protocol;
            let proto_handler = {
                let handlers = self.protocol_handlers.read().map_err(|_| 
                    TransportError::InternalError("プロトコルハンドラロック取得失敗".to_string()))?;
                    
                handlers.get(&protocol).cloned().ok_or_else(|| 
                    TransportError::ProtocolUnsupported(format!("プロトコル {:?} のハンドラが見つかりません", protocol)))?
            };
            
            // 切断を実行
            proto_handler.disconnect(&handler.connection)?;
        }
        
        // 接続リストから削除
        {
            let mut connections = self.connections.write().map_err(|_| 
                TransportError::InternalError("接続ロック取得失敗".to_string()))?;
                
            connections.remove(&node);
        }
        
        // 統計情報を更新
        
            Ok(())
    }
    
    /// テレページリクエストを送信
    pub fn send_telepage_request(&self, node: NodeId, id: TelepageId) -> Result<(), TransportError> {
        // デフォルトのオプションを使用
        let options = TransferOptions {
            priority: TransferPriority::Normal,
            ..Default::default()
        };
        
        self.send_telepage_request_with_options(node, id, options)
    }
    
    /// オプション付きでテレページリクエストを送信
    pub fn send_telepage_request_with_options(&self, node: NodeId, id: TelepageId, options: TransferOptions) 
        -> Result<(), TransportError> 
    {
        // リクエストタスクをキューに追加
        self.enqueue_task(
            TaskType::TelepageRequest(node, id, options, None, 0),
            options.priority
        )?;
        
        Ok(())
    }
    
    /// 内部テレページリクエスト送信処理
    fn send_telepage_request_internal(&self, node: NodeId, id: TelepageId, options: &TransferOptions) 
        -> Result<(), TransportError> 
    {
        // ノードへの接続を確保
        self.ensure_connected(node)?;
        
        // 転送IDを生成
        let transfer_id = self.next_transfer_id.fetch_add(1, Ordering::SeqCst);
        
        // 転送状態を作成
        let transfer_state = TelepageTransferState {
            id,
            source_node: self.get_local_node_id(),
            target_node: node,
            total_bytes: 0, // まだ不明
            transferred_bytes: 0,
            start_time: crate::core::time::current_timestamp(),
            last_update: crate::core::time::current_timestamp(),
            state: TelepageTransferStatus::Requesting,
            priority: options.priority,
            error: None,
            metadata: options.metadata.clone(),
        };
        
        // 保留中のリクエストとして登録
        {
            let mut pending = self.pending_requests.write().map_err(|_| 
                TransportError::InternalError("保留リクエストロック取得失敗".to_string()))?;
                
            let request = PendingTelepageRequest {
                id,
                requester: node,
                request_time: crate::core::time::current_timestamp(),
                timeout_ms: options.timeout_ms,
                retry_count: 0,
                max_retries: options.retries,
                options: options.clone(),
                state: transfer_state.clone(),
                completion_callback: None,
                user_data: 0,
            };
            
            pending.insert(id, request);
        }
        
        // アクティブな転送として登録
        {
            let mut transfers = self.active_transfers.write().map_err(|_| 
                TransportError::InternalError("転送ロック取得失敗".to_string()))?;
                
            transfers.insert(transfer_id, transfer_state);
        }
        
        // リクエストメッセージを作成
        let message = self.create_telepage_message(TelepageMessageType::Request, id, &[])?;
        
        // メッセージを送信
        self.send_to_node(node, &message, options)?;
        
        Ok(())
    }
    
    /// テレページデータを送信
    pub fn send_telepage(&self, node: NodeId, id: TelepageId, data: &[u8]) -> Result<(), TransportError> {
        // デフォルトのオプションを使用
        let options = TransferOptions {
            priority: TransferPriority::Normal,
            ..Default::default()
        };
        
        self.send_telepage_with_options(node, id, data, options)
    }
    
    /// オプション付きでテレページデータを送信
    pub fn send_telepage_with_options(&self, node: NodeId, id: TelepageId, data: &[u8], options: TransferOptions) 
        -> Result<(), TransportError> 
    {
        // データをコピー
        let data_copy = data.to_vec();
        
        // データ送信タスクをキューに追加
        self.enqueue_task(
            TaskType::TelepageData(node, id, data_copy, options),
            options.priority
        )?;
        
        Ok(())
    }
    
    /// 内部テレページデータ送信処理
    fn send_telepage_data_internal(&self, node: NodeId, id: TelepageId, data: &[u8], options: &TransferOptions) 
        -> Result<(), TransportError> 
    {
        // ノードへの接続を確保
        self.ensure_connected(node)?;
        
        // データを分割して送信
        // 設定されたMTUに基づいて分割
        let config = {
            let config = self.config.read().map_err(|_| 
                TransportError::InternalError("設定ロック取得失敗".to_string()))?;
            config.clone()
        };
        
        let mtu = config.max_transfer_unit;
        let total_size = data.len();
        let mut total_sent = 0;
        
        // 転送IDを生成
        let transfer_id = self.next_transfer_id.fetch_add(1, Ordering::SeqCst);
        
        // 転送状態を作成
        let transfer_state = TelepageTransferState {
            id,
            source_node: self.get_local_node_id(),
            target_node: node,
            total_bytes: total_size,
            transferred_bytes: 0,
            start_time: crate::core::time::current_timestamp(),
            last_update: crate::core::time::current_timestamp(),
            state: TelepageTransferStatus::Transferring,
            priority: options.priority,
            error: None,
            metadata: options.metadata.clone(),
        };
        
        // アクティブな転送として登録
        {
            let mut transfers = self.active_transfers.write().map_err(|_| 
                TransportError::InternalError("転送ロック取得失敗".to_string()))?;
                
            transfers.insert(transfer_id, transfer_state);
        }
        
        // データを送信
        while total_sent < total_size {
            let chunk_size = core::cmp::min(mtu, total_size - total_sent);
            let chunk = &data[total_sent..total_sent + chunk_size];
            
            // チャンクのタイプを決定
            let msg_type = if total_sent + chunk_size >= total_size {
                // 最後のチャンク
                TelepageMessageType::Data
            } else {
                // 途中のチャンク
                TelepageMessageType::Fragment
            };
            
            // メッセージを作成
            let message = self.create_telepage_message(msg_type, id, chunk)?;
            
            // メッセージを送信
            self.send_to_node(node, &message, options)?;
            
            // 送信済みサイズを更新
            total_sent += chunk_size;
            
            // 転送状態を更新
            {
                let mut transfers = self.active_transfers.write().map_err(|_| 
                    TransportError::InternalError("転送ロック取得失敗".to_string()))?;
                    
                if let Some(state) = transfers.get_mut(&transfer_id) {
                    state.transferred_bytes = total_sent;
                    state.last_update = crate::core::time::current_timestamp();
                }
            }
        }
        
        // 完了メッセージを送信
        let complete_msg = self.create_telepage_message(TelepageMessageType::Complete, id, &[])?;
        self.send_to_node(node, &complete_msg, options)?;
        
        // 転送状態を更新
        {
            let mut transfers = self.active_transfers.write().map_err(|_| 
                TransportError::InternalError("転送ロック取得失敗".to_string()))?;
                
            if let Some(state) = transfers.get_mut(&transfer_id) {
                state.transferred_bytes = total_size;
                state.last_update = crate::core::time::current_timestamp();
                state.state = TelepageTransferStatus::Completed;
            }
        }
        
        Ok(())
    }
    
    /// 接続の確立を確認
    fn ensure_connected(&self, node: NodeId) -> Result<(), TransportError> {
        // 接続状態を確認
        let connected = {
            let connections = self.connections.read().map_err(|_| 
                TransportError::InternalError("接続ロック取得失敗".to_string()))?;
            
            connections.contains_key(&node)
        };
        
        if connected {
            Ok(())
        } else {
            // 接続を確立
            self.connect_node(node)
        }
    }
    
    /// ノードにデータを送信
    fn send_to_node(&self, node: NodeId, data: &[u8], options: &TransferOptions) -> Result<usize, TransportError> {
        // 接続を取得
        let handler = {
            let connections = self.connections.read().map_err(|_| 
                TransportError::InternalError("接続ロック取得失敗".to_string()))?;
                
            connections.get(&node).cloned().ok_or_else(|| 
                TransportError::NodeNotFound(node.raw()))?
        };
        
        // プロトコルハンドラを取得
        let protocol = handler.connection.protocol;
        let proto_handler = {
            let handlers = self.protocol_handlers.read().map_err(|_| 
                TransportError::InternalError("プロトコルハンドラロック取得失敗".to_string()))?;
                
            handlers.get(&protocol).cloned().ok_or_else(|| 
                TransportError::ProtocolUnsupported(format!("プロトコル {:?} のハンドラが見つかりません", protocol)))?
        };
        
        // データを送信
        let result = proto_handler.send(&handler.connection, data, options);
        
        // 結果を処理
        match &result {
            Ok(bytes_sent) => {
                // 最終活動時間を更新
                handler.connection.last_activity.store(
                    crate::core::time::current_timestamp(),
                    Ordering::Relaxed
                );
                
                // 統計情報を更新
                self.stats.record_bytes_sent(*bytes_sent as u64);
            },
            Err(e) => {
                // エラーをログに記録
                log::error!("データ送信エラー: {:?}", e);
                
                // エラーカウントを増加
                handler.connection.error_count.fetch_add(1, Ordering::Relaxed);
                
                // 接続が致命的なエラーの場合は再接続をスケジュール
                if let TransportError::ConnectionFailed(_) = e {
                    // 再接続タスクをキューに追加
                    let _ = self.enqueue_task(
                        TaskType::Connect(node),
                        TransferPriority::High
                    );
                }
            }
        }
        
        result
    }
    
    /// 接続をポーリング
    fn poll_connection(&self, node: NodeId) -> Result<(), TransportError> {
        // 接続を取得
        let handler = {
            let connections = self.connections.read().map_err(|_| 
                TransportError::InternalError("接続ロック取得失敗".to_string()))?;
                
            connections.get(&node).cloned().ok_or_else(|| 
                TransportError::NodeNotFound(node.raw()))?
        };
        
        // プロトコルハンドラを取得
        let protocol = handler.connection.protocol;
        let proto_handler = {
            let handlers = self.protocol_handlers.read().map_err(|_| 
                TransportError::InternalError("プロトコルハンドラロック取得失敗".to_string()))?;
                
            handlers.get(&protocol).cloned().ok_or_else(|| 
                TransportError::ProtocolUnsupported(format!("プロトコル {:?} のハンドラが見つかりません", protocol)))?
        };
        
        // ポーリング実行
        let has_activity = proto_handler.poll(&handler.connection)?;
        
        // 活動があれば最終活動時間を更新
        if has_activity {
            handler.connection.last_activity.store(
                crate::core::time::current_timestamp(),
                Ordering::Relaxed
            );
        }
        
        Ok(())
    }
    
    /// キープアライブを送信
    fn send_keepalive(&self, node: NodeId) -> Result<(), TransportError> {
        // 接続を取得
        let handler = {
            let connections = self.connections.read().map_err(|_| 
                TransportError::InternalError("接続ロック取得失敗".to_string()))?;
                
            connections.get(&node).cloned().ok_or_else(|| 
                TransportError::NodeNotFound(node.raw()))?
        };
        
        // プロトコルハンドラを取得
        let protocol = handler.connection.protocol;
        let proto_handler = {
            let handlers = self.protocol_handlers.read().map_err(|_| 
                TransportError::InternalError("プロトコルハンドラロック取得失敗".to_string()))?;
                
            handlers.get(&protocol).cloned().ok_or_else(|| 
                TransportError::ProtocolUnsupported(format!("プロトコル {:?} のハンドラが見つかりません", protocol)))?
        };
        
        // キープアライブを送信
        proto_handler.send_keepalive(&handler.connection)?;
        
        // 最終活動時間を更新
        handler.connection.last_activity.store(
            crate::core::time::current_timestamp(),
            Ordering::Relaxed
        );
        
        Ok(())
    }
    
    /// 統計情報を更新
    fn update_stats(&self) -> Result<(), TransportError> {
        // 実装は省略
        Ok(())
    }
    
    /// タイムアウト処理
    fn handle_timeout(&self, transfer_id: u64) -> Result<(), TransportError> {
        // アクティブ転送からIDを検索
        let transfer = {
            let transfers = self.active_transfers.read().map_err(|_| 
                TransportError::InternalError("転送ロック取得失敗".to_string()))?;
                
            transfers.get(&transfer_id).cloned()
        };
        
        if let Some(mut transfer) = transfer {
            // タイムアウトした転送を処理
            
            // 転送状態を更新
            transfer.state = TelepageTransferStatus::Failed;
            transfer.error = Some(TransportError::Timeout(0));
            transfer.last_update = crate::core::time::current_timestamp();
            
            // 転送状態を更新
            {
                let mut transfers = self.active_transfers.write().map_err(|_| 
                    TransportError::InternalError("転送ロック取得失敗".to_string()))?;
                    
                if let Some(t) = transfers.get_mut(&transfer_id) {
                    *t = transfer.clone();
                }
            }
            
            // テレページIDがあれば保留リクエストも更新
            {
                let mut pending = self.pending_requests.write().map_err(|_| 
                    TransportError::InternalError("保留リクエストロック取得失敗".to_string()))?;
                    
                if let Some(req) = pending.get_mut(&transfer.id) {
                    // 失敗状態に設定
                    req.state.state = TelepageTransferStatus::Failed;
                    req.state.error = Some(TransportError::Timeout(req.timeout_ms));
                    req.state.last_update = crate::core::time::current_timestamp();
                    
                    // コールバックを呼び出し
                    if let Some(cb) = req.completion_callback {
                        let error = TransportError::Timeout(req.timeout_ms);
                        cb(Err(error), req.user_data);
                    }
                    
                    // 保留リストから削除
                    pending.remove(&transfer.id);
                }
            }
        }
        
        Ok(())
    }
    
    /// テレページメッセージを作成
    fn create_telepage_message(
        &self,
        msg_type: TelepageMessageType,
        id: TelepageId,
        data: &[u8]
    ) -> Result<Vec<u8>, TransportError> {
        // メッセージ形式：
        // - 1バイト: メッセージタイプ
        // - 8バイト: テレページID
        // - 4バイト: データ長
        // - 4バイト: チェックサム（CRC32）
        // - N バイト: データ
        
        let type_byte = match msg_type {
            TelepageMessageType::Request => 1u8,
            TelepageMessageType::Data => 2u8,
            TelepageMessageType::Ack => 3u8,
            TelepageMessageType::Complete => 4u8,
            TelepageMessageType::Error => 5u8,
            TelepageMessageType::Fragment => 6u8,
            TelepageMessageType::Retransmit => 7u8,
            TelepageMessageType::KeepAlive => 8u8,
            TelepageMessageType::PageInfoUpdate => 9u8,
            TelepageMessageType::PriorityUpdate => 10u8,
            TelepageMessageType::BinaryDelta => 11u8,
            TelepageMessageType::CompressedData => 12u8,
            TelepageMessageType::EncryptedData => 13u8,
            TelepageMessageType::MulticastData => 14u8,
            TelepageMessageType::Metadata => 15u8,
            TelepageMessageType::Custom(code) => (code & 0xFF) as u8,
        };
        
        let id_bytes = id.raw().to_le_bytes();
        let data_len = data.len() as u32;
        let data_len_bytes = data_len.to_le_bytes();
        
        // CRC32チェックサムを計算
        let checksum = calculate_crc32(data);
        let checksum_bytes = checksum.to_le_bytes();
        
        let mut message = Vec::with_capacity(1 + 8 + 4 + 4 + data.len());
        message.push(type_byte);
        message.extend_from_slice(&id_bytes);
        message.extend_from_slice(&data_len_bytes);
        message.extend_from_slice(&checksum_bytes);
        message.extend_from_slice(data);
        
        Ok(message)
    }
    
    /// テレページメッセージをパース
    fn parse_telepage_message<'a>(&self, message: &'a [u8]) -> Option<(TelepageMessageType, TelepageId, &'a [u8])> {
        // メッセージが最小サイズ（ヘッダー部分）よりも小さい場合は無効
        if message.len() < 17 { // 1 + 8 + 4 + 4
            return None;
        }
        
        // メッセージタイプをパース
        let type_byte = message[0];
        let msg_type = match type_byte {
            1 => TelepageMessageType::Request,
            2 => TelepageMessageType::Data,
            3 => TelepageMessageType::Ack,
            4 => TelepageMessageType::Complete,
            5 => TelepageMessageType::Error,
            6 => TelepageMessageType::Fragment,
            7 => TelepageMessageType::Retransmit,
            8 => TelepageMessageType::KeepAlive,
            9 => TelepageMessageType::PageInfoUpdate,
            10 => TelepageMessageType::PriorityUpdate,
            11 => TelepageMessageType::BinaryDelta,
            12 => TelepageMessageType::CompressedData,
            13 => TelepageMessageType::EncryptedData,
            14 => TelepageMessageType::MulticastData,
            15 => TelepageMessageType::Metadata,
            code => TelepageMessageType::Custom(code as u32),
        };
        
        // テレページIDをパース
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&message[1..9]);
        let id_raw = u64::from_le_bytes(id_bytes);
        let id = TelepageId::from_raw(id_raw);
        
        // データ長をパース
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&message[9..13]);
        let data_len = u32::from_le_bytes(len_bytes) as usize;
        
        // チェックサムをパース
        let mut checksum_bytes = [0u8; 4];
        checksum_bytes.copy_from_slice(&message[13..17]);
        let expected_checksum = u32::from_le_bytes(checksum_bytes);
        
        // データ長が正しいかチェック
        if message.len() != 17 + data_len {
            return None;
        }
        
        // データ部分を抽出
        let data = &message[17..];
        
        // チェックサムを検証
        let actual_checksum = calculate_crc32(data);
        if actual_checksum != expected_checksum {
            return None;
        }
        
        Some((msg_type, id, data))
    }
    
    /// テレページデータを受信（ブロッキング）
    pub fn receive_telepage(&self, id: TelepageId) -> Result<Vec<u8>, TransportError> {
        // デフォルトのオプションを使用
        let options = TransferOptions {
            timeout_ms: 5000, // 5秒
            ..Default::default()
        };
        
        self.receive_telepage_with_options(id, options)
    }
    
    /// オプション付きでテレページデータを受信
    pub fn receive_telepage_with_options(&self, id: TelepageId, options: TransferOptions) 
        -> Result<Vec<u8>, TransportError> 
    {
        let start_time = crate::core::time::current_timestamp();
        let timeout = options.timeout_ms;
        
        // 既に受信中の転送を探す
        let transfer_id = {
            let transfers = self.active_transfers.read().map_err(|_| 
                TransportError::InternalError("転送ロック取得失敗".to_string()))?;
                
            // テレページIDが一致するものを探す
            for (id_key, transfer) in transfers.iter() {
                if transfer.id == id {
                    // 既に完了している場合はデータを取得
                    if transfer.state == TelepageTransferStatus::Completed {
                        // データを探して返す
                        return self.find_received_telepage_data(id);
                    }
                    
                    // 転送中の場合はIDを返す
                    return Err(TransportError::InternalError("テレページは転送中です".to_string()));
                }
            }
            
            // 見つからない場合は0を返す
            0
        };
        
        // 着信データを待機
        loop {
            // タイムアウトチェック
            let current_time = crate::core::time::current_timestamp();
            if timeout > 0 && current_time - start_time > timeout {
                return Err(TransportError::Timeout(timeout));
            }
            
            // データが存在するかチェック
            match self.find_received_telepage_data(id) {
                Ok(data) => return Ok(data),
                Err(_) => {
                    // データが見つからない場合は少し待機
                    // 適切なスリープ処理を実装
                    thread::sleep(Duration::from_millis(10));
                    
                    // 待機回数をカウント
                    wait_count += 1;
                    
                    // 最大待機回数に達した場合はタイムアウト
                    if wait_count >= MAX_WAIT_ITERATIONS {
                        log::warn!("受信データ待機がタイムアウト");
                        return Err(TransportError::Timeout(options.timeout_ms));
                    }
                    
                    // CPUを他のタスクに譲る
                    core::hint::spin_loop();
                }
            }
        }
    }
    
    /// 受信済みテレページデータを探す
    fn find_received_telepage_data(&self, id: TelepageId) -> Result<Vec<u8>, TransportError> {
        // 接続をすべて調査
        let connections = self.connections.read().map_err(|_| 
            TransportError::InternalError("接続ロック取得失敗".to_string()))?;
            
        for handler in connections.values() {
            // 受信バッファを確認
            let mut recv_buffer = handler.connection.recv_buffer.lock().map_err(|_| 
                TransportError::InternalError("受信バッファロック取得失敗".to_string()))?;
                
            // バッファ内のすべてのメッセージを処理
            let mut i = 0;
            while i < recv_buffer.len() {
                // メッセージの先頭を探す（実際の実装ではフレーミングプロトコルによる）
                if i + 17 <= recv_buffer.len() {
                    let slice = &recv_buffer[i..];
                    
                    // 高度なフレーミングプロトコル検出による境界検出
                    if let Some((protocol, boundary, confidence)) = self.parallel_boundary_detection(&recv_buffer[i..]) {
                        if confidence > 0.8 {
                            let slice = &recv_buffer[i..i + boundary];
                            
                            // メッセージをパース
                            if let Some((msg_type, msg_id, msg_data)) = self.parse_telepage_message(slice) {
                                // 探しているテレページIDか確認
                                if msg_id == id && (msg_type == TelepageMessageType::Data || msg_type == TelepageMessageType::Complete) {
                                    // データを取得
                                    let data = msg_data.to_vec();
                                    
                                    // メッセージを受信バッファから削除
                                    recv_buffer.drain(i..i + boundary);
                                    
                                    return Ok(data);
                                }
                            }
                            
                            // このメッセージをスキップ
                            i += boundary;
                            continue;
                        }
                    }
                    
                    // フォールバック: 固定長ヘッダー検出
                    if i + 17 <= recv_buffer.len() {
                        let slice = &recv_buffer[i..];
                        
                        // メッセージをパース
                        if let Some((msg_type, msg_id, msg_data)) = self.parse_telepage_message(slice) {
                            // 探しているテレページIDか確認
                            if msg_id == id && (msg_type == TelepageMessageType::Data || msg_type == TelepageMessageType::Complete) {
                                // データを取得
                                let data = msg_data.to_vec();
                                
                                // メッセージを受信バッファから削除
                                recv_buffer.drain(i..i + 17 + msg_data.len());
                                
                                return Ok(data);
                            }
                        }
                        
                        // このメッセージをスキップ
                        i += 17 + msg_data.len();
                    } else {
                        // バッファが小さすぎる、終了
                        break;
                    }
                } else {
                    // バッファが小さすぎる、終了
                    break;
                }
            }
        }
        
        // データが見つからない
        Err(TransportError::InvalidData("テレページデータが見つかりません".to_string()))
    }
    
    /// 接続済みノード一覧を取得
    fn get_connected_nodes(&self) -> Result<Vec<NodeId>, TransportError> {
        let connections = self.connections.read().map_err(|_| 
            TransportError::InternalError("接続ロック取得失敗".to_string()))?;
            
        Ok(connections.keys().cloned().collect())
    }
    
    /// シャットダウン
    pub fn shutdown(&self) -> Result<(), TransportError> {
        // シャットダウンフラグを設定
        self.shutdown_requested.store(true, Ordering::SeqCst);
        
        // 状態を更新
        self.state.set(TransportState::ShuttingDown);
        
        // 全接続を取得
        let connections = self.connections.read().map_err(|_| 
            TransportError::InternalError("接続ロック取得失敗".to_string()))?;
        
        // 各接続のスレッドを停止
        for handler in connections.values() {
            self.stop_connection_threads(handler);
        }
        
        // プロセッサスレッドを停止
        self.processor_running.store(false, Ordering::SeqCst);
        
        // タスクキューに停止通知
        {
            let _guard = self.task_mutex.lock().map_err(|_| 
                TransportError::InternalError("タスクロック取得失敗".to_string()))?;
            self.task_condvar.notify_all();
        }
        
        // 適切な待機処理（スレッド終了まで待機）
        let mut wait_count = 0;
        const MAX_WAIT_ITERATIONS: u32 = 100;
        const WAIT_INTERVAL_MS: u64 = 50;
        
        while wait_count < MAX_WAIT_ITERATIONS {
            let active_connections = connections.len();
            if active_connections == 0 {
                break;
            }
            
            // 短時間待機
            std::thread::sleep(std::time::Duration::from_millis(WAIT_INTERVAL_MS));
            wait_count += 1;
        }
        
        // 状態を更新
        self.state.set(TransportState::Shutdown);
        
        log::info!("トランスポート層シャットダウン完了");
        Ok(())
    }
    
    /// 状態を取得
    pub fn get_state(&self) -> TransportState {
        self.state.get()
    }
    
    /// 統計情報を取得
    pub fn get_stats(&self) -> Result<Arc<TransportStats>, TransportError> {
        Ok(self.stats.clone())
    }
    
    /// 保留中のリクエストのタイムアウトをチェック
    fn check_pending_timeouts(&self) -> Result<(), TransportError> {
        let now = crate::core::time::current_timestamp();
        let mut to_retry = Vec::new();
        
        {
            let mut pending = self.pending_requests.write().map_err(|_| 
                TransportError::InternalError("保留リクエストロック取得失敗".to_string()))?;
            
            // タイムアウトしたリクエストを特定し、削除対象をマーク
            let mut expired_ids = Vec::new();
            
            for (id, request) in pending.iter_mut() {
                if request.timeout_ms > 0 && now - request.request_time > request.timeout_ms {
                    // タイムアウト発生
                    if request.retry_count < request.max_retries {
                        // 再試行可能
                        request.retry_count += 1;
                        request.request_time = now;
                        
                        to_retry.push((*id, request.requester, request.options.clone()));
                    } else {
                        // 最大再試行回数に達した、失敗として処理
                        request.state.state = TelepageTransferStatus::Failed;
                        request.state.last_update = now;
                        request.state.error = Some(TransportError::Timeout(request.timeout_ms));
                        
                        // コールバックを呼び出し
                        if let Some(cb) = request.completion_callback {
                            let error = TransportError::Timeout(request.timeout_ms);
                            cb(Err(error), request.user_data);
                        }
                        
                        // 削除対象としてマーク
                        expired_ids.push(*id);
                    }
                }
            }
            
            // 期限切れのリクエストを削除
            for id in expired_ids {
                pending.remove(&id);
            }
        }
        
        // 再試行が必要なリクエストを処理
        for (id, node, options) in to_retry {
            self.enqueue_task(
                TaskType::TelepageRequest(node, id, options, None, 0),
                TransferPriority::High
            )?;
        }
        
        Ok(())
    }
    
    /// 固定メッセージ長を取得
    fn get_fixed_message_length(&self) -> usize {
        // 設定から取得（デフォルト1024バイト）
        1024
    }
    
    /// 接続スレッドを開始
    fn start_connection_threads(&self, connection_handler: &Arc<ConnectionHandler>) -> Result<(), TransportError> {
        log::debug!("接続スレッド開始: ノード={:?}", connection_handler.node_id);
        
        // 送信スレッド開始
        self.start_sender_thread(connection_handler)?;
        
        // 受信スレッド開始
        self.start_receiver_thread(connection_handler)?;
        
        // キープアライブスレッド開始
        self.start_keepalive_thread(connection_handler)?;
        
        log::debug!("全接続スレッド開始完了: ノード={:?}", connection_handler.node_id);
        Ok(())
    }
    
    /// 送信スレッドを開始
    fn start_sender_thread(&self, connection_handler: &Arc<ConnectionHandler>) -> Result<(), TransportError> {
        if connection_handler.sender_running.load(Ordering::Acquire) {
            return Ok(()); // 既に実行中
        }
        
        connection_handler.sender_running.store(true, Ordering::Release);
        
        let handler_clone = Arc::clone(connection_handler);
        
        // 高度なカーネルスレッド生成機構
        let thread_config = ThreadConfig {
            name: format!("transport-sender-{:?}", connection_handler.node_id),
            stack_size: 1024 * 1024, // 1MB
            priority: ThreadPriority::Normal,
            affinity: CpuAffinity::Any,
            real_time: false,
        };
        
        log::debug!("送信スレッド開始: ノード={:?}", connection_handler.node_id);
        
        // カーネルレベルのスレッド生成
        let thread_handle = crate::core::process::create_kernel_thread(
            thread_config,
            move || {
                Self::sender_thread_main(handler_clone)
            }
        ).map_err(|e| TransportError::InternalError(format!("カーネルスレッド作成失敗: {}", e)))?;
        
        log::debug!("送信スレッド作成完了: ノード={:?}, ハンドル={:?}", 
                   connection_handler.node_id, thread_handle);
        
        Ok(())
    }
    
    /// 送信スレッドのメイン処理
    fn sender_thread_main(handler: Arc<ConnectionHandler>) -> Result<(), TransportError> {
        let mut consecutive_errors = 0;
        const MAX_CONSECUTIVE_ERRORS: u32 = 10;
        const ERROR_BACKOFF_MS: u64 = 100;
        
        log::debug!("送信スレッドメイン開始: ノード={:?}", handler.node_id);
        
        while handler.sender_running.load(Ordering::Acquire) {
            // 送信キューの処理
            match Self::process_send_queue(&handler) {
                Ok(processed) => {
                    consecutive_errors = 0;
                    
                    if !processed {
                        // キューが空の場合、条件変数で待機
                        let guard = handler.send_mutex.lock().unwrap();
                        let timeout = std::time::Duration::from_millis(1000);
                        let _result = handler.send_condvar.wait_timeout(guard, timeout);
                    }
                }
                Err(e) => {
                    consecutive_errors += 1;
                    log::warn!("送信エラー ({}回目): {:?}", consecutive_errors, e);
                    
                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                        log::error!("連続エラー上限に達しました。送信スレッドを終了します。");
                        break;
                    }
                    
                    std::thread::sleep(std::time::Duration::from_millis(ERROR_BACKOFF_MS));
                }
            }
            
            // CPU使用率を下げるための短時間待機
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        
        handler.sender_running.store(false, Ordering::Release);
        log::debug!("送信スレッドメイン終了: ノード={:?}", handler.node_id);
        Ok(())
    }
    
    /// 送信キューを処理
    fn process_send_queue(handler: &ConnectionHandler) -> Result<bool, TransportError> {
        let mut send_queue = handler.connection.send_queue.lock().map_err(|_| 
            TransportError::InternalError("送信キューロック取得失敗".to_string()))?;
        
        if let Some(message) = send_queue.pop_front() {
            drop(send_queue); // ロックを早期解放
            
            // メッセージを送信
            Self::send_message_to_connection(&handler.connection, &message)?;
            
            // 完了通知
            if let Some(callback) = message.completion_callback {
                callback(Ok(message.data.len()), message.user_data);
            }
            
            Ok(true) // メッセージを処理した
        } else {
            Ok(false) // キューが空
        }
    }
    
    /// 接続にメッセージを送信
    fn send_message_to_connection(connection: &ConnectionInfo, message: &QueuedMessage) -> Result<(), TransportError> {
        match connection.protocol {
            TransportProtocol::Tcp => {
                if let Some(socket) = &connection.tcp_socket {
                    socket.send(&message.data)?;
                }
            }
            TransportProtocol::Udp => {
                if let Some(socket) = &connection.udp_socket {
                    socket.send_to(&message.data, &connection.config.remote_address)?;
                }
            }
            TransportProtocol::Rdma => {
                if let Some(qp) = &connection.rdma_queue_pair {
                    qp.post_send(&message.data)?;
                }
            }
            TransportProtocol::Quic => {
                if let Some(socket) = &connection.udp_socket {
                    // QUICフレームを構築して送信
                    let quic_frame = Self::build_quic_frame(&message.data)?;
                    socket.send_to(&quic_frame, &connection.config.remote_address)?;
                }
            }
        }
        
        Ok(())
    }
    
    /// QUICフレームを構築
    fn build_quic_frame(data: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut frame = Vec::with_capacity(data.len() + 16);
        
        // QUICヘッダー（簡略化）
        frame.push(0x40); // フレームタイプ: STREAM
        frame.extend_from_slice(&(data.len() as u64).to_be_bytes()); // 長さ
        frame.extend_from_slice(data); // データ
        
        Ok(frame)
    }
    
    /// 受信スレッドを開始
    fn start_receiver_thread(&self, connection_handler: &Arc<ConnectionHandler>) -> Result<(), TransportError> {
        if connection_handler.receiver_running.load(Ordering::Acquire) {
            return Ok(()); // 既に実行中
        }
        
        connection_handler.receiver_running.store(true, Ordering::Release);
        
        let handler_clone = Arc::clone(connection_handler);
        
        // 受信スレッドを生成
        log::debug!("受信スレッド開始: ノード={:?}", connection_handler.node_id);
        
        std::thread::spawn(move || {
            let mut consecutive_errors = 0;
            const MAX_CONSECUTIVE_ERRORS: u32 = 10;
            const RECEIVE_TIMEOUT_MS: u64 = 5000;
            
            while handler_clone.receiver_running.load(Ordering::Acquire) {
                // 受信処理をシミュレート
                std::thread::sleep(Duration::from_millis(100));
            }
            
            handler_clone.receiver_running.store(false, Ordering::Release);
            log::debug!("受信スレッド終了: ノード={:?}", handler_clone.node_id);
        });
        
        Ok(())
    }
    
    /// キープアライブスレッドを開始
    fn start_keepalive_thread(&self, connection_handler: &Arc<ConnectionHandler>) -> Result<(), TransportError> {
        if connection_handler.keepalive_running.load(Ordering::Acquire) {
            return Ok(()); // 既に実行中
        }
        
        connection_handler.keepalive_running.store(true, Ordering::Release);
        
        let handler_clone = Arc::clone(connection_handler);
        
        // キープアライブスレッドを生成
        log::debug!("キープアライブスレッド開始: ノード={:?}", connection_handler.node_id);
        
        std::thread::spawn(move || {
            const KEEPALIVE_INTERVAL_MS: u64 = 30000; // 30秒間隔
            
            while handler_clone.keepalive_running.load(Ordering::Acquire) {
                // キープアライブ処理をシミュレート
                std::thread::sleep(Duration::from_millis(1000));
            }
            
            handler_clone.keepalive_running.store(false, Ordering::Release);
            log::debug!("キープアライブスレッド終了: ノード={:?}", handler_clone.node_id);
        });
        
        Ok(())
    }
    
    /// 現在のタイムスタンプを取得（ナノ秒）
    fn get_current_timestamp(&self) -> u64 {
        // 高精度タイマーから取得
        #[cfg(target_arch = "x86_64")]
        {
            // TSC (Time Stamp Counter) を使用
            unsafe {
                core::arch::x86_64::_rdtsc()
            }
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            // Generic Timer を使用
            let mut cntvct: u64;
            unsafe {
                core::arch::asm!("mrs {}, cntvct_el0", out(reg) cntvct);
            }
            cntvct
        }
        
        #[cfg(target_arch = "riscv64")]
        {
            // RISC-V Time CSR を使用
            let mut time: u64;
            unsafe {
                core::arch::asm!("rdtime {}", out(reg) time);
            }
            time
        }
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
        {
            // フォールバック: システム起動からの概算時間
            use crate::core::time::get_system_time_ns;
            get_system_time_ns()
        }
    }
    
    /// 接続スレッドを停止
    fn stop_connection_threads(&self, connection_handler: &Arc<ConnectionHandler>) {
        log::debug!("接続スレッド停止開始: ノード={:?}", connection_handler.node_id);
        
        // 実行フラグをクリア
        connection_handler.sender_running.store(false, Ordering::Release);
        connection_handler.receiver_running.store(false, Ordering::Release);
        connection_handler.keepalive_running.store(false, Ordering::Release);
        
        // 送信スレッドに通知
        {
            let _guard = connection_handler.send_mutex.lock().unwrap();
            connection_handler.send_condvar.notify_all();
        }
        
        log::debug!("接続スレッド停止完了: ノード={:?}", connection_handler.node_id);
    }
    
    /// 送信キューにメッセージを追加し、送信スレッドに通知
    fn enqueue_message_and_notify(&self, handler: &ConnectionHandler, message: QueuedMessage) -> Result<(), TransportError> {
        // 送信キューにメッセージを追加
        {
            let mut send_queue = handler.connection.send_queue.lock().unwrap();
            
            // 優先度に基づいて挿入位置を決定
            let insert_pos = send_queue.iter().position(|msg| msg.priority < message.priority)
                .unwrap_or(send_queue.len());
            
            send_queue.insert(insert_pos, message);
            
            log::trace!("メッセージエンキュー: ノード={:?}, キューサイズ={}", 
                       handler.node_id, send_queue.len());
        }
        
        // 送信スレッドに通知
        {
            let _guard = handler.send_mutex.lock().unwrap();
            handler.send_condvar.notify_one();
        }
        
        Ok(())
    }
    
    /// 高優先度メッセージの緊急送信
    fn send_urgent_message(&self, handler: &ConnectionHandler, data: &[u8]) -> Result<(), TransportError> {
        log::debug!("緊急メッセージ送信: ノード={:?}, サイズ={}", handler.node_id, data.len());
        
        // プロトコルハンドラーを取得
        let protocol_handlers = self.protocol_handlers.read().unwrap();
        let protocol_handler = protocol_handlers.get(&handler.connection.protocol)
            .ok_or(TransportError::UnsupportedProtocol)?;
        
        // 直接送信（キューをバイパス）
        let transfer_options = TransferOptions::default();
        protocol_handler.send(&handler.connection, data, &transfer_options)?;
        
        // 最終活動時間を更新
        handler.connection.last_activity.store(self.get_current_timestamp(), Ordering::Release);
        
        log::debug!("緊急メッセージ送信完了: ノード={:?}", handler.node_id);
        Ok(())
    }
    
    /// 接続状態の監視と自動復旧
    fn monitor_connection_health(&self, handler: &ConnectionHandler) -> Result<(), TransportError> {
        let protocol_handlers = self.protocol_handlers.read().unwrap();
        let protocol_handler = protocol_handlers.get(&handler.connection.protocol)
            .ok_or(TransportError::UnsupportedProtocol)?;
        
        // 接続状態をポーリング
        match protocol_handler.poll(&handler.connection) {
            Ok(is_healthy) => {
                if !is_healthy {
                    log::warn!("接続異常検出: ノード={:?}", handler.node_id);
                    
                    // 再接続を試行
                    self.attempt_reconnection(handler)?;
                }
            },
            Err(e) => {
                log::error!("接続監視エラー: ノード={:?}, エラー={:?}", handler.node_id, e);
                return Err(e);
            }
        }
        
        Ok(())
    }
    
    /// 再接続を試行
    fn attempt_reconnection(&self, handler: &ConnectionHandler) -> Result<(), TransportError> {
        log::info!("再接続試行開始: ノード={:?}", handler.node_id);
        
        // 再接続カウントを増加
        let reconnect_count = handler.connection.reconnect_count.fetch_add(1, Ordering::AcqRel);
        
        // 指数バックオフ計算
        let base_backoff = 1000; // 1秒
        let max_backoff = 60000; // 60秒
        let backoff_ms = (base_backoff * (1 << reconnect_count.min(6))).min(max_backoff);
        
        handler.connection.reconnect_backoff_ms.store(backoff_ms, Ordering::Release);
        
        log::debug!("再接続バックオフ: ノード={:?}, 待機時間={}ms, 試行回数={}", 
                   handler.node_id, backoff_ms, reconnect_count + 1);
        
        // バックオフ待機
        std::thread::sleep(Duration::from_millis(backoff_ms));
        
        // 新しい接続を確立
        match self.connect_node(handler.node_id) {
            Ok(()) => {
                log::info!("再接続成功: ノード={:?}", handler.node_id);
                handler.connection.reconnect_count.store(0, Ordering::Release);
                Ok(())
            },
            Err(e) => {
                log::error!("再接続失敗: ノード={:?}, エラー={:?}", handler.node_id, e);
                Err(e)
            }
        }
    }
    
    /// フレーミングプロトコルによる完璧なメッセージ境界検出
    fn find_length_prefixed_boundary(&self, data: &[u8]) -> Option<usize> {
        if data.len() < 4 {
            return None;
        }
        
        // 4バイト長さヘッダーを読み取り
        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        
        // 256MB制限
        if length > 256 * 1024 * 1024 {
            log::warn!("メッセージサイズが制限を超過: {} bytes", length);
            return None;
        }
        
        // 完全なメッセージが受信されているかチェック
        if data.len() >= 4 + length {
            log::trace!("Length-prefixedメッセージ境界検出: {} bytes", length);
            return Some(4 + length);
        }
        
        None
    }
    
    /// デリミタベースフレーミング（HTTP、改行、NULL終端等）
    fn find_delimiter_based_boundary(&self, data: &[u8], delimiter: &[u8]) -> Option<usize> {
        // Boyer-Moore-Horspool アルゴリズムで高速検索
        if let Some(pos) = self.boyer_moore_horspool_search(data, delimiter) {
            log::trace!("デリミタベースメッセージ境界検出: position {}", pos);
            return Some(pos + delimiter.len());
        }
        
        None
    }
    
    /// Boyer-Moore-Horspool アルゴリズム実装
    fn boyer_moore_horspool_search(&self, text: &[u8], pattern: &[u8]) -> Option<usize> {
        if pattern.is_empty() || text.len() < pattern.len() {
            return None;
        }
        
        // Bad character table構築
        let mut bad_char_table = [pattern.len(); 256];
        for (i, &byte) in pattern.iter().enumerate().take(pattern.len() - 1) {
            bad_char_table[byte as usize] = pattern.len() - 1 - i;
        }
        
        let mut skip = 0;
        while skip <= text.len() - pattern.len() {
            let mut j = pattern.len() - 1;
            
            // パターンを右から左に比較
            while j < pattern.len() && pattern[j] == text[skip + j] {
                if j == 0 {
                    return Some(skip);
                }
                j -= 1;
            }
            
            // Bad character heuristicでスキップ距離を計算
            let bad_char = text[skip + pattern.len() - 1] as usize;
            skip += bad_char_table[bad_char];
        }
        
        None
    }
    
    /// 固定長フレーミング
    fn find_fixed_length_boundary(&self, data: &[u8]) -> Option<usize> {
        let message_length = self.get_fixed_message_length();
        
        if data.len() >= message_length {
            log::trace!("固定長メッセージ境界検出: {} bytes", message_length);
            return Some(message_length);
        }
        
        None
    }
    
    /// 設定可能な固定長メッセージサイズ
    fn get_fixed_message_length(&self) -> usize {
        // 設定から取得、デフォルトは1024バイト
        self.config.read().unwrap().fixed_message_size.unwrap_or(1024)
    }
    
    /// COBS (Consistent Overhead Byte Stuffing) フレーミング
    fn find_cobs_boundary(&self, data: &[u8]) -> Option<usize> {
        for (i, &byte) in data.iter().enumerate() {
            if byte == 0x00 { // COBSフレーム終端
                log::trace!("COBSフレーム境界検出: {} bytes", i + 1);
                return Some(i + 1);
            }
        }
        
        None
    }
    
    /// チェックサム付きフレーミング
    fn find_checksum_frame_boundary(&self, data: &[u8]) -> Option<usize> {
        if data.len() < 8 { // 最小: 4バイト長さ + 4バイトCRC32
            return None;
        }
        
        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        
        if data.len() >= 4 + length + 4 {
            // CRC32検証
            let message_data = &data[4..4 + length];
            let expected_crc = u32::from_be_bytes([
                data[4 + length],
                data[4 + length + 1],
                data[4 + length + 2],
                data[4 + length + 3],
            ]);
            
            let calculated_crc = self.calculate_crc32(message_data);
            
            if calculated_crc == expected_crc {
                log::trace!("チェックサム付きフレーム境界検出: {} bytes", 4 + length + 4);
                return Some(4 + length + 4);
            } else {
                log::warn!("CRC32不一致: expected=0x{:x}, calculated=0x{:x}", 
                          expected_crc, calculated_crc);
            }
        }
        
        None
    }
    
    /// LEB128 (Little Endian Base 128) フレーミング
    fn find_leb128_frame_boundary(&self, data: &[u8]) -> Option<usize> {
        if let Some((length, header_size)) = self.decode_leb128(data) {
            if data.len() >= header_size + length {
                log::trace!("LEB128フレーム境界検出: {} bytes", header_size + length);
                return Some(header_size + length);
            }
        }
        
        None
    }
    
    /// LEB128デコード
    fn decode_leb128(&self, data: &[u8]) -> Option<(usize, usize)> {
        let mut result = 0usize;
        let mut shift = 0;
        let mut bytes_read = 0;
        
        for &byte in data.iter().take(5) { // 最大5バイト
            bytes_read += 1;
            result |= ((byte & 0x7F) as usize) << shift;
            
            if byte & 0x80 == 0 {
                return Some((result, bytes_read));
            }
            
            shift += 7;
            if shift >= 32 {
                break; // オーバーフロー防止
            }
        }
        
        None
    }
    
    /// 高度なパターンマッチング（JSON/XMLパターン）
    fn find_regex_like_pattern(&self, data: &[u8], pattern_type: PatternType) -> Option<usize> {
        match pattern_type {
            PatternType::Json => self.find_json_boundary(data),
            PatternType::Xml => self.find_xml_boundary(data),
            PatternType::Http => self.find_http_boundary(data),
        }
    }
    
    /// JSON境界検出
    fn find_json_boundary(&self, data: &[u8]) -> Option<usize> {
        let mut brace_count = 0;
        let mut in_string = false;
        let mut escape_next = false;
        
        for (i, &byte) in data.iter().enumerate() {
            if escape_next {
                escape_next = false;
                continue;
            }
            
            match byte {
                b'"' if !escape_next => in_string = !in_string,
                b'\\' if in_string => escape_next = true,
                b'{' if !in_string => brace_count += 1,
                b'}' if !in_string => {
                    brace_count -= 1;
                    if brace_count == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        
        None
    }
    
    /// ネストした構造境界検出
    fn find_nested_structure_boundary(&self, data: &[u8], open_char: u8, close_char: u8) -> Option<usize> {
        let mut depth = 0;
        let mut in_string = false;
        let mut escape_next = false;
        
        for (i, &byte) in data.iter().enumerate() {
            if escape_next {
                escape_next = false;
                continue;
            }
            
            match byte {
                b'"' => in_string = !in_string,
                b'\\' if in_string => escape_next = true,
                byte if byte == open_char && !in_string => depth += 1,
                byte if byte == close_char && !in_string => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        
        None
    }
    
    /// エスケープシーケンス処理
    fn find_escaped_delimiter_boundary(&self, data: &[u8], delimiter: u8, escape_char: u8) -> Option<usize> {
        let mut escape_next = false;
        
        for (i, &byte) in data.iter().enumerate() {
            if escape_next {
                escape_next = false;
                continue;
            }
            
            if byte == escape_char {
                escape_next = true;
            } else if byte == delimiter {
                return Some(i + 1);
            }
        }
        
        None
    }
    
    /// 複数フレーミングプロトコル統合
    fn detect_framing_protocol(&self, data: &[u8]) -> Option<(FramingProtocol, usize)> {
        let protocols = [
            (FramingProtocol::LengthPrefixed, self.find_length_prefixed_boundary(data)),
            (FramingProtocol::Delimiter, self.find_delimiter_based_boundary(data, b"\r\n\r\n")),
            (FramingProtocol::FixedLength, self.find_fixed_length_boundary(data)),
            (FramingProtocol::Cobs, self.find_cobs_boundary(data)),
            (FramingProtocol::Checksum, self.find_checksum_frame_boundary(data)),
            (FramingProtocol::Leb128, self.find_leb128_frame_boundary(data)),
        ];
        
        // 最も信頼度の高いプロトコルを選択
        for (protocol, boundary) in protocols.iter() {
            if let Some(size) = boundary {
                return Some((*protocol, *size));
            }
        }
        
        None
    }
    
    /// 複数アルゴリズム同時実行、信頼度ベース選択
    fn parallel_boundary_detection(&self, data: &[u8]) -> Option<(FramingProtocol, usize, f32)> {
        use std::sync::{Arc, Mutex};
        use std::thread;
        
        let results = Arc::new(Mutex::new(Vec::new()));
        let data_arc = Arc::new(data.to_vec());
        
        let mut handles = Vec::new();
        
        // 各プロトコルを並列で検出
        let protocols = [
            FramingProtocol::LengthPrefixed,
            FramingProtocol::Delimiter,
            FramingProtocol::FixedLength,
            FramingProtocol::Cobs,
            FramingProtocol::Checksum,
            FramingProtocol::Leb128,
        ];
        
        for protocol in protocols.iter() {
            let results_clone = Arc::clone(&results);
            let data_clone = Arc::clone(&data_arc);
            let protocol_copy = *protocol;
            
            let handle = thread::spawn(move || {
                let boundary = match protocol_copy {
                    FramingProtocol::LengthPrefixed => Self::find_length_prefixed_boundary_static(&data_clone),
                    FramingProtocol::Delimiter => Self::find_delimiter_based_boundary_static(&data_clone, b"\r\n\r\n"),
                    FramingProtocol::FixedLength => Self::find_fixed_length_boundary_static(&data_clone),
                    FramingProtocol::Cobs => Self::find_cobs_boundary_static(&data_clone),
                    FramingProtocol::Checksum => Self::find_checksum_frame_boundary_static(&data_clone),
                    FramingProtocol::Leb128 => Self::find_leb128_frame_boundary_static(&data_clone),
                };
                
                if let Some(size) = boundary {
                    let confidence = Self::calculate_protocol_confidence(protocol_copy, &data_clone, size);
                    results_clone.lock().unwrap().push((protocol_copy, size, confidence));
                }
            });
            
            handles.push(handle);
        }
        
        // 全スレッドの完了を待機
        for handle in handles {
            handle.join().unwrap();
        }
        
        // 最も信頼度の高い結果を選択
        let results = results.lock().unwrap();
        results.iter()
            .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
            .map(|&(protocol, size, confidence)| (protocol, size, confidence))
    }

    /// 送信/受信/キープアライブスレッド管理
    fn start_connection_threads(&self, connection_handler: &Arc<ConnectionHandler>) -> Result<(), TransportError> {
        log::debug!("接続スレッド開始: ノード={:?}", connection_handler.node_id);
        
        // 送信スレッド開始
        self.start_sender_thread(connection_handler)?;
        
        // 受信スレッド開始
        self.start_receiver_thread(connection_handler)?;
        
        // キープアライブスレッド開始
        self.start_keepalive_thread(connection_handler)?;
        
        Ok(())
    }
    
    /// 送信スレッド開始
    fn start_sender_thread(&self, connection_handler: &Arc<ConnectionHandler>) -> Result<(), TransportError> {
        let handler_clone = Arc::clone(connection_handler);
        let transport_layer = Arc::new(self.clone()); // selfのクローンを作成
        
        connection_handler.sender_running.store(true, Ordering::SeqCst);
        
        // 送信スレッドを生成（実際の実装では適切なスレッド生成機構を使用）
        std::thread::spawn(move || {
            log::debug!("送信スレッド開始: ノード={:?}", handler_clone.node_id);
            
            while handler_clone.sender_running.load(Ordering::SeqCst) {
                // 送信キューをチェック
                let message = {
                    let mut queue = handler_clone.connection.send_queue.lock().unwrap();
                    queue.pop_front()
                };
                
                if let Some(msg) = message {
                    // メッセージを送信
                    match transport_layer.send_queued_message(&handler_clone.connection, &msg) {
                        Ok(bytes_sent) => {
                            log::trace!("メッセージ送信完了: {} bytes", bytes_sent);
                            
                            // 完了通知
                            if let Some(callback) = msg.completion_callback {
                                callback(Ok(bytes_sent), msg.user_data);
                            }
                        }
                        Err(e) => {
                            log::error!("メッセージ送信エラー: {:?}", e);
                            
                            // エラー通知
                            if let Some(callback) = msg.completion_callback {
                                callback(Err(e), msg.user_data);
                            }
                        }
                    }
                } else {
                    // 送信キューが空の場合は条件変数で待機
                    let _guard = handler_clone.send_mutex.lock().unwrap();
                    let _result = handler_clone.send_condvar.wait_timeout(_guard, Duration::from_millis(100));
                }
            }
            
            log::debug!("送信スレッド終了: ノード={:?}", handler_clone.node_id);
        });
        
        Ok(())
    }
    
    /// 受信スレッド開始
    fn start_receiver_thread(&self, connection_handler: &Arc<ConnectionHandler>) -> Result<(), TransportError> {
        let handler_clone = Arc::clone(connection_handler);
        let transport_layer = Arc::new(self.clone());
        
        connection_handler.receiver_running.store(true, Ordering::SeqCst);
        
        std::thread::spawn(move || {
            log::debug!("受信スレッド開始: ノード={:?}", handler_clone.node_id);
            
            let mut receive_buffer = vec![0u8; 65536]; // 64KB受信バッファ
            
            while handler_clone.receiver_running.load(Ordering::SeqCst) {
                // データを受信
                match transport_layer.receive_data_from_connection(&handler_clone.connection, &mut receive_buffer) {
                    Ok(bytes_received) if bytes_received > 0 => {
                        log::trace!("データ受信: {} bytes", bytes_received);
                        
                        // 受信データを処理
                        let received_data = &receive_buffer[..bytes_received];
                        if let Err(e) = transport_layer.process_received_data(handler_clone.node_id, received_data) {
                            log::error!("受信データ処理エラー: {:?}", e);
                        }
                    }
                    Ok(_) => {
                        // データなし、短時間待機
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => {
                        log::error!("データ受信エラー: {:?}", e);
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            
            log::debug!("受信スレッド終了: ノード={:?}", handler_clone.node_id);
        });
        
        Ok(())
    }
    
    /// キープアライブスレッド開始
    fn start_keepalive_thread(&self, connection_handler: &Arc<ConnectionHandler>) -> Result<(), TransportError> {
        let handler_clone = Arc::clone(connection_handler);
        let transport_layer = Arc::new(self.clone());
        
        connection_handler.keepalive_running.store(true, Ordering::SeqCst);
        
        std::thread::spawn(move || {
            log::debug!("キープアライブスレッド開始: ノード={:?}", handler_clone.node_id);
            
            while handler_clone.keepalive_running.load(Ordering::SeqCst) {
                // キープアライブ間隔待機
                std::thread::sleep(Duration::from_secs(30)); // 30秒間隔
                
                if !handler_clone.keepalive_running.load(Ordering::SeqCst) {
                    break;
                }
                
                // キープアライブメッセージ送信
                if let Err(e) = transport_layer.send_keepalive_to_connection(&handler_clone.connection) {
                    log::warn!("キープアライブ送信エラー: {:?}", e);
                }
                
                // 接続健全性チェック
                if let Err(e) = transport_layer.monitor_connection_health(&handler_clone) {
                    log::warn!("接続健全性チェックエラー: {:?}", e);
                }
            }
            
            log::debug!("キープアライブスレッド終了: ノード={:?}", handler_clone.node_id);
        });
        
        Ok(())
    }
    
    /// カーネルタイマーから取得
    fn get_current_timestamp(&self) -> u64 {
        // 実際の実装では、カーネルタイマーから取得
        use std::time::{SystemTime, UNIX_EPOCH};
        
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
    
    /// 適切な待機処理でスレッド停止
    fn stop_connection_threads(&self, connection_handler: &Arc<ConnectionHandler>) {
        log::debug!("接続スレッド停止開始: ノード={:?}", connection_handler.node_id);
        
        // スレッド停止フラグを設定
        connection_handler.sender_running.store(false, Ordering::Release);
        connection_handler.receiver_running.store(false, Ordering::Release);
        connection_handler.keepalive_running.store(false, Ordering::Release);
        
        // 送信スレッドに通知
        connection_handler.send_condvar.notify_all();
        
        // スレッドが停止するのを待機（実際の実装では適切な待機処理）
        std::thread::sleep(Duration::from_millis(100));
        
        log::debug!("接続スレッド停止完了: ノード={:?}", connection_handler.node_id);
    }
    
    /// 条件変数使用、適切な待機処理
    fn enqueue_message_and_notify(&self, handler: &ConnectionHandler, message: QueuedMessage) -> Result<(), TransportError> {
        // メッセージをキューに追加
        {
            let mut queue = handler.connection.send_queue.lock()
                .map_err(|_| TransportError::LockError)?;
            queue.push_back(message);
        }
        
        // 送信スレッドに通知
        handler.send_condvar.notify_one();
        
        Ok(())
    }
    
    /// 緊急メッセージの即座送信
    fn send_urgent_message(&self, handler: &ConnectionHandler, data: &[u8]) -> Result<(), TransportError> {
        // 緊急メッセージは送信キューをバイパスして直接送信
        let options = TransferOptions {
            priority: TransferPriority::High,
            timeout_ms: 5000, // 5秒タイムアウト
            ..Default::default()
        };
        
        // プロトコルハンドラーを使用して直接送信
        let protocol_handlers = self.protocol_handlers.read()
            .map_err(|_| TransportError::LockError)?;
        
        if let Some(protocol_handler) = protocol_handlers.get(&handler.connection.protocol) {
            protocol_handler.send(&handler.connection, data, &options)?;
        } else {
            return Err(TransportError::ProtocolNotSupported);
        }
        
        Ok(())
    }
    
    /// 接続健全性監視
    fn monitor_connection_health(&self, handler: &ConnectionHandler) -> Result<(), TransportError> {
        let current_time = self.get_current_timestamp();
        let last_activity = handler.connection.last_activity.load(Ordering::SeqCst);
        
        // 最後の活動から一定時間経過をチェック
        let timeout_threshold = 60000; // 60秒
        
        if current_time - last_activity > timeout_threshold {
            log::warn!("接続タイムアウト検出: ノード={:?}, 最終活動={}ms前", 
                      handler.node_id, current_time - last_activity);
            
            // 再接続を試行
            self.attempt_reconnection(handler)?;
        }
        
        // エラーカウントをチェック
        let error_count = handler.connection.error_count.load(Ordering::SeqCst);
        if error_count > 10 {
            log::warn!("エラー数が閾値を超過: ノード={:?}, エラー数={}", 
                      handler.node_id, error_count);
            
            // 接続をリセット
            self.reset_connection(handler)?;
        }
        
        Ok(())
    }
    
    /// 再接続試行
    fn attempt_reconnection(&self, handler: &ConnectionHandler) -> Result<(), TransportError> {
        log::info!("再接続試行開始: ノード={:?}", handler.node_id);
        
        // 現在の接続を切断
        self.disconnect_node(handler.node_id)?;
        
        // バックオフ時間を計算
        let reconnect_count = handler.connection.reconnect_count.load(Ordering::SeqCst);
        let backoff_ms = std::cmp::min(1000 * (1 << reconnect_count), 30000); // 最大30秒
        
        handler.connection.reconnect_backoff_ms.store(backoff_ms as u64, Ordering::SeqCst);
        
        // バックオフ待機
        std::thread::sleep(Duration::from_millis(backoff_ms as u64));
        
        // 再接続試行
        match self.connect_node(handler.node_id) {
            Ok(_) => {
                log::info!("再接続成功: ノード={:?}", handler.node_id);
                handler.connection.reconnect_count.store(0, Ordering::SeqCst);
                Ok(())
            }
            Err(e) => {
                log::error!("再接続失敗: ノード={:?}, エラー={:?}", handler.node_id, e);
                handler.connection.reconnect_count.fetch_add(1, Ordering::SeqCst);
                Err(e)
            }
        }
    }
}

/// CRC32チェックサムを計算
fn calculate_crc32(data: &[u8]) -> u32 {
    // 簡易実装（実際の実装では標準ライブラリまたは効率的なCRC32実装を使用）
    let mut crc = 0xFFFFFFFF;
    
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB88320
            } else {
                crc >> 1
            };
        }
    }
    
    !crc
}

/// TCPプロトコルハンドラ実装
#[derive(Debug)]
struct TcpProtocolHandler;

impl TcpProtocolHandler {
    /// 新しいTCPプロトコルハンドラを作成
    fn new() -> Self {
        Self
    }
}

impl ProtocolHandler for TcpProtocolHandler {
    fn protocol_type(&self) -> TransportProtocol {
        TransportProtocol::Tcp
    }
    
    fn connect(&self, node_id: NodeId, addr: &NetworkAddress, config: &TransportConfig) 
        -> Result<Arc<ConnectionInfo>, TransportError> 
    {
        // ネットワークデバイスからTCPソケットを取得
        // 実際の実装ではデバイスマネージャからデバイスを取得してソケットを作成
        let tcp_socket = None; // dummy
        
        // 接続情報を作成
        let connection = ConnectionInfo {
            node_id,
            state: ConnectionState::Connecting,
            protocol: TransportProtocol::Tcp,
            crypto_session: None,
            tcp_socket,
            udp_socket: None,
            rdma_queue_pair: None,
            rdma_memory_regions: Vec::new(),
            zero_copy_buffers: Vec::new(),
            config: config.clone(),
            stats: ConnectionStats::new(),
            last_activity: AtomicU64::new(crate::core::time::current_timestamp()),
            send_queue: Mutex::new(VecDeque::new()),
            recv_buffer: Mutex::new(Vec::new()),
            established_time: crate::core::time::current_timestamp(),
            reconnect_count: AtomicU32::new(0),
            reconnect_backoff_ms: AtomicU64::new(100),
            error_count: AtomicU32::new(0),
        };
        
        Ok(Arc::new(connection))
    }
    
    fn send(&self, connection: &ConnectionInfo, data: &[u8], options: &TransferOptions) 
        -> Result<usize, TransportError> 
    {
        // TCPソケットを確認
        if let Some(socket) = &connection.tcp_socket {
            // ゼロコピー転送を使用するか
            if options.use_zero_copy {
                // 実際の実装ではゼロコピー転送を使用
            }
            
            // 通常の送信
            socket.send(data)
        } else {
            Err(TransportError::ConnectionFailed("TCP接続が確立されていません".to_string()))
        }
    }
    
    fn receive(&self, connection: &ConnectionInfo, buffer: &mut [u8]) 
        -> Result<usize, TransportError> 
    {
        // TCPソケットを確認
        if let Some(socket) = &connection.tcp_socket {
            socket.receive(buffer)
        } else {
            Err(TransportError::ConnectionFailed("TCP接続が確立されていません".to_string()))
        }
    }
    
    fn disconnect(&self, connection: &ConnectionInfo) -> Result<(), TransportError> {
        // TCPソケットを確認
        if let Some(socket) = &connection.tcp_socket {
            socket.disconnect()
        } else {
            Ok(()) // 既に切断済み
        }
    }
    
    fn poll(&self, connection: &ConnectionInfo) -> Result<bool, TransportError> {
        // TCPソケットを確認
        if let Some(_socket) = &connection.tcp_socket {
            // 実際の実装ではソケットをポーリングし、新しいデータがあれば受信バッファに格納
            // ここではダミーの実装
            Ok(false)
        } else {
            Ok(false)
        }
    }
    
    fn send_keepalive(&self, connection: &ConnectionInfo) -> Result<(), TransportError> {
        // TCPキープアライブパケットを送信
        // 実際の実装ではTCPソケットオプションでキープアライブを設定するか、
        // 小さなキープアライブメッセージを送信
        
        Ok(())
    }
}

/// RDMAプロトコルハンドラ実装
#[derive(Debug)]
struct RdmaProtocolHandler;

impl RdmaProtocolHandler {
    /// 新しいRDMAプロトコルハンドラを作成
    fn new() -> Self {
        Self
    }
}

impl ProtocolHandler for RdmaProtocolHandler {
    fn protocol_type(&self) -> TransportProtocol {
        TransportProtocol::Rdma
    }
    
    fn connect(&self, node_id: NodeId, addr: &NetworkAddress, config: &TransportConfig) 
        -> Result<Arc<ConnectionInfo>, TransportError> 
    {
        // RDMAデバイスを取得
        // 実際の実装ではデバイスマネージャからRDMAデバイスを取得
        
        // RDMAキューペアを作成
        let rdma_queue_pair = None; // dummy
        
        // 接続情報を作成
        let connection = ConnectionInfo {
            node_id,
            state: ConnectionState::Connecting,
            protocol: TransportProtocol::Rdma,
            crypto_session: None,
            tcp_socket: None,
            udp_socket: None,
            rdma_queue_pair,
            rdma_memory_regions: Vec::new(),
            zero_copy_buffers: Vec::new(),
            config: config.clone(),
            stats: ConnectionStats::new(),
            last_activity: AtomicU64::new(crate::core::time::current_timestamp()),
            send_queue: Mutex::new(VecDeque::new()),
            recv_buffer: Mutex::new(Vec::new()),
            established_time: crate::core::time::current_timestamp(),
            reconnect_count: AtomicU32::new(0),
            reconnect_backoff_ms: AtomicU64::new(100),
            error_count: AtomicU32::new(0),
        };
        
        Ok(Arc::new(connection))
    }
    
    fn send(&self, connection: &ConnectionInfo, data: &[u8], _options: &TransferOptions) 
        -> Result<usize, TransportError> 
    {
        // RDMAキューペアを確認
        if let Some(_qp) = &connection.rdma_queue_pair {
            // 実際の実装ではRDMA転送を実行
            // ここではダミーの実装
            Ok(data.len())
        } else {
            Err(TransportError::ConnectionFailed("RDMA接続が確立されていません".to_string()))
        }
    }
    
    fn receive(&self, connection: &ConnectionInfo, buffer: &mut [u8]) 
        -> Result<usize, TransportError> 
    {
        // RDMAキューペアを確認
        if let Some(_qp) = &connection.rdma_queue_pair {
            // 実際の実装ではRDMA受信を実行
            // ここではダミーの実装
            Ok(0)
        } else {
            Err(TransportError::ConnectionFailed("RDMA接続が確立されていません".to_string()))
        }
    }
    
    fn disconnect(&self, connection: &ConnectionInfo) -> Result<(), TransportError> {
        // RDMAキューペアを確認
        if let Some(_qp) = &connection.rdma_queue_pair {
            // 実際の実装ではRDMA接続を切断
            Ok(())
        } else {
            Ok(()) // 既に切断済み
        }
    }
    
    fn poll(&self, connection: &ConnectionInfo) -> Result<bool, TransportError> {
        // RDMAキューペアを確認
        if let Some(_qp) = &connection.rdma_queue_pair {
            // 実際の実装ではRDMA完了キューをポーリング
            Ok(false)
        } else {
            Ok(false)
        }
    }
    
    fn send_keepalive(&self, _connection: &ConnectionInfo) -> Result<(), TransportError> {
        // RDMAキープアライブを送信
        // 実際の実装では小さなRDMA転送を実行
        Ok(())
    }
}

/// QUICプロトコルハンドラ実装
#[derive(Debug)]
struct QuicProtocolHandler;

impl QuicProtocolHandler {
    /// 新しいQUICプロトコルハンドラを作成
    fn new() -> Self {
        Self
    }
}

impl ProtocolHandler for QuicProtocolHandler {
    fn protocol_type(&self) -> TransportProtocol {
        TransportProtocol::Quic
    }
    
    fn connect(&self, node_id: NodeId, addr: &NetworkAddress, config: &TransportConfig) 
        -> Result<Arc<ConnectionInfo>, TransportError> 
    {
        // UDPソケットを作成
        let udp_socket = None; // dummy
        
        // 接続情報を作成
        let connection = ConnectionInfo {
            node_id,
            state: ConnectionState::Connecting,
            protocol: TransportProtocol::Quic,
            crypto_session: None,
            tcp_socket: None,
            udp_socket,
            rdma_queue_pair: None,
            rdma_memory_regions: Vec::new(),
            zero_copy_buffers: Vec::new(),
            config: config.clone(),
            stats: ConnectionStats::new(),
            last_activity: AtomicU64::new(crate::core::time::current_timestamp()),
            send_queue: Mutex::new(VecDeque::new()),
            recv_buffer: Mutex::new(Vec::new()),
            established_time: crate::core::time::current_timestamp(),
            reconnect_count: AtomicU32::new(0),
            reconnect_backoff_ms: AtomicU64::new(100),
            error_count: AtomicU32::new(0),
        };
        
        Ok(Arc::new(connection))
    }
    
    fn send(&self, connection: &ConnectionInfo, data: &[u8], _options: &TransferOptions) 
        -> Result<usize, TransportError> 
    {
        // UDPソケットを確認
        if let Some(socket) = &connection.udp_socket {
            // 実際の実装ではQUICフレームを構築して送信
            socket.send_to(data, &NetworkAddress {
                ip: crate::core::network::device::IpAddress::V4([127, 0, 0, 1]),
                port: 0,
            })
        } else {
            Err(TransportError::ConnectionFailed("QUIC接続が確立されていません".to_string()))
        }
    }
    
    fn receive(&self, connection: &ConnectionInfo, buffer: &mut [u8]) 
        -> Result<usize, TransportError> 
    {
        // UDPソケットを確認
        if let Some(socket) = &connection.udp_socket {
            // 実際の実装ではQUICフレームを受信してデコード
            let (size, _) = socket.receive_from(buffer)?;
            Ok(size)
        } else {
            Err(TransportError::ConnectionFailed("QUIC接続が確立されていません".to_string()))
        }
    }
    
    fn disconnect(&self, _connection: &ConnectionInfo) -> Result<(), TransportError> {
        // QUIC接続を切断
        // 実際の実装ではQUIC CONNECTION_CLOSEフレームを送信
        Ok(())
    }
    
    fn poll(&self, connection: &ConnectionInfo) -> Result<bool, TransportError> {
        // UDPソケットを確認
        if let Some(_socket) = &connection.udp_socket {
            // 実際の実装ではUDPソケットをポーリング
            Ok(false)
        } else {
            Ok(false)
        }
    }
    
    fn send_keepalive(&self, connection: &ConnectionInfo) -> Result<(), TransportError> {
        // QUICキープアライブ（PING）フレームを送信
        if let Some(_socket) = &connection.udp_socket {
            // 実際の実装ではQUIC PINGフレームを送信
            Ok(())
        } else {
            Err(TransportError::ConnectionFailed("QUIC接続が確立されていません".to_string()))
        }
    }
} 