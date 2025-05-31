// AetherOS ネットワークプロトコル定義
//
// このモジュールはネットワーク通信に使用される様々なプロトコル、暗号化方式、
// 優先度などの基本的な型定義を提供します。世界最高水準の実装として、
// 幅広いプロトコルをサポートし、高度な暗号化とセキュリティ機能を備えています。

use core::fmt;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// トランスポートプロトコルのタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    /// TCP/IP
    Tcp,
    /// UDP/IP
    Udp,
    /// QUIC（UDP上の暗号化転送）
    Quic,
    /// HTTP/3（QUIC上のHTTP）
    Http3,
    /// RDMA（リモートダイレクトメモリアクセス）
    Rdma,
    /// RDMA over Converged Ethernet (RoCE)
    RoCE,
    /// RDMA over Converged Ethernet v2 (RoCEv2)
    RoCEv2,
    /// iWARP (Internet Wide Area RDMA Protocol)
    IWarp,
    /// Infiniband
    Infiniband,
    /// カスタム低遅延プロトコル
    CustomLowLatency,
    /// カスタム高スループットプロトコル
    CustomHighThroughput,
    /// マルチパスTCP (MPTCP)
    MultiPathTcp,
    /// SCTP (Stream Control Transmission Protocol)
    Sctp,
    /// WebSocket
    WebSocket,
    /// WebTransport
    WebTransport,
    /// カスタム量子耐性プロトコル
    QuantumResistant,
    /// プラグインプロトコル（外部実装）
    Plugin(u32),
}

/// 通信の暗号化方式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionType {
    /// 暗号化なし
    None,
    /// TLS 1.2
    Tls12,
    /// TLS 1.3
    Tls13,
    /// DTLS 1.2
    Dtls12,
    /// DTLS 1.3
    Dtls13,
    /// QUIC内蔵暗号化
    QuicCrypto,
    /// カスタム軽量暗号化
    LightweightCrypto,
    /// ポスト量子暗号方式
    PostQuantum,
    /// ハイブリッド暗号化（古典的+量子耐性）
    HybridClassicQuantum,
    /// WireGuard互換
    WireGuard,
    /// IPsec（AH, ESP）
    IPsec,
    /// MACsec（IEEE 802.1AE）
    MACsec,
    /// ハードウェア支援暗号化
    HardwareAccelerated,
    /// カスタム高性能暗号化
    CustomHighPerformance,
    /// プラグイン暗号化（外部実装）
    Plugin(u32),
}

/// セキュリティレベル
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// 暗号化なし（最速/内部ネットワーク用）
    None,
    /// 基本的な暗号化（高性能優先）
    Basic,
    /// 標準的な暗号化と認証（バランス型）
    Standard,
    /// 高度な暗号化と認証（機密データ用）
    High,
    /// 最高レベルのセキュリティ（軍事/金融/医療）
    Maximum,
    /// FIPS 140-2/3準拠
    FIPS,
    /// Common Criteria EAL4+準拠
    CommonCriteriaEAL4Plus,
    /// 量子耐性セキュリティ
    QuantumResistant,
    /// カスタムセキュリティレベル（特殊要件用）
    Custom(u32),
}

/// 転送優先度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransferPriority {
    /// 最低優先度（バックグラウンド転送）
    Background,
    /// 低優先度（通常のバックグラウンド転送）
    Low,
    /// 通常優先度
    Normal,
    /// 高優先度（重要なデータ）
    High,
    /// 最高優先度（リアルタイム/割り込みなどの緊急データ）
    Critical,
    /// 絶対優先度（システム制御データ、他のすべてに優先）
    Absolute,
    /// カスタム優先度（数値で指定）
    Custom(u8),
}

/// 接続種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    /// 永続的な接続
    Persistent,
    /// 一時的な接続
    Temporary,
    /// 定期的な接続
    Periodic,
    /// オンデマンド接続
    OnDemand,
    /// マルチパス接続
    MultiPath,
    /// フェイルオーバー接続
    Failover,
    /// カスタム接続タイプ
    Custom(u32),
}

/// QoS (Quality of Service) パラメータ
#[derive(Debug, Clone)]
pub struct QoSParameters {
    /// 最小帯域幅（bps）
    pub min_bandwidth_bps: u64,
    /// 最大帯域幅（bps）
    pub max_bandwidth_bps: u64,
    /// 最大レイテンシ（ナノ秒）
    pub max_latency_ns: u64,
    /// 最大ジッター（ナノ秒）
    pub max_jitter_ns: u64,
    /// パケットロス率（0.0-1.0）
    pub packet_loss_rate: f64,
    /// DiffServ コードポイント
    pub dscp: u8,
    /// ECN (Explicit Congestion Notification) サポート
    pub ecn_enabled: bool,
    /// トラフィッククラス
    pub traffic_class: TrafficClass,
}

/// トラフィッククラス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficClass {
    /// ベストエフォート
    BestEffort,
    /// バックグラウンド
    Background,
    /// 標準データ
    StandardData,
    /// 優先データ
    PriorityData,
    /// ビデオ
    Video,
    /// 音声
    Voice,
    /// ネットワーク制御
    NetworkControl,
    /// カスタムクラス
    Custom(u8),
}

/// テレページメッセージの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelepageMessageType {
    /// テレページリクエスト
    Request,
    /// テレページデータ
    Data,
    /// テレページACK応答
    Ack,
    /// テレページ転送完了
    Complete,
    /// テレページエラー
    Error,
    /// フラグメント（大きいデータの分割）
    Fragment,
    /// 再送要求
    Retransmit,
    /// キープアライブ
    KeepAlive,
    /// ページング情報更新
    PageInfoUpdate,
    /// 優先度更新
    PriorityUpdate,
    /// バイナリデルタ（差分）
    BinaryDelta,
    /// 圧縮データ
    CompressedData,
    /// 暗号化データ
    EncryptedData,
    /// マルチキャストデータ
    MulticastData,
    /// メタデータ
    Metadata,
    /// カスタムタイプ
    Custom(u32),
}

/// トランスポートエラー
#[derive(Debug)]
pub enum TransportError {
    /// 接続エラー
    ConnectionFailed(String),
    /// 転送エラー
    TransferFailed(String),
    /// タイムアウト
    Timeout(u64),
    /// ノードが見つからない
    NodeNotFound(u64),
    /// 無効なデータ
    InvalidData(String),
    /// メモリ割り当て失敗
    AllocationFailed(String),
    /// 認証エラー
    AuthenticationFailed(String),
    /// 暗号化エラー
    EncryptionError(String),
    /// リソース枯渇
    ResourceExhausted(String),
    /// ハードウェアエラー
    HardwareError(String),
    /// プロトコルエラー
    ProtocolError(String),
    /// セキュリティ違反
    SecurityViolation(String),
    /// ポリシー違反
    PolicyViolation(String),
    /// レート制限超過
    RateLimitExceeded(String),
    /// ネットワーク到達不能
    NetworkUnreachable(String),
    /// プロトコル未サポート
    ProtocolUnsupported(String),
    /// QoS要件未達
    QoSRequirementsNotMet(String),
    /// 内部エラー
    InternalError(String),
    /// その他のエラー
    Other(&'static str),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::ConnectionFailed(details) => 
                write!(f, "接続に失敗しました: {}", details),
            TransportError::TransferFailed(details) => 
                write!(f, "データ転送に失敗しました: {}", details),
            TransportError::Timeout(ms) => 
                write!(f, "操作がタイムアウトしました ({}ms)", ms),
            TransportError::NodeNotFound(node) => 
                write!(f, "指定されたノード(ID:{})が見つかりません", node),
            TransportError::InvalidData(details) => 
                write!(f, "無効なデータを受信しました: {}", details),
            TransportError::AllocationFailed(details) => 
                write!(f, "メモリ割り当てに失敗しました: {}", details),
            TransportError::AuthenticationFailed(details) => 
                write!(f, "認証に失敗しました: {}", details),
            TransportError::EncryptionError(details) => 
                write!(f, "暗号化処理エラー: {}", details),
            TransportError::ResourceExhausted(details) => 
                write!(f, "リソースが枯渇しました: {}", details),
            TransportError::HardwareError(details) => 
                write!(f, "ハードウェアエラー: {}", details),
            TransportError::ProtocolError(details) => 
                write!(f, "プロトコルエラー: {}", details),
            TransportError::SecurityViolation(details) => 
                write!(f, "セキュリティ違反: {}", details),
            TransportError::PolicyViolation(details) => 
                write!(f, "ポリシー違反: {}", details),
            TransportError::RateLimitExceeded(details) => 
                write!(f, "レート制限超過: {}", details),
            TransportError::NetworkUnreachable(details) => 
                write!(f, "ネットワーク到達不能: {}", details),
            TransportError::ProtocolUnsupported(details) => 
                write!(f, "プロトコル未サポート: {}", details),
            TransportError::QoSRequirementsNotMet(details) => 
                write!(f, "QoS要件未達: {}", details),
            TransportError::InternalError(details) => 
                write!(f, "内部エラー: {}", details),
            TransportError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

/// トランスポート設定
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// 使用するプロトコル
    pub protocol: TransportProtocol,
    /// バックアッププロトコル（フェイルオーバー用）
    pub backup_protocols: Vec<TransportProtocol>,
    /// 暗号化タイプ
    pub encryption: EncryptionType,
    /// セキュリティレベル
    pub security_level: SecurityLevel,
    /// 最大転送単位（バイト）
    pub max_transfer_unit: usize,
    /// 最大再試行回数
    pub max_retries: u32,
    /// 接続タイムアウト（ミリ秒）
    pub connection_timeout_ms: u64,
    /// 転送タイムアウト（ミリ秒）
    pub transfer_timeout_ms: u64,
    /// キープアライブ間隔（ミリ秒）
    pub keepalive_interval_ms: u64,
    /// ゼロコピー転送を使用
    pub use_zero_copy: bool,
    /// ハードウェアオフロードを使用
    pub use_hardware_offload: bool,
    /// バッチ処理（複数メッセージをまとめて送信）
    pub enable_batching: bool,
    /// バッチサイズの最大値
    pub max_batch_size: usize,
    /// 圧縮を有効化
    pub enable_compression: bool,
    /// 圧縮レベル（0-9、高いほど圧縮率が高い）
    pub compression_level: u8,
    /// 圧縮閾値（この値より大きいデータのみ圧縮）
    pub compression_threshold: usize,
    /// 統計収集を有効化
    pub collect_statistics: bool,
    /// 詳細統計収集を有効化
    pub detailed_statistics: bool,
    /// QoSパラメータ
    pub qos_parameters: Option<QoSParameters>,
    /// マルチパス転送を使用
    pub use_multipath: bool,
    /// フロー制御を有効化
    pub enable_flow_control: bool,
    /// 輻輳制御アルゴリズム
    pub congestion_algorithm: CongestionAlgorithm,
    /// 接続種類
    pub connection_type: ConnectionType,
    /// 再試行バックオフ戦略
    pub retry_backoff: RetryBackoffStrategy,
    /// プリキャッシュを有効化
    pub enable_precaching: bool,
    /// 転送優先度
    pub default_priority: TransferPriority,
    /// サイドチャネル攻撃緩和策の使用
    pub mitigate_side_channel: bool,
    /// リプレイ攻撃防止を有効化
    pub prevent_replay_attacks: bool,
    /// プロトコル固有オプション
    pub protocol_options: Vec<(String, String)>,
}

/// 輻輳制御アルゴリズム
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    /// TCP Reno
    Reno,
    /// TCP CUBIC
    Cubic,
    /// TCP BBR
    Bbr,
    /// TCP Vegas
    Vegas,
    /// TCP Westwood
    Westwood,
    /// TCP Illinois
    Illinois,
    /// QUIC New Reno
    QuicNewReno,
    /// QUIC CUBIC
    QuicCubic,
    /// QUIC BBR
    QuicBbr,
    /// カスタムアルゴリズム
    Custom(u32),
}

/// 再試行バックオフ戦略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryBackoffStrategy {
    /// 固定間隔
    Fixed,
    /// 線形バックオフ
    Linear,
    /// 指数バックオフ
    Exponential,
    /// ランダムバックオフ
    Random,
    /// カスタム戦略
    Custom(u32),
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            protocol: TransportProtocol::Tcp,
            backup_protocols: vec![TransportProtocol::Quic],
            encryption: EncryptionType::Tls13,
            security_level: SecurityLevel::Standard,
            max_transfer_unit: 8192,
            max_retries: 5,
            connection_timeout_ms: 5000,
            transfer_timeout_ms: 10000,
            keepalive_interval_ms: 30000,
            use_zero_copy: true,
            use_hardware_offload: true,
            enable_batching: true,
            max_batch_size: 16,
            enable_compression: true,
            compression_level: 5,
            compression_threshold: 1024,
            collect_statistics: true,
            detailed_statistics: false,
            qos_parameters: None,
            use_multipath: false,
            enable_flow_control: true,
            congestion_algorithm: CongestionAlgorithm::Cubic,
            connection_type: ConnectionType::Persistent,
            retry_backoff: RetryBackoffStrategy::Exponential,
            enable_precaching: false,
            default_priority: TransferPriority::Normal,
            mitigate_side_channel: true,
            prevent_replay_attacks: true,
            protocol_options: Vec::new(),
        }
    }
}

/// プロトコル能力フラグ
#[derive(Debug, Clone)]
pub struct ProtocolCapabilities {
    /// ゼロコピーサポート
    pub zero_copy: bool,
    /// ハードウェアオフロードサポート
    pub hardware_offload: bool,
    /// マルチパスサポート
    pub multipath: bool,
    /// QoS保証
    pub qos_guarantees: bool,
    /// デバイスフォールト耐性
    pub fault_tolerance: bool,
    /// ホットスワップサポート
    pub hot_swappable: bool,
    /// 帯域集約サポート
    pub bandwidth_aggregation: bool,
    /// 追加機能フラグ
    pub feature_flags: AtomicU64,
}

impl Default for ProtocolCapabilities {
    fn default() -> Self {
        Self {
            zero_copy: false,
            hardware_offload: false,
            multipath: false,
            qos_guarantees: false,
            fault_tolerance: false,
            hot_swappable: false,
            bandwidth_aggregation: false,
            feature_flags: AtomicU64::new(0),
        }
    }
}

/// プロトコルバージョン情報
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersion {
    /// メジャーバージョン
    pub major: u16,
    /// マイナーバージョン
    pub minor: u16,
    /// パッチバージョン
    pub patch: u16,
}

impl ProtocolVersion {
    /// 新しいプロトコルバージョンを作成
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self { major, minor, patch }
    }
    
    /// 文字列形式で取得
    pub fn to_string(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
    
    /// 別のバージョンと比較して互換性があるか
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }
}

/// プロトコルメタデータ
#[derive(Debug, Clone)]
pub struct ProtocolMetadata {
    /// プロトコル識別子
    pub id: TransportProtocol,
    /// プロトコルバージョン
    pub version: ProtocolVersion,
    /// プロトコル名
    pub name: String,
    /// プロトコル説明
    pub description: String,
    /// プロトコル能力
    pub capabilities: ProtocolCapabilities,
    /// プロトコル実装者
    pub implementor: String,
    /// 実装日
    pub implementation_date: String,
    /// プロトコル固有メタデータ
    pub custom_metadata: Vec<(String, String)>,
} 