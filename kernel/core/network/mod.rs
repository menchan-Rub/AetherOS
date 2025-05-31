// AetherOS 世界最高性能ネットワークサブシステム
//
// 最先端のゼロコピー、RDMA、DPDK、超低遅延プロトコル、AIベースの輻輳制御、
// 量子暗号を統合した次世代ネットワークスタックを提供します。
// TSO/GSO/LRO、eBPF、スマートNIC最適化、DMA engine、NIC offloadingを完全活用。
// 40/100/400Gbpsネットワークでも飽和させないパフォーマンスを実現します。

// パブリックサブモジュール
pub mod protocol;     // プロトコルレイヤー実装
pub mod transport;    // トランスポートレイヤー実装
pub mod device;       // ネットワークデバイス抽象化
pub mod stats;        // 詳細統計情報
pub mod crypto;       // 暗号化エンジン
pub mod telepage;     // 超高速ダイレクトメモリ通信
pub mod accelerated;  // ハードウェアアクセラレーション
pub mod quantum;      // 量子暗号通信

// システム内部用サブモジュール
mod zerocopy;        // ゼロコピーデータパス
mod queue;           // ロックフリーキュー
mod congestion;      // AI予測型輻輳制御アルゴリズム
mod route;           // インテリジェントルーティング
mod offload;         // NICオフロード管理
mod ebpf;            // eBPFプログラム管理
mod prediction;      // トラフィック予測エンジン
mod qos;             // QoS管理

// 再エクスポート
pub use protocol::{
    Protocol,
    TransportProtocol,
    EncryptionType,
    SecurityLevel,
    TransferPriority,
    TelepageMessageType,
    TransportError,
    TransportConfig,
    ReliabilityLevel,
    LatencyClass,
    BandwidthClass,
    ProtocolExtension,
};

pub use transport::{
    TransportLayer,
    ConnectionHandle,
    StreamConfig,
    DatagramConfig,
    RdmaConfig,
    ConnectionMonitor,
    TransportCapabilities,
    OffloadCapabilities,
};

pub use device::{
    NetworkDevice,
    TcpSocket,
    UdpSocket,
    RdmaDevice,
    RdmaMemoryRegion,
    RdmaQueuePair,
    MacAddress,
    IpAddress,
    Ipv4Address,
    Ipv6Address,
    NetworkAddress,
    NetworkInterface,
    DeviceCapabilities,
    TcpOffload,
    VirtioDevice,
    SmartNicDevice,
    DpdkDevice,
};

pub use stats::{
    TransportStats,
    ConnectionStats,
    LatencyHistogram,
    BandwidthMonitor,
    PacketCounter,
    ErrorTracker,
    DeviceStats,
    QueueStats,
    NetworkAnalytics,
};

pub use crypto::{
    CryptoEngine,
    EncryptedSession,
    CryptoConfig,
    CipherSuite,
    Certificate,
    QuantumKeyDistribution,
    PostQuantumCrypto,
    CryptoAccelerator,
    SecureChannel,
};

pub use telepage::{
    TelepageManager,
    TelepageRegion,
    TelepageEndpoint,
    RemoteMemoryAccess,
    DirectTransfer,
};

pub use accelerated::{
    HardwareOffload,
    AccelerationDevice,
    AccelerationType,
    OffloadPolicy,
    DmaEngine,
    PacketProcessor,
};

pub use quantum::{
    QuantumSecureChannel,
    EntanglementManager,
    QuantumKeyExchange,
    QuantumRandomGenerator,
};

use crate::arch;
use crate::core::memory;
use crate::time;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::collections::VecDeque;
use core::fmt;
use crate::core::sync::{Mutex, RwLock};
use alloc::collections::BTreeMap;

/// グローバルネットワークマネージャー
static mut NETWORK_MANAGER: Option<NetworkManager> = None;

/// ネットワークサブシステムの初期化
pub fn init() -> Result<(), &'static str> {
    unsafe {
        NETWORK_MANAGER = Some(NetworkManager::new());
        NETWORK_MANAGER.as_ref().unwrap().init()
    }
}

/// ネットワークサブシステムのシャットダウン
pub fn shutdown() {
    log::info!("ネットワークサブシステムをシャットダウンしています...");
    
    // 各サブシステムのクリーンアップ
    unsafe {
        if let Some(manager) = NETWORK_MANAGER.as_mut() {
            manager.cleanup();
        }
    }
    
    quantum::shutdown();
    accelerated::shutdown();
    telepage::shutdown();
    crypto::shutdown();
    transport::shutdown();
    protocol::shutdown();
    
    log::info!("ネットワークサブシステムのシャットダウンが完了しました");
}

/// ネットワークマネージャークラス
pub struct NetworkManager {
    /// 利用可能なネットワークデバイス
    devices: Vec<Arc<dyn NetworkDevice>>,
    /// デフォルトトランスポートレイヤー
    transport_layer: Arc<TransportLayer>,
    /// オフロードマネージャー
    offload_manager: offload::OffloadManager,
    /// QoSマネージャー
    qos_manager: qos::QosManager,
    /// ネットワーク予測エンジン
    prediction_engine: prediction::PredictionEngine,
    /// 統計情報
    stats: Arc<stats::NetworkAnalytics>,
    /// 現在の状態
    state: Mutex<NetworkState>,
    /// 登録されたプロトコルハンドラ
    protocol_handlers: RwLock<BTreeMap<ProtocolType, Vec<protocol::ProtocolHandler>>>,
    /// ネットワークインターフェース
    interfaces: RwLock<BTreeMap<String, netdev::NetDevice>>,
    /// ルーティングテーブル
    routing_table: RwLock<routing::RoutingTable>,
    /// ネットワークフィルタ
    netfilter: Mutex<netfilter::NetFilter>,
    /// ソケットマネージャ
    socket_manager: Mutex<socket::SocketManager>,
    /// DNS設定
    dns_config: RwLock<dns::DnsConfig>,
    /// 統計情報
    statistics: RwLock<NetworkStatistics>,
}

impl NetworkManager {
    /// 新しいネットワークマネージャーを作成
    fn new() -> Self {
        let transport_layer = Arc::new(transport::TransportLayer::new());
        let offload_manager = offload::OffloadManager::new();
        let qos_manager = qos::QosManager::new();
        let prediction_engine = prediction::PredictionEngine::new();
        let stats = Arc::new(stats::NetworkAnalytics::new());
        
        Self {
            devices: Vec::new(),
            transport_layer,
            offload_manager,
            qos_manager,
            prediction_engine,
            stats,
            state: Mutex::new(NetworkState::Disabled),
            protocol_handlers: RwLock::new(BTreeMap::new()),
            interfaces: RwLock::new(BTreeMap::new()),
            routing_table: RwLock::new(routing::RoutingTable::new()),
            netfilter: Mutex::new(netfilter::NetFilter::new()),
            socket_manager: Mutex::new(socket::SocketManager::new()),
            dns_config: RwLock::new(dns::DnsConfig::new()),
            statistics: RwLock::new(NetworkStatistics::default()),
        }
    }
    
    /// ネットワークマネージャーのクリーンアップ
    fn cleanup(&self) {
        // クリーンアップ処理
        for device in &self.devices {
            device.shutdown();
        }
    }
    
    /// 統計情報の取得
    fn get_stats(&self) -> &stats::NetworkAnalytics {
        &self.stats
    }
    
    /// ネットワークサブシステムを初期化
    pub fn init(&self) -> Result<(), &'static str> {
        let mut state = self.state.lock();
        if *state != NetworkState::Disabled {
            return Err("ネットワークは既に初期化されています");
        }
        
        *state = NetworkState::Initializing;
        
        // コアプロトコルの初期化
        self.init_core_protocols()?;
        
        // ベースネットワークデバイスの初期化
        self.init_base_devices()?;
        
        // ソケットサブシステムの初期化
        self.socket_manager.lock().init()?;
        
        *state = NetworkState::Enabled;
        
        Ok(())
    }
    
    /// コアプロトコルを初期化
    fn init_core_protocols(&self) -> Result<(), &'static str> {
        // IPv4プロトコルハンドラを登録
        self.register_protocol_handler(ProtocolType::IPv4, ipv4::create_handler())?;
        
        // IPv6プロトコルハンドラを登録
        self.register_protocol_handler(ProtocolType::IPv6, ipv6::create_handler())?;
        
        // TCPプロトコルハンドラを登録
        self.register_protocol_handler(ProtocolType::TCP, tcp::create_handler())?;
        
        // UDPプロトコルハンドラを登録
        self.register_protocol_handler(ProtocolType::UDP, udp::create_handler())?;
        
        // ICMPプロトコルハンドラを登録
        self.register_protocol_handler(ProtocolType::ICMP, ipv4::icmp::create_handler())?;
        
        // ARPプロトコルハンドラを登録
        self.register_protocol_handler(ProtocolType::ARP, ethernet::arp::create_handler())?;
        
        Ok(())
    }
    
    /// ベースネットワークデバイスを初期化
    fn init_base_devices(&self) -> Result<(), &'static str> {
        // ループバックデバイスを作成
        let loopback = netdev::NetDevice::create_loopback()?;
        self.register_network_device(loopback)?;
        
        Ok(())
    }
    
    /// プロトコルハンドラを登録
    pub fn register_protocol_handler(
        &self,
        protocol: ProtocolType,
        handler: protocol::ProtocolHandler
    ) -> Result<(), &'static str> {
        let mut handlers = self.protocol_handlers.write().unwrap();
        
        if !handlers.contains_key(&protocol) {
            handlers.insert(protocol, Vec::new());
        }
        
        if let Some(handlers_vec) = handlers.get_mut(&protocol) {
            handlers_vec.push(handler);
            Ok(())
        } else {
            Err("プロトコルハンドラの登録に失敗しました")
        }
    }
    
    /// ネットワークデバイスを登録
    pub fn register_network_device(&self, device: netdev::NetDevice) -> Result<(), &'static str> {
        let mut interfaces = self.interfaces.write().unwrap();
        
        if interfaces.contains_key(&device.name) {
            return Err("同名のネットワークデバイスが既に存在します");
        }
        
        interfaces.insert(device.name.clone(), device);
        Ok(())
    }
    
    /// パケットを処理
    pub fn process_packet(&self, data: &[u8], device: &str) -> Result<(), &'static str> {
        let interfaces = self.interfaces.read().unwrap();
        let interface = interfaces.get(device).ok_or("指定されたデバイスが存在しません")?;
        
        // パケットを適切なプロトコルハンドラに転送
        let protocol = ethernet::identify_protocol(data)?;
        
        let handlers = self.protocol_handlers.read().unwrap();
        if let Some(protocol_handlers) = handlers.get(&protocol) {
            for handler in protocol_handlers {
                if let Err(e) = handler(data, interface.name.as_str()) {
                    crate::log::warn!("プロトコルハンドラがエラーを報告: {}", e);
                }
            }
        }
        
        // 統計情報を更新
        let mut stats = self.statistics.write().unwrap();
        stats.rx_packets += 1;
        stats.rx_bytes += data.len() as u64;
        
        Ok(())
    }
    
    /// パケットを送信
    pub fn send_packet(&self, data: &[u8], device: &str) -> Result<(), &'static str> {
        let interfaces = self.interfaces.read().unwrap();
        let interface = interfaces.get(device).ok_or("指定されたデバイスが存在しません")?;
        
        // パケットをデバイスに送信
        interface.send(data)?;
        
        // 統計情報を更新
        let mut stats = self.statistics.write().unwrap();
        stats.tx_packets += 1;
        stats.tx_bytes += data.len() as u64;
        
        Ok(())
    }
    
    /// ネットワークサブシステムの状態を取得
    pub fn get_state(&self) -> NetworkState {
        *self.state.lock()
    }
    
    /// ネットワーク統計情報を取得
    pub fn get_statistics(&self) -> NetworkStatistics {
        self.statistics.read().unwrap().clone()
    }
    
    /// ソケットを作成
    pub fn create_socket(
        &self,
        domain: AddressFamily,
        socket_type: SocketType,
        protocol: ProtocolType
    ) -> Result<socket::SocketHandle, &'static str> {
        self.socket_manager.lock().create_socket(domain, socket_type, protocol)
    }
    
    /// DHCPクライアントを開始
    pub fn start_dhcp_client(&self, interface_name: &str) -> Result<(), &'static str> {
        dhcp::start_client(self, interface_name)
    }
    
    /// DNSサーバーを設定
    pub fn set_dns_servers(&self, servers: Vec<String>) -> Result<(), &'static str> {
        let mut dns_config = self.dns_config.write().unwrap();
        dns_config.set_nameservers(servers);
        Ok(())
    }
}

/// ネットワークサブシステムの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkState {
    /// 無効
    Disabled,
    /// 初期化中
    Initializing,
    /// 有効
    Enabled,
    /// 一時停止中
    Suspended,
    /// エラー
    Error,
}

/// ネットワークプロトコルタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    /// IPv4
    IPv4,
    /// IPv6
    IPv6,
    /// TCP
    TCP,
    /// UDP
    UDP,
    /// ICMP
    ICMP,
    /// ICMPv6
    ICMPv6,
    /// ARP
    ARP,
    /// IGMP
    IGMP,
    /// DNS
    DNS,
    /// DHCP
    DHCP,
    /// HTTP
    HTTP,
    /// TLS
    TLS,
    /// カスタムプロトコル
    Custom(u32),
}

/// ネットワークアドレスファミリー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4
    IPv4,
    /// IPv6
    IPv6,
    /// UNIXドメインソケット
    Unix,
    /// Bluetooth
    Bluetooth,
    /// Netlink
    Netlink,
    /// パケットソケット
    Packet,
}

/// ソケットタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    /// ストリーム
    Stream,
    /// データグラム
    Datagram,
    /// RAWソケット
    Raw,
    /// シーケンスパケット
    SeqPacket,
}

/// ネットワーク統計情報
#[derive(Debug, Default)]
pub struct NetworkStatistics {
    /// 送信パケット数
    pub tx_packets: u64,
    /// 受信パケット数
    pub rx_packets: u64,
    /// 送信バイト数
    pub tx_bytes: u64,
    /// 受信バイト数
    pub rx_bytes: u64,
    /// ドロップされたパケット数
    pub dropped_packets: u64,
    /// エラーパケット数
    pub error_packets: u64,
}

/// ネットワークサブシステムのステータス情報
#[derive(Debug, Clone)]
pub struct NetworkStatus {
    /// アクティブな接続数
    pub active_connections: usize,
    /// 送信バイト数（合計）
    pub total_bytes_sent: u64,
    /// 受信バイト数（合計）
    pub total_bytes_received: u64,
    /// 利用可能なネットワークデバイス数
    pub available_devices: usize,
    /// エラー数
    pub error_count: u64,
    /// 現在の送信スループット (bytes/sec)
    pub current_tx_throughput: u64,
    /// 現在の受信スループット (bytes/sec)
    pub current_rx_throughput: u64,
    /// パケットの平均レイテンシ (ns)
    pub avg_packet_latency_ns: u64,
    /// オフロード使用率 (%)
    pub offload_utilization: u8,
    /// ハードウェアアクセラレーション使用中
    pub hw_acceleration_active: bool,
    /// 量子暗号化有効
    pub quantum_encryption_active: bool,
}

/// ネットワークサブシステムのステータスを取得
pub fn get_status() -> NetworkStatus {
    let manager = global_manager();
    let stats = manager.get_stats();
    
    NetworkStatus {
        active_connections: stats.active_connections(),
        total_bytes_sent: stats.total_bytes_sent(),
        total_bytes_received: stats.total_bytes_received(),
        available_devices: manager.devices.len(),
        error_count: stats.total_errors(),
        current_tx_throughput: stats.current_tx_throughput(),
        current_rx_throughput: stats.current_rx_throughput(),
        avg_packet_latency_ns: stats.avg_packet_latency_ns(),
        offload_utilization: stats.offload_utilization(),
        hw_acceleration_active: manager.offload_manager.is_active(),
        quantum_encryption_active: quantum::is_active(),
    }
}

/// グローバルネットワークマネージャーを取得
pub fn global_manager() -> &'static NetworkManager {
    unsafe {
        NETWORK_MANAGER.as_ref().expect("ネットワークマネージャーが初期化されていません")
    }
}

/// グローバルトランスポートレイヤーのインスタンスを取得
pub fn global_transport() -> &'static TransportLayer {
    &global_manager().transport_layer
}

pub mod tcp;
pub mod udp;
pub mod ipv4;
pub mod ipv6;
pub mod ethernet;
pub mod routing;
pub mod firewall;
pub mod socket;
pub mod dns;
pub mod http;
pub mod adaptive;
pub mod qos;
pub mod distributed;
pub mod vpn;

/// ネットワークアドレス表現
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkAddress {
    MAC([u8; 6]),
    IPv4([u8; 4]),
    IPv6([u8; 16]),
    Domain(String),
}

impl fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkAddress::MAC(addr) => {
                write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                       addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
            }
            NetworkAddress::IPv4(addr) => {
                write!(f, "{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
            }
            NetworkAddress::IPv6(addr) => {
                // 簡略化したIPv6表記
                write!(f, "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                       addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                       addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15])
            }
            NetworkAddress::Domain(domain) => {
                write!(f, "{}", domain)
            }
        }
    }
}

/// インターフェイスの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceState {
    Down,
    Up,
    Testing,
    Unknown,
    Dormant,
    NotPresent,
}

/// ネットワークパケット
#[derive(Debug, Clone)]
pub struct Packet {
    pub protocol: ProtocolType,
    pub source: Option<NetworkAddress>,
    pub destination: Option<NetworkAddress>,
    pub payload: Vec<u8>,
    pub ttl: u8,
    pub priority: u8,
    pub timestamp: u64,
    pub interface_id: u32,
}

impl Packet {
    pub fn new(protocol: ProtocolType, payload: Vec<u8>) -> Self {
        Packet {
            protocol,
            source: None,
            destination: None,
            payload,
            ttl: 64,
            priority: 0,
            timestamp: crate::arch::time::current_time_ns(),
            interface_id: 0,
        }
    }
    
    pub fn with_addresses(protocol: ProtocolType, source: NetworkAddress, 
                          destination: NetworkAddress, payload: Vec<u8>) -> Self {
        Packet {
            protocol,
            source: Some(source),
            destination: Some(destination),
            payload,
            ttl: 64,
            priority: 0,
            timestamp: crate::arch::time::current_time_ns(),
            interface_id: 0,
        }
    }
    
    pub fn size(&self) -> usize {
        self.payload.len()
    }
}

/// ネットワークエラータイプ
#[derive(Debug)]
pub enum NetworkError {
    DeviceNotFound,
    DeviceNotReady,
    AddressNotResolved,
    ConnectionRefused,
    ConnectionTimeout,
    ConnectionReset,
    NoRoute,
    PacketTooLarge,
    ProtocolError,
    InternalError,
    PermissionDenied,
    ResourceBusy,
    AddressInUse,
    InvalidAddress,
    InvalidParameter,
    OperationNotSupported,
    Other(String),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::DeviceNotFound => write!(f, "ネットワークデバイスが見つかりません"),
            NetworkError::DeviceNotReady => write!(f, "ネットワークデバイスが準備できていません"),
            NetworkError::AddressNotResolved => write!(f, "アドレスを解決できませんでした"),
            NetworkError::ConnectionRefused => write!(f, "接続が拒否されました"),
            NetworkError::ConnectionTimeout => write!(f, "接続がタイムアウトしました"),
            NetworkError::ConnectionReset => write!(f, "接続がリセットされました"),
            NetworkError::NoRoute => write!(f, "宛先へのルートがありません"),
            NetworkError::PacketTooLarge => write!(f, "パケットが大きすぎます"),
            NetworkError::ProtocolError => write!(f, "プロトコルエラーが発生しました"),
            NetworkError::InternalError => write!(f, "内部エラーが発生しました"),
            NetworkError::PermissionDenied => write!(f, "権限がありません"),
            NetworkError::ResourceBusy => write!(f, "リソースがビジー状態です"),
            NetworkError::AddressInUse => write!(f, "アドレスは既に使用中です"),
            NetworkError::InvalidAddress => write!(f, "無効なアドレスです"),
            NetworkError::InvalidParameter => write!(f, "無効なパラメータです"),
            NetworkError::OperationNotSupported => write!(f, "操作はサポートされていません"),
            NetworkError::Other(msg) => write!(f, "その他のネットワークエラー: {}", msg),
        }
    }
}

pub type NetworkResult<T> = Result<T, NetworkError>;

/// ネットワークインターフェイス抽象トレイト
pub trait NetworkInterface: Send + Sync {
    fn name(&self) -> &str;
    fn id(&self) -> u32;
    fn state(&self) -> InterfaceState;
    fn mac_address(&self) -> Option<[u8; 6]>;
    
    fn send_packet(&self, packet: &Packet) -> NetworkResult<usize>;
    fn receive_packet(&self) -> NetworkResult<Option<Packet>>;
    
    fn set_state(&mut self, state: InterfaceState) -> NetworkResult<()>;
    fn set_mtu(&mut self, mtu: u32) -> NetworkResult<()>;
    fn get_mtu(&self) -> u32;
    
    fn set_ipv4_address(&mut self, addr: [u8; 4], subnet_mask: [u8; 4]) -> NetworkResult<()>;
    fn set_ipv6_address(&mut self, addr: [u8; 16], prefix_len: u8) -> NetworkResult<()>;
    
    fn get_ipv4_address(&self) -> Option<([u8; 4], [u8; 4])>;
    fn get_ipv6_address(&self) -> Option<([u8; 16], u8)>;
    
    fn statistics(&self) -> InterfaceStatistics;
    fn capabilities(&self) -> InterfaceCapabilities;
    
    fn flush(&mut self) -> NetworkResult<()>;
    fn reset(&mut self) -> NetworkResult<()>;
}

/// インターフェイス統計情報
#[derive(Debug, Clone, Copy)]
pub struct InterfaceStatistics {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub multicast: u64,
    pub collisions: u64,
}

/// インターフェイス機能
#[derive(Debug, Clone, Copy)]
pub struct InterfaceCapabilities {
    pub max_mtu: u32,
    pub min_mtu: u32,
    pub supports_ipv4: bool,
    pub supports_ipv6: bool,
    pub supports_multicast: bool,
    pub supports_broadcast: bool,
    pub supports_promiscuous: bool,
    pub supports_vlan: bool,
    pub supports_tso: bool,
    pub supports_gso: bool,
    pub supports_checksum_offload: bool,
}

/// ソケットタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    Stream,
    Datagram,
    Raw,
}

/// ソケットオプション
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketOption {
    ReuseAddress,
    ReusePort,
    Broadcast,
    KeepAlive,
    Linger(u32),
    RecvTimeout(u64),
    SendTimeout(u64),
    RecvBuffer(u32),
    SendBuffer(u32),
    NoDelay,
    Cork,
}

/// ソケットプロトコル指定
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketProtocol {
    IPv4,
    IPv6,
    Dual,
}

/// ソケットアドレス
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketAddress {
    IPv4 {
        addr: [u8; 4],
        port: u16,
    },
    IPv6 {
        addr: [u8; 16],
        port: u16,
        flow_info: u32,
        scope_id: u32,
    },
    Unix {
        path: String,
    },
}

/// ネットワークマネージャー
pub struct NetworkManager {
    interfaces: Vec<Box<dyn NetworkInterface>>,
    next_interface_id: AtomicU64,
    route_table: routing::RouteTable,
    firewall: firewall::Firewall,
}

impl NetworkManager {
    pub fn new() -> Self {
        NetworkManager {
            interfaces: Vec::new(),
            next_interface_id: AtomicU64::new(1),
            route_table: routing::RouteTable::new(),
            firewall: firewall::Firewall::new(),
        }
    }
    
    pub fn register_interface(&mut self, interface: Box<dyn NetworkInterface>) -> u32 {
        let id = self.next_interface_id.fetch_add(1, Ordering::SeqCst) as u32;
        self.interfaces.push(interface);
        id
    }
    
    pub fn get_interface(&self, id: u32) -> Option<&dyn NetworkInterface> {
        self.interfaces.iter()
            .find(|iface| iface.id() == id)
            .map(|iface| iface.as_ref())
    }
    
    pub fn get_interface_mut(&mut self, id: u32) -> Option<&mut dyn NetworkInterface> {
        self.interfaces.iter_mut()
            .find(|iface| iface.id() == id)
            .map(|iface| iface.as_mut())
    }
    
    pub fn get_interface_by_name(&self, name: &str) -> Option<&dyn NetworkInterface> {
        self.interfaces.iter()
            .find(|iface| iface.name() == name)
            .map(|iface| iface.as_ref())
    }
    
    pub fn list_interfaces(&self) -> Vec<u32> {
        self.interfaces.iter().map(|iface| iface.id()).collect()
    }
    
    pub fn send_packet(&self, packet: &Packet) -> NetworkResult<usize> {
        // ファイアウォールチェック
        if !self.firewall.allow_outbound_packet(packet) {
            return Err(NetworkError::PermissionDenied);
        }
        
        // インターフェイス取得
        let interface = self.get_interface(packet.interface_id)
            .ok_or(NetworkError::DeviceNotFound)?;
            
        // 実際のパケット送信
        interface.send_packet(packet)
    }
    
    pub fn add_route(&mut self, route: routing::Route) -> NetworkResult<()> {
        self.route_table.add_route(route)
    }
    
    pub fn remove_route(&mut self, destination: &NetworkAddress) -> NetworkResult<()> {
        self.route_table.remove_route(destination)
    }
    
    pub fn get_route(&self, destination: &NetworkAddress) -> Option<&routing::Route> {
        self.route_table.find_route(destination)
    }
    
    pub fn add_firewall_rule(&mut self, rule: firewall::FirewallRule) -> NetworkResult<u32> {
        self.firewall.add_rule(rule)
    }
    
    pub fn remove_firewall_rule(&mut self, rule_id: u32) -> NetworkResult<()> {
        self.firewall.remove_rule(rule_id)
    }
}

/// グローバルネットワークマネージャーの取得
pub fn get_network_manager() -> &'static mut NetworkManager {
    unsafe {
        if NETWORK_MANAGER.is_none() {
            NETWORK_MANAGER = Some(NetworkManager::new());
        }
        NETWORK_MANAGER.as_mut().unwrap()
    }
}

/// ネットワークスタックの初期化
pub fn init() {
    let manager = get_network_manager();
    
    // 各プロトコルスタックの初期化
    ipv4::init();
    ipv6::init();
    tcp::init();
    udp::init();
    ethernet::init();
    
    // 拡張機能の初期化
    routing::init();
    firewall::init();
    dns::init();
    adaptive::init();
    qos::init();
    
    // 分散ネットワーク機能
    distributed::init();
} 