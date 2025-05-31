// AetherOS ネットワークデバイス抽象化
//
// このモジュールはネットワークハードウェアデバイスとの通信を抽象化し、
// 統一的なインターフェースを提供します。TCP/IP, RDMA等の様々なハードウェアに対応します。

use core::fmt::Debug;
use alloc::vec::Vec;
use alloc::string::String;
use crate::core::network::protocol::TransportError;

/// デバイスID型
pub type DeviceId = u32;

/// MAC アドレス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

/// IP アドレス (v4/v6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddress {
    /// IPv4 アドレス
    V4([u8; 4]),
    /// IPv6 アドレス
    V6([u8; 16]),
}

/// ネットワークアドレス (IP:ポート)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkAddress {
    /// IP アドレス
    pub ip: IpAddress,
    /// ポート番号
    pub port: u16,
}

/// ソケット型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    /// TCP ソケット
    Tcp,
    /// UDP ソケット
    Udp,
    /// Raw ソケット
    Raw,
}

/// ソケットオプション
#[derive(Debug, Clone)]
pub enum SocketOption {
    /// タイムアウト (ミリ秒)
    Timeout(u64),
    /// 再利用可能
    ReuseAddr(bool),
    /// ノンブロッキング
    NonBlocking(bool),
    /// 送信バッファサイズ
    SendBufferSize(usize),
    /// 受信バッファサイズ
    ReceiveBufferSize(usize),
    /// Keep-Alive
    KeepAlive(bool),
    /// TTL (Time To Live)
    Ttl(u8),
    /// ToS (Type of Service)
    Tos(u8),
}

/// 送信記述子
#[derive(Debug)]
pub struct TransmitDescriptor {
    /// バッファアドレス
    pub buffer: *const u8,
    /// バッファ長
    pub length: usize,
    /// オフロードフラグ
    pub offload_flags: u32,
    /// メタデータ
    pub metadata: u64,
}

/// 受信記述子
#[derive(Debug)]
pub struct ReceiveDescriptor {
    /// バッファアドレス
    pub buffer: *mut u8,
    /// バッファ長
    pub length: usize,
    /// 受信データ長
    pub received: usize,
    /// 送信元アドレス
    pub src_addr: Option<NetworkAddress>,
    /// メタデータ
    pub metadata: u64,
}

/// TCPソケット
pub trait TcpSocket: Debug + Send + Sync {
    /// 接続タイムアウトを設定
    fn set_connection_timeout(&self, timeout_ms: u64) -> Result<(), TransportError>;
    
    /// 接続を確立
    fn connect(&self, addr: &NetworkAddress) -> Result<(), TransportError>;
    
    /// データを送信
    fn send(&self, data: &[u8]) -> Result<usize, TransportError>;
    
    /// データを受信
    fn receive(&self, buffer: &mut [u8]) -> Result<usize, TransportError>;
    
    /// 切断
    fn disconnect(&self) -> Result<(), TransportError>;
    
    /// オプションを設定
    fn set_option(&self, option: SocketOption) -> Result<(), TransportError>;
    
    /// オプションを取得
    fn get_option(&self, option_name: &str) -> Result<SocketOption, TransportError>;
}

/// UDPソケット
pub trait UdpSocket: Debug + Send + Sync {
    /// バインド
    fn bind(&self, addr: &NetworkAddress) -> Result<(), TransportError>;
    
    /// データグラムを送信
    fn send_to(&self, data: &[u8], addr: &NetworkAddress) -> Result<usize, TransportError>;
    
    /// データグラムを受信
    fn receive_from(&self, buffer: &mut [u8]) -> Result<(usize, NetworkAddress), TransportError>;
    
    /// オプションを設定
    fn set_option(&self, option: SocketOption) -> Result<(), TransportError>;
    
    /// オプションを取得
    fn get_option(&self, option_name: &str) -> Result<SocketOption, TransportError>;
}

/// ネットワークデバイスの能力フラグ
pub const DEVICE_CAPABILITY_TCP: u32 = 0x0001;
pub const DEVICE_CAPABILITY_UDP: u32 = 0x0002;
pub const DEVICE_CAPABILITY_RDMA: u32 = 0x0004;
pub const DEVICE_CAPABILITY_ZERO_COPY: u32 = 0x0008;
pub const DEVICE_CAPABILITY_TSO: u32 = 0x0010;    // TCP Segmentation Offload
pub const DEVICE_CAPABILITY_LRO: u32 = 0x0020;    // Large Receive Offload
pub const DEVICE_CAPABILITY_CHECKSUM: u32 = 0x0040; // チェックサム計算のオフロード

/// ネットワークデバイス
pub trait NetworkDevice: Debug + Send + Sync {
    /// デバイスID
    fn id(&self) -> DeviceId;
    
    /// デバイス名
    fn name(&self) -> &str;
    
    /// MACアドレス
    fn mac_address(&self) -> MacAddress;
    
    /// 能力フラグ
    fn capabilities(&self) -> u32;
    
    /// TCPソケットを作成
    fn create_tcp_socket(&self) -> Result<Box<dyn TcpSocket>, TransportError>;
    
    /// UDPソケットを作成
    fn create_udp_socket(&self) -> Result<Box<dyn UdpSocket>, TransportError>;
    
    /// 送信キューに追加
    fn queue_transmit(&self, desc: TransmitDescriptor) -> Result<(), TransportError>;
    
    /// 受信キューから取得
    fn dequeue_receive(&self) -> Result<ReceiveDescriptor, TransportError>;
    
    /// 送受信をポーリング（ノンブロッキング）
    fn poll(&self) -> Result<bool, TransportError>;
    
    /// 統計情報をリセット
    fn reset_stats(&self) -> Result<(), TransportError>;
    
    /// 統計情報を取得
    fn get_stats(&self) -> Result<DeviceStats, TransportError>;
}

/// デバイス統計情報
#[derive(Debug, Default, Clone)]
pub struct DeviceStats {
    /// 送信パケット数
    pub tx_packets: u64,
    /// 受信パケット数
    pub rx_packets: u64,
    /// 送信バイト数
    pub tx_bytes: u64,
    /// 受信バイト数
    pub rx_bytes: u64,
    /// 送信エラー
    pub tx_errors: u64,
    /// 受信エラー
    pub rx_errors: u64,
    /// 送信ドロップ
    pub tx_dropped: u64,
    /// 受信ドロップ
    pub rx_dropped: u64,
    /// 衝突回数
    pub collisions: u64,
    /// ハードウェア障害
    pub hw_errors: u64,
}

/// RDMAメモリ領域
pub trait RdmaMemoryRegion: Debug + Send + Sync {
    /// 開始アドレス
    fn address(&self) -> *mut u8;
    
    /// サイズ
    fn size(&self) -> usize;
    
    /// リモートからアクセス可能か
    fn is_remotely_accessible(&self) -> bool;
    
    /// リモートキー（ある場合）
    fn remote_key(&self) -> Option<u32>;
    
    /// ローカルキー
    fn local_key(&self) -> u32;
}

/// RDMAキューペア
pub trait RdmaQueuePair: Debug + Send + Sync {
    /// ID
    fn id(&self) -> u32;
    
    /// 状態
    fn state(&self) -> RdmaQueuePairState;
    
    /// リモートノードに接続
    fn connect(&self, addr: &NetworkAddress, timeout_ms: u64) -> Result<(), TransportError>;
    
    /// 切断
    fn disconnect(&self) -> Result<(), TransportError>;
    
    /// Send操作を実行（ローカル→リモート）
    fn post_send(&self, region: &dyn RdmaMemoryRegion, offset: usize, length: usize) -> Result<u64, TransportError>;
    
    /// Receive操作を投稿（リモート→ローカル）
    fn post_receive(&self, region: &dyn RdmaMemoryRegion, offset: usize, length: usize) -> Result<u64, TransportError>;
    
    /// RDMA Write操作（ローカル→リモート）
    fn rdma_write(&self, 
                 local_region: &dyn RdmaMemoryRegion, 
                 local_offset: usize,
                 remote_addr: u64, 
                 remote_key: u32,
                 length: usize) -> Result<u64, TransportError>;
    
    /// RDMA Read操作（リモート→ローカル）
    fn rdma_read(&self, 
                local_region: &dyn RdmaMemoryRegion, 
                local_offset: usize,
                remote_addr: u64, 
                remote_key: u32,
                length: usize) -> Result<u64, TransportError>;
    
    /// 完了イベントをポーリング
    fn poll_completion(&self) -> Result<Option<RdmaCompletion>, TransportError>;
}

/// RDMAキューペアの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdmaQueuePairState {
    /// リセット
    Reset,
    /// 初期化済み
    Init,
    /// 準備完了
    ReadyToReceive,
    /// 接続済み
    Connected,
    /// エラー
    Error,
}

/// RDMA完了イベント
#[derive(Debug, Clone)]
pub struct RdmaCompletion {
    /// 操作ID
    pub id: u64,
    /// 完了ステータス
    pub status: RdmaCompletionStatus,
    /// 転送バイト数
    pub bytes_transferred: usize,
}

/// RDMA完了ステータス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdmaCompletionStatus {
    /// 成功
    Success,
    /// リモートアクセスエラー
    RemoteAccessError,
    /// ローカルエラー
    LocalError,
    /// タイムアウト
    Timeout,
    /// プロトコルエラー
    ProtocolError,
}

/// RDMAデバイス
pub trait RdmaDevice: Debug + Send + Sync {
    /// デバイスID
    fn id(&self) -> DeviceId;
    
    /// デバイス名
    fn name(&self) -> &str;
    
    /// 能力フラグ
    fn capabilities(&self) -> u32;
    
    /// メモリ領域を登録
    fn register_memory(&self, size: usize) -> Result<Box<dyn RdmaMemoryRegion>, TransportError>;
    
    /// 指定アドレスのメモリ領域を登録
    fn register_memory_at(&self, addr: *mut u8, size: usize) -> Result<Box<dyn RdmaMemoryRegion>, TransportError>;
    
    /// メモリ領域を解放
    fn deregister_memory(&self, region: &dyn RdmaMemoryRegion) -> Result<(), TransportError>;
    
    /// キューペアを作成
    fn create_queue_pair(&self) -> Result<Box<dyn RdmaQueuePair>, TransportError>;
    
    /// キューペアを破棄
    fn destroy_queue_pair(&self, qp: &dyn RdmaQueuePair) -> Result<(), TransportError>;
    
    /// 統計情報を取得
    fn get_stats(&self) -> Result<RdmaStats, TransportError>;
}

/// RDMA統計情報
#[derive(Debug, Default, Clone)]
pub struct RdmaStats {
    /// 送信操作数
    pub send_ops: u64,
    /// 受信操作数
    pub recv_ops: u64,
    /// RDMA Write操作数
    pub write_ops: u64,
    /// RDMA Read操作数
    pub read_ops: u64,
    /// 送信バイト数
    pub bytes_sent: u64,
    /// 受信バイト数
    pub bytes_received: u64,
    /// エラー数
    pub errors: u64,
    /// 完了数
    pub completions: u64,
} 