// AetherOS ネットワークデバイス管理
//
// 物理および仮想ネットワークデバイスを管理するサブシステム

use alloc::string::String;
use alloc::vec::Vec;
use crate::core::sync::{Mutex, RwLock};
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

/// MACアドレス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress {
    pub bytes: [u8; 6],
}

impl MacAddress {
    /// 新しいMACアドレスを作成
    pub fn new(bytes: [u8; 6]) -> Self {
        Self { bytes }
    }
    
    /// 文字列からMACアドレスを解析
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err("無効なMACアドレス形式");
        }
        
        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16).map_err(|_| "無効なMACアドレス形式")?;
        }
        
        Ok(Self { bytes })
    }
    
    /// MACアドレスを文字列形式に変換
    pub fn to_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.bytes[0], self.bytes[1], self.bytes[2],
            self.bytes[3], self.bytes[4], self.bytes[5]
        )
    }
    
    /// ブロードキャストMACアドレスを取得
    pub fn broadcast() -> Self {
        Self { bytes: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] }
    }
    
    /// マルチキャストアドレスかどうかをチェック
    pub fn is_multicast(&self) -> bool {
        (self.bytes[0] & 0x01) != 0
    }
    
    /// ブロードキャストアドレスかどうかをチェック
    pub fn is_broadcast(&self) -> bool {
        self.bytes == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    }
}

/// IPアドレス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddress {
    /// IPv4アドレス
    V4([u8; 4]),
    /// IPv6アドレス
    V6([u8; 16]),
}

impl IpAddress {
    /// 新しいIPv4アドレスを作成
    pub fn v4(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self::V4([a, b, c, d])
    }
    
    /// 新しいIPv6アドレスを作成
    pub fn v6(bytes: [u8; 16]) -> Self {
        Self::V6(bytes)
    }
    
    /// 文字列からIPアドレスを解析
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        if s.contains(':') {
            // IPv6形式
            // 簡略化のため、基本的なIPv6のみ対応
            if s.len() < 2 || s.len() > 39 {
                return Err("無効なIPv6アドレス形式");
            }
            
            let mut result = [0u8; 16];
            // ... IPv6解析ロジック（簡略化）...
            
            Ok(Self::V6(result))
        } else {
            // IPv4形式
            let parts: Vec<&str> = s.split('.').collect();
            if parts.len() != 4 {
                return Err("無効なIPv4アドレス形式");
            }
            
            let mut bytes = [0u8; 4];
            for (i, part) in parts.iter().enumerate() {
                bytes[i] = part.parse().map_err(|_| "無効なIPv4アドレス形式")?;
            }
            
            Ok(Self::V4(bytes))
        }
    }
    
    /// IPアドレスを文字列形式に変換
    pub fn to_string(&self) -> String {
        match self {
            Self::V4(bytes) => {
                format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
            },
            Self::V6(bytes) => {
                let mut segments = [0u16; 8];
                for i in 0..8 {
                    segments[i] = ((bytes[i * 2] as u16) << 8) | (bytes[i * 2 + 1] as u16);
                }
                
                // IPv6文字列表現（簡略化なし）
                format!(
                    "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
                    segments[0], segments[1], segments[2], segments[3],
                    segments[4], segments[5], segments[6], segments[7]
                )
            }
        }
    }
    
    /// アドレスファミリーを取得
    pub fn family(&self) -> super::AddressFamily {
        match self {
            Self::V4(_) => super::AddressFamily::IPv4,
            Self::V6(_) => super::AddressFamily::IPv6,
        }
    }
}

/// ネットワークアドレス（IP + ポート）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketAddress {
    pub ip: IpAddress,
    pub port: u16,
}

impl SocketAddress {
    /// 新しいソケットアドレスを作成
    pub fn new(ip: IpAddress, port: u16) -> Self {
        Self { ip, port }
    }
    
    /// 文字列からソケットアドレスを解析
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        let parts: Vec<&str> = match s.rfind(':') {
            Some(idx) if s.contains('.') => {
                // IPv4:ポート
                vec![&s[..idx], &s[idx+1..]]
            },
            Some(idx) if s.starts_with('[') && s[..idx].ends_with(']') => {
                // [IPv6]:ポート
                vec![&s[1..idx-1], &s[idx+1..]]
            },
            _ => return Err("無効なソケットアドレス形式"),
        };
        
        if parts.len() != 2 {
            return Err("無効なソケットアドレス形式");
        }
        
        let ip = IpAddress::parse(parts[0])?;
        let port = parts[1].parse::<u16>().map_err(|_| "無効なポート番号")?;
        
        Ok(Self { ip, port })
    }
    
    /// ソケットアドレスを文字列形式に変換
    pub fn to_string(&self) -> String {
        match self.ip {
            IpAddress::V4(_) => format!("{}:{}", self.ip.to_string(), self.port),
            IpAddress::V6(_) => format!("[{}]:{}", self.ip.to_string(), self.port),
        }
    }
}

/// ネットワークデバイスの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    /// 無効
    Down,
    /// 有効
    Up,
    /// 一時停止
    Suspended,
    /// エラー
    Error,
}

/// ネットワークデバイスの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// イーサネット
    Ethernet,
    /// ワイヤレス
    Wireless,
    /// ループバック
    Loopback,
    /// 仮想
    Virtual,
    /// トンネル
    Tunnel,
    /// ブリッジ
    Bridge,
    /// その他
    Other,
}

/// ネットワークデバイス設定
#[derive(Debug, Clone)]
pub struct NetDeviceConfig {
    /// MACアドレス
    pub mac_address: Option<MacAddress>,
    /// MTU (Maximum Transmission Unit)
    pub mtu: usize,
    /// デバイスタイプ
    pub device_type: DeviceType,
    /// プロミスキャスモード（全パケットを受信）
    pub promiscuous: bool,
    /// トランクモード（VLANタグ付きパケットを処理）
    pub trunk_mode: bool,
    /// オフロード機能
    pub offload_features: u32,
    /// 送信キューの最大長
    pub tx_queue_len: usize,
}

impl Default for NetDeviceConfig {
    fn default() -> Self {
        Self {
            mac_address: None,
            mtu: 1500,
            device_type: DeviceType::Other,
            promiscuous: false,
            trunk_mode: false,
            offload_features: 0,
            tx_queue_len: 1000,
        }
    }
}

/// ネットワークデバイス統計情報
#[derive(Debug, Default, Clone)]
pub struct NetDeviceStats {
    /// 送信パケット数
    pub tx_packets: u64,
    /// 受信パケット数
    pub rx_packets: u64,
    /// 送信バイト数
    pub tx_bytes: u64,
    /// 受信バイト数
    pub rx_bytes: u64,
    /// 送信エラー数
    pub tx_errors: u64,
    /// 受信エラー数
    pub rx_errors: u64,
    /// 送信ドロップ数
    pub tx_dropped: u64,
    /// 受信ドロップ数
    pub rx_dropped: u64,
    /// 衝突回数
    pub collisions: u64,
    /// 複数衝突フレーム
    pub multicast: u64,
}

/// デバイス送信関数型
pub type SendFunction = fn(&[u8]) -> Result<(), &'static str>;

/// ネットワークデバイス
pub struct NetDevice {
    /// デバイス名
    pub name: String,
    /// デバイス設定
    pub config: RwLock<NetDeviceConfig>,
    /// デバイス状態
    pub state: AtomicBool, // true=up, false=down
    /// 統計情報
    pub stats: RwLock<NetDeviceStats>,
    /// デバイスタイプ
    pub device_type: DeviceType,
    /// IPアドレス（複数可）
    pub addresses: RwLock<Vec<(IpAddress, u8)>>,  // (IP, プレフィックス長)
    /// 送信関数
    send_fn: RwLock<Option<SendFunction>>,
    /// キャリア状態 (リンクアップ/ダウン)
    carrier: AtomicBool,
}

impl NetDevice {
    /// 新しいネットワークデバイスを作成
    pub fn new(name: String, device_type: DeviceType, config: NetDeviceConfig) -> Self {
        Self {
            name,
            config: RwLock::new(config),
            state: AtomicBool::new(false), // 初期状態はダウン
            stats: RwLock::new(NetDeviceStats::default()),
            device_type,
            addresses: RwLock::new(Vec::new()),
            send_fn: RwLock::new(None),
            carrier: AtomicBool::new(false),
        }
    }
    
    /// ループバックデバイスを作成
    pub fn create_loopback() -> Result<Self, &'static str> {
        let mut config = NetDeviceConfig::default();
        config.device_type = DeviceType::Loopback;
        config.mtu = 65536;
        
        let mut device = Self::new(
            String::from("lo"),
            DeviceType::Loopback,
            config,
        );
        
        // ループバックデバイスはIPv4とIPv6のループバックアドレスを持つ
        device.add_address(IpAddress::v4(127, 0, 0, 1), 8)?;
        // IPv6のループバックアドレス ::1
        let mut ipv6_loopback = [0u8; 16];
        ipv6_loopback[15] = 1;
        device.add_address(IpAddress::V6(ipv6_loopback), 128)?;
        
        // ループバックデバイスの送信関数を設定
        *device.send_fn.write().unwrap() = Some(Self::loopback_send);
        
        // デバイスを有効化
        device.set_up()?;
        device.carrier.store(true, Ordering::SeqCst);
        
        Ok(device)
    }
    
    /// ループバックデバイスの送信関数（受信に回す）
    fn loopback_send(data: &[u8]) -> Result<(), &'static str> {
        // ループバックデバイスでは送信データをそのまま受信キューに入れる
        super::process_packet(data, "lo")
    }
    
    /// デバイスを有効化
    pub fn set_up(&self) -> Result<(), &'static str> {
        self.state.store(true, Ordering::SeqCst);
        Ok(())
    }
    
    /// デバイスを無効化
    pub fn set_down(&self) -> Result<(), &'static str> {
        self.state.store(false, Ordering::SeqCst);
        Ok(())
    }
    
    /// デバイスの状態を取得
    pub fn get_state(&self) -> DeviceState {
        if !self.state.load(Ordering::SeqCst) {
            DeviceState::Down
        } else if !self.carrier.load(Ordering::SeqCst) {
            DeviceState::Suspended
        } else {
            DeviceState::Up
        }
    }
    
    /// IPアドレスを追加
    pub fn add_address(&self, addr: IpAddress, prefix_len: u8) -> Result<(), &'static str> {
        let mut addresses = self.addresses.write().unwrap();
        
        // 同じアドレスが既に存在するかチェック
        if addresses.iter().any(|(a, _)| *a == addr) {
            return Err("アドレスが既に存在します");
        }
        
        // プレフィックス長の妥当性チェック
        let max_prefix = match addr {
            IpAddress::V4(_) => 32,
            IpAddress::V6(_) => 128,
        };
        
        if prefix_len > max_prefix {
            return Err("無効なプレフィックス長");
        }
        
        addresses.push((addr, prefix_len));
        Ok(())
    }
    
    /// IPアドレスを削除
    pub fn del_address(&self, addr: IpAddress) -> Result<(), &'static str> {
        let mut addresses = self.addresses.write().unwrap();
        
        let initial_len = addresses.len();
        addresses.retain(|(a, _)| *a != addr);
        
        if addresses.len() == initial_len {
            Err("指定されたアドレスが見つかりません")
        } else {
            Ok(())
        }
    }
    
    /// 送信関数を設定
    pub fn set_send_function(&self, send_fn: SendFunction) {
        *self.send_fn.write().unwrap() = Some(send_fn);
    }
    
    /// パケットを送信
    pub fn send(&self, data: &[u8]) -> Result<(), &'static str> {
        // デバイスがアップ状態でなければエラー
        if !self.state.load(Ordering::SeqCst) {
            return Err("デバイスがダウン状態です");
        }
        
        // MTUサイズチェック
        let config = self.config.read().unwrap();
        if data.len() > config.mtu {
            return Err("パケットサイズがMTUを超えています");
        }
        
        // 送信関数を呼び出し
        if let Some(send_fn) = *self.send_fn.read().unwrap() {
            let result = send_fn(data);
            
            // 統計情報を更新
            let mut stats = self.stats.write().unwrap();
            if result.is_ok() {
                stats.tx_packets += 1;
                stats.tx_bytes += data.len() as u64;
            } else {
                stats.tx_errors += 1;
            }
            
            result
        } else {
            Err("送信関数が設定されていません")
        }
    }
    
    /// パケットを受信（デバイスドライバから呼び出される）
    pub fn receive(&self, data: &[u8]) -> Result<(), &'static str> {
        // デバイスがアップ状態でなければパケットをドロップ
        if !self.state.load(Ordering::SeqCst) {
            let mut stats = self.stats.write().unwrap();
            stats.rx_dropped += 1;
            return Err("デバイスがダウン状態です");
        }
        
        // 統計情報を更新
        let mut stats = self.stats.write().unwrap();
        stats.rx_packets += 1;
        stats.rx_bytes += data.len() as u64;
        
        // パケットをネットワークスタックに渡す
        super::process_packet(data, &self.name)
    }
    
    /// MACアドレスを設定
    pub fn set_mac_address(&self, mac: MacAddress) -> Result<(), &'static str> {
        if self.device_type == DeviceType::Loopback {
            return Err("ループバックデバイスのMACアドレスは変更できません");
        }
        
        let mut config = self.config.write().unwrap();
        config.mac_address = Some(mac);
        Ok(())
    }
    
    /// MACアドレスを取得
    pub fn get_mac_address(&self) -> Option<MacAddress> {
        self.config.read().unwrap().mac_address
    }
    
    /// MTUを設定
    pub fn set_mtu(&self, mtu: usize) -> Result<(), &'static str> {
        if mtu < 68 || mtu > 65536 {
            return Err("無効なMTU値");
        }
        
        let mut config = self.config.write().unwrap();
        config.mtu = mtu;
        Ok(())
    }
    
    /// MTUを取得
    pub fn get_mtu(&self) -> usize {
        self.config.read().unwrap().mtu
    }
    
    /// キャリア状態を設定
    pub fn set_carrier(&self, state: bool) {
        self.carrier.store(state, Ordering::SeqCst);
    }
    
    /// プロミスキャスモードを設定
    pub fn set_promiscuous(&self, enable: bool) -> Result<(), &'static str> {
        let mut config = self.config.write().unwrap();
        config.promiscuous = enable;
        Ok(())
    }
} 