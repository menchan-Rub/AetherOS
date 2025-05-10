// USBデバイスサブシステム
// AetherOS用高性能USBデバイス管理システム

//! # AetherOS USBデバイス管理
//!
//! このモジュールはUSBデバイスの検出、列挙、管理を担当します。
//! 主な機能:
//! - USBデバイスの自動検出と列挙
//! - デバイスクラスドライバーフレームワーク
//! - デバイス記述子の解析と管理
//! - エンドポイント管理
//! - 転送キューの管理
//! - ホットプラグイベント処理

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use spin::{Mutex, RwLock};

use crate::drivers::usb::{
    UsbDeviceInfo, UsbError, UsbSpeed, UsbDeviceType, UsbDeviceDescriptor,
    UsbDirection, UsbRequestType, UsbRequestRecipient, UsbSetupPacket,
    UsbStandardRequest, UsbDescriptorType, hci::{UsbHci, UsbSubsystem},
};

/// USBエンドポイント属性
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbEndpointType {
    /// コントロール転送エンドポイント
    Control = 0,
    /// アイソクロナス転送エンドポイント
    Isochronous = 1,
    /// バルク転送エンドポイント
    Bulk = 2,
    /// 割り込み転送エンドポイント
    Interrupt = 3,
}

impl UsbEndpointType {
    /// エンドポイント属性から作成
    pub fn from_attributes(attrs: u8) -> Self {
        match attrs & 0x3 {
            0 => Self::Control,
            1 => Self::Isochronous,
            2 => Self::Bulk,
            3 => Self::Interrupt,
            _ => unreachable!(),
        }
    }
}

/// USBエンドポイント情報
#[derive(Debug, Clone)]
pub struct UsbEndpointInfo {
    /// エンドポイント番号
    pub number: u8,
    /// エンドポイントアドレス (含む方向ビット)
    pub address: u8,
    /// エンドポイントの方向
    pub direction: UsbDirection,
    /// エンドポイントのタイプ
    pub endpoint_type: UsbEndpointType,
    /// 最大パケットサイズ
    pub max_packet_size: u16,
    /// インターバル (ミリ秒)
    pub interval: u8,
}

impl UsbEndpointInfo {
    /// エンドポイント記述子から作成
    pub fn from_descriptor(desc: &[u8]) -> Option<Self> {
        if desc.len() < 7 || desc[1] != UsbDescriptorType::Endpoint as u8 {
            return None;
        }

        let address = desc[2];
        let attributes = desc[3];
        let max_packet_size = u16::from_le_bytes([desc[4], desc[5]]);
        let interval = desc[6];
        
        Some(Self {
            number: address & 0x0F,
            address,
            direction: if (address & 0x80) != 0 { UsbDirection::In } else { UsbDirection::Out },
            endpoint_type: UsbEndpointType::from_attributes(attributes),
            max_packet_size,
            interval,
        })
    }
}

/// USBインターフェース情報
#[derive(Debug, Clone)]
pub struct UsbInterfaceInfo {
    /// インターフェース番号
    pub number: u8,
    /// 代替設定
    pub alt_setting: u8,
    /// インターフェースクラス
    pub class: u8,
    /// インターフェースサブクラス
    pub subclass: u8,
    /// インターフェースプロトコル
    pub protocol: u8,
    /// インターフェース文字列インデックス
    pub string_index: Option<u8>,
    /// エンドポイント
    pub endpoints: Vec<UsbEndpointInfo>,
    /// インターフェース名
    pub name: Option<String>,
}

/// USBデバイス設定情報
#[derive(Debug, Clone)]
pub struct UsbConfigurationInfo {
    /// 設定値
    pub value: u8,
    /// 文字列インデックス
    pub string_index: Option<u8>,
    /// 属性
    pub attributes: u8,
    /// 最大電力 (mA)
    pub max_power: u16,
    /// インターフェース
    pub interfaces: Vec<UsbInterfaceInfo>,
}

impl UsbConfigurationInfo {
    /// 自己電源かどうか
    pub fn is_self_powered(&self) -> bool {
        (self.attributes & 0x40) != 0
    }
    
    /// リモートウェイクアップをサポートするかどうか
    pub fn supports_remote_wakeup(&self) -> bool {
        (self.attributes & 0x20) != 0
    }
}

/// USBデバイス状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbDeviceState {
    /// 接続されていない
    Disconnected,
    /// 接続済み（未設定）
    Connected,
    /// アドレス設定済み
    Addressed,
    /// 設定済み（使用可能）
    Configured,
    /// 一時停止
    Suspended,
    /// エラー状態
    Error,
}

/// USB転送タイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbTransferType {
    /// コントロール転送
    Control,
    /// アイソクロナス転送
    Isochronous,
    /// バルク転送
    Bulk,
    /// 割り込み転送
    Interrupt,
}

/// USB転送状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbTransferStatus {
    /// 完了
    Completed,
    /// エラー
    Error,
    /// タイムアウト
    Timeout,
    /// キャンセル
    Cancelled,
    /// 転送中
    InProgress,
    /// ステール（エラー）
    Stalled,
}

/// USB転送
pub struct UsbTransfer {
    /// 転送の種類
    pub transfer_type: UsbTransferType,
    /// デバイスアドレス
    pub device_address: u8,
    /// エンドポイントアドレス
    pub endpoint_address: u8,
    /// セットアップパケット（コントロール転送の場合）
    pub setup_packet: Option<UsbSetupPacket>,
    /// データバッファ
    pub buffer: Option<Vec<u8>>,
    /// 実際に転送されたバイト数
    pub actual_length: usize,
    /// 転送状態
    pub status: UsbTransferStatus,
    /// コールバック
    pub callback: Option<Box<dyn FnOnce(&UsbTransfer) + Send + 'static>>,
}

/// USBデバイス
pub struct UsbDevice {
    /// デバイス情報
    pub info: UsbDeviceInfo,
    /// デバイスの状態
    pub state: AtomicU8,
    /// 現在の設定
    pub current_configuration: Option<Arc<UsbConfigurationInfo>>,
    /// 利用可能な設定
    pub configurations: Vec<Arc<UsbConfigurationInfo>>,
    /// デバイスドライバー
    pub driver: Option<Arc<dyn UsbDeviceDriver + Send + Sync>>,
    /// HCIへの参照
    pub hci: Arc<dyn UsbHci + Send + Sync>,
}

impl UsbDevice {
    /// 新しいUSBデバイスを作成
    pub fn new(info: UsbDeviceInfo, hci: Arc<dyn UsbHci + Send + Sync>) -> Self {
        Self {
            info,
            state: AtomicU8::new(UsbDeviceState::Connected as u8),
            current_configuration: None,
            configurations: Vec::new(),
            driver: None,
            hci,
        }
    }
    
    /// デバイスの状態を取得
    pub fn state(&self) -> UsbDeviceState {
        match self.state.load(Ordering::Acquire) {
            0 => UsbDeviceState::Disconnected,
            1 => UsbDeviceState::Connected,
            2 => UsbDeviceState::Addressed,
            3 => UsbDeviceState::Configured,
            4 => UsbDeviceState::Suspended,
            _ => UsbDeviceState::Error,
        }
    }
    
    /// デバイスの状態を設定
    pub fn set_state(&self, state: UsbDeviceState) {
        self.state.store(state as u8, Ordering::Release);
    }

    /// デバイスを設定する
    pub fn configure(&mut self, config_value: u8) -> Result<(), UsbError> {
        // 設定を見つける
        let config = self.configurations.iter()
            .find(|c| c.value == config_value)
            .ok_or(UsbError::DeviceError("指定された設定が見つかりません"))?;
        
        // デバイスに設定を適用
        let setup = UsbSetupPacket::new(
            UsbDirection::Out,
            UsbRequestType::Standard,
            UsbRequestRecipient::Device,
            UsbStandardRequest::SetConfiguration as u8,
            config_value as u16,
            0,
            0,
        );
        
        self.control_transfer(setup, None)?;
        
        // 現在の設定を更新
        self.current_configuration = Some(Arc::clone(config));
        
        // 状態を更新
        self.set_state(UsbDeviceState::Configured);
        
        Ok(())
    }
    
    /// コントロール転送を実行
    pub fn control_transfer(&self, setup: UsbSetupPacket, data: Option<&mut [u8]>) -> Result<usize, UsbError> {
        self.hci.control_transfer(self.info.address, setup, data)
    }
    
    /// バルク転送を実行
    pub fn bulk_transfer(&self, endpoint: u8, data: &mut [u8]) -> Result<usize, UsbError> {
        self.hci.bulk_transfer(self.info.address, endpoint, data)
    }
    
    /// 割り込み転送を実行
    pub fn interrupt_transfer(&self, endpoint: u8, data: &mut [u8]) -> Result<usize, UsbError> {
        self.hci.interrupt_transfer(self.info.address, endpoint, data)
    }
    
    /// 文字列記述子を取得
    pub fn get_string_descriptor(&self, index: u8, language_id: u16) -> Result<String, UsbError> {
        // まず記述子の長さを取得
        let mut buf = [0u8; 8];
        let setup = UsbSetupPacket::new(
            UsbDirection::In,
            UsbRequestType::Standard,
            UsbRequestRecipient::Device,
            UsbStandardRequest::GetDescriptor as u8,
            ((UsbDescriptorType::String as u16) << 8) | (index as u16),
            language_id,
            buf.len() as u16,
        );
        
        let len = self.control_transfer(setup, Some(&mut buf))?;
        if len < 2 || buf[1] != UsbDescriptorType::String as u8 {
            return Err(UsbError::DeviceError("無効な文字列記述子"));
        }
        
        let total_len = buf[0] as usize;
        if total_len <= 2 {
            return Ok(String::new());
        }
        
        // 完全な記述子を取得
        let mut string_data = vec![0u8; total_len];
        let setup = UsbSetupPacket::new(
            UsbDirection::In,
            UsbRequestType::Standard,
            UsbRequestRecipient::Device,
            UsbStandardRequest::GetDescriptor as u8,
            ((UsbDescriptorType::String as u16) << 8) | (index as u16),
            language_id,
            total_len as u16,
        );
        
        let len = self.control_transfer(setup, Some(&mut string_data))?;
        if len < 2 || string_data[1] != UsbDescriptorType::String as u8 {
            return Err(UsbError::DeviceError("無効な文字列記述子"));
        }
        
        // UTF-16LEからUTF-8に変換
        let mut result = String::new();
        for i in (2..len).step_by(2) {
            if i + 1 >= len {
                break;
            }
            
            let utf16_char = u16::from_le_bytes([string_data[i], string_data[i + 1]]);
            if let Some(c) = char::from_u32(utf16_char as u32) {
                result.push(c);
            }
        }
        
        Ok(result)
    }
}

/// USBデバイスドライバートレイト
pub trait UsbDeviceDriver {
    /// ドライバー名を取得
    fn name(&self) -> &str;
    
    /// サポートするベンダーIDとプロダクトIDのペア
    fn supported_devices(&self) -> &[(u16, u16)];
    
    /// サポートするクラス、サブクラス、プロトコルの組み合わせ
    fn supported_classes(&self) -> &[(u8, u8, u8)];
    
    /// このドライバーがデバイスをサポートするかどうかチェック
    fn probe(&self, device: &UsbDeviceInfo) -> bool {
        // ベンダーID/プロダクトIDでチェック
        for &(vid, pid) in self.supported_devices() {
            if device.vendor_id == vid && device.product_id == pid {
                return true;
            }
        }
        
        // クラス/サブクラス/プロトコルでチェック
        for &(class, subclass, protocol) in self.supported_classes() {
            if device.device_class == class && 
               device.device_subclass == subclass && 
               device.device_protocol == protocol {
                return true;
            }
        }
        
        false
    }
    
    /// デバイスを初期化
    fn init(&self, device: &mut UsbDevice) -> Result<(), UsbError>;
    
    /// デバイスを削除
    fn remove(&self, device: &UsbDevice) -> Result<(), UsbError>;
}

/// USBデバイスマネージャー
pub struct UsbDeviceManager {
    /// 接続されているデバイス
    devices: RwLock<BTreeMap<u8, Arc<Mutex<UsbDevice>>>>,
    /// 登録されているドライバー
    drivers: RwLock<Vec<Arc<dyn UsbDeviceDriver + Send + Sync>>>,
    /// 初期化済みフラグ
    initialized: AtomicBool,
}

impl UsbDeviceManager {
    /// 新しいUSBデバイスマネージャーを作成
    pub fn new() -> Self {
        Self {
            devices: RwLock::new(BTreeMap::new()),
            drivers: RwLock::new(Vec::new()),
            initialized: AtomicBool::new(false),
        }
    }
    
    /// デバイスマネージャーを初期化
    pub fn init(&self) -> Result<(), UsbError> {
        if self.initialized.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        
        Ok(())
    }
    
    /// ドライバーを登録
    pub fn register_driver(&self, driver: Arc<dyn UsbDeviceDriver + Send + Sync>) {
        let mut drivers = self.drivers.write();
        drivers.push(driver);
    }
    
    /// デバイスを追加
    pub fn add_device(&self, info: UsbDeviceInfo, hci: Arc<dyn UsbHci + Send + Sync>) -> Result<(), UsbError> {
        let mut device = UsbDevice::new(info, hci);
        
        // 適切なドライバーを検索
        let mut selected_driver = None;
        {
            let drivers = self.drivers.read();
            for driver in drivers.iter() {
                if driver.probe(&device.info) {
                    selected_driver = Some(Arc::clone(driver));
                    break;
                }
            }
        }
        
        // ドライバーが見つかった場合は初期化
        if let Some(driver) = selected_driver {
            driver.init(&mut device)?;
            device.driver = Some(driver);
        }
        
        // デバイスを登録
        let device_arc = Arc::new(Mutex::new(device));
        let mut devices = self.devices.write();
        devices.insert(info.address, device_arc);
        
        Ok(())
    }
    
    /// デバイスを削除
    pub fn remove_device(&self, address: u8) -> Result<(), UsbError> {
        let mut devices = self.devices.write();
        
        if let Some(device_arc) = devices.remove(&address) {
            let device = device_arc.lock();
            
            // ドライバーがあれば削除処理を呼び出す
            if let Some(driver) = &device.driver {
                driver.remove(&device)?;
            }
            
            // デバイスの状態を切断済みに設定
            device.set_state(UsbDeviceState::Disconnected);
        }
        
        Ok(())
    }
    
    /// デバイスを取得
    pub fn get_device(&self, address: u8) -> Option<Arc<Mutex<UsbDevice>>> {
        let devices = self.devices.read();
        devices.get(&address).cloned()
    }
    
    /// 接続されているすべてのデバイスを取得
    pub fn get_all_devices(&self) -> Vec<Arc<Mutex<UsbDevice>>> {
        let devices = self.devices.read();
        devices.values().cloned().collect()
    }
}

// シングルトンインスタンス
static DEVICE_MANAGER: spin::Once<UsbDeviceManager> = spin::Once::new();

/// USBデバイスマネージャーのグローバルインスタンスを取得
pub fn get_device_manager() -> &'static UsbDeviceManager {
    DEVICE_MANAGER.call_once(|| UsbDeviceManager::new())
}

/// USBデバイスサブシステムを初期化
pub fn init() -> Result<(), &'static str> {
    // デバイスマネージャーを初期化
    get_device_manager().init().map_err(|_| "USBデバイスマネージャーの初期化に失敗しました")?;
    
    Ok(())
}

/// USB診断情報を表示
pub fn print_diagnostic_info() {
    let manager = get_device_manager();
    let devices = manager.get_all_devices();
    
    if devices.is_empty() {
        crate::println!("接続されているUSBデバイスはありません");
        return;
    }
    
    crate::println!("接続されているUSBデバイス:");
    for device_arc in devices {
        let device = device_arc.lock();
        crate::println!("  アドレス {:02X}: {}", device.info.address, device.info.description());
        
        if let Some(config) = &device.current_configuration {
            crate::println!("    設定: {}", config.value);
            
            for interface in &config.interfaces {
                let class_name = crate::drivers::usb::UsbClass::from_code(interface.class).name();
                if let Some(name) = &interface.name {
                    crate::println!("    インターフェース {}: {} ({})", interface.number, name, class_name);
                } else {
                    crate::println!("    インターフェース {}: {}", interface.number, class_name);
                }
                
                for endpoint in &interface.endpoints {
                    let direction = match endpoint.direction {
                        UsbDirection::In => "IN",
                        UsbDirection::Out => "OUT",
                    };
                    
                    let type_str = match endpoint.endpoint_type {
                        UsbEndpointType::Control => "コントロール",
                        UsbEndpointType::Isochronous => "アイソクロナス",
                        UsbEndpointType::Bulk => "バルク",
                        UsbEndpointType::Interrupt => "割り込み",
                    };
                    
                    crate::println!("      エンドポイント {:02X}: {} {} (最大 {} バイト)", 
                        endpoint.address, direction, type_str, endpoint.max_packet_size);
                }
            }
        }
    }
} 