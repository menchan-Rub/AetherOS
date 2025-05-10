// USBホストコントローラインターフェースモジュール
// AetherOS用高性能USBドライバー実装
// 作成者: AetherOSチーム

//! # USBホストコントローラインターフェース
//! 
//! このモジュールは、さまざまなUSBホストコントローラインターフェース（UHCI、OHCI、EHCI、xHCI）の
//! 共通抽象化レイヤーを提供します。

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, RwLock};

use crate::drivers::pci::{PciDevice, PciClass};
use crate::mm::PhysAddr;
use crate::sync::OnceCell;

/// USBのスピード規格
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UsbSpeed {
    /// Low Speed (1.5 Mbps)
    Low,
    /// Full Speed (12 Mbps)
    Full,
    /// High Speed (480 Mbps)
    High,
    /// Super Speed (5 Gbps)
    Super,
    /// Super Speed+ (10 Gbps)
    SuperPlus,
}

/// USBデバイスの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbDeviceType {
    /// 標準的なUSBデバイス
    Standard,
    /// ハブデバイス
    Hub,
    /// 複合デバイス
    Composite,
    /// コミュニケーションデバイス
    Communication,
    /// ワイヤレスコントローラ
    Wireless,
    /// アプリケーション固有デバイス
    ApplicationSpecific,
    /// ベンダー固有デバイス
    VendorSpecific,
}

/// USBリクエストの方向
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbDirection {
    /// ホストからデバイスへ
    HostToDevice,
    /// デバイスからホストへ
    DeviceToHost,
}

/// USBリクエストの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbRequestType {
    /// 標準リクエスト
    Standard,
    /// クラス固有リクエスト
    Class,
    /// ベンダー固有リクエスト
    Vendor,
    /// 予約済み
    Reserved,
}

/// USBリクエストの受信者
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbRequestRecipient {
    /// デバイス全体
    Device,
    /// 特定のインターフェース
    Interface,
    /// 特定のエンドポイント
    Endpoint,
    /// その他
    Other,
}

/// USBリクエストのセットアップパケット
#[derive(Debug, Clone, Copy)]
pub struct UsbSetupPacket {
    /// リクエスト種別（方向、種類、受信者を含む）
    pub request_type: u8,
    /// リクエストコード
    pub request: u8,
    /// リクエスト値
    pub value: u16,
    /// リクエストインデックス
    pub index: u16,
    /// データ長
    pub length: u16,
}

impl UsbSetupPacket {
    /// 新しいセットアップパケットを作成
    pub fn new(
        direction: UsbDirection,
        request_type: UsbRequestType,
        recipient: UsbRequestRecipient,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
    ) -> Self {
        let dir_bit = match direction {
            UsbDirection::HostToDevice => 0,
            UsbDirection::DeviceToHost => 1,
        };
        
        let type_bits = match request_type {
            UsbRequestType::Standard => 0,
            UsbRequestType::Class => 1,
            UsbRequestType::Vendor => 2,
            UsbRequestType::Reserved => 3,
        };
        
        let recipient_bits = match recipient {
            UsbRequestRecipient::Device => 0,
            UsbRequestRecipient::Interface => 1,
            UsbRequestRecipient::Endpoint => 2,
            UsbRequestRecipient::Other => 3,
        };
        
        let request_type = (dir_bit << 7) | (type_bits << 5) | recipient_bits;
        
        Self {
            request_type,
            request,
            value,
            index,
            length,
        }
    }
    
    /// 方向を取得
    pub fn direction(&self) -> UsbDirection {
        if (self.request_type & 0x80) != 0 {
            UsbDirection::DeviceToHost
        } else {
            UsbDirection::HostToDevice
        }
    }
    
    /// リクエスト種類を取得
    pub fn request_type(&self) -> UsbRequestType {
        match (self.request_type >> 5) & 0x3 {
            0 => UsbRequestType::Standard,
            1 => UsbRequestType::Class,
            2 => UsbRequestType::Vendor,
            _ => UsbRequestType::Reserved,
        }
    }
    
    /// 受信者を取得
    pub fn recipient(&self) -> UsbRequestRecipient {
        match self.request_type & 0x1F {
            0 => UsbRequestRecipient::Device,
            1 => UsbRequestRecipient::Interface,
            2 => UsbRequestRecipient::Endpoint,
            _ => UsbRequestRecipient::Other,
        }
    }
}

/// 標準USBデバイスリクエスト
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbStandardRequest {
    /// デバイスステータスの取得
    GetStatus = 0x00,
    /// 機能のクリア
    ClearFeature = 0x01,
    /// 機能の設定
    SetFeature = 0x03,
    /// アドレスの設定
    SetAddress = 0x05,
    /// デスクリプタの取得
    GetDescriptor = 0x06,
    /// デスクリプタの設定
    SetDescriptor = 0x07,
    /// 設定の取得
    GetConfiguration = 0x08,
    /// 設定の設定
    SetConfiguration = 0x09,
    /// インターフェースの取得
    GetInterface = 0x0A,
    /// インターフェースの設定
    SetInterface = 0x0B,
    /// 同期フレームの取得
    SynchFrame = 0x0C,
    /// SET_SEL (SuperSpeed)
    SetSel = 0x30,
    /// SET_ISOCH_DELAY (SuperSpeed)
    SetIsochDelay = 0x31,
}

/// USBデスクリプタの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbDescriptorType {
    /// デバイスデスクリプタ
    Device = 0x01,
    /// 設定デスクリプタ
    Configuration = 0x02,
    /// 文字列デスクリプタ
    String = 0x03,
    /// インターフェースデスクリプタ
    Interface = 0x04,
    /// エンドポイントデスクリプタ
    Endpoint = 0x05,
    /// デバイス修飾子デスクリプタ
    DeviceQualifier = 0x06,
    /// その他速度設定デスクリプタ
    OtherSpeedConfiguration = 0x07,
    /// インターフェース電力デスクリプタ
    InterfacePower = 0x08,
    /// OTGデスクリプタ
    Otg = 0x09,
    /// デバッグデスクリプタ
    Debug = 0x0A,
    /// インターフェース関連付けデスクリプタ
    InterfaceAssociation = 0x0B,
    /// BOS デスクリプタ (USB 3.0)
    Bos = 0x0F,
    /// デバイス機能デスクリプタ (USB 3.0)
    DeviceCapability = 0x10,
    /// SuperSpeed USB エンドポイント同伴子デスクリプタ (USB 3.0)
    SuperSpeedEndpointCompanion = 0x30,
}

/// USBデバイスデスクリプタ
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct UsbDeviceDescriptor {
    /// デスクリプタの長さ
    pub length: u8,
    /// デスクリプタのタイプ
    pub descriptor_type: u8,
    /// USB仕様のバージョン
    pub usb_version: u16,
    /// デバイスクラス
    pub device_class: u8,
    /// デバイスサブクラス
    pub device_subclass: u8,
    /// デバイスプロトコル
    pub device_protocol: u8,
    /// 最大パケットサイズ
    pub max_packet_size0: u8,
    /// ベンダーID
    pub vendor_id: u16,
    /// 製品ID
    pub product_id: u16,
    /// デバイスバージョン
    pub device_version: u16,
    /// 製造者文字列インデックス
    pub manufacturer_string: u8,
    /// 製品文字列インデックス
    pub product_string: u8,
    /// シリアル番号文字列インデックス
    pub serial_number_string: u8,
    /// 設定の数
    pub num_configurations: u8,
}

/// USBホストコントローラーの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbHciType {
    /// Universal Host Controller Interface (UHCI)
    Uhci,
    /// Open Host Controller Interface (OHCI)
    Ohci,
    /// Enhanced Host Controller Interface (EHCI)
    Ehci,
    /// eXtensible Host Controller Interface (xHCI)
    Xhci,
    /// 未知のコントローラー
    Unknown,
}

/// USBホストコントローラーインターフェース（HCI）の抽象化
pub trait UsbHci: Send + Sync {
    /// HCIの種類を取得
    fn hci_type(&self) -> UsbHciType;
    
    /// HCIの初期化
    fn initialize(&self) -> Result<(), &'static str>;
    
    /// 利用可能なルートハブポートの数を取得
    fn root_hub_port_count(&self) -> usize;
    
    /// 指定されたポートにデバイスが接続されているかチェック
    fn is_device_connected(&self, port: usize) -> bool;
    
    /// 指定されたポートのデバイス速度を取得
    fn get_port_speed(&self, port: usize) -> Option<UsbSpeed>;
    
    /// ポートリセットを実行
    fn reset_port(&self, port: usize) -> Result<(), &'static str>;
    
    /// コントロール転送を実行
    fn control_transfer(
        &self,
        device_addr: u8,
        setup: UsbSetupPacket,
        data: Option<&mut [u8]>,
    ) -> Result<usize, &'static str>;
}

/// USBホストコントローラードライバーのファクトリー
pub trait UsbHciFactory: Send + Sync {
    /// ホストコントローラーの種類を取得
    fn hci_type(&self) -> UsbHciType;
    
    /// PCIデバイスからホストコントローラーを作成できるか判定
    fn can_handle_device(&self, device: &PciDevice) -> bool;
    
    /// PCIデバイスからホストコントローラーを作成
    fn create_hci(&self, device: Arc<PciDevice>) -> Result<Arc<dyn UsbHci>, &'static str>;
}

/// USBサブシステム
pub struct UsbSubsystem {
    /// 登録されたHCIファクトリー
    factories: RwLock<Vec<Arc<dyn UsbHciFactory>>>,
    /// 検出されたホストコントローラー
    controllers: RwLock<Vec<Arc<dyn UsbHci>>>,
    /// 初期化完了フラグ
    initialized: AtomicBool,
}

impl UsbSubsystem {
    /// USBサブシステムのグローバルインスタンス
    pub static INSTANCE: OnceCell<UsbSubsystem> = OnceCell::new();
    
    /// 新しいUSBサブシステムを作成
    pub fn new() -> Self {
        Self {
            factories: RwLock::new(Vec::new()),
            controllers: RwLock::new(Vec::new()),
            initialized: AtomicBool::new(false),
        }
    }
    
    /// HCIファクトリーを登録
    pub fn register_hci_factory(&self, factory: Arc<dyn UsbHciFactory>) {
        let mut factories = self.factories.write();
        factories.push(factory);
    }
    
    /// PCIデバイスからUSBホストコントローラーを作成
    fn create_hci_from_pci(&self, device: Arc<PciDevice>) -> Option<Arc<dyn UsbHci>> {
        let factories = self.factories.read();
        
        for factory in factories.iter() {
            if factory.can_handle_device(&device) {
                if let Ok(hci) = factory.create_hci(device.clone()) {
                    return Some(hci);
                }
            }
        }
        
        None
    }
    
    /// PCIバスからUSBホストコントローラーを検出
    fn detect_controllers_from_pci(&self) -> Result<(), &'static str> {
        use crate::drivers::pci::PciSubsystem;
        
        if let Some(pci) = PciSubsystem::INSTANCE.get() {
            // SerialBusController (0x0C), USB Controller (0x03)
            let usb_devices = pci.find_devices_by_class(0x0C, 0x03);
            
            let mut controllers = self.controllers.write();
            
            for device in usb_devices {
                if let Some(hci) = self.create_hci_from_pci(device.clone()) {
                    log::info!(
                        "USBホストコントローラーを検出: {:?} ({:?})",
                        hci.hci_type(),
                        device.info.address
                    );
                    
                    if let Err(e) = hci.initialize() {
                        log::error!(
                            "USBホストコントローラーの初期化に失敗: {:?} - {}",
                            hci.hci_type(),
                            e
                        );
                        continue;
                    }
                    
                    controllers.push(hci);
                }
            }
            
            Ok(())
        } else {
            Err("PCIサブシステムが初期化されていません")
        }
    }
    
    /// USBサブシステムを初期化
    pub fn initialize(&self) -> Result<(), &'static str> {
        if self.initialized.load(Ordering::SeqCst) {
            return Ok(());
        }
        
        // ホストコントローラーの検出（PCIバスから）
        self.detect_controllers_from_pci()?;
        
        // 少なくとも1つのコントローラーが必要
        if self.controllers.read().is_empty() {
            return Err("USBホストコントローラーが見つかりませんでした");
        }
        
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }
    
    /// 全てのUSBホストコントローラーを取得
    pub fn get_controllers(&self) -> Vec<Arc<dyn UsbHci>> {
        let controllers = self.controllers.read();
        controllers.clone()
    }
    
    /// 指定された種類のUSBホストコントローラーを取得
    pub fn get_controllers_by_type(&self, hci_type: UsbHciType) -> Vec<Arc<dyn UsbHci>> {
        let controllers = self.controllers.read();
        controllers
            .iter()
            .filter(|c| c.hci_type() == hci_type)
            .cloned()
            .collect()
    }
}

/// USBサブシステムの初期化
pub fn init() -> Result<(), &'static str> {
    let subsystem = UsbSubsystem::new();
    
    // 各種HCIファクトリーを登録（各実装によって提供される）
    
    // サブシステムを初期化
    subsystem.initialize()?;
    
    // グローバルインスタンスを設定
    UsbSubsystem::INSTANCE.set(subsystem)
        .map_err(|_| "USBサブシステムの初期化に失敗しました")?;
    
    Ok(())
}

/// USB関連の診断情報を出力
pub fn print_diagnostic_info() {
    if let Some(usb) = UsbSubsystem::INSTANCE.get() {
        let controllers = usb.get_controllers();
        
        log::info!("USBホストコントローラー一覧 ({} 台見つかりました):", controllers.len());
        
        for (i, controller) in controllers.iter().enumerate() {
            let port_count = controller.root_hub_port_count();
            
            log::info!(
                "  コントローラー #{}: {:?} ({} ポート)",
                i,
                controller.hci_type(),
                port_count
            );
            
            // 各ポートの状態を確認
            for port in 0..port_count {
                if controller.is_device_connected(port) {
                    let speed = controller.get_port_speed(port).unwrap_or(UsbSpeed::Full);
                    log::info!(
                        "    ポート #{}: デバイス接続中 (速度: {:?})",
                        port,
                        speed
                    );
                } else {
                    log::info!("    ポート #{}: デバイスなし", port);
                }
            }
        }
    } else {
        log::warn!("USBサブシステムが初期化されていません");
    }
} 