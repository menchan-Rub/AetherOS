// USBドライバーモジュール
// AetherOS用高性能USBドライバー実装
// 作成者: AetherOSチーム

//! # AetherOS USBサブシステム
//! 
//! このモジュールは、AetherOSのUSBデバイスドライバーサブシステムを提供します。
//! 高性能かつ拡張性の高いUSBドライバーフレームワークを実装し、さまざまなUSBデバイスをサポートします。
//! 主な特徴:
//! 
//! - USBホストコントローラーインターフェース (HCI) 抽象化
//! - UHCI, OHCI, EHCI, xHCIのサポート
//! - USB 1.1, 2.0, 3.0, 3.1のデバイスサポート
//! - ホットプラグ検出と自動デバイス列挙
//! - スレッドセーフなデバイスアクセス
//! - 高度な電力管理

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, RwLock};

// サブモジュールの公開
pub mod hci;  // ホストコントローラーインターフェース
pub mod xhci; // eXtensible Host Controller Interface
pub mod device; // USBデバイスサブシステム

// 公開要素の再エクスポート
pub use self::hci::{
    UsbHci, UsbHciType, UsbSubsystem, UsbSpeed, UsbDeviceType,
    UsbSetupPacket, UsbDirection, UsbRequestType, UsbRequestRecipient,
    UsbStandardRequest, UsbDescriptorType, UsbDeviceDescriptor
};

/// USBデバイスクラスコード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbClass {
    /// インターフェースで定義
    Interface = 0x00,
    /// オーディオ
    Audio = 0x01,
    /// 通信デバイス
    Communications = 0x02,
    /// HID (Human Interface Device)
    Hid = 0x03,
    /// 物理デバイス
    Physical = 0x05,
    /// 画像デバイス
    Image = 0x06,
    /// プリンタ
    Printer = 0x07,
    /// マスストレージ
    MassStorage = 0x08,
    /// USBハブ
    Hub = 0x09,
    /// CDCデータ
    CdcData = 0x0A,
    /// スマートカード
    SmartCard = 0x0B,
    /// コンテンツセキュリティ
    ContentSecurity = 0x0D,
    /// ビデオ
    Video = 0x0E,
    /// パーソナルヘルスケア
    PersonalHealthcare = 0x0F,
    /// オーディオ/ビデオデバイス
    AudioVideo = 0x10,
    /// ビルボード
    Billboard = 0x11,
    /// タイプCブリッジ
    TypeCBridge = 0x12,
    /// ワイヤレスコントローラー
    Wireless = 0xE0,
    /// その他
    Miscellaneous = 0xEF,
    /// アプリケーション固有
    ApplicationSpecific = 0xFE,
    /// ベンダー固有
    VendorSpecific = 0xFF,
    /// 不明
    Unknown = 0x100,
}

impl UsbClass {
    /// クラスコードからUSBクラスを取得
    pub fn from_code(code: u8) -> Self {
        match code {
            0x00 => Self::Interface,
            0x01 => Self::Audio,
            0x02 => Self::Communications,
            0x03 => Self::Hid,
            0x05 => Self::Physical,
            0x06 => Self::Image,
            0x07 => Self::Printer,
            0x08 => Self::MassStorage,
            0x09 => Self::Hub,
            0x0A => Self::CdcData,
            0x0B => Self::SmartCard,
            0x0D => Self::ContentSecurity,
            0x0E => Self::Video,
            0x0F => Self::PersonalHealthcare,
            0x10 => Self::AudioVideo,
            0x11 => Self::Billboard,
            0x12 => Self::TypeCBridge,
            0xE0 => Self::Wireless,
            0xEF => Self::Miscellaneous,
            0xFE => Self::ApplicationSpecific,
            0xFF => Self::VendorSpecific,
            _ => Self::Unknown,
        }
    }
    
    /// クラス名を取得
    pub fn name(&self) -> &'static str {
        match self {
            Self::Interface => "Interface Defined",
            Self::Audio => "Audio",
            Self::Communications => "Communications",
            Self::Hid => "Human Interface Device",
            Self::Physical => "Physical",
            Self::Image => "Image",
            Self::Printer => "Printer",
            Self::MassStorage => "Mass Storage",
            Self::Hub => "Hub",
            Self::CdcData => "CDC Data",
            Self::SmartCard => "Smart Card",
            Self::ContentSecurity => "Content Security",
            Self::Video => "Video",
            Self::PersonalHealthcare => "Personal Healthcare",
            Self::AudioVideo => "Audio/Video",
            Self::Billboard => "Billboard",
            Self::TypeCBridge => "Type-C Bridge",
            Self::Wireless => "Wireless Controller",
            Self::Miscellaneous => "Miscellaneous",
            Self::ApplicationSpecific => "Application Specific",
            Self::VendorSpecific => "Vendor Specific",
            Self::Unknown => "Unknown",
        }
    }
}

/// USBサブシステムエラー
#[derive(Debug, Clone)]
pub enum UsbError {
    /// 初期化エラー
    InitializationFailed(&'static str),
    /// デバイスエラー
    DeviceError(&'static str),
    /// 転送エラー
    TransferError(&'static str),
    /// タイムアウト
    Timeout(&'static str),
    /// コントローラーが見つからない
    NoController,
    /// サポートされていない操作
    Unsupported,
    /// リソース不足
    OutOfResources,
    /// その他のエラー
    Other(&'static str),
}

impl fmt::Display for UsbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitializationFailed(msg) => write!(f, "USB初期化エラー: {}", msg),
            Self::DeviceError(msg) => write!(f, "USBデバイスエラー: {}", msg),
            Self::TransferError(msg) => write!(f, "USB転送エラー: {}", msg),
            Self::Timeout(msg) => write!(f, "USBタイムアウト: {}", msg),
            Self::NoController => write!(f, "USBコントローラーが見つかりません"),
            Self::Unsupported => write!(f, "サポートされていないUSB操作"),
            Self::OutOfResources => write!(f, "USBリソース不足"),
            Self::Other(msg) => write!(f, "USBエラー: {}", msg),
        }
    }
}

/// USBデバイス情報
#[derive(Debug, Clone)]
pub struct UsbDeviceInfo {
    /// USBアドレス
    pub address: u8,
    /// ベンダーID
    pub vendor_id: u16,
    /// 製品ID
    pub product_id: u16,
    /// デバイスクラス
    pub device_class: u8,
    /// デバイスサブクラス
    pub device_subclass: u8,
    /// デバイスプロトコル
    pub device_protocol: u8,
    /// USB仕様バージョン
    pub usb_version: u16,
    /// デバイスバージョン
    pub device_version: u16,
    /// 最大パケットサイズ（エンドポイント0）
    pub max_packet_size0: u8,
    /// 設定の数
    pub num_configurations: u8,
    /// 製造者名
    pub manufacturer: Option<String>,
    /// 製品名
    pub product: Option<String>,
    /// シリアル番号
    pub serial_number: Option<String>,
    /// USB速度
    pub speed: UsbSpeed,
    /// 親ハブのアドレス（もしあれば）
    pub parent_hub_addr: Option<u8>,
    /// 親ハブのポート番号（もしあれば）
    pub parent_port: Option<u8>,
}

impl UsbDeviceInfo {
    /// デバイスクラスの名前を取得
    pub fn class_name(&self) -> &'static str {
        UsbClass::from_code(self.device_class).name()
    }
    
    /// デバイスの説明を取得
    pub fn description(&self) -> String {
        let class_name = self.class_name();
        
        if let (Some(manufacturer), Some(product)) = (&self.manufacturer, &self.product) {
            format!("{} {} ({})", manufacturer, product, class_name)
        } else if let Some(product) = &self.product {
            format!("{} ({})", product, class_name)
        } else {
            format!("USB Device {:04x}:{:04x} ({})", self.vendor_id, self.product_id, class_name)
        }
    }
}

/// USBサブシステムの初期化
pub fn init() -> Result<(), &'static str> {
    // HCIサブシステムの初期化
    hci::init()?;
    
    // xHCIドライバーの登録
    xhci::register_driver()?;
    
    // デバイスサブシステムの初期化
    device::init()?;
    
    // 初期診断情報を出力
    print_diagnostic_info();
    
    Ok(())
}

/// USB診断情報を表示
pub fn print_diagnostic_info() {
    // HCI診断情報
    hci::print_diagnostic_info();
    
    // デバイス診断情報
    device::print_diagnostic_info();
} 