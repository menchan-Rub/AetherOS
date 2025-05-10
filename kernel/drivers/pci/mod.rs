// AetherOS PCIドライバ
//
// このモジュールはAetherOSのPCIバスドライバの実装を提供します。
// PCIデバイスの検出、設定、および管理機能が含まれています。

use alloc::string::String;
use alloc::vec::Vec;
use alloc::boxed::Box;

use crate::core::log;
use crate::core::sync::SpinLock;
use crate::core::io::MemoryRegion;

pub mod address;
pub mod config;
pub mod config_access;
pub mod config_access_util;
pub mod device;
pub mod device_trait;

/// PCIアドレス
///
/// PCIデバイスを一意に識別するためのアドレス情報を保持します。
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PciAddress {
    /// PCIセグメント（拡張PCI構成空間用）
    pub segment: u16,
    /// PCIバス番号
    pub bus: u8,
    /// PCIデバイス番号
    pub device: u8,
    /// PCIファンクション番号
    pub function: u8,
}

impl PciAddress {
    /// 新しいPCIアドレスを作成
    pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        Self {
            segment,
            bus,
            device,
            function,
        }
    }
    
    /// デフォルトのPCIアドレスを作成（ホストブリッジを指す）
    pub const fn default() -> Self {
        Self {
            segment: 0,
            bus: 0,
            device: 0,
            function: 0,
        }
    }
    
    /// セグメント、バス、デバイス、ファンクションをデバッグ形式で表示
    pub fn to_debug_string(&self) -> String {
        format!("{:04x}:{:02x}:{:02x}.{:01x}", self.segment, self.bus, self.device, self.function)
    }
}

/// PCIデバイス情報
///
/// PCIデバイスの基本情報を保持する構造体。
#[derive(Debug, Clone)]
pub struct PciDeviceInfo {
    /// PCIアドレス
    pub address: PciAddress,
    /// ベンダーID
    pub vendor_id: u16,
    /// デバイスID
    pub device_id: u16,
    /// クラスコード
    pub class_code: u8,
    /// サブクラスコード
    pub subclass_code: u8,
    /// プログラミングインターフェース
    pub prog_if: u8,
    /// リビジョンID
    pub revision_id: u8,
    /// ヘッダタイプ
    pub header_type: u8,
    /// サブシステムベンダーID
    pub subsystem_vendor_id: u16,
    /// サブシステムID
    pub subsystem_id: u16,
    /// 割り込みライン
    pub interrupt_line: u8,
    /// 割り込みピン
    pub interrupt_pin: u8,
}

impl PciDeviceInfo {
    /// クラスコード、サブクラスコード、プログラミングインターフェースを32ビット値として取得
    pub fn get_class_code(&self) -> u32 {
        ((self.class_code as u32) << 16) | ((self.subclass_code as u32) << 8) | (self.prog_if as u32)
    }
    
    /// PCIデバイスのクラス名を取得
    pub fn get_class_name(&self) -> &'static str {
        match self.class_code {
            0x00 => "未分類デバイス",
            0x01 => "マスストレージコントローラ",
            0x02 => "ネットワークコントローラ",
            0x03 => "ディスプレイコントローラ",
            0x04 => "マルチメディアデバイス",
            0x05 => "メモリコントローラ",
            0x06 => "ブリッジデバイス",
            0x07 => "シンプル通信コントローラ",
            0x08 => "ベースシステム周辺機器",
            0x09 => "入力デバイス",
            0x0A => "ドッキングステーション",
            0x0B => "プロセッサ",
            0x0C => "シリアルバスコントローラ",
            0x0D => "ワイヤレスコントローラ",
            0x0E => "インテリジェントI/Oコントローラ",
            0x0F => "サテライト通信コントローラ",
            0x10 => "暗号化コントローラ",
            0x11 => "信号処理コントローラ",
            0x12 => "処理アクセラレータ",
            0x13 => "非必須計装",
            0x40 => "コプロセッサ",
            0xFF => "不明なデバイス",
            _ => "予約済みデバイスクラス",
        }
    }
    
    /// サブシステム文字列を取得
    pub fn get_subsystem_description(&self) -> String {
        if self.subsystem_vendor_id != 0 || self.subsystem_id != 0 {
            format!("サブシステム: ベンダー={:04x}, ID={:04x}",
                   self.subsystem_vendor_id, self.subsystem_id)
        } else {
            "サブシステム: なし".to_string()
        }
    }
    
    /// PCI-PCIブリッジかどうかを判定
    pub fn is_pci_bridge(&self) -> bool {
        self.class_code == 0x06 && self.subclass_code == 0x04
    }
    
    /// マルチファンクションデバイスかどうかを判定
    pub fn is_multifunction(&self) -> bool {
        (self.header_type & 0x80) != 0
    }
    
    /// ヘッダタイプを取得（0x7Fでマスク）
    pub fn get_header_type(&self) -> u8 {
        self.header_type & 0x7F
    }
}

/// PCIリソースタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciResourceType {
    /// I/Oポート空間
    Io,
    /// メモリ空間（32ビット）
    Memory32,
    /// メモリ空間（64ビット）
    Memory64,
    /// プリフェッチ可能なメモリ（32ビット）
    PrefetchableMemory32,
    /// プリフェッチ可能なメモリ（64ビット）
    PrefetchableMemory64,
    /// 拡張コンフィギュレーション空間
    ExtendedConfig,
}

/// PCIリソース
#[derive(Debug, Clone)]
pub struct PciResource {
    /// リソースタイプ
    pub resource_type: PciResourceType,
    /// ベースアドレス（物理）
    pub base: u64,
    /// サイズ（バイト単位）
    pub size: u64,
    /// リソースインデックス（BARインデックスなど）
    pub index: usize,
    /// フラグ
    pub flags: u32,
}

impl PciResource {
    /// 新しいPCIリソースを作成
    pub fn new(resource_type: PciResourceType, base: u64, size: u64, index: usize, flags: u32) -> Self {
        Self {
            resource_type,
            base,
            size,
            index,
            flags,
        }
    }
    
    /// メモリリソースとしてのメモリリージョンを取得
    pub fn as_memory_region(&self) -> Option<MemoryRegion> {
        match self.resource_type {
            PciResourceType::Memory32 | 
            PciResourceType::Memory64 | 
            PciResourceType::PrefetchableMemory32 | 
            PciResourceType::PrefetchableMemory64 => {
                if self.base != 0 && self.size > 0 {
                    Some(MemoryRegion::new(self.base as usize, self.size as usize))
                } else {
                    None
                }
            },
            _ => None,
        }
    }
}

/// PCIデバイスマネージャー
///
/// システム内のすべてのPCIデバイスを管理するシングルトン。
pub struct PciManager {
    /// 検出されたPCIデバイスのリスト
    devices: SpinLock<Vec<Box<dyn device::PciDevice + Send + Sync>>>,
    /// PCIハードウェア操作オブジェクト
    hw_ops: Box<dyn config::PciHwOps + Send + Sync>,
}

impl PciManager {
    /// 新しいPCIデバイスマネージャーを作成
    pub fn new() -> Self {
        let hw_ops = config::create_config_space();
        
        Self {
            devices: SpinLock::new(Vec::new()),
            hw_ops,
        }
    }
    
    /// PCIバスをスキャンしてデバイスを検出
    pub fn scan_devices(&self) -> usize {
        let mut device_infos = Vec::new();
        
        // ルートバスをスキャン
        self.hw_ops.scan_bus(0, 0, &mut device_infos);
        
        // 検出されたデバイスをログに記録
        log::info!("{}個のPCIデバイスを検出しました", device_infos.len());
        
        for info in &device_infos {
            log::debug!("PCI {:04x}:{:04x} ({}.{}.{}) - {} {}",
                      info.vendor_id, info.device_id,
                      info.class_code, info.subclass_code, info.prog_if,
                      info.get_class_name(),
                      info.get_subsystem_description());
        }
        
        // デバイスインスタンスを作成
        let mut devices = self.devices.lock();
        
        for info in device_infos {
            // デバイスインスタンスを作成
            let device = device::create_pci_device(info, &*self.hw_ops);
            devices.push(device);
        }
        
        devices.len()
    }
    
    /// 特定のクラス・サブクラスのPCIデバイスを検索
    pub fn find_devices_by_class(
        &self,
        class_code: u8,
        subclass_code: u8,
    ) -> Vec<&(dyn device::PciDevice + Send + Sync)> {
        let devices = self.devices.lock();
        let mut result = Vec::new();
        
        for device in devices.iter() {
            let info = device.get_device_info();
            if info.class_code == class_code && info.subclass_code == subclass_code {
                result.push(&**device);
            }
        }
        
        result
    }
    
    /// ベンダーIDとデバイスIDでPCIデバイスを検索
    pub fn find_devices_by_id(
        &self,
        vendor_id: u16,
        device_id: u16,
    ) -> Vec<&(dyn device::PciDevice + Send + Sync)> {
        let devices = self.devices.lock();
        let mut result = Vec::new();
        
        for device in devices.iter() {
            let info = device.get_device_info();
            if info.vendor_id == vendor_id && info.device_id == device_id {
                result.push(&**device);
            }
        }
        
        result
    }
    
    /// PCIアドレスでデバイスを検索
    pub fn find_device_by_address(
        &self,
        address: &PciAddress,
    ) -> Option<&(dyn device::PciDevice + Send + Sync)> {
        let devices = self.devices.lock();
        
        for device in devices.iter() {
            let info = device.get_device_info();
            if &info.address == address {
                return Some(&**device);
            }
        }
        
        None
    }
    
    /// PCIハードウェア操作オブジェクトを取得
    pub fn get_hw_ops(&self) -> &(dyn config::PciHwOps + Send + Sync) {
        &*self.hw_ops
    }
}

/// グローバルPCIマネージャーインスタンス
static mut PCI_MANAGER: Option<PciManager> = None;

/// PCIサブシステムを初期化
pub fn init() -> usize {
    // PCIマネージャーを作成
    let manager = PciManager::new();
    
    // デバイスをスキャン
    let device_count = manager.scan_devices();
    
    // グローバルインスタンスを設定
    unsafe {
        PCI_MANAGER = Some(manager);
    }
    
    log::info!("PCIサブシステムが初期化されました: {}デバイスが検出されました", device_count);
    
    device_count
}

/// グローバルPCIマネージャーを取得
pub fn get_manager() -> &'static PciManager {
    unsafe {
        PCI_MANAGER.as_ref().expect("PCIマネージャーが初期化されていません")
    }
} 