// PCIデバイストレイト
//
// PCIデバイスのトレイトと基本実装を提供します。
// PCIデバイスドライバはこのトレイトを使用してデバイスとやり取りします。

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use super::address::PciAddress;
use super::config_access::PciConfigAccess;

/// PCIデバイスのベンダーID
pub type PciVendorId = u16;

/// PCIデバイスのデバイスID
pub type PciDeviceId = u16;

/// PCIデバイスクラスコード
pub type PciClassCode = u8;

/// PCIデバイスサブクラスコード
pub type PciSubclassCode = u8;

/// PCIプログラミングインターフェース
pub type PciProgIf = u8;

/// PCIリビジョンID
pub type PciRevisionId = u8;

/// PCIデバイス情報
#[derive(Debug, Clone)]
pub struct PciDeviceInfo {
    /// PCIアドレス
    pub address: PciAddress,
    /// ベンダーID
    pub vendor_id: PciVendorId,
    /// デバイスID
    pub device_id: PciDeviceId,
    /// クラスコード
    pub class_code: PciClassCode,
    /// サブクラスコード
    pub subclass_code: PciSubclassCode,
    /// プログラミングインターフェース
    pub prog_if: PciProgIf,
    /// リビジョンID
    pub revision_id: PciRevisionId,
    /// ヘッダタイプ (0x00: 通常デバイス, 0x01: PCI-PCIブリッジ, 0x02: CardBusブリッジ)
    pub header_type: u8,
    /// サブシステムベンダーID
    pub subsystem_vendor_id: PciVendorId,
    /// サブシステムID
    pub subsystem_id: PciDeviceId,
    /// 割り込みライン
    pub interrupt_line: u8,
    /// 割り込みピン (0=なし, 1=INTA#, 2=INTB#, 3=INTC#, 4=INTD#)
    pub interrupt_pin: u8,
}

impl PciDeviceInfo {
    /// マルチファンクションデバイスかどうかをチェック
    pub fn is_multifunction(&self) -> bool {
        (self.header_type & 0x80) != 0
    }
    
    /// ヘッダタイプを取得（マルチファンクションビットを除く）
    pub fn header_type_code(&self) -> u8 {
        self.header_type & 0x7F
    }
    
    /// PCI-PCIブリッジかどうかをチェック
    pub fn is_pci_bridge(&self) -> bool {
        self.class_code == 0x06 && self.subclass_code == 0x04
    }
    
    /// クラスコード、サブクラスコード、プログラミングインターフェースを32ビット値として取得
    pub fn get_class_code_combined(&self) -> u32 {
        ((self.class_code as u32) << 16) | ((self.subclass_code as u32) << 8) | (self.prog_if as u32)
    }
}

/// PCIリソースタイプ
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PciResourceType {
    /// I/Oポート空間
    Io,
    /// メモリ空間（32ビット）
    Memory32,
    /// メモリ空間（16ビット）
    Memory16,
    /// プリフェッチ可能なメモリ空間（32ビット）
    Memory32Prefetchable,
    /// メモリ空間（64ビット）
    Memory64,
    /// プリフェッチ可能なメモリ空間（64ビット）
    Memory64Prefetchable,
    /// ROM
    Rom,
}

/// PCIリソース
#[derive(Debug, Clone)]
pub struct PciResource {
    /// リソースタイプ
    pub resource_type: PciResourceType,
    /// ベースアドレス
    pub address: usize,
    /// サイズ（バイト単位）
    pub size: usize,
    /// リソースの名前（"BAR0"など）
    pub name: String,
}

impl PciResource {
    /// 新しいPCIリソースを作成
    pub fn new(address: usize, size: usize, resource_type: PciResourceType, name: String) -> Self {
        Self {
            resource_type,
            address,
            size,
            name,
        }
    }
    
    /// メモリリソースかどうかをチェック
    pub fn is_memory(&self) -> bool {
        match self.resource_type {
            PciResourceType::Memory16 | 
            PciResourceType::Memory32 | 
            PciResourceType::Memory64 |
            PciResourceType::Memory32Prefetchable |
            PciResourceType::Memory64Prefetchable |
            PciResourceType::Rom => true,
            _ => false,
        }
    }
    
    /// I/Oリソースかどうかをチェック
    pub fn is_io(&self) -> bool {
        self.resource_type == PciResourceType::Io
    }
    
    /// プリフェッチ可能かどうかをチェック
    pub fn is_prefetchable(&self) -> bool {
        match self.resource_type {
            PciResourceType::Memory32Prefetchable |
            PciResourceType::Memory64Prefetchable => true,
            _ => false,
        }
    }
    
    /// 64ビットリソースかどうかをチェック
    pub fn is_64bit(&self) -> bool {
        match self.resource_type {
            PciResourceType::Memory64 |
            PciResourceType::Memory64Prefetchable => true,
            _ => false,
        }
    }
}

/// PCIケイパビリティID
pub type PciCapabilityId = u8;

/// PCIケイパビリティ
#[derive(Debug, Clone)]
pub struct PciCapability {
    /// ケイパビリティID
    pub id: PciCapabilityId,
    /// コンフィギュレーション空間内のオフセット
    pub offset: u8,
    /// ケイパビリティのバージョン（あれば）
    pub version: Option<u8>,
    /// ケイパビリティの追加データ
    pub data: Vec<u8>,
}

impl PciCapability {
    /// 新しいPCIケイパビリティを作成
    pub fn new(id: PciCapabilityId, offset: u8, version: Option<u8>, data: Vec<u8>) -> Self {
        Self {
            id,
            offset,
            version,
            data,
        }
    }
    
    /// ケイパビリティの名前を取得
    pub fn get_name(&self) -> &'static str {
        match self.id {
            0x01 => "Power Management",
            0x02 => "AGP",
            0x03 => "VPD",
            0x04 => "Slot Identification",
            0x05 => "MSI",
            0x06 => "CompactPCI Hot Swap",
            0x07 => "PCI-X",
            0x08 => "HyperTransport",
            0x09 => "Vendor Specific",
            0x0A => "Debug Port",
            0x0B => "CompactPCI Central Resource Control",
            0x0C => "PCI Hot-Plug",
            0x0D => "PCI Bridge Subsystem Vendor ID",
            0x0E => "AGP 8x",
            0x0F => "Secure Device",
            0x10 => "PCI Express",
            0x11 => "MSI-X",
            0x12 => "SATA Data/Index Config",
            0x13 => "Advanced Features",
            _ => "Unknown",
        }
    }
}

/// PCIデバイストレイト
///
/// PCIデバイスの基本操作を定義します。
pub trait PciDevice: fmt::Debug + Send + Sync {
    /// デバイス情報を取得
    fn get_device_info(&self) -> &PciDeviceInfo;
    
    /// デバイスアドレスを取得
    fn get_address(&self) -> PciAddress;
    
    /// 8ビット値をコンフィギュレーション空間から読み取る
    fn read_config_u8(&self, offset: u8) -> u8;
    
    /// 16ビット値をコンフィギュレーション空間から読み取る
    fn read_config_u16(&self, offset: u8) -> u16;
    
    /// 32ビット値をコンフィギュレーション空間から読み取る
    fn read_config_u32(&self, offset: u8) -> u32;
    
    /// 8ビット値をコンフィギュレーション空間に書き込む
    fn write_config_u8(&self, offset: u8, value: u8);
    
    /// 16ビット値をコンフィギュレーション空間に書き込む
    fn write_config_u16(&self, offset: u8, value: u16);
    
    /// 32ビット値をコンフィギュレーション空間に書き込む
    fn write_config_u32(&self, offset: u8, value: u32);
    
    /// デバイスリソースを取得
    fn get_resources(&self) -> Vec<PciResource>;
    
    /// デバイスケイパビリティを取得
    fn get_capabilities(&self) -> Vec<PciCapability>;
    
    /// デバイスを有効化（メモリ空間とI/O空間アクセスを有効化）
    fn enable(&self) -> Result<(), &'static str>;
    
    /// デバイスを無効化
    fn disable(&self) -> Result<(), &'static str>;
    
    /// バスマスタリングを有効化
    fn enable_bus_master(&self) -> Result<(), &'static str>;
    
    /// バスマスタリングを無効化
    fn disable_bus_master(&self) -> Result<(), &'static str>;
    
    /// 割り込みを有効化
    fn enable_interrupt(&self) -> Result<(), &'static str>;
    
    /// 割り込みを無効化
    fn disable_interrupt(&self) -> Result<(), &'static str>;
    
    /// デバイスが有効かどうかをチェック
    fn is_enabled(&self) -> bool;
    
    /// バスマスタリングが有効かどうかをチェック
    fn is_bus_master_enabled(&self) -> bool;
    
    /// 割り込みが無効かどうかをチェック
    fn is_interrupt_disabled(&self) -> bool;
    
    /// ドライバがアタッチされているかどうかをチェック
    fn is_driver_attached(&self) -> bool;
    
    /// ドライバのアタッチ状態を設定
    fn set_driver_attached(&self, attached: bool);
}

/// 基本的なPCIデバイス実装
pub struct GenericPciDevice {
    /// デバイス情報
    pub info: PciDeviceInfo,
    /// コンフィギュレーション空間アクセサ
    pub config_accessor: Box<dyn PciConfigAccess>,
    /// リソース
    pub resources: Vec<PciResource>,
    /// ケイパビリティ
    pub capabilities: Vec<PciCapability>,
    /// デバイスが有効か
    pub enabled: AtomicBool,
    /// バスマスタリングが有効か
    pub bus_master_enabled: AtomicBool,
    /// 割り込みが無効か
    pub interrupt_disabled: AtomicBool,
    /// ドライバがアタッチされているか
    pub driver_attached: AtomicBool,
}

impl GenericPciDevice {
    /// 新しいPCIデバイスを作成
    pub fn new(
        info: PciDeviceInfo,
        config_accessor: Box<dyn PciConfigAccess>,
        resources: Vec<PciResource>,
        capabilities: Vec<PciCapability>,
    ) -> Self {
        // コマンドレジスタを読み取って現在の状態を確認
        let cmd = config_accessor.read_config_word(&info.address, 0x04);
        
        Self {
            info,
            config_accessor,
            resources,
            capabilities,
            enabled: AtomicBool::new((cmd & 0x03) != 0),
            bus_master_enabled: AtomicBool::new((cmd & 0x04) != 0),
            interrupt_disabled: AtomicBool::new((cmd & 0x400) != 0),
            driver_attached: AtomicBool::new(false),
        }
    }
}

impl PciDevice for GenericPciDevice {
    fn get_device_info(&self) -> &PciDeviceInfo {
        &self.info
    }
    
    fn get_address(&self) -> PciAddress {
        self.info.address.clone()
    }
    
    fn read_config_u8(&self, offset: u8) -> u8 {
        self.config_accessor.read_config_byte(&self.info.address, offset)
    }
    
    fn read_config_u16(&self, offset: u8) -> u16 {
        self.config_accessor.read_config_word(&self.info.address, offset)
    }
    
    fn read_config_u32(&self, offset: u8) -> u32 {
        self.config_accessor.read_config_dword(&self.info.address, offset)
    }
    
    fn write_config_u8(&self, offset: u8, value: u8) {
        self.config_accessor.write_config_byte(&self.info.address, offset, value);
    }
    
    fn write_config_u16(&self, offset: u8, value: u16) {
        self.config_accessor.write_config_word(&self.info.address, offset, value);
    }
    
    fn write_config_u32(&self, offset: u8, value: u32) {
        self.config_accessor.write_config_dword(&self.info.address, offset, value);
    }
    
    fn get_resources(&self) -> Vec<PciResource> {
        self.resources.clone()
    }
    
    fn get_capabilities(&self) -> Vec<PciCapability> {
        self.capabilities.clone()
    }
    
    fn enable(&self) -> Result<(), &'static str> {
        // 現在のコマンドレジスタを読み取り
        let mut cmd = self.read_config_u16(0x04);
        
        // メモリ空間アクセスとI/O空間アクセスを有効化
        cmd |= 0x03;
        
        // 更新したコマンドを書き込み
        self.write_config_u16(0x04, cmd);
        
        // 状態を更新
        self.enabled.store(true, Ordering::SeqCst);
        
        Ok(())
    }
    
    fn disable(&self) -> Result<(), &'static str> {
        // 現在のコマンドレジスタを読み取り
        let mut cmd = self.read_config_u16(0x04);
        
        // メモリ空間アクセスとI/O空間アクセスを無効化
        cmd &= !0x03;
        
        // 更新したコマンドを書き込み
        self.write_config_u16(0x04, cmd);
        
        // 状態を更新
        self.enabled.store(false, Ordering::SeqCst);
        
        Ok(())
    }
    
    fn enable_bus_master(&self) -> Result<(), &'static str> {
        // 現在のコマンドレジスタを読み取り
        let mut cmd = self.read_config_u16(0x04);
        
        // バスマスタリングを有効化
        cmd |= 0x04;
        
        // 更新したコマンドを書き込み
        self.write_config_u16(0x04, cmd);
        
        // 状態を更新
        self.bus_master_enabled.store(true, Ordering::SeqCst);
        
        Ok(())
    }
    
    fn disable_bus_master(&self) -> Result<(), &'static str> {
        // 現在のコマンドレジスタを読み取り
        let mut cmd = self.read_config_u16(0x04);
        
        // バスマスタリングを無効化
        cmd &= !0x04;
        
        // 更新したコマンドを書き込み
        self.write_config_u16(0x04, cmd);
        
        // 状態を更新
        self.bus_master_enabled.store(false, Ordering::SeqCst);
        
        Ok(())
    }
    
    fn enable_interrupt(&self) -> Result<(), &'static str> {
        // 現在のコマンドレジスタを読み取り
        let mut cmd = self.read_config_u16(0x04);
        
        // 割り込み無効ビットをクリア
        cmd &= !0x400;
        
        // 更新したコマンドを書き込み
        self.write_config_u16(0x04, cmd);
        
        // 状態を更新
        self.interrupt_disabled.store(false, Ordering::SeqCst);
        
        Ok(())
    }
    
    fn disable_interrupt(&self) -> Result<(), &'static str> {
        // 現在のコマンドレジスタを読み取り
        let mut cmd = self.read_config_u16(0x04);
        
        // 割り込み無効ビットをセット
        cmd |= 0x400;
        
        // 更新したコマンドを書き込み
        self.write_config_u16(0x04, cmd);
        
        // 状態を更新
        self.interrupt_disabled.store(true, Ordering::SeqCst);
        
        Ok(())
    }
    
    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }
    
    fn is_bus_master_enabled(&self) -> bool {
        self.bus_master_enabled.load(Ordering::SeqCst)
    }
    
    fn is_interrupt_disabled(&self) -> bool {
        self.interrupt_disabled.load(Ordering::SeqCst)
    }
    
    fn is_driver_attached(&self) -> bool {
        self.driver_attached.load(Ordering::SeqCst)
    }
    
    fn set_driver_attached(&self, attached: bool) {
        self.driver_attached.store(attached, Ordering::SeqCst);
    }
}

impl fmt::Debug for GenericPciDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenericPciDevice")
            .field("address", &self.info.address)
            .field("vendor_id", &format_args!("0x{:04x}", self.info.vendor_id))
            .field("device_id", &format_args!("0x{:04x}", self.info.device_id))
            .field("class", &format_args!("{:02x}.{:02x}.{:02x}", 
                    self.info.class_code, self.info.subclass_code, self.info.prog_if))
            .field("enabled", &self.enabled)
            .field("bus_master", &self.bus_master_enabled)
            .field("int_disabled", &self.interrupt_disabled)
            .field("resources", &self.resources.len())
            .field("capabilities", &self.capabilities.len())
            .finish()
    }
} 