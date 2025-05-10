// PCIドライバーモジュール
// AetherOS用高性能PCIドライバー実装
// 作成者: AetherOSチーム

//! # PCIドライバーモジュール
//! 
//! このモジュールは、PCIデバイスの検出、列挙、および管理を提供します。
//! 高性能かつ安全なインターフェースを通じて、AetherOSカーネルにPCIデバイスへのアクセスを提供します。

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, RwLock};

use crate::arch::io::{inl, inw, outl, outw};
use crate::mm::PhysAddr;
use crate::sync::OnceCell;

/// PCI設定空間へのアクセス方法
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciAccessMethod {
    /// I/Oポート経由でのアクセス（0xCF8/0xCFCポート）
    IoPort,
    /// メモリマップドI/O経由でのアクセス
    Mmio,
    /// Enhanced Configuration Access Mechanism (ECAM)
    Ecam,
}

/// PCIバス上のデバイスを一意に識別するアドレス
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PciAddress {
    /// セグメント番号（PCIeで使用）
    pub segment: u16,
    /// バス番号
    pub bus: u8,
    /// デバイス番号
    pub device: u8,
    /// 機能番号
    pub function: u8,
}

impl PciAddress {
    /// 新しいPCIアドレスを作成
    pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        // デバイス番号は0-31の範囲内
        debug_assert!(device < 32);
        // 機能番号は0-7の範囲内
        debug_assert!(function < 8);
        
        Self {
            segment,
            bus,
            device,
            function,
        }
    }
    
    /// レガシーPCIアドレスを作成（セグメント0）
    pub const fn legacy(bus: u8, device: u8, function: u8) -> Self {
        Self::new(0, bus, device, function)
    }
    
    /// PCI設定アドレスレジスタの値を生成
    pub fn config_address(&self) -> u32 {
        let bus = self.bus as u32;
        let device = self.device as u32;
        let function = self.function as u32;
        
        // PCI CONFIG_ADDRESS レジスタのフォーマット:
        // |31|30-24|23-16|15-11|10-8|7-2|1-0|
        // |EN|Reserv|Bus  |Dev  |Func|Reg|0  |
        
        0x8000_0000 | (bus << 16) | (device << 11) | (function << 8)
    }
}

impl fmt::Display for PciAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f, 
            "{:04x}:{:02x}:{:02x}.{:x}",
            self.segment,
            self.bus,
            self.device,
            self.function
        )
    }
}

/// PCIデバイスの標準ヘッダ情報
#[derive(Debug, Clone)]
pub struct PciDeviceInfo {
    /// デバイスのPCIアドレス
    pub address: PciAddress,
    /// ベンダーID
    pub vendor_id: u16,
    /// デバイスID
    pub device_id: u16,
    /// コマンドレジスタ
    pub command: u16,
    /// ステータスレジスタ
    pub status: u16,
    /// リビジョンID
    pub revision_id: u8,
    /// プログラムインターフェース
    pub prog_if: u8,
    /// サブクラスコード
    pub subclass: u8,
    /// クラスコード
    pub class_code: u8,
    /// キャッシュラインサイズ
    pub cache_line_size: u8,
    /// レイテンシタイマー
    pub latency_timer: u8,
    /// ヘッダタイプ
    pub header_type: u8,
    /// BIST (Built-In Self Test)
    pub bist: u8,
    /// サブシステムベンダーID
    pub subsystem_vendor_id: u16,
    /// サブシステムID
    pub subsystem_id: u16,
    /// 割り込みライン
    pub interrupt_line: u8,
    /// 割り込みピン
    pub interrupt_pin: u8,
}

/// PCIデバイスクラス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciClass {
    Unclassified(u8),
    MassStorage(u8),
    NetworkController(u8),
    DisplayController(u8),
    MultimediaDevice(u8),
    MemoryController(u8),
    BridgeDevice(u8),
    SimpleCommunicationController(u8),
    BaseSystemPeripheral(u8),
    InputDevice(u8),
    DockingStation(u8),
    Processor(u8),
    SerialBusController(u8),
    WirelessController(u8),
    IntelligentController(u8),
    SatelliteCommunicationController(u8),
    EncryptionController(u8),
    SignalProcessingController(u8),
    ProcessingAccelerator(u8),
    NonEssentialInstrumentation(u8),
    Reserved(u8, u8),
    Other(u8, u8),
}

impl PciClass {
    /// クラスコードとサブクラスからPciClassを作成
    pub fn from_class_subclass(class: u8, subclass: u8) -> Self {
        match class {
            0x00 => Self::Unclassified(subclass),
            0x01 => Self::MassStorage(subclass),
            0x02 => Self::NetworkController(subclass),
            0x03 => Self::DisplayController(subclass),
            0x04 => Self::MultimediaDevice(subclass),
            0x05 => Self::MemoryController(subclass),
            0x06 => Self::BridgeDevice(subclass),
            0x07 => Self::SimpleCommunicationController(subclass),
            0x08 => Self::BaseSystemPeripheral(subclass),
            0x09 => Self::InputDevice(subclass),
            0x0A => Self::DockingStation(subclass),
            0x0B => Self::Processor(subclass),
            0x0C => Self::SerialBusController(subclass),
            0x0D => Self::WirelessController(subclass),
            0x0E => Self::IntelligentController(subclass),
            0x0F => Self::SatelliteCommunicationController(subclass),
            0x10 => Self::EncryptionController(subclass),
            0x11 => Self::SignalProcessingController(subclass),
            0x12 => Self::ProcessingAccelerator(subclass),
            0x13 => Self::NonEssentialInstrumentation(subclass),
            0x14..=0xFE => Self::Reserved(class, subclass),
            0xFF => Self::Other(class, subclass),
        }
    }
}

/// PCI Base Address Register (BAR)の情報
#[derive(Debug, Clone)]
pub struct PciBar {
    /// BARのインデックス (0-5)
    pub index: usize,
    /// BARの値
    pub value: u32,
    /// BARのサイズ（バイト）
    pub size: u64,
    /// メモリマップドかI/Oマップドか
    pub is_memory: bool,
    /// メモリマップドの場合、プリフェッチャブルかどうか
    pub prefetchable: bool,
    /// メモリタイプ（メモリマップドの場合）
    pub mem_type: PciMemoryType,
    /// 64ビットアドレス空間を使用するか（メモリマップドの場合）
    pub is_64bit: bool,
    /// 物理アドレス
    pub address: PhysAddr,
}

/// PCIメモリタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciMemoryType {
    /// 32ビットアドレス空間
    Bit32,
    /// 64ビットアドレス空間
    Bit64,
    /// 1MBより下の予約領域
    Below1MB,
}

/// PCI設定空間へのアクセスを提供するトレイト
pub trait PciAccess: Send + Sync {
    /// 8ビット値を読み取る
    fn read8(&self, addr: PciAddress, offset: u8) -> u8;
    
    /// 16ビット値を読み取る
    fn read16(&self, addr: PciAddress, offset: u8) -> u16;
    
    /// 32ビット値を読み取る
    fn read32(&self, addr: PciAddress, offset: u8) -> u32;
    
    /// 8ビット値を書き込む
    fn write8(&self, addr: PciAddress, offset: u8, value: u8);
    
    /// 16ビット値を書き込む
    fn write16(&self, addr: PciAddress, offset: u8, value: u16);
    
    /// 32ビット値を書き込む
    fn write32(&self, addr: PciAddress, offset: u8, value: u32);
}

/// I/Oポート経由でPCI設定空間にアクセスする実装
pub struct IoPortPciAccess;

impl PciAccess for IoPortPciAccess {
    fn read8(&self, addr: PciAddress, offset: u8) -> u8 {
        // CONFIG_ADDRESS を設定
        let addr_value = addr.config_address() | (offset as u32 & 0xFC);
        unsafe {
            outl(0xCF8, addr_value);
            // offset & 3 はバイト内のオフセット
            ((inl(0xCFC) >> ((offset & 3) * 8)) & 0xFF) as u8
        }
    }
    
    fn read16(&self, addr: PciAddress, offset: u8) -> u16 {
        // アライメントチェック
        debug_assert!(offset & 1 == 0, "16ビット読み取りは2バイトアライメントが必要");
        
        let addr_value = addr.config_address() | (offset as u32 & 0xFC);
        unsafe {
            outl(0xCF8, addr_value);
            // offset & 2 は2バイト内のオフセット
            ((inl(0xCFC) >> ((offset & 2) * 8)) & 0xFFFF) as u16
        }
    }
    
    fn read32(&self, addr: PciAddress, offset: u8) -> u32 {
        // アライメントチェック
        debug_assert!(offset & 3 == 0, "32ビット読み取りは4バイトアライメントが必要");
        
        let addr_value = addr.config_address() | (offset as u32 & 0xFC);
        unsafe {
            outl(0xCF8, addr_value);
            inl(0xCFC)
        }
    }
    
    fn write8(&self, addr: PciAddress, offset: u8, value: u8) {
        // このI/O書き込みは複雑...読み取り-修正-書き込みが必要
        let addr_value = addr.config_address() | (offset as u32 & 0xFC);
        let shift = (offset & 3) * 8;
        let mask = !(0xFFu32 << shift);
        
        unsafe {
            outl(0xCF8, addr_value);
            let old = inl(0xCFC);
            let new = (old & mask) | ((value as u32) << shift);
            outl(0xCF8, addr_value);
            outl(0xCFC, new);
        }
    }
    
    fn write16(&self, addr: PciAddress, offset: u8, value: u16) {
        // アライメントチェック
        debug_assert!(offset & 1 == 0, "16ビット書き込みは2バイトアライメントが必要");
        
        let addr_value = addr.config_address() | (offset as u32 & 0xFC);
        let shift = (offset & 2) * 8;
        let mask = !(0xFFFFu32 << shift);
        
        unsafe {
            outl(0xCF8, addr_value);
            let old = inl(0xCFC);
            let new = (old & mask) | ((value as u32) << shift);
            outl(0xCF8, addr_value);
            outl(0xCFC, new);
        }
    }
    
    fn write32(&self, addr: PciAddress, offset: u8, value: u32) {
        // アライメントチェック
        debug_assert!(offset & 3 == 0, "32ビット書き込みは4バイトアライメントが必要");
        
        let addr_value = addr.config_address() | (offset as u32 & 0xFC);
        unsafe {
            outl(0xCF8, addr_value);
            outl(0xCFC, value);
        }
    }
}

/// PCIドライバーサブシステム
pub struct PciSubsystem {
    /// 使用するアクセス方法
    access_method: PciAccessMethod,
    /// 現在有効なPCIアクセッサ
    accessor: Arc<dyn PciAccess>,
    /// 検出されたデバイスのリスト
    devices: RwLock<BTreeMap<PciAddress, Arc<PciDevice>>>,
    /// 初期化完了フラグ
    initialized: AtomicBool,
}

impl PciSubsystem {
    /// PCIサブシステムのグローバルインスタンス
    pub static INSTANCE: OnceCell<PciSubsystem> = OnceCell::new();
    
    /// 新しいPCIサブシステムを作成
    pub fn new() -> Self {
        // デフォルトでI/Oポートアクセスを使用
        let access_method = PciAccessMethod::IoPort;
        let accessor: Arc<dyn PciAccess> = Arc::new(IoPortPciAccess);
        
        Self {
            access_method,
            accessor,
            devices: RwLock::new(BTreeMap::new()),
            initialized: AtomicBool::new(false),
        }
    }
    
    /// PCIサブシステムを初期化
    pub fn initialize(&self) -> Result<(), &'static str> {
        if self.initialized.load(Ordering::SeqCst) {
            return Ok(());
        }
        
        // PCIデバイスの検出
        self.enumerate_devices()?;
        
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }
    
    /// すべてのPCIデバイスを列挙
    fn enumerate_devices(&self) -> Result<(), &'static str> {
        let mut devices = self.devices.write();
        
        // すべてのバス、デバイス、機能をスキャン
        for bus in 0..256 {
            for device in 0..32 {
                for function in 0..8 {
                    let addr = PciAddress::legacy(bus as u8, device as u8, function as u8);
                    
                    // ベンダーIDを確認（0xFFFFはデバイスが存在しないことを示す）
                    let vendor_id = self.accessor.read16(addr, 0x00);
                    if vendor_id == 0xFFFF {
                        // 機能0が存在しない場合、このデバイスの他の機能もスキップ
                        if function == 0 {
                            break;
                        }
                        continue;
                    }
                    
                    // デバイス情報を読み取る
                    let device_info = self.read_device_info(addr);
                    
                    // PCIデバイスオブジェクトを作成
                    let pci_device = Arc::new(PciDevice::new(device_info, Arc::clone(&self.accessor)));
                    
                    // デバイスをマップに追加
                    devices.insert(addr, pci_device);
                    
                    // マルチファンクションデバイスかどうかを確認
                    if function == 0 {
                        let header_type = self.accessor.read8(addr, 0x0E);
                        if header_type & 0x80 == 0 {
                            // シングルファンクションデバイス
                            break;
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// デバイス情報を読み取る
    fn read_device_info(&self, addr: PciAddress) -> PciDeviceInfo {
        let accessor = &self.accessor;
        
        PciDeviceInfo {
            address: addr,
            vendor_id: accessor.read16(addr, 0x00),
            device_id: accessor.read16(addr, 0x02),
            command: accessor.read16(addr, 0x04),
            status: accessor.read16(addr, 0x06),
            revision_id: accessor.read8(addr, 0x08),
            prog_if: accessor.read8(addr, 0x09),
            subclass: accessor.read8(addr, 0x0A),
            class_code: accessor.read8(addr, 0x0B),
            cache_line_size: accessor.read8(addr, 0x0C),
            latency_timer: accessor.read8(addr, 0x0D),
            header_type: accessor.read8(addr, 0x0E),
            bist: accessor.read8(addr, 0x0F),
            subsystem_vendor_id: accessor.read16(addr, 0x2C),
            subsystem_id: accessor.read16(addr, 0x2E),
            interrupt_line: accessor.read8(addr, 0x3C),
            interrupt_pin: accessor.read8(addr, 0x3D),
        }
    }
    
    /// すべてのPCIデバイスを取得
    pub fn get_devices(&self) -> Vec<Arc<PciDevice>> {
        let devices = self.devices.read();
        devices.values().cloned().collect()
    }
    
    /// 特定のPCIアドレスのデバイスを取得
    pub fn get_device(&self, addr: PciAddress) -> Option<Arc<PciDevice>> {
        let devices = self.devices.read();
        devices.get(&addr).cloned()
    }
    
    /// 特定のベンダーおよびデバイスIDを持つすべてのデバイスを検索
    pub fn find_devices(&self, vendor_id: u16, device_id: u16) -> Vec<Arc<PciDevice>> {
        let devices = self.devices.read();
        devices
            .values()
            .filter(|dev| {
                dev.info.vendor_id == vendor_id && dev.info.device_id == device_id
            })
            .cloned()
            .collect()
    }
    
    /// 特定のクラスおよびサブクラスを持つすべてのデバイスを検索
    pub fn find_devices_by_class(&self, class: u8, subclass: u8) -> Vec<Arc<PciDevice>> {
        let devices = self.devices.read();
        devices
            .values()
            .filter(|dev| {
                dev.info.class_code == class && dev.info.subclass == subclass
            })
            .cloned()
            .collect()
    }
}

/// PCIデバイスの表現
pub struct PciDevice {
    /// デバイス情報
    pub info: PciDeviceInfo,
    /// PCI設定空間へのアクセサ
    accessor: Arc<dyn PciAccess>,
    /// デバイスのBARs
    bars: Mutex<[Option<PciBar>; 6]>,
}

impl PciDevice {
    /// 新しいPCIデバイスを作成
    pub fn new(info: PciDeviceInfo, accessor: Arc<dyn PciAccess>) -> Self {
        Self {
            info,
            accessor,
            bars: Mutex::new([None, None, None, None, None, None]),
        }
    }
    
    /// デバイスのPCIクラス情報を取得
    pub fn class(&self) -> PciClass {
        PciClass::from_class_subclass(self.info.class_code, self.info.subclass)
    }
    
    /// デバイスのBARを読み取る
    pub fn read_bar(&self, index: usize) -> Option<PciBar> {
        if index >= 6 {
            return None;
        }
        
        let mut bars = self.bars.lock();
        
        // 既に読み取り済みの場合
        if let Some(bar) = &bars[index] {
            return Some(bar.clone());
        }
        
        // BARの読み取り処理
        let offset = 0x10 + (index * 4) as u8;
        let bar_value = self.accessor.read32(self.info.address, offset);
        
        // BARが未使用の場合
        if bar_value == 0 {
            return None;
        }
        
        // メモリタイプかI/Oタイプか判定
        let is_memory = (bar_value & 0x1) == 0;
        
        if is_memory {
            // メモリマップドBAR
            let mem_type = match (bar_value >> 1) & 0x3 {
                0 => PciMemoryType::Bit32,
                1 => PciMemoryType::Below1MB,
                2 => PciMemoryType::Bit64,
                _ => return None, // 予約済み
            };
            
            let prefetchable = (bar_value & 0x8) != 0;
            let is_64bit = mem_type == PciMemoryType::Bit64;
            
            // BARのサイズを決定するために、一時的にすべて1に設定
            self.accessor.write32(self.info.address, offset, 0xFFFFFFFF);
            let size_mask = self.accessor.read32(self.info.address, offset);
            // 元の値に戻す
            self.accessor.write32(self.info.address, offset, bar_value);
            
            // アドレスマスクを計算（下位ビットをクリア）
            let base_addr = bar_value & !0xF;
            
            // 64ビットBARの場合、上位32ビットも読み取る
            let mut addr64 = base_addr as u64;
            if is_64bit && index < 5 {
                let upper = self.accessor.read32(self.info.address, offset + 4);
                addr64 |= (upper as u64) << 32;
                
                // 上位BARも使用済みとマーク
                bars[index + 1] = Some(PciBar {
                    index: index + 1,
                    value: upper,
                    size: 0, // 上位BARは独自のサイズを持たない
                    is_memory: true,
                    prefetchable: false,
                    mem_type: PciMemoryType::Bit64,
                    is_64bit: true,
                    address: PhysAddr::new(0), // ダミー値
                });
            }
            
            // サイズを計算（ビット操作）
            let size = if size_mask == 0 {
                0
            } else {
                // 最下位ビットから連続する0の数を数える
                let mut size_bits = !size_mask & 0xFFFFFFF0;
                size_bits |= size_bits >> 1;
                size_bits |= size_bits >> 2;
                size_bits |= size_bits >> 4;
                size_bits |= size_bits >> 8;
                size_bits |= size_bits >> 16;
                (size_bits + 1) as u64
            };
            
            let bar = PciBar {
                index,
                value: bar_value,
                size,
                is_memory,
                prefetchable,
                mem_type,
                is_64bit,
                address: PhysAddr::new(addr64),
            };
            
            bars[index] = Some(bar.clone());
            Some(bar)
        } else {
            // I/OマップドBAR
            // アドレスマスクを計算（下位ビットをクリア）
            let base_addr = bar_value & !0x3;
            
            // BARのサイズを決定するために、一時的にすべて1に設定
            self.accessor.write32(self.info.address, offset, 0xFFFFFFFF);
            let size_mask = self.accessor.read32(self.info.address, offset);
            // 元の値に戻す
            self.accessor.write32(self.info.address, offset, bar_value);
            
            // サイズを計算（ビット操作）
            let size = if size_mask == 0 {
                0
            } else {
                // 最下位ビットから連続する0の数を数える
                let mut size_bits = !size_mask & 0xFFFFFFFC;
                size_bits |= size_bits >> 1;
                size_bits |= size_bits >> 2;
                size_bits |= size_bits >> 4;
                size_bits |= size_bits >> 8;
                size_bits |= size_bits >> 16;
                (size_bits + 1) as u64
            };
            
            let bar = PciBar {
                index,
                value: bar_value,
                size,
                is_memory: false,
                prefetchable: false,
                mem_type: PciMemoryType::Bit32, // I/OはBit32として扱う
                is_64bit: false,
                address: PhysAddr::new(base_addr as u64),
            };
            
            bars[index] = Some(bar.clone());
            Some(bar)
        }
    }
    
    /// すべてのBARを読み取る
    pub fn read_all_bars(&self) -> [Option<PciBar>; 6] {
        for i in 0..6 {
            self.read_bar(i);
        }
        
        *self.bars.lock()
    }
    
    /// 8ビット値を読み取る
    pub fn read8(&self, offset: u8) -> u8 {
        self.accessor.read8(self.info.address, offset)
    }
    
    /// 16ビット値を読み取る
    pub fn read16(&self, offset: u8) -> u16 {
        self.accessor.read16(self.info.address, offset)
    }
    
    /// 32ビット値を読み取る
    pub fn read32(&self, offset: u8) -> u32 {
        self.accessor.read32(self.info.address, offset)
    }
    
    /// 8ビット値を書き込む
    pub fn write8(&self, offset: u8, value: u8) {
        self.accessor.write8(self.info.address, offset, value)
    }
    
    /// 16ビット値を書き込む
    pub fn write16(&self, offset: u8, value: u16) {
        self.accessor.write16(self.info.address, offset, value)
    }
    
    /// 32ビット値を書き込む
    pub fn write32(&self, offset: u8, value: u32) {
        self.accessor.write32(self.info.address, offset, value)
    }
    
    /// デバイスのバスマスタリングを有効化
    pub fn enable_bus_mastering(&self) {
        let command = self.read16(0x04);
        self.write16(0x04, command | 0x4);
    }
    
    /// デバイスのメモリ空間アクセスを有効化
    pub fn enable_memory_space(&self) {
        let command = self.read16(0x04);
        self.write16(0x04, command | 0x2);
    }
    
    /// デバイスのI/O空間アクセスを有効化
    pub fn enable_io_space(&self) {
        let command = self.read16(0x04);
        self.write16(0x04, command | 0x1);
    }
}

impl fmt::Debug for PciDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PciDevice")
            .field("address", &self.info.address)
            .field("vendor_id", &format_args!("0x{:04x}", self.info.vendor_id))
            .field("device_id", &format_args!("0x{:04x}", self.info.device_id))
            .field("class", &self.class())
            .field("revision", &self.info.revision_id)
            .finish()
    }
}

/// PCIサブシステムの初期化
pub fn init() -> Result<(), &'static str> {
    let subsystem = PciSubsystem::new();
    subsystem.initialize()?;
    
    // グローバルインスタンスを設定
    PciSubsystem::INSTANCE.set(subsystem)
        .map_err(|_| "PCIサブシステムの初期化に失敗しました")?;
    
    Ok(())
}

/// PCI関連の診断情報を出力
pub fn print_diagnostic_info() {
    if let Some(pci) = PciSubsystem::INSTANCE.get() {
        let devices = pci.get_devices();
        
        log::info!("PCIデバイス一覧 ({} 台見つかりました):", devices.len());
        
        for device in devices {
            log::info!(
                "  {:04x}:{:02x}:{:02x}.{:x} - ベンダー: 0x{:04x}, デバイス: 0x{:04x}, クラス: {:?}",
                device.info.address.segment,
                device.info.address.bus,
                device.info.address.device,
                device.info.address.function,
                device.info.vendor_id,
                device.info.device_id,
                device.class(),
            );
        }
    } else {
        log::warn!("PCIサブシステムが初期化されていません");
    }
} 