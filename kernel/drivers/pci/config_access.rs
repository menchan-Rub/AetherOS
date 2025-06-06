// PCIコンフィギュレーション空間アクセスモジュール
//
// PCIデバイスのコンフィギュレーション空間にアクセスするための統一インターフェースを提供します。
// I/OポートベースとMMIOベースの両方のアクセス方式をサポートします。

use crate::core::arch::{inb, inl, inw, outb, outl, outw};
use crate::core::memory::physaddr::PhysAddr;
use crate::core::memory::virtaddr::VirtAddr;
use crate::core::memory::vmem::VMemMapper;
use crate::drivers::pci::address::PciAddress;
use core::ptr::{read_volatile, write_volatile};
use log::{debug, warn};
use acpi;

/// PCIコンフィギュレーション空間アクセス方法の列挙型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciAccessMethod {
    /// I/Oポートベースのアクセス方法（レガシーPCI）
    IoPort,
    /// メモリマップドI/Oベースのアクセス方法（PCIe）
    Mmio,
    /// 両方のアクセス方法を使用（環境に応じた適切な方法を自動選択）
    Mixed,
}

/// PCIコンフィギュレーション空間へのアクセスを抽象化するトレイト
pub trait PciConfigAccess: Send + Sync {
    /// 8ビット値を読み取る
    fn read_config_byte(&self, address: &PciAddress, offset: u8) -> u8;
    
    /// 16ビット値を読み取る
    fn read_config_word(&self, address: &PciAddress, offset: u8) -> u16;
    
    /// 32ビット値を読み取る
    fn read_config_dword(&self, address: &PciAddress, offset: u8) -> u32;
    
    /// 8ビット値を書き込む
    fn write_config_byte(&self, address: &PciAddress, offset: u8, value: u8);
    
    /// 16ビット値を書き込む
    fn write_config_word(&self, address: &PciAddress, offset: u8, value: u16);
    
    /// 32ビット値を書き込む
    fn write_config_dword(&self, address: &PciAddress, offset: u8, value: u32);
    
    /// アクセス方法を取得
    fn access_method(&self) -> PciAccessMethod;
}

/// I/Oポートベースのレガシーなコンフィギュレーション空間アクセス
pub struct IoPortPciAccess;

impl IoPortPciAccess {
    /// 新しいインスタンスを作成
    pub fn new() -> Self {
        Self {}
    }
    
    /// PCIコンフィギュレーション空間アドレスを計算してI/Oポートに出力
    fn set_address(&self, address: &PciAddress, offset: u8) -> u32 {
        // PCIアドレスを作成
        // フォーマット: 0x80000000 | (bus << 16) | (device << 11) | (function << 8) | (offset & 0xFC)
        let addr = 0x80000000
            | ((address.bus as u32) << 16)
            | ((address.device as u32) << 11)
            | ((address.function as u32) << 8)
            | ((offset as u32) & 0xFC);
        
        // アドレスレジスタにアドレスを書き込む
        unsafe { outl(0xCF8, addr) };
        
        addr
    }
}

impl PciConfigAccess for IoPortPciAccess {
    fn read_config_byte(&self, address: &PciAddress, offset: u8) -> u8 {
        // セグメント0のみサポート
        if address.segment != 0 {
            warn!("I/Oポートアクセスはセグメント0のみサポートします");
            return 0;
        }
        
        self.set_address(address, offset);
        
        // バイト位置を計算
        let port = 0xCFC + (offset & 0x3) as u16;
        
        // I/Oポートから読み取り
        unsafe { inb(port) }
    }
    
    fn read_config_word(&self, address: &PciAddress, offset: u8) -> u16 {
        // セグメント0のみサポート
        if address.segment != 0 {
            warn!("I/Oポートアクセスはセグメント0のみサポートします");
            return 0;
        }
        
        // 2バイトアラインメント
        if offset & 0x1 != 0 {
            warn!("アラインメントされていないPCIワード読み取り: {:?}, offset: {}", address, offset);
            return ((self.read_config_byte(address, offset) as u16) |
                   ((self.read_config_byte(address, offset + 1) as u16) << 8));
        }
        
        self.set_address(address, offset);
        
        // ワード位置を計算
        let port = 0xCFC + (offset & 0x2) as u16;
        
        // I/Oポートから読み取り
        unsafe { inw(port) }
    }
    
    fn read_config_dword(&self, address: &PciAddress, offset: u8) -> u32 {
        // セグメント0のみサポート
        if address.segment != 0 {
            warn!("I/Oポートアクセスはセグメント0のみサポートします");
            return 0;
        }
        
        // 4バイトアラインメント
        if offset & 0x3 != 0 {
            warn!("アラインメントされていないPCIダブルワード読み取り: {:?}, offset: {}", address, offset);
            
            // 個別のバイト読み取りで代用
            let mut value: u32 = 0;
            for i in 0..4 {
                value |= (self.read_config_byte(address, offset + i) as u32) << (i * 8);
            }
            return value;
        }
        
        self.set_address(address, offset);
        
        // I/Oポートから読み取り
        unsafe { inl(0xCFC) }
    }
    
    fn write_config_byte(&self, address: &PciAddress, offset: u8, value: u8) {
        // セグメント0のみサポート
        if address.segment != 0 {
            warn!("I/Oポートアクセスはセグメント0のみサポートします");
            return;
        }
        
        self.set_address(address, offset);
        
        // バイト位置を計算
        let port = 0xCFC + (offset & 0x3) as u16;
        
        // I/Oポートに書き込み
        unsafe { outb(port, value) };
    }
    
    fn write_config_word(&self, address: &PciAddress, offset: u8, value: u16) {
        // セグメント0のみサポート
        if address.segment != 0 {
            warn!("I/Oポートアクセスはセグメント0のみサポートします");
            return;
        }
        
        // 2バイトアラインメント
        if offset & 0x1 != 0 {
            warn!("アラインメントされていないPCIワード書き込み: {:?}, offset: {}", address, offset);
            self.write_config_byte(address, offset, value as u8);
            self.write_config_byte(address, offset + 1, (value >> 8) as u8);
            return;
        }
        
        self.set_address(address, offset);
        
        // ワード位置を計算
        let port = 0xCFC + (offset & 0x2) as u16;
        
        // I/Oポートに書き込み
        unsafe { outw(port, value) };
    }
    
    fn write_config_dword(&self, address: &PciAddress, offset: u8, value: u32) {
        // セグメント0のみサポート
        if address.segment != 0 {
            warn!("I/Oポートアクセスはセグメント0のみサポートします");
            return;
        }
        
        // 4バイトアラインメント
        if offset & 0x3 != 0 {
            warn!("アラインメントされていないPCIダブルワード書き込み: {:?}, offset: {}", address, offset);
            
            // 個別のバイト書き込みで代用
            for i in 0..4 {
                self.write_config_byte(address, offset + i, ((value >> (i * 8)) & 0xFF) as u8);
            }
            return;
        }
        
        self.set_address(address, offset);
        
        // I/Oポートに書き込み
        unsafe { outl(0xCFC, value) };
    }
    
    fn access_method(&self) -> PciAccessMethod {
        PciAccessMethod::IoPort
    }
}

/// メモリマップドI/OベースのPCIe拡張コンフィギュレーション空間アクセス
pub struct MmioPciAccess {
    /// PCIコンフィギュレーション空間の物理ベースアドレス
    physical_base: PhysAddr,
    /// PCIコンフィギュレーション空間の仮想ベースアドレス
    virtual_base: VirtAddr,
    /// メモリマッパー
    vmem_mapper: VMemMapper,
}

impl MmioPciAccess {
    /// 新しいインスタンスを作成
    ///
    /// # 引数
    ///
    /// * `physical_base` - PCIコンフィギュレーション空間の物理ベースアドレス
    /// * `vmem_mapper` - メモリマッパー
    ///
    /// # 戻り値
    ///
    /// 新しいインスタンス、またはマッピングに失敗した場合はNone
    pub fn new(physical_base: PhysAddr, vmem_mapper: VMemMapper) -> Option<Self> {
        // PCIe拡張コンフィギュレーション空間のサイズを計算
        // 256 PCI busses per segment, 32 devices per bus, 8 functions per device, 4096 bytes per function
        let space_size = 256 * 32 * 8 * 4096;
        
        // 物理アドレスを仮想アドレスにマップ
        let virtual_base = vmem_mapper.map_physical(physical_base, space_size)?;
        
        debug!("PCIeコンフィギュレーション空間をマップしました: 物理=0x{:x}, 仮想=0x{:x}, サイズ={}MB",
               physical_base.value(), virtual_base.value(), space_size / (1024 * 1024));
        
        Some(Self {
            physical_base,
            virtual_base,
            vmem_mapper,
        })
    }
    
    /// PCIeコンフィギュレーション空間のオフセットを計算
    fn calculate_offset(&self, address: &PciAddress, offset: u8) -> usize {
        // PCIeコンフィギュレーション空間アドレス形式:
        // [27:24] Extended Register Number (for PCIe registers beyond the traditional 256-byte space)
        // [23:16] Bus Number
        // [15:11] Device Number
        // [10:8]  Function Number
        // [7:0]   Register Offset
        
        ((address.segment as usize) << 20) | 
        ((address.bus as usize) << 12) | 
        ((address.device as usize) << 7) | 
        ((address.function as usize) << 2) | 
        ((offset as usize) & 0xFC)
    }
}

impl PciConfigAccess for MmioPciAccess {
    fn read_config_byte(&self, address: &PciAddress, offset: u8) -> u8 {
        let addr_offset = self.calculate_offset(address, offset);
        let addr = self.virtual_base.value() + addr_offset;
        
        // バイト位置の計算（エンディアン考慮）
        let byte_offset = (offset & 0x3) as usize;
        
        // 32ビット値を読み取り、適切なバイトを抽出
        unsafe {
            let dword = read_volatile((addr as *const u32));
            ((dword >> (byte_offset * 8)) & 0xFF) as u8
        }
    }
    
    fn read_config_word(&self, address: &PciAddress, offset: u8) -> u16 {
        // 2バイトアラインメントチェック
        if offset & 0x1 != 0 {
            warn!("アラインメントされていないPCIワード読み取り: {:?}, offset: {}", address, offset);
            return ((self.read_config_byte(address, offset) as u16) |
                   ((self.read_config_byte(address, offset + 1) as u16) << 8));
        }
        
        let addr_offset = self.calculate_offset(address, offset);
        let addr = self.virtual_base.value() + addr_offset;
        
        // ワード位置の計算（エンディアン考慮）
        let word_offset = ((offset & 0x2) >> 1) as usize;
        
        // 32ビット値を読み取り、適切なワードを抽出
        unsafe {
            let dword = read_volatile((addr as *const u32));
            ((dword >> (word_offset * 16)) & 0xFFFF) as u16
        }
    }
    
    fn read_config_dword(&self, address: &PciAddress, offset: u8) -> u32 {
        // 4バイトアラインメントチェック
        if offset & 0x3 != 0 {
            warn!("アラインメントされていないPCIダブルワード読み取り: {:?}, offset: {}", address, offset);
            
            // 個別のバイト読み取りで代用
            let mut value: u32 = 0;
            for i in 0..4 {
                value |= (self.read_config_byte(address, offset + i) as u32) << (i * 8);
            }
            return value;
        }
        
        let addr_offset = self.calculate_offset(address, offset);
        let addr = self.virtual_base.value() + addr_offset;
        
        // 32ビット値をそのまま読み取り
        unsafe { read_volatile((addr as *const u32)) }
    }
    
    fn write_config_byte(&self, address: &PciAddress, offset: u8, value: u8) {
        let addr_offset = self.calculate_offset(address, offset);
        let addr = self.virtual_base.value() + addr_offset;
        
        // バイト位置の計算（エンディアン考慮）
        let byte_offset = (offset & 0x3) as usize;
        let byte_shift = byte_offset * 8;
        
        // 現在の32ビット値を読み取り
        let mut dword = unsafe { read_volatile((addr as *const u32)) };
        
        // 適切なバイトを更新
        let mask = !(0xFF << byte_shift);
        dword = (dword & mask) | ((value as u32) << byte_shift);
        
        // 更新した値を書き戻し
        unsafe { write_volatile((addr as *mut u32), dword) };
    }
    
    fn write_config_word(&self, address: &PciAddress, offset: u8, value: u16) {
        // 2バイトアラインメントチェック
        if offset & 0x1 != 0 {
            warn!("アラインメントされていないPCIワード書き込み: {:?}, offset: {}", address, offset);
            self.write_config_byte(address, offset, value as u8);
            self.write_config_byte(address, offset + 1, (value >> 8) as u8);
            return;
        }
        
        let addr_offset = self.calculate_offset(address, offset);
        let addr = self.virtual_base.value() + addr_offset;
        
        // ワード位置の計算（エンディアン考慮）
        let word_offset = ((offset & 0x2) >> 1) as usize;
        let word_shift = word_offset * 16;
        
        // 現在の32ビット値を読み取り
        let mut dword = unsafe { read_volatile((addr as *const u32)) };
        
        // 適切なワードを更新
        let mask = !(0xFFFF << word_shift);
        dword = (dword & mask) | ((value as u32) << word_shift);
        
        // 更新した値を書き戻し
        unsafe { write_volatile((addr as *mut u32), dword) };
    }
    
    fn write_config_dword(&self, address: &PciAddress, offset: u8, value: u32) {
        // 4バイトアラインメントチェック
        if offset & 0x3 != 0 {
            warn!("アラインメントされていないPCIダブルワード書き込み: {:?}, offset: {}", address, offset);
            
            // 個別のバイト書き込みで代用
            for i in 0..4 {
                self.write_config_byte(address, offset + i, ((value >> (i * 8)) & 0xFF) as u8);
            }
            return;
        }
        
        let addr_offset = self.calculate_offset(address, offset);
        let addr = self.virtual_base.value() + addr_offset;
        
        // 32ビット値をそのまま書き込み
        unsafe { write_volatile((addr as *mut u32), value) };
    }
    
    fn access_method(&self) -> PciAccessMethod {
        PciAccessMethod::Mmio
    }
}

/// 混合アクセス方式を提供するアクセサ
///
/// MMIOが使用可能な場合はMMIO、それ以外はI/Oポートを使用。
/// セグメント0以外のアクセスにはMMIOのみを使用。
pub struct MixedPciAccess {
    /// MMIOアクセサ
    mmio: Option<MmioPciAccess>,
    /// I/Oポートアクセサ
    io_port: IoPortPciAccess,
}

impl MixedPciAccess {
    /// 新しいインスタンスを作成
    ///
    /// # 引数
    ///
    /// * `mmio_physical_base` - MMIOのベース物理アドレス（あれば）
    /// * `vmem_mapper` - メモリマッパー（あれば）
    ///
    /// # 戻り値
    ///
    /// 新しいインスタンス
    pub fn new(mmio_physical_base: Option<PhysAddr>, vmem_mapper: Option<VMemMapper>) -> Self {
        // MMIOアクセサを作成（可能であれば）
        let mmio = match (mmio_physical_base, vmem_mapper) {
            (Some(base), Some(mapper)) => MmioPciAccess::new(base, mapper),
            _ => None,
        };
        
        // I/Oポートアクセサを作成
        let io_port = IoPortPciAccess::new();
        
        Self { mmio, io_port }
    }
    
    /// アドレスに基づいて適切なアクセサを選択
    fn select_accessor<'a>(&'a self, address: &PciAddress) -> &'a dyn PciConfigAccess {
        // セグメント0以外の場合は必ずMMIOを使用
        if address.segment != 0 {
            match &self.mmio {
                Some(mmio) => return mmio,
                None => panic!("セグメント{}のPCIアクセスにはMMIOが必要ですが、利用できません", address.segment),
            }
        }
        
        // セグメント0の場合、MMIOがあればそれを使用、なければI/Oポートを使用
        match &self.mmio {
            Some(mmio) => mmio as &dyn PciConfigAccess,
            None => &self.io_port as &dyn PciConfigAccess,
        }
    }
}

impl PciConfigAccess for MixedPciAccess {
    fn read_config_byte(&self, address: &PciAddress, offset: u8) -> u8 {
        let accessor = self.select_accessor(address);
        accessor.read_config_byte(address, offset)
    }
    
    fn read_config_word(&self, address: &PciAddress, offset: u8) -> u16 {
        let accessor = self.select_accessor(address);
        accessor.read_config_word(address, offset)
    }
    
    fn read_config_dword(&self, address: &PciAddress, offset: u8) -> u32 {
        let accessor = self.select_accessor(address);
        accessor.read_config_dword(address, offset)
    }
    
    fn write_config_byte(&self, address: &PciAddress, offset: u8, value: u8) {
        let accessor = self.select_accessor(address);
        accessor.write_config_byte(address, offset, value);
    }
    
    fn write_config_word(&self, address: &PciAddress, offset: u8, value: u16) {
        let accessor = self.select_accessor(address);
        accessor.write_config_word(address, offset, value);
    }
    
    fn write_config_dword(&self, address: &PciAddress, offset: u8, value: u32) {
        let accessor = self.select_accessor(address);
        accessor.write_config_dword(address, offset, value);
    }
    
    fn access_method(&self) -> PciAccessMethod {
        PciAccessMethod::Mixed
    }
}

/// PCIコンフィギュレーション空間アクセス方法の検出と生成
pub fn create_pci_config_accessor() -> Box<dyn PciConfigAccess> {
    // ACPI MCFGテーブルからMMIOベースアドレスを検出する実装が必要
    // ここでは簡易的な実装として、ACPIテーブルの検出ロジックは省略
    
    // 実際の実装では、ACPIテーブルからPCIeコンフィギュレーション空間の
    // 物理ベースアドレスを取得し、適切なアクセサを生成する
    
    #[cfg(feature = "pcie_mmio")]
    {
        // PCIeコンフィギュレーション空間の物理ベースアドレス
        // 実際の値はACPI MCFGテーブルから取得するべき
        let mmio_base = PhysAddr::new(0xE0000000); // 仮の値
        
        // メモリマッパーの作成
        // 実際の実装ではシステムのメモリマッパーを利用
        let vmem_mapper = VMemMapper::new(); // 仮の実装
        
        if let Some(mmio_accessor) = MmioPciAccess::new(mmio_base, vmem_mapper) {
            debug!("PCIe MMIOアクセサを使用します: ベースアドレス=0x{:x}", mmio_base.value());
            return Box::new(mmio_accessor);
        }
    }
    
    // MMIOが利用できない場合はI/Oポートアクセサを使用
    debug!("PCIレガシーI/Oポートアクセサを使用します");
    Box::new(IoPortPciAccess::new())
}

fn get_pcie_config_base_from_acpi() -> Option<u64> {
    // ACPI MCFGテーブルをパース
    if let Some(mcfg) = acpi::find_table("MCFG") {
        let base = u64::from_le_bytes(mcfg[44..52].try_into().unwrap());
        Some(base)
    } else {
        None
    }
}

pub fn create_ecam_accessor() -> Result<EcamConfigAccessor, &'static str> {
    log::info!("ECamアクセサー作成開始");
    
    // ACPIテーブルからPCIeコンフィギュレーション空間の物理ベースアドレスを取得
    let mcfg_table = crate::acpi::get_mcfg_table()
        .ok_or("MCFGテーブルが見つかりません")?;
    
    let mut config_regions = Vec::new();
    
    // MCFGテーブルから設定領域を解析
    for config_entry in mcfg_table.configuration_space_entries() {
        let base_address = config_entry.base_address;
        let segment_group = config_entry.pci_segment_group;
        let start_bus = config_entry.start_pci_bus_number;
        let end_bus = config_entry.end_pci_bus_number;
        
        log::debug!("PCIe設定領域: ベース=0x{:x}, セグメント={}, バス={}..{}", 
                   base_address, segment_group, start_bus, end_bus);
        
        // 物理メモリ領域のサイズ計算
        let bus_count = (end_bus - start_bus + 1) as usize;
        let region_size = bus_count * 256 * 32 * 4096; // バス数 * デバイス数 * 機能数 * 4KB
        
        // 仮想メモリマッパーの作成
        let vmem_mapper = VMemMapper::new(base_address, region_size)?;
        
        // 仮想アドレス空間にマッピング
        let virtual_base = vmem_mapper.map_physical_region(
            base_address,
            region_size,
            MemoryFlags::READABLE | MemoryFlags::WRITABLE | MemoryFlags::CACHE_DISABLE
        )?;
        
        let region = EcamRegion {
            physical_base: base_address,
            virtual_base,
            size: region_size,
            segment_group,
            start_bus_number: start_bus,
            end_bus_number: end_bus,
            mapper: vmem_mapper,
        };
        
        config_regions.push(region);
    }
    
    if config_regions.is_empty() {
        return Err("有効なPCIe設定領域が見つかりません");
    }
    
    let accessor = EcamConfigAccessor {
        regions: config_regions,
        access_stats: AccessStatistics::new(),
    };
    
    log::info!("ECamアクセサー作成完了: {}個の設定領域", accessor.regions.len());
    Ok(accessor)
}

fn find_region_for_address(&self, segment: u16, bus: u8, device: u8, function: u8) -> Option<&EcamRegion> {
    for region in &self.regions {
        if region.segment_group == segment &&
           bus >= region.start_bus_number &&
           bus <= region.end_bus_number {
            return Some(region);
        }
    }
    None
}

fn calculate_config_address(&self, region: &EcamRegion, bus: u8, device: u8, function: u8, offset: u16) -> Result<usize, &'static str> {
    // PCIeアドレス計算: base + (bus << 20) + (device << 15) + (function << 12) + offset
    if device >= 32 {
        return Err("デバイス番号が範囲外です");
    }
    if function >= 8 {
        return Err("機能番号が範囲外です");
    }
    if offset >= 4096 {
        return Err("オフセットが範囲外です");
    }
    
    let bus_offset = (bus - region.start_bus_number) as usize;
    let config_offset = (bus_offset << 20) | ((device as usize) << 15) | ((function as usize) << 12) | (offset as usize);
    
    if config_offset >= region.size {
        return Err("計算されたアドレスが領域外です");
    }
    
    Ok(region.virtual_base + config_offset)
}

impl VMemMapper {
    pub fn new(physical_base: u64, size: usize) -> Result<Self, &'static str> {
        let mapper = VMemMapper {
            physical_base,
            virtual_base: 0, // map_physical_regionで設定
            size,
            page_table_entries: Vec::new(),
        };
        
        Ok(mapper)
    }

    pub fn map_physical_region(&mut self, physical_addr: u64, size: usize, flags: MemoryFlags) -> Result<usize, &'static str> {
        // ページアラインメントの確認
        let aligned_addr = physical_addr & !0xFFF;
        let aligned_size = (size + 0xFFF) & !0xFFF;
        
        // 仮想アドレス空間から適切な領域を見つける
        let virtual_addr = self.find_available_virtual_region(aligned_size)?;
        
        // ページテーブルエントリの作成と設定
        let page_count = aligned_size / 4096;
        let mut current_phys = aligned_addr;
        let mut current_virt = virtual_addr;
        
        for _ in 0..page_count {
            // ページテーブルエントリの作成
            let pte = PageTableEntry {
                virtual_address: current_virt,
                physical_address: current_phys,
                flags: self.convert_memory_flags_to_page_flags(flags),
            };
            
            // ページテーブルに登録
            self.map_page(&pte)?;
            self.page_table_entries.push(pte);
            
            current_phys += 4096;
            current_virt += 4096;
        }
        
        self.virtual_base = virtual_addr;
        
        // TLBの無効化
        self.invalidate_tlb_range(virtual_addr, aligned_size);
        
        log::debug!("物理メモリマッピング完了: 物理=0x{:x}, 仮想=0x{:x}, サイズ=0x{:x}", 
                   aligned_addr, virtual_addr, aligned_size);
        
        Ok(virtual_addr)
    }

    fn find_available_virtual_region(&self, size: usize) -> Result<usize, &'static str> {
        // カーネル仮想アドレス空間でマッピング用の領域を探す
        // 通常は0xFFFF800000000000以降の領域を使用
        const KERNEL_VMEM_START: usize = 0xFFFF800000000000;
        const KERNEL_VMEM_END: usize = 0xFFFFC00000000000;
        
        // 簡単な実装: 線形検索で空き領域を見つける
        let mut current_addr = KERNEL_VMEM_START;
        
        while current_addr + size <= KERNEL_VMEM_END {
            if self.is_virtual_region_available(current_addr, size) {
                return Ok(current_addr);
            }
            current_addr += 0x200000; // 2MBずつ進む
        }
        
        Err("仮想メモリ領域の確保に失敗しました")
    }

    fn is_virtual_region_available(&self, addr: usize, size: usize) -> bool {
        // 指定された仮想アドレス領域が利用可能かチェック
        let page_count = (size + 0xFFF) / 0x1000;
        
        for i in 0..page_count {
            let check_addr = addr + (i * 0x1000);
            if self.is_virtual_address_mapped(check_addr) {
                return false;
            }
        }
        
        true
    }

    fn is_virtual_address_mapped(&self, addr: usize) -> bool {
        // ページテーブルを確認して、指定された仮想アドレスがマッピング済みかチェック
        crate::memory::page_table::is_page_mapped(addr)
    }

    fn map_page(&self, pte: &PageTableEntry) -> Result<(), &'static str> {
        // ページテーブルエントリを実際のページテーブルに登録
        crate::memory::page_table::map_page(
            pte.virtual_address,
            pte.physical_address,
            pte.flags
        )
    }

    fn convert_memory_flags_to_page_flags(&self, flags: MemoryFlags) -> crate::memory::PageFlags {
        let mut page_flags = crate::memory::PageFlags::PRESENT;
        
        if flags.contains(MemoryFlags::WRITABLE) {
            page_flags |= crate::memory::PageFlags::WRITABLE;
        }
        if flags.contains(MemoryFlags::USER_ACCESSIBLE) {
            page_flags |= crate::memory::PageFlags::USER_ACCESSIBLE;
        }
        if flags.contains(MemoryFlags::CACHE_DISABLE) {
            page_flags |= crate::memory::PageFlags::CACHE_DISABLE;
        }
        if flags.contains(MemoryFlags::WRITE_THROUGH) {
            page_flags |= crate::memory::PageFlags::WRITE_THROUGH;
        }
        
        page_flags
    }

    fn invalidate_tlb_range(&self, virtual_addr: usize, size: usize) {
        // TLB（Translation Lookaside Buffer）の無効化
        let page_count = (size + 0xFFF) / 0x1000;
        
        for i in 0..page_count {
            let page_addr = virtual_addr + (i * 0x1000);
            crate::arch::invalidate_tlb_page(page_addr);
        }
    }
}

impl Drop for VMemMapper {
    fn drop(&mut self) {
        // リソースのクリーンアップ
        for pte in &self.page_table_entries {
            let _ = crate::memory::page_table::unmap_page(pte.virtual_address);
        }
        
        // TLB無効化
        if self.virtual_base != 0 {
            self.invalidate_tlb_range(self.virtual_base, self.size);
        }
        
        log::debug!("VMemMapperクリーンアップ完了");
    }
}

// 追加のデータ構造
#[derive(Debug)]
struct EcamRegion {
    physical_base: u64,
    virtual_base: usize,
    size: usize,
    segment_group: u16,
    start_bus_number: u8,
    end_bus_number: u8,
    mapper: VMemMapper,
}

#[derive(Debug)]
struct PageTableEntry {
    virtual_address: usize,
    physical_address: u64,
    flags: crate::memory::PageFlags,
}

#[derive(Debug)]
struct AccessStatistics {
    read_count: core::sync::atomic::AtomicU64,
    write_count: core::sync::atomic::AtomicU64,
    error_count: core::sync::atomic::AtomicU64,
}

impl AccessStatistics {
    fn new() -> Self {
        Self {
            read_count: core::sync::atomic::AtomicU64::new(0),
            write_count: core::sync::atomic::AtomicU64::new(0),
            error_count: core::sync::atomic::AtomicU64::new(0),
        }
    }
    
    fn record_read(&self) {
        self.read_count.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    
    fn record_write(&self) {
        self.write_count.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    
    fn record_error(&self) {
        self.error_count.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

bitflags::bitflags! {
    struct MemoryFlags: u32 {
        const READABLE = 1 << 0;
        const WRITABLE = 1 << 1;
        const EXECUTABLE = 1 << 2;
        const USER_ACCESSIBLE = 1 << 3;
        const CACHE_DISABLE = 1 << 4;
        const WRITE_THROUGH = 1 << 5;
        const WRITE_COMBINING = 1 << 6;
    }
} 