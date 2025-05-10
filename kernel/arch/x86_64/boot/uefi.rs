// AetherOS x86_64 UEFIブートサポート
//
// UEFIブート情報の解析と必要なデータ構造を定義します

use crate::kernel::arch::x86_64::boot::{BootInfo, BootMemoryMap, BootProtocol, FramebufferInfo, FramebufferColorInfo};
use crate::kernel::mm::PhysAddr;
use alloc::vec::Vec;
use core::mem;
use core::slice;
use core::str;
use core::ptr::NonNull;

/// UEFI GUIDの構造体
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// UEFI GUIDを生成するコンストラクタ
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Guid {
        Guid {
            data1,
            data2,
            data3,
            data4,
        }
    }
}

/// UEFI情報のブートマジック
pub const UEFI_BOOT_MAGIC: u32 = 0xE1F5A9B3;

/// UEFIのメモリタイプを表す列挙型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EfiMemoryType {
    /// 未使用メモリ
    Reserved = 0,
    /// 通常のRAM
    LoaderCode = 1,
    /// 通常のRAM（ローダーデータ）
    LoaderData = 2,
    /// UEFI特権コード用に予約
    BootServicesCode = 3,
    /// UEFI特権データ用に予約
    BootServicesData = 4,
    /// ランタイムサービスコード用に予約
    RuntimeServicesCode = 5,
    /// ランタイムサービスデータ用に予約
    RuntimeServicesData = 6,
    /// 通常のRAM（自由に使用可能）
    ConventionalMemory = 7,
    /// 使用不可能なメモリ
    Unusable = 8,
    /// ACPIテーブル用に予約
    AcpiReclaimMemory = 9,
    /// ACPIのNVS用に予約
    AcpiNvsMemory = 10,
    /// メモリマップドI/O用
    MmioRegion = 11,
    /// メモリマップドI/Oポート用
    MmioPortSpace = 12,
    /// プロセッサ固有のメモリ
    ProcessorReserved = 13,
    /// Pal Code用に予約
    PalCode = 14,
    /// 持続的メモリ
    PersistentMemory = 15,
    /// その他のタイプ
    Other(u32),
}

impl From<u32> for EfiMemoryType {
    fn from(value: u32) -> Self {
        match value {
            0 => EfiMemoryType::Reserved,
            1 => EfiMemoryType::LoaderCode,
            2 => EfiMemoryType::LoaderData,
            3 => EfiMemoryType::BootServicesCode,
            4 => EfiMemoryType::BootServicesData,
            5 => EfiMemoryType::RuntimeServicesCode,
            6 => EfiMemoryType::RuntimeServicesData,
            7 => EfiMemoryType::ConventionalMemory,
            8 => EfiMemoryType::Unusable,
            9 => EfiMemoryType::AcpiReclaimMemory,
            10 => EfiMemoryType::AcpiNvsMemory,
            11 => EfiMemoryType::MmioRegion,
            12 => EfiMemoryType::MmioPortSpace,
            13 => EfiMemoryType::ProcessorReserved,
            14 => EfiMemoryType::PalCode,
            15 => EfiMemoryType::PersistentMemory,
            _ => EfiMemoryType::Other(value),
        }
    }
}

/// UEFIメモリマップエントリのメモリ属性
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EfiMemoryAttributes(u64);

impl EfiMemoryAttributes {
    /// ビットがセットされているかどうかを確認
    fn is_set(&self, bit: u64) -> bool {
        (self.0 & bit) != 0
    }

    /// Uncached (UC)
    pub fn is_uncached(&self) -> bool {
        self.is_set(0x1)
    }

    /// Write Combining (WC)
    pub fn is_write_combining(&self) -> bool {
        self.is_set(0x2)
    }

    /// Write Through (WT)
    pub fn is_write_through(&self) -> bool {
        self.is_set(0x4)
    }

    /// Write Back (WB)
    pub fn is_write_back(&self) -> bool {
        self.is_set(0x8)
    }

    /// Write Protected (WP)
    pub fn is_write_protected(&self) -> bool {
        self.is_set(0x1000)
    }

    /// Read Protected (RP)
    pub fn is_read_protected(&self) -> bool {
        self.is_set(0x2000)
    }

    /// Execution Protected (XP)
    pub fn is_execution_protected(&self) -> bool {
        self.is_set(0x4000)
    }

    /// Non-volatile (NV)
    pub fn is_non_volatile(&self) -> bool {
        self.is_set(0x8000)
    }

    /// メモリがより信頼性が高い場合
    pub fn is_more_reliable(&self) -> bool {
        self.is_set(0x10000)
    }

    /// READ/WRITE/EXECUTE権限の確認
    pub fn is_read_only(&self) -> bool {
        self.is_write_protected()
    }

    pub fn is_write_only(&self) -> bool {
        self.is_read_protected()
    }

    pub fn is_no_execute(&self) -> bool {
        self.is_execution_protected()
    }
}

/// UEFIメモリマップエントリ
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct EfiMemoryDescriptor {
    /// メモリタイプ
    pub memory_type: u32,
    /// 予約済み (将来の互換性のため)
    pub _padding: u32,
    /// メモリの物理アドレス
    pub physical_start: u64,
    /// メモリの仮想アドレス
    pub virtual_start: u64,
    /// ページ数 (4KBページ単位)
    pub number_of_pages: u64,
    /// メモリ属性
    pub attribute: u64,
}

/// UEFIフレームバッファピクセルフォーマット
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EfiPixelFormat {
    /// RGB形式
    RedGreenBlueReserved8BitPerColor = 0,
    /// BGR形式
    BlueGreenRedReserved8BitPerColor = 1,
    /// ビットマスク使用
    BitMask = 2,
    /// BLT専用
    BltOnly = 3,
    /// 不明なフォーマット
    Unknown(u32),
}

impl From<u32> for EfiPixelFormat {
    fn from(value: u32) -> Self {
        match value {
            0 => EfiPixelFormat::RedGreenBlueReserved8BitPerColor,
            1 => EfiPixelFormat::BlueGreenRedReserved8BitPerColor,
            2 => EfiPixelFormat::BitMask,
            3 => EfiPixelFormat::BltOnly,
            _ => EfiPixelFormat::Unknown(value),
        }
    }
}

/// UEFI GOPからのピクセル情報
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct EfiPixelBitmask {
    pub red_mask: u32,
    pub green_mask: u32,
    pub blue_mask: u32,
    pub reserved_mask: u32,
}

/// UEFIグラフィックス出力モード情報
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct EfiGraphicsOutputModeInfo {
    pub version: u32,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
    pub pixel_format: u32,
    pub pixel_information: EfiPixelBitmask,
    pub pixels_per_scan_line: u32,
}

/// UEFIブートパラメータ構造体
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UefiBootParams {
    /// ブートマジック（UEFIであることを識別するためのマジック値）
    pub boot_magic: u32,
    
    /// システムテーブルの物理アドレス
    pub system_table: u64,
    
    /// メモリマップの物理アドレス
    pub memory_map: u64,
    
    /// メモリマップのサイズ（バイト単位）
    pub memory_map_size: u64,
    
    /// メモリマップのディスクリプタサイズ
    pub memory_map_desc_size: u64,
    
    /// ACPIの物理アドレス
    pub acpi_rsdp: u64,
    
    /// フレームバッファ情報
    pub framebuffer_addr: u64,
    pub framebuffer_size: u64,
    pub framebuffer_width: u32,
    pub framebuffer_height: u32,
    pub framebuffer_pitch: u32,
    pub framebuffer_bpp: u32,
    pub framebuffer_pixel_format: u32,
    
    /// コマンドライン文字列へのポインタ
    pub cmdline_ptr: u64,
    
    /// コマンドライン文字列の長さ
    pub cmdline_size: u64,
}

/// UEFIブート情報パーサー
#[derive(Debug)]
pub struct UefiParser {
    /// ブートパラメータへのポインタ
    boot_params: &'static UefiBootParams,
}

impl UefiParser {
    /// 新しいパーサーを作成
    pub fn new(boot_params_addr: PhysAddr) -> Self {
        let boot_params = unsafe { &*(boot_params_addr.as_usize() as *const UefiBootParams) };
        Self { boot_params }
    }

    /// ブートパラメータを取得
    pub fn boot_params(&self) -> &UefiBootParams {
        self.boot_params
    }

    /// メモリマップエントリのイテレータを取得
    pub fn memory_map(&self) -> EfiMemoryMapIterator {
        let map_addr = self.boot_params.memory_map as usize;
        let map_size = self.boot_params.memory_map_size as usize;
        let desc_size = self.boot_params.memory_map_desc_size as usize;
        let entries_count = map_size / desc_size;

        EfiMemoryMapIterator {
            current_index: 0,
            entries_count,
            map_addr,
            desc_size,
        }
    }

    /// フレームバッファ情報を取得
    pub fn framebuffer_info(&self) -> Option<EfiFramebufferInfo> {
        if self.boot_params.framebuffer_addr == 0 {
            return None;
        }

        let pixel_format = EfiPixelFormat::from(self.boot_params.framebuffer_pixel_format);
        
        Some(EfiFramebufferInfo {
            addr: PhysAddr::new(self.boot_params.framebuffer_addr as usize),
            size: self.boot_params.framebuffer_size as usize,
            width: self.boot_params.framebuffer_width as usize,
            height: self.boot_params.framebuffer_height as usize,
            pitch: self.boot_params.framebuffer_pitch as usize,
            bpp: self.boot_params.framebuffer_bpp as usize,
            pixel_format,
        })
    }

    /// ACPIのRSDP物理アドレスを取得
    pub fn acpi_rsdp(&self) -> Option<PhysAddr> {
        if self.boot_params.acpi_rsdp == 0 {
            None
        } else {
            Some(PhysAddr::new(self.boot_params.acpi_rsdp as usize))
        }
    }

    /// コマンドライン文字列を取得
    pub fn command_line(&self) -> Option<&str> {
        if self.boot_params.cmdline_ptr == 0 || self.boot_params.cmdline_size == 0 {
            return None;
        }

        let cmdline_addr = self.boot_params.cmdline_ptr as usize;
        let cmdline_size = self.boot_params.cmdline_size as usize;
        let bytes = unsafe { slice::from_raw_parts(cmdline_addr as *const u8, cmdline_size) };
        
        // 文字列をUTF-8として解釈（エラー時は空文字列を返す）
        str::from_utf8(bytes).ok()
    }
}

/// UEFIメモリマップエントリイテレータ
pub struct EfiMemoryMapIterator {
    current_index: usize,
    entries_count: usize,
    map_addr: usize,
    desc_size: usize,
}

impl Iterator for EfiMemoryMapIterator {
    type Item = &'static EfiMemoryDescriptor;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index >= self.entries_count {
            return None;
        }

        let entry_addr = self.map_addr + (self.current_index * self.desc_size);
        let entry = unsafe { &*(entry_addr as *const EfiMemoryDescriptor) };
        
        self.current_index += 1;
        
        Some(entry)
    }
}

/// UEFIフレームバッファ情報
#[derive(Debug, Clone)]
pub struct EfiFramebufferInfo {
    pub addr: PhysAddr,
    pub size: usize,
    pub width: usize,
    pub height: usize,
    pub pitch: usize,
    pub bpp: usize,
    pub pixel_format: EfiPixelFormat,
}

impl EfiFramebufferInfo {
    /// ピクセルオフセットを計算
    pub fn pixel_offset(&self, x: usize, y: usize) -> usize {
        y * self.pitch + x * (self.bpp / 8)
    }
    
    /// ピクセルフォーマットがRGBかどうかを判定
    pub fn is_rgb(&self) -> bool {
        self.pixel_format == EfiPixelFormat::RedGreenBlueReserved8BitPerColor
    }
    
    /// ピクセルフォーマットがBGRかどうかを判定
    pub fn is_bgr(&self) -> bool {
        self.pixel_format == EfiPixelFormat::BlueGreenRedReserved8BitPerColor
    }
}

/// UEFI メモリタイプ
#[repr(u32)]
pub enum MemoryType {
    EfiReservedMemoryType = 0,
    EfiLoaderCode = 1,
    EfiLoaderData = 2,
    EfiBootServicesCode = 3,
    EfiBootServicesData = 4,
    EfiRuntimeServicesCode = 5,
    EfiRuntimeServicesData = 6,
    EfiConventionalMemory = 7,
    EfiUnusableMemory = 8,
    EfiACPIReclaimMemory = 9,
    EfiACPIMemoryNVS = 10,
    EfiMemoryMappedIO = 11,
    EfiMemoryMappedIOPortSpace = 12,
    EfiPalCode = 13,
    EfiPersistentMemory = 14,
    EfiMaxMemoryType = 15,
}

/// UEFI メモリディスクリプタ
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryDescriptor {
    pub memory_type: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

/// UEFI システムテーブル
#[derive(Debug)]
#[repr(C)]
pub struct SystemTable {
    pub header: TableHeader,
    pub firmware_vendor: u64, // UEFIでは実際にはポインタですが、簡略化のため整数に
    pub firmware_revision: u32,
    pub console_in_handle: u64,
    pub con_in: u64,
    pub console_out_handle: u64,
    pub con_out: u64,
    pub standard_error_handle: u64,
    pub std_err: u64,
    pub runtime_services: u64,
    pub boot_services: u64,
    pub number_of_table_entries: usize,
    pub configuration_table: u64,
}

/// UEFI テーブルヘッダ
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

/// UEFI 設定テーブル
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ConfigurationTable {
    pub vendor_guid: Guid,
    pub vendor_table: u64,
}

/// ACPI GUID
pub const ACPI_20_TABLE_GUID: Guid = Guid::new(
    0x8868e871,
    0xe4f1,
    0x11d3,
    [0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
);

/// ACPI 1.0 GUID
pub const ACPI_TABLE_GUID: Guid = Guid::new(
    0xeb9d2d30,
    0x2d88,
    0x11d3,
    [0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
);

/// SMBIOS GUID
pub const SMBIOS_TABLE_GUID: Guid = Guid::new(
    0xeb9d2d31,
    0x2d88,
    0x11d3,
    [0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
);

/// UEFI GraphicsOutputProtocol GUID
pub const GOP_GUID: Guid = Guid::new(
    0x9042a9de,
    0x23dc,
    0x4a38,
    [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
);

/// UEFI ブート情報
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UefiBootInfo {
    pub system_table: u64,
    pub memory_map: u64,
    pub memory_map_size: usize,
    pub memory_map_desc_size: usize,
    pub gop_base: u64,
    pub gop_mode: u32,
    pub kernel_load_base: u64,
    pub kernel_entry_point: u64,
    pub acpi_rsdp: u64,
    pub cmdline: u64,
    pub initrd_addr: u64,
    pub initrd_size: usize,
}

/// GraphicsOutputProtocolMode
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GraphicsOutputProtocolMode {
    pub max_mode: u32,
    pub mode: u32,
    pub info: u64, // ポインタからusize扱い
    pub size_of_info: usize,
    pub framebuffer_base: u64,
    pub framebuffer_size: usize,
}

/// GraphicsOutputModeInfo
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct GraphicsOutputModeInfo {
    pub version: u32,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
    pub pixel_format: u32,
    pub pixel_info: PixelBitmask,
    pub pixels_per_scan_line: u32,
}

/// PixelBitmask
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PixelBitmask {
    pub red_mask: u32,
    pub green_mask: u32,
    pub blue_mask: u32,
    pub reserved_mask: u32,
}

/// PixelFormat
#[repr(u32)]
pub enum PixelFormat {
    PixelRedGreenBlueReserved8BitPerColor = 0,
    PixelBlueGreenRedReserved8BitPerColor = 1,
    PixelBitMask = 2,
    PixelBltOnly = 3,
    PixelFormatMax = 4,
}

/// ビットマスクから位置とサイズを計算
fn calculate_position_and_size(mask: u32) -> (u8, u8) {
    if mask == 0 {
        return (0, 0);
    }

    let mut pos = 0;
    let mut size = 0;
    let mut temp = mask;

    // 最下位のビットを見つける
    while temp & 1 == 0 {
        pos += 1;
        temp >>= 1;
    }

    // 連続したビットの数を数える
    while temp & 1 == 1 {
        size += 1;
        temp >>= 1;
    }

    (pos, size)
}

/// UEFI情報の解析
pub unsafe fn parse_uefi_boot_info(info_addr: usize) -> BootInfo {
    let boot_info_ptr = info_addr as *const UefiBootInfo;
    let boot_info = &*boot_info_ptr;
    
    // ブート情報構造体を初期化
    let mut os_boot_info = BootInfo {
        memory_map: BootMemoryMap {
            available_regions: Vec::new(),
            reserved_regions: Vec::new(),
            acpi_regions: Vec::new(),
            nvs_regions: Vec::new(),
            bad_regions: Vec::new(),
        },
        cmdline: None,
        framebuffer: None,
        acpi_rsdp: None,
        initrd: None,
        smbios: None,
        boot_protocol: BootProtocol::UEFI {
            info_addr: PhysAddr::new(info_addr),
        },
    };
    
    // コマンドラインの解析
    if boot_info.cmdline != 0 {
        let cmdline_ptr = boot_info.cmdline as *const u8;
        let mut len = 0;
        while *cmdline_ptr.add(len) != 0 {
            len += 1;
        }
        let cmdline_slice = slice::from_raw_parts(cmdline_ptr, len);
        os_boot_info.cmdline = core::str::from_utf8(cmdline_slice).ok();
    }
    
    // メモリマップの解析
    if boot_info.memory_map != 0 && boot_info.memory_map_size > 0 {
        let memory_map_ptr = boot_info.memory_map as *const u8;
        let entry_count = boot_info.memory_map_size / boot_info.memory_map_desc_size;
        
        for i in 0..entry_count {
            let offset = i * boot_info.memory_map_desc_size;
            let desc_ptr = memory_map_ptr.add(offset) as *const MemoryDescriptor;
            let desc = &*desc_ptr;
            
            let addr = PhysAddr::new(desc.physical_start as usize);
            let size = (desc.number_of_pages * 4096) as usize;
            
            match desc.memory_type {
                // 通常メモリ、ブートサービスコード/データはフリーにできる
                7 | 1 | 2 | 3 | 4 => {
                    os_boot_info.memory_map.available_regions.push((addr, size));
                },
                // ACPI再利用可能メモリ
                9 => {
                    os_boot_info.memory_map.acpi_regions.push((addr, size));
                },
                // ACPI NVSメモリ
                10 => {
                    os_boot_info.memory_map.nvs_regions.push((addr, size));
                },
                // 使用不可能なメモリ
                8 => {
                    os_boot_info.memory_map.bad_regions.push((addr, size));
                },
                // その他は予約として扱う
                _ => {
                    os_boot_info.memory_map.reserved_regions.push((addr, size));
                }
            }
        }
    }
    
    // フレームバッファの解析
    if boot_info.gop_base != 0 {
        let gop_mode_ptr = (boot_info.gop_base + 24) as *const GraphicsOutputProtocolMode;
        let gop_mode = &*gop_mode_ptr;
        
        if gop_mode.info != 0 {
            let mode_info_ptr = gop_mode.info as *const GraphicsOutputModeInfo;
            let mode_info = &*mode_info_ptr;
            
            let color_info = match mode_info.pixel_format {
                0 => {
                    // PixelRedGreenBlueReserved8BitPerColor
                    FramebufferColorInfo::RGB {
                        red_pos: 16,
                        red_size: 8,
                        green_pos: 8,
                        green_size: 8,
                        blue_pos: 0,
                        blue_size: 8,
                    }
                },
                1 => {
                    // PixelBlueGreenRedReserved8BitPerColor
                    FramebufferColorInfo::RGB {
                        red_pos: 0,
                        red_size: 8,
                        green_pos: 8,
                        green_size: 8,
                        blue_pos: 16,
                        blue_size: 8,
                    }
                },
                2 => {
                    // PixelBitMask
                    let (red_pos, red_size) = calculate_position_and_size(mode_info.pixel_info.red_mask);
                    let (green_pos, green_size) = calculate_position_and_size(mode_info.pixel_info.green_mask);
                    let (blue_pos, blue_size) = calculate_position_and_size(mode_info.pixel_info.blue_mask);
                    
                    FramebufferColorInfo::RGB {
                        red_pos,
                        red_size,
                        green_pos,
                        green_size,
                        blue_pos,
                        blue_size,
                    }
                },
                _ => {
                    // その他のフォーマットはパレットとして扱う
                    FramebufferColorInfo::Palette
                }
            };
            
            os_boot_info.framebuffer = Some(FramebufferInfo {
                addr: PhysAddr::new(gop_mode.framebuffer_base as usize),
                width: mode_info.horizontal_resolution as usize,
                height: mode_info.vertical_resolution as usize,
                bpp: match mode_info.pixel_format {
                    0 | 1 => 32,  // 32bpp RGBA/BGRA
                    2 => {        // BitMask
                        let total_bits = mode_info.pixel_info.red_mask.count_ones() +
                                        mode_info.pixel_info.green_mask.count_ones() +
                                        mode_info.pixel_info.blue_mask.count_ones() +
                                        mode_info.pixel_info.reserved_mask.count_ones();
                        total_bits as u8
                    },
                    _ => 0,
                },
                pitch: (mode_info.pixels_per_scan_line * 4) as usize,
                color_info,
            });
        }
    }
    
    // ACPIテーブルの設定
    if boot_info.acpi_rsdp != 0 {
        os_boot_info.acpi_rsdp = Some(PhysAddr::new(boot_info.acpi_rsdp as usize));
    } else if boot_info.system_table != 0 {
        // システムテーブルからACPI RSDPを探す
        let system_table = &*(boot_info.system_table as *const SystemTable);
        
        if system_table.configuration_table != 0 && system_table.number_of_table_entries > 0 {
            let config_tables = slice::from_raw_parts(
                system_table.configuration_table as *const ConfigurationTable,
                system_table.number_of_table_entries
            );
            
            // ACPI 2.0テーブルを優先的に探す
            for table in config_tables {
                if table.vendor_guid == ACPI_20_TABLE_GUID {
                    os_boot_info.acpi_rsdp = Some(PhysAddr::new(table.vendor_table as usize));
                    break;
                }
            }
            
            // ACPI 1.0テーブルを探す（2.0が見つからなかった場合）
            if os_boot_info.acpi_rsdp.is_none() {
                for table in config_tables {
                    if table.vendor_guid == ACPI_TABLE_GUID {
                        os_boot_info.acpi_rsdp = Some(PhysAddr::new(table.vendor_table as usize));
                        break;
                    }
                }
            }
            
            // SMBIOSテーブルを探す
            for table in config_tables {
                if table.vendor_guid == SMBIOS_TABLE_GUID {
                    os_boot_info.smbios = Some(PhysAddr::new(table.vendor_table as usize));
                    break;
                }
            }
        }
    }
    
    // Initrdの設定
    if boot_info.initrd_addr != 0 && boot_info.initrd_size > 0 {
        os_boot_info.initrd = Some((
            PhysAddr::new(boot_info.initrd_addr as usize),
            boot_info.initrd_size
        ));
    }
    
    os_boot_info
}

/// UEFI情報かどうかを確認
pub fn check_uefi(system_table_addr: PhysAddr) -> Option<PhysAddr> {
    let header = unsafe { &*((system_table_addr.as_usize()) as *const TableHeader) };
    
    // シグネチャチェック（これは仮の実装、実際にはEFIシステムテーブルのシグネチャと比較）
    if header.signature != 0x5453595320494249 { // "IBI SYST" in little-endian
        return None;
    }
    
    Some(system_table_addr)
} 