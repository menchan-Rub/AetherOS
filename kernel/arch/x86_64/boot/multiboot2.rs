// AetherOS x86_64 Multiboot2パーサー
//
// Multiboot2仕様に基づいたブート情報の解析を行います
// 参考: https://www.gnu.org/software/grub/manual/multiboot2/multiboot.html

use crate::kernel::arch::x86_64::boot::{BootInfo, BootMemoryMap, BootProtocol, FramebufferInfo, FramebufferColorInfo};
use crate::kernel::mm::PhysAddr;
use core::ptr;
use core::slice;
use alloc::vec::Vec;
use core::mem::{size_of, MaybeUninit};
use core::ptr::addr_of;
use core::str;

/// Multiboot2マジック値
pub const MULTIBOOT2_MAGIC: u32 = 0x36d76289;

/// タグタイプ
#[repr(u32)]
pub enum TagType {
    End = 0,
    CmdLine = 1,
    BootLoaderName = 2,
    Module = 3,
    BasicMemInfo = 4,
    BootDev = 5,
    MemoryMap = 6,
    VBEInfo = 7,
    FramebufferInfo = 8,
    ELFSections = 9,
    APMTable = 10,
    EFI32SystemTable = 11,
    EFI64SystemTable = 12,
    SMBIOSTables = 13,
    ACPIOldRSDP = 14,
    ACPINewRSDP = 15,
    NetworkInfo = 16,
    EFIMemoryMap = 17,
    EFIBootServicesNotTerminated = 18,
    EFI32ImageHandle = 19,
    EFI64ImageHandle = 20,
    ImageLoadBasePhysAddr = 21,
}

/// タグヘッダ
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TagHeader {
    pub tag_type: u32,
    pub size: u32,
}

/// Multiboot2ヘッダ
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MultibootHeader {
    pub total_size: u32,
    pub reserved: u32,
}

/// メモリマップエントリ
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryMapEntry {
    pub base_addr: u64,
    pub length: u64,
    pub entry_type: u32,
    pub reserved: u32,
}

/// メモリタイプ
#[repr(u32)]
pub enum MemoryType {
    Available = 1,
    Reserved = 2,
    ACPIReclaimable = 3,
    ACPINVS = 4,
    BadMemory = 5,
}

/// フレームバッファタグ
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FramebufferTag {
    pub header: TagHeader,
    pub framebuffer_addr: u64,
    pub framebuffer_pitch: u32,
    pub framebuffer_width: u32,
    pub framebuffer_height: u32,
    pub framebuffer_bpp: u8,
    pub framebuffer_type: u8,
    pub reserved: u8,
    // 後続にカラー情報が続く
}

/// コマンドラインタグ
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CommandLineTag {
    pub header: TagHeader,
    // 後続に文字列が続く
}

/// ACPIタグ
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ACPITag {
    pub header: TagHeader,
    // 後続にRSDPが続く
}

/// SMBIOSタグ
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SMBIOSTag {
    pub header: TagHeader,
    // 後続にSMBIOS構造体が続く
}

/// モジュールタグ
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ModuleTag {
    pub header: TagHeader,
    pub mod_start: u32,
    pub mod_end: u32,
    // 後続に文字列が続く
}

/// Multiboot2情報の解析
pub unsafe fn parse_multiboot2_info(info_addr: usize, magic: u32) -> BootInfo {
    assert_eq!(magic, MULTIBOOT2_MAGIC, "無効なMultiboot2マジック値");
    
    let header = &*(info_addr as *const MultibootHeader);
    let total_size = header.total_size as usize;
    
    // 基本的なブート情報構造体を初期化
    let mut boot_info = BootInfo {
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
        boot_protocol: BootProtocol::Multiboot2 {
            magic,
            info_addr: PhysAddr::new(info_addr),
        },
    };
    
    // タグの反復処理を行う
    let mut tag_addr = info_addr + core::mem::size_of::<MultibootHeader>();
    while tag_addr < info_addr + total_size {
        let tag = &*(tag_addr as *const TagHeader);
        
        if tag.tag_type == 0 {
            // 終了タグ
            break;
        }
        
        match tag.tag_type {
            1 => {
                // コマンドライン
                let cmdline_tag = &*(tag_addr as *const CommandLineTag);
                let string_addr = tag_addr + core::mem::size_of::<CommandLineTag>();
                let cmdline = parse_cstr(string_addr);
                boot_info.cmdline = Some(cmdline);
            },
            3 => {
                // モジュール（initrd）
                let module_tag = &*(tag_addr as *const ModuleTag);
                let string_addr = tag_addr + core::mem::size_of::<ModuleTag>();
                let _module_name = parse_cstr(string_addr);
                
                // モジュールがinitrdかどうかを判断
                // シンプルに最初のモジュールをinitrdとして扱う
                if boot_info.initrd.is_none() {
                    boot_info.initrd = Some((
                        PhysAddr::new(module_tag.mod_start as usize),
                        (module_tag.mod_end - module_tag.mod_start) as usize
                    ));
                }
            },
            6 => {
                // メモリマップ
                let entry_size = *((tag_addr + 8) as *const u32);
                let entry_version = *((tag_addr + 12) as *const u32);
                
                if entry_version == 0 {
                    let entries_start = tag_addr + 16;
                    let entries_end = tag_addr + tag.size as usize;
                    
                    let mut entry_addr = entries_start;
                    while entry_addr < entries_end {
                        let entry = &*(entry_addr as *const MemoryMapEntry);
                        
                        match entry.entry_type {
                            1 => {
                                // 利用可能なメモリ
                                boot_info.memory_map.available_regions.push((
                                    PhysAddr::new(entry.base_addr as usize),
                                    entry.length as usize
                                ));
                            },
                            2 => {
                                // 予約済みメモリ
                                boot_info.memory_map.reserved_regions.push((
                                    PhysAddr::new(entry.base_addr as usize),
                                    entry.length as usize
                                ));
                            },
                            3 => {
                                // ACPI再利用可能メモリ
                                boot_info.memory_map.acpi_regions.push((
                                    PhysAddr::new(entry.base_addr as usize),
                                    entry.length as usize
                                ));
                            },
                            4 => {
                                // ACPI NVSメモリ
                                boot_info.memory_map.nvs_regions.push((
                                    PhysAddr::new(entry.base_addr as usize),
                                    entry.length as usize
                                ));
                            },
                            5 => {
                                // 不良メモリ
                                boot_info.memory_map.bad_regions.push((
                                    PhysAddr::new(entry.base_addr as usize),
                                    entry.length as usize
                                ));
                            },
                            _ => {
                                // 未知のメモリタイプ、予約済みとして扱う
                                boot_info.memory_map.reserved_regions.push((
                                    PhysAddr::new(entry.base_addr as usize),
                                    entry.length as usize
                                ));
                            }
                        }
                        
                        entry_addr += entry_size as usize;
                    }
                }
            },
            8 => {
                // フレームバッファ情報
                let fb_tag = &*(tag_addr as *const FramebufferTag);
                
                let color_info = match fb_tag.framebuffer_type {
                    1 => {
                        // RGBカラーモデル
                        let color_info_ptr = (tag_addr + core::mem::size_of::<FramebufferTag>()) as *const u8;
                        let red_shift = *color_info_ptr;
                        let red_mask = *(color_info_ptr.add(1));
                        let green_shift = *(color_info_ptr.add(2));
                        let green_mask = *(color_info_ptr.add(3));
                        let blue_shift = *(color_info_ptr.add(4));
                        let blue_mask = *(color_info_ptr.add(5));
                        
                        FramebufferColorInfo::RGB {
                            red_pos: red_shift,
                            red_size: red_mask,
                            green_pos: green_shift,
                            green_size: green_mask,
                            blue_pos: blue_shift,
                            blue_size: blue_mask,
                        }
                    },
                    0 | _ => {
                        // パレットまたは不明なタイプ
                        FramebufferColorInfo::Palette
                    }
                };
                
                boot_info.framebuffer = Some(FramebufferInfo {
                    addr: PhysAddr::new(fb_tag.framebuffer_addr as usize),
                    width: fb_tag.framebuffer_width as usize,
                    height: fb_tag.framebuffer_height as usize,
                    bpp: fb_tag.framebuffer_bpp,
                    pitch: fb_tag.framebuffer_pitch as usize,
                    color_info,
                });
            },
            14 => {
                // 旧ACPIテーブル
                let acpi_tag = &*(tag_addr as *const ACPITag);
                let rsdp_addr = tag_addr + core::mem::size_of::<ACPITag>();
                boot_info.acpi_rsdp = Some(PhysAddr::new(rsdp_addr));
            },
            15 => {
                // 新ACPIテーブル（優先される）
                let acpi_tag = &*(tag_addr as *const ACPITag);
                let rsdp_addr = tag_addr + core::mem::size_of::<ACPITag>();
                boot_info.acpi_rsdp = Some(PhysAddr::new(rsdp_addr));
            },
            13 => {
                // SMBIOSテーブル
                let smbios_tag = &*(tag_addr as *const SMBIOSTag);
                let smbios_addr = tag_addr + core::mem::size_of::<SMBIOSTag>();
                boot_info.smbios = Some(PhysAddr::new(smbios_addr));
            },
            _ => {
                // その他のタグは無視
            }
        }
        
        // タグのアライメントは8バイト
        let tag_size = tag.size as usize;
        tag_addr += (tag_size + 7) & !7;
    }
    
    boot_info
}

/// C文字列をパースして&strに変換
unsafe fn parse_cstr(addr: usize) -> &'static str {
    let mut len = 0;
    while *((addr + len) as *const u8) != 0 {
        len += 1;
    }
    
    let bytes = slice::from_raw_parts(addr as *const u8, len);
    core::str::from_utf8_unchecked(bytes)
}

/// Multiboot2情報パーサー
#[derive(Debug)]
pub struct Multiboot2Parser {
    info_addr: PhysAddr,
}

impl Multiboot2Parser {
    /// 新しいパーサーを作成
    pub fn new(info_addr: PhysAddr) -> Self {
        Self { info_addr }
    }

    /// Multiboot2情報構造体を取得
    fn info(&self) -> &Multiboot2Info {
        unsafe { &*(self.info_addr.as_usize() as *const Multiboot2Info) }
    }

    /// タグを反復処理するイテレータを取得
    pub fn tags(&self) -> TagIterator {
        let base_addr = self.info_addr.as_usize() + size_of::<Multiboot2Info>();
        
        // アライメント調整（8バイト境界へ）
        let aligned_addr = (base_addr + 7) & !0x7;
        
        TagIterator {
            current_addr: aligned_addr,
            end_addr: self.info_addr.as_usize() + self.info().total_size as usize,
        }
    }

    /// 特定のタイプのタグを検索
    pub fn find_tag(&self, tag_type: TagType) -> Option<*const TagHeader> {
        for tag in self.tags() {
            let header = unsafe { &*tag };
            if TagType::from(header.typ) == tag_type {
                return Some(tag);
            }
        }
        None
    }

    /// コマンドライン文字列を取得
    pub fn command_line(&self) -> Option<&str> {
        self.find_tag(TagType::CommandLine).map(|tag| {
            let cmd_tag = tag as *const CommandLineTag;
            let string_addr = unsafe { (cmd_tag as usize) + size_of::<CommandLineTag>() };
            
            // NULL終端の文字列を探す
            let mut len = 0;
            while unsafe { *(string_addr + len) as *const u8 } != 0 {
                len += 1;
            }
            
            let bytes = unsafe { slice::from_raw_parts(string_addr as *const u8, len) };
            str::from_utf8(bytes).unwrap_or("")
        })
    }

    /// ブートローダー名を取得
    pub fn bootloader_name(&self) -> Option<&str> {
        self.find_tag(TagType::BootLoaderName).map(|tag| {
            let name_tag = tag as *const BootLoaderNameTag;
            let string_addr = unsafe { (name_tag as usize) + size_of::<BootLoaderNameTag>() };
            
            // NULL終端の文字列を探す
            let mut len = 0;
            while unsafe { *(string_addr + len) as *const u8 } != 0 {
                len += 1;
            }
            
            let bytes = unsafe { slice::from_raw_parts(string_addr as *const u8, len) };
            str::from_utf8(bytes).unwrap_or("")
        })
    }

    /// メモリマップエントリのイテレータを取得
    pub fn memory_map(&self) -> Option<MemoryMapIterator> {
        self.find_tag(TagType::MemoryMap).map(|tag| {
            let mmap_tag = unsafe { &*(tag as *const MemoryMapTag) };
            let entries_addr = unsafe { (tag as usize) + size_of::<MemoryMapTag>() };
            let entries_count = (mmap_tag.header.size as usize - size_of::<MemoryMapTag>()) / mmap_tag.entry_size as usize;
            
            MemoryMapIterator {
                current_index: 0,
                entries_count,
                entries_addr,
                entry_size: mmap_tag.entry_size as usize,
            }
        })
    }

    /// フレームバッファ情報を取得
    pub fn framebuffer_info(&self) -> Option<FramebufferInfo> {
        self.find_tag(TagType::FramebufferInfo).map(|tag| {
            let fb_tag = unsafe { &*(tag as *const FramebufferTag) };
            let fb_type = FramebufferType::from(fb_tag.framebuffer_type);
            
            // カラー情報の取得
            let color_info = if fb_type == FramebufferType::RGB {
                // RGBカラー情報の場所に移動
                let color_info_addr = unsafe { (tag as usize) + size_of::<FramebufferTag>() };
                let color_info = unsafe { &*(color_info_addr as *const ColorInfo) };
                
                Some(RGBColorInfo {
                    red_mask: color_info.red_mask,
                    red_shift: color_info.red_shift,
                    red_bits: color_info.red_bits,
                    green_mask: color_info.green_mask,
                    green_shift: color_info.green_shift,
                    green_bits: color_info.green_bits,
                    blue_mask: color_info.blue_mask,
                    blue_shift: color_info.blue_shift,
                    blue_bits: color_info.blue_bits,
                })
            } else {
                None
            };
            
            FramebufferInfo {
                addr: PhysAddr::new(fb_tag.framebuffer_addr as usize),
                pitch: fb_tag.framebuffer_pitch as usize,
                width: fb_tag.framebuffer_width as usize,
                height: fb_tag.framebuffer_height as usize,
                bpp: fb_tag.framebuffer_bpp,
                framebuffer_type: fb_type,
                color_info,
            }
        })
    }
}

/// タグイテレータ
pub struct TagIterator {
    current_addr: usize,
    end_addr: usize,
}

impl Iterator for TagIterator {
    type Item = *const TagHeader;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_addr >= self.end_addr {
            return None;
        }

        let tag = self.current_addr as *const TagHeader;
        let header = unsafe { &*tag };
        
        if header.typ == TagType::End as u32 {
            self.current_addr = self.end_addr; // イテレーション終了
            return None;
        }
        
        // 次のタグアドレスを計算（8バイト境界でアライン）
        self.current_addr += ((header.size as usize) + 7) & !0x7;
        
        Some(tag)
    }
}

/// メモリマップエントリイテレータ
pub struct MemoryMapIterator {
    current_index: usize,
    entries_count: usize,
    entries_addr: usize,
    entry_size: usize,
}

impl Iterator for MemoryMapIterator {
    type Item = &'static MemoryMapEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index >= self.entries_count {
            return None;
        }

        let entry_addr = self.entries_addr + (self.current_index * self.entry_size);
        let entry = unsafe { &*(entry_addr as *const MemoryMapEntry) };
        
        self.current_index += 1;
        
        Some(entry)
    }
}

/// RGBカラー情報
#[derive(Debug, Clone, Copy)]
pub struct RGBColorInfo {
    pub red_mask: u32,
    pub red_shift: u8,
    pub red_bits: u8,
    pub green_mask: u32,
    pub green_shift: u8,
    pub green_bits: u8,
    pub blue_mask: u32,
    pub blue_shift: u8,
    pub blue_bits: u8,
}

/// フレームバッファ情報
#[derive(Debug, Clone)]
pub struct FramebufferInfo {
    pub addr: PhysAddr,
    pub pitch: usize,
    pub width: usize,
    pub height: usize,
    pub bpp: usize,
    pub framebuffer_type: FramebufferType,
    pub color_info: Option<RGBColorInfo>,
}

impl FramebufferInfo {
    /// ピクセルオフセットを計算
    pub fn pixel_offset(&self, x: usize, y: usize) -> usize {
        y * self.pitch + x * (self.bpp / 8)
    }
    
    /// カラー値からRGB値を計算 (RGBタイプの場合)
    pub fn extract_rgb(&self, color: u32) -> Option<(u8, u8, u8)> {
        self.color_info.map(|info| {
            let r = ((color & info.red_mask) >> info.red_shift) as u8;
            let g = ((color & info.green_mask) >> info.green_shift) as u8;
            let b = ((color & info.blue_mask) >> info.blue_shift) as u8;
            (r, g, b)
        })
    }
}

/// フレームバッファタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FramebufferType {
    /// インデックスカラー
    Indexed = 0,
    /// RGBカラー
    RGB = 1,
    /// EGAテキスト
    Text = 2,
    /// 未知のタイプ
    Unknown(u8),
}

impl From<u8> for FramebufferType {
    fn from(value: u8) -> Self {
        match value {
            0 => FramebufferType::Indexed,
            1 => FramebufferType::RGB,
            2 => FramebufferType::Text,
            _ => FramebufferType::Unknown(value),
        }
    }
}

/// Multiboot2情報ヘッダータグタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TagType {
    End = 0,
    CommandLine = 1,
    BootLoaderName = 2,
    Module = 3,
    BasicMemInfo = 4,
    BIOSBootDev = 5,
    MemoryMap = 6,
    VBEInfo = 7,
    FramebufferInfo = 8,
    ELFSymbols = 9,
    APMTable = 10,
    EFI32SystemTablePtr = 11,
    EFI64SystemTablePtr = 12,
    SMBIOSTables = 13,
    ACPIRSDPv1 = 14,
    ACPIRSDPv2 = 15,
    NetworkInfo = 16,
    EFIMemoryMap = 17,
    EFIBootServicesNotTerminated = 18,
    EFI32ImageHandle = 19,
    EFI64ImageHandle = 20,
    ImageLoadBasePhysAddr = 21,
    Unknown(u32),
}

impl From<u32> for TagType {
    fn from(value: u32) -> Self {
        match value {
            0 => TagType::End,
            1 => TagType::CommandLine,
            2 => TagType::BootLoaderName,
            3 => TagType::Module,
            4 => TagType::BasicMemInfo,
            5 => TagType::BIOSBootDev,
            6 => TagType::MemoryMap,
            7 => TagType::VBEInfo,
            8 => TagType::FramebufferInfo,
            9 => TagType::ELFSymbols,
            10 => TagType::APMTable,
            11 => TagType::EFI32SystemTablePtr,
            12 => TagType::EFI64SystemTablePtr,
            13 => TagType::SMBIOSTables,
            14 => TagType::ACPIRSDPv1,
            15 => TagType::ACPIRSDPv2,
            16 => TagType::NetworkInfo,
            17 => TagType::EFIMemoryMap,
            18 => TagType::EFIBootServicesNotTerminated,
            19 => TagType::EFI32ImageHandle,
            20 => TagType::EFI64ImageHandle,
            21 => TagType::ImageLoadBasePhysAddr,
            _ => TagType::Unknown(value),
        }
    }
}

/// Multiboot2情報構造体
#[derive(Debug)]
#[repr(C, packed)]
pub struct Multiboot2Info {
    /// 情報構造体の合計サイズ (bytes)
    pub total_size: u32,
    /// 予約済み (0)
    pub reserved: u32,
    // 可変長のタグデータが続く
}

/// メモリマップエントリのメモリタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryType {
    /// 未定義/予約済み
    Reserved = 0,
    /// 利用可能なRAM
    Available = 1,
    /// ACPI情報
    ACPI = 3,
    /// 保持が必要なメモリ領域
    PreserveOnHibernation = 4,
    /// 不良メモリ領域
    Defective = 5,
    /// 未知のタイプ
    Unknown(u32),
}

impl From<u32> for MemoryType {
    fn from(value: u32) -> Self {
        match value {
            0 => MemoryType::Reserved,
            1 => MemoryType::Available,
            3 => MemoryType::ACPI,
            4 => MemoryType::PreserveOnHibernation,
            5 => MemoryType::Defective,
            _ => MemoryType::Unknown(value),
        }
    }
}

/// メモリマップエントリ
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct MemoryMapEntry {
    /// ベースアドレス
    pub base_addr: u64,
    /// 領域のサイズ
    pub length: u64,
    /// メモリタイプ
    pub typ: u32,
    /// 予約済み
    pub reserved: u32,
}

/// メモリマップタグ
#[derive(Debug)]
#[repr(C, packed)]
pub struct MemoryMapTag {
    /// タグヘッダー
    pub header: TagHeader,
    /// エントリサイズ
    pub entry_size: u32,
    /// エントリバージョン
    pub entry_version: u32,
    // 可変長のエントリが続く
}

/// RGBカラー情報
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct ColorInfo {
    /// 赤チャンネルのビットマスク
    pub red_mask: u32,
    /// 赤チャンネルのシフト量
    pub red_shift: u8,
    /// 赤チャンネルのビット数
    pub red_bits: u8,
    /// 緑チャンネルのビットマスク
    pub green_mask: u32,
    /// 緑チャンネルのシフト量
    pub green_shift: u8,
    /// 緑チャンネルのビット数
    pub green_bits: u8,
    /// 青チャンネルのビットマスク
    pub blue_mask: u32,
    /// 青チャンネルのシフト量
    pub blue_shift: u8,
    /// 青チャンネルのビット数
    pub blue_bits: u8,
}

/// フレームバッファ情報タグ
#[derive(Debug)]
#[repr(C, packed)]
pub struct FramebufferTag {
    /// タグヘッダー
    pub header: TagHeader,
    /// フレームバッファアドレス
    pub addr: u64,
    /// ピッチ（1行のバイト数）
    pub pitch: u32,
    /// 幅（ピクセル単位）
    pub width: u32,
    /// 高さ（ピクセル単位）
    pub height: u32,
    /// ビット深度（1ピクセルあたりのビット数）
    pub bpp: u8,
    /// フレームバッファタイプ
    pub framebuffer_type: u8,
    /// 予約済み
    pub reserved: u16,
    // フレームバッファタイプによって異なるデータが続く
}

/// コマンドラインタグ
#[derive(Debug)]
#[repr(C, packed)]
pub struct CommandLineTag {
    /// タグヘッダー
    pub header: TagHeader,
    // その後に NULL 終端のコマンドライン文字列が続く
}

/// ブートローダー名タグ
#[derive(Debug)]
#[repr(C, packed)]
pub struct BootLoaderNameTag {
    /// タグヘッダー
    pub header: TagHeader,
    // その後に NULL 終端のブートローダー名文字列が続く
}

/// フレームバッファ情報タグ
#[derive(Debug)]
#[repr(C, packed)]
pub struct FramebufferTag {
    /// タグヘッダー
    pub header: TagHeader,
    /// フレームバッファアドレス
    pub addr: u64,
    /// ピッチ（1行のバイト数）
    pub pitch: u32,
    /// 幅（ピクセル単位）
    pub width: u32,
    /// 高さ（ピクセル単位）
    pub height: u32,
    /// ビット深度（1ピクセルあたりのビット数）
    pub bpp: u8,
    /// フレームバッファタイプ
    pub framebuffer_type: u8,
    /// 予約済み
    pub reserved: u16,
    // フレームバッファタイプによって異なるデータが続く
}

/// フレームバッファ情報
#[derive(Debug, Clone)]
pub struct FramebufferInfo {
    pub addr: PhysAddr,
    pub pitch: usize,
    pub width: usize,
    pub height: usize,
    pub bpp: usize,
    pub framebuffer_type: FramebufferType,
    pub color_info: Option<RGBColorInfo>,
}

impl FramebufferInfo {
    /// ピクセルオフセットを計算
    pub fn pixel_offset(&self, x: usize, y: usize) -> usize {
        y * self.pitch + x * (self.bpp / 8)
    }
    
    /// カラー値からRGB値を計算 (RGBタイプの場合)
    pub fn extract_rgb(&self, color: u32) -> Option<(u8, u8, u8)> {
        self.color_info.map(|info| {
            let r = ((color & info.red_mask) >> info.red_shift) as u8;
            let g = ((color & info.green_mask) >> info.green_shift) as u8;
            let b = ((color & info.blue_mask) >> info.blue_shift) as u8;
            (r, g, b)
        })
    }
} 