//! ブートプロトコル関連モジュール
//!
//! 複数のブートプロトコル（UEFI、Multiboot2など）をサポートするためのモジュール。
//! ブートローダーから渡された情報を解析し、カーネルで使いやすい形式に変換します。

mod multiboot2;
mod uefi;

use crate::memory::addr::PhysAddr;
use core::fmt;

/// ブートプロトコルタイプの列挙型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootProtocolType {
    /// UEFIブートプロトコル
    Uefi,
    /// Multiboot2プロトコル
    Multiboot2,
    /// 不明なブートプロトコル
    Unknown,
}

/// ブートパラメータの共通トレイト
pub trait BootParams {
    /// ブートプロトコルのタイプを取得
    fn protocol_type(&self) -> BootProtocolType;
    
    /// コマンドライン文字列を取得
    fn command_line(&self) -> Option<&str>;
    
    /// ブートローダーの名前を取得
    fn bootloader_name(&self) -> Option<&str>;
    
    /// ACPIのRSDPアドレスを取得
    fn acpi_rsdp(&self) -> Option<PhysAddr>;
    
    /// フレームバッファ情報を取得
    fn framebuffer_info(&self) -> Option<FramebufferInfo>;
    
    /// メモリマップ情報を取得
    fn memory_map(&self) -> MemoryMapIterator;
}

/// メモリ領域のタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegionType {
    /// 通常の利用可能なRAM
    Available,
    /// ACPI情報用の領域（解放可能）
    AcpiReclaimable,
    /// ACPI NVS領域（解放不可）
    AcpiNvs,
    /// 予約済み領域（使用不可）
    Reserved,
    /// 不良メモリ領域
    BadMemory,
    /// ブートローダー用領域（使用不可）
    BootloaderReserved,
    /// カーネルとモジュール用領域（使用不可）
    KernelAndModules,
    /// フレームバッファ領域
    Framebuffer,
    /// その他の種類
    Other,
}

/// ブートプロトコルに依存しないメモリマップエントリ
#[derive(Debug, Clone, Copy)]
pub struct MemoryMapEntry {
    /// メモリ領域の物理開始アドレス
    pub start_addr: PhysAddr,
    /// メモリ領域のサイズ（バイト単位）
    pub size: usize,
    /// メモリ領域の種類
    pub region_type: MemoryRegionType,
}

impl fmt::Display for MemoryMapEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let end_addr = self.start_addr.as_usize() + self.size - 1;
        write!(
            f,
            "{:#018x} - {:#018x} ({:#10x} bytes): {:?}",
            self.start_addr.as_usize(),
            end_addr,
            self.size,
            self.region_type
        )
    }
}

/// メモリマップイテレータのトレイト
pub trait MemoryMapIter: Iterator<Item = MemoryMapEntry> {}

/// メモリマップエントリのイテレータ
pub enum MemoryMapIterator {
    /// Multiboot2メモリマップイテレータ
    Multiboot2(multiboot2::MemoryMapIterator),
    /// UEFIメモリマップイテレータ
    Uefi(UefiMemoryMapAdapter),
    /// 空のイテレータ（エラー時）
    Empty,
}

impl Iterator for MemoryMapIterator {
    type Item = MemoryMapEntry;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            MemoryMapIterator::Multiboot2(iter) => iter.next(),
            MemoryMapIterator::Uefi(iter) => iter.next(),
            MemoryMapIterator::Empty => None,
        }
    }
}

/// UEFIメモリマップをMemoryMapEntry形式に変換するアダプタ
pub struct UefiMemoryMapAdapter {
    inner: uefi::EfiMemoryMapIterator,
}

impl UefiMemoryMapAdapter {
    /// 新しいUEFIメモリマップアダプタを作成
    pub fn new(inner: uefi::EfiMemoryMapIterator) -> Self {
        Self { inner }
    }
}

impl Iterator for UefiMemoryMapAdapter {
    type Item = MemoryMapEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|desc| {
            let start_addr = PhysAddr::new(desc.physical_start as usize);
            let size = (desc.number_of_pages as usize) * 4096; // 4KB pages
            let region_type = match uefi::EfiMemoryType::from(desc.memory_type) {
                uefi::EfiMemoryType::ConventionalMemory => MemoryRegionType::Available,
                uefi::EfiMemoryType::AcpiReclaimMemory => MemoryRegionType::AcpiReclaimable,
                uefi::EfiMemoryType::AcpiNvsMemory => MemoryRegionType::AcpiNvs,
                uefi::EfiMemoryType::Unusable => MemoryRegionType::BadMemory,
                uefi::EfiMemoryType::LoaderCode | uefi::EfiMemoryType::LoaderData => {
                    MemoryRegionType::BootloaderReserved
                }
                uefi::EfiMemoryType::BootServicesCode | uefi::EfiMemoryType::BootServicesData => {
                    MemoryRegionType::Available // Boot services memory can be reused after ExitBootServices
                }
                uefi::EfiMemoryType::RuntimeServicesCode | uefi::EfiMemoryType::RuntimeServicesData => {
                    MemoryRegionType::Reserved // Runtime services must remain reserved
                }
                uefi::EfiMemoryType::MmioRegion | uefi::EfiMemoryType::MmioPortSpace => {
                    MemoryRegionType::Reserved
                }
                _ => MemoryRegionType::Reserved,
            };

            MemoryMapEntry {
                start_addr,
                size,
                region_type,
            }
        })
    }
}

/// ピクセルフォーマットの列挙型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// RGBフォーマット
    RGB,
    /// BGRフォーマット
    BGR,
    /// インデックスカラーフォーマット
    Indexed,
    /// その他のフォーマット
    Other,
}

/// ブートプロトコルに依存しないフレームバッファ情報
#[derive(Debug, Clone)]
pub struct FramebufferInfo {
    /// フレームバッファの物理アドレス
    pub addr: PhysAddr,
    /// フレームバッファのサイズ（バイト単位）
    pub size: usize,
    /// 横解像度（ピクセル数）
    pub width: usize,
    /// 縦解像度（ピクセル数）
    pub height: usize,
    /// 1ラインあたりのバイト数
    pub pitch: usize,
    /// 1ピクセルあたりのビット数
    pub bpp: usize,
    /// ピクセルフォーマット
    pub pixel_format: PixelFormat,
}

impl FramebufferInfo {
    /// ピクセルのオフセットを計算
    pub fn pixel_offset(&self, x: usize, y: usize) -> usize {
        y * self.pitch + x * (self.bpp / 8)
    }

    /// Multiboot2のフレームバッファ情報から変換
    pub fn from_multiboot2(mb_fb: &multiboot2::FramebufferTag) -> Self {
        let pixel_format = match mb_fb.framebuffer_type() {
            multiboot2::FramebufferType::RGB => PixelFormat::RGB,
            multiboot2::FramebufferType::IndexedColor => PixelFormat::Indexed,
            _ => PixelFormat::Other,
        };

        Self {
            addr: PhysAddr::new(mb_fb.framebuffer_addr() as usize),
            size: mb_fb.framebuffer_height() as usize * mb_fb.framebuffer_pitch() as usize,
            width: mb_fb.framebuffer_width() as usize,
            height: mb_fb.framebuffer_height() as usize,
            pitch: mb_fb.framebuffer_pitch() as usize,
            bpp: mb_fb.framebuffer_bpp() as usize,
            pixel_format,
        }
    }

    /// UEFIのフレームバッファ情報から変換
    pub fn from_uefi(uefi_fb: &uefi::EfiFramebufferInfo) -> Self {
        let pixel_format = if uefi_fb.is_rgb() {
            PixelFormat::RGB
        } else if uefi_fb.is_bgr() {
            PixelFormat::BGR
        } else {
            PixelFormat::Other
        };

        Self {
            addr: uefi_fb.addr,
            size: uefi_fb.size,
            width: uefi_fb.width,
            height: uefi_fb.height,
            pitch: uefi_fb.pitch,
            bpp: uefi_fb.bpp,
            pixel_format,
        }
    }
}

/// ブート情報
#[derive(Debug)]
pub enum BootInfo {
    /// Multiboot2からのブート情報
    Multiboot2(multiboot2::Multiboot2Parser),
    /// UEFIからのブート情報
    Uefi(uefi::UefiParser),
    /// 不明なブート情報（エラー時）
    Unknown,
}

impl BootInfo {
    /// ブート情報を初期化
    ///
    /// # 安全性
    ///
    /// この関数は、以下の条件が満たされた場合にのみ安全です：
    /// - `boot_info_addr`が有効な物理アドレスを指している
    /// - そのアドレスに適切な形式のブート情報構造体が存在する
    pub unsafe fn init(boot_info_addr: PhysAddr) -> Self {
        // まずMultiboot2かどうかを確認
        if let Some(mb2_info) = multiboot2::check_multiboot2(boot_info_addr) {
            return BootInfo::Multiboot2(multiboot2::Multiboot2Parser::new(mb2_info));
        }

        // 次にUEFIかどうかを確認
        let possible_uefi = boot_info_addr.as_usize() as *const u32;
        if !possible_uefi.is_null() && *possible_uefi == uefi::UEFI_BOOT_MAGIC {
            return BootInfo::Uefi(uefi::UefiParser::new(boot_info_addr));
        }

        // どちらでもない場合は不明
        BootInfo::Unknown
    }

    /// ブートプロトコルのタイプを取得
    pub fn protocol_type(&self) -> BootProtocolType {
        match self {
            BootInfo::Multiboot2(_) => BootProtocolType::Multiboot2,
            BootInfo::Uefi(_) => BootProtocolType::Uefi,
            BootInfo::Unknown => BootProtocolType::Unknown,
        }
    }

    /// コマンドライン文字列を取得
    pub fn command_line(&self) -> Option<&str> {
        match self {
            BootInfo::Multiboot2(parser) => parser.command_line(),
            BootInfo::Uefi(parser) => parser.command_line(),
            BootInfo::Unknown => None,
        }
    }

    /// ブートローダーの名前を取得
    pub fn bootloader_name(&self) -> Option<&str> {
        match self {
            BootInfo::Multiboot2(parser) => parser.bootloader_name(),
            BootInfo::Uefi(_) => Some("UEFI"),
            BootInfo::Unknown => None,
        }
    }

    /// ACPIのRSDPアドレスを取得
    pub fn acpi_rsdp(&self) -> Option<PhysAddr> {
        match self {
            BootInfo::Multiboot2(_) => None, // Multiboot2にはRSDP情報がない
            BootInfo::Uefi(parser) => parser.acpi_rsdp(),
            BootInfo::Unknown => None,
        }
    }

    /// フレームバッファ情報を取得
    pub fn framebuffer_info(&self) -> Option<FramebufferInfo> {
        match self {
            BootInfo::Multiboot2(parser) => {
                parser.framebuffer_info().map(|fb| FramebufferInfo::from_multiboot2(&fb))
            }
            BootInfo::Uefi(parser) => {
                parser.framebuffer_info().map(|fb| FramebufferInfo::from_uefi(&fb))
            }
            BootInfo::Unknown => None,
        }
    }

    /// メモリマップを取得
    pub fn memory_map(&self) -> MemoryMapIterator {
        match self {
            BootInfo::Multiboot2(parser) => {
                MemoryMapIterator::Multiboot2(parser.memory_map())
            }
            BootInfo::Uefi(parser) => {
                MemoryMapIterator::Uefi(UefiMemoryMapAdapter::new(parser.memory_map()))
            }
            BootInfo::Unknown => MemoryMapIterator::Empty,
        }
    }
}