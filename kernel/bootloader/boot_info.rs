// ブート情報構造体モジュール
//
// カーネル初期化に必要なブートローダーからの情報を提供

use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use super::memory_map::{MemoryMap, MemoryRegion};
use super::graphics::FramebufferInfo;

/// ACPIテーブル情報
#[derive(Debug, Clone)]
pub struct AcpiInfo {
    /// RSdp（Root System Description Pointer）の物理アドレス
    pub rsdp_address: usize,
    /// ACPI バージョン（1または2）
    pub version: u8,
}

/// マルチブートモジュール情報
#[derive(Debug, Clone)]
pub struct MultibootModule {
    /// モジュール開始物理アドレス
    pub start: usize,
    /// モジュール終了物理アドレス
    pub end: usize,
    /// モジュール名（コマンドライン引数）
    pub cmdline: String,
}

/// ブートドライブ情報
#[derive(Debug, Clone)]
pub struct BootDriveInfo {
    /// ドライブ番号
    pub drive_number: u8,
    /// パーティション情報
    pub partition: Option<PartitionInfo>,
}

/// パーティション情報
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    /// パーティション番号（1始まり）
    pub number: u8,
    /// パーティション種別
    pub partition_type: u8,
    /// 開始セクタ
    pub start_lba: u64,
    /// セクタ数
    pub sector_count: u64,
}

/// ブート情報構造体
#[derive(Debug, Clone)]
pub struct BootInfo {
    /// メモリマップ
    pub memory_map: MemoryMap,
    /// フレームバッファ情報
    pub framebuffer: Option<FramebufferInfo>,
    /// ACPI情報
    pub acpi: Option<AcpiInfo>,
    /// コマンドライン引数
    pub cmdline: String,
    /// カーネルの物理ロードアドレス
    pub kernel_physical_start: usize,
    /// カーネルの物理終了アドレス
    pub kernel_physical_end: usize,
    /// 初期RAMディスク情報
    pub initrd: Option<(usize, usize)>, // (開始アドレス, サイズ)
    /// マルチブートモジュール
    pub modules: Vec<MultibootModule>,
    /// ブートドライブ情報
    pub boot_drive: Option<BootDriveInfo>,
    /// システムのブートタイプ
    pub boot_type: super::BootType,
    /// 使用可能な物理メモリ合計（バイト）
    pub total_memory: usize,
}

impl BootInfo {
    /// 新しいブート情報構造体の作成
    pub fn new(
        memory_map: MemoryMap,
        framebuffer: Option<FramebufferInfo>,
        acpi: Option<AcpiInfo>,
        cmdline: String,
        boot_type: super::BootType,
    ) -> Self {
        // 使用可能メモリ合計を計算
        let total_memory = memory_map
            .regions()
            .iter()
            .filter(|r| r.is_usable())
            .map(|r| r.length)
            .sum();

        Self {
            memory_map,
            framebuffer,
            acpi,
            cmdline,
            kernel_physical_start: 0,
            kernel_physical_end: 0,
            initrd: None,
            modules: Vec::new(),
            boot_drive: None,
            boot_type,
            total_memory,
        }
    }

    /// テスト環境用の最小限ブート情報の作成
    pub fn create_test_environment() -> Self {
        use super::memory_map::{MemoryRegion, MemoryType};
        
        // シンプルなメモリマップ（テスト用）
        let mut memory_map = MemoryMap::new();
        
        // 1MBのリザーブ領域（従来の低メモリ）
        memory_map.add_region(MemoryRegion {
            base: 0,
            length: 0x100000, // 1MB
            memory_type: MemoryType::Reserved,
        });
        
        // 128MBの使用可能領域（テスト用）
        memory_map.add_region(MemoryRegion {
            base: 0x100000, // 1MB
            length: 0x8000000, // 128MB
            memory_type: MemoryType::Available,
        });
        
        // フレームバッファなし、ACPIなし、コマンドラインなし
        Self::new(
            memory_map,
            None,
            None,
            String::from(""),
            super::BootType::Test,
        )
    }
    
    /// UEFIシステムテーブルから作成
    pub fn from_uefi(
        memory_map: MemoryMap,
        framebuffer: Option<FramebufferInfo>,
        acpi_address: Option<usize>,
        cmdline: String,
    ) -> Self {
        let acpi = acpi_address.map(|addr| AcpiInfo {
            rsdp_address: addr,
            version: 2, // UEFIは通常ACPI 2.0以上
        });
        
        Self::new(
            memory_map,
            framebuffer,
            acpi,
            cmdline,
            super::BootType::Uefi,
        )
    }
    
    /// レガシーBIOSから作成
    pub fn from_legacy(
        memory_map: MemoryMap,
        framebuffer: Option<FramebufferInfo>,
        acpi_address: Option<usize>,
        cmdline: String,
        drive_info: Option<BootDriveInfo>,
    ) -> Self {
        let acpi = acpi_address.map(|addr| AcpiInfo {
            rsdp_address: addr,
            version: 1, // レガシーBIOSはACPI 1.0が多い
        });
        
        let mut info = Self::new(
            memory_map,
            framebuffer,
            acpi,
            cmdline,
            super::BootType::Legacy,
        );
        
        info.boot_drive = drive_info;
        info
    }
    
    /// 初期RAMディスク情報を設定
    pub fn set_initrd(&mut self, start: usize, size: usize) {
        self.initrd = Some((start, size));
    }
    
    /// カーネル物理アドレス範囲を設定
    pub fn set_kernel_physical_range(&mut self, start: usize, end: usize) {
        self.kernel_physical_start = start;
        self.kernel_physical_end = end;
    }
    
    /// モジュールを追加
    pub fn add_module(&mut self, start: usize, end: usize, cmdline: String) {
        self.modules.push(MultibootModule {
            start,
            end,
            cmdline,
        });
    }
} 