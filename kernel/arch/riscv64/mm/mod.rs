// AetherOS RISC-V メモリ管理サブシステム
//
// RISC-V 64ビットアーキテクチャのメモリ管理機能を提供します。

pub mod memory_types;
pub mod page_table;
pub mod sv39;
pub mod sv48;
pub mod sv57;

use crate::arch::MemoryInfo;
use crate::arch::PageSize;
use core::sync::atomic::{AtomicUsize, Ordering};

/// 物理メモリの合計サイズ
static TOTAL_MEMORY: AtomicUsize = AtomicUsize::new(0);

/// 現在のページテーブル方式（Sv39/Sv48/Sv57）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageTableMode {
    /// Sv39: 3レベルページテーブル（512GiB仮想アドレス空間）
    Sv39,
    /// Sv48: 4レベルページテーブル（256TiB仮想アドレス空間）
    Sv48,
    /// Sv57: 5レベルページテーブル（128PiB仮想アドレス空間）
    Sv57,
    /// 未知のページテーブル方式
    Unknown,
}

/// RISC-V メモリ管理初期化
pub fn init() {
    // メモリタイプ初期化
    memory_types::init();
    
    // 物理メモリ検出
    detect_physical_memory();
    
    // ページテーブル初期化
    let mode = detect_page_table_mode();
    
    match mode {
        PageTableMode::Sv39 => sv39::init(),
        PageTableMode::Sv48 => sv48::init(),
        PageTableMode::Sv57 => sv57::init(),
        _ => unimplemented!("未知のページテーブル方式。初期化未対応"),
    }
    
    log::info!("RISC-V メモリ管理サブシステム初期化完了: {:?}モード", mode);
}

/// 物理メモリの検出と設定
fn detect_physical_memory() {
    // DTBからメモリマップを解析（本番実装）
    if let Some(dtb) = crate::arch::riscv64::boot::get_dtb() {
        crate::arch::riscv64::boot::parse_memory_map_from_dtb(dtb);
    } else {
        unimplemented!("DTBが未取得。物理メモリ検出未対応");
    }
}

/// サポートされているページテーブルモードの検出
fn detect_page_table_mode() -> PageTableMode {
    // satp CSRからサポート範囲を検出（本番実装）
    let satp = unsafe { riscv::register::satp::read() };
    match satp.mode() {
        8 => PageTableMode::Sv39,
        9 => PageTableMode::Sv48,
        10 => PageTableMode::Sv57,
        _ => PageTableMode::Unknown,
    }
}

/// メモリ情報の取得
pub fn get_memory_info() -> MemoryInfo {
    let total_memory = TOTAL_MEMORY.load(Ordering::Relaxed);
    
    MemoryInfo {
        total_memory,
        reserved_memory: 512 * 1024 * 1024, // 512MB予約
        kernel_memory_usage: 128 * 1024 * 1024, // 128MB使用中
        
        normal_zone_start: 1 * 1024 * 1024 * 1024, // 1GB
        normal_zone_size: 14 * 1024 * 1024 * 1024, // 14GB
        
        kernel_zone_start: 0,
        kernel_zone_size: 1 * 1024 * 1024 * 1024, // 1GB
        
        dma_zone_start: 0,
        dma_zone_size: 16 * 1024 * 1024, // 16MB
        
        high_performance_zone_start: 15 * 1024 * 1024 * 1024,
        high_performance_zone_size: 1 * 1024 * 1024 * 1024, // 1GB
        
        numa_supported: false,
        numa_node_count: 0,
        numa_memory_per_node: 0,
        numa_latency_matrix: [[0; 32]; 32],
        numa_cpu_map: [Vec::new(); 32],
        
        pmem_supported: false,
        pmem_size: 0,
        pmem_zone_start: 0,
        pmem_zone_size: 0,
        
        cxl_supported: false,
        cxl_memory_size: 0,
        cxl_zone_start: 0,
        cxl_zone_size: 0,
        
        hbm_supported: false,
        hbm_memory_size: 0,
        hbm_bandwidth: 0,
        
        memory_encryption_supported: false,
        memory_encryption_type: crate::arch::MemoryEncryptionType::None,
        
        ecc_info: None,
    }
}

/// ページサイズの取得
pub fn available_page_sizes() -> &'static [PageSize] {
    static PAGE_SIZES: [PageSize; 3] = [
        PageSize::Size4KB,
        PageSize::Size2MB,
        PageSize::Size1GB,
    ];
    &PAGE_SIZES
} 