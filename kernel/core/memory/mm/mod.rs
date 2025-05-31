// AetherOS 高性能メモリ管理システム
//
// 世界最高水準のメモリ管理機能を提供する包括的実装

pub mod page;        // ページ管理
pub mod paging;      // ページングサブシステム
pub mod vmalloc;     // 仮想メモリアロケータ
pub mod vma;         // 仮想メモリ領域
pub mod mmap;        // メモリマッピング
pub mod tlb;         // TLB管理
pub mod hugepage;    // 大ページサポート
pub mod ksm;         // カーネル同一ページマージ
pub mod cow;         // コピーオンライト
pub mod zerocopy;    // ゼロコピー転送
pub mod telepages;   // テレポーテーションページング
pub mod slab;        // スラブアロケータ
pub mod slub;        // SLUBアロケータ

use crate::arch::{MemoryInfo, PageSize, VirtualAddress, PhysicalAddress};
use crate::core::memory::buddy::{allocate_pages, free_pages};
use crate::core::memory::MemoryTier;
use crate::core::process::Process;
use core::ops::Range;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::RwLock;
use log::info;
use core::fmt;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use crate::core::sync::{Mutex, SpinLock};
use std::sync::atomic::AtomicBool;

/// ページフラグ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageFlags {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub user: bool,
    pub cached: bool,
    pub global: bool,
}

impl PageFlags {
    pub fn kernel_code() -> Self {
        Self {
            readable: true,
            writable: false,
            executable: true,
            user: false,
            cached: true,
            global: true,
        }
    }
    
    pub fn kernel_data() -> Self {
        Self {
            readable: true,
            writable: true,
            executable: false,
            user: false,
            cached: true,
            global: true,
        }
    }
    
    pub fn user_code() -> Self {
        Self {
            readable: true,
            writable: false,
            executable: true,
            user: true,
            cached: true,
            global: false,
        }
    }
    
    pub fn user_data() -> Self {
        Self {
            readable: true,
            writable: true,
            executable: false,
            user: true,
            cached: true,
            global: false,
        }
    }
    
    pub fn device() -> Self {
        Self {
            readable: true,
            writable: true,
            executable: false,
            user: false,
            cached: false,
            global: true,
        }
    }
}

impl fmt::Display for PageFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}{}{}",
            if self.readable { "r" } else { "-" },
            if self.writable { "w" } else { "-" },
            if self.executable { "x" } else { "-" },
            if self.user { "u" } else { "-" },
            if self.cached { "c" } else { "-" },
            if self.global { "g" } else { "-" },
        )
    }
}

/// 仮想アドレス空間領域
#[derive(Debug)]
pub struct MemoryRegion {
    pub start: usize,
    pub size: usize,
    pub flags: PageFlags,
    pub name: &'static str,
}

/// メモリ管理統計情報
#[derive(Debug, Default)]
pub struct MemoryStats {
    /// 総物理メモリ量
    pub total_physical: AtomicU64,
    /// 使用可能物理メモリ量
    pub available_physical: AtomicU64,
    /// 使用中物理メモリ量
    pub used_physical: AtomicU64,
    /// カーネルメモリ使用量
    pub kernel_memory: AtomicU64,
    /// ユーザーメモリ使用量
    pub user_memory: AtomicU64,
    /// キャッシュメモリ使用量
    pub cache_memory: AtomicU64,
    /// バッファメモリ使用量
    pub buffer_memory: AtomicU64,
    /// ページフォルト回数
    pub page_faults: AtomicU64,
    /// メジャーページフォルト回数
    pub major_page_faults: AtomicU64,
    /// スワップイン回数
    pub swap_ins: AtomicU64,
    /// スワップアウト回数
    pub swap_outs: AtomicU64,
}

/// ページテーブル最適化統計
#[derive(Debug, Default)]
pub struct PageTableOptimizationStats {
    /// 統合されたページテーブルエントリ数
    pub consolidated_entries: AtomicU64,
    /// 削除された空のページテーブル数
    pub removed_empty_tables: AtomicU64,
    /// TLB最適化回数
    pub tlb_optimizations: AtomicU64,
    /// 最適化実行時間（ナノ秒）
    pub optimization_time_ns: AtomicU64,
}

/// メモリ管理システム
pub struct MemoryManager {
    /// メモリ統計
    stats: MemoryStats,
    /// ページテーブル最適化統計
    pt_stats: PageTableOptimizationStats,
    /// アクティブなページテーブル
    active_page_tables: Mutex<BTreeMap<usize, PageTableInfo>>,
    /// メモリ領域マッピング
    memory_regions: SpinLock<Vec<MemoryRegion>>,
}

/// ページテーブル情報
#[derive(Debug, Clone)]
pub struct PageTableInfo {
    /// ページテーブルの物理アドレス
    pub physical_addr: PhysicalAddress,
    /// レベル（PML4=4, PDPT=3, PD=2, PT=1）
    pub level: u8,
    /// エントリ数
    pub entry_count: usize,
    /// 最後のアクセス時刻
    pub last_access: u64,
    /// 使用中フラグ
    pub in_use: bool,
}

/// メモリ領域情報
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// 開始仮想アドレス
    pub start_vaddr: VirtualAddress,
    /// 終了仮想アドレス
    pub end_vaddr: VirtualAddress,
    /// 物理アドレス（連続領域の場合）
    pub physical_addr: Option<PhysicalAddress>,
    /// 領域タイプ
    pub region_type: MemoryRegionType,
    /// アクセス権限
    pub permissions: MemoryPermissions,
    /// 使用統計
    pub usage_stats: MemoryUsageStats,
}

/// メモリ領域タイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegionType {
    /// カーネルコード
    KernelCode,
    /// カーネルデータ
    KernelData,
    /// カーネルスタック
    KernelStack,
    /// カーネルヒープ
    KernelHeap,
    /// ユーザーコード
    UserCode,
    /// ユーザーデータ
    UserData,
    /// ユーザースタック
    UserStack,
    /// ユーザーヒープ
    UserHeap,
    /// 共有メモリ
    SharedMemory,
    /// デバイスメモリ
    DeviceMemory,
    /// PMEM領域
    PersistentMemory,
}

/// メモリアクセス権限
#[derive(Debug, Clone, Copy)]
pub struct MemoryPermissions {
    /// 読み取り可能
    pub readable: bool,
    /// 書き込み可能
    pub writable: bool,
    /// 実行可能
    pub executable: bool,
    /// ユーザーアクセス可能
    pub user_accessible: bool,
}

/// メモリ使用統計
#[derive(Debug, Clone, Default)]
pub struct MemoryUsageStats {
    /// アクセス回数
    pub access_count: u64,
    /// 最後のアクセス時刻
    pub last_access_time: u64,
    /// ページフォルト回数
    pub page_fault_count: u64,
    /// 書き込み回数
    pub write_count: u64,
}

impl MemoryManager {
    /// 新しいメモリマネージャーを作成
    pub fn new() -> Self {
        Self {
            stats: MemoryStats::default(),
            pt_stats: PageTableOptimizationStats::default(),
            active_page_tables: Mutex::new(BTreeMap::new()),
            memory_regions: SpinLock::new(Vec::new()),
        }
    }
    
    /// メモリ管理システムを初期化
    pub fn init(&self) -> Result<(), &'static str> {
        log::info!("メモリ管理システムを初期化中...");
        
        // 物理メモリ情報を取得
        self.detect_physical_memory()?;
        
        // 初期メモリ領域を設定
        self.setup_initial_regions()?;
        
        // ページテーブル最適化を開始
        self.start_optimization_background_task();
        
        log::info!("メモリ管理システム初期化完了");
        Ok(())
    }
    
    /// 物理メモリを検出
    fn detect_physical_memory(&self) -> Result<(), &'static str> {
        // E820メモリマップまたは他の方法で物理メモリを検出
        let total_memory = self.get_total_physical_memory();
        let available_memory = self.get_available_physical_memory();
        
        self.stats.total_physical.store(total_memory, Ordering::SeqCst);
        self.stats.available_physical.store(available_memory, Ordering::SeqCst);
        
        log::info!("物理メモリ検出完了: 総容量={}MB, 使用可能={}MB", 
                  total_memory / (1024 * 1024), 
                  available_memory / (1024 * 1024));
        
        Ok(())
    }
    
    /// 総物理メモリ量を取得
    fn get_total_physical_memory(&self) -> u64 {
        // E820マップやACPIから物理メモリ情報を取得
        let mut total_memory = 0u64;
        
        // E820メモリマップから取得
        if let Ok(e820_map) = crate::arch::memory::get_e820_memory_map() {
            for entry in e820_map.entries {
                total_memory += entry.length;
            }
            
            log::debug!("E820から総物理メモリ取得: {}MB", total_memory / (1024 * 1024));
            return total_memory;
        }
        
        // ACPIからメモリ情報を取得
        if let Ok(acpi_memory) = crate::arch::acpi::get_total_memory() {
            total_memory = acpi_memory;
            log::debug!("ACPIから総物理メモリ取得: {}MB", total_memory / (1024 * 1024));
            return total_memory;
        }
        
        // DMI/SMBIOSからメモリ情報を取得
        if let Ok(dmi_memory) = crate::arch::dmi::get_total_memory() {
            total_memory = dmi_memory;
            log::debug!("DMIから総物理メモリ取得: {}MB", total_memory / (1024 * 1024));
            return total_memory;
        }
        
        // フォールバック: CPUIDから推定
        #[cfg(target_arch = "x86_64")]
        {
            if let Ok(cpuid_memory) = self.estimate_memory_from_cpuid() {
                total_memory = cpuid_memory;
                log::warn!("CPUIDから総物理メモリ推定: {}MB", total_memory / (1024 * 1024));
                return total_memory;
            }
        }
        
        // 最後の手段: デフォルト値
        total_memory = 4 * 1024 * 1024 * 1024; // 4GB
        log::warn!("デフォルト値を使用: {}MB", total_memory / (1024 * 1024));
        total_memory
    }
    
    /// 使用可能物理メモリ量を取得
    fn get_available_physical_memory(&self) -> u64 {
        // 予約領域を除いた使用可能メモリを計算
        let total_memory = self.get_total_physical_memory();
        let mut available_memory = total_memory;
        
        // カーネル使用領域を除外
        let kernel_memory = self.calculate_kernel_memory_usage();
        available_memory = available_memory.saturating_sub(kernel_memory);
        
        // ファームウェア予約領域を除外
        let firmware_reserved = self.calculate_firmware_reserved_memory();
        available_memory = available_memory.saturating_sub(firmware_reserved);
        
        // ハードウェア予約領域を除外
        let hardware_reserved = self.calculate_hardware_reserved_memory();
        available_memory = available_memory.saturating_sub(hardware_reserved);
        
        // E820予約領域を除外
        if let Ok(e820_map) = crate::arch::memory::get_e820_memory_map() {
            for entry in e820_map.entries {
                if entry.region_type != 1 { // Type 1 = Usable
                    available_memory = available_memory.saturating_sub(entry.length);
                }
            }
        }
        
        // ACPI NVS領域を除外
        if let Ok(acpi_nvs) = crate::arch::acpi::get_nvs_memory_size() {
            available_memory = available_memory.saturating_sub(acpi_nvs);
        }
        
        // UEFI Runtime Services領域を除外
        if let Ok(uefi_runtime) = crate::arch::uefi::get_runtime_services_memory_size() {
            available_memory = available_memory.saturating_sub(uefi_runtime);
        }
        
        log::info!("使用可能物理メモリ: {}MB (総容量: {}MB)", 
                  available_memory / (1024 * 1024), 
                  total_memory / (1024 * 1024));
        
        available_memory
    }
    
    /// カーネルメモリ使用量を計算
    fn calculate_kernel_memory_usage(&self) -> u64 {
        let mut kernel_memory = 0u64;
        
        // カーネルコードセクション
        extern "C" {
            static __text_start: u8;
            static __text_end: u8;
        }
        
        unsafe {
            let text_size = (&__text_end as *const u8 as usize) - (&__text_start as *const u8 as usize);
            kernel_memory += text_size as u64;
        }
        
        // カーネルデータセクション
        extern "C" {
            static __data_start: u8;
            static __data_end: u8;
        }
        
        unsafe {
            let data_size = (&__data_end as *const u8 as usize) - (&__data_start as *const u8 as usize);
            kernel_memory += data_size as u64;
        }
        
        // カーネルBSSセクション
        extern "C" {
            static __bss_start: u8;
            static __bss_end: u8;
        }
        
        unsafe {
            let bss_size = (&__bss_end as *const u8 as usize) - (&__bss_start as *const u8 as usize);
            kernel_memory += bss_size as u64;
        }
        
        // カーネルスタック
        let stack_size = 1024 * 1024; // 1MB per CPU
        let cpu_count = crate::arch::cpu::get_cpu_count();
        kernel_memory += (stack_size * cpu_count) as u64;
        
        // カーネルヒープ（動的割り当て）
        if let Ok(heap_usage) = crate::core::memory::heap::get_current_usage() {
            kernel_memory += heap_usage;
        }
        
        log::debug!("カーネルメモリ使用量: {}MB", kernel_memory / (1024 * 1024));
        kernel_memory
    }
    
    /// ファームウェア予約メモリを計算
    fn calculate_firmware_reserved_memory(&self) -> u64 {
        let mut reserved = 0u64;
        
        // BIOS/UEFI予約領域
        reserved += 1024 * 1024; // 1MB for BIOS
        
        // UEFI Runtime Services
        if let Ok(uefi_size) = crate::arch::uefi::get_runtime_services_size() {
            reserved += uefi_size;
        }
        
        // ACPI Tables
        if let Ok(acpi_size) = crate::arch::acpi::get_tables_size() {
            reserved += acpi_size;
        }
        
        // SMM (System Management Mode)
        reserved += 2 * 1024 * 1024; // 2MB for SMM
        
        log::debug!("ファームウェア予約メモリ: {}MB", reserved / (1024 * 1024));
        reserved
    }
    
    /// ハードウェア予約メモリを計算
    fn calculate_hardware_reserved_memory(&self) -> u64 {
        let mut reserved = 0u64;
        
        // DMA領域
        reserved += 16 * 1024 * 1024; // 16MB for DMA
        
        // PCIデバイス用メモリマップドI/O
        if let Ok(pci_memory) = crate::drivers::pci::get_total_memory_usage() {
            reserved += pci_memory;
        }
        
        // グラフィックスメモリ
        if let Ok(gpu_memory) = crate::drivers::graphics::get_reserved_memory() {
            reserved += gpu_memory;
        }
        
        // ネットワークデバイスバッファ
        if let Ok(network_memory) = crate::drivers::network::get_buffer_memory() {
            reserved += network_memory;
        }
        
        // USB コントローラー
        if let Ok(usb_memory) = crate::drivers::usb::get_controller_memory() {
            reserved += usb_memory;
        }
        
        log::debug!("ハードウェア予約メモリ: {}MB", reserved / (1024 * 1024));
        reserved
    }
    
    /// CPUIDからメモリサイズを推定
    #[cfg(target_arch = "x86_64")]
    fn estimate_memory_from_cpuid(&self) -> Result<u64, &'static str> {
        // CPUID機能を使用してメモリサイズを推定
        let mut eax: u32;
        let mut ebx: u32;
        let mut ecx: u32;
        let mut edx: u32;
        
        unsafe {
            // CPUID leaf 0x80000008: Physical Address Size
            eax = 0x80000008;
            core::arch::asm!(
                "cpuid",
                inout("eax") eax,
                out("ebx") ebx,
                out("ecx") ecx,
                out("edx") edx,
            );
            
            let physical_address_bits = eax & 0xFF;
            if physical_address_bits > 0 {
                let max_physical_memory = 1u64 << physical_address_bits;
                
                // 実際のメモリは最大値より小さいので、一般的な値で制限
                let estimated_memory = max_physical_memory.min(64 * 1024 * 1024 * 1024); // 最大64GB
                
                log::debug!("CPUID推定メモリ: {}MB (物理アドレスビット: {})", 
                           estimated_memory / (1024 * 1024), physical_address_bits);
                
                return Ok(estimated_memory);
            }
        }
        
        Err("CPUIDからメモリサイズを取得できません")
    }
    
    /// 初期メモリ領域を設定
    fn setup_initial_regions(&self) -> Result<(), &'static str> {
        let mut regions = self.memory_regions.lock();
        
        // カーネルコード領域
        regions.push(MemoryRegion {
            start_vaddr: VirtualAddress::new(0xFFFF_FFFF_8000_0000),
            end_vaddr: VirtualAddress::new(0xFFFF_FFFF_8100_0000),
            physical_addr: Some(PhysicalAddress::new(0x100000)),
            region_type: MemoryRegionType::KernelCode,
            permissions: MemoryPermissions {
                readable: true,
                writable: false,
                executable: true,
                user_accessible: false,
            },
            usage_stats: MemoryUsageStats::default(),
        });
        
        // カーネルデータ領域
        regions.push(MemoryRegion {
            start_vaddr: VirtualAddress::new(0xFFFF_FFFF_8100_0000),
            end_vaddr: VirtualAddress::new(0xFFFF_FFFF_8200_0000),
            physical_addr: Some(PhysicalAddress::new(0x200000)),
            region_type: MemoryRegionType::KernelData,
            permissions: MemoryPermissions {
                readable: true,
                writable: true,
                executable: false,
                user_accessible: false,
            },
            usage_stats: MemoryUsageStats::default(),
        });
        
        // カーネルヒープ領域
        regions.push(MemoryRegion {
            start_vaddr: VirtualAddress::new(0xFFFF_FFFF_C000_0000),
            end_vaddr: VirtualAddress::new(0xFFFF_FFFF_E000_0000),
            physical_addr: None, // 動的割り当て
            region_type: MemoryRegionType::KernelHeap,
            permissions: MemoryPermissions {
                readable: true,
                writable: true,
                executable: false,
                user_accessible: false,
            },
            usage_stats: MemoryUsageStats::default(),
        });
        
        log::debug!("初期メモリ領域設定完了: {}個の領域", regions.len());
        Ok(())
    }
    
    /// ページテーブル最適化のバックグラウンドタスクを開始
    fn start_optimization_background_task(&self) {
        // 定期的にページテーブル最適化を実行するタスクを開始
        log::info!("ページテーブル最適化バックグラウンドタスクを開始");
        
        // タスク実行間隔（5分）
        let optimization_interval = 5 * 60 * 1000; // 5分
        
        // バックグラウンドタスクを作成
        let task = PageTableOptimizationTask {
            interval_ms: optimization_interval,
            last_run: AtomicU64::new(0),
            enabled: AtomicBool::new(true),
        };
        
        // タスクスケジューラーに登録
        if let Err(e) = crate::scheduler::register_background_task(
            "page_table_optimization",
            Box::new(move || {
                if task.enabled.load(Ordering::Relaxed) {
                    let current_time = crate::time::current_time_ms();
                    let last_run = task.last_run.load(Ordering::Relaxed);
                    
                    if current_time - last_run >= task.interval_ms {
                        log::debug!("ページテーブル最適化を実行中...");
                        
                        // 最適化処理を実行
                        if let Err(e) = MEMORY_MANAGER.optimize_page_tables() {
                            log::error!("ページテーブル最適化エラー: {}", e);
                        }
                        
                        task.last_run.store(current_time, Ordering::Relaxed);
                    }
                }
            })
        ) {
            log::error!("ページテーブル最適化タスクの登録に失敗: {}", e);
        } else {
            log::info!("ページテーブル最適化タスクが正常に登録されました");
        }
    }
    
    /// ページテーブルを最適化
    pub fn optimize_page_tables(&self) -> Result<(), &'static str> {
        let start_time = crate::time::current_time_ns();
        
        log::debug!("ページテーブル最適化を開始...");
        
        let mut consolidated_entries = 0u64;
        let mut removed_tables = 0u64;
        let mut tlb_optimizations = 0u64;
        
        // 1. 未使用ページテーブルエントリの統合
        consolidated_entries += self.consolidate_unused_entries()?;
        
        // 2. 空のページテーブルの削除
        removed_tables += self.remove_empty_page_tables()?;
        
        // 3. TLB最適化
        tlb_optimizations += self.optimize_tlb()?;
        
        // 4. ページテーブルキャッシュ最適化
        self.optimize_page_table_cache()?;
        
        let end_time = crate::time::current_time_ns();
        let optimization_time = end_time - start_time;
        
        // 統計情報を更新
        self.pt_stats.consolidated_entries.fetch_add(consolidated_entries, Ordering::SeqCst);
        self.pt_stats.removed_empty_tables.fetch_add(removed_tables, Ordering::SeqCst);
        self.pt_stats.tlb_optimizations.fetch_add(tlb_optimizations, Ordering::SeqCst);
        self.pt_stats.optimization_time_ns.store(optimization_time, Ordering::SeqCst);
        
        log::info!("ページテーブル最適化完了: 統合エントリ={}, 削除テーブル={}, TLB最適化={}, 実行時間={}μs",
                  consolidated_entries, removed_tables, tlb_optimizations, optimization_time / 1000);
        
        Ok(())
    }
    
    /// 未使用ページテーブルエントリを統合
    fn consolidate_unused_entries(&self) -> Result<u64, &'static str> {
        log::trace!("未使用ページテーブルエントリの統合を実行中...");
        
        let mut consolidated_count = 0u64;
        
        // アーキテクチャ固有の実装
        #[cfg(target_arch = "x86_64")]
        {
            consolidated_count += self.consolidate_x86_64_page_tables()?;
        }
        
        log::trace!("エントリ統合完了: {}個のエントリを統合", consolidated_count);
        Ok(consolidated_count)
    }
    
    /// x86_64ページテーブルの統合
    #[cfg(target_arch = "x86_64")]
    fn consolidate_x86_64_page_tables(&self) -> Result<u64, &'static str> {
        let mut consolidated = 0u64;
        
        unsafe {
            // CR3レジスタからページテーブルのベースアドレスを取得
            let mut cr3: u64;
            core::arch::asm!("mov {}, cr3", out(reg) cr3);
            
            let pml4_base = (cr3 & 0xFFFF_FFFF_F000) as *mut u64;
            
            // PML4レベルの最適化
            for pml4_idx in 0..512 {
                let pml4_entry = *pml4_base.add(pml4_idx);
                
                if pml4_entry & 1 == 0 {
                    continue; // Present bit not set
                }
                
                let pdpt_base = ((pml4_entry & 0xFFFF_FFFF_F000) as usize + 0xFFFF_8000_0000_0000) as *mut u64;
                
                // PDPTレベルの最適化
                for pdpt_idx in 0..512 {
                    let pdpt_entry = *pdpt_base.add(pdpt_idx);
                    
                    if pdpt_entry & 1 == 0 {
                        continue;
                    }
                    
                    // 1GBページの統合チェック
                    if self.can_consolidate_to_1gb_page(pdpt_base, pdpt_idx) {
                        self.consolidate_to_1gb_page(pdpt_base, pdpt_idx)?;
                        consolidated += 512; // 512個の2MBページを1個の1GBページに統合
                        continue;
                    }
                    
                    let pd_base = ((pdpt_entry & 0xFFFF_FFFF_F000) as usize + 0xFFFF_8000_0000_0000) as *mut u64;
                    
                    // PDレベルの最適化
                    for pd_idx in 0..512 {
                        let pd_entry = *pd_base.add(pd_idx);
                        
                        if pd_entry & 1 == 0 {
                            continue;
                        }
                        
                        // 2MBページの統合チェック
                        if self.can_consolidate_to_2mb_page(pd_base, pd_idx) {
                            self.consolidate_to_2mb_page(pd_base, pd_idx)?;
                            consolidated += 512; // 512個の4KBページを1個の2MBページに統合
                        }
                    }
                }
            }
        }
        
        Ok(consolidated)
    }
    
    /// 1GBページへの統合が可能かチェック
    #[cfg(target_arch = "x86_64")]
    fn can_consolidate_to_1gb_page(&self, pdpt_base: *mut u64, pdpt_idx: usize) -> bool {
        // 連続する512個の2MBページが同じ属性を持つかチェック
        unsafe {
            let pdpt_entry = *pdpt_base.add(pdpt_idx);
            
            if pdpt_entry & 1 == 0 || pdpt_entry & (1 << 7) != 0 {
                return false; // Present bit not set or already a large page
            }
            
            let pd_base = ((pdpt_entry & 0xFFFF_FFFF_F000) as usize + 0xFFFF_8000_0000_0000) as *mut u64;
            
            // 最初の2MBページエントリの属性を取得
            let first_entry = *pd_base;
            if first_entry & 1 == 0 || first_entry & (1 << 7) == 0 {
                return false; // Not present or not a 2MB page
            }
            
            let base_flags = first_entry & 0xFFF;
            let base_physical = first_entry & 0xFFFF_FFFF_E00000; // 2MB aligned
            
            // 全ての2MBページが連続していて同じ属性を持つかチェック
            for i in 1..512 {
                let entry = *pd_base.add(i);
                
                if entry & 1 == 0 || entry & (1 << 7) == 0 {
                    return false; // Not present or not a 2MB page
                }
                
                let entry_flags = entry & 0xFFF;
                let entry_physical = entry & 0xFFFF_FFFF_E00000;
                let expected_physical = base_physical + (i as u64 * 0x200000); // 2MB increment
                
                if entry_flags != base_flags || entry_physical != expected_physical {
                    return false;
                }
            }
            
            true
        }
    }
    
    /// 1GBページに統合
    #[cfg(target_arch = "x86_64")]
    fn consolidate_to_1gb_page(&self, pdpt_base: *mut u64, pdpt_idx: usize) -> Result<(), &'static str> {
        // 1GBページエントリを作成し、古いページテーブルを解放
        unsafe {
            let pdpt_entry = *pdpt_base.add(pdpt_idx);
            let pd_base = ((pdpt_entry & 0xFFFF_FFFF_F000) as usize + 0xFFFF_8000_0000_0000) as *mut u64;
            
            // 最初の2MBページエントリから物理アドレスと属性を取得
            let first_entry = *pd_base;
            let base_physical = first_entry & 0xFFFF_FFFF_C0000000; // 1GB aligned
            let base_flags = first_entry & 0xFFF;
            
            // 1GBページエントリを作成（PS bit = 1）
            let large_page_entry = base_physical | base_flags | (1 << 7);
            
            // PDPTエントリを更新
            *pdpt_base.add(pdpt_idx) = large_page_entry;
            
            // 古いページディレクトリを解放
            let pd_physical = PhysicalAddress::new(pdpt_entry & 0xFFFF_FFFF_F000);
            self.free_page_table_page(pd_physical)?;
            
            // TLBをフラッシュ（1GB範囲）
            let virtual_base = (pdpt_idx << 30) as u64;
            for i in 0..512 {
                let virtual_addr = virtual_base + (i * 0x200000); // 2MB increments
                core::arch::asm!(
                    "invlpg [{}]",
                    in(reg) virtual_addr,
                    options(nostack, preserves_flags)
                );
            }
            
            log::trace!("1GBページに統合完了: PDPT[{}] -> 0x{:016x}", pdpt_idx, base_physical);
        }
        
        Ok(())
    }
    
    /// 2MBページへの統合が可能かチェック
    #[cfg(target_arch = "x86_64")]
    fn can_consolidate_to_2mb_page(&self, pd_base: *mut u64, pd_idx: usize) -> bool {
        // 連続する512個の4KBページが同じ属性を持つかチェック
        unsafe {
            let pd_entry = *pd_base.add(pd_idx);
            
            if pd_entry & 1 == 0 || pd_entry & (1 << 7) != 0 {
                return false; // Present bit not set or already a large page
            }
            
            let pt_base = ((pd_entry & 0xFFFF_FFFF_F000) as usize + 0xFFFF_8000_0000_0000) as *mut u64;
            
            // 最初のページエントリの属性を取得
            let first_entry = *pt_base;
            if first_entry & 1 == 0 {
                return false;
            }
            
            let base_flags = first_entry & 0xFFF;
            let base_physical = first_entry & 0xFFFF_FFFF_F000;
            
            // 全ての4KBページが連続していて同じ属性を持つかチェック
            for i in 1..512 {
                let entry = *pt_base.add(i);
                
                if entry & 1 == 0 {
                    return false; // Present bit not set
                }
                
                let entry_flags = entry & 0xFFF;
                let entry_physical = entry & 0xFFFF_FFFF_F000;
                let expected_physical = base_physical + (i as u64 * 0x1000);
                
                if entry_flags != base_flags || entry_physical != expected_physical {
                    return false;
                }
            }
            
            true
        }
    }
    
    /// 2MBページに統合
    #[cfg(target_arch = "x86_64")]
    fn consolidate_to_2mb_page(&self, pd_base: *mut u64, pd_idx: usize) -> Result<(), &'static str> {
        // 2MBページエントリを作成し、古いページテーブルを解放
        unsafe {
            let pd_entry = *pd_base.add(pd_idx);
            let pt_base = ((pd_entry & 0xFFFF_FFFF_F000) as usize + 0xFFFF_8000_0000_0000) as *mut u64;
            
            // 最初のページエントリから物理アドレスと属性を取得
            let first_entry = *pt_base;
            let base_physical = first_entry & 0xFFFF_FFFF_F000;
            let base_flags = first_entry & 0xFFF;
            
            // 2MBページエントリを作成（PS bit = 1）
            let large_page_entry = base_physical | base_flags | (1 << 7);
            
            // ページディレクトリエントリを更新
            *pd_base.add(pd_idx) = large_page_entry;
            
            // 古いページテーブルを解放
            let pt_physical = PhysicalAddress::new(pd_entry & 0xFFFF_FFFF_F000);
            self.free_page_table_page(pt_physical)?;
            
            // TLBをフラッシュ
            let virtual_base = (pd_idx << 21) as u64;
            for i in 0..512 {
                let virtual_addr = virtual_base + (i * 0x1000);
                core::arch::asm!(
                    "invlpg [{}]",
                    in(reg) virtual_addr,
                    options(nostack, preserves_flags)
                );
            }
            
            log::trace!("2MBページに統合完了: PD[{}] -> 0x{:016x}", pd_idx, base_physical);
        }
        
        Ok(())
    }
    
    /// 空のページテーブルを削除
    fn remove_empty_page_tables(&self) -> Result<u64, &'static str> {
        log::trace!("空のページテーブルの削除を実行中...");
        
        let mut removed_count = 0u64;
        let mut page_tables = self.active_page_tables.lock();
        
        // 使用されていないページテーブルを特定
        let mut to_remove = Vec::new();
        
        for (&addr, info) in page_tables.iter() {
            if !info.in_use && info.entry_count == 0 {
                // 最後のアクセスから十分時間が経過している場合のみ削除
                let current_time = crate::time::current_time_ns();
                if current_time - info.last_access > 1_000_000_000 { // 1秒
                    to_remove.push(addr);
                }
            }
        }
        
        // 空のページテーブルを削除
        for addr in to_remove {
            if let Some(info) = page_tables.remove(&addr) {
                // 物理ページを解放
                self.free_page_table_page(info.physical_addr)?;
                removed_count += 1;
                
                log::trace!("空のページテーブルを削除: アドレス=0x{:x}, レベル={}", 
                           addr, info.level);
            }
        }
        
        log::trace!("空のページテーブル削除完了: {}個のテーブルを削除", removed_count);
        Ok(removed_count)
    }
    
    /// ページテーブルページを解放
    fn free_page_table_page(&self, physical_addr: PhysicalAddress) -> Result<(), &'static str> {
        // 物理ページアロケータに返却
        log::trace!("ページテーブルページを解放: 物理アドレス=0x{:x}", 
                   physical_addr.as_usize());
        
        // バディアロケータに物理ページを返却
        if let Some(buddy_allocator) = self.get_buddy_allocator() {
            buddy_allocator.free_page(physical_addr)?;
        }
        
        // 統計情報を更新
        self.stats.used_physical.fetch_sub(4096, Ordering::Relaxed);
        self.stats.available_physical.fetch_add(4096, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// TLBを最適化
    fn optimize_tlb(&self) -> Result<u64, &'static str> {
        log::trace!("TLB最適化を実行中...");
        
        let mut optimization_count = 0u64;
        
        // アーキテクチャ固有のTLB最適化
        #[cfg(target_arch = "x86_64")]
        {
            // 選択的TLBフラッシュ
            self.selective_tlb_flush()?;
            optimization_count += 1;
            
            // PCID（Process Context Identifier）最適化
            if self.is_pcid_supported() {
                self.optimize_pcid()?;
                optimization_count += 1;
            }
        }
        
        log::trace!("TLB最適化完了: {}回の最適化を実行", optimization_count);
        Ok(optimization_count)
    }
    
    /// 選択的TLBフラッシュ
    #[cfg(target_arch = "x86_64")]
    fn selective_tlb_flush(&self) -> Result<(), &'static str> {
        // 変更されたページのみをTLBからフラッシュ
        let page_tables = self.active_page_tables.lock();
        let current_time = crate::time::current_time_ns();
        
        for (&vaddr, info) in page_tables.iter() {
            // 最近変更されたページテーブルのみフラッシュ
            if current_time - info.last_access < 1_000_000 { // 1ms以内
                unsafe {
                    // 該当する仮想アドレス範囲をフラッシュ
                    let page_size = match info.level {
                        1 => 0x1000,      // 4KB
                        2 => 0x200000,    // 2MB
                        3 => 0x40000000,  // 1GB
                        _ => 0x1000,
                    };
                    
                    for offset in (0..page_size).step_by(0x1000) {
                        let flush_addr = vaddr + offset;
                        core::arch::asm!(
                            "invlpg [{}]",
                            in(reg) flush_addr,
                            options(nostack, preserves_flags)
                        );
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// PCIDサポートをチェック
    #[cfg(target_arch = "x86_64")]
    fn is_pcid_supported(&self) -> bool {
        // CPUID.01H:ECX.PCID[bit 17]をチェック
        unsafe {
            let mut eax: u32;
            let mut ebx: u32;
            let mut ecx: u32;
            let mut edx: u32;
            
            core::arch::asm!(
                "cpuid",
                inout("eax") 1u32 => eax,
                out("ebx") ebx,
                out("ecx") ecx,
                out("edx") edx,
                options(nostack, preserves_flags)
            );
            
            (ecx & (1 << 17)) != 0
        }
    }
    
    /// PCID最適化
    #[cfg(target_arch = "x86_64")]
    fn optimize_pcid(&self) -> Result<(), &'static str> {
        // PCIDを使用してTLBエントリを効率的に管理
        unsafe {
            // CR4.PCIDEビットを有効化
            let mut cr4: u64;
            core::arch::asm!("mov {}, cr4", out(reg) cr4);
            cr4 |= 1 << 17; // PCIDE bit
            core::arch::asm!("mov cr4, {}", in(reg) cr4);
            
            // プロセス固有のPCIDを設定
            let current_process_id = self.get_current_process_id();
            let pcid = (current_process_id & 0xFFF) as u64; // 12-bit PCID
            
            // CR3にPCIDを設定（bit 63をクリアしてTLBフラッシュを回避）
            let mut cr3: u64;
            core::arch::asm!("mov {}, cr3", out(reg) cr3);
            cr3 = (cr3 & 0xFFFFFFFFFFFFF000) | pcid; // Clear PCID bits and set new PCID
            core::arch::asm!("mov cr3, {}", in(reg) cr3);
            
            log::trace!("PCID最適化完了: プロセス={}, PCID={}", current_process_id, pcid);
        }
        
        Ok(())
    }
    
    /// ページテーブルキャッシュを最適化
    fn optimize_page_table_cache(&self) -> Result<(), &'static str> {
        log::trace!("ページテーブルキャッシュ最適化を実行中...");
        
        // キャッシュヒット率を向上させるための最適化
        self.reorganize_page_table_cache()?;
        
        // プリフェッチ最適化
        self.optimize_page_table_prefetch()?;
        
        log::trace!("ページテーブルキャッシュ最適化完了");
        Ok(())
    }
    
    /// ページテーブルキャッシュを再編成
    fn reorganize_page_table_cache(&self) -> Result<(), &'static str> {
        // アクセス頻度に基づいてキャッシュを再編成
        let mut page_tables = self.active_page_tables.lock();
        let current_time = crate::time::current_time_ns();
        
        // アクセス頻度でソート
        let mut sorted_tables: Vec<_> = page_tables.iter().collect();
        sorted_tables.sort_by(|a, b| {
            let freq_a = a.1.access_count as f64 / (current_time - a.1.last_access + 1) as f64;
            let freq_b = b.1.access_count as f64 / (current_time - b.1.last_access + 1) as f64;
            freq_b.partial_cmp(&freq_a).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        // 高頻度アクセスのページテーブルを優先的にキャッシュ
        for (i, (&addr, info)) in sorted_tables.iter().enumerate() {
            if i < 64 { // 上位64個を高優先度キャッシュに配置
                self.set_page_table_cache_priority(addr, CachePriority::High)?;
            } else if i < 256 { // 次の192個を中優先度に
                self.set_page_table_cache_priority(addr, CachePriority::Medium)?;
            } else { // 残りは低優先度
                self.set_page_table_cache_priority(addr, CachePriority::Low)?;
            }
        }
        
        Ok(())
    }
    
    /// ページテーブルプリフェッチを最適化
    fn optimize_page_table_prefetch(&self) -> Result<(), &'static str> {
        // アクセスパターンに基づいてプリフェッチを最適化
        let page_tables = self.active_page_tables.lock();
        
        for (&addr, info) in page_tables.iter() {
            // 連続アクセスパターンを検出
            if self.detect_sequential_access_pattern(addr)? {
                // 次のページテーブルをプリフェッチ
                let next_addr = addr + self.get_page_table_size(info.level);
                self.prefetch_page_table(next_addr)?;
            }
            
            // ランダムアクセスパターンの場合は関連ページテーブルをプリフェッチ
            if self.detect_random_access_pattern(addr)? {
                let related_addrs = self.get_related_page_table_addresses(addr, info.level)?;
                for related_addr in related_addrs {
                    self.prefetch_page_table(related_addr)?;
                }
            }
        }
        
        Ok(())
    }
    
    /// メモリ統計を更新
    pub fn update_memory_statistics(&self) -> Result<(), &'static str> {
        log::trace!("メモリ統計を更新中...");
        
        // バディアロケータ統計を更新
        self.update_buddy_allocator_stats()?;
        
        // SLUBアロケータ統計を更新
        self.update_slub_allocator_stats()?;
        
        // テラページアロケータ統計を更新
        self.update_telepage_allocator_stats()?;
        
        // システム全体の統計を計算
        self.calculate_system_memory_stats()?;
        
        log::trace!("メモリ統計更新完了");
        Ok(())
    }
    
    /// バディアロケータ統計を更新
    fn update_buddy_allocator_stats(&self) -> Result<(), &'static str> {
        // バディアロケータから統計情報を取得
        if let Some(buddy_allocator) = self.get_buddy_allocator() {
            let buddy_stats = buddy_allocator.get_statistics()?;
            
            self.stats.used_physical.store(buddy_stats.used_bytes, Ordering::Relaxed);
            self.stats.available_physical.store(buddy_stats.free_bytes, Ordering::Relaxed);
            
            // フラグメンテーション情報を更新
            let fragmentation_ratio = buddy_stats.fragmentation_ratio;
            if fragmentation_ratio > 0.7 {
                log::warn!("バディアロケータの断片化が深刻: {:.2}%", fragmentation_ratio * 100.0);
                // 断片化解消を試行
                buddy_allocator.defragment()?;
            }
            
            log::trace!("バディアロケータ統計更新: 使用={} MB, 利用可能={} MB, 断片化={:.2}%",
                       buddy_stats.used_bytes / (1024 * 1024),
                       buddy_stats.free_bytes / (1024 * 1024),
                       fragmentation_ratio * 100.0);
        }
        
        Ok(())
    }
    
    /// SLUBアロケータ統計を更新
    fn update_slub_allocator_stats(&self) -> Result<(), &'static str> {
        // SLUBアロケータから統計情報を取得
        if let Some(slub_allocator) = self.get_slub_allocator() {
            let slub_stats = slub_allocator.get_statistics()?;
            
            // キャッシュ効率を監視
            let cache_efficiency = slub_stats.cache_hit_rate;
            if cache_efficiency < 0.8 {
                log::warn!("SLUBキャッシュ効率が低下: {:.2}%", cache_efficiency * 100.0);
                // キャッシュサイズを調整
                slub_allocator.adjust_cache_sizes()?;
            }
            
            // スラブ使用率を監視
            for (size_class, usage) in slub_stats.slab_usage.iter() {
                if *usage > 0.9 {
                    log::debug!("SLUBサイズクラス{}の使用率が高い: {:.2}%", size_class, usage * 100.0);
                    // 新しいスラブを事前割り当て
                    slub_allocator.preallocate_slab(*size_class)?;
                }
            }
            
            log::trace!("SLUBアロケータ統計更新: キャッシュ効率={:.2}%, アクティブスラブ={}",
                       cache_efficiency * 100.0, slub_stats.active_slabs);
        }
        
        Ok(())
    }
    
    /// テラページアロケータ統計を更新
    fn update_telepage_allocator_stats(&self) -> Result<(), &'static str> {
        // テラページアロケータから統計情報を取得
        if let Some(telepage_allocator) = self.get_telepage_allocator() {
            let telepage_stats = telepage_allocator.get_statistics()?;
            
            // テラページ使用効率を監視
            let utilization = telepage_stats.utilization_rate;
            if utilization < 0.5 {
                log::warn!("テラページ使用効率が低い: {:.2}%", utilization * 100.0);
                // 未使用テラページを解放
                telepage_allocator.release_unused_pages()?;
            }
            
            // 転送効率を監視
            let transfer_efficiency = telepage_stats.transfer_efficiency;
            if transfer_efficiency < 0.9 {
                log::debug!("テラページ転送効率: {:.2}%", transfer_efficiency * 100.0);
                // 転送アルゴリズムを最適化
                telepage_allocator.optimize_transfer_algorithm()?;
            }
            
            log::trace!("テラページアロケータ統計更新: 使用率={:.2}%, 転送効率={:.2}%",
                       utilization * 100.0, transfer_efficiency * 100.0);
        }
        
        Ok(())
    }
    
    /// システム全体のメモリ統計を計算
    fn calculate_system_memory_stats(&self) -> Result<(), &'static str> {
        let kernel_memory = self.stats.kernel_memory.load(Ordering::Relaxed);
        let user_memory = self.stats.user_memory.load(Ordering::Relaxed);
        let cache_memory = self.stats.cache_memory.load(Ordering::Relaxed);
        let buffer_memory = self.stats.buffer_memory.load(Ordering::Relaxed);
        
        let total_used = kernel_memory + user_memory + cache_memory + buffer_memory;
        self.stats.used_physical.store(total_used, Ordering::SeqCst);
        
        let total_physical = self.stats.total_physical.load(Ordering::Relaxed);
        let available = total_physical.saturating_sub(total_used);
        self.stats.available_physical.store(available, Ordering::SeqCst);
        
        log::trace!("システムメモリ統計: 使用中={}MB, 使用可能={}MB", 
                   total_used / (1024 * 1024), 
                   available / (1024 * 1024));
        
        Ok(())
    }
    
    /// キャッシュクリーンアップを実行
    pub fn cleanup_caches(&self) -> Result<(), &'static str> {
        log::debug!("キャッシュクリーンアップを開始...");
        
        let start_time = crate::time::current_time_ns();
        
        // SLUBキャッシュクリーンアップ
        self.cleanup_slub_cache()?;
        
        // ページキャッシュクリーンアップ
        self.cleanup_page_cache()?;
        
        // バディアロケータクリーンアップ
        self.cleanup_buddy_allocator()?;
        
        let end_time = crate::time::current_time_ns();
        let cleanup_time = end_time - start_time;
        
        log::info!("キャッシュクリーンアップ完了: 実行時間={}μs", cleanup_time / 1000);
        Ok(())
    }
    
    /// SLUBキャッシュをクリーンアップ
    fn cleanup_slub_cache(&self) -> Result<(), &'static str> {
        log::trace!("SLUBキャッシュクリーンアップを実行中...");
        
        // 未使用のSLUBオブジェクトを解放
        if let Some(slub_allocator) = self.get_slub_allocator() {
            // 空のスラブを解放
            let freed_slabs = slub_allocator.free_empty_slabs()?;
            log::debug!("空のスラブを解放: {}個", freed_slabs);
            
            // 部分的に使用されているスラブを統合
            let consolidated_slabs = slub_allocator.consolidate_partial_slabs()?;
            log::debug!("部分スラブを統合: {}個", consolidated_slabs);
            
            // キャッシュサイズを最適化
            slub_allocator.optimize_cache_sizes()?;
            
            // 統計情報を更新
            let stats = slub_allocator.get_statistics()?;
            log::trace!("SLUBクリーンアップ完了: アクティブスラブ={}, メモリ使用量={} KB",
                       stats.active_slabs, stats.memory_usage / 1024);
        }
        
        Ok(())
    }
    
    /// ページキャッシュをクリーンアップ
    fn cleanup_page_cache(&self) -> Result<(), &'static str> {
        log::trace!("ページキャッシュクリーンアップを実行中...");
        
        // 古いページキャッシュエントリを解放
        if let Some(page_cache) = self.get_page_cache() {
            let current_time = crate::time::current_time_ns();
            
            // LRU（Least Recently Used）アルゴリズムで古いページを特定
            let lru_pages = page_cache.get_lru_pages(current_time - 30_000_000_000)?; // 30秒前
            
            let mut freed_pages = 0;
            for page_addr in lru_pages {
                if page_cache.is_page_dirty(page_addr)? {
                    // ダーティページは書き戻し
                    page_cache.writeback_page(page_addr)?;
                }
                
                // ページを解放
                page_cache.free_page(page_addr)?;
                freed_pages += 1;
            }
            
            log::debug!("古いページキャッシュエントリを解放: {}ページ", freed_pages);
            
            // キャッシュ統計を更新
            let cache_stats = page_cache.get_statistics()?;
            log::trace!("ページキャッシュクリーンアップ完了: キャッシュサイズ={} MB, ヒット率={:.2}%",
                       cache_stats.total_size / (1024 * 1024), cache_stats.hit_rate * 100.0);
        }
        
        Ok(())
    }
    
    /// バディアロケータをクリーンアップ
    fn cleanup_buddy_allocator(&self) -> Result<(), &'static str> {
        log::trace!("バディアロケータクリーンアップを実行中...");
        
        // フラグメンテーションを解消
        if let Some(buddy_allocator) = self.get_buddy_allocator() {
            // 隣接する空きブロックを統合
            let consolidated_blocks = buddy_allocator.consolidate_free_blocks()?;
            log::debug!("空きブロックを統合: {}個", consolidated_blocks);
            
            // 大きな空きブロックを作成
            let large_blocks_created = buddy_allocator.create_large_blocks()?;
            log::debug!("大きな空きブロックを作成: {}個", large_blocks_created);
            
            // メモリ圧縮を実行
            if buddy_allocator.get_fragmentation_ratio()? > 0.6 {
                log::info!("メモリ圧縮を実行中...");
                buddy_allocator.compact_memory()?;
            }
            
            // 統計情報を更新
            let buddy_stats = buddy_allocator.get_statistics()?;
            log::trace!("バディアロケータクリーンアップ完了: 断片化率={:.2}%, 最大空きブロック={} KB",
                       buddy_stats.fragmentation_ratio * 100.0,
                       buddy_stats.largest_free_block / 1024);
        }
        
        Ok(())
    }
    
    /// メモリ統計を取得
    pub fn get_memory_statistics(&self) -> MemoryStats {
        MemoryStats {
            total_physical: AtomicU64::new(self.stats.total_physical.load(Ordering::Relaxed)),
            available_physical: AtomicU64::new(self.stats.available_physical.load(Ordering::Relaxed)),
            used_physical: AtomicU64::new(self.stats.used_physical.load(Ordering::Relaxed)),
            kernel_memory: AtomicU64::new(self.stats.kernel_memory.load(Ordering::Relaxed)),
            user_memory: AtomicU64::new(self.stats.user_memory.load(Ordering::Relaxed)),
            cache_memory: AtomicU64::new(self.stats.cache_memory.load(Ordering::Relaxed)),
            buffer_memory: AtomicU64::new(self.stats.buffer_memory.load(Ordering::Relaxed)),
            page_faults: AtomicU64::new(self.stats.page_faults.load(Ordering::Relaxed)),
            major_page_faults: AtomicU64::new(self.stats.major_page_faults.load(Ordering::Relaxed)),
            swap_ins: AtomicU64::new(self.stats.swap_ins.load(Ordering::Relaxed)),
            swap_outs: AtomicU64::new(self.stats.swap_outs.load(Ordering::Relaxed)),
        }
    }
    
    /// ページテーブル最適化統計を取得
    pub fn get_page_table_optimization_stats(&self) -> PageTableOptimizationStats {
        PageTableOptimizationStats {
            consolidated_entries: AtomicU64::new(self.pt_stats.consolidated_entries.load(Ordering::Relaxed)),
            removed_empty_tables: AtomicU64::new(self.pt_stats.removed_empty_tables.load(Ordering::Relaxed)),
            tlb_optimizations: AtomicU64::new(self.pt_stats.tlb_optimizations.load(Ordering::Relaxed)),
            optimization_time_ns: AtomicU64::new(self.pt_stats.optimization_time_ns.load(Ordering::Relaxed)),
        }
    }
    
    /// メモリ診断を実行
    pub fn diagnose_memory_system(&self) {
        let stats = self.get_memory_statistics();
        let pt_stats = self.get_page_table_optimization_stats();
        
        log::info!("=== メモリシステム診断 ===");
        log::info!("総物理メモリ: {}MB", stats.total_physical.load(Ordering::Relaxed) / (1024 * 1024));
        log::info!("使用可能メモリ: {}MB", stats.available_physical.load(Ordering::Relaxed) / (1024 * 1024));
        log::info!("使用中メモリ: {}MB", stats.used_physical.load(Ordering::Relaxed) / (1024 * 1024));
        log::info!("カーネルメモリ: {}MB", stats.kernel_memory.load(Ordering::Relaxed) / (1024 * 1024));
        log::info!("ユーザーメモリ: {}MB", stats.user_memory.load(Ordering::Relaxed) / (1024 * 1024));
        log::info!("キャッシュメモリ: {}MB", stats.cache_memory.load(Ordering::Relaxed) / (1024 * 1024));
        log::info!("バッファメモリ: {}MB", stats.buffer_memory.load(Ordering::Relaxed) / (1024 * 1024));
        log::info!("ページフォルト: {}", stats.page_faults.load(Ordering::Relaxed));
        log::info!("メジャーページフォルト: {}", stats.major_page_faults.load(Ordering::Relaxed));
        
        log::info!("=== ページテーブル最適化統計 ===");
        log::info!("統合エントリ数: {}", pt_stats.consolidated_entries.load(Ordering::Relaxed));
        log::info!("削除テーブル数: {}", pt_stats.removed_empty_tables.load(Ordering::Relaxed));
        log::info!("TLB最適化回数: {}", pt_stats.tlb_optimizations.load(Ordering::Relaxed));
        log::info!("最適化実行時間: {}μs", pt_stats.optimization_time_ns.load(Ordering::Relaxed) / 1000);
        
        // メモリ使用率を計算
        let total = stats.total_physical.load(Ordering::Relaxed);
        let used = stats.used_physical.load(Ordering::Relaxed);
        let usage_percent = if total > 0 { (used * 100) / total } else { 0 };
        
        log::info!("メモリ使用率: {}%", usage_percent);
        
        if usage_percent > 90 {
            log::warn!("メモリ使用率が高くなっています");
        }
    }
}

/// グローバルメモリマネージャー
static MEMORY_MANAGER: once_cell::sync::Lazy<MemoryManager> = 
    once_cell::sync::Lazy::new(|| MemoryManager::new());

/// メモリ管理システムを初期化
pub fn init() -> Result<(), &'static str> {
    log::info!("メモリ管理システムを初期化中...");
    MEMORY_MANAGER.init()
}

/// ページテーブルを最適化
pub fn optimize_page_tables() -> Result<(), &'static str> {
    MEMORY_MANAGER.optimize_page_tables()
}

/// メモリ統計を更新
pub fn update_memory_statistics() -> Result<(), &'static str> {
    MEMORY_MANAGER.update_memory_statistics()
}

/// キャッシュクリーンアップを実行
pub fn cleanup_caches() -> Result<(), &'static str> {
    MEMORY_MANAGER.cleanup_caches()
}

/// メモリ統計を取得
pub fn get_memory_statistics() -> MemoryStats {
    MEMORY_MANAGER.get_memory_statistics()
}

/// ページテーブル最適化統計を取得
pub fn get_page_table_optimization_stats() -> PageTableOptimizationStats {
    MEMORY_MANAGER.get_page_table_optimization_stats()
}

/// メモリ診断を実行
pub fn diagnose_memory_system() {
    MEMORY_MANAGER.diagnose_memory_system()
}

// 新しい構造体定義
struct PageTableOptimizationTask {
    interval_ms: u64,
    last_run: AtomicU64,
    enabled: AtomicBool,
} 