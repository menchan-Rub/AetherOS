// AetherOS グローバルメモリアロケータ
//
// 物理/仮想メモリの割り当て統合インターフェースを提供します。
// 複数のアロケーション戦略とバックエンドをサポートし、コンテキストに応じた
// 最適なメモリ割り当てを行います。

use crate::arch::{MemoryInfo, PageSize};
use crate::core::memory::buddy::{self, alloc_pages, free_pages};
use crate::core::memory::slab::{self, ObjectCache};
use crate::core::memory::{pmem, cxl, numa, MemoryTier};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// アロケーション戦略
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AllocationStrategy {
    /// 速度優先（メモリ使用効率より速度を優先）
    SpeedFirst,
    /// メモリ効率優先（断片化を最小限に）
    MemoryEfficient,
    /// 省電力優先（バッテリー駆動時に有効）
    PowerSaving,
    /// レイテンシ優先（応答性重視アプリケーション向け）
    LowLatency,
    /// 可用性優先（耐障害性向上）
    HighAvailability,
    /// パフォーマンス優先（計算集約型アプリケーション向け）
    HighPerformance,
}

/// スモールアロケーションの閾値（この値以下のアロケーションはスラブから割り当て）
const SMALL_ALLOC_THRESHOLD: usize = 4096;

/// 高性能メモリ割り当て用に確保する物理メモリの割合（パーミル単位）
const HIGH_PERFORMANCE_MEMORY_PERMIL: usize = 100; // 10%

/// アロケータ統計
struct AllocatorStats {
    /// 総割り当て回数
    total_allocations: AtomicUsize,
    /// 総解放回数
    total_frees: AtomicUsize,
    /// 現在の割り当てメモリ量
    current_allocated: AtomicUsize,
    /// ピーク時の割り当てメモリ量
    peak_allocated: AtomicUsize, 
    /// スラブ割り当て回数
    slab_allocations: AtomicUsize,
    /// バディ割り当て回数
    buddy_allocations: AtomicUsize,
    /// PMEM割り当て回数
    pmem_allocations: AtomicUsize,
    /// CXL割り当て回数
    cxl_allocations: AtomicUsize,
    /// 割り当て失敗回数
    allocation_failures: AtomicUsize,
}

impl AllocatorStats {
    /// 新しい統計オブジェクトを作成
    fn new() -> Self {
        Self {
            total_allocations: AtomicUsize::new(0),
            total_frees: AtomicUsize::new(0),
            current_allocated: AtomicUsize::new(0),
            peak_allocated: AtomicUsize::new(0),
            slab_allocations: AtomicUsize::new(0),
            buddy_allocations: AtomicUsize::new(0),
            pmem_allocations: AtomicUsize::new(0),
            cxl_allocations: AtomicUsize::new(0),
            allocation_failures: AtomicUsize::new(0),
        }
    }

    /// 割り当てを記録
    fn record_allocation(&self, size: usize, source: AllocSource) {
        self.total_allocations.fetch_add(1, Ordering::Relaxed);
        let current = self.current_allocated.fetch_add(size, Ordering::Relaxed) + size;
        
        // ピーク値の更新
        let mut peak = self.peak_allocated.load(Ordering::Relaxed);
        while current > peak {
            match self.peak_allocated.compare_exchange_weak(
                peak, current, Ordering::Relaxed, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }
        
        // 割り当てソース別のカウント更新
        match source {
            AllocSource::Slab => {
                self.slab_allocations.fetch_add(1, Ordering::Relaxed);
            },
            AllocSource::Buddy => {
                self.buddy_allocations.fetch_add(1, Ordering::Relaxed);
            },
            AllocSource::Pmem => {
                self.pmem_allocations.fetch_add(1, Ordering::Relaxed);
            },
            AllocSource::Cxl => {
                self.cxl_allocations.fetch_add(1, Ordering::Relaxed);
            },
        }
    }

    /// 解放を記録
    fn record_free(&self, size: usize) {
        self.total_frees.fetch_add(1, Ordering::Relaxed);
        self.current_allocated.fetch_sub(size, Ordering::Relaxed);
    }

    /// 割り当て失敗を記録
    fn record_failure(&self) {
        self.allocation_failures.fetch_add(1, Ordering::Relaxed);
    }
}

/// 割り当てソース
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum AllocSource {
    /// スラブアロケータ
    Slab,
    /// バディアロケータ
    Buddy,
    /// 不揮発性メモリ
    Pmem,
    /// CXLメモリ
    Cxl,
}

/// メモリアロケータマネージャ
struct AllocatorManager {
    /// 現在の割り当て戦略
    strategy: RwLock<AllocationStrategy>,
    /// 統計情報
    stats: AllocatorStats,
    /// 汎用オブジェクトキャッシュ
    caches: RwLock<BTreeMap<usize, ObjectCache<u8>>>,
    /// 高性能メモリ領域
    high_perf_regions: RwLock<Vec<(usize, usize)>>, // (開始アドレス, サイズ)
    /// 初期化済みフラグ
    initialized: AtomicUsize,
}

/// グローバルアロケータマネージャ
static ALLOCATOR_MANAGER: AllocatorManager = AllocatorManager {
    strategy: RwLock::new(AllocationStrategy::MemoryEfficient),
    stats: AllocatorStats::new(),
    caches: RwLock::new(BTreeMap::new()),
    high_perf_regions: RwLock::new(Vec::new()),
    initialized: AtomicUsize::new(0),
};

/// アロケータサブシステムの初期化
pub fn init() {
    // 初期化フェンス
    if ALLOCATOR_MANAGER.initialized.load(Ordering::Acquire) != 0 {
        return;
    }

    // 高性能メモリ領域の確保
    reserve_high_performance_memory();
    
    // よく使われるサイズのオブジェクトキャッシュを事前に作成
    let common_sizes = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];
    let mut caches = ALLOCATOR_MANAGER.caches.write();
    
    for &size in &common_sizes {
        let cache_name = alloc::format!("allocator-{}", size);
        if let Ok(cache) = slab::create_cache_raw::<u8>(cache_name.as_str(), size, 8) {
            caches.insert(size, cache);
        }
    }
    
    // 初期化完了
    ALLOCATOR_MANAGER.initialized.store(1, Ordering::Release);
    
    log::info!("グローバルメモリアロケータの初期化完了");
}

/// 高性能メモリ領域を予約
fn reserve_high_performance_memory() {
    // 物理メモリの一部を高性能アロケーション用に確保
    let total_physical = crate::core::memory::get_total_physical();
    let reserve_size = total_physical * HIGH_PERFORMANCE_MEMORY_PERMIL / 1000;
    
    if reserve_size > 0 {
        // バディアロケータから連続した物理メモリを確保
        let page_size = PageSize::Default as usize;
        let num_pages = (reserve_size + page_size - 1) / page_size;
        
        if let Some(pages_start) = buddy::alloc_pages(num_pages, 0) {
            let mut high_perf_regions = ALLOCATOR_MANAGER.high_perf_regions.write();
            high_perf_regions.push((pages_start, num_pages * page_size));
            
            log::info!("高性能メモリ領域を確保: アドレス={:#x}, サイズ={}MB",
                       pages_start, num_pages * page_size / 1024 / 1024);
        }
    }
}

/// メモリ割り当て戦略を設定
pub fn set_allocation_strategy(strategy: AllocationStrategy) {
    if ALLOCATOR_MANAGER.initialized.load(Ordering::Relaxed) != 0 {
        *ALLOCATOR_MANAGER.strategy.write() = strategy;
        log::info!("メモリ割り当て戦略を変更: {:?}", strategy);
    }
}

/// 指定されたサイズのメモリを割り当て
pub fn allocate(size: usize) -> Option<*mut u8> {
    if size == 0 {
        return Some(1 as *mut u8); // ゼロサイズは特殊値を返す
    }
    
    // 現在の割り当て戦略を取得
    let strategy = *ALLOCATOR_MANAGER.strategy.read();
    
    // 戦略に基づいて適切なアロケータを選択
    let result = if size <= SMALL_ALLOC_THRESHOLD {
        allocate_small(size, strategy)
    } else {
        allocate_large(size, strategy)
    };
    
    // 割り当て結果を記録
    match result {
        Some(ptr) => {
            let source = if size <= SMALL_ALLOC_THRESHOLD {
                AllocSource::Slab
            } else {
                AllocSource::Buddy
            };
            ALLOCATOR_MANAGER.stats.record_allocation(size, source);
            Some(ptr)
        },
        None => {
            ALLOCATOR_MANAGER.stats.record_failure();
            None
        }
    }
}

/// 小サイズのメモリを割り当て（スラブベース）
fn allocate_small(size: usize, strategy: AllocationStrategy) -> Option<*mut u8> {
    // サイズを次の2のべき乗に揃える
    let aligned_size = size.next_power_of_two();
    
    // 対応するキャッシュを取得または作成
    let mut caches = ALLOCATOR_MANAGER.caches.write();
    
    if !caches.contains_key(&aligned_size) {
        let cache_name = alloc::format!("allocator-{}", aligned_size);
        if let Ok(cache) = slab::create_cache_raw::<u8>(cache_name.as_str(), aligned_size, 8) {
            caches.insert(aligned_size, cache);
        } else {
            return allocate_from_buddy(size, 8); // キャッシュ作成失敗時はバディから
        }
    }
    
    // キャッシュから割り当て
    let cache = &caches.get(&aligned_size).unwrap();
    match cache.alloc() {
        Ok(obj) => Some(obj as *mut u8),
        Err(_) => allocate_from_buddy(size, 8), // スラブ割り当て失敗時はバディから
    }
}

/// 大サイズのメモリを割り当て（バディベース）
fn allocate_large(size: usize, strategy: AllocationStrategy) -> Option<*mut u8> {
    // 適切なアライメントを計算
    let align = if size > 4096 { 4096 } else { 8 };
    
    // 戦略に基づいてバックエンドを選択
    match strategy {
        AllocationStrategy::SpeedFirst | AllocationStrategy::LowLatency => {
            // 標準DRAMから割り当て
            allocate_from_buddy(size, align)
        },
        AllocationStrategy::MemoryEfficient => {
            // 最適なメモリソースから割り当て
            allocate_from_optimal_source(size, align)
        },
        AllocationStrategy::PowerSaving => {
            // 可能であれば不揮発性メモリから割り当て（省電力）
            if pmem::is_supported() && size > 1024*1024 {
                match pmem::allocate(size) {
                    Some(ptr) => Some(ptr),
                    None => allocate_from_buddy(size, align),
                }
            } else {
                allocate_from_buddy(size, align)
            }
        },
        AllocationStrategy::HighAvailability => {
            // 冗長性のために複数のメモリソースからの割り当てを考慮
            // 簡略化のため単一割り当てを実装
            allocate_from_buddy(size, align)
        },
        AllocationStrategy::HighPerformance => {
            // 高性能予約領域またはNUMAローカルメモリから割り当て
            allocate_high_performance(size, align)
        },
    }
}

/// バディアロケータからメモリを割り当て
fn allocate_from_buddy(size: usize, align: usize) -> Option<*mut u8> {
    let page_size = PageSize::Default as usize;
    
    // アライメントに合わせたページ数を計算
    let aligned_size = (size + align - 1) & !(align - 1);
    let pages = (aligned_size + page_size - 1) / page_size;
    
    // バディアロケータから物理ページを割り当て
    match buddy::alloc_pages(pages, 0) {
        Some(phys_addr) => {
            // 物理ページを仮想アドレス空間にマップ
            let virt_addr = crate::core::memory::mm::map_physical(phys_addr, pages * page_size)
                .unwrap_or(0);
            
            if virt_addr != 0 {
                return Some(virt_addr as *mut u8);
            }
            
            // マッピング失敗時は物理ページを解放
            buddy::free_pages(phys_addr, pages);
            None
        },
        None => None,
    }
}

/// 最適なメモリソースからメモリを割り当て
fn allocate_from_optimal_source(size: usize, align: usize) -> Option<*mut u8> {
    // サイズに基づいて最適なメモリソースを選択
    if size >= 1024 * 1024 && pmem::is_supported() {
        // 大きなアロケーションは不揮発性メモリに
        match pmem::allocate(size) {
            Some(ptr) => return Some(ptr),
            None => {},
        }
    }
    
    if size >= 4096 * 64 && cxl::is_supported() {
        // 中間サイズはCXLメモリに
        match cxl::allocate(size) {
            Some(ptr) => return Some(ptr),
            None => {},
        }
    }
    
    // デフォルトはバディアロケータから
    allocate_from_buddy(size, align)
}

/// 高性能メモリを割り当て
pub fn allocate_high_performance(size: usize, align: usize) -> Option<*mut u8> {
    // まず高性能予約領域からの割り当てを試みる
    let high_perf_regions = ALLOCATOR_MANAGER.high_perf_regions.read();
    if !high_perf_regions.is_empty() {
        // TODO: 予約された高性能領域からサブアロケータを使用してメモリを割り当てる処理を実装する
        // ここでは簡略化のため、予約領域があることを確認するだけ
        log::warn!("allocate_from_optimal_source: High-performance region found, but sub-allocator is not implemented. Falling back.");
    }
    
    // NUMAシステムの場合、現在のCPUに最も近いノードから割り当て
    if numa::is_supported() {
        let current_cpu = crate::arch::get_current_cpu();
        if let Some(node) = numa::get_node_for_cpu(current_cpu) {
            match numa::allocate_on_node(size, node) {
                Some(ptr) => return Some(ptr),
                None => {},
            }
        }
    }
    
    // それ以外の場合はバディアロケータから
    allocate_from_buddy(size, align)
}

/// 指定されたアライメントでメモリを割り当て
pub fn allocate_aligned(size: usize, align: usize) -> Option<*mut u8> {
    if size == 0 {
        return Some(align as *mut u8); // ゼロサイズは特殊値を返す
    }
    
    // アライメントが2のべき乗であることを確認
    if !align.is_power_of_two() {
        return None;
    }
    
    // 小さなアロケーションでアライメントも小さい場合はスラブから
    if size <= SMALL_ALLOC_THRESHOLD && align <= 8 {
        allocate_small(size, *ALLOCATOR_MANAGER.strategy.read())
    } else {
        // それ以外はバディアロケータから
        let result = allocate_from_buddy(size, align);
        
        if let Some(ptr) = result {
            ALLOCATOR_MANAGER.stats.record_allocation(size, AllocSource::Buddy);
        } else {
            ALLOCATOR_MANAGER.stats.record_failure();
        }
        
        result
    }
}

/// メモリを解放
pub fn free(ptr: *mut u8, size: usize) -> Result<(), &'static str> {
    if ptr.is_null() || size == 0 {
        return Ok(());
    }
    
    // ゼロサイズ特殊値の場合
    if ptr as usize <= PageSize::Default as usize {
        return Ok(());
    }
    
    // 物理アドレスの範囲でメモリソースを特定
    let phys_addr = crate::core::memory::mm::virtual_to_physical(ptr as usize)
        .ok_or("無効な仮想アドレス")?;
    
    // PMEMの範囲内かチェック
    if pmem::is_supported() && pmem::is_pmem_address(phys_addr) {
        pmem::free(ptr, size)?;
        ALLOCATOR_MANAGER.stats.record_free(size);
        return Ok(());
    }
    
    // CXLの範囲内かチェック
    if cxl::is_supported() && cxl::is_cxl_address(phys_addr) {
        cxl::free(ptr, size)?;
        ALLOCATOR_MANAGER.stats.record_free(size);
        return Ok(());
    }
    
    // それ以外の場合、サイズに基づいてスラブかバディを選択
    if size <= SMALL_ALLOC_THRESHOLD {
        // スラブアロケータから割り当てられた可能性がある
        let aligned_size = size.next_power_of_two();
        let caches = ALLOCATOR_MANAGER.caches.read();
        
        if let Some(cache) = caches.get(&aligned_size) {
            // キャッシュに返却
            if cache.free(ptr as *mut u8).is_ok() {
                ALLOCATOR_MANAGER.stats.record_free(size);
                return Ok(());
            }
        }
    }
    
    // バディアロケータから割り当てられたとして処理
    free_from_buddy(ptr, size)?;
    ALLOCATOR_MANAGER.stats.record_free(size);
    
    Ok(())
}

/// バディアロケータにメモリを返却
fn free_from_buddy(ptr: *mut u8, size: usize) -> Result<(), &'static str> {
    let page_size = PageSize::Default as usize;
    
    // 仮想アドレスから物理アドレスを取得
    let phys_addr = crate::core::memory::mm::virtual_to_physical(ptr as usize)
        .ok_or("無効な仮想アドレス")?;
    
    // ページ数を計算
    let pages = (size + page_size - 1) / page_size;
    
    // 仮想アドレスのマッピングを解除
    crate::core::memory::mm::unmap_range(ptr as usize, pages * page_size)?;
    
    // 物理ページをバディアロケータに返却
    buddy::free_pages(phys_addr, pages);
    
    Ok(())
}

/// アロケータ統計情報を取得
pub fn get_stats() -> MemoryAllocationStats {
    MemoryAllocationStats {
        total_allocations: ALLOCATOR_MANAGER.stats.total_allocations.load(Ordering::Relaxed),
        total_frees: ALLOCATOR_MANAGER.stats.total_frees.load(Ordering::Relaxed),
        current_allocated: ALLOCATOR_MANAGER.stats.current_allocated.load(Ordering::Relaxed),
        peak_allocated: ALLOCATOR_MANAGER.stats.peak_allocated.load(Ordering::Relaxed),
        slab_allocations: ALLOCATOR_MANAGER.stats.slab_allocations.load(Ordering::Relaxed),
        buddy_allocations: ALLOCATOR_MANAGER.stats.buddy_allocations.load(Ordering::Relaxed),
        pmem_allocations: ALLOCATOR_MANAGER.stats.pmem_allocations.load(Ordering::Relaxed),
        cxl_allocations: ALLOCATOR_MANAGER.stats.cxl_allocations.load(Ordering::Relaxed),
        allocation_failures: ALLOCATOR_MANAGER.stats.allocation_failures.load(Ordering::Relaxed),
    }
}

/// アロケータ統計情報を表示
pub fn print_stats() {
    let stats = get_stats();
    
    log::info!("=== メモリアロケータ統計 ===");
    log::info!("割り当て回数: {}", stats.total_allocations);
    log::info!("解放回数: {}", stats.total_frees);
    log::info!("現在の割り当て: {}KB", stats.current_allocated / 1024);
    log::info!("ピーク時割り当て: {}KB", stats.peak_allocated / 1024);
    log::info!("スラブ割り当て: {}", stats.slab_allocations);
    log::info!("バディ割り当て: {}", stats.buddy_allocations);
    log::info!("PMEM割り当て: {}", stats.pmem_allocations);
    log::info!("CXL割り当て: {}", stats.cxl_allocations);
    log::info!("割り当て失敗: {}", stats.allocation_failures);
    log::info!("===========================");
}

/// メモリ割り当て統計
#[derive(Debug, Clone, Copy)]
pub struct MemoryAllocationStats {
    /// 総割り当て回数
    pub total_allocations: usize,
    /// 総解放回数
    pub total_frees: usize,
    /// 現在の割り当てメモリ量
    pub current_allocated: usize,
    /// ピーク時の割り当てメモリ量
    pub peak_allocated: usize,
    /// スラブ割り当て回数
    pub slab_allocations: usize,
    /// バディ割り当て回数
    pub buddy_allocations: usize,
    /// PMEM割り当て回数
    pub pmem_allocations: usize,
    /// CXL割り当て回数
    pub cxl_allocations: usize,
    /// 割り当て失敗回数
    pub allocation_failures: usize,
} 