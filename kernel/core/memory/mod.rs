// AetherOS メモリ管理サブシステム
//
// 次世代適応型メモリ管理システムを実装します:
// - NUMA/CXL最適化
// - 階層型メモリ（DRAM/PMEM/NVM）統合
// - メモリ安全性保証
// - 予測的ページング
// - データローカリティ分析
// - 空間意識型メモリ配置
// - 分散シャードメモリ

pub mod mm;          // 仮想メモリ管理
pub mod slab;        // スラブアロケータ
pub mod buddy;       // バディアロケータ
pub mod pmem;        // 不揮発性メモリ管理
pub mod numa;        // NUMAサポート
pub mod cxl;         // CXLメモリデバイス管理
pub mod cache;       // メモリキャッシュ管理
pub mod predictor;   // 予測的ページングエンジン
pub mod locality;    // データローカリティ最適化
pub mod allocator;   // グローバルメモリアロケータ
pub mod safety;      // メモリ安全性保証
pub mod telepage;    // テレパージ（遠隔メモリ共有）

use crate::arch::MemoryInfo;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::ptr::NonNull;

/// システム全体のメモリ使用統計
pub struct MemoryStats {
    /// 物理メモリ総量（バイト単位）
    pub total_physical: usize,
    /// 利用可能な物理メモリ（バイト単位）
    pub available_physical: AtomicUsize,
    /// カーネル使用メモリ（バイト単位）
    pub kernel_used: AtomicUsize,
    /// ユーザー空間使用メモリ（バイト単位）
    pub userspace_used: AtomicUsize,
    /// キャッシュに使用されているメモリ（バイト単位）
    pub cache_used: AtomicUsize,
    /// 不揮発性メモリ総量（バイト単位）
    pub total_pmem: usize,
    /// CXLメモリ総量（バイト単位）
    pub total_cxl: usize,
    /// NUMAノード数
    pub numa_node_count: usize,
    /// NUMAノード情報
    pub numa_nodes: Vec<NumaNodeInfo>,
}

/// NUMAノード情報
pub struct NumaNodeInfo {
    /// ノードID
    pub id: usize,
    /// メモリ総量（バイト単位）
    pub memory_total: usize,
    /// 利用可能なメモリ（バイト単位）
    pub memory_available: AtomicUsize,
    /// アクセスレイテンシ（ナノ秒単位）
    pub latency_ns: usize,
    /// ローカルCPUコア
    pub local_cpus: Vec<usize>,
}

/// メモリ階層タイプ
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemoryTier {
    /// 高速DRAM（DDR5, HBM）
    FastDram,
    /// 標準DRAM
    StandardDram,
    /// 不揮発性メモリ（PMEM）
    PersistentMemory,
    /// CXL拡張メモリ
    CxlMemory,
    /// スワップ/仮想メモリ
    SwapMemory,
}

/// グローバルメモリ統計
static mut MEMORY_STATS: Option<MemoryStats> = None;

/// メモリ管理サブシステムの初期化
pub fn init() {
    // アーキテクチャ固有のメモリ情報を取得
    let mem_info = crate::arch::get_memory_info();
    
    // メモリ統計の初期化
    init_memory_stats(&mem_info);
    
    // 物理メモリマネージャの初期化
    buddy::init(&mem_info);
    
    // スラブアロケータの初期化
    slab::init();
    
    // 仮想メモリマネージャの初期化
    mm::init(&mem_info);
    
    // NUMAサポートの初期化（存在する場合）
    if mem_info.numa_supported {
        numa::init(&mem_info);
    }
    
    // CXLメモリサポートの初期化（存在する場合）
    if mem_info.cxl_supported {
        cxl::init(&mem_info);
    }
    
    // 永続メモリサポートの初期化（存在する場合）
    if mem_info.pmem_supported {
        pmem::init(&mem_info);
    }
    
    // キャッシュマネージャの初期化
    cache::init();
    
    // 予測的ページングエンジンの初期化
    predictor::init();
    
    // データローカリティ最適化の初期化
    locality::init();
    
    // グローバルアロケータの初期化
    allocator::init();
    
    // メモリ安全性モジュールの初期化
    safety::init();
    
    log::info!("メモリ管理サブシステム初期化完了: {}MB物理メモリ, {}MBキャッシュ",
               get_total_physical() / 1024 / 1024,
               get_cache_size() / 1024 / 1024);
}

/// メモリ統計の初期化
fn init_memory_stats(mem_info: &MemoryInfo) {
    let mut numa_nodes = Vec::new();
    
    // NUMAノード情報の構築
    if mem_info.numa_supported {
        for i in 0..mem_info.numa_node_count {
            let node_info = NumaNodeInfo {
                id: i,
                memory_total: mem_info.numa_memory_per_node,
                memory_available: AtomicUsize::new(mem_info.numa_memory_per_node),
                latency_ns: mem_info.numa_latency_matrix[i][i],
                local_cpus: mem_info.numa_cpu_map[i].clone(),
            };
            numa_nodes.push(node_info);
        }
    }
    
    // グローバルメモリ統計の構築
    let stats = MemoryStats {
        total_physical: mem_info.total_memory,
        available_physical: AtomicUsize::new(mem_info.total_memory - mem_info.reserved_memory),
        kernel_used: AtomicUsize::new(mem_info.kernel_memory_usage),
        userspace_used: AtomicUsize::new(0),
        cache_used: AtomicUsize::new(0),
        total_pmem: mem_info.pmem_size,
        total_cxl: mem_info.cxl_memory_size,
        numa_node_count: mem_info.numa_node_count,
        numa_nodes,
    };
    
    // 安全ではないが、初期化時に一度だけ呼び出される
    unsafe {
        MEMORY_STATS = Some(stats);
    }
}

/// 物理メモリ総量を取得
pub fn get_total_physical() -> usize {
    unsafe {
        MEMORY_STATS.as_ref().map_or(0, |stats| stats.total_physical)
    }
}

/// 利用可能な物理メモリを取得
pub fn get_available_physical() -> usize {
    unsafe {
        MEMORY_STATS.as_ref().map_or(0, |stats| stats.available_physical.load(Ordering::Relaxed))
    }
}

/// カーネル使用メモリを取得
pub fn get_kernel_used() -> usize {
    unsafe {
        MEMORY_STATS.as_ref().map_or(0, |stats| stats.kernel_used.load(Ordering::Relaxed))
    }
}

/// キャッシュサイズを取得
pub fn get_cache_size() -> usize {
    unsafe {
        MEMORY_STATS.as_ref().map_or(0, |stats| stats.cache_used.load(Ordering::Relaxed))
    }
}

/// メモリ使用を記録
pub fn record_memory_allocation(size: usize, is_kernel: bool) {
    unsafe {
        if let Some(stats) = MEMORY_STATS.as_ref() {
            stats.available_physical.fetch_sub(size, Ordering::Relaxed);
            
            if is_kernel {
                stats.kernel_used.fetch_add(size, Ordering::Relaxed);
            } else {
                stats.userspace_used.fetch_add(size, Ordering::Relaxed);
            }
        }
    }
}

/// メモリ解放を記録
pub fn record_memory_deallocation(size: usize, is_kernel: bool) {
    unsafe {
        if let Some(stats) = MEMORY_STATS.as_ref() {
            stats.available_physical.fetch_add(size, Ordering::Relaxed);
            
            if is_kernel {
                stats.kernel_used.fetch_sub(size, Ordering::Relaxed);
            } else {
                stats.userspace_used.fetch_sub(size, Ordering::Relaxed);
            }
        }
    }
}

/// 特定のメモリ階層に最適なメモリ領域を割り当て
pub fn allocate_in_tier(size: usize, tier: MemoryTier) -> Option<*mut u8> {
    match tier {
        MemoryTier::FastDram => {
            // 高速DRAMからの割り当て
            allocator::allocate_high_performance(size)
        }
        MemoryTier::StandardDram => {
            // 標準DRAMからの割り当て
            allocator::allocate(size)
        }
        MemoryTier::PersistentMemory => {
            // 永続メモリからの割り当て（サポートされている場合）
            if pmem::is_supported() {
                pmem::allocate(size)
            } else {
                allocator::allocate(size)
            }
        }
        MemoryTier::CxlMemory => {
            // CXLメモリからの割り当て（サポートされている場合）
            if cxl::is_supported() {
                cxl::allocate(size)
            } else {
                allocator::allocate(size)
            }
        }
        MemoryTier::SwapMemory => {
            // スワップからの割り当て（最後の手段）
            mm::allocate_with_swap(size)
        }
    }
}

/// 指定されたCPUコアに最も近いメモリを割り当て（NUMAノード最適化）
pub fn allocate_local_to_cpu(size: usize, cpu_id: usize) -> Option<*mut u8> {
    if numa::is_supported() {
        let node_id = numa::get_node_for_cpu(cpu_id);
        numa::allocate_on_node(size, node_id)
    } else {
        allocator::allocate(size)
    }
}

/// グローバルメモリ管理APIの提供
pub struct MemoryManager;

impl MemoryManager {
    /// 指定したサイズのメモリを割り当て
    pub fn allocate(size: usize) -> Option<NonNull<u8>> {
        // サイズに応じて適切なアロケータを選択
        if size <= 8192 {
            // 小さいサイズはスラブアロケータを使用
            slab::SlabAllocatorAPI::allocate(size)
        } else {
            // 大きいサイズはバディアロケータを使用
            buddy::BUDDY_ALLOCATOR.allocate(size)
                .map(|ptr| unsafe { NonNull::new_unchecked(ptr as *mut u8) })
        }
    }
    
    /// メモリを解放
    pub fn free(ptr: NonNull<u8>, size: usize) -> Result<(), &'static str> {
        if size <= 8192 {
            // 小さいサイズはスラブアロケータを使用
            slab::SlabAllocatorAPI::free(ptr, size)
        } else {
            // 大きいサイズはバディアロケータを使用
            buddy::BUDDY_ALLOCATOR.free(ptr.as_ptr() as *mut u8);
            Ok(())
        }
    }
    
    /// 型指定メモリを割り当て
    pub fn allocate_typed<T>() -> Option<NonNull<T>> {
        let size = core::mem::size_of::<T>();
        
        if size <= 8192 {
            // 小さいサイズはスラブアロケータを使用
            slab::SlabAllocatorAPI::allocate_typed::<T>()
        } else {
            // 大きいサイズはバディアロケータを使用
            buddy::BUDDY_ALLOCATOR.allocate(size)
                .map(|ptr| unsafe { NonNull::new_unchecked(ptr as *mut T) })
        }
    }
    
    /// 型指定メモリを解放
    pub fn free_typed<T>(ptr: NonNull<T>) -> Result<(), &'static str> {
        let size = core::mem::size_of::<T>();
        
        if size <= 8192 {
            // 小さいサイズはスラブアロケータを使用
            slab::SlabAllocatorAPI::free_typed::<T>()
        } else {
            // 大きいサイズはバディアロケータを使用
            buddy::BUDDY_ALLOCATOR.free(ptr.as_ptr() as *mut u8);
            Ok(())
        }
    }
    
    /// 専用オブジェクトキャッシュを作成
    pub fn create_object_cache<T>(name: &'static str) -> Result<slab::ObjectCache<T>, &'static str> {
        slab::SlabAllocatorAPI::create_object_cache::<T>(name)
    }
    
    /// メモリ統計情報を出力
    pub fn print_stats() {
        log::info!("===== メモリ統計情報 =====");
        
        // バディアロケータの統計情報
        let buddy_stats = buddy::BUDDY_ALLOCATOR.get_stats();
        log::info!("バディアロケータ:");
        log::info!("  合計メモリ: {} KB", buddy_stats.total_memory / 1024);
        log::info!("  使用メモリ: {} KB", buddy_stats.used_memory / 1024);
        log::info!("  空きメモリ: {} KB", buddy_stats.free_memory / 1024);
        log::info!("  割り当て数: {}", buddy_stats.allocation_count);
        log::info!("  解放数: {}", buddy_stats.free_count);
        
        // スラブアロケータの統計情報は別途実装予定
        
        log::info!("==========================");
    }
} 