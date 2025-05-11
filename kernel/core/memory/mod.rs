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
pub mod reverse_map; // 物理→仮想アドレス逆引きマップ

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

/// メモリティア（階層）
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryTier {
    /// 高速DRAM（低レイテンシ、高コスト）
    FastDRAM,
    /// 標準DRAM
    StandardDRAM,
    /// 不揮発性メモリ（PMEM、Optane等）
    PMEM,
    /// 拡張メモリ（CXL等）
    ExtendedMemory,
    /// リモートノードメモリ（NUMA）
    RemoteMemory,
    /// スワップ/ストレージバックド
    Storage,
}

/// アドレス空間種別
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AddressSpaceType {
    /// カーネルアドレス空間
    Kernel,
    /// ユーザーアドレス空間
    User,
    /// I/Oアドレス空間
    IO,
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
    
    // 逆引きマップの初期化
    reverse_map::init();
    
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
    
    // テレページの初期化
    telepage::init();
    
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
        MemoryTier::FastDRAM => {
            // 高速DRAMからの割り当て
            allocator::allocate_high_performance(size)
        }
        MemoryTier::StandardDRAM => {
            // 標準DRAMからの割り当て
            allocator::allocate(size)
        }
        MemoryTier::PMEM => {
            // 永続メモリからの割り当て（サポートされている場合）
            if pmem::is_supported() {
                pmem::allocate(size)
            } else {
                allocator::allocate(size)
            }
        }
        MemoryTier::ExtendedMemory => {
            // CXLメモリからの割り当て（サポートされている場合）
            if cxl::is_supported() {
                cxl::allocate(size)
            } else {
                allocator::allocate(size)
            }
        }
        MemoryTier::RemoteMemory => {
            // NUMAメモリからの割り当て
            if numa::is_supported() {
                let node = numa::get_current_node();
                numa::allocate_on_node(size, node)
            } else {
                allocator::allocate(size)
            }
        }
        MemoryTier::Storage => {
            // スワップ/ストレージバックドからの割り当て
            // ここでは標準メモリから割り当てるフォールバック
            allocator::allocate(size)
        }
    }
}

/// 特定のCPUに近いメモリから割り当て
pub fn allocate_local_to_cpu(size: usize, cpu_id: usize) -> Option<*mut u8> {
    // NUMAが有効な場合、指定されたCPUのローカルノードから割り当て
    if numa::is_supported() {
        if let Some(node) = numa::get_node_for_cpu(cpu_id) {
            return numa::allocate_on_node(size, node);
        }
    }
    
    // NUMAが無効か、ノードが見つからない場合は通常の割り当て
        allocator::allocate(size)
}

/// 物理ページから仮想アドレスへの逆引きマップを取得
pub fn get_reverse_mapping() -> &'static reverse_map::PhysicalToVirtualMap {
    reverse_map::get_global_map()
}

/// 予測に基づいてメモリを先読み
pub fn prefetch_memory(addr: *const u8, hint: PrefetchHint) {
    // 予測的ページングエンジンと連携
    if predictor::is_enabled() {
        // アドレスをページフレームに変換
        let page_frame = (addr as usize) / crate::arch::PageSize::Default as usize;
        
        // 現在のプロセスIDを取得
        let process_id = crate::core::process::current_process_id();
        
        // ヒントに基づいて先読み
        match hint {
            PrefetchHint::Read => {
                predictor::record_page_access(page_frame, process_id, false);
                let _ = predictor::prefetch_predicted_pages(page_frame, process_id);
            },
            PrefetchHint::Write => {
                predictor::record_page_access(page_frame, process_id, true);
                let _ = predictor::prefetch_predicted_pages(page_frame, process_id);
            },
            PrefetchHint::Sequential => {
                // 連続アクセスパターンを記録
                predictor::set_prefetch_count(8); // より積極的にプリフェッチ
                let _ = predictor::prefetch_predicted_pages(page_frame, process_id);
            },
            PrefetchHint::Random => {
                // ランダムアクセスパターンを記録
                predictor::set_prefetch_count(2); // 控えめにプリフェッチ
                let _ = predictor::prefetch_predicted_pages(page_frame, process_id);
            },
        }
    }
}

/// プリフェッチヒント
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PrefetchHint {
    /// 読み取りアクセス
    Read,
    /// 書き込みアクセス
    Write,
    /// 連続アクセス
    Sequential,
    /// ランダムアクセス
    Random,
}

/// ページフォルト発生時の処理
pub fn handle_page_fault_event(vaddr: usize, is_write: bool) {
    // 既存のページフォルト処理
    // ...
    
    // 予測的ページングエンジンに通知
    let page_frame = vaddr / crate::arch::PageSize::Default as usize;
    let process_id = crate::core::process::current_process_id();
    
    // ページフォルト情報を予測エンジンに送信
    predictor::handle_page_fault(page_frame, process_id);
}

/// メモリアクセス最適化のためのヒント提供
pub fn hint_memory_access_pattern(addr_range: (usize, usize), pattern: AccessPattern) {
    match pattern {
        AccessPattern::Sequential => {
            // 連続的なアクセスパターン
            predictor::set_prediction_mode(predictor::PredictionMode::Heuristic);
            
            // FileAccessHintの設定
            let file_id = get_file_id_from_range(addr_range.0, addr_range.1);
            if let Some(id) = file_id {
                predictor::register_file_access_hint(id, predictor::FileAccessHint::Sequential);
            }
        },
        AccessPattern::Random => {
            // ランダムアクセスパターン
            predictor::set_prediction_mode(predictor::PredictionMode::Markov);
            
            // FileAccessHintの設定
            let file_id = get_file_id_from_range(addr_range.0, addr_range.1);
            if let Some(id) = file_id {
                predictor::register_file_access_hint(id, predictor::FileAccessHint::Random);
            }
        },
        AccessPattern::ReadMostly => {
            // 読み取り主体のアクセスパターン
            predictor::set_prefetch_enabled(true);
            predictor::set_prefetch_count(8);
        },
        AccessPattern::WriteMostly => {
            // 書き込み主体のアクセスパターン
            predictor::set_prefetch_enabled(true);
            predictor::set_prefetch_count(4);
        },
        AccessPattern::SingleAccess => {
            // 一度だけアクセスするパターン
            predictor::set_prefetch_enabled(false);
            
            // FileAccessHintの設定
            let file_id = get_file_id_from_range(addr_range.0, addr_range.1);
            if let Some(id) = file_id {
                predictor::register_file_access_hint(id, predictor::FileAccessHint::OneTime);
            }
        },
        AccessPattern::MultiStream => {
            // 複数スレッドからのアクセス
            predictor::set_prediction_mode(predictor::PredictionMode::Hybrid);
            
            // FileAccessHintの設定
            let file_id = get_file_id_from_range(addr_range.0, addr_range.1);
            if let Some(id) = file_id {
                predictor::register_file_access_hint(id, predictor::FileAccessHint::MultiStream);
            }
        },
    }
}

/// メモリアクセスパターンの種類
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AccessPattern {
    /// 連続的なアクセス
    Sequential,
    /// ランダムアクセス
    Random,
    /// 読み取り主体
    ReadMostly,
    /// 書き込み主体
    WriteMostly,
    /// 一度だけアクセス
    SingleAccess,
    /// 複数スレッドからアクセス
    MultiStream,
}

/// アドレス範囲からファイルIDを取得
fn get_file_id_from_range(start: usize, end: usize) -> Option<usize> {
    // 実際の実装では、メモリマップドファイルの情報から対応するファイルIDを取得
    // ここでは簡略化のためにダミー実装
    None
}

/// NUMA最適化されたメモリアロケーション
pub fn allocate_numa_optimized(size: usize, process_id: Option<usize>) -> Option<*mut u8> {
    // プロセスのワーキングセットを予測
    let optimal_node = if let Some(pid) = process_id {
        // NUMAノード別のワーキングセットを取得
        let numa_sets = predictor::predict_numa_optimized_working_set(pid, 1000);
        
        // 最大のワーキングセットを持つノードを選択
        numa_sets.iter()
            .max_by_key(|(_, pages)| pages.len())
            .map(|(node, _)| *node)
    } else {
        None
    };
    
    // 最適なNUMAノードからメモリを割り当て
    if let Some(node) = optimal_node {
        numa::allocate_on_node(size, node)
    } else {
        // 通常の割り当て
        allocator::allocate(size)
    }
}

/// スワップアウト候補ページの選択
pub fn select_pages_for_swapout(count: usize) -> Vec<usize> {
    // 予測エンジンからスワップアウト候補を取得
    let candidates = predictor::suggest_swapout_pages(count * 2);
    
    // 実際のスワップアウト対象を選択
    // ここでは単純に候補をそのまま返しているが、
    // 実際の実装ではページの状態（ダーティかどうかなど）も考慮する
    candidates.into_iter().take(count).collect()
}

/// メモリマネージャグローバルインスタンス
pub struct MemoryManager;

impl MemoryManager {
    /// メモリを割り当て
    pub fn allocate(size: usize) -> Option<NonNull<u8>> {
        let ptr = allocator::allocate(size);
        
        // ポインタをNonNullに変換
        ptr.map(|p| unsafe { NonNull::new_unchecked(p) })
    }
    
    /// メモリを解放
    pub fn free(ptr: NonNull<u8>, size: usize) -> Result<(), &'static str> {
        allocator::free(ptr.as_ptr(), size)?;
            Ok(())
    }
    
    /// 型Tのオブジェクトサイズのメモリを割り当て
    pub fn allocate_typed<T>() -> Option<NonNull<T>> {
        let size = core::mem::size_of::<T>();
        let align = core::mem::align_of::<T>();
        
        // サイズが0の場合は特別な処理
        if size == 0 {
            return NonNull::new(align as *mut T);
        }
        
        let ptr = allocator::allocate_aligned(size, align);
        
        // ポインタを変換
        ptr.map(|p| unsafe { NonNull::new_unchecked(p as *mut T) })
    }
    
    /// 型Tのオブジェクトのメモリを解放
    pub fn free_typed<T>(ptr: NonNull<T>) -> Result<(), &'static str> {
        let size = core::mem::size_of::<T>();
        
        // サイズが0の場合は何もしない
        if size == 0 {
            return Ok(());
        }
        
        allocator::free(ptr.as_ptr() as *mut u8, size)?;
            Ok(())
    }
    
    /// 型Tのオブジェクトキャッシュを作成
    pub fn create_object_cache<T>(name: &'static str) -> Result<slab::ObjectCache<T>, &'static str> {
        slab::create_cache(name)
    }
    
    /// メモリ使用統計を表示
    pub fn print_stats() {
        unsafe {
            if let Some(stats) = MEMORY_STATS.as_ref() {
                log::info!("メモリ統計:");
                log::info!("  物理メモリ総量: {}MB", stats.total_physical / 1024 / 1024);
                log::info!("  利用可能物理メモリ: {}MB", stats.available_physical.load(Ordering::Relaxed) / 1024 / 1024);
                log::info!("  カーネル使用メモリ: {}MB", stats.kernel_used.load(Ordering::Relaxed) / 1024 / 1024);
                log::info!("  ユーザー空間メモリ: {}MB", stats.userspace_used.load(Ordering::Relaxed) / 1024 / 1024);
                log::info!("  キャッシュメモリ: {}MB", stats.cache_used.load(Ordering::Relaxed) / 1024 / 1024);
                
                if stats.total_pmem > 0 {
                    log::info!("  不揮発性メモリ: {}MB, 利用可能: {}MB", 
                              stats.total_pmem / 1024 / 1024,
                              pmem::get_available_memory() / 1024 / 1024);
                }
                
                if stats.total_cxl > 0 {
                    log::info!("  CXLメモリ: {}MB, 利用可能: {}MB", 
                              stats.total_cxl / 1024 / 1024,
                              cxl::get_available_memory() / 1024 / 1024);
                }
                
                if stats.numa_node_count > 1 {
                    log::info!("  NUMAノード数: {}", stats.numa_node_count);
                    for node in &stats.numa_nodes {
                        log::info!("    ノード#{}: {}MB/{}MB", 
                                  node.id, 
                                  node.memory_available.load(Ordering::Relaxed) / 1024 / 1024,
                                  node.memory_total / 1024 / 1024);
                    }
                }
                
                // 詳細な統計の表示
                buddy::print_stats();
                slab::print_stats();
                
                if pmem::is_supported() {
                    pmem::print_info();
                }
                
                if cxl::is_supported() {
                    cxl::print_info();
                }
                
                if numa::is_supported() {
                    numa::print_info();
                }
            }
        }
    }
}

/// メモリティアを判定
pub fn determine_memory_tier(phys_addr: usize) -> MemoryTier {
    // NVDIMMの範囲内にあるかチェック
    if pmem::is_supported() && pmem::is_pmem_address(phys_addr) {
        return MemoryTier::PMEM;
    }
    
    // CXLデバイスの範囲内にあるかチェック
    if cxl::is_supported() && cxl::is_cxl_address(phys_addr) {
        return MemoryTier::ExtendedMemory;
    }
    
    // NUMA構成の場合、リモートノードかチェック
    if numa::is_supported() {
        let current_node = numa::get_current_node();
        let addr_node = numa::get_node_for_address(phys_addr);
        
        if let Some(node) = addr_node {
            if node != current_node {
                return MemoryTier::RemoteMemory;
            }
        }
    }
    
    // それ以外は標準DRAMとみなす
    MemoryTier::StandardDRAM
}

/// 特定の物理アドレスが使用中か確認
pub fn is_physical_address_used(phys_addr: usize) -> bool {
    // 物理アドレスを対応するページフレーム番号に変換
    let frame_num = phys_addr / crate::arch::PageSize::Default as usize;
    
    // バディアロケータのフレーム使用状況を確認
    buddy::is_frame_allocated(frame_num)
}

/// カーネルのメモリレイアウト情報を取得
pub fn get_kernel_memory_layout() -> Vec<MemoryRegion> {
    // カーネルのメモリマップを取得
    let mut regions = Vec::new();
    
    // テキストセクション
    regions.push(MemoryRegion {
        start: 0xffffffff80000000,
        size: 0x100000,
        region_type: MemoryRegionType::KernelText,
        name: "kernel_text",
    });
    
    // データセクション
    regions.push(MemoryRegion {
        start: 0xffffffff80100000,
        size: 0x100000,
        region_type: MemoryRegionType::KernelData,
        name: "kernel_data",
    });
    
    // BSS/ヒープ
    regions.push(MemoryRegion {
        start: 0xffffffff80200000,
        size: 0x800000,
        region_type: MemoryRegionType::KernelHeap,
        name: "kernel_heap",
    });
    
    regions
}

/// メモリ領域情報
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// 開始アドレス
    pub start: usize,
    /// サイズ（バイト）
    pub size: usize,
    /// 領域種別
    pub region_type: MemoryRegionType,
    /// 領域名
    pub name: &'static str,
}

/// メモリ領域種別
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemoryRegionType {
    /// カーネルテキスト
    KernelText,
    /// カーネルデータ
    KernelData,
    /// カーネルスタック
    KernelStack,
    /// カーネルヒープ
    KernelHeap,
    /// ユーザーテキスト
    UserText,
    /// ユーザーデータ
    UserData,
    /// ユーザースタック
    UserStack,
    /// 共有メモリ
    SharedMemory,
    /// デバイスメモリ
    DeviceMemory,
    /// 予約済み
    Reserved,
    /// 未使用
    Free,
} 