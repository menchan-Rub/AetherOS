// AetherOS バディアロケータ
// 物理メモリページ割り当ての基盤システム

use crate::memory::{AllocFlags, PAGE_SIZE};
use crate::sync::{SpinLock, Mutex};
use core::sync::atomic::{AtomicUsize, Ordering};
use alloc::vec::Vec;

mod block;
mod allocator;
mod api;

pub use allocator::BuddyAllocator;
pub use api::{allocate_pages, free_pages, allocate_huge_pages, free_huge_pages};
pub use block::BuddyBlock;

/// バディシステムの最大オーダー
pub const MAX_ORDER: usize = 11;  // 4KBから8MBまで

/// ゾーン種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneType {
    /// DMA用ゾーン（低メモリ領域）
    DMA,
    /// 通常使用ゾーン
    Normal,
    /// 高メモリ領域
    HighMem,
}

/// メモリゾーン情報
#[derive(Debug, Clone)]
pub struct ZoneInfo {
    /// ゾーン名
    pub name: &'static str,
    
    /// ゾーン種別
    pub zone_type: ZoneType,
    
    /// 開始ページフレーム番号
    pub start_pfn: usize,
    
    /// 終了ページフレーム番号
    pub end_pfn: usize,
    
    /// 総ページ数
    pub total_pages: usize,
    
    /// 空きページ数
    pub free_pages: usize,
}

/// バディ断片化統計
#[derive(Debug, Clone)]
pub struct FragStats {
    /// 総ページ数
    pub total_pages: usize,
    
    /// 空きページ数
    pub free_pages: usize,
    
    /// 最大の連続空き領域（ページ数）
    pub largest_free: usize,
    
    /// 断片化インデックス（0-100）
    /// 0: 断片化なし、100: 完全に断片化
    pub fragmentation_index: usize,
}

/// バディアロケータ統計
#[derive(Debug, Clone)]
pub struct BuddyStats {
    /// 各オーダーの空きブロック数
    pub free_blocks: [usize; MAX_ORDER + 1],
    
    /// 総割り当て数
    pub total_allocs: usize,
    
    /// 総解放数
    pub total_frees: usize,
    
    /// 総ページ数
    pub total_pages: usize,
    
    /// 空きページ数
    pub free_pages: usize,
    
    /// 各ノードの統計情報
    pub nodes: Vec<NodeStats>,
}

/// NUMAノード統計
#[derive(Debug, Clone)]
pub struct NodeStats {
    /// ノードID
    pub node_id: usize,
    
    /// 総ページ数
    pub total_pages: usize,
    
    /// 空きページ数
    pub free_pages: usize,
    
    /// ゾーン情報
    pub zones: Vec<ZoneInfo>,
    
    /// 断片化情報
    pub fragmentation: FragStats,
}

/// バディアロケータ設定
#[derive(Debug, Clone)]
pub struct BuddyConfig {
    /// 先行割り当て率（0.0～1.0）
    pub prefetch_ratio: f32,
    
    /// デフラグ実行のしきい値（0～100%）
    pub defrag_threshold: usize,
    
    /// 連続割り当て最大サイズ（ページ数）
    pub max_contiguous_allocation: usize,
    
    /// バックグラウンドデフラグ有効化
    pub enable_background_defrag: bool,
    
    /// メモリゾーンバランス比率
    pub zone_balance_ratio: [f32; 3], // DMA, Normal, HighMem
}

/// デフォルトのバディ設定
static DEFAULT_CONFIG: BuddyConfig = BuddyConfig {
    prefetch_ratio: 0.1,
    defrag_threshold: 70,
    max_contiguous_allocation: 1024,
    enable_background_defrag: true,
    zone_balance_ratio: [0.1, 0.7, 0.2],
};

/// 現在の設定
static CURRENT_CONFIG: SpinLock<BuddyConfig> = SpinLock::new(BuddyConfig {
    prefetch_ratio: 0.1,
    defrag_threshold: 70,
    max_contiguous_allocation: 1024,
    enable_background_defrag: true,
    zone_balance_ratio: [0.1, 0.7, 0.2],
});

/// グローバルアロケータインスタンス
static mut GLOBAL_ALLOCATOR: Option<allocator::BuddyAllocator> = None;

/// グローバル統計情報
static mut GLOBAL_STATS: BuddyStats = BuddyStats {
    free_blocks: [0; MAX_ORDER + 1],
    total_allocs: 0,
    total_frees: 0,
    total_pages: 0,
    free_pages: 0,
    nodes: Vec::new(),
};

/// バディアロケータ初期化
pub fn init(memory_map: &[crate::arch::MemoryRegion]) -> Result<(), &'static str> {
    // メモリマップを解析
    let usable_regions = memory_map.iter()
        .filter(|region| region.is_usable())
        .collect::<Vec<_>>();
    
    if usable_regions.is_empty() {
        return Err("使用可能なメモリ領域がありません");
    }
    
    // NUMAノード数を取得（簡略化のため1とする）
    let numa_nodes = 1;
    
    // グローバルアロケータを作成
    let allocator = allocator::BuddyAllocator::new(
        usable_regions,
        numa_nodes,
    )?;
    
    // グローバル変数に保存
    unsafe {
        GLOBAL_ALLOCATOR = Some(allocator);
    }
    
    // 初期統計情報を更新
    update_stats();
    
    Ok(())
}

/// 通常ページ（4KB）の割り当て
pub fn allocate_pages(count: usize, flags: AllocFlags, numa_node: u8) -> Result<usize, &'static str> {
    // サイズチェック
    if count == 0 {
        return Err("0ページの割り当ては不可能です");
    }
    
    // グローバルアロケータから割り当て
    let result = unsafe {
        match &mut GLOBAL_ALLOCATOR {
            Some(allocator) => allocator.allocate(count, flags, numa_node as usize),
            None => return Err("バディアロケータが初期化されていません"),
        }
    };
    
    // 成功したら統計情報を更新
    if result.is_ok() {
        unsafe {
            GLOBAL_STATS.total_allocs += 1;
            GLOBAL_STATS.free_pages -= count;
        }
    }
    
    result
}

/// 通常ページの解放
pub fn free_pages(address: usize, count: usize) -> Result<(), &'static str> {
    // アドレスとサイズの検証
    if address == 0 {
        return Err("無効なアドレスです");
    }
    
    if count == 0 {
        return Err("0ページの解放は不正です");
    }
    
    // ページアライメントチェック
    if address % PAGE_SIZE != 0 {
        return Err("アドレスがページアラインされていません");
    }
    
    // グローバルアロケータで解放
    let result = unsafe {
        match &mut GLOBAL_ALLOCATOR {
            Some(allocator) => allocator.free(address, count),
            None => return Err("バディアロケータが初期化されていません"),
        }
    };
    
    // 成功したら統計情報を更新
    if result.is_ok() {
        unsafe {
            GLOBAL_STATS.total_frees += 1;
            GLOBAL_STATS.free_pages += count;
        }
    }
    
    result
}

/// ヒュージページ（2MB）の割り当て
pub fn allocate_huge_pages(count: usize, flags: AllocFlags, numa_node: u8) -> Result<usize, &'static str> {
    // サイズチェック
    if count == 0 {
        return Err("0ページの割り当ては不可能です");
    }
    
    // 通常ページに変換（1ヒュージページ = 512通常ページ）
    let page_count = count * 512;
    
    // ヒュージページフラグを追加
    let huge_flags = flags.merge(AllocFlags::HUGE_PAGE);
    
    // グローバルアロケータから割り当て
    allocate_pages(page_count, huge_flags, numa_node)
}

/// ヒュージページの解放
pub fn free_huge_pages(address: usize, count: usize) -> Result<(), &'static str> {
    // アドレスとサイズの検証
    if address == 0 {
        return Err("無効なアドレスです");
    }
    
    if count == 0 {
        return Err("0ページの解放は不正です");
    }
    
    // ヒュージページアライメントチェック（2MB = 0x200000）
    if address % 0x200000 != 0 {
        return Err("アドレスがヒュージページアラインされていません");
    }
    
    // 通常ページに変換
    let page_count = count * 512;
    
    // グローバルアロケータで解放
    free_pages(address, page_count)
}

/// ギガンティックページ（1GB）の割り当て
pub fn allocate_gigantic_pages(count: usize, flags: AllocFlags, numa_node: u8) -> Result<usize, &'static str> {
    // サイズチェック
    if count == 0 {
        return Err("0ページの割り当ては不可能です");
    }
    
    // 通常ページに変換（1ギガページ = 262144通常ページ）
    let page_count = count * 262144;
    
    // ギガページフラグを追加
    let giga_flags = flags.merge(AllocFlags::GIGANTIC_PAGE);
    
    // グローバルアロケータから割り当て
    allocate_pages(page_count, giga_flags, numa_node)
}

/// ギガンティックページの解放
pub fn free_gigantic_pages(address: usize, count: usize) -> Result<(), &'static str> {
    // アドレスとサイズの検証
    if address == 0 {
        return Err("無効なアドレスです");
    }
    
    if count == 0 {
        return Err("0ページの解放は不正です");
    }
    
    // ギガページアライメントチェック（1GB = 0x40000000）
    if address % 0x40000000 != 0 {
        return Err("アドレスがギガページアラインされていません");
    }
    
    // 通常ページに変換
    let page_count = count * 262144;
    
    // グローバルアロケータで解放
    free_pages(address, page_count)
}

/// 連続した物理ページの割り当て
pub fn allocate_pages_contiguous(count: usize, flags: AllocFlags, numa_node: u8) -> Result<usize, &'static str> {
    // 連続フラグを追加
    let contiguous_flags = flags.merge(AllocFlags::CONTIGUOUS);
    
    // グローバルアロケータから割り当て
    allocate_pages(count, contiguous_flags, numa_node)
}

/// 断片化の分析
pub fn analyze_fragmentation() -> Result<FragStats, &'static str> {
    unsafe {
        match &GLOBAL_ALLOCATOR {
            Some(allocator) => Ok(allocator.analyze_fragmentation()),
            None => Err("バディアロケータが初期化されていません"),
        }
    }
}

/// ゾーン情報の取得
pub fn get_zone_info() -> Vec<ZoneInfo> {
    unsafe {
        match &GLOBAL_ALLOCATOR {
            Some(allocator) => allocator.get_zone_info(),
            None => Vec::new(),
        }
    }
}

/// アロケータ統計の更新
fn update_stats() {
    unsafe {
        match &GLOBAL_ALLOCATOR {
            Some(allocator) => {
                GLOBAL_STATS = allocator.get_stats();
            }
            None => {}
        }
    }
}

/// アロケータ統計の取得
pub fn get_stats() -> BuddyStats {
    update_stats();
    unsafe { GLOBAL_STATS.clone() }
}

/// バディアロケータの設定取得
pub fn get_config() -> BuddyConfig {
    CURRENT_CONFIG.lock().clone()
}

/// バディアロケータの設定更新
pub fn update_config(config: BuddyConfig) {
    let mut current = CURRENT_CONFIG.lock();
    *current = config;
} 