// AetherOS ページアロケータ API
//
// このモジュールは物理ページの割り当てと解放のためのAPIを提供します。
// カーネルのメモリ管理システムの基盤となります。

use crate::arch::{PhysicalAddress, PAGE_SIZE as ARCH_PAGE_SIZE};
use crate::core::memory::mm::page::buddy::BuddyAllocator;
use spin::{Mutex, Once};
use log::{debug, info};

/// ページサイズ（バイト単位）
pub const PAGE_SIZE: usize = ARCH_PAGE_SIZE;

/// グローバルバディアロケータ
static GLOBAL_ALLOCATOR: Once<Mutex<BuddyAllocator>> = Once::new();

/// ページアロケータを初期化する
pub fn init() {
    let mut allocator = BuddyAllocator::new();
    allocator.init();
    
    GLOBAL_ALLOCATOR.call_once(|| {
        info!("ページアロケータが初期化されました");
        Mutex::new(allocator)
    });
}

/// 連続した物理ページを割り当てる
///
/// # 引数
/// * `num_pages` - 割り当てるページ数
///
/// # 戻り値
/// * 割り当てが成功した場合は物理アドレス、失敗した場合は `None`
pub fn alloc_pages(num_pages: usize) -> Option<usize> {
    let mut allocator = GLOBAL_ALLOCATOR.get().unwrap().lock();
    let result = allocator.alloc_pages(num_pages);
    
    if let Some(addr) = result {
        debug!("ページ割り当て: アドレス={:#x}, ページ数={}", addr, num_pages);
    } else {
        debug!("ページ割り当て失敗: ページ数={}", num_pages);
    }
    
    result
}

/// 物理ページを解放する
///
/// # 引数
/// * `addr` - 解放する最初のページの物理アドレス
/// * `num_pages` - 解放するページ数
pub fn free_pages(addr: usize, num_pages: usize) {
    let mut allocator = GLOBAL_ALLOCATOR.get().unwrap().lock();
    allocator.free_pages(addr, num_pages);
    debug!("ページ解放: アドレス={:#x}, ページ数={}", addr, num_pages);
}

/// アロケータの状態をダンプする
pub fn dump_stats() {
    let allocator = GLOBAL_ALLOCATOR.get().unwrap().lock();
    let stats = allocator.get_stats();
    
    info!("===== ページアロケータ状態 =====");
    info!("総メモリ: {} KB", stats.total_memory / 1024);
    info!("使用中: {} KB ({}%)", 
         stats.used_memory / 1024,
         stats.used_memory * 100 / stats.total_memory);
    info!("空き: {} KB ({}%)", 
         stats.free_memory / 1024,
         stats.free_memory * 100 / stats.total_memory);
    info!("総ページ数: {}", stats.total_pages);
    info!("使用中ページ: {}", stats.used_pages);
    info!("フラグメンテーション: {}%", stats.fragmentation_percent);
    info!("================================");
}

/// 空きページ数を取得する
pub fn get_free_pages_count() -> usize {
    let allocator = GLOBAL_ALLOCATOR.get().unwrap().lock();
    allocator.get_free_pages_count()
}

/// 使用中ページ数を取得する
pub fn get_used_pages_count() -> usize {
    let allocator = GLOBAL_ALLOCATOR.get().unwrap().lock();
    allocator.get_used_pages_count()
}

/// 総ページ数を取得する
pub fn get_total_pages_count() -> usize {
    let allocator = GLOBAL_ALLOCATOR.get().unwrap().lock();
    allocator.get_total_pages_count()
}

/// 連続した空きページを探す（割り当てなし）
///
/// # 引数
/// * `num_pages` - 必要なページ数
///
/// # 戻り値
/// * 十分な連続ページがある場合は開始アドレス、ない場合は `None`
pub fn find_free_pages(num_pages: usize) -> Option<PhysicalAddress> {
    let allocator = GLOBAL_ALLOCATOR.get().unwrap().lock();
    allocator.find_free_pages(num_pages)
}

/// メモリ領域を予約する（他のアロケータが使用できないようにする）
///
/// # 引数
/// * `start_addr` - 予約する開始物理アドレス
/// * `num_pages` - 予約するページ数
///
/// # 戻り値
/// * 成功した場合は `true`、失敗した場合は `false`
pub fn reserve_memory_region(start_addr: PhysicalAddress, num_pages: usize) -> bool {
    let mut allocator = GLOBAL_ALLOCATOR.get().unwrap().lock();
    let result = allocator.reserve_region(start_addr, num_pages);
    
    if result {
        debug!("メモリ領域予約: 開始={:#x}, ページ数={}", start_addr, num_pages);
    } else {
        debug!("メモリ領域予約失敗: 開始={:#x}, ページ数={}", start_addr, num_pages);
    }
    
    result
}

/// メモリ領域の予約を解除する
///
/// # 引数
/// * `start_addr` - 解除する開始物理アドレス
/// * `num_pages` - 解除するページ数
///
/// # 戻り値
/// * 成功した場合は `true`、失敗した場合は `false`
pub fn unreserve_memory_region(start_addr: PhysicalAddress, num_pages: usize) -> bool {
    let mut allocator = GLOBAL_ALLOCATOR.get().unwrap().lock();
    let result = allocator.unreserve_region(start_addr, num_pages);
    
    if result {
        debug!("メモリ領域予約解除: 開始={:#x}, ページ数={}", start_addr, num_pages);
    } else {
        debug!("メモリ領域予約解除失敗: 開始={:#x}, ページ数={}", start_addr, num_pages);
    }
    
    result
} 