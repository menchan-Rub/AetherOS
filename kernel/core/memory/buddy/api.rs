// AetherOS バディアロケータ API
//
// このモジュールはバディアロケータの公開APIを提供します。
// カーネルのコンポーネントはこのAPIを通じてメモリ割り当てと解放を行います。

use super::{AllocatorStats, BuddyAllocator, BuddyConfig, AllocationFlags, AllocationPriority, ZoneType};
use crate::core::sync::Mutex;
use crate::arch::MemoryInfo;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;
use spin::Once;
use log::{debug, info, warn};

/// グローバルバディアロケータ
static BUDDY_ALLOCATOR: Once<Mutex<BuddyAllocator>> = Once::new();
/// 初期化済みフラグ
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// バディアロケータを初期化する
pub fn init(memory_info: &MemoryInfo) -> Result<(), &'static str> {
    // 既に初期化済みの場合は何もしない
    if INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        return Ok(());
    }
    
    // メモリ管理情報からバディアロケータを設定
    let config = BuddyConfig {
        min_addr: memory_info.normal_zone_start,
        max_addr: memory_info.normal_zone_start + memory_info.normal_zone_size,
        page_size: 4096, // 通常のページサイズ
        max_order: 11,   // 最大2^11 = 2048ページ
        numa_node: None, // NUMAサポートなし
        zone_type: ZoneType::Normal,
    };
    
    // バディアロケータを作成
    let allocator = BuddyAllocator::new(config);
    
    // アロケータを初期化
    allocator.init()?;
    
    // グローバルアロケータを設定
    BUDDY_ALLOCATOR.call_once(|| {
        info!("バディアロケータが初期化されました");
        Mutex::new(allocator)
    });
    
    // 初期化完了フラグを設定
    INITIALIZED.store(true, core::sync::atomic::Ordering::Release);
    
    Ok(())
}

/// 基本的なページ割り当て関数
/// 
/// # 引数
/// * `num_pages` - 割り当てるページ数
/// 
/// # 戻り値
/// 割り当てられた物理アドレス、または失敗時は None
pub fn allocate_pages(num_pages: usize) -> Option<usize> {
    // デフォルトの割り当てフラグを使用
    let flags = AllocationFlags::default();
    allocate_pages_with_flags(num_pages, flags)
}

/// フラグ付きのページ割り当て関数
/// 
/// # 引数
/// * `num_pages` - 割り当てるページ数
/// * `flags` - 割り当てフラグ
/// 
/// # 戻り値
/// 割り当てられた物理アドレス、または失敗時は None
pub fn allocate_pages_with_flags(num_pages: usize, flags: AllocationFlags) -> Option<usize> {
    if !INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        warn!("バディアロケータが初期化されていません");
        return None;
    }
    
    let allocator = BUDDY_ALLOCATOR.get().unwrap().lock();
    let addr = allocator.allocate_pages(num_pages, flags);
    
    if let Some(addr) = addr {
        debug!("メモリ割り当て: アドレス={:#x}, ページ数={}", addr, num_pages);
    } else {
        warn!("メモリ割り当て失敗: ページ数={}", num_pages);
    }
    
    addr
}

/// ゼロ初期化されたページを割り当て
/// 
/// # 引数
/// * `num_pages` - 割り当てるページ数
/// 
/// # 戻り値
/// 割り当てられたゼロ初期化された物理アドレス、または失敗時は None
pub fn allocate_zeroed_pages(num_pages: usize) -> Option<usize> {
    let mut flags = AllocationFlags::default();
    flags.zero = true;
    allocate_pages_with_flags(num_pages, flags)
}

/// 連続した物理ページを割り当て
/// 
/// # 引数
/// * `num_pages` - 割り当てるページ数
/// 
/// # 戻り値
/// 割り当てられた連続した物理アドレス、または失敗時は None
pub fn allocate_contiguous_pages(num_pages: usize) -> Option<usize> {
    let mut flags = AllocationFlags::default();
    flags.contiguous = true;
    allocate_pages_with_flags(num_pages, flags)
}

/// 物理ページを解放
/// 
/// # 引数
/// * `addr` - 解放する物理アドレス
/// * `num_pages` - 解放するページ数
/// 
/// # 戻り値
/// 成功時は Ok(()), 失敗時はエラーメッセージ
pub fn free_pages(addr: usize, num_pages: usize) -> Result<(), &'static str> {
    if !INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        return Err("バディアロケータが初期化されていません");
    }
    
    let allocator = BUDDY_ALLOCATOR.get().unwrap().lock();
    let result = allocator.free_pages(addr, num_pages);
    
    if result.is_ok() {
        debug!("メモリ解放: アドレス={:#x}, ページ数={}", addr, num_pages);
    } else {
        warn!("メモリ解放失敗: アドレス={:#x}, ページ数={}", addr, num_pages);
    }
    
    result
}

/// バイト数からページ数に変換
/// 
/// # 引数
/// * `bytes` - バイト数
/// 
/// # 戻り値
/// 必要なページ数
pub fn bytes_to_pages(bytes: usize) -> usize {
    (bytes + 4095) / 4096 // 4096 = ページサイズ
}

/// アロケータの統計情報を取得
/// 
/// # 戻り値
/// アロケータの統計情報
pub fn get_stats() -> Option<AllocatorStats> {
    if !INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        return None;
    }
    
    let allocator = BUDDY_ALLOCATOR.get().unwrap().lock();
    Some(allocator.get_stats())
}

/// メモリ使用状況をダンプ（デバッグ用）
pub fn dump_memory_status() {
    if !INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        warn!("バディアロケータが初期化されていません");
        return;
    }
    
    if let Some(stats) = get_stats() {
        info!("=== メモリ状態 ===");
        info!("総メモリ: {} バイト ({} ページ)", stats.total_memory, stats.total_pages);
        info!("使用中: {} バイト ({} ページ)", stats.used_memory, stats.used_pages);
        info!("空き: {} バイト ({} ページ)", stats.free_memory, stats.total_pages - stats.used_pages);
        info!("フラグメンテーション率: {}%", stats.fragmentation_percent);
        info!("===============");
    }
}

/// メモリコンパクションを実行
/// 
/// # 戻り値
/// コンパクションされたブロック数
pub fn compact_memory() -> usize {
    if !INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        warn!("バディアロケータが初期化されていません");
        return 0;
    }
    
    let allocator = BUDDY_ALLOCATOR.get().unwrap().lock();
    let compacted = allocator.compact_memory();
    
    info!("メモリコンパクション: {}ブロックがマージされました", compacted);
    
    compacted
} 