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
use super::{allocate_pages as buddy_allocate, free_pages as buddy_free};
use crate::memory::{AllocFlags, PAGE_SIZE};

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

/// 通常ページ（4KB）の割り当て
/// 
/// # 引数
/// * `count` - 割り当てるページ数
/// * `flags` - 割り当てフラグ
/// * `numa_node` - NUMAノード指定（0は自動選択）
/// 
/// # 戻り値
/// * `Ok(usize)` - 割り当てられたメモリの物理アドレス
/// * `Err(&'static str)` - エラーメッセージ
#[inline]
pub fn allocate_pages(count: usize, flags: AllocFlags, numa_node: u8) -> Result<usize, &'static str> {
    // バディアロケータの実装に委譲
    buddy_allocate(count, flags, numa_node)
}

/// 通常ページの解放
/// 
/// # 引数
/// * `address` - 解放するメモリの物理アドレス
/// * `count` - 解放するページ数
/// 
/// # 戻り値
/// * `Ok(())` - 成功
/// * `Err(&'static str)` - エラーメッセージ
#[inline]
pub fn free_pages(address: usize, count: usize) -> Result<(), &'static str> {
    // バディアロケータの実装に委譲
    buddy_free(address, count)
}

/// 連続した物理ページの割り当て
/// 
/// # 引数
/// * `count` - 割り当てるページ数
/// * `flags` - 割り当てフラグ
/// * `numa_node` - NUMAノード指定（0は自動選択）
/// 
/// # 戻り値
/// * `Ok(usize)` - 割り当てられたメモリの物理アドレス
/// * `Err(&'static str)` - エラーメッセージ
pub fn allocate_pages_contiguous(count: usize, flags: AllocFlags, numa_node: u8) -> Result<usize, &'static str> {
    // CONTIGUOUSフラグを追加
    let contiguous_flags = flags.merge(AllocFlags::CONTIGUOUS);
    
    // バディアロケータで割り当て
    buddy_allocate(count, contiguous_flags, numa_node)
}

/// 指定アライメントを持つページの割り当て
/// 
/// # 引数
/// * `count` - 割り当てるページ数
/// * `alignment` - アライメント（バイト単位、2の累乗である必要あり）
/// * `flags` - 割り当てフラグ
/// * `numa_node` - NUMAノード指定（0は自動選択）
/// 
/// # 戻り値
/// * `Ok(usize)` - 割り当てられたメモリの物理アドレス
/// * `Err(&'static str)` - エラーメッセージ
pub fn allocate_pages_aligned(
    count: usize,
    alignment: usize,
    flags: AllocFlags,
    numa_node: u8,
) -> Result<usize, &'static str> {
    // アライメントが2の累乗かチェック
    if !alignment.is_power_of_two() {
        return Err("アライメントは2の累乗である必要があります");
    }
    
    // アライメントがページサイズ以下の場合は通常の割り当て
    if alignment <= PAGE_SIZE {
        return buddy_allocate(count, flags, numa_node);
    }
    
    // アライメントページ数を計算（ページサイズの倍数に変換）
    let alignment_pages = alignment / PAGE_SIZE;
    
    // 必要なページを多めに割り当て
    let extra_pages = alignment_pages - 1;
    let alloc_count = count + extra_pages;
    
    // 多めに割り当て
    let address = buddy_allocate(alloc_count, flags, numa_node)?;
    
    // アライメントを計算
    let aligned_address = (address + alignment - 1) & !(alignment - 1);
    
    // アドレスが既にアライメントされている場合
    if address == aligned_address {
        return Ok(address);
    }
    
    // 余分なページを解放（前方）
    let front_waste = aligned_address - address;
    if front_waste > 0 {
        let front_waste_pages = front_waste / PAGE_SIZE;
        if front_waste_pages > 0 {
            buddy_free(address, front_waste_pages)?;
        }
    }
    
    // 余分なページを解放（後方）
    let end_address = address + (alloc_count * PAGE_SIZE);
    let aligned_end = aligned_address + (count * PAGE_SIZE);
    let back_waste = end_address - aligned_end;
    if back_waste > 0 {
        let back_waste_pages = back_waste / PAGE_SIZE;
        if back_waste_pages > 0 {
            buddy_free(aligned_end, back_waste_pages)?;
        }
    }
    
    Ok(aligned_address)
}

/// ゼロクリアしたページの割り当て
/// 
/// # 引数
/// * `count` - 割り当てるページ数
/// * `flags` - 割り当てフラグ
/// * `numa_node` - NUMAノード指定（0は自動選択）
/// 
/// # 戻り値
/// * `Ok(usize)` - 割り当てられたメモリの物理アドレス
/// * `Err(&'static str)` - エラーメッセージ
pub fn allocate_zeroed_pages(count: usize, flags: AllocFlags, numa_node: u8) -> Result<usize, &'static str> {
    // ZEROフラグを追加
    let zero_flags = flags.merge(AllocFlags::ZERO);
    
    // バディアロケータで割り当て
    buddy_allocate(count, zero_flags, numa_node)
}

/// DMA用ページの割り当て（32ビットアドレス空間内）
/// 
/// # 引数
/// * `count` - 割り当てるページ数
/// * `flags` - 割り当てフラグ
/// * `numa_node` - NUMAノード指定（0は自動選択）
/// 
/// # 戻り値
/// * `Ok(usize)` - 割り当てられたメモリの物理アドレス
/// * `Err(&'static str)` - エラーメッセージ
pub fn allocate_dma_pages(count: usize, flags: AllocFlags, numa_node: u8) -> Result<usize, &'static str> {
    // DMAフラグを追加
    let dma_flags = flags.merge(AllocFlags::DMA);
    
    // バディアロケータで割り当て
    buddy_allocate(count, dma_flags, numa_node)
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