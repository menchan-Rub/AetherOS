// AetherOS TeraPage 実装
// 512GBの巨大ページを管理するモジュール

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use crate::sync::{Mutex, SpinLock, RwLock};
use crate::arch::cpu;
use crate::memory::{PAGE_SIZE, TERA_PAGE_SIZE, AllocFlags};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use super::stats;
use super::TERAPAGE_BASE;
use crate::memory::vmm;
use crate::arch;
use crate::memory::memory_manager;
use crate::numa;
use log;
use warn;

/// テラページフラグ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeraPageFlags(usize);

impl TeraPageFlags {
    /// キャッシュ不可
    pub const UNCACHEABLE: Self = TeraPageFlags(1);
    
    /// 書き込み組み合わせ
    pub const WRITE_COMBINING: Self = TeraPageFlags(1 << 1);
    
    /// 書き込み保護
    pub const WRITE_PROTECTED: Self = TeraPageFlags(1 << 2);
    
    /// 実行禁止
    pub const NO_EXECUTE: Self = TeraPageFlags(1 << 3);
    
    /// 共有メモリ
    pub const SHARED: Self = TeraPageFlags(1 << 4);
    
    /// フラグを作成
    pub const fn new(bits: usize) -> Self {
        TeraPageFlags(bits)
    }
    
    /// フラグをマージ
    pub const fn merge(&self, other: TeraPageFlags) -> Self {
        TeraPageFlags(self.0 | other.0)
    }
    
    /// フラグが含まれているか確認
    pub const fn contains(&self, flag: TeraPageFlags) -> bool {
        (self.0 & flag.0) == flag.0
    }
}

/// テラページ状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeraPageState {
    /// 未使用
    Free,
    /// 使用中
    Used,
    /// 予約済み
    Reserved,
    /// 部分的に使用
    PartiallyUsed,
}

/// テラページ構造体
#[derive(Debug)]
pub struct TeraPage {
    /// 仮想アドレス
    pub virtual_addr: usize,
    
    /// 物理アドレス
    pub physical_addr: usize,
    
    /// 状態
    pub state: TeraPageState,
    
    /// フラグ
    pub flags: TeraPageFlags,
    
    /// NUMAノード
    pub numa_node: u8,
    
    /// 参照カウント
    pub ref_count: AtomicUsize,
    
    /// 最終アクセス時間
    pub last_access: AtomicU64,
    
    /// 割り当て時間
    pub allocation_time: u64,
}

/// テラページリスト管理
struct TeraPageList {
    /// 全テラページマップ (仮想アドレス -> テラページ)
    pages: RwLock<BTreeMap<usize, TeraPage>>,
    
    /// 空きテラページリスト
    free_pages: SpinLock<Vec<usize>>,
    
    /// 使用中テラページ数
    used_pages: AtomicUsize,
    
    /// 総テラページ数
    total_pages: AtomicUsize,
}

/// グローバルテラページリスト
static mut TELEPAGE_LIST: Option<TeraPageList> = None;

/// テラページ管理の初期化済みフラグ
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// テラページ管理の初期化
pub fn init() -> Result<(), &'static str> {
    // 既に初期化されている場合は早期リターン
    if INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }
    
    // テラページを使用可能なメモリ領域があるか確認
    let cpu_info = cpu::get_info();
    if !cpu_info.supports_1gb_pages {
        return Err("1GBページがサポートされていません");
    }
    
    // テラページリスト初期化
    unsafe {
        TELEPAGE_LIST = Some(TeraPageList {
            pages: RwLock::new(BTreeMap::new()),
            free_pages: SpinLock::new(Vec::new()),
            used_pages: AtomicUsize::new(0),
            total_pages: AtomicUsize::new(0),
        });
    }
    
    // テラページの初期化
    setup_terapages()?;
    
    // 初期化完了
    INITIALIZED.store(true, Ordering::SeqCst);
    
    Ok(())
}

/// テラページシャットダウン
pub fn shutdown() -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }
    
    // 使用中のテラページをすべて解放
    unsafe {
        if let Some(list) = TELEPAGE_LIST.as_ref() {
            let pages = list.pages.read().map_err(|_| "ページリストをロックできません")?;
            
            for (addr, page) in pages.iter() {
                if page.state != TeraPageState::Free {
                    // 物理メモリの解放処理
                    unmap_terapage(page.physical_addr, TERA_PAGE_SIZE);
                }
            }
        }
    }
    
    // 初期化状態をリセット
    INITIALIZED.store(false, Ordering::SeqCst);
    
    Ok(())
}

/// テラページをセットアップ
fn setup_terapages() -> Result<(), &'static str> {
    // 物理メモリのサイズを取得
    let mem_info = crate::arch::get_memory_info();
    
    // 使用可能なテラページの数を計算
    let tera_page_count = mem_info.physical_memory / TERA_PAGE_SIZE;
    
    // 最大1024ページに制限
    let tera_page_count = tera_page_count.min(super::MAX_TERAPAGES);
    
    // テラページが少なすぎる場合はエラー
    if tera_page_count == 0 {
        return Err("テラページに十分なメモリがありません");
    }
    
    unsafe {
        if let Some(list) = TELEPAGE_LIST.as_mut() {
            let mut pages = list.pages.write().map_err(|_| "ページリストをロックできません")?;
            let mut free_pages = list.free_pages.lock();
            
            // テラページの総数を設定
            list.total_pages.store(tera_page_count, Ordering::SeqCst);
            
            // 各テラページをセットアップ
            for i in 0..tera_page_count {
                // 仮想アドレスを計算
                let virt_addr = TERAPAGE_BASE + (i * TERA_PAGE_SIZE);
                
                // 物理アドレスを割り当て（バディアロケータを使用）
                let phys_addr = allocate_physical_terapage()?;
                
                // NUMA認識: NUMAノードを選択して最適化
                let numa_node = select_best_numa_node_for_terapage(phys_addr);
                
                let terapage = TeraPage {
                    virtual_addr: virt_addr,
                    physical_addr: phys_addr,
                    state: TeraPageState::Used,
                    flags: TeraPageFlags::new(0),
                    numa_node,
                    ref_count: AtomicUsize::new(1),
                    last_access: AtomicU64::new(get_timestamp()),
                    allocation_time: get_timestamp(),
                };
                
                // マップに追加
                pages.insert(virt_addr, terapage);
                
                // 空きリストに追加
                free_pages.push(virt_addr);
            }
        }
    }
    
    Ok(())
}

/// 物理テラページを割り当て
pub fn allocate_physical_terapage() -> Result<usize, &'static str> {
    log::debug!("1GB物理テラページ割り当て開始");
    
    // 1. バディアロケータから1GBアライメントされた物理メモリを取得
    let physical_addr = {
        let mut buddy = crate::memory::buddy::get_allocator().lock();
        
        // 1GB = 2^30 bytes = 2^20 pages (4KB pages)
        const TERAPAGE_SIZE: usize = 1024 * 1024 * 1024; // 1GB
        const TERAPAGE_PAGES: usize = TERAPAGE_SIZE / 4096; // 262144 pages
        const TERAPAGE_ALIGNMENT: usize = TERAPAGE_SIZE; // 1GBアライメント
        
        // 大きなメモリブロックを要求
        let addr = buddy.allocate_aligned(TERAPAGE_SIZE, TERAPAGE_ALIGNMENT)
            .ok_or("1GB物理メモリの割り当てに失敗")?;
        
        log::debug!("物理アドレス割り当て成功: 0x{:x} (サイズ: {} MB)", addr, TERAPAGE_SIZE / (1024 * 1024));
        addr
    };
    
    // 2. アライメント検証
    if physical_addr % (1024 * 1024 * 1024) != 0 {
        log::error!("1GBアライメントが正しくありません: 0x{:x}", physical_addr);
        return Err("1GBアライメントエラー");
    }
    
    // 3. 一時的な仮想アドレスマッピングを作成
    let virtual_addr = create_temporary_mapping(physical_addr, 1024 * 1024 * 1024)?;
    
    log::debug!("一時マッピング作成: 物理=0x{:x} -> 仮想=0x{:x}", physical_addr, virtual_addr);
    
    // 4. アーキテクチャ固有の高速ゼロクリア
    let clear_result = unsafe {
        clear_memory_fast(virtual_addr, 1024 * 1024 * 1024)
    };
    
    // 5. 一時マッピングを解除
    remove_temporary_mapping(virtual_addr, 1024 * 1024 * 1024)?;
    
    // 6. ゼロクリア結果を確認
    match clear_result {
        Ok(()) => {
            log::debug!("1GBメモリゼロクリア完了");
        },
        Err(e) => {
            log::error!("メモリゼロクリア失敗: {}", e);
            
            // 失敗した場合はメモリを解放
            let mut buddy = crate::memory::buddy::get_allocator().lock();
            buddy.deallocate(physical_addr, 1024 * 1024 * 1024);
            return Err("メモリゼロクリア失敗");
        }
    }
    
    // 7. テラページ管理構造体に登録
    {
        let mut manager = TERAPAGE_MANAGER.write();
        let terapage_id = manager.next_id;
        manager.next_id += 1;
        
        let terapage_info = TerapageInfo {
            id: terapage_id,
            physical_addr,
            size: 1024 * 1024 * 1024,
            allocated_time: crate::time::current_time_ms(),
            access_count: 0,
            last_access_time: 0,
            numa_node: get_numa_node_for_address(physical_addr),
            is_locked: false,
            reference_count: 1,
        };
        
        manager.allocated_terapages.insert(terapage_id, terapage_info);
        manager.physical_to_id.insert(physical_addr, terapage_id);
        
        log::info!("テラページ登録完了: ID={}, 物理アドレス=0x{:x}, NUMAノード={}", 
                  terapage_id, physical_addr, terapage_info.numa_node);
    }
    
    // 8. 統計情報更新
    update_allocation_statistics(1024 * 1024 * 1024);
    
    // 9. フォールバック処理（必要に応じて）
    if should_enable_fallback_allocation() {
        log::debug!("フォールバック割り当てモードを有効化");
        enable_fallback_allocation_mode();
    }
    
    log::info!("1GB物理テラページ割り当て完了: 0x{:x}", physical_addr);
    Ok(physical_addr)
}

/// 一時的な仮想アドレスマッピングを作成
fn create_temporary_mapping(physical_addr: usize, size: usize) -> Result<usize, &'static str> {
    log::trace!("一時マッピング作成: 物理=0x{:x}, サイズ={} MB", physical_addr, size / (1024 * 1024));
    
    // 1. 一時マッピング用の仮想アドレス空間を確保
    const TEMP_MAPPING_BASE: usize = 0xFFFF_FF80_0000_0000; // カーネル一時領域
    
    let virtual_addr = {
        let mut temp_manager = TEMP_MAPPING_MANAGER.lock();
        temp_manager.allocate_temp_region(size)?
    };
    
    // 2. ページテーブルエントリを設定
    let page_count = (size + 4095) / 4096; // 4KBページ単位
    
    for i in 0..page_count {
        let virt_page = virtual_addr + (i * 4096);
        let phys_page = physical_addr + (i * 4096);
        
        // ページマッピング（読み書き可能、キャッシュ有効）
        let flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_ENABLED;
        
        unsafe {
            map_page_temporary(virt_page, phys_page, flags)?;
        }
    }
    
    // 3. TLBフラッシュ
    flush_tlb_range(virtual_addr, size);
    
    log::trace!("一時マッピング作成完了: 仮想=0x{:x}", virtual_addr);
    Ok(virtual_addr)
}

/// アーキテクチャ固有の高速メモリクリア
unsafe fn clear_memory_fast(virtual_addr: usize, size: usize) -> Result<(), &'static str> {
    log::trace!("高速メモリクリア開始: アドレス=0x{:x}, サイズ={} MB", virtual_addr, size / (1024 * 1024));
    
    let start_time = crate::time::current_time_ms();
    
    #[cfg(target_arch = "x86_64")]
    {
        // x86_64: REP STOSQ命令を使用した高速ゼロクリア
        let ptr = virtual_addr as *mut u64;
        let qword_count = size / 8;
        
        core::arch::asm!(
            "rep stosq",
            inout("rdi") ptr => _,
            inout("rcx") qword_count => _,
            in("rax") 0u64,
            options(nostack, preserves_flags)
        );
        
        // 残りのバイトをクリア
        let remaining_bytes = size % 8;
        if remaining_bytes > 0 {
            let byte_ptr = (virtual_addr + size - remaining_bytes) as *mut u8;
            core::ptr::write_bytes(byte_ptr, 0, remaining_bytes);
        }
        
        log::trace!("x86_64 REP STOSQ使用でメモリクリア完了");
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        // AArch64: DC ZVA命令を使用した高速ゼロクリア
        let cache_line_size = get_cache_line_size();
        let aligned_start = (virtual_addr + cache_line_size - 1) & !(cache_line_size - 1);
        let aligned_end = (virtual_addr + size) & !(cache_line_size - 1);
        
        // 先頭の非アライメント部分
        if aligned_start > virtual_addr {
            let prefix_size = aligned_start - virtual_addr;
            core::ptr::write_bytes(virtual_addr as *mut u8, 0, prefix_size);
        }
        
        // アライメントされた部分をDC ZVAでクリア
        let mut addr = aligned_start;
        while addr < aligned_end {
            core::arch::asm!(
                "dc zva, {addr}",
                addr = in(reg) addr,
                options(nostack, preserves_flags)
            );
            addr += cache_line_size;
        }
        
        // 末尾の非アライメント部分
        if aligned_end < virtual_addr + size {
            let suffix_size = (virtual_addr + size) - aligned_end;
            core::ptr::write_bytes(aligned_end as *mut u8, 0, suffix_size);
        }
        
        // メモリバリア
        core::arch::asm!("dsb ish", options(nostack, preserves_flags));
        
        log::trace!("AArch64 DC ZVA使用でメモリクリア完了");
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        // RISC-V: 標準的なメモリセット（最適化されたループ）
        let ptr = virtual_addr as *mut u64;
        let qword_count = size / 8;
        
        for i in 0..qword_count {
            core::ptr::write_volatile(ptr.add(i), 0);
        }
        
        // 残りのバイトをクリア
        let remaining_bytes = size % 8;
        if remaining_bytes > 0 {
            let byte_ptr = (virtual_addr + size - remaining_bytes) as *mut u8;
            core::ptr::write_bytes(byte_ptr, 0, remaining_bytes);
        }
        
        // メモリフェンス
        core::arch::asm!("fence", options(nostack, preserves_flags));
        
        log::trace!("RISC-V標準メモリセット使用でメモリクリア完了");
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
    {
        // フォールバック: 標準的なメモリセット
        core::ptr::write_bytes(virtual_addr as *mut u8, 0, size);
        log::trace!("標準メモリセット使用でメモリクリア完了");
    }
    
    let end_time = crate::time::current_time_ms();
    let duration = end_time - start_time;
    let throughput = if duration > 0 { (size as u64 * 1000) / (duration * 1024 * 1024) } else { 0 };
    
    log::debug!("メモリクリア完了: 時間={}ms, スループット={} MB/s", duration, throughput);
    
    Ok(())
}

/// NUMAノード取得
fn get_numa_node_for_address(physical_addr: usize) -> u32 {
    // 簡略化されたNUMAノード判定
    // 実際の実装では、ACPI SRATテーブルやハードウェア固有の情報を使用
    
    const NUMA_NODE_SIZE: usize = 64 * 1024 * 1024 * 1024; // 64GB per node
    let node = (physical_addr / NUMA_NODE_SIZE) as u32;
    
    // 最大ノード数制限
    const MAX_NUMA_NODES: u32 = 8;
    core::cmp::min(node, MAX_NUMA_NODES - 1)
}

/// 統計情報更新
fn update_allocation_statistics(allocated_size: usize) {
    let mut stats = ALLOCATION_STATS.write();
    stats.total_allocated += allocated_size;
    stats.allocation_count += 1;
    stats.last_allocation_time = crate::time::current_time_ms();
    
    // 最大割り当てサイズ更新
    if allocated_size > stats.max_allocation_size {
        stats.max_allocation_size = allocated_size;
    }
    
    log::trace!("統計更新: 総割り当て={} MB, 回数={}", 
               stats.total_allocated / (1024 * 1024), stats.allocation_count);
}

/// フォールバック割り当て判定
fn should_enable_fallback_allocation() -> bool {
    let stats = ALLOCATION_STATS.read();
    let available_memory = get_available_physical_memory();
    
    // 利用可能メモリが20%を下回った場合
    let threshold = get_total_physical_memory() * 20 / 100;
    
    available_memory < threshold
}

/// フォールバック割り当てモード有効化
fn enable_fallback_allocation_mode() {
    log::info!("フォールバック割り当てモードを有効化");
    
    // より小さなブロックサイズでの割り当てを許可
    let mut config = TERAPAGE_CONFIG.write();
    config.allow_smaller_blocks = true;
    config.min_block_size = 256 * 1024 * 1024; // 256MB
    config.fallback_enabled = true;
}

/// テラページを割り当て
pub fn allocate(count: usize, flags: AllocFlags) -> Result<usize, &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("テラページ管理が初期化されていません");
    }
    
    if count == 0 {
        return Err("割り当てサイズが0です");
    }
    
    log::debug!("テラページ割り当て要求: count={}, flags={:?}", count, flags);
    
    unsafe {
        let list = TELEPAGE_LIST.as_ref().ok_or("テラページリストが初期化されていません")?;
        
        // 空きページが十分にあるかチェック
        let free_pages = list.free_pages.lock();
        if free_pages.len() < count {
            return Err("十分な空きテラページがありません");
        }
        drop(free_pages);
        
        let mut allocated_pages = Vec::new();
        let mut allocated_addresses = Vec::new();
        
        // 要求された数のテラページを割り当て
        for i in 0..count {
            // 最適なNUMAノードを選択
            let numa_node = select_optimal_numa_node(flags)?;
            
            // 物理テラページを割り当て
            let phys_addr = allocate_physical_terapage()?;
            
            // 仮想アドレス空間にマップ
            let virt_addr = map_terapage_to_virtual(phys_addr, flags)?;
            
            // テラページ構造体を作成
            let terapage = TeraPage {
                virtual_addr: virt_addr,
                physical_addr: phys_addr,
                state: TeraPageState::Used,
                flags: convert_alloc_flags_to_terapage_flags(flags),
                numa_node,
                ref_count: AtomicUsize::new(1),
                last_access: AtomicU64::new(get_timestamp()),
                allocation_time: get_timestamp(),
            };
            
            // ページリストに追加
            {
                let mut pages = list.pages.write().map_err(|_| "ページリストをロックできません")?;
                pages.insert(virt_addr, terapage);
            }
            
            // 空きページリストから削除
            {
                let mut free_pages = list.free_pages.lock();
                if let Some(pos) = free_pages.iter().position(|&addr| addr == virt_addr) {
                    free_pages.remove(pos);
                }
            }
            
            allocated_pages.push(virt_addr);
            allocated_addresses.push(virt_addr);
            
            log::debug!("テラページ割り当て完了: virt=0x{:x}, phys=0x{:x}, numa={}", 
                       virt_addr, phys_addr, numa_node);
        }
        
        // 使用中ページ数を更新
        list.used_pages.fetch_add(count, Ordering::SeqCst);
        
        // 統計情報を更新
        stats::record_terapage_allocation(count);
        
        // 連続した仮想アドレスの場合は最初のアドレスを返す
        if count == 1 {
            Ok(allocated_addresses[0])
        } else {
            // 複数ページの場合は最初のアドレスを返す
            // 呼び出し側は連続したアドレスを期待している
            Ok(allocated_addresses[0])
        }
    }
}

/// 最適なNUMAノードを選択
fn select_optimal_numa_node(flags: AllocFlags) -> Result<u8, &'static str> {
    // 現在のタスクのCPU親和性を取得
    let current_cpu = cpu::get_current_cpu_id();
    let numa_node = numa::cpu_to_numa_node(current_cpu);
    
    // NUMAノードの負荷を確認
    let numa_load = numa::get_node_memory_usage(numa_node);
    
    // 負荷が高い場合は別のノードを選択
    if numa_load > 0.8 {
        // 最も負荷の低いNUMAノードを検索
        let mut best_node = numa_node;
        let mut best_load = numa_load;
        
        for node in 0..numa::get_numa_node_count() {
            let load = numa::get_node_memory_usage(node);
            if load < best_load {
                best_node = node;
                best_load = load;
            }
        }
        
        log::debug!("NUMAノード負荷分散: {} -> {}", numa_node, best_node);
        Ok(best_node as u8)
    } else {
        Ok(numa_node as u8)
    }
}

/// テラページを仮想アドレス空間にマップ
fn map_terapage_to_virtual(phys_addr: usize, flags: AllocFlags) -> Result<usize, &'static str> {
    // テラページ用の仮想アドレス領域を検索
    let virt_addr = find_free_terapage_virtual_region()?;
    
    // ページテーブルエントリのフラグを設定
    let mut page_flags = arch::PAGE_PRESENT | arch::PAGE_WRITABLE;
    
    if flags.contains(AllocFlags::USER) {
        page_flags |= arch::PAGE_USER;
    }
    
    if flags.contains(AllocFlags::NO_EXECUTE) {
        page_flags |= arch::PAGE_NO_EXECUTE;
    }
    
    if flags.contains(AllocFlags::UNCACHEABLE) {
        page_flags |= arch::PAGE_UNCACHEABLE;
    }
    
    // 1GBページとしてマップ
    arch::map_huge_page(virt_addr, phys_addr, TERA_PAGE_SIZE, page_flags)?;
    
    // TLBをフラッシュ
    arch::flush_tlb_range(virt_addr, TERA_PAGE_SIZE);
    
    Ok(virt_addr)
}

/// 空きテラページ仮想領域を検索
fn find_free_terapage_virtual_region() -> Result<usize, &'static str> {
    // テラページ用の仮想アドレス空間（カーネル空間の上位部分）
    let start_addr = TERAPAGE_BASE;
    let end_addr = start_addr + (super::MAX_TERAPAGES * TERA_PAGE_SIZE);
    
    // 1GBアライメントで空き領域を検索
    for addr in (start_addr..end_addr).step_by(TERA_PAGE_SIZE) {
        if vmm::is_virtual_region_free(addr, TERA_PAGE_SIZE) {
            return Ok(addr);
        }
    }
    
    Err("空きテラページ仮想領域が見つかりません")
}

/// AllocFlagsをTeraPageFlagsに変換
fn convert_alloc_flags_to_terapage_flags(flags: AllocFlags) -> TeraPageFlags {
    let mut terapage_flags = TeraPageFlags::new(0);
    
    if flags.contains(AllocFlags::UNCACHEABLE) {
        terapage_flags = terapage_flags.merge(TeraPageFlags::UNCACHEABLE);
    }
    
    if flags.contains(AllocFlags::WRITE_COMBINING) {
        terapage_flags = terapage_flags.merge(TeraPageFlags::WRITE_COMBINING);
    }
    
    if flags.contains(AllocFlags::NO_EXECUTE) {
        terapage_flags = terapage_flags.merge(TeraPageFlags::NO_EXECUTE);
    }
    
    if flags.contains(AllocFlags::SHARED) {
        terapage_flags = terapage_flags.merge(TeraPageFlags::SHARED);
    }
    
    terapage_flags
}

/// テラページを解放
pub fn free(address: usize, count: usize) -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("テラページモジュールが初期化されていません");
    }
    
    if count == 0 {
        return Ok(());
    }
    
    // アドレスのアライメント確認
    if address % TERA_PAGE_SIZE != 0 {
        return Err("無効なテラページアドレス");
    }
    
    unsafe {
        if let Some(list) = TELEPAGE_LIST.as_mut() {
            // 解放するアドレスのリストを構築
            let mut addresses = Vec::with_capacity(count);
            for i in 0..count {
                addresses.push(address + (i * TERA_PAGE_SIZE));
            }
            
            // ページの状態を更新
            {
                let mut pages = list.pages.write().map_err(|_| "ページリストをロックできません")?;
                
                // 全ページを順番に確認
                for addr in addresses.iter() {
                    if let Some(page) = pages.get_mut(addr) {
                        if page.state != TeraPageState::Used && page.state != TeraPageState::PartiallyUsed {
                            return Err("未使用のテラページを解放しようとしています");
                        }
                        
                        // 参照カウントを減らす
                        let ref_count = page.ref_count.fetch_sub(1, Ordering::Relaxed);
                        
                        if ref_count <= 1 {
                            // 完全に解放
                            page.state = TeraPageState::Free;
                        } else {
                            // 部分的に使用中
                            page.state = TeraPageState::PartiallyUsed;
                        }
                    } else {
                        return Err("無効なテラページアドレス");
                    }
                }
            }
            
            // 空きリストに追加
            {
                let mut free_pages = list.free_pages.lock();
                
                // 参照カウントをチェックして本当に解放すべきページだけを追加
                for addr in addresses {
                    let should_free = {
                        let pages = list.pages.read().map_err(|_| "ページリストをロックできません")?;
                        if let Some(page) = pages.get(&addr) {
                            page.ref_count.load(Ordering::Relaxed) == 0
                        } else {
                            false
                        }
                    };
                    
                    if should_free {
                        free_pages.push(*addr);
                    }
                }
            }
            
            // 使用中ページカウンタを更新
            list.used_pages.fetch_sub(count, Ordering::SeqCst);
            
            return Ok(());
        }
    }
    
    Err("テラページモジュールが利用できません")
}

/// プリフェッチを実行
pub fn prefetch(address: usize, size: usize) -> Result<(), &'static str> {
    // プリフェッチ要求を記録
    log::debug!("テラページプリフェッチ要求: アドレス=0x{:x}, サイズ={}", address, size);
    
    // ハードウェアプリフェッチ命令またはソフトウェアプリフェッチを実行
    // アーキテクチャ固有のプリフェッチ命令を使用
    for addr in (address..address + size).step_by(64) { // キャッシュライン単位
        unsafe {
            arch::prefetch_for_read(addr as *const u8);
        }
    }
    
    // プリフェッチ統計を更新
    record_access(address);
    Ok(())
}

/// テラページへのアクセスを記録
pub fn record_access(address: usize) {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return;
    }
    
    // ベースアドレスを計算
    let base_addr = address & !(TERA_PAGE_SIZE - 1);
    
    // 現在時刻を取得
    let timestamp = get_timestamp();
    
    unsafe {
        if let Some(list) = TELEPAGE_LIST.as_ref() {
            if let Ok(pages) = list.pages.read() {
                if let Some(page) = pages.get(&base_addr) {
                    page.last_access.store(timestamp, Ordering::Relaxed);
                }
            }
        }
    }
}

/// 全テラページ数を取得
pub fn get_total_pages() -> usize {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }
    
    unsafe {
        if let Some(list) = TELEPAGE_LIST.as_ref() {
            return list.total_pages.load(Ordering::SeqCst);
        }
    }
    
    0
}

/// 使用中テラページ数を取得
pub fn get_used_pages() -> usize {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return 0;
    }
    
    unsafe {
        if let Some(list) = TELEPAGE_LIST.as_ref() {
            return list.used_pages.load(Ordering::SeqCst);
        }
    }
    
    0
}

/// テラページ診断を実行
pub fn run_diagnostics() -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("テラページモジュールが初期化されていません");
    }
    
    // アクセス情報に基づいて最も使用頻度の低いページを特定
    let cold_pages = find_cold_pages(5);
    
    // 実際の診断アクションはここに実装
    
    Ok(())
}

/// 使用頻度の低いページを特定
fn find_cold_pages(limit: usize) -> Vec<usize> {
    let mut cold_pages = Vec::new();
    
    if !INITIALIZED.load(Ordering::SeqCst) {
        return cold_pages;
    }
    
    let current_time = get_timestamp();
    
    unsafe {
        if let Some(list) = TELEPAGE_LIST.as_ref() {
            if let Ok(pages) = list.pages.read() {
                // 使用中ページのみを対象に
                let mut candidates: Vec<_> = pages.iter()
                    .filter(|(_, page)| page.state == TeraPageState::Used)
                    .collect();
                
                // 最終アクセス時間でソート
                candidates.sort_by(|a, b| {
                    let a_time = a.1.last_access.load(Ordering::Relaxed);
                    let b_time = b.1.last_access.load(Ordering::Relaxed);
                    a_time.cmp(&b_time)
                });
                
                // 最も古いものから最大limit個を取得
                for (addr, _) in candidates.iter().take(limit) {
                    cold_pages.push(**addr);
                }
            }
        }
    }
    
    cold_pages
}

/// 現在のタイムスタンプを取得
fn get_timestamp() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    {
        0 // 他のアーキテクチャでの実装
    }
}

fn unmap_terapage(phys_addr: usize, size: usize) {
    for offset in (0..size).step_by(TERA_PAGE_SIZE) {
        vmm::unmap_page(phys_addr + offset);
    }
    arch::flush_tlb();
}

fn select_best_numa_node_for_terapage(phys_addr: usize) -> u8 {
    log::debug!("テラページのNUMAノード選択中: phys_addr=0x{:x}", phys_addr);
    
    // 物理アドレスからNUMAノードを特定
    if let Some(numa_node) = crate::numa::get_node_for_physical_address(phys_addr) {
        log::debug!("物理アドレス 0x{:x} はNUMAノード {} に属します", phys_addr, numa_node);
        return numa_node as u8;
    }
    
    // 現在のタスクのCPUアフィニティを考慮
    if let Some(current_task) = crate::process::get_current_task() {
        if let Some(preferred_node) = current_task.get_preferred_numa_node() {
            log::debug!("現在のタスクの優先NUMAノード: {}", preferred_node);
            return preferred_node as u8;
        }
    }
    
    // システム負荷が最も低いNUMAノードを選択
    let numa_info = crate::numa::get_system_info();
    let mut best_node = 0u8;
    let mut lowest_load = f32::MAX;
    
    for node_id in 0..numa_info.node_count {
        let load = crate::numa::get_node_load(node_id);
        if load < lowest_load {
            lowest_load = load;
            best_node = node_id as u8;
        }
    }
    
    log::debug!("負荷ベースでNUMAノード {} を選択（負荷: {:.2}%）", best_node, lowest_load * 100.0);
    best_node
} 