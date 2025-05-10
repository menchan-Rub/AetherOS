// AetherOS ページ管理サブシステム
//
// 物理ページの割り当て、解放、および追跡を処理します。
// このモジュールは、物理メモリリソースの低レベル管理を担当し、
// バディアロケータや他のメモリアロケータと連携します。

use crate::arch::{MemoryInfo, PageSize, PhysicalAddress};
use crate::core::memory::buddy::BuddyAllocator;
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::vec::Vec;
use spin::Mutex;
use log::{debug, warn, trace};

/// ページの状態を追跡するビットフラグ
pub mod flags {
    pub const FREE: u8 = 0;
    pub const ALLOCATED: u8 = 1 << 0;
    pub const RESERVED: u8 = 1 << 1;
    pub const MMIO_REGION: u8 = 1 << 2;
    pub const KERNEL_USED: u8 = 1 << 3;
    pub const USER_USED: u8 = 1 << 4;
    pub const SHARED: u8 = 1 << 5;
    pub const COW: u8 = 1 << 6;
    pub const CACHE_WB: u8 = 1 << 7;  // ライトバックキャッシュ
}

/// ページのメモリタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageMemoryType {
    Normal,        // 通常のメモリ
    DeviceUncached, // デバイスメモリ（キャッシュなし）
    DeviceWriteCombining, // デバイスメモリ（ライト結合）
    DeviceBuffered, // デバイスメモリ（バッファリング）
}

/// 物理ページの情報を追跡する構造体
#[derive(Debug)]
pub struct PageInfo {
    flags: u8,
    refcount: u16,
    order: u8,  // バディアロケータのオーダー（サイズ）
    mem_type: PageMemoryType,
    owner_pid: u32,  // 所有プロセスID（0はカーネル）
    numa_node: u8,   // このページが属するNUMAノード
}

impl Default for PageInfo {
    fn default() -> Self {
        Self {
            flags: flags::FREE,
            refcount: 0,
            order: 0,
            mem_type: PageMemoryType::Normal,
            owner_pid: 0,
            numa_node: 0,
        }
    }
}

/// ページ使用統計
pub struct PageStats {
    pub total_pages: usize,
    pub free_pages: AtomicU64,
    pub reserved_pages: AtomicU64,
    pub kernel_pages: AtomicU64,
    pub user_pages: AtomicU64,
    pub shared_pages: AtomicU64,
    pub mmio_pages: AtomicU64,
}

impl PageStats {
    pub fn new(total: usize) -> Self {
        Self {
            total_pages: total,
            free_pages: AtomicU64::new(total as u64),
            reserved_pages: AtomicU64::new(0),
            kernel_pages: AtomicU64::new(0),
            user_pages: AtomicU64::new(0),
            shared_pages: AtomicU64::new(0),
            mmio_pages: AtomicU64::new(0),
        }
    }
    
    pub fn allocated_pages(&self) -> u64 {
        self.total_pages as u64 - self.free_pages.load(Ordering::Relaxed)
    }
    
    pub fn usage_percentage(&self) -> f64 {
        let allocated = self.allocated_pages();
        (allocated as f64 / self.total_pages as f64) * 100.0
    }
    
    pub fn update_stats(&self, old_flags: u8, new_flags: u8, count: u64) {
        // 古いフラグから統計を減算
        if old_flags & flags::FREE != 0 {
            self.free_pages.fetch_sub(count, Ordering::Relaxed);
        }
        if old_flags & flags::RESERVED != 0 {
            self.reserved_pages.fetch_sub(count, Ordering::Relaxed);
        }
        if old_flags & flags::KERNEL_USED != 0 {
            self.kernel_pages.fetch_sub(count, Ordering::Relaxed);
        }
        if old_flags & flags::USER_USED != 0 {
            self.user_pages.fetch_sub(count, Ordering::Relaxed);
        }
        if old_flags & flags::SHARED != 0 {
            self.shared_pages.fetch_sub(count, Ordering::Relaxed);
        }
        if old_flags & flags::MMIO_REGION != 0 {
            self.mmio_pages.fetch_sub(count, Ordering::Relaxed);
        }
        
        // 新しいフラグに統計を加算
        if new_flags & flags::FREE != 0 {
            self.free_pages.fetch_add(count, Ordering::Relaxed);
        }
        if new_flags & flags::RESERVED != 0 {
            self.reserved_pages.fetch_add(count, Ordering::Relaxed);
        }
        if new_flags & flags::KERNEL_USED != 0 {
            self.kernel_pages.fetch_add(count, Ordering::Relaxed);
        }
        if new_flags & flags::USER_USED != 0 {
            self.user_pages.fetch_add(count, Ordering::Relaxed);
        }
        if new_flags & flags::SHARED != 0 {
            self.shared_pages.fetch_add(count, Ordering::Relaxed);
        }
        if new_flags & flags::MMIO_REGION != 0 {
            self.mmio_pages.fetch_add(count, Ordering::Relaxed);
        }
    }
}

/// ページマネージャ構造体
pub struct PageManager {
    page_info: Vec<PageInfo>,
    base_addr: PhysicalAddress,
    total_pages: usize,
    page_size: usize,
    stats: PageStats,
    buddy: Mutex<BuddyAllocator>,
}

static mut PAGE_MANAGER: Option<PageManager> = None;

impl PageManager {
    /// 新しいページマネージャを作成
    pub fn new(mem_info: &MemoryInfo, buddy: BuddyAllocator) -> Self {
        let page_size = PageSize::Default as usize;
        let total_memory = mem_info.total_memory;
        let total_pages = total_memory / page_size;
        
        // ページ情報を格納するベクタを初期化
        let mut page_info = Vec::with_capacity(total_pages);
        for _ in 0..total_pages {
            page_info.push(PageInfo::default());
        }
        
        let stats = PageStats::new(total_pages);
        
        // 予約済み領域をマーク
        let reserved_regions = &mem_info.reserved_regions;
        for region in reserved_regions {
            let start_page = region.start_addr / page_size;
            let end_page = (region.start_addr + region.size + page_size - 1) / page_size;
            
            for page_idx in start_page..end_page {
                if page_idx < total_pages {
                    page_info[page_idx].flags = flags::RESERVED;
                    stats.update_stats(flags::FREE, flags::RESERVED, 1);
                }
            }
        }
        
        // デバイスメモリ領域をマーク
        let mmio_regions = &mem_info.mmio_regions;
        for region in mmio_regions {
            let start_page = region.start_addr / page_size;
            let end_page = (region.start_addr + region.size + page_size - 1) / page_size;
            
            for page_idx in start_page..end_page {
                if page_idx < total_pages {
                    page_info[page_idx].flags = flags::MMIO_REGION;
                    page_info[page_idx].mem_type = PageMemoryType::DeviceUncached;
                    stats.update_stats(flags::FREE, flags::MMIO_REGION, 1);
                }
            }
        }
        
        Self {
            page_info,
            base_addr: 0,
            total_pages,
            page_size,
            stats,
            buddy: Mutex::new(buddy),
        }
    }
    
    /// ページマネージャを初期化
    pub fn init(mem_info: &MemoryInfo) {
        debug!("ページマネージャを初期化中...");
        
        let buddy = BuddyAllocator::new();
        let manager = Self::new(mem_info, buddy);
        
        unsafe {
            PAGE_MANAGER = Some(manager);
        }
        
        debug!("ページマネージャの初期化が完了しました");
    }
    
    /// グローバルページマネージャへの参照を取得
    pub fn get() -> &'static PageManager {
        unsafe {
            PAGE_MANAGER.as_ref().expect("ページマネージャが初期化されていません")
        }
    }
    
    /// グローバルページマネージャへの可変参照を取得
    pub fn get_mut() -> &'static mut PageManager {
        unsafe {
            PAGE_MANAGER.as_mut().expect("ページマネージャが初期化されていません")
        }
    }
    
    /// 単一のページを割り当て
    pub fn alloc_page(&self, flags: u8, mem_type: PageMemoryType, owner_pid: u32) -> Option<PhysicalAddress> {
        self.alloc_pages(1, flags, mem_type, owner_pid)
    }
    
    /// 複数の連続したページを割り当て
    pub fn alloc_pages(&self, count: usize, flags: u8, mem_type: PageMemoryType, owner_pid: u32) -> Option<PhysicalAddress> {
        // バディアロケータからメモリを取得
        let mut buddy = self.buddy.lock();
        let order = buddy.size_to_order(count * self.page_size);
        let phys_addr = buddy.allocate(order)?;
        drop(buddy);
        
        // ページ数を取得（割り当てられた実際のサイズがリクエストより大きい場合がある）
        let actual_order = if count.is_power_of_two() {
            count.trailing_zeros() as u8
        } else {
            (count.next_power_of_two()).trailing_zeros() as u8
        };
        let actual_pages = 1usize << actual_order;
        
        // ページの物理アドレスからインデックスを計算
        let page_idx = (phys_addr as usize - self.base_addr as usize) / self.page_size;
        
        // ページ情報を更新
        for i in 0..actual_pages {
            if page_idx + i < self.total_pages {
                let old_flags = self.page_info[page_idx + i].flags;
                self.page_info[page_idx + i].flags = flags | flags::ALLOCATED;
                self.page_info[page_idx + i].refcount = 1;
                self.page_info[page_idx + i].order = actual_order;
                self.page_info[page_idx + i].mem_type = mem_type;
                self.page_info[page_idx + i].owner_pid = owner_pid;
                
                // 統計を更新
                self.stats.update_stats(old_flags, flags | flags::ALLOCATED, 1);
            }
        }
        
        trace!("{}ページを割り当てました（実際は{}）- 物理アドレス: 0x{:x}", count, actual_pages, phys_addr);
        Some(phys_addr)
    }
    
    /// ページを解放
    pub fn free_page(&self, phys_addr: PhysicalAddress) {
        self.free_pages(phys_addr, 1);
    }
    
    /// 複数の連続したページを解放
    pub fn free_pages(&self, phys_addr: PhysicalAddress, count: usize) {
        // ページインデックスを計算
        let page_idx = (phys_addr as usize - self.base_addr as usize) / self.page_size;
        
        if page_idx >= self.total_pages {
            warn!("無効な物理アドレスを解放しようとしました: 0x{:x}", phys_addr);
            return;
        }
        
        // 実際の割り当てサイズを取得
        let order = self.page_info[page_idx].order;
        let actual_pages = 1usize << order;
        
        // 参照カウントをチェック
        if self.page_info[page_idx].refcount > 1 {
            // 参照カウントを減らすだけ
            self.page_info[page_idx].refcount -= 1;
            trace!("ページ 0x{:x} の参照カウントを {} に減らしました", 
                  phys_addr, self.page_info[page_idx].refcount);
            return;
        }
        
        // フラグと統計を更新
        for i in 0..actual_pages {
            if page_idx + i < self.total_pages {
                let old_flags = self.page_info[page_idx + i].flags;
                self.page_info[page_idx + i].flags = flags::FREE;
                self.page_info[page_idx + i].refcount = 0;
                self.page_info[page_idx + i].owner_pid = 0;
                
                // 統計を更新
                self.stats.update_stats(old_flags, flags::FREE, 1);
            }
        }
        
        // バディアロケータに返却
        let mut buddy = self.buddy.lock();
        buddy.free(phys_addr, order);
        
        trace!("{}ページ（アドレス: 0x{:x}）を解放しました", actual_pages, phys_addr);
    }
    
    /// 物理ページの参照カウントを増加
    pub fn increment_ref(&self, phys_addr: PhysicalAddress) -> bool {
        let page_idx = (phys_addr as usize - self.base_addr as usize) / self.page_size;
        
        if page_idx >= self.total_pages {
            warn!("無効な物理アドレスの参照カウントを増加しようとしました: 0x{:x}", phys_addr);
            return false;
        }
        
        if self.page_info[page_idx].flags & flags::ALLOCATED == 0 {
            warn!("割り当てられていないページの参照カウントを増加しようとしました: 0x{:x}", phys_addr);
            return false;
        }
        
        if self.page_info[page_idx].refcount == u16::MAX {
            warn!("ページの参照カウントが最大値に達しています: 0x{:x}", phys_addr);
            return false;
        }
        
        // 参照カウントを増加
        self.page_info[page_idx].refcount += 1;
        
        // 共有フラグを設定（refcount > 1）
        if self.page_info[page_idx].refcount > 1 {
            let old_flags = self.page_info[page_idx].flags;
            self.page_info[page_idx].flags |= flags::SHARED;
            if old_flags & flags::SHARED == 0 {
                self.stats.update_stats(old_flags, self.page_info[page_idx].flags, 1);
            }
        }
        
        trace!("ページ 0x{:x} の参照カウントを {} に増加しました", 
              phys_addr, self.page_info[page_idx].refcount);
        
        true
    }
    
    /// 物理ページの参照カウントを減少
    pub fn decrement_ref(&self, phys_addr: PhysicalAddress) -> bool {
        let page_idx = (phys_addr as usize - self.base_addr as usize) / self.page_size;
        
        if page_idx >= self.total_pages {
            warn!("無効な物理アドレスの参照カウントを減少しようとしました: 0x{:x}", phys_addr);
            return false;
        }
        
        if self.page_info[page_idx].flags & flags::ALLOCATED == 0 {
            warn!("割り当てられていないページの参照カウントを減少しようとしました: 0x{:x}", phys_addr);
            return false;
        }
        
        if self.page_info[page_idx].refcount == 0 {
            warn!("参照カウントが0のページを減少しようとしました: 0x{:x}", phys_addr);
            return false;
        }
        
        // 参照カウントを減少
        self.page_info[page_idx].refcount -= 1;
        
        trace!("ページ 0x{:x} の参照カウントを {} に減少しました", 
              phys_addr, self.page_info[page_idx].refcount);
        
        // 参照カウントが0になった場合、ページを解放
        if self.page_info[page_idx].refcount == 0 {
            let order = self.page_info[page_idx].order;
            
            // SHARED フラグをクリア
            if self.page_info[page_idx].flags & flags::SHARED != 0 {
                let old_flags = self.page_info[page_idx].flags;
                self.page_info[page_idx].flags &= !flags::SHARED;
                self.stats.update_stats(old_flags, self.page_info[page_idx].flags, 1);
            }
            
            // ページを実際に解放
            self.free_pages(phys_addr, 1 << order);
            return true;
        }
        
        // 参照カウントが1になった場合、SHAREDフラグをクリア
        if self.page_info[page_idx].refcount == 1 && (self.page_info[page_idx].flags & flags::SHARED != 0) {
            let old_flags = self.page_info[page_idx].flags;
            self.page_info[page_idx].flags &= !flags::SHARED;
            self.stats.update_stats(old_flags, self.page_info[page_idx].flags, 1);
        }
        
        true
    }
    
    /// ページフラグを設定
    pub fn set_page_flags(&self, phys_addr: PhysicalAddress, new_flags: u8) -> bool {
        let page_idx = (phys_addr as usize - self.base_addr as usize) / self.page_size;
        
        if page_idx >= self.total_pages {
            warn!("無効な物理アドレスのフラグを設定しようとしました: 0x{:x}", phys_addr);
            return false;
        }
        
        let old_flags = self.page_info[page_idx].flags;
        self.page_info[page_idx].flags = new_flags;
        
        // 統計を更新
        self.stats.update_stats(old_flags, new_flags, 1);
        
        true
    }
    
    /// ページのメモリタイプを設定
    pub fn set_memory_type(&self, phys_addr: PhysicalAddress, mem_type: PageMemoryType) -> bool {
        let page_idx = (phys_addr as usize - self.base_addr as usize) / self.page_size;
        
        if page_idx >= self.total_pages {
            warn!("無効な物理アドレスのメモリタイプを設定しようとしました: 0x{:x}", phys_addr);
            return false;
        }
        
        self.page_info[page_idx].mem_type = mem_type;
        true
    }
    
    /// ページの所有者を設定
    pub fn set_owner(&self, phys_addr: PhysicalAddress, owner_pid: u32) -> bool {
        let page_idx = (phys_addr as usize - self.base_addr as usize) / self.page_size;
        
        if page_idx >= self.total_pages {
            warn!("無効な物理アドレスの所有者を設定しようとしました: 0x{:x}", phys_addr);
            return false;
        }
        
        self.page_info[page_idx].owner_pid = owner_pid;
        
        // ユーザフラグを更新
        let old_flags = self.page_info[page_idx].flags;
        if owner_pid == 0 {
            // カーネル所有
            self.page_info[page_idx].flags &= !flags::USER_USED;
            self.page_info[page_idx].flags |= flags::KERNEL_USED;
        } else {
            // ユーザプロセス所有
            self.page_info[page_idx].flags &= !flags::KERNEL_USED;
            self.page_info[page_idx].flags |= flags::USER_USED;
        }
        
        // 統計を更新（フラグが変わった場合のみ）
        if old_flags != self.page_info[page_idx].flags {
            self.stats.update_stats(old_flags, self.page_info[page_idx].flags, 1);
        }
        
        true
    }
    
    /// ページ情報を取得
    pub fn get_page_info(&self, phys_addr: PhysicalAddress) -> Option<&PageInfo> {
        let page_idx = (phys_addr as usize - self.base_addr as usize) / self.page_size;
        
        if page_idx >= self.total_pages {
            return None;
        }
        
        Some(&self.page_info[page_idx])
    }
    
    /// ページの参照カウントを取得
    pub fn get_ref_count(&self, phys_addr: PhysicalAddress) -> u16 {
        let page_idx = (phys_addr as usize - self.base_addr as usize) / self.page_size;
        
        if page_idx >= self.total_pages {
            return 0;
        }
        
        self.page_info[page_idx].refcount
    }
    
    /// ページがCOW（コピーオンライト）かどうかをチェック
    pub fn is_cow_page(&self, phys_addr: PhysicalAddress) -> bool {
        let page_idx = (phys_addr as usize - self.base_addr as usize) / self.page_size;
        
        if page_idx >= self.total_pages {
            return false;
        }
        
        self.page_info[page_idx].flags & flags::COW != 0
    }
    
    /// ページをCOW（コピーオンライト）として設定
    pub fn set_cow_page(&self, phys_addr: PhysicalAddress, is_cow: bool) -> bool {
        let page_idx = (phys_addr as usize - self.base_addr as usize) / self.page_size;
        
        if page_idx >= self.total_pages {
            warn!("無効な物理アドレスをCOWとして設定しようとしました: 0x{:x}", phys_addr);
            return false;
        }
        
        let old_flags = self.page_info[page_idx].flags;
        
        if is_cow {
            self.page_info[page_idx].flags |= flags::COW;
        } else {
            self.page_info[page_idx].flags &= !flags::COW;
        }
        
        true
    }
    
    /// メモリ統計情報を取得
    pub fn get_stats(&self) -> &PageStats {
        &self.stats
    }
    
    /// 利用可能なメモリ容量（バイト単位）を取得
    pub fn available_memory(&self) -> usize {
        self.stats.free_pages.load(Ordering::Relaxed) as usize * self.page_size
    }
    
    /// 使用中のメモリ容量（バイト単位）を取得
    pub fn used_memory(&self) -> usize {
        self.stats.allocated_pages() as usize * self.page_size
    }
    
    /// 物理アドレスが有効かどうかをチェック
    pub fn is_valid_address(&self, phys_addr: PhysicalAddress) -> bool {
        let page_idx = (phys_addr as usize - self.base_addr as usize) / self.page_size;
        
        page_idx < self.total_pages
    }
    
    /// ページがMMIO領域かどうかをチェック
    pub fn is_mmio_page(&self, phys_addr: PhysicalAddress) -> bool {
        let page_idx = (phys_addr as usize - self.base_addr as usize) / self.page_size;
        
        if page_idx >= self.total_pages {
            return false;
        }
        
        self.page_info[page_idx].flags & flags::MMIO_REGION != 0
    }
    
    /// 特定のプロセスが所有するページの数を取得
    pub fn count_process_pages(&self, pid: u32) -> usize {
        let mut count = 0;
        
        for info in &self.page_info {
            if info.owner_pid == pid && info.flags & flags::ALLOCATED != 0 {
                count += 1;
            }
        }
        
        count
    }
    
    /// プロセスが所有するすべてのページを解放
    pub fn free_process_pages(&self, pid: u32) {
        let mut pages_to_free = Vec::new();
        
        // 解放すべきページを収集（最初のページのみを保存）
        for i in 0..self.total_pages {
            if self.page_info[i].owner_pid == pid && 
               self.page_info[i].flags & flags::ALLOCATED != 0 {
                // このページがバディアロケーションの先頭ページであることを確認
                // （最初のページだけを解放する必要がある）
                let phys_addr = self.base_addr + (i * self.page_size) as u64;
                pages_to_free.push(phys_addr);
                
                // オーダーに基づいて次のチェックをスキップ
                let order = self.page_info[i].order;
                let skip_pages = (1 << order) - 1;
                if skip_pages > 0 {
                    i += skip_pages;
                }
            }
        }
        
        // 収集したページを解放
        for phys_addr in pages_to_free {
            self.free_page(phys_addr);
        }
        
        debug!("PID {} のページ {} 個を解放しました", pid, pages_to_free.len());
    }
    
    /// デバッグ情報を出力
    pub fn dump_info(&self) {
        let stats = self.get_stats();
        debug!("=== ページマネージャ情報 ===");
        debug!("総ページ数: {}", stats.total_pages);
        debug!("空きページ: {}", stats.free_pages.load(Ordering::Relaxed));
        debug!("予約ページ: {}", stats.reserved_pages.load(Ordering::Relaxed));
        debug!("カーネルページ: {}", stats.kernel_pages.load(Ordering::Relaxed));
        debug!("ユーザーページ: {}", stats.user_pages.load(Ordering::Relaxed));
        debug!("共有ページ: {}", stats.shared_pages.load(Ordering::Relaxed));
        debug!("MMIO ページ: {}", stats.mmio_pages.load(Ordering::Relaxed));
        debug!("メモリ使用率: {:.2}%", stats.usage_percentage());
        debug!("========================");
    }
} 