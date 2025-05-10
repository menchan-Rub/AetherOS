// AetherOS カーネル - 仮想メモリアロケータ実装
//
// このモジュールは、カーネル空間内で連続した仮想メモリを確保するための
// 機能を提供します。物理メモリは連続している必要はありません。

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::core::arch::paging::{PageSize, PageTable, PhysAddr, VirtAddr};
use crate::core::memory::mm::mmap::{AddressSpace, MapPermissions, MmapError};
use crate::core::memory::mm::page::{AllocFlags, Page, PAGE_SIZE};
use crate::core::sync::RwLock;

/// 仮想メモリアロケータのステータス
#[derive(Debug)]
pub struct VmallocStats {
    /// 割り当てられた総バイト数
    pub total_allocated: usize,
    /// 解放された総バイト数
    pub total_freed: usize,
    /// 現在の割り当て数
    pub active_allocations: usize,
    /// 最大の割り当てサイズ
    pub max_allocation_size: usize,
}

/// 仮想メモリ領域
#[derive(Debug)]
struct VmallocRegion {
    /// 開始アドレス
    start: VirtAddr,
    /// サイズ
    size: usize,
    /// 割り当てID
    id: usize,
}

/// カーネル仮想メモリアロケータ
#[derive(Debug)]
pub struct Vmalloc {
    /// 仮想メモリ領域のマップ
    regions: RwLock<BTreeMap<VirtAddr, VmallocRegion>>,
    /// 次の割り当てID
    next_id: AtomicUsize,
    /// 仮想アドレス空間の開始アドレス
    start_addr: VirtAddr,
    /// 仮想アドレス空間の終了アドレス
    end_addr: VirtAddr,
    /// アドレス空間
    address_space: Arc<AddressSpace>,
    /// 割り当てられた総バイト数
    total_allocated: AtomicUsize,
    /// 解放された総バイト数
    total_freed: AtomicUsize,
    /// 最大の割り当てサイズ
    max_allocation_size: AtomicUsize,
}

impl Vmalloc {
    /// 新しい仮想メモリアロケータを作成
    pub fn new(
        start_addr: VirtAddr,
        end_addr: VirtAddr,
        address_space: Arc<AddressSpace>,
    ) -> Self {
        Self {
            regions: RwLock::new(BTreeMap::new()),
            next_id: AtomicUsize::new(1),
            start_addr,
            end_addr,
            address_space,
            total_allocated: AtomicUsize::new(0),
            total_freed: AtomicUsize::new(0),
            max_allocation_size: AtomicUsize::new(0),
        }
    }

    /// 指定サイズの連続した仮想メモリを割り当て
    pub fn alloc(&self, size: usize, align: usize) -> Result<VirtAddr, VmallocError> {
        if size == 0 {
            return Err(VmallocError::InvalidSize);
        }

        // サイズとアライメントを調整
        let aligned_size = align_up(size, PAGE_SIZE);
        let align = align.max(PAGE_SIZE);

        // 適切な空き領域を見つける
        let addr = self.find_free_region(aligned_size, align)?;

        // 新しい領域を作成
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let region = VmallocRegion {
            start: addr,
            size: aligned_size,
            id,
        };

        // 領域を保存
        let mut regions = self.regions.write();
        regions.insert(addr, region);

        // 実際のページを割り当ててマップ
        self.map_pages(addr, aligned_size)?;

        // 統計情報を更新
        self.total_allocated.fetch_add(aligned_size, Ordering::SeqCst);
        let current_max = self.max_allocation_size.load(Ordering::SeqCst);
        if aligned_size > current_max {
            self.max_allocation_size.store(aligned_size, Ordering::SeqCst);
        }

        Ok(addr)
    }

    /// 指定サイズの連続した仮想メモリを割り当て（ゼロ初期化）
    pub fn zalloc(&self, size: usize, align: usize) -> Result<VirtAddr, VmallocError> {
        if size == 0 {
            return Err(VmallocError::InvalidSize);
        }

        // サイズとアライメントを調整
        let aligned_size = align_up(size, PAGE_SIZE);
        let align = align.max(PAGE_SIZE);

        // 適切な空き領域を見つける
        let addr = self.find_free_region(aligned_size, align)?;

        // 新しい領域を作成
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let region = VmallocRegion {
            start: addr,
            size: aligned_size,
            id,
        };

        // 領域を保存
        let mut regions = self.regions.write();
        regions.insert(addr, region);

        // 実際のページを割り当ててマップ（ゼロ初期化フラグ付き）
        self.map_zero_pages(addr, aligned_size)?;

        // 統計情報を更新
        self.total_allocated.fetch_add(aligned_size, Ordering::SeqCst);
        let current_max = self.max_allocation_size.load(Ordering::SeqCst);
        if aligned_size > current_max {
            self.max_allocation_size.store(aligned_size, Ordering::SeqCst);
        }

        Ok(addr)
    }

    /// 割り当てた仮想メモリを解放
    pub fn free(&self, addr: VirtAddr) -> Result<(), VmallocError> {
        // 領域を取得
        let mut regions = self.regions.write();
        let region = regions.get(&addr)
            .ok_or(VmallocError::InvalidAddress)?
            .clone();

        // 領域を削除
        regions.remove(&addr);

        // ページをアンマップ
        self.address_space.unmap(addr, region.size)
            .map_err(|_| VmallocError::UnmappingError)?;

        // 統計情報を更新
        self.total_freed.fetch_add(region.size, Ordering::SeqCst);

        Ok(())
    }

    /// 空き領域を見つける
    fn find_free_region(&self, size: usize, align: usize) -> Result<VirtAddr, VmallocError> {
        let regions = self.regions.read();

        // 最初の候補: 開始アドレス
        let mut candidate = align_up(self.start_addr.as_usize(), align);
        let mut candidate_addr = VirtAddr::new(candidate);

        // 既存の領域をイテレート
        for (region_addr, region) in regions.iter() {
            // 候補アドレスが既存領域と重なる場合、既存領域の末尾に移動
            if candidate_addr < region_addr.add(region.size) && 
               candidate_addr.add(size) > *region_addr {
                candidate = align_up(region_addr.as_usize() + region.size, align);
                candidate_addr = VirtAddr::new(candidate);
            }
        }

        // 候補アドレスが終了アドレスを超えないことを確認
        if candidate_addr.add(size) <= self.end_addr {
            Ok(candidate_addr)
        } else {
            Err(VmallocError::OutOfMemory)
        }
    }

    /// ページを割り当ててマップ
    fn map_pages(&self, addr: VirtAddr, size: usize) -> Result<(), VmallocError> {
        let pages_count = size / PAGE_SIZE;
        let permissions = MapPermissions::readwrite();

        let mut current_addr = addr;
        for _ in 0..pages_count {
            // 新しいページを割り当て
            let page = Page::alloc(AllocFlags::NONE)
                .map_err(|_| VmallocError::OutOfMemory)?;

            // ページをマップ
            let page_table = self.address_space.page_table.lock();
            match page_table.map(
                current_addr,
                page.phys_addr(),
                PageSize::Size4KiB,
                convert_permissions(permissions),
            ) {
                Ok(_) => (),
                Err(_) => return Err(VmallocError::MappingError),
            }

            current_addr = current_addr.add(PAGE_SIZE);
        }

        Ok(())
    }

    /// ゼロ初期化されたページを割り当ててマップ
    fn map_zero_pages(&self, addr: VirtAddr, size: usize) -> Result<(), VmallocError> {
        let pages_count = size / PAGE_SIZE;
        let permissions = MapPermissions::readwrite();

        let mut current_addr = addr;
        for _ in 0..pages_count {
            // ゼロ初期化されたページを割り当て
            let page = Page::alloc(AllocFlags::ZERO)
                .map_err(|_| VmallocError::OutOfMemory)?;

            // ページをマップ
            let page_table = self.address_space.page_table.lock();
            match page_table.map(
                current_addr,
                page.phys_addr(),
                PageSize::Size4KiB,
                convert_permissions(permissions),
            ) {
                Ok(_) => (),
                Err(_) => return Err(VmallocError::MappingError),
            }

            current_addr = current_addr.add(PAGE_SIZE);
        }

        Ok(())
    }

    /// アドレスが有効な割り当てかどうか確認
    pub fn is_valid_allocation(&self, addr: VirtAddr) -> bool {
        let regions = self.regions.read();
        regions.contains_key(&addr)
    }

    /// アドレスの割り当てサイズを取得
    pub fn get_allocation_size(&self, addr: VirtAddr) -> Result<usize, VmallocError> {
        let regions = self.regions.read();
        match regions.get(&addr) {
            Some(region) => Ok(region.size),
            None => Err(VmallocError::InvalidAddress),
        }
    }

    /// 割り当て情報を取得
    pub fn get_stats(&self) -> VmallocStats {
        VmallocStats {
            total_allocated: self.total_allocated.load(Ordering::SeqCst),
            total_freed: self.total_freed.load(Ordering::SeqCst),
            active_allocations: self.regions.read().len(),
            max_allocation_size: self.max_allocation_size.load(Ordering::SeqCst),
        }
    }

    /// 現在の割り当て数を取得
    pub fn allocation_count(&self) -> usize {
        self.regions.read().len()
    }

    /// 現在使用中の総メモリ量を取得
    pub fn total_memory_usage(&self) -> usize {
        self.total_allocated.load(Ordering::SeqCst) - self.total_freed.load(Ordering::SeqCst)
    }
}

/// 仮想メモリアロケータエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmallocError {
    /// メモリ不足
    OutOfMemory,
    /// 無効なアドレス
    InvalidAddress,
    /// 無効なサイズ
    InvalidSize,
    /// アライメントエラー
    AlignmentError,
    /// マッピングエラー
    MappingError,
    /// アンマッピングエラー
    UnmappingError,
}

impl From<MmapError> for VmallocError {
    fn from(err: MmapError) -> Self {
        match err {
            MmapError::OutOfMemory => VmallocError::OutOfMemory,
            MmapError::InvalidAddress => VmallocError::InvalidAddress,
            MmapError::MappingError => VmallocError::MappingError,
            MmapError::UnmappingError => VmallocError::UnmappingError,
            _ => VmallocError::MappingError,
        }
    }
}

// ヘルパー関数

/// 値を指定アライメントに切り上げ
fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// パーミッションを変換
fn convert_permissions(perms: MapPermissions) -> u64 {
    // アーキテクチャ固有の実装に依存
    let mut result = 0;
    
    if perms.read {
        result |= 1;
    }
    
    if perms.write {
        result |= 2;
    }
    
    if perms.execute {
        result |= 4;
    }
    
    if perms.user {
        result |= 8;
    }
    
    if !perms.cacheable {
        result |= 16;
    }
    
    result
}

/// グローバルVmallocインスタンス
pub static VMALLOC: Mutex<Option<Vmalloc>> = Mutex::new(None);

/// 指定サイズの仮想メモリを割り当て
pub fn vmalloc(size: usize, align: usize) -> Result<VirtAddr, VmallocError> {
    VMALLOC.lock().as_ref()
        .ok_or(VmallocError::OutOfMemory)?
        .alloc(size, align)
}

/// 指定サイズの仮想メモリを割り当て（ゼロ初期化）
pub fn vzalloc(size: usize, align: usize) -> Result<VirtAddr, VmallocError> {
    VMALLOC.lock().as_ref()
        .ok_or(VmallocError::OutOfMemory)?
        .zalloc(size, align)
}

/// 割り当てた仮想メモリを解放
pub fn vfree(addr: VirtAddr) -> Result<(), VmallocError> {
    VMALLOC.lock().as_ref()
        .ok_or(VmallocError::InvalidAddress)?
        .free(addr)
}

/// 仮想メモリアロケータを初期化
pub fn init_vmalloc(
    start_addr: VirtAddr,
    end_addr: VirtAddr,
    address_space: Arc<AddressSpace>,
) {
    let mut vmalloc_guard = VMALLOC.lock();
    *vmalloc_guard = Some(Vmalloc::new(start_addr, end_addr, address_space));
}

/// 仮想メモリアロケータの統計情報を取得
pub fn vmalloc_stats() -> Option<VmallocStats> {
    VMALLOC.lock().as_ref().map(|v| v.get_stats())
}

/// アドレスが有効な割り当てかどうか確認
pub fn is_vmalloc_addr(addr: VirtAddr) -> bool {
    VMALLOC.lock().as_ref()
        .map(|v| v.is_valid_allocation(addr))
        .unwrap_or(false)
}

/// アドレスの割り当てサイズを取得
pub fn vmalloc_size(addr: VirtAddr) -> Result<usize, VmallocError> {
    VMALLOC.lock().as_ref()
        .ok_or(VmallocError::InvalidAddress)?
        .get_allocation_size(addr)
} 