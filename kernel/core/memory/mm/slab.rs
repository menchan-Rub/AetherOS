// AetherOS Slabアロケータ実装
//
// Slabアロケータは同じサイズのオブジェクトを効率的に割り当てるために使用されます。
// カーネルのデータ構造（タスク、ファイルディスクリプタなど）の管理に最適です。

use crate::arch::PhysicalAddress;
use crate::core::memory::mm::page::{PageManager, PageMemoryType, flags};
use core::alloc::Layout;
use core::ptr::NonNull;
use spin::{Mutex, MutexGuard};
use alloc::vec::Vec;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::{String, ToString};
use log::{debug, trace, warn};

/// Slabのカラーリングオフセットの最大値
const MAX_SLAB_COLOR: usize = 16;

/// Slabサイズ（通常は1ページサイズ）
const SLAB_SIZE: usize = 4096;

/// アラインメント要件
const MIN_ALIGNMENT: usize = 8;

/// slabオブジェクトのメタデータ
struct SlabObjectMeta {
    /// 次の空きオブジェクトへのオフセット、または None
    next_free: Option<u16>, 
}

/// Slabページを表す構造体
struct SlabPage {
    /// このSlabのベースとなる物理アドレス
    phys_addr: PhysicalAddress,
    /// 仮想アドレス（マップされた場合）
    virt_addr: usize,
    /// 1つのオブジェクトのサイズ
    obj_size: usize,
    /// このSlabページ内の合計オブジェクト数
    total_objects: usize,
    /// 使用中のオブジェクト数
    used_objects: usize,
    /// 最初の空きオブジェクトのインデックスまたはNone
    free_list: Option<u16>,
    /// このSlabページのカラーリングオフセット
    color_offset: usize,
    /// このSlabの所有者キャッシュへの参照
    owner_cache: String,
}

impl SlabPage {
    /// 新しいSlabページを作成する
    fn new(
        phys_addr: PhysicalAddress, 
        virt_addr: usize, 
        obj_size: usize, 
        color_offset: usize,
        owner: &str
    ) -> Self {
        // オブジェクトサイズにメタデータのサイズを加える
        let real_obj_size = obj_size.max(core::mem::size_of::<SlabObjectMeta>());
        // 最小アラインメントに合わせる
        let aligned_size = (real_obj_size + MIN_ALIGNMENT - 1) & !(MIN_ALIGNMENT - 1);
        
        // 使用可能な領域を計算（カラーリングオフセット後）
        let usable_space = SLAB_SIZE - color_offset;
        let total_objects = usable_space / aligned_size;
        
        // 空きリストの初期化
        let mut result = Self {
            phys_addr,
            virt_addr,
            obj_size: aligned_size,
            total_objects,
            used_objects: 0,
            free_list: if total_objects > 0 { Some(0) } else { None },
            color_offset,
            owner_cache: owner.to_string(),
        };
        
        // 空きリストを初期化
        result.init_free_list();
        
        result
    }
    
    /// 空きリストを初期化する
    fn init_free_list(&mut self) {
        // 各オブジェクトを連結リストに繋げる
        for i in 0..(self.total_objects as u16 - 1) {
            let obj_addr = self.obj_addr(i);
            unsafe {
                let meta = obj_addr as *mut SlabObjectMeta;
                (*meta).next_free = Some(i + 1);
            }
        }
        
        // 最後のオブジェクトはリストの終端
        if self.total_objects > 0 {
            let last_obj_addr = self.obj_addr((self.total_objects - 1) as u16);
            unsafe {
                let meta = last_obj_addr as *mut SlabObjectMeta;
                (*meta).next_free = None;
            }
        }
        
        // 空きリストの先頭を設定
        self.free_list = if self.total_objects > 0 { Some(0) } else { None };
        self.used_objects = 0;
    }
    
    /// 指定されたインデックスのオブジェクトのアドレスを計算する
    fn obj_addr(&self, idx: u16) -> usize {
        self.virt_addr + self.color_offset + (idx as usize * self.obj_size)
    }
    
    /// オブジェクトを割り当てる
    fn alloc_object(&mut self) -> Option<usize> {
        // 空きオブジェクトがない場合
        if self.free_list.is_none() {
            return None;
        }
        
        // 空きリストから取り出す
        let free_idx = self.free_list.unwrap();
        let obj_addr = self.obj_addr(free_idx);
        
        // 次の空きオブジェクトを取得
        unsafe {
            let meta = obj_addr as *mut SlabObjectMeta;
            self.free_list = (*meta).next_free;
        }
        
        self.used_objects += 1;
        trace!("Slabオブジェクト割り当て: addr=0x{:x}, オーナー={}", obj_addr, self.owner_cache);
        
        Some(obj_addr)
    }
    
    /// オブジェクトを解放する
    fn free_object(&mut self, addr: usize) -> bool {
        // アドレスがこのSlabページに属しているか確認
        if addr < self.virt_addr + self.color_offset || 
           addr >= self.virt_addr + SLAB_SIZE {
            return false;
        }
        
        // オブジェクト境界にアラインされているか確認
        let offset = addr - (self.virt_addr + self.color_offset);
        if offset % self.obj_size != 0 {
            warn!("Slabオブジェクトの解放に不正なアドレス: 0x{:x}", addr);
            return false;
        }
        
        // オブジェクトインデックスを計算
        let obj_idx = (offset / self.obj_size) as u16;
        
        // 空きリストに追加
        unsafe {
            let meta = addr as *mut SlabObjectMeta;
            (*meta).next_free = self.free_list;
        }
        
        self.free_list = Some(obj_idx);
        self.used_objects -= 1;
        
        trace!("Slabオブジェクト解放: addr=0x{:x}, オーナー={}", addr, self.owner_cache);
        
        true
    }
    
    /// このSlabページが空かどうか
    fn is_empty(&self) -> bool {
        self.used_objects == 0
    }
    
    /// このSlabページが満杯かどうか
    fn is_full(&self) -> bool {
        self.used_objects == self.total_objects
    }
    
    /// このSlabページの使用率
    fn usage_percentage(&self) -> f32 {
        if self.total_objects == 0 {
            return 0.0;
        }
        (self.used_objects as f32 / self.total_objects as f32) * 100.0
    }
}

/// SlabオブジェクトのROキャッシュ
struct SlabCache {
    /// キャッシュ名
    name: String,
    /// オブジェクトサイズ
    obj_size: usize,
    /// アラインメント要件
    alignment: usize,
    /// Slabページのリスト（パーティャル、フル、空き）
    partial_slabs: Vec<SlabPage>,
    full_slabs: Vec<SlabPage>,
    free_slabs: Vec<SlabPage>,
    /// カラーリングオフセットカウンタ
    next_color: usize,
    /// 作成済みのSlabページ数
    slab_count: usize,
    /// 割り当て済みのオブジェクト数
    allocated_objects: usize,
    /// NUMA対応のための優先ノード
    numa_node: Option<u8>,
}

impl SlabCache {
    /// 新しいSlabキャッシュを作成
    fn new(name: &str, obj_size: usize, alignment: usize) -> Self {
        Self {
            name: name.to_string(),
            obj_size: obj_size.max(MIN_ALIGNMENT),
            alignment: alignment.max(MIN_ALIGNMENT),
            partial_slabs: Vec::new(),
            full_slabs: Vec::new(),
            free_slabs: Vec::new(),
            next_color: 0,
            slab_count: 0,
            allocated_objects: 0,
            numa_node: None,
        }
    }
    
    /// ページマネージャからSlabページを確保
    fn allocate_slab(&mut self) -> Option<SlabPage> {
        let page_manager = PageManager::get();
        
        // ページを確保
        let phys_addr = page_manager.alloc_page(
            flags::KERNEL_USED,
            PageMemoryType::Normal,
            0, // カーネル所有
        )?;
        
        // ビット方向での一貫性を保つためのカラーリング
        let color_offset = (self.next_color % MAX_SLAB_COLOR) * MIN_ALIGNMENT;
        self.next_color = (self.next_color + 1) % MAX_SLAB_COLOR;
        
        // TODO: 物理→仮想アドレスマッピングが本来は必要だが、
        // ここでは簡略化のため、物理アドレスをそのまま使用
        let virt_addr = phys_addr as usize;
        
        // 新しいSlabページを作成
        let slab = SlabPage::new(phys_addr, virt_addr, self.obj_size, color_offset, &self.name);
        self.slab_count += 1;
        
        Some(slab)
    }
    
    /// Slabページを解放
    fn free_slab(&mut self, slab: SlabPage) {
        let page_manager = PageManager::get();
        
        // ページマネージャに返却
        page_manager.free_page(slab.phys_addr);
        self.slab_count -= 1;
    }
    
    /// オブジェクトを割り当て
    fn alloc_object(&mut self) -> Option<usize> {
        // 1. パーシャルSlabから割り当てを試みる
        for i in 0..self.partial_slabs.len() {
            if let Some(addr) = self.partial_slabs[i].alloc_object() {
                // Slabが満杯になった場合はフルリストに移動
                if self.partial_slabs[i].is_full() {
                    let full_slab = self.partial_slabs.remove(i);
                    self.full_slabs.push(full_slab);
                }
                self.allocated_objects += 1;
                return Some(addr);
            }
        }
        
        // 2. 空きSlabリストから取得
        if !self.free_slabs.is_empty() {
            let mut slab = self.free_slabs.pop().unwrap();
            let addr = slab.alloc_object().unwrap(); // ここで失敗はあり得ない
            self.partial_slabs.push(slab);
            self.allocated_objects += 1;
            return Some(addr);
        }
        
        // 3. 新しいSlabを割り当て
        if let Some(mut slab) = self.allocate_slab() {
            let addr = slab.alloc_object().unwrap(); // ここで失敗はあり得ない
            self.partial_slabs.push(slab);
            self.allocated_objects += 1;
            return Some(addr);
        }
        
        None
    }
    
    /// オブジェクトを解放
    fn free_object(&mut self, addr: usize) -> bool {
        // 1. フルSlabリストから探す
        for i in 0..self.full_slabs.len() {
            if self.full_slabs[i].free_object(addr) {
                // Slabが部分的に空きになった場合はパーシャルリストに移動
                let slab = self.full_slabs.remove(i);
                self.partial_slabs.push(slab);
                self.allocated_objects -= 1;
                return true;
            }
        }
        
        // 2. パーシャルSlabリストから探す
        for i in 0..self.partial_slabs.len() {
            if self.partial_slabs[i].free_object(addr) {
                // Slabが完全に空になった場合は空きリストに移動
                if self.partial_slabs[i].is_empty() {
                    let empty_slab = self.partial_slabs.remove(i);
                    
                    // 空きSlabの数が多すぎる場合は解放
                    if self.free_slabs.len() > 2 {
                        self.free_slab(empty_slab);
                    } else {
                        self.free_slabs.push(empty_slab);
                    }
                }
                self.allocated_objects -= 1;
                return true;
            }
        }
        
        // 3. 空きSlabリストからも念のため探す（通常はここにはないはず）
        for slab in &mut self.free_slabs {
            if slab.free_object(addr) {
                self.allocated_objects -= 1;
                return true;
            }
        }
        
        false
    }
    
    /// キャッシュのメモリを破棄
    fn destroy(&mut self) {
        // すべてのSlabページを解放
        for slab in self.partial_slabs.drain(..) {
            self.free_slab(slab);
        }
        
        for slab in self.full_slabs.drain(..) {
            self.free_slab(slab);
        }
        
        for slab in self.free_slabs.drain(..) {
            self.free_slab(slab);
        }
        
        self.allocated_objects = 0;
        self.slab_count = 0;
    }
    
    /// キャッシュの使用状況を報告
    fn report_usage(&self) -> (usize, usize, usize, usize) {
        (
            self.obj_size,
            self.allocated_objects,
            self.slab_count,
            self.slab_count * SLAB_SIZE,
        )
    }
}

/// Slabアロケータ管理構造体
pub struct SlabAllocator {
    /// サイズ別の汎用キャッシュ（8, 16, 32, 64, 128, 256, 512, 1024, 2048バイト）
    size_caches: BTreeMap<usize, SlabCache>,
    /// 名前付きの特殊キャッシュ
    named_caches: BTreeMap<String, SlabCache>,
}

impl SlabAllocator {
    /// 新しいSlabアロケータを作成
    pub fn new() -> Self {
        let mut allocator = Self {
            size_caches: BTreeMap::new(),
            named_caches: BTreeMap::new(),
        };
        
        // 標準サイズキャッシュを初期化
        let standard_sizes = [8, 16, 32, 64, 128, 256, 512, 1024, 2048];
        for &size in &standard_sizes {
            let cache_name = format!("size-{}", size);
            let cache = SlabCache::new(&cache_name, size, MIN_ALIGNMENT);
            allocator.size_caches.insert(size, cache);
        }
        
        allocator
    }
    
    /// 適切なサイズのキャッシュを選択
    fn select_size_cache(&self, size: usize) -> Option<usize> {
        self.size_caches.keys()
            .filter(|&&cache_size| cache_size >= size)
            .min()
            .copied()
    }
    
    /// 特定サイズのメモリを汎用キャッシュから割り当て
    pub fn allocate(&mut self, size: usize) -> Option<usize> {
        // サイズが大きすぎる場合は処理できない
        if size > 2048 {
            return None;
        }
        
        // 適切なサイズキャッシュを選択
        let cache_size = self.select_size_cache(size)?;
        let cache = self.size_caches.get_mut(&cache_size)?;
        
        cache.alloc_object()
    }
    
    /// メモリを解放
    pub fn deallocate(&mut self, ptr: usize) -> bool {
        // まず汎用キャッシュで試す
        for (_, cache) in &mut self.size_caches {
            if cache.free_object(ptr) {
                return true;
            }
        }
        
        // 次に名前付きキャッシュで試す
        for (_, cache) in &mut self.named_caches {
            if cache.free_object(ptr) {
                return true;
            }
        }
        
        false
    }
    
    /// 名前付きキャッシュを作成
    pub fn create_cache(&mut self, name: &str, obj_size: usize, alignment: usize) -> bool {
        if self.named_caches.contains_key(name) {
            return false;
        }
        
        let cache = SlabCache::new(name, obj_size, alignment);
        self.named_caches.insert(name.to_string(), cache);
        
        true
    }
    
    /// 名前付きキャッシュからメモリを割り当て
    pub fn allocate_from_cache(&mut self, name: &str) -> Option<usize> {
        self.named_caches.get_mut(name)?.alloc_object()
    }
    
    /// 名前付きキャッシュを削除
    pub fn destroy_cache(&mut self, name: &str) -> bool {
        if let Some(mut cache) = self.named_caches.remove(name) {
            cache.destroy();
            true
        } else {
            false
        }
    }
    
    /// すべてのキャッシュの使用状況を報告
    pub fn report_usage(&self) {
        debug!("=== Slabアロケータ使用状況 ===");
        debug!("汎用サイズキャッシュ:");
        let mut total_objects = 0;
        let mut total_memory = 0;
        
        for (size, cache) in &self.size_caches {
            let (obj_size, allocated, slabs, memory) = cache.report_usage();
            debug!("  サイズ {}B: {}オブジェクト, {}スラブ, 合計{}KB",
                  obj_size, allocated, slabs, memory / 1024);
            total_objects += allocated;
            total_memory += memory;
        }
        
        debug!("名前付きキャッシュ:");
        for (name, cache) in &self.named_caches {
            let (obj_size, allocated, slabs, memory) = cache.report_usage();
            debug!("  {}: サイズ{}B, {}オブジェクト, {}スラブ, 合計{}KB",
                  name, obj_size, allocated, slabs, memory / 1024);
            total_objects += allocated;
            total_memory += memory;
        }
        
        debug!("合計: {}オブジェクト, {}KB", total_objects, total_memory / 1024);
        debug!("===========================");
    }
}

// グローバルSlabアロケータのインスタンス
static SLAB_ALLOCATOR: Mutex<Option<SlabAllocator>> = Mutex::new(None);

/// SlabアロケータのAPIモジュール
pub mod api {
    use super::*;
    
    /// Slabアロケータを初期化
    pub fn init() {
        debug!("Slabアロケータを初期化中...");
        
        let allocator = SlabAllocator::new();
        let mut global = SLAB_ALLOCATOR.lock();
        *global = Some(allocator);
        
        debug!("Slabアロケータの初期化が完了しました");
    }
    
    /// Slabアロケータを取得
    fn get_allocator<'a>() -> MutexGuard<'a, Option<SlabAllocator>> {
        let guard = SLAB_ALLOCATOR.lock();
        if guard.is_none() {
            panic!("Slabアロケータが初期化されていません");
        }
        guard
    }
    
    /// 特定サイズのメモリを割り当て
    pub fn allocate(size: usize) -> Option<NonNull<u8>> {
        let mut allocator = get_allocator();
        
        if let Some(addr) = allocator.as_mut().unwrap().allocate(size) {
            unsafe { NonNull::new(addr as *mut u8) }
        } else {
            None
        }
    }
    
    /// メモリを解放
    pub fn deallocate(ptr: NonNull<u8>) -> bool {
        let mut allocator = get_allocator();
        
        allocator.as_mut().unwrap().deallocate(ptr.as_ptr() as usize)
    }
    
    /// レイアウトに基づいてメモリを割り当て
    pub fn allocate_layout(layout: Layout) -> Option<NonNull<u8>> {
        if layout.size() <= 2048 && layout.align() <= MIN_ALIGNMENT {
            allocate(layout.size())
        } else {
            None
        }
    }
    
    /// 名前付きキャッシュを作成
    pub fn create_cache(name: &str, obj_size: usize, alignment: usize) -> bool {
        let mut allocator = get_allocator();
        
        allocator.as_mut().unwrap().create_cache(name, obj_size, alignment)
    }
    
    /// 名前付きキャッシュからオブジェクトを割り当て
    pub fn allocate_from_cache(name: &str) -> Option<NonNull<u8>> {
        let mut allocator = get_allocator();
        
        if let Some(addr) = allocator.as_mut().unwrap().allocate_from_cache(name) {
            unsafe { NonNull::new(addr as *mut u8) }
        } else {
            None
        }
    }
    
    /// 名前付きキャッシュを削除
    pub fn destroy_cache(name: &str) -> bool {
        let mut allocator = get_allocator();
        
        allocator.as_mut().unwrap().destroy_cache(name)
    }
    
    /// すべてのキャッシュの使用状況を報告
    pub fn report_usage() {
        let allocator = get_allocator();
        
        allocator.as_ref().unwrap().report_usage();
    }
}

/// グローバルアロケータ機能のためのラッパー関数
pub mod global_alloc {
    use super::*;
    use core::alloc::{GlobalAlloc, Layout};
    use core::ptr;
    
    /// グローバルアロケータの実装
    pub struct SlabGlobalAlloc;
    
    unsafe impl GlobalAlloc for SlabGlobalAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if let Some(ptr) = api::allocate_layout(layout) {
                ptr.as_ptr()
            } else {
                // サイズが大きい場合や初期化前の場合はページアロケータを直接使用
                let page_manager = PageManager::get();
                let size = layout.size();
                let pages = (size + SLAB_SIZE - 1) / SLAB_SIZE;
                
                if let Some(phys_addr) = page_manager.alloc_pages(
                    pages,
                    flags::KERNEL_USED,
                    PageMemoryType::Normal,
                    0, // カーネル所有
                ) {
                    // TODO: 仮想アドレスマッピング
                    phys_addr as *mut u8
                } else {
                    ptr::null_mut()
                }
            }
        }
        
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            if layout.size() <= 2048 && layout.align() <= MIN_ALIGNMENT {
                if let Some(non_null) = NonNull::new(ptr) {
                    if !api::deallocate(non_null) {
                        // Slabアロケータでの解放に失敗した場合
                        warn!("Slabアロケータで解放できないポインタ: {:p}", ptr);
                    }
                }
            } else {
                // ページアロケータで割り当てたメモリを解放
                let page_manager = PageManager::get();
                page_manager.free_pages(ptr as PhysicalAddress, (layout.size() + SLAB_SIZE - 1) / SLAB_SIZE);
            }
        }
    }
}