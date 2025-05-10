// AetherOS スラブアロケータ実装
//
// このファイルはメモリスラブアロケータのコア実装を提供します。
// スラブアロケータは同じサイズのオブジェクトを効率的に割り当てるために設計されています。

use alloc::vec::Vec;
use core::ptr::NonNull;
use core::marker::PhantomData;
use core::mem::size_of;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::core::memory::pmem::region::PmemRegion;
use crate::core::memory::page::{Page, PageFlags};
use super::object::SlabObject;
use super::sync::{SpinLock, RwLock};
use crate::core::log::{trace, debug, warn};

/// スラブページのフラグ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlabPageState {
    /// 空き
    Free,
    /// 部分的に使用中
    PartiallyUsed,
    /// 完全に使用中
    Full,
}

/// スラブページ
///
/// 同じサイズのオブジェクト群を保持する物理ページ
pub struct SlabPage {
    /// このスラブが属するキャッシュへの参照
    cache: NonNull<SlabCache>,
    /// 基礎となる物理ページ
    page: Page,
    /// フリーリストの先頭
    free_list: SpinLock<Option<NonNull<SlabObject>>>,
    /// このスラブ内の空きオブジェクト数
    free_count: AtomicUsize,
    /// このスラブの状態
    state: AtomicUsize,
    /// オブジェクトの合計数
    total_objects: usize,
}

/// スラブキャッシュ
///
/// 特定サイズのメモリオブジェクトを管理するキャッシュ
pub struct SlabCache {
    /// オブジェクトサイズ
    object_size: usize,
    /// オブジェクトのアライメント
    object_align: usize,
    /// このキャッシュの名前
    name: &'static str,
    /// カラー化オフセットの最大値
    max_color_offset: usize,
    /// 現在のカラーオフセット
    color_offset: AtomicUsize,
    /// 空きスラブのリスト
    free_slabs: SpinLock<Vec<NonNull<SlabPage>>>,
    /// 部分的に使用されているスラブのリスト
    partial_slabs: SpinLock<Vec<NonNull<SlabPage>>>,
    /// 完全に使用されているスラブのリスト
    full_slabs: SpinLock<Vec<NonNull<SlabPage>>>,
    /// 統計情報: 割り当て数
    allocation_count: AtomicUsize,
    /// 統計情報: 解放数
    free_count: AtomicUsize,
}

/// スラブアロケータ
///
/// 異なるサイズのオブジェクトのためのスラブキャッシュを管理
pub struct SlabAllocator {
    /// 一般的なサイズのオブジェクト用のキャッシュ
    general_caches: RwLock<Vec<NonNull<SlabCache>>>,
    /// 専用キャッシュ (特定の構造体やカーネルオブジェクト用)
    specialized_caches: RwLock<Vec<NonNull<SlabCache>>>,
    /// PMEM領域（永続メモリ）があれば使用
    pmem_region: Option<PmemRegion>,
    /// インスタンス名
    name: &'static str,
}

/// アロケータマネージャ
/// 
/// システム全体のスラブアロケータを管理
pub struct SlabAllocatorManager {
    /// 一般的なスラブアロケータ (通常のメモリ用)
    general_allocator: SpinLock<SlabAllocator>,
    /// NUMA対応アロケータ (NUMAノード別)
    numa_allocators: SpinLock<Vec<SlabAllocator>>,
    /// 初期化済みフラグ
    initialized: AtomicUsize,
}

// SlabPage実装
impl SlabPage {
    /// 新しいスラブページを作成
    pub fn new(cache: NonNull<SlabCache>, object_size: usize, color_offset: usize) -> Result<Self, &'static str> {
        // ページを確保
        let page = Page::alloc(PageFlags::KERNEL_MEMORY)
            .map_err(|_| "スラブページ用のメモリ確保に失敗")?;
        
        // 利用可能な合計サイズを計算
        let available_size = page.size() - color_offset;
        
        // このページに収まるオブジェクト数を計算
        let total_objects = available_size / object_size;
        
        if total_objects == 0 {
            return Err("オブジェクトサイズが大きすぎるため、ページに収まりません");
        }
        
        // スラブページを初期化
        let mut slab_page = SlabPage {
            cache,
            page,
            free_list: SpinLock::new(None),
            free_count: AtomicUsize::new(total_objects),
            state: AtomicUsize::new(SlabPageState::Free as usize),
            total_objects,
        };
        
        // オブジェクトチェーンを作成
        slab_page.init_free_list(object_size, color_offset)?;
        
        Ok(slab_page)
    }
    
    /// フリーリストを初期化
    fn init_free_list(&mut self, object_size: usize, color_offset: usize) -> Result<(), &'static str> {
        // ページの開始アドレスを取得
        let base_addr = self.page.virtual_address().as_usize();
        
        // カラーオフセットを適用
        let start_addr = base_addr + color_offset;
        
        // 最初のオブジェクトポインタ
        let mut prev_obj: Option<NonNull<SlabObject>> = None;
        
        // 各オブジェクトを連結
        for i in 0..self.total_objects {
            let obj_addr = start_addr + (i * object_size);
            
            // 安全でない操作: メモリ領域をSlabObjectとして初期化
            let obj_ptr = unsafe {
                let ptr = obj_addr as *mut SlabObject;
                // 次のポインタをNullで初期化
                *ptr = SlabObject::new(None);
                NonNull::new_unchecked(ptr)
            };
            
            // 前のオブジェクトと連結
            if let Some(prev) = prev_obj {
                unsafe {
                    (*prev.as_ptr()).set_next(Some(obj_ptr));
                }
            } else {
                // 最初のオブジェクトをリストの先頭に設定
                *self.free_list.lock() = Some(obj_ptr);
            }
            
            prev_obj = Some(obj_ptr);
        }
        
        Ok(())
    }
    
    /// オブジェクトを割り当て
    pub fn allocate(&self) -> Option<NonNull<u8>> {
        // 空きがない場合は早期リターン
        if self.free_count.load(Ordering::Relaxed) == 0 {
            return None;
        }
        
        // フリーリストからオブジェクトを取得
        let mut free_list = self.free_list.lock();
        
        let obj_ptr = free_list.take()?;
        
        // 次のオブジェクトをフリーリストの先頭に設定
        unsafe {
            *free_list = (*obj_ptr.as_ptr()).next();
        }
        
        // 空きオブジェクト数を減少
        let new_free_count = self.free_count.fetch_sub(1, Ordering::Relaxed) - 1;
        
        // スラブの状態を更新
        if new_free_count == 0 {
            self.state.store(SlabPageState::Full as usize, Ordering::Relaxed);
        } else if new_free_count < self.total_objects {
            self.state.store(SlabPageState::PartiallyUsed as usize, Ordering::Relaxed);
        }
        
        // u8ポインタとして返す
        Some(unsafe { NonNull::new_unchecked(obj_ptr.as_ptr() as *mut u8) })
    }
    
    /// オブジェクトを解放
    pub fn free(&self, ptr: NonNull<u8>) -> Result<(), &'static str> {
        // ポインタがこのスラブに所属しているか確認
        let addr = ptr.as_ptr() as usize;
        let base_addr = self.page.virtual_address().as_usize();
        let page_end = base_addr + self.page.size();
        
        if addr < base_addr || addr >= page_end {
            return Err("ポインタはこのスラブに所属していません");
        }
        
        // SlabObjectにキャスト
        let obj_ptr = unsafe { NonNull::new_unchecked(ptr.as_ptr() as *mut SlabObject) };
        
        // フリーリストに追加
        let mut free_list = self.free_list.lock();
        
        unsafe {
            // 新しいオブジェクトの次ポインタを現在のフリーリストの先頭に設定
            (*obj_ptr.as_ptr()) = SlabObject::new(*free_list);
            
            // フリーリストの先頭を更新
            *free_list = Some(obj_ptr);
        }
        
        // 空きオブジェクト数を増加
        let new_free_count = self.free_count.fetch_add(1, Ordering::Relaxed) + 1;
        
        // スラブの状態を更新
        if new_free_count == self.total_objects {
            self.state.store(SlabPageState::Free as usize, Ordering::Relaxed);
        } else {
            self.state.store(SlabPageState::PartiallyUsed as usize, Ordering::Relaxed);
        }
        
        Ok(())
    }
    
    /// スラブの状態を取得
    pub fn state(&self) -> SlabPageState {
        match self.state.load(Ordering::Relaxed) {
            0 => SlabPageState::Free,
            1 => SlabPageState::PartiallyUsed,
            2 => SlabPageState::Full,
            _ => SlabPageState::Free, // デフォルト値
        }
    }
    
    /// 使用率を取得 (0-100%)
    pub fn usage_percent(&self) -> u8 {
        let free = self.free_count.load(Ordering::Relaxed);
        let used = self.total_objects - free;
        
        ((used as f32 / self.total_objects as f32) * 100.0) as u8
    }
}

// スラブキャッシュの実装
impl SlabCache {
    /// 新しいスラブキャッシュを作成
    pub fn new(
        name: &'static str,
        object_size: usize,
        object_align: usize
    ) -> Self {
        // 最小オブジェクトサイズを確保
        let min_size = SlabObject::min_size();
        let actual_size = if object_size < min_size {
            min_size
        } else {
            object_size
        };
        
        // アライメントを調整
        let actual_align = if object_align < 8 {
            8 // 最小8バイトアライメント
        } else {
            object_align
        };
        
        // キャッシュカラーリングの設定
        // メモリアクセスパターンの最適化のため、開始位置をランダム化
        let max_color_offset = Page::size() % actual_size;
        
        Self {
            object_size: actual_size,
            object_align: actual_align,
            name,
            max_color_offset,
            color_offset: AtomicUsize::new(0),
            free_slabs: SpinLock::new(Vec::new()),
            partial_slabs: SpinLock::new(Vec::new()),
            full_slabs: SpinLock::new(Vec::new()),
            allocation_count: AtomicUsize::new(0),
            free_count: AtomicUsize::new(0),
        }
    }
    
    /// 次のカラーオフセットを取得
    fn next_color_offset(&self) -> usize {
        if self.max_color_offset == 0 {
            return 0;
        }
        
        // 現在の値を取得し、循環的に増加
        let current = self.color_offset.load(Ordering::Relaxed);
        let next = (current + self.object_align) % self.max_color_offset;
        
        self.color_offset.store(next, Ordering::Relaxed);
        current
    }
    
    /// 新しいスラブページを作成して追加
    fn add_new_slab(&self) -> Result<NonNull<SlabPage>, &'static str> {
        // 自身のポインタを取得
        let self_ptr = unsafe { NonNull::new_unchecked(self as *const _ as *mut _) };
        
        // 次のカラーオフセットを取得
        let color_offset = self.next_color_offset();
        
        // 新しいスラブページを作成
        let slab_page = Box::new(SlabPage::new(self_ptr, self.object_size, color_offset)?);
        
        // ヒープに確保したスラブページへのポインタを取得
        let slab_ptr = unsafe { NonNull::new_unchecked(Box::into_raw(slab_page)) };
        
        // フリースラブリストに追加
        self.free_slabs.lock().push(slab_ptr);
        
        Ok(slab_ptr)
    }
    
    /// メモリを割り当て
    pub fn allocate(&self) -> Option<NonNull<u8>> {
        // 部分的に使用されているスラブから割り当てを試みる
        {
            let mut partial_slabs = self.partial_slabs.lock();
            
            for &slab_ptr in partial_slabs.iter() {
                unsafe {
                    if let Some(ptr) = (*slab_ptr.as_ptr()).allocate() {
                        // 割り当て成功の統計情報を更新
                        self.allocation_count.fetch_add(1, Ordering::Relaxed);
                        
                        // スラブが満杯になった場合はフルリストに移動
                        if (*slab_ptr.as_ptr()).state() == SlabPageState::Full {
                            let index = partial_slabs.iter().position(|&s| s == slab_ptr).unwrap();
                            let slab = partial_slabs.remove(index);
                            self.full_slabs.lock().push(slab);
                        }
                        
                        return Some(ptr);
                    }
                }
            }
        }
        
        // 空きスラブから割り当てを試みる
        {
            let mut free_slabs = self.free_slabs.lock();
            
            if let Some(&slab_ptr) = free_slabs.first() {
                unsafe {
                    if let Some(ptr) = (*slab_ptr.as_ptr()).allocate() {
                        // 割り当て成功の統計情報を更新
                        self.allocation_count.fetch_add(1, Ordering::Relaxed);
                        
                        // スラブの状態に応じてリストを移動
                        let slab = free_slabs.remove(0);
                        
                        match (*slab_ptr.as_ptr()).state() {
                            SlabPageState::PartiallyUsed => {
                                self.partial_slabs.lock().push(slab);
                            }
                            SlabPageState::Full => {
                                self.full_slabs.lock().push(slab);
                            }
                            _ => {
                                // 予期せぬ状態、空きリストに戻す
                                free_slabs.push(slab);
                            }
                        }
                        
                        return Some(ptr);
                    }
                }
            }
        }
        
        // 新しいスラブを作成して割り当て
        match self.add_new_slab() {
            Ok(slab_ptr) => {
                unsafe {
                    if let Some(ptr) = (*slab_ptr.as_ptr()).allocate() {
                        // 割り当て成功の統計情報を更新
                        self.allocation_count.fetch_add(1, Ordering::Relaxed);
                        
                        // スラブの状態に応じてリストを移動
                        let mut free_slabs = self.free_slabs.lock();
                        let index = free_slabs.iter().position(|&s| s == slab_ptr).unwrap();
                        let slab = free_slabs.remove(index);
                        
                        match (*slab_ptr.as_ptr()).state() {
                            SlabPageState::PartiallyUsed => {
                                self.partial_slabs.lock().push(slab);
                            }
                            SlabPageState::Full => {
                                self.full_slabs.lock().push(slab);
                            }
                            _ => {
                                // 予期せぬ状態、空きリストに戻す
                                free_slabs.push(slab);
                            }
                        }
                        
                        return Some(ptr);
                    }
                }
                
                // 割り当てに失敗した場合
                None
            }
            Err(err) => {
                warn!("新しいスラブページの作成に失敗: {}", err);
                None
            }
        }
    }
    
    /// メモリを解放
    pub fn free(&self, ptr: NonNull<u8>) -> Result<(), &'static str> {
        // ポインタが所属するスラブを見つける
        let addr = ptr.as_ptr() as usize;
        let slab_ptr = self.find_slab_containing(addr)?;
        
        // スラブの状態を記録
        let prev_state = unsafe { (*slab_ptr.as_ptr()).state() };
        
        // オブジェクトを解放
        unsafe {
            (*slab_ptr.as_ptr()).free(ptr)?;
        }
        
        // 解放成功の統計情報を更新
        self.free_count.fetch_add(1, Ordering::Relaxed);
        
        // スラブの新しい状態
        let new_state = unsafe { (*slab_ptr.as_ptr()).state() };
        
        // 状態が変わった場合、適切なリストに移動
        if prev_state != new_state {
            self.move_slab_between_lists(slab_ptr, prev_state, new_state)?;
        }
        
        Ok(())
    }
    
    /// アドレスを含むスラブを検索
    fn find_slab_containing(&self, addr: usize) -> Result<NonNull<SlabPage>, &'static str> {
        // すべてのスラブリストを検索
        for slab_ptr in self.free_slabs.lock().iter() {
            unsafe {
                let base = (*slab_ptr.as_ptr()).page.virtual_address().as_usize();
                let size = (*slab_ptr.as_ptr()).page.size();
                
                if addr >= base && addr < (base + size) {
                    return Ok(*slab_ptr);
                }
            }
        }
        
        for slab_ptr in self.partial_slabs.lock().iter() {
            unsafe {
                let base = (*slab_ptr.as_ptr()).page.virtual_address().as_usize();
                let size = (*slab_ptr.as_ptr()).page.size();
                
                if addr >= base && addr < (base + size) {
                    return Ok(*slab_ptr);
                }
            }
        }
        
        for slab_ptr in self.full_slabs.lock().iter() {
            unsafe {
                let base = (*slab_ptr.as_ptr()).page.virtual_address().as_usize();
                let size = (*slab_ptr.as_ptr()).page.size();
                
                if addr >= base && addr < (base + size) {
                    return Ok(*slab_ptr);
                }
            }
        }
        
        Err("アドレスを含むスラブが見つかりません")
    }
    
    /// スラブを適切なリストに移動
    fn move_slab_between_lists(
        &self,
        slab_ptr: NonNull<SlabPage>,
        from_state: SlabPageState,
        to_state: SlabPageState
    ) -> Result<(), &'static str> {
        // 同じ状態なら何もしない
        if from_state == to_state {
            return Ok(());
        }
        
        // 現在のリストからスラブを削除
        let slab = match from_state {
            SlabPageState::Free => {
                let mut free_slabs = self.free_slabs.lock();
                let index = free_slabs.iter().position(|&s| s == slab_ptr)
                    .ok_or("フリーリストにスラブが見つかりません")?;
                free_slabs.remove(index)
            },
            SlabPageState::PartiallyUsed => {
                let mut partial_slabs = self.partial_slabs.lock();
                let index = partial_slabs.iter().position(|&s| s == slab_ptr)
                    .ok_or("部分使用リストにスラブが見つかりません")?;
                partial_slabs.remove(index)
            },
            SlabPageState::Full => {
                let mut full_slabs = self.full_slabs.lock();
                let index = full_slabs.iter().position(|&s| s == slab_ptr)
                    .ok_or("フルリストにスラブが見つかりません")?;
                full_slabs.remove(index)
            },
        };
        
        // 新しいリストにスラブを追加
        match to_state {
            SlabPageState::Free => self.free_slabs.lock().push(slab),
            SlabPageState::PartiallyUsed => self.partial_slabs.lock().push(slab),
            SlabPageState::Full => self.full_slabs.lock().push(slab),
        }
        
        Ok(())
    }
    
    /// キャッシュの統計情報を取得
    pub fn stats(&self) -> SlabCacheStats {
        SlabCacheStats {
            name: self.name,
            object_size: self.object_size,
            object_align: self.object_align,
            free_slabs: self.free_slabs.lock().len(),
            partial_slabs: self.partial_slabs.lock().len(),
            full_slabs: self.full_slabs.lock().len(),
            allocations: self.allocation_count.load(Ordering::Relaxed),
            frees: self.free_count.load(Ordering::Relaxed),
        }
    }
}

/// スラブキャッシュの統計情報
#[derive(Debug, Clone)]
pub struct SlabCacheStats {
    pub name: &'static str,
    pub object_size: usize,
    pub object_align: usize,
    pub free_slabs: usize,
    pub partial_slabs: usize,
    pub full_slabs: usize,
    pub allocations: usize,
    pub frees: usize,
}

// スラブアロケータの実装
impl SlabAllocator {
    /// 新しいスラブアロケータを作成
    pub fn new(name: &'static str, pmem_region: Option<PmemRegion>) -> Self {
        Self {
            general_caches: RwLock::new(Vec::new()),
            specialized_caches: RwLock::new(Vec::new()),
            pmem_region,
            name,
        }
    }
    
    /// 一般的なサイズのキャッシュを作成
    pub fn create_general_caches(&self) {
        let mut caches = self.general_caches.write();
        
        // 一般的なサイズの範囲を設定
        let sizes = [
            8, 16, 32, 64, 96, 128, 192, 256, 384, 512, 
            768, 1024, 1536, 2048, 3072, 4096, 8192
        ];
        
        for &size in &sizes {
            let name = match size {
                8 => "slab-8",
                16 => "slab-16",
                32 => "slab-32",
                64 => "slab-64",
                96 => "slab-96",
                128 => "slab-128",
                192 => "slab-192",
                256 => "slab-256",
                384 => "slab-384",
                512 => "slab-512",
                768 => "slab-768",
                1024 => "slab-1k",
                1536 => "slab-1.5k",
                2048 => "slab-2k",
                3072 => "slab-3k",
                4096 => "slab-4k",
                8192 => "slab-8k",
                _ => "slab-unknown",
            };
            
            let cache = Box::new(SlabCache::new(name, size, 8));
            let cache_ptr = unsafe { NonNull::new_unchecked(Box::into_raw(cache)) };
            caches.push(cache_ptr);
        }
    }
    
    /// 特定の構造体用のキャッシュを作成
    pub fn create_specialized_cache<T>(&self, name: &'static str) -> Result<NonNull<SlabCache>, &'static str> {
        let size = size_of::<T>();
        let align = core::mem::align_of::<T>();
        
        let cache = Box::new(SlabCache::new(name, size, align));
        let cache_ptr = unsafe { NonNull::new_unchecked(Box::into_raw(cache)) };
        
        // 専用キャッシュリストに追加
        self.specialized_caches.write().push(cache_ptr);
        
        Ok(cache_ptr)
    }
    
    /// 指定したサイズに最適なキャッシュを見つける
    fn find_cache_for_size(&self, size: usize) -> Option<NonNull<SlabCache>> {
        // 一般キャッシュから適切なサイズを探す
        let caches = self.general_caches.read();
        
        for &cache_ptr in caches.iter() {
            unsafe {
                let cache_size = (*cache_ptr.as_ptr()).object_size;
                if cache_size >= size {
                    return Some(cache_ptr);
                }
            }
        }
        
        None
    }
    
    /// メモリを割り当て
    pub fn allocate(&self, size: usize) -> Option<NonNull<u8>> {
        if size == 0 {
            return None;
        }
        
        // 適切なキャッシュを見つける
        if let Some(cache_ptr) = self.find_cache_for_size(size) {
            unsafe {
                return (*cache_ptr.as_ptr()).allocate();
            }
        }
        
        // 適切なキャッシュが見つからない場合
        debug!("要求されたサイズ {} に適切なキャッシュが見つかりません", size);
        None
    }
    
    /// メモリを解放
    pub fn free(&self, ptr: NonNull<u8>, size: usize) -> Result<(), &'static str> {
        if let Some(cache_ptr) = self.find_cache_for_size(size) {
            unsafe {
                return (*cache_ptr.as_ptr()).free(ptr);
            }
        }
        
        Err("ポインタに対応するキャッシュが見つかりません")
    }
    
    /// 特定の型用の割り当て
    pub fn allocate_typed<T>(&self) -> Option<NonNull<T>> {
        let size = size_of::<T>();
        
        if let Some(ptr) = self.allocate(size) {
            // u8ポインタからTポインタに変換
            let typed_ptr = unsafe {
                NonNull::new_unchecked(ptr.as_ptr() as *mut T)
            };
            Some(typed_ptr)
        } else {
            None
        }
    }
    
    /// 特定の型用の解放
    pub fn free_typed<T>(&self, ptr: NonNull<T>) -> Result<(), &'static str> {
        let size = size_of::<T>();
        
        // Tポインタからu8ポインタに変換
        let u8_ptr = unsafe {
            NonNull::new_unchecked(ptr.as_ptr() as *mut u8)
        };
        
        self.free(u8_ptr, size)
    }
}

// スラブアロケータマネージャーの実装
impl SlabAllocatorManager {
    /// 新しいスラブアロケータマネージャーを作成
    pub fn new() -> Self {
        let general_allocator = SlabAllocator::new("general", None);
        
        Self {
            general_allocator: SpinLock::new(general_allocator),
            numa_allocators: SpinLock::new(Vec::new()),
            initialized: AtomicUsize::new(0),
        }
    }
    
    /// マネージャーを初期化
    pub fn initialize(&self) -> Result<(), &'static str> {
        // 既に初期化済みか確認
        if self.initialized.load(Ordering::Relaxed) != 0 {
            return Ok(());
        }
        
        // 一般的なアロケータを初期化
        {
            let mut allocator = self.general_allocator.lock();
            allocator.create_general_caches();
        }
        
        // NUMA対応アロケータを初期化 (将来的に実装)
        
        // 初期化完了フラグを設定
        self.initialized.store(1, Ordering::Relaxed);
        
        trace!("スラブアロケータマネージャーが初期化されました");
        Ok(())
    }
    
    /// メモリを割り当て
    pub fn allocate(&self, size: usize) -> Option<NonNull<u8>> {
        // 未初期化の場合は初期化を試みる
        if self.initialized.load(Ordering::Relaxed) == 0 {
            if let Err(err) = self.initialize() {
                warn!("スラブアロケータの初期化に失敗: {}", err);
                return None;
            }
        }
        
        // 一般アロケータから割り当て
        self.general_allocator.lock().allocate(size)
    }
    
    /// メモリを解放
    pub fn free(&self, ptr: NonNull<u8>, size: usize) -> Result<(), &'static str> {
        // 未初期化の場合はエラー
        if self.initialized.load(Ordering::Relaxed) == 0 {
            return Err("スラブアロケータが初期化されていません");
        }
        
        // 一般アロケータで解放
        self.general_allocator.lock().free(ptr, size)
    }
    
    /// 型付きメモリ割り当て
    pub fn allocate_typed<T>(&self) -> Option<NonNull<T>> {
        let size = size_of::<T>();
        
        if let Some(ptr) = self.allocate(size) {
            // u8ポインタからTポインタに変換
            let typed_ptr = unsafe {
                NonNull::new_unchecked(ptr.as_ptr() as *mut T)
            };
            Some(typed_ptr)
        } else {
            None
        }
    }
    
    /// 型付きメモリ解放
    pub fn free_typed<T>(&self, ptr: NonNull<T>) -> Result<(), &'static str> {
        let size = size_of::<T>();
        
        // Tポインタからu8ポインタに変換
        let u8_ptr = unsafe {
            NonNull::new_unchecked(ptr.as_ptr() as *mut u8)
        };
        
        self.free(u8_ptr, size)
    }
}

/// システム全体で使用するスラブアロケータのグローバルインスタンス
pub static SLAB_ALLOCATOR: SlabAllocatorManager = SlabAllocatorManager::new();

// テスト用コード
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_slab_page() {
        // スラブキャッシュを作成
        let cache = Box::new(SlabCache::new("test-cache", 64, 8));
        let cache_ptr = unsafe { NonNull::new_unchecked(Box::leak(cache)) };
        
        // スラブページを作成
        let slab_page = SlabPage::new(cache_ptr, 64, 0).unwrap();
        
        // 初期状態を確認
        assert_eq!(slab_page.state(), SlabPageState::Free);
        
        // オブジェクトを割り当て
        let obj1 = slab_page.allocate().unwrap();
        
        // 状態が変わったことを確認
        assert_eq!(slab_page.state(), SlabPageState::PartiallyUsed);
        
        // オブジェクトを解放
        slab_page.free(obj1).unwrap();
        
        // 状態が元に戻ったことを確認
        assert_eq!(slab_page.state(), SlabPageState::Free);
    }
    
    #[test]
    fn test_slab_cache() {
        // スラブキャッシュを作成
        let cache = SlabCache::new("test-cache", 64, 8);
        
        // オブジェクトを割り当て
        let obj1 = cache.allocate().unwrap();
        let obj2 = cache.allocate().unwrap();
        
        // 統計情報を確認
        let stats = cache.stats();
        assert_eq!(stats.allocations, 2);
        assert_eq!(stats.frees, 0);
        
        // オブジェクトを解放
        cache.free(obj1).unwrap();
        
        // 統計情報が更新されたことを確認
        let stats = cache.stats();
        assert_eq!(stats.allocations, 2);
        assert_eq!(stats.frees, 1);
        
        // 残りのオブジェクトを解放
        cache.free(obj2).unwrap();
    }
} 