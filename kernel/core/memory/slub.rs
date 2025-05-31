// AetherOS SLUB (Slab Unqueued Blocks) メモリアロケータ
//
// Linuxカーネルのインスパイアを受けた高効率メモリアロケータ実装
// - 細かいオブジェクト割り当て向け最適化
// - キャッシュ効率を最大化
// - 高速割り当て・解放
// - メモリフラグメンテーション最小化

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use core::mem;
use alloc::vec::Vec;
use crate::core::sync::{Mutex, SpinLock};
use super::buddy::{BuddyAllocator, PhysicalAddress, BUDDY_ALLOCATOR};
use super::mm::page::{PAGE_SIZE, Page};

/// スラブサイズクラス（バイト単位）
/// 一般的に使用されるサイズに合わせて最適化
const SLUB_SIZES: &[usize] = &[
    8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224, 256, 320, 384, 448, 512, 640, 768, 896, 1024,
    1280, 1536, 1792, 2048, 2560, 3072, 3584, 4096
];

/// ページ毎のオブジェクト数の下限
const MIN_OBJECTS_PER_PAGE: usize = 8;

/// スラブの列挙体状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlubState {
    /// 完全（すべてのオブジェクトが利用可能）
    Full,
    /// 部分的（一部のオブジェクトが使用中）
    Partial,
    /// 空（すべてのオブジェクトが使用中）
    Empty,
}

/// スラブヘッダ構造体
#[repr(C)]
struct SlubPage {
    /// オブジェクトサイズ
    obj_size: usize,
    /// このスラブでの空きオブジェクト数
    free_count: AtomicUsize,
    /// 空きオブジェクトへのポインタ
    free_list: AtomicPtr<u8>,
    /// 次のスラブページへのポインタ
    next: AtomicPtr<SlubPage>,
    /// 前のスラブページへのポインタ
    prev: AtomicPtr<SlubPage>,
    /// このスラブが所属するキャッシュ
    cache: *mut SlubCache,
    /// フラグ（予約用）
    flags: AtomicUsize,
}

/// スラブキャッシュ構造体
struct SlubCache {
    /// オブジェクトサイズ
    obj_size: usize,
    /// オブジェクト間のオフセット（アライメント含む）
    obj_offset: usize,
    /// ページ毎のオブジェクト数
    objects_per_page: usize,
    /// 完全なスラブのリスト（すべてのオブジェクトが空き）
    full_slabs: SpinLock<*mut SlubPage>,
    /// 部分的なスラブのリスト（一部が使用中）
    partial_slabs: SpinLock<*mut SlubPage>,
    /// 空のスラブのリスト（すべて使用中）
    empty_slabs: SpinLock<*mut SlubPage>,
    /// このキャッシュで現在割り当て済みのページ数
    allocated_pages: AtomicUsize,
    /// アロケーション数
    alloc_count: AtomicUsize,
    /// フリー数
    free_count: AtomicUsize,
    /// アライメント
    alignment: usize,
    /// 名前（デバッグ用）
    name: &'static str,
}

/// カラーリングオフセット最大値
const MAX_COLOR_OFFSET: usize = 16;

/// グローバルSLUBアロケータ構造体
pub struct SlubAllocator {
    /// サイズ毎のキャッシュ
    caches: Vec<SlubCache>,
    /// 汎用キャッシュ（サイズ未指定の場合）
    generic_caches: Vec<SlubCache>,
    /// スラブキャッシュ（カーネルオブジェクト専用）
    kernel_caches: SpinLock<Vec<SlubCache>>,
    /// 初期化済みフラグ
    initialized: AtomicUsize,
    /// 統計情報
    stats: SlubStats,
}

/// SLUBアロケータの統計情報
#[derive(Debug, Default)]
struct SlubStats {
    /// 総割り当てオブジェクト数
    total_allocations: AtomicUsize,
    /// 総解放オブジェクト数
    total_frees: AtomicUsize,
    /// 割り当てられたページ総数
    total_pages: AtomicUsize,
    /// 割り当て失敗数
    allocation_failures: AtomicUsize,
    /// 現在使用中のオブジェクト数
    active_objects: AtomicUsize,
    /// 現在使用中のページ数
    active_pages: AtomicUsize,
    /// キャッシュミス数
    cache_misses: AtomicUsize,
}

/// SLUBアロケータのシングルトンインスタンス
pub static mut SLUB_ALLOCATOR: Option<SlubAllocator> = None;

impl SlubAllocator {
    /// 新しいSLUBアロケータを作成
    pub fn new() -> Self {
        // 固定サイズのキャッシュを初期化
        let mut caches = Vec::with_capacity(SLUB_SIZES.len());
        
        for &size in SLUB_SIZES {
            caches.push(Self::create_cache(size, size, "size"));
        }
        
        Self {
            caches,
            generic_caches: Vec::new(),
            kernel_caches: SpinLock::new(Vec::new()),
            initialized: AtomicUsize::new(0),
            stats: SlubStats::default(),
        }
    }
    
    /// SLUBアロケータを初期化
    pub fn init(&mut self) {
        if self.initialized.load(Ordering::SeqCst) != 0 {
            return;
        }
        
        // 汎用キャッシュを初期化
        self.init_generic_caches();
        
        // 初期化完了
        self.initialized.store(1, Ordering::SeqCst);
        
        // ログ出力
        log::info!("SLUB アロケータ初期化完了 ({} キャッシュ)", self.caches.len());
    }
    
    /// 汎用キャッシュを初期化
    fn init_generic_caches(&mut self) {
        // ページサイズベースの大きいオブジェクト用キャッシュ
        // ページサイズの1/2、1/4、1/8などでキャッシュを作成
        
        let page_size = PAGE_SIZE;
        let mut size = page_size / 2;
        
        while size > SLUB_SIZES[SLUB_SIZES.len() - 1] {
            self.generic_caches.push(Self::create_cache(size, size, "generic"));
            size /= 2;
        }
    }
    
    /// 指定サイズとアライメントで新しいスラブキャッシュを作成
    fn create_cache(size: usize, alignment: usize, name: &'static str) -> SlubCache {
        // オブジェクトサイズはアライメントに合わせて調整
        let obj_size = if size < mem::size_of::<*mut u8>() {
            mem::size_of::<*mut u8>()
        } else {
            size
        };
        
        // アライメントを2のべき乗に調整
        let alignment = if !alignment.is_power_of_two() {
            alignment.next_power_of_two()
        } else {
            alignment
        };
        
        // オブジェクト間隔はサイズとアライメントの最大値
        let obj_offset = if obj_size < alignment {
            alignment
        } else {
            // アライメントに合わせて切り上げ
            (obj_size + alignment - 1) & !(alignment - 1)
        };
        
        // ページ当たりのオブジェクト数を計算
        // ヘッダ分のスペースを考慮
        let header_size = mem::size_of::<SlubPage>();
        let usable_size = PAGE_SIZE - header_size;
        let objects_per_page = usable_size / obj_offset;
        
        // 最低限のオブジェクト数を確保
        let objects_per_page = if objects_per_page < MIN_OBJECTS_PER_PAGE {
            // 小さすぎる場合は複数ページを使用
            let pages_needed = (MIN_OBJECTS_PER_PAGE * obj_offset + usable_size - 1) / usable_size;
            (pages_needed * usable_size) / obj_offset
        } else {
            objects_per_page
        };
        
        SlubCache {
            obj_size,
            obj_offset,
            objects_per_page,
            full_slabs: SpinLock::new(ptr::null_mut()),
            partial_slabs: SpinLock::new(ptr::null_mut()),
            empty_slabs: SpinLock::new(ptr::null_mut()),
            allocated_pages: AtomicUsize::new(0),
            alloc_count: AtomicUsize::new(0),
            free_count: AtomicUsize::new(0),
            alignment,
            name,
        }
    }
    
    /// メモリを割り当て
    pub fn allocate(&self, layout: Layout) -> *mut u8 {
        if self.initialized.load(Ordering::SeqCst) == 0 {
            // 初期化前の割り当ては直接バディアロケータを使用
            return self.fallback_allocate(layout);
        }
        
        let size = layout.size();
        let align = layout.align();
        
        // 適切なキャッシュを見つける
        if let Some(cache) = self.find_cache(size, align) {
            self.allocate_from_cache(cache)
        } else {
            // 適切なキャッシュがない場合はバディアロケータを使用
            self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
            self.fallback_allocate(layout)
        }
    }
    
    /// キャッシュからメモリを割り当て
    fn allocate_from_cache(&self, cache: &SlubCache) -> *mut u8 {
        // 部分的にフリーなスラブから割り当てを試みる
        let mut partial_slabs = cache.partial_slabs.lock();
        
        if !(*partial_slabs).is_null() {
            // 部分的なスラブがある場合、そこから割り当て
            let slab = unsafe { &mut **partial_slabs };
            let obj = self.allocate_from_slab(slab);
            
            if !obj.is_null() {
                // 割り当て成功
                cache.alloc_count.fetch_add(1, Ordering::Relaxed);
                self.stats.total_allocations.fetch_add(1, Ordering::Relaxed);
                self.stats.active_objects.fetch_add(1, Ordering::Relaxed);
                
                // スラブの状態を更新
                self.update_slab_state(slab, cache);
                
                return obj;
            }
        }
        
        // 完全なスラブから割り当てを試みる
        let mut full_slabs = cache.full_slabs.lock();
        
        if !(*full_slabs).is_null() {
            // 完全なスラブがある場合、そこから割り当て
            let slab = unsafe { &mut **full_slabs };
            let obj = self.allocate_from_slab(slab);
            
            if !obj.is_null() {
                // 割り当て成功
                cache.alloc_count.fetch_add(1, Ordering::Relaxed);
                self.stats.total_allocations.fetch_add(1, Ordering::Relaxed);
                self.stats.active_objects.fetch_add(1, Ordering::Relaxed);
                
                // スラブの状態を更新
                self.update_slab_state(slab, cache);
                
                return obj;
            }
        }
        
        // 既存のスラブからの割り当てに失敗した場合、新しいスラブを作成
        let new_slab = self.create_new_slab(cache);
        if new_slab.is_null() {
            // スラブ作成失敗
            self.stats.allocation_failures.fetch_add(1, Ordering::Relaxed);
            return ptr::null_mut();
        }
        
        // 新しいスラブから割り当て
        let slab = unsafe { &mut *new_slab };
        let obj = self.allocate_from_slab(slab);
        
        if !obj.is_null() {
            // 割り当て成功
            cache.alloc_count.fetch_add(1, Ordering::Relaxed);
            self.stats.total_allocations.fetch_add(1, Ordering::Relaxed);
            self.stats.active_objects.fetch_add(1, Ordering::Relaxed);
            
            // 新しいスラブを部分的リストに追加
            self.add_slab_to_list(slab, &mut partial_slabs);
            
            // スラブの状態を更新
            self.update_slab_state(slab, cache);
            
            return obj;
        }
        
        // すべての割り当て試行が失敗
        self.stats.allocation_failures.fetch_add(1, Ordering::Relaxed);
        ptr::null_mut()
    }
    
    /// スラブからオブジェクトを割り当て
    fn allocate_from_slab(&self, slab: &mut SlubPage) -> *mut u8 {
        // フリーリストからオブジェクトを取得
        let free_obj = slab.free_list.load(Ordering::Acquire);
        
        if free_obj.is_null() {
            // フリーリストが空
            return ptr::null_mut();
        }
        
        // フリーリストの次の要素を取得
        let next_free = unsafe { *(free_obj as *const *mut u8) };
        
        // フリーリストを更新
        slab.free_list.store(next_free, Ordering::Release);
        
        // フリーカウントを減らす
        slab.free_count.fetch_sub(1, Ordering::Relaxed);
        
        // オブジェクトを返す
        free_obj
    }
    
    /// 新しいスラブを作成
    fn create_new_slab(&self, cache: &SlubCache) -> *mut SlubPage {
        // ページアロケータからメモリを確保
        let page_count = (cache.objects_per_page * cache.obj_offset + PAGE_SIZE - 1) / PAGE_SIZE;
        let page_addr = unsafe { BUDDY_ALLOCATOR.as_ref().unwrap().allocate_pages(page_count) };
        
        if page_addr == 0 {
            // ページアロケーションに失敗
            return ptr::null_mut();
        }
        
        // 統計情報を更新
        cache.allocated_pages.fetch_add(page_count, Ordering::Relaxed);
        self.stats.total_pages.fetch_add(page_count, Ordering::Relaxed);
        self.stats.active_pages.fetch_add(page_count, Ordering::Relaxed);
        
        // スラブヘッダをセットアップ
        let slab = page_addr as *mut SlubPage;
        unsafe {
            (*slab).obj_size = cache.obj_size;
            (*slab).free_count = AtomicUsize::new(cache.objects_per_page);
            (*slab).next = AtomicPtr::new(ptr::null_mut());
            (*slab).prev = AtomicPtr::new(ptr::null_mut());
            (*slab).cache = cache as *const _ as *mut _;
            (*slab).flags = AtomicUsize::new(0);
            
            // フリーリストをセットアップ
            // スラブページの先頭（ヘッダの後）からオブジェクトを配置
            let first_obj = (slab as usize + mem::size_of::<SlubPage>()) as *mut u8;
            (*slab).free_list = AtomicPtr::new(first_obj);
            
            // フリーリストを連結リストとして初期化
            let mut current = first_obj;
            for i in 0..cache.objects_per_page - 1 {
                let next = (first_obj as usize + (i + 1) * cache.obj_offset) as *mut u8;
                *(current as *mut *mut u8) = next;
                current = next;
            }
            
            // 最後のオブジェクトのnextをnullに
            *(current as *mut *mut u8) = ptr::null_mut();
        }
        
        slab
    }
    
    /// スラブを適切なリストに追加
    fn add_slab_to_list(&self, slab: &mut SlubPage, list: &mut *mut SlubPage) {
        if !(*list).is_null() {
            // リストの先頭に追加
            unsafe {
                (**list).prev.store(slab, Ordering::Release);
            }
        }
        
        slab.next.store(*list, Ordering::Release);
        slab.prev.store(ptr::null_mut(), Ordering::Release);
        *list = slab;
    }
    
    /// スラブをリストから削除
    fn remove_slab_from_list(&self, slab: &mut SlubPage, list: &mut *mut SlubPage) {
        let prev = slab.prev.load(Ordering::Acquire);
        let next = slab.next.load(Ordering::Acquire);
        
        if prev.is_null() {
            // リストの先頭
            *list = next;
        } else {
            // 中間または末尾
            unsafe {
                (*prev).next.store(next, Ordering::Release);
            }
        }
        
        if !next.is_null() {
            unsafe {
                (*next).prev.store(prev, Ordering::Release);
            }
        }
        
        // スラブのリンクをクリア
        slab.next.store(ptr::null_mut(), Ordering::Release);
        slab.prev.store(ptr::null_mut(), Ordering::Release);
    }
    
    /// スラブの状態を更新して適切なリストに移動
    fn update_slab_state(&self, slab: &mut SlubPage, cache: &SlubCache) {
        let free_count = slab.free_count.load(Ordering::Relaxed);
        let total_objects = cache.objects_per_page;
        
        // スラブの現在の状態を決定
        let current_state = if free_count == 0 {
            SlubState::Empty
        } else if free_count == total_objects {
            SlubState::Full
        } else {
            SlubState::Partial
        };
        
        // スラブを適切なリストに移動
        match current_state {
            SlubState::Empty => {
                // 部分的リストから空リストへ移動
                let mut partial_slabs = cache.partial_slabs.lock();
                if slab.next.load(Ordering::Relaxed) != ptr::null_mut() || 
                   slab.prev.load(Ordering::Relaxed) != ptr::null_mut() ||
                   *partial_slabs == slab {
                    self.remove_slab_from_list(slab, &mut partial_slabs);
                }
                drop(partial_slabs);
                
                let mut empty_slabs = cache.empty_slabs.lock();
                self.add_slab_to_list(slab, &mut empty_slabs);
            },
            SlubState::Partial => {
                // 状態に応じて適切なリストへ移動
                if slab.next.load(Ordering::Relaxed) == ptr::null_mut() && 
                   slab.prev.load(Ordering::Relaxed) == ptr::null_mut() {
                    // リストに含まれていない新しいスラブ
                    let mut partial_slabs = cache.partial_slabs.lock();
                    self.add_slab_to_list(slab, &mut partial_slabs);
                } else {
                    // 既に部分リストにあるのでそのまま
                }
            },
            SlubState::Full => {
                // 空リストから完全リストへ移動
                let mut full_slabs = cache.full_slabs.lock();
                if slab.next.load(Ordering::Relaxed) != ptr::null_mut() || 
                   slab.prev.load(Ordering::Relaxed) != ptr::null_mut() {
                    // 既にリストに含まれている場合は一旦削除
                    let mut empty_slabs = cache.empty_slabs.lock();
                    self.remove_slab_from_list(slab, &mut empty_slabs);
                }
                
                self.add_slab_to_list(slab, &mut full_slabs);
            },
        }
    }
    
    /// メモリを解放
    pub fn deallocate(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        
        if self.initialized.load(Ordering::SeqCst) == 0 {
            // 初期化前の解放は直接バディアロケータを使用
            self.fallback_deallocate(ptr, layout);
            return;
        }
        
        // ポインタからスラブを見つける
        if let Some(slab) = self.find_slab(ptr) {
            self.deallocate_to_slab(ptr, slab);
        } else {
            // スラブが見つからない場合はバディアロケータを使用
            self.fallback_deallocate(ptr, layout);
        }
    }
    
    /// スラブにオブジェクトを返却
    fn deallocate_to_slab(&self, ptr: *mut u8, slab: &SlubPage) {
        // キャッシュを取得
        let cache = unsafe { &*slab.cache };
        
        // フリーリストに追加
        let current_free = slab.free_list.load(Ordering::Acquire);
        unsafe {
            *(ptr as *mut *mut u8) = current_free;
        }
        slab.free_list.store(ptr, Ordering::Release);
        
        // フリーカウントを増やす
        let new_free_count = slab.free_count.fetch_add(1, Ordering::Relaxed) + 1;
        
        // 統計情報を更新
        cache.free_count.fetch_add(1, Ordering::Relaxed);
        self.stats.total_frees.fetch_add(1, Ordering::Relaxed);
        self.stats.active_objects.fetch_sub(1, Ordering::Relaxed);
        
        // スラブがすべて解放された場合の処理
        if new_free_count == cache.objects_per_page {
            // スラブを空リストから完全リストに移動
            let mut partial_slabs = cache.partial_slabs.lock();
            let mut empty_slabs = cache.empty_slabs.lock();
            
            if slab.next.load(Ordering::Relaxed) != ptr::null_mut() || 
               slab.prev.load(Ordering::Relaxed) != ptr::null_mut() {
                // リストに含まれている場合は一旦削除
                if *empty_slabs == slab as *mut _ {
                    self.remove_slab_from_list(slab as *mut _, &mut empty_slabs);
                } else {
                    self.remove_slab_from_list(slab as *mut _, &mut partial_slabs);
                }
            }
            
            let mut full_slabs = cache.full_slabs.lock();
            self.add_slab_to_list(slab as *mut _, &mut full_slabs);
        } else if new_free_count == 1 {
            // スラブが空から部分的に変わった場合
            let mut empty_slabs = cache.empty_slabs.lock();
            if slab.next.load(Ordering::Relaxed) != ptr::null_mut() || 
               slab.prev.load(Ordering::Relaxed) != ptr::null_mut() ||
               *empty_slabs == slab as *mut _ {
                self.remove_slab_from_list(slab as *mut _, &mut empty_slabs);
            }
            
            let mut partial_slabs = cache.partial_slabs.lock();
            self.add_slab_to_list(slab as *mut _, &mut partial_slabs);
        }
    }
    
    /// ポインタからスラブを見つける
    fn find_slab(&self, ptr: *mut u8) -> Option<&SlubPage> {
        // ポインタをページ境界にアライン
        let page_addr = (ptr as usize) & !(PAGE_SIZE - 1);
        
        // ページの先頭にスラブヘッダがある
        let slab = page_addr as *const SlubPage;
        
        // 有効なスラブかチェック
        unsafe {
            // 簡易的なチェック：obj_sizeが妥当なサイズか
            if (*slab).obj_size > 0 && (*slab).obj_size <= PAGE_SIZE {
                Some(&*slab)
            } else {
                None
            }
        }
    }
    
    /// サイズとアライメントに合ったキャッシュを見つける
    fn find_cache(&self, size: usize, align: usize) -> Option<&SlubCache> {
        // 固定サイズキャッシュから検索
        for cache in &self.caches {
            if cache.obj_size >= size && cache.alignment >= align {
                return Some(cache);
            }
        }
        
        // 汎用キャッシュから検索
        for cache in &self.generic_caches {
            if cache.obj_size >= size && cache.alignment >= align {
                return Some(cache);
            }
        }
        
        // カーネルオブジェクトキャッシュから検索
        let kernel_caches = self.kernel_caches.lock();
        for cache in &*kernel_caches {
            if cache.obj_size >= size && cache.alignment >= align {
                return Some(cache);
            }
        }
        
        None
    }
    
    /// フォールバックアロケーション（バディアロケータを使用）
    fn fallback_allocate(&self, layout: Layout) -> *mut u8 {
        // バディアロケータを使用
        unsafe {
            if let Some(buddy) = BUDDY_ALLOCATOR.as_ref() {
                let size = layout.size();
                let align = layout.align();
                
                // 必要なページ数を計算（アライメントを考慮）
                let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
                let addr = buddy.allocate_pages(pages);
                
                if addr == 0 {
                    return ptr::null_mut();
                }
                
                // アライメントに合わせる
                let aligned_addr = (addr + align - 1) & !(align - 1);
                
                aligned_addr as *mut u8
            } else {
                ptr::null_mut()
            }
        }
    }
    
    /// フォールバック解放（バディアロケータを使用）
    fn fallback_deallocate(&self, ptr: *mut u8, layout: Layout) {
        // バディアロケータを使用
        unsafe {
            if let Some(buddy) = BUDDY_ALLOCATOR.as_ref() {
                let size = layout.size();
                
                // ページ数を計算
                let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
                
                // ページ境界にアライン
                let page_addr = (ptr as usize) & !(PAGE_SIZE - 1);
                
                buddy.free_pages(page_addr, pages);
            }
        }
    }
    
    /// カーネルオブジェクト用の専用キャッシュを作成
    pub fn create_kmem_cache(&self, name: &'static str, size: usize, align: usize) -> Option<&SlubCache> {
        if self.initialized.load(Ordering::SeqCst) == 0 {
            return None;
        }
        
        let mut kernel_caches = self.kernel_caches.lock();
        let cache = Self::create_cache(size, align, name);
        kernel_caches.push(cache);
        
        // 最後に追加したキャッシュへの参照を返す
        Some(&kernel_caches[kernel_caches.len() - 1])
    }
    
    /// SLUB統計情報を取得
    pub fn get_stats(&self) -> &SlubStats {
        &self.stats
    }
    
    /// SLUBキャッシュ情報を出力（デバッグ用）
    pub fn print_cache_info(&self) {
        log::debug!("SLUB キャッシュ情報:");
        
        for (i, cache) in self.caches.iter().enumerate() {
            let allocs = cache.alloc_count.load(Ordering::Relaxed);
            let frees = cache.free_count.load(Ordering::Relaxed);
            let pages = cache.allocated_pages.load(Ordering::Relaxed);
            
            log::debug!("  キャッシュ[{}]: {}バイト, 割当={}, 解放={}, ページ={}",
                       i, cache.obj_size, allocs, frees, pages);
        }
        
        let stats = &self.stats;
        let total_allocs = stats.total_allocations.load(Ordering::Relaxed);
        let total_frees = stats.total_frees.load(Ordering::Relaxed);
        let active = stats.active_objects.load(Ordering::Relaxed);
        let pages = stats.active_pages.load(Ordering::Relaxed);
        
        log::debug!("総統計: 割当={}, 解放={}, 使用中={}, ページ={}",
                   total_allocs, total_frees, active, pages);
    }
}

/// SLUBアロケータのグローバルインスタンスを初期化
pub fn init_slub_allocator() {
    unsafe {
        if SLUB_ALLOCATOR.is_none() {
            SLUB_ALLOCATOR = Some(SlubAllocator::new());
            SLUB_ALLOCATOR.as_mut().unwrap().init();
        }
    }
}

/// グローバルSLUBアロケータのアクセサ
pub fn global_slub() -> &'static SlubAllocator {
    unsafe {
        SLUB_ALLOCATOR.as_ref().expect("SLUBアロケータが初期化されていません")
    }
}

// GlobalAlloc実装 - カーネル全体のアロケータとして使用可能
unsafe impl GlobalAlloc for SlubAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.allocate(layout)
    }
    
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.deallocate(ptr, layout)
    }
    
    // 配置 (aligned) アロケーションをサポート
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = self.allocate(layout);
        if !ptr.is_null() {
            ptr::write_bytes(ptr, 0, layout.size());
        }
        ptr
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: GlobalSlub = GlobalSlub;

/// グローバルアロケータとしてラップするための構造体
pub struct GlobalSlub;

unsafe impl GlobalAlloc for GlobalSlub {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if let Some(slub) = SLUB_ALLOCATOR.as_ref() {
            slub.allocate(layout)
        } else {
            // SLUBが初期化されていない場合はバディアロケータを使用
            if let Some(buddy) = BUDDY_ALLOCATOR.as_ref() {
                let pages = (layout.size() + PAGE_SIZE - 1) / PAGE_SIZE;
                let addr = buddy.allocate_pages(pages);
                
                if addr == 0 {
                    ptr::null_mut()
                } else {
                    // アライメントに合わせる
                    let align = layout.align();
                    let aligned_addr = (addr + align - 1) & !(align - 1);
                    aligned_addr as *mut u8
                }
            } else {
                // どちらも使えない場合はNULLを返す
                ptr::null_mut()
            }
        }
    }
    
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(slub) = SLUB_ALLOCATOR.as_ref() {
            slub.deallocate(ptr, layout);
        } else if let Some(buddy) = BUDDY_ALLOCATOR.as_ref() {
            // ページ境界にアライン
            let page_addr = (ptr as usize) & !(PAGE_SIZE - 1);
            let pages = (layout.size() + PAGE_SIZE - 1) / PAGE_SIZE;
            buddy.free_pages(page_addr, pages);
        }
    }
} 