// AetherOS スラブアロケータ実装
//
// このファイルはスラブアロケータの主要な機能と管理構造を実装します。

use core::sync::atomic::{AtomicUsize, Ordering};
use alloc::vec::Vec;
use spin::RwLock;

use crate::core::memory::buddy::{self, BuddyAllocator};
use crate::core::sync::once::Once;
use crate::arch::{self, PAGE_SIZE};
use crate::core::numa::NodeId;

use super::cache::{SlabCache, SlabCacheConfig};
use super::statistics::SlabStatistics;
use super::page::SlabPage;

/// スラブアロケータシステムで使用する最小のオブジェクトサイズ（バイト単位）
pub const MIN_OBJECT_SIZE: usize = 8;

/// スラブアロケータシステムで使用する最大のオブジェクトサイズ（バイト単位）
pub const MAX_OBJECT_SIZE: usize = 8192;

/// スラブキャッシュの数（サイズクラスごとに1つ）
pub const NUM_CACHES: usize = MAX_OBJECT_SIZE / MIN_OBJECT_SIZE;

/// スラブアロケータのグローバルインスタンス
static SLAB_ALLOCATOR: Once<RwLock<SlabAllocator>> = Once::new();

/// スラブアロケータを初期化する
pub fn init() {
    SLAB_ALLOCATOR.call_once(|| {
        let allocator = SlabAllocator::new();
        RwLock::new(allocator)
    });
}

/// グローバルスラブアロケータへの参照を取得する
pub fn get() -> &'static RwLock<SlabAllocator> {
    SLAB_ALLOCATOR.get()
        .expect("スラブアロケータが初期化されていません")
}

/// スラブアロケータのメイン構造体
pub struct SlabAllocator {
    /// サイズクラスごとのスラブキャッシュ
    caches: Vec<SlabCache>,
    
    /// 総割り当て回数
    total_allocations: AtomicUsize,
    
    /// 総解放回数
    total_frees: AtomicUsize,
    
    /// 現在割り当てられているバイト数
    allocated_bytes: AtomicUsize,
    
    /// スラブページの総数
    total_pages: AtomicUsize,
}

impl SlabAllocator {
    /// 新しいスラブアロケータを作成する
    pub fn new() -> Self {
        let mut caches = Vec::with_capacity(NUM_CACHES);
        
        // 各サイズクラスに対してキャッシュを初期化
        for i in 0..NUM_CACHES {
            let object_size = (i + 1) * MIN_OBJECT_SIZE;
            let config = SlabCacheConfig {
                object_size,
                align: MIN_OBJECT_SIZE,
                min_objects: 4,
                max_objects: 1024,
                grow_factor: 2,
            };
            
            caches.push(SlabCache::new(config));
        }
        
        Self {
            caches,
            total_allocations: AtomicUsize::new(0),
            total_frees: AtomicUsize::new(0),
            allocated_bytes: AtomicUsize::new(0),
            total_pages: AtomicUsize::new(0),
        }
    }
    
    /// 指定されたサイズのメモリを割り当てる
    pub fn allocate(&self, size: usize) -> Option<*mut u8> {
        // サイズが最大サイズを超える場合はバディアロケータに委譲
        if size > MAX_OBJECT_SIZE {
            let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
            let ptr = buddy::allocate_pages(pages);
            if let Some(ptr) = ptr {
                self.total_allocations.fetch_add(1, Ordering::Relaxed);
                self.allocated_bytes.fetch_add(pages * PAGE_SIZE, Ordering::Relaxed);
                return Some(ptr as *mut u8);
            }
            return None;
        }
        
        // 適切なサイズクラスを決定
        let size_class = super::size_class_for(size);
        let cache_index = (size_class / MIN_OBJECT_SIZE) - 1;
        
        if cache_index >= self.caches.len() {
            return None;
        }
        
        // 対応するキャッシュから割り当て
        let cache = &self.caches[cache_index];
        let ptr = cache.allocate();
        
        if let Some(ptr) = ptr {
            self.total_allocations.fetch_add(1, Ordering::Relaxed);
            self.allocated_bytes.fetch_add(size_class, Ordering::Relaxed);
        }
        
        ptr
    }
    
    /// メモリを解放する
    pub fn free(&self, ptr: *mut u8) {
        if ptr.is_null() {
            return;
        }
        
        // ポインタがどのスラブに属しているか確認
        for (i, cache) in self.caches.iter().enumerate() {
            if cache.owns(ptr) {
                let size_class = (i + 1) * MIN_OBJECT_SIZE;
                cache.free(ptr);
                self.total_frees.fetch_add(1, Ordering::Relaxed);
                self.allocated_bytes.fetch_sub(size_class, Ordering::Relaxed);
                return;
            }
        }
        
        // スラブに属していない場合はバディアロケータ経由で解放
        // ページアライメントを確認
        let addr = ptr as usize;
        if addr % PAGE_SIZE == 0 {
            // サイズは不明なので、ページの先頭メタデータから取得する必要がある
            // 仮実装：単一ページとして解放
            buddy::free_pages(ptr as *mut u64, 1);
            self.total_frees.fetch_add(1, Ordering::Relaxed);
            self.allocated_bytes.fetch_sub(PAGE_SIZE, Ordering::Relaxed);
        }
    }
    
    /// 指定されたNUMAノードに属するメモリを割り当てる
    pub fn allocate_on_node(&self, size: usize, node: NodeId) -> Option<*mut u8> {
        // 実装予定: NUMAノード指定のアロケーション
        // 現在は通常のアロケーションにフォールバック
        self.allocate(size)
    }
    
    /// 現在のスラブアロケータの統計情報を取得する
    pub fn get_statistics(&self) -> SlabStatistics {
        let mut stats = SlabStatistics {
            total_allocated_bytes: self.allocated_bytes.load(Ordering::Relaxed),
            total_allocations: self.total_allocations.load(Ordering::Relaxed),
            total_frees: self.total_frees.load(Ordering::Relaxed),
            total_slabs: self.total_pages.load(Ordering::Relaxed),
            cache_info: Vec::with_capacity(self.caches.len()),
        };
        
        // 各キャッシュの情報を収集
        for (i, cache) in self.caches.iter().enumerate() {
            let size_class = (i + 1) * MIN_OBJECT_SIZE;
            let cache_stats = cache.get_statistics(size_class);
            stats.cache_info.push(cache_stats);
        }
        
        stats
    }
    
    /// すべてのキャッシュでメンテナンス処理を実行する
    pub fn perform_maintenance(&self) {
        for cache in &self.caches {
            cache.shrink_if_needed();
        }
    }
    
    /// 新しいスラブページを割り当てる
    pub fn allocate_slab_page(&self) -> Option<&mut SlabPage> {
        let ptr = buddy::allocate_pages(1) as *mut SlabPage;
        if ptr.is_null() {
            return None;
        }
        
        self.total_pages.fetch_add(1, Ordering::Relaxed);
        
        // ページを初期化
        unsafe {
            let page = &mut *ptr;
            core::ptr::write(page, SlabPage::new());
            Some(page)
        }
    }
    
    /// スラブページを解放する
    pub fn free_slab_page(&self, page: &mut SlabPage) {
        let ptr = page as *mut SlabPage;
        buddy::free_pages(ptr as *mut u64, 1);
        self.total_pages.fetch_sub(1, Ordering::Relaxed);
    }
} 