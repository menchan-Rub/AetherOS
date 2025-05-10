// AetherOS スラブアロケータモジュール
//
// このモジュールはメモリスラブアロケータのコア実装を提供します。
// スラブアロケータは同じサイズのオブジェクトを効率的に割り当てるために設計されています。

mod object;
mod slab;
mod sync;

use core::ptr::NonNull;
use core::alloc::{GlobalAlloc, Layout};
use object::{SlabObject, SlabObjectGuard, SlabObjectCache};
use slab::{SlabAllocator, SlabAllocatorManager, SlabCache, SLAB_ALLOCATOR};
use sync::{SpinLock, RwLock};

// Re-export public APIs
pub use object::{SlabObjectGuard, SlabObjectCache};
pub use slab::{SlabCacheStats, SlabPageState};
pub use sync::{SpinLock, RwLock, SpinLockGuard, RwLockReadGuard, RwLockWriteGuard};

/// スラブアロケータのグローバルAPIを提供する構造体
pub struct SlabAllocatorAPI;

impl SlabAllocatorAPI {
    /// スラブアロケータを初期化
    pub fn initialize() -> Result<(), &'static str> {
        SLAB_ALLOCATOR.initialize()
    }

    /// 指定したサイズのメモリを割り当て
    pub fn allocate(size: usize) -> Option<NonNull<u8>> {
        SLAB_ALLOCATOR.allocate(size)
    }

    /// 指定したサイズのメモリを解放
    pub fn free(ptr: NonNull<u8>, size: usize) -> Result<(), &'static str> {
        SLAB_ALLOCATOR.free(ptr, size)
    }

    /// 型指定メモリを割り当て
    pub fn allocate_typed<T>() -> Option<NonNull<T>> {
        SLAB_ALLOCATOR.allocate_typed::<T>()
    }

    /// 型指定メモリを解放
    pub fn free_typed<T>(ptr: NonNull<T>) -> Result<(), &'static str> {
        SLAB_ALLOCATOR.free_typed::<T>()
    }

    /// オブジェクトガードを作成
    ///
    /// このメソッドはオブジェクトを割り当て、
    /// スコープから抜けると自動的に解放される
    /// SlabObjectGuardを返します。
    pub fn allocate_object<T>() -> Option<SlabObjectGuard<T>> 
    where
        T: 'static,
    {
        struct GlobalSlabCache;
        
        impl SlabObjectCache for GlobalSlabCache {
            fn free_object<T>(&self, ptr: NonNull<T>) -> Result<(), &'static str> {
                SLAB_ALLOCATOR.free_typed::<T>(ptr)
            }
        }
        
        // 静的キャッシュインスタンス
        static GLOBAL_CACHE: GlobalSlabCache = GlobalSlabCache;
        
        if let Some(ptr) = SLAB_ALLOCATOR.allocate_typed::<T>() {
            Some(SlabObjectGuard::new(ptr, &GLOBAL_CACHE))
        } else {
            None
        }
    }
    
    /// カスタム構造体用のキャッシュを作成
    pub fn create_object_cache<T>(name: &'static str) -> Result<ObjectCache<T>, &'static str> {
        let cache_ptr = SLAB_ALLOCATOR.general_allocator.lock().create_specialized_cache::<T>(name)?;
        Ok(ObjectCache {
            cache_ptr,
            _marker: core::marker::PhantomData,
        })
    }
}

/// 特定の型用のオブジェクトキャッシュ
pub struct ObjectCache<T> {
    cache_ptr: NonNull<SlabCache>,
    _marker: core::marker::PhantomData<T>,
}

impl<T> SlabObjectCache for ObjectCache<T> {
    fn free_object<U>(&self, ptr: NonNull<U>) -> Result<(), &'static str> {
        // 型チェック（デバッグビルドのみ）
        #[cfg(debug_assertions)]
        {
            assert_eq!(core::mem::size_of::<T>(), core::mem::size_of::<U>());
            assert_eq!(core::mem::align_of::<T>(), core::mem::align_of::<U>());
        }
        
        unsafe {
            // ポインタ型をTに変換
            let t_ptr = NonNull::new_unchecked(ptr.as_ptr() as *mut T);
            
            // キャッシュを使用して解放
            (*self.cache_ptr.as_ptr()).free(NonNull::new_unchecked(t_ptr.as_ptr() as *mut u8))
        }
    }
}

impl<T> ObjectCache<T> {
    /// キャッシュから新しいオブジェクトを割り当て
    pub fn allocate(&self) -> Option<SlabObjectGuard<T>> {
        unsafe {
            if let Some(ptr) = (*self.cache_ptr.as_ptr()).allocate() {
                // ポインタ型をTに変換
                let t_ptr = NonNull::new_unchecked(ptr.as_ptr() as *mut T);
                
                // ガードを作成
                Some(SlabObjectGuard::new(t_ptr, self))
            } else {
                None
            }
        }
    }
    
    /// 統計情報を取得
    pub fn stats(&self) -> SlabCacheStats {
        unsafe {
            (*self.cache_ptr.as_ptr()).stats()
        }
    }
}

/// グローバルアロケータ実装
///
/// Rustのグローバルアロケータとしてスラブアロケータを使用するための実装
#[global_allocator]
pub static GLOBAL_ALLOCATOR: KernelAllocator = KernelAllocator;

pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // スラブアロケータが初期化されていない場合は初期化を試みる
        if let Err(_) = SLAB_ALLOCATOR.initialize() {
            return core::ptr::null_mut();
        }
        
        // アライメントを考慮したサイズを計算
        let size = layout.size().max(layout.align());
        
        match SLAB_ALLOCATOR.allocate(size) {
            Some(ptr) => ptr.as_ptr(),
            None => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        
        // アライメントを考慮したサイズを計算
        let size = layout.size().max(layout.align());
        
        if let Err(_) = SLAB_ALLOCATOR.free(NonNull::new_unchecked(ptr), size) {
            // 解放に失敗した場合はログ出力かパニック
            #[cfg(debug_assertions)]
            panic!("メモリ解放に失敗しました");
        }
    }
}

// テスト用コード
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    
    #[test]
    fn test_slab_allocator_api() {
        // スラブアロケータを初期化
        SlabAllocatorAPI::initialize().unwrap();
        
        // メモリを割り当て
        let ptr = SlabAllocatorAPI::allocate(64).unwrap();
        
        // メモリを解放
        SlabAllocatorAPI::free(ptr, 64).unwrap();
    }
    
    #[test]
    fn test_object_cache() {
        // テスト用構造体
        struct TestObject {
            id: u64,
            data: [u8; 32],
        }
        
        // 専用キャッシュを作成
        let cache = SlabAllocatorAPI::create_object_cache::<TestObject>("test-object").unwrap();
        
        // オブジェクトのコレクションを作成
        let mut objects = Vec::new();
        
        // 10個のオブジェクトを割り当て
        for i in 0..10 {
            let mut obj = cache.allocate().unwrap();
            obj.id = i;
            obj.data.fill(i as u8);
            objects.push(obj);
        }
        
        // データが正しいことを確認
        for (i, obj) in objects.iter().enumerate() {
            assert_eq!(obj.id, i as u64);
            assert!(obj.data.iter().all(|&b| b == i as u8));
        }
        
        // 統計情報を確認
        let stats = cache.stats();
        assert_eq!(stats.allocations, 10);
        
        // オブジェクトを解放
        objects.clear();
        
        // 解放後の統計情報を確認
        let stats = cache.stats();
        assert_eq!(stats.frees, 10);
    }
    
    #[test]
    fn test_global_allocator() {
        // グローバルアロケータを使用した割り当てテスト
        let mut vec: Vec<u32> = Vec::with_capacity(100);
        
        for i in 0..100 {
            vec.push(i);
        }
        
        // データを確認
        for (i, &value) in vec.iter().enumerate() {
            assert_eq!(value, i as u32);
        }
    }
} 