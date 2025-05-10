// AetherOS スラブアロケータのオブジェクト実装
//
// このファイルはスラブアロケータのオブジェクト管理を提供します。
// スラブオブジェクトはフリーリストで連結され、メモリの効率的な割り当てと解放を可能にします。

use core::ptr::NonNull;
use core::mem::size_of;

/// スラブオブジェクト
///
/// スラブアロケータのフリーリストを構成するノード。
/// 未使用時は次のノードへのポインタを格納し、
/// 使用中は実際のデータとして使用されます。
#[repr(C)]
pub struct SlabObject {
    /// 次の空きオブジェクトへのポインタ
    next: Option<NonNull<SlabObject>>,
}

impl SlabObject {
    /// 新しいスラブオブジェクトを作成
    pub fn new(next: Option<NonNull<SlabObject>>) -> Self {
        Self { next }
    }

    /// 次のオブジェクトを設定
    pub fn set_next(&mut self, next: Option<NonNull<SlabObject>>) {
        self.next = next;
    }

    /// 次のオブジェクトを取得
    pub fn next(&self) -> Option<NonNull<SlabObject>> {
        self.next
    }

    /// スラブオブジェクトの最小サイズを取得
    ///
    /// これはポインタ1つのサイズに相当し、
    /// 最小のスラブオブジェクトサイズを決定します。
    pub fn min_size() -> usize {
        size_of::<Self>()
    }
}

/// スラブオブジェクトドロップガード
///
/// スラブから割り当てられたオブジェクトが確実にドロップされるようにするためのガード
pub struct SlabObjectGuard<T> {
    /// オブジェクトへのポインタ
    ptr: NonNull<T>,
    /// このオブジェクトが所属するスラブキャッシュへの参照
    cache: &'static dyn SlabObjectCache,
}

/// スラブオブジェクトキャッシュトレイト
///
/// オブジェクトの解放方法を知っているキャッシュを表す
pub trait SlabObjectCache {
    /// オブジェクトを解放
    fn free_object<T>(&self, ptr: NonNull<T>) -> Result<(), &'static str>;
}

impl<T> SlabObjectGuard<T> {
    /// 新しいスラブオブジェクトガードを作成
    pub fn new(ptr: NonNull<T>, cache: &'static dyn SlabObjectCache) -> Self {
        Self { ptr, cache }
    }

    /// 内部ポインタを取得（読み取り専用）
    pub fn as_ref(&self) -> &T {
        unsafe { self.ptr.as_ref() }
    }

    /// 内部ポインタを取得（可変）
    pub fn as_mut(&mut self) -> &mut T {
        unsafe { self.ptr.as_mut() }
    }

    /// 内部ポインタを消費して返す
    ///
    /// このメソッドを呼び出すと、ガードはオブジェクトの所有権を放棄し、
    /// 呼び出し元がオブジェクトの解放に責任を持つ必要があります。
    pub fn into_inner(self) -> NonNull<T> {
        // ドロップを防ぐためにフォーゲット
        let ptr = self.ptr;
        core::mem::forget(self);
        ptr
    }
}

impl<T> Drop for SlabObjectGuard<T> {
    fn drop(&mut self) {
        // オブジェクトをドロップしてから、スラブに解放
        unsafe {
            core::ptr::drop_in_place(self.ptr.as_ptr());
        }
        
        // オブジェクトをキャッシュに返却
        if let Err(e) = self.cache.free_object(self.ptr) {
            // エラー処理 (ログ記録など)
            // ここではパニックしないが、エラーを記録
            #[cfg(debug_assertions)]
            panic!("スラブオブジェクトの解放に失敗: {}", e);
        }
    }
}

impl<T> core::ops::Deref for SlabObjectGuard<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T> core::ops::DerefMut for SlabObjectGuard<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

// テスト用コード
#[cfg(test)]
mod tests {
    use super::*;
    
    // テスト用のモックキャッシュ
    struct MockCache {
        freed: core::sync::atomic::AtomicBool,
    }
    
    impl MockCache {
        fn new() -> Self {
            Self {
                freed: core::sync::atomic::AtomicBool::new(false),
            }
        }
        
        fn was_freed(&self) -> bool {
            self.freed.load(core::sync::atomic::Ordering::Relaxed)
        }
    }
    
    impl SlabObjectCache for MockCache {
        fn free_object<T>(&self, _ptr: NonNull<T>) -> Result<(), &'static str> {
            self.freed.store(true, core::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn test_slab_object() {
        // スラブオブジェクトを作成
        let obj2 = Box::new(SlabObject::new(None));
        let obj2_ptr = unsafe { NonNull::new_unchecked(Box::into_raw(obj2)) };
        
        let mut obj1 = SlabObject::new(Some(obj2_ptr));
        
        // 次のポインタが正しく設定されていることを確認
        assert!(obj1.next().is_some());
        
        // 次のポインタを変更
        obj1.set_next(None);
        
        // 次のポインタがNoneになったことを確認
        assert!(obj1.next().is_none());
        
        // メモリリークを防ぐためにobj2_ptrを再びBoxに変換して解放
        unsafe {
            let _ = Box::from_raw(obj2_ptr.as_ptr());
        }
    }
    
    #[test]
    fn test_slab_object_guard() {
        // テスト用データ
        struct TestData {
            value: i32,
        }
        
        // モックキャッシュを作成（静的ライフタイム）
        static MOCK_CACHE: MockCache = MockCache {
            freed: core::sync::atomic::AtomicBool::new(false),
        };
        
        // テストデータを作成
        let data = Box::new(TestData { value: 42 });
        let data_ptr = unsafe { NonNull::new_unchecked(Box::into_raw(data)) };
        
        // スコープを作成してガードをドロップ
        {
            let mut guard = SlabObjectGuard::new(data_ptr, &MOCK_CACHE);
            
            // データにアクセス
            assert_eq!(guard.value, 42);
            
            // データを変更
            guard.value = 100;
            assert_eq!(guard.value, 100);
        }
        
        // ガードがドロップされ、キャッシュのfree_objectが呼ばれたことを確認
        assert!(MOCK_CACHE.was_freed());
    }
} 