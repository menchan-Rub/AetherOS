// AetherOS SLUB ページ実装

use core::sync::atomic::{AtomicUsize, Ordering};
use crate::memory::{PAGE_SIZE, buddy};
use super::CacheId;

/// スラブページの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageState {
    /// 空きスラブ
    Free,
    /// 部分的に使用されているスラブ
    Partial,
    /// 完全に使用されているスラブ
    Full,
}

/// スラブページ構造体
#[derive(Debug)]
pub struct SlubPage {
    /// ページアドレス
    address: usize,
    
    /// オブジェクトサイズ
    object_size: usize,
    
    /// スラブあたりのオブジェクト数
    objects_per_slab: usize,
    
    /// 使用中オブジェクト数
    used_objects: AtomicUsize,
    
    /// カラーオフセット（キャッシュライン配置最適化用）
    color_offset: usize,
    
    /// 最初のフリーオブジェクトへのポインタ
    free_list: AtomicUsize,
    
    /// オーナーキャッシュID
    owner_id: CacheId,
}

impl SlubPage {
    /// 新しいスラブページを作成
    pub fn new(
        address: usize,
        object_size: usize,
        objects_per_slab: usize,
        color_offset: usize,
        owner_id: CacheId,
        zero_init: bool
    ) -> Self {
        // 最初のオブジェクトの開始アドレスを計算
        let first_obj_addr = address + color_offset;
        
        let page = SlubPage {
            address,
            object_size,
            objects_per_slab,
            used_objects: AtomicUsize::new(0),
            color_offset,
            free_list: AtomicUsize::new(first_obj_addr),
            owner_id,
        };
        
        // フリーリストを初期化
        page.initialize_free_list(zero_init);
        
        page
    }
    
    /// フリーリストを初期化
    fn initialize_free_list(&self, zero_init: bool) {
        let first_obj_addr = self.address + self.color_offset;
        
        // 各オブジェクトを連結リストとして初期化
        for i in 0..self.objects_per_slab - 1 {
            let obj_addr = first_obj_addr + i * self.object_size;
            let next_obj_addr = obj_addr + self.object_size;
            
            if zero_init {
                // オブジェクト本体をゼロクリア
                unsafe {
                    core::ptr::write_bytes(
                        obj_addr as *mut u8, 
                        0, 
                        self.object_size - core::mem::size_of::<usize>()
                    );
                }
            }
            
            // 次のオブジェクトへのポインタを設定
            unsafe {
                *(obj_addr as *mut usize) = next_obj_addr;
            }
        }
        
        // 最後のオブジェクトのポインタを0に設定
        let last_obj_addr = first_obj_addr + (self.objects_per_slab - 1) * self.object_size;
        
        if zero_init {
            // 最後のオブジェクト本体もゼロクリア
            unsafe {
                core::ptr::write_bytes(
                    last_obj_addr as *mut u8, 
                    0, 
                    self.object_size - core::mem::size_of::<usize>()
                );
            }
        }
        
        // 最後のオブジェクトのポインタを0に設定
        unsafe {
            *(last_obj_addr as *mut usize) = 0;
        }
    }
    
    /// ページアドレスを取得
    pub fn address(&self) -> usize {
        self.address
    }
    
    /// オブジェクトを割り当て
    pub fn allocate_object(&self) -> Option<usize> {
        // 空きオブジェクトがあるか確認
        let free_obj_addr = self.free_list.load(Ordering::Acquire);
        if free_obj_addr == 0 {
            return None;
        }
        
        // 次の空きオブジェクトをロード
        let next_free = unsafe { *(free_obj_addr as *const usize) };
        
        // フリーリストを更新
        self.free_list.store(next_free, Ordering::Release);
        
        // 使用中カウントを更新
        self.used_objects.fetch_add(1, Ordering::Relaxed);
        
        // リストポインタのオフセット分を進めてユーザーデータの開始アドレスを返す
        Some(free_obj_addr + core::mem::size_of::<usize>())
    }
    
    /// オブジェクトを解放
    pub fn free_object(&self, address: usize) -> Result<(), &'static str> {
        // アドレスがこのスラブのものか検証
        if address < self.address || address >= self.address + PAGE_SIZE {
            return Err("オブジェクトがこのスラブに属していません");
        }
        
        // リストポインタ用にアドレスを調整
        let obj_addr = address - core::mem::size_of::<usize>();
        
        // 現在のフリーリストの先頭を取得
        let current_free = self.free_list.load(Ordering::Relaxed);
        
        // 解放されたオブジェクトを新しいフリーリストの先頭に設定
        unsafe {
            *(obj_addr as *mut usize) = current_free;
        }
        
        // フリーリストを更新
        self.free_list.store(obj_addr, Ordering::Release);
        
        // 使用中カウントを更新
        self.used_objects.fetch_sub(1, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// スラブが空かどうか
    pub fn is_empty(&self) -> bool {
        self.used_objects.load(Ordering::Relaxed) == 0
    }
    
    /// スラブが満杯かどうか
    pub fn is_full(&self) -> bool {
        self.used_objects.load(Ordering::Relaxed) >= self.objects_per_slab
    }
    
    /// スラブの状態を取得
    pub fn state(&self) -> PageState {
        let used = self.used_objects.load(Ordering::Relaxed);
        
        if used == 0 {
            PageState::Free
        } else if used >= self.objects_per_slab {
            PageState::Full
        } else {
            PageState::Partial
        }
    }
    
    /// 使用中のオブジェクト数を取得
    pub fn used_count(&self) -> usize {
        self.used_objects.load(Ordering::Relaxed)
    }
    
    /// オーナーキャッシュIDを取得
    pub fn owner_id(&self) -> CacheId {
        self.owner_id
    }
    
    /// スラブを破棄（バディアロケータに返却）
    pub fn destroy(&self) {
        // バディアロケータに返却
        let _ = buddy::free_pages(self.address, 1);
    }
} 