// AetherOS スラブページ実装
//
// このファイルはスラブアロケータのページ管理を実装します。
// スラブページは同じサイズのオブジェクトを効率的に管理するための単位です。

use core::ptr::NonNull;
use core::mem;
use crate::core::memory::slab::object::SlabObject;
use crate::core::memory::PAGE_SIZE;
use crate::utils::logging::{log_debug, log_warn};

/// スラブページの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlabPageState {
    /// 空のページ（オブジェクトが割り当てられていない）
    Empty,
    
    /// 部分的に使用中のページ（一部のオブジェクトが割り当て済み）
    Partial,
    
    /// 完全に使用中のページ（すべてのオブジェクトが割り当て済み）
    Full,
}

/// スラブページの構造体
pub struct SlabPage {
    /// スラブページの先頭アドレス
    base_addr: *mut u8,
    
    /// オブジェクトサイズ
    object_size: usize,
    
    /// ページサイズ
    page_size: usize,
    
    /// 空きオブジェクトのリスト
    free_list: Option<NonNull<SlabObject>>,
    
    /// ページ内の総オブジェクト数
    total_objects: usize,
    
    /// 使用中のオブジェクト数
    used_objects: usize,
}

// 安全でないコードを含むため、Sendとsyncトレイトを手動実装
unsafe impl Send for SlabPage {}
unsafe impl Sync for SlabPage {}

impl SlabPage {
    /// 新しいスラブページを作成する
    ///
    /// # 引数
    /// * `base_addr` - ページの先頭アドレス
    /// * `object_size` - 各オブジェクトのサイズ（バイト）
    /// * `page_size` - ページサイズ（デフォルトは4KiB）
    ///
    /// # 安全性
    /// * `base_addr`は有効なメモリ領域を指しており、`page_size`バイトのメモリが確保されていること
    /// * 指定された領域は他のスラブページと重複していないこと
    pub unsafe fn new(base_addr: *mut u8, object_size: usize, page_size: usize) -> NonNull<Self> {
        let effective_size = page_size - mem::size_of::<SlabPage>();
        let total_objects = effective_size / object_size;
        
        // ページ構造体を先頭に配置
        let page_ptr = base_addr as *mut SlabPage;
        
        // メモリ上に構造体を初期化
        *page_ptr = SlabPage {
            base_addr,
            object_size,
            page_size,
            free_list: None,
            total_objects,
            used_objects: 0,
        };
        
        // オブジェクト用のメモリ領域を確保
        let objects_base = base_addr.add(mem::size_of::<SlabPage>());
        
        // 空きリストを構築
        let mut current_obj: Option<NonNull<SlabObject>> = None;
        
        // 最後のオブジェクトから構築（後入れ先出しリスト）
        for i in (0..total_objects).rev() {
            let obj_addr = objects_base.add(i * object_size);
            let obj = SlabObject::new(obj_addr);
            
            // 次のオブジェクトへのリンクを設定
            let obj_ref = obj.as_mut();
            obj_ref.next = current_obj;
            
            // このオブジェクトを現在のオブジェクトとする
            current_obj = Some(obj);
        }
        
        // 空きリストを設定
        (*page_ptr).free_list = current_obj;
        
        // NonNullポインタを返す
        NonNull::new_unchecked(page_ptr)
    }
    
    /// オブジェクトを割り当てる
    pub fn allocate(&mut self) -> Option<*mut u8> {
        if let Some(obj_ptr) = self.free_list {
            // 空きリストから最初のオブジェクトを取得
            let obj = unsafe { obj_ptr.as_ref() };
            
            // 空きリストを更新
            self.free_list = obj.next;
            
            // 使用中オブジェクト数を更新
            self.used_objects += 1;
            
            // オブジェクトが全て割り当てられたかチェック
            if self.free_list.is_none() {
                log_debug!("スラブページが満杯になりました");
            }
            
            // ポインタをオブジェクトデータ領域に変換して返す
            Some(obj_ptr.as_ptr() as *mut u8)
        } else {
            // 空きオブジェクトがない
            log_warn!("スラブページに空きオブジェクトがありません");
            None
        }
    }
    
    /// オブジェクトを解放する
    pub fn free(&mut self, ptr: *mut u8, clear_memory: bool) -> bool {
        // ポインタがこのページに含まれるか検証
        if !self.contains(ptr) {
            log_warn!("無効なポインタが解放されようとしました: {:p}", ptr);
            return false;
        }
        
        // メモリをゼロクリアする必要がある場合
        if clear_memory {
            unsafe {
                core::ptr::write_bytes(ptr, 0, self.object_size);
            }
        }
        
        // SlabObjectとして扱う
        let obj = unsafe { SlabObject::new(ptr) };
        
        // 空きリストに追加
        let obj_ref = unsafe { obj.as_mut() };
        obj_ref.next = self.free_list;
        self.free_list = Some(obj);
        
        // 使用中オブジェクト数を更新
        self.used_objects -= 1;
        
        true
    }
    
    /// 指定されたポインタがこのページに含まれるか確認する
    pub fn contains(&self, ptr: *mut u8) -> bool {
        let ptr_addr = ptr as usize;
        let base_addr = self.base_addr as usize;
        let end_addr = base_addr + self.page_size;
        
        // ポインタがページの範囲内にあるかチェック
        ptr_addr >= base_addr && ptr_addr < end_addr
    }
    
    /// ページの状態を取得する
    pub fn state(&self) -> SlabPageState {
        if self.used_objects == 0 {
            SlabPageState::Empty
        } else if self.used_objects == self.total_objects {
            SlabPageState::Full
        } else {
            SlabPageState::Partial
        }
    }
    
    /// 総オブジェクト数を取得する
    pub fn total_objects(&self) -> usize {
        self.total_objects
    }
    
    /// 使用中のオブジェクト数を取得する
    pub fn used_objects(&self) -> usize {
        self.used_objects
    }
    
    /// 空きオブジェクト数を取得する
    pub fn free_objects(&self) -> usize {
        self.total_objects - self.used_objects
    }
    
    /// 使用率を取得する（0.0 〜 1.0）
    pub fn utilization(&self) -> f64 {
        if self.total_objects > 0 {
            self.used_objects as f64 / self.total_objects as f64
        } else {
            0.0
        }
    }
}

/// シンプルなスラブページアロケータ
/// 
/// スラブページを管理するためのシンプルなアロケータ
pub struct SlabPageAllocator {
    /// 割り当て可能なページサイズ
    page_size: usize,
}

impl SlabPageAllocator {
    /// 新しいスラブページアロケータを作成する
    pub fn new(page_size: usize) -> Self {
        SlabPageAllocator {
            page_size: page_size.max(PAGE_SIZE),
        }
    }
    
    /// スラブページを割り当てる
    /// 
    /// バディアロケータなど下位のアロケータからメモリページを取得し、
    /// SlabPageとして初期化する
    pub fn allocate_page(&self, object_size: usize, raw_memory: *mut u8) -> Option<NonNull<SlabPage>> {
        if raw_memory.is_null() {
            return None;
        }
        
        let page = unsafe { SlabPage::new(raw_memory, object_size, self.page_size) };
        Some(page)
    }
    
    /// ページサイズを取得する
    pub fn page_size(&self) -> usize {
        self.page_size
    }
}

/// テスト用のスラブページアロケータ
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::alloc::{alloc, dealloc, Layout};
    
    #[test]
    fn test_slab_page_allocation() {
        // テスト用のメモリを確保
        let layout = Layout::from_size_align(4096, 4096).unwrap();
        let memory = unsafe { alloc(layout) };
        
        // スラブページを作成
        let page_ptr = unsafe { SlabPage::new(memory, 128, 4096) };
        let page = unsafe { page_ptr.as_mut() };
        
        // 総オブジェクト数を確認
        assert!(page.total_objects() > 0);
        
        // いくつかのオブジェクトを割り当て
        let obj1 = page.allocate().unwrap();
        let obj2 = page.allocate().unwrap();
        
        // 使用中オブジェクト数を確認
        assert_eq!(page.used_objects(), 2);
        
        // オブジェクトを解放
        assert!(page.free(obj1, true));
        
        // 使用中オブジェクト数を再確認
        assert_eq!(page.used_objects(), 1);
        
        // クリーンアップ
        unsafe { dealloc(memory, layout) };
    }
} 