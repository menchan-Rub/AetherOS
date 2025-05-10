// AetherOS Slab Page
//
// このモジュールはSlabページを実装します。Slabページは
// 物理メモリページ上に複数のオブジェクトを管理します。

use crate::core::memory::mm::page::api::{alloc_pages, free_pages, PAGE_SIZE};
use super::object::SlabObjectMeta;
use core::{mem, ptr};
use log::debug;

/// Slabページの状態
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SlabPageState {
    /// 空のページ（オブジェクトが割り当てられていない）
    Empty,
    /// 部分的に使用されているページ（一部のオブジェクトが割り当てられている）
    Partial,
    /// 完全に使用されているページ（すべてのオブジェクトが割り当てられている）
    Full,
}

/// Slabページ
///
/// 物理ページ上に配置され、同じサイズの複数のオブジェクトを
/// 管理するためのデータ構造。
#[derive(Clone)]
pub struct SlabPage {
    /// ページの基底アドレス
    base_addr: *mut u8,
    /// フリーリストの先頭ポインタ
    free_list: *mut SlabObjectMeta,
    /// ページ内のオブジェクト数
    object_count: usize,
    /// 使用中のオブジェクト数
    used_count: usize,
    /// オブジェクトサイズ
    object_size: usize,
}

// *mut u8は複数のスレッドで安全に共有できる
unsafe impl Send for SlabPage {}
unsafe impl Sync for SlabPage {}

impl SlabPage {
    /// 新しいSlabページを作成
    ///
    /// # 引数
    /// * `obj_size` - オブジェクトのサイズ（バイト）
    /// * `align` - アラインメント要件
    ///
    /// # 戻り値
    /// * 成功した場合は `Some(SlabPage)`、失敗した場合は `None`
    pub fn new(obj_size: usize, align: usize) -> Option<Self> {
        // 物理ページを確保
        let page_addr = alloc_pages(1)?;
        
        // オブジェクトのサイズを調整（メタデータサイズとアラインメントを考慮）
        let real_size = Self::calculate_object_size(obj_size, align);
        
        // ページ内のオブジェクト数を計算
        let count = (PAGE_SIZE - mem::size_of::<SlabPage>()) / real_size;
        if count == 0 {
            // オブジェクトサイズが大きすぎる場合は解放して失敗
            free_pages(page_addr, 1);
            return None;
        }
        
        // Slabページ構造体を初期化
        let mut page = SlabPage {
            base_addr: page_addr as *mut u8,
            free_list: ptr::null_mut(),
            object_count: count,
            used_count: 0,
            object_size: real_size,
        };
        
        // フリーリストを初期化
        page.init_free_list();
        
        debug!("新しいSlabページを作成: アドレス={:p}, オブジェクト数={}, サイズ={}", 
               page.base_addr, count, real_size);
        
        Some(page)
    }
    
    /// オブジェクトの実際のサイズを計算する（メタデータとアラインメントを考慮）
    fn calculate_object_size(obj_size: usize, align: usize) -> usize {
        // メタデータサイズを含めたサイズを計算
        let meta_size = mem::size_of::<SlabObjectMeta>();
        let size_with_meta = obj_size + meta_size;
        
        // アラインメント要件に合わせて調整
        let remainder = size_with_meta % align;
        if remainder == 0 {
            size_with_meta
        } else {
            size_with_meta + (align - remainder)
        }
    }
    
    /// フリーリストを初期化
    fn init_free_list(&mut self) {
        let base = self.base_addr as usize;
        let object_size = self.object_size;
        
        // フリーリストの先頭を設定
        self.free_list = (base as *mut SlabObjectMeta).cast();
        
        // 各オブジェクトをリンクしてフリーリストを構築
        unsafe {
            for i in 0..self.object_count - 1 {
                let current = (base + i * object_size) as *mut SlabObjectMeta;
                let next = (base + (i + 1) * object_size) as *mut SlabObjectMeta;
                (*current).next = next;
            }
            
            // 最後のオブジェクトのnextはnull
            let last = (base + (self.object_count - 1) * object_size) as *mut SlabObjectMeta;
            (*last).next = ptr::null_mut();
        }
    }
    
    /// オブジェクトを割り当てる
    ///
    /// # 引数
    /// * `_obj_size` - オブジェクトサイズ（未使用だが、インターフェースの一貫性のため）
    ///
    /// # 戻り値
    /// * 成功した場合はオブジェクトへのポインタ、失敗した場合は `None`
    pub fn alloc_object(&mut self, _obj_size: usize) -> Option<*mut u8> {
        if self.free_list.is_null() {
            return None;
        }
        
        unsafe {
            // フリーリストから最初のオブジェクトを取得
            let obj_meta = self.free_list;
            
            // フリーリストを次のオブジェクトに更新
            self.free_list = (*obj_meta).next;
            
            // 使用中オブジェクト数を更新
            self.used_count += 1;
            
            // メタデータの後にあるデータ部分へのポインタを返す
            let data_ptr = (obj_meta as usize + mem::size_of::<SlabObjectMeta>()) as *mut u8;
            
            debug!("オブジェクト割り当て: アドレス={:p}, ページ={:p}", data_ptr, self.base_addr);
            
            Some(data_ptr)
        }
    }
    
    /// オブジェクトを解放する
    ///
    /// # 引数
    /// * `ptr` - 解放するオブジェクトへのポインタ
    ///
    /// # 戻り値
    /// * 成功した場合は `true`、失敗した場合は `false`
    pub fn free_object(&mut self, ptr: *mut u8) -> bool {
        // ポインタがこのページ内にあるか確認
        if !self.contains(ptr) {
            return false;
        }
        
        // データポインタからメタデータへのポインタを計算
        let meta_ptr = (ptr as usize - mem::size_of::<SlabObjectMeta>()) as *mut SlabObjectMeta;
        
        unsafe {
            // このオブジェクトをフリーリストの先頭に追加
            (*meta_ptr).next = self.free_list;
            self.free_list = meta_ptr;
            
            // 使用中オブジェクト数を更新
            self.used_count -= 1;
            
            debug!("オブジェクト解放: アドレス={:p}, ページ={:p}", ptr, self.base_addr);
            
            true
        }
    }
    
    /// 指定されたポインタがこのページに含まれているかをチェック
    ///
    /// # 引数
    /// * `ptr` - チェックするポインタ
    ///
    /// # 戻り値
    /// * このページに含まれている場合は `true`
    pub fn contains(&self, ptr: *mut u8) -> bool {
        let addr = ptr as usize;
        let start = self.base_addr as usize;
        let end = start + PAGE_SIZE;
        
        // ポインタがページの範囲内にあるかチェック
        addr >= start && addr < end
    }
    
    /// ページが完全に割り当てられているかをチェック
    pub fn is_full(&self) -> bool {
        self.used_count == self.object_count
    }
    
    /// ページが空（すべてのオブジェクトが解放されている）かをチェック
    pub fn is_empty(&self) -> bool {
        self.used_count == 0
    }
    
    /// ページの状態を取得
    pub fn get_state(&self) -> SlabPageState {
        if self.is_empty() {
            SlabPageState::Empty
        } else if self.is_full() {
            SlabPageState::Full
        } else {
            SlabPageState::Partial
        }
    }
    
    /// ページ内のオブジェクト数を取得
    pub fn get_object_count(&self) -> usize {
        self.object_count
    }
    
    /// 使用中のオブジェクト数を取得
    pub fn get_used_object_count(&self) -> usize {
        self.used_count
    }
    
    /// ページの基底アドレスを取得
    pub fn get_base_address(&self) -> *mut u8 {
        self.base_addr
    }
}

impl Drop for SlabPage {
    fn drop(&mut self) {
        // 使用中のオブジェクトがある場合は警告
        if self.used_count > 0 {
            debug!("警告: 使用中のオブジェクトがあるSlabページが解放されます: 使用中={}/{}", 
                   self.used_count, self.object_count);
        }
        
        // 物理ページを解放
        free_pages(self.base_addr as usize, 1);
        debug!("Slabページを解放: アドレス={:p}", self.base_addr);
    }
} 