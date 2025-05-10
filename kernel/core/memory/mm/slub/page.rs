// AetherOS Slub Page
//
// このモジュールはSlubページを実装します。Slubページは
// 物理メモリページ上に複数のオブジェクトを管理します。
// Slabよりも効率的なメモリ使用と高速な割り当て/解放を実現します。

use crate::core::memory::mm::page::api::{alloc_pages, free_pages, PAGE_SIZE};
use super::object::SlubObjectMeta;
use core::{mem, ptr};
use log::{debug, warn, trace};

/// Slubページの状態
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SlubPageState {
    /// 空のページ（オブジェクトが割り当てられていない）
    Empty,
    /// 部分的に使用されているページ（一部のオブジェクトが割り当てられている）
    Partial,
    /// 完全に使用されているページ（すべてのオブジェクトが割り当てられている）
    Full,
}

/// Slubページ
///
/// 物理ページ上に配置され、同じサイズの複数のオブジェクトを
/// 管理するためのデータ構造。Slabよりも最適化されています。
#[derive(Clone)]
pub struct SlubPage {
    /// ページの基底アドレス
    base_addr: *mut u8,
    /// フリーリストの先頭ポインタ
    free_list: *mut SlubObjectMeta,
    /// ページ内のオブジェクト数
    object_count: usize,
    /// 使用中のオブジェクト数
    used_count: usize,
    /// オブジェクトサイズ
    object_size: usize,
    /// メモリ節約モード
    memory_saving: bool,
}

// *mut u8は複数のスレッドで安全に共有できる
unsafe impl Send for SlubPage {}
unsafe impl Sync for SlubPage {}

impl SlubPage {
    /// 新しいSlubページを作成
    ///
    /// # 引数
    /// * `obj_size` - オブジェクトのサイズ（バイト）
    /// * `align` - アラインメント要件
    /// * `memory_saving` - メモリ節約モードを使用するか
    ///
    /// # 戻り値
    /// * 成功した場合は `Some(SlubPage)`、失敗した場合は `None`
    pub fn new(obj_size: usize, align: usize, memory_saving: bool) -> Option<Self> {
        // 物理ページを確保
        let page_addr = alloc_pages(1)?;
        
        // オブジェクトのサイズを調整（メタデータサイズとアラインメントを考慮）
        let real_size = Self::calculate_object_size(obj_size, align);
        
        // ページ内のオブジェクト数を計算
        let count = (PAGE_SIZE - mem::size_of::<SlubPage>()) / real_size;
        if count == 0 {
            // オブジェクトサイズが大きすぎる場合は解放して失敗
            free_pages(page_addr, 1);
            return None;
        }
        
        // Slubページ構造体を初期化
        let mut page = SlubPage {
            base_addr: page_addr as *mut u8,
            free_list: ptr::null_mut(),
            object_count: count,
            used_count: 0,
            object_size: real_size,
            memory_saving,
        };
        
        // フリーリストを初期化
        page.init_free_list();
        
        debug!("新しいSlubページを作成: アドレス={:p}, オブジェクト数={}, サイズ={}, メモリ節約={}",
               page.base_addr, count, real_size, memory_saving);
        
        Some(page)
    }
    
    /// オブジェクトの実際のサイズを計算する（メタデータとアラインメントを考慮）
    fn calculate_object_size(obj_size: usize, align: usize) -> usize {
        // メタデータサイズを含めたサイズを計算
        let meta_size = mem::size_of::<SlubObjectMeta>();
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
        self.free_list = (base as *mut SlubObjectMeta).cast();
        
        // 各オブジェクトをリンクしてフリーリストを構築
        unsafe {
            for i in 0..self.object_count - 1 {
                let current = (base + i * object_size) as *mut SlubObjectMeta;
                let next = (base + (i + 1) * object_size) as *mut SlubObjectMeta;
                
                // メモリ節約モードに応じてメタデータを初期化
                if self.memory_saving {
                    (*current) = SlubObjectMeta::new_compact();
                } else {
                    (*current) = SlubObjectMeta::new(self.base_addr);
                }
                
                (*current).next = next;
            }
            
            // 最後のオブジェクトのnextはnull
            let last = (base + (self.object_count - 1) * object_size) as *mut SlubObjectMeta;
            
            if self.memory_saving {
                (*last) = SlubObjectMeta::new_compact();
            } else {
                (*last) = SlubObjectMeta::new(self.base_addr);
            }
            
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
            let data_ptr = (obj_meta as usize + mem::size_of::<SlubObjectMeta>()) as *mut u8;
            
            trace!("オブジェクト割り当て: アドレス={:p}, ページ={:p}", data_ptr, self.base_addr);
            
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
        let meta_ptr = (ptr as usize - mem::size_of::<SlubObjectMeta>()) as *mut SlubObjectMeta;
        
        unsafe {
            // SLUB最適化：メモリ節約モードでない場合は、逆参照によるページ所有権の確認
            if !self.memory_saving && (*meta_ptr).page != self.base_addr {
                warn!("Slubページの不一致検出: 期待={:p}, 実際={:p}, オブジェクト={:p}",
                     self.base_addr, (*meta_ptr).page, ptr);
                return false;
            }
            
            // このオブジェクトをフリーリストの先頭に追加
            (*meta_ptr).next = self.free_list;
            self.free_list = meta_ptr;
            
            // 使用中オブジェクト数を更新
            self.used_count -= 1;
            
            trace!("オブジェクト解放: アドレス={:p}, ページ={:p}", ptr, self.base_addr);
            
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
        
        // SLUB最適化：アドレス範囲チェックの高速化
        // ポインタがページの範囲内にあるかだけでなく、オブジェクト境界上にあるかもチェック
        if addr >= start && addr < end {
            // オブジェクト境界チェック：オブジェクトの開始位置から正確なオフセットにあるか
            let obj_offset = (addr - start - mem::size_of::<SlubObjectMeta>()) % self.object_size;
            obj_offset == 0
        } else {
            false
        }
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
    pub fn get_state(&self) -> SlubPageState {
        if self.is_empty() {
            SlubPageState::Empty
        } else if self.is_full() {
            SlubPageState::Full
        } else {
            SlubPageState::Partial
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
    
    /// メモリ使用効率を取得
    pub fn get_memory_efficiency(&self) -> f32 {
        let total_size = PAGE_SIZE;
        let used_size = self.object_size * self.used_count;
        
        used_size as f32 / total_size as f32
    }
    
    /// オブジェクトのフラグメンテーション率を取得
    pub fn get_fragmentation_ratio(&self) -> f32 {
        if self.object_count == 0 {
            return 0.0;
        }
        
        1.0 - (self.used_count as f32 / self.object_count as f32)
    }
}

impl Drop for SlubPage {
    fn drop(&mut self) {
        // 使用中のオブジェクトがある場合は警告
        if self.used_count > 0 {
            warn!("警告: 使用中のオブジェクトがあるSlubページが解放されます: 使用中={}/{}", 
                   self.used_count, self.object_count);
        }
        
        // 物理ページを解放
        free_pages(self.base_addr as usize, 1);
        debug!("Slubページを解放: アドレス={:p}", self.base_addr);
    }
} 