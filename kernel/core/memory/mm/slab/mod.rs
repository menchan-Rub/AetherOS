// AetherOS Slabアロケータ
//
// このモジュールはカーネルのSlabメモリアロケータを実装します。
// Slabアロケータは、同じサイズの多数のオブジェクトを効率的に
// 割り当てるために使用されます。

mod object;
mod page;
pub mod api;

pub use object::SlabObjectMeta;
pub use page::{SlabPage, SlabPageState};
pub use crate::core::memory::mm::page::api::PAGE_SIZE;

/// キャッシュの情報を格納する構造体
#[derive(Debug, Clone, Copy)]
pub struct SlabCacheInfo {
    /// オブジェクトのサイズ（バイト）
    pub object_size: usize,
    /// アラインメント要件
    pub alignment: usize,
    /// 合計オブジェクト数
    pub total_objects: usize,
    /// 割り当て済みオブジェクト数
    pub allocated_objects: usize,
    /// Slabページ数
    pub page_count: usize,
}

/// Slabキャッシュ
///
/// 特定のサイズのオブジェクトを管理するためのキャッシュ。
/// 複数のSlabページを保持し、オブジェクトの割り当てと
/// 解放を効率的に行います。
pub struct SlabCache {
    /// キャッシュの名前
    name: &'static str,
    /// オブジェクトサイズ（バイト）
    object_size: usize,
    /// アラインメント要件
    alignment: usize,
    /// 完全に割り当てられていないSlabページのリスト
    partial_pages: alloc::vec::Vec<SlabPage>,
    /// 完全に割り当てられたSlabページのリスト
    full_pages: alloc::vec::Vec<SlabPage>,
    /// 空のSlabページのリスト（回収用）
    free_pages: alloc::vec::Vec<SlabPage>,
    /// 合計割り当て済みオブジェクト数
    allocated_count: usize,
    /// 合計オブジェクト数
    total_count: usize,
}

impl SlabCache {
    /// 新しいSlabキャッシュを作成
    ///
    /// # 引数
    /// * `name` - キャッシュの名前
    /// * `obj_size` - オブジェクトサイズ（バイト）
    /// * `align` - アラインメント要件
    pub fn new(name: &'static str, obj_size: usize, align: usize) -> Self {
        SlabCache {
            name,
            object_size: obj_size,
            alignment: align,
            partial_pages: alloc::vec::Vec::new(),
            full_pages: alloc::vec::Vec::new(),
            free_pages: alloc::vec::Vec::new(),
            allocated_count: 0,
            total_count: 0,
        }
    }

    /// オブジェクトを割り当てる
    ///
    /// # 戻り値
    /// * 成功した場合はオブジェクトへのポインタ、失敗した場合は `None`
    pub fn alloc(&mut self) -> Option<*mut u8> {
        // 部分的に使用されているページから割り当てを試みる
        for i in 0..self.partial_pages.len() {
            if let Some(ptr) = self.partial_pages[i].alloc_object(self.object_size) {
                // ページが完全に割り当てられたら、full_pagesに移動
                if self.partial_pages[i].is_full() {
                    let page = self.partial_pages.remove(i);
                    self.full_pages.push(page);
                }
                self.allocated_count += 1;
                return Some(ptr);
            }
        }

        // 空のページがあればそれを使用
        if !self.free_pages.is_empty() {
            let mut page = self.free_pages.pop().unwrap();
            let ptr = page.alloc_object(self.object_size).unwrap();
            
            // ページが完全に割り当てられたらfull_pagesに、そうでなければpartial_pagesに追加
            if page.is_full() {
                self.full_pages.push(page);
            } else {
                self.partial_pages.push(page);
            }
            
            self.allocated_count += 1;
            return Some(ptr);
        }

        // 新しいページを作成
        match SlabPage::new(self.object_size, self.alignment) {
            Some(mut page) => {
                // 新しいページの合計オブジェクト数を追加
                self.total_count += page.get_object_count();
                
                let ptr = page.alloc_object(self.object_size).unwrap();
                
                // ページが完全に割り当てられたらfull_pagesに、そうでなければpartial_pagesに追加
                if page.is_full() {
                    self.full_pages.push(page);
                } else {
                    self.partial_pages.push(page);
                }
                
                self.allocated_count += 1;
                Some(ptr)
            }
            None => None,
        }
    }

    /// オブジェクトが解放可能かチェック
    ///
    /// # 引数
    /// * `ptr` - チェックするポインタ
    ///
    /// # 戻り値
    /// * このキャッシュに属している場合は `true`
    pub fn can_free(&self, ptr: *mut u8) -> bool {
        // partial_pagesでチェック
        for page in &self.partial_pages {
            if page.contains(ptr) {
                return true;
            }
        }
        
        // full_pagesでチェック
        for page in &self.full_pages {
            if page.contains(ptr) {
                return true;
            }
        }
        
        false
    }

    /// オブジェクトを解放する
    ///
    /// # 引数
    /// * `ptr` - 解放するオブジェクトへのポインタ
    ///
    /// # 戻り値
    /// * 成功した場合は `true`、失敗した場合は `false`
    pub fn free(&mut self, ptr: *mut u8) -> bool {
        // partial_pagesでポインタを検索して解放
        for i in 0..self.partial_pages.len() {
            if self.partial_pages[i].contains(ptr) {
                let success = self.partial_pages[i].free_object(ptr);
                if success {
                    self.allocated_count -= 1;
                    
                    // ページが空になったら、free_pagesに移動
                    if self.partial_pages[i].is_empty() {
                        let page = self.partial_pages.remove(i);
                        self.free_pages.push(page);
                    }
                }
                return success;
            }
        }
        
        // full_pagesでポインタを検索して解放
        for i in 0..self.full_pages.len() {
            if self.full_pages[i].contains(ptr) {
                let success = self.full_pages[i].free_object(ptr);
                if success {
                    self.allocated_count -= 1;
                    
                    // ページがもう完全に割り当てられていない場合、partial_pagesに移動
                    if !self.full_pages[i].is_full() {
                        let page = self.full_pages.remove(i);
                        self.partial_pages.push(page);
                    }
                }
                return success;
            }
        }
        
        false
    }

    /// 未使用ページを解放してキャッシュを縮小
    ///
    /// # 戻り値
    /// * 解放されたページ数
    pub fn shrink(&mut self) -> usize {
        let initial_count = self.free_pages.len();
        
        // 使用率が低いpartialページも解放候補に
        self.partial_pages.retain(|page| {
            let usage = page.get_used_object_count() as f32 / page.get_object_count() as f32;
            
            if usage < 0.25 { // 25%以下の使用率のページは解放
                self.free_pages.push(page.clone());
                false
            } else {
                true
            }
        });
        
        // 空きページを解放
        let freed_pages = self.free_pages.len();
        self.total_count -= self.free_pages.iter().map(|p| p.get_object_count()).sum::<usize>();
        self.free_pages.clear();
        
        freed_pages - initial_count
    }

    /// キャッシュの情報を取得
    pub fn get_info(&self) -> SlabCacheInfo {
        SlabCacheInfo {
            object_size: self.object_size,
            alignment: self.alignment,
            total_objects: self.total_count,
            allocated_objects: self.allocated_count,
            page_count: self.partial_pages.len() + self.full_pages.len() + self.free_pages.len(),
        }
    }

    /// キャッシュ名を取得
    pub fn get_name(&self) -> &'static str {
        self.name
    }

    /// オブジェクトサイズを取得
    pub fn get_object_size(&self) -> usize {
        self.object_size
    }

    /// アラインメントを取得
    pub fn get_alignment(&self) -> usize {
        self.alignment
    }
} 