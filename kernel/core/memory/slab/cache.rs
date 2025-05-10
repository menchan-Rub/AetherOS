// AetherOS スラブキャッシュ実装
//
// このファイルはスラブアロケータのキャッシュ管理を実装します。
// キャッシュは同じサイズのオブジェクトを効率的に割り当てるための仕組みです。

use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use crate::core::memory::slab::page::{SlabPage, SlabPageState};
use crate::core::memory::slab::object::SlabObject;
use crate::core::numa::NumaNodeId;
use crate::utils::logging::{log_debug, log_info, log_warn};

/// スラブキャッシュの構造体
/// 
/// このキャッシュは特定のサイズのオブジェクト群を管理します。
/// 複数のスラブページを保持し、効率的なメモリ割り当てを実現します。
pub struct SlabCache {
    /// キャッシュ名
    name: &'static str,
    
    /// オブジェクトサイズ
    object_size: usize,
    
    /// アラインメント
    alignment: usize,
    
    /// 空のスラブページリスト (NUMA対応)
    empty_pages: BTreeMap<NumaNodeId, Vec<NonNull<SlabPage>>>,
    
    /// 部分的に使用中のスラブページリスト (NUMA対応)
    partial_pages: BTreeMap<NumaNodeId, Vec<NonNull<SlabPage>>>,
    
    /// 完全に使用中のスラブページリスト (NUMA対応)
    full_pages: BTreeMap<NumaNodeId, Vec<NonNull<SlabPage>>>,
    
    /// 割り当て済みオブジェクト数
    allocated_objects: AtomicUsize,
    
    /// キャッシュの総オブジェクト数
    total_objects: AtomicUsize,
    
    /// オブジェクト解放時にゼロクリアするかどうか
    clear_on_free: bool,
}

impl SlabCache {
    /// 新しいスラブキャッシュを作成する
    pub fn new(name: &'static str, object_size: usize, alignment: usize, clear_on_free: bool) -> Self {
        // 最小オブジェクトサイズはSlabObjectの大きさ以上に設定
        let actual_size = core::cmp::max(object_size, SlabObject::size());
        
        // アラインメントに合わせてサイズを調整
        let aligned_size = if alignment > 0 {
            (actual_size + alignment - 1) & !(alignment - 1)
        } else {
            actual_size
        };
        
        log_info!("スラブキャッシュ作成: {} (サイズ: {}, アラインメント: {})", 
                 name, aligned_size, alignment);
        
        SlabCache {
            name,
            object_size: aligned_size,
            alignment,
            empty_pages: BTreeMap::new(),
            partial_pages: BTreeMap::new(),
            full_pages: BTreeMap::new(),
            allocated_objects: AtomicUsize::new(0),
            total_objects: AtomicUsize::new(0),
            clear_on_free,
        }
    }
    
    /// キャッシュにスラブページを追加する
    pub fn add_page(&mut self, page: NonNull<SlabPage>, numa_node: NumaNodeId) {
        let page_ref = unsafe { page.as_ref() };
        let total_objects = page_ref.total_objects();
        
        // 総オブジェクト数を更新
        self.total_objects.fetch_add(total_objects, Ordering::SeqCst);
        
        // ページの状態に応じてリストに追加
        match page_ref.state() {
            SlabPageState::Empty => {
                self.empty_pages.entry(numa_node).or_insert_with(Vec::new).push(page);
            },
            SlabPageState::Partial => {
                self.partial_pages.entry(numa_node).or_insert_with(Vec::new).push(page);
                // 割り当て済みオブジェクト数を更新
                self.allocated_objects.fetch_add(page_ref.used_objects(), Ordering::SeqCst);
            },
            SlabPageState::Full => {
                self.full_pages.entry(numa_node).or_insert_with(Vec::new).push(page);
                // 割り当て済みオブジェクト数を更新
                self.allocated_objects.fetch_add(total_objects, Ordering::SeqCst);
            },
        }
    }
    
    /// メモリオブジェクトを割り当てる
    pub fn allocate(&mut self, numa_node: NumaNodeId) -> Option<*mut u8> {
        // 希望するNUMAノードに部分的に使用中のページがあるか確認
        let alloc_result = if let Some(partial_list) = self.partial_pages.get_mut(&numa_node) {
            if !partial_list.is_empty() {
                // 部分的に使用中のページからオブジェクトを割り当て
                let page_ptr = partial_list[0];
                let page = unsafe { page_ptr.as_mut() };
                let obj_ptr = page.allocate();
                
                // 割り当て後のページ状態を確認
                if page.state() == SlabPageState::Full {
                    // ページが満杯になった場合は別リストに移動
                    let page_ptr = partial_list.remove(0);
                    self.full_pages.entry(numa_node).or_insert_with(Vec::new).push(page_ptr);
                }
                
                // 割り当て済みオブジェクト数を更新
                if obj_ptr.is_some() {
                    self.allocated_objects.fetch_add(1, Ordering::SeqCst);
                }
                
                obj_ptr
            } else {
                None
            }
        } else {
            None
        };
        
        // 部分的に使用中のページから割り当てできなかった場合、空ページを使用
        if alloc_result.is_none() {
            if let Some(empty_list) = self.empty_pages.get_mut(&numa_node) {
                if !empty_list.is_empty() {
                    // 空ページからオブジェクトを割り当て
                    let page_ptr = empty_list.remove(0);
                    let page = unsafe { page_ptr.as_mut() };
                    let obj_ptr = page.allocate();
                    
                    // ページを部分的に使用中リストに移動
                    self.partial_pages.entry(numa_node).or_insert_with(Vec::new).push(page_ptr);
                    
                    // 割り当て済みオブジェクト数を更新
                    if obj_ptr.is_some() {
                        self.allocated_objects.fetch_add(1, Ordering::SeqCst);
                    }
                    
                    return obj_ptr;
                }
            }
            
            // 指定されたNUMAノードに空きがなかった場合は他のノードを試す
            log_debug!("指定されたNUMAノード{}に空きページがないため、他のノードを試します", numa_node);
            for (node_id, empty_list) in self.empty_pages.iter_mut() {
                if !empty_list.is_empty() {
                    // 空ページからオブジェクトを割り当て
                    let page_ptr = empty_list.remove(0);
                    let page = unsafe { page_ptr.as_mut() };
                    let obj_ptr = page.allocate();
                    
                    // ページを部分的に使用中リストに移動
                    self.partial_pages.entry(*node_id).or_insert_with(Vec::new).push(page_ptr);
                    
                    // 割り当て済みオブジェクト数を更新
                    if obj_ptr.is_some() {
                        self.allocated_objects.fetch_add(1, Ordering::SeqCst);
                    }
                    
                    log_debug!("NUMAノード{}からオブジェクトを割り当てました", node_id);
                    return obj_ptr;
                }
            }
            
            // それでも空きがない場合は、部分的に使用中のページから他のノードを試す
            for (node_id, partial_list) in self.partial_pages.iter_mut() {
                if !partial_list.is_empty() {
                    // 部分的に使用中のページからオブジェクトを割り当て
                    let page_ptr = partial_list[0];
                    let page = unsafe { page_ptr.as_mut() };
                    let obj_ptr = page.allocate();
                    
                    // 割り当て後のページ状態を確認
                    if page.state() == SlabPageState::Full {
                        // ページが満杯になった場合は別リストに移動
                        let page_ptr = partial_list.remove(0);
                        self.full_pages.entry(*node_id).or_insert_with(Vec::new).push(page_ptr);
                    }
                    
                    // 割り当て済みオブジェクト数を更新
                    if obj_ptr.is_some() {
                        self.allocated_objects.fetch_add(1, Ordering::SeqCst);
                    }
                    
                    log_warn!("NUMAノード{}から緊急割り当てを行いました（最適でない可能性があります）", node_id);
                    return obj_ptr;
                }
            }
            
            None
        } else {
            alloc_result
        }
    }
    
    /// メモリオブジェクトを解放する
    pub fn free(&mut self, ptr: *mut u8) -> bool {
        // ptr がどのページに属しているか探す
        for (node_id, full_list) in self.full_pages.iter_mut() {
            for (idx, page_ptr) in full_list.iter().enumerate() {
                let page = unsafe { page_ptr.as_ref() };
                if page.contains(ptr) {
                    // ページを見つけた
                    let page_mut = unsafe { page_ptr.as_mut() };
                    
                    // オブジェクトを解放
                    page_mut.free(ptr, self.clear_on_free);
                    
                    // ページが部分的に使用中に変わった場合はリストを移動
                    if page_mut.state() == SlabPageState::Partial {
                        let page_ptr = full_list.remove(idx);
                        self.partial_pages.entry(*node_id).or_insert_with(Vec::new).push(page_ptr);
                    }
                    
                    // 割り当て済みオブジェクト数を更新
                    self.allocated_objects.fetch_sub(1, Ordering::SeqCst);
                    return true;
                }
            }
        }
        
        for (node_id, partial_list) in self.partial_pages.iter_mut() {
            for (idx, page_ptr) in partial_list.iter().enumerate() {
                let page = unsafe { page_ptr.as_ref() };
                if page.contains(ptr) {
                    // ページを見つけた
                    let page_mut = unsafe { page_ptr.as_mut() };
                    
                    // オブジェクトを解放
                    page_mut.free(ptr, self.clear_on_free);
                    
                    // ページが空になった場合はリストを移動
                    if page_mut.state() == SlabPageState::Empty {
                        let page_ptr = partial_list.remove(idx);
                        self.empty_pages.entry(*node_id).or_insert_with(Vec::new).push(page_ptr);
                    }
                    
                    // 割り当て済みオブジェクト数を更新
                    self.allocated_objects.fetch_sub(1, Ordering::SeqCst);
                    return true;
                }
            }
        }
        
        // 指定されたポインタに対応するオブジェクトが見つからなかった
        log_warn!("無効なポインタが解放されようとしました: {:p}", ptr);
        false
    }
    
    /// キャッシュの統計情報を取得する
    pub fn stats(&self) -> SlabCacheStats {
        let allocated = self.allocated_objects.load(Ordering::SeqCst);
        let total = self.total_objects.load(Ordering::SeqCst);
        
        SlabCacheStats {
            name: self.name,
            object_size: self.object_size,
            allocated_objects: allocated,
            total_objects: total,
            utilization: if total > 0 { (allocated as f64 / total as f64) * 100.0 } else { 0.0 },
        }
    }
    
    /// キャッシュの使用率を取得する（0.0 〜 1.0）
    pub fn utilization(&self) -> f64 {
        let allocated = self.allocated_objects.load(Ordering::SeqCst);
        let total = self.total_objects.load(Ordering::SeqCst);
        
        if total > 0 {
            allocated as f64 / total as f64
        } else {
            0.0
        }
    }
    
    /// キャッシュの名前を取得する
    pub fn name(&self) -> &'static str {
        self.name
    }
    
    /// オブジェクトサイズを取得する
    pub fn object_size(&self) -> usize {
        self.object_size
    }
}

/// スラブキャッシュの統計情報
pub struct SlabCacheStats {
    /// キャッシュ名
    pub name: &'static str,
    
    /// オブジェクトサイズ
    pub object_size: usize,
    
    /// 割り当て済みオブジェクト数
    pub allocated_objects: usize,
    
    /// 総オブジェクト数
    pub total_objects: usize,
    
    /// 使用率（%）
    pub utilization: f64,
} 