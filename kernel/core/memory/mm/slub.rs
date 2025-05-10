// AetherOS SLUBアロケータ実装
//
// SLUBアロケータは同じサイズのオブジェクトを効率的に割り当てるために使用されます。
// Slabアロケータを改良し、メタデータのオーバーヘッドを削減、特にマルチコアシステムで効率的です。

use crate::arch::PhysicalAddress;
use crate::core::memory::mm::page::{PageManager, PageMemoryType, flags};
use core::alloc::Layout;
use core::ptr::NonNull;
use spin::{Mutex, MutexGuard};
use alloc::vec::Vec;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::{String, ToString};
use log::{debug, trace, warn, info};
use crate::core::memory::mm::slub::{SlubCache, SlubCacheInfo};
use crate::arch::cpu;
use spin::Once;

/// SLUBサイズ（通常は1ページサイズ）
const SLUB_SIZE: usize = 4096;

/// 最小アラインメント要件
const MIN_ALIGNMENT: usize = 8;

/// CPUごとのキャッシュサイズ
const CPU_CACHE_SIZE: usize = 8;

/// グローバルSLUBアロケータ
static SLUB_ALLOCATOR: Once<Mutex<Option<SlubAllocator>>> = Once::new();

/// CPUごとのSLUBキャッシュ
/// 各CPUコアは独自のキャッシュを持ち、ロックの競合を減らします
#[derive(Debug)]
struct CpuSlubCache {
    /// キャッシュ名
    cache_name: &'static str,
    /// オブジェクトプール
    objects: [Option<*mut u8>; CPU_CACHE_SIZE],
    /// 使用中のオブジェクト数
    used_count: usize,
}

impl CpuSlubCache {
    /// 新しいCPUキャッシュを作成
    fn new(name: &'static str) -> Self {
        Self {
            cache_name: name,
            objects: [None; CPU_CACHE_SIZE],
            used_count: 0,
        }
    }
    
    /// キャッシュからオブジェクトを取得
    fn get_object(&mut self) -> Option<*mut u8> {
        if self.used_count == 0 {
            return None;
        }
        
        self.used_count -= 1;
        let obj = self.objects[self.used_count].take();
        
        trace!("CPU{} キャッシュからオブジェクトを取得: {:p}, 残り: {}", 
               cpu::current_id(), obj.unwrap(), self.used_count);
        
        obj
    }
    
    /// キャッシュにオブジェクトを追加
    fn put_object(&mut self, obj: *mut u8) -> bool {
        if self.used_count >= CPU_CACHE_SIZE {
            return false;
        }
        
        self.objects[self.used_count] = Some(obj);
        self.used_count += 1;
        
        trace!("CPU{} キャッシュにオブジェクトを追加: {:p}, 合計: {}", 
               cpu::current_id(), obj, self.used_count);
        
        true
    }
    
    /// キャッシュを空にする
    fn drain(&mut self) -> Vec<*mut u8> {
        let mut result = Vec::with_capacity(self.used_count);
        
        for i in 0..self.used_count {
            if let Some(obj) = self.objects[i].take() {
                result.push(obj);
            }
        }
        
        self.used_count = 0;
        result
    }
}

/// SLUBアロケータの構成
#[derive(Debug, Clone, Copy)]
pub struct SlubConfig {
    /// メモリ節約モード（メタデータを圧縮）
    pub memory_saving: bool,
    /// CPUごとのキャッシュを有効にする
    pub cpu_cache: bool,
    /// デバッグ情報を有効にする
    pub debug: bool,
}

impl Default for SlubConfig {
    fn default() -> Self {
        Self {
            memory_saving: true,
            cpu_cache: true,
            debug: false,
        }
    }
}

/// SLUB アロケータ
pub struct SlubAllocator {
    /// サイズ別の汎用キャッシュ（8, 16, 32, 64, 128, 256, 512, 1024, 2048バイト）
    size_caches: BTreeMap<usize, SlubCache>,
    /// 名前付きの特殊キャッシュ
    named_caches: BTreeMap<&'static str, SlubCache>,
    /// CPUごとのキャッシュ
    cpu_caches: Vec<BTreeMap<&'static str, CpuSlubCache>>,
    /// 構成
    config: SlubConfig,
}

impl SlubAllocator {
    /// 新しいSLUBアロケータを作成
    pub fn new(config: SlubConfig) -> Self {
        // CPU数を取得
        let num_cpus = cpu::count();
        
        // CPUごとのキャッシュを初期化
        let mut cpu_caches = Vec::with_capacity(num_cpus);
        for _ in 0..num_cpus {
            cpu_caches.push(BTreeMap::new());
        }
        
        // 標準サイズのキャッシュを用意
        let mut size_caches = BTreeMap::new();
        let sizes = [8, 16, 32, 64, 128, 256, 512, 1024, 2048];
        
        for &size in &sizes {
            let cache = SlubCache::new(
                match size {
                    8 => "size-8",
                    16 => "size-16",
                    32 => "size-32",
                    64 => "size-64",
                    128 => "size-128",
                    256 => "size-256",
                    512 => "size-512",
                    1024 => "size-1024",
                    2048 => "size-2048",
                    _ => panic!("未知のサイズ")
                },
                size,
                MIN_ALIGNMENT,
                config.cpu_cache,
                config.memory_saving
            );
            
            size_caches.insert(size, cache);
        }
        
        SlubAllocator {
            size_caches,
            named_caches: BTreeMap::new(),
            cpu_caches,
            config,
        }
    }
    
    /// 適切なサイズのキャッシュを選択
    fn select_size_cache(&self, size: usize) -> Option<usize> {
        self.size_caches.keys()
            .filter(|&&k| k >= size)
            .min()
            .copied()
    }
    
    /// オブジェクトを割り当てる
    pub fn allocate(&mut self, size: usize, alignment: usize) -> Option<*mut u8> {
        let align = alignment.max(MIN_ALIGNMENT);
        
        // サイズが大きすぎる場合は標準アロケータにフォールバック
        if size > 2048 {
            warn!("SLUBアロケータ: サイズが大きすぎます: {} バイト", size);
            return None;
        }
        
        // 適切なサイズのキャッシュを見つける
        if let Some(cache_size) = self.select_size_cache(size) {
            // 現在のCPU ID
            let cpu_id = cpu::current_id();
            
            if self.config.cpu_cache && cpu_id < self.cpu_caches.len() {
                // CPUキャッシュから取得を試みる
                let cache_name = match cache_size {
                    8 => "size-8",
                    16 => "size-16",
                    32 => "size-32",
                    64 => "size-64",
                    128 => "size-128",
                    256 => "size-256",
                    512 => "size-512",
                    1024 => "size-1024",
                    2048 => "size-2048",
                    _ => panic!("未知のサイズ")
                };
                
                if let Some(cpu_cache) = self.cpu_caches[cpu_id].get_mut(cache_name) {
                    if let Some(obj) = cpu_cache.get_object() {
                        trace!("CPUキャッシュからオブジェクトを割り当て: サイズ={}, addr={:p}", cache_size, obj);
                        return Some(obj);
                    }
                } else {
                    // CPUキャッシュが存在しない場合は作成
                    let mut new_cache = CpuSlubCache::new(cache_name);
                    let inserted = self.cpu_caches[cpu_id].insert(cache_name, new_cache);
                    
                    if inserted.is_none() {
                        trace!("CPU{} に新しいキャッシュを作成: {}", cpu_id, cache_name);
                    }
                }
            }
            
            // グローバルキャッシュから取得
            let obj = self.size_caches.get_mut(&cache_size).and_then(|cache| cache.alloc());
            
            if let Some(ptr) = obj {
                trace!("グローバルキャッシュからオブジェクトを割り当て: サイズ={}, addr={:p}", cache_size, ptr);
            } else {
                trace!("オブジェクト割り当て失敗: サイズ={}", cache_size);
            }
            
            obj
        } else {
            None
        }
    }
    
    /// オブジェクトを解放する
    pub fn deallocate(&mut self, ptr: *mut u8) -> bool {
        let cpu_id = cpu::current_id();
        
        // 各サイズのキャッシュで解放を試みる
        for (size, cache) in &mut self.size_caches {
            if cache.can_free(ptr) {
                if self.config.cpu_cache && cpu_id < self.cpu_caches.len() {
                    // CPUキャッシュに入れることを試みる
                    let cache_name = match *size {
                        8 => "size-8",
                        16 => "size-16",
                        32 => "size-32",
                        64 => "size-64",
                        128 => "size-128",
                        256 => "size-256",
                        512 => "size-512",
                        1024 => "size-1024",
                        2048 => "size-2048",
                        _ => panic!("未知のサイズ")
                    };
                    
                    if let Some(cpu_cache) = self.cpu_caches[cpu_id].get_mut(cache_name) {
                        if cpu_cache.put_object(ptr) {
                            trace!("オブジェクトをCPUキャッシュに返却: サイズ={}, addr={:p}", size, ptr);
                            return true;
                        }
                    }
                }
                
                // グローバルキャッシュに返却
                let result = cache.free(ptr);
                if result {
                    trace!("オブジェクトをグローバルキャッシュに返却: サイズ={}, addr={:p}", size, ptr);
                } else {
                    warn!("オブジェクト解放に失敗: サイズ={}, addr={:p}", size, ptr);
                }
                return result;
            }
        }
        
        // 名前付きキャッシュでも試す
        for (name, cache) in &mut self.named_caches {
            if cache.can_free(ptr) {
                if self.config.cpu_cache && cpu_id < self.cpu_caches.len() {
                    // CPUキャッシュに入れることを試みる
                    if let Some(cpu_cache) = self.cpu_caches[cpu_id].get_mut(name) {
                        if cpu_cache.put_object(ptr) {
                            trace!("オブジェクトをCPUキャッシュに返却: キャッシュ={}, addr={:p}", name, ptr);
                            return true;
                        }
                    }
                }
                
                // グローバルキャッシュに返却
                let result = cache.free(ptr);
                if result {
                    trace!("オブジェクトをグローバルキャッシュに返却: キャッシュ={}, addr={:p}", name, ptr);
                } else {
                    warn!("オブジェクト解放に失敗: キャッシュ={}, addr={:p}", name, ptr);
                }
                return result;
            }
        }
        
        warn!("SLUBアロケータ: 解放対象のオブジェクトが見つかりません: {:p}", ptr);
        false
    }
    
    /// 名前付きキャッシュを作成
    pub fn create_cache(&mut self, name: &'static str, obj_size: usize, alignment: usize) -> bool {
        if self.named_caches.contains_key(name) {
            warn!("SLUBアロケータ: キャッシュは既に存在します: {}", name);
            return false;
        }
        
        let cache = SlubCache::new(
            name,
            obj_size,
            alignment.max(MIN_ALIGNMENT),
            self.config.cpu_cache,
            self.config.memory_saving
        );
        
        self.named_caches.insert(name, cache);
        
        // 各CPUにキャッシュエントリを作成
        if self.config.cpu_cache {
            for cpu_id in 0..self.cpu_caches.len() {
                let cpu_cache = CpuSlubCache::new(name);
                self.cpu_caches[cpu_id].insert(name, cpu_cache);
            }
        }
        
        debug!("新しいSLUBキャッシュを作成: 名前={}, サイズ={}, アライン={}", 
               name, obj_size, alignment);
        
        true
    }
    
    /// 名前付きキャッシュからオブジェクトを割り当てる
    pub fn allocate_from_cache(&mut self, name: &'static str) -> Option<*mut u8> {
        let cpu_id = cpu::current_id();
        
        if self.config.cpu_cache && cpu_id < self.cpu_caches.len() {
            // CPUキャッシュから取得を試みる
            if let Some(cpu_cache) = self.cpu_caches[cpu_id].get_mut(name) {
                if let Some(obj) = cpu_cache.get_object() {
                    trace!("CPUキャッシュからオブジェクトを割り当て: キャッシュ={}, addr={:p}", name, obj);
                    return Some(obj);
                }
            }
        }
        
        // グローバルキャッシュから取得
        let obj = self.named_caches.get_mut(name).and_then(|cache| cache.alloc());
        
        if let Some(ptr) = obj {
            trace!("グローバルキャッシュからオブジェクトを割り当て: キャッシュ={}, addr={:p}", name, ptr);
        } else {
            trace!("オブジェクト割り当て失敗: キャッシュ={}", name);
        }
        
        obj
    }
    
    /// キャッシュを削除
    pub fn destroy_cache(&mut self, name: &'static str) -> bool {
        // CPUキャッシュを削除し、残りのオブジェクトをすべて解放
        if self.config.cpu_cache {
            for cpu_id in 0..self.cpu_caches.len() {
                if let Some(mut cpu_cache) = self.cpu_caches[cpu_id].remove(name) {
                    let objects = cpu_cache.drain();
                    
                    if let Some(cache) = self.named_caches.get_mut(name) {
                        for obj in objects {
                            cache.free(obj);
                        }
                    }
                }
            }
        }
        
        // グローバルキャッシュを削除
        if self.named_caches.remove(name).is_some() {
            debug!("SLUBキャッシュを削除: {}", name);
            true
        } else {
            warn!("SLUBキャッシュが見つかりません: {}", name);
            false
        }
    }
    
    /// すべてのキャッシュの使用状況を報告
    pub fn report_usage(&self) {
        info!("===== SLUBアロケータ使用状況 =====");
        
        // サイズ別キャッシュの情報を表示
        info!("サイズ別キャッシュ ({}個):", self.size_caches.len());
        for (size, cache) in &self.size_caches {
            let info = cache.get_info();
            info!("  サイズ {}: オブジェクト={}/{}, ページ={}, メモリ={}KB",
                 size,
                 info.allocated_objects,
                 info.total_objects,
                 info.page_count,
                 info.memory_footprint / 1024
            );
        }
        
        // 名前付きキャッシュの情報を表示
        info!("名前付きキャッシュ ({}個):", self.named_caches.len());
        for (name, cache) in &self.named_caches {
            let info = cache.get_info();
            info!("  {}: サイズ={}, オブジェクト={}/{}, ページ={}, メモリ={}KB",
                 name,
                 info.object_size,
                 info.allocated_objects,
                 info.total_objects,
                 info.page_count,
                 info.memory_footprint / 1024
            );
        }
        
        // CPUキャッシュの情報（有効な場合）
        if self.config.cpu_cache {
            info!("CPUキャッシュ:");
            for (cpu_id, cpu_cache_map) in self.cpu_caches.iter().enumerate() {
                let total_objects: usize = cpu_cache_map.values()
                    .map(|cache| cache.used_count)
                    .sum();
                
                info!("  CPU{}: キャッシュ数={}, オブジェクト={}",
                     cpu_id, cpu_cache_map.len(), total_objects);
            }
        }
        
        info!("===================================");
    }
    
    /// CPUキャッシュからグローバルプールへオブジェクトを移動
    pub fn drain_cpu_caches(&mut self) {
        if !self.config.cpu_cache {
            return;
        }
        
        for cpu_id in 0..self.cpu_caches.len() {
            let cpu_cache_map = &mut self.cpu_caches[cpu_id];
            
            for (name, cpu_cache) in cpu_cache_map.iter_mut() {
                let objects = cpu_cache.drain();
                
                // オブジェクトをグローバルキャッシュに戻す
                if !objects.is_empty() {
                    if let Some(cache) = self.named_caches.get_mut(name) {
                        for obj in objects {
                            cache.free(obj);
                        }
                    } else if let Some(size) = match *name {
                        "size-8" => Some(8),
                        "size-16" => Some(16),
                        "size-32" => Some(32),
                        "size-64" => Some(64),
                        "size-128" => Some(128),
                        "size-256" => Some(256),
                        "size-512" => Some(512),
                        "size-1024" => Some(1024),
                        "size-2048" => Some(2048),
                        _ => None
                    } {
                        if let Some(cache) = self.size_caches.get_mut(&size) {
                            for obj in objects {
                                cache.free(obj);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// SLUBアロケータのAPI
pub mod api {
    use super::*;
    
    /// SLUBアロケータを初期化
    pub fn init() {
        SLUB_ALLOCATOR.call_once(|| {
            let config = SlubConfig::default();
            let allocator = SlubAllocator::new(config);
            info!("SLUBアロケータ初期化完了: CPUキャッシュ={}, メモリ節約モード={}",
                 config.cpu_cache, config.memory_saving);
            Mutex::new(Some(allocator))
        });
    }
    
    /// アロケータインスタンスを取得
    fn get_allocator<'a>() -> MutexGuard<'a, Option<SlubAllocator>> {
        match SLUB_ALLOCATOR.try_get() {
            Some(allocator) => allocator.lock(),
            None => {
                init();
                SLUB_ALLOCATOR.get().unwrap().lock()
            }
        }
    }
    
    /// オブジェクトを割り当てる
    pub fn allocate(size: usize, align: usize) -> Option<NonNull<u8>> {
        let mut allocator = get_allocator();
        
        if let Some(alloc) = allocator.as_mut() {
            alloc.allocate(size, align)
                .map(|ptr| unsafe { NonNull::new_unchecked(ptr) })
        } else {
            None
        }
    }
    
    /// レイアウトに基づいてオブジェクトを割り当てる
    pub fn allocate_layout(layout: Layout) -> Option<NonNull<u8>> {
        allocate(layout.size(), layout.align())
    }
    
    /// オブジェクトを解放
    pub fn deallocate(ptr: NonNull<u8>) -> bool {
        let mut allocator = get_allocator();
        
        if let Some(alloc) = allocator.as_mut() {
            alloc.deallocate(ptr.as_ptr())
        } else {
            false
        }
    }
    
    /// 名前付きキャッシュを作成
    pub fn create_cache(name: &'static str, obj_size: usize, alignment: usize) -> bool {
        let mut allocator = get_allocator();
        
        if let Some(alloc) = allocator.as_mut() {
            alloc.create_cache(name, obj_size, alignment)
        } else {
            false
        }
    }
    
    /// 名前付きキャッシュからオブジェクトを割り当てる
    pub fn allocate_from_cache(name: &'static str) -> Option<NonNull<u8>> {
        let mut allocator = get_allocator();
        
        if let Some(alloc) = allocator.as_mut() {
            alloc.allocate_from_cache(name)
                .map(|ptr| unsafe { NonNull::new_unchecked(ptr) })
        } else {
            None
        }
    }
    
    /// キャッシュを削除
    pub fn destroy_cache(name: &'static str) -> bool {
        let mut allocator = get_allocator();
        
        if let Some(alloc) = allocator.as_mut() {
            alloc.destroy_cache(name)
        } else {
            false
        }
    }
    
    /// すべてのキャッシュの使用状況を報告
    pub fn report_usage() {
        let allocator = get_allocator();
        
        if let Some(alloc) = allocator.as_ref() {
            alloc.report_usage();
        } else {
            warn!("SLUBアロケータは初期化されていません");
        }
    }
    
    /// CPUキャッシュをグローバルプールに排出
    pub fn drain_cpu_caches() {
        let mut allocator = get_allocator();
        
        if let Some(alloc) = allocator.as_mut() {
            alloc.drain_cpu_caches();
        }
    }
    
    /// SLUBアロケータの構成を設定
    pub fn set_config(config: SlubConfig) -> bool {
        let mut allocator = get_allocator();
        
        if let Some(alloc) = allocator.as_mut() {
            // 既存のキャッシュをすべて解放（シンプルにするために新しいインスタンスを作成）
            alloc.drain_cpu_caches();
            *allocator = Some(SlubAllocator::new(config));
            true
        } else {
            false
        }
    }
}

/// グローバルアロケータとして登録するための実装
pub mod global_alloc {
    use super::*;
    use core::alloc::GlobalAlloc;
    
    #[derive(Debug)]
    pub struct SlubGlobalAlloc;
    
    unsafe impl GlobalAlloc for SlubGlobalAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // サイズが大きすぎる場合や、アラインメントが厳しい場合は
            // buddy アロケータにフォールバック
            if layout.size() <= 2048 && layout.align() <= 32 {
                match api::allocate_layout(layout) {
                    Some(ptr) => ptr.as_ptr(),
                    None => {
                        // SLUBアロケータで失敗した場合はバディアロケータにフォールバック
                        crate::core::memory::buddy::allocate(layout)
                            .map(|ptr| ptr.as_ptr())
                            .unwrap_or(core::ptr::null_mut())
                    }
                }
            } else {
                // 大きなサイズはバディアロケータで処理
                crate::core::memory::buddy::allocate(layout)
                    .map(|ptr| ptr.as_ptr())
                    .unwrap_or(core::ptr::null_mut())
            }
        }
        
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            if !ptr.is_null() {
                if layout.size() <= 2048 && layout.align() <= 32 {
                    // SLUBで解放を試みる
                    let ptr_nn = NonNull::new_unchecked(ptr);
                    if !api::deallocate(ptr_nn) {
                        // SLUBで解放できなかった場合はバディアロケータで解放
                        crate::core::memory::buddy::deallocate(ptr_nn, layout);
                    }
                } else {
                    // 大きなサイズはバディアロケータで解放
                    crate::core::memory::buddy::deallocate(NonNull::new_unchecked(ptr), layout);
                }
            }
        }
    }
} 