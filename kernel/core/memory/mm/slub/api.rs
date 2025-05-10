// AetherOS SLUBアロケータ API
//
// このモジュールはSLUBアロケータの公開APIを提供します。
// カーネル内のコンポーネントはこのAPIを通じてSLUBアロケータを利用します。

use crate::sync::Mutex;
use alloc::collections::BTreeMap;
use log::{debug, info, warn, error};
use spin::Once;
use core::alloc::Layout;
use core::ptr::NonNull;
use alloc::string::String;
use alloc::vec::Vec;
use crate::core::memory::mm::slub::{SlubCache, SlubCacheInfo};
use crate::arch::cpu;

/// グローバルSLUBキャッシュレジストリ
static SLUB_REGISTRY: Once<Mutex<BTreeMap<&'static str, SlubCache>>> = Once::new();

/// CPUごとのキャッシュの有効/無効
static CPU_CACHE_ENABLED: Once<bool> = Once::new();

/// メモリ節約モードの有効/無効
static MEMORY_SAVING_ENABLED: Once<bool> = Once::new();

/// CPUごとのSLUBキャッシュエントリ
struct CpuCacheEntry {
    /// キャッシュ名
    name: &'static str,
    /// オブジェクトプール
    objects: Vec<*mut u8>,
    /// 最大サイズ
    max_size: usize,
}

/// CPUごとのキャッシュ
static CPU_CACHES: Once<Vec<Mutex<BTreeMap<&'static str, CpuCacheEntry>>>> = Once::new();

/// SLUBアロケータを初期化する
pub fn init() {
    // CPU・メモリ最適化設定を初期化
    CPU_CACHE_ENABLED.call_once(|| true); // デフォルトで有効
    MEMORY_SAVING_ENABLED.call_once(|| true); // デフォルトで有効
    
    // CPUごとのキャッシュを初期化
    let num_cpus = cpu::count();
    CPU_CACHES.call_once(|| {
        let mut caches = Vec::with_capacity(num_cpus);
        for _ in 0..num_cpus {
            caches.push(Mutex::new(BTreeMap::new()));
        }
        caches
    });
    
    // グローバルSLUBレジストリを初期化
    SLUB_REGISTRY.call_once(|| {
        let registry = BTreeMap::new();
        info!("SLUBアロケータが初期化されました");
        Mutex::new(registry)
    });

    // 標準サイズのキャッシュを事前に作成
    create_cache("size-8", 8, 8);
    create_cache("size-16", 16, 8);
    create_cache("size-32", 32, 8);
    create_cache("size-64", 64, 8);
    create_cache("size-128", 128, 8);
    create_cache("size-256", 256, 8);
    create_cache("size-512", 512, 16);
    create_cache("size-1024", 1024, 16);
    create_cache("size-2048", 2048, 16);
    create_cache("size-4096", 4096, 32);

    info!("標準SLUBキャッシュが作成されました");
}

/// 新しいSLUBキャッシュを作成する
///
/// # 引数
/// * `name` - キャッシュの名前
/// * `obj_size` - オブジェクトサイズ（バイト）
/// * `align` - アラインメント要件
///
/// # 戻り値
/// * 成功した場合は `true`、既に同名のキャッシュが存在する場合は `false`
pub fn create_cache(name: &'static str, obj_size: usize, align: usize) -> bool {
    let mut registry = SLUB_REGISTRY.get().unwrap().lock();
    
    if registry.contains_key(name) {
        debug!("SLUBキャッシュ '{}' は既に存在します", name);
        return false;
    }
    
    // CPUキャッシュが有効かどうかを取得
    let cpu_cache_enabled = *CPU_CACHE_ENABLED.get().unwrap();
    
    // メモリ節約モードが有効かどうかを取得
    let memory_saving = *MEMORY_SAVING_ENABLED.get().unwrap();
    
    let cache = SlubCache::new(name, obj_size, align, cpu_cache_enabled, memory_saving);
    registry.insert(name, cache);
    
    // CPUごとのキャッシュエントリを作成（有効な場合）
    if cpu_cache_enabled {
        let cpu_caches = CPU_CACHES.get().unwrap();
        let cpu_count = cpu_caches.len();
        
        for cpu_id in 0..cpu_count {
            let mut cpu_cache = cpu_caches[cpu_id].lock();
            
            // CPU単位キャッシュの最大サイズは小さいオブジェクトほど多く
            let max_objects = match obj_size {
                0..=32 => 64,
                33..=128 => 32,
                129..=512 => 16,
                _ => 8,
            };
            
            cpu_cache.insert(name, CpuCacheEntry {
                name,
                objects: Vec::with_capacity(max_objects),
                max_size: max_objects,
            });
        }
    }
    
    debug!("新しいSLUBキャッシュ '{}' が作成されました (サイズ={}, アライン={})", 
           name, obj_size, align);
    true
}

/// 適切なサイズのキャッシュを選択
fn select_size_cache(size: usize) -> Option<&'static str> {
    match size {
        0..=8 => Some("size-8"),
        9..=16 => Some("size-16"),
        17..=32 => Some("size-32"),
        33..=64 => Some("size-64"),
        65..=128 => Some("size-128"),
        129..=256 => Some("size-256"),
        257..=512 => Some("size-512"),
        513..=1024 => Some("size-1024"),
        1025..=2048 => Some("size-2048"),
        2049..=4096 => Some("size-4096"),
        _ => None
    }
}

/// CPUキャッシュからオブジェクトを取得
fn get_from_cpu_cache(name: &'static str) -> Option<*mut u8> {
    // CPUキャッシュが無効なら早期リターン
    if !CPU_CACHE_ENABLED.get().map_or(false, |&v| v) {
        return None;
    }
    
    let cpu_id = cpu::current_id();
    let cpu_caches = CPU_CACHES.get()?;
    
    if cpu_id >= cpu_caches.len() {
        return None;
    }
    
    let mut cpu_cache = cpu_caches[cpu_id].lock();
    
    if let Some(entry) = cpu_cache.get_mut(name) {
        if !entry.objects.is_empty() {
            let obj = entry.objects.pop().unwrap();
            debug!("CPU{}キャッシュからオブジェクトを取得: キャッシュ={}, アドレス={:p}", 
                   cpu_id, name, obj);
            return Some(obj);
        }
    }
    
    None
}

/// オブジェクトをCPUキャッシュに返却
fn put_to_cpu_cache(name: &'static str, ptr: *mut u8) -> bool {
    // CPUキャッシュが無効なら早期リターン
    if !CPU_CACHE_ENABLED.get().map_or(false, |&v| v) {
        return false;
    }
    
    let cpu_id = cpu::current_id();
    let cpu_caches = CPU_CACHES.get()?;
    
    if cpu_id >= cpu_caches.len() {
        return false;
    }
    
    let mut cpu_cache = cpu_caches[cpu_id].lock();
    
    if let Some(entry) = cpu_cache.get_mut(name) {
        if entry.objects.len() < entry.max_size {
            entry.objects.push(ptr);
            debug!("CPU{}キャッシュにオブジェクトを返却: キャッシュ={}, アドレス={:p}", 
                   cpu_id, name, ptr);
            return true;
        }
    }
    
    false
}

/// 指定されたキャッシュからオブジェクトを割り当てる
///
/// # 引数
/// * `name` - キャッシュの名前
///
/// # 戻り値
/// * 成功した場合はオブジェクトへのポインタ、失敗した場合は `None`
pub fn alloc_from(name: &'static str) -> Option<*mut u8> {
    // まずCPUキャッシュから取得を試みる
    if let Some(obj) = get_from_cpu_cache(name) {
        return Some(obj);
    }
    
    // グローバルキャッシュから取得
    let mut registry = SLUB_REGISTRY.get().unwrap().lock();
    
    registry.get_mut(name).and_then(|cache| {
        let ptr = cache.alloc();
        if ptr.is_some() {
            debug!("SLUBキャッシュ '{}' からオブジェクトを割り当てました: {:p}", name, ptr.unwrap());
        } else {
            debug!("SLUBキャッシュ '{}' からの割り当てに失敗しました", name);
        }
        ptr
    })
}

/// 最適なサイズのキャッシュからオブジェクトを割り当てる
///
/// # 引数
/// * `size` - 必要なサイズ（バイト）
/// * `align` - アラインメント要件
///
/// # 戻り値
/// * 成功した場合はオブジェクトへのポインタ、失敗した場合は `None`
pub fn alloc(size: usize, align: usize) -> Option<*mut u8> {
    if size > 4096 {
        debug!("SLUBアロケータ: サイズ{}は大きすぎます", size);
        return None;
    }
    
    // 適切なサイズのキャッシュを選択
    if let Some(cache_name) = select_size_cache(size) {
        // まずCPUキャッシュから取得を試みる
        if let Some(obj) = get_from_cpu_cache(cache_name) {
            return Some(obj);
        }
        
        // グローバルキャッシュから取得
        let mut registry = SLUB_REGISTRY.get().unwrap().lock();
        
        if let Some(cache) = registry.get_mut(cache_name) {
            let obj = cache.alloc();
            if let Some(ptr) = obj {
                trace!("SLUBキャッシュ '{}' からオブジェクトを割り当て: {:p}", cache_name, ptr);
            }
            return obj;
        }
    }
    
    debug!("サイズ {} アライン {} に適合するSLUBキャッシュがありません", size, align);
    None
}

/// レイアウトに基づいてオブジェクトを割り当てる
pub fn alloc_layout(layout: Layout) -> Option<NonNull<u8>> {
    alloc(layout.size(), layout.align())
        .map(|ptr| unsafe { NonNull::new_unchecked(ptr) })
}

/// オブジェクトを解放する
///
/// # 引数
/// * `ptr` - 解放するオブジェクトへのポインタ
///
/// # 戻り値
/// * 成功した場合は `true`、失敗した場合は `false`
pub fn free(ptr: *mut u8) -> bool {
    let mut registry = SLUB_REGISTRY.get().unwrap().lock();
    
    // 全てのキャッシュを調べて、このポインタを所有しているものを探す
    for (name, cache) in registry.iter_mut() {
        if cache.can_free(ptr) {
            // まずCPUキャッシュへの返却を試みる
            if put_to_cpu_cache(name, ptr) {
                return true;
            }
            
            // グローバルキャッシュに返却
            let result = cache.free(ptr);
            if result {
                trace!("オブジェクト {:p} を解放しました (キャッシュ '{}')", ptr, name);
            } else {
                warn!("オブジェクト {:p} の解放に失敗しました (キャッシュ '{}')", ptr, name);
            }
            return result;
        }
    }
    
    warn!("オブジェクト {:p} を所有するSLUBキャッシュが見つかりません", ptr);
    false
}

/// CPUキャッシュの設定を変更
///
/// # 引数
/// * `enabled` - 有効にする場合は `true`、無効にする場合は `false`
pub fn set_cpu_cache(enabled: bool) {
    let old_value = *CPU_CACHE_ENABLED.get().unwrap();
    
    if old_value == enabled {
        return;
    }
    
    // 値を更新
    unsafe {
        let ptr = CPU_CACHE_ENABLED.get().unwrap() as *const bool as *mut bool;
        *ptr = enabled;
    }
    
    // 無効化する場合は、すべてのCPUキャッシュの内容をグローバルキャッシュに排出
    if !enabled {
        drain_cpu_caches();
    }
    
    info!("SLUBアロケータのCPUキャッシュを{}に設定しました", 
          if enabled { "有効" } else { "無効" });
}

/// メモリ節約モードの設定を変更
///
/// # 引数
/// * `enabled` - 有効にする場合は `true`、無効にする場合は `false`
pub fn set_memory_saving(enabled: bool) {
    let old_value = *MEMORY_SAVING_ENABLED.get().unwrap();
    
    if old_value == enabled {
        return;
    }
    
    // 値を更新
    unsafe {
        let ptr = MEMORY_SAVING_ENABLED.get().unwrap() as *const bool as *mut bool;
        *ptr = enabled;
    }
    
    info!("SLUBアロケータのメモリ節約モードを{}に設定しました", 
          if enabled { "有効" } else { "無効" });
}

/// CPUキャッシュからグローバルキャッシュにすべてのオブジェクトを排出
pub fn drain_cpu_caches() {
    // CPUキャッシュが無効なら早期リターン
    if !CPU_CACHE_ENABLED.get().map_or(false, |&v| v) {
        return;
    }
    
    let cpu_caches = match CPU_CACHES.get() {
        Some(caches) => caches,
        None => return,
    };
    
    let mut registry = SLUB_REGISTRY.get().unwrap().lock();
    
    // 各CPUのキャッシュを処理
    for cpu_id in 0..cpu_caches.len() {
        let mut cpu_cache = cpu_caches[cpu_id].lock();
        
        // 各キャッシュエントリを処理
        for (name, entry) in cpu_cache.iter_mut() {
            if entry.objects.is_empty() {
                continue;
            }
            
            // グローバルキャッシュに移動
            if let Some(global_cache) = registry.get_mut(name) {
                for ptr in entry.objects.drain(..) {
                    global_cache.free(ptr);
                }
                debug!("CPU{}キャッシュからオブジェクトを排出: キャッシュ={}", cpu_id, name);
            } else {
                error!("CPU{}キャッシュに対応するグローバルキャッシュがありません: {}", cpu_id, name);
                entry.objects.clear();
            }
        }
    }
    
    debug!("すべてのCPUキャッシュを排出しました");
}

/// キャッシュの使用状況を報告する
pub fn report_usage() {
    let registry = SLUB_REGISTRY.get().unwrap().lock();
    
    info!("===== SLUBアロケータ使用状況 =====");
    info!("登録されたキャッシュ数: {}", registry.len());
    info!("CPUキャッシュ: {}", if *CPU_CACHE_ENABLED.get().unwrap() { "有効" } else { "無効" });
    info!("メモリ節約モード: {}", if *MEMORY_SAVING_ENABLED.get().unwrap() { "有効" } else { "無効" });
    
    // CPUキャッシュの状態を報告
    if *CPU_CACHE_ENABLED.get().unwrap() {
        if let Some(cpu_caches) = CPU_CACHES.get() {
            info!("CPUキャッシュ状態:");
            
            for cpu_id in 0..cpu_caches.len() {
                let cpu_cache = cpu_caches[cpu_id].lock();
                
                let total_objects: usize = cpu_cache.values()
                    .map(|entry| entry.objects.len())
                    .sum();
                
                info!("  CPU{}: キャッシュ数={}, オブジェクト={}",
                     cpu_id, cpu_cache.len(), total_objects);
            }
        }
    }
    
    // 各キャッシュの情報を表示
    for (name, cache) in registry.iter() {
        let info = cache.get_info();
        info!("キャッシュ '{}': オブジェクトサイズ={}, 使用中={}/{}, ページ数={}, メモリ={}KB",
            name, 
            info.object_size,
            info.allocated_objects,
            info.total_objects,
            info.page_count,
            info.memory_footprint / 1024
        );
    }
    
    info!("================================");
}

/// 名前からキャッシュ情報を取得する
pub fn get_cache_info(name: &str) -> Option<SlubCacheInfo> {
    let registry = SLUB_REGISTRY.get().unwrap().lock();
    registry.get(name).map(|cache| cache.get_info())
}

/// すべてのキャッシュを強制的に縮小する
pub fn shrink_all() {
    // まずCPUキャッシュを排出
    drain_cpu_caches();
    
    // グローバルキャッシュを縮小
    let mut registry = SLUB_REGISTRY.get().unwrap().lock();
    
    for (name, cache) in registry.iter_mut() {
        let freed = cache.shrink();
        if freed > 0 {
            debug!("SLUBキャッシュ '{}' から {} ページを解放しました", name, freed);
        }
    }
}

/// 特定のキャッシュを削除する
pub fn destroy_cache(name: &str) -> bool {
    // まずCPUキャッシュを排出
    if *CPU_CACHE_ENABLED.get().unwrap() {
        if let Some(cpu_caches) = CPU_CACHES.get() {
            for cpu_id in 0..cpu_caches.len() {
                let mut cpu_cache = cpu_caches[cpu_id].lock();
                cpu_cache.remove(name);
            }
        }
    }
    
    // グローバルキャッシュを削除
    let mut registry = SLUB_REGISTRY.get().unwrap().lock();
    
    if let Some(_) = registry.remove(name) {
        debug!("SLUBキャッシュ '{}' を削除しました", name);
        true
    } else {
        debug!("SLUBキャッシュ '{}' は存在しません", name);
        false
    }
} 