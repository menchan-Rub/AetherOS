// AetherOS Slabアロケータ API
//
// このモジュールはSlabアロケータの公開APIを提供します。
// カーネル内のコンポーネントはこのAPIを通じてSlabアロケータを利用します。

use crate::sync::Mutex;
use alloc::collections::BTreeMap;
use log::{debug, info};
use spin::Once;

use super::{SlabCache, SlabCacheInfo};

/// グローバルSlabキャッシュレジストリ
static SLAB_REGISTRY: Once<Mutex<BTreeMap<&'static str, SlabCache>>> = Once::new();

/// Slabアロケータを初期化する
pub fn init() {
    // グローバルSlabレジストリを初期化
    SLAB_REGISTRY.call_once(|| {
        let registry = BTreeMap::new();
        info!("Slabアロケータが初期化されました");
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

    info!("標準Slabキャッシュが作成されました");
}

/// 新しいSlabキャッシュを作成する
///
/// # 引数
/// * `name` - キャッシュの名前
/// * `obj_size` - オブジェクトサイズ（バイト）
/// * `align` - アラインメント要件
///
/// # 戻り値
/// * 成功した場合は `true`、既に同名のキャッシュが存在する場合は `false`
pub fn create_cache(name: &'static str, obj_size: usize, align: usize) -> bool {
    let mut registry = SLAB_REGISTRY.get().unwrap().lock();
    
    if registry.contains_key(name) {
        debug!("キャッシュ '{}' は既に存在します", name);
        return false;
    }
    
    let cache = SlabCache::new(name, obj_size, align);
    registry.insert(name, cache);
    debug!("新しいキャッシュ '{}' が作成されました (サイズ={}, アライン={})", name, obj_size, align);
    true
}

/// 指定されたキャッシュからオブジェクトを割り当てる
///
/// # 引数
/// * `name` - キャッシュの名前
///
/// # 戻り値
/// * 成功した場合はオブジェクトへのポインタ、失敗した場合は `None`
pub fn alloc_from(name: &str) -> Option<*mut u8> {
    let mut registry = SLAB_REGISTRY.get().unwrap().lock();
    
    registry.get_mut(name).and_then(|cache| {
        let ptr = cache.alloc();
        if ptr.is_some() {
            debug!("キャッシュ '{}' からオブジェクトを割り当てました: {:p}", name, ptr.unwrap());
        } else {
            debug!("キャッシュ '{}' からの割り当てに失敗しました", name);
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
    let registry = SLAB_REGISTRY.get().unwrap().lock();
    
    // サイズに合った最小のキャッシュを探す
    let cache_name = registry.iter()
        .filter(|(_, cache)| {
            cache.get_object_size() >= size && cache.get_alignment() >= align
        })
        .min_by_key(|(_, cache)| cache.get_object_size())
        .map(|(name, _)| *name);
    
    drop(registry);
    
    match cache_name {
        Some(name) => alloc_from(name),
        None => {
            debug!("サイズ {} アライン {} に適合するキャッシュがありません", size, align);
            None
        }
    }
}

/// オブジェクトを解放する
///
/// # 引数
/// * `ptr` - 解放するオブジェクトへのポインタ
///
/// # 戻り値
/// * 成功した場合は `true`、失敗した場合は `false`
pub fn free(ptr: *mut u8) -> bool {
    let mut registry = SLAB_REGISTRY.get().unwrap().lock();
    
    // 全てのキャッシュを調べて、このポインタを所有しているものを探す
    for cache in registry.values_mut() {
        if cache.can_free(ptr) {
            let result = cache.free(ptr);
            if result {
                debug!("オブジェクト {:p} を解放しました (キャッシュ '{}')", ptr, cache.get_name());
            } else {
                debug!("オブジェクト {:p} の解放に失敗しました (キャッシュ '{}')", ptr, cache.get_name());
            }
            return result;
        }
    }
    
    debug!("オブジェクト {:p} を所有するキャッシュが見つかりません", ptr);
    false
}

/// キャッシュの使用状況を報告する
pub fn report_usage() {
    let registry = SLAB_REGISTRY.get().unwrap().lock();
    
    info!("===== Slabアロケータ使用状況 =====");
    info!("登録されたキャッシュ数: {}", registry.len());
    
    for (name, cache) in registry.iter() {
        let info = cache.get_info();
        info!("キャッシュ '{}': オブジェクトサイズ={}, 使用中={}/{}, ページ数={}",
            name, 
            info.object_size,
            info.allocated_objects,
            info.total_objects,
            info.page_count
        );
    }
    
    info!("================================");
}

/// 名前からキャッシュ情報を取得する
pub fn get_cache_info(name: &str) -> Option<SlabCacheInfo> {
    let registry = SLAB_REGISTRY.get().unwrap().lock();
    registry.get(name).map(|cache| cache.get_info())
}

/// すべてのキャッシュを強制的に縮小する
pub fn shrink_all() {
    let mut registry = SLAB_REGISTRY.get().unwrap().lock();
    
    for (name, cache) in registry.iter_mut() {
        let freed = cache.shrink();
        if freed > 0 {
            debug!("キャッシュ '{}' から {} ページを解放しました", name, freed);
        }
    }
}

/// 特定のキャッシュを削除する
pub fn destroy_cache(name: &str) -> bool {
    let mut registry = SLAB_REGISTRY.get().unwrap().lock();
    
    if let Some(_) = registry.remove(name) {
        debug!("キャッシュ '{}' を削除しました", name);
        true
    } else {
        debug!("キャッシュ '{}' は存在しません", name);
        false
    }
} 