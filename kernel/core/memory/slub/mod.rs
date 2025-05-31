// AetherOS SLUBアロケータ
// 高性能オブジェクトアロケータ実装

use alloc::collections::LinkedList;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::{size_of, align_of};
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::arch::cpu;
use crate::memory::{AllocFlags, PAGE_SIZE};
use crate::sync::{Mutex, SpinLock};
use crate::memory::buddy;

mod cache;
mod page;
mod object;
mod cpu_cache;
mod stats;

pub use cache::{SlubCache, CacheId, CacheFlags};
pub use stats::SlubStats;

/// SLUBアロケータの設定
pub struct SlubConfig {
    /// パーCPUキャッシュのサイズ
    pub per_cpu_cache_size: usize,
    
    /// スラブ解放しきい値（0～100%）
    pub slab_release_threshold: usize,
    
    /// バルク転送サイズ
    pub bulk_transfer_size: usize,
    
    /// カラーリングオフセット最大値
    pub max_color_offset: usize,
    
    /// 緊急時の収縮率
    pub emergency_shrink_ratio: f32,
}

/// デフォルトのSLUB設定
static DEFAULT_CONFIG: SlubConfig = SlubConfig {
    per_cpu_cache_size: 64,
    slab_release_threshold: 50,
    bulk_transfer_size: 16,
    max_color_offset: 16,
    emergency_shrink_ratio: 0.5,
};

/// 現在の設定
static mut CURRENT_CONFIG: SlubConfig = SlubConfig {
    per_cpu_cache_size: 64,
    slab_release_threshold: 50,
    bulk_transfer_size: 16,
    max_color_offset: 16,
    emergency_shrink_ratio: 0.5,
};

/// 標準サイズクラス定義
const SIZE_CLASSES: [usize; 12] = [
    8, 16, 32, 64, 128, 256,      // 小サイズクラス
    512, 1024, 2048,              // 中サイズクラス
    4096, 8192, 16384             // 大サイズクラス
];

/// 事前定義キャッシュの最大数
const MAX_PREDEFINED_CACHES: usize = 32;

/// ユーザー定義キャッシュの最大数
const MAX_USER_CACHES: usize = 128;

/// 全キャッシュのリスト
static mut CACHES: [Option<SlubCache>; MAX_PREDEFINED_CACHES + MAX_USER_CACHES] = [None; MAX_PREDEFINED_CACHES + MAX_USER_CACHES];

/// 次に割り当てられるキャッシュID
static NEXT_CACHE_ID: AtomicUsize = AtomicUsize::new(MAX_PREDEFINED_CACHES);

/// グローバルSLUB統計情報
static mut GLOBAL_STATS: SlubStats = SlubStats {
    total_allocs: 0,
    total_frees: 0,
    active_objects: 0,
    total_slabs: 0,
    active_slabs: 0,
    total_pages: 0,
    cache_hits: 0,
    cache_misses: 0,
};

/// SLUBアロケータの初期化
pub fn init() -> Result<(), &'static str> {
    // コア数を取得
    let core_count = cpu::get_info().core_count;
    
    // 設定を適用
    unsafe {
        CURRENT_CONFIG = DEFAULT_CONFIG;
        CURRENT_CONFIG.per_cpu_cache_size = core_count * 8;
    }
    
    // 標準サイズクラスのキャッシュを初期化
    for (i, &size) in SIZE_CLASSES.iter().enumerate() {
        let align = if size < 8 { 8 } else { size };
        let name = alloc::format!("size-{}", size);
        
        let cache = SlubCache::new(
            i,
            &name,
            size,
            align,
            CacheFlags::ZERO
        )?;
        
        unsafe {
            CACHES[i] = Some(cache);
        }
    }
    
    // 初期化完了
    Ok(())
}

/// オブジェクト割り当て
pub fn allocate(size: usize, flags: AllocFlags) -> Result<usize, &'static str> {
    // サイズ0の場合はエラー
    if size == 0 {
        return Err("サイズ0の割り当ては不可能です");
    }
    
    // 適切なキャッシュを探す
    let cache_id = find_size_class_cache(size);
    
    // キャッシュから割り当て
    let result = cache_alloc(cache_id);
    
    // 統計情報を更新
    if result.is_ok() {
        unsafe {
            GLOBAL_STATS.total_allocs += 1;
            GLOBAL_STATS.active_objects += 1;
        }
    }
    
    result
}

/// 適切なサイズクラスキャッシュを見つける
fn find_size_class_cache(size: usize) -> CacheId {
    // 最も近いサイズクラスを探す
    for (i, &class_size) in SIZE_CLASSES.iter().enumerate() {
        if size <= class_size {
            return i;
        }
    }
    
    // サイズが大きすぎる場合は最大のサイズクラスを返す
    SIZE_CLASSES.len() - 1
}

/// オブジェクト解放
pub fn free(address: usize, size: usize) -> Result<(), &'static str> {
    // アドレスが0の場合はエラー
    if address == 0 {
        return Err("無効なアドレスです");
    }
    
    // キャッシュIDを特定
    let cache_id = find_size_class_cache(size);
    
    // キャッシュに返却
    let result = cache_free(cache_id, address);
    
    // 統計情報を更新
    if result.is_ok() {
        unsafe {
            GLOBAL_STATS.total_frees += 1;
            GLOBAL_STATS.active_objects -= 1;
        }
    }
    
    result
}

/// アライメント付き割り当て
pub fn allocate_aligned(size: usize, align: usize, flags: AllocFlags) -> Result<usize, &'static str> {
    // アライメントが2の累乗かチェック
    if !align.is_power_of_two() {
        return Err("アライメントは2の累乗である必要があります");
    }
    
    // アライメントがサイズより大きい場合は特別処理
    if align > size {
        // アライメント要件を満たすサイズで割り当て
        let adjusted_size = align;
        return allocate(adjusted_size, flags);
    }
    
    // 通常の割り当て
    allocate(size, flags)
}

/// 新しいキャッシュの作成
pub fn create_cache(name: &str, size: usize, align: usize, flags: CacheFlags) -> Result<CacheId, &'static str> {
    // サイズとアライメントの検証
    if size == 0 {
        return Err("サイズ0のキャッシュは作成できません");
    }
    
    if !align.is_power_of_two() {
        return Err("アライメントは2の累乗である必要があります");
    }
    
    // 次のキャッシュIDを取得
    let id = NEXT_CACHE_ID.fetch_add(1, Ordering::SeqCst);
    
    // 最大数チェック
    if id >= MAX_PREDEFINED_CACHES + MAX_USER_CACHES {
        NEXT_CACHE_ID.fetch_sub(1, Ordering::SeqCst);
        return Err("キャッシュの最大数に達しました");
    }
    
    // 新しいキャッシュを作成
    let cache = SlubCache::new(
        id,
        name,
        size,
        align,
        flags
    )?;
    
    // キャッシュを登録
    unsafe {
        CACHES[id] = Some(cache);
    }
    
    Ok(id)
}

/// キャッシュからのオブジェクト割り当て
pub fn cache_alloc(cache_id: CacheId) -> Result<usize, &'static str> {
    // キャッシュの存在確認
    let cache = unsafe {
        match CACHES.get(cache_id) {
            Some(Some(cache)) => cache,
            _ => return Err("無効なキャッシュIDです"),
        }
    };
    
    // キャッシュからオブジェクトを割り当て
    cache.allocate()
}

/// キャッシュへのオブジェクト返却
pub fn cache_free(cache_id: CacheId, address: usize) -> Result<(), &'static str> {
    // キャッシュの存在確認
    let cache = unsafe {
        match CACHES.get(cache_id) {
            Some(Some(cache)) => cache,
            _ => return Err("無効なキャッシュIDです"),
        }
    };
    
    // キャッシュにオブジェクトを返却
    cache.free(address)
}

/// キャッシュの破棄
pub fn destroy_cache(cache_id: CacheId) -> Result<(), &'static str> {
    // システム予約キャッシュは破棄不可
    if cache_id < MAX_PREDEFINED_CACHES {
        return Err("システム予約キャッシュは破棄できません");
    }
    
    // キャッシュの存在確認
    unsafe {
        match CACHES.get_mut(cache_id) {
            Some(cache_opt) => {
                if let Some(cache) = cache_opt.take() {
                    // キャッシュを解放
                    cache.destroy()?;
                    Ok(())
                } else {
                    Err("指定されたキャッシュは存在しません")
                }
            }
            None => Err("無効なキャッシュIDです"),
        }
    }
}

/// メモリ不足時の緊急収縮
pub fn emergency_shrink() -> Result<usize, &'static str> {
    let mut freed_pages = 0;
    
    // 全キャッシュを収縮
    unsafe {
        for cache_opt in CACHES.iter() {
            if let Some(cache) = cache_opt {
                freed_pages += cache.shrink()?;
            }
        }
    }
    
    Ok(freed_pages)
}

/// 統計情報の取得
pub fn get_stats() -> SlubStats {
    unsafe { GLOBAL_STATS.clone() }
}

/// SLUBアロケータの設定取得
pub fn get_config() -> &'static SlubConfig {
    unsafe { &CURRENT_CONFIG }
}

/// SLUBアロケータの設定更新
pub fn update_config(config: SlubConfig) {
    unsafe {
        CURRENT_CONFIG = config;
    }
} 