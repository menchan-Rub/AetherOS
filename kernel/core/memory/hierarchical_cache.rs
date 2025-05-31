// AetherOS 階層型メモリキャッシュサブシステム
//
// L1/L2キャッシュとディスクキャッシュを統合し、アクセス速度を最大化
// データの特性と使用傾向に基づいて最適なキャッシュ層を選択

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::core::sync::{Mutex, RwLock, SpinLock};

// キャッシュレベル定義
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CacheLevel {
    /// 最速アクセス用L1キャッシュ
    L1,
    /// 中速アクセス用L2キャッシュ
    L2,
    /// 低速大容量用L3キャッシュ
    L3,
    /// ディスクキャッシュ
    Disk,
}

// キャッシュ置換ポリシー
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CacheReplacementPolicy {
    /// 最も長く使われていないエントリを破棄（Least Recently Used）
    LRU,
    /// 最も頻繁に使われていないエントリを破棄（Least Frequently Used）
    LFU,
    /// 最近使われたエントリを優先的に保持（Most Recently Used）
    MRU,
    /// ランダムにエントリを破棄
    Random,
    /// First In, First Out
    FIFO,
    /// 最適な置換アルゴリズムを動的に選択
    Adaptive,
}

// キャッシュエントリの状態
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CacheEntryState {
    /// 有効なデータ
    Valid,
    /// 無効なデータ
    Invalid,
    /// 変更されたデータ（書き戻しが必要）
    Modified,
    /// 排他的データ（他のキャッシュレベルには存在しない）
    Exclusive,
    /// 読み取り専用の共有データ
    Shared,
}

// キャッシュアクセスパターン
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CacheAccessPattern {
    /// シーケンシャルアクセス
    Sequential,
    /// ランダムアクセス
    Random,
    /// 局所性の高いアクセス
    Localized,
    /// 繰り返しアクセス
    Repeated,
    /// ストリーミングアクセス
    Streaming,
    /// 混合アクセス
    Mixed,
}

// キャッシュエントリ
#[derive(Clone)]
pub struct CacheEntry<T: Clone> {
    /// キーID
    pub key: usize,
    /// キャッシュされたデータ
    pub data: T,
    /// エントリの状態
    pub state: CacheEntryState,
    /// 最終アクセス時間
    pub last_accessed: u64,
    /// アクセス回数
    pub access_count: usize,
    /// 挿入時間
    pub creation_time: u64,
    /// データサイズ（バイト）
    pub size: usize,
}

// キャッシュレベルの設定
#[derive(Clone)]
pub struct CacheLevelConfig {
    /// キャッシュレベル
    pub level: CacheLevel,
    /// キャッシュサイズ（バイト）
    pub size: usize,
    /// ラインサイズ/ブロックサイズ（バイト）
    pub line_size: usize,
    /// ウェイ数（関連度）
    pub ways: usize,
    /// 置換ポリシー
    pub replacement_policy: CacheReplacementPolicy,
    /// ライトバックかライトスルーか
    pub write_back: bool,
    /// プリフェッチを有効にするか
    pub prefetch_enabled: bool,
    /// プリフェッチするブロック数
    pub prefetch_blocks: usize,
}

// 階層型キャッシュの統計情報
#[derive(Clone)]
pub struct CacheStats {
    /// キャッシュヒット数
    pub hits: usize,
    /// キャッシュミス数
    pub misses: usize,
    /// 読み取り操作数
    pub reads: usize,
    /// 書き込み操作数
    pub writes: usize,
    /// 削除操作数
    pub evictions: usize,
    /// キャッシュヒット率（%）
    pub hit_ratio: f32,
    /// 平均アクセス時間（ナノ秒）
    pub avg_access_time_ns: f32,
    /// キャッシュレベル間の移動回数
    pub promotions: usize,
    /// キャッシュレベル間の降格回数
    pub demotions: usize,
}

// 階層型キャッシュマネージャ
pub struct HierarchicalCacheManager<T: Clone> {
    /// 各キャッシュレベルのデータ
    cache_levels: BTreeMap<CacheLevel, RwLock<BTreeMap<usize, CacheEntry<T>>>>,
    /// 各キャッシュレベルの統計情報
    stats: BTreeMap<CacheLevel, Mutex<CacheStats>>,
    /// 各キャッシュレベルの設定
    configs: BTreeMap<CacheLevel, CacheLevelConfig>,
    /// LRU追跡用（キャッシュレベルごとのLRUリスト）
    lru_lists: BTreeMap<CacheLevel, Mutex<VecDeque<usize>>>,
    /// インクルージョンポリシー（上位キャッシュのデータは下位キャッシュにも存在するか）
    inclusive: AtomicBool,
    /// グローバルな統計情報を有効にするか
    stats_enabled: AtomicBool,
    /// キャッシュプロモーションしきい値（これ以上のアクセス数で上のレベルに移動）
    promotion_threshold: AtomicUsize,
}

impl<T: Clone> HierarchicalCacheManager<T> {
    // 新しい階層型キャッシュマネージャを作成
    pub fn new() -> Self {
        let mut manager = Self {
            cache_levels: BTreeMap::new(),
            stats: BTreeMap::new(),
            configs: BTreeMap::new(),
            lru_lists: BTreeMap::new(),
            inclusive: AtomicBool::new(false), // デフォルトは排他型
            stats_enabled: AtomicBool::new(true),
            promotion_threshold: AtomicUsize::new(10), // デフォルトは10回アクセスで昇格
        };
        
        // デフォルトのキャッシュレベル設定を追加
        manager.add_cache_level(CacheLevelConfig {
            level: CacheLevel::L1,
            size: 64 * 1024, // 64KB
            line_size: 64,    // 64バイト
            ways: 8,
            replacement_policy: CacheReplacementPolicy::LRU,
            write_back: true,
            prefetch_enabled: true,
            prefetch_blocks: 2,
        });
        
        manager.add_cache_level(CacheLevelConfig {
            level: CacheLevel::L2,
            size: 256 * 1024, // 256KB
            line_size: 128,    // 128バイト
            ways: 16,
            replacement_policy: CacheReplacementPolicy::LRU,
            write_back: true,
            prefetch_enabled: true,
            prefetch_blocks: 4,
        });
        
        manager.add_cache_level(CacheLevelConfig {
            level: CacheLevel::L3,
            size: 8 * 1024 * 1024, // 8MB
            line_size: 256,    // 256バイト
            ways: 32,
            replacement_policy: CacheReplacementPolicy::LFU,
            write_back: true,
            prefetch_enabled: false,
            prefetch_blocks: 0,
        });
        
        manager.add_cache_level(CacheLevelConfig {
            level: CacheLevel::Disk,
            size: 256 * 1024 * 1024, // 256MB
            line_size: 4096,   // 4KB（ページサイズに合わせる）
            ways: 64,
            replacement_policy: CacheReplacementPolicy::FIFO,
            write_back: false, // ディスクはライトスルー
            prefetch_enabled: false,
            prefetch_blocks: 0,
        });
        
        manager
    }
    
    // キャッシュレベルを追加
    pub fn add_cache_level(&mut self, config: CacheLevelConfig) -> bool {
        if self.configs.contains_key(&config.level) {
            return false; // 既に存在する
        }
        
        // キャッシュストアを初期化
        self.cache_levels.insert(config.level, RwLock::new(BTreeMap::new()));
        
        // 統計情報を初期化
        self.stats.insert(config.level, Mutex::new(CacheStats {
            hits: 0,
            misses: 0,
            reads: 0,
            writes: 0,
            evictions: 0,
            hit_ratio: 0.0,
            avg_access_time_ns: 0.0,
            promotions: 0,
            demotions: 0,
        }));
        
        // LRUリストを初期化
        self.lru_lists.insert(config.level, Mutex::new(VecDeque::new()));
        
        // 設定を保存
        self.configs.insert(config.level, config);
        
        true
    }
    
    // キャッシュレベルの設定を変更
    pub fn update_cache_level(&mut self, level: CacheLevel, new_config: CacheLevelConfig) -> bool {
        if !self.configs.contains_key(&level) || new_config.level != level {
            return false;
        }
        
        // 現在のキャッシュ内容を維持しながら設定を更新
        self.configs.insert(level, new_config);
        
        // キャッシュサイズが小さくなった場合は、超過エントリを削除
        self.enforce_size_limit(level);
        
        true
    }
    
    // キャッシュサイズ制限を適用
    fn enforce_size_limit(&self, level: CacheLevel) {
        let config = match self.configs.get(&level) {
            Some(cfg) => cfg,
            None => return,
        };
        
        let mut cache = self.cache_levels.get(&level).unwrap().write().unwrap();
        let mut lru_list = self.lru_lists.get(&level).unwrap().lock().unwrap();
        
        // 現在のキャッシュサイズを計算
        let mut current_size: usize = cache.values().map(|entry| entry.size).sum();
        
        // サイズ制限を超えている場合、LRUエントリを削除
        while current_size > config.size && !lru_list.is_empty() {
            if let Some(key) = lru_list.pop_front() {
                if let Some(entry) = cache.remove(&key) {
                    current_size -= entry.size;
                    
                    // 統計情報を更新
                    if self.stats_enabled.load(Ordering::Relaxed) {
                        let mut stats = self.stats.get(&level).unwrap().lock().unwrap();
                        stats.evictions += 1;
                    }
                }
            }
        }
    }
    
    // インクルージョンポリシーを設定
    pub fn set_inclusive(&self, inclusive: bool) {
        self.inclusive.store(inclusive, Ordering::Relaxed);
    }
    
    // 統計情報の収集を有効/無効化
    pub fn enable_stats(&self, enabled: bool) {
        self.stats_enabled.store(enabled, Ordering::Relaxed);
    }
    
    // プロモーションしきい値を設定
    pub fn set_promotion_threshold(&self, threshold: usize) {
        self.promotion_threshold.store(threshold, Ordering::Relaxed);
    }
    
    // キャッシュの統計情報を取得
    pub fn get_stats(&self) -> BTreeMap<CacheLevel, CacheStats> {
        let mut result = BTreeMap::new();
        
        for (&level, stats_mutex) in &self.stats {
            let stats = stats_mutex.lock().unwrap().clone();
            result.insert(level, stats);
        }
        
        result
    }
    
    // 特定のキャッシュレベルの統計情報をリセット
    pub fn reset_stats(&self, level: CacheLevel) -> bool {
        if let Some(stats_mutex) = self.stats.get(&level) {
            let mut stats = stats_mutex.lock().unwrap();
            *stats = CacheStats {
                hits: 0,
                misses: 0,
                reads: 0,
                writes: 0,
                evictions: 0,
                hit_ratio: 0.0,
                avg_access_time_ns: 0.0,
                promotions: 0,
                demotions: 0,
            };
            return true;
        }
        
        false
    }
    
    // キャッシュからデータを読み取り
    pub fn get(&self, key: usize) -> Option<T> {
        let current_time = crate::time::current_time_ms();
        let mut found_level = None;
        let mut found_entry = None;
        
        // 最上位のキャッシュレベルから検索
        for &level in self.cache_levels.keys().rev() {
            let cache = self.cache_levels.get(&level).unwrap().read().unwrap();
            
            if let Some(entry) = cache.get(&key) {
                // エントリを見つけた
                found_level = Some(level);
                found_entry = Some(entry.clone());
                break;
            }
        }
        
        if let (Some(level), Some(mut entry)) = (found_level, found_entry) {
            // 統計情報を更新
            if self.stats_enabled.load(Ordering::Relaxed) {
                let mut stats = self.stats.get(&level).unwrap().lock().unwrap();
                stats.hits += 1;
                stats.reads += 1;
                
                // ヒット率を更新
                stats.hit_ratio = stats.hits as f32 / (stats.hits + stats.misses) as f32;
            }
            
            // LRUリストを更新
            {
                let mut lru_list = self.lru_lists.get(&level).unwrap().lock().unwrap();
                // 既存のエントリを削除
                lru_list.retain(|&k| k != key);
                // 最新アクセスとしてリストの末尾に追加
                lru_list.push_back(key);
            }
            
            // エントリの統計情報を更新
            {
                let mut cache = self.cache_levels.get(&level).unwrap().write().unwrap();
                if let Some(entry) = cache.get_mut(&key) {
                    entry.last_accessed = current_time;
                    entry.access_count += 1;
                    
                    // アクセス数がしきい値を超えた場合、より上位のキャッシュレベルに昇格
                    let threshold = self.promotion_threshold.load(Ordering::Relaxed);
                    if entry.access_count >= threshold {
                        // 昇格可能なレベルを確認
                        let next_level = match level {
                            CacheLevel::Disk => Some(CacheLevel::L3),
                            CacheLevel::L3 => Some(CacheLevel::L2),
                            CacheLevel::L2 => Some(CacheLevel::L1),
                            CacheLevel::L1 => None, // 既に最上位
                        };
                        
                        if let Some(next_level) = next_level {
                            self.promote_entry(key, level, next_level);
                        }
                    }
                }
            }
            
            // プリフェッチ処理
            self.handle_prefetch(key, level);
            
            return Some(entry.data);
        } else {
            // 全レベルにデータが見つからない場合はミス
            if self.stats_enabled.load(Ordering::Relaxed) {
                // 最下位レベルのミス統計を更新
                if let Some(stats_mutex) = self.stats.values().next() {
                    let mut stats = stats_mutex.lock().unwrap();
                    stats.misses += 1;
                    stats.reads += 1;
                    
                    // ヒット率を更新
                    stats.hit_ratio = stats.hits as f32 / (stats.hits + stats.misses) as f32;
                }
            }
            
            None
        }
    }
    
    // キャッシュにデータを書き込み
    pub fn put(&self, key: usize, data: T, size: usize) -> bool {
        let current_time = crate::time::current_time_ms();
        
        // 書き込み先のキャッシュレベルを決定（基本的に最上位レベル）
        let target_level = *self.cache_levels.keys().rev().next().unwrap_or(&CacheLevel::L1);
        
        // エントリを作成
        let entry = CacheEntry {
            key,
            data: data.clone(),
            state: CacheEntryState::Valid,
            last_accessed: current_time,
            access_count: 1,
            creation_time: current_time,
            size,
        };
        
        // キャッシュに追加
        {
            let mut cache = self.cache_levels.get(&target_level).unwrap().write().unwrap();
            
            // エントリを追加
            cache.insert(key, entry);
            
            // LRUリストを更新
            let mut lru_list = self.lru_lists.get(&target_level).unwrap().lock().unwrap();
            // 既存のエントリを削除
            lru_list.retain(|&k| k != key);
            // 最新アクセスとしてリストの末尾に追加
            lru_list.push_back(key);
        }
        
        // サイズ制限を適用
        self.enforce_size_limit(target_level);
        
        // 統計情報を更新
        if self.stats_enabled.load(Ordering::Relaxed) {
            let mut stats = self.stats.get(&target_level).unwrap().lock().unwrap();
            stats.writes += 1;
        }
        
        // インクルーシブキャッシュの場合、下位レベルにもデータを書き込む
        if self.inclusive.load(Ordering::Relaxed) {
            // 下位のキャッシュレベルにも追加
            for &level in self.cache_levels.keys() {
                if level < target_level {
                    // 下位のキャッシュレベルにデータをコピー
                    let entry = CacheEntry {
                        key,
                        data: data.clone(),
                        state: CacheEntryState::Shared,
                        last_accessed: current_time,
                        access_count: 1,
                        creation_time: current_time,
                        size,
                    };
                    
                    let mut cache = self.cache_levels.get(&level).unwrap().write().unwrap();
                    cache.insert(key, entry);
                    
                    // LRUリストを更新
                    let mut lru_list = self.lru_lists.get(&level).unwrap().lock().unwrap();
                    lru_list.retain(|&k| k != key);
                    lru_list.push_back(key);
                    
                    // サイズ制限を適用
                    self.enforce_size_limit(level);
                }
            }
        }
        
        true
    }
    
    // キャッシュからデータを削除
    pub fn remove(&self, key: usize) -> bool {
        let mut removed = false;
        
        // 全てのキャッシュレベルからデータを削除
        for &level in self.cache_levels.keys() {
            let mut cache = self.cache_levels.get(&level).unwrap().write().unwrap();
            
            if cache.remove(&key).is_some() {
                removed = true;
                
                // LRUリストから削除
                let mut lru_list = self.lru_lists.get(&level).unwrap().lock().unwrap();
                lru_list.retain(|&k| k != key);
                
                // 統計情報を更新
                if self.stats_enabled.load(Ordering::Relaxed) {
                    let mut stats = self.stats.get(&level).unwrap().lock().unwrap();
                    stats.evictions += 1;
                }
            }
        }
        
        removed
    }
    
    // エントリを上位キャッシュレベルに昇格
    fn promote_entry(&self, key: usize, from_level: CacheLevel, to_level: CacheLevel) {
        if from_level >= to_level {
            return; // 昇格は上位レベルへのみ
        }
        
        // 元のレベルからエントリを取得
        let mut entry_opt = None;
        {
            let mut cache = self.cache_levels.get(&from_level).unwrap().write().unwrap();
            
            if let Some(entry) = cache.get(&key) {
                entry_opt = Some(entry.clone());
                
                // 排他型の場合は元のレベルから削除
                if !self.inclusive.load(Ordering::Relaxed) {
                    cache.remove(&key);
                    
                    // LRUリストから削除
                    let mut lru_list = self.lru_lists.get(&from_level).unwrap().lock().unwrap();
                    lru_list.retain(|&k| k != key);
                }
            }
        }
        
        // 上位レベルに追加
        if let Some(mut entry) = entry_opt {
            // エントリの状態を更新
            entry.access_count = 1; // 新しいレベルでのアクセスカウントをリセット
            entry.state = if self.inclusive.load(Ordering::Relaxed) {
                CacheEntryState::Shared
            } else {
                CacheEntryState::Exclusive
            };
            
            let mut cache = self.cache_levels.get(&to_level).unwrap().write().unwrap();
            cache.insert(key, entry);
            
            // LRUリストを更新
            let mut lru_list = self.lru_lists.get(&to_level).unwrap().lock().unwrap();
            lru_list.retain(|&k| k != key);
            lru_list.push_back(key);
            
            // サイズ制限を適用
            self.enforce_size_limit(to_level);
            
            // 統計情報を更新
            if self.stats_enabled.load(Ordering::Relaxed) {
                let mut from_stats = self.stats.get(&from_level).unwrap().lock().unwrap();
                from_stats.promotions += 1;
                
                let mut to_stats = self.stats.get(&to_level).unwrap().lock().unwrap();
                to_stats.demotions += 1;
            }
        }
    }
    
    // プリフェッチ処理
    fn handle_prefetch(&self, key: usize, level: CacheLevel) {
        let config = match self.configs.get(&level) {
            Some(cfg) => cfg,
            None => return,
        };
        
        if !config.prefetch_enabled || config.prefetch_blocks == 0 {
            return;
        }
        
        // シーケンシャルアクセスを仮定して、次のブロックをプリフェッチ
        for i in 1..=config.prefetch_blocks {
            let next_key = key + i;
            
            // 既にキャッシュにあるか確認
            let mut already_cached = false;
            for &check_level in self.cache_levels.keys() {
                let cache = self.cache_levels.get(&check_level).unwrap().read().unwrap();
                if cache.contains_key(&next_key) {
                    already_cached = true;
                    break;
                }
            }
            
            if !already_cached {
                // ここでプリフェッチするための仕組みが必要
                // 実際のシステムでは低レベルのキャッシュからデータをロードする
                // ...（プリフェッチ実装）
            }
        }
    }
    
    // キャッシュのクリア
    pub fn clear(&self) {
        for &level in self.cache_levels.keys() {
            let mut cache = self.cache_levels.get(&level).unwrap().write().unwrap();
            cache.clear();
            
            let mut lru_list = self.lru_lists.get(&level).unwrap().lock().unwrap();
            lru_list.clear();
        }
    }
    
    // キャッシュサイズの取得
    pub fn get_size(&self, level: CacheLevel) -> Option<(usize, usize)> {
        let config = self.configs.get(&level)?;
        let cache = self.cache_levels.get(&level)?.read().unwrap();
        
        let current_size: usize = cache.values().map(|entry| entry.size).sum();
        
        Some((current_size, config.size))
    }
    
    // キャッシュエントリ数の取得
    pub fn get_entry_count(&self, level: CacheLevel) -> Option<usize> {
        let cache = self.cache_levels.get(&level)?.read().unwrap();
        Some(cache.len())
    }
    
    // 特定キーのエントリ情報を取得
    pub fn get_entry_info(&self, key: usize) -> Option<(CacheLevel, CacheEntryState, usize, u64)> {
        for &level in self.cache_levels.keys().rev() {
            let cache = self.cache_levels.get(&level).unwrap().read().unwrap();
            
            if let Some(entry) = cache.get(&key) {
                return Some((level, entry.state, entry.access_count, entry.last_accessed));
            }
        }
        
        None
    }
}

/// グローバル階層型キャッシュマネージャ
static mut HIERARCHICAL_CACHE_MANAGER: Option<HierarchicalCacheManager<Vec<u8>>> = None;

/// 階層型キャッシュサブシステムを初期化
pub fn init() -> Result<(), &'static str> {
    unsafe {
        if HIERARCHICAL_CACHE_MANAGER.is_some() {
            return Err("階層型キャッシュマネージャは既に初期化されています");
        }
        
        HIERARCHICAL_CACHE_MANAGER = Some(HierarchicalCacheManager::new());
    }
    
    log::info!("階層型メモリキャッシュサブシステムを初期化しました");
    
    Ok(())
}

/// グローバル階層型キャッシュマネージャを取得
pub fn get_cache_manager() -> &'static HierarchicalCacheManager<Vec<u8>> {
    unsafe {
        HIERARCHICAL_CACHE_MANAGER.as_ref().expect("階層型キャッシュマネージャが初期化されていません")
    }
}

/// キャッシュ設定を更新
pub fn update_cache_config(level: CacheLevel, size: usize, line_size: usize, ways: usize) -> bool {
    unsafe {
        if let Some(manager) = HIERARCHICAL_CACHE_MANAGER.as_mut() {
            if let Some(current_config) = manager.configs.get(&level) {
                let mut new_config = current_config.clone();
                new_config.size = size;
                new_config.line_size = line_size;
                new_config.ways = ways;
                
                return manager.update_cache_level(level, new_config);
            }
        }
    }
    
    false
}

/// インクルージョンポリシーを設定
pub fn set_inclusive_policy(inclusive: bool) {
    let manager = get_cache_manager();
    manager.set_inclusive(inclusive);
    
    log::info!("キャッシュインクルージョンポリシーを設定: {}", if inclusive { "inclusive" } else { "exclusive" });
}

/// 統計情報の収集を有効/無効化
pub fn enable_cache_stats(enabled: bool) {
    let manager = get_cache_manager();
    manager.enable_stats(enabled);
    
    log::info!("キャッシュ統計情報収集を {}", if enabled { "有効化" } else { "無効化" });
}

/// キャッシュの統計情報を取得
pub fn get_cache_stats() -> BTreeMap<CacheLevel, CacheStats> {
    let manager = get_cache_manager();
    manager.get_stats()
}

/// 特定のキャッシュレベルの統計情報をリセット
pub fn reset_cache_stats(level: CacheLevel) -> bool {
    let manager = get_cache_manager();
    manager.reset_stats(level)
}

/// キャッシュレベルの詳細情報を取得
pub fn get_cache_level_info(level: CacheLevel) -> Option<String> {
    unsafe {
        if let Some(manager) = HIERARCHICAL_CACHE_MANAGER.as_ref() {
            if let Some(config) = manager.configs.get(&level) {
                let stats = manager.stats.get(&level)?.lock().unwrap();
                
                let info = format!(
                    "キャッシュレベル: {:?}\n\
                     サイズ: {} バイト\n\
                     ラインサイズ: {} バイト\n\
                     ウェイ数: {}\n\
                     置換ポリシー: {:?}\n\
                     ライトバック: {}\n\
                     プリフェッチ: {}\n\
                     ----統計情報----\n\
                     ヒット数: {}\n\
                     ミス数: {}\n\
                     ヒット率: {:.2}%\n\
                     平均アクセス時間: {:.2}ns\n\
                     読み取り数: {}\n\
                     書き込み数: {}\n\
                     削除数: {}",
                    level, config.size, config.line_size, config.ways,
                    config.replacement_policy, config.write_back,
                    if config.prefetch_enabled { "有効" } else { "無効" },
                    stats.hits, stats.misses,
                    stats.hit_ratio * 100.0, stats.avg_access_time_ns,
                    stats.reads, stats.writes, stats.evictions
                );
                
                return Some(info);
            }
        }
    }
    
    None
}

/// データをキャッシュに保存
pub fn cache_put(key: usize, data: Vec<u8>) -> bool {
    let manager = get_cache_manager();
    manager.put(key, data.clone(), data.len())
}

/// データをキャッシュから取得
pub fn cache_get(key: usize) -> Option<Vec<u8>> {
    let manager = get_cache_manager();
    manager.get(key)
}

/// データをキャッシュから削除
pub fn cache_remove(key: usize) -> bool {
    let manager = get_cache_manager();
    manager.remove(key)
}

/// キャッシュをクリア
pub fn cache_clear() {
    let manager = get_cache_manager();
    manager.clear();
    
    log::info!("キャッシュをクリアしました");
}

/// キャッシュサイズ情報を取得
pub fn get_cache_size_info() -> String {
    let manager = get_cache_manager();
    let mut info = String::from("キャッシュサイズ情報:\n");
    
    for &level in manager.cache_levels.keys() {
        if let Some((current, total)) = manager.get_size(level) {
            let percentage = (current as f32 / total as f32) * 100.0;
            info.push_str(&format!("{:?}: {}/{} バイト ({:.1}%)\n", 
                                  level, current, total, percentage));
        }
    }
    
    info
}

/// キャッシュエントリ数を取得
pub fn get_cache_entry_count() -> String {
    let manager = get_cache_manager();
    let mut info = String::from("キャッシュエントリ数:\n");
    
    for &level in manager.cache_levels.keys() {
        if let Some(count) = manager.get_entry_count(level) {
            info.push_str(&format!("{:?}: {} エントリ\n", level, count));
        }
    }
    
    info
}

/// 特定キーのエントリ情報を取得
pub fn get_entry_info(key: usize) -> Option<String> {
    let manager = get_cache_manager();
    
    if let Some((level, state, access_count, last_accessed)) = manager.get_entry_info(key) {
        let info = format!(
            "キー {} の情報:\n\
             キャッシュレベル: {:?}\n\
             状態: {:?}\n\
             アクセス回数: {}\n\
             最終アクセス時間: {}",
            key, level, state, access_count, last_accessed
        );
        
        Some(info)
    } else {
        None
    }
}

/// プロモーションしきい値を設定
pub fn set_promotion_threshold(threshold: usize) {
    let manager = get_cache_manager();
    manager.set_promotion_threshold(threshold);
    
    log::info!("キャッシュプロモーションしきい値を {} に設定しました", threshold);
} 