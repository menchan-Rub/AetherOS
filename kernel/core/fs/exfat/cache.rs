// exFAT 高性能キャッシュ実装
//
// 超高速アクセスのための先進的キャッシュシステム

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::collections::{BTreeMap, VecDeque};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{RwLock, Mutex};
use super::super::{FsError, FsResult, Metadata};

/// キャッシュエントリの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheState {
    /// クリーン状態（変更なし）
    Clean,
    /// ダーティ状態（変更あり、未保存）
    Dirty,
    /// 保存中
    Saving,
    /// ロック状態（他のスレッドが使用中）
    Locked,
}

/// クラスタキャッシュエントリ
pub struct ClusterCacheEntry {
    /// クラスタ番号
    cluster_number: u32,
    /// クラスタデータ
    data: Vec<u8>,
    /// キャッシュ状態
    state: CacheState,
    /// 最終アクセス時刻
    last_access: u64,
    /// アクセス回数
    access_count: AtomicUsize,
}

/// メタデータキャッシュエントリ
pub struct MetadataCacheEntry {
    /// ファイルパス
    path: String,
    /// メタデータ
    metadata: Metadata,
    /// キャッシュ状態
    state: CacheState,
    /// 最終アクセス時刻
    last_access: u64,
    /// アクセス回数
    access_count: AtomicUsize,
}

/// ディレクトリキャッシュエントリ
pub struct DirCacheEntry {
    /// ディレクトリパス
    path: String,
    /// 親ディレクトリのクラスタ番号
    parent_cluster: u32,
    /// ディレクトリエントリのリスト（ファイル名と最初のクラスタ番号のペア）
    entries: Vec<(String, u32)>,
    /// キャッシュ状態
    state: CacheState,
    /// 最終アクセス時刻
    last_access: u64,
    /// アクセス回数
    access_count: AtomicUsize,
}

/// FATキャッシュエントリ
pub struct FatCacheEntry {
    /// FATインデックス
    fat_index: usize,
    /// FATエントリのチャンク
    entries: Vec<u32>,
    /// キャッシュ状態
    state: CacheState,
    /// 最終アクセス時刻
    last_access: u64,
    /// アクセス回数
    access_count: AtomicUsize,
}

/// 統合キャッシュシステム
pub struct ExfatCache {
    /// クラスタキャッシュ（クラスタ番号 -> データ）
    cluster_cache: RwLock<BTreeMap<u32, Arc<RwLock<ClusterCacheEntry>>>>,
    /// メタデータキャッシュ（パス -> メタデータ）
    metadata_cache: RwLock<BTreeMap<String, Arc<RwLock<MetadataCacheEntry>>>>,
    /// ディレクトリキャッシュ（パス -> ディレクトリエントリ）
    dir_cache: RwLock<BTreeMap<String, Arc<RwLock<DirCacheEntry>>>>,
    /// FATキャッシュ（FATインデックス -> FATエントリ）
    fat_cache: RwLock<BTreeMap<usize, Arc<RwLock<FatCacheEntry>>>>,
    /// LRUリスト（クラスタキャッシュ用）
    cluster_lru: Mutex<VecDeque<u32>>,
    /// LRUリスト（メタデータキャッシュ用）
    metadata_lru: Mutex<VecDeque<String>>,
    /// LRUリスト（ディレクトリキャッシュ用）
    dir_lru: Mutex<VecDeque<String>>,
    /// LRUリスト（FATキャッシュ用）
    fat_lru: Mutex<VecDeque<usize>>,
    /// 最大キャッシュサイズ
    max_size: usize,
    /// 現在のシステム時刻取得関数
    current_time_fn: fn() -> u64,
    /// 統計情報：ヒット数
    hits: AtomicUsize,
    /// 統計情報：ミス数
    misses: AtomicUsize,
}

impl ExfatCache {
    /// 新しいキャッシュインスタンスを作成
    pub fn new(max_size: usize) -> Self {
        Self {
            cluster_cache: RwLock::new(BTreeMap::new()),
            metadata_cache: RwLock::new(BTreeMap::new()),
            dir_cache: RwLock::new(BTreeMap::new()),
            fat_cache: RwLock::new(BTreeMap::new()),
            cluster_lru: Mutex::new(VecDeque::with_capacity(max_size)),
            metadata_lru: Mutex::new(VecDeque::with_capacity(max_size)),
            dir_lru: Mutex::new(VecDeque::with_capacity(max_size)),
            fat_lru: Mutex::new(VecDeque::with_capacity(max_size)),
            max_size,
            current_time_fn: || 0, // デフォルトではダミーの時刻関数
            hits: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
        }
    }
    
    /// 時刻取得関数を設定
    pub fn set_time_function(&mut self, time_fn: fn() -> u64) {
        self.current_time_fn = time_fn;
    }
    
    /// 現在時刻を取得
    fn current_time(&self) -> u64 {
        (self.current_time_fn)()
    }
    
    /// クラスタデータをキャッシュに追加
    pub fn add_cluster(&self, cluster_number: u32, data: Vec<u8>) -> FsResult<()> {
        let now = self.current_time();
        let mut cache = self.cluster_cache.write();
        let mut lru = self.cluster_lru.lock();
        
        // キャッシュが一杯なら古いエントリを削除
        if cache.len() >= self.max_size && !cache.contains_key(&cluster_number) {
            self.evict_cluster(&mut cache, &mut lru)?;
        }
        
        // 新しいエントリを追加
        let entry = ClusterCacheEntry {
            cluster_number,
            data,
            state: CacheState::Clean,
            last_access: now,
            access_count: AtomicUsize::new(1),
        };
        
        cache.insert(cluster_number, Arc::new(RwLock::new(entry)));
        lru.push_back(cluster_number);
        
        Ok(())
    }
    
    /// クラスタデータをキャッシュから取得
    pub fn get_cluster(&self, cluster_number: u32) -> Option<Vec<u8>> {
        let cache = self.cluster_cache.read();
        
        if let Some(entry_arc) = cache.get(&cluster_number) {
            let mut entry = entry_arc.write();
            let now = self.current_time();
            entry.last_access = now;
            entry.access_count.fetch_add(1, Ordering::Relaxed);
            
            // LRUリストを更新
            drop(cache);
            let mut lru = self.cluster_lru.lock();
            if let Some(pos) = lru.iter().position(|&c| c == cluster_number) {
                lru.remove(pos);
            }
            lru.push_back(cluster_number);
            
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.data.clone())
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
    
    /// メタデータをキャッシュに追加
    pub fn add_metadata(&self, path: &str, metadata: Metadata) -> FsResult<()> {
        let now = self.current_time();
        let mut cache = self.metadata_cache.write();
        let mut lru = self.metadata_lru.lock();
        
        // キャッシュが一杯なら古いエントリを削除
        if cache.len() >= self.max_size && !cache.contains_key(path) {
            self.evict_metadata(&mut cache, &mut lru)?;
        }
        
        // 新しいエントリを追加
        let entry = MetadataCacheEntry {
            path: path.to_string(),
            metadata,
            state: CacheState::Clean,
            last_access: now,
            access_count: AtomicUsize::new(1),
        };
        
        cache.insert(path.to_string(), Arc::new(RwLock::new(entry)));
        lru.push_back(path.to_string());
        
        Ok(())
    }
    
    /// メタデータをキャッシュから取得
    pub fn get_metadata(&self, path: &str) -> Option<Metadata> {
        let cache = self.metadata_cache.read();
        
        if let Some(entry_arc) = cache.get(path) {
            let mut entry = entry_arc.write();
            let now = self.current_time();
            entry.last_access = now;
            entry.access_count.fetch_add(1, Ordering::Relaxed);
            
            // LRUリストを更新
            drop(cache);
            let mut lru = self.metadata_lru.lock();
            if let Some(pos) = lru.iter().position(|p| p == path) {
                lru.remove(pos);
            }
            lru.push_back(path.to_string());
            
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.metadata.clone())
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
    
    /// ディレクトリエントリをキャッシュに追加
    pub fn add_directory(&self, path: &str, parent_cluster: u32, entries: Vec<(String, u32)>) -> FsResult<()> {
        let now = self.current_time();
        let mut cache = self.dir_cache.write();
        let mut lru = self.dir_lru.lock();
        
        // キャッシュが一杯なら古いエントリを削除
        if cache.len() >= self.max_size && !cache.contains_key(path) {
            self.evict_directory(&mut cache, &mut lru)?;
        }
        
        // 新しいエントリを追加
        let entry = DirCacheEntry {
            path: path.to_string(),
            parent_cluster,
            entries,
            state: CacheState::Clean,
            last_access: now,
            access_count: AtomicUsize::new(1),
        };
        
        cache.insert(path.to_string(), Arc::new(RwLock::new(entry)));
        lru.push_back(path.to_string());
        
        Ok(())
    }
    
    /// ディレクトリエントリをキャッシュから取得
    pub fn get_directory(&self, path: &str) -> Option<Vec<(String, u32)>> {
        let cache = self.dir_cache.read();
        
        if let Some(entry_arc) = cache.get(path) {
            let mut entry = entry_arc.write();
            let now = self.current_time();
            entry.last_access = now;
            entry.access_count.fetch_add(1, Ordering::Relaxed);
            
            // LRUリストを更新
            drop(cache);
            let mut lru = self.dir_lru.lock();
            if let Some(pos) = lru.iter().position(|p| p == path) {
                lru.remove(pos);
            }
            lru.push_back(path.to_string());
            
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.entries.clone())
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
    
    /// FATエントリをキャッシュに追加
    pub fn add_fat_entries(&self, fat_index: usize, entries: Vec<u32>) -> FsResult<()> {
        let now = self.current_time();
        let mut cache = self.fat_cache.write();
        let mut lru = self.fat_lru.lock();
        
        // キャッシュが一杯なら古いエントリを削除
        if cache.len() >= self.max_size && !cache.contains_key(&fat_index) {
            self.evict_fat(&mut cache, &mut lru)?;
        }
        
        // 新しいエントリを追加
        let entry = FatCacheEntry {
            fat_index,
            entries,
            state: CacheState::Clean,
            last_access: now,
            access_count: AtomicUsize::new(1),
        };
        
        cache.insert(fat_index, Arc::new(RwLock::new(entry)));
        lru.push_back(fat_index);
        
        Ok(())
    }
    
    /// FATエントリをキャッシュから取得
    pub fn get_fat_entries(&self, fat_index: usize) -> Option<Vec<u32>> {
        let cache = self.fat_cache.read();
        
        if let Some(entry_arc) = cache.get(&fat_index) {
            let mut entry = entry_arc.write();
            let now = self.current_time();
            entry.last_access = now;
            entry.access_count.fetch_add(1, Ordering::Relaxed);
            
            // LRUリストを更新
            drop(cache);
            let mut lru = self.fat_lru.lock();
            if let Some(pos) = lru.iter().position(|&idx| idx == fat_index) {
                lru.remove(pos);
            }
            lru.push_back(fat_index);
            
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.entries.clone())
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
    
    /// クラスタをダーティとしてマーク
    pub fn mark_cluster_dirty(&self, cluster_number: u32) -> FsResult<()> {
        let cache = self.cluster_cache.read();
        
        if let Some(entry_arc) = cache.get(&cluster_number) {
            let mut entry = entry_arc.write();
            entry.state = CacheState::Dirty;
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }
    
    /// メタデータをダーティとしてマーク
    pub fn mark_metadata_dirty(&self, path: &str) -> FsResult<()> {
        let cache = self.metadata_cache.read();
        
        if let Some(entry_arc) = cache.get(path) {
            let mut entry = entry_arc.write();
            entry.state = CacheState::Dirty;
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }
    
    /// すべてのダーティエントリをフラッシュ
    pub fn flush_all(&self) -> FsResult<()> {
        self.flush_dirty_clusters()?;
        self.flush_dirty_metadata()?;
        self.flush_dirty_directories()?;
        self.flush_dirty_fat()?;
        
        Ok(())
    }
    
    /// ダーティクラスタをフラッシュ
    fn flush_dirty_clusters(&self) -> FsResult<()> {
        // 実際には永続ストレージに書き戻す処理を実装
        // 今回はダミー実装
        let mut cache = self.cluster_cache.write();
        
        for (_, entry_arc) in cache.iter_mut() {
            let mut entry = entry_arc.write();
            if entry.state == CacheState::Dirty {
                // ここで実際にディスクに書き込む処理
                entry.state = CacheState::Clean;
            }
        }
        
        Ok(())
    }
    
    /// ダーティメタデータをフラッシュ
    fn flush_dirty_metadata(&self) -> FsResult<()> {
        // 実際には永続ストレージに書き戻す処理を実装
        // 今回はダミー実装
        let mut cache = self.metadata_cache.write();
        
        for (_, entry_arc) in cache.iter_mut() {
            let mut entry = entry_arc.write();
            if entry.state == CacheState::Dirty {
                // ここで実際にディスクに書き込む処理
                entry.state = CacheState::Clean;
            }
        }
        
        Ok(())
    }
    
    /// ダーティディレクトリをフラッシュ
    fn flush_dirty_directories(&self) -> FsResult<()> {
        // 実際には永続ストレージに書き戻す処理を実装
        // 今回はダミー実装
        let mut cache = self.dir_cache.write();
        
        for (_, entry_arc) in cache.iter_mut() {
            let mut entry = entry_arc.write();
            if entry.state == CacheState::Dirty {
                // ここで実際にディスクに書き込む処理
                entry.state = CacheState::Clean;
            }
        }
        
        Ok(())
    }
    
    /// ダーティFATをフラッシュ
    fn flush_dirty_fat(&self) -> FsResult<()> {
        // 実際には永続ストレージに書き戻す処理を実装
        // 今回はダミー実装
        let mut cache = self.fat_cache.write();
        
        for (_, entry_arc) in cache.iter_mut() {
            let mut entry = entry_arc.write();
            if entry.state == CacheState::Dirty {
                // ここで実際にディスクに書き込む処理
                entry.state = CacheState::Clean;
            }
        }
        
        Ok(())
    }
    
    /// クラスタキャッシュから古いエントリを削除
    fn evict_cluster(&self, cache: &mut BTreeMap<u32, Arc<RwLock<ClusterCacheEntry>>>, lru: &mut VecDeque<u32>) -> FsResult<()> {
        // LRUリストから古いエントリを取得
        while let Some(cluster_number) = lru.pop_front() {
            if let Some(entry_arc) = cache.get(&cluster_number) {
                let entry = entry_arc.read();
                if entry.state == CacheState::Clean {
                    // クリーンなエントリは安全に削除可能
                    cache.remove(&cluster_number);
                    return Ok(());
                } else if entry.state == CacheState::Dirty {
                    // ダーティなエントリはフラッシュしてから削除
                    drop(entry);
                    // フラッシュ処理（実際にはディスクに書き込む）
                    let mut entry = entry_arc.write();
                    entry.state = CacheState::Clean;
                    drop(entry);
                    cache.remove(&cluster_number);
                    return Ok(());
                }
                // ロック中のエントリはスキップ
                lru.push_back(cluster_number);
            }
        }
        
        // すべてのエントリがロック中の場合（通常は起きない）
        Err(FsError::ResourceBusy)
    }
    
    /// メタデータキャッシュから古いエントリを削除
    fn evict_metadata(&self, cache: &mut BTreeMap<String, Arc<RwLock<MetadataCacheEntry>>>, lru: &mut VecDeque<String>) -> FsResult<()> {
        // LRUリストから古いエントリを取得
        while let Some(path) = lru.pop_front() {
            if let Some(entry_arc) = cache.get(&path) {
                let entry = entry_arc.read();
                if entry.state == CacheState::Clean {
                    // クリーンなエントリは安全に削除可能
                    cache.remove(&path);
                    return Ok(());
                } else if entry.state == CacheState::Dirty {
                    // ダーティなエントリはフラッシュしてから削除
                    drop(entry);
                    // フラッシュ処理（実際にはディスクに書き込む）
                    let mut entry = entry_arc.write();
                    entry.state = CacheState::Clean;
                    drop(entry);
                    cache.remove(&path);
                    return Ok(());
                }
                // ロック中のエントリはスキップ
                lru.push_back(path);
            }
        }
        
        // すべてのエントリがロック中の場合（通常は起きない）
        Err(FsError::ResourceBusy)
    }
    
    /// ディレクトリキャッシュから古いエントリを削除
    fn evict_directory(&self, cache: &mut BTreeMap<String, Arc<RwLock<DirCacheEntry>>>, lru: &mut VecDeque<String>) -> FsResult<()> {
        // LRUリストから古いエントリを取得
        while let Some(path) = lru.pop_front() {
            if let Some(entry_arc) = cache.get(&path) {
                let entry = entry_arc.read();
                if entry.state == CacheState::Clean {
                    // クリーンなエントリは安全に削除可能
                    cache.remove(&path);
                    return Ok(());
                } else if entry.state == CacheState::Dirty {
                    // ダーティなエントリはフラッシュしてから削除
                    drop(entry);
                    // フラッシュ処理（実際にはディスクに書き込む）
                    let mut entry = entry_arc.write();
                    entry.state = CacheState::Clean;
                    drop(entry);
                    cache.remove(&path);
                    return Ok(());
                }
                // ロック中のエントリはスキップ
                lru.push_back(path);
            }
        }
        
        // すべてのエントリがロック中の場合（通常は起きない）
        Err(FsError::ResourceBusy)
    }
    
    /// FATキャッシュから古いエントリを削除
    fn evict_fat(&self, cache: &mut BTreeMap<usize, Arc<RwLock<FatCacheEntry>>>, lru: &mut VecDeque<usize>) -> FsResult<()> {
        // LRUリストから古いエントリを取得
        while let Some(fat_index) = lru.pop_front() {
            if let Some(entry_arc) = cache.get(&fat_index) {
                let entry = entry_arc.read();
                if entry.state == CacheState::Clean {
                    // クリーンなエントリは安全に削除可能
                    cache.remove(&fat_index);
                    return Ok(());
                } else if entry.state == CacheState::Dirty {
                    // ダーティなエントリはフラッシュしてから削除
                    drop(entry);
                    // フラッシュ処理（実際にはディスクに書き込む）
                    let mut entry = entry_arc.write();
                    entry.state = CacheState::Clean;
                    drop(entry);
                    cache.remove(&fat_index);
                    return Ok(());
                }
                // ロック中のエントリはスキップ
                lru.push_back(fat_index);
            }
        }
        
        // すべてのエントリがロック中の場合（通常は起きない）
        Err(FsError::ResourceBusy)
    }
    
    /// キャッシュ統計情報を取得
    pub fn get_stats(&self) -> (usize, usize) {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        (hits, misses)
    }
    
    /// キャッシュヒット率を計算
    pub fn hit_ratio(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
    
    /// キャッシュをクリア
    pub fn clear(&self) -> FsResult<()> {
        // ダーティエントリをすべてフラッシュ
        self.flush_all()?;
        
        // キャッシュをクリア
        let mut cluster_cache = self.cluster_cache.write();
        let mut metadata_cache = self.metadata_cache.write();
        let mut dir_cache = self.dir_cache.write();
        let mut fat_cache = self.fat_cache.write();
        
        let mut cluster_lru = self.cluster_lru.lock();
        let mut metadata_lru = self.metadata_lru.lock();
        let mut dir_lru = self.dir_lru.lock();
        let mut fat_lru = self.fat_lru.lock();
        
        cluster_cache.clear();
        metadata_cache.clear();
        dir_cache.clear();
        fat_cache.clear();
        
        cluster_lru.clear();
        metadata_lru.clear();
        dir_lru.clear();
        fat_lru.clear();
        
        Ok(())
    }
} 