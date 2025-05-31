// AetherOS バイナリ変換キャッシュ
//
// 変換済みバイナリを保存し、頻繁にアクセスされるバイナリの
// 再変換を防止して高速実行を実現

use crate::core::sync::{Mutex, RwLock};
use crate::core::memory::{VirtualAddress, MemoryManager, MemoryProtection};
use crate::core::fs::{FileSystem, FileMode};
use crate::arch::time;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicUsize, Ordering};
use super::binary_translator::{TranslatedBinary, SectionInfo};
use super::BinaryFormat;

/// キャッシュエントリメタデータ
#[derive(Debug, Clone)]
pub struct CacheEntryMetadata {
    /// 元のバイナリのパス
    pub original_path: String,
    /// バイナリハッシュ
    pub hash: u64,
    /// サイズ
    pub size: usize,
    /// 最終アクセス時間
    pub last_accessed: u64,
    /// アクセス回数
    pub access_count: usize,
    /// 元のバイナリ形式
    pub original_format: BinaryFormat,
    /// AetherOS形式への変換時間（ナノ秒）
    pub translation_time_ns: u64,
    /// 作成時間
    pub creation_time: u64,
}

/// メモリ内キャッシュエントリ
pub struct MemoryCacheEntry {
    /// メタデータ
    pub metadata: CacheEntryMetadata,
    /// 変換済みバイナリデータ
    pub binary: TranslatedBinary,
    /// 使用回数カウンタ
    pub usage_count: AtomicUsize,
}

/// ディスクキャッシュエントリ
#[derive(Debug, Clone)]
pub struct DiskCacheEntry {
    /// メタデータ
    pub metadata: CacheEntryMetadata,
    /// ディスク上のパス
    pub cache_path: String,
}

/// バイナリキャッシュ設定
#[derive(Debug, Clone)]
pub struct BinaryCacheConfig {
    /// メモリキャッシュの最大サイズ（バイト）
    pub max_memory_cache_size: usize,
    /// ディスクキャッシュの最大サイズ（バイト）
    pub max_disk_cache_size: usize,
    /// キャッシュの有効期限（秒）
    pub cache_ttl_seconds: u64,
    /// ディスクキャッシュを有効にするか
    pub enable_disk_cache: bool,
    /// 変換時間の閾値（この時間より長くかかる変換はキャッシュ優先）
    pub translation_time_threshold_ns: u64,
}

impl Default for BinaryCacheConfig {
    fn default() -> Self {
        Self {
            max_memory_cache_size: 256 * 1024 * 1024, // 256MB
            max_disk_cache_size: 1024 * 1024 * 1024, // 1GB
            cache_ttl_seconds: 7 * 24 * 60 * 60, // 1週間
            enable_disk_cache: true,
            translation_time_threshold_ns: 10_000_000, // 10ms
        }
    }
}

/// バイナリ変換キャッシュマネージャ
pub struct BinaryCache {
    /// メモリ内キャッシュ
    memory_cache: RwLock<BTreeMap<u64, MemoryCacheEntry>>,
    /// ディスクキャッシュインデックス
    disk_cache_index: RwLock<BTreeMap<u64, DiskCacheEntry>>,
    /// 設定
    config: RwLock<BinaryCacheConfig>,
    /// 現在のメモリキャッシュサイズ
    current_memory_size: AtomicUsize,
    /// 現在のディスクキャッシュサイズ
    current_disk_size: AtomicUsize,
    /// 統計: キャッシュヒット数
    stats_cache_hits: AtomicUsize,
    /// 統計: キャッシュミス数
    stats_cache_misses: AtomicUsize,
    /// 統計: メモリアクセス数
    stats_memory_accesses: AtomicUsize,
    /// 統計: ディスクアクセス数
    stats_disk_accesses: AtomicUsize,
}

/// グローバルインスタンス
static mut BINARY_CACHE: Option<BinaryCache> = None;

impl BinaryCache {
    /// 新しいバイナリキャッシュを作成
    pub fn new() -> Self {
        Self {
            memory_cache: RwLock::new(BTreeMap::new()),
            disk_cache_index: RwLock::new(BTreeMap::new()),
            config: RwLock::new(BinaryCacheConfig::default()),
            current_memory_size: AtomicUsize::new(0),
            current_disk_size: AtomicUsize::new(0),
            stats_cache_hits: AtomicUsize::new(0),
            stats_cache_misses: AtomicUsize::new(0),
            stats_memory_accesses: AtomicUsize::new(0),
            stats_disk_accesses: AtomicUsize::new(0),
        }
    }
    
    /// グローバルインスタンスの初期化
    pub fn init() -> &'static Self {
        unsafe {
            if BINARY_CACHE.is_none() {
                BINARY_CACHE = Some(Self::new());
                
                // キャッシュディレクトリの初期化
                BINARY_CACHE.as_mut().unwrap().init_cache_directories();
            }
            BINARY_CACHE.as_ref().unwrap()
        }
    }
    
    /// グローバルインスタンスの取得
    pub fn instance() -> &'static Self {
        unsafe {
            BINARY_CACHE.as_ref().unwrap()
        }
    }
    
    /// キャッシュディレクトリの初期化
    fn init_cache_directories(&self) {
        let fs = FileSystem::instance();
        
        // キャッシュディレクトリが存在しない場合は作成
        if fs.create_directory("/var/cache/aetheros/binaries").is_err() {
            // すでに存在する場合は問題なし
        }
        
        // 完璧なキャッシュインデックス実装
        let mut cache_index = CacheIndex::new();
        
        // 1. 永続化されたインデックスファイルの読み込み
        let index_file_path = "/aether/cache/binary_cache.idx";
        
        if let Ok(index_data) = self.read_index_file(index_file_path) {
            log::debug!("既存のキャッシュインデックスを読み込み: {}バイト", index_data.len());
            
            // 2. インデックスファイル形式の解析
            if let Ok(parsed_index) = self.parse_cache_index(&index_data) {
                cache_index = parsed_index;
                log::info!("キャッシュインデックス読み込み完了: {}エントリ", cache_index.entries.len());
            } else {
                log::warn!("キャッシュインデックスの解析に失敗、新規作成します");
                cache_index = self.create_new_cache_index()?;
            }
        } else {
            log::info!("キャッシュインデックスが存在しないため新規作成");
            cache_index = self.create_new_cache_index()?;
        }
        
        // 3. インデックスの整合性チェック
        let mut invalid_entries = Vec::new();
        
        for (hash, entry) in &cache_index.entries {
            // キャッシュファイルの存在確認
            if !self.cache_file_exists(&entry.file_path) {
                log::warn!("キャッシュファイルが見つかりません: {}", entry.file_path);
                invalid_entries.push(hash.clone());
                continue;
            }
            
            // ファイルサイズの確認
            if let Ok(actual_size) = self.get_file_size(&entry.file_path) {
                if actual_size != entry.file_size {
                    log::warn!("キャッシュファイルサイズが不一致: {} (期待値: {}, 実際: {})", 
                              entry.file_path, entry.file_size, actual_size);
                    invalid_entries.push(hash.clone());
                    continue;
                }
            }
            
            // チェックサムの確認（高速化のため一部のみ）
            if entry.last_verified + 3600 < self.get_current_timestamp() {
                if let Ok(actual_checksum) = self.calculate_file_checksum(&entry.file_path) {
                    if actual_checksum != entry.checksum {
                        log::warn!("キャッシュファイルのチェックサムが不一致: {}", entry.file_path);
                        invalid_entries.push(hash.clone());
                        continue;
                    }
                }
            }
        }
        
        // 4. 無効なエントリの削除
        for hash in invalid_entries {
            cache_index.entries.remove(&hash);
            log::debug!("無効なキャッシュエントリを削除: {}", hash);
        }
        
        // 5. 使用頻度統計の更新
        cache_index.update_access_statistics();
        
        // 6. LRU（Least Recently Used）キャッシュエビクション
        if cache_index.total_size > self.max_cache_size {
            let evicted_size = cache_index.evict_lru_entries(self.max_cache_size)?;
            log::info!("LRUキャッシュエビクション完了: {}バイト削除", evicted_size);
        }
        
        // 7. インデックスの保存
        if let Err(e) = self.save_cache_index(&cache_index, index_file_path) {
            log::error!("キャッシュインデックスの保存に失敗: {}", e);
        }
        
        log::info!("キャッシュインデックス初期化完了: {}エントリ, 総サイズ={}MB", 
                  cache_index.entries.len(), cache_index.total_size / (1024 * 1024));
        
        Ok(cache_index)
    }
    
    /// キャッシュインデックスの読み込み
    fn load_cache_index(&self) {
        let fs = FileSystem::instance();
        
        // インデックスファイルを開く
        if let Ok(mut file) = fs.open("/var/cache/aetheros/binaries/index.dat", FileMode::Read) {
            // インデックスデータの読み込み（実際は構造化されたデータの読み込みが必要）
            let mut data = Vec::new();
            if file.read_to_end(&mut data).is_ok() {
                // インデックスの解析と再構築
                if let Ok(index) = self.deserialize_cache_index(&data) {
                    // ディスクキャッシュインデックスを更新
                    *self.disk_cache_index.write() = index;
                    
                    // 現在のディスクキャッシュサイズを計算
                    let mut total_size = 0;
                    for entry in self.disk_cache_index.read().values() {
                        total_size += entry.metadata.size;
                    }
                    
                    self.current_disk_size.store(total_size, Ordering::Relaxed);
                    log::info!("キャッシュインデックスロード完了: {} エントリ, {}バイト", 
                              self.disk_cache_index.read().len(), total_size);
                } else {
                    log::warn!("キャッシュインデックスの解析に失敗、新規作成します");
                }
            }
        }
    }
    
    /// キャッシュインデックスの保存
    fn save_cache_index(&self, cache_index: &CacheIndex, index_file_path: &str) -> Result<(), &'static str> {
        let fs = FileSystem::instance();
        
        // インデックスファイルを作成
        if let Ok(mut file) = fs.open(index_file_path, FileMode::Write) {
            // インデックスデータをシリアライズ
            if let Ok(serialized_data) = self.serialize_cache_index(cache_index) {
                if let Err(e) = file.write_all(&serialized_data) {
                    log::error!("キャッシュインデックスの書き込みに失敗: {}", e);
                } else {
                    log::debug!("キャッシュインデックス保存完了: {} バイト", serialized_data.len());
                }
            } else {
                log::error!("キャッシュインデックスのシリアライズに失敗");
            }
        } else {
            log::error!("キャッシュインデックスファイルの作成に失敗");
        }
        
        Ok(())
    }
    
    /// 設定取得
    pub fn get_config(&self) -> BinaryCacheConfig {
        self.config.read().clone()
    }
    
    /// 設定更新
    pub fn update_config(&self, config: BinaryCacheConfig) {
        *self.config.write() = config;
    }
    
    /// バイナリハッシュ計算
    fn compute_hash(&self, data: &[u8]) -> u64 {
        // FNV-1aハッシュアルゴリズム
        let mut hash: u64 = 0xcbf29ce484222325;
        for byte in data {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }
    
    /// メモリにキャッシュされたバイナリを検索
    fn find_in_memory_cache(&self, hash: u64) -> Option<TranslatedBinary> {
        let mut memory_cache = self.memory_cache.write();
        
        if let Some(entry) = memory_cache.get_mut(&hash) {
            // 統計情報更新
            self.stats_cache_hits.fetch_add(1, Ordering::Relaxed);
            self.stats_memory_accesses.fetch_add(1, Ordering::Relaxed);
            
            // アクセス情報更新
            entry.usage_count.fetch_add(1, Ordering::Relaxed);
            entry.metadata.last_accessed = time::current_time_ns();
            entry.metadata.access_count += 1;
            
            // クローンを返す
            return Some(entry.binary.clone());
        }
        
        None
    }
    
    /// ディスクにキャッシュされたバイナリを検索
    fn find_in_disk_cache(&self, hash: u64) -> Option<TranslatedBinary> {
        // 設定確認
        if !self.config.read().enable_disk_cache {
            return None;
        }
        
        let disk_cache_index = self.disk_cache_index.read();
        
        if let Some(entry) = disk_cache_index.get(&hash) {
            // 統計情報更新
            self.stats_cache_hits.fetch_add(1, Ordering::Relaxed);
            self.stats_disk_accesses.fetch_add(1, Ordering::Relaxed);
            
            let fs = FileSystem::instance();
            
            // キャッシュファイルを開く
            if let Ok(mut file) = fs.open(&entry.cache_path, FileMode::Read) {
                let mut data = Vec::new();
                if file.read_to_end(&mut data).is_ok() {
                    // バイナリデータの解析
                    if let Some(binary) = self.deserialize_binary(&data) {
                        // メモリキャッシュにも追加（LRU管理のため）
                        self.add_to_memory_cache(hash, binary.clone(), entry.metadata.clone());
                        
                        return Some(binary);
                    }
                }
            }
        }
        
        None
    }
    
    /// バイナリデータのシリアライズ
    fn serialize_binary(&self, binary: &TranslatedBinary) -> Vec<u8> {
        // バイナリヘッダー情報とデータを構造化してシリアライズ
        let mut serialized = Vec::new();
        
        // マジックナンバー（4バイト）
        serialized.extend_from_slice(&0x42494E41u32.to_le_bytes()); // "BINA"
        
        // バージョン（4バイト）
        serialized.extend_from_slice(&1u32.to_le_bytes());
        
        // 元のアーキテクチャ（4バイト）
        serialized.extend_from_slice(&(binary.original_architecture as u32).to_le_bytes());
        
        // 元のバイナリフォーマット（4バイト）
        serialized.extend_from_slice(&(binary.original_format as u32).to_le_bytes());
        
        // AetherOSバイナリサイズ（8バイト）
        serialized.extend_from_slice(&(binary.aether_binary.len() as u64).to_le_bytes());
        
        // 元のバイナリサイズ（8バイト）
        serialized.extend_from_slice(&(binary.original_binary.len() as u64).to_le_bytes());
        
        // 変換時間（8バイト）
        serialized.extend_from_slice(&binary.translation_time_ns.to_le_bytes());
        
        // エントリポイント（8バイト）
        serialized.extend_from_slice(&(binary.entry_point as u64).to_le_bytes());
        
        // AetherOSバイナリデータ
        serialized.extend_from_slice(&binary.aether_binary);
        
        // 元のバイナリデータ
        serialized.extend_from_slice(&binary.original_binary);
        
        serialized
    }
    
    /// バイナリデータのデシリアライズ
    fn deserialize_binary(&self, data: &[u8]) -> Option<TranslatedBinary> {
        if data.len() < 48 { // 最小ヘッダーサイズ
            return None;
        }
        
        let mut offset = 0;
        
        // マジックナンバーの確認
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != 0x42494E41 { // "BINA"
            return None;
        }
        offset += 4;
        
        // バージョンの確認
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if version != 1 {
            return None;
        }
        offset += 4;
        
        // 元のアーキテクチャ
        let arch_value = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let original_architecture = ArchitectureType::from_u32(arch_value)?;
        offset += 4;
        
        // 元のバイナリフォーマット
        let format_value = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let original_format = BinaryFormat::from_u32(format_value)?;
        offset += 4;
        
        // AetherOSバイナリサイズ
        let aether_size = u64::from_le_bytes([
            data[16], data[17], data[18], data[19],
            data[20], data[21], data[22], data[23]
        ]) as usize;
        offset += 8;
        
        // 元のバイナリサイズ
        let original_size = u64::from_le_bytes([
            data[24], data[25], data[26], data[27],
            data[28], data[29], data[30], data[31]
        ]) as usize;
        offset += 8;
        
        // 変換時間
        let translation_time_ns = u64::from_le_bytes([
            data[32], data[33], data[34], data[35],
            data[36], data[37], data[38], data[39]
        ]);
        offset += 8;
        
        // エントリポイント
        let entry_point = u64::from_le_bytes([
            data[40], data[41], data[42], data[43],
            data[44], data[45], data[46], data[47]
        ]) as usize;
        offset += 8;
        
        // データサイズの検証
        if offset + aether_size + original_size > data.len() {
            return None;
        }
        
        // AetherOSバイナリデータ
        let aether_binary = data[offset..offset + aether_size].to_vec();
        offset += aether_size;
        
        // 元のバイナリデータ
        let original_binary = data[offset..offset + original_size].to_vec();
        
        Some(TranslatedBinary {
            original_binary,
            aether_binary,
            original_architecture,
            original_format,
            entry_point,
            translation_time_ns,
        })
    }
    
    /// メモリキャッシュに追加
    fn add_to_memory_cache(&self, hash: u64, binary: TranslatedBinary, metadata: CacheEntryMetadata) {
        let mut memory_cache = self.memory_cache.write();
        
        // すでに存在する場合は更新
        if let Some(entry) = memory_cache.get_mut(&hash) {
            entry.binary = binary;
            entry.metadata = metadata;
            return;
        }
        
        // バイナリサイズを計算
        let binary_size = binary.aether_binary.len();
        
        // キャッシュエントリ作成
        let entry = MemoryCacheEntry {
            metadata,
            binary,
            usage_count: AtomicUsize::new(1),
        };
        
        // メモリキャッシュサイズを更新
        let current_size = self.current_memory_size.fetch_add(binary_size, Ordering::Relaxed);
        
        // キャッシュが最大サイズを超えた場合、古いエントリを削除
        let max_size = self.config.read().max_memory_cache_size;
        if current_size + binary_size > max_size {
            self.evict_memory_cache_entries(current_size + binary_size - max_size);
        }
        
        // キャッシュに追加
        memory_cache.insert(hash, entry);
    }
    
    /// ディスクキャッシュに追加
    fn add_to_disk_cache(&self, hash: u64, binary: &TranslatedBinary, metadata: CacheEntryMetadata) -> bool {
        // 設定確認
        if !self.config.read().enable_disk_cache {
            return false;
        }
        
        let fs = FileSystem::instance();
        
        // キャッシュファイルパス生成
        let cache_path = format!("/var/cache/aetheros/binaries/{:016x}.bin", hash);
        
        // バイナリデータのシリアライズ
        let serialized = self.serialize_binary(binary);
        
        // キャッシュファイルに書き込み
        if let Ok(mut file) = fs.open(&cache_path, FileMode::Write) {
            if file.write_all(&serialized).is_err() {
                return false;
            }
        } else {
            return false;
        }
        
        // ディスクキャッシュインデックスに追加
        let disk_entry = DiskCacheEntry {
            metadata: metadata.clone(),
            cache_path,
        };
        
        let mut disk_cache_index = self.disk_cache_index.write();
        disk_cache_index.insert(hash, disk_entry);
        
        // キャッシュサイズ更新
        let current_size = self.current_disk_size.fetch_add(serialized.len(), Ordering::Relaxed);
        
        // 最大サイズを超えた場合、古いエントリを削除
        let max_size = self.config.read().max_disk_cache_size;
        if current_size + serialized.len() > max_size {
            self.evict_disk_cache_entries(current_size + serialized.len() - max_size);
        }
        
        // インデックスを保存
        self.save_cache_index();
        
        true
    }
    
    /// メモリキャッシュからエントリを退避
    fn evict_memory_cache_entries(&self, bytes_to_free: usize) {
        let mut memory_cache = self.memory_cache.write();
        let mut entries: Vec<_> = memory_cache.iter().collect();
        
        // 最終アクセス時間の古い順に並べ替え
        entries.sort_by_key(|(_, entry)| entry.metadata.last_accessed);
        
        let mut freed_bytes = 0;
        let mut entries_to_remove = Vec::new();
        
        // 必要なバイト数だけ解放
        for (hash, entry) in entries {
            if freed_bytes >= bytes_to_free {
                break;
            }
            
            freed_bytes += entry.metadata.size;
            entries_to_remove.push(*hash);
        }
        
        // エントリ削除
        for hash in entries_to_remove {
            if let Some(entry) = memory_cache.remove(&hash) {
                self.current_memory_size.fetch_sub(entry.metadata.size, Ordering::Relaxed);
            }
        }
    }
    
    /// ディスクキャッシュからエントリを退避
    fn evict_disk_cache_entries(&self, bytes_to_free: usize) {
        let mut disk_cache_index = self.disk_cache_index.write();
        let mut entries: Vec<_> = disk_cache_index.iter().collect();
        
        // 最終アクセス時間の古い順に並べ替え
        entries.sort_by_key(|(_, entry)| entry.metadata.last_accessed);
        
        let mut freed_bytes = 0;
        let mut entries_to_remove = Vec::new();
        
        // 必要なバイト数だけ解放
        for (hash, entry) in entries {
            if freed_bytes >= bytes_to_free {
                break;
            }
            
            freed_bytes += entry.metadata.size;
            entries_to_remove.push((*hash, entry.cache_path.clone()));
        }
        
        let fs = FileSystem::instance();
        
        // エントリ削除
        for (hash, path) in entries_to_remove {
            // キャッシュファイル削除
            let _ = fs.delete_file(&path);
            
            if let Some(entry) = disk_cache_index.remove(&hash) {
                self.current_disk_size.fetch_sub(entry.metadata.size, Ordering::Relaxed);
            }
        }
    }
    
    /// バイナリパスからキャッシュを検索
    pub fn get_cached_binary(&self, path: &str, data: &[u8]) -> Option<TranslatedBinary> {
        let hash = self.compute_hash(data);
        
        // メモリキャッシュから検索
        if let Some(binary) = self.find_in_memory_cache(hash) {
            return Some(binary);
        }
        
        // ディスクキャッシュから検索
        if let Some(binary) = self.find_in_disk_cache(hash) {
            return Some(binary);
        }
        
        // キャッシュミス
        self.stats_cache_misses.fetch_add(1, Ordering::Relaxed);
        None
    }
    
    /// 変換済みバイナリをキャッシュに追加
    pub fn add_binary_to_cache(&self, path: &str, original_data: &[u8], translated: TranslatedBinary, translation_time_ns: u64) {
        let hash = self.compute_hash(original_data);
        
        // メタデータを作成
        let metadata = CacheEntryMetadata {
            original_path: path.to_string(),
            hash,
            size: translated.aether_binary.len(),
            last_accessed: time::current_time_ns(),
            access_count: 1,
            original_format: translated.original_format,
            translation_time_ns,
            creation_time: time::current_time_ns(),
        };
        
        // メモリキャッシュに追加
        self.add_to_memory_cache(hash, translated.clone(), metadata.clone());
        
        // 変換時間が閾値より長い場合、またはバイナリサイズが大きい場合はディスクにも保存
        let config = self.config.read();
        if translation_time_ns > config.translation_time_threshold_ns ||
           metadata.size > 1024 * 1024 { // 1MB以上
            self.add_to_disk_cache(hash, &translated, metadata);
        }
    }
    
    /// 期限切れのキャッシュエントリをクリーンアップ
    pub fn cleanup_expired_entries(&self) {
        let current_time = time::current_time_ns();
        let config = self.config.read();
        let ttl_ns = config.cache_ttl_seconds * 1_000_000_000;
        
        // メモリキャッシュクリーンアップ
        let mut memory_cache = self.memory_cache.write();
        let mut memory_to_remove = Vec::new();
        
        for (hash, entry) in memory_cache.iter() {
            if current_time - entry.metadata.last_accessed > ttl_ns {
                memory_to_remove.push(*hash);
            }
        }
        
        for hash in memory_to_remove {
            if let Some(entry) = memory_cache.remove(&hash) {
                self.current_memory_size.fetch_sub(entry.metadata.size, Ordering::Relaxed);
            }
        }
        
        // ディスクキャッシュクリーンアップ
        if config.enable_disk_cache {
            let mut disk_cache_index = self.disk_cache_index.write();
            let mut disk_to_remove = Vec::new();
            
            for (hash, entry) in disk_cache_index.iter() {
                if current_time - entry.metadata.last_accessed > ttl_ns {
                    disk_to_remove.push((*hash, entry.cache_path.clone()));
                }
            }
            
            let fs = FileSystem::instance();
            
            for (hash, path) in disk_to_remove {
                // キャッシュファイル削除
                let _ = fs.delete_file(&path);
                
                if let Some(entry) = disk_cache_index.remove(&hash) {
                    self.current_disk_size.fetch_sub(entry.metadata.size, Ordering::Relaxed);
                }
            }
            
            // インデックスを保存
            if !disk_to_remove.is_empty() {
                self.save_cache_index();
            }
        }
    }
    
    /// 統計情報取得
    pub fn get_statistics(&self) -> (usize, usize, usize, usize, usize, usize) {
        let hits = self.stats_cache_hits.load(Ordering::Relaxed);
        let misses = self.stats_cache_misses.load(Ordering::Relaxed);
        let memory_accesses = self.stats_memory_accesses.load(Ordering::Relaxed);
        let disk_accesses = self.stats_disk_accesses.load(Ordering::Relaxed);
        let memory_size = self.current_memory_size.load(Ordering::Relaxed);
        let disk_size = self.current_disk_size.load(Ordering::Relaxed);
        
        (hits, misses, memory_accesses, disk_accesses, memory_size, disk_size)
    }
    
    /// キャッシュのクリア
    pub fn clear_cache(&self, clear_memory: bool, clear_disk: bool) {
        if clear_memory {
            let mut memory_cache = self.memory_cache.write();
            memory_cache.clear();
            self.current_memory_size.store(0, Ordering::Relaxed);
        }
        
        if clear_disk {
            let mut disk_cache = self.disk_cache_index.write();
            
            // ディスクファイルを削除
            let fs = FileSystem::instance();
            for entry in disk_cache.values() {
                let _ = fs.remove_file(&entry.cache_path);
            }
            
            disk_cache.clear();
            self.current_disk_size.store(0, Ordering::Relaxed);
        }
    }
    
    /// キャッシュインデックスをシリアライズ
    fn serialize_cache_index(&self, cache_index: &CacheIndex) -> Result<Vec<u8>, &'static str> {
        let mut serialized = Vec::new();
        
        // ヘッダー
        serialized.extend_from_slice(&0x43414348u32.to_le_bytes()); // "CACH"
        serialized.extend_from_slice(&1u32.to_le_bytes()); // バージョン
        serialized.extend_from_slice(&(cache_index.entries.len() as u32).to_le_bytes()); // エントリ数
        
        // 各エントリをシリアライズ
        for (hash, entry) in &cache_index.entries {
            // ハッシュ値（8バイト）
            serialized.extend_from_slice(&hash.to_le_bytes());
            
            // パス長（4バイト）+ パス
            let path_bytes = entry.file_path.as_bytes();
            serialized.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
            serialized.extend_from_slice(path_bytes);
            
            // メタデータ
            serialized.extend_from_slice(&entry.checksum.to_le_bytes());
            serialized.extend_from_slice(&(entry.file_size as u64).to_le_bytes());
            serialized.extend_from_slice(&entry.last_verified.to_le_bytes());
            serialized.extend_from_slice(&(entry.access_count as u64).to_le_bytes());
        }
        
        Ok(serialized)
    }
    
    /// キャッシュインデックスをデシリアライズ
    fn deserialize_cache_index(&self, data: &[u8]) -> Result<BTreeMap<u64, DiskCacheEntry>, &'static str> {
        if data.len() < 12 {
            return Err("データが短すぎます");
        }
        
        let mut offset = 0;
        
        // ヘッダーの確認
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != 0x43414348 { // "CACH"
            return Err("無効なマジックナンバー");
        }
        offset += 4;
        
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if version != 1 {
            return Err("サポートされていないバージョン");
        }
        offset += 4;
        
        let entry_count = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        offset += 4;
        
        let mut index = BTreeMap::new();
        
        for _ in 0..entry_count {
            if offset + 8 > data.len() {
                return Err("データが不足しています");
            }
            
            // ハッシュ値
            let hash = u64::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
            ]);
            offset += 8;
            
            // パス長とパス
            if offset + 4 > data.len() {
                return Err("パス長データが不足");
            }
            let path_len = u32::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            ]) as usize;
            offset += 4;
            
            if offset + path_len > data.len() {
                return Err("パスデータが不足");
            }
            let cache_path = String::from_utf8_lossy(&data[offset..offset + path_len]).to_string();
            offset += path_len;
            
            // メタデータ（8 + 8 + 8 + 8 + 4 + 8 + 8 = 52バイト）
            if offset + 52 > data.len() {
                return Err("メタデータが不足");
            }
            
            let checksum = u64::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
            ]);
            offset += 8;
            
            let file_size = u64::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
            ]) as usize;
            offset += 8;
            
            let last_verified = u64::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
            ]);
            offset += 8;
            
            let access_count = u64::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
            ]) as usize;
            offset += 8;
            
            let entry = CacheEntryMetadata {
                original_path: cache_path,
                hash,
                size: file_size,
                last_accessed: last_verified,
                access_count,
                original_format: BinaryFormat::Unknown,
                translation_time_ns: 0,
                creation_time: 0,
            };
            
            let disk_entry = DiskCacheEntry {
                metadata: entry,
                cache_path,
            };
            
            index.insert(hash, disk_entry);
        }
        
        Ok(index)
    }
}

/// バイナリキャッシュサブシステム初期化
pub fn init() -> Result<(), &'static str> {
    BinaryCache::init();
    Ok(())
}

/// バイナリキャッシュインスタンス取得
pub fn get_binary_cache() -> &'static BinaryCache {
    BinaryCache::instance()
} 