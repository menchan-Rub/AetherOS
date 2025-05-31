// ファイルシステムキャッシュ実装
//
// ファイルシステムへのアクセス速度を向上させるためのキャッシュ機構

use core::sync::atomic::{AtomicU64, Ordering};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::RwLock;
use super::{FsError, FsResult, InodeNum};

/// キャッシュエントリのステータス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheStatus {
    /// クリーン（ディスクと同期済み）
    Clean,
    /// ダーティ（変更あり、ディスクと未同期）
    Dirty,
}

/// キャッシュされたブロックデータ
struct CachedBlock {
    /// ブロックデータ
    data: RwLock<Vec<u8>>,
    /// キャッシュ状態
    status: RwLock<CacheStatus>,
    /// 最終アクセス時間
    last_access: AtomicU64,
    /// 参照カウント
    ref_count: AtomicU64,
}

impl CachedBlock {
    /// 新しいキャッシュブロックを作成
    fn new(data: Vec<u8>) -> Self {
        Self {
            data: RwLock::new(data),
            status: RwLock::new(CacheStatus::Clean),
            last_access: AtomicU64::new(current_time()),
            ref_count: AtomicU64::new(1),
        }
    }
    
    /// 参照カウントを増加
    fn inc_ref(&self) {
        self.ref_count.fetch_add(1, Ordering::SeqCst);
    }
    
    /// 参照カウントを減少
    fn dec_ref(&self) -> u64 {
        self.ref_count.fetch_sub(1, Ordering::SeqCst) - 1
    }
    
    /// アクセス時間を更新
    fn update_access_time(&self) {
        self.last_access.store(current_time(), Ordering::SeqCst);
    }
    
    /// ダーティとしてマーク
    fn mark_dirty(&self) {
        *self.status.write() = CacheStatus::Dirty;
    }
    
    /// クリーンとしてマーク
    fn mark_clean(&self) {
        *self.status.write() = CacheStatus::Clean;
    }
    
    /// データ読み取り
    fn read(&self) -> Vec<u8> {
        self.update_access_time();
        self.data.read().clone()
    }
    
    /// データ書き込み
    fn write(&self, data: Vec<u8>) {
        self.update_access_time();
        *self.data.write() = data;
        self.mark_dirty();
    }
    
    /// ダーティ状態かどうか
    fn is_dirty(&self) -> bool {
        *self.status.read() == CacheStatus::Dirty
    }
}

/// ブロックキャッシュの実装
struct BlockCache {
    /// キャッシュされたブロック (デバイスID, ブロック番号) => ブロックデータ
    blocks: RwLock<BTreeMap<(u64, u64), Arc<CachedBlock>>>,
    /// 最大キャッシュサイズ（ブロック数）
    max_blocks: usize,
    /// キャッシュヒット数
    hits: AtomicU64,
    /// キャッシュミス数
    misses: AtomicU64,
}

impl BlockCache {
    /// 新しいブロックキャッシュを作成
    fn new(max_blocks: usize) -> Self {
        Self {
            blocks: RwLock::new(BTreeMap::new()),
            max_blocks,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }
    
    /// ブロックをキャッシュから取得（キャッシュミス時はNone）
    fn get_block(&self, device_id: u64, block_num: u64) -> Option<Arc<CachedBlock>> {
        let blocks = self.blocks.read();
        let key = (device_id, block_num);
        
        if let Some(block) = blocks.get(&key) {
            // キャッシュヒット
            self.hits.fetch_add(1, Ordering::Relaxed);
            let block = block.clone();
            block.inc_ref();
            Some(block)
        } else {
            // キャッシュミス
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
    
    /// ブロックをキャッシュに追加
    fn add_block(&self, device_id: u64, block_num: u64, data: Vec<u8>) -> Arc<CachedBlock> {
        let mut blocks = self.blocks.write();
        let key = (device_id, block_num);
        
        // キャッシュサイズをチェック
        if blocks.len() >= self.max_blocks && !blocks.contains_key(&key) {
            self.evict_blocks(1, &mut blocks);
        }
        
        // 既存のブロックがあれば更新、なければ新規作成
        match blocks.get(&key) {
            Some(block) => {
                let block = block.clone();
                block.inc_ref();
                block.write(data);
                block
            }
            None => {
                let block = Arc::new(CachedBlock::new(data));
                blocks.insert(key, block.clone());
                block
            }
        }
    }
    
    /// ブロックを解放（参照カウント減少）
    fn release_block(&self, device_id: u64, block_num: u64) {
        let blocks = self.blocks.read();
        let key = (device_id, block_num);
        
        if let Some(block) = blocks.get(&key) {
            if block.dec_ref() == 0 {
                // 参照カウントが0になったらキャッシュから削除
                drop(blocks); // readロックを解放
                let mut blocks = self.blocks.write();
                blocks.remove(&key);
            }
        }
    }
    
    /// ブロックを書き込み（ダーティとしてマーク）
    fn write_block(&self, device_id: u64, block_num: u64, data: Vec<u8>) -> Arc<CachedBlock> {
        if let Some(block) = self.get_block(device_id, block_num) {
            block.write(data);
            block
        } else {
            self.add_block(device_id, block_num, data)
        }
    }
    
    /// キャッシュからブロックを追い出す
    fn evict_blocks(&self, count: usize, blocks: &mut BTreeMap<(u64, u64), Arc<CachedBlock>>) {
        // アクセス時間順に並べ替え
        let mut block_times: Vec<_> = blocks.iter()
            .map(|((dev, blk), block)| ((dev, blk), block.last_access.load(Ordering::Relaxed)))
            .collect();
        
        // 参照カウントが1（キャッシュのみが参照）かつ最も古いアクセス時間のものから削除
        block_times.sort_by_key(|(_, time)| *time);
        
        let mut evicted = 0;
        for ((dev, blk), _) in block_times {
            if evicted >= count {
                break;
            }
            
            let key = (*dev, *blk);
            let can_evict = match blocks.get(&key) {
                Some(block) => block.ref_count.load(Ordering::SeqCst) == 1,
                None => false,
            };
            
            if can_evict {
                // ダーティブロックはフラッシュしてからキャッシュから削除
                if let Some(block) = blocks.get(&key) {
                    if block.is_dirty() {
                        flush_block_to_device(*dev, *blk, block.read());
                    }
                }
                
                blocks.remove(&key);
                evicted += 1;
            }
        }
    }
    
    /// すべてのダーティブロックをフラッシュ
    fn flush_all(&self) -> FsResult<()> {
        let blocks = self.blocks.read();
        
        for ((dev, blk), block) in blocks.iter() {
            if block.is_dirty() {
                flush_block_to_device(*dev, *blk, block.read());
                block.mark_clean();
            }
        }
        
        Ok(())
    }
    
    /// キャッシュ統計を取得
    fn stats(&self) -> CacheStats {
        let blocks = self.blocks.read();
        let total = blocks.len();
        let dirty = blocks.values().filter(|b| b.is_dirty()).count();
        
        CacheStats {
            total_blocks: total,
            dirty_blocks: dirty,
            max_blocks: self.max_blocks,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }
}

/// キャッシュ統計情報
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    /// キャッシュされたブロック総数
    pub total_blocks: usize,
    /// ダーティブロック数
    pub dirty_blocks: usize,
    /// 最大キャッシュサイズ
    pub max_blocks: usize,
    /// キャッシュヒット数
    pub hits: u64,
    /// キャッシュミス数
    pub misses: u64,
}

/// アイノードキャッシュのエントリ
struct CachedInode {
    /// デバイスID
    device_id: u64,
    /// アイノード番号
    ino: InodeNum,
    /// アイノードデータ（ファイルシステム固有のシリアル化形式）
    data: RwLock<Vec<u8>>,
    /// キャッシュ状態
    status: RwLock<CacheStatus>,
    /// 最終アクセス時間
    last_access: AtomicU64,
    /// 参照カウント
    ref_count: AtomicU64,
}

impl CachedInode {
    /// 新しいキャッシュアイノードを作成
    fn new(device_id: u64, ino: InodeNum, data: Vec<u8>) -> Self {
        Self {
            device_id,
            ino,
            data: RwLock::new(data),
            status: RwLock::new(CacheStatus::Clean),
            last_access: AtomicU64::new(current_time()),
            ref_count: AtomicU64::new(1),
        }
    }
    
    // 以下はCachedBlockと同様のメソッド
    fn inc_ref(&self) {
        self.ref_count.fetch_add(1, Ordering::SeqCst);
    }
    
    fn dec_ref(&self) -> u64 {
        self.ref_count.fetch_sub(1, Ordering::SeqCst) - 1
    }
    
    fn update_access_time(&self) {
        self.last_access.store(current_time(), Ordering::SeqCst);
    }
    
    fn mark_dirty(&self) {
        *self.status.write() = CacheStatus::Dirty;
    }
    
    fn mark_clean(&self) {
        *self.status.write() = CacheStatus::Clean;
    }
    
    fn read(&self) -> Vec<u8> {
        self.update_access_time();
        self.data.read().clone()
    }
    
    fn write(&self, data: Vec<u8>) {
        self.update_access_time();
        *self.data.write() = data;
        self.mark_dirty();
    }
    
    fn is_dirty(&self) -> bool {
        *self.status.read() == CacheStatus::Dirty
    }
}

/// アイノードキャッシュの実装
struct InodeCache {
    /// キャッシュされたアイノード (デバイスID, アイノード番号) => アイノードデータ
    inodes: RwLock<BTreeMap<(u64, InodeNum), Arc<CachedInode>>>,
    /// 最大キャッシュサイズ（アイノード数）
    max_inodes: usize,
    /// キャッシュヒット数
    hits: AtomicU64,
    /// キャッシュミス数
    misses: AtomicU64,
}

impl InodeCache {
    /// 新しいアイノードキャッシュを作成
    fn new(max_inodes: usize) -> Self {
        Self {
            inodes: RwLock::new(BTreeMap::new()),
            max_inodes,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }
    
    /// アイノードをキャッシュから取得
    fn get_inode(&self, device_id: u64, ino: InodeNum) -> Option<Arc<CachedInode>> {
        let inodes = self.inodes.read();
        let key = (device_id, ino);
        
        if let Some(inode) = inodes.get(&key) {
            // キャッシュヒット
            self.hits.fetch_add(1, Ordering::Relaxed);
            let inode = inode.clone();
            inode.inc_ref();
            Some(inode)
        } else {
            // キャッシュミス
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
    
    /// アイノードをキャッシュに追加
    fn add_inode(&self, device_id: u64, ino: InodeNum, data: Vec<u8>) -> Arc<CachedInode> {
        let mut inodes = self.inodes.write();
        let key = (device_id, ino);
        
        // キャッシュサイズをチェック
        if inodes.len() >= self.max_inodes && !inodes.contains_key(&key) {
            self.evict_inodes(1, &mut inodes);
        }
        
        // 既存のアイノードがあれば更新、なければ新規作成
        match inodes.get(&key) {
            Some(inode) => {
                let inode = inode.clone();
                inode.inc_ref();
                inode.write(data);
                inode
            }
            None => {
                let inode = Arc::new(CachedInode::new(device_id, ino, data));
                inodes.insert(key, inode.clone());
                inode
            }
        }
    }
    
    /// アイノードを解放（参照カウント減少）
    fn release_inode(&self, device_id: u64, ino: InodeNum) {
        let inodes = self.inodes.read();
        let key = (device_id, ino);
        
        if let Some(inode) = inodes.get(&key) {
            if inode.dec_ref() == 0 {
                // 参照カウントが0になったらキャッシュから削除
                drop(inodes); // readロックを解放
                let mut inodes = self.inodes.write();
                inodes.remove(&key);
            }
        }
    }
    
    /// アイノードを書き込み（ダーティとしてマーク）
    fn write_inode(&self, device_id: u64, ino: InodeNum, data: Vec<u8>) -> Arc<CachedInode> {
        if let Some(inode) = self.get_inode(device_id, ino) {
            inode.write(data);
            inode
        } else {
            self.add_inode(device_id, ino, data)
        }
    }
    
    /// キャッシュからアイノードを追い出す
    fn evict_inodes(&self, count: usize, inodes: &mut BTreeMap<(u64, InodeNum), Arc<CachedInode>>) {
        // アクセス時間順に並べ替え
        let mut inode_times: Vec<_> = inodes.iter()
            .map(|((dev, ino), inode)| ((dev, ino), inode.last_access.load(Ordering::Relaxed)))
            .collect();
        
        // 参照カウントが1（キャッシュのみが参照）かつ最も古いアクセス時間のものから削除
        inode_times.sort_by_key(|(_, time)| *time);
        
        let mut evicted = 0;
        for ((dev, ino), _) in inode_times {
            if evicted >= count {
                break;
            }
            
            let key = (*dev, *ino);
            let can_evict = match inodes.get(&key) {
                Some(inode) => inode.ref_count.load(Ordering::SeqCst) == 1,
                None => false,
            };
            
            if can_evict {
                // ダーティアイノードはフラッシュしてからキャッシュから削除
                if let Some(inode) = inodes.get(&key) {
                    if inode.is_dirty() {
                        flush_inode_to_device(*dev, *ino, inode.read());
                    }
                }
                
                inodes.remove(&key);
                evicted += 1;
            }
        }
    }
    
    /// すべてのダーティアイノードをフラッシュ
    fn flush_all(&self) -> FsResult<()> {
        let inodes = self.inodes.read();
        
        for ((dev, ino), inode) in inodes.iter() {
            if inode.is_dirty() {
                flush_inode_to_device(*dev, *ino, inode.read());
                inode.mark_clean();
            }
        }
        
        Ok(())
    }
}

/// グローバルブロックキャッシュ
static BLOCK_CACHE: RwLock<Option<BlockCache>> = RwLock::new(None);

/// グローバルアイノードキャッシュ
static INODE_CACHE: RwLock<Option<InodeCache>> = RwLock::new(None);

/// 現在時間を取得（システム起動からの経過時間）
fn current_time() -> u64 {
    // システムの現在時刻をミリ秒単位で取得
    crate::time::get_current_time().as_millis()
}

/// ブロックをデバイスに書き込む
fn flush_block_to_device(device_id: u64, block_num: u64, data: Vec<u8>) {
    // デバイスマネージャからデバイスを取得
    let device_manager = crate::drivers::block::get_device_manager();
    
    match device_manager.get_device(device_id) {
        Some(device) => {
            // ブロックサイズを取得して整合性チェック
            let block_size = device.get_block_size();
            
            if data.len() as u64 != block_size {
                log::error!("ブロック書き込みエラー: サイズ不一致 - 予期: {} 実際: {}", 
                           block_size, data.len());
                return;
            }
            
            // ブロック書き込み実行
            match device.write_block(block_num, &data) {
                Ok(_) => {
                    log::debug!("ブロック書き込み成功: デバイス {} ブロック {} データサイズ {}バイト", 
                               device_id, block_num, data.len());
                },
                Err(err) => {
                    log::error!("ブロック書き込みエラー: デバイス {} ブロック {} - エラー: {:?}", 
                               device_id, block_num, err);
                }
            }
        },
        None => {
            log::error!("ブロック書き込みエラー: デバイス {} が見つかりません", device_id);
        }
    }
}

/// アイノードをデバイスに書き込む
fn flush_inode_to_device(device_id: u64, ino: InodeNum, data: Vec<u8>) {
    // デバイスマネージャからデバイスを取得
    let device_manager = crate::drivers::block::get_device_manager();
    
    match device_manager.get_device(device_id) {
        Some(device) => {
            // ファイルシステム固有のアイノードマップを取得
            let fs_manager = crate::core::fs::get_fs_manager();
            let fs_handler = fs_manager.get_handler_for_device(device_id);
            
            match fs_handler {
                Some(handler) => {
                    // アイノード番号をブロック番号に変換
                    match handler.get_inode_block_location(ino) {
                        Ok((block_num, offset)) => {
                            // ブロックを読み取り
                            match device.read_block(block_num) {
                                Ok(mut block_data) => {
                                    // アイノードデータをブロックに書き込み
                                    if offset + data.len() <= block_data.len() {
                                        block_data[offset..(offset + data.len())].copy_from_slice(&data);
                                        
                                        // 更新したブロックを書き込み
                                        match device.write_block(block_num, &block_data) {
                                            Ok(_) => {
                                                log::debug!("アイノード書き込み成功: デバイス {} アイノード {} データサイズ {}バイト",
                                                           device_id, ino, data.len());
                                            },
                                            Err(err) => {
                                                log::error!("アイノード書き込みエラー: ブロック書き込み失敗 - エラー: {:?}", err);
                                            }
                                        }
                                    } else {
                                        log::error!("アイノード書き込みエラー: オフセット + サイズがブロックサイズを超えています");
                                    }
                                },
                                Err(err) => {
                                    log::error!("アイノード書き込みエラー: ブロック読み取り失敗 - エラー: {:?}", err);
                                }
                            }
                        },
                        Err(err) => {
                            log::error!("アイノード書き込みエラー: アイノード位置の計算に失敗 - エラー: {:?}", err);
                        }
                    }
                },
                None => {
                    log::error!("アイノード書き込みエラー: デバイス {} のファイルシステムハンドラが見つかりません", device_id);
                }
            }
        },
        None => {
            log::error!("アイノード書き込みエラー: デバイス {} が見つかりません", device_id);
        }
    }
}

/// キャッシュシステムを初期化
pub fn init() -> FsResult<()> {
    // デフォルト値は環境に応じて調整可能
    let block_cache_size = 8192;  // 8192ブロック（32MBなど、ブロックサイズによる）
    let inode_cache_size = 4096;  // 4096アイノード
    
    *BLOCK_CACHE.write() = Some(BlockCache::new(block_cache_size));
    *INODE_CACHE.write() = Some(InodeCache::new(inode_cache_size));
    
    log::info!("ファイルシステムキャッシュ初期化完了: ブロックキャッシュ {}個, アイノードキャッシュ {}個",
              block_cache_size, inode_cache_size);
    
    Ok(())
}

/// ブロックをキャッシュから取得（キャッシュミス時はNone）
pub fn get_cached_block(device_id: u64, block_num: u64) -> Option<Arc<CachedBlock>> {
    if let Some(cache) = BLOCK_CACHE.read().as_ref() {
        cache.get_block(device_id, block_num)
    } else {
        None
    }
}

/// ブロックをキャッシュに追加/更新
pub fn cache_block(device_id: u64, block_num: u64, data: Vec<u8>) -> Option<Arc<CachedBlock>> {
    if let Some(cache) = BLOCK_CACHE.read().as_ref() {
        Some(cache.add_block(device_id, block_num, data))
    } else {
        None
    }
}

/// ブロックをキャッシュから解放
pub fn release_block(device_id: u64, block_num: u64) {
    if let Some(cache) = BLOCK_CACHE.read().as_ref() {
        cache.release_block(device_id, block_num);
    }
}

/// アイノードをキャッシュから取得
pub fn get_cached_inode(device_id: u64, ino: InodeNum) -> Option<Arc<CachedInode>> {
    if let Some(cache) = INODE_CACHE.read().as_ref() {
        cache.get_inode(device_id, ino)
    } else {
        None
    }
}

/// アイノードをキャッシュに追加/更新
pub fn cache_inode(device_id: u64, ino: InodeNum, data: Vec<u8>) -> Option<Arc<CachedInode>> {
    if let Some(cache) = INODE_CACHE.read().as_ref() {
        Some(cache.add_inode(device_id, ino, data))
    } else {
        None
    }
}

/// アイノードをキャッシュから解放
pub fn release_inode(device_id: u64, ino: InodeNum) {
    if let Some(cache) = INODE_CACHE.read().as_ref() {
        cache.release_inode(device_id, ino);
    }
}

/// すべてのキャッシュをフラッシュ
pub fn flush_all() -> FsResult<()> {
    // ブロックキャッシュをフラッシュ
    if let Some(cache) = BLOCK_CACHE.read().as_ref() {
        cache.flush_all()?;
    }
    
    // アイノードキャッシュをフラッシュ
    if let Some(cache) = INODE_CACHE.read().as_ref() {
        cache.flush_all()?;
    }
    
    Ok(())
}

/// キャッシュ統計を取得
pub fn get_cache_stats() -> Option<CacheStats> {
    if let Some(cache) = BLOCK_CACHE.read().as_ref() {
        Some(cache.stats())
    } else {
        None
    }
} 