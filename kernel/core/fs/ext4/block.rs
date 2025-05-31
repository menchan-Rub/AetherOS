// Ext4 ブロックデバイスインターフェース
//
// ブロックデバイスへのアクセスを抽象化するインターフェース

use alloc::vec::Vec;
use alloc::sync::Arc;
use spin::RwLock;
use super::super::{FsError, FsResult, cache};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::collections::HashSet;

/// ブロックデバイス
pub struct BlockDevice {
    /// デバイスパス
    path: String,
    /// デバイスID
    device_id: u64,
    /// キャッシュの使用可否
    use_cache: bool,
    /// デバイスハンドル（実装依存）
    handle: RwLock<DeviceHandle>,
    /// ブロックサイズ
    block_size: u64,
    /// ブロックカウント
    block_count: u64,
    /// キャッシュ
    cache: RwLock<BTreeMap<u64, Vec<u8>>>,
    /// ダーティブロック
    dirty_blocks: Mutex<HashSet<u64>>,
}

/// デバイスハンドル（実装依存）
enum DeviceHandle {
    /// ファイルベースのデバイス
    File(/* ファイルハンドル */),
    /// メモリ上のデバイス（テスト用）
    Memory(Vec<Vec<u8>>),
    /// ブロックデバイス（実際のデバイス）
    Block(/* デバイスハンドル */),
    /// 未初期化
    None,
}

impl BlockDevice {
    /// ブロックデバイスをオープン
    pub fn open(path: &str) -> FsResult<Self> {
        let device_id = calculate_device_id(path);
        
        // デバイスパスを解析してファイルかブロックデバイスかを判断
        if path.starts_with("/dev/") {
            // ブロックデバイス
            match crate::fs::devfs::open_block_device(path) {
                Ok(handle) => {
                    // デバイス情報を取得
                    let block_size = handle.get_block_size()
                        .unwrap_or(DEFAULT_BLOCK_SIZE);
                    let block_count = handle.get_block_count()
                        .unwrap_or(DEFAULT_BLOCK_COUNT);
                    
                    // デバイス固有のパラメータを取得
                    let use_cache = !path.contains("nocache");
                    
                    // デバイスオプションの解析（デバイスパスに含まれる可能性がある）
                    let options = parse_device_options(path);
                    
                    // ブロックデバイスのキャッシュ初期化
                    let cache_size = options.get("cache_size")
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(DEFAULT_CACHE_SIZE);
                    
                    Ok(Self {
                        path: path.to_string(),
                        device_id,
                        use_cache,
                        handle: RwLock::new(DeviceHandle::Block(handle)),
                        block_size,
                        block_count,
                        cache: RwLock::new(BTreeMap::with_capacity(cache_size)),
                        dirty_blocks: Mutex::new(HashSet::new()),
                    })
                },
                Err(e) => {
                    log::error!("ブロックデバイス {} のオープンに失敗: {:?}", path, e);
                    Err(e)
                }
            }
        } else {
            // 通常のファイル
            match crate::fs::open_file(path, OpenMode::ReadWrite) {
                Ok(file) => {
                    // ファイルのサイズからブロック数を計算
                    let size = file.size()?;
                    let block_count = (size + DEFAULT_BLOCK_SIZE - 1) / DEFAULT_BLOCK_SIZE;
                    
                    Ok(Self {
                        path: path.to_string(),
                        device_id,
                        use_cache: true,
                        handle: RwLock::new(DeviceHandle::File(file)),
                        block_size: DEFAULT_BLOCK_SIZE,
                        block_count,
                        cache: RwLock::new(BTreeMap::new()),
                        dirty_blocks: Mutex::new(HashSet::new()),
                    })
                },
                Err(e) => {
                    // 新規ファイル作成を試みる
                    if e == FsError::NotFound && path.contains("create") {
                        match crate::fs::open_file(path, OpenMode::Create) {
                            Ok(file) => {
                                // 新規ファイルを作成し、初期サイズを設定
                                let init_size = DEFAULT_BLOCK_COUNT * DEFAULT_BLOCK_SIZE;
                                file.resize(init_size)?;
                                
                                Ok(Self {
                                    path: path.to_string(),
                                    device_id,
                                    use_cache: true,
                                    handle: RwLock::new(DeviceHandle::File(file)),
                                    block_size: DEFAULT_BLOCK_SIZE,
                                    block_count: DEFAULT_BLOCK_COUNT,
                                    cache: RwLock::new(BTreeMap::new()),
                                    dirty_blocks: Mutex::new(HashSet::new()),
                                })
                            },
                            Err(create_err) => Err(create_err)
                        }
                    } else {
                        log::error!("ファイル {} のオープンに失敗: {:?}", path, e);
                        Err(e)
                    }
                }
            }
        }
    }
    
    /// デバイスID取得
    pub fn device_id(&self) -> u64 {
        self.device_id
    }
    
    /// ブロックデバイスを閉じる
    pub fn close(&self) -> FsResult<()> {
        // まずキャッシュを同期
        self.sync()?;

        // デバイスに応じたクローズ処理
        let handle = self.handle.read();
        match &*handle {
            DeviceHandle::File(file) => {
                // ファイルをフラッシュして閉じる
                file.flush()?;
                file.close()?;
                log::debug!("ファイル {} を閉じました", self.path);
            },
            DeviceHandle::Block(block) => {
                // ブロックデバイスを閉じる
                block.close()?;
                log::debug!("ブロックデバイス {} を閉じました", self.path);
                
                // ジャーナルの同期（該当する場合）
                if let Some(journal) = block.get_journal() {
                    journal.sync()?;
                    log::debug!("デバイス {} のジャーナルを同期しました", self.path);
                }
            },
            DeviceHandle::Memory(_) => {
                // メモリデバイスの場合、すべてのデータを永続化
                if self.path.starts_with("/dev/persist_mem") {
                    // メモリ内容をディスクに保存
                    self.persist_memory_device()?;
                    log::debug!("メモリデバイス {} の内容を永続化しました", self.path);
                }
            },
            DeviceHandle::None => {
                return Err(FsError::DeviceError);
            },
        }

        // キャッシュをクリア
        let mut cache = self.cache.write();
        cache.clear();
        
        // ダーティブロックをクリア
        let mut dirty = self.dirty_blocks.lock();
        dirty.clear();
        
        log::info!("ブロックデバイス {} を正常に閉じました", self.path);
        
        Ok(())
    }
    
    /// ブロックサイズを設定
    pub fn set_block_size(&mut self, block_size: u64) {
        self.block_size = block_size;
    }
    
    /// ブロックサイズを取得
    pub fn block_size(&self) -> u64 {
        self.block_size
    }
    
    /// キャッシュの使用設定
    pub fn set_use_cache(&mut self, use_cache: bool) {
        self.use_cache = use_cache;
    }
    
    /// 単一ブロックを読み込み
    pub fn read_block(&self, block_index: u64) -> FsResult<Vec<u8>> {
        self.read_blocks(block_index, 1)
    }
    
    /// 複数ブロックを読み込み
    pub fn read_blocks(&self, start_block: u64, count: u64) -> FsResult<Vec<u8>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        
        let mut result = Vec::with_capacity((self.block_size as usize) * (count as usize));
        
        for i in 0..count {
            let block_index = start_block + i;
            
            // キャッシュから読み込み試行
            if self.use_cache {
                if let Some(cached_block) = cache::get_cached_block(self.device_id, block_index) {
                    result.extend_from_slice(&cached_block.read());
                    continue;
                }
            }
            
            // デバイスから直接読み込み
            let block_data = self.read_block_from_device(block_index)?;
            
            // キャッシュに保存
            if self.use_cache {
                let _ = cache::cache_block(self.device_id, block_index, block_data.clone());
            }
            
            result.extend_from_slice(&block_data);
        }
        
        Ok(result)
    }
    
    /// 単一ブロックを書き込み
    pub fn write_block(&self, block_index: u64, data: &[u8]) -> FsResult<()> {
        if data.len() != self.block_size as usize {
            return Err(FsError::InvalidData);
        }
        
        // デバイスに書き込み
        self.write_block_to_device(block_index, data)?;
        
        // キャッシュを更新
        if self.use_cache {
            let _ = cache::cache_block(self.device_id, block_index, data.to_vec());
        }
        
        Ok(())
    }
    
    /// 複数ブロックを書き込み
    pub fn write_blocks(&self, start_block: u64, data: &[u8]) -> FsResult<()> {
        let block_size = self.block_size as usize;
        let total_blocks = (data.len() + block_size - 1) / block_size;
        
        for i in 0..total_blocks {
            let block_index = start_block + (i as u64);
            let start = i * block_size;
            let end = core::cmp::min((i + 1) * block_size, data.len());
            
            // ブロックデータを準備
            let mut block_data = Vec::with_capacity(block_size);
            block_data.extend_from_slice(&data[start..end]);
            
            // ブロックサイズに満たない場合はゼロで埋める
            if block_data.len() < block_size {
                block_data.resize(block_size, 0);
            }
            
            // ブロックを書き込み
            self.write_block(block_index, &block_data)?;
        }
        
        Ok(())
    }
    
    /// デバイスを同期（すべての変更をフラッシュ）
    pub fn sync(&self) -> FsResult<()> {
        // キャッシュからダーティブロックを取得
        let dirty_blocks = {
            let mut dirty = self.dirty_blocks.lock();
            let blocks = dirty.clone();
            dirty.clear();
            blocks
        };

        // ダーティブロックをデバイスに書き出し
        let cache = self.cache.read();
        for block_idx in dirty_blocks {
            if let Some(block_data) = cache.get(&block_idx) {
                // ブロックをデバイスに書き込み
                self.write_block_direct(block_idx, block_data)?;
            }
        }

        // デバイスに応じた同期処理
        let handle = self.handle.read();
        match &*handle {
            DeviceHandle::File(file) => {
                file.flush()?;
            },
            DeviceHandle::Block(block_device) => {
                // ブロックデバイスの同期
                block_device.flush()?;
                
                // ジャーナルの同期（該当する場合）
                if let Some(journal) = block_device.get_journal() {
                    journal.sync()?;
                }
                
                // メタデータの同期
                block_device.sync_metadata()?;
            },
            DeviceHandle::Memory(_) => {
                // メモリデバイスは特別な操作不要
            },
            DeviceHandle::None => {
                return Err(FsError::DeviceError);
            },
        }

        log::debug!("ブロックデバイス {} を同期しました", self.path);
        Ok(())
    }
    
    /// デバイスからブロックを直接読み込み（キャッシュを使用しない）
    fn read_block_from_device(&self, block_index: u64) -> FsResult<Vec<u8>> {
        let handle = self.handle.read();
        
        match &*handle {
            DeviceHandle::Memory(blocks) => {
                // メモリデバイスからの読み込み（テスト用）
                if block_index as usize >= blocks.len() {
                    // 範囲外のブロックはゼロで埋める
                    let mut data = Vec::with_capacity(self.block_size as usize);
                    data.resize(self.block_size as usize, 0);
                    return Ok(data);
                }
                
                Ok(blocks[block_index as usize].clone())
            },
            DeviceHandle::File(file) => {
                // ファイルからの読み込み
                let position = block_index * self.block_size;
                let mut data = Vec::with_capacity(self.block_size as usize);
                data.resize(self.block_size as usize, 0);
                
                // ファイルをシーク
                file.seek(position)?;
                
                // データを読み込み
                let bytes_read = file.read(&mut data)?;
                if bytes_read < self.block_size as usize {
                    // 足りない部分はゼロで埋める
                    data.resize(self.block_size as usize, 0);
                }
                
                Ok(data)
            },
            DeviceHandle::Block(block_device) => {
                // ブロックデバイスからの読み込み
                let mut data = Vec::with_capacity(self.block_size as usize);
                data.resize(self.block_size as usize, 0);
                
                // デバイスからの読み込み
                block_device.read_block(block_index, &mut data)?;
                
                Ok(data)
            },
            DeviceHandle::None => {
                Err(FsError::DeviceError)
            },
        }
    }
    
    /// デバイスにブロックを直接書き込み（キャッシュを使用しない）
    fn write_block_to_device(&self, block_index: u64, data: &[u8]) -> FsResult<()> {
        let mut handle = self.handle.write();
        
        match &mut *handle {
            DeviceHandle::Memory(blocks) => {
                // メモリデバイスへの書き込み（テスト用）
                if block_index as usize >= blocks.len() {
                    // 足りないブロックを追加
                    while block_index as usize >= blocks.len() {
                        let mut empty_block = Vec::with_capacity(self.block_size as usize);
                        empty_block.resize(self.block_size as usize, 0);
                        blocks.push(empty_block);
                    }
                }
                
                blocks[block_index as usize] = data.to_vec();
                Ok(())
            },
            DeviceHandle::File(file) => {
                // ファイルへの書き込み
                let position = block_index * self.block_size;
                
                // ファイルをシーク
                file.seek(position)?;
                
                // データを書き込み
                let bytes_written = file.write(data)?;
                if bytes_written != data.len() {
                    return Err(FsError::IoError);
                }
                
                // 書き込み済みフラグを立てる
                let mut dirty_blocks = self.dirty_blocks.lock();
                dirty_blocks.insert(block_index);
                
                Ok(())
            },
            DeviceHandle::Block(block_device) => {
                // ブロックデバイスへの書き込み
                block_device.write_block(block_index, data)?;
                
                // 書き込み済みフラグを立てる
                let mut dirty_blocks = self.dirty_blocks.lock();
                dirty_blocks.insert(block_index);
                
                Ok(())
            },
            DeviceHandle::None => {
                Err(FsError::DeviceError)
            },
        }
    }
    
    /// ブロックを直接デバイスに書き込む（キャッシュ経由せず）
    fn write_block_direct(&self, block_idx: u64, data: &[u8]) -> FsResult<()> {
        // 実際のデバイス書き込み処理を行う
        let handle = self.handle.read();
        match &*handle {
            DeviceHandle::File(file) => {
                let position = block_idx * self.block_size;
                
                // シークして書き込み
                file.seek(position)?;
                file.write(data)?;
                
                Ok(())
            },
            DeviceHandle::Block(block_device) => {
                block_device.write_block(block_idx, data)
            },
            DeviceHandle::Memory(blocks) => {
                if block_idx as usize >= blocks.len() {
                    return Err(FsError::InvalidData);
                }
                
                // メモリモデルでは直接アクセスできないのでクローンを作成
                let mut blocks_mut = blocks.clone();
                blocks_mut[block_idx as usize] = data.to_vec();
                
                Ok(())
            },
            DeviceHandle::None => {
                Err(FsError::DeviceError)
            },
        }
    }
    
    // メモリデバイスの内容を永続化
    fn persist_memory_device(&self) -> FsResult<()> {
        // メモリデバイスの内容をファイルに保存（必要な場合）
        let handle = self.handle.read();
        
        if let DeviceHandle::Memory(blocks) = &*handle {
            // 保存先のパスを決定
            let persist_path = format!("/var/lib/devices/{}.img", self.device_id);
            
            // ファイルを開く
            let file = crate::fs::open_file(&persist_path, OpenMode::Create)?;
            
            // ブロックデータを書き込む
            for (i, block) in blocks.iter().enumerate() {
                let offset = i as u64 * self.block_size;
                file.seek(offset)?;
                file.write(block)?;
            }
            
            // 変更をフラッシュして閉じる
            file.flush()?;
            file.close()?;
            
            log::info!("メモリデバイス {} の内容を {} に保存しました", self.path, persist_path);
        }
        
        Ok(())
    }
}

/// デバイスパスからデバイスIDを計算
fn calculate_device_id(path: &str) -> u64 {
    // シンプルなハッシュ関数
    let mut id: u64 = 0;
    for byte in path.bytes() {
        id = id.wrapping_mul(31).wrapping_add(byte as u64);
    }
    id
} 