// NTFS ファイルシステム実装
//
// Microsoft NTFSファイルシステムの実装

mod superblock;
mod record;
mod attribute;
mod bitmap;
mod index;
mod security;
mod compression;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use spin::RwLock;
use super::{FsError, FsResult, FileType, Metadata, FsStats, Permissions, FileHandle, DirHandle, OpenMode, Filesystem};
use self::superblock::NtfsSuperblock;

/// NTFSファイルシステム
pub struct NtfsFilesystem {
    /// ファイルシステム名
    name: String,
    /// マウントされたデバイス
    devices: RwLock<BTreeMap<String, Arc<dyn super::vfs::BlockDevice>>>,
    /// スーパーブロックキャッシュ
    superblocks: RwLock<BTreeMap<String, NtfsSuperblock>>,
}

impl NtfsFilesystem {
    /// 新しいNTFSファイルシステムインスタンスを作成
    pub fn new() -> Self {
        Self {
            name: "ntfs".to_string(),
            devices: RwLock::new(BTreeMap::new()),
            superblocks: RwLock::new(BTreeMap::new()),
        }
    }
    
    /// スーパーブロックを読み込み
    fn read_superblock(&self, device: &dyn super::vfs::BlockDevice) -> FsResult<NtfsSuperblock> {
        // NTFSのブートセクタを読み込み
        let data = device.read_block(0)?;
        NtfsSuperblock::parse(&data)
    }
    
    /// パスを解析
    fn parse_path(&self, path: &str) -> FsResult<PathInfo> {
        // パスを解析して構造化
        let clean_path = path.trim().trim_matches('/');
        
        // ルートディレクトリの場合
        if clean_path.is_empty() {
            return Ok(PathInfo {
                path: "/".to_string(),
                parent: "/".to_string(),
                name: "".to_string(),
                is_root: true,
            });
        }
        
        // 最後のコンポーネントを取得
        let components: Vec<&str> = clean_path.split('/').collect();
        let name = components.last().unwrap_or(&"").to_string();
        
        // 親パスを取得
        let parent = if components.len() > 1 {
            components[..components.len() - 1].join("/")
        } else {
            "/".to_string()
        };
        
        Ok(PathInfo {
            path: format!("/{}", clean_path),
            parent,
            name,
            is_root: false,
        })
    }
    
    /// パスからデバイスを検索
    fn find_device_for_path(&self, path: &str) -> FsResult<String> {
        // マウントポイントからデバイスを検索
        let devices = self.devices.read();
        
        // 最長一致するマウントポイントを検索
        let mut best_match = "";
        let mut best_device = "";
        
        for (device_path, _) in devices.iter() {
            // マウントポイントのパスを取得（実際のシステムでは別のマッピングテーブルから取得）
            let mount_point = self.get_mount_point_for_device(device_path);
            
            // パスがマウントポイントから始まり、かつ今までの最長一致より長い場合
            if path.starts_with(&mount_point) && mount_point.len() > best_match.len() {
                best_match = &mount_point;
                best_device = device_path;
            }
        }
        
        if !best_device.is_empty() {
            return Ok(best_device.to_string());
        }
        
        // マウントポイントが見つからない場合、デフォルトのデバイスを返す
        if let Some((device_path, _)) = devices.iter().next() {
            return Ok(device_path.clone());
        }
        
        Err(FsError::NotFound)
    }
    
    /// デバイスパスからマウントポイントを取得
    fn get_mount_point_for_device(&self, device_path: &str) -> String {
        // 本来はVFSからのマッピングを使用
        // この実装ではシンプルにデバイスパスをそのまま返す
        device_path.to_string()
    }
}

/// パス情報
struct PathInfo {
    /// 完全パス
    path: String,
    /// 親ディレクトリのパス
    parent: String,
    /// ファイル名/ディレクトリ名
    name: String,
    /// ルートディレクトリかどうか
    is_root: bool,
}

impl Filesystem for NtfsFilesystem {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn init(&self) -> FsResult<()> {
        Ok(())
    }
    
    fn mount(&self, device: &str, mount_point: &str, options: &str) -> FsResult<()> {
        // デバイスが既にマウントされているかチェック
        {
            let devices = self.devices.read();
            if devices.contains_key(device) {
                return Err(FsError::AlreadyExists);
            }
        }
        
        // ブロックデバイスをオープン
        let block_device = super::vfs::open_block_device(device)?;
        
        // スーパーブロックを読み込み
        let superblock = self.read_superblock(&*block_device)?;
        
        // NTFSシグネチャをチェック
        if !superblock.is_valid_signature() {
            return Err(FsError::BadMagic);
        }
        
        // キャッシュに保存
        {
            let mut devices = self.devices.write();
            devices.insert(device.to_string(), block_device);
            
            let mut superblocks = self.superblocks.write();
            superblocks.insert(device.to_string(), superblock);
        }
        
        log::info!("NTFSファイルシステムをマウント: {} -> {}", device, mount_point);
        
        Ok(())
    }
    
    fn unmount(&self, mount_point: &str) -> FsResult<()> {
        // マウントポイントのデバイスを取得
        let devices = self.devices.read();
        let device = devices.get(mount_point).ok_or(FsError::NotFound)?;

        // キャッシュをフラッシュ
        device.flush_cache()?;

        // デバイスを同期
        device.sync()?;

        // マウント済みデバイスから削除
        drop(devices);
        let mut devices = self.devices.write();
        devices.remove(mount_point);

        // スーパーブロックキャッシュから削除
        let mut superblocks = self.superblocks.write();
        superblocks.remove(mount_point);

        log::info!("NTFSファイルシステムをアンマウント: {}", mount_point);
        Ok(())
    }
    
    fn open_file(&self, path: &str, mode: OpenMode) -> FsResult<Arc<dyn FileHandle>> {
        // パスを解析
        let parsed_path = self.parse_path(path)?;
        
        // デバイスを検索
        let device_path = self.find_device_for_path(path)?;
        let devices = self.devices.read();
        let device = devices.get(&device_path).ok_or(FsError::NotFound)?;
        
        // スーパーブロックを取得
        let superblocks = self.superblocks.read();
        let superblock = superblocks.get(&device_path).ok_or(FsError::NotFound)?;
        
        // MFTを検索してファイルレコードを取得
        let mft = superblock.get_mft_record(device.as_ref())?;
        let file_record = mft.find_file_by_path(&parsed_path.path, device.as_ref())?;
        
        // ファイルハンドルを作成
        let file_handle = self::record::NtfsFileHandle::new(
            file_record,
            device.clone(),
            superblock.clone(),
            mode
        )?;
        
        Ok(Arc::new(file_handle))
    }
    
    fn open_directory(&self, path: &str) -> FsResult<Arc<dyn DirHandle>> {
        // パスを解析
        let parsed_path = self.parse_path(path)?;
        
        // デバイスを検索
        let device_path = self.find_device_for_path(path)?;
        let devices = self.devices.read();
        let device = devices.get(&device_path).ok_or(FsError::NotFound)?;
        
        // スーパーブロックを取得
        let superblocks = self.superblocks.read();
        let superblock = superblocks.get(&device_path).ok_or(FsError::NotFound)?;
        
        // MFTを検索してディレクトリレコードを取得
        let mft = superblock.get_mft_record(device.as_ref())?;
        let dir_record = mft.find_file_by_path(&parsed_path.path, device.as_ref())?;
        
        // ディレクトリであるかチェック
        if !dir_record.is_directory() {
            return Err(FsError::NotADirectory);
        }
        
        // ディレクトリハンドルを作成
        let dir_handle = self::record::NtfsDirHandle::new(
            dir_record,
            device.clone(),
            superblock.clone()
        )?;
        
        Ok(Arc::new(dir_handle))
    }
    
    fn metadata(&self, path: &str) -> FsResult<Metadata> {
        // パスを解析
        let parsed_path = self.parse_path(path)?;
        
        // デバイスを検索
        let device_path = self.find_device_for_path(path)?;
        let devices = self.devices.read();
        let device = devices.get(&device_path).ok_or(FsError::NotFound)?;
        
        // スーパーブロックを取得
        let superblocks = self.superblocks.read();
        let superblock = superblocks.get(&device_path).ok_or(FsError::NotFound)?;
        
        // MFTを検索してファイルレコードを取得
        let mft = superblock.get_mft_record(device.as_ref())?;
        let file_record = mft.find_file_by_path(&parsed_path.path, device.as_ref())?;
        
        // メタデータを取得
        let metadata = file_record.get_metadata()?;
        
        Ok(metadata)
    }
    
    fn stats(&self, mount_point: &str) -> FsResult<FsStats> {
        // デバイスを検索
        let devices = self.devices.read();
        let device = devices.get(mount_point).ok_or(FsError::NotFound)?;
        
        // スーパーブロックを取得
        let superblocks = self.superblocks.read();
        let superblock = superblocks.get(mount_point).ok_or(FsError::NotFound)?;
        
        // ボリューム情報を取得
        let volume_info = superblock.get_volume_info(device.as_ref())?;
        
        // ファイルシステム統計を作成
        let stats = FsStats {
            total_blocks: volume_info.total_sectors,
            free_blocks: volume_info.free_sectors,
            available_blocks: volume_info.free_sectors,
            total_nodes: volume_info.total_mft_records,
            free_nodes: volume_info.free_mft_records,
            block_size: superblock.bytes_per_sector() as u32,
            max_filename_length: 255, // NTFS supports up to 255 characters
        };
        
        Ok(stats)
    }
    
    fn sync(&self) -> FsResult<()> {
        // すべてのデバイスを同期
        let devices = self.devices.read();
        for (_, device) in devices.iter() {
            device.sync()?;
        }
        
        Ok(())
    }
} 