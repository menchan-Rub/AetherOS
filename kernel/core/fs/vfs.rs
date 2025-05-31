// 仮想ファイルシステム (VFS) 実装
//
// 様々なファイルシステムを統一したインターフェースで扱うための抽象レイヤー

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use spin::RwLock;
use crate::core::sync::Mutex;
use super::{FsError, FsResult};

/// アイノード番号
pub type InodeNum = u64;

/// ファイルシステムID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FsId(u64);

impl FsId {
    /// 新しいFsIdを生成
    fn new() -> Self {
        static NEXT_FS_ID: AtomicU64 = AtomicU64::new(1);
        Self(NEXT_FS_ID.fetch_add(1, Ordering::SeqCst))
    }
}

/// ブロックデバイスの抽象トレイト
pub trait BlockDevice: Send + Sync {
    /// デバイスID
    fn device_id(&self) -> u64;
    
    /// ブロックサイズ（バイト単位）
    fn block_size(&self) -> u64;
    
    /// 総ブロック数
    fn total_blocks(&self) -> u64;
    
    /// 単一ブロックを読み込み
    fn read_block(&self, block_index: u64) -> FsResult<Vec<u8>>;
    
    /// 複数ブロックを読み込み
    fn read_blocks(&self, start_block: u64, count: u64) -> FsResult<Vec<u8>>;
    
    /// 単一ブロックを書き込み
    fn write_block(&self, block_index: u64, data: &[u8]) -> FsResult<()>;
    
    /// 複数ブロックを書き込み
    fn write_blocks(&self, start_block: u64, data: &[u8]) -> FsResult<()>;
    
    /// デバイスを同期（すべての変更をフラッシュ）
    fn sync(&self) -> FsResult<()>;
    
    /// デバイスを閉じる
    fn close(&self) -> FsResult<()>;
}

/// ファイル/ディレクトリの権限
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions {
    /// 読み取り権限
    pub read: bool,
    /// 書き込み権限
    pub write: bool,
    /// 実行権限
    pub execute: bool,
}

impl Default for Permissions {
    fn default() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
        }
    }
}

/// ファイルタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// 通常ファイル
    Regular,
    /// ディレクトリ
    Directory, 
    /// シンボリックリンク
    SymbolicLink,
    /// デバイスファイル
    BlockDevice,
    /// キャラクタデバイス
    CharDevice,
    /// 名前付きパイプ
    NamedPipe,
    /// Unixソケット
    Socket,
}

/// ファイル/ディレクトリのメタデータ
#[derive(Debug, Clone)]
pub struct Metadata {
    /// アイノード番号
    pub inode: InodeNum,
    /// ファイルタイプ
    pub file_type: FileType,
    /// ファイルサイズ（バイト単位）
    pub size: u64,
    /// 所有者ID
    pub uid: u32,
    /// グループID
    pub gid: u32,
    /// 権限
    pub permissions: Permissions,
    /// 作成時間（UNIXタイムスタンプ）
    pub created: u64,
    /// 最終アクセス時間
    pub accessed: u64,
    /// 最終変更時間
    pub modified: u64,
    /// ハードリンク数
    pub links: u32,
    /// ブロックサイズ
    pub block_size: u32,
    /// ブロック数
    pub blocks: u64,
}

/// ファイルシステム統計情報
#[derive(Debug, Clone)]
pub struct FsStats {
    /// 総ブロック数
    pub total_blocks: u64,
    /// 空きブロック数
    pub free_blocks: u64,
    /// 利用可能ブロック数
    pub available_blocks: u64,
    /// 総ノード数
    pub total_nodes: u64,
    /// 空きノード数
    pub free_nodes: u64,
    /// ブロックサイズ
    pub block_size: u32,
    /// 最大ファイル名長
    pub max_filename_length: u32,
}

/// ファイルオープンモード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// 読み取り専用
    ReadOnly,
    /// 書き込み専用
    WriteOnly,
    /// 読み書き両方
    ReadWrite,
    /// 追記モード
    Append,
    /// 切り詰め（既存ファイルを空にする）
    Truncate,
    /// 作成（存在しない場合）
    Create,
    /// 常に新規作成（既存の場合は上書き）
    CreateNew,
}

/// ディレクトリエントリ
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// エントリ名
    pub name: String,
    /// アイノード番号
    pub inode: InodeNum,
    /// ファイルタイプ
    pub file_type: FileType,
}

/// ファイルハンドルの抽象トレイト
pub trait FileHandle: Send + Sync {
    /// ファイルから読み込み
    fn read(&self, buffer: &mut [u8], offset: u64) -> FsResult<usize>;
    
    /// ファイルに書き込み
    fn write(&self, buffer: &[u8], offset: u64) -> FsResult<usize>;
    
    /// ファイルをフラッシュ（キャッシュを永続ストレージに書き込み）
    fn flush(&self) -> FsResult<()>;
    
    /// ファイルのサイズを取得
    fn size(&self) -> FsResult<u64>;
    
    /// ファイルのサイズを変更
    fn resize(&self, new_size: u64) -> FsResult<()>;
    
    /// ファイルのメタデータを取得
    fn metadata(&self) -> FsResult<Metadata>;
    
    /// ファイルをロック
    fn lock(&self, exclusive: bool) -> FsResult<()>;
    
    /// ファイルのロックを解除
    fn unlock(&self) -> FsResult<()>;
    
    /// ファイルが読み込み可能か
    fn can_read(&self) -> bool;
    
    /// ファイルが書き込み可能か
    fn can_write(&self) -> bool;
}

/// ディレクトリハンドルの抽象トレイト
pub trait DirHandle: Send + Sync {
    /// ディレクトリエントリを読み込み
    fn read_entries(&self) -> FsResult<Vec<DirEntry>>;
    
    /// ディレクトリ内のファイルを検索
    fn lookup(&self, name: &str) -> FsResult<DirEntry>;
    
    /// 新しいファイルを作成
    fn create_file(&self, name: &str, permissions: Permissions) -> FsResult<Arc<dyn FileHandle>>;
    
    /// 新しいディレクトリを作成
    fn create_directory(&self, name: &str, permissions: Permissions) -> FsResult<()>;
    
    /// ファイル/ディレクトリを削除
    fn remove(&self, name: &str) -> FsResult<()>;
    
    /// ファイル/ディレクトリの名前を変更
    fn rename(&self, old_name: &str, new_name: &str) -> FsResult<()>;
    
    /// シンボリックリンクを作成
    fn create_symlink(&self, name: &str, target: &str) -> FsResult<()>;
    
    /// ディレクトリのメタデータを取得
    fn metadata(&self) -> FsResult<Metadata>;
}

/// ファイルシステムドライバの抽象トレイト
pub trait Filesystem: Send + Sync {
    /// ファイルシステムの名前
    fn name(&self) -> &str;
    
    /// ファイルシステムを初期化
    fn init(&self) -> FsResult<()>;
    
    /// ファイルシステムをマウント
    fn mount(&self, device: &str, mount_point: &str, options: &str) -> FsResult<()>;
    
    /// ファイルシステムをアンマウント
    fn unmount(&self, mount_point: &str) -> FsResult<()>;
    
    /// ファイルを開く
    fn open_file(&self, path: &str, mode: OpenMode) -> FsResult<Arc<dyn FileHandle>>;
    
    /// ディレクトリを開く
    fn open_directory(&self, path: &str) -> FsResult<Arc<dyn DirHandle>>;
    
    /// ファイル/ディレクトリのメタデータを取得
    fn metadata(&self, path: &str) -> FsResult<Metadata>;
    
    /// ファイルシステムの統計情報を取得
    fn stats(&self, mount_point: &str) -> FsResult<FsStats>;
    
    /// ファイルシステムをシンク（すべての変更を永続化）
    fn sync(&self) -> FsResult<()>;
    
    /// ファイルシステムをチェック（任意）
    fn check(&self) -> FsResult<bool> {
        Ok(true)
    }
    
    /// ファイルシステムを修復（任意）
    fn repair(&self) -> FsResult<bool> {
        Ok(false)
    }
}

/// マウントポイント情報
#[derive(Debug)]
struct MountPoint {
    /// マウントされたファイルシステム
    fs: Arc<dyn Filesystem>,
    /// デバイスパス
    device: String,
    /// マウントポイントパス
    path: String,
    /// マウントオプション
    options: String,
}

/// ファイルシステムレジストリ
struct FilesystemRegistry {
    /// 登録されたファイルシステムドライバ
    filesystems: BTreeMap<String, Arc<dyn Filesystem>>,
    /// マウントポイント
    mount_points: Vec<MountPoint>,
}

impl FilesystemRegistry {
    /// 新しいレジストリを作成
    fn new() -> Self {
        Self {
            filesystems: BTreeMap::new(),
            mount_points: Vec::new(),
        }
    }
    
    /// ファイルシステムを登録
    fn register(&mut self, name: &str, fs: Arc<dyn Filesystem>) -> FsResult<()> {
        if self.filesystems.contains_key(name) {
            return Err(FsError::AlreadyExists);
        }
        
        self.filesystems.insert(name.to_string(), fs);
        Ok(())
    }
    
    /// ファイルシステムをマウント
    fn mount(&mut self, fs_type: &str, device: &str, mount_point: &str, options: &str) -> FsResult<()> {
        let fs = self.filesystems.get(fs_type)
            .ok_or(FsError::NotFound)?
            .clone();
        
        fs.mount(device, mount_point, options)?;
        
        self.mount_points.push(MountPoint {
            fs,
            device: device.to_string(),
            path: mount_point.to_string(),
            options: options.to_string(),
        });
        
        Ok(())
    }
    
    /// ファイルシステムをアンマウント
    fn unmount(&mut self, mount_point: &str) -> FsResult<()> {
        let idx = self.mount_points.iter()
            .position(|mp| mp.path == mount_point)
            .ok_or(FsError::NotFound)?;
        
        let mp = &self.mount_points[idx];
        mp.fs.unmount(mount_point)?;
        
        self.mount_points.remove(idx);
        Ok(())
    }
    
    /// パスに対応するマウントポイントを検索
    fn find_mount_point(&self, path: &str) -> Option<&MountPoint> {
        self.mount_points.iter()
            .filter(|mp| path.starts_with(&mp.path))
            .max_by_key(|mp| mp.path.len())
    }
}

/// グローバルファイルシステムレジストリ
static FS_REGISTRY: Mutex<Option<FilesystemRegistry>> = Mutex::new(None);

/// 仮想ファイルシステムを初期化
pub fn init() -> FsResult<()> {
    let mut registry = FS_REGISTRY.lock();
    *registry = Some(FilesystemRegistry::new());
    Ok(())
}

/// ファイルシステムドライバを登録
pub fn register_filesystem(name: &str, fs: impl Filesystem + 'static) -> FsResult<()> {
    let mut registry = FS_REGISTRY.lock();
    
    if let Some(reg) = registry.as_mut() {
        reg.register(name, Arc::new(fs))
    } else {
        Err(FsError::NotSupported)
    }
}

/// ファイルシステムをマウント
pub fn mount(fs_type: &str, device: &str, mount_point: &str, options: &str) -> FsResult<()> {
    let mut registry = FS_REGISTRY.lock();
    
    if let Some(reg) = registry.as_mut() {
        reg.mount(fs_type, device, mount_point, options)
    } else {
        Err(FsError::NotSupported)
    }
}

/// ファイルシステムをアンマウント
pub fn unmount(mount_point: &str) -> FsResult<()> {
    let mut registry = FS_REGISTRY.lock();
    
    if let Some(reg) = registry.as_mut() {
        reg.unmount(mount_point)
    } else {
        Err(FsError::NotSupported)
    }
}

/// パスを正規化
fn normalize_path(path: &str) -> String {
    // パスを絶対パスに変換
    let mut normalized = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };
    
    // 末尾のスラッシュを削除
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    
    normalized
}

/// ファイルを開く
pub fn open_file(path: &str, mode: OpenMode) -> FsResult<Arc<dyn FileHandle>> {
    let registry = FS_REGISTRY.lock();
    
    if let Some(reg) = registry.as_ref() {
        let normalized_path = normalize_path(path);
        let mp = reg.find_mount_point(&normalized_path)
            .ok_or(FsError::NotFound)?;
        
        // マウントポイントのプレフィックスを削除してファイルシステム内の相対パスを取得
        let rel_path = normalized_path.strip_prefix(&mp.path)
            .unwrap_or(&normalized_path);
        
        // スラッシュで始まるようにする
        let rel_path = if rel_path.starts_with('/') {
            rel_path.to_string()
        } else {
            format!("/{}", rel_path)
        };
        
        mp.fs.open_file(&rel_path, mode)
    } else {
        Err(FsError::NotSupported)
    }
}

/// ディレクトリを開く
pub fn open_directory(path: &str) -> FsResult<Arc<dyn DirHandle>> {
    let registry = FS_REGISTRY.lock();
    
    if let Some(reg) = registry.as_ref() {
        let normalized_path = normalize_path(path);
        let mp = reg.find_mount_point(&normalized_path)
            .ok_or(FsError::NotFound)?;
        
        // マウントポイントのプレフィックスを削除
        let rel_path = normalized_path.strip_prefix(&mp.path)
            .unwrap_or(&normalized_path);
        
        // スラッシュで始まるようにする
        let rel_path = if rel_path.starts_with('/') {
            rel_path.to_string()
        } else {
            format!("/{}", rel_path)
        };
        
        mp.fs.open_directory(&rel_path)
    } else {
        Err(FsError::NotSupported)
    }
}

/// ファイル/ディレクトリのメタデータを取得
pub fn metadata(path: &str) -> FsResult<Metadata> {
    let registry = FS_REGISTRY.lock();
    
    if let Some(reg) = registry.as_ref() {
        let normalized_path = normalize_path(path);
        let mp = reg.find_mount_point(&normalized_path)
            .ok_or(FsError::NotFound)?;
        
        // マウントポイントのプレフィックスを削除
        let rel_path = normalized_path.strip_prefix(&mp.path)
            .unwrap_or(&normalized_path);
        
        // スラッシュで始まるようにする
        let rel_path = if rel_path.starts_with('/') {
            rel_path.to_string()
        } else {
            format!("/{}", rel_path)
        };
        
        mp.fs.metadata(&rel_path)
    } else {
        Err(FsError::NotSupported)
    }
}

/// すべてのファイルシステムを同期
pub fn sync_all() -> FsResult<()> {
    let registry = FS_REGISTRY.lock();
    
    if let Some(reg) = registry.as_ref() {
        for mp in &reg.mount_points {
            // エラーが発生してもすべてのファイルシステムを同期試行
            let _ = mp.fs.sync();
        }
        Ok(())
    } else {
        Err(FsError::NotSupported)
    }
}

/// ブロックデバイスを開く
pub fn open_block_device(path: &str) -> FsResult<Arc<dyn BlockDevice>> {
    // デバイスパスからデバイスドライバを決定
    fn get_device_driver(device_path: &str) -> FsResult<Arc<dyn DeviceDriver>> {
        // デバイスのパスからタイプを判断
        if device_path.starts_with("/dev/sd") {
            // SCSIディスク
            return scsi::get_driver(device_path);
        } else if device_path.starts_with("/dev/hd") {
            // IDEディスク
            return ide::get_driver(device_path);
        } else if device_path.starts_with("/dev/nvme") {
            // NVMeディスク
            return nvme::get_driver(device_path);
        } else if device_path.starts_with("/dev/mmcblk") {
            // eMMC/SDカード
            return mmc::get_driver(device_path);
        } else if device_path.starts_with("/dev/loop") {
            // ループデバイス
            return loopdev::get_driver(device_path);
        } else if device_path.starts_with("/dev/ram") {
            // RAMディスク
            return ramdisk::get_driver(device_path);
        } else {
            // その他のデバイス：ジェネリックブロックドライバを使用
            return generic::get_driver(device_path);
        }
    }
    
    // デバイスパスからデバイスファイルを開く
    match crate::fs::devfs::open_device(path) {
        Ok(handle) => {
            let device_id = calculate_device_id(path);
            let device_info = handle.get_device_info()?;
            
            Ok(Arc::new(Self {
                path: path.to_string(),
                device_id,
                block_size: device_info.block_size,
                total_blocks: device_info.total_blocks,
            }))
        },
        Err(_) => {
            // 通常のファイルとして開く
            let file = crate::fs::open_file(path, OpenMode::ReadWrite)?;
            let size = file.size()?;
            let block_size = 512; // デフォルトブロックサイズ
            let total_blocks = (size + block_size - 1) / block_size;
            
            Ok(Arc::new(Self {
                path: path.to_string(),
                device_id: calculate_device_id(path),
                block_size,
                total_blocks,
            }))
        }
    }
}

/// ファイルベースのブロックデバイス実装
struct FileBlockDevice {
    path: String,
    device_id: u64,
    block_size: u64,
    total_blocks: u64,
}

impl FileBlockDevice {
    /// ファイルベースのブロックデバイスを開く
    fn open(path: &str) -> FsResult<Self> {
        // 実際のファイルを開く
        let fs_type = identify_filesystem(path)?;
        
        // ファイルシステム固有のオープン処理
        let mut file = match fs_type {
            FilesystemType::Ext4 => {
                crate::fs::ext4::open_file(path, OpenMode::ReadOnly)?
            },
            FilesystemType::ExFat => {
                crate::fs::exfat::open_file(path, OpenMode::ReadOnly)?
            },
            FilesystemType::Ntfs => {
                crate::fs::ntfs::open_file(path, OpenMode::ReadOnly)?
            },
            FilesystemType::Fat32 => {
                crate::fs::fat32::open_file(path, OpenMode::ReadOnly)?
            },
            // その他のファイルシステムタイプに対応
            _ => return Err(FsError::UnsupportedFilesystem),
        };
        
        // ファイルのメタデータを取得
        let metadata = file.metadata()?;
        let size = metadata.size;
        
        Ok(Self {
            path: path.to_string(),
            size,
            current_position: 0,
            is_open: true,
        })
    }
}

impl BlockDevice for FileBlockDevice {
    fn device_id(&self) -> u64 {
        self.device_id
    }
    
    fn block_size(&self) -> u64 {
        self.block_size
    }
    
    fn total_blocks(&self) -> u64 {
        self.total_blocks
    }
    
    fn read_block(&self, block_index: u64) -> FsResult<Vec<u8>> {
        let offset = block_index * self.block_size;
        let buffer_size = self.block_size as usize;

        match crate::fs::devfs::open_device(&self.path) {
            Ok(device) => {
                // デバイスから直接読み込み
                let mut buffer = vec![0; buffer_size];
                let bytes_read = device.read(&mut buffer, offset)?;
                
                if bytes_read < buffer_size {
                    // パディング
                    buffer.resize(buffer_size, 0);
                }
                
                Ok(buffer)
            },
            Err(_) => {
                // 通常のファイルとして読み込み
                let file = crate::fs::open_file(&self.path, OpenMode::ReadOnly)?;
                let mut buffer = vec![0; buffer_size];
                let bytes_read = file.read(&mut buffer, offset)?;
                
                if bytes_read < buffer_size {
                    // パディング
                    buffer.resize(buffer_size, 0);
                }
                
                Ok(buffer)
            }
        }
    }
    
    fn read_blocks(&self, start_block: u64, count: u64) -> FsResult<Vec<u8>> {
        // 現在は単純な実装として、各ブロックを個別に読み込む
        let mut result = Vec::with_capacity((self.block_size as usize) * (count as usize));
        
        for i in 0..count {
            let block_data = self.read_block(start_block + i)?;
            result.extend_from_slice(&block_data);
        }
        
        Ok(result)
    }
    
    fn write_block(&self, block_index: u64, data: &[u8]) -> FsResult<()> {
        let offset = block_index * self.block_size;

        match crate::fs::devfs::open_device(&self.path) {
            Ok(device) => {
                // デバイスに直接書き込み
                let bytes_written = device.write(data, offset)?;
                
                if bytes_written < data.len() {
                    return Err(FsError::IoError);
                }
                
                Ok(())
            },
            Err(_) => {
                // 通常のファイルとして書き込み
                let file = crate::fs::open_file(&self.path, OpenMode::ReadWrite)?;
                let bytes_written = file.write(data, offset)?;
                
                if bytes_written < data.len() {
                    return Err(FsError::IoError);
                }
                
                Ok(())
            }
        }
    }
    
    fn write_blocks(&self, start_block: u64, data: &[u8]) -> FsResult<()> {
        // 現在は単純な実装として、各ブロックを個別に書き込む
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
            
            self.write_block(block_index, &block_data)?;
        }
        
        Ok(())
    }
    
    fn sync(&self) -> FsResult<()> {
        // デバイスに応じた同期処理を実行
        if let Ok(device) = crate::fs::devfs::open_device(&self.path) {
            // デバイスを同期
            device.sync()?;
            return Ok(());
        }

        // 通常のファイルの場合
        match identify_filesystem(&self.path)? {
            FilesystemType::Ext4 => crate::fs::ext4::sync_file(&self.path),
            FilesystemType::ExFat => crate::fs::exfat::sync_file(&self.path),
            FilesystemType::Ntfs => crate::fs::ntfs::sync_file(&self.path),
            FilesystemType::Fat32 => crate::fs::fat32::sync_file(&self.path),
            _ => {
                // ジャーナルがある場合は同期
                if crate::fs::journal::has_journal(&self.path) {
                    crate::fs::journal::sync()?;
                }
                
                // キャッシュバッファをフラッシュ
                crate::fs::cache::flush_file(&self.path)?;
                
                Ok(())
            }
        }
    }
    
    fn close(&self) -> FsResult<()> {
        // ファイルシステムタイプを特定
        let fs_type = identify_filesystem(&self.path)?;
        
        // 変更があればデータをフラッシュ
        self.sync()?;
        
        // ファイルシステム固有のクローズ処理
        match fs_type {
            FilesystemType::Ext4 => crate::fs::ext4::close_file(&self.path),
            FilesystemType::ExFat => crate::fs::exfat::close_file(&self.path),
            FilesystemType::Ntfs => crate::fs::ntfs::close_file(&self.path),
            FilesystemType::Fat32 => crate::fs::fat32::close_file(&self.path),
            _ => {
                // 汎用的なクローズ処理
                // リソース解放と関連するキャッシュのクリア
                crate::fs::cache::invalidate_file(&self.path)?;
                Ok(())
            }
        }
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