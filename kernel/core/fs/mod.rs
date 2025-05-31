// AetherOS ファイルシステムモジュール
//
// 世界最高性能・最高信頼性のファイルシステム実装

mod vfs;         // 仮想ファイルシステム
mod fat32;       // FAT32ファイルシステム
mod btrfs;       // Btrfsファイルシステム
mod exfat;       // exFATファイルシステム
mod ntfs;        // NTFSファイルシステム
mod xfs;         // XFSファイルシステム
mod zfs;         // ZFSファイルシステム
mod f2fs;        // F2FSファイルシステム
mod apfs;        // APFSファイルシステム
mod hfs;         // HFS+ファイルシステム
mod iso9660;     // ISO9660ファイルシステム（CD-ROM）
mod udf;         // UDFファイルシステム（DVD）
mod minix;       // Minixファイルシステム
mod cache;       // 高速ファイルシステムキャッシュ
mod journal;     // 最適化ジャーナリング
mod transaction; // 原子的トランザクション処理

pub use self::vfs::*;
pub use self::cache::*;
pub use self::journal::*;
pub use self::transaction::*;

// ファイルシステム固有の実装をエクスポート
pub mod implementations {
    pub use super::fat32::*;
    pub use super::btrfs::*;
    pub use super::exfat::*;
    pub use super::ntfs::*;
    pub use super::xfs::*;
    pub use super::zfs::*;
    pub use super::f2fs::*;
    pub use super::apfs::*;
    pub use super::hfs::*;
    pub use super::iso9660::*;
    pub use super::udf::*;
    pub use super::minix::*;
}

// エラー定義
#[derive(Debug)]
pub enum FsError {
    NotFound,
    PermissionDenied,
    InvalidData,
    AlreadyExists,
    NotDirectory,
    IsDirectory,
    NotEmpty,
    ReadOnly,
    DeviceError,
    IoError,
    CorruptedFs,
    OutOfSpace,
    TransactionFailed,
    JournalError,
    NotSupported,
    FilesystemCorrupted,
    BadSuperblock,
    UnsupportedFeature,
    UnsupportedVersion,
    IncompatibleFeatures,
    BadMagic,
    ResourceBusy,              // ビジーリソース
    Deadlock,                  // デッドロック検出
    CrossDeviceLink,           // デバイス間リンク
    StaleFileHandle,           // 無効なファイルハンドル
    OverflowError,             // オーバーフローエラー
    NetworkError,              // ネットワークエラー
    ProtocolError,             // プロトコルエラー
    Timeout,                   // タイムアウト
    CacheInconsistency,        // キャッシュ不整合
    MetadataError,             // メタデータエラー
    Other(&'static str),
}

pub type FsResult<T> = Result<T, FsError>;

// ファイルシステム初期化
pub fn init() -> FsResult<()> {
    // 高性能キャッシュシステムを初期化
    cache::init_with_options(true, 65536, 4096)?;
    
    // 先進的ジャーナリングシステムを初期化
    journal::init_with_options(true, 8192)?;
    
    // VFSを高度なオプションで初期化
    vfs::init_with_options(true, true, 1024)?;
    
    // 標準のファイルシステムドライバを登録（最適化順）
    vfs::register_filesystem("ext4", ext4::Ext4Filesystem::new_optimized(true, 1024))?;
    vfs::register_filesystem("ext3", ext4::Ext4Filesystem::new_optimized(false, 512))?;
    vfs::register_filesystem("ext2", ext4::Ext4Filesystem::new_optimized(false, 256))?;
    vfs::register_filesystem("btrfs", btrfs::BtrfsFilesystem::new_optimized(true))?;
    vfs::register_filesystem("xfs", xfs::XfsFilesystem::new_optimized())?;
    vfs::register_filesystem("zfs", zfs::ZfsFilesystem::new_with_compression(true))?;
    vfs::register_filesystem("f2fs", f2fs::F2fsFilesystem::new_optimized())?;
    
    // Windowsとの互換性用ファイルシステム
    vfs::register_filesystem("ntfs", ntfs::NtfsFilesystem::new_with_options(true, true))?;
    vfs::register_filesystem("exfat", exfat::ExfatFilesystem::new_with_options(true, true))?;
    vfs::register_filesystem("fat32", fat32::Fat32Filesystem::new_with_options(true))?;
    vfs::register_filesystem("fat16", fat32::Fat16Filesystem::new_with_options(true))?;
    vfs::register_filesystem("fat12", fat32::Fat12Filesystem::new_with_options(true))?;
    vfs::register_filesystem("vfat", fat32::VfatFilesystem::new_with_options(true))?;
    
    // macOSとの互換性用ファイルシステム
    vfs::register_filesystem("apfs", apfs::ApfsFilesystem::new_with_encryption(true))?;
    vfs::register_filesystem("hfs", hfs::HfsFilesystem::new_optimized())?;
    vfs::register_filesystem("hfsplus", hfs::HfsPlusFilesystem::new_optimized())?;
    
    // 光学メディア向けファイルシステム
    vfs::register_filesystem("iso9660", iso9660::Iso9660Filesystem::new_with_joliet(true))?;
    vfs::register_filesystem("udf", udf::UdfFilesystem::new_optimized())?;
    
    // 歴史的・特殊用途向けファイルシステム
    vfs::register_filesystem("minix", minix::MinixFilesystem::new_optimized())?;
    
    log::info!("世界最高性能ファイルシステムモジュール初期化完了");
    
    Ok(())
} 