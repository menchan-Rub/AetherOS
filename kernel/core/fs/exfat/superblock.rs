// exFAT スーパーブロック実装
//
// exFATファイルシステムのブートセクタとスーパーブロック構造

use alloc::vec::Vec;
use super::super::{FsError, FsResult};

/// exFATブートセクタのオフセット
const EXFAT_SIGNATURE_OFFSET: usize = 3;
const EXFAT_SIGNATURE: &[u8] = b"EXFAT   ";
const BYTES_PER_SECTOR_OFFSET: usize = 108;
const SECTORS_PER_CLUSTER_OFFSET: usize = 109;
const CLUSTER_HEAP_OFFSET_OFFSET: usize = 88;
const CLUSTER_COUNT_OFFSET: usize = 92;
const FIRST_CLUSTER_OF_ROOT_DIR_OFFSET: usize = 96;
const VOLUME_SERIAL_OFFSET: usize = 100;
const FS_VERSION_OFFSET: usize = 104;
const VOLUME_FLAGS_OFFSET: usize = 106;
const FAT_OFFSET_OFFSET: usize = 80;
const FAT_LENGTH_OFFSET: usize = 84;

/// exFATスーパーブロック（ブートセクタから解析）
#[derive(Debug, Clone)]
pub struct ExfatSuperblock {
    /// セクタあたりのバイト数（通常512）
    pub bytes_per_sector: u16,
    /// クラスタあたりのセクタ数（2のべき乗）
    pub sectors_per_cluster: u8,
    /// クラスタヒープのオフセット（セクタ単位）
    pub cluster_heap_offset: u32,
    /// 総クラスタ数
    pub cluster_count: u32,
    /// ルートディレクトリの最初のクラスタ
    pub first_cluster_of_root_dir: u32,
    /// ボリュームシリアル番号
    pub volume_serial: u32,
    /// ファイルシステムのバージョン
    pub fs_version: u16,
    /// ボリュームフラグ
    pub volume_flags: u16,
    /// FATのオフセット（セクタ単位）
    pub fat_offset: u32,
    /// FATの長さ（セクタ単位）
    pub fat_length: u32,
    /// 生のブートセクタデータ
    pub boot_sector_data: Vec<u8>,
}

impl ExfatSuperblock {
    /// ブートセクタからexFATスーパーブロックをパース
    pub fn parse(data: &[u8]) -> FsResult<Self> {
        if data.len() < 512 {
            return Err(FsError::InvalidData);
        }
        
        // exFATシグネチャを確認
        let signature = &data[EXFAT_SIGNATURE_OFFSET..EXFAT_SIGNATURE_OFFSET + 8];
        if signature != EXFAT_SIGNATURE {
            return Err(FsError::BadMagic);
        }
        
        let bytes_per_sector = u16::from_le_bytes([
            data[BYTES_PER_SECTOR_OFFSET], 
            data[BYTES_PER_SECTOR_OFFSET + 1]
        ]);
        
        let sectors_per_cluster = data[SECTORS_PER_CLUSTER_OFFSET];
        
        let cluster_heap_offset = u32::from_le_bytes([
            data[CLUSTER_HEAP_OFFSET_OFFSET],
            data[CLUSTER_HEAP_OFFSET_OFFSET + 1],
            data[CLUSTER_HEAP_OFFSET_OFFSET + 2],
            data[CLUSTER_HEAP_OFFSET_OFFSET + 3],
        ]);
        
        let cluster_count = u32::from_le_bytes([
            data[CLUSTER_COUNT_OFFSET],
            data[CLUSTER_COUNT_OFFSET + 1],
            data[CLUSTER_COUNT_OFFSET + 2],
            data[CLUSTER_COUNT_OFFSET + 3],
        ]);
        
        let first_cluster_of_root_dir = u32::from_le_bytes([
            data[FIRST_CLUSTER_OF_ROOT_DIR_OFFSET],
            data[FIRST_CLUSTER_OF_ROOT_DIR_OFFSET + 1],
            data[FIRST_CLUSTER_OF_ROOT_DIR_OFFSET + 2],
            data[FIRST_CLUSTER_OF_ROOT_DIR_OFFSET + 3],
        ]);
        
        let volume_serial = u32::from_le_bytes([
            data[VOLUME_SERIAL_OFFSET],
            data[VOLUME_SERIAL_OFFSET + 1],
            data[VOLUME_SERIAL_OFFSET + 2],
            data[VOLUME_SERIAL_OFFSET + 3],
        ]);
        
        let fs_version = u16::from_le_bytes([
            data[FS_VERSION_OFFSET],
            data[FS_VERSION_OFFSET + 1],
        ]);
        
        let volume_flags = u16::from_le_bytes([
            data[VOLUME_FLAGS_OFFSET],
            data[VOLUME_FLAGS_OFFSET + 1],
        ]);
        
        let fat_offset = u32::from_le_bytes([
            data[FAT_OFFSET_OFFSET],
            data[FAT_OFFSET_OFFSET + 1],
            data[FAT_OFFSET_OFFSET + 2],
            data[FAT_OFFSET_OFFSET + 3],
        ]);
        
        let fat_length = u32::from_le_bytes([
            data[FAT_LENGTH_OFFSET],
            data[FAT_LENGTH_OFFSET + 1],
            data[FAT_LENGTH_OFFSET + 2],
            data[FAT_LENGTH_OFFSET + 3],
        ]);
        
        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            cluster_heap_offset,
            cluster_count,
            first_cluster_of_root_dir,
            volume_serial,
            fs_version,
            volume_flags,
            fat_offset,
            fat_length,
            boot_sector_data: data[0..512].to_vec(),
        })
    }
    
    /// 有効なexFATシグネチャを持っているかどうか
    pub fn is_valid_signature(&self) -> bool {
        self.boot_sector_data.len() >= EXFAT_SIGNATURE_OFFSET + 8 &&
        &self.boot_sector_data[EXFAT_SIGNATURE_OFFSET..EXFAT_SIGNATURE_OFFSET + 8] == EXFAT_SIGNATURE
    }
    
    /// クラスタサイズを取得（バイト単位）
    pub fn cluster_size(&self) -> u32 {
        self.bytes_per_sector as u32 * self.sectors_per_cluster as u32
    }
    
    /// 最大ファイルサイズを取得
    pub fn max_file_size(&self) -> u64 {
        0xFFFF_FFFF_FFFF_FFFF // exFATは64ビットファイルサイズをサポート
    }
    
    /// 総容量を取得（バイト単位）
    pub fn total_size(&self) -> u64 {
        self.cluster_count as u64 * self.cluster_size() as u64
    }
    
    /// ボリュームが読み取り専用としてマウントされているかどうか
    pub fn is_read_only(&self) -> bool {
        (self.volume_flags & 0x0001) != 0
    }
    
    /// ボリュームラベルを取得（実装されていない）
    pub fn volume_label(&self) -> &str {
        // ボリュームラベルはディレクトリエントリに保存されているため、
        // この実装ではアクセスできない
        "Unknown"
    }
}

/// 外部公開用の型
pub type ExfatBootSector = ExfatSuperblock; 