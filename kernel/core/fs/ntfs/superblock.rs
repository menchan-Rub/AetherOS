// NTFS スーパーブロック実装
//
// NTFSファイルシステムのブートセクタとパラメータ

use alloc::vec::Vec;
use super::super::{FsError, FsResult};

/// NTFSブートセクタのオフセット
const NTFS_SIGNATURE_OFFSET: usize = 3;
const NTFS_SIGNATURE: &[u8] = b"NTFS    ";
const BYTES_PER_SECTOR_OFFSET: usize = 0x0B;
const SECTORS_PER_CLUSTER_OFFSET: usize = 0x0D;
const MEDIA_DESCRIPTOR_OFFSET: usize = 0x15;
const SECTORS_PER_TRACK_OFFSET: usize = 0x18;
const NUMBER_OF_HEADS_OFFSET: usize = 0x1A;
const HIDDEN_SECTORS_OFFSET: usize = 0x1C;
const TOTAL_SECTORS_OFFSET: usize = 0x28;
const MFT_CLUSTER_OFFSET: usize = 0x30;
const MFT_MIRROR_CLUSTER_OFFSET: usize = 0x38;
const CLUSTERS_PER_MFT_RECORD_OFFSET: usize = 0x40;
const CLUSTERS_PER_INDEX_BUFFER_OFFSET: usize = 0x44;
const VOLUME_SERIAL_OFFSET: usize = 0x48;

/// NTFSスーパーブロック
#[derive(Debug, Clone)]
pub struct NtfsSuperblock {
    /// セクタあたりのバイト数
    pub bytes_per_sector: u16,
    /// クラスタあたりのセクタ数
    pub sectors_per_cluster: u8,
    /// メディア記述子
    pub media_descriptor: u8,
    /// トラックあたりのセクタ数
    pub sectors_per_track: u16,
    /// ヘッド数
    pub number_of_heads: u16,
    /// 隠しセクタ数
    pub hidden_sectors: u32,
    /// 総セクタ数
    pub total_sectors: u64,
    /// MFT開始クラスタ
    pub mft_cluster: u64,
    /// MFTミラー開始クラスタ
    pub mft_mirror_cluster: u64,
    /// MFTレコードあたりのクラスタ数（負の場合はバイト数を2の累乗で表現）
    pub clusters_per_mft_record: i8,
    /// インデックスバッファあたりのクラスタ数（負の場合はバイト数を2の累乗で表現）
    pub clusters_per_index_buffer: i8,
    /// ボリュームシリアル番号
    pub volume_serial: u64,
    /// 生のブートセクタデータ
    pub boot_sector_data: Vec<u8>,
}

impl NtfsSuperblock {
    /// ブートセクタからNTFSスーパーブロックをパース
    pub fn parse(data: &[u8]) -> FsResult<Self> {
        if data.len() < 512 {
            return Err(FsError::InvalidData);
        }
        
        // NTFSシグネチャをチェック
        let signature = &data[NTFS_SIGNATURE_OFFSET..NTFS_SIGNATURE_OFFSET + 8];
        if signature != NTFS_SIGNATURE {
            return Err(FsError::BadMagic);
        }
        
        let bytes_per_sector = u16::from_le_bytes([
            data[BYTES_PER_SECTOR_OFFSET],
            data[BYTES_PER_SECTOR_OFFSET + 1],
        ]);
        
        let sectors_per_cluster = data[SECTORS_PER_CLUSTER_OFFSET];
        let media_descriptor = data[MEDIA_DESCRIPTOR_OFFSET];
        
        let sectors_per_track = u16::from_le_bytes([
            data[SECTORS_PER_TRACK_OFFSET],
            data[SECTORS_PER_TRACK_OFFSET + 1],
        ]);
        
        let number_of_heads = u16::from_le_bytes([
            data[NUMBER_OF_HEADS_OFFSET],
            data[NUMBER_OF_HEADS_OFFSET + 1],
        ]);
        
        let hidden_sectors = u32::from_le_bytes([
            data[HIDDEN_SECTORS_OFFSET],
            data[HIDDEN_SECTORS_OFFSET + 1],
            data[HIDDEN_SECTORS_OFFSET + 2],
            data[HIDDEN_SECTORS_OFFSET + 3],
        ]);
        
        let total_sectors = u64::from_le_bytes([
            data[TOTAL_SECTORS_OFFSET],
            data[TOTAL_SECTORS_OFFSET + 1],
            data[TOTAL_SECTORS_OFFSET + 2],
            data[TOTAL_SECTORS_OFFSET + 3],
            data[TOTAL_SECTORS_OFFSET + 4],
            data[TOTAL_SECTORS_OFFSET + 5],
            data[TOTAL_SECTORS_OFFSET + 6],
            data[TOTAL_SECTORS_OFFSET + 7],
        ]);
        
        let mft_cluster = u64::from_le_bytes([
            data[MFT_CLUSTER_OFFSET],
            data[MFT_CLUSTER_OFFSET + 1],
            data[MFT_CLUSTER_OFFSET + 2],
            data[MFT_CLUSTER_OFFSET + 3],
            data[MFT_CLUSTER_OFFSET + 4],
            data[MFT_CLUSTER_OFFSET + 5],
            data[MFT_CLUSTER_OFFSET + 6],
            data[MFT_CLUSTER_OFFSET + 7],
        ]);
        
        let mft_mirror_cluster = u64::from_le_bytes([
            data[MFT_MIRROR_CLUSTER_OFFSET],
            data[MFT_MIRROR_CLUSTER_OFFSET + 1],
            data[MFT_MIRROR_CLUSTER_OFFSET + 2],
            data[MFT_MIRROR_CLUSTER_OFFSET + 3],
            data[MFT_MIRROR_CLUSTER_OFFSET + 4],
            data[MFT_MIRROR_CLUSTER_OFFSET + 5],
            data[MFT_MIRROR_CLUSTER_OFFSET + 6],
            data[MFT_MIRROR_CLUSTER_OFFSET + 7],
        ]);
        
        let clusters_per_mft_record = data[CLUSTERS_PER_MFT_RECORD_OFFSET] as i8;
        let clusters_per_index_buffer = data[CLUSTERS_PER_INDEX_BUFFER_OFFSET] as i8;
        
        let volume_serial = u64::from_le_bytes([
            data[VOLUME_SERIAL_OFFSET],
            data[VOLUME_SERIAL_OFFSET + 1],
            data[VOLUME_SERIAL_OFFSET + 2],
            data[VOLUME_SERIAL_OFFSET + 3],
            data[VOLUME_SERIAL_OFFSET + 4],
            data[VOLUME_SERIAL_OFFSET + 5],
            data[VOLUME_SERIAL_OFFSET + 6],
            data[VOLUME_SERIAL_OFFSET + 7],
        ]);
        
        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            media_descriptor,
            sectors_per_track,
            number_of_heads,
            hidden_sectors,
            total_sectors,
            mft_cluster,
            mft_mirror_cluster,
            clusters_per_mft_record,
            clusters_per_index_buffer,
            volume_serial,
            boot_sector_data: data[0..512].to_vec(),
        })
    }
    
    /// 有効なNTFSシグネチャを持っているかどうか
    pub fn is_valid_signature(&self) -> bool {
        self.boot_sector_data.len() >= NTFS_SIGNATURE_OFFSET + 8 &&
        &self.boot_sector_data[NTFS_SIGNATURE_OFFSET..NTFS_SIGNATURE_OFFSET + 8] == NTFS_SIGNATURE
    }
    
    /// クラスタサイズを取得（バイト単位）
    pub fn cluster_size(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }
    
    /// MFTレコードサイズを取得（バイト単位）
    pub fn mft_record_size(&self) -> u64 {
        if self.clusters_per_mft_record >= 0 {
            self.cluster_size() * self.clusters_per_mft_record as u64
        } else {
            1 << (-self.clusters_per_mft_record as u32)
        }
    }
    
    /// インデックスバッファサイズを取得（バイト単位）
    pub fn index_buffer_size(&self) -> u64 {
        if self.clusters_per_index_buffer >= 0 {
            self.cluster_size() * self.clusters_per_index_buffer as u64
        } else {
            1 << (-self.clusters_per_index_buffer as u32)
        }
    }
    
    /// 総容量を取得（バイト単位）
    pub fn total_size(&self) -> u64 {
        self.total_sectors * self.bytes_per_sector as u64
    }
    
    /// MFTのオフセットを取得（バイト単位）
    pub fn mft_offset(&self) -> u64 {
        self.mft_cluster * self.cluster_size()
    }
    
    /// MFTミラーのオフセットを取得（バイト単位）
    pub fn mft_mirror_offset(&self) -> u64 {
        self.mft_mirror_cluster * self.cluster_size()
    }
} 