// FAT スーパーブロック実装
//
// FAT12/FAT16/FAT32/VFAT ファイルシステムのブートセクタと関連機能

use alloc::vec::Vec;
use super::super::{FsError, FsResult};

/// FATブートセクタのオフセット
const FAT_SIGNATURE_OFFSET: usize = 510;
const FAT_SIGNATURE: u16 = 0xAA55;
const BYTES_PER_SECTOR_OFFSET: usize = 11;
const SECTORS_PER_CLUSTER_OFFSET: usize = 13;
const RESERVED_SECTORS_OFFSET: usize = 14;
const NUM_FATS_OFFSET: usize = 16;
const ROOT_ENTRIES_OFFSET: usize = 17;
const TOTAL_SECTORS_16_OFFSET: usize = 19;
const MEDIA_TYPE_OFFSET: usize = 21;
const SECTORS_PER_FAT_16_OFFSET: usize = 22;
const SECTORS_PER_TRACK_OFFSET: usize = 24;
const NUM_HEADS_OFFSET: usize = 26;
const HIDDEN_SECTORS_OFFSET: usize = 28;
const TOTAL_SECTORS_32_OFFSET: usize = 32;

// FAT32固有のオフセット
const SECTORS_PER_FAT_32_OFFSET: usize = 36;
const EXTENDED_FLAGS_OFFSET: usize = 40;
const FS_VERSION_OFFSET: usize = 42;
const ROOT_CLUSTER_OFFSET: usize = 44;
const FS_INFO_OFFSET: usize = 48;
const BACKUP_BOOT_OFFSET: usize = 50;
const DRIVE_NUMBER_32_OFFSET: usize = 64;
const EXTENDED_BOOT_SIGNATURE_OFFSET: usize = 66;
const VOLUME_ID_32_OFFSET: usize = 67;
const VOLUME_LABEL_32_OFFSET: usize = 71;
const FS_TYPE_32_OFFSET: usize = 82;

// FAT12/16固有のオフセット
const DRIVE_NUMBER_OFFSET: usize = 36;
const VOLUME_ID_OFFSET: usize = 39;
const VOLUME_LABEL_OFFSET: usize = 43;
const FS_TYPE_OFFSET: usize = 54;

/// FATタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatType {
    /// FAT12
    Fat12,
    /// FAT16
    Fat16,
    /// FAT32
    Fat32,
    /// VFAT
    Vfat,
}

impl FatType {
    /// 自動検出によるFATタイプ判別
    pub fn detect(total_clusters: u32) -> Self {
        if total_clusters < 4085 {
            Self::Fat12
        } else if total_clusters < 65525 {
            Self::Fat16
        } else {
            Self::Fat32
        }
    }
    
    /// 別のFATタイプと互換性があるかどうか
    pub fn is_compatible_with(&self, other: FatType) -> bool {
        match (self, other) {
            // VFATはFAT12/16/32のいずれかの拡張
            (Self::Vfat, _) => true,
            (_, Self::Vfat) => true,
            // 同じタイプは互換性あり
            (a, b) if a == b => true,
            // 他は互換性なし
            _ => false,
        }
    }
}

/// FATスーパーブロック
#[derive(Debug, Clone)]
pub struct FatSuperblock {
    /// OEMラベル
    pub oem_name: [u8; 8],
    /// セクタあたりのバイト数
    pub bytes_per_sector: u16,
    /// クラスタあたりのセクタ数
    pub sectors_per_cluster: u8,
    /// 予約セクタ数
    pub reserved_sectors: u16,
    /// FAT数（通常2）
    pub num_fats: u8,
    /// ルートディレクトリエントリ数
    pub root_entries: u16,
    /// 総セクタ数（16ビット値）
    pub total_sectors_16: u16,
    /// メディアタイプ
    pub media_type: u8,
    /// FAT1つあたりのセクタ数（FAT12/16）
    pub sectors_per_fat_16: u16,
    /// トラックあたりのセクタ数
    pub sectors_per_track: u16,
    /// ヘッド数
    pub num_heads: u16,
    /// 隠しセクタ数
    pub hidden_sectors: u32,
    /// 総セクタ数（32ビット値）
    pub total_sectors_32: u32,
    
    /// FAT1つあたりのセクタ数（FAT32）
    pub sectors_per_fat_32: u32,
    /// 拡張フラグ（FAT32）
    pub extended_flags: u16,
    /// ファイルシステムバージョン（FAT32）
    pub fs_version: u16,
    /// ルートディレクトリの最初のクラスタ（FAT32）
    pub root_cluster: u32,
    /// FSINFOセクタの位置（FAT32）
    pub fs_info_sector: u16,
    /// バックアップブートセクタの位置（FAT32）
    pub backup_boot_sector: u16,
    
    /// ドライブ番号
    pub drive_number: u8,
    /// ボリュームID
    pub volume_id: u32,
    /// ボリュームラベル
    pub volume_label: [u8; 11],
    /// ファイルシステムタイプ文字列
    pub fs_type: [u8; 8],
    
    /// 検出されたFATタイプ
    pub detected_fat_type: FatType,
    /// 生のブートセクタデータ
    pub boot_sector_data: Vec<u8>,
}

impl FatSuperblock {
    /// ブートセクタからFATスーパーブロックをパース
    pub fn parse(data: &[u8], expected_type: FatType) -> FsResult<Self> {
        if data.len() < 512 {
            return Err(FsError::InvalidData);
        }
        
        // 有効なFATシグネチャをチェック
        let signature = u16::from_le_bytes([
            data[FAT_SIGNATURE_OFFSET],
            data[FAT_SIGNATURE_OFFSET + 1],
        ]);
        
        if signature != FAT_SIGNATURE {
            return Err(FsError::BadMagic);
        }
        
        let bytes_per_sector = u16::from_le_bytes([
            data[BYTES_PER_SECTOR_OFFSET],
            data[BYTES_PER_SECTOR_OFFSET + 1],
        ]);
        
        let sectors_per_cluster = data[SECTORS_PER_CLUSTER_OFFSET];
        
        let reserved_sectors = u16::from_le_bytes([
            data[RESERVED_SECTORS_OFFSET],
            data[RESERVED_SECTORS_OFFSET + 1],
        ]);
        
        let num_fats = data[NUM_FATS_OFFSET];
        
        let root_entries = u16::from_le_bytes([
            data[ROOT_ENTRIES_OFFSET],
            data[ROOT_ENTRIES_OFFSET + 1],
        ]);
        
        let total_sectors_16 = u16::from_le_bytes([
            data[TOTAL_SECTORS_16_OFFSET],
            data[TOTAL_SECTORS_16_OFFSET + 1],
        ]);
        
        let media_type = data[MEDIA_TYPE_OFFSET];
        
        let sectors_per_fat_16 = u16::from_le_bytes([
            data[SECTORS_PER_FAT_16_OFFSET],
            data[SECTORS_PER_FAT_16_OFFSET + 1],
        ]);
        
        let sectors_per_track = u16::from_le_bytes([
            data[SECTORS_PER_TRACK_OFFSET],
            data[SECTORS_PER_TRACK_OFFSET + 1],
        ]);
        
        let num_heads = u16::from_le_bytes([
            data[NUM_HEADS_OFFSET],
            data[NUM_HEADS_OFFSET + 1],
        ]);
        
        let hidden_sectors = u32::from_le_bytes([
            data[HIDDEN_SECTORS_OFFSET],
            data[HIDDEN_SECTORS_OFFSET + 1],
            data[HIDDEN_SECTORS_OFFSET + 2],
            data[HIDDEN_SECTORS_OFFSET + 3],
        ]);
        
        let total_sectors_32 = u32::from_le_bytes([
            data[TOTAL_SECTORS_32_OFFSET],
            data[TOTAL_SECTORS_32_OFFSET + 1],
            data[TOTAL_SECTORS_32_OFFSET + 2],
            data[TOTAL_SECTORS_32_OFFSET + 3],
        ]);
        
        // 総セクタ数の計算
        let total_sectors = if total_sectors_16 == 0 { total_sectors_32 } else { total_sectors_16 as u32 };
        
        // FAT32またはFAT12/16かを判定
        let is_fat32 = sectors_per_fat_16 == 0 && root_entries == 0;
        
        let mut sectors_per_fat_32 = 0;
        let mut extended_flags = 0;
        let mut fs_version = 0;
        let mut root_cluster = 0;
        let mut fs_info_sector = 0;
        let mut backup_boot_sector = 0;
        let mut drive_number = 0;
        let mut volume_id = 0;
        let mut volume_label = [0; 11];
        let mut fs_type = [0; 8];
        
        if is_fat32 {
            // FAT32固有のフィールドを読み込み
            sectors_per_fat_32 = u32::from_le_bytes([
                data[SECTORS_PER_FAT_32_OFFSET],
                data[SECTORS_PER_FAT_32_OFFSET + 1],
                data[SECTORS_PER_FAT_32_OFFSET + 2],
                data[SECTORS_PER_FAT_32_OFFSET + 3],
            ]);
            
            extended_flags = u16::from_le_bytes([
                data[EXTENDED_FLAGS_OFFSET],
                data[EXTENDED_FLAGS_OFFSET + 1],
            ]);
            
            fs_version = u16::from_le_bytes([
                data[FS_VERSION_OFFSET],
                data[FS_VERSION_OFFSET + 1],
            ]);
            
            root_cluster = u32::from_le_bytes([
                data[ROOT_CLUSTER_OFFSET],
                data[ROOT_CLUSTER_OFFSET + 1],
                data[ROOT_CLUSTER_OFFSET + 2],
                data[ROOT_CLUSTER_OFFSET + 3],
            ]);
            
            fs_info_sector = u16::from_le_bytes([
                data[FS_INFO_OFFSET],
                data[FS_INFO_OFFSET + 1],
            ]);
            
            backup_boot_sector = u16::from_le_bytes([
                data[BACKUP_BOOT_OFFSET],
                data[BACKUP_BOOT_OFFSET + 1],
            ]);
            
            drive_number = data[DRIVE_NUMBER_32_OFFSET];
            
            volume_id = u32::from_le_bytes([
                data[VOLUME_ID_32_OFFSET],
                data[VOLUME_ID_32_OFFSET + 1],
                data[VOLUME_ID_32_OFFSET + 2],
                data[VOLUME_ID_32_OFFSET + 3],
            ]);
            
            volume_label.copy_from_slice(&data[VOLUME_LABEL_32_OFFSET..VOLUME_LABEL_32_OFFSET + 11]);
            fs_type.copy_from_slice(&data[FS_TYPE_32_OFFSET..FS_TYPE_32_OFFSET + 8]);
        } else {
            // FAT12/16固有のフィールドを読み込み
            drive_number = data[DRIVE_NUMBER_OFFSET];
            
            volume_id = u32::from_le_bytes([
                data[VOLUME_ID_OFFSET],
                data[VOLUME_ID_OFFSET + 1],
                data[VOLUME_ID_OFFSET + 2],
                data[VOLUME_ID_OFFSET + 3],
            ]);
            
            volume_label.copy_from_slice(&data[VOLUME_LABEL_OFFSET..VOLUME_LABEL_OFFSET + 11]);
            fs_type.copy_from_slice(&data[FS_TYPE_OFFSET..FS_TYPE_OFFSET + 8]);
        }
        
        // OEM名を読み込み
        let mut oem_name = [0; 8];
        oem_name.copy_from_slice(&data[3..11]);
        
        // データ領域のセクタ数
        let root_dir_sectors = ((root_entries * 32) + (bytes_per_sector - 1)) / bytes_per_sector;
        let sectors_per_fat = if sectors_per_fat_16 == 0 { sectors_per_fat_32 } else { sectors_per_fat_16 as u32 };
        let first_data_sector = reserved_sectors as u32 + (num_fats as u32 * sectors_per_fat) + root_dir_sectors as u32;
        let data_sectors = total_sectors - first_data_sector;
        let total_clusters = data_sectors / sectors_per_cluster as u32;
        
        // クラスタ数からFATタイプを自動検出
        let detected_fat_type = FatType::detect(total_clusters);
        
        // スーパーブロックのFSタイプからVFATかどうかを判定
        let detected_fs_type = core::str::from_utf8(&fs_type).unwrap_or("");
        let is_vfat = detected_fs_type.contains("FAT") && detected_fs_type.contains("VFAT");
        
        // 最終的なFATタイプを決定
        let final_fat_type = if is_vfat {
            FatType::Vfat
        } else {
            detected_fat_type
        };
        
        // 期待するタイプと互換性があるかチェック
        if !expected_type.is_compatible_with(final_fat_type) {
            log::warn!("検出されたFATタイプ ({:?}) は期待するタイプ ({:?}) と互換性がありません", 
                       final_fat_type, expected_type);
            // ここではエラーを返さず、あとでマウントメソッドでチェック
        }
        
        Ok(Self {
            oem_name,
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            root_entries,
            total_sectors_16,
            media_type,
            sectors_per_fat_16,
            sectors_per_track,
            num_heads,
            hidden_sectors,
            total_sectors_32,
            sectors_per_fat_32,
            extended_flags,
            fs_version,
            root_cluster,
            fs_info_sector,
            backup_boot_sector,
            drive_number,
            volume_id,
            volume_label,
            fs_type,
            detected_fat_type: final_fat_type,
            boot_sector_data: data[0..512].to_vec(),
        })
    }
    
    /// 有効なFATシグネチャを持っているかどうか
    pub fn is_valid_signature(&self) -> bool {
        if self.boot_sector_data.len() < FAT_SIGNATURE_OFFSET + 2 {
            return false;
        }
        
        let signature = u16::from_le_bytes([
            self.boot_sector_data[FAT_SIGNATURE_OFFSET],
            self.boot_sector_data[FAT_SIGNATURE_OFFSET + 1],
        ]);
        
        signature == FAT_SIGNATURE
    }
    
    /// FATタイプを返す
    pub fn fat_type(&self) -> FatType {
        self.detected_fat_type
    }
    
    /// FAT1つあたりのセクタ数
    pub fn sectors_per_fat(&self) -> u32 {
        if self.sectors_per_fat_16 == 0 {
            self.sectors_per_fat_32
        } else {
            self.sectors_per_fat_16 as u32
        }
    }
    
    /// 総セクタ数
    pub fn total_sectors(&self) -> u32 {
        if self.total_sectors_16 == 0 {
            self.total_sectors_32
        } else {
            self.total_sectors_16 as u32
        }
    }
    
    /// クラスタサイズ（バイト単位）
    pub fn cluster_size(&self) -> u32 {
        self.bytes_per_sector as u32 * self.sectors_per_cluster as u32
    }
    
    /// 総容量（バイト単位）
    pub fn total_size(&self) -> u64 {
        self.total_sectors() as u64 * self.bytes_per_sector as u64
    }
    
    /// ボリュームラベルを文字列として取得
    pub fn volume_label_str(&self) -> &str {
        let mut len = 0;
        while len < self.volume_label.len() && self.volume_label[len] != 0 && self.volume_label[len] != b' ' {
            len += 1;
        }
        
        core::str::from_utf8(&self.volume_label[0..len]).unwrap_or("不明なボリューム")
    }
    
    /// ファイルシステムタイプを文字列として取得
    pub fn fs_type_str(&self) -> &str {
        let mut len = 0;
        while len < self.fs_type.len() && self.fs_type[len] != 0 && self.fs_type[len] != b' ' {
            len += 1;
        }
        
        core::str::from_utf8(&self.fs_type[0..len]).unwrap_or("不明なタイプ")
    }
    
    /// ルートディレクトリの先頭セクタを取得
    pub fn root_dir_first_sector(&self) -> u32 {
        if self.detected_fat_type == FatType::Fat32 {
            // FAT32ではルートディレクトリはクラスタに配置
            self.first_data_sector() + (self.root_cluster - 2) * self.sectors_per_cluster as u32
        } else {
            // FAT12/16ではルートディレクトリは固定位置
            self.reserved_sectors as u32 + (self.num_fats as u32 * self.sectors_per_fat())
        }
    }
    
    /// データ領域の先頭セクタを取得
    pub fn first_data_sector(&self) -> u32 {
        let root_dir_sectors = ((self.root_entries * 32) + (self.bytes_per_sector - 1)) / self.bytes_per_sector;
        self.reserved_sectors as u32 + (self.num_fats as u32 * self.sectors_per_fat()) + root_dir_sectors as u32
    }
} 