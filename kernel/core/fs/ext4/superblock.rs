// Ext4 スーパーブロック実装
//
// Ext4ファイルシステムのスーパーブロック構造体と関連機能

use alloc::vec::Vec;
use super::super::{FsError, FsResult};

/// Ext4 スーパーブロック
#[derive(Debug, Clone)]
pub struct Ext4Superblock {
    /// アイノード数
    pub inode_count: u32,
    /// ブロック数
    pub block_count: u32,
    /// 予約ブロック数
    pub reserved_blocks: u32,
    /// 空きブロック数
    pub free_blocks: u32,
    /// 空きアイノード数
    pub free_inodes: u32,
    /// 最初のデータブロック
    pub first_data_block: u32,
    /// ブロックサイズ (log2(ブロックサイズ) - 10)
    pub log_block_size: u32,
    /// フラグメントサイズ (log2(フラグメントサイズ) - 10)
    pub log_fragment_size: u32,
    /// グループごとのブロック数
    pub blocks_per_group: u32,
    /// グループごとのフラグメント数
    pub fragments_per_group: u32,
    /// グループごとのアイノード数
    pub inodes_per_group: u32,
    /// 最終マウント時間
    pub mount_time: u32,
    /// 最終書き込み時間
    pub write_time: u32,
    /// マウント回数
    pub mount_count: u16,
    /// fsckまでの最大マウント回数
    pub max_mount_count: u16,
    /// マジックシグネチャ (0xEF53)
    pub magic: u16,
    /// ファイルシステムの状態
    pub state: u16,
    /// エラー時の動作
    pub errors: u16,
    /// マイナーリビジョンレベル
    pub minor_rev_level: u16,
    /// 最終fsck時間
    pub last_check: u32,
    /// fsck間隔（秒単位）
    pub check_interval: u32,
    /// 作成OSのID
    pub creator_os: u32,
    /// リビジョンレベル
    pub rev_level: u32,
    /// デフォルトユーザーID
    pub def_resuid: u16,
    /// デフォルトグループID
    pub def_resgid: u16,
    
    // EXT4拡張フィールド (リビジョンレベル >= 1 の場合)
    /// 最初の非予約アイノード
    pub first_inode: u32,
    /// アイノードサイズ
    pub inode_size: u16,
    /// このスーパーブロックが存在するブロックグループ
    pub block_group_nr: u16,
    /// 互換性のある機能フラグ
    pub feature_compat: u32,
    /// 非互換性の機能フラグ
    pub feature_incompat: u32,
    /// 読み取り専用互換性のある機能フラグ
    pub feature_ro_compat: u32,
    /// ファイルシステムUUID
    pub uuid: [u8; 16],
    /// ボリューム名
    pub volume_name: [u8; 16],
    /// 最終マウントパス
    pub last_mounted: [u8; 64],
    /// アルゴリズムの使用ビットマップ
    pub algorithm_usage_bitmap: u32,
    
    // パフォーマンスに関する追加フィールド
    /// プリアロケーションブロック数
    pub prealloc_blocks: u8,
    /// ディレクトリのプリアロケーションブロック数
    pub prealloc_dir_blocks: u8,
    /// 予約されたGDTブロック
    pub reserved_gdt_blocks: u16,
    
    // ジャーナリングの追加フィールド
    /// ジャーナルUUID
    pub journal_uuid: [u8; 16],
    /// ジャーナルアイノード
    pub journal_inum: u32,
    /// ジャーナルデバイス
    pub journal_dev: u32,
    /// オーファンアイノードリストの先頭
    pub last_orphan: u32,
    
    // ディレクトリインデックスの追加フィールド
    /// htreeハッシュシード
    pub hash_seed: [u32; 4],
    /// デフォルトハッシュバージョン
    pub def_hash_version: u8,
    /// デフォルトマウントオプション
    pub default_mount_opts: u32,
    /// 最初のメタブロックグループ
    pub first_meta_bg: u32,
    
    // 64ビット拡張用フィールド
    /// スーパーブロックの作成時間
    pub mkfs_time: u32,
    /// ジャーナルのバックアップ
    pub jnl_blocks: [u32; 17],
    
    // 64ビットサポート
    /// 64ビットブロック数
    pub blocks_count_hi: u32,
    /// 64ビット予約ブロック数
    pub reserved_blocks_hi: u32,
    /// 64ビット空きブロック数
    pub free_blocks_hi: u32,
    /// 最小アイノードサイズ
    pub min_extra_isize: u16,
    /// 望ましいアイノードサイズ
    pub want_extra_isize: u16,
    /// ドライバの互換性フラグ
    pub flags: u32,
    /// RAIDストライプ幅
    pub raid_stride: u16,
    /// ストライドミリ秒
    pub mmp_interval: u16,
    /// MMPブロック
    pub mmp_block: u64,
    /// RAIDストライプ幅
    pub raid_stripe_width: u32,
    /// グループあたりのフレックスブロックグループ数
    pub log_groups_per_flex: u8,
    /// チェックサムタイプ
    pub checksum_type: u8,
}

impl Ext4Superblock {
    /// スーパーブロックをパース
    pub fn parse(data: &[u8]) -> FsResult<Self> {
        if data.len() < 1024 {
            return Err(FsError::InvalidData);
        }
        
        // オフセット0からスーパーブロックを読み取り
        let inode_count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let block_count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let reserved_blocks = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let free_blocks = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let free_inodes = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let first_data_block = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let log_block_size = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
        let log_fragment_size = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
        let blocks_per_group = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        let fragments_per_group = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
        let inodes_per_group = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);
        let mount_time = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
        let write_time = u32::from_le_bytes([data[48], data[49], data[50], data[51]]);
        let mount_count = u16::from_le_bytes([data[52], data[53]]);
        let max_mount_count = u16::from_le_bytes([data[54], data[55]]);
        let magic = u16::from_le_bytes([data[56], data[57]]);
        
        // マジックナンバーのチェック
        if magic != 0xEF53 {
            return Err(FsError::InvalidData);
        }
        
        let state = u16::from_le_bytes([data[58], data[59]]);
        let errors = u16::from_le_bytes([data[60], data[61]]);
        let minor_rev_level = u16::from_le_bytes([data[62], data[63]]);
        let last_check = u32::from_le_bytes([data[64], data[65], data[66], data[67]]);
        let check_interval = u32::from_le_bytes([data[68], data[69], data[70], data[71]]);
        let creator_os = u32::from_le_bytes([data[72], data[73], data[74], data[75]]);
        let rev_level = u32::from_le_bytes([data[76], data[77], data[78], data[79]]);
        let def_resuid = u16::from_le_bytes([data[80], data[81]]);
        let def_resgid = u16::from_le_bytes([data[82], data[83]]);
        
        // EXT4拡張フィールド
        let first_inode = u32::from_le_bytes([data[84], data[85], data[86], data[87]]);
        let inode_size = u16::from_le_bytes([data[88], data[89]]);
        let block_group_nr = u16::from_le_bytes([data[90], data[91]]);
        let feature_compat = u32::from_le_bytes([data[92], data[93], data[94], data[95]]);
        let feature_incompat = u32::from_le_bytes([data[96], data[97], data[98], data[99]]);
        let feature_ro_compat = u32::from_le_bytes([data[100], data[101], data[102], data[103]]);
        
        let mut uuid = [0; 16];
        uuid.copy_from_slice(&data[104..120]);
        
        let mut volume_name = [0; 16];
        volume_name.copy_from_slice(&data[120..136]);
        
        let mut last_mounted = [0; 64];
        last_mounted.copy_from_slice(&data[136..200]);
        
        let algorithm_usage_bitmap = u32::from_le_bytes([data[200], data[201], data[202], data[203]]);
        
        // パフォーマンスに関するフィールド
        let prealloc_blocks = data[204];
        let prealloc_dir_blocks = data[205];
        let reserved_gdt_blocks = u16::from_le_bytes([data[206], data[207]]);
        
        // ジャーナリングフィールド
        let mut journal_uuid = [0; 16];
        journal_uuid.copy_from_slice(&data[208..224]);
        
        let journal_inum = u32::from_le_bytes([data[224], data[225], data[226], data[227]]);
        let journal_dev = u32::from_le_bytes([data[228], data[229], data[230], data[231]]);
        let last_orphan = u32::from_le_bytes([data[232], data[233], data[234], data[235]]);
        
        // ディレクトリインデックスフィールド
        let mut hash_seed = [0; 4];
        hash_seed[0] = u32::from_le_bytes([data[236], data[237], data[238], data[239]]);
        hash_seed[1] = u32::from_le_bytes([data[240], data[241], data[242], data[243]]);
        hash_seed[2] = u32::from_le_bytes([data[244], data[245], data[246], data[247]]);
        hash_seed[3] = u32::from_le_bytes([data[248], data[249], data[250], data[251]]);
        
        let def_hash_version = data[252];
        let default_mount_opts = u32::from_le_bytes([data[256], data[257], data[258], data[259]]);
        let first_meta_bg = u32::from_le_bytes([data[260], data[261], data[262], data[263]]);
        
        // 64ビット拡張用フィールド
        let mkfs_time = u32::from_le_bytes([data[264], data[265], data[266], data[267]]);
        
        let mut jnl_blocks = [0; 17];
        for i in 0..17 {
            let offset = 268 + i * 4;
            jnl_blocks[i] = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
        }
        
        // 64ビットサポート
        let blocks_count_hi = u32::from_le_bytes([data[336], data[337], data[338], data[339]]);
        let reserved_blocks_hi = u32::from_le_bytes([data[340], data[341], data[342], data[343]]);
        let free_blocks_hi = u32::from_le_bytes([data[344], data[345], data[346], data[347]]);
        let min_extra_isize = u16::from_le_bytes([data[348], data[349]]);
        let want_extra_isize = u16::from_le_bytes([data[350], data[351]]);
        let flags = u32::from_le_bytes([data[352], data[353], data[354], data[355]]);
        let raid_stride = u16::from_le_bytes([data[356], data[357]]);
        let mmp_interval = u16::from_le_bytes([data[358], data[359]]);
        let mmp_block = u64::from_le_bytes([
            data[360], data[361], data[362], data[363],
            data[364], data[365], data[366], data[367],
        ]);
        let raid_stripe_width = u32::from_le_bytes([data[368], data[369], data[370], data[371]]);
        let log_groups_per_flex = data[372];
        let checksum_type = data[373];
        
        Ok(Self {
            inode_count,
            block_count,
            reserved_blocks,
            free_blocks,
            free_inodes,
            first_data_block,
            log_block_size,
            log_fragment_size,
            blocks_per_group,
            fragments_per_group,
            inodes_per_group,
            mount_time,
            write_time,
            mount_count,
            max_mount_count,
            magic,
            state,
            errors,
            minor_rev_level,
            last_check,
            check_interval,
            creator_os,
            rev_level,
            def_resuid,
            def_resgid,
            first_inode,
            inode_size,
            block_group_nr,
            feature_compat,
            feature_incompat,
            feature_ro_compat,
            uuid,
            volume_name,
            last_mounted,
            algorithm_usage_bitmap,
            prealloc_blocks,
            prealloc_dir_blocks,
            reserved_gdt_blocks,
            journal_uuid,
            journal_inum,
            journal_dev,
            last_orphan,
            hash_seed,
            def_hash_version,
            default_mount_opts,
            first_meta_bg,
            mkfs_time,
            jnl_blocks,
            blocks_count_hi,
            reserved_blocks_hi,
            free_blocks_hi,
            min_extra_isize,
            want_extra_isize,
            flags,
            raid_stride,
            mmp_interval,
            mmp_block,
            raid_stripe_width,
            log_groups_per_flex,
            checksum_type,
        })
    }
    
    /// 実際のブロックサイズを計算 (バイト単位)
    pub fn block_size(&self) -> u64 {
        1024 << self.log_block_size
    }
    
    /// 総ブロック数を取得 (64ビットサポート)
    pub fn total_blocks(&self) -> u64 {
        ((self.blocks_count_hi as u64) << 32) | (self.block_count as u64)
    }
    
    /// 空きブロック数を取得 (64ビットサポート)
    pub fn total_free_blocks(&self) -> u64 {
        ((self.free_blocks_hi as u64) << 32) | (self.free_blocks as u64)
    }
    
    /// 予約ブロック数を取得 (64ビットサポート)
    pub fn total_reserved_blocks(&self) -> u64 {
        ((self.reserved_blocks_hi as u64) << 32) | (self.reserved_blocks as u64)
    }
    
    /// 互換性のある機能をチェック
    pub fn has_feature_compat(&self, flag: u32) -> bool {
        (self.feature_compat & flag) != 0
    }
    
    /// 非互換性の機能をチェック
    pub fn has_feature_incompat(&self, flag: u32) -> bool {
        (self.feature_incompat & flag) != 0
    }
    
    /// 読み取り専用互換性のある機能をチェック
    pub fn has_feature_ro_compat(&self, flag: u32) -> bool {
        (self.feature_ro_compat & flag) != 0
    }
    
    /// ファイルシステムが64ビット対応かどうか
    pub fn is_64bit(&self) -> bool {
        self.has_feature_incompat(0x80) // INCOMPAT_64BIT
    }
    
    /// ボリューム名を文字列として取得
    pub fn volume_name_str(&self) -> &str {
        // NUL終端文字列に変換
        let mut len = 0;
        while len < self.volume_name.len() && self.volume_name[len] != 0 {
            len += 1;
        }
        
        // 安全な方法で文字列を作成
        core::str::from_utf8(&self.volume_name[0..len]).unwrap_or("不明なボリューム名")
    }
}

/// スーパーブロックとして使用する型の別名（外部公開用）
pub type Superblock = Ext4Superblock; 