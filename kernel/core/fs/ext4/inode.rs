// Ext4 アイノード実装
//
// Ext4ファイルシステムのアイノード構造体と関連機能

use alloc::vec::Vec;
use super::super::{FsError, FsResult};

/// アイノードフラグ
#[repr(u32)]
pub enum InodeFlags {
    /// セキュアな削除
    SecureDeletion = 0x00000001,
    /// ファイル削除時に内容を保持
    KeepCopy = 0x00000002,
    /// ファイル圧縮
    Compression = 0x00000004,
    /// 同期更新
    Synchronous = 0x00000008,
    /// 変更不可
    Immutable = 0x00000010,
    /// 追加のみ
    AppendOnly = 0x00000020,
    /// ダンプしない
    NoDump = 0x00000040,
    /// 最終アクセス時間を更新しない
    NoAccessTime = 0x00000080,
    /// ダーティ
    Dirty = 0x00000100,
    /// 圧縮ブロック
    CompressedBlocks = 0x00000200,
    /// 同期ディレクトリ
    SynchronousDir = 0x00000400,
    /// ジャーナリングされた特殊なデータ
    Journal = 0x00000800,
    /// エクステント
    Extents = 0x00080000,
    /// 巨大ファイル
    HugeFile = 0x00200000,
    /// ディレクトリアイノードはディレクトリインデックスノードを使用
    DirIndex = 0x00001000,
    /// AFS特殊アイノード
    AfsSpecialInode = 0x00002000,
    /// Ext3のメタデータチェックサム
    Ext3Metadata = 0x00004000,
    /// プロジェクトの継承
    ProjectInherited = 0x00020000,
    /// 透過的暗号化
    Encrypt = 0x00800000,
    /// ディレクトリはCasefolding機能を使用
    Casefold = 0x10000000,
}

/// Ext4アイノード
#[derive(Debug, Clone)]
pub struct Ext4Inode {
    /// ファイルタイプとアクセス権
    pub mode: u16,
    /// 所有者のユーザーID
    pub uid: u32,
    /// ファイルサイズ（下位32ビット）
    pub size_lo: u32,
    /// 最終アクセス時間
    pub atime: u32,
    /// アイノード変更時間
    pub ctime: u32,
    /// 最終修正時間
    pub mtime: u32,
    /// 削除時間
    pub dtime: u32,
    /// グループID
    pub gid: u32,
    /// ハードリンクの数
    pub links_count: u16,
    /// 512バイト単位のブロック数
    pub blocks_lo: u32,
    /// ファイルのフラグ
    pub flags: u32,
    /// OSごとの特定の情報
    pub osd1: u32,
    /// ブロックポインタまたはエクステントツリー
    pub block: [u32; 15],
    /// ファイルバージョン（NFS用）
    pub generation: u32,
    /// 拡張属性ブロック（ACL）
    pub file_acl_lo: u32,
    /// ファイルサイズ（上位32ビット）
    pub size_hi: u32,
    /// 断片アドレス
    pub fragment_addr: u32,
    /// OSごとの特定の情報2
    pub osd2: [u8; 12],
    
    // Ext4の追加フィールド（inode_size > 128の場合）
    /// エクストラアイノードサイズ
    pub extra_isize: u16,
    /// チェックサム上位16ビット
    pub checksum_hi: u16,
    /// 変更時間の拡張ナノ秒部分
    pub ctime_extra: u32,
    /// 最終修正時間の拡張ナノ秒部分
    pub mtime_extra: u32,
    /// 最終アクセス時間の拡張ナノ秒部分
    pub atime_extra: u32,
    /// ファイル作成時間
    pub crtime: u32,
    /// ファイル作成時間の拡張ナノ秒部分
    pub crtime_extra: u32,
    /// バージョン上位32ビット
    pub version_hi: u32,
    /// プロジェクトID
    pub projid: u32,
    
    // 計算されたフィールド
    /// 合計ファイルサイズ
    pub size: u64,
    /// 合計ブロック数
    pub blocks: u64,
}

impl Ext4Inode {
    /// アイノードデータをパース
    pub fn parse(data: &[u8], size: usize) -> FsResult<Self> {
        if data.len() < 128 {
            return Err(FsError::InvalidData);
        }
        
        let mode = u16::from_le_bytes([data[0], data[1]]);
        let uid_lo = u16::from_le_bytes([data[2], data[3]]);
        let size_lo = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let atime = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let ctime = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let mtime = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let dtime = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let gid_lo = u16::from_le_bytes([data[24], data[25]]);
        let links_count = u16::from_le_bytes([data[26], data[27]]);
        let blocks_lo = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
        let flags = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        let osd1 = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
        
        let mut block = [0; 15];
        for i in 0..15 {
            let offset = 40 + i * 4;
            block[i] = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
        }
        
        let generation = u32::from_le_bytes([data[100], data[101], data[102], data[103]]);
        let file_acl_lo = u32::from_le_bytes([data[104], data[105], data[106], data[107]]);
        let size_hi = u32::from_le_bytes([data[108], data[109], data[110], data[111]]);
        let fragment_addr = u32::from_le_bytes([data[112], data[113], data[114], data[115]]);
        
        let mut osd2 = [0; 12];
        osd2.copy_from_slice(&data[116..128]);
        
        // Ext4の追加フィールド（inode_size > 128の場合）
        let mut extra_isize = 0;
        let mut checksum_hi = 0;
        let mut ctime_extra = 0;
        let mut mtime_extra = 0;
        let mut atime_extra = 0;
        let mut crtime = 0;
        let mut crtime_extra = 0;
        let mut version_hi = 0;
        let mut projid = 0;
        
        if size > 128 && data.len() >= size {
            extra_isize = u16::from_le_bytes([data[128], data[129]]);
            checksum_hi = u16::from_le_bytes([data[130], data[131]]);
            ctime_extra = u32::from_le_bytes([data[132], data[133], data[134], data[135]]);
            mtime_extra = u32::from_le_bytes([data[136], data[137], data[138], data[139]]);
            atime_extra = u32::from_le_bytes([data[140], data[141], data[142], data[143]]);
            crtime = u32::from_le_bytes([data[144], data[145], data[146], data[147]]);
            crtime_extra = u32::from_le_bytes([data[148], data[149], data[150], data[151]]);
            version_hi = u32::from_le_bytes([data[152], data[153], data[154], data[155]]);
            projid = u32::from_le_bytes([data[156], data[157], data[158], data[159]]);
        }
        
        // 高次ビットを考慮したUID/GID
        let uid_hi = (osd2[2] as u32) << 16 | (osd2[3] as u32) << 24;
        let gid_hi = (osd2[4] as u32) << 16 | (osd2[5] as u32) << 24;
        let uid = uid_hi | (uid_lo as u32);
        let gid = gid_hi | (gid_lo as u32);
        
        // 計算されたフィールド
        let size = ((size_hi as u64) << 32) | (size_lo as u64);
        let blocks_hi = ((osd2[0] as u64) << 32) | ((osd2[1] as u64) << 40);
        let blocks = blocks_hi | (blocks_lo as u64);
        
        Ok(Self {
            mode,
            uid,
            size_lo,
            atime,
            ctime,
            mtime,
            dtime,
            gid,
            links_count,
            blocks_lo,
            flags,
            osd1,
            block,
            generation,
            file_acl_lo,
            size_hi,
            fragment_addr,
            osd2,
            extra_isize,
            checksum_hi,
            ctime_extra,
            mtime_extra,
            atime_extra,
            crtime,
            crtime_extra,
            version_hi,
            projid,
            size,
            blocks,
        })
    }
    
    /// アイノードがディレクトリかどうか
    pub fn is_directory(&self) -> bool {
        (self.mode & 0xF000) == 0x4000
    }
    
    /// アイノードが通常ファイルかどうか
    pub fn is_regular_file(&self) -> bool {
        (self.mode & 0xF000) == 0x8000
    }
    
    /// アイノードがシンボリックリンクかどうか
    pub fn is_symlink(&self) -> bool {
        (self.mode & 0xF000) == 0xA000
    }
    
    /// アイノードがブロックデバイスかどうか
    pub fn is_block_device(&self) -> bool {
        (self.mode & 0xF000) == 0x6000
    }
    
    /// アイノードがキャラクタデバイスかどうか
    pub fn is_character_device(&self) -> bool {
        (self.mode & 0xF000) == 0x2000
    }
    
    /// アイノードがFIFO（名前付きパイプ）かどうか
    pub fn is_fifo(&self) -> bool {
        (self.mode & 0xF000) == 0x1000
    }
    
    /// アイノードがソケットかどうか
    pub fn is_socket(&self) -> bool {
        (self.mode & 0xF000) == 0xC000
    }
    
    /// アイノードがエクステントモードかどうか
    pub fn has_extents(&self) -> bool {
        (self.flags & InodeFlags::Extents as u32) != 0
    }
    
    /// アイノードが小さいシンボリックリンクかどうか（データがblock配列内にある）
    pub fn is_fast_symlink(&self) -> bool {
        self.is_symlink() && self.size < 60
    }
}

/// アイノードとして使用する型の別名（外部公開用）
pub type Inode = Ext4Inode; 