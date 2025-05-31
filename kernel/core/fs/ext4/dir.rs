// Ext4 ディレクトリエントリ実装
//
// ディレクトリエントリの構造と操作

use core::str;
use alloc::vec::Vec;
use alloc::string::{String, ToString};
use super::super::{FsError, FsResult, FileType};

/// ディレクトリエントリタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DirectoryEntryType {
    /// 不明
    Unknown = 0,
    /// 通常ファイル
    RegularFile = 1,
    /// ディレクトリ
    Directory = 2,
    /// キャラクタデバイス
    CharDevice = 3,
    /// ブロックデバイス
    BlockDevice = 4,
    /// FIFO（名前付きパイプ）
    Fifo = 5,
    /// ソケット
    Socket = 6,
    /// シンボリックリンク
    SymbolicLink = 7,
}

impl DirectoryEntryType {
    /// バイト値からディレクトリエントリタイプを作成
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            1 => Self::RegularFile,
            2 => Self::Directory,
            3 => Self::CharDevice,
            4 => Self::BlockDevice,
            5 => Self::Fifo,
            6 => Self::Socket,
            7 => Self::SymbolicLink,
            _ => Self::Unknown,
        }
    }
    
    /// ファイルタイプに変換
    pub fn to_file_type(&self) -> FileType {
        match self {
            Self::RegularFile => FileType::Regular,
            Self::Directory => FileType::Directory,
            Self::CharDevice => FileType::CharDevice,
            Self::BlockDevice => FileType::BlockDevice,
            Self::Fifo => FileType::NamedPipe,
            Self::Socket => FileType::Socket,
            Self::SymbolicLink => FileType::SymbolicLink,
            Self::Unknown => FileType::Regular,
        }
    }
}

/// Ext4ディレクトリエントリ
#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    /// アイノード番号
    pub inode: u32,
    /// エントリの長さ
    pub rec_len: u16,
    /// 名前の長さ
    pub name_len: u8,
    /// ファイルタイプ
    pub file_type: DirectoryEntryType,
    /// ファイル名
    pub name: String,
}

impl DirectoryEntry {
    /// ディレクトリエントリをパース
    pub fn parse(data: &[u8], offset: usize) -> FsResult<(Self, usize)> {
        if data.len() < offset + 8 {
            return Err(FsError::InvalidData);
        }
        
        let inode = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]);
        
        let rec_len = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
        let name_len = data[offset + 6];
        let file_type = DirectoryEntryType::from_byte(data[offset + 7]);
        
        if data.len() < offset + 8 + name_len as usize {
            return Err(FsError::InvalidData);
        }
        
        let name_bytes = &data[offset + 8..offset + 8 + name_len as usize];
        let name = match str::from_utf8(name_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => return Err(FsError::InvalidData),
        };
        
        let entry = Self {
            inode,
            rec_len,
            name_len,
            file_type,
            name,
        };
        
        Ok((entry, rec_len as usize))
    }
    
    /// ディレクトリエントリをシリアライズ
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(8 + self.name.len());
        
        // アイノード番号
        result.extend_from_slice(&self.inode.to_le_bytes());
        
        // エントリ長
        result.extend_from_slice(&self.rec_len.to_le_bytes());
        
        // 名前長
        result.push(self.name_len);
        
        // ファイルタイプ
        result.push(self.file_type as u8);
        
        // 名前
        result.extend_from_slice(self.name.as_bytes());
        
        // 必要に応じてパディング
        let padding = self.rec_len as usize - (8 + self.name.len());
        result.resize(result.len() + padding, 0);
        
        result
    }
    
    /// 新しいディレクトリエントリを作成
    pub fn new(
        inode: u32,
        name: &str,
        file_type: DirectoryEntryType,
    ) -> Self {
        let name_len = name.len() as u8;
        
        // エントリ長の計算 (8バイトヘッダ + 名前長、4バイト境界に合わせる)
        let rec_len = (8 + name.len() + 3) & !3;
        let rec_len = rec_len as u16;
        
        Self {
            inode,
            rec_len,
            name_len,
            file_type,
            name: name.to_string(),
        }
    }
    
    /// レコードサイズを実際のエントリサイズと末尾のパディングに分ける
    pub fn actual_size(&self) -> u16 {
        (8 + self.name_len as u16 + 3) & !3
    }
}

/// ディレクトリブロックを解析して、すべてのエントリを取得
pub fn parse_directory_block(data: &[u8]) -> FsResult<Vec<DirectoryEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0;
    
    while offset < data.len() {
        let (entry, entry_size) = DirectoryEntry::parse(data, offset)?;
        
        // アイノード0はエントリが削除されたことを意味する
        if entry.inode != 0 {
            entries.push(entry);
        }
        
        offset += entry_size;
        
        // エントリサイズが0の場合は無限ループを防ぐ
        if entry_size == 0 {
            break;
        }
    }
    
    Ok(entries)
} 