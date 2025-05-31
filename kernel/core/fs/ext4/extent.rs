// Ext4 エクステント実装
//
// Ext4ファイルシステムのエクステント機能

use alloc::vec::Vec;
use super::super::{FsError, FsResult};

/// エクステントヘッダ
#[derive(Debug, Clone, Copy)]
pub struct ExtentHeader {
    /// マジックシグネチャ (0xF30A)
    pub magic: u16,
    /// このエクステントブロック内のエントリ数
    pub entries: u16,
    /// このエクステントブロック内の最大エントリ数
    pub max: u16,
    /// ツリーの深さ (0はリーフノード)
    pub depth: u16,
    /// 世代
    pub generation: u32,
}

impl ExtentHeader {
    /// エクステントヘッダをパース
    pub fn parse(data: &[u8]) -> FsResult<Self> {
        if data.len() < 12 {
            return Err(FsError::InvalidData);
        }
        
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != 0xF30A {
            return Err(FsError::InvalidData);
        }
        
        let entries = u16::from_le_bytes([data[2], data[3]]);
        let max = u16::from_le_bytes([data[4], data[5]]);
        let depth = u16::from_le_bytes([data[6], data[7]]);
        let generation = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        
        Ok(Self {
            magic,
            entries,
            max,
            depth,
            generation,
        })
    }
    
    /// エクステントヘッダをシリアライズ
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(12);
        
        result.extend_from_slice(&self.magic.to_le_bytes());
        result.extend_from_slice(&self.entries.to_le_bytes());
        result.extend_from_slice(&self.max.to_le_bytes());
        result.extend_from_slice(&self.depth.to_le_bytes());
        result.extend_from_slice(&self.generation.to_le_bytes());
        
        result
    }
    
    /// 新しいエクステントヘッダを作成
    pub fn new(entries: u16, max: u16, depth: u16) -> Self {
        Self {
            magic: 0xF30A,
            entries,
            max,
            depth,
            generation: 0,
        }
    }
    
    /// リーフノードかどうか
    pub fn is_leaf(&self) -> bool {
        self.depth == 0
    }
}

/// エクステントインデックス（ノードエントリ）
#[derive(Debug, Clone, Copy)]
pub struct ExtentIndex {
    /// このインデックスノードがカバーする最初の論理ブロック
    pub block: u32,
    /// 子ノードを指すブロック
    pub leaf_lo: u32,
    /// 子ノードを指すブロック（上位16ビット）
    pub leaf_hi: u16,
    /// 未使用
    pub unused: u16,
}

impl ExtentIndex {
    /// エクステントインデックスをパース
    pub fn parse(data: &[u8]) -> FsResult<Self> {
        if data.len() < 12 {
            return Err(FsError::InvalidData);
        }
        
        let block = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let leaf_lo = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let leaf_hi = u16::from_le_bytes([data[8], data[9]]);
        let unused = u16::from_le_bytes([data[10], data[11]]);
        
        Ok(Self {
            block,
            leaf_lo,
            leaf_hi,
            unused,
        })
    }
    
    /// エクステントインデックスをシリアライズ
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(12);
        
        result.extend_from_slice(&self.block.to_le_bytes());
        result.extend_from_slice(&self.leaf_lo.to_le_bytes());
        result.extend_from_slice(&self.leaf_hi.to_le_bytes());
        result.extend_from_slice(&self.unused.to_le_bytes());
        
        result
    }
    
    /// 子ノードのブロック番号を取得（64ビット）
    pub fn leaf(&self) -> u64 {
        ((self.leaf_hi as u64) << 32) | (self.leaf_lo as u64)
    }
    
    /// 新しいエクステントインデックスを作成
    pub fn new(block: u32, leaf: u64) -> Self {
        Self {
            block,
            leaf_lo: leaf as u32,
            leaf_hi: (leaf >> 32) as u16,
            unused: 0,
        }
    }
}

/// エクステントリーフ（データエントリ）
#[derive(Debug, Clone, Copy)]
pub struct ExtentLeaf {
    /// このエクステントがカバーする最初の論理ブロック
    pub block: u32,
    /// このエクステントの長さ
    pub len: u16,
    /// 初期化されていないブロックフラグ
    pub uninit: u16,
    /// 物理ブロック（下位32ビット）
    pub start_lo: u32,
    /// 物理ブロック（上位16ビット）
    pub start_hi: u16,
    /// 未使用
    pub unused: u16,
}

impl ExtentLeaf {
    /// エクステントリーフをパース
    pub fn parse(data: &[u8]) -> FsResult<Self> {
        if data.len() < 12 {
            return Err(FsError::InvalidData);
        }
        
        let block = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let len = u16::from_le_bytes([data[4], data[5]]);
        let uninit = u16::from_le_bytes([data[6], data[7]]);
        let start_lo = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let start_hi = u16::from_le_bytes([data[12], data[13]]);
        let unused = u16::from_le_bytes([data[14], data[15]]);
        
        Ok(Self {
            block,
            len,
            uninit,
            start_lo,
            start_hi,
            unused,
        })
    }
    
    /// エクステントリーフをシリアライズ
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(16);
        
        result.extend_from_slice(&self.block.to_le_bytes());
        result.extend_from_slice(&self.len.to_le_bytes());
        result.extend_from_slice(&self.uninit.to_le_bytes());
        result.extend_from_slice(&self.start_lo.to_le_bytes());
        result.extend_from_slice(&self.start_hi.to_le_bytes());
        result.extend_from_slice(&self.unused.to_le_bytes());
        
        result
    }
    
    /// 物理ブロック開始位置を取得（64ビット）
    pub fn start(&self) -> u64 {
        ((self.start_hi as u64) << 32) | (self.start_lo as u64)
    }
    
    /// 新しいエクステントリーフを作成
    pub fn new(block: u32, len: u16, start: u64) -> Self {
        Self {
            block,
            len,
            uninit: 0,
            start_lo: start as u32,
            start_hi: (start >> 32) as u16,
            unused: 0,
        }
    }
    
    /// 初期化されていないブロックかどうか
    pub fn is_uninitialized(&self) -> bool {
        self.uninit != 0
    }
}

/// エクステントツリーからファイル内の論理ブロックに対応する物理ブロックを見つける
pub fn find_physical_block(
    file_block: u32,
    inode_data: &[u8],
) -> FsResult<u64> {
    // まずヘッダを解析
    let header = ExtentHeader::parse(&inode_data[0..12])?;
    
    if header.magic != 0xF30A {
        return Err(FsError::InvalidData);
    }
    
    if header.is_leaf() {
        // リーフノードの場合、直接エクステントを探す
        return find_block_in_leaf(file_block, &inode_data[12..], header.entries);
    } else {
        // インデックスノードの場合、適切な子ノードを見つける
        return find_block_in_index(file_block, &inode_data[12..], header.entries);
    }
}

/// リーフノード内でブロックを探す
fn find_block_in_leaf(file_block: u32, data: &[u8], entries: u16) -> FsResult<u64> {
    for i in 0..entries {
        let offset = i as usize * 12;
        if offset + 12 > data.len() {
            return Err(FsError::InvalidData);
        }
        
        let extent = ExtentLeaf::parse(&data[offset..offset+12])?;
        
        // ブロックがこのエクステント内にあるかチェック
        if file_block >= extent.block && file_block < extent.block + extent.len as u32 {
            let block_offset = file_block - extent.block;
            return Ok(extent.start() + block_offset as u64);
        }
    }
    
    // ブロックが見つからない場合
    Err(FsError::NotFound)
}

/// インデックスノード内で適切な子ノードを探す
fn find_block_in_index(file_block: u32, data: &[u8], entries: u16) -> FsResult<u64> {
    for i in 0..entries {
        // エントリの開始オフセット計算: ヘッダ(12byte) + エントリインデックス × エントリサイズ(12byte)
        let offset = 12 + (i as usize) * 12;
        
        if offset + 12 > data.len() {
            return Err(FsError::InvalidFormat);
        }
        
        // エクステントインデックスからデータを抽出
        let ee_block = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]);
        
        let ee_len = u16::from_le_bytes([
            data[offset + 4], data[offset + 5]
        ]);
        
        let ee_start_hi = u16::from_le_bytes([
            data[offset + 6], data[offset + 7]
        ]);
        
        let ee_start_lo = u32::from_le_bytes([
            data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11]
        ]);
        
        let ee_start = ((ee_start_hi as u64) << 32) | (ee_start_lo as u64);
        
        // 指定されたブロックが現在のエクステント範囲内かチェック
        if file_block >= ee_block && file_block < ee_block + (ee_len as u32) {
            // デバイスマネージャからデバイスを取得
            let device_manager = crate::drivers::block::get_device_manager();
            let device_id = get_current_device_id(); // 現在処理中のデバイスID取得関数（実装必要）
            
            if let Some(device) = device_manager.get_device(device_id) {
                // 子ノードブロックを読み込み
                match device.read_block(ee_start) {
                    Ok(node_data) => {
                        // 読み込んだノードを解析
                        return parse_extent_node(file_block, &node_data);
                    },
                    Err(_) => {
                        return Err(FsError::IoError);
                    }
                }
            } else {
                return Err(FsError::DeviceNotFound);
            }
        }
    }
    
    Err(FsError::FileBlockNotFound)
} 