// Ext4 ビットマップ処理
//
// ブロックとアイノードのビットマップ処理

use alloc::vec::Vec;
use super::super::{FsError, FsResult};

/// ビットマップを操作するためのヘルパー関数
pub struct Bitmap;

impl Bitmap {
    /// ビットマップ内の指定ビットをチェック
    pub fn check_bit(bitmap: &[u8], bit_index: usize) -> bool {
        let byte_index = bit_index / 8;
        let bit_offset = bit_index % 8;
        
        if byte_index >= bitmap.len() {
            return false;
        }
        
        (bitmap[byte_index] & (1 << bit_offset)) != 0
    }
    
    /// ビットマップ内の指定ビットを設定
    pub fn set_bit(bitmap: &mut [u8], bit_index: usize) {
        let byte_index = bit_index / 8;
        let bit_offset = bit_index % 8;
        
        if byte_index < bitmap.len() {
            bitmap[byte_index] |= 1 << bit_offset;
        }
    }
    
    /// ビットマップ内の指定ビットをクリア
    pub fn clear_bit(bitmap: &mut [u8], bit_index: usize) {
        let byte_index = bit_index / 8;
        let bit_offset = bit_index % 8;
        
        if byte_index < bitmap.len() {
            bitmap[byte_index] &= !(1 << bit_offset);
        }
    }
    
    /// ビットマップ内の最初の空きビットを検索
    pub fn find_first_zero(bitmap: &[u8], start_bit: usize, max_bits: usize) -> Option<usize> {
        let mut bit_index = start_bit;
        
        while bit_index < max_bits {
            let byte_index = bit_index / 8;
            
            if byte_index >= bitmap.len() {
                return None;
            }
            
            let byte = bitmap[byte_index];
            
            // バイト内のすべてのビットが1の場合はスキップ
            if byte == 0xFF {
                // 次のバイトの先頭にスキップ
                bit_index = (byte_index + 1) * 8;
                continue;
            }
            
            // バイト内の0ビットを検索
            let bit_offset = bit_index % 8;
            let mask = 1 << bit_offset;
            
            if (byte & mask) == 0 {
                return Some(bit_index);
            }
            
            bit_index += 1;
        }
        
        None
    }
    
    /// ビットマップ内の連続する空きビットを検索
    pub fn find_contiguous_zeros(bitmap: &[u8], start_bit: usize, max_bits: usize, count: usize) -> Option<usize> {
        if count == 0 {
            return Some(start_bit);
        }
        
        let mut start = start_bit;
        let mut found = 0;
        
        while start + found < max_bits {
            if Self::check_bit(bitmap, start + found) {
                // 1が見つかったら、次の開始位置から再検索
                start = start + found + 1;
                found = 0;
                continue;
            }
            
            found += 1;
            if found == count {
                return Some(start);
            }
        }
        
        None
    }
    
    /// ビットマップ内のセットされたビット数を数える
    pub fn count_bits(bitmap: &[u8]) -> usize {
        let mut count = 0;
        
        for &byte in bitmap {
            count += byte.count_ones() as usize;
        }
        
        count
    }
}

/// ブロックビットマップ処理
pub struct BlockBitmap;

impl BlockBitmap {
    /// ブロックビットマップを読み込み
    pub fn read_bitmap(device_id: u64, block_bitmap_block: u64) -> FsResult<Vec<u8>> {
        // デバイスマネージャからデバイスを取得
        let device_manager = crate::drivers::block::get_device_manager();
        let device = match device_manager.get_device(device_id) {
            Some(dev) => dev,
            None => {
                log::error!("ブロックビットマップ読み込み: デバイス ID {} が見つかりません", device_id);
                return Err(FsError::DeviceNotFound);
            }
        };
        
        // ブロックを読み込み
        match device.read_block(block_bitmap_block) {
            Ok(data) => {
                log::debug!("ブロックビットマップ読み込み: デバイス {} ブロック {} サイズ {}バイト",
                          device_id, block_bitmap_block, data.len());
                Ok(data)
            },
            Err(e) => {
                log::error!("ブロックビットマップ読み込みエラー: デバイス {} ブロック {} エラー {:?}",
                          device_id, block_bitmap_block, e);
                Err(FsError::IoError)
            }
        }
    }
    
    /// 空きブロックを割り当て
    pub fn allocate_block(device_id: u64, block_bitmap_block: u64, start_bit: usize, max_bits: usize) -> FsResult<u64> {
        let mut bitmap = Self::read_bitmap(device_id, block_bitmap_block)?;
        
        if let Some(free_bit) = Bitmap::find_first_zero(&bitmap, start_bit, max_bits) {
            Bitmap::set_bit(&mut bitmap, free_bit);
            
            // ビットマップを書き戻す
            Self::write_bitmap(device_id, block_bitmap_block, &bitmap)?;
            
            Ok(free_bit as u64)
        } else {
            Err(FsError::OutOfSpace)
        }
    }
    
    /// 複数の連続する空きブロックを割り当て
    pub fn allocate_blocks(device_id: u64, block_bitmap_block: u64, start_bit: usize, max_bits: usize, count: usize) -> FsResult<u64> {
        let mut bitmap = Self::read_bitmap(device_id, block_bitmap_block)?;
        
        if let Some(start_free) = Bitmap::find_contiguous_zeros(&bitmap, start_bit, max_bits, count) {
            // ビットを設定
            for i in 0..count {
                Bitmap::set_bit(&mut bitmap, start_free + i);
            }
            
            // ビットマップを書き戻す
            Self::write_bitmap(device_id, block_bitmap_block, &bitmap)?;
            
            Ok(start_free as u64)
        } else {
            Err(FsError::OutOfSpace)
        }
    }
    
    /// ブロックを解放
    pub fn free_block(device_id: u64, block_bitmap_block: u64, block: usize) -> FsResult<()> {
        let mut bitmap = Self::read_bitmap(device_id, block_bitmap_block)?;
        
        Bitmap::clear_bit(&mut bitmap, block);
        
        // ビットマップを書き戻す
        Self::write_bitmap(device_id, block_bitmap_block, &bitmap)?;
        
        Ok(())
    }
    
    /// 複数のブロックを解放
    pub fn free_blocks(device_id: u64, block_bitmap_block: u64, start_block: usize, count: usize) -> FsResult<()> {
        let mut bitmap = Self::read_bitmap(device_id, block_bitmap_block)?;
        
        for i in 0..count {
            Bitmap::clear_bit(&mut bitmap, start_block + i);
        }
        
        // ビットマップを書き戻す
        Self::write_bitmap(device_id, block_bitmap_block, &bitmap)?;
        
        Ok(())
    }
    
    /// ビットマップを書き込み
    fn write_bitmap(device_id: u64, block_bitmap_block: u64, bitmap: &[u8]) -> FsResult<()> {
        // デバイスマネージャからデバイスを取得
        let device_manager = crate::drivers::block::get_device_manager();
        let device = match device_manager.get_device(device_id) {
            Some(dev) => dev,
            None => {
                log::error!("ブロックビットマップ書き込み: デバイス ID {} が見つかりません", device_id);
                return Err(FsError::DeviceNotFound);
            }
        };
        
        // ブロックサイズを検証
        let block_size = device.get_block_size() as usize;
        if bitmap.len() != block_size {
            log::error!("ブロックビットマップ書き込み: サイズが不正です: 予期={}, 実際={}",
                      block_size, bitmap.len());
            return Err(FsError::InvalidSize);
        }
        
        // ブロックを書き込み
        match device.write_block(block_bitmap_block, bitmap) {
            Ok(_) => {
                log::debug!("ブロックビットマップ書き込み: デバイス {} ブロック {} サイズ {}バイト",
                          device_id, block_bitmap_block, bitmap.len());
                Ok(())
            },
            Err(e) => {
                log::error!("ブロックビットマップ書き込みエラー: デバイス {} ブロック {} エラー {:?}",
                          device_id, block_bitmap_block, e);
                Err(FsError::IoError)
            }
        }
    }
}

/// アイノードビットマップ処理
pub struct InodeBitmap;

impl InodeBitmap {
    /// アイノードビットマップを読み込み
    pub fn read_bitmap(device_id: u64, inode_bitmap_block: u64) -> FsResult<Vec<u8>> {
        // デバイスマネージャからデバイスを取得
        let device_manager = crate::drivers::block::get_device_manager();
        let device = match device_manager.get_device(device_id) {
            Some(dev) => dev,
            None => {
                log::error!("アイノードビットマップ読み込み: デバイス ID {} が見つかりません", device_id);
                return Err(FsError::DeviceNotFound);
            }
        };
        
        // ブロックを読み込み
        match device.read_block(inode_bitmap_block) {
            Ok(data) => {
                log::debug!("アイノードビットマップ読み込み: デバイス {} ブロック {} サイズ {}バイト",
                          device_id, inode_bitmap_block, data.len());
                Ok(data)
            },
            Err(e) => {
                log::error!("アイノードビットマップ読み込みエラー: デバイス {} ブロック {} エラー {:?}",
                          device_id, inode_bitmap_block, e);
                Err(FsError::IoError)
            }
        }
    }
    
    /// 空きアイノードを割り当て
    pub fn allocate_inode(device_id: u64, inode_bitmap_block: u64, start_bit: usize, max_bits: usize) -> FsResult<u64> {
        let mut bitmap = Self::read_bitmap(device_id, inode_bitmap_block)?;
        
        if let Some(free_bit) = Bitmap::find_first_zero(&bitmap, start_bit, max_bits) {
            Bitmap::set_bit(&mut bitmap, free_bit);
            
            // ビットマップを書き戻す
            Self::write_bitmap(device_id, inode_bitmap_block, &bitmap)?;
            
            // アイノード番号は1ベース
            Ok((free_bit + 1) as u64)
        } else {
            Err(FsError::OutOfSpace)
        }
    }
    
    /// アイノードを解放
    pub fn free_inode(device_id: u64, inode_bitmap_block: u64, inode: usize) -> FsResult<()> {
        let mut bitmap = Self::read_bitmap(device_id, inode_bitmap_block)?;
        
        // アイノード番号は1ベース
        Bitmap::clear_bit(&mut bitmap, inode - 1);
        
        // ビットマップを書き戻す
        Self::write_bitmap(device_id, inode_bitmap_block, &bitmap)?;
        
        Ok(())
    }
    
    /// ビットマップを書き込み
    fn write_bitmap(device_id: u64, inode_bitmap_block: u64, bitmap: &[u8]) -> FsResult<()> {
        // デバイスマネージャからデバイスを取得
        let device_manager = crate::drivers::block::get_device_manager();
        let device = match device_manager.get_device(device_id) {
            Some(dev) => dev,
            None => {
                log::error!("アイノードビットマップ書き込み: デバイス ID {} が見つかりません", device_id);
                return Err(FsError::DeviceNotFound);
            }
        };
        
        // ブロックサイズを検証
        let block_size = device.get_block_size() as usize;
        if bitmap.len() != block_size {
            log::error!("アイノードビットマップ書き込み: サイズが不正です: 予期={}, 実際={}",
                      block_size, bitmap.len());
            return Err(FsError::InvalidSize);
        }
        
        // ブロックを書き込み
        match device.write_block(inode_bitmap_block, bitmap) {
            Ok(_) => {
                log::debug!("アイノードビットマップ書き込み: デバイス {} ブロック {} サイズ {}バイト",
                          device_id, inode_bitmap_block, bitmap.len());
                Ok(())
            },
            Err(e) => {
                log::error!("アイノードビットマップ書き込みエラー: デバイス {} ブロック {} エラー {:?}",
                          device_id, inode_bitmap_block, e);
                Err(FsError::IoError)
            }
        }
    }
} 