// Ext4 ジャーナル実装
//
// Ext4ファイルシステムのジャーナリング機能

use alloc::vec::Vec;
use super::super::{FsError, FsResult, journal as fs_journal};
use log;

/// Ext4ジャーナルディスクリプタタグ
#[derive(Debug, Clone, Copy)]
pub struct JournalDescriptorTag {
    /// ブロック番号
    pub blocknr: u32,
    /// フラグ
    pub flags: u32,
}

/// Ext4ジャーナルブロックタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum JournalBlockType {
    /// ディスクリプタブロック
    Descriptor = 0x4,
    /// コミットブロック
    Commit = 0x5,
    /// スーパーブロック V1
    SuperblockV1 = 0x1,
    /// スーパーブロック V2
    SuperblockV2 = 0x2,
    /// リボケーションブロック
    Revoke = 0x3,
}

/// Ext4ジャーナルヘッダ
#[derive(Debug, Clone, Copy)]
pub struct JournalHeader {
    /// マジックシグネチャ
    pub magic: u32,
    /// ブロックタイプ
    pub block_type: JournalBlockType,
    /// トランザクションID
    pub sequence: u32,
}

impl JournalHeader {
    /// ジャーナルヘッダをパース
    pub fn parse(data: &[u8]) -> FsResult<Self> {
        if data.len() < 12 {
            return Err(FsError::InvalidData);
        }
        
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let block_type_raw = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let sequence = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        
        let block_type = match block_type_raw {
            0x1 => JournalBlockType::SuperblockV1,
            0x2 => JournalBlockType::SuperblockV2,
            0x3 => JournalBlockType::Revoke,
            0x4 => JournalBlockType::Descriptor,
            0x5 => JournalBlockType::Commit,
            _ => return Err(FsError::InvalidData),
        };
        
        Ok(Self {
            magic,
            block_type,
            sequence,
        })
    }
    
    /// ジャーナルヘッダをシリアライズ
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(12);
        
        result.extend_from_slice(&self.magic.to_be_bytes());
        result.extend_from_slice(&(self.block_type as u32).to_be_bytes());
        result.extend_from_slice(&self.sequence.to_be_bytes());
        
        result
    }
}

/// Ext4ジャーナルスーパーブロック
#[derive(Debug, Clone)]
pub struct JournalSuperblock {
    /// ヘッダ
    pub header: JournalHeader,
    /// ジャーナルブロック数
    pub block_count: u32,
    /// 最初の使用可能なブロック
    pub first: u32,
    /// 最初の未コミットブロック
    pub first_uncommitted: u32,
    /// エラーのあるブロック
    pub errno: u32,
}

impl JournalSuperblock {
    /// ジャーナルスーパーブロックをパース
    pub fn parse(data: &[u8]) -> FsResult<Self> {
        if data.len() < 28 {
            return Err(FsError::InvalidData);
        }
        
        let header = JournalHeader::parse(&data[0..12])?;
        
        let block_count = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let first = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let first_uncommitted = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let errno = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
        
        Ok(Self {
            header,
            block_count,
            first,
            first_uncommitted,
            errno,
        })
    }
}

/// Ext4ジャーナル管理
pub struct Journal {
    /// ファイルシステムデバイスID
    device_id: u64,
    /// ジャーナルアイノード番号
    journal_inode: u32,
    /// ジャーナルのスーパーブロック
    superblock: Option<JournalSuperblock>,
}

impl Journal {
    /// 新しいジャーナルインスタンスを作成
    pub fn new(device_id: u64, journal_inode: u32) -> Self {
        Self {
            device_id,
            journal_inode,
            superblock: None,
        }
    }
    
    /// ジャーナルを初期化
    pub fn init(&mut self) -> FsResult<()> {
        log::info!("Ext4ジャーナルを初期化: デバイス={}, アイノード={}", 
                 self.device_id, self.journal_inode);
        
        // ジャーナルアイノードからブロックを取得
        let inode_data = read_inode(self.device_id, self.journal_inode)?;
        
        // アイノードからジャーナルの先頭ブロック番号を取得
        let journal_blocks = extract_inode_blocks(&inode_data)?;
        
        if journal_blocks.is_empty() {
            log::error!("ジャーナルアイノードにブロックがありません");
            return Err(FsError::InvalidData);
        }
        
        let journal_first_block = journal_blocks[0];
        
        // デバイスをオープン
        let device_manager = crate::drivers::block::get_device_manager();
        let device = match device_manager.get_device(self.device_id) {
            Some(dev) => dev,
            None => {
                log::error!("デバイス ID {} が見つかりません", self.device_id);
                return Err(FsError::DeviceNotFound);
            }
        };
        
        // ジャーナルスーパーブロックを読み込み
        let sb_data = match device.read_block(journal_first_block) {
            Ok(data) => data,
            Err(e) => {
                log::error!("ジャーナルスーパーブロック読み込みエラー: {:?}", e);
                return Err(FsError::IoError);
            }
        };
        
        // スーパーブロックを解析
        let superblock = match JournalSuperblock::parse(&sb_data) {
            Ok(sb) => sb,
            Err(e) => {
                log::error!("ジャーナルスーパーブロック解析エラー: {:?}", e);
                return Err(e);
            }
        };
        
        // スーパーブロックのマジックナンバーを確認
        if superblock.header.magic != EXT4_JOURNAL_MAGIC {
            log::error!("無効なジャーナルマジックナンバー: 0x{:X}", superblock.header.magic);
            return Err(FsError::InvalidFormat);
        }
        
        // ジャーナル情報をログ出力
        log::info!("Ext4ジャーナル: ブロック数={}, 最初のブロック={}, 未コミット={}",
                 superblock.block_count, superblock.first, superblock.first_uncommitted);
        
        // エラーがあればログ出力
        if superblock.errno != 0 {
            log::warn!("ジャーナルにエラーあり: errno={}", superblock.errno);
        }
        
        // スーパーブロックを保存
        self.superblock = Some(superblock);
        
        Ok(())
    }
    
    /// トランザクションを開始
    pub fn begin_transaction(&self) -> FsResult<u64> {
        // ファイルシステムのジャーナルマネージャを使用
        fs_journal::begin_transaction()
    }
    
    /// メタデータブロックをジャーナルに記録
    pub fn log_metadata(&self, transaction_id: u64, block_nr: u64, data: &[u8]) -> FsResult<()> {
        fs_journal::log_metadata(transaction_id, self.device_id, block_nr, data)
    }
    
    /// データブロックをジャーナルに記録
    pub fn log_data(&self, transaction_id: u64, block_nr: u64, data: &[u8]) -> FsResult<()> {
        fs_journal::log_data(transaction_id, self.device_id, block_nr, data)
    }
    
    /// トランザクションをコミット
    pub fn commit_transaction(&self, transaction_id: u64) -> FsResult<()> {
        fs_journal::commit_transaction(transaction_id)
    }
    
    /// トランザクションをアボート
    pub fn abort_transaction(&self, transaction_id: u64) -> FsResult<()> {
        fs_journal::abort_transaction(transaction_id)
    }
    
    /// ジャーナルをリカバリ
    pub fn recover(&self) -> FsResult<()> {
        log::info!("Ext4ジャーナルリカバリを開始します");
        
        // ジャーナルデバイスをオープン
        let device = DeviceHandle::open(&self.journal_path)?;
        
        // ジャーナルスーパーブロックを読み込み
        let sb_data = device.read_at(0, 1024)?;
        
        if sb_data.len() < 1024 {
            log::error!("ジャーナルスーパーブロックの読み込みに失敗");
            return Err(FsError::IoError);
        }
        
        // スーパーブロックを解析（例: マジックナンバーを確認）
        let magic = u32::from_le_bytes([sb_data[0], sb_data[1], sb_data[2], sb_data[3]]);
        if magic != EXT4_JOURNAL_MAGIC {
            log::error!("無効なジャーナルマジックナンバー: 0x{:X}", magic);
            return Err(FsError::InvalidFormat);
        }
        
        // ジャーナルのシーケンス番号
        let seq = u32::from_le_bytes([sb_data[12], sb_data[13], sb_data[14], sb_data[15]]);
        
        // リカバリの開始と終了ブロック
        let start = u32::from_le_bytes([sb_data[16], sb_data[17], sb_data[18], sb_data[19]]);
        let end = u32::from_le_bytes([sb_data[20], sb_data[21], sb_data[22], sb_data[23]]);
        
        if start == 0 || end == 0 {
            log::info!("リカバリ不要: コミット済みトランザクションなし");
            return Ok(());
        }
        
        log::info!("ジャーナルリカバリ: シーケンス={}, 開始ブロック={}, 終了ブロック={}", 
                 seq, start, end);
        
        // ジャーナルからブロックを読み込み
        let mut block_num = start;
        let mut recovered_blocks = 0;
        
        while block_num <= end {
            let block_data = device.read_block(block_num as u64)?;
            
            // ブロックヘッダを解析
            let block_type = u32::from_le_bytes([
                block_data[0], block_data[1], block_data[2], block_data[3]
            ]);
            
            // データブロックの場合
            if block_type == EXT4_JOURNAL_BLOCK_DATA {
                // ブロック情報（デバイスIDとブロック番号）を取得
                let target_device_id = u32::from_le_bytes([
                    block_data[4], block_data[5], block_data[6], block_data[7]
                ]) as u64;
                
                let target_block_num = u32::from_le_bytes([
                    block_data[8], block_data[9], block_data[10], block_data[11]
                ]) as u64;
                
                // ジャーナルのブロックを実際のデバイスに適用
                if let Err(e) = write_block_to_device(target_device_id, target_block_num, &block_data[12..]) {
                    log::error!("リカバリ中にブロック書き込みに失敗: デバイス={}, ブロック={}, エラー={:?}", 
                              target_device_id, target_block_num, e);
                    // エラーがあっても続行（ベストエフォート）
                } else {
                    recovered_blocks += 1;
                }
            }
            
            block_num += 1;
        }
        
        log::info!("Ext4ジャーナルリカバリ完了: {} ブロック復元", recovered_blocks);
        
        // ジャーナルをクリア（リカバリ完了）
        clear_journal()?;
        
        Ok(())
    }
}

/// Ext4ジャーナルフラグ
#[repr(u32)]
pub enum JournalFlag {
    /// エスケープ
    Escape = 0x1,
    /// 同じブロックの2つのタグ
    SameUUID = 0x2,
    /// 最後のタグ
    LastTag = 0x4,
    /// コミットブロック
    Commit = 0x8,
} 