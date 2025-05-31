// AetherOS ext4ファイルシステム ドライバ
//
// Linux互換ext4ファイルシステムを実装

use alloc::string::String;
use alloc::vec::Vec;
use crate::core::sync::{Mutex, RwLock};
use crate::core::fs::{FileSystem, FileSystemType, FileAttributes, OpenFlags, FileDescriptor};
use crate::core::memory::{PageSize, VirtualAddress, PhysicalAddress};
use core::sync::atomic::{AtomicU64, Ordering};

mod superblock;
mod inode;
mod extents;
mod journal;
mod bitmap;
mod dir;

use superblock::Superblock;
use inode::Inode;
use journal::Journal;

/// ext4ファイルシステムの実装
pub struct Ext4FileSystem {
    /// デバイスパス
    device_path: String,
    /// スーパーブロック
    superblock: RwLock<Superblock>,
    /// ジャーナル
    journal: RwLock<Option<Journal>>,
    /// ブロックサイズ（バイト）
    block_size: usize,
    /// マウントフラグ
    mount_flags: u32,
    /// ディスク上のiノードサイズ
    inode_size: usize,
    /// ファイルシステムがマウントされているか
    mounted: AtomicU64,
    /// iノードキャッシュ
    inode_cache: RwLock<Vec<(u32, Inode)>>,
}

/// ext4マウントオプション
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountOption {
    /// ジャーナリングを有効化
    Journal,
    /// ジャーナリングを無効化
    NoJournal,
    /// データブロックのジャーナリングを有効化
    DataJournal,
    /// データブロックの順序付けのみ
    DataOrderd,
    /// データブロックのジャーナリングなし
    DataWriteback,
    /// バリアを無効化
    NoBarrier,
    /// 自動修復を無効化
    NoRecover,
    /// ディスク同期を無効化
    Async,
    /// エラー時に再マウント（読み取り専用）
    Remount,
    /// 読み取り専用
    ReadOnly,
    /// バリアを有効化
    Barrier,
    /// iノードのユーザー拡張属性
    UserXattr,
    /// アクセス時間の更新なし
    NoAtime,
    /// 追記専用バージョニング
    JournalChecksum,
}

/// ext4特有のエラーコード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ext4Error {
    /// 無効なスーパーブロック
    InvalidSuperblock,
    /// サポートされていない機能
    UnsupportedFeature,
    /// 無効なiノード
    InvalidInode,
    /// 無効なブロック
    InvalidBlock,
    /// ジャーナルエラー
    JournalError,
    /// デバイスエラー
    DeviceError,
    /// I/Oエラー
    IoError,
    /// ファイルシステムが満杯
    NoSpace,
    /// ファイルシステムが読み取り専用
    ReadOnly,
    /// 無効なパラメータ
    InvalidArgument,
    /// 内部エラー
    InternalError,
}

impl Ext4FileSystem {
    /// 新しいext4ファイルシステムを作成
    pub fn new(device_path: &str) -> Self {
        Self {
            device_path: String::from(device_path),
            superblock: RwLock::new(Superblock::new()),
            journal: RwLock::new(None),
            block_size: 0,
            mount_flags: 0,
            inode_size: 0,
            mounted: AtomicU64::new(0),
            inode_cache: RwLock::new(Vec::new()),
        }
    }
    
    /// ext4ファイルシステムをマウント
    pub fn mount(&self, mount_flags: u32) -> Result<(), Ext4Error> {
        // すでにマウントされている場合はエラー
        if self.mounted.load(Ordering::SeqCst) != 0 {
            return Err(Ext4Error::InvalidArgument);
        }
        
        // デバイスからスーパーブロックを読み込む
        self.read_superblock()?;
        
        let sb = self.superblock.read().unwrap();
        
        // スーパーブロックを検証
        if !sb.is_valid_ext4() {
            return Err(Ext4Error::InvalidSuperblock);
        }
        
        // サポートされていない機能をチェック
        if !self.check_supported_features(&sb) {
            return Err(Ext4Error::UnsupportedFeature);
        }
        
        // ブロックサイズを計算
        let block_size = 1024 << sb.get_log_block_size();
        drop(sb);
        
        // 内部状態を設定
        self.block_size = block_size;
        self.mount_flags = mount_flags;
        
        // フラグがread-onlyでなければファイルシステム整合性チェック
        if (mount_flags & super::MOUNT_READ_ONLY) == 0 {
            self.check_consistency()?;
        }
        
        // ジャーナル初期化
        self.init_journal()?;
        
        // マウント状態を設定
        self.mounted.store(1, Ordering::SeqCst);
        
        Ok(())
    }
    
    /// スーパーブロックを読み込む
    fn read_superblock(&self) -> Result<(), Ext4Error> {
        const SUPERBLOCK_OFFSET: u64 = 1024;
        const SUPERBLOCK_SIZE: usize = 1024;

        log::info!("ext4: デバイス '{}' からスーパーブロック読み込み開始", self.device_path);

        // 1. ブロックデバイスからスーパーブロックを読み込み
        let mut buffer = vec![0u8; SUPERBLOCK_SIZE];
        let sector_offset = SUPERBLOCK_OFFSET / 512;
        let sector_count = (SUPERBLOCK_SIZE + 511) / 512;

        match crate::drivers::block::read_sectors(&self.device_path, sector_offset, &mut buffer[..sector_count * 512]) {
            Ok(_) => {
                log::debug!("ext4: スーパーブロック読み込み成功: {}バイト", buffer.len());
                
                // 2. スーパーブロック構造体の解析
                let sb_data = &buffer[SUPERBLOCK_OFFSET % 512..];
                if sb_data.len() < 1024 {
                    log::error!("ext4: スーパーブロックデータ不足: {}バイト", sb_data.len());
                    return Err(Ext4Error::InvalidSuperblock);
                }
                
                // 3. マジックナンバーの確認
                let magic = u16::from_le_bytes([sb_data[56], sb_data[57]]);
                if magic != superblock::EXT4_SUPER_MAGIC {
                    log::error!("ext4: 無効なマジックナンバー: 0x{:04x} (期待値: 0x{:04x})", 
                               magic, superblock::EXT4_SUPER_MAGIC);
                    return Err(Ext4Error::InvalidSuperblock);
                }
                
                // 4. スーパーブロック構造体の構築
                let mut sb = Superblock::new();
                
                // 基本フィールド
                sb.s_inodes_count = u32::from_le_bytes([sb_data[0], sb_data[1], sb_data[2], sb_data[3]]);
                sb.s_blocks_count_lo = u32::from_le_bytes([sb_data[4], sb_data[5], sb_data[6], sb_data[7]]);
                sb.s_r_blocks_count_lo = u32::from_le_bytes([sb_data[8], sb_data[9], sb_data[10], sb_data[11]]);
                sb.s_free_blocks_count_lo = u32::from_le_bytes([sb_data[12], sb_data[13], sb_data[14], sb_data[15]]);
                sb.s_free_inodes_count = u32::from_le_bytes([sb_data[16], sb_data[17], sb_data[18], sb_data[19]]);
                sb.s_first_data_block = u32::from_le_bytes([sb_data[20], sb_data[21], sb_data[22], sb_data[23]]);
                sb.s_log_block_size = u32::from_le_bytes([sb_data[24], sb_data[25], sb_data[26], sb_data[27]]);
                sb.s_log_cluster_size = u32::from_le_bytes([sb_data[28], sb_data[29], sb_data[30], sb_data[31]]);
                sb.s_blocks_per_group = u32::from_le_bytes([sb_data[32], sb_data[33], sb_data[34], sb_data[35]]);
                sb.s_clusters_per_group = u32::from_le_bytes([sb_data[36], sb_data[37], sb_data[38], sb_data[39]]);
                sb.s_inodes_per_group = u32::from_le_bytes([sb_data[40], sb_data[41], sb_data[42], sb_data[43]]);
                sb.s_mtime = u32::from_le_bytes([sb_data[44], sb_data[45], sb_data[46], sb_data[47]]);
                sb.s_wtime = u32::from_le_bytes([sb_data[48], sb_data[49], sb_data[50], sb_data[51]]);
                sb.s_mnt_count = u16::from_le_bytes([sb_data[52], sb_data[53]]);
                sb.s_max_mnt_count = u16::from_le_bytes([sb_data[54], sb_data[55]]);
                sb.s_magic = magic;
                sb.s_state = u16::from_le_bytes([sb_data[58], sb_data[59]]);
                sb.s_errors = u16::from_le_bytes([sb_data[60], sb_data[61]]);
                sb.s_minor_rev_level = u16::from_le_bytes([sb_data[62], sb_data[63]]);
                
                // タイムスタンプと revision
                sb.s_lastcheck = u32::from_le_bytes([sb_data[64], sb_data[65], sb_data[66], sb_data[67]]);
                sb.s_checkinterval = u32::from_le_bytes([sb_data[68], sb_data[69], sb_data[70], sb_data[71]]);
                sb.s_creator_os = u32::from_le_bytes([sb_data[72], sb_data[73], sb_data[74], sb_data[75]]);
                sb.s_rev_level = u32::from_le_bytes([sb_data[76], sb_data[77], sb_data[78], sb_data[79]]);
                sb.s_def_resuid = u16::from_le_bytes([sb_data[80], sb_data[81]]);
                sb.s_def_resgid = u16::from_le_bytes([sb_data[82], sb_data[83]]);
                
                // 拡張フィールド（EXT4_DYNAMIC_REV以上の場合）
                if sb.s_rev_level >= superblock::EXT4_DYNAMIC_REV {
                    sb.s_first_ino = u32::from_le_bytes([sb_data[84], sb_data[85], sb_data[86], sb_data[87]]);
                    sb.s_inode_size = u16::from_le_bytes([sb_data[88], sb_data[89]]);
                    sb.s_block_group_nr = u16::from_le_bytes([sb_data[90], sb_data[91]]);
                    sb.s_feature_compat = u32::from_le_bytes([sb_data[92], sb_data[93], sb_data[94], sb_data[95]]);
                    sb.s_feature_incompat = u32::from_le_bytes([sb_data[96], sb_data[97], sb_data[98], sb_data[99]]);
                    sb.s_feature_ro_compat = u32::from_le_bytes([sb_data[100], sb_data[101], sb_data[102], sb_data[103]]);
                    
                    // UUID (16バイト)
                    sb.s_uuid.copy_from_slice(&sb_data[104..120]);
                    
                    // ボリューム名 (16バイト)
                    sb.s_volume_name.copy_from_slice(&sb_data[120..136]);
                    
                    // 最後のマウントパス (64バイト)
                    sb.s_last_mounted.copy_from_slice(&sb_data[136..200]);
                    
                    // アルゴリズムビットマップ
                    sb.s_algorithm_usage_bitmap = u32::from_le_bytes([sb_data[200], sb_data[201], sb_data[202], sb_data[203]]);
                } else {
                    // 旧バージョンのデフォルト値
                    sb.s_first_ino = 11;
                    sb.s_inode_size = 128;
                    sb.s_feature_compat = 0;
                    sb.s_feature_incompat = 0;
                    sb.s_feature_ro_compat = 0;
                }
                
                // 5. スーパーブロックの妥当性検証
                if sb.s_log_block_size > 16 {
                    log::error!("ext4: 無効なブロックサイズ指数: {}", sb.s_log_block_size);
                    return Err(Ext4Error::InvalidSuperblock);
                }
                
                let block_size = 1024u32 << sb.s_log_block_size;
                if block_size < 1024 || block_size > 65536 {
                    log::error!("ext4: サポートされていないブロックサイズ: {}バイト", block_size);
                    return Err(Ext4Error::UnsupportedFeature);
                }
                
                if sb.s_inodes_per_group == 0 || sb.s_blocks_per_group == 0 {
                    log::error!("ext4: 無効なグループサイズ: inode/group={}, blocks/group={}", 
                               sb.s_inodes_per_group, sb.s_blocks_per_group);
                    return Err(Ext4Error::InvalidSuperblock);
                }
                
                if sb.s_inode_size < 128 || sb.s_inode_size > block_size as u16 {
                    log::error!("ext4: 無効なiノードサイズ: {}バイト", sb.s_inode_size);
                    return Err(Ext4Error::InvalidSuperblock);
                }
                
                // 6. スーパーブロックを保存
                let mut sb_guard = self.superblock.write().unwrap();
                *sb_guard = sb;
                drop(sb_guard);
                
                // 7. 内部状態の更新
                self.block_size = block_size as usize;
                self.inode_size = sb.s_inode_size as usize;
                
                log::info!("ext4: スーパーブロック解析完了 - ブロックサイズ={}KB, iノードサイズ={}B, グループ数={}", 
                          block_size / 1024, sb.s_inode_size, 
                          (sb.s_blocks_count_lo + sb.s_blocks_per_group - 1) / sb.s_blocks_per_group);
                
                Ok(())
            }
            Err(e) => {
                log::error!("ext4: デバイス '{}' からの読み込みエラー: {:?}", self.device_path, e);
                Err(Ext4Error::DeviceError)
            }
        }
    }
    
    /// サポートされている機能をチェック
    fn check_supported_features(&self, sb: &Superblock) -> bool {
        // 必須機能をチェック
        if sb.has_unsupported_required_features() {
            return false;
        }
        
        // 読み取り専用マウントならread-only互換機能のみチェック
        if (self.mount_flags & super::MOUNT_READ_ONLY) != 0 {
            return !sb.has_unsupported_ro_features();
        }
        
        // 読み書きマウントなら読み書き互換性もチェック
        !sb.has_unsupported_rw_features()
    }
    
    /// ファイルシステム整合性チェック
    fn check_consistency(&self) -> Result<(), Ext4Error> {
        let sb = self.superblock.read().unwrap();
        
        // クリーンにアンマウントされていないかチェック
        if !sb.is_clean() {
            // ジャーナルによる回復が必要
            if sb.has_journal() {
                // ジャーナルによる回復を実行（リカバリー）
                return self.recover_journal();
            } else {
                // ジャーナルがなく、整合性がない場合はエラー
                return Err(Ext4Error::JournalError);
            }
        }
        
        Ok(())
    }
    
    /// ジャーナルを初期化
    fn init_journal(&self) -> Result<(), Ext4Error> {
        let sb = self.superblock.read().unwrap();
        
        if sb.has_journal() {
            let journal_inode = sb.get_journal_inode();
            let mut journal = self.journal.write().unwrap();
            
            // ジャーナルを初期化
            *journal = Some(Journal::new(journal_inode));
            
            // ジャーナルをロード
            if let Some(ref mut j) = *journal {
                j.load()?;
            }
        }
        
        Ok(())
    }
    
    /// ジャーナルによるリカバリー
    fn recover_journal(&self) -> Result<(), Ext4Error> {
        // ジャーナルがあれば回復を試みる
        if let Some(ref mut journal) = *self.journal.write().unwrap() {
            journal.recover()?;
        }
        
        Ok(())
    }
    
    /// ext4ファイルシステムをアンマウント
    pub fn unmount(&self) -> Result<(), Ext4Error> {
        // マウントされていなければエラー
        if self.mounted.load(Ordering::SeqCst) == 0 {
            return Err(Ext4Error::InvalidArgument);
        }
        
        // 読み書きマウントならジャーナルをコミット
        if (self.mount_flags & super::MOUNT_READ_ONLY) == 0 {
            if let Some(ref mut journal) = *self.journal.write().unwrap() {
                journal.commit()?;
            }
        }
        
        // スーパーブロックをフラッシュ
        let mut sb = self.superblock.write().unwrap();
        sb.mark_clean();
        self.write_superblock(&sb)?;
        
        // マウント状態を解除
        self.mounted.store(0, Ordering::SeqCst);
        
        Ok(())
    }
    
    /// スーパーブロックを書き込む
    fn write_superblock(&self, sb: &Superblock) -> Result<(), Ext4Error> {
        // デバイスに書き込む実装（スタブ）
        Ok(())
    }
    
    /// ファイルを開く
    pub fn open(&self, path: &str, flags: OpenFlags) -> Result<FileDescriptor, Ext4Error> {
        // マウントされていなければエラー
        if self.mounted.load(Ordering::SeqCst) == 0 {
            return Err(Ext4Error::InvalidArgument);
        }
        
        // 読み取り専用マウントで書き込みフラグがあればエラー
        if (self.mount_flags & super::MOUNT_READ_ONLY) != 0 && 
           (flags & OpenFlags::WRITE).bits() != 0 {
            return Err(Ext4Error::ReadOnly);
        }
        
        // パスからiノードを検索
        let inode_num = self.lookup_path(path)?;
        
        // iノードを取得
        let inode = self.get_inode(inode_num)?;
        
        // ディレクトリをファイルとして開けない
        if inode.is_directory() && (flags & OpenFlags::DIRECTORY).bits() == 0 {
            return Err(Ext4Error::InvalidArgument);
        }
        
        // ファイルオープン処理
        // ...（実装省略）
        
        // ファイルディスクリプタを作成して返す
        let fd = FileDescriptor::new(inode_num as u64);
        Ok(fd)
    }
    
    /// パスからiノードを検索
    fn lookup_path(&self, path: &str) -> Result<u32, Ext4Error> {
        let components = path.split('/').filter(|c| !c.is_empty());
        
        // ルートiノード（通常は2）から開始
        let mut current_inode = 2u32;
        
        for component in components {
            // 現在のiノードがディレクトリであることを確認
            let inode = self.get_inode(current_inode)?;
            if !inode.is_directory() {
                return Err(Ext4Error::InvalidArgument);
            }
            
            // ディレクトリエントリから次のiノードを検索
            current_inode = dir::lookup_directory(&inode, component)?;
        }
        
        Ok(current_inode)
    }
    
    /// iノードを取得
    fn get_inode(&self, inode_num: u32) -> Result<Inode, Ext4Error> {
        // キャッシュを確認
        let cache = self.inode_cache.read().unwrap();
        for (num, inode) in cache.iter() {
            if *num == inode_num {
                return Ok(inode.clone());
            }
        }
        drop(cache);
        
        // キャッシュにない場合はディスクから読み込む
        let sb = self.superblock.read().unwrap();
        let inode = inode::read_inode(&sb, inode_num)?;
        
        // キャッシュに追加
        let mut cache = self.inode_cache.write().unwrap();
        cache.push((inode_num, inode.clone()));
        
        // キャッシュが大きすぎる場合は古いエントリを削除
        if cache.len() > 100 {
            cache.remove(0);
        }
        
        Ok(inode)
    }
    
    /// ファイルからデータを読み込む
    pub fn read(&self, fd: &FileDescriptor, buffer: &mut [u8], offset: u64) -> Result<usize, Ext4Error> {
        // マウントされていなければエラー
        if self.mounted.load(Ordering::SeqCst) == 0 {
            return Err(Ext4Error::InvalidArgument);
        }
        
        // ファイルディスクリプタからiノードを取得
        let inode_num = fd.get_inode() as u32;
        let inode = self.get_inode(inode_num)?;
        
        // ファイルサイズを確認
        if offset >= inode.get_size() {
            return Ok(0); // ファイル終端
        }
        
        // 読み込むサイズを計算
        let remaining = inode.get_size() - offset;
        let read_size = core::cmp::min(buffer.len() as u64, remaining) as usize;
        
        // ファイルデータを読み込む
        let bytes_read = self.read_file_data(&inode, buffer, offset)?;
        
        Ok(bytes_read)
    }
    
    /// ファイルデータを読み込む
    fn read_file_data(&self, inode: &Inode, buffer: &mut [u8], offset: u64) -> Result<usize, Ext4Error> {
        // 読み込むブロックを特定
        let start_block = (offset / self.block_size as u64) as u32;
        let end_block = ((offset + buffer.len() as u64 - 1) / self.block_size as u64) as u32;
        
        let mut bytes_read = 0;
        let mut buffer_offset = 0;
        
        // 各ブロックを読み込む完全実装
        for block_idx in start_block..=end_block {
            // 物理ブロック番号を取得
            let phys_block = inode.get_physical_block(block_idx)?;
            
            // ブロックが割り当てられていない場合はゼロで埋める
            if phys_block == 0 {
                let sparse_size = core::cmp::min(
                    self.block_size - ((offset as usize + buffer_offset) % self.block_size),
                    buffer.len() - buffer_offset
                );
                
                for i in 0..sparse_size {
                    buffer[buffer_offset + i] = 0;
                }
                
                bytes_read += sparse_size;
                buffer_offset += sparse_size;
                continue;
            }
            
            // ブロックをデバイスから読み込む完全実装
            let mut block_buffer = vec![0u8; self.block_size];
            self.read_block(phys_block, &mut block_buffer)?;
            
            // ブロック内でのオフセットとサイズを計算
            let block_start_offset = if block_idx == start_block {
                (offset % self.block_size as u64) as usize
            } else {
                0
            };
            
            let available_in_block = self.block_size - block_start_offset;
            let copy_size = core::cmp::min(
                available_in_block,
                buffer.len() - buffer_offset
            );
            
            // データをコピー
            buffer[buffer_offset..buffer_offset + copy_size]
                .copy_from_slice(&block_buffer[block_start_offset..block_start_offset + copy_size]);
            
            bytes_read += copy_size;
            buffer_offset += copy_size;
            
            // バッファが満杯になったら終了
            if buffer_offset >= buffer.len() {
                break;
            }
        }
        
        Ok(bytes_read)
    }
    
    /// ブロックをデバイスから読み込む
    fn read_block(&self, block_number: u32, buffer: &mut [u8]) -> Result<(), Ext4Error> {
        if buffer.len() != self.block_size {
            return Err(Ext4Error::InvalidArgument);
        }
        
        // LBA（論理ブロックアドレス）計算
        let lba = block_number as u64 * (self.block_size / 512) as u64;
        
        // ブロックデバイスから読み込み
        match crate::drivers::block::read_sectors(&self.device_path, lba, buffer) {
            Ok(_) => Ok(()),
            Err(_) => Err(Ext4Error::IoError),
        }
    }
    
    /// ファイルにデータを書き込む
    pub fn write(&self, fd: &FileDescriptor, buffer: &[u8], offset: u64) -> Result<usize, Ext4Error> {
        // マウントされていなければエラー
        if self.mounted.load(Ordering::SeqCst) == 0 {
            return Err(Ext4Error::InvalidArgument);
        }
        
        // 読み取り専用マウントならエラー
        if (self.mount_flags & super::MOUNT_READ_ONLY) != 0 {
            return Err(Ext4Error::ReadOnly);
        }
        
        // ファイルディスクリプタからiノードを取得
        let inode_num = fd.get_inode() as u32;
        let mut inode = self.get_inode(inode_num)?;
        
        // ジャーナルトランザクションを開始
        if let Some(ref mut journal) = *self.journal.write().unwrap() {
            journal.start_transaction()?;
        }
        
        // ファイルサイズを拡張する必要があるか
        let end_offset = offset + buffer.len() as u64;
        if end_offset > inode.get_size() {
            inode.set_size(end_offset);
        }
        
        // ファイルデータを書き込む
        let bytes_written = self.write_file_data(&mut inode, buffer, offset)?;
        
        // iノードを更新
        inode.set_mtime(self.get_current_time());
        self.update_inode(&inode)?;
        
        // ジャーナルトランザクションをコミット
        if let Some(ref mut journal) = *self.journal.write().unwrap() {
            journal.commit_transaction()?;
        }
        
        Ok(bytes_written)
    }
    
    /// ファイルデータを書き込む
    fn write_file_data(&self, inode: &mut Inode, buffer: &[u8], offset: u64) -> Result<usize, Ext4Error> {
        // 書き込むブロックを特定
        let start_block = (offset / self.block_size as u64) as u32;
        let end_block = ((offset + buffer.len() as u64 - 1) / self.block_size as u64) as u32;
        
        let mut bytes_written = 0;
        let mut buffer_offset = 0;
        
        // 各ブロックを書き込む完全実装
        for block_idx in start_block..=end_block {
            // 物理ブロック番号を取得、必要なら割り当て
            let mut phys_block = inode.get_physical_block(block_idx)?;
            if phys_block == 0 {
                phys_block = self.allocate_block()?;
                inode.set_physical_block(block_idx, phys_block)?;
            }
            
            // ブロック内でのオフセットとサイズを計算
            let block_start_offset = if block_idx == start_block {
                (offset % self.block_size as u64) as usize
            } else {
                0
            };
            
            let available_in_block = self.block_size - block_start_offset;
            let write_size = core::cmp::min(
                available_in_block,
                buffer.len() - buffer_offset
            );
            
            // 部分書き込みの場合、既存ブロックデータを読み込む
            let mut block_buffer = vec![0u8; self.block_size];
            if block_start_offset > 0 || write_size < self.block_size {
                self.read_block(phys_block, &mut block_buffer)?;
            }
            
            // 新しいデータを適切な位置にコピー
            block_buffer[block_start_offset..block_start_offset + write_size]
                .copy_from_slice(&buffer[buffer_offset..buffer_offset + write_size]);
            
            // ブロックをデバイスに書き込み
            self.write_block(phys_block, &block_buffer)?;
            
            bytes_written += write_size;
            buffer_offset += write_size;
            
            // バッファが完了したら終了
            if buffer_offset >= buffer.len() {
                break;
            }
        }
        
        Ok(bytes_written)
    }
    
    /// ブロックをデバイスに書き込む
    fn write_block(&self, block_number: u32, buffer: &[u8]) -> Result<(), Ext4Error> {
        if buffer.len() != self.block_size {
            return Err(Ext4Error::InvalidArgument);
        }
        
        // LBA（論理ブロックアドレス）計算
        let lba = block_number as u64 * (self.block_size / 512) as u64;
        
        // ブロックデバイスに書き込み
        match crate::drivers::block::write_sectors(&self.device_path, lba, buffer) {
            Ok(_) => {
                // ライトキャッシュの同期（バリア）
                if (self.mount_flags & super::MOUNT_BARRIER) != 0 {
                    crate::drivers::block::sync_device(&self.device_path)?;
                }
                Ok(())
            },
            Err(_) => Err(Ext4Error::IoError),
        }
    }
    
    /// ブロックを割り当てる
    fn allocate_block(&self) -> Result<u32, Ext4Error> {
        // ブロックグループビットマップから空きブロックを検索して割り当ての完全実装
        
        let sb = self.superblock.read().unwrap();
        let blocks_per_group = sb.get_blocks_per_group();
        let block_groups = (sb.get_total_blocks() + blocks_per_group - 1) / blocks_per_group;
        
        // 各ブロックグループを順次検索
        for group_idx in 0..block_groups {
            // ブロックグループディスクリプタを読み込み
            let group_desc = self.read_block_group_descriptor(group_idx)?;
            
            // 空きブロックがあるかチェック
            if group_desc.get_free_blocks_count() == 0 {
                continue;
            }
            
            // ブロックビットマップを読み込み
            let bitmap_block = group_desc.get_block_bitmap_block();
            let mut bitmap = vec![0u8; self.block_size];
            self.read_block(bitmap_block, &mut bitmap)?;
            
            // 空きブロックを検索
            for byte_idx in 0..(self.block_size) {
                if bitmap[byte_idx] == 0xFF {
                    continue; // すべてのビットが設定済み
                }
                
                // バイト内で最初の空きビットを検索
                for bit_idx in 0..8 {
                    if (bitmap[byte_idx] & (1 << bit_idx)) == 0 {
                        // 空きブロック発見
                        let block_in_group = byte_idx * 8 + bit_idx;
                        let global_block = group_idx * blocks_per_group + block_in_group as u32;
                        
                        // ビットマップを更新
                        bitmap[byte_idx] |= 1 << bit_idx;
                        self.write_block(bitmap_block, &bitmap)?;
                        
                        // ブロックグループディスクリプタ更新
                        let mut updated_desc = group_desc;
                        updated_desc.set_free_blocks_count(updated_desc.get_free_blocks_count() - 1);
                        self.write_block_group_descriptor(group_idx, &updated_desc)?;
                        
                        // スーパーブロックの空きブロック数更新
                        let mut sb_mut = self.superblock.write().unwrap();
                        sb_mut.set_free_blocks_count(sb_mut.get_free_blocks_count() - 1);
                        self.write_superblock(&sb_mut)?;
                        
                        return Ok(global_block);
                    }
                }
            }
        }
        
        Err(Ext4Error::NoSpace)
    }
    
    /// ブロックグループディスクリプタを読み込み
    fn read_block_group_descriptor(&self, group_idx: u32) -> Result<BlockGroupDescriptor, Ext4Error> {
        let sb = self.superblock.read().unwrap();
        let desc_per_block = self.block_size / sb.get_desc_size();
        
        // ディスクリプタテーブルの位置計算
        let desc_table_block = if self.block_size == 1024 { 2 } else { 1 };
        let desc_block = desc_table_block + (group_idx / desc_per_block as u32);
        let desc_offset = (group_idx % desc_per_block as u32) * sb.get_desc_size();
        
        // ブロックを読み込み
        let mut block_buffer = vec![0u8; self.block_size];
        self.read_block(desc_block, &mut block_buffer)?;
        
        // ディスクリプタを解析
        let desc_data = &block_buffer[desc_offset as usize..(desc_offset + sb.get_desc_size()) as usize];
        Ok(BlockGroupDescriptor::from_bytes(desc_data))
    }
    
    /// ブロックグループディスクリプタを書き込み
    fn write_block_group_descriptor(&self, group_idx: u32, descriptor: &BlockGroupDescriptor) -> Result<(), Ext4Error> {
        let sb = self.superblock.read().unwrap();
        let desc_per_block = self.block_size / sb.get_desc_size();
        
        // ディスクリプタテーブルの位置計算
        let desc_table_block = if self.block_size == 1024 { 2 } else { 1 };
        let desc_block = desc_table_block + (group_idx / desc_per_block as u32);
        let desc_offset = (group_idx % desc_per_block as u32) * sb.get_desc_size();
        
        // 既存ブロックを読み込み
        let mut block_buffer = vec![0u8; self.block_size];
        self.read_block(desc_block, &mut block_buffer)?;
        
        // ディスクリプタデータを更新
        let desc_bytes = descriptor.to_bytes();
        block_buffer[desc_offset as usize..(desc_offset + sb.get_desc_size()) as usize]
            .copy_from_slice(&desc_bytes);
        
        // ブロックを書き込み
        self.write_block(desc_block, &block_buffer)?;
        
        Ok(())
    }
    
    /// iノードを更新
    fn update_inode(&self, inode: &Inode) -> Result<(), Ext4Error> {
        // iノードをディスクに書き込む完全実装
        
        let sb = self.superblock.read().unwrap();
        let inode_num = inode.get_number();
        
        // iノードが属するブロックグループを計算
        let inodes_per_group = sb.get_inodes_per_group();
        let group_idx = (inode_num - 1) / inodes_per_group;
        let inode_idx_in_group = (inode_num - 1) % inodes_per_group;
        
        // ブロックグループディスクリプタを読み込み
        let group_desc = self.read_block_group_descriptor(group_idx)?;
        
        // iノードテーブルの位置を計算
        let inode_table_block = group_desc.get_inode_table_block();
        let inodes_per_block = self.block_size / self.inode_size;
        let block_offset = inode_idx_in_group / inodes_per_block as u32;
        let inode_offset_in_block = (inode_idx_in_group % inodes_per_block as u32) * self.inode_size as u32;
        
        // iノードが含まれるブロックを読み込み
        let target_block = inode_table_block + block_offset;
        let mut block_buffer = vec![0u8; self.block_size];
        self.read_block(target_block, &mut block_buffer)?;
        
        // iノードデータをシリアライズ
        let inode_bytes = inode.to_bytes(self.inode_size);
        
        // ブロック内の適切な位置にiノードデータをコピー
        let start_offset = inode_offset_in_block as usize;
        let end_offset = start_offset + self.inode_size;
        block_buffer[start_offset..end_offset].copy_from_slice(&inode_bytes);
        
        // ブロックをディスクに書き込み
        self.write_block(target_block, &block_buffer)?;
        
        // ジャーナルにトランザクションを記録
        if let Some(ref mut journal) = *self.journal.write().unwrap() {
            journal.log_inode_update(inode_num, &inode_bytes)?;
        }
        
        // キャッシュも更新
        let mut cache = self.inode_cache.write().unwrap();
        
        // 既存のキャッシュエントリを検索
        for (cached_num, cached_inode) in cache.iter_mut() {
            if *cached_num == inode_num {
                *cached_inode = inode.clone();
                return Ok(());
            }
        }
        
        // キャッシュにない場合は追加（LRU方式でキャッシュサイズ制限）
        const MAX_CACHE_SIZE: usize = 1024;
        if cache.len() >= MAX_CACHE_SIZE {
            // 最も古いエントリを削除
            cache.remove(0);
        }
        cache.push((inode_num, inode.clone()));
        
        log::debug!("iノード {} を更新しました", inode_num);
        Ok(())
    }
    
    /// 現在時刻を取得（UNIXタイムスタンプ）
    fn get_current_time(&self) -> u32 {
        // システムタイマーから現在時刻を取得
        let current_ns = crate::time::current_time_ns();
        
        // ナノ秒を秒に変換（UNIXタイムスタンプ）
        let unix_timestamp = current_ns / 1_000_000_000;
        
        // 32ビットに収まるよう調整（2038年問題対応は別途必要）
        if unix_timestamp > u32::MAX as u64 {
            log::warn!("タイムスタンプが32ビットを超えています: {}", unix_timestamp);
            u32::MAX
        } else {
            unix_timestamp as u32
        }
    }
}

/// ext4ファイルシステム型の登録
pub fn register() -> Result<(), &'static str> {
    super::register_filesystem(FileSystemType {
        name: "ext4",
        create: |device| {
            let fs = Ext4FileSystem::new(device);
            Ok(fs)
        },
    })
}

/// ext4ファイルシステムタイプの取得
pub fn get_fs_type() -> FileSystemType {
    FileSystemType {
        name: "ext4",
        create: |device| {
            let fs = Ext4FileSystem::new(device);
            Ok(fs)
        },
    }
} 