// ファイルシステムジャーナリング実装
//
// システムクラッシュからの回復とデータ整合性を保証するジャーナル機能

use core::sync::atomic::{AtomicU64, Ordering};
use alloc::string::String;
use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::collections::VecDeque;
use spin::RwLock;
use super::{FsError, FsResult};
use device::DeviceHandle;

/// ジャーナルレコードタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalRecordType {
    /// トランザクション開始
    Begin,
    /// メタデータ更新
    Metadata,
    /// データブロック更新
    Data,
    /// トランザクションコミット
    Commit,
    /// チェックポイント（ジャーナルの切り詰め）
    Checkpoint,
}

/// ジャーナルレコードヘッダ
#[derive(Debug, Clone)]
pub struct JournalRecordHeader {
    /// レコードタイプ
    pub record_type: JournalRecordType,
    /// トランザクションID
    pub transaction_id: u64,
    /// デバイスID
    pub device_id: u64,
    /// ブロック番号（データブロック/メタデータブロックの場合）
    pub block_number: Option<u64>,
    /// レコードサイズ
    pub size: u32,
    /// CRC32チェックサム
    pub checksum: u32,
}

/// ジャーナルレコード
#[derive(Debug, Clone)]
pub struct JournalRecord {
    /// レコードヘッダ
    pub header: JournalRecordHeader,
    /// レコードデータ
    pub data: Vec<u8>,
}

/// ジャーナル状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalState {
    /// 初期化中
    Initializing,
    /// アイドル状態
    Idle,
    /// トランザクション実行中
    InTransaction,
    /// リカバリ中
    Recovering,
    /// エラー状態
    Error,
}

/// ジャーナルトランザクション
struct JournalTransaction {
    /// トランザクションID
    id: u64,
    /// 開始時間（UNIX時間）
    start_time: u64,
    /// レコード
    records: Vec<JournalRecord>,
    /// コミット済みフラグ
    committed: bool,
}

impl JournalTransaction {
    /// 新しいトランザクションを作成
    fn new(id: u64) -> Self {
        Self {
            id,
            start_time: current_time(),
            records: Vec::new(),
            committed: false,
        }
    }
    
    /// レコードを追加
    fn add_record(&mut self, record_type: JournalRecordType, device_id: u64, block_number: Option<u64>, data: Vec<u8>) {
        let header = JournalRecordHeader {
            record_type,
            transaction_id: self.id,
            device_id,
            block_number,
            size: data.len() as u32,
            checksum: calculate_checksum(&data),
        };
        
        self.records.push(JournalRecord {
            header,
            data,
        });
    }
    
    /// トランザクションをシリアライズ
    fn serialize(&self) -> Vec<u8> {
        let mut output = Vec::new();
        
        // トランザクション開始レコード
        let begin_header = JournalRecordHeader {
            record_type: JournalRecordType::Begin,
            transaction_id: self.id,
            device_id: 0,
            block_number: None,
            size: 0,
            checksum: 0,
        };
        
        serialize_record_header(&begin_header, &mut output);
        
        // 各レコードをシリアライズ
        for record in &self.records {
            serialize_record_header(&record.header, &mut output);
            output.extend_from_slice(&record.data);
        }
        
        // トランザクションコミットレコード
        let commit_header = JournalRecordHeader {
            record_type: JournalRecordType::Commit,
            transaction_id: self.id,
            device_id: 0,
            block_number: None,
            size: 0,
            checksum: 0,
        };
        
        serialize_record_header(&commit_header, &mut output);
        
        output
    }
}

/// ジャーナルマネージャ
pub struct JournalManager {
    /// ジャーナルデバイスパス
    device_path: String,
    /// 現在の状態
    state: RwLock<JournalState>,
    /// 現在のトランザクション
    current_transaction: RwLock<Option<JournalTransaction>>,
    /// コミット済みトランザクションキュー（デバイスに書き込み待ち）
    commit_queue: RwLock<VecDeque<JournalTransaction>>,
    /// 次のトランザクションID
    next_transaction_id: AtomicU64,
    /// ジャーナル最大サイズ（バイト単位）
    max_size: u64,
    /// 現在のジャーナルサイズ
    current_size: AtomicU64,
    /// チェックポイント閾値（この割合を超えるとチェックポイントが必要）
    checkpoint_threshold: f32,
    /// ジャーナルブロックサイズ
    block_size: u32,
}

impl JournalManager {
    /// 新しいジャーナルマネージャを作成
    pub fn new(device_path: &str, max_size: u64, block_size: u32) -> Self {
        Self {
            device_path: device_path.to_string(),
            state: RwLock::new(JournalState::Initializing),
            current_transaction: RwLock::new(None),
            commit_queue: RwLock::new(VecDeque::new()),
            next_transaction_id: AtomicU64::new(1),
            max_size,
            current_size: AtomicU64::new(0),
            checkpoint_threshold: 0.75, // 75%を超えるとチェックポイント
            block_size,
        }
    }
    
    /// ジャーナルを初期化
    pub fn init(&self) -> FsResult<()> {
        let mut state = self.state.write();
        
        if *state != JournalState::Initializing {
            return Err(FsError::InvalidData);
        }
        
        // ジャーナルデバイスをオープン
        let mut device = match DeviceHandle::open(&self.device_path) {
            Ok(dev) => dev,
            Err(e) => {
                log::error!("ジャーナルデバイス {} のオープンに失敗: {:?}", self.device_path, e);
                return Err(e);
            }
        };
        
        // ジャーナルデバイスが適切なサイズを持っているか確認
        let device_size = device.get_size()?;
        if device_size < MIN_JOURNAL_SIZE {
            log::error!("ジャーナルデバイスが小さすぎます: {} バイト (最小 {} バイト)",
                      device_size, MIN_JOURNAL_SIZE);
            return Err(FsError::InvalidSize);
        }
        
        // ジャーナルヘッダを読み込み
        let header_data = device.read_at(0, std::mem::size_of::<JournalHeader>())?;
        
        if header_data.len() < std::mem::size_of::<JournalHeader>() {
            log::error!("ジャーナルヘッダの読み込みに失敗: 不完全なデータ");
            return Err(FsError::IoError);
        }
        
        // ヘッダーデータをデシリアライズ
        let header = deserialize_header(&header_data)?;
        
        // マジックナンバーをチェック
        if header.magic != JOURNAL_MAGIC {
            log::error!("ジャーナルヘッダの不正なマジックナンバー: 0x{:X}", header.magic);
            return Err(FsError::InvalidFormat);
        }
        
        // チェックサムを検証
        let calculated_checksum = calculate_crc32(&header_data[4..]); // マジック後のデータからCRC計算
        if calculated_checksum != header.checksum {
            log::error!("ジャーナルヘッダのチェックサムが一致しません: 計算値={:X}, ヘッダ値={:X}",
                      calculated_checksum, header.checksum);
            return Err(FsError::InvalidChecksum);
        }
        
        // リカバリが必要か確認
        let needs_recovery = check_recovery_needed(&self.device_path);
        
        if needs_recovery {
            *state = JournalState::Recovering;
            self.recover()?;
        }
        
        *state = JournalState::Idle;
        log::info!("ジャーナル初期化完了: {}", self.device_path);
        
        Ok(())
    }
    
    /// トランザクションを開始
    pub fn begin_transaction(&self) -> FsResult<u64> {
        let mut state = self.state.write();
        
        if *state != JournalState::Idle {
            return Err(FsError::InvalidData);
        }
        
        *state = JournalState::InTransaction;
        
        let transaction_id = self.next_transaction_id.fetch_add(1, Ordering::SeqCst);
        let transaction = JournalTransaction::new(transaction_id);
        
        *self.current_transaction.write() = Some(transaction);
        
        Ok(transaction_id)
    }
    
    /// メタデータブロックをジャーナルに追加
    pub fn log_metadata(&self, transaction_id: u64, device_id: u64, block_number: u64, data: &[u8]) -> FsResult<()> {
        let state = self.state.read();
        
        if *state != JournalState::InTransaction {
            return Err(FsError::InvalidData);
        }
        
        let mut current_transaction = self.current_transaction.write();
        
        if let Some(transaction) = current_transaction.as_mut() {
            if transaction.id != transaction_id {
                return Err(FsError::InvalidData);
            }
            
            transaction.add_record(
                JournalRecordType::Metadata,
                device_id,
                Some(block_number),
                data.to_vec()
            );
            
            Ok(())
        } else {
            Err(FsError::InvalidData)
        }
    }
    
    /// データブロックをジャーナルに追加
    pub fn log_data(&self, transaction_id: u64, device_id: u64, block_number: u64, data: &[u8]) -> FsResult<()> {
        let state = self.state.read();
        
        if *state != JournalState::InTransaction {
            return Err(FsError::InvalidData);
        }
        
        let mut current_transaction = self.current_transaction.write();
        
        if let Some(transaction) = current_transaction.as_mut() {
            if transaction.id != transaction_id {
                return Err(FsError::InvalidData);
            }
            
            transaction.add_record(
                JournalRecordType::Data,
                device_id,
                Some(block_number),
                data.to_vec()
            );
            
            Ok(())
        } else {
            Err(FsError::InvalidData)
        }
    }
    
    /// トランザクションをコミット
    pub fn commit_transaction(&self, transaction_id: u64) -> FsResult<()> {
        let mut state = self.state.write();
        
        if *state != JournalState::InTransaction {
            return Err(FsError::InvalidData);
        }
        
        let mut current_transaction = self.current_transaction.write();
        
        if let Some(mut transaction) = current_transaction.take() {
            if transaction.id != transaction_id {
                // トランザクションIDが一致しない、元に戻す
                *current_transaction = Some(transaction);
                return Err(FsError::InvalidData);
            }
            
            // トランザクションをコミット済みとしてマーク
            transaction.committed = true;
            
            // コミットキューに追加
            self.commit_queue.write().push_back(transaction);
            
            // バックグラウンドでの書き込み処理をトリガー
            self.trigger_journal_write();
            
            *state = JournalState::Idle;
            Ok(())
        } else {
            Err(FsError::InvalidData)
        }
    }
    
    /// トランザクションをアボート
    pub fn abort_transaction(&self, transaction_id: u64) -> FsResult<()> {
        let mut state = self.state.write();
        
        if *state != JournalState::InTransaction {
            return Err(FsError::InvalidData);
        }
        
        let mut current_transaction = self.current_transaction.write();
        
        if let Some(transaction) = current_transaction.take() {
            if transaction.id != transaction_id {
                // トランザクションIDが一致しない、元に戻す
                *current_transaction = Some(transaction);
                return Err(FsError::InvalidData);
            }
            
            // トランザクションを破棄（何もしない）
            
            *state = JournalState::Idle;
            Ok(())
        } else {
            Err(FsError::InvalidData)
        }
    }
    
    /// ジャーナルをチェックポイント（古いトランザクションをクリア）
    pub fn checkpoint(&self) -> FsResult<()> {
        let state = self.state.read();
        
        if *state != JournalState::Idle {
            return Err(FsError::InvalidData);
        }
        
        // すべてのコミット済みトランザクションが実際のストレージに書き込まれていることを確認
        self.sync()?;
        
        // チェックポイントレコードを書き込み
        let checkpoint_transaction = JournalTransaction::new(self.next_transaction_id.fetch_add(1, Ordering::SeqCst));
        let serialized = checkpoint_transaction.serialize();
        
        // ジャーナルデバイスに書き込み
        let device = DeviceHandle::open(&self.device_path)?;
        
        // トランザクションヘッダを作成
        let mut tx_header = TransactionHeader {
            magic: TRANSACTION_MAGIC,
            sequence: self.next_sequence.fetch_add(1, Ordering::SeqCst),
            timestamp: current_time(),
            block_count: blocks.len() as u32,
            checksum: 0, // 一時的に0を設定、後で計算
            flags: flags,
            _reserved: [0; 16],
        };
        
        // ヘッダをシリアライズ
        let mut tx_data = serialize_transaction_header(&tx_header);
        
        // ブロックデータを追加
        for block in blocks {
            // ブロック情報をシリアライズ
            tx_data.extend_from_slice(block.data.as_slice());
        }
        
        // チェックサムを計算して設定
        tx_header.checksum = calculate_crc32(&tx_data[4..]); // マジック後のデータからCRC計算
        
        // 先頭にヘッダを置き換え（チェックサム更新）
        let header_bytes = serialize_transaction_header(&tx_header);
        tx_data[..header_bytes.len()].copy_from_slice(&header_bytes);
        
        // ジャーナルの適切な位置に書き込み
        let offset = self.get_next_transaction_offset()?;
        device.write_at(offset, &tx_data)?;
        
        // ジャーナルサイズをリセット
        self.current_size.store(serialized.len() as u64, Ordering::SeqCst);
        
        log::info!("ジャーナルチェックポイント完了");
        
        Ok(())
    }
    
    /// すべてのジャーナルデータを永続ストレージに書き込み
    pub fn sync(&self) -> FsResult<()> {
        // コミットキュー内のすべてのトランザクションを処理
        self.process_commit_queue()?;
        
        // ジャーナルデバイスを同期
        let device = DeviceHandle::open(&self.device_path)?;
        device.sync()?;
        
        log::debug!("ジャーナルをディスクに同期しました: {}", self.device_path);
        
        Ok(())
    }
    
    /// ジャーナルからシステムをリカバリ
    fn recover(&self) -> FsResult<()> {
        log::info!("ジャーナルからのリカバリを開始");
        
        // ジャーナルからすべてのコミット済みトランザクションを読み込み
        let transactions = self.read_committed_transactions()?;
        
        log::info!("リカバリ対象のトランザクション: {}個", transactions.len());
        
        // 各トランザクションを再適用
        for transaction in transactions {
            self.replay_transaction(&transaction)?;
        }
        
        log::info!("ジャーナルリカバリ完了");
        
        Ok(())
    }
    
    /// コミット済みトランザクションをジャーナルから読み込み
    fn read_committed_transactions(&self) -> FsResult<Vec<JournalTransaction>> {
        let device = DeviceHandle::open(&self.device_path)?;
        let mut transactions = Vec::new();
        
        // ジャーナルヘッダを読み込み
        let header_data = device.read_at(0, std::mem::size_of::<JournalHeader>())?;
        let header = deserialize_header(&header_data)?;
        
        // 最初のトランザクションオフセット
        let mut offset = std::mem::size_of::<JournalHeader>() as u64;
        
        while offset < header.journal_size {
            // トランザクションヘッダを読み込み
            let tx_header_data = device.read_at(offset, std::mem::size_of::<TransactionHeader>())?;
            
            if tx_header_data.len() < std::mem::size_of::<TransactionHeader>() {
                break; // データが不完全
            }
            
            // ヘッダデシリアライズ
            let tx_header = deserialize_transaction_header(&tx_header_data)?;
            
            // マジックナンバーチェック
            if tx_header.magic != TRANSACTION_MAGIC {
                break; // トランザクション境界に達した
            }
            
            // コミット済みトランザクションのみを読み込む
            if tx_header.flags & TRANSACTION_FLAG_COMMITTED != 0 {
                let block_data_size = tx_header.block_count as usize * self.block_size;
                let tx_data_offset = offset + std::mem::size_of::<TransactionHeader>() as u64;
                
                // ブロックデータを読み込み
                let block_data = device.read_at(tx_data_offset, block_data_size)?;
                
                if block_data.len() < block_data_size {
                    break; // データが不完全
                }
                
                // ブロックをパース
                let mut blocks = Vec::with_capacity(tx_header.block_count as usize);
                for i in 0..tx_header.block_count as usize {
                    let block_offset = i * self.block_size;
                    let block_data = block_data[block_offset..block_offset + self.block_size].to_vec();
                    
                    // ブロック情報のヘッダ部分を解析
                    let device_id = u64::from_le_bytes([
                        block_data[0], block_data[1], block_data[2], block_data[3],
                        block_data[4], block_data[5], block_data[6], block_data[7],
                    ]);
                    
                    let block_num = u64::from_le_bytes([
                        block_data[8], block_data[9], block_data[10], block_data[11],
                        block_data[12], block_data[13], block_data[14], block_data[15],
                    ]);
                    
                    blocks.push(JournalBlock {
                        device_id,
                        block_num,
                        data: block_data[16..].to_vec(),
                    });
                }
                
                // トランザクションを構築
                transactions.push(JournalTransaction {
                    sequence: tx_header.sequence,
                    timestamp: tx_header.timestamp,
                    blocks,
                    committed: true,
                });
            }
            
            // 次のトランザクションへ
            offset += std::mem::size_of::<TransactionHeader>() as u64 + 
                     (tx_header.block_count as u64 * self.block_size as u64);
            
            // 4KBアライメントを維持
            if offset % 4096 != 0 {
                offset = ((offset / 4096) + 1) * 4096;
            }
        }
        
        Ok(transactions)
    }
    
    /// トランザクションを再適用
    fn replay_transaction(&self, transaction: &JournalTransaction) -> FsResult<()> {
        log::info!("トランザクション {} を再適用", transaction.id);
        
        if !transaction.committed {
            // コミットされていないトランザクションは無視
            return Ok(());
        }
        
        // トランザクション内の各レコードを適用
        for record in &transaction.records {
            match record.header.record_type {
                JournalRecordType::Metadata | JournalRecordType::Data => {
                    if let Some(block_number) = record.header.block_number {
                        // データをデバイスに書き込み
                        write_block_to_device(
                            record.header.device_id,
                            block_number,
                            &record.data
                        )?;
                    }
                },
                _ => {}, // 他のレコードタイプは無視
            }
        }
        
        Ok(())
    }
    
    /// ジャーナル書き込み処理をトリガー
    fn trigger_journal_write(&self) {
        // バックグラウンドスレッドを起動して非同期でジャーナル書き込み
        let journal = self.clone();
        std::thread::spawn(move || {
            journal.write_journal_sync();
        });
    }
    
    /// コミットキュー内のトランザクションを処理
    fn process_commit_queue(&self) -> FsResult<()> {
        let mut commit_queue = self.commit_queue.write();
        
        while let Some(transaction) = commit_queue.pop_front() {
            // トランザクションをシリアライズ
            let serialized = transaction.serialize();
            
            // ジャーナルデバイスに書き込み
            let device = DeviceHandle::open(&self.device_path)?;
            let offset = self.get_next_transaction_offset()?;
            device.write_at(offset, &serialized)?;
            device.sync()?;
            log::debug!("トランザクション {} をジャーナルに書き込み ({} バイト)",
                      transaction.id, serialized.len());
            
            // ジャーナルサイズを更新
            self.current_size.fetch_add(serialized.len() as u64, Ordering::SeqCst);
            
            // トランザクション内の各レコードを実際のデバイスに適用
            for record in &transaction.records {
                match record.header.record_type {
                    JournalRecordType::Metadata | JournalRecordType::Data => {
                        if let Some(block_number) = record.header.block_number {
                            // データをデバイスに書き込み
                            write_block_to_device(
                                record.header.device_id,
                                block_number,
                                &record.data
                            )?;
                        }
                    },
                    _ => {}, // 他のレコードタイプは無視
                }
            }
        }
        
        Ok(())
    }
}

/// グローバルジャーナルマネージャ
static JOURNAL_MANAGER: RwLock<Option<JournalManager>> = RwLock::new(None);

/// ジャーナルマネージャを初期化
pub fn init() -> FsResult<()> {
    let journal_device = "/dev/journal";
    let max_size = 256 * 1024 * 1024; // 256MB
    let block_size = 4096; // 4KB
    
    let journal = JournalManager::new(journal_device, max_size, block_size);
    journal.init()?;
    
    *JOURNAL_MANAGER.write() = Some(journal);
    
    Ok(())
}

/// トランザクションを開始
pub fn begin_transaction() -> FsResult<u64> {
    if let Some(journal) = JOURNAL_MANAGER.read().as_ref() {
        journal.begin_transaction()
    } else {
        Err(FsError::NotSupported)
    }
}

/// メタデータブロックをジャーナルに追加
pub fn log_metadata(transaction_id: u64, device_id: u64, block_number: u64, data: &[u8]) -> FsResult<()> {
    if let Some(journal) = JOURNAL_MANAGER.read().as_ref() {
        journal.log_metadata(transaction_id, device_id, block_number, data)
    } else {
        Err(FsError::NotSupported)
    }
}

/// データブロックをジャーナルに追加
pub fn log_data(transaction_id: u64, device_id: u64, block_number: u64, data: &[u8]) -> FsResult<()> {
    if let Some(journal) = JOURNAL_MANAGER.read().as_ref() {
        journal.log_data(transaction_id, device_id, block_number, data)
    } else {
        Err(FsError::NotSupported)
    }
}

/// トランザクションをコミット
pub fn commit_transaction(transaction_id: u64) -> FsResult<()> {
    if let Some(journal) = JOURNAL_MANAGER.read().as_ref() {
        journal.commit_transaction(transaction_id)
    } else {
        Err(FsError::NotSupported)
    }
}

/// トランザクションをアボート
pub fn abort_transaction(transaction_id: u64) -> FsResult<()> {
    if let Some(journal) = JOURNAL_MANAGER.read().as_ref() {
        journal.abort_transaction(transaction_id)
    } else {
        Err(FsError::NotSupported)
    }
}

/// ジャーナルをチェックポイント
pub fn checkpoint() -> FsResult<()> {
    if let Some(journal) = JOURNAL_MANAGER.read().as_ref() {
        journal.checkpoint()
    } else {
        Err(FsError::NotSupported)
    }
}

/// ジャーナルを同期
pub fn sync() -> FsResult<()> {
    if let Some(journal) = JOURNAL_MANAGER.read().as_ref() {
        journal.sync()
    } else {
        Err(FsError::NotSupported)
    }
}

/// 現在時間を取得（UNIX時間）
fn current_time() -> u64 {
    // システムの現在時刻をマイクロ秒精度で取得
    crate::time::get_current_time().as_micros()
}

/// レコードヘッダをシリアライズ
fn serialize_record_header(header: &JournalRecordHeader, output: &mut Vec<u8>) {
    // 出力バッファの初期位置を保存（チェックサム計算用）
    let start_pos = output.len();
    
    // レコードタイプ（1バイト）
    output.push(match header.record_type {
        JournalRecordType::Begin => 1,
        JournalRecordType::Metadata => 2,
        JournalRecordType::Data => 3,
        JournalRecordType::Commit => 4,
        JournalRecordType::Checkpoint => 5,
    });
    
    // トランザクションID (8バイト)
    output.extend_from_slice(&header.transaction_id.to_le_bytes());
    
    // デバイスID (8バイト)
    output.extend_from_slice(&header.device_id.to_le_bytes());
    
    // ブロック番号 (8バイト)
    let block_number = header.block_number.unwrap_or(0);
    output.extend_from_slice(&block_number.to_le_bytes());
    
    // サイズ (4バイト)
    output.extend_from_slice(&header.size.to_le_bytes());
    
    // チェックサム (4バイト)
    output.extend_from_slice(&header.checksum.to_le_bytes());
}

/// データのチェックサムを計算
fn calculate_checksum(data: &[u8]) -> u32 {
    // CRC-32実装
    let mut crc: u32 = 0xFFFFFFFF;
    
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = if (crc & 1) != 0 { 0xEDB88320 } else { 0 };
            crc = (crc >> 1) ^ mask;
        }
    }
    
    !crc
}

/// リカバリが必要かチェック
fn check_recovery_needed(device_path: &str) -> bool {
    // ジャーナルデバイスをオープン
    let device = match DeviceHandle::open(device_path) {
        Ok(dev) => dev,
        Err(_) => return false,
    };
    
    // ジャーナルヘッダを読み込み
    let header_data = match device.read_at(0, std::mem::size_of::<JournalHeader>()) {
        Ok(data) => data,
        Err(_) => return false,
    };
    
    if header_data.len() < std::mem::size_of::<JournalHeader>() {
        return false;
    }
    
    // ヘッダをデシリアライズ
    let header = match deserialize_header(&header_data) {
        Ok(h) => h,
        Err(_) => return false,
    };
    
    // ダーティフラグをチェック
    if header.flags & JOURNAL_FLAG_DIRTY != 0 {
        return true;
    }
    
    // 最後のチェックポイントシーケンス番号を取得
    let checkpoint_seq = header.last_checkpoint_seq;
    
    // トランザクションを走査して、コミット済みだがチェックポイントされていないものを探す
    let mut offset = std::mem::size_of::<JournalHeader>() as u64;
    
    while offset < header.journal_size {
        // トランザクションヘッダを読み込み
        let tx_header_data = match device.read_at(offset, std::mem::size_of::<TransactionHeader>()) {
            Ok(data) => data,
            Err(_) => break,
        };
        
        if tx_header_data.len() < std::mem::size_of::<TransactionHeader>() {
            break;
        }
        
        // ヘッダをデシリアライズ
        let tx_header = match deserialize_transaction_header(&tx_header_data) {
            Ok(h) => h,
            Err(_) => break,
        };
        
        // マジックナンバーをチェック
        if tx_header.magic != TRANSACTION_MAGIC {
            break;
        }
        
        // コミット済みでチェックポイントされていないトランザクションがあればリカバリが必要
        if (tx_header.flags & TRANSACTION_FLAG_COMMITTED) != 0 && 
           tx_header.sequence > checkpoint_seq {
            return true;
        }
        
        // 次のトランザクションへ
        offset += std::mem::size_of::<TransactionHeader>() as u64 + 
                 (tx_header.block_count as u64 * header.block_size as u64);
        
        // 4KBアライメントを維持
        if offset % 4096 != 0 {
            offset = ((offset / 4096) + 1) * 4096;
        }
    }
    
    false
}

/// ブロックをデバイスに書き込む
fn write_block_to_device(device_id: u64, block_number: u64, data: &[u8]) -> FsResult<()> {
    // デバイスマネージャからデバイスを取得
    let device_manager = crate::drivers::block::get_device_manager();
    let device = match device_manager.get_device(device_id) {
        Some(dev) => dev,
        None => {
            log::error!("デバイス ID {} が見つかりません", device_id);
            return Err(FsError::DeviceNotFound);
        }
    };
    
    // ブロックサイズの検証
    let block_size = device.get_block_size() as usize;
    if data.len() != block_size {
        log::error!("ブロックサイズが一致しません: 予期={}, 実際={}", block_size, data.len());
        return Err(FsError::InvalidSize);
    }
    
    // ブロックを書き込み
    if let Err(e) = device.write_block(block_number, data) {
        log::error!("ブロック書き込みエラー: デバイス={}, ブロック={}, エラー={:?}",
                  device_id, block_number, e);
        return Err(FsError::IoError);
    }
    
    log::debug!("ブロック書き込み: デバイス {} ブロック {} データサイズ {}バイト",
               device_id, block_number, data.len());
    Ok(())
}

/// CRC32チェックサムを計算
fn calculate_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = if (crc & 1) != 0 { 0xEDB88320 } else { 0 };
            crc = (crc >> 1) ^ mask;
        }
    }
    
    !crc
}

/// ヘッダ構造体をバイナリにシリアライズ
fn serialize_header(header: &JournalHeader, output: &mut Vec<u8>) {
    // ヘッダ構造体をバイナリにシリアライズ
    let mut header_bytes = Vec::with_capacity(std::mem::size_of::<JournalHeader>());
    
    // マジックナンバー
    header_bytes.extend_from_slice(&header.magic.to_le_bytes());
    
    // チェックサム（一時的に0で初期化）
    header_bytes.extend_from_slice(&0u32.to_le_bytes());
    
    // バージョン
    header_bytes.extend_from_slice(&header.version.to_le_bytes());
    
    // ジャーナルサイズ
    header_bytes.extend_from_slice(&header.journal_size.to_le_bytes());
    
    // ブロックサイズ
    header_bytes.extend_from_slice(&header.block_size.to_le_bytes());
    
    // フラグ
    header_bytes.extend_from_slice(&header.flags.to_le_bytes());
    
    // 予約領域
    header_bytes.extend_from_slice(&[0u8; 16]);
    
    // チェックサムを計算して設定
    let checksum = calculate_crc32(&header_bytes[4..]); // マジック後のデータからCRC計算
    let checksum_bytes = checksum.to_le_bytes();
    header_bytes[4..8].copy_from_slice(&checksum_bytes);
    
    header_bytes
} 