// ファイルシステムトランザクション処理
//
// 複数の操作をアトミックに実行するためのトランザクション機能

use core::sync::atomic::{AtomicU64, Ordering};
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::RwLock;
use super::{FsError, FsResult, journal};

/// トランザクション状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionState {
    /// 開始済み
    Started,
    /// コミット済み
    Committed,
    /// アボート済み
    Aborted,
}

/// ファイルシステムトランザクション
///
/// 複数のファイルシステム操作をアトミックに実行するためのトランザクション。
/// すべての操作が成功した場合のみコミットされ、失敗した場合はすべての変更がロールバックされる。
pub struct Transaction {
    /// トランザクションID
    id: u64,
    /// ジャーナルトランザクションID
    journal_id: Option<u64>,
    /// トランザクション状態
    state: RwLock<TransactionState>,
    /// このトランザクションで変更されたブロック
    modified_blocks: RwLock<Vec<(u64, u64, Vec<u8>)>>, // (デバイスID, ブロック番号, データ)
}

impl Transaction {
    /// 新しいトランザクションを開始
    fn new() -> FsResult<Self> {
        static NEXT_TRANSACTION_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_TRANSACTION_ID.fetch_add(1, Ordering::SeqCst);
        
        Ok(Self {
            id,
            journal_id: None,
            state: RwLock::new(TransactionState::Started),
            modified_blocks: RwLock::new(Vec::new()),
        })
    }
    
    /// トランザクションID取得
    pub fn id(&self) -> u64 {
        self.id
    }
    
    /// トランザクションがアクティブかどうか
    pub fn is_active(&self) -> bool {
        *self.state.read() == TransactionState::Started
    }
    
    /// トランザクションが完了したかどうか（コミットまたはアボート）
    pub fn is_completed(&self) -> bool {
        let state = *self.state.read();
        state == TransactionState::Committed || state == TransactionState::Aborted
    }
    
    /// ブロックを読み込み
    ///
    /// トランザクション内で変更されたブロックがある場合はそのデータを返し、
    /// ない場合はデバイスから読み込む
    pub fn read_block(&self, device_id: u64, block_number: u64, block_size: usize) -> FsResult<Vec<u8>> {
        let modified_blocks = self.modified_blocks.read();
        
        // このトランザクションで変更されたブロックがあれば、それを返す
        for (dev, blk, data) in modified_blocks.iter() {
            if *dev == device_id && *blk == block_number {
                return Ok(data.clone());
            }
        }
        
        // 変更されたブロックがなければ、デバイスから読み込む
        read_block_from_device(device_id, block_number, block_size)
    }
    
    /// ブロックを書き込み
    ///
    /// トランザクション内でブロックを変更する。実際のデバイスへの書き込みは
    /// トランザクションのコミット時に行われる。
    pub fn write_block(&self, device_id: u64, block_number: u64, data: &[u8]) -> FsResult<()> {
        if !self.is_active() {
            return Err(FsError::InvalidData);
        }
        
        let mut modified_blocks = self.modified_blocks.write();
        
        // 既にこのブロックが変更されているかチェック
        for (i, (dev, blk, _)) in modified_blocks.iter_mut().enumerate() {
            if *dev == device_id && *blk == block_number {
                // 既存のデータを更新
                modified_blocks[i] = (device_id, block_number, data.to_vec());
                return Ok(());
            }
        }
        
        // 新しいブロックを追加
        modified_blocks.push((device_id, block_number, data.to_vec()));
        Ok(())
    }
    
    /// トランザクションをコミット
    ///
    /// トランザクション内のすべての変更を永続化する
    pub fn commit(self) -> FsResult<()> {
        let mut state = self.state.write();
        
        if *state != TransactionState::Started {
            return Err(FsError::InvalidData);
        }
        
        // ジャーナルトランザクションを開始
        let journal_id = match self.journal_id {
            Some(id) => id,
            None => journal::begin_transaction()?,
        };
        
        let modified_blocks = self.modified_blocks.read();
        
        // 各ブロックをジャーナルに記録
        for (device_id, block_number, data) in modified_blocks.iter() {
            let is_metadata = is_metadata_block(*device_id, *block_number);
            
            if is_metadata {
                // メタデータブロックをジャーナリング
                journal::log_metadata(journal_id, *device_id, *block_number, data)?;
            } else {
                // データブロックをジャーナリング
                journal::log_data(journal_id, *device_id, *block_number, data)?;
            }
        }
        
        // ジャーナルトランザクションをコミット
        journal::commit_transaction(journal_id)?;
        
        // トランザクション状態を更新
        *state = TransactionState::Committed;
        
        Ok(())
    }
    
    /// トランザクションをアボート
    ///
    /// トランザクション内のすべての変更を破棄する
    pub fn abort(self) -> FsResult<()> {
        let mut state = self.state.write();
        
        if *state != TransactionState::Started {
            return Err(FsError::InvalidData);
        }
        
        // ジャーナルトランザクションもアボート
        if let Some(journal_id) = self.journal_id {
            journal::abort_transaction(journal_id)?;
        }
        
        // 変更をクリア
        self.modified_blocks.write().clear();
        
        // トランザクション状態を更新
        *state = TransactionState::Aborted;
        
        Ok(())
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if *self.state.read() == TransactionState::Started {
            // トランザクションが明示的にコミットまたはアボートされずに破棄された場合、アボートする
            log::warn!("トランザクション {} が明示的に終了せずに破棄されました。自動的にアボートします。", self.id);
            
            if let Some(journal_id) = self.journal_id {
                let _ = journal::abort_transaction(journal_id);
            }
        }
    }
}

/// グローバルトランザクションマネージャ
struct TransactionManager {
    /// 次のトランザクションID
    next_id: AtomicU64,
}

impl TransactionManager {
    /// 新しいトランザクションマネージャを作成
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
        }
    }
    
    /// 新しいトランザクションを開始
    fn begin_transaction(&self) -> FsResult<Transaction> {
        Transaction::new()
    }
}

/// グローバルトランザクションマネージャインスタンス
static TRANSACTION_MANAGER: RwLock<Option<TransactionManager>> = RwLock::new(None);

/// トランザクションマネージャを初期化
pub fn init() -> FsResult<()> {
    *TRANSACTION_MANAGER.write() = Some(TransactionManager::new());
    Ok(())
}

/// 新しいトランザクションを開始
pub fn begin_transaction() -> FsResult<Arc<Transaction>> {
    if let Some(manager) = TRANSACTION_MANAGER.read().as_ref() {
        let transaction = manager.begin_transaction()?;
        Ok(Arc::new(transaction))
    } else {
        Err(FsError::NotSupported)
    }
}

/// デバイスからブロックを読み込む
fn read_block_from_device(device_id: u64, block_number: u64, block_size: usize) -> FsResult<Vec<u8>> {
    // デバイスマネージャからデバイスを取得
    let device_manager = crate::drivers::block::get_device_manager();
    let device = match device_manager.get_device(device_id) {
        Some(dev) => dev,
        None => {
            log::error!("デバイス ID {} が見つかりません", device_id);
            return Err(FsError::DeviceNotFound);
        }
    };
    
    // ブロックサイズを検証
    let device_block_size = device.get_block_size() as usize;
    if block_size != device_block_size {
        log::error!("ブロックサイズが一致しません: 予期={}, デバイス={}", 
                  block_size, device_block_size);
        return Err(FsError::InvalidSize);
    }
    
    // ブロックを読み込み
    match device.read_block(block_number) {
        Ok(data) => {
            if data.len() != block_size {
                log::error!("読み込みデータサイズが不正: 予期={}, 実際={}", 
                          block_size, data.len());
                return Err(FsError::IoError);
            }
            Ok(data)
        },
        Err(e) => {
            log::error!("ブロック読み込みエラー: デバイス={}, ブロック={}, エラー={:?}",
                      device_id, block_number, e);
            Err(FsError::IoError)
        }
    }
}

/// ブロックがメタデータかどうかを判定
fn is_metadata_block(device_id: u64, block_number: u64) -> bool {
    // ファイルシステムマネージャを取得
    let fs_manager = crate::core::fs::get_fs_manager();
    
    // デバイスに対応するファイルシステムドライバを取得
    if let Some(fs_driver) = fs_manager.get_driver_for_device(device_id) {
        // ファイルシステム固有のメタデータ判定を呼び出す
        return fs_driver.is_metadata_block(device_id, block_number);
    }
    
    // ファイルシステムが不明な場合のフォールバック
    // 一般的なヒューリスティック：先頭の数ブロックはメタデータである可能性が高い
    
    // スーパーブロックやメタデータのための予約領域（例：先頭64ブロック）
    if block_number < 64 {
        return true;
    }
    
    // ビットマップブロックやアイノードテーブルのためのヒューリスティック
    // 多くのファイルシステムでは、特定の領域にメタデータが集中している
    
    // デバイスマネージャからデバイス情報を取得し、デバイスサイズを考慮
    let device_manager = crate::drivers::block::get_device_manager();
    if let Some(device) = device_manager.get_device(device_id) {
        let total_blocks = device.get_size() / device.get_block_size();
        
        // 一般的な経験則：サイズの1%をメタデータとして予約
        let metadata_reserved = total_blocks / 100;
        
        if block_number < metadata_reserved {
            return true;
        }
    }
    
    false
}

/// with_transactionヘルパー関数
///
/// トランザクション内で複数の操作を実行し、すべて成功した場合のみコミットする
pub fn with_transaction<F, T>(f: F) -> FsResult<T>
where
    F: FnOnce(&Transaction) -> FsResult<T>,
{
    let transaction = begin_transaction()?;
    
    // クロージャを実行
    match f(&transaction) {
        Ok(result) => {
            // 成功した場合、トランザクションをコミット
            if let Err(e) = Arc::try_unwrap(transaction)
                .map_err(|_| FsError::Other("トランザクションが他の場所で参照されています"))?
                .commit()
            {
                return Err(e);
            }
            Ok(result)
        }
        Err(e) => {
            // 失敗した場合、トランザクションをアボート
            if let Ok(transaction) = Arc::try_unwrap(transaction) {
                let _ = transaction.abort();
            }
            Err(e)
        }
    }
} 