// AetherOS テレページメモリコヒーレンス（一貫性）システム
// 分散メモリ環境での一貫性を保証するプロトコル実装

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use crate::sync::{Mutex, SpinLock, RwLock};
use crate::memory::{PAGE_SIZE, AllocFlags};
use crate::network::rdma;
use alloc::vec::Vec;
use alloc::collections::{BTreeMap, HashMap, HashSet};
use alloc::string::String;
use super::remote;
use crate::network;
use crate::core::memory::mm::page::PageAllocator;
use core::alloc::{Layout, GlobalAlloc};
use crate::ALLOCATOR; // グローバルアロケータをインポート

/// 初期化済みフラグ
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// コヒーレンスモデル
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoherenceModel {
    /// 強い一貫性（シーケンシャル一貫性）
    /// 全てのメモリアクセスがグローバルな順序で観測される
    Sequential,
    
    /// リリース一貫性
    /// 同期ポイントでのみ一貫性を保証
    Release,
    
    /// 弱い一貫性
    /// 最小限の保証のみを提供
    Weak,
    
    /// モザイク一貫性
    /// ページ単位で異なる一貫性レベルを適用
    Mosaic,
}

/// コヒーレンス状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoherenceState {
    /// 排他的所有（読み書き可能）
    Exclusive,
    
    /// 共有（読み取りのみ）
    Shared,
    
    /// 無効（現在のコピーは無効）
    Invalid,
    
    /// 変更済み（ローカルで変更されたが同期されていない）
    Modified,
}

/// メモリアクセスタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessType {
    /// 読み取り
    Read,
    
    /// 書き込み
    Write,
    
    /// アトミック操作
    Atomic,
}

/// メモリバリアタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierType {
    /// 読み込みバリア
    Read,
    
    /// 書き込みバリア
    Write,
    
    /// 完全バリア
    Full,
    
    /// アクワイア（同期取得）
    Acquire,
    
    /// リリース（同期解放）
    Release,
}

/// ページメタデータ
#[derive(Debug)]
struct PageMetadata {
    /// 物理アドレス
    physical_addr: usize,
    
    /// 現在の状態
    state: CoherenceState,
    
    /// 所有ノード（排他的またはModified状態の場合）
    owner_node: Option<remote::RemoteNodeId>,
    
    /// 共有ノードリスト（Shared状態の場合）
    sharing_nodes: HashSet<remote::RemoteNodeId>,
    
    /// 最終変更ノード
    last_modified_by: Option<remote::RemoteNodeId>,
    
    /// 最終変更タイムスタンプ
    last_modified_time: u64,
    
    /// ロックカウント
    lock_count: AtomicUsize,
    
    /// 現在のコヒーレンスモデル
    coherence_model: CoherenceModel,
}

/// グローバルページディレクトリ
static mut PAGE_DIRECTORY: Option<RwLock<BTreeMap<usize, PageMetadata>>> = None;

/// ローカルキャッシュディレクトリ
static mut LOCAL_CACHE: Option<RwLock<BTreeMap<usize, CoherenceState>>> = None;

/// 保留中の書き込み（アドレス→データ）
static mut PENDING_WRITES: Option<RwLock<BTreeMap<usize, Vec<u8>>>> = None;

/// モジュール初期化
pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }
    
    unsafe {
        PAGE_DIRECTORY = Some(RwLock::new(BTreeMap::new()));
        LOCAL_CACHE = Some(RwLock::new(BTreeMap::new()));
        PENDING_WRITES = Some(RwLock::new(BTreeMap::new()));
    }
    
    // リモートノードの初期化を確認
    if !remote::is_node_available(0) {
        return Err("リモートノードが利用できないため、コヒーレンスシステムを初期化できません");
    }
    
    INITIALIZED.store(true, Ordering::SeqCst);
    
    Ok(())
}

/// シャットダウン処理
pub fn shutdown() -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }
    
    // 保留中の書き込みをフラッシュ
    flush_all_pending_writes()?;
    
    // キャッシュと保留書き込みをクリア
    unsafe {
        if let Some(cache_lock) = LOCAL_CACHE.as_ref() {
            if let Ok(mut cache) = cache_lock.write() {
                cache.clear();
            }
        }
        
        if let Some(pending_lock) = PENDING_WRITES.as_ref() {
            if let Ok(mut pending) = pending_lock.write() {
                pending.clear();
            }
        }
    }
    
    INITIALIZED.store(false, Ordering::SeqCst);
    
    Ok(())
}

/// ページコヒーレンスモデルを設定
pub fn set_page_coherence_model(page_addr: usize, model: CoherenceModel) -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("コヒーレンスシステムが初期化されていません");
    }
    
    // ページのアライメントを確認
    let aligned_addr = page_addr & !(PAGE_SIZE - 1);
    
    unsafe {
        if let Some(dir_lock) = PAGE_DIRECTORY.as_ref() {
            if let Ok(mut directory) = dir_lock.write() {
                if let Some(metadata) = directory.get_mut(&aligned_addr) {
                    // モデルを更新
                    metadata.coherence_model = model;
                } else {
                    // 新しいエントリを作成
                    let metadata = PageMetadata {
                        physical_addr: aligned_addr,
                        state: CoherenceState::Invalid,
                        owner_node: None,
                        sharing_nodes: HashSet::new(),
                        last_modified_by: None,
                        last_modified_time: get_timestamp(),
                        lock_count: AtomicUsize::new(0),
                        coherence_model: model,
                    };
                    directory.insert(aligned_addr, metadata);
                }
                
                return Ok(());
            }
        }
    }
    
    Err("ページディレクトリにアクセスできません")
}

/// ページコヒーレンスモデルを取得
pub fn get_page_coherence_model(page_addr: usize) -> Result<CoherenceModel, &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("コヒーレンスシステムが初期化されていません");
    }
    
    // ページのアライメントを確認
    let aligned_addr = page_addr & !(PAGE_SIZE - 1);
    
    unsafe {
        if let Some(dir_lock) = PAGE_DIRECTORY.as_ref() {
            if let Ok(directory) = dir_lock.read() {
                if let Some(metadata) = directory.get(&aligned_addr) {
                    return Ok(metadata.coherence_model);
                } else {
                    // デフォルトは弱い一貫性
                    return Ok(CoherenceModel::Weak);
                }
            }
        }
    }
    
    Err("ページディレクトリにアクセスできません")
}

/// メモリアクセスの前処理（アクセス権限をチェックし、必要に応じてデータを同期）
pub fn before_memory_access(addr: usize, access_type: AccessType, size: usize) -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("コヒーレンスシステムが初期化されていません");
    }
    
    // ページのアライメントを確認
    let aligned_addr = addr & !(PAGE_SIZE - 1);
    
    // コヒーレンスモデルを取得
    let model = get_page_coherence_model(aligned_addr)?;
    
    // アクセスタイプに基づいて一貫性を確保
    match access_type {
        AccessType::Read => {
            ensure_read_coherence(aligned_addr, model)?;
        },
        AccessType::Write => {
            ensure_write_coherence(aligned_addr, model)?;
        },
        AccessType::Atomic => {
            ensure_atomic_coherence(aligned_addr, model)?;
        },
    }
    
    Ok(())
}

/// メモリアクセスの後処理（状態の更新、通知など）
pub fn after_memory_access(addr: usize, access_type: AccessType, size: usize) -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("コヒーレンスシステムが初期化されていません");
    }
    
    // ページのアライメントを確認
    let aligned_addr = addr & !(PAGE_SIZE - 1);
    
    // コヒーレンスモデルを取得
    let model = get_page_coherence_model(aligned_addr)?;
    
    // アクセスタイプに基づいて状態を更新
    match access_type {
        AccessType::Read => {
            // 読み取りアクセスは状態を変更しない
        },
        AccessType::Write => {
            update_after_write(aligned_addr, model)?;
        },
        AccessType::Atomic => {
            update_after_atomic(aligned_addr, model)?;
        },
    }
    
    Ok(())
}

/// メモリバリアを実行
pub fn memory_barrier(barrier_type: BarrierType) -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("コヒーレンスシステムが初期化されていません");
    }
    
    match barrier_type {
        BarrierType::Read => {
            // 読み込みバリア - 保留中の読み込みを完了させる
            sync_all_read_caches()?;
        },
        BarrierType::Write => {
            // 書き込みバリア - 保留中の書き込みをフラッシュする
            flush_all_pending_writes()?;
        },
        BarrierType::Full => {
            // 完全バリア - 読み書きの両方を同期
            sync_all_read_caches()?;
            flush_all_pending_writes()?;
        },
        BarrierType::Acquire => {
            // アクワイアバリア - 読み込みを完了させる
            sync_all_read_caches()?;
        },
        BarrierType::Release => {
            // リリースバリア - 書き込みをフラッシュする
            flush_all_pending_writes()?;
        },
    }
    
    Ok(())
}

/// 読み取り一貫性を確保
fn ensure_read_coherence(addr: usize, model: CoherenceModel) -> Result<(), &'static str> {
    let local_state = get_local_state(addr)?;
    
    // ローカル状態に基づいてアクション
    match local_state {
        CoherenceState::Invalid => {
            // 無効な場合は、最新のデータを取得する必要がある
            fetch_latest_data(addr, model)?;
        },
        CoherenceState::Shared | CoherenceState::Exclusive | CoherenceState::Modified => {
            // これらの状態では読み取り可能
        },
    }
    
    Ok(())
}

/// 書き込み一貫性を確保
fn ensure_write_coherence(addr: usize, model: CoherenceModel) -> Result<(), &'static str> {
    let local_state = get_local_state(addr)?;
    
    // ローカル状態に基づいてアクション
    match local_state {
        CoherenceState::Invalid | CoherenceState::Shared => {
            // 排他的アクセスを取得
            acquire_exclusive_access(addr, model)?;
        },
        CoherenceState::Exclusive | CoherenceState::Modified => {
            // これらの状態では書き込み可能
        },
    }
    
    Ok(())
}

/// アトミック操作の一貫性を確保
fn ensure_atomic_coherence(addr: usize, model: CoherenceModel) -> Result<(), &'static str> {
    // アトミック操作は排他的アクセスが必要
    acquire_exclusive_access(addr, model)?;
    
    Ok(())
}

/// 書き込み後の状態更新
fn update_after_write(addr: usize, model: CoherenceModel) -> Result<(), &'static str> {
    // ローカル状態を変更済みに更新
    update_local_state(addr, CoherenceState::Modified)?;
    
    // 一貫性モデルに基づいて通知
    match model {
        CoherenceModel::Sequential => {
            // 即時に他のノードに変更を通知
            notify_modifications(addr)?;
        },
        CoherenceModel::Release => {
            // リリースバリアまで遅延
            queue_pending_write(addr)?;
        },
        CoherenceModel::Weak | CoherenceModel::Mosaic => {
            // 遅延通知（最適化）
            queue_pending_write(addr)?;
        },
    }
    
    Ok(())
}

/// アトミック操作後の状態更新
fn update_after_atomic(addr: usize, model: CoherenceModel) -> Result<(), &'static str> {
    // アトミック操作は常に即時一貫性が必要
    update_local_state(addr, CoherenceState::Modified)?;
    notify_modifications(addr)?;
    
    Ok(())
}

/// ローカルの状態を取得
fn get_local_state(addr: usize) -> Result<CoherenceState, &'static str> {
    let aligned_addr = addr & !(PAGE_SIZE - 1);
    
    unsafe {
        if let Some(cache_lock) = LOCAL_CACHE.as_ref() {
            if let Ok(cache) = cache_lock.read() {
                if let Some(&state) = cache.get(&aligned_addr) {
                    return Ok(state);
                }
            }
        }
    }
    
    // キャッシュに存在しない場合はInvalid
    Ok(CoherenceState::Invalid)
}

/// ローカルの状態を更新
fn update_local_state(addr: usize, state: CoherenceState) -> Result<(), &'static str> {
    let aligned_addr = addr & !(PAGE_SIZE - 1);
    
    unsafe {
        if let Some(cache_lock) = LOCAL_CACHE.as_ref() {
            if let Ok(mut cache) = cache_lock.write() {
                cache.insert(aligned_addr, state);
                return Ok(());
            }
        }
    }
    
    Err("ローカルキャッシュにアクセスできません")
}

/// 最新のデータを取得
fn fetch_latest_data(addr: usize, model: CoherenceModel) -> Result<(), &'static str> {
    let aligned_addr = addr & !(PAGE_SIZE - 1);
    
    // ディレクトリからページメタデータを取得
    let (owner_node, state) = unsafe {
        if let Some(dir_lock) = PAGE_DIRECTORY.as_ref() {
            if let Ok(directory) = dir_lock.read() {
                if let Some(metadata) = directory.get(&aligned_addr) {
                    (metadata.owner_node, metadata.state)
                } else {
                    (None, CoherenceState::Invalid)
                }
            } else {
                return Err("ページディレクトリにアクセスできません");
            }
        } else {
            return Err("ページディレクトリが初期化されていません");
        }
    };
    
    // 所有者からデータを取得
    if let Some(node_id) = owner_node {
        // リモートから読み込み
        let local_buffer = allocate_temp_buffer(PAGE_SIZE)?;
        remote::copy_from_remote(node_id, aligned_addr, local_buffer, PAGE_SIZE)?;
        
        // ローカルメモリにコピー
        copy_to_local_memory(aligned_addr, local_buffer, PAGE_SIZE)?;
        
        // 一時バッファを解放
        free_temp_buffer(local_buffer, PAGE_SIZE)?;
        
        // ローカルの状態を共有に更新
        update_local_state(aligned_addr, CoherenceState::Shared)?;
        
        // ディレクトリを更新
        update_directory_sharing(aligned_addr, remote::get_local_node_id())?;
    } else {
        // 所有者がいない場合、メモリをゼロ初期化
        zero_initialize_memory(aligned_addr, PAGE_SIZE)?;
        
        // ローカルの状態を排他的に更新
        update_local_state(aligned_addr, CoherenceState::Exclusive)?;
        
        // ディレクトリを更新
        update_directory_owner(aligned_addr, remote::get_local_node_id())?;
    }
    
    Ok(())
}

/// 排他的アクセスを取得
fn acquire_exclusive_access(addr: usize, model: CoherenceModel) -> Result<(), &'static str> {
    let aligned_addr = addr & !(PAGE_SIZE - 1);
    let local_node = remote::get_local_node_id();
    
    // ディレクトリからページメタデータを取得
    let (owner_node, sharing_nodes, state) = unsafe {
        if let Some(dir_lock) = PAGE_DIRECTORY.as_ref() {
            if let Ok(mut directory) = dir_lock.write() {
                if let Some(metadata) = directory.get_mut(&aligned_addr) {
                    // 既に所有者の場合は早期リターン
                    if metadata.owner_node == Some(local_node) {
                        update_local_state(aligned_addr, CoherenceState::Exclusive)?;
                        return Ok(());
                    }
                    
                    let owner = metadata.owner_node;
                    let sharing = metadata.sharing_nodes.clone();
                    let state = metadata.state;
                    
                    // ディレクトリを更新
                    metadata.owner_node = Some(local_node);
                    metadata.state = CoherenceState::Exclusive;
                    metadata.sharing_nodes.clear();
                    metadata.last_modified_by = Some(local_node);
                    metadata.last_modified_time = get_timestamp();
                    
                    (owner, sharing, state)
                } else {
                    // 新しいエントリを作成
                    let metadata = PageMetadata {
                        physical_addr: aligned_addr,
                        state: CoherenceState::Exclusive,
                        owner_node: Some(local_node),
                        sharing_nodes: HashSet::new(),
                        last_modified_by: Some(local_node),
                        last_modified_time: get_timestamp(),
                        lock_count: AtomicUsize::new(0),
                        coherence_model: model,
                    };
                    directory.insert(aligned_addr, metadata);
                    
                    (None, HashSet::new(), CoherenceState::Invalid)
                }
            } else {
                return Err("ページディレクトリにアクセスできません");
            }
        } else {
            return Err("ページディレクトリが初期化されていません");
        }
    };
    
    // 他のノードの無効化
    if let Some(owner) = owner_node {
        if owner != local_node {
            // 以前の所有者から最新データを取得
            let local_buffer = allocate_temp_buffer(PAGE_SIZE)?;
            remote::copy_from_remote(owner, aligned_addr, local_buffer, PAGE_SIZE)?;
            
            // ローカルメモリにコピー
            copy_to_local_memory(aligned_addr, local_buffer, PAGE_SIZE)?;
            
            // 一時バッファを解放
            free_temp_buffer(local_buffer, PAGE_SIZE)?;
            
            // 以前の所有者に無効化を通知
            send_invalidate_notification(owner, aligned_addr)?;
        }
    }
    
    // 共有ノードに無効化を通知
    for node in sharing_nodes {
        if node != local_node {
            send_invalidate_notification(node, aligned_addr)?;
        }
    }
    
    // ローカルの状態を排他的に更新
    update_local_state(aligned_addr, CoherenceState::Exclusive)?;
    
    Ok(())
}

/// ディレクトリの共有状態を更新
fn update_directory_sharing(addr: usize, node_id: remote::RemoteNodeId) -> Result<(), &'static str> {
    let aligned_addr = addr & !(PAGE_SIZE - 1);
    
    unsafe {
        if let Some(dir_lock) = PAGE_DIRECTORY.as_ref() {
            if let Ok(mut directory) = dir_lock.write() {
                if let Some(metadata) = directory.get_mut(&aligned_addr) {
                    metadata.sharing_nodes.insert(node_id);
                    metadata.state = CoherenceState::Shared;
                    return Ok(());
                } else {
                    // 新しいエントリを作成
                    let mut sharing_nodes = HashSet::new();
                    sharing_nodes.insert(node_id);
                    
                    let metadata = PageMetadata {
                        physical_addr: aligned_addr,
                        state: CoherenceState::Shared,
                        owner_node: None,
                        sharing_nodes,
                        last_modified_by: None,
                        last_modified_time: get_timestamp(),
                        lock_count: AtomicUsize::new(0),
                        coherence_model: CoherenceModel::Weak, // デフォルト
                    };
                    directory.insert(aligned_addr, metadata);
                    return Ok(());
                }
            }
        }
    }
    
    Err("ページディレクトリにアクセスできません")
}

/// ディレクトリの所有者を更新
fn update_directory_owner(addr: usize, node_id: remote::RemoteNodeId) -> Result<(), &'static str> {
    let aligned_addr = addr & !(PAGE_SIZE - 1);
    
    unsafe {
        if let Some(dir_lock) = PAGE_DIRECTORY.as_ref() {
            if let Ok(mut directory) = dir_lock.write() {
                if let Some(metadata) = directory.get_mut(&aligned_addr) {
                    metadata.owner_node = Some(node_id);
                    metadata.state = CoherenceState::Exclusive;
                    metadata.sharing_nodes.clear();
                    metadata.last_modified_by = Some(node_id);
                    metadata.last_modified_time = get_timestamp();
                    return Ok(());
                } else {
                    // 新しいエントリを作成
                    let metadata = PageMetadata {
                        physical_addr: aligned_addr,
                        state: CoherenceState::Exclusive,
                        owner_node: Some(node_id),
                        sharing_nodes: HashSet::new(),
                        last_modified_by: Some(node_id),
                        last_modified_time: get_timestamp(),
                        lock_count: AtomicUsize::new(0),
                        coherence_model: CoherenceModel::Weak, // デフォルト
                    };
                    directory.insert(aligned_addr, metadata);
                    return Ok(());
                }
            }
        }
    }
    
    Err("ページディレクトリにアクセスできません")
}

/// 無効化通知を送信
fn send_invalidate_notification(node_id: remote::RemoteNodeId, addr: usize) -> Result<(), &'static str> {
    // ネットワーク経由でリモートノードに無効化通知を送信
    let conn = network::get_connection(node_id)?;
    conn.send_message(NetworkMessage::Invalidate { addr })?;
    Ok(())
}

/// 変更通知を送信
fn notify_modifications(addr: usize) -> Result<(), &'static str> {
    let aligned_addr = addr & !(PAGE_SIZE - 1);
    
    // ディレクトリから共有ノードリストを取得
    let sharing_nodes = unsafe {
        if let Some(dir_lock) = PAGE_DIRECTORY.as_ref() {
            if let Ok(directory) = dir_lock.read() {
                if let Some(metadata) = directory.get(&aligned_addr) {
                    metadata.sharing_nodes.clone()
                } else {
                    HashSet::new()
                }
            } else {
                return Err("ページディレクトリにアクセスできません");
            }
        } else {
            return Err("ページディレクトリが初期化されていません");
        }
    };
    
    // 各共有ノードに更新を通知
    for node_id in sharing_nodes {
        send_update_notification(node_id, aligned_addr)?;
    }
    
    Ok(())
}

/// 更新通知を送信
fn send_update_notification(node_id: remote::RemoteNodeId, addr: usize) -> Result<(), &'static str> {
    // ネットワーク経由でリモートノードに更新通知を送信
    let conn = network::get_connection(node_id)?;
    conn.send_message(NetworkMessage::Update { addr })?;
    Ok(())
}

/// 保留中の書き込みをキュー
fn queue_pending_write(addr: usize) -> Result<(), &'static str> {
    let aligned_addr = addr & !(PAGE_SIZE - 1);
    
    // 現在のページデータをバッファにコピー
    let buffer = allocate_temp_buffer(PAGE_SIZE)?;
    copy_from_local_memory(aligned_addr, buffer, PAGE_SIZE)?;
    
    // バッファを保留中書き込みに追加
    unsafe {
        if let Some(pending_lock) = PENDING_WRITES.as_ref() {
            if let Ok(mut pending) = pending_lock.write() {
                // バッファからVec<u8>を作成
                let mut data = Vec::with_capacity(PAGE_SIZE);
                for i in 0..PAGE_SIZE {
                    data.push(unsafe { *(buffer as *const u8).add(i) });
                }
                
                pending.insert(aligned_addr, data);
                return Ok(());
            }
        }
    }
    
    // 一時バッファを解放
    free_temp_buffer(buffer, PAGE_SIZE)?;
    
    Err("保留中書き込みキューにアクセスできません")
}

/// すべての保留中書き込みをフラッシュ
fn flush_all_pending_writes() -> Result<(), &'static str> {
    let pending_writes = unsafe {
        if let Some(pending_lock) = PENDING_WRITES.as_ref() {
            if let Ok(mut pending) = pending_lock.write() {
                // 保留中書き込みをキャプチャ
                let writes = pending.clone();
                // キューをクリア
                pending.clear();
                writes
            } else {
                return Err("保留中書き込みキューにアクセスできません");
            }
        } else {
            return Err("保留中書き込みキューが初期化されていません");
        }
    };
    
    // 各書き込みを処理
    for (addr, data) in pending_writes.iter() {
        // データを一時バッファにコピー
        let buffer = allocate_temp_buffer(PAGE_SIZE)?;
        unsafe {
            for (i, &byte) in data.iter().enumerate() {
                *((buffer as *mut u8).add(i)) = byte;
            }
        }
        
        // 変更通知を送信
        notify_modifications(*addr)?;
        
        // 一時バッファを解放
        free_temp_buffer(buffer, PAGE_SIZE)?;
    }
    
    Ok(())
}

/// すべての読み込みキャッシュを同期
fn sync_all_read_caches() -> Result<(), &'static str> {
    // TODO: 読み取りキャッシュの同期ロジックを実装
    Ok(())
}

/// 一時バッファを割り当て
fn allocate_temp_buffer(size: usize) -> Result<usize, &'static str> {
    // グローバルアロケータを使用してバッファを割り当て
    match memory::allocate_kernel_memory(size, AllocFlags::KERNEL) {
        Some(addr) => Ok(addr),
        None => Err("一時バッファの割り当てに失敗しました"),
    }
}

/// 一時バッファを解放
fn free_temp_buffer(addr: usize, size: usize) -> Result<(), &'static str> {
    // TODO: allocate_temp_buffer と同様に、専用バッファプールへの返却を検討。
    if addr == 0 {
        return Err("Temporary buffer free: Cannot free null address");
    }
    let layout = Layout::from_size_align(size, PAGE_SIZE)
        .map_err(|_| "Temporary buffer free: Invalid layout")?;
    unsafe {
        ALLOCATOR.dealloc(addr as *mut u8, layout);
    }
    log::trace!("Freed temporary buffer at {:#x} (size {})", addr, size);
    Ok(())
}

/// ローカルメモリにコピー
fn copy_to_local_memory(dest: usize, src: usize, size: usize) -> Result<(), &'static str> {
    unsafe {
        core::ptr::copy_nonoverlapping(
            src as *const u8,
            dest as *mut u8,
            size
        );
    }
    
    Ok(())
}

/// ローカルメモリからコピー
fn copy_from_local_memory(src: usize, dest: usize, size: usize) -> Result<(), &'static str> {
    unsafe {
        core::ptr::copy_nonoverlapping(
            src as *const u8,
            dest as *mut u8,
            size
        );
    }
    
    Ok(())
}

/// メモリをゼロ初期化
fn zero_initialize_memory(addr: usize, size: usize) -> Result<(), &'static str> {
    unsafe {
        core::ptr::write_bytes(addr as *mut u8, 0, size);
    }
    
    Ok(())
}

/// 現在のタイムスタンプを取得
fn get_timestamp() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    {
        0 // 他のアーキテクチャでの実装
    }
} 