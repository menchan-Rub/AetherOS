// AetherOS リモートメモリ管理
// RDMA (Remote Direct Memory Access) を活用した遠隔メモリアクセス機能

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use crate::sync::{Mutex, SpinLock, RwLock};
use crate::arch::cpu;
use crate::memory::{PAGE_SIZE, AllocFlags};
use crate::network::rdma::{self, RdmaConnection, RdmaError, RdmaCapabilities};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::string::String;
use super::stats;
use super::REMOTE_MEMORY_BASE;

/// リモートノードID型
pub type RemoteNodeId = usize;

/// 最大リモートノード数
const MAX_NODES: usize = 64;

/// ノードあたりの最大メモリ領域
const MAX_REGIONS_PER_NODE: usize = 16;

/// リモートメモリ領域構造体
#[derive(Debug)]
pub struct RemoteMemoryRegion {
    /// 領域ID
    pub id: usize,
    
    /// ローカル仮想アドレス
    pub local_addr: usize,
    
    /// リモート仮想アドレス
    pub remote_addr: usize,
    
    /// サイズ (バイト)
    pub size: usize,
    
    /// ページ数
    pub pages: usize,
    
    /// RDMAキー（リモートアクセス用）
    pub rkey: u32,
    
    /// ノードID
    pub node_id: RemoteNodeId,
    
    /// アクセスレイテンシ (ナノ秒)
    pub latency_ns: AtomicU64,
    
    /// 最後のアクセス時刻
    pub last_access: AtomicU64,
    
    /// 使用中かどうか
    pub is_used: AtomicBool,
}

/// リモートノード情報
#[derive(Debug)]
struct RemoteNode {
    /// ノードID
    id: RemoteNodeId,
    
    /// ホスト名
    hostname: String,
    
    /// RDMAエンドポイント
    endpoint: String,
    
    /// RDMA接続
    connection: Option<RdmaConnection>,
    
    /// 接続状態
    connected: AtomicBool,
    
    /// メモリ領域
    regions: [Option<RemoteMemoryRegion>; MAX_REGIONS_PER_NODE],
    
    /// 総メモリ容量 (バイト)
    total_memory: AtomicUsize,
    
    /// 使用中メモリ (バイト)
    used_memory: AtomicUsize,
    
    /// 現在のレイテンシ (ナノ秒)
    current_latency: AtomicU64,
    
    /// 帯域幅 (MB/秒)
    bandwidth_mbps: AtomicUsize,
    
    /// RDMAケイパビリティ
    capabilities: RdmaCapabilities,
}

/// リモートノードリスト
static mut REMOTE_NODES: [Option<RemoteNode>; MAX_NODES] = [None; MAX_NODES];

/// 初期化済みフラグ
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// ノード数
static NODE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// アクティブノード数
static ACTIVE_NODE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 総ページ数
static TOTAL_PAGES: AtomicUsize = AtomicUsize::new(0);

/// グローバルアドレスマップ (仮想アドレス -> (ノードID, 領域ID))
static mut ADDRESS_MAP: Option<RwLock<BTreeMap<usize, (RemoteNodeId, usize)>>> = None;

/// リモートメモリモジュールの初期化
pub fn init() -> Result<(), &'static str> {
    // 既に初期化されている場合は早期リターン
    if INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }
    
    // RDMAサポートを確認
    if !rdma::is_available() {
        return Err("RDMAがサポートされていません");
    }
    
    // アドレスマップを初期化
    unsafe {
        ADDRESS_MAP = Some(RwLock::new(BTreeMap::new()));
    }
    
    // リモートノードを検出
    discover_nodes()?;
    
    // 初期化完了
    INITIALIZED.store(true, Ordering::SeqCst);
    
    Ok(())
}

/// リモートメモリのシャットダウン
pub fn shutdown() -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }
    
    // すべてのノードとの接続を切断
    unsafe {
        for node_opt in REMOTE_NODES.iter_mut() {
            if let Some(node) = node_opt {
                if node.connected.load(Ordering::SeqCst) {
                    // 接続を切断
                    if let Some(conn) = node.connection.take() {
                        let _ = conn.disconnect();
                    }
                    node.connected.store(false, Ordering::SeqCst);
                }
            }
        }
    }
    
    // アドレスマップをクリア
    unsafe {
        if let Some(map) = ADDRESS_MAP.as_ref() {
            if let Ok(mut write_map) = map.write() {
                write_map.clear();
            }
        }
    }
    
    // 初期化状態をリセット
    INITIALIZED.store(false, Ordering::SeqCst);
    ACTIVE_NODE_COUNT.store(0, Ordering::SeqCst);
    
    Ok(())
}

/// リモートノードのディスカバリー
fn discover_nodes() -> Result<(), &'static str> {
    // RDMAノードの検出
    let nodes = rdma::discover_nodes().map_err(|_| "RDMAノードの検出に失敗しました")?;
    
    let mut count = 0;
    
    // 検出したノードを登録
    for (i, rdma_node) in nodes.iter().enumerate().take(MAX_NODES) {
        let node = RemoteNode {
            id: i,
            hostname: rdma_node.hostname.clone(),
            endpoint: rdma_node.endpoint.clone(),
            connection: None,
            connected: AtomicBool::new(false),
            regions: [None; MAX_REGIONS_PER_NODE],
            total_memory: AtomicUsize::new(rdma_node.memory_size),
            used_memory: AtomicUsize::new(0),
            current_latency: AtomicU64::new(rdma_node.latency_ns),
            bandwidth_mbps: AtomicUsize::new(rdma_node.bandwidth_mbps),
            capabilities: rdma_node.capabilities,
        };
        
        unsafe {
            REMOTE_NODES[i] = Some(node);
        }
        
        count += 1;
    }
    
    // 総ページ数を計算
    let mut total_pages = 0;
    
    unsafe {
        for node_opt in REMOTE_NODES.iter() {
            if let Some(node) = node_opt {
                let node_pages = node.total_memory.load(Ordering::Relaxed) / PAGE_SIZE;
                total_pages += node_pages;
            }
        }
    }
    
    // 統計情報を更新
    NODE_COUNT.store(count, Ordering::SeqCst);
    TOTAL_PAGES.store(total_pages, Ordering::SeqCst);
    
    Ok(())
}

/// ノードに接続
fn connect_to_node(node_id: RemoteNodeId) -> Result<(), &'static str> {
    if node_id >= MAX_NODES {
        return Err("無効なノードIDです");
    }
    
    unsafe {
        let node = REMOTE_NODES[node_id].as_mut().ok_or("ノードが存在しません")?;
        
        // 既に接続済みならスキップ
        if node.connected.load(Ordering::SeqCst) {
            return Ok(());
        }
        
        // RDMA接続を確立
        let connection = rdma::connect(&node.endpoint)
            .map_err(|_| "RDMAノードへの接続に失敗しました")?;
        
        // 接続情報を保存
        node.connection = Some(connection);
        node.connected.store(true, Ordering::SeqCst);
        
        // アクティブノード数を更新
        ACTIVE_NODE_COUNT.fetch_add(1, Ordering::SeqCst);
    }
    
    Ok(())
}

/// リモートメモリを割り当て
pub fn allocate(node_id: RemoteNodeId, pages: usize, flags: AllocFlags) -> Result<usize, &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("リモートメモリモジュールが初期化されていません");
    }
    
    if pages == 0 {
        return Err("0ページの割り当てはできません");
    }
    
    if node_id >= MAX_NODES {
        return Err("無効なノードIDです");
    }
    
    // ノードに接続
    connect_to_node(node_id)?;
    
    // ノードからメモリを割り当て
    unsafe {
        let node = REMOTE_NODES[node_id].as_mut().ok_or("ノードが存在しません")?;
        
        // 接続状態を確認
        if !node.connected.load(Ordering::SeqCst) {
            return Err("ノードに接続されていません");
        }
        
        // 利用可能なメモリがあるか確認
        let size = pages * PAGE_SIZE;
        let available = node.total_memory.load(Ordering::Relaxed) - node.used_memory.load(Ordering::Relaxed);
        
        if size > available {
            return Err("ノードに十分なメモリがありません");
        }
        
        // 利用可能なリージョンIDを探す
        let region_id = node.regions.iter().position(Option::is_none)
            .ok_or("これ以上のメモリ領域を割り当てできません")?;
        
        // RDMA接続から確認
        let connection = node.connection.as_ref().ok_or("RDMA接続が確立されていません")?;
        
        // リモートメモリ領域の割り当て
        let (remote_addr, rkey) = connection.allocate_memory(size)
            .map_err(|_| "リモートメモリの割り当てに失敗しました")?;
        
        // ローカル仮想アドレスの計算
        let local_addr = calculate_local_address(node_id, region_id, pages);
        
        // リモートメモリ領域構造体を作成
        let region = RemoteMemoryRegion {
            id: region_id,
            local_addr,
            remote_addr,
            size,
            pages,
            rkey,
            node_id,
            latency_ns: AtomicU64::new(node.current_latency.load(Ordering::Relaxed)),
            last_access: AtomicU64::new(get_timestamp()),
            is_used: AtomicBool::new(true),
        };
        
        // 領域を登録
        node.regions[region_id] = Some(region);
        
        // 使用メモリを更新
        node.used_memory.fetch_add(size, Ordering::Relaxed);
        
        // アドレスマップに追加
        if let Some(map) = ADDRESS_MAP.as_ref() {
            if let Ok(mut write_map) = map.write() {
                write_map.insert(local_addr, (node_id, region_id));
            } else {
                return Err("アドレスマップの更新に失敗しました");
            }
        }
        
        // 統計情報を記録
        stats::record_remote_allocation(
            local_addr, 
            pages, 
            node_id, 
            node.current_latency.load(Ordering::Relaxed)
        );
        
        return Ok(local_addr);
    }
}

/// リモートメモリを解放
pub fn free(node_id: RemoteNodeId, address: usize, pages: usize) -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("リモートメモリモジュールが初期化されていません");
    }
    
    if pages == 0 {
        return Ok(());
    }
    
    if node_id >= MAX_NODES {
        return Err("無効なノードIDです");
    }
    
    unsafe {
        let node = REMOTE_NODES[node_id].as_mut().ok_or("ノードが存在しません")?;
        
        // ノードの状態を確認
        if !node.connected.load(Ordering::SeqCst) {
            return Err("ノードに接続されていません");
        }
        
        // アドレスからリージョンIDを特定
        let region_id = match ADDRESS_MAP.as_ref() {
            Some(map) => {
                if let Ok(read_map) = map.read() {
                    match read_map.get(&address) {
                        Some(&(id, region)) if id == node_id => region,
                        _ => return Err("指定されたアドレスはこのノードに属していません")
                    }
                } else {
                    return Err("アドレスマップの読み取りに失敗しました");
                }
            },
            None => return Err("アドレスマップが初期化されていません")
        };
        
        // リージョンを取得
        let region = match node.regions[region_id].as_ref() {
            Some(r) if r.is_used.load(Ordering::Relaxed) => r,
            _ => return Err("指定されたリージョンは使用されていません")
        };
        
        // 期待されるページ数を確認
        if region.pages != pages {
            return Err("指定されたページ数が割り当て時と一致しません");
        }
        
        // RDMA接続から確認
        let connection = node.connection.as_ref().ok_or("RDMA接続が確立されていません")?;
        
        // リモートメモリを解放
        connection.free_memory(region.remote_addr, region.size)
            .map_err(|_| "リモートメモリの解放に失敗しました")?;
        
        // 使用メモリを更新
        node.used_memory.fetch_sub(region.size, Ordering::Relaxed);
        
        // リージョンの使用フラグを更新
        if let Some(r) = node.regions[region_id].as_mut() {
            r.is_used.store(false, Ordering::Relaxed);
        }
        
        // リージョンをクリア
        node.regions[region_id] = None;
        
        // アドレスマップから削除
        if let Some(map) = ADDRESS_MAP.as_ref() {
            if let Ok(mut write_map) = map.write() {
                write_map.remove(&address);
            }
        }
    }
    
    Ok(())
}

/// ローカルアドレスを計算
fn calculate_local_address(node_id: RemoteNodeId, region_id: usize, pages: usize) -> usize {
    // ノードIDとリージョンIDを組み合わせてアドレスを生成
    let node_offset = node_id * (MAX_REGIONS_PER_NODE * 0x40000000); // 1GBノードごと
    let region_offset = region_id * 0x4000000; // 64MBリージョンごと
    
    REMOTE_MEMORY_BASE + node_offset + region_offset
}

/// アドレスからノードIDを取得
pub fn get_node_id_from_address(address: usize) -> Result<RemoteNodeId, &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("リモートメモリモジュールが初期化されていません");
    }
    
    // アドレスマップから検索
    unsafe {
        if let Some(map) = ADDRESS_MAP.as_ref() {
            if let Ok(read_map) = map.read() {
                if let Some(&(node_id, _)) = read_map.get(&address) {
                    return Ok(node_id);
                }
            }
        }
    }
    
    Err("指定されたアドレスに対応するノードが見つかりません")
}

/// データをリモートメモリにコピー
pub fn copy_to_remote(node_id: RemoteNodeId, source: usize, dest: usize, size: usize) -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("リモートメモリモジュールが初期化されていません");
    }
    
    if node_id >= MAX_NODES {
        return Err("無効なノードIDです");
    }
    
    unsafe {
        let node = REMOTE_NODES[node_id].as_ref().ok_or("ノードが存在しません")?;
        
        // ノードの状態を確認
        if !node.connected.load(Ordering::SeqCst) {
            return Err("ノードに接続されていません");
        }
        
        // リージョンIDを特定
        let region_id = match ADDRESS_MAP.as_ref() {
            Some(map) => {
                if let Ok(read_map) = map.read() {
                    match read_map.get(&dest) {
                        Some(&(id, region)) if id == node_id => region,
                        _ => return Err("指定されたアドレスはこのノードに属していません")
                    }
                } else {
                    return Err("アドレスマップの読み取りに失敗しました");
                }
            },
            None => return Err("アドレスマップが初期化されていません")
        };
        
        // リージョンを取得
        let region = match node.regions[region_id].as_ref() {
            Some(r) if r.is_used.load(Ordering::Relaxed) => r,
            _ => return Err("指定されたリージョンは使用されていません")
        };
        
        // 領域サイズを確認
        if dest + size > region.local_addr + region.size {
            return Err("コピーサイズが領域を超えています");
        }
        
        // リモートアドレスを計算
        let remote_offset = dest - region.local_addr;
        let remote_addr = region.remote_addr + remote_offset;
        
        // 接続を取得
        let connection = node.connection.as_ref().ok_or("RDMA接続が確立されていません")?;
        
        // データをコピー
        connection.write(source as *const u8, remote_addr, size, region.rkey)
            .map_err(|_| "リモートメモリへの書き込みに失敗しました")?;
        
        // アクセス時刻を更新
        region.last_access.store(get_timestamp(), Ordering::Relaxed);
    }
    
    Ok(())
}

/// データをリモートメモリから読み込み
pub fn copy_from_remote(node_id: RemoteNodeId, source: usize, dest: usize, size: usize) -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("リモートメモリモジュールが初期化されていません");
    }
    
    if node_id >= MAX_NODES {
        return Err("無効なノードIDです");
    }
    
    unsafe {
        let node = REMOTE_NODES[node_id].as_ref().ok_or("ノードが存在しません")?;
        
        // ノードの状態を確認
        if !node.connected.load(Ordering::SeqCst) {
            return Err("ノードに接続されていません");
        }
        
        // リージョンIDを特定
        let region_id = match ADDRESS_MAP.as_ref() {
            Some(map) => {
                if let Ok(read_map) = map.read() {
                    match read_map.get(&source) {
                        Some(&(id, region)) if id == node_id => region,
                        _ => return Err("指定されたアドレスはこのノードに属していません")
                    }
                } else {
                    return Err("アドレスマップの読み取りに失敗しました");
                }
            },
            None => return Err("アドレスマップが初期化されていません")
        };
        
        // リージョンを取得
        let region = match node.regions[region_id].as_ref() {
            Some(r) if r.is_used.load(Ordering::Relaxed) => r,
            _ => return Err("指定されたリージョンは使用されていません")
        };
        
        // 領域サイズを確認
        if source + size > region.local_addr + region.size {
            return Err("コピーサイズが領域を超えています");
        }
        
        // リモートアドレスを計算
        let remote_offset = source - region.local_addr;
        let remote_addr = region.remote_addr + remote_offset;
        
        // 接続を取得
        let connection = node.connection.as_ref().ok_or("RDMA接続が確立されていません")?;
        
        // データを読み込み
        connection.read(remote_addr, dest as *mut u8, size, region.rkey)
            .map_err(|_| "リモートメモリからの読み込みに失敗しました")?;
        
        // アクセス時刻を更新
        region.last_access.store(get_timestamp(), Ordering::Relaxed);
    }
    
    Ok(())
}

/// 最適なノードを選択
pub fn select_optimal_node(pages: usize) -> Result<RemoteNodeId, &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("リモートメモリモジュールが初期化されていません");
    }
    
    let size = pages * PAGE_SIZE;
    let mut best_node_id = 0;
    let mut best_score = 0.0;
    let mut found = false;
    
    unsafe {
        for i in 0..MAX_NODES {
            if let Some(node) = REMOTE_NODES[i].as_ref() {
                // 接続状態を確認
                if !node.connected.load(Ordering::SeqCst) {
                    // 未接続ノードは自動的に接続を試みる
                    if let Err(_) = connect_to_node(i) {
                        continue;
                    }
                }
                
                // 利用可能なメモリがあるか確認
                let available = node.total_memory.load(Ordering::Relaxed) - node.used_memory.load(Ordering::Relaxed);
                if size > available {
                    continue;
                }
                
                // リージョンの空きがあるか確認
                if !node.regions.iter().any(Option::is_none) {
                    continue;
                }
                
                // ノードのスコアを計算
                let latency = node.current_latency.load(Ordering::Relaxed) as f64;
                let bandwidth = node.bandwidth_mbps.load(Ordering::Relaxed) as f64;
                let mem_ratio = available as f64 / node.total_memory.load(Ordering::Relaxed) as f64;
                
                // スコアは帯域幅とメモリ比率に比例し、レイテンシに反比例
                let score = (bandwidth * mem_ratio) / (latency + 1.0);
                
                if !found || score > best_score {
                    best_node_id = i;
                    best_score = score;
                    found = true;
                }
            }
        }
    }
    
    if found {
        Ok(best_node_id)
    } else {
        Err("利用可能なリモートノードがありません")
    }
}

/// 移行に最適なノードを選択
pub fn select_optimal_node_for_migration(source: usize, size: usize) -> Result<RemoteNodeId, &'static str> {
    // 基本的には通常の選択と同じだが、移行元データの特性に応じて最適化できる
    let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    select_optimal_node(pages)
}

/// ノードが利用可能かどうかを確認
pub fn is_node_available(node_id: RemoteNodeId) -> bool {
    if node_id >= MAX_NODES || !INITIALIZED.load(Ordering::SeqCst) {
        return false;
    }
    
    unsafe {
        if let Some(node) = REMOTE_NODES[node_id].as_ref() {
            // 接続状態を確認
            if !node.connected.load(Ordering::SeqCst) {
                // 未接続なら接続を試みる
                if let Err(_) = connect_to_node(node_id) {
                    return false;
                }
            }
            
            return node.connected.load(Ordering::SeqCst);
        }
    }
    
    false
}

/// リモートメモリにプリフェッチを実行
pub fn prefetch(node_id: RemoteNodeId, address: usize, size: usize) -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("リモートメモリモジュールが初期化されていません");
    }
    
    if node_id >= MAX_NODES {
        return Err("無効なノードIDです");
    }
    
    unsafe {
        let node = REMOTE_NODES[node_id].as_ref().ok_or("ノードが存在しません")?;
        
        // ノードの状態を確認
        if !node.connected.load(Ordering::SeqCst) {
            return Err("ノードに接続されていません");
        }
        
        // リージョンIDを特定
        let region_id = match ADDRESS_MAP.as_ref() {
            Some(map) => {
                if let Ok(read_map) = map.read() {
                    match read_map.get(&address) {
                        Some(&(id, region)) if id == node_id => region,
                        _ => return Err("指定されたアドレスはこのノードに属していません")
                    }
                } else {
                    return Err("アドレスマップの読み取りに失敗しました");
                }
            },
            None => return Err("アドレスマップが初期化されていません")
        };
        
        // リージョンを取得
        let region = match node.regions[region_id].as_ref() {
            Some(r) if r.is_used.load(Ordering::Relaxed) => r,
            _ => return Err("指定されたリージョンは使用されていません")
        };
        
        // 領域サイズを確認
        if address + size > region.local_addr + region.size {
            return Err("プリフェッチサイズが領域を超えています");
        }
        
        // リモートアドレスを計算
        let remote_offset = address - region.local_addr;
        let remote_addr = region.remote_addr + remote_offset;
        
        // 接続を取得
        let connection = node.connection.as_ref().ok_or("RDMA接続が確立されていません")?;
        
        // プリフェッチ
        connection.prefetch(remote_addr, size, region.rkey)
            .map_err(|_| "リモートメモリのプリフェッチに失敗しました")?;
    }
    
    Ok(())
}

/// すべてのノードとデータを同期
pub fn sync_all() -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("リモートメモリモジュールが初期化されていません");
    }
    
    unsafe {
        for i in 0..MAX_NODES {
            if let Some(node) = REMOTE_NODES[i].as_ref() {
                if node.connected.load(Ordering::SeqCst) {
                    // 接続を取得
                    if let Some(connection) = node.connection.as_ref() {
                        // すべてのリージョンを同期
                        for region_opt in node.regions.iter() {
                            if let Some(region) = region_opt {
                                if region.is_used.load(Ordering::Relaxed) {
                                    // データを同期
                                    connection.flush(region.remote_addr, region.size, region.rkey)
                                        .map_err(|_| "リモートメモリの同期に失敗しました")?;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok(())
}

/// 接続パラメータを最適化
pub fn optimize_parameters(network_latency_ns: u64) -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }
    
    unsafe {
        for i in 0..MAX_NODES {
            if let Some(node) = REMOTE_NODES[i].as_mut() {
                if node.connected.load(Ordering::SeqCst) {
                    if let Some(connection) = node.connection.as_mut() {
                        // パラメータを最適化
                        connection.optimize_for_latency(network_latency_ns)
                            .map_err(|_| "接続パラメータの最適化に失敗しました")?;
                        
                        // 現在のレイテンシを更新
                        let measured_latency = connection.measure_latency()
                            .map_err(|_| "レイテンシの測定に失敗しました")?;
                        
                        node.current_latency.store(measured_latency, Ordering::Relaxed);
                    }
                }
            }
        }
    }
    
    Ok(())
}

/// 診断の実行
pub fn run_diagnostics() -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("リモートメモリモジュールが初期化されていません");
    }
    
    // 現在の帯域使用状況を取得
    let mut total_bandwidth = 0;
    
    unsafe {
        for i in 0..MAX_NODES {
            if let Some(node) = REMOTE_NODES[i].as_ref() {
                if node.connected.load(Ordering::SeqCst) {
                    if let Some(connection) = node.connection.as_ref() {
                        // 帯域使用率を計測
                        let bandwidth = connection.measure_bandwidth()
                            .unwrap_or(0);
                        
                        total_bandwidth += bandwidth;
                        
                        // 統計情報に記録
                        stats::record_bandwidth_usage(i, bandwidth);
                    }
                }
            }
        }
    }
    
    Ok(())
}

/// ノード数を取得
pub fn get_node_count() -> usize {
    NODE_COUNT.load(Ordering::SeqCst)
}

/// アクティブノード数を取得
pub fn get_active_node_count() -> usize {
    ACTIVE_NODE_COUNT.load(Ordering::SeqCst)
}

/// 総ページ数を取得
pub fn get_total_pages() -> usize {
    TOTAL_PAGES.load(Ordering::SeqCst)
}

/// 割り当て済みページ数を取得
pub fn get_allocated_pages() -> usize {
    unsafe {
        let mut allocated = 0;
        
        for i in 0..MAX_NODES {
            if let Some(node) = REMOTE_NODES[i].as_ref() {
                allocated += node.used_memory.load(Ordering::Relaxed) / PAGE_SIZE;
            }
        }
        
        allocated
    }
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