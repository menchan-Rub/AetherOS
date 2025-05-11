// AetherOS NUMA (Non-Uniform Memory Access) モジュール
//
// このモジュールは、マルチプロセッサシステムにおける非均一メモリアクセス（NUMA）を
// 管理するための機能を提供します。NUMAシステムでは、メモリへのアクセス時間は
// アクセスするCPUによって異なります。

use crate::arch::MemoryInfo;
use crate::core::memory::{NumaNodeInfo, MemoryTier};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;

/// NUMAトポロジーマネージャ
pub struct NumaManager {
    /// ノード数
    nodes_count: usize,
    /// ノード情報
    nodes: Vec<NumaNodeInfo>,
    /// レイテンシマトリクス [from_node][to_node]
    latency_matrix: Vec<Vec<usize>>,
    /// 各ノードのメモリ使用率 (パーセント)
    node_usage: Vec<AtomicUsize>,
}

/// NUMA配置ポリシー
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NumaPolicy {
    /// 常にCPUに最も近いノードを使用
    StrictLocal,
    /// ローカルノードが閾値以上に使用されている場合、次に近いノードを使用
    PreferLocal(usize), // 閾値パーセント (例: 80 = 80%)
    /// システム全体で均等に分散
    Interleave,
    /// 特定のノードに固定
    Bind(usize),
    /// 任意のノードを使用 (システムに任せる)
    Any,
}

/// スレッドごとのNUMAポリシー
pub static DEFAULT_POLICY: RwLock<NumaPolicy> = RwLock::new(NumaPolicy::PreferLocal(80));

/// グローバルNUMAマネージャ
static mut NUMA_MANAGER: Option<NumaManager> = None;

/// モジュールの初期化
pub fn init(mem_info: &MemoryInfo) {
    let nodes_count = mem_info.numa_node_count;
    if nodes_count <= 1 {
        log::warn!("NUMAが検出されないか単一ノードのみ: NUMA管理を簡略化します");
        return;
    }
    
    log::info!("NUMAサポートを初期化中: {} ノード検出", nodes_count);
    
    // ノード情報をメモリ情報から抽出
    let mut nodes = Vec::with_capacity(nodes_count);
    for i in 0..nodes_count {
        let node_info = NumaNodeInfo {
            id: i,
            memory_total: mem_info.numa_memory_per_node,
            memory_available: AtomicUsize::new(mem_info.numa_memory_per_node),
            latency_ns: mem_info.numa_latency_matrix[i][i],
            local_cpus: mem_info.numa_cpu_map[i].clone(),
        };
        nodes.push(node_info);
    }
    
    // 使用率追跡器
    let node_usage = (0..nodes_count)
        .map(|_| AtomicUsize::new(0))
        .collect::<Vec<_>>();
    
    let numa_manager = NumaManager {
        nodes_count,
        nodes,
        latency_matrix: mem_info.numa_latency_matrix.clone(),
        node_usage,
    };
    
    unsafe {
        NUMA_MANAGER = Some(numa_manager);
    }
    
    log::info!("NUMA初期化完了: {} ノード, アクセスマトリクス構築完了", nodes_count);
}

/// 特定のCPUに最も近いNUMAノードを取得
pub fn get_node_for_cpu(cpu_id: usize) -> Option<usize> {
    let manager = unsafe { NUMA_MANAGER.as_ref()? };
    
    // CPUが属するノードを検索
    for (node_id, node) in manager.nodes.iter().enumerate() {
        if node.local_cpus.contains(&cpu_id) {
            return Some(node_id);
        }
    }
    
    // 見つからない場合は0番ノードを返す
    if !manager.nodes.is_empty() {
        return Some(0);
    }
    
    None
}

/// 現在実行中のCPUのローカルNUMAノードを取得
pub fn get_local_node() -> Option<usize> {
    let cpu_id = crate::arch::get_current_cpu();
    get_node_for_cpu(cpu_id)
}

/// ノード間の相対的なアクセスコスト（レイテンシベース）を取得
pub fn get_access_cost(from_node: usize, to_node: usize) -> Option<usize> {
    let manager = unsafe { NUMA_MANAGER.as_ref()? };
    
    if from_node >= manager.nodes_count || to_node >= manager.nodes_count {
        return None;
    }
    
    Some(manager.latency_matrix[from_node][to_node])
}

/// 現在のポリシーに基づいて適切なNUMAノードを選択
pub fn select_node_for_allocation(size: usize, requesting_cpu: Option<usize>) -> Option<usize> {
    let manager = unsafe { NUMA_MANAGER.as_ref()? };
    if manager.nodes_count <= 1 {
        return Some(0); // 単一ノードの場合はそれを返す
    }
    
    // CPUがどのノードに属しているかを特定
    let current_cpu = requesting_cpu.unwrap_or_else(|| crate::arch::get_current_cpu());
    let local_node = get_node_for_cpu(current_cpu)?;
    
    // 現在のポリシーを取得
    let policy = *DEFAULT_POLICY.read();
    
    match policy {
        NumaPolicy::StrictLocal => {
            // 常にローカルノードから割り当て
            Some(local_node)
        },
        NumaPolicy::PreferLocal(threshold) => {
            // ローカルノードの使用率をチェック
            let local_usage = manager.node_usage[local_node].load(Ordering::Relaxed);
            
            if local_usage < threshold {
                // 閾値以下ならローカルノードを使用
                Some(local_node)
            } else {
                // 閾値を超えている場合は次に利用可能なノードを探す
                find_least_used_node(manager, Some(local_node))
            }
        },
        NumaPolicy::Interleave => {
            // 最も使用率の低いノードを選択
            find_least_used_node(manager, None)
        },
        NumaPolicy::Bind(node) => {
            // 指定されたノードが有効なら使用
            if node < manager.nodes_count {
                Some(node)
            } else {
                Some(local_node) // 無効なら現在のノード
            }
        },
        NumaPolicy::Any => {
            // 最も利用可能なメモリが多いノードを選択
            find_node_with_most_available_memory(manager)
        }
    }
}

/// メモリ割り当て時にNUMAノードの使用率を更新
pub fn record_allocation(node: usize, size: usize) {
    let manager = unsafe {
        if let Some(manager) = NUMA_MANAGER.as_ref() {
            manager
        } else {
            return;
        }
    };
    
    if node >= manager.nodes_count {
        return;
    }
    
    // ノードの利用可能メモリを減らす
    if let Some(node_info) = manager.nodes.get(node) {
        let prev = node_info.memory_available.fetch_sub(size, Ordering::Relaxed);
        
        // 利用可能メモリが不足している場合はログ記録
        if prev < size {
            node_info.memory_available.store(0, Ordering::Relaxed);
            log::warn!("NUMA警告: ノード{}のメモリオーバーコミット", node);
        }
        
        // 使用率の計算と更新
        let total = node_info.memory_total;
        let available = node_info.memory_available.load(Ordering::Relaxed);
        let usage_percent = ((total - available) * 100) / total;
        
        manager.node_usage[node].store(usage_percent, Ordering::Relaxed);
    }
}

/// メモリ解放時にNUMAノードの使用率を更新
pub fn record_deallocation(node: usize, size: usize) {
    let manager = unsafe {
        if let Some(manager) = NUMA_MANAGER.as_ref() {
            manager
        } else {
            return;
        }
    };
    
    if node >= manager.nodes_count {
        return;
    }
    
    // ノードの利用可能メモリを増やす
    if let Some(node_info) = manager.nodes.get(node) {
        node_info.memory_available.fetch_add(size, Ordering::Relaxed);
        
        // 使用率の更新
        let total = node_info.memory_total;
        let available = node_info.memory_available.load(Ordering::Relaxed);
        let usage_percent = ((total - available) * 100) / total;
        
        manager.node_usage[node].store(usage_percent, Ordering::Relaxed);
    }
}

/// グローバルNUMAポリシーを設定
pub fn set_default_policy(policy: NumaPolicy) {
    *DEFAULT_POLICY.write() = policy;
    log::debug!("NUMAデフォルトポリシーを設定: {:?}", policy);
}

/// 使用率が最も低いノードを見つける
fn find_least_used_node(manager: &NumaManager, exclude_node: Option<usize>) -> Option<usize> {
    let mut lowest_usage = 100;
    let mut best_node = 0;
    
    for node in 0..manager.nodes_count {
        // 除外ノードならスキップ
        if let Some(excluded) = exclude_node {
            if node == excluded {
                continue;
            }
        }
        
        let usage = manager.node_usage[node].load(Ordering::Relaxed);
        if usage < lowest_usage {
            lowest_usage = usage;
            best_node = node;
        }
    }
    
    Some(best_node)
}

/// 利用可能メモリが最も多いノードを見つける
fn find_node_with_most_available_memory(manager: &NumaManager) -> Option<usize> {
    let mut most_available = 0;
    let mut best_node = 0;
    
    for (node, info) in manager.nodes.iter().enumerate() {
        let available = info.memory_available.load(Ordering::Relaxed);
        if available > most_available {
            most_available = available;
            best_node = node;
        }
    }
    
    Some(best_node)
}

/// 特定のNUMAノードでメモリを割り当て
pub fn allocate_on_node(size: usize, node: usize) -> Option<*mut u8> {
    let manager = unsafe { NUMA_MANAGER.as_ref()? };
    
    if node >= manager.nodes_count {
        return None;
    }
    
    // ノードの空き容量チェック
    let node_info = &manager.nodes[node];
    let available = node_info.memory_available.load(Ordering::Relaxed);
    
    if available < size {
        log::warn!("NUMAノード{}に十分なメモリがありません: 要求={}, 利用可能={}", 
                  node, size, available);
        return None;
    }
    
    // バディアロケータを通じて特定ノードに割り当て
    let ptr = crate::core::memory::buddy::allocate_on_node(size, node);
    
    // 割り当てに成功したらノード統計を更新
    if let Some(ptr) = ptr {
        record_allocation(node, size);
    }
    
    ptr
}

/// NUMAノード数を取得
pub fn get_node_count() -> usize {
    unsafe {
        NUMA_MANAGER.as_ref().map_or(1, |m| m.nodes_count)
    }
}

/// NUMA情報を表示
pub fn print_info() {
    let manager = unsafe {
        if let Some(manager) = NUMA_MANAGER.as_ref() {
            manager
        } else {
            log::info!("NUMA非対応システムまたは未初期化");
            return;
        }
    };
    
    log::info!("--- NUMA情報 ---");
    log::info!("ノード数: {}", manager.nodes_count);
    
    for (i, node) in manager.nodes.iter().enumerate() {
        let total_mb = node.memory_total / 1024 / 1024;
        let available_mb = node.memory_available.load(Ordering::Relaxed) / 1024 / 1024;
        let usage = ((node.memory_total - node.memory_available.load(Ordering::Relaxed)) * 100) 
                    / node.memory_total;
        
        log::info!("ノード#{}: メモリ: {}MB/{}MB (使用率: {}%), CPUs: {:?}",
                  i, available_mb, total_mb, usage, node.local_cpus);
    }
    
    log::info!("現在のデフォルトポリシー: {:?}", *DEFAULT_POLICY.read());
    log::info!("-----------------");
} 