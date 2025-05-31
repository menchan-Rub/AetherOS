// AetherOS プロセスアフィニティ管理サブシステム
//
// 高度なCPU/NUMA/キャッシュアフィニティ管理を提供し、
// ハードウェアトポロジーを考慮した最適なスケジューリングを実現します。

use crate::arch;
use crate::core::memory::{MemoryManager, PhysicalAddress};
use crate::core::process::{Process, ProcessId, Thread, ThreadId};
use crate::core::sync::{Mutex, RwLock, SpinLock, AtomicU64};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

// サブモジュール
mod topology;    // トポロジー対応
mod policy;      // アフィニティポリシー
mod numa;        // NUMAアフィニティ
mod cache;       // キャッシュアフィニティ
mod sibling;     // SMT/コアシブリング対応
mod balancer;    // ロードバランサー

// 公開インターフェース
pub use topology::TopologyNode;
pub use policy::{AffinityPolicy, AffinityStrategy};
pub use numa::{NUMANode, NUMADistance, NUMATopology};
pub use cache::{CacheLevel, CacheHierarchy, CacheAffinityHint};
pub use sibling::{CoreSibling, SMTGroup};
pub use balancer::{LoadBalancingPolicy, LoadData};

/// グローバルアフィニティマネージャー
static mut AFFINITY_MANAGER: Option<AffinityManager> = None;

/// アフィニティ初期化
pub fn init() {
    log::info!("プロセスアフィニティ管理サブシステムを初期化しています...");
    
    // NUMAトポロジーを検出
    let numa_topology = NUMATopology::detect();
    
    // キャッシュ階層を検出
    let cache_hierarchy = CacheHierarchy::detect();
    
    // ハードウェアトポロジーを検出
    let hw_topology = arch::detect_hardware_topology();
    
    // アフィニティマネージャを作成
    let manager = AffinityManager::new(
        numa_topology,
        cache_hierarchy,
        hw_topology,
    );
    
    // グローバルインスタンスを設定
    unsafe {
        AFFINITY_MANAGER = Some(manager);
    }
    
    log::info!("プロセスアフィニティ管理サブシステム初期化完了");
}

/// グローバルマネージャーを取得
pub fn global_manager() -> &'static AffinityManager {
    unsafe {
        AFFINITY_MANAGER.as_ref().expect("アフィニティマネージャが初期化されていません")
    }
}

/// CPUマスク
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CpuMask {
    /// CPUビットマスク
    bits: Vec<u64>,
}

impl CpuMask {
    /// 新しいCPUマスクを作成
    pub fn new() -> Self {
        // システムのCPU数に基づいてサイズを決定
        let max_cpus = arch::get_max_cpus();
        let num_words = (max_cpus + 63) / 64;
        let mut bits = Vec::with_capacity(num_words);
        
        for _ in 0..num_words {
            bits.push(0);
        }
        
        Self { bits }
    }
    
    /// 全CPUを含むマスクを作成
    pub fn all() -> Self {
        let mut mask = Self::new();
        
        // 全CPUをセット
        let max_cpus = arch::get_max_cpus();
        for cpu_id in 0..max_cpus {
            mask.set(cpu_id as u32);
        }
        
        mask
    }
    
    /// 単一CPUのマスクを作成
    pub fn single(cpu_id: u32) -> Self {
        let mut mask = Self::new();
        mask.set(cpu_id);
        mask
    }
    
    /// 特定のCPUをマスクに含める
    pub fn set(&mut self, cpu_id: u32) {
        let word_index = (cpu_id / 64) as usize;
        let bit_index = cpu_id % 64;
        
        if word_index < self.bits.len() {
            self.bits[word_index] |= 1u64 << bit_index;
        }
    }
    
    /// 特定のCPUをマスクから除外
    pub fn clear(&mut self, cpu_id: u32) {
        let word_index = (cpu_id / 64) as usize;
        let bit_index = cpu_id % 64;
        
        if word_index < self.bits.len() {
            self.bits[word_index] &= !(1u64 << bit_index);
        }
    }
    
    /// 特定のCPUがマスクに含まれているか確認
    pub fn is_set(&self, cpu_id: u32) -> bool {
        let word_index = (cpu_id / 64) as usize;
        let bit_index = cpu_id % 64;
        
        if word_index < self.bits.len() {
            (self.bits[word_index] & (1u64 << bit_index)) != 0
        } else {
            false
        }
    }
    
    /// マスクに含まれるCPU数を取得
    pub fn count(&self) -> u32 {
        let mut count = 0;
        
        for word in &self.bits {
            count += word.count_ones();
        }
        
        count
    }
    
    /// マスクに含まれるCPU IDのリストを取得
    pub fn to_cpu_list(&self) -> Vec<u32> {
        let mut cpu_list = Vec::new();
        
        for (word_index, word) in self.bits.iter().enumerate() {
            let base_cpu_id = word_index as u32 * 64;
            
            for bit_index in 0..64 {
                if (word & (1u64 << bit_index)) != 0 {
                    cpu_list.push(base_cpu_id + bit_index);
                }
            }
        }
        
        cpu_list
    }
    
    /// マスクのAND演算
    pub fn and(&self, other: &Self) -> Self {
        let mut result = Self::new();
        
        for i in 0..self.bits.len().min(other.bits.len()) {
            result.bits[i] = self.bits[i] & other.bits[i];
        }
        
        result
    }
    
    /// マスクのOR演算
    pub fn or(&self, other: &Self) -> Self {
        let mut result = Self::new();
        
        for i in 0..self.bits.len().min(other.bits.len()) {
            result.bits[i] = self.bits[i] | other.bits[i];
        }
        
        result
    }
    
    /// マスクの反転
    pub fn invert(&self) -> Self {
        let mut result = Self::new();
        
        for i in 0..self.bits.len() {
            result.bits[i] = !self.bits[i];
        }
        
        // システムの最大CPU数を超えるビットをクリア
        let max_cpus = arch::get_max_cpus();
        let max_word = max_cpus / 64;
        let max_bit = max_cpus % 64;
        
        if max_word < result.bits.len() {
            // 最後のワードの不要なビットをクリア
            if max_bit > 0 {
                let mask = (1u64 << max_bit) - 1;
                result.bits[max_word as usize] &= mask;
            }
            
            // それ以降のワードをクリア
            for i in (max_word + 1) as usize..result.bits.len() {
                result.bits[i] = 0;
            }
        }
        
        result
    }
}

/// アフィニティ種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffinityType {
    /// CPUアフィニティ
    Cpu,
    /// NUMAアフィニティ
    Numa,
    /// キャッシュアフィニティ
    Cache,
    /// コアアフィニティ
    Core,
    /// SMTアフィニティ
    Smt,
    /// メモリアフィニティ
    Memory,
}

/// アフィニティレベル
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AffinityLevel {
    /// システム全体
    System,
    /// NUMAノード
    NumaNode,
    /// ソケット
    Socket,
    /// クラスタ
    Cluster,
    /// コアグループ
    CoreGroup,
    /// 物理コア
    PhysicalCore,
    /// 論理コア（SMT）
    LogicalCore,
}

/// アフィニティ操作結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AffinityResult {
    /// 成功
    Success,
    /// 不正なCPU ID
    InvalidCpuId,
    /// サポートされていない機能
    UnsupportedFeature,
    /// 対象が見つからない
    TargetNotFound,
    /// 権限なし
    PermissionDenied,
    /// 一般エラー
    GeneralError,
}

/// アフィニティマネージャー
pub struct AffinityManager {
    /// NUMAトポロジー
    numa_topology: NUMATopology,
    /// キャッシュ階層
    cache_hierarchy: CacheHierarchy,
    /// ハードウェアトポロジー
    hw_topology: arch::HardwareTopology,
    /// プロセスアフィニティマップ
    process_affinities: RwLock<BTreeMap<ProcessId, CpuMask>>,
    /// スレッドアフィニティマップ
    thread_affinities: RwLock<BTreeMap<ThreadId, CpuMask>>,
    /// プロセスNUMAポリシー
    process_numa_policies: RwLock<BTreeMap<ProcessId, NUMAPolicy>>,
    /// アフィニティポリシー
    affinity_policy: RwLock<AffinityPolicy>,
    /// 統計情報
    stats: AffinityStats,
}

impl AffinityManager {
    /// 新しいアフィニティマネージャーを作成
    pub fn new(
        numa_topology: NUMATopology,
        cache_hierarchy: CacheHierarchy,
        hw_topology: arch::HardwareTopology,
    ) -> Self {
        Self {
            numa_topology,
            cache_hierarchy,
            hw_topology,
            process_affinities: RwLock::new(BTreeMap::new()),
            thread_affinities: RwLock::new(BTreeMap::new()),
            process_numa_policies: RwLock::new(BTreeMap::new()),
            affinity_policy: RwLock::new(AffinityPolicy::balanced()),
            stats: AffinityStats::new(),
        }
    }
    
    /// プロセスのCPUアフィニティを設定
    pub fn set_process_affinity(&self, process_id: ProcessId, cpu_mask: CpuMask) -> AffinityResult {
        // CPUマスクを検証
        if cpu_mask.count() == 0 {
            return AffinityResult::InvalidCpuId;
        }
        
        // プロセスアフィニティを更新
        let mut process_affinities = self.process_affinities.write();
        process_affinities.insert(process_id, cpu_mask);
        
        // 統計更新
        self.stats.process_affinity_changes.fetch_add(1, Ordering::Relaxed);
        
        AffinityResult::Success
    }
    
    /// スレッドのCPUアフィニティを設定
    pub fn set_thread_affinity(&self, thread_id: ThreadId, cpu_mask: CpuMask) -> AffinityResult {
        // CPUマスクを検証
        if cpu_mask.count() == 0 {
            return AffinityResult::InvalidCpuId;
        }
        
        // スレッドアフィニティを更新
        let mut thread_affinities = self.thread_affinities.write();
        thread_affinities.insert(thread_id, cpu_mask);
        
        // 統計更新
        self.stats.thread_affinity_changes.fetch_add(1, Ordering::Relaxed);
        
        AffinityResult::Success
    }
    
    /// プロセスのCPUアフィニティを取得
    pub fn get_process_affinity(&self, process_id: ProcessId) -> Option<CpuMask> {
        let process_affinities = self.process_affinities.read();
        process_affinities.get(&process_id).cloned()
    }
    
    /// スレッドのCPUアフィニティを取得
    pub fn get_thread_affinity(&self, thread_id: ThreadId) -> Option<CpuMask> {
        let thread_affinities = self.thread_affinities.read();
        thread_affinities.get(&thread_id).cloned()
    }
    
    /// スレッドの実効アフィニティを取得
    pub fn get_effective_affinity(&self, thread_id: ThreadId, process_id: ProcessId) -> CpuMask {
        let thread_affinities = self.thread_affinities.read();
        let process_affinities = self.process_affinities.read();
        
        // スレッドのアフィニティがあれば、そのアフィニティとプロセスのアフィニティの共通部分を使用
        if let Some(thread_mask) = thread_affinities.get(&thread_id) {
            if let Some(process_mask) = process_affinities.get(&process_id) {
                return thread_mask.and(process_mask);
            }
            return thread_mask.clone();
        }
        
        // スレッドアフィニティがない場合は、プロセスアフィニティを使用
        if let Some(process_mask) = process_affinities.get(&process_id) {
            return process_mask.clone();
        }
        
        // どちらも設定されていない場合は、全CPUを許可
        CpuMask::all()
    }
    
    /// NUMAポリシーを設定
    pub fn set_numa_policy(&self, process_id: ProcessId, policy: NUMAPolicy) -> AffinityResult {
        let mut numa_policies = self.process_numa_policies.write();
        numa_policies.insert(process_id, policy);
        
        self.stats.numa_policy_changes.fetch_add(1, Ordering::Relaxed);
        
        AffinityResult::Success
    }
    
    /// NUMAポリシーを取得
    pub fn get_numa_policy(&self, process_id: ProcessId) -> Option<NUMAPolicy> {
        let numa_policies = self.process_numa_policies.read();
        numa_policies.get(&process_id).cloned()
    }
    
    /// 指定されたノードのCPUマスクを取得
    pub fn get_node_cpu_mask(&self, node_id: u32) -> Option<CpuMask> {
        self.numa_topology.get_node_cpu_mask(node_id)
    }
    
    /// 指定されたCPUが属するNUMAノードを取得
    pub fn get_cpu_node(&self, cpu_id: u32) -> Option<u32> {
        self.numa_topology.get_cpu_node(cpu_id)
    }
    
    /// メモリアクセスコストの最適なCPUを取得
    pub fn get_optimal_cpu_for_memory(&self, addr: PhysicalAddress) -> Option<u32> {
        // アドレスからNUMAノードを特定
        if let Some(node_id) = self.numa_topology.get_node_for_address(addr) {
            // ノードの最もロードが低いCPUを選択
            if let Some(cpu_mask) = self.numa_topology.get_node_cpu_mask(node_id) {
                let cpu_list = cpu_mask.to_cpu_list();
                if !cpu_list.is_empty() {
                    // 実際のCPU負荷を考慮して最適なCPUを選択
                    let mut min_load = u64::MAX;
                    let mut optimal_cpu = cpu_list[0];
                    
                    for cpu_id in cpu_list {
                        // リアルタイムでCPU負荷を取得
                        let load = crate::arch::cpu::get_cpu_load_percentage(cpu_id);
                        
                        // 利用可能なメモリも考慮
                        let available_memory = crate::arch::memory::get_cpu_available_memory(cpu_id)
                            .unwrap_or(0);
                        
                        // 負荷とメモリ状況を総合的に評価
                        let score = load as u64 + if available_memory < 1024 * 1024 { 50 } else { 0 }; // 1MB未満なら重いペナルティ
                        
                        if score < min_load {
                            min_load = score;
                            optimal_cpu = cpu_id;
                        }
                    }
                    
                    log::debug!("メモリアドレス 0x{:x} に対する最適CPU: {}", addr.as_usize(), optimal_cpu);
                    return Some(optimal_cpu);
                }
            }
        }
        
        // フォールバック: システム全体で最も負荷の低いCPUを選択
        self.select_least_loaded_cpu()
    }
    
    /// 最も負荷の低いCPUを選択
    fn select_least_loaded_cpu(&self) -> Option<u32> {
        let cpu_count = crate::arch::cpu::get_cpu_count();
        let mut min_load = u64::MAX;
        let mut optimal_cpu = 0;
        
        for cpu_id in 0..cpu_count {
            if let Ok(load) = crate::arch::cpu::get_cpu_load_percentage(cpu_id) {
                if load < min_load {
                    min_load = load;
                    optimal_cpu = cpu_id;
                }
            }
        }
        
        if min_load != u64::MAX {
            Some(optimal_cpu)
        } else {
            None
        }
    }
    
    /// プロセスに対する最適なアフィニティを推奨
    pub fn suggest_process_affinity(&self, process_id: ProcessId) -> CpuMask {
        // システムの負荷とプロセス特性に基づいてアフィニティを推奨
        let policy = {
            let policy = self.affinity_policy.read();
            policy.clone()
        };
        
        match policy.strategy {
            AffinityStrategy::Compact => {
                // できるだけ近いCPUを使う（キャッシュ共有の最大化）
                self.create_compact_mask(process_id)
            },
            AffinityStrategy::Scatter => {
                // できるだけ離れたCPUを使う（リソース競合の最小化）
                self.create_scattered_mask(process_id)
            },
            AffinityStrategy::Balanced => {
                // システム全体のバランスを取る
                self.create_balanced_mask(process_id)
            },
            AffinityStrategy::NumaLocal => {
                // 単一NUMAノードに制限
                if let Some(node_id) = self.suggest_numa_node(process_id) {
                    if let Some(mask) = self.numa_topology.get_node_cpu_mask(node_id) {
                        return mask;
                    }
                }
                CpuMask::all()
            },
        }
    }
    
    /// スレッドに対する最適なアフィニティを推奨
    pub fn suggest_thread_affinity(&self, thread_id: ThreadId, process_id: ProcessId) -> CpuMask {
        // スレッドの特性に基づいてアフィニティを推奨
        // プロセスアフィニティの制約内で推奨
        let process_mask = self.get_process_affinity(process_id).unwrap_or_else(CpuMask::all);
        
        // スレッドタイプに基づく推奨
        let suggested_mask = self.suggest_thread_mask_by_type(thread_id, process_id);
        
        // プロセスアフィニティの制約を適用
        suggested_mask.and(&process_mask)
    }
    
    /// スレッドタイプに基づくマスク推奨
    fn suggest_thread_mask_by_type(&self, thread_id: ThreadId, process_id: ProcessId) -> CpuMask {
        // スレッドの実行特性を分析
        let thread_characteristics = self.analyze_thread_characteristics(thread_id, process_id);
        
        match thread_characteristics.workload_type {
            WorkloadType::CPUIntensive => {
                // CPU集約的なワークロード: 高性能コアを優先
                self.create_high_performance_mask()
            },
            WorkloadType::IOBound => {
                // I/O待機が多い: 効率コアを使用してエネルギー節約
                self.create_efficient_mask()
            },
            WorkloadType::MemoryIntensive => {
                // メモリ集約的: メモリ帯域幅が豊富なCPUを選択
                self.create_memory_optimized_mask()
            },
            WorkloadType::RealTime => {
                // リアルタイム: 専用コアを割り当て
                self.create_dedicated_mask()
            },
            WorkloadType::Interactive => {
                // インタラクティブ: 応答性重視
                self.create_responsive_mask()
            },
            WorkloadType::Background => {
                // バックグラウンド: リソースを控えめに使用
                self.create_background_mask()
            },
        }
    }
    
    /// スレッド特性を分析
    fn analyze_thread_characteristics(&self, thread_id: ThreadId, process_id: ProcessId) -> ThreadCharacteristics {
        // スレッドの実行統計を収集
        let runtime_stats = crate::core::process::get_thread_runtime_stats(thread_id)
            .unwrap_or_default();
        
        // CPU使用率を基にワークロードタイプを推定
        let workload_type = if runtime_stats.cpu_usage_percent > 80.0 {
            WorkloadType::CPUIntensive
        } else if runtime_stats.io_wait_percent > 60.0 {
            WorkloadType::IOBound
        } else if runtime_stats.memory_bandwidth_usage > 70.0 {
            WorkloadType::MemoryIntensive
        } else if runtime_stats.is_realtime {
            WorkloadType::RealTime
        } else if runtime_stats.interactive_score > 0.7 {
            WorkloadType::Interactive
        } else {
            WorkloadType::Background
        };
        
        ThreadCharacteristics {
            workload_type,
            priority: runtime_stats.priority,
            cpu_usage_percent: runtime_stats.cpu_usage_percent,
            memory_usage_mb: runtime_stats.memory_usage_mb,
            io_operations_per_second: runtime_stats.io_operations_per_second,
        }
    }
    
    /// 最適なNUMAノードを推奨
    fn suggest_numa_node(&self, process_id: ProcessId) -> Option<u32> {
        // プロセスのメモリ使用パターンを分析
        let memory_pattern = crate::core::process::analyze_memory_access_pattern(process_id)
            .unwrap_or_default();
        
        // 最も頻繁にアクセスされるメモリ領域のNUMAノードを特定
        if !memory_pattern.hot_addresses.is_empty() {
            for addr in memory_pattern.hot_addresses.iter().take(5) { // 上位5つのホットアドレス
                if let Some(node_id) = self.numa_topology.get_node_for_address(*addr) {
                    // そのノードの負荷をチェック
                    let node_load = self.numa_topology.get_node_load(node_id);
                    if node_load < 80 { // 80%未満の負荷なら推奨
                        return Some(node_id);
                    }
                }
            }
        }
        
        // フォールバック: 最もロードが低いノードを選択
        let node_count = self.numa_topology.get_node_count();
        if node_count <= 1 {
            return if node_count == 1 { Some(0) } else { None };
        }
        
        let mut min_load = u64::MAX;
        let mut min_node = 0;
        
        for node_id in 0..node_count {
            let load = self.numa_topology.get_node_load(node_id);
            if load < min_load {
                min_load = load;
                min_node = node_id;
            }
        }
        
        Some(min_node)
    }
    
    /// コンパクトなCPUマスクを作成
    fn create_compact_mask(&self, process_id: ProcessId) -> CpuMask {
        // プロセスの要求に基づいて必要なCPU数を決定
        let required_cpus = self.estimate_required_cpus(process_id);
        
        let mut mask = CpuMask::new();
        let socket_count = self.hw_topology.get_socket_count();
        
        if socket_count > 0 {
            // 最も負荷の低いソケットを選択
            let mut min_socket_load = u64::MAX;
            let mut target_socket = 0;
            
            for socket_id in 0..socket_count {
                let socket_load = self.calculate_socket_load(socket_id);
                if socket_load < min_socket_load {
                    min_socket_load = socket_load;
                    target_socket = socket_id;
                }
            }
            
            // 選択されたソケット内で連続するコアを割り当て
            let cores = self.hw_topology.get_cores_in_socket(target_socket);
            let mut assigned_cpus = 0;
            
            for core_id in cores {
                if assigned_cpus >= required_cpus {
                    break;
                }
                
                let cpus = self.hw_topology.get_logical_cpus_in_core(core_id);
                for cpu_id in cpus {
                    if assigned_cpus >= required_cpus {
                        break;
                    }
                    mask.set(cpu_id);
                    assigned_cpus += 1;
                }
            }
        }
        
        // 必要なCPU数が不足している場合は他のソケットからも追加
        if mask.count() < required_cpus {
            for socket_id in 0..socket_count {
                if mask.count() >= required_cpus {
                    break;
                }
                
                let cores = self.hw_topology.get_cores_in_socket(socket_id);
                for core_id in cores {
                    let cpus = self.hw_topology.get_logical_cpus_in_core(core_id);
                    for cpu_id in cpus {
                        if !mask.is_set(cpu_id) {
                            mask.set(cpu_id);
                            if mask.count() >= required_cpus {
                                break;
                            }
                        }
                    }
                    if mask.count() >= required_cpus {
                        break;
                    }
                }
            }
        }
        
        if mask.count() == 0 {
            mask = CpuMask::all(); // フォールバック
        }
        
        mask
    }
    
    /// 分散したCPUマスクを作成
    fn create_scattered_mask(&self, process_id: ProcessId) -> CpuMask {
        let required_cpus = self.estimate_required_cpus(process_id);
        let mut mask = CpuMask::new();
        
        let socket_count = self.hw_topology.get_socket_count();
        let mut assigned_cpus = 0;
        
        // 各ソケットから均等にCPUを選択
        let cpus_per_socket = (required_cpus + socket_count - 1) / socket_count; // 切り上げ除算
        
        for socket_id in 0..socket_count {
            if assigned_cpus >= required_cpus {
                break;
            }
            
            let cores = self.hw_topology.get_cores_in_socket(socket_id);
            let mut socket_assigned = 0;
            
            for core_id in cores {
                if socket_assigned >= cpus_per_socket || assigned_cpus >= required_cpus {
                    break;
                }
                
                // 各コアから1つのCPUを選択（SMTを活用しない）
                let cpus = self.hw_topology.get_logical_cpus_in_core(core_id);
                if !cpus.is_empty() {
                    mask.set(cpus[0]); // 最初のCPUのみ使用
                    socket_assigned += 1;
                    assigned_cpus += 1;
                }
            }
        }
        
        if mask.count() == 0 {
            mask = CpuMask::all(); // フォールバック
        }
        
        mask
    }
    
    /// バランスの取れたマスクを作成
    fn create_balanced_mask(&self, process_id: ProcessId) -> CpuMask {
        let required_cpus = self.estimate_required_cpus(process_id);
        let mut mask = CpuMask::new();
        
        // システム全体の負荷を考慮してCPUを選択
        let cpu_count = crate::arch::cpu::get_cpu_count();
        let mut cpu_loads = Vec::new();
        
        for cpu_id in 0..cpu_count {
            if let Ok(load) = crate::arch::cpu::get_cpu_load_percentage(cpu_id) {
                cpu_loads.push((cpu_id, load));
            }
        }
        
        // 負荷の低い順にソート
        cpu_loads.sort_by(|a, b| a.1.cmp(&b.1));
        
        // 必要な数だけ負荷の低いCPUを選択
        for (cpu_id, _load) in cpu_loads.iter().take(required_cpus as usize) {
            mask.set(*cpu_id);
        }
        
        if mask.count() == 0 {
            mask = CpuMask::all(); // フォールバック
        }
        
        mask
    }
    
    /// グローバルアフィニティポリシーを設定
    pub fn set_affinity_policy(&self, policy: AffinityPolicy) {
        let mut current_policy = self.affinity_policy.write();
        *current_policy = policy;
    }
    
    /// グローバルアフィニティポリシーを取得
    pub fn get_affinity_policy(&self) -> AffinityPolicy {
        let policy = self.affinity_policy.read();
        policy.clone()
    }
    
    /// アフィニティ統計情報を取得
    pub fn get_stats(&self) -> AffinityStatsSnapshot {
        AffinityStatsSnapshot {
            process_affinity_changes: self.stats.process_affinity_changes.load(Ordering::Relaxed),
            thread_affinity_changes: self.stats.thread_affinity_changes.load(Ordering::Relaxed),
            numa_policy_changes: self.stats.numa_policy_changes.load(Ordering::Relaxed),
            optimal_placements: self.stats.optimal_placements.load(Ordering::Relaxed),
        }
    }
    
    /// 必要なCPU数を推定
    fn estimate_required_cpus(&self, process_id: ProcessId) -> u32 {
        // プロセスの特性に基づいて必要なCPU数を推定
        if let Ok(process_info) = crate::core::process::get_process_info(process_id) {
            // スレッド数を基に推定
            let thread_count = process_info.thread_count;
            
            // CPU集約的なプロセスはより多くのCPUを必要とする
            let cpu_multiplier = if process_info.is_cpu_intensive {
                2.0
            } else if process_info.is_io_bound {
                0.5
            } else {
                1.0
            };
            
            let estimated = (thread_count as f32 * cpu_multiplier).ceil() as u32;
            
            // システムのCPU数を超えないように制限
            let max_cpus = crate::arch::cpu::get_cpu_count();
            estimated.min(max_cpus).max(1)
        } else {
            1 // デフォルト値
        }
    }
    
    /// ソケットの負荷を計算
    fn calculate_socket_load(&self, socket_id: u32) -> u64 {
        let cores = self.hw_topology.get_cores_in_socket(socket_id);
        let mut total_load = 0u64;
        let mut cpu_count = 0;
        
        for core_id in cores {
            let cpus = self.hw_topology.get_logical_cpus_in_core(core_id);
            for cpu_id in cpus {
                if let Ok(load) = crate::arch::cpu::get_cpu_load_percentage(cpu_id) {
                    total_load += load;
                    cpu_count += 1;
                }
            }
        }
        
        if cpu_count > 0 {
            total_load / cpu_count as u64
        } else {
            0
        }
    }
    
    /// 高性能マスクを作成
    fn create_high_performance_mask(&self) -> CpuMask {
        let mut mask = CpuMask::new();
        
        // P-コア（Performance cores）を優先的に選択
        let cpu_count = crate::arch::cpu::get_cpu_count();
        
        for cpu_id in 0..cpu_count {
            if crate::arch::cpu::is_performance_core(cpu_id).unwrap_or(false) {
                mask.set(cpu_id);
            }
        }
        
        // P-コアがない場合は全CPUを使用
        if mask.count() == 0 {
            mask = CpuMask::all();
        }
        
        mask
    }
    
    /// 効率マスクを作成
    fn create_efficient_mask(&self) -> CpuMask {
        let mut mask = CpuMask::new();
        
        // E-コア（Efficiency cores）を優先的に選択
        let cpu_count = crate::arch::cpu::get_cpu_count();
        
        for cpu_id in 0..cpu_count {
            if crate::arch::cpu::is_efficiency_core(cpu_id).unwrap_or(false) {
                mask.set(cpu_id);
            }
        }
        
        // E-コアがない場合は負荷の低いCPUを選択
        if mask.count() == 0 {
            if let Some(cpu_id) = self.select_least_loaded_cpu() {
                mask.set(cpu_id);
            } else {
                mask = CpuMask::all();
            }
        }
        
        mask
    }
    
    /// メモリ最適化マスクを作成
    fn create_memory_optimized_mask(&self) -> CpuMask {
        let mut mask = CpuMask::new();
        
        // メモリ帯域幅の高いNUMAノードのCPUを選択
        let node_count = self.numa_topology.get_node_count();
        let mut best_nodes = Vec::new();
        
        for node_id in 0..node_count {
            let memory_bandwidth = self.numa_topology.get_node_memory_bandwidth(node_id);
            best_nodes.push((node_id, memory_bandwidth));
        }
        
        // メモリ帯域幅の高い順にソート
        best_nodes.sort_by(|a, b| b.1.cmp(&a.1));
        
        // 上位ノードのCPUを選択
        for (node_id, _bandwidth) in best_nodes.iter().take(2) { // 上位2ノード
            if let Some(node_mask) = self.numa_topology.get_node_cpu_mask(*node_id) {
                mask = mask.or(&node_mask);
            }
        }
        
        if mask.count() == 0 {
            mask = CpuMask::all();
        }
        
        mask
    }
    
    /// 専用マスクを作成（リアルタイム用）
    fn create_dedicated_mask(&self) -> CpuMask {
        let mut mask = CpuMask::new();
        
        // 分離されたCPUを選択（他のプロセスが使用していないCPU）
        let cpu_count = crate::arch::cpu::get_cpu_count();
        
        for cpu_id in 0..cpu_count {
            // CPU利用率が非常に低い（5%未満）CPUを選択
            if let Ok(load) = crate::arch::cpu::get_cpu_load_percentage(cpu_id) {
                if load < 5 {
                    mask.set(cpu_id);
                    // リアルタイムには1つのCPUで十分
                    break;
                }
            }
        }
        
        // 利用可能なCPUがない場合は最も負荷の低いCPUを選択
        if mask.count() == 0 {
            if let Some(cpu_id) = self.select_least_loaded_cpu() {
                mask.set(cpu_id);
            } else {
                mask = CpuMask::single(0); // フォールバック
            }
        }
        
        mask
    }
    
    /// 応答性重視マスクを作成
    fn create_responsive_mask(&self) -> CpuMask {
        let mut mask = CpuMask::new();
        
        // 最高周波数で動作可能なCPUを選択
        let cpu_count = crate::arch::cpu::get_cpu_count();
        let mut cpu_frequencies = Vec::new();
        
        for cpu_id in 0..cpu_count {
            if let Ok(max_freq) = crate::arch::cpu::get_max_frequency(cpu_id) {
                cpu_frequencies.push((cpu_id, max_freq));
            }
        }
        
        // 最高周波数順にソート
        cpu_frequencies.sort_by(|a, b| b.1.cmp(&a.1));
        
        // 上位50%のCPUを選択
        let select_count = (cpu_frequencies.len() / 2).max(1);
        for (cpu_id, _freq) in cpu_frequencies.iter().take(select_count) {
            mask.set(*cpu_id);
        }
        
        if mask.count() == 0 {
            mask = CpuMask::all();
        }
        
        mask
    }
    
    /// バックグラウンドマスクを作成
    fn create_background_mask(&self) -> CpuMask {
        let mut mask = CpuMask::new();
        
        // 効率コアまたは最も負荷の低いCPUを選択
        let cpu_count = crate::arch::cpu::get_cpu_count();
        
        // まず効率コアを探す
        for cpu_id in 0..cpu_count {
            if crate::arch::cpu::is_efficiency_core(cpu_id).unwrap_or(false) {
                mask.set(cpu_id);
                break; // バックグラウンドタスクには1つのCPUで十分
            }
        }
        
        // 効率コアがない場合は最も負荷の低いCPUを選択
        if mask.count() == 0 {
            if let Some(cpu_id) = self.select_least_loaded_cpu() {
                mask.set(cpu_id);
            } else {
                mask = CpuMask::single(0);
            }
        }
        
        mask
    }
}

/// NUMAポリシー
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NUMAPolicy {
    /// デフォルト（システムによる自動選択）
    Default,
    /// バインド（指定されたノードのみを使用）
    Bind(Vec<u32>),
    /// 優先（指定されたノードを優先的に使用）
    Preferred(Vec<u32>),
    /// インターリーブ（複数ノードに分散）
    Interleave(Vec<u32>),
    /// ローカル（ローカルノードのみ使用）
    Local,
}

/// アフィニティ統計情報
pub struct AffinityStats {
    /// プロセスアフィニティ変更回数
    process_affinity_changes: AtomicU64,
    /// スレッドアフィニティ変更回数
    thread_affinity_changes: AtomicU64,
    /// NUMAポリシー変更回数
    numa_policy_changes: AtomicU64,
    /// 最適配置回数
    optimal_placements: AtomicU64,
}

impl AffinityStats {
    fn new() -> Self {
        Self {
            process_affinity_changes: AtomicU64::new(0),
            thread_affinity_changes: AtomicU64::new(0),
            numa_policy_changes: AtomicU64::new(0),
            optimal_placements: AtomicU64::new(0),
        }
    }
}

/// アフィニティ統計スナップショット
#[derive(Debug, Clone)]
pub struct AffinityStatsSnapshot {
    pub process_affinity_changes: u64,
    pub thread_affinity_changes: u64,
    pub numa_policy_changes: u64,
    pub optimal_placements: u64,
}

// パブリックインターフェース関数

/// スレッドのCPUアフィニティを設定
pub fn set_affinity(thread_id: ThreadId, cpu_mask: CpuMask) -> AffinityResult {
    global_manager().set_thread_affinity(thread_id, cpu_mask)
}

/// スレッドのCPUアフィニティを取得
pub fn get_affinity(thread_id: ThreadId) -> Option<CpuMask> {
    global_manager().get_thread_affinity(thread_id)
}

/// プロセスのCPUアフィニティを設定
pub fn set_process_affinity(process_id: ProcessId, cpu_mask: CpuMask) -> AffinityResult {
    global_manager().set_process_affinity(process_id, cpu_mask)
}

/// プロセスのCPUアフィニティを取得
pub fn get_process_affinity(process_id: ProcessId) -> Option<CpuMask> {
    global_manager().get_process_affinity(process_id)
}

/// プロセスのNUMAポリシーを設定
pub fn set_numa_policy(process_id: ProcessId, policy: NUMAPolicy) -> AffinityResult {
    global_manager().set_numa_policy(process_id, policy)
}

/// プロセスのNUMAポリシーを取得
pub fn get_numa_policy(process_id: ProcessId) -> Option<NUMAPolicy> {
    global_manager().get_numa_policy(process_id)
}

/// スレッドに対する最適なアフィニティを提案
pub fn optimize_affinity(thread_id: ThreadId, process_id: ProcessId) -> CpuMask {
    global_manager().suggest_thread_affinity(thread_id, process_id)
}

/// スレッドが関連付けられているNUMAノードを取得
pub fn numanode_for_thread(thread_id: ThreadId) -> Option<u32> {
    if let Some(affinity) = global_manager().get_thread_affinity(thread_id) {
        let cpu_list = affinity.to_cpu_list();
        if !cpu_list.is_empty() {
            return global_manager().get_cpu_node(cpu_list[0]);
        }
    }
    None
}

/// メモリアクセスに最適なCPUを提案
pub fn memory_locality_hint(addr: PhysicalAddress) -> Option<u32> {
    global_manager().get_optimal_cpu_for_memory(addr)
}

/// すべてのNUMAノードを取得
pub fn get_numa_nodes() -> Vec<NUMANode> {
    global_manager().numa_topology.get_all_nodes()
}

/// 指定されたNUMAノードのメモリ使用状況を取得
pub fn get_numa_memory_info(node_id: u32) -> Option<NumaMemoryInfo> {
    global_manager().numa_topology.get_memory_info(node_id)
}

/// NUMAメモリ情報
#[derive(Debug, Clone)]
pub struct NumaMemoryInfo {
    /// 合計サイズ（バイト）
    pub total_size: u64,
    /// 空きサイズ（バイト）
    pub free_size: u64,
    /// 使用率（0-100）
    pub usage_percent: u32,
}

/// ワークロードタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadType {
    /// CPU集約的
    CPUIntensive,
    /// I/O待機が多い
    IOBound,
    /// メモリ集約的
    MemoryIntensive,
    /// リアルタイム
    RealTime,
    /// インタラクティブ
    Interactive,
    /// バックグラウンド
    Background,
}

/// スレッド特性
#[derive(Debug, Clone)]
pub struct ThreadCharacteristics {
    /// ワークロードタイプ
    pub workload_type: WorkloadType,
    /// 優先度
    pub priority: u32,
    /// CPU使用率（パーセント）
    pub cpu_usage_percent: f32,
    /// メモリ使用量（MB）
    pub memory_usage_mb: u32,
    /// 秒あたりI/O操作数
    pub io_operations_per_second: u32,
}

/// ランタイム統計
#[derive(Debug, Clone, Default)]
pub struct ThreadRuntimeStats {
    /// CPU使用率（パーセント）
    pub cpu_usage_percent: f32,
    /// I/O待機時間の割合（パーセント）
    pub io_wait_percent: f32,
    /// メモリ帯域幅使用率（パーセント）
    pub memory_bandwidth_usage: f32,
    /// リアルタイムタスクフラグ
    pub is_realtime: bool,
    /// インタラクティブスコア（0.0-1.0）
    pub interactive_score: f32,
    /// 優先度
    pub priority: u32,
    /// メモリ使用量（MB）
    pub memory_usage_mb: u32,
    /// 秒あたりI/O操作数
    pub io_operations_per_second: u32,
}

/// メモリアクセスパターン
#[derive(Debug, Clone, Default)]
pub struct MemoryAccessPattern {
    /// 頻繁にアクセスされるアドレス
    pub hot_addresses: Vec<PhysicalAddress>,
    /// アクセス頻度マップ
    pub access_frequency: BTreeMap<PhysicalAddress, u64>,
    /// 最近のアクセス履歴
    pub recent_accesses: Vec<(PhysicalAddress, u64)>, // (address, timestamp)
}

/// 物理アドレス
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysicalAddress(usize);

impl PhysicalAddress {
    pub fn new(addr: usize) -> Self {
        Self(addr)
    }
    
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

/// プロセス情報
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// プロセスID
    pub process_id: ProcessId,
    /// スレッド数
    pub thread_count: u32,
    /// CPU集約的フラグ
    pub is_cpu_intensive: bool,
    /// I/Oバウンドフラグ
    pub is_io_bound: bool,
    /// メモリ使用量（バイト）
    pub memory_usage_bytes: usize,
    /// 優先度
    pub priority: u32,
}

// テスト用コード（実際の実装では適切なテストケースを含める）
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cpu_mask() {
        // テスト実装
    }
    
    #[test]
    fn test_affinity_policy() {
        // テスト実装
    }
} 
} 