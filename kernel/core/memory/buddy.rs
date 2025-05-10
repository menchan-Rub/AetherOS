// AetherOS バディアロケータ
//
// バディアロケータは物理メモリ管理のための効率的なメモリ割り当てアルゴリズムを実装します。
// これにより、フラグメンテーションを最小限に抑えながら様々なサイズのメモリブロックを
// 効率的に割り当てることができます。
//
// 特長:
// - キャッシュラインフレンドリーなデータ構造
// - NUMAアウェアなメモリ割り当て
// - メモリアクセスパターン分析と最適化
// - メモリコンパクション機能
// - CXL/永続メモリ対応

use crate::arch::MemoryInfo;
use crate::sync::{Mutex, SpinLock, RwLock};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::cmp::{max, min};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use core::mem::MaybeUninit;

/// メモリオーダのサイズ定数
const ORDER_SIZES: [usize; MAX_ORDER + 1] = [
    4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288,
    1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728,
];

/// 最大メモリオーダー（2^MAX_ORDER ページ）
const MAX_ORDER: usize = 15;
/// ページサイズ（バイト単位）
const PAGE_SIZE: usize = 4096;
/// ブロックヘッダサイズ
const BLOCK_HEADER_SIZE: usize = core::mem::size_of::<BlockHeader>();
/// キャッシュラインサイズ (通常64バイト)
const CACHE_LINE_SIZE: usize = 64;
/// 最大NUMAノード数
const MAX_NUMA_NODES: usize = 32;
/// ヒューリスティックな予測に用いるアクセス履歴サンプル数
const ACCESS_HISTORY_SAMPLES: usize = 64;
/// マジックナンバー（メモリ破損検出用）
const BLOCK_MAGIC: u32 = 0xA173_05A1;

/// アロケータの状態
#[repr(C, align(64))] // キャッシュラインアライメント
struct BuddyAllocatorState {
    /// 利用可能なメモリブロックのリスト（オーダー別）
    free_lists: [Option<NonNull<BlockHeader>>; MAX_ORDER + 1],
    /// 各オーダーの空きブロック数（スレッドセーフ）
    free_counts: [AtomicUsize; MAX_ORDER + 1],
    /// 割り当て済みブロック数
    allocated_blocks: AtomicUsize,
    /// 物理メモリの開始アドレス
    memory_start: usize,
    /// 管理するメモリ領域のサイズ
    memory_size: usize,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// NUMAノードID (ゾーンがNUMAノードに関連付けられている場合)
    numa_node_id: u8,
    /// 平均割り当て待ち時間 (ナノ秒) - 統計用
    avg_allocation_latency_ns: AtomicU32,
    /// 最大割り当て待ち時間 (ナノ秒) - 統計用
    max_allocation_latency_ns: AtomicU32,
    /// コンパクション試行回数
    compaction_attempts: AtomicUsize,
    /// コンパクション成功回数
    compaction_successes: AtomicUsize,
    /// パディング（キャッシュライン境界調整用）
    _padding: [u8; 8],
}

/// 単一メモリゾーン用バディアロケータ
#[repr(C, align(64))] // キャッシュラインアライメント
struct BuddyAllocator {
    /// アロケータの状態
    state: SpinLock<BuddyAllocatorState>,
    /// 割り当てカウンター（パフォーマンス分析用）
    allocation_count: AtomicUsize,
    /// 解放カウンター（パフォーマンス分析用）
    free_count: AtomicUsize,
    /// 割り当て失敗カウンター（パフォーマンス分析用）
    allocation_failures: AtomicUsize,
    /// ゾーンID
    zone_id: usize,
    /// メモリゾーンのタイプ
    zone_type: MemoryZoneType,
    /// メモリアクセスパターン予測器
    access_predictor: Option<MemoryAccessPredictor>,
    /// 最近のメモリアクセス履歴（ホット/コールド分析用）
    #[cfg(feature = "memory_profiling")]
    access_history: SpinLock<AccessHistoryBuffer>,
    /// パディング（キャッシュライン境界調整用）
    _padding: [u8; 24],
}

/// キャッシュフレンドリーなアクセス履歴バッファ
#[cfg(feature = "memory_profiling")]
#[repr(C, align(64))]
struct AccessHistoryBuffer {
    /// 循環バッファ内の現在の位置
    position: usize,
    /// アクセス記録の循環バッファ
    records: [MaybeUninit<MemoryAccessRecord>; ACCESS_HISTORY_SAMPLES],
}

#[cfg(feature = "memory_profiling")]
impl AccessHistoryBuffer {
    /// 新しいアクセス履歴バッファを作成
    fn new() -> Self {
        Self {
            position: 0,
            records: unsafe { MaybeUninit::uninit().assume_init() },
        }
    }
    
    /// アクセス記録を追加
    fn add(&mut self, record: MemoryAccessRecord) {
        self.records[self.position].write(record);
        self.position = (self.position + 1) % ACCESS_HISTORY_SAMPLES;
    }
    
    /// アクセス履歴から最近のアクセスレコードを取得
    fn get_recent_records(&self) -> Vec<MemoryAccessRecord> {
        let mut result = Vec::with_capacity(ACCESS_HISTORY_SAMPLES);
        
        // 現在の位置から反時計回りに収集
        for i in 0..ACCESS_HISTORY_SAMPLES {
            let index = (self.position + ACCESS_HISTORY_SAMPLES - 1 - i) % ACCESS_HISTORY_SAMPLES;
            unsafe {
                result.push(self.records[index].assume_init());
            }
        }
        
        result
    }
}

/// メモリアクセスパターン予測器
#[repr(C, align(64))]
struct MemoryAccessPredictor {
    /// ホットページのリスト (頻繁にアクセスされるページ)
    hot_pages: SpinLock<BTreeMap<usize, HotPageInfo>>,
    /// 予測精度 (0.0-1.0)
    prediction_accuracy: AtomicU32, // 固定小数点表現 (0-1000 = 0.0-1.0)
    /// 予測による最適化成功回数
    optimization_successes: AtomicUsize,
    /// 予測による最適化試行回数
    optimization_attempts: AtomicUsize,
}

/// ホットページ情報
#[derive(Clone)]
struct HotPageInfo {
    /// 最後のアクセス時間（ティック）
    last_access: u64,
    /// アクセス頻度カウンター
    access_count: u32,
    /// CPUアフィニティ（このページに最もアクセスするCPU/コア）
    cpu_affinity: u8,
    /// NUMAノードアフィニティ
    numa_affinity: u8,
}

/// メモリゾーンタイプの列挙型
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemoryZoneType {
    /// 通常のDRAM（アクセス制限なし）
    Normal,
    /// 予約された（カーネル専用）メモリ
    Reserved,
    /// DMAに使用可能な連続したメモリ
    DMA,
    /// 高速DRAM（HBM、低レイテンシーDRAM）
    HighPerformance,
    /// 不揮発性メモリ（PMEM）
    Persistent,
    /// CXL拡張メモリ
    CXL,
}

/// NUMAノード情報
#[derive(Clone)]
pub struct NumaNodeInfo {
    /// ノードID
    id: u8,
    /// このノードに関連するCPUコア
    cpu_cores: Vec<u8>,
    /// ノードのメモリ容量
    memory_size: usize,
    /// 他のノードとのレイテンシマトリックス
    latency_matrix: [u16; MAX_NUMA_NODES],
}

/// メモリブロックヘッダー
#[repr(C, align(64))] // キャッシュラインアライメント
struct BlockHeader {
    /// ブロックサイズのオーダー（2^オーダー ページ）
    order: u8,
    /// 使用中フラグ
    in_use: AtomicBool,
    /// メモリゾーンID
    zone_id: u16,
    /// 次の空きブロックへのポインタ
    next_free: Option<NonNull<BlockHeader>>,
    /// 物理アドレス
    physical_addr: usize,
    /// マジックナンバー（破損検出用）
    magic: u32,
    /// NUMAノードID
    numa_node_id: u8,
    /// メモリの使用目的タグ (デバッグ/プロファイリング用)
    purpose_tag: [u8; 8],
    /// 割り当てスタックトレース保存用ポインタ（デバッグビルド時のみ使用）
    #[cfg(debug_assertions)]
    allocation_trace: Option<NonNull<u8>>,
    /// 割り当て時間（ティック）
    allocation_time: u64,
    /// 最終アクセス時間（ティック）
    last_access_time: AtomicU32,
    /// アクセスカウンター
    access_count: AtomicU32,
    /// パディング（キャッシュライン境界調整用）
    _padding: [u8; 8],
}

/// 複数のメモリゾーンを管理するグローバルアロケータマネージャ
pub struct BuddyAllocatorManager {
    /// ゾーン別アロケータ
    zones: Vec<BuddyAllocator>,
    /// NUMAノード情報
    numa_nodes: Vec<NumaNodeInfo>,
    /// 使用中ブロックのグローバルトラッキング
    active_blocks: RwLock<BTreeMap<usize, BlockInfo>>,
    /// メモリアクセスパターン分析のトレース
    #[cfg(feature = "memory_profiling")]
    access_trace: Mutex<Vec<MemoryAccessRecord>>,
}

/// ブロック情報 (グローバルトラッキング用)
struct BlockInfo {
    /// ブロックの大きさ (バイト)
    size: usize,
    /// ゾーンID
    zone_id: usize,
    /// NUMAノードID
    numa_node_id: u8,
    /// 割り当てスレッドID
    thread_id: u32,
    /// 割り当て時間 (ティック)
    allocation_time: u64,
}

#[cfg(feature = "memory_profiling")]
/// メモリアクセス記録（プロファイリング用）
#[derive(Copy, Clone, Debug)]
struct MemoryAccessRecord {
    /// アクセスタイプ（読み取り/書き込み/割り当て/解放）
    access_type: MemoryAccessType,
    /// アクセスサイズ
    size: usize,
    /// アクセス時間（ティック単位）
    timestamp: u64,
    /// 呼び出し元CPU ID
    cpu_id: usize,
    /// メモリアドレス
    address: usize,
}

#[cfg(feature = "memory_profiling")]
/// メモリアクセスタイプ（プロファイリング用）
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MemoryAccessType {
    Allocate,
    Free,
    Read,
    Write,
}

/// アロケーション速度優先設定
#[derive(Debug, Clone, Copy)]
pub enum AllocationPriority {
    /// 標準優先度
    Normal,
    /// 高速割り当て優先 (可能な限り遅延を減らす)
    Speed,
    /// メモリ効率優先 (フラグメンテーション最小化)
    Efficiency,
    /// NUMAローカリティ優先 (指定したNUMAノードから優先割り当て)
    NumaLocal(u8),
}

/// アロケーションフラグ
#[derive(Debug, Clone, Copy)]
pub struct AllocationFlags {
    /// アロケーション優先度
    pub priority: AllocationPriority,
    /// 隣接物理メモリを要求 (DMA等でハードウェアが要求する場合)
    pub contiguous: bool,
    /// メモリを事前に0クリアする
    pub zero: bool,
    /// メモリの使用目的タグ (デバッグ/プロファイリング用)
    pub purpose_tag: [u8; 8],
}

impl Default for AllocationFlags {
    fn default() -> Self {
        Self {
            priority: AllocationPriority::Normal,
            contiguous: false,
            zero: false,
            purpose_tag: [0; 8],
        }
    }
}

/// グローバルバディアロケータマネージャのインスタンス
static mut BUDDY_ALLOCATOR_MANAGER: Option<BuddyAllocatorManager> = None;

/// バディアロケータの初期化
pub fn init(mem_info: &MemoryInfo) {
    let mut zones = Vec::new();
    let mut numa_nodes = Vec::new();
    
    // NUMAノード情報の構築
    if mem_info.numa_supported {
        for node_id in 0..mem_info.numa_node_count {
            let mut node_info = NumaNodeInfo {
                id: node_id as u8,
                cpu_cores: Vec::new(),
                memory_size: mem_info.numa_memory_per_node,
                latency_matrix: [0; MAX_NUMA_NODES],
            };
            
            // CPUコア情報をコピー
            if node_id < mem_info.numa_cpu_map.len() {
                for &cpu_id in &mem_info.numa_cpu_map[node_id] {
                    node_info.cpu_cores.push(cpu_id as u8);
                }
            }
            
            // レイテンシ情報をコピー
            for target_node in 0..mem_info.numa_node_count {
                if target_node < MAX_NUMA_NODES && node_id < mem_info.numa_latency_matrix.len() {
                    node_info.latency_matrix[target_node] = mem_info.numa_latency_matrix[node_id][target_node] as u16;
                }
            }
            
            numa_nodes.push(node_info);
        }
    }
    
    // 標準メモリゾーンの初期化
    zones.push(BuddyAllocator::new(
        0,
        mem_info.normal_zone_start,
        mem_info.normal_zone_size,
        MemoryZoneType::Normal,
        if mem_info.numa_supported { Some(0) } else { None },
    ));
    
    // カーネル予約ゾーンの初期化
    zones.push(BuddyAllocator::new(
        1,
        mem_info.kernel_zone_start,
        mem_info.kernel_zone_size,
        MemoryZoneType::Reserved,
        if mem_info.numa_supported { Some(0) } else { None },
    ));
    
    // DMAゾーンの初期化（存在する場合）
    if mem_info.dma_zone_size > 0 {
        zones.push(BuddyAllocator::new(
            2,
            mem_info.dma_zone_start,
            mem_info.dma_zone_size,
            MemoryZoneType::DMA,
            if mem_info.numa_supported { Some(0) } else { None },
        ));
    }
    
    // 高性能ゾーンの初期化（HBMなど、存在する場合）
    if mem_info.high_performance_zone_size > 0 {
        zones.push(BuddyAllocator::new(
            3,
            mem_info.high_performance_zone_start,
            mem_info.high_performance_zone_size,
            MemoryZoneType::HighPerformance,
            if mem_info.numa_supported { Some(0) } else { None },
        ));
    }
    
    // 永続メモリゾーンの初期化（存在する場合）
    if mem_info.pmem_supported && mem_info.pmem_zone_size > 0 {
        zones.push(BuddyAllocator::new(
            4,
            mem_info.pmem_zone_start,
            mem_info.pmem_zone_size,
            MemoryZoneType::Persistent,
            if mem_info.numa_supported { Some(0) } else { None },
        ));
    }
    
    // CXLメモリゾーンの初期化（存在する場合）
    if mem_info.cxl_supported && mem_info.cxl_zone_size > 0 {
        zones.push(BuddyAllocator::new(
            5,
            mem_info.cxl_zone_start,
            mem_info.cxl_zone_size,
            MemoryZoneType::CXL,
            if mem_info.numa_supported { Some(0) } else { None },
        ));
    }
    
    // NUMA対応システムの場合、各NUMAノード用の追加ゾーンを作成
    if mem_info.numa_supported && mem_info.numa_node_count > 1 {
        // ノード1以降のゾーンを追加 (ノード0は既に追加済み)
        for node_id in 1..mem_info.numa_node_count {
            let zone_offset = zones.len();
            let node_memory_start = mem_info.normal_zone_start + node_id * mem_info.numa_memory_per_node;
            
            // 各NUMAノードに標準ゾーンを追加
            zones.push(BuddyAllocator::new(
                zone_offset,
                node_memory_start,
                mem_info.numa_memory_per_node,
                MemoryZoneType::Normal,
                Some(node_id),
            ));
        }
    }
    
    // グローバルマネージャの作成と初期化
    let manager = BuddyAllocatorManager {
        zones,
        numa_nodes,
        active_blocks: RwLock::new(BTreeMap::new()),
        #[cfg(feature = "memory_profiling")]
        access_trace: Mutex::new(Vec::with_capacity(10000)), // 初期容量
    };
    
    // グローバルマネージャを設定
    unsafe {
        BUDDY_ALLOCATOR_MANAGER = Some(manager);
    }
    
    // 各ゾーンの初期化
    for zone_id in 0..get_zone_count() {
        initialize_zone(zone_id);
    }
    
    log::info!("バディアロケータ初期化完了: {}ゾーン, NUMAノード数: {}", 
        get_zone_count(), 
        if mem_info.numa_supported { mem_info.numa_node_count } else { 1 }
    );
}

/// ゾーン数を取得
pub fn get_zone_count() -> usize {
    unsafe {
        BUDDY_ALLOCATOR_MANAGER.as_ref().map_or(0, |manager| manager.zones.len())
    }
}

/// 指定されたゾーンを初期化
fn initialize_zone(zone_id: usize) {
    unsafe {
        if let Some(manager) = BUDDY_ALLOCATOR_MANAGER.as_mut() {
            if zone_id < manager.zones.len() {
                manager.zones[zone_id].initialize();
            }
        }
    }
}

/// メモリアクセス予測器の実装
impl MemoryAccessPredictor {
    /// 新しいメモリアクセス予測器を作成
    fn new() -> Self {
        Self {
            hot_pages: SpinLock::new(BTreeMap::new()),
            prediction_accuracy: AtomicU32::new(500), // 初期値 0.5
            optimization_successes: AtomicUsize::new(0),
            optimization_attempts: AtomicUsize::new(0),
        }
    }
    
    /// メモリアクセスを記録
    fn record_access(&self, address: usize, cpu_id: u8, numa_node: u8, timestamp: u64) {
        let page_addr = address & !(PAGE_SIZE - 1);
        let mut hot_pages = self.hot_pages.lock();
        
        let info = hot_pages.entry(page_addr).or_insert_with(|| HotPageInfo {
            last_access: timestamp,
            access_count: 0,
            cpu_affinity: cpu_id,
            numa_affinity: numa_node,
        });
        
        info.last_access = timestamp;
        info.access_count = info.access_count.saturating_add(1);
        
        // CPUアフィニティの更新 (単純な履歴ベースのヒューリスティック)
        if info.cpu_affinity == cpu_id {
            // 同じCPUからのアクセスが続く - アフィニティ強化
        } else {
            // アクセスパターンが変わった - 新しいCPUにアフィニティを更新
            info.cpu_affinity = cpu_id;
        }
    }
    
    /// メモリアクセスパターンに基づいて最適なNUMAノードを選択
    fn suggest_optimal_numa_node(&self, current_cpu: u8) -> Option<u8> {
        let hot_pages = self.hot_pages.lock();
        
        // アクセス頻度でソートされたページのベクトルを作成
        let mut hot_page_vec: Vec<(&usize, &HotPageInfo)> = hot_pages.iter().collect();
        hot_page_vec.sort_by(|a, b| b.1.access_count.cmp(&a.1.access_count));
        
        // 上位のホットページに基づいてNUMAノード選択
        let mut numa_votes = [0u32; MAX_NUMA_NODES];
        
        // 最も頻繁にアクセスされる上位ページを分析
        for (_, info) in hot_page_vec.iter().take(10) {
            if info.cpu_affinity == current_cpu {
                // 現在のCPUにアフィニティがあるページは重みを増加
                numa_votes[info.numa_affinity as usize] += info.access_count * 2;
            } else {
                numa_votes[info.numa_affinity as usize] += info.access_count;
            }
        }
        
        // 最大票数を持つNUMAノードを見つける
        let mut max_votes = 0;
        let mut best_node = 0;
        
        for (node, &votes) in numa_votes.iter().enumerate() {
            if votes > max_votes {
                max_votes = votes;
                best_node = node;
            }
        }
        
        if max_votes > 0 {
            Some(best_node as u8)
        } else {
            None
        }
    }
    
    /// 予測成功を記録
    fn record_prediction_success(&self) {
        let attempts = self.optimization_attempts.fetch_add(1, Ordering::Relaxed) + 1;
        let successes = self.optimization_successes.fetch_add(1, Ordering::Relaxed) + 1;
        
        // 予測精度を更新 (指数移動平均)
        let current_accuracy = self.prediction_accuracy.load(Ordering::Relaxed);
        let new_accuracy = (current_accuracy * 9 + ((successes * 1000) / attempts) as u32) / 10;
        self.prediction_accuracy.store(new_accuracy, Ordering::Relaxed);
    }
    
    /// 予測失敗を記録
    fn record_prediction_failure(&self) {
        let attempts = self.optimization_attempts.fetch_add(1, Ordering::Relaxed) + 1;
        let successes = self.optimization_successes.load(Ordering::Relaxed);
        
        // 予測精度を更新 (指数移動平均)
        let current_accuracy = self.prediction_accuracy.load(Ordering::Relaxed);
        let new_accuracy = (current_accuracy * 9 + ((successes * 1000) / attempts) as u32) / 10;
        self.prediction_accuracy.store(new_accuracy, Ordering::Relaxed);
    }
    
    /// メモリアクセスパターンを分析して最適化提案を生成
    fn generate_optimization_hints(&self) -> Vec<MemoryOptimizationHint> {
        let hot_pages = self.hot_pages.lock();
        let mut result = Vec::new();
        
        // 現在最もホットなページを特定
        let mut hot_page_vec: Vec<(&usize, &HotPageInfo)> = hot_pages.iter()
            .filter(|(_, info)| info.access_count > 10) // 頻繁にアクセスされるページのみ
            .collect();
        
        if hot_page_vec.is_empty() {
            return result;
        }
        
        // アクセス頻度でソート
        hot_page_vec.sort_by(|a, b| b.1.access_count.cmp(&a.1.access_count));
        
        // 最適なNUMAノードごとにグループ化
        let mut numa_groups: BTreeMap<u8, Vec<usize>> = BTreeMap::new();
        
        for (&addr, info) in hot_page_vec.iter().take(32) { // 上位32ページを分析
            numa_groups.entry(info.numa_affinity)
                .or_insert_with(Vec::new)
                .push(*addr);
        }
        
        // 各NUMAノードに対して最適化ヒントを生成
        for (numa_node, addresses) in numa_groups {
            if addresses.len() > 1 { // 複数のホットページがある場合
                result.push(MemoryOptimizationHint {
                    hint_type: MemoryOptimizationHintType::NumaColocation,
                    target_addresses: addresses,
                    target_numa_node: numa_node,
                    expected_benefit: (addresses.len() * 10) as u32, // ヒューリスティックな利益評価
                });
            }
        }
        
        result
    }
}

/// メモリ最適化ヒントタイプ
enum MemoryOptimizationHintType {
    /// NUMAノード間でのページ再配置
    NumaColocation,
    /// キャッシュラインの共有最適化
    CacheLineSharing,
    /// ページの先読み提案
    PagePrefetch,
}

/// メモリ最適化ヒント
struct MemoryOptimizationHint {
    /// ヒントのタイプ
    hint_type: MemoryOptimizationHintType,
    /// 対象メモリアドレスのリスト
    target_addresses: Vec<usize>,
    /// 対象NUMAノード (NumaColocationの場合)
    target_numa_node: u8,
    /// 期待される利益 (リソース消費に対する効果の推定値)
    expected_benefit: u32,
}

/// バディアロケータの実装
impl BuddyAllocator {
    /// 新しいバディアロケータを作成
    fn new(zone_id: usize, memory_start: usize, memory_size: usize, zone_type: MemoryZoneType, numa_node: Option<usize>) -> Self {
        // OrderingSizeとデフォルトの初期化
        let free_counts = [
            AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
            AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
            AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
            AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
        ];
        
        // メモリアクセス予測器はプロファイリング機能が有効な場合のみ初期化
        #[cfg(feature = "memory_profiling")]
        let access_predictor = Some(MemoryAccessPredictor::new());
        
        #[cfg(not(feature = "memory_profiling"))]
        let access_predictor = None;
        
        BuddyAllocator {
            state: SpinLock::new(BuddyAllocatorState {
                free_lists: [None; MAX_ORDER + 1],
                free_counts,
                allocated_blocks: AtomicUsize::new(0),
                memory_start,
                memory_size,
                initialized: AtomicBool::new(false),
                numa_node_id: numa_node.unwrap_or(0) as u8,
                avg_allocation_latency_ns: AtomicU32::new(0),
                max_allocation_latency_ns: AtomicU32::new(0),
                compaction_attempts: AtomicUsize::new(0),
                compaction_successes: AtomicUsize::new(0),
                _padding: [0; 8],
            }),
            allocation_count: AtomicUsize::new(0),
            free_count: AtomicUsize::new(0),
            allocation_failures: AtomicUsize::new(0),
            zone_id,
            zone_type,
            access_predictor,
            #[cfg(feature = "memory_profiling")]
            access_history: SpinLock::new(AccessHistoryBuffer::new()),
            _padding: [0; 24],
        }
    }
    
    /// バディアロケータを初期化
    fn initialize(&self) {
        let mut state = self.state.lock();
        if state.initialized.load(Ordering::SeqCst) {
            return;
        }

        // メモリ領域のサイズを取得
        let memory_size = state.memory_size;
        let memory_start = state.memory_start;

        // メモリ領域を最大のブロックに分割
        let mut current_addr = memory_start;
        let mut remaining_size = memory_size;

        while remaining_size >= PAGE_SIZE {
            // 現在の残りサイズに収まる最大のオーダーを計算
            let order = Self::calculate_max_order_for_size(remaining_size);
            let block_size = ORDER_SIZES[order];

            if block_size <= remaining_size {
                // ブロックの物理アドレスを適切にアライメント
                let aligned_addr = (current_addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                let alignment_padding = aligned_addr - current_addr;
                
                if alignment_padding > 0 {
                    current_addr += alignment_padding;
                    remaining_size -= alignment_padding;
                    if remaining_size < PAGE_SIZE {
                        break;
                    }
                }

                // 新しいブロックヘッダを作成
                let block_header = BlockHeader {
                    order: order as u8,
                    in_use: AtomicBool::new(false),
                    zone_id: self.zone_id as u16,
                    next_free: None,
                    physical_addr: aligned_addr,
                    magic: BLOCK_MAGIC,
                    numa_node_id: state.numa_node_id,
                    purpose_tag: [0; 8],
                    #[cfg(debug_assertions)]
                    allocation_trace: None,
                    allocation_time: 0,
                    last_access_time: AtomicU32::new(0),
                    access_count: AtomicU32::new(0),
                    _padding: [0; 8],
                };

                // ヘッダをメモリに書き込み
                unsafe {
                    let header_ptr = aligned_addr as *mut BlockHeader;
                    *header_ptr = block_header;
                    
                    // 空きリストに追加
                    let non_null_ptr = NonNull::new_unchecked(header_ptr);
                    Self::add_to_free_list(&mut state.free_lists[order], non_null_ptr);
                    
                    // カウンタを更新
                    state.free_counts[order].fetch_add(1, Ordering::Relaxed);
                }

                // 次のブロックアドレスと残りサイズを更新
                current_addr += block_size;
                remaining_size -= block_size;
            } else {
                // 現在のオーダーに収まらない場合は、より小さなオーダーで試行
                break;
            }
        }

        // ゾーンが初期化されたとマーク
        state.initialized.store(true, Ordering::SeqCst);
        
        // 初期化ログを出力
        let total_pages = memory_size / PAGE_SIZE;
        let mut total_free_blocks = 0;
        for i in 0..=MAX_ORDER {
            total_free_blocks += state.free_counts[i].load(Ordering::Relaxed);
        }
        
        log::info!("バディアロケータ初期化完了 - ゾーン {}: {}MB, NUMAノード: {}, 空きブロック: {}",
            self.zone_id,
            memory_size / 1024 / 1024,
            state.numa_node_id,
            total_free_blocks
        );
    }

    /// 最大オーダーを計算
    fn calculate_max_order_for_size(size: usize) -> usize {
        let mut order = 0;
        while order < MAX_ORDER && ORDER_SIZES[order + 1] <= size {
            order += 1;
        }
        order
    }

    /// 空きリストにブロックを追加（LIFO）
    fn add_to_free_list(head: &mut Option<NonNull<BlockHeader>>, block: NonNull<BlockHeader>) {
        unsafe {
            block.as_mut().next_free = *head;
            *head = Some(block);
        }
    }

    /// 指定したオーダーからブロックを割り当て
    fn allocate_order(&self, target_order: usize, flags: AllocationFlags) -> Option<NonNull<BlockHeader>> {
        let current_cpu = crate::arch::get_current_cpu_id() as u8;
        let start_time = crate::time::get_current_ticks();
        
        // まず、指定したオーダーで直接割り当てを試みる
        let result = self.allocate_order_direct(target_order, current_cpu);
        
        if result.is_some() {
            // 割り当て成功
            return result;
        }
        
        // 直接割り当てに失敗した場合、大きなブロックを分割して割り当てる
        let mut state = self.state.lock();
        let mut current_order = target_order;
        
        // 大きなオーダーから順に空きブロックを探す
        while current_order <= MAX_ORDER {
            if state.free_counts[current_order].load(Ordering::Relaxed) > 0 {
                if let Some(mut block) = state.free_lists[current_order].take() {
                    // 空きブロックを見つけた
                    unsafe {
                        // 空きリストの先頭を更新
                        state.free_lists[current_order] = block.as_ref().next_free;
                        state.free_counts[current_order].fetch_sub(1, Ordering::Relaxed);
                        
                        // 現在のブロックのオーダーが目標より大きい場合は分割する
                        let mut current_block = block;
                        let mut current_block_order = current_order;
                        
                        while current_block_order > target_order {
                            // 一つ小さいオーダーに分割
                            current_block_order -= 1;
                            
                            // バディブロックのアドレスを計算
                            let buddy_addr = current_block.as_ref().physical_addr + ORDER_SIZES[current_block_order];
                            
                            // バディブロックのヘッダを初期化
                            let buddy_header = BlockHeader {
                                order: current_block_order as u8,
                                in_use: AtomicBool::new(false),
                                zone_id: self.zone_id as u16,
                                next_free: None,
                                physical_addr: buddy_addr,
                                magic: BLOCK_MAGIC,
                                numa_node_id: state.numa_node_id,
                                purpose_tag: [0; 8],
                                #[cfg(debug_assertions)]
                                allocation_trace: None,
                                allocation_time: 0,
                                last_access_time: AtomicU32::new(0),
                                access_count: AtomicU32::new(0),
                                _padding: [0; 8],
                            };
                            
                            // バディブロックを書き込む
                            *(buddy_addr as *mut BlockHeader) = buddy_header;
                            
                            // バディブロックを空きリストに追加
                            let buddy_ptr = NonNull::new_unchecked(buddy_addr as *mut BlockHeader);
                            Self::add_to_free_list(&mut state.free_lists[current_block_order], buddy_ptr);
                            state.free_counts[current_block_order].fetch_add(1, Ordering::Relaxed);
                            
                            // 現在のブロックのオーダーを更新
                            current_block.as_mut().order = current_block_order as u8;
                        }
                        
                        // 割り当てるブロックを使用中にマーク
                        current_block.as_mut().in_use.store(true, Ordering::SeqCst);
                        current_block.as_mut().next_free = None;
                        current_block.as_mut().allocation_time = start_time;
                        current_block.as_mut().purpose_tag = flags.purpose_tag;
                        
                        // 使用統計を更新
                        state.allocated_blocks.fetch_add(1, Ordering::Relaxed);
                        self.allocation_count.fetch_add(1, Ordering::Relaxed);
                        
                        // メモリをゼロクリア（フラグが設定されている場合）
                        if flags.zero {
                            let data_start = (current_block.as_ref().physical_addr + BLOCK_HEADER_SIZE) as *mut u8;
                            let data_size = ORDER_SIZES[target_order] - BLOCK_HEADER_SIZE;
                            core::ptr::write_bytes(data_start, 0, data_size);
                        }
                        
                        // 割り当て完了
                        let end_time = crate::time::get_current_ticks();
                        let allocation_time_ns = (end_time - start_time) * crate::time::TICK_TO_NS;
                        
                        // 統計情報を更新
                        let current_avg = state.avg_allocation_latency_ns.load(Ordering::Relaxed);
                        let new_avg = if current_avg == 0 {
                            allocation_time_ns as u32
                        } else {
                            (current_avg * 7 + allocation_time_ns as u32) / 8 // 指数移動平均
                        };
                        state.avg_allocation_latency_ns.store(new_avg, Ordering::Relaxed);
                        
                        let current_max = state.max_allocation_latency_ns.load(Ordering::Relaxed);
                        if allocation_time_ns as u32 > current_max {
                            state.max_allocation_latency_ns.store(allocation_time_ns as u32, Ordering::Relaxed);
                        }
                        
                        // メモリアクセス予測器に記録（有効な場合）
                        if let Some(predictor) = &self.access_predictor {
                            predictor.record_access(
                                current_block.as_ref().physical_addr,
                                current_cpu,
                                state.numa_node_id,
                                start_time
                            );
                        }
                        
                        return Some(current_block);
                    }
                }
            }
            
            // 次のオーダーを試す
            current_order += 1;
        }
        
        // 割り当て失敗
        self.allocation_failures.fetch_add(1, Ordering::Relaxed);
        None
    }
    
    /// 指定したオーダーから直接割り当て（高速パス、ロックを最小限に）
    fn allocate_order_direct(&self, target_order: usize, current_cpu: u8) -> Option<NonNull<BlockHeader>> {
        // 高速パスのための原子的操作
        if self.state.lock().free_counts[target_order].load(Ordering::Relaxed) == 0 {
            // 空きブロックがない場合は早期リターン
            return None;
        }
        
        // このオーダーに空きブロックがある場合、割り当てを試みる
        let mut state = self.state.lock();
        if let Some(block) = state.free_lists[target_order].take() {
            unsafe {
                // 空きリストの先頭を更新
                state.free_lists[target_order] = block.as_ref().next_free;
                state.free_counts[target_order].fetch_sub(1, Ordering::Relaxed);
                
                // ブロックを使用中にマーク
                block.as_mut().in_use.store(true, Ordering::SeqCst);
                block.as_mut().next_free = None;
                block.as_mut().allocation_time = crate::time::get_current_ticks();
                
                // 使用統計を更新
                state.allocated_blocks.fetch_add(1, Ordering::Relaxed);
                self.allocation_count.fetch_add(1, Ordering::Relaxed);
                
                // メモリアクセス予測器に記録（有効な場合）
                if let Some(predictor) = &self.access_predictor {
                    predictor.record_access(
                        block.as_ref().physical_addr,
                        current_cpu,
                        state.numa_node_id,
                        block.as_ref().allocation_time
                    );
                }
                
                return Some(block);
            }
        }
        
        None
    }
    
    /// 指定サイズのメモリを割り当て
    fn allocate(&self, size: usize, flags: AllocationFlags) -> Option<*mut u8> {
        // ヘッダを含めた必要サイズを計算
        let required_size = size + BLOCK_HEADER_SIZE;
        
        // 必要なオーダーを計算
        let mut order = 0;
        while order <= MAX_ORDER && ORDER_SIZES[order] < required_size {
            order += 1;
        }
        
        if order > MAX_ORDER {
            // 要求サイズが大きすぎる
            return None;
        }
        
        // ブロックを割り当て
        match self.allocate_order(order, flags) {
            Some(block) => {
                unsafe {
                    // ヘッダの直後のデータ領域のアドレスを返す
                    let data_addr = block.as_ref().physical_addr + BLOCK_HEADER_SIZE;
                    Some(data_addr as *mut u8)
                }
            }
            None => None
        }
    }
    
    /// メモリブロックを解放
    fn free(&self, block_ptr: NonNull<BlockHeader>) -> bool {
        let current_cpu = crate::arch::get_current_cpu_id() as u8;
        let start_time = crate::time::get_current_ticks();
        
        unsafe {
            // ブロックの基本検証
            let block = block_ptr.as_ref();
            
            if block.magic != BLOCK_MAGIC {
                // 破損したメモリヘッダ
                log::error!("破損したメモリヘッダを検出: addr={:x}, magic={:x}", 
                    block.physical_addr, block.magic);
                return false;
            }
            
            if !block.in_use.load(Ordering::SeqCst) {
                // 既に解放されているブロック
                log::error!("二重解放を検出: addr={:x}", block.physical_addr);
                return false;
            }
            
            if block.zone_id as usize != self.zone_id {
                // 間違ったゾーンへの解放
                log::error!("異なるゾーンへのメモリ解放: addr={:x}, expected_zone={}, actual_zone={}", 
                    block.physical_addr, self.zone_id, block.zone_id);
                return false;
            }
            
            // メモリアクセス予測器に記録（有効な場合）
            if let Some(predictor) = &self.access_predictor {
                predictor.record_access(
                    block.physical_addr,
                    current_cpu,
                    block.numa_node_id,
                    start_time
                );
            }
            
            // メモリブロックを解放処理
            let mut state = self.state.lock();
            let mut current_block = block_ptr;
            let mut current_order = block.order as usize;
            
            // ブロックを未使用にマーク
            current_block.as_mut().in_use.store(false, Ordering::SeqCst);
            
            // バディブロックのマージを試みる
            while current_order < MAX_ORDER {
                // バディのアドレスを計算
                let block_addr = current_block.as_ref().physical_addr;
                let buddy_addr = block_addr ^ ORDER_SIZES[current_order];
                
                // バディが有効範囲内かチェック
                if buddy_addr < state.memory_start || buddy_addr >= state.memory_start + state.memory_size {
                    break;
                }
                
                // バディブロックのヘッダを取得
                let buddy_ptr = buddy_addr as *mut BlockHeader;
                let buddy = &*buddy_ptr;
                
                // バディが使用中または異なるオーダーの場合はマージできない
                if buddy.in_use.load(Ordering::SeqCst) || buddy.order as usize != current_order || buddy.magic != BLOCK_MAGIC {
                    break;
                }
                
                // バディを空きリストから削除
                Self::remove_from_free_list(&mut state.free_lists[current_order], NonNull::new_unchecked(buddy_ptr));
                state.free_counts[current_order].fetch_sub(1, Ordering::Relaxed);
                
                // 小さいアドレスのブロックを親ブロックとして使用
                let parent_addr = core::cmp::min(block_addr, buddy_addr);
                
                // 親ブロックのオーダーを更新
                let parent_ptr = parent_addr as *mut BlockHeader;
                let parent = &mut *parent_ptr;
                
                parent.order = (current_order + 1) as u8;
                current_block = NonNull::new_unchecked(parent_ptr);
                current_order += 1;
            }
            
            // マージされたブロックを空きリストに追加
            Self::add_to_free_list(&mut state.free_lists[current_order], current_block);
            state.free_counts[current_order].fetch_add(1, Ordering::Relaxed);
            
            // 使用統計を更新
            state.allocated_blocks.fetch_sub(1, Ordering::Relaxed);
            self.free_count.fetch_add(1, Ordering::Relaxed);
            
            true
        }
    }

    /// 空きリストからブロックを削除
    fn remove_from_free_list(&self, head: &mut Option<NonNull<BlockHeader>>, block: NonNull<BlockHeader>) {
        unsafe {
            if let Some(mut current) = *head {
                // 先頭ブロックが削除対象の場合
                if current.as_ptr() == block.as_ptr() {
                    *head = current.as_ref().next_free;
                    return;
                }
                
                // リストを走査して削除対象を検索
                let mut prev = current;
                while let Some(next) = prev.as_ref().next_free {
                    if next.as_ptr() == block.as_ptr() {
                        // 見つけた場合、リストから削除
                        prev.as_mut().next_free = next.as_ref().next_free;
                        return;
                    }
                    
                    if let Some(next_non_null) = prev.as_ref().next_free {
                        prev = next_non_null;
                    } else {
                        break;
                    }
                }
            }
        }
    }
    
    /// メモリコンパクションを実行（利用可能なメモリの断片化を低減）
    fn perform_compaction(&self) -> usize {
        let mut state = self.state.lock();
        state.compaction_attempts.fetch_add(1, Ordering::Relaxed);
        
        // コンパクション対象の小さなオーダーの閾値
        const COMPACTION_THRESHOLD: usize = 4; // 16KB以下のブロック
        
        let mut compacted_blocks = 0;
        
        // 小さなオーダーのブロックリストを走査
        for order in 0..=COMPACTION_THRESHOLD {
            // 次のオーダーに空きがない場合はスキップ
            if state.free_counts[order + 1].load(Ordering::Relaxed) == 0 {
                continue;
            }
            
            // 現在のオーダーの空きブロックを順番に処理
            let mut i = 0;
            while i < state.free_counts[order].load(Ordering::Relaxed) {
                if let Some(block) = state.free_lists[order] {
                    unsafe {
                        // 隣接するバディブロックを検索
                        let block_addr = block.as_ref().physical_addr;
                        let buddy_addr = block_addr ^ ORDER_SIZES[order];
                        
                        // バディが有効範囲内かチェック
                        if buddy_addr >= state.memory_start && buddy_addr < state.memory_start + state.memory_size {
                            // バディブロックのヘッダを取得
                            let buddy_ptr = buddy_addr as *mut BlockHeader;
                            let buddy = &*buddy_ptr;
                            
                            // バディも同じオーダーの空きブロックであればマージ可能
                            if !buddy.in_use.load(Ordering::SeqCst) && buddy.order as usize == order && buddy.magic == BLOCK_MAGIC {
                                // 両方のブロックを空きリストから削除
                                self.remove_from_free_list(&mut state.free_lists[order], block);
                                self.remove_from_free_list(&mut state.free_lists[order], NonNull::new_unchecked(buddy_ptr));
                                state.free_counts[order].fetch_sub(2, Ordering::Relaxed);
                                
                                // 小さいアドレスのブロックを親ブロックとして使用
                                let parent_addr = core::cmp::min(block_addr, buddy_addr);
                                
                                // 親ブロックのオーダーを更新して空きリストに追加
                                let parent_ptr = parent_addr as *mut BlockHeader;
                                let parent = &mut *parent_ptr;
                                
                                parent.order = (order + 1) as u8;
                                parent.next_free = None;
                                
                                Self::add_to_free_list(&mut state.free_lists[order + 1], NonNull::new_unchecked(parent_ptr));
                                state.free_counts[order + 1].fetch_add(1, Ordering::Relaxed);
                                
                                compacted_blocks += 1;
                                continue; // 同じインデックスを再処理
                            }
                        }
                    }
                }
                
                i += 1;
            }
        }
        
        if compacted_blocks > 0 {
            state.compaction_successes.fetch_add(1, Ordering::Relaxed);
        }
        
        compacted_blocks
    }
}

/// グローバルバディアロケータマネージャの実装
impl BuddyAllocatorManager {
    /// 指定したゾーンタイプにメモリを割り当て
    fn allocate_in_zone_type(&self, size: usize, zone_type: MemoryZoneType, flags: AllocationFlags) -> Option<*mut u8> {
        // 現在のCPUを取得
        let current_cpu = crate::arch::get_current_cpu_id();
        let current_numa_node = self.get_numa_node_for_cpu(current_cpu);
        
        // NUMAローカル優先モードの場合、ノード指定を取得
        let target_numa_node = match flags.priority {
            AllocationPriority::NumaLocal(node) => Some(node),
            _ => None
        };
        
        // NUMAローカル優先かつ、予測器が有効な場合は最適なノードを提案
        let predicted_node = if target_numa_node.is_none() && matches!(flags.priority, AllocationPriority::Normal) {
            // 各ゾーンの予測器から提案を収集
            let mut best_node = None;
            let mut best_confidence = 0;
            
            for zone in &self.zones {
                if zone.zone_type == zone_type {
                    if let Some(predictor) = &zone.access_predictor {
                        if let Some(node) = predictor.suggest_optimal_numa_node(current_cpu as u8) {
                            let confidence = predictor.prediction_accuracy.load(Ordering::Relaxed);
                            if confidence > best_confidence {
                                best_confidence = confidence;
                                best_node = Some(node);
                            }
                        }
                    }
                }
            }
            
            if best_confidence > 600 { // 60%以上の信頼度
                best_node
            } else {
                None
            }
        } else {
            None
        };
        
        // 割り当て優先度に応じた割り当て戦略
        match flags.priority {
            AllocationPriority::Speed => {
                // 高速割り当て優先: 現在のNUMAノードから順に試行
                for zone in &self.zones {
                    if zone.zone_type == zone_type && zone.state.lock().numa_node_id == current_numa_node as u8 {
                        if let Some(ptr) = zone.allocate(size, flags) {
                            return Some(ptr);
                        }
                    }
                }
                
                // 現在のノードで失敗した場合、他のノードを試行
                for zone in &self.zones {
                    if zone.zone_type == zone_type && zone.state.lock().numa_node_id != current_numa_node as u8 {
                        if let Some(ptr) = zone.allocate(size, flags) {
                            return Some(ptr);
                        }
                    }
                }
            },
            AllocationPriority::NumaLocal(node) => {
                // 特定のNUMAノード優先
                for zone in &self.zones {
                    if zone.zone_type == zone_type && zone.state.lock().numa_node_id == node {
                        if let Some(ptr) = zone.allocate(size, flags) {
                            return Some(ptr);
                        }
                    }
                }
                
                // 指定ノードで失敗した場合、最も近いノードを選択
                if !self.numa_nodes.is_empty() {
                    // レイテンシに基づいたノードの優先順位を計算
                    let mut node_distances: Vec<(u8, u16)> = Vec::new();
                    
                    for numa_info in &self.numa_nodes {
                        if numa_info.id != node && node as usize < numa_info.latency_matrix.len() {
                            node_distances.push((numa_info.id, numa_info.latency_matrix[node as usize]));
                        }
                    }
                    
                    // レイテンシの低い順にソート
                    node_distances.sort_by_key(|&(_, latency)| latency);
                    
                    // 近いノードから順に試行
                    for (test_node, _) in node_distances {
                        for zone in &self.zones {
                            if zone.zone_type == zone_type && zone.state.lock().numa_node_id == test_node {
                                if let Some(ptr) = zone.allocate(size, flags) {
                                    return Some(ptr);
                                }
                            }
                        }
                    }
                }
            },
            AllocationPriority::Efficiency => {
                // メモリ効率優先: フラグメンテーションが最も少ないゾーンを選択
                let mut best_zone_index = None;
                let mut best_fragmentation = usize::MAX;
                
                for (i, zone) in self.zones.iter().enumerate() {
                    if zone.zone_type == zone_type {
                        let fragmentation = self.calculate_zone_fragmentation(i);
                        if fragmentation < best_fragmentation {
                            best_fragmentation = fragmentation;
                            best_zone_index = Some(i);
                        }
                    }
                }
                
                if let Some(index) = best_zone_index {
                    if let Some(ptr) = self.zones[index].allocate(size, flags) {
                        return Some(ptr);
                    }
                }
                
                // それでも失敗した場合は通常モードにフォールバック
                for zone in &self.zones {
                    if zone.zone_type == zone_type {
                        if let Some(ptr) = zone.allocate(size, flags) {
                            return Some(ptr);
                        }
                    }
                }
            },
            AllocationPriority::Normal => {
                // 標準優先度（予測ノードがある場合はそれを優先）
                if let Some(predicted) = predicted_node {
                    for zone in &self.zones {
                        if zone.zone_type == zone_type && zone.state.lock().numa_node_id == predicted {
                            if let Some(ptr) = zone.allocate(size, flags) {
                                // 予測が成功した場合、予測器に報告
                                if let Some(predictor) = &zone.access_predictor {
                                    predictor.record_prediction_success();
                                }
                                return Some(ptr);
                            }
                        }
                    }
                }
                
                // 現在のNUMAノードを最初に試行
                for zone in &self.zones {
                    if zone.zone_type == zone_type && zone.state.lock().numa_node_id == current_numa_node as u8 {
                        if let Some(ptr) = zone.allocate(size, flags) {
                            return Some(ptr);
                        }
                    }
                }
                
                // 他のノードも試行
                for zone in &self.zones {
                    if zone.zone_type == zone_type && zone.state.lock().numa_node_id != current_numa_node as u8 {
                        if let Some(ptr) = zone.allocate(size, flags) {
                            // 予測と異なるノードが使用された場合、失敗として記録
                            if let Some(predictor) = &zone.access_predictor {
                                if predicted_node.is_some() {
                                    predictor.record_prediction_failure();
                                }
                            }
                            return Some(ptr);
                        }
                    }
                }
            }
        }
        
        // すべての試行が失敗
        None
    }
    
    /// ゾーンのフラグメンテーションスコアを計算（低いほど良い）
    fn calculate_zone_fragmentation(&self, zone_index: usize) -> usize {
        if zone_index >= self.zones.len() {
            return usize::MAX;
        }
        
        let state = self.zones[zone_index].state.lock();
        let mut fragmentation_score = 0;
        
        // 小さいブロックの割合を計算
        let mut total_blocks = 0;
        let mut small_blocks = 0;
        
        for order in 0..=MAX_ORDER {
            let count = state.free_counts[order].load(Ordering::Relaxed);
            total_blocks += count;
            
            if order < 4 { // 16KB以下を小さいブロックとみなす
                small_blocks += count;
            }
            
            // 大きなオーダーの不足に高いペナルティを課す
            if order > 8 && count == 0 { // 1MB以上のブロックがない場合
                fragmentation_score += 1000 * (MAX_ORDER - order);
            }
        }
        
        if total_blocks > 0 {
            fragmentation_score += (small_blocks * 100) / total_blocks;
        }
        
        fragmentation_score
    }
    
    /// CPUがどのNUMAノードに属するかを判定
    fn get_numa_node_for_cpu(&self, cpu_id: usize) -> usize {
        for (node_id, info) in self.numa_nodes.iter().enumerate() {
            if info.cpu_cores.contains(&(cpu_id as u8)) {
                return node_id;
            }
        }
        0 // デフォルトはノード0
    }
    
    /// NUMAアウェアなメモリ最適化を実行
    fn optimize_numa_memory(&self) -> usize {
        let mut optimization_count = 0;
        
        // 予測エンジンからの最適化提案を収集
        let mut all_hints = Vec::new();
        
        for zone in &self.zones {
            if let Some(predictor) = &zone.access_predictor {
                let hints = predictor.generate_optimization_hints();
                all_hints.extend(hints);
            }
        }
        
        // ベネフィットが最も高い提案を選択
        all_hints.sort_by(|a, b| b.expected_benefit.cmp(&a.expected_benefit));
        
        // 上位10個の提案を実行
        for hint in all_hints.iter().take(10) {
            match hint.hint_type {
                MemoryOptimizationHintType::NumaColocation => {
                    // メモリページを最適なNUMAノードに再配置
                    for &addr in &hint.target_addresses {
                        if self.migrate_page_to_numa_node(addr, hint.target_numa_node) {
                            optimization_count += 1;
                        }
                    }
                },
                MemoryOptimizationHintType::CacheLineSharing => {
                    // キャッシュライン共有の最適化（将来実装）
                },
                MemoryOptimizationHintType::PagePrefetch => {
                    // ページプリフェッチ（将来実装）
                }
            }
        }
        
        optimization_count
    }
    
    /// メモリページを別のNUMAノードに移動
    fn migrate_page_to_numa_node(&self, addr: usize, target_node: u8) -> bool {
        // このページが割り当て済みかチェック
        let page_addr = addr & !(PAGE_SIZE - 1);
        let active_blocks = self.active_blocks.read();
        
        if !active_blocks.contains_key(&page_addr) {
            return false;
        }
        
        // 現在のNUMAノードを判定
        let mut current_node = 0;
        for zone in &self.zones {
            let state = zone.state.lock();
            if page_addr >= state.memory_start && 
               page_addr < state.memory_start + state.memory_size {
                current_node = state.numa_node_id;
                break;
            }
        }
        
        if current_node == target_node {
            // 既に目標ノードにある
            return false;
        }
        
        // 対象ノードに新しいページを割り当て
        let flags = AllocationFlags {
            priority: AllocationPriority::NumaLocal(target_node),
            contiguous: false,
            zero: false,
            purpose_tag: [0; 8],
        };
        
        // 新しいページの割り当て
        let new_page = self.allocate_in_zone_type(PAGE_SIZE - BLOCK_HEADER_SIZE, MemoryZoneType::Normal, flags);
        
        if let Some(new_ptr) = new_page {
            unsafe {
                // データをコピー
                core::ptr::copy_nonoverlapping(
                    page_addr as *const u8, 
                    new_ptr,
                    PAGE_SIZE - BLOCK_HEADER_SIZE
                );
                
                // ページテーブルの更新処理
                let virt_addrs = self.get_virtual_mappings_for_physical(page_addr);
                
                for virt_addr in virt_addrs {
                    // 新しい物理アドレスを計算
                    let new_phys_addr = new_ptr as usize - BLOCK_HEADER_SIZE;
                    
                    // ページテーブルエントリを更新
                    let mut pte = PageTableEntry::new();
                    pte.set_physical_address(new_phys_addr);
                    pte.set_present(true);
                    pte.set_writable(true);
                    
                    // NUMAノード情報を設定
                    pte.set_numa_node(target_node);
                    
                    // ページテーブルを更新
                    let page_table = unsafe { &mut *self.get_current_page_table() };
                    page_table.update_entry(virt_addr, pte);
                    
                    // TLBをフラッシュ
                    unsafe {
                        flush_tlb_single(virt_addr);
                    }
                    
                    // アクセス統計をリセット
                    if let Some(stats) = self.page_access_stats.write().get_mut(&virt_addr) {
                        stats.last_migration = crate::time::current_time_ms();
                        stats.access_count_since_migration = 0;
                    }
                }
                
                // 古いページを解放
                self.free((page_addr + BLOCK_HEADER_SIZE) as *mut u8);
                
                // 移行統計を更新
                self.numa_stats.write().migrations_count += 1;
                
                // 移行イベントをログに記録
                log::trace!("NUMAページ移行: 物理アドレス 0x{:x} をノード{}からノード{}へ移動", 
                           page_addr, current_node, target_node);
                
                return true;
            }
        }
        
        // 移行失敗をログに記録
        log::debug!("NUMAページ移行失敗: ノード{}に十分なメモリがありません", target_node);
        false
    }
    
    /// 定期的なメモリメンテナンスタスクを実行（断片化低減、最適化）
    pub fn perform_maintenance(&self) {
        // 各ゾーンでコンパクションを実行
        let mut total_compacted = 0;
        for zone in &self.zones {
            total_compacted += zone.perform_compaction();
        }
        
        if total_compacted > 0 {
            log::debug!("メモリコンパクション完了: {}ブロック統合", total_compacted);
        }
        
        // NUMAメモリ最適化（プロファイリングが有効な場合）
        #[cfg(feature = "memory_profiling")]
        {
            let optimized = self.optimize_numa_memory();
            if optimized > 0 {
                log::debug!("NUMAメモリ最適化完了: {}ページ再配置", optimized);
            }
        }
    }
}

/// 汎用メモリを割り当て（標準ゾーン）
pub fn allocate(size: usize, flags: AllocationFlags) -> Option<*mut u8> {
    unsafe {
        BUDDY_ALLOCATOR_MANAGER.as_ref()?.allocate_in_zone_type(size, MemoryZoneType::Normal, flags)
    }
}

/// カーネル専用メモリを割り当て（予約ゾーン）
pub fn allocate_kernel(size: usize, flags: AllocationFlags) -> Option<*mut u8> {
    unsafe {
        BUDDY_ALLOCATOR_MANAGER.as_ref()?.allocate_in_zone_type(size, MemoryZoneType::Reserved, flags)
    }
}

/// DMA用メモリを割り当て（DMAゾーン）
pub fn allocate_dma(size: usize, flags: AllocationFlags) -> Option<*mut u8> {
    let mut dma_flags = flags;
    dma_flags.contiguous = true; // DMAは常に物理的に連続したメモリが必要
    
    unsafe {
        BUDDY_ALLOCATOR_MANAGER.as_ref()?.allocate_in_zone_type(size, MemoryZoneType::DMA, dma_flags)
    }
}

/// 高性能メモリを割り当て（高性能ゾーン）
pub fn allocate_high_performance(size: usize, flags: AllocationFlags) -> Option<*mut u8> {
    unsafe {
        BUDDY_ALLOCATOR_MANAGER.as_ref()?.allocate_in_zone_type(size, MemoryZoneType::HighPerformance, flags)
    }
}

/// 永続メモリを割り当て（永続ゾーン）
pub fn allocate_persistent(size: usize, flags: AllocationFlags) -> Option<*mut u8> {
    unsafe {
        BUDDY_ALLOCATOR_MANAGER.as_ref()?.allocate_in_zone_type(size, MemoryZoneType::Persistent, flags)
    }
}

/// CXLメモリを割り当て（CXLゾーン）
pub fn allocate_cxl(size: usize, flags: AllocationFlags) -> Option<*mut u8> {
    unsafe {
        BUDDY_ALLOCATOR_MANAGER.as_ref()?.allocate_in_zone_type(size, MemoryZoneType::CXL, flags)
    }
}

/// メモリを解放
pub fn free(ptr: *mut u8) -> bool {
    if ptr.is_null() {
        return false;
    }
    
    unsafe {
        if let Some(manager) = BUDDY_ALLOCATOR_MANAGER.as_ref() {
            manager.free(ptr)
        } else {
            false
        }
    }
}

/// 指定ゾーンの空きメモリ量を取得（バイト単位）
pub fn get_free_memory(zone_id: usize) -> usize {
    unsafe {
        if let Some(manager) = BUDDY_ALLOCATOR_MANAGER.as_ref() {
            if zone_id < manager.zones.len() {
                let state = manager.zones[zone_id].state.lock();
                let mut total_free = 0;
                
                for order in 0..=MAX_ORDER {
                    total_free += state.free_counts[order].load(Ordering::Relaxed) * ORDER_SIZES[order];
                }
                
                return total_free;
            }
        }
        0
    }
}

/// 総利用可能メモリ量を取得（バイト単位）
pub fn get_total_free_memory() -> usize {
    unsafe {
        if let Some(manager) = BUDDY_ALLOCATOR_MANAGER.as_ref() {
            let mut total_free = 0;
            
            for zone_id in 0..manager.zones.len() {
                total_free += get_free_memory(zone_id);
            }
            
            return total_free;
        }
        0
    }
}

/// メモリ統計情報を取得
pub fn get_memory_stats() -> Vec<(MemoryZoneType, usize, usize)> {
    let mut result = Vec::new();
    
    unsafe {
        if let Some(manager) = BUDDY_ALLOCATOR_MANAGER.as_ref() {
            for zone in &manager.zones {
                let state = zone.state.lock();
                let total_size = state.memory_size;
                
                let mut free_size = 0;
                for order in 0..=MAX_ORDER {
                    free_size += state.free_counts[order].load(Ordering::Relaxed) * ORDER_SIZES[order];
                }
                
                result.push((zone.zone_type, total_size, free_size));
            }
        }
    }
    
    result
}

/// NUMAノード情報を取得
pub fn get_numa_info() -> Vec<NumaNodeInfo> {
    unsafe {
        if let Some(manager) = BUDDY_ALLOCATOR_MANAGER.as_ref() {
            return manager.numa_nodes.clone();
        }
    }
    Vec::new()
}

/// 定期メンテナンスタスクを実行（断片化低減など）
pub fn perform_maintenance() {
    unsafe {
        if let Some(manager) = BUDDY_ALLOCATOR_MANAGER.as_ref() {
            manager.perform_maintenance();
        }
    }
}

/// デバッグ情報を出力
pub fn print_debug_info() {
    unsafe {
        if let Some(manager) = BUDDY_ALLOCATOR_MANAGER.as_ref() {
            log::info!("===== メモリアロケータ情報 =====");
            
            for (i, zone) in manager.zones.iter().enumerate() {
                let state = zone.state.lock();
                let total = state.memory_size;
                let allocated = state.allocated_blocks.load(Ordering::Relaxed);
                
                let mut free = 0;
                for order in 0..=MAX_ORDER {
                    free += state.free_counts[order].load(Ordering::Relaxed) * ORDER_SIZES[order];
                }
                
                let usage_percent = if total > 0 {
                    100 - (free * 100 / total)
                } else {
                    0
                };
                
                log::info!("ゾーン {}: タイプ={:?}, NUMAノード={}, サイズ={}MB, 使用中={}%, 割り当て数={}",
                    i, zone.zone_type, state.numa_node_id, total / (1024 * 1024), 
                    usage_percent, allocated);
                
                if let Some(predictor) = &zone.access_predictor {
                    let accuracy = predictor.prediction_accuracy.load(Ordering::Relaxed) as f32 / 1000.0;
                    log::info!("  予測精度: {:.1}%, 最適化試行: {}, 成功: {}",
                        accuracy * 100.0,
                        predictor.optimization_attempts.load(Ordering::Relaxed),
                        predictor.optimization_successes.load(Ordering::Relaxed));
                }
                
                log::info!("  平均割り当て時間: {}ns, 最大: {}ns, コンパクション: 試行={}, 成功={}",
                    state.avg_allocation_latency_ns.load(Ordering::Relaxed),
                    state.max_allocation_latency_ns.load(Ordering::Relaxed),
                    state.compaction_attempts.load(Ordering::Relaxed),
                    state.compaction_successes.load(Ordering::Relaxed));
            }
            
            log::info!("=================================");
        }
    }
} 