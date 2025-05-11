// AetherOS データローカリティ最適化モジュール
//
// このモジュールは、メモリアクセスパターンの分析に基づいて、
// データの配置を最適化し、キャッシュ効率と性能を向上させます。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::RwLock;
use crate::arch::MemoryInfo;
use crate::core::memory::{MemoryTier, numa};

/// アクセスパターンタイプ
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AccessPattern {
    /// ランダムアクセス（予測困難）
    Random,
    /// シーケンシャルアクセス（連続的）
    Sequential,
    /// ストライドアクセス（一定間隔）
    Strided(usize), // ストライド幅
    /// 局所的アクセス（狭い範囲内）
    Localized(usize), // 局所性ウィンドウサイズ
    /// 時間的局所性（同じアドレスに繰り返しアクセス）
    TemporalLocality(usize), // 再アクセス頻度
    /// 混合パターン
    Mixed,
}

/// データブロック情報
pub struct DataBlock {
    /// 開始アドレス
    pub address: usize,
    /// サイズ（バイト）
    pub size: usize,
    /// アクセスカウント
    pub access_count: AtomicUsize,
    /// 最後のアクセス時間（ティック）
    pub last_access: AtomicUsize,
    /// アクセスパターン
    pub pattern: RwLock<AccessPattern>,
    /// 割り当てられているメモリ階層
    pub current_tier: RwLock<MemoryTier>,
    /// NUMAノード（割り当てられている場合）
    pub numa_node: Option<usize>,
    /// 関連プロセスID
    pub process_id: Option<usize>,
}

/// ローカリティエンジン
struct LocalityEngine {
    /// 追跡中のデータブロック
    blocks: Vec<DataBlock>,
    /// アクセスヒストリー
    access_history: Vec<(usize, usize)>, // (アドレス, 時間)
    /// 現在の時間（ティック）
    current_time: AtomicUsize,
    /// キャッシュライン分析が有効か
    cache_line_analysis: bool,
    /// キャッシュの詳細情報
    cache_info: CacheInfo,
    /// ページサイズ
    page_size: usize,
    /// TLBエントリ数
    tlb_entries: usize,
    /// 再配置が有効か
    relocation_enabled: bool,
}

/// キャッシュ情報
struct CacheInfo {
    /// L1キャッシュラインサイズ
    l1_line_size: usize,
    /// L1キャッシュサイズ
    l1_size: usize,
    /// L2キャッシュラインサイズ
    l2_line_size: usize,
    /// L2キャッシュサイズ
    l2_size: usize,
    /// L3キャッシュラインサイズ
    l3_line_size: usize,
    /// L3キャッシュサイズ
    l3_size: usize,
    /// キャッシュ連想度
    associativity: usize,
}

/// グローバルローカリティエンジン
static mut LOCALITY_ENGINE: Option<LocalityEngine> = None;

/// モジュールの初期化
pub fn init() {
    let mem_info = crate::arch::get_memory_info();
    
    let cache_info = CacheInfo {
        l1_line_size: mem_info.l1_line_size,
        l1_size: mem_info.l1_cache_size,
        l2_line_size: mem_info.l2_line_size,
        l2_size: mem_info.l2_cache_size,
        l3_line_size: mem_info.l3_line_size,
        l3_size: mem_info.l3_cache_size,
        associativity: mem_info.cache_associativity,
    };
    
    let engine = LocalityEngine {
        blocks: Vec::new(),
        access_history: Vec::with_capacity(1024), // 履歴サイズは設定可能
        current_time: AtomicUsize::new(0),
        cache_line_analysis: true,
        cache_info,
        page_size: mem_info.page_size,
        tlb_entries: mem_info.tlb_entries,
        relocation_enabled: true,
    };
    
    unsafe {
        LOCALITY_ENGINE = Some(engine);
    }
    
    log::info!("データローカリティ最適化エンジン初期化完了: キャッシュライン分析={}, 自動再配置={}",
              engine.cache_line_analysis, engine.relocation_enabled);
}

/// データブロックを追跡対象として登録
pub fn register_data_block(address: usize, size: usize, process_id: Option<usize>) -> usize {
    let engine = unsafe {
        match LOCALITY_ENGINE.as_mut() {
            Some(engine) => engine,
            None => return 0, // エンジンが初期化されていない
        }
    };
    
    // NUMAノードの特定
    let numa_node = if numa::is_supported() {
        if let Some(cpu_id) = crate::arch::get_current_cpu_option() {
            numa::get_node_for_cpu(cpu_id)
        } else {
            None
        }
    } else {
        None
    };
    
    // データブロックの作成
    let block = DataBlock {
        address,
        size,
        access_count: AtomicUsize::new(0),
        last_access: AtomicUsize::new(engine.current_time.load(Ordering::Relaxed)),
        pattern: RwLock::new(AccessPattern::Mixed), // 初期はMixed
        current_tier: RwLock::new(MemoryTier::StandardDram), // 初期は標準DRAM
        numa_node,
        process_id,
    };
    
    // ブロックを追加し、IDを返す
    engine.blocks.push(block);
    engine.blocks.len() - 1
}

/// メモリアクセスを記録
pub fn record_memory_access(block_id: usize, offset: usize) {
    let engine = unsafe {
        match LOCALITY_ENGINE.as_mut() {
            Some(engine) => engine,
            None => return, // エンジンが初期化されていない
        }
    };
    
    // ブロックIDの検証
    if block_id >= engine.blocks.len() {
        return;
    }
    
    let block = &engine.blocks[block_id];
    
    // アクセスカウントの更新
    block.access_count.fetch_add(1, Ordering::Relaxed);
    
    // 現在時刻の取得と更新
    let current_time = engine.current_time.fetch_add(1, Ordering::Relaxed);
    block.last_access.store(current_time, Ordering::Relaxed);
    
    // アクセスアドレスの計算
    let access_address = block.address + offset;
    
    // アクセス履歴の記録
    engine.access_history.push((access_address, current_time));
    if engine.access_history.len() > 1024 {
        // 履歴が多すぎる場合は古いものを削除
        engine.access_history.remove(0);
    }
    
    // 一定間隔でアクセスパターン解析
    if block.access_count.load(Ordering::Relaxed) % 100 == 0 {
        analyze_access_pattern(block_id);
    }
}

/// アクセスパターンの解析
fn analyze_access_pattern(block_id: usize) {
    let engine = unsafe {
        match LOCALITY_ENGINE.as_ref() {
            Some(engine) => engine,
            None => return,
        }
    };
    
    // ブロックIDの検証
    if block_id >= engine.blocks.len() {
        return;
    }
    
    let block = &engine.blocks[block_id];
    
    // ブロックに関するアクセス履歴の抽出
    let block_history: Vec<_> = engine.access_history.iter()
        .filter(|(addr, _)| {
            *addr >= block.address && *addr < block.address + block.size
        })
        .collect();
    
    if block_history.len() < 10 {
        // 十分なデータがない場合は分析しない
        return;
    }
    
    // アクセスパターンの分析
    let pattern = detect_pattern(&block_history, block);
    
    // パターンの更新
    *block.pattern.write() = pattern;
    
    // 必要に応じて最適化の推奨
    if engine.relocation_enabled {
        recommend_optimization(block_id, pattern);
    }
}

/// アクセスパターンの検出
fn detect_pattern(history: &[&(usize, usize)], block: &DataBlock) -> AccessPattern {
    // アクセスアドレスのみを抽出
    let addresses: Vec<usize> = history.iter().map(|(addr, _)| *addr).collect();
    
    // シーケンシャルアクセスの検出
    if is_sequential(&addresses) {
        return AccessPattern::Sequential;
    }
    
    // ストライドアクセスの検出
    if let Some(stride) = detect_stride(&addresses) {
        return AccessPattern::Strided(stride);
    }
    
    // 局所性の検出
    if let Some(window_size) = detect_locality(&addresses) {
        return AccessPattern::Localized(window_size);
    }
    
    // 時間的局所性の検出
    if let Some(frequency) = detect_temporal_locality(history) {
        return AccessPattern::TemporalLocality(frequency);
    }
    
    // 特定のパターンが見つからない場合はランダムまたは混合
    if addresses.len() > 30 {
        // 十分なサンプルがあればランダム性を評価
        if is_random(&addresses) {
            AccessPattern::Random
        } else {
            AccessPattern::Mixed
        }
    } else {
        AccessPattern::Mixed
    }
}

/// シーケンシャルアクセスかどうかを判定
fn is_sequential(addresses: &[usize]) -> bool {
    if addresses.len() < 3 {
        return false;
    }
    
    // 連続したアドレスへのアクセスをチェック
    let mut sequential_count = 0;
    for i in 1..addresses.len() {
        // 正確な連続性よりも傾向を重視
        if addresses[i] == addresses[i-1] + 1 ||
           addresses[i] == addresses[i-1] + 4 ||
           addresses[i] == addresses[i-1] + 8 {
            sequential_count += 1;
        }
    }
    
    // 80%以上がシーケンシャルなら真と判定
    sequential_count >= addresses.len() * 4 / 5
}

/// ストライドパターンの検出
fn detect_stride(addresses: &[usize]) -> Option<usize> {
    if addresses.len() < 4 {
        return None;
    }
    
    // 差分の計算
    let mut diffs = Vec::with_capacity(addresses.len() - 1);
    for i in 1..addresses.len() {
        if addresses[i] > addresses[i-1] {
            diffs.push(addresses[i] - addresses[i-1]);
        }
    }
    
    if diffs.is_empty() {
        return None;
    }
    
    // 最も頻繁な差分を検出
    let mut frequency = alloc::collections::BTreeMap::new();
    for &diff in &diffs {
        *frequency.entry(diff).or_insert(0) += 1;
    }
    
    let (stride, count) = frequency.iter()
        .max_by_key(|(_, &count)| count)
        .unwrap_or((&0, &0));
    
    // 50%以上の差分が同じならストライドパターンと判定
    if *count >= diffs.len() / 2 {
        Some(*stride)
    } else {
        None
    }
}

/// 空間的局所性の検出
fn detect_locality(addresses: &[usize]) -> Option<usize> {
    if addresses.len() < 4 {
        return None;
    }
    
    // アドレス範囲の計算
    let min_addr = *addresses.iter().min().unwrap_or(&0);
    let max_addr = *addresses.iter().max().unwrap_or(&0);
    let range = max_addr - min_addr;
    
    // アドレス範囲が小さい場合は局所的と判断
    if range < 4096 {
        Some(range)
    } else {
        None
    }
}

/// 時間的局所性の検出
fn detect_temporal_locality(history: &[&(usize, usize)]) -> Option<usize> {
    if history.len() < 4 {
        return None;
    }
    
    // アドレスの再アクセス頻度をカウント
    let mut addr_count = alloc::collections::BTreeMap::new();
    for &(addr, _) in history {
        *addr_count.entry(addr).or_insert(0) += 1;
    }
    
    // 複数回アクセスされたアドレスの割合
    let multi_access_count = addr_count.values().filter(|&&count| count > 1).count();
    let distinct_addr_count = addr_count.len();
    
    if multi_access_count > distinct_addr_count / 2 {
        // 半数以上のアドレスが複数回アクセスされている場合、時間的局所性が高い
        let avg_access = history.len() / distinct_addr_count;
        Some(avg_access)
    } else {
        None
    }
}

/// ランダムアクセスかどうかを判定
fn is_random(addresses: &[usize]) -> bool {
    if addresses.len() < 10 {
        return false;
    }
    
    // シンプルなランダム性判定 (より精密な統計的テストに置き換え可能)
    let jumps = addresses.windows(2)
        .map(|w| if w[1] > w[0] { w[1] - w[0] } else { w[0] - w[1] })
        .collect::<Vec<_>>();
    
    let avg_jump = jumps.iter().sum::<usize>() / jumps.len();
    let variance = jumps.iter()
        .map(|&j| if j > avg_jump { j - avg_jump } else { avg_jump - j })
        .sum::<usize>() / jumps.len();
    
    // 分散が大きければランダムと判定
    variance > avg_jump * 10
}

/// 最適化の推奨
fn recommend_optimization(block_id: usize, pattern: AccessPattern) {
    let engine = unsafe {
        match LOCALITY_ENGINE.as_mut() {
            Some(engine) => engine,
            None => return,
        }
    };
    
    // ブロックIDの検証
    if block_id >= engine.blocks.len() {
        return;
    }
    
    let block = &engine.blocks[block_id];
    let current_tier = *block.current_tier.read();
    
    // パターンに基づく最適なメモリ階層の判断
    let optimal_tier = match pattern {
        AccessPattern::Random => {
            // ランダムアクセスは高速メモリが有利
            MemoryTier::FastDram
        },
        AccessPattern::Sequential => {
            // シーケンシャルアクセスはCXLやPMEMでも十分
            if block.size > 1024 * 1024 * 10 {
                // 大きいブロックはCXLへ
                MemoryTier::CxlMemory
            } else {
                // 小さいブロックは標準DRAMで十分
                MemoryTier::StandardDram
            }
        },
        AccessPattern::Strided(stride) => {
            // ストライドパターンはキャッシュライン効率に影響
            if stride < engine.cache_info.l1_line_size {
                // 小さいストライドは高速DRAMが有利
                MemoryTier::FastDram
            } else {
                // 大きいストライドは標準DRAMで十分
                MemoryTier::StandardDram
            }
        },
        AccessPattern::Localized(window) => {
            // ローカルアクセスはキャッシュサイズに応じて判断
            if window < engine.cache_info.l1_size / 2 {
                // 小さいウィンドウは標準DRAMで十分
                MemoryTier::StandardDram
            } else if window < engine.cache_info.l3_size {
                // 中サイズは高速DRAM
                MemoryTier::FastDram
            } else {
                // 大きいウィンドウはCXL
                MemoryTier::CxlMemory
            }
        },
        AccessPattern::TemporalLocality(frequency) => {
            // 時間的局所性は高いほど高速メモリが有利
            if frequency > 10 {
                MemoryTier::FastDram
            } else {
                MemoryTier::StandardDram
            }
        },
        AccessPattern::Mixed => {
            // 混合パターンはサイズに応じて判断
            if block.size > 1024 * 1024 {
                MemoryTier::CxlMemory
            } else {
                MemoryTier::StandardDram
            }
        },
    };
    
    // 現在と最適階層が異なる場合、移動を提案
    if current_tier != optimal_tier {
        // データの移動処理を行う
        if should_relocate(block, current_tier, optimal_tier) {
            log::debug!("データブロック #{} ({}バイト): {:?} -> {:?} へ再配置を推奨",
                       block_id, block.size, current_tier, optimal_tier);
            
            // ここで実際の再配置処理を行う場合は実装
            if engine.relocation_enabled {
                // TODO: relocate_data_block(block_id, optimal_tier);
            }
            
            // 最適な階層を更新
            *block.current_tier.write() = optimal_tier;
        }
    }
}

/// 再配置すべきかの判断
fn should_relocate(block: &DataBlock, current_tier: MemoryTier, optimal_tier: MemoryTier) -> bool {
    // アクセス頻度が低い場合は再配置しない
    if block.access_count.load(Ordering::Relaxed) < 100 {
        return false;
    }
    
    // 小さすぎるブロックは再配置コストが大きいので避ける
    if block.size < 4096 {
        return false;
    }
    
    // 現在の階層と最適階層の差が大きい場合は再配置
    match (current_tier, optimal_tier) {
        (MemoryTier::StandardDram, MemoryTier::FastDram) => true,
        (MemoryTier::CxlMemory, MemoryTier::FastDram) => true,
        (MemoryTier::StandardDram, MemoryTier::PersistentMemory) => {
            // 永続性が必要な場合のみ
            block.access_count.load(Ordering::Relaxed) > 1000
        },
        (MemoryTier::FastDram, MemoryTier::CxlMemory) => {
            // 高速DRAMから遅いメモリへの移動は慎重に
            block.size > 1024 * 1024 * 50 // 非常に大きい場合のみ
        },
        _ => false,
    }
}

/// 現在追跡中のデータブロック数を取得
pub fn get_tracked_block_count() -> usize {
    unsafe {
        LOCALITY_ENGINE.as_ref().map_or(0, |e| e.blocks.len())
    }
}

/// 指定ブロックのアクセスパターンを取得
pub fn get_block_pattern(block_id: usize) -> Option<AccessPattern> {
    unsafe {
        LOCALITY_ENGINE.as_ref().and_then(|e| {
            e.blocks.get(block_id).map(|b| *b.pattern.read())
        })
    }
}

/// キャッシュライン最適化情報を取得
pub fn get_cache_line_optimization_info() -> CacheLineInfo {
    let engine = unsafe {
        match LOCALITY_ENGINE.as_ref() {
            Some(engine) => engine,
            None => return CacheLineInfo::default(),
        }
    };
    
    CacheLineInfo {
        l1_line_size: engine.cache_info.l1_line_size,
        l2_line_size: engine.cache_info.l2_line_size,
        l3_line_size: engine.cache_info.l3_line_size,
        page_size: engine.page_size,
        optimal_stride: engine.cache_info.l1_line_size,
    }
}

/// キャッシュライン最適化情報
#[derive(Debug, Copy, Clone)]
pub struct CacheLineInfo {
    /// L1キャッシュラインサイズ
    pub l1_line_size: usize,
    /// L2キャッシュラインサイズ
    pub l2_line_size: usize,
    /// L3キャッシュラインサイズ
    pub l3_line_size: usize,
    /// ページサイズ
    pub page_size: usize,
    /// 最適なストライド
    pub optimal_stride: usize,
}

impl Default for CacheLineInfo {
    fn default() -> Self {
        Self {
            l1_line_size: 64,
            l2_line_size: 64,
            l3_line_size: 64,
            page_size: 4096,
            optimal_stride: 64,
        }
    }
}

/// 指定ブロックのデータレイアウト最適化レコメンデーションを取得
pub fn get_layout_recommendation(block_id: usize) -> Option<LayoutRecommendation> {
    unsafe {
        LOCALITY_ENGINE.as_ref().and_then(|e| {
            e.blocks.get(block_id).map(|b| {
                let pattern = *b.pattern.read();
                let cache_info = &e.cache_info;
                
                // パターンに基づいたレコメンデーション
                match pattern {
                    AccessPattern::Sequential => LayoutRecommendation {
                        alignment: cache_info.l1_line_size,
                        prefetch_distance: cache_info.l1_size / 4,
                        access_strategy: AccessStrategy::Sequential,
                        memory_tier: MemoryTier::StandardDram,
                    },
                    AccessPattern::Strided(stride) => LayoutRecommendation {
                        alignment: cache_info.l1_line_size,
                        prefetch_distance: stride * 4,
                        access_strategy: AccessStrategy::Strided(stride),
                        memory_tier: if stride < cache_info.l1_line_size {
                            MemoryTier::FastDram
                        } else {
                            MemoryTier::StandardDram
                        },
                    },
                    AccessPattern::Localized(window) => LayoutRecommendation {
                        alignment: cache_info.l1_line_size,
                        prefetch_distance: window,
                        access_strategy: AccessStrategy::Compact,
                        memory_tier: if window < cache_info.l1_size {
                            MemoryTier::StandardDram
                        } else {
                            MemoryTier::FastDram
                        },
                    },
                    AccessPattern::TemporalLocality(_) => LayoutRecommendation {
                        alignment: cache_info.l1_line_size,
                        prefetch_distance: 0, // プリフェッチは不要
                        access_strategy: AccessStrategy::CacheOptimized,
                        memory_tier: MemoryTier::FastDram,
                    },
                    AccessPattern::Random => LayoutRecommendation {
                        alignment: cache_info.l1_line_size,
                        prefetch_distance: 0, // ランダムアクセスではプリフェッチ無効
                        access_strategy: AccessStrategy::RandomAccess,
                        memory_tier: MemoryTier::FastDram,
                    },
                    AccessPattern::Mixed => LayoutRecommendation {
                        alignment: cache_info.l1_line_size,
                        prefetch_distance: cache_info.l1_line_size * 2,
                        access_strategy: AccessStrategy::Balanced,
                        memory_tier: MemoryTier::StandardDram,
                    },
                }
            })
        })
    }
}

/// データレイアウト最適化レコメンデーション
#[derive(Debug, Copy, Clone)]
pub struct LayoutRecommendation {
    /// 推奨アライメント
    pub alignment: usize,
    /// プリフェッチ距離
    pub prefetch_distance: usize,
    /// アクセス戦略
    pub access_strategy: AccessStrategy,
    /// 推奨メモリ階層
    pub memory_tier: MemoryTier,
}

/// メモリアクセス戦略
#[derive(Debug, Copy, Clone)]
pub enum AccessStrategy {
    /// シーケンシャルアクセス最適化
    Sequential,
    /// ストライドアクセス最適化
    Strided(usize),
    /// コンパクトアクセス最適化
    Compact,
    /// キャッシュ最適化アクセス
    CacheOptimized,
    /// ランダムアクセス最適化
    RandomAccess,
    /// バランス型アクセス
    Balanced,
}

/// オブジェクトのメモリレイアウトを最適化
pub fn optimize_memory_layout<T>(objects: &mut [T]) -> LayoutOptimizationResult {
    let start_addr = objects.as_ptr() as usize;
    let size = core::mem::size_of::<T>() * objects.len();
    
    // データブロックとして登録
    let block_id = register_data_block(start_addr, size, None);
    
    // 初期状態では最適化は行わず、追跡のみ設定
    LayoutOptimizationResult {
        block_id,
        optimized: false,
        recommendation: None,
    }
}

/// レイアウト最適化結果
pub struct LayoutOptimizationResult {
    /// 割り当てられたブロックID
    pub block_id: usize,
    /// 最適化が行われたか
    pub optimized: bool,
    /// 推奨設定
    pub recommendation: Option<LayoutRecommendation>,
}

/// プリフェッチヒント
pub fn prefetch_hint(address: *const u8, size: usize, temporal: bool) {
    // アーキテクチャのプリフェッチ命令を使用
    crate::arch::prefetch(address, size, temporal);
}

/// データローカリティ統計の表示
pub fn print_stats() {
    let engine = unsafe {
        match LOCALITY_ENGINE.as_ref() {
            Some(engine) => engine,
            None => {
                log::info!("データローカリティエンジンが初期化されていません");
                return;
            }
        }
    };
    
    log::info!("=== データローカリティ統計 ===");
    log::info!("追跡中データブロック: {}", engine.blocks.len());
    
    // パターンごとのブロック数をカウント
    let mut pattern_counts = alloc::collections::BTreeMap::new();
    for block in &engine.blocks {
        let pattern = *block.pattern.read();
        *pattern_counts.entry(format!("{:?}", pattern)).or_insert(0) += 1;
    }
    
    // パターン分布の表示
    log::info!("アクセスパターン分布:");
    for (pattern, count) in pattern_counts {
        log::info!("  {}: {} ブロック", pattern, count);
    }
    
    // キャッシュ情報の表示
    log::info!("キャッシュ情報:");
    log::info!("  L1: {}バイト (ライン: {}バイト)", 
              engine.cache_info.l1_size, engine.cache_info.l1_line_size);
    log::info!("  L2: {}バイト (ライン: {}バイト)", 
              engine.cache_info.l2_size, engine.cache_info.l2_line_size);
    log::info!("  L3: {}バイト (ライン: {}バイト)", 
              engine.cache_info.l3_size, engine.cache_info.l3_line_size);
    
    log::info!("ページサイズ: {}バイト", engine.page_size);
    log::info!("TLBエントリ数: {}", engine.tlb_entries);
    log::info!("自動再配置: {}", if engine.relocation_enabled { "有効" } else { "無効" });
    log::info!("=============================");
} 