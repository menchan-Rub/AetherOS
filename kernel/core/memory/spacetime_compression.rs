// AetherOS 時空間メモリ圧縮システム
//
// 時間的・空間的冗長性を活用したメモリ圧縮技術を実装します。
// 一時点での似たデータパターン（空間的冗長性）と
// 同一アドレスの経時変化（時間的冗長性）の両方を利用して
// メモリ使用効率を大幅に向上させます。

use alloc::vec::Vec;
use alloc::collections::{BTreeMap, BTreeSet};
use core::sync::atomic::{AtomicUsize, AtomicBool, AtomicF64, Ordering};
use crate::arch::MemoryInfo;
use log::{info, debug, warn};

/// 時空間圧縮マネージャの状態
static mut SPACETIME_COMPRESSION: Option<SpacetimeCompression> = None;

/// 時間的・空間的冗長性を活用した圧縮メモリ
pub struct SpacetimeCompression {
    /// 時間的辞書（前回の状態との差分用）
    temporal_dictionary: TemporalDictionary,
    /// 空間的パターンキャッシュ
    spatial_patterns: SpatialPatternCache,
    /// 圧縮率
    compression_ratio: AtomicF64,
    /// 圧縮されたページ数
    compressed_pages: AtomicUsize,
    /// 圧縮によって節約されたメモリ量
    saved_memory: AtomicUsize,
    /// 圧縮・解凍操作カウント
    operation_count: AtomicUsize,
    /// 有効フラグ
    enabled: AtomicBool,
}

/// 時間的辞書
struct TemporalDictionary {
    /// 過去の状態マップ (アドレス → 過去の状態)
    previous_states: BTreeMap<usize, Vec<u8>>,
    /// デルタエンコーディングマップ (アドレス → デルタシーケンス)
    delta_encodings: BTreeMap<usize, Vec<DeltaEncoding>>,
    /// 最大保持エントリ数
    max_entries: usize,
    /// 過去の状態を保持する最大間隔（ミリ秒）
    max_interval_ms: u64,
}

/// デルタエンコーディング
#[derive(Debug, Clone)]
struct DeltaEncoding {
    /// タイムスタンプ
    timestamp: u64,
    /// オフセット（ページ内）
    offset: usize,
    /// 長さ
    length: usize,
    /// デルタデータ（変更部分のみ）
    delta_data: Vec<u8>,
}

/// 空間的パターンキャッシュ
struct SpatialPatternCache {
    /// 共通パターンマップ (パターンハッシュ → パターンデータ)
    patterns: BTreeMap<u64, Vec<u8>>,
    /// 参照カウント (パターンハッシュ → 参照数)
    reference_counts: BTreeMap<u64, usize>,
    /// パターン検出閾値（最小一致長）
    pattern_threshold: usize,
    /// 最大パターン数
    max_patterns: usize,
}

/// 圧縮ページ
#[derive(Debug, Clone)]
pub struct CompressedPage {
    /// 元のアドレス
    original_addr: usize,
    /// 元のサイズ
    original_size: usize,
    /// 圧縮後のサイズ
    compressed_size: usize,
    /// 圧縮方法
    compression_method: CompressionMethod,
    /// 圧縮されたデータ
    compressed_data: Vec<u8>,
    /// 解凍に必要な参照情報
    references: Vec<Reference>,
}

/// 圧縮領域
#[derive(Debug, Clone)]
pub struct CompressedRegion {
    /// 元のアドレス
    original_addr: usize,
    /// 元のサイズ
    original_size: usize,
    /// 圧縮後のサイズ
    compressed_size: usize,
    /// 圧縮ページのリスト
    pages: Vec<CompressedPage>,
    /// 総圧縮率
    compression_ratio: f64,
}

/// 圧縮方法
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    /// 差分圧縮（時間的）
    DeltaEncoding,
    /// パターン参照（空間的）
    PatternReference,
    /// ゼロページ特殊圧縮
    ZeroPage,
    /// ランレングス圧縮
    RunLength,
    /// 辞書圧縮
    Dictionary,
    /// ハイブリッド圧縮
    Hybrid,
}

/// 参照情報
#[derive(Debug, Clone)]
struct Reference {
    /// 参照タイプ
    ref_type: ReferenceType,
    /// 参照先アドレス
    ref_addr: usize,
    /// オフセット
    offset: usize,
    /// 長さ
    length: usize,
    /// 参照パターンID（PatternReference用）
    pattern_id: Option<u64>,
}

/// 参照タイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReferenceType {
    /// 時間的参照（前回の状態）
    Temporal,
    /// 空間的参照（共通パターン）
    Spatial,
    /// 自己参照（同一ページ内の繰り返し）
    Self,
}

/// 時空間圧縮の初期化
pub fn init(mem_info: &MemoryInfo) {
    // 辞書サイズとパターンキャッシュサイズの計算
    let total_memory = mem_info.total_memory;
    let dictionary_size = total_memory / 200; // 0.5%をディクショナリに
    let pattern_cache_size = total_memory / 200; // 0.5%をパターンキャッシュに
    
    // 辞書エントリ数の計算（平均4KBのページを想定）
    let dictionary_entries = dictionary_size / 4096;
    
    // 時間的辞書の初期化
    let temporal_dictionary = TemporalDictionary {
        previous_states: BTreeMap::new(),
        delta_encodings: BTreeMap::new(),
        max_entries: dictionary_entries,
        max_interval_ms: 10000, // 10秒
    };
    
    // 空間的パターンキャッシュの初期化
    let spatial_patterns = SpatialPatternCache {
        patterns: BTreeMap::new(),
        reference_counts: BTreeMap::new(),
        pattern_threshold: 64, // 最小64バイトのパターン
        max_patterns: pattern_cache_size / 128, // 平均128バイトのパターンを想定
    };
    
    let compression = SpacetimeCompression {
        temporal_dictionary,
        spatial_patterns,
        compression_ratio: AtomicF64::new(1.0),
        compressed_pages: AtomicUsize::new(0),
        saved_memory: AtomicUsize::new(0),
        operation_count: AtomicUsize::new(0),
        enabled: AtomicBool::new(true),
    };
    
    unsafe {
        SPACETIME_COMPRESSION = Some(compression);
    }
    
    // 定期的なメンテナンス処理をスケジュール
    crate::scheduling::register_periodic_task(
        compression_maintenance_task,
        "spacetime_compression_maintenance",
        30 * 1000, // 30秒間隔
    );
    
    info!("時空間メモリ圧縮を初期化しました: 辞書エントリ数={}, パターン最大数={}",
          dictionary_entries, pattern_cache_size / 128);
}

/// 時間的類似性に基づく増分圧縮
pub fn compress_temporal_redundancy(page_addr: usize, page_data: &[u8]) -> Option<CompressedPage> {
    if !is_enabled() {
        return None;
    }
    
    unsafe {
        if let Some(compression) = SPACETIME_COMPRESSION.as_mut() {
            // 前回の状態があるか確認
            if let Some(previous_data) = compression.temporal_dictionary.previous_states.get(&page_addr) {
                if previous_data.len() == page_data.len() {
                    // デルタエンコーディングを計算
                    let delta = compute_delta_encoding(previous_data, page_data);
                    
                    // デルタが効率的なら圧縮ページを作成
                    if delta.len() < page_data.len() / 4 { // 75%以上の圧縮率
                        let now = crate::time::current_time_ms();
                        
                        // デルタエンコーディングをマップに追加
                        let delta_record = DeltaEncoding {
                            timestamp: now,
                            offset: 0,
                            length: page_data.len(),
                            delta_data: delta.clone(),
                        };
                        
                        let delta_list = compression.temporal_dictionary.delta_encodings
                            .entry(page_addr)
                            .or_insert_with(Vec::new);
                        
                        delta_list.push(delta_record);
                        
                        // 最大エントリ数を超えたら古いものを削除
                        if delta_list.len() > 10 {
                            delta_list.remove(0);
                        }
                        
                        // 圧縮ページの作成
                        let compressed = CompressedPage {
                            original_addr: page_addr,
                            original_size: page_data.len(),
                            compressed_size: delta.len(),
                            compression_method: CompressionMethod::DeltaEncoding,
                            compressed_data: delta,
                            references: vec![
                                Reference {
                                    ref_type: ReferenceType::Temporal,
                                    ref_addr: page_addr,
                                    offset: 0,
                                    length: page_data.len(),
                                    pattern_id: None,
                                }
                            ],
                        };
                        
                        // 統計情報更新
                        let saved = page_data.len() - compressed.compressed_size;
                        compression.saved_memory.fetch_add(saved, Ordering::Relaxed);
                        compression.compressed_pages.fetch_add(1, Ordering::Relaxed);
                        compression.operation_count.fetch_add(1, Ordering::Relaxed);
                        
                        // 圧縮率を更新
                        update_compression_ratio(compression);
                        
                        return Some(compressed);
                    }
                }
            }
            
            // 圧縮しない場合でも、現在の状態を保存
            let mut state_copy = Vec::with_capacity(page_data.len());
            state_copy.extend_from_slice(page_data);
            
            compression.temporal_dictionary.previous_states.insert(page_addr, state_copy);
            
            // 辞書サイズ制限
            if compression.temporal_dictionary.previous_states.len() > compression.temporal_dictionary.max_entries {
                // 最も古いエントリを削除
                if let Some((&oldest_key, _)) = compression.temporal_dictionary.previous_states.iter().next() {
                    compression.temporal_dictionary.previous_states.remove(&oldest_key);
                    compression.temporal_dictionary.delta_encodings.remove(&oldest_key);
                }
            }
        }
    }
    
    None
}

/// デルタエンコーディングの計算
fn compute_delta_encoding(previous: &[u8], current: &[u8]) -> Vec<u8> {
    let mut delta = Vec::new();
    let mut run_start = 0;
    let mut in_diff_run = false;
    
    for i in 0..previous.len() {
        if i >= current.len() {
            break;
        }
        
        if previous[i] != current[i] {
            if !in_diff_run {
                // 差分開始
                run_start = i;
                in_diff_run = true;
            }
        } else if in_diff_run {
            // 差分終了
            let run_length = i - run_start;
            
            // [オフセット(4バイト)][長さ(2バイト)][データ(...)]の形式で記録
            delta.extend_from_slice(&(run_start as u32).to_le_bytes());
            delta.extend_from_slice(&(run_length as u16).to_le_bytes());
            delta.extend_from_slice(&current[run_start..i]);
            
            in_diff_run = false;
        }
    }
    
    // 最後の差分があれば記録
    if in_diff_run {
        let run_length = current.len() - run_start;
        
        delta.extend_from_slice(&(run_start as u32).to_le_bytes());
        delta.extend_from_slice(&(run_length as u16).to_le_bytes());
        delta.extend_from_slice(&current[run_start..]);
    }
    
    delta
}

/// 空間的類似性に基づくパターン圧縮
pub fn compress_spatial_patterns(region_addr: usize, region_data: &[u8]) -> Option<CompressedRegion> {
    if !is_enabled() || region_data.len() < 1024 {
        return None;
    }
    
    unsafe {
        if let Some(compression) = SPACETIME_COMPRESSION.as_mut() {
            // 共通パターンを検出
            let patterns = detect_patterns(region_data, compression.spatial_patterns.pattern_threshold);
            
            if patterns.is_empty() {
                return None;
            }
            
            // 既存のパターンキャッシュとマッチング
            let mut matched_patterns = Vec::new();
            let mut new_patterns = Vec::new();
            
            for pattern in &patterns {
                let pattern_hash = hash_pattern(&pattern.data);
                
                if compression.spatial_patterns.patterns.contains_key(&pattern_hash) {
                    // 既存パターンとマッチ
                    matched_patterns.push((pattern_hash, pattern.offset, pattern.length));
                    
                    // 参照カウントをインクリメント
                    let count = compression.spatial_patterns.reference_counts
                        .entry(pattern_hash)
                        .or_insert(0);
                    *count += 1;
                } else {
                    // 新パターン
                    new_patterns.push((pattern_hash, pattern.clone()));
                }
            }
            
            // 新パターンを追加（キャッシュサイズを考慮）
            for (hash, pattern) in new_patterns {
                // キャッシュ容量を確認
                if compression.spatial_patterns.patterns.len() >= compression.spatial_patterns.max_patterns {
                    // 最も参照の少ないパターンを削除
                    if let Some((&least_used_hash, _)) = compression
                        .spatial_patterns.reference_counts.iter()
                        .min_by_key(|(_, &count)| count) {
                        compression.spatial_patterns.patterns.remove(&least_used_hash);
                        compression.spatial_patterns.reference_counts.remove(&least_used_hash);
                    }
                }
                
                // 新パターンを追加
                compression.spatial_patterns.patterns.insert(hash, pattern.data.clone());
                compression.spatial_patterns.reference_counts.insert(hash, 1);
                
                // マッチングリストに追加
                matched_patterns.push((hash, pattern.offset, pattern.length));
            }
            
            // パターン参照に基づく圧縮領域を作成
            let page_size = 4096;
            let pages_count = (region_data.len() + page_size - 1) / page_size;
            let mut compressed_pages = Vec::with_capacity(pages_count);
            let mut total_original_size = 0;
            let mut total_compressed_size = 0;
            
            for page_idx in 0..pages_count {
                let page_offset = page_idx * page_size;
                let page_end = core::cmp::min(page_offset + page_size, region_data.len());
                let page_size = page_end - page_offset;
                
                let page_addr = region_addr + page_offset;
                
                // このページに関係するパターンを抽出
                let page_patterns: Vec<_> = matched_patterns.iter()
                    .filter(|(_, offset, length)| {
                        let pattern_end = offset + length;
                        // パターンとページの重なりをチェック
                        offset < &(page_offset + page_size) && pattern_end > page_offset
                    })
                    .collect();
                
                if !page_patterns.is_empty() {
                    // パターン参照の圧縮ページを作成
                    let mut references = Vec::with_capacity(page_patterns.len());
                    
                    for &(hash, offset, length) in &page_patterns {
                        references.push(Reference {
                            ref_type: ReferenceType::Spatial,
                            ref_addr: 0, // パターンキャッシュ参照は特別な参照先
                            offset,
                            length,
                            pattern_id: Some(hash),
                        });
                    }
                    
                    // 残りのデータを非圧縮で保持するための参照マップを作成
                    let mut remaining_data = Vec::new();
                    let mut covered = vec![false; page_size];
                    
                    // パターンで覆われる範囲をマーク
                    for &(_, offset, length) in &page_patterns {
                        let rel_start = if offset < page_offset { 0 } else { offset - page_offset };
                        let rel_end = core::cmp::min(rel_start + length, page_size);
                        
                        for i in rel_start..rel_end {
                            covered[i] = true;
                        }
                    }
                    
                    // 覆われていない部分を非圧縮データとして追加
                    for i in 0..page_size {
                        if !covered[i] && page_offset + i < region_data.len() {
                            remaining_data.push(region_data[page_offset + i]);
                        }
                    }
                    
                    // 圧縮ページ作成
                    let compressed_page = CompressedPage {
                        original_addr: page_addr,
                        original_size: page_size,
                        compressed_size: remaining_data.len(),
                        compression_method: CompressionMethod::PatternReference,
                        compressed_data: remaining_data,
                        references,
                    };
                    
                    total_original_size += page_size;
                    total_compressed_size += compressed_page.compressed_size;
                    compressed_pages.push(compressed_page);
                    
                    // 統計情報更新
                    compression.compressed_pages.fetch_add(1, Ordering::Relaxed);
                }
            }
            
            if !compressed_pages.is_empty() {
                // 統計情報更新
                let saved = total_original_size - total_compressed_size;
                compression.saved_memory.fetch_add(saved, Ordering::Relaxed);
                compression.operation_count.fetch_add(compressed_pages.len(), Ordering::Relaxed);
                
                // 圧縮率更新
                update_compression_ratio(compression);
                
                let ratio = if total_original_size > 0 {
                    total_compressed_size as f64 / total_original_size as f64
                } else {
                    1.0
                };
                
                // 圧縮領域を返す
                return Some(CompressedRegion {
                    original_addr: region_addr,
                    original_size: region_data.len(),
                    compressed_size: total_compressed_size,
                    pages: compressed_pages,
                    compression_ratio: ratio,
                });
            }
        }
    }
    
    None
}

/// パターン検出結果
struct DetectedPattern {
    /// オフセット
    offset: usize,
    /// 長さ
    length: usize,
    /// パターンデータ
    data: Vec<u8>,
}

/// パターン検出
fn detect_patterns(data: &[u8], min_size: usize) -> Vec<DetectedPattern> {
    let mut patterns = Vec::new();
    let mut hash_map = BTreeMap::new();
    
    // ローリングハッシュを使用して効率的にパターンを検出
    if data.len() < min_size {
        return patterns;
    }
    
    // 異なるサイズのウィンドウで反復
    for window_size in [64, 128, 256, 512, 1024].iter() {
        if *window_size < min_size || *window_size > data.len() {
            continue;
        }
        
        hash_map.clear();
        
        // オーバーラップするウィンドウでスキャン
        for i in 0..=(data.len() - window_size) {
            let window = &data[i..(i + window_size)];
            let hash = hash_window(window);
            
            hash_map.entry(hash)
                .and_modify(|offsets: &mut Vec<usize>| {
                    offsets.push(i);
                })
                .or_insert_with(|| vec![i]);
        }
        
        // 重複パターンを抽出
        for (hash, offsets) in hash_map {
            if offsets.len() > 1 {
                // 2回以上出現したパターン
                let offset = offsets[0];
                let pattern_data = data[offset..(offset + window_size)].to_vec();
                
                patterns.push(DetectedPattern {
                    offset,
                    length: *window_size,
                    data: pattern_data,
                });
                
                // パターンが多すぎる場合は制限
                if patterns.len() >= 100 {
                    break;
                }
            }
        }
    }
    
    // パターンが重複しないようにフィルタリング
    if patterns.len() > 1 {
        patterns.sort_by_key(|p| (-(p.length as isize), p.offset));
        
        let mut filtered_patterns = Vec::new();
        let mut covered = vec![false; data.len()];
        
        for pattern in patterns {
            // このパターンが既にカバーされた領域と重複しないか確認
            let mut overlap = false;
            for i in pattern.offset..(pattern.offset + pattern.length) {
                if i < covered.len() && covered[i] {
                    overlap = true;
                    break;
                }
            }
            
            if !overlap {
                // パターンで覆われる範囲をマーク
                for i in pattern.offset..(pattern.offset + pattern.length) {
                    if i < covered.len() {
                        covered[i] = true;
                    }
                }
                
                filtered_patterns.push(pattern);
            }
        }
        
        filtered_patterns
    } else {
        patterns
    }
}

/// ウィンドウのハッシュ計算
fn hash_window(window: &[u8]) -> u64 {
    // 簡易ハッシュ関数
    let mut hash = 0u64;
    
    for (i, &b) in window.iter().enumerate().take(64) {
        hash = hash.wrapping_add((b as u64) << (i % 8 * 8));
    }
    
    hash
}

/// パターンのハッシュ計算
fn hash_pattern(pattern: &[u8]) -> u64 {
    // より堅牢なハッシュ関数
    let mut h = 0xcbf29ce484222325u64;
    
    for &b in pattern {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    
    h
}

/// 圧縮ページの解凍
pub fn decompress_page(compressed: &CompressedPage) -> Option<Vec<u8>> {
    if !is_enabled() {
        return None;
    }
    
    unsafe {
        if let Some(compression) = SPACETIME_COMPRESSION.as_mut() {
            compression.operation_count.fetch_add(1, Ordering::Relaxed);
            
            match compressed.compression_method {
                CompressionMethod::DeltaEncoding => {
                    // 差分圧縮の解凍
                    if let Some(reference) = compressed.references.first() {
                        if reference.ref_type == ReferenceType::Temporal {
                            // 前回の状態を取得
                            if let Some(previous_data) = compression.temporal_dictionary.previous_states.get(&reference.ref_addr) {
                                // デルタを適用
                                return Some(apply_delta(previous_data, &compressed.compressed_data));
                            }
                        }
                    }
                },
                CompressionMethod::PatternReference => {
                    // パターン参照の解凍
                    let mut result = vec![0u8; compressed.original_size];
                    let mut filled = vec![false; compressed.original_size];
                    
                    // まずパターンで埋める
                    for reference in &compressed.references {
                        if reference.ref_type == ReferenceType::Spatial {
                            if let Some(pattern_id) = reference.pattern_id {
                                if let Some(pattern_data) = compression.spatial_patterns.patterns.get(&pattern_id) {
                                    // パターンデータをコピー
                                    let rel_start = reference.offset - compressed.original_addr;
                                    let copy_len = core::cmp::min(reference.length, compressed.original_size - rel_start);
                                    
                                    for i in 0..copy_len {
                                        if i < pattern_data.len() && rel_start + i < result.len() {
                                            result[rel_start + i] = pattern_data[i];
                                            filled[rel_start + i] = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    // 残りの部分を非圧縮データで埋める
                    let mut data_idx = 0;
                    for i in 0..result.len() {
                        if !filled[i] && data_idx < compressed.compressed_data.len() {
                            result[i] = compressed.compressed_data[data_idx];
                            data_idx += 1;
                        }
                    }
                    
                    return Some(result);
                },
                _ => {
                    // その他の圧縮方法（今回は未実装）
                }
            }
        }
    }
    
    None
}

/// デルタの適用
fn apply_delta(base: &[u8], delta: &[u8]) -> Vec<u8> {
    let mut result = base.to_vec();
    let mut pos = 0;
    
    while pos + 6 <= delta.len() { // 最低オフセット(4) + 長さ(2)のバイト数
        // オフセットと長さを読み取り
        let offset = u32::from_le_bytes([
            delta[pos], delta[pos+1], delta[pos+2], delta[pos+3]
        ]) as usize;
        pos += 4;
        
        let length = u16::from_le_bytes([delta[pos], delta[pos+1]]) as usize;
        pos += 2;
        
        // データをコピー
        if offset + length <= result.len() && pos + length <= delta.len() {
            for i in 0..length {
                result[offset + i] = delta[pos + i];
            }
            pos += length;
        } else {
            // 不正なデルタ
            break;
        }
    }
    
    result
}

/// 圧縮率の更新
fn update_compression_ratio(compression: &mut SpacetimeCompression) {
    let original_size = compression.compressed_pages.load(Ordering::Relaxed) * 4096; // 標準ページサイズを想定
    let saved = compression.saved_memory.load(Ordering::Relaxed);
    
    if original_size > 0 {
        let compressed_size = if saved < original_size {
            original_size - saved
        } else {
            0
        };
        
        let ratio = compressed_size as f64 / original_size as f64;
        compression.compression_ratio.store(ratio, Ordering::Relaxed);
    }
}

/// 定期的な圧縮メンテナンスタスク
fn compression_maintenance_task() {
    if !is_enabled() {
        return;
    }
    
    unsafe {
        if let Some(compression) = SPACETIME_COMPRESSION.as_mut() {
            // 古くなった時間的辞書エントリを削除
            let now = crate::time::current_time_ms();
            let max_age = compression.temporal_dictionary.max_interval_ms;
            
            let mut old_keys = Vec::new();
            
            // 古い時間的デルタをクリーンアップ
            for (addr, deltas) in &mut compression.temporal_dictionary.delta_encodings {
                deltas.retain(|delta| now - delta.timestamp < max_age);
                
                if deltas.is_empty() {
                    old_keys.push(*addr);
                }
            }
            
            // 空になったエントリを削除
            for key in old_keys {
                compression.temporal_dictionary.delta_encodings.remove(&key);
                
                // 対応する過去の状態も削除
                if !compression.temporal_dictionary.delta_encodings.contains_key(&key) {
                    compression.temporal_dictionary.previous_states.remove(&key);
                }
            }
            
            // 使用頻度の低いパターンを削除
            if compression.spatial_patterns.patterns.len() > compression.spatial_patterns.max_patterns / 2 {
                // 参照カウントでソート
                let mut pattern_refs: Vec<_> = compression.spatial_patterns.reference_counts.iter().collect();
                pattern_refs.sort_by_key(|(_, &count)| count);
                
                // 下位20%を削除
                let to_remove = pattern_refs.len() / 5;
                for i in 0..to_remove {
                    if i < pattern_refs.len() {
                        let (hash, _) = pattern_refs[i];
                        compression.spatial_patterns.patterns.remove(hash);
                        compression.spatial_patterns.reference_counts.remove(hash);
                    }
                }
            }
            
            // 統計情報をログ
            let ratio = compression.compression_ratio.load(Ordering::Relaxed);
            let saved_mb = compression.saved_memory.load(Ordering::Relaxed) / (1024 * 1024);
            
            debug!("時空間圧縮統計: 圧縮率={:.2}, 節約メモリ={}MB, ページ数={}",
                  ratio, saved_mb, compression.compressed_pages.load(Ordering::Relaxed));
        }
    }
}

/// 時空間圧縮が有効かどうかをチェック
pub fn is_enabled() -> bool {
    unsafe {
        SPACETIME_COMPRESSION.is_some() && 
        SPACETIME_COMPRESSION.as_ref().unwrap().enabled.load(Ordering::Relaxed)
    }
}

/// 時空間圧縮の有効/無効切り替え
pub fn set_enabled(enabled: bool) {
    unsafe {
        if let Some(compression) = SPACETIME_COMPRESSION.as_mut() {
            compression.enabled.store(enabled, Ordering::Relaxed);
            info!("時空間メモリ圧縮を{}", if enabled { "有効化" } else { "無効化" });
        }
    }
}

/// 時空間圧縮の状態を取得
pub fn get_state() -> Option<SpacetimeCompressionState> {
    unsafe {
        SPACETIME_COMPRESSION.as_ref().map(|compression| {
            SpacetimeCompressionState {
                temporal_entries: compression.temporal_dictionary.previous_states.len(),
                spatial_patterns: compression.spatial_patterns.patterns.len(),
                compression_ratio: compression.compression_ratio.load(Ordering::Relaxed),
                compressed_pages: compression.compressed_pages.load(Ordering::Relaxed),
                saved_memory: compression.saved_memory.load(Ordering::Relaxed),
                enabled: compression.enabled.load(Ordering::Relaxed),
            }
        })
    }
}

/// 時空間圧縮の状態情報
#[derive(Debug, Clone)]
pub struct SpacetimeCompressionState {
    /// 時間的辞書エントリ数
    pub temporal_entries: usize,
    /// 空間的パターン数
    pub spatial_patterns: usize,
    /// 圧縮率
    pub compression_ratio: f64,
    /// 圧縮ページ数
    pub compressed_pages: usize,
    /// 節約されたメモリ量
    pub saved_memory: usize,
    /// 有効状態
    pub enabled: bool,
}

/// 時空間圧縮の詳細情報を表示
pub fn print_info() {
    if let Some(state) = get_state() {
        let saved_mb = state.saved_memory / (1024 * 1024);
        
        info!("時空間メモリ圧縮状態:");
        info!("  状態: {}", if state.enabled { "有効" } else { "無効" });
        info!("  圧縮率: {:.2} (元サイズの{:.1}%)", 
             state.compression_ratio, state.compression_ratio * 100.0);
        info!("  節約メモリ: {}MB", saved_mb);
        info!("  圧縮ページ数: {}", state.compressed_pages);
        info!("  時間的辞書エントリ: {}", state.temporal_entries);
        info!("  空間的パターン: {}", state.spatial_patterns);
    } else {
        info!("時空間メモリ圧縮: 未初期化");
    }
} 