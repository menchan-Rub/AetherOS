// exFAT 最適化クラスタアロケータ
//
// 高性能なクラスタ割り当てと断片化防止機能

use alloc::vec::Vec;
use spin::{RwLock, Mutex};
use core::sync::atomic::{AtomicU32, Ordering};
use super::super::{FsError, FsResult};

/// アロケーション戦略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationStrategy {
    /// 最初に見つかった空きクラスタを使用
    FirstFit,
    /// 最適なサイズの空きクラスタを探す
    BestFit,
    /// 最大の空きクラスタを使用
    WorstFit,
    /// 以前に割り当てられたクラスタの近くを使用
    NextFit,
    /// 連続したクラスタを優先的に割り当て
    Contiguous,
    /// ファイルタイプに基づいた最適な割り当て
    Intelligent,
}

/// 空きクラスタの範囲
#[derive(Debug, Clone, Copy)]
struct FreeClusterRange {
    /// 開始クラスタ番号
    start: u32,
    /// クラスタ数
    count: u32,
}

/// クラスタ使用状況の履歴
struct ClusterUsageHistory {
    /// 最近割り当てられたクラスタ
    recent_allocations: Vec<u32>,
    /// 最近解放されたクラスタ
    recent_deallocations: Vec<u32>,
    /// ホットスポットとなっているクラスタ領域
    hotspot_regions: Vec<(u32, u32)>,
    /// 最大履歴サイズ
    max_history_size: usize,
}

impl ClusterUsageHistory {
    fn new(max_history_size: usize) -> Self {
        Self {
            recent_allocations: Vec::with_capacity(max_history_size),
            recent_deallocations: Vec::with_capacity(max_history_size),
            hotspot_regions: Vec::new(),
            max_history_size,
        }
    }
    
    fn record_allocation(&mut self, cluster: u32) {
        if self.recent_allocations.len() >= self.max_history_size {
            self.recent_allocations.remove(0);
        }
        self.recent_allocations.push(cluster);
        self.update_hotspots();
    }
    
    fn record_deallocation(&mut self, cluster: u32) {
        if self.recent_deallocations.len() >= self.max_history_size {
            self.recent_deallocations.remove(0);
        }
        self.recent_deallocations.push(cluster);
    }
    
    fn update_hotspots(&mut self) {
        // TODO: クラスタアクセスパターンを分析してホットスポットを特定する処理を実装する
        // ここではダミー実装
        // TODO: ホットスポット検出アルゴリズムを実装する。
        //       考慮事項:
        //       1. recent_allocations の内容を分析し、頻繁にアクセスされるクラスタ範囲を特定。
        //       2. hotspot_regions を更新。古いホットスポットは削除または統合する。
        //       3. 閾値やウィンドウサイズなどのパラメータを導入して調整可能にする。
        //       4. パフォーマンスへの影響を最小限に抑える（例: 一定間隔でのみ実行）。

        if self.recent_allocations.len() < self.max_history_size / 2 {
            // 十分な履歴がない場合は何もしない
            return;
        }

        // 簡単な例: 直近の割り当てが特定の範囲に集中しているかを確認
        // これは非常に単純なものであり、実際のユースケースではより洗練されたアルゴリズムが必要。
        let mut counts: alloc::collections::BTreeMap<u32, usize> = alloc::collections::BTreeMap::new();
        for &cluster_start in &self.recent_allocations {
            // 簡単のため、1024クラスタ単位で集計
            let region_key = cluster_start / 1024;
            *counts.entry(region_key).or_insert(0) += 1;
        }

        self.hotspot_regions.clear();
        for (region_key, count) in counts {
            // 例: 履歴の10%以上が集中していたらホットスポットとみなす (非常に単純な閾値)
            if count > self.recent_allocations.len() / 10 {
                let start_cluster = region_key * 1024;
                let end_cluster = start_cluster + 1023; // 1024クラスタの範囲
                self.hotspot_regions.push((start_cluster, end_cluster));
                log::trace!("ExFAT Allocator: New hotspot detected: clusters {} - {}", start_cluster, end_cluster);
            }
        }

        // 古いホットスポットの削除ロジックなども必要
        // self.hotspot_regions.retain(|(start, end)| ...); 
    }
}

/// exFAT クラスタアロケータ
pub struct ExfatAllocator {
    /// ボリューム全体のビットマップ（実際はもっと効率的なデータ構造を使用）
    bitmap: RwLock<Vec<bool>>,
    /// 空きクラスタの範囲リスト
    free_ranges: RwLock<Vec<FreeClusterRange>>,
    /// クラスタ使用履歴
    history: Mutex<ClusterUsageHistory>,
    /// 次に検索を開始するクラスタ（NextFit用）
    next_cluster: AtomicU32,
    /// 総クラスタ数
    total_clusters: u32,
    /// 現在の割り当て戦略
    current_strategy: RwLock<AllocationStrategy>,
    /// デフラグが必要かどうか
    needs_defrag: AtomicU32, // 0 = 不要, 1-100 = 必要性の度合い（%）
}

impl ExfatAllocator {
    /// 新しいアロケータを作成
    pub fn new() -> Self {
        Self {
            bitmap: RwLock::new(Vec::new()),
            free_ranges: RwLock::new(Vec::new()),
            history: Mutex::new(ClusterUsageHistory::new(100)),
            next_cluster: AtomicU32::new(2), // クラスタは2から始まる
            total_clusters: 0,
            current_strategy: RwLock::new(AllocationStrategy::Contiguous),
            needs_defrag: AtomicU32::new(0),
        }
    }
    
    /// ビットマップを初期化
    pub fn initialize(&self, bitmap_data: &[u8], total_clusters: u32) -> FsResult<()> {
        let mut bitmap = self.bitmap.write();
        *bitmap = Vec::with_capacity(total_clusters as usize);
        
        // ビットマップデータからbool配列に変換
        for byte in bitmap_data {
            for bit in 0..8 {
                if bitmap.len() >= total_clusters as usize {
                    break;
                }
                let is_used = (byte & (1 << bit)) != 0;
                bitmap.push(is_used);
            }
        }
        
        // 必要に応じて残りを追加
        while bitmap.len() < total_clusters as usize {
            bitmap.push(false);
        }
        
        self.total_clusters = total_clusters;
        self.update_free_ranges()?;
        
        Ok(())
    }
    
    /// 空きクラスタの範囲リストを更新
    fn update_free_ranges(&self) -> FsResult<()> {
        let bitmap = self.bitmap.read();
        let mut free_ranges = self.free_ranges.write();
        free_ranges.clear();
        
        let mut start = 0;
        let mut in_free_range = false;
        
        for (i, &is_used) in bitmap.iter().enumerate() {
            if !is_used && !in_free_range {
                // 新しい空き範囲の開始
                start = i as u32;
                in_free_range = true;
            } else if is_used && in_free_range {
                // 空き範囲の終了
                let count = i as u32 - start;
                free_ranges.push(FreeClusterRange { start, count });
                in_free_range = false;
            }
        }
        
        // 最後の範囲が空きだった場合
        if in_free_range {
            let count = bitmap.len() as u32 - start;
            free_ranges.push(FreeClusterRange { start, count });
        }
        
        // 断片化率を計算
        let fragmentation = self.calculate_fragmentation(&free_ranges);
        self.needs_defrag.store(fragmentation, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// 断片化率を計算（0-100）
    fn calculate_fragmentation(&self, free_ranges: &[FreeClusterRange]) -> u32 {
        if free_ranges.is_empty() {
            return 0;
        }
        
        // 空き領域の総数
        let total_free = free_ranges.iter().map(|r| r.count).sum::<u32>();
        if total_free == 0 {
            return 0;
        }
        
        // 最大の連続した空き領域
        let max_contiguous = free_ranges.iter().map(|r| r.count).max().unwrap_or(0);
        
        // 空き領域の数（多いほど断片化している）
        let num_free_ranges = free_ranges.len() as u32;
        
        // 断片化率 = (1 - 最大連続空き / 総空き) * 補正係数
        let frag_ratio = 1.0 - (max_contiguous as f64 / total_free as f64);
        
        // 空き領域数による補正
        let correction = (num_free_ranges as f64).sqrt() / 10.0;
        
        // 最終的な断片化率（0-100）
        let fragmentation = (frag_ratio * 100.0 * (1.0 + correction)).min(100.0);
        
        fragmentation as u32
    }
    
    /// クラスタを割り当て
    pub fn allocate(&self, count: u32) -> FsResult<u32> {
        if count == 0 {
            return Err(FsError::InvalidData);
        }
        
        // 現在の割り当て戦略を取得
        let strategy = *self.current_strategy.read();
        
        // 割り当て戦略に基づいてクラスタを割り当て
        let start_cluster = match strategy {
            AllocationStrategy::FirstFit => self.allocate_first_fit(count)?,
            AllocationStrategy::BestFit => self.allocate_best_fit(count)?,
            AllocationStrategy::WorstFit => self.allocate_worst_fit(count)?,
            AllocationStrategy::NextFit => self.allocate_next_fit(count)?,
            AllocationStrategy::Contiguous => self.allocate_contiguous(count)?,
            AllocationStrategy::Intelligent => self.allocate_intelligent(count)?,
        };
        
        // ビットマップを更新
        {
            let mut bitmap = self.bitmap.write();
            for i in 0..count {
                if (start_cluster + i) as usize >= bitmap.len() {
                    return Err(FsError::OutOfSpace);
                }
                bitmap[(start_cluster + i) as usize] = true;
            }
        }
        
        // 空き範囲リストを更新
        self.update_free_ranges()?;
        
        // 履歴を更新
        {
            let mut history = self.history.lock();
            history.record_allocation(start_cluster);
        }
        
        Ok(start_cluster)
    }
    
    /// クラスタを解放
    pub fn deallocate(&self, start: u32, count: u32) -> FsResult<()> {
        if count == 0 {
            return Ok(());
        }
        
        // ビットマップを更新
        {
            let mut bitmap = self.bitmap.write();
            for i in 0..count {
                if (start + i) as usize >= bitmap.len() {
                    return Err(FsError::InvalidData);
                }
                bitmap[(start + i) as usize] = false;
            }
        }
        
        // 空き範囲リストを更新
        self.update_free_ranges()?;
        
        // 履歴を更新
        {
            let mut history = self.history.lock();
            history.record_deallocation(start);
        }
        
        Ok(())
    }
    
    /// FirstFit戦略でクラスタを割り当て
    fn allocate_first_fit(&self, count: u32) -> FsResult<u32> {
        let free_ranges = self.free_ranges.read();
        
        for range in free_ranges.iter() {
            if range.count >= count {
                return Ok(range.start);
            }
        }
        
        Err(FsError::OutOfSpace)
    }
    
    /// BestFit戦略でクラスタを割り当て
    fn allocate_best_fit(&self, count: u32) -> FsResult<u32> {
        let free_ranges = self.free_ranges.read();
        
        let mut best_range: Option<&FreeClusterRange> = None;
        let mut best_waste = u32::MAX;
        
        for range in free_ranges.iter() {
            if range.count >= count {
                let waste = range.count - count;
                if waste < best_waste {
                    best_waste = waste;
                    best_range = Some(range);
                }
            }
        }
        
        if let Some(range) = best_range {
            Ok(range.start)
        } else {
            Err(FsError::OutOfSpace)
        }
    }
    
    /// WorstFit戦略でクラスタを割り当て
    fn allocate_worst_fit(&self, count: u32) -> FsResult<u32> {
        let free_ranges = self.free_ranges.read();
        
        let mut best_range: Option<&FreeClusterRange> = None;
        let mut most_remaining = 0;
        
        for range in free_ranges.iter() {
            if range.count >= count {
                let remaining = range.count - count;
                if remaining > most_remaining {
                    most_remaining = remaining;
                    best_range = Some(range);
                }
            }
        }
        
        if let Some(range) = best_range {
            Ok(range.start)
        } else {
            Err(FsError::OutOfSpace)
        }
    }
    
    /// NextFit戦略でクラスタを割り当て
    fn allocate_next_fit(&self, count: u32) -> FsResult<u32> {
        let free_ranges = self.free_ranges.read();
        
        // 前回割り当てた位置から検索
        let next = self.next_cluster.load(Ordering::Relaxed);
        
        // next以降で最初に見つかった空き範囲
        for range in free_ranges.iter() {
            if range.start >= next && range.count >= count {
                self.next_cluster.store(range.start + count, Ordering::Relaxed);
                return Ok(range.start);
            }
        }
        
        // 見つからなければ先頭から検索
        for range in free_ranges.iter() {
            if range.count >= count {
                self.next_cluster.store(range.start + count, Ordering::Relaxed);
                return Ok(range.start);
            }
        }
        
        Err(FsError::OutOfSpace)
    }
    
    /// Contiguous戦略でクラスタを割り当て（常に連続した領域を確保）
    fn allocate_contiguous(&self, count: u32) -> FsResult<u32> {
        let bitmap = self.bitmap.read();
        
        // 連続した空きクラスタを検索
        let mut current_free = 0;
        let mut start_candidate = 0;
        
        for (i, &is_used) in bitmap.iter().enumerate() {
            if !is_used {
                if current_free == 0 {
                    start_candidate = i as u32;
                }
                current_free += 1;
                
                if current_free >= count {
                    return Ok(start_candidate);
                }
            } else {
                current_free = 0;
            }
        }
        
        Err(FsError::OutOfSpace)
    }
    
    /// Intelligent戦略でクラスタを割り当て
    fn allocate_intelligent(&self, count: u32) -> FsResult<u32> {
        // ファイルタイプやアクセスパターンに基づいて最適な割り当て場所を決定
        // TODO: より高度なインテリジェント割り当て戦略を実装する。
        //       考慮事項:
        //       1. ファイルタイプ (例: メディアファイルは連続領域、メタデータは高速アクセス領域など) を判別する手段。
        //          (このアロケータレベルではファイルタイプを直接知るのは難しいため、ヒントを受け取るインターフェースが必要か？)
        //       2. `self.history` (特に `hotspot_regions`) を活用し、コールドな領域や特定の用途に適した領域を選択する。
        //       3. 書き込み頻度や読み取り頻度などの統計情報を考慮する。
        //       4. 将来の拡張性やデフラグのしやすさを考慮する。

        let history = self.history.lock();

        // 例: ホットスポットを避けて割り当てる (非常に単純な試み)
        if !history.hotspot_regions.is_empty() {
            // 最も大きなコールド領域を探す (FirstFitやBestFitの変形)
            let mut best_cold_start = None;
            let mut max_cold_size = 0;

            // free_ranges をイテレートし、ホットスポットと重ならない最大の空き領域を探す
            let free_ranges_guard = self.free_ranges.read();
            for range in free_ranges_guard.iter() {
                if range.count >= count {
                    let is_hot = history.hotspot_regions.iter().any(|(hot_start, hot_end)| {
                        // 範囲が重なるかチェック
                        range.start < *hot_end && range.start + range.count > *hot_start
                    });
                    if !is_hot && range.count > max_cold_size {
                        max_cold_size = range.count;
                        best_cold_start = Some(range.start);
                    }
                }
            }
            drop(free_ranges_guard);

            if let Some(start_cluster) = best_cold_start {
                log::debug!("Intelligent allocation: Found a cold region at cluster {} for {} clusters.", start_cluster, count);
                // ここで実際に割り当ててしまうとロックの順番が問題になるため、
                // allocate_first_fit_from_specific_start のようなヘルパーを呼び出すか、
                // 選択した開始クラスタを返すだけにして、呼び出し元で実際の割り当てを行う。
                // 今回は単純化のため、見つかったクラスターでContiguousを試みる。
                return self.allocate_contiguous_from_hint(count, start_cluster);
            }
        }
        
        log::debug!("Intelligent allocation: No specific cold region found, falling back to Contiguous.");
        // 履歴に基づいて最適な割り当て場所を決定
        // TODO: より高度なクラスタ割り当てアルゴリズムを実装する
        // フォールバックとして連続割り当てを試みる
        self.allocate_contiguous(count)
    }
    
    /// 割り当て戦略を変更
    pub fn set_strategy(&self, strategy: AllocationStrategy) {
        let mut current = self.current_strategy.write();
        *current = strategy;
    }
    
    /// クラスタが使用中かどうかを確認
    pub fn is_cluster_used(&self, cluster: u32) -> FsResult<bool> {
        let bitmap = self.bitmap.read();
        
        if cluster as usize >= bitmap.len() {
            return Err(FsError::InvalidData);
        }
        
        Ok(bitmap[cluster as usize])
    }
    
    /// 空きクラスタ数を取得
    pub fn free_cluster_count(&self) -> u32 {
        let bitmap = self.bitmap.read();
        
        bitmap.iter().filter(|&&is_used| !is_used).count() as u32
    }
    
    /// 最大の連続した空きクラスタ数を取得
    pub fn max_contiguous_free(&self) -> u32 {
        let free_ranges = self.free_ranges.read();
        
        free_ranges.iter()
            .map(|range| range.count)
            .max()
            .unwrap_or(0)
    }
    
    /// 断片化率を取得
    pub fn fragmentation_percent(&self) -> u32 {
        self.needs_defrag.load(Ordering::Relaxed)
    }
    
    /// デフラグが必要かどうかを確認
    pub fn needs_defragmentation(&self) -> bool {
        self.fragmentation_percent() > 30 // 30%以上で必要
    }
    
    /// ビットマップをエクスポート
    pub fn export_bitmap(&self) -> Vec<u8> {
        let bitmap = self.bitmap.read();
        let mut result = Vec::with_capacity((bitmap.len() + 7) / 8);
        
        for chunk in bitmap.chunks(8) {
            let mut byte = 0u8;
            for (i, &is_used) in chunk.iter().enumerate() {
                if is_used {
                    byte |= 1 << i;
                }
            }
            result.push(byte);
        }
        
        result
    }
} 