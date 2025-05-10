// AetherOS テレページング予測器
//
// このモジュールはメモリアクセスパターンを分析し、
// 将来のページアクセスを予測する機能を提供します。

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use log::{debug, trace};

/// ページアクセスパターン
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPattern {
    /// 不明（分析中）
    Unknown,
    /// ホット（頻繁にアクセス）
    Hot,
    /// コールド（まれにアクセス）
    Cold,
    /// シーケンシャル（連続アクセス）
    Sequential,
    /// ランダム（ランダムアクセス）
    Random,
    /// 繰り返し（周期的アクセス）
    Repetitive,
    /// 局所的（特定範囲内でのアクセス）
    Localized,
}

impl Default for AccessPattern {
    fn default() -> Self {
        Self::Unknown
    }
}

/// ページアクセス履歴エントリ
#[derive(Debug, Clone, Copy)]
struct AccessHistoryEntry {
    /// アクセスされたページアドレス
    page_addr: usize,
    /// アクセス時のタイムスタンプ
    timestamp: u64,
    /// アクセスタイプ（読み取り、書き込み、実行など）
    access_type: u8,
}

/// ページ間の関連性エントリ
#[derive(Debug, Clone)]
struct PageCorrelation {
    /// 先行ページ
    source_page: usize,
    /// 後続ページ
    target_page: usize,
    /// 発生回数
    occurrence_count: usize,
    /// 最後の発生時刻
    last_occurrence: u64,
    /// 時間差の平均（ナノ秒）
    avg_time_delta: u64,
    /// 確率（0-100）
    probability: u8,
}

/// アクセスパターン予測器
pub struct AccessPredictor {
    /// ページアクセス履歴
    history: VecDeque<AccessHistoryEntry>,
    /// ページ間の関連性マップ
    correlations: BTreeMap<usize, Vec<PageCorrelation>>,
    /// ホットページのマップ（アドレス -> アクセス頻度）
    hot_pages: BTreeMap<usize, usize>,
    /// ページフォルト履歴
    fault_history: VecDeque<(usize, u64)>,
    /// 予測モデルの最終更新時刻
    last_model_update: u64,
    /// 学習モードが有効か
    learning_enabled: AtomicBool,
    /// パターン検出感度（0-100）
    pattern_sensitivity: AtomicU8,
    /// 記録する履歴の最大長
    max_history_length: usize,
    /// 前回アクセスされたページ
    last_accessed_page: Option<usize>,
}

impl AccessPredictor {
    /// 新しいアクセスパターン予測器を作成
    pub fn new() -> Self {
        Self {
            history: VecDeque::with_capacity(1024),
            correlations: BTreeMap::new(),
            hot_pages: BTreeMap::new(),
            fault_history: VecDeque::with_capacity(128),
            last_model_update: 0,
            learning_enabled: AtomicBool::new(true),
            pattern_sensitivity: AtomicU8::new(80),
            max_history_length: 1024,
            last_accessed_page: None,
        }
    }

    /// 予測器を初期化
    pub fn init(&mut self) {
        self.history.clear();
        self.correlations.clear();
        self.hot_pages.clear();
        self.fault_history.clear();
        self.last_model_update = 0;
        self.last_accessed_page = None;
    }

    /// ページアクセスを記録
    pub fn record_access(&mut self, page_addr: usize, timestamp: u64, access_type: u8) {
        // 履歴に追加
        let entry = AccessHistoryEntry {
            page_addr,
            timestamp,
            access_type,
        };
        
        self.history.push_back(entry);
        
        // 履歴が最大長を超えた場合、古いエントリを削除
        if self.history.len() > self.max_history_length {
            self.history.pop_front();
        }
        
        // ホットページカウンタを更新
        *self.hot_pages.entry(page_addr).or_insert(0) += 1;
        
        // 前回アクセスとの関連性を記録
        if let Some(last_page) = self.last_accessed_page {
            if last_page != page_addr && self.learning_enabled.load(Ordering::Relaxed) {
                self.update_correlation(last_page, page_addr, timestamp);
            }
        }
        
        self.last_accessed_page = Some(page_addr);
        
        // 定期的にモデルを更新（100アクセスごと）
        if self.history.len() % 100 == 0 {
            self.update_model(timestamp);
        }
        
        trace!("ページアクセス記録: アドレス={:#x}, タイムスタンプ={}", page_addr, timestamp);
    }

    /// ページフォルトを記録
    pub fn record_fault(&mut self, page_addr: usize, timestamp: u64) {
        self.fault_history.push_back((page_addr, timestamp));
        
        // 履歴が長すぎる場合は古いエントリを削除
        if self.fault_history.len() > 128 {
            self.fault_history.pop_front();
        }
        
        debug!("ページフォルト記録: アドレス={:#x}, タイムスタンプ={}", page_addr, timestamp);
    }

    /// ページアクセスパターンを分析
    pub fn analyze_pattern(&mut self, page_addr: usize, access_count: usize, timestamp: u64) -> AccessPattern {
        // アクセス頻度に基づく基本分類
        let is_hot = self.is_hot_page(page_addr, access_count);
        
        // 十分なデータがない場合
        if self.history.len() < 10 {
            return if is_hot { AccessPattern::Hot } else { AccessPattern::Cold };
        }
        
        // このページに関連する履歴エントリを抽出
        let page_history: Vec<AccessHistoryEntry> = self.history.iter()
            .filter(|entry| entry.page_addr == page_addr)
            .cloned()
            .collect();
        
        if page_history.is_empty() {
            return AccessPattern::Unknown;
        }
        
        // 1. シーケンシャルかランダムかを判定
        let is_sequential = self.detect_sequential_pattern(&page_history);
        
        // 2. 局所性を判定
        let is_localized = self.detect_locality(page_addr);
        
        // 3. 繰り返しパターンを判定
        let is_repetitive = self.detect_repetitive_pattern(&page_history);
        
        // パターンの決定
        if is_sequential {
            AccessPattern::Sequential
        } else if is_repetitive {
            AccessPattern::Repetitive
        } else if is_localized {
            AccessPattern::Localized
        } else if is_hot {
            AccessPattern::Hot
        } else {
            AccessPattern::Cold
        }
    }

    /// 将来アクセスされる可能性の高いページを予測
    pub fn predict_future_accesses(&self, current_page: usize, threshold: u8) -> Vec<usize> {
        let mut predicted = Vec::new();
        
        // 現在のページに関連する相関を取得
        if let Some(correlations) = self.correlations.get(&current_page) {
            // 確率の高い順にソート
            let mut sorted_correlations = correlations.clone();
            sorted_correlations.sort_by(|a, b| b.probability.cmp(&a.probability));
            
            // しきい値以上の確率を持つページを予測リストに追加
            for corr in sorted_correlations.iter() {
                if corr.probability >= threshold {
                    predicted.push(corr.target_page);
                }
            }
        }
        
        // 近接ページも予測
        let page_base = current_page & !0xFFF; // 4KBアライメント
        for offset in 1..8 {
            let next_page = page_base + (offset * 4096);
            if !predicted.contains(&next_page) && self.is_likely_to_access(next_page) {
                predicted.push(next_page);
            }
        }
        
        trace!("ページアクセス予測: 現在ページ={:#x}, 予測数={}", current_page, predicted.len());
        predicted
    }

    /// ページ間の関連性を更新
    fn update_correlation(&mut self, source_page: usize, target_page: usize, timestamp: u64) {
        // 以前の関連エントリを探す
        let correlations = self.correlations.entry(source_page).or_insert_with(Vec::new);
        
        let mut found = false;
        for corr in correlations.iter_mut() {
            if corr.target_page == target_page {
                // 既存の関連性を更新
                corr.occurrence_count += 1;
                let time_delta = timestamp.saturating_sub(corr.last_occurrence);
                // 指数移動平均で時間差を更新
                corr.avg_time_delta = (corr.avg_time_delta * 7 + time_delta) / 8;
                corr.last_occurrence = timestamp;
                
                // 確率を更新
                self.update_probability(corr);
                
                found = true;
                break;
            }
        }
        
        if !found {
            // 新しい関連性を追加
            let correlation = PageCorrelation {
                source_page,
                target_page,
                occurrence_count: 1,
                last_occurrence: timestamp,
                avg_time_delta: 0,
                probability: 50, // デフォルト確率
            };
            correlations.push(correlation);
        }
    }

    /// 確率値を更新
    fn update_probability(&mut self, correlation: &mut PageCorrelation) {
        // ソースページの総アクセス数
        let source_access_count = self.hot_pages.get(&correlation.source_page).cloned().unwrap_or(0);
        
        if source_access_count > 0 {
            // 発生頻度に基づく確率計算
            let raw_prob = (correlation.occurrence_count * 100) / source_access_count;
            // 上限100%
            correlation.probability = raw_prob.min(100) as u8;
        }
    }

    /// 予測モデル全体を更新
    fn update_model(&mut self, timestamp: u64) {
        if !self.learning_enabled.load(Ordering::Relaxed) {
            return;
        }
        
        // 前回の更新から十分な時間が経過していない場合はスキップ
        if timestamp - self.last_model_update < 1000 {
            return;
        }
        
        // 古い相関を削除（最後のアクセスから長時間経過しているもの）
        let cutoff_time = timestamp.saturating_sub(10000);
        
        for correlations in self.correlations.values_mut() {
            correlations.retain(|corr| corr.last_occurrence >= cutoff_time);
        }
        
        // 空の相関リストを持つエントリを削除
        self.correlations.retain(|_, correlations| !correlations.is_empty());
        
        // 古いホットページを削除
        self.hot_pages.retain(|page, _| {
            self.history.iter().any(|entry| entry.page_addr == *page && entry.timestamp >= cutoff_time)
        });
        
        self.last_model_update = timestamp;
        trace!("予測モデル更新: タイムスタンプ={}", timestamp);
    }

    /// 学習モードの設定
    pub fn set_learning_enabled(&mut self, enabled: bool) {
        self.learning_enabled.store(enabled, Ordering::Relaxed);
    }

    /// パターン検出感度の設定
    pub fn set_sensitivity(&mut self, sensitivity: u8) {
        self.pattern_sensitivity.store(sensitivity.min(100), Ordering::Relaxed);
    }

    /// ページがホットかどうかを判定
    fn is_hot_page(&self, page_addr: usize, access_count: usize) -> bool {
        // 単純なしきい値ベースの判定
        let threshold = 10;
        
        if access_count > threshold {
            return true;
        }
        
        // 最近のアクセス履歴での出現頻度
        let recent_count = self.history.iter()
            .rev()
            .take(100)
            .filter(|entry| entry.page_addr == page_addr)
            .count();
            
        recent_count > 5
    }

    /// シーケンシャルパターンを検出
    fn detect_sequential_pattern(&self, history: &[AccessHistoryEntry]) -> bool {
        // 隣接ページへの連続アクセスがあるかをチェック
        if history.len() < 3 {
            return false;
        }
        
        let mut sequential_count = 0;
        
        for window in history.windows(2) {
            let current = window[0].page_addr;
            let next = window[1].page_addr;
            
            // ページが4KBアライメントの隣接ページかチェック
            let current_base = current & !0xFFF;
            let next_base = next & !0xFFF;
            
            if next_base == current_base + 4096 {
                sequential_count += 1;
            }
        }
        
        // 十分な連続アクセスがあればシーケンシャルパターンと判定
        let sensitivity = self.pattern_sensitivity.load(Ordering::Relaxed) as usize;
        let threshold = (history.len() * sensitivity) / 100;
        
        sequential_count >= threshold / 5
    }

    /// 局所性を検出
    fn detect_locality(&self, page_addr: usize) -> bool {
        // ページの近傍へのアクセスが多いかをチェック
        let page_base = page_addr & !0xFFF;
        let locality_range = 16 * 4096; // 16ページの範囲
        
        let locality_count = self.history.iter()
            .filter(|entry| {
                let entry_base = entry.page_addr & !0xFFF;
                entry_base >= page_base.saturating_sub(locality_range) &&
                entry_base <= page_base + locality_range
            })
            .count();
            
        let sensitivity = self.pattern_sensitivity.load(Ordering::Relaxed) as usize;
        let threshold = (self.history.len() * sensitivity) / 100;
        
        locality_count >= threshold / 3
    }

    /// 繰り返しパターンを検出
    fn detect_repetitive_pattern(&self, history: &[AccessHistoryEntry]) -> bool {
        if history.len() < 5 {
            return false;
        }
        
        // タイムスタンプの間隔を分析
        let mut intervals = Vec::with_capacity(history.len() - 1);
        
        for window in history.windows(2) {
            let interval = window[1].timestamp.saturating_sub(window[0].timestamp);
            intervals.push(interval);
        }
        
        // 間隔の類似性を評価
        let avg_interval = intervals.iter().sum::<u64>() / intervals.len() as u64;
        let similar_intervals = intervals.iter()
            .filter(|&&interval| {
                let diff = if interval > avg_interval {
                    interval - avg_interval
                } else {
                    avg_interval - interval
                };
                // 平均の30%以内の誤差を許容
                diff <= (avg_interval * 30) / 100
            })
            .count();
            
        let sensitivity = self.pattern_sensitivity.load(Ordering::Relaxed) as usize;
        let threshold = (intervals.len() * sensitivity) / 100;
        
        similar_intervals >= threshold / 2
    }

    /// 今後アクセスされる可能性が高いページかを判定
    fn is_likely_to_access(&self, page_addr: usize) -> bool {
        // ホットページか
        if let Some(count) = self.hot_pages.get(&page_addr) {
            if *count > 5 {
                return true;
            }
        }
        
        // 最近フォルトしたページか
        if self.fault_history.iter().any(|(addr, _)| *addr == page_addr) {
            return true;
        }
        
        // 他のページからの高い相関があるか
        for correlations in self.correlations.values() {
            for corr in correlations {
                if corr.target_page == page_addr && corr.probability >= 70 {
                    return true;
                }
            }
        }
        
        false
    }
} 