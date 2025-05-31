// AetherOS テレページングメモリオブザーバー
//
// このモジュールはメモリアクセスやページフォルトをモニタリングし、
// 統計情報を収集、分析するための機能を提供します。

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;
use log::{debug, info, trace, warn};
use spin::RwLock;

use super::predictor::AccessPattern;

/// メモリアクセスタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessType {
    /// 読み込み
    Read,
    /// 書き込み
    Write,
    /// 実行
    Execute,
    /// ページフォルト
    Fault,
}

/// メモリアクセスイベント
#[derive(Debug, Clone)]
pub struct AccessEvent {
    /// ページアドレス
    page_addr: usize,
    /// アクセスタイプ
    access_type: AccessType,
    /// タイムスタンプ（ナノ秒）
    timestamp: u64,
    /// プロセスID（存在する場合）
    process_id: Option<u64>,
    /// スレッドID（存在する場合）
    thread_id: Option<u64>,
}

/// ページアクセス統計
#[derive(Debug, Clone)]
pub struct PageAccessStats {
    /// ページアドレス
    page_addr: usize,
    /// 読み込み回数
    read_count: u64,
    /// 書き込み回数
    write_count: u64,
    /// 実行回数
    exec_count: u64,
    /// フォルト回数
    fault_count: u64,
    /// 最終アクセス時刻
    last_access: u64,
    /// 最初のアクセス時刻
    first_access: u64,
    /// アクセス間隔の平均（ナノ秒）
    avg_interval: u64,
    /// 識別されたアクセスパターン
    pattern: Option<AccessPattern>,
}

impl PageAccessStats {
    /// 新しいページアクセス統計を作成
    fn new(page_addr: usize, timestamp: u64) -> Self {
        Self {
            page_addr,
            read_count: 0,
            write_count: 0,
            exec_count: 0,
            fault_count: 0,
            last_access: timestamp,
            first_access: timestamp,
            avg_interval: 0,
            pattern: None,
        }
    }

    /// アクセスを記録
    fn record_access(&mut self, access_type: AccessType, timestamp: u64) {
        match access_type {
            AccessType::Read => self.read_count += 1,
            AccessType::Write => self.write_count += 1,
            AccessType::Execute => self.exec_count += 1,
            AccessType::Fault => self.fault_count += 1,
        }

        // 平均間隔を更新
        if self.last_access > 0 && timestamp > self.last_access {
            let interval = timestamp - self.last_access;
            let total_accesses = self.read_count + self.write_count + self.exec_count + self.fault_count;
            
            if total_accesses > 1 {
                // 加重平均を計算
                self.avg_interval = ((self.avg_interval * (total_accesses - 1)) + interval) / total_accesses;
            } else {
                self.avg_interval = interval;
            }
        }

        self.last_access = timestamp;
    }

    /// 合計アクセス回数を取得
    pub fn total_accesses(&self) -> u64 {
        self.read_count + self.write_count + self.exec_count
    }

    /// ホット（頻繁にアクセスされる）ページかどうかを判断
    pub fn is_hot(&self, threshold: u64, time_window: u64, current_time: u64) -> bool {
        // 一定期間内のアクセス回数が閾値を超えているか
        let total = self.total_accesses();
        let time_diff = current_time.saturating_sub(self.first_access);
        
        if time_diff == 0 {
            return false;
        }
        
        // 単位時間あたりのアクセス頻度を計算
        let access_rate = (total as f64 * time_window as f64) / time_diff as f64;
        
        access_rate >= threshold as f64
    }
}

/// メモリオブザーバーの設定
#[derive(Debug, Clone)]
pub struct MemoryObserverConfig {
    /// イベント履歴の最大サイズ
    max_history_size: usize,
    /// 統計情報を保持する最大ページ数
    max_tracked_pages: usize,
    /// アクセス頻度の計測ウィンドウ（ナノ秒）
    access_window_ns: u64,
    /// ホットページの閾値（単位時間あたりのアクセス回数）
    hot_page_threshold: u64,
    /// 詳細なロギングを有効にするかどうか
    verbose_logging: bool,
    /// 統計情報の自動分析間隔（ナノ秒）
    analysis_interval_ns: u64,
}

impl Default for MemoryObserverConfig {
    fn default() -> Self {
        Self {
            max_history_size: 1000,
            max_tracked_pages: 10000,
            access_window_ns: 1_000_000_000, // 1秒
            hot_page_threshold: 10,          // 1秒あたり10回以上のアクセス
            verbose_logging: false,
            analysis_interval_ns: 10_000_000_000, // 10秒
        }
    }
}

/// メモリアクセスのホットスポット分析
#[derive(Debug, Clone)]
pub struct HotspotAnalysis {
    /// ホットページのリスト（アドレス、アクセス回数）
    hot_pages: Vec<(usize, u64)>,
    /// ページフォルトが多いページのリスト（アドレス、フォルト回数）
    fault_prone_pages: Vec<(usize, u64)>,
    /// アクセスパターン別ページ数
    pattern_distribution: BTreeMap<AccessPattern, usize>,
    /// 分析タイムスタンプ
    timestamp: u64,
    /// 分析対象期間（ナノ秒）
    period_ns: u64,
}

/// メモリアクセスオブザーバー
pub struct MemoryObserver {
    /// 設定
    config: RwLock<MemoryObserverConfig>,
    /// 有効状態
    enabled: AtomicBool,
    /// アクセスイベント履歴
    access_history: RwLock<VecDeque<AccessEvent>>,
    /// ページごとのアクセス統計
    page_stats: RwLock<BTreeMap<usize, PageAccessStats>>,
    /// ページアクセスのヒートマップ（相対的な頻度）
    heatmap: RwLock<BTreeMap<usize, f64>>,
    /// 最後の分析タイムスタンプ
    last_analysis: AtomicU64,
    /// 総イベント数
    total_events: AtomicU64,
    /// 分析済みイベント数
    analyzed_events: AtomicU64,
    /// 現在のメモリ使用量（バイト）
    memory_usage: AtomicUsize,
}

impl MemoryObserver {
    /// 新しいメモリオブザーバーを作成
    pub fn new() -> Self {
        Self {
            config: RwLock::new(MemoryObserverConfig::default()),
            enabled: AtomicBool::new(true),
            access_history: RwLock::new(VecDeque::with_capacity(1000)),
            page_stats: RwLock::new(BTreeMap::new()),
            heatmap: RwLock::new(BTreeMap::new()),
            last_analysis: AtomicU64::new(0),
            total_events: AtomicU64::new(0),
            analyzed_events: AtomicU64::new(0),
            memory_usage: AtomicUsize::new(0),
        }
    }

    /// オブザーバーを初期化
    pub fn init(&mut self) {
        let config = self.config.read();
        
        // 履歴キューの初期化
        {
            let mut history = self.access_history.write();
            history.clear();
            history.reserve(config.max_history_size);
        }
        
        // 統計情報の初期化
        {
            let mut stats = self.page_stats.write();
            stats.clear();
        }
        
        // ヒートマップの初期化
        {
            let mut heatmap = self.heatmap.write();
            heatmap.clear();
        }
        
        // カウンタのリセット
        self.total_events.store(0, Ordering::Relaxed);
        self.analyzed_events.store(0, Ordering::Relaxed);
        self.last_analysis.store(0, Ordering::Relaxed);
        self.enabled.store(true, Ordering::Relaxed);
        
        info!("メモリオブザーバー初期化完了");
    }

    /// メモリアクセスを記録
    pub fn record_access(&self, page_addr: usize, access_type: AccessType, timestamp: u64, process_id: Option<u64>, thread_id: Option<u64>) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        // イベントを作成
        let event = AccessEvent {
            page_addr,
            access_type,
            timestamp,
            process_id,
            thread_id,
        };
        
        // 履歴に追加
        {
            let mut history = self.access_history.write();
            let config = self.config.read();
            
            // 最大サイズを超えたら古いイベントを削除
            if history.len() >= config.max_history_size {
                history.pop_front();
            }
            
            history.push_back(event.clone());
        }
        
        // 統計情報を更新
        {
            let mut stats = self.page_stats.write();
            let config = self.config.read();
            
            // 追跡ページ数が上限に達したら何もしない
            if stats.len() >= config.max_tracked_pages && !stats.contains_key(&page_addr) {
                return;
            }
            
            let page_stat = stats.entry(page_addr).or_insert_with(|| PageAccessStats::new(page_addr, timestamp));
            page_stat.record_access(access_type, timestamp);
        }
        
        // イベント総数を更新
        self.total_events.fetch_add(1, Ordering::Relaxed);
        
        // 詳細ログが有効なら出力
        if self.config.read().verbose_logging {
            trace!("メモリアクセス記録: アドレス={:#x}, タイプ={:?}, プロセスID={:?}", 
                   page_addr, access_type, process_id);
        }
        
        // 定期的に分析を実行
        self.check_and_run_analysis(timestamp);
    }

    /// ページフォルトを記録
    pub fn record_fault(&self, page_addr: usize, timestamp: u64, process_id: Option<u64>, thread_id: Option<u64>) {
        self.record_access(page_addr, AccessType::Fault, timestamp, process_id, thread_id);
        
        // フォールト専用の処理があれば追加
        debug!("ページフォルト記録: アドレス={:#x}, プロセスID={:?}", page_addr, process_id);
    }

    /// 定期分析を実行するかチェック
    fn check_and_run_analysis(&self, current_time: u64) {
        let config = self.config.read();
        let last = self.last_analysis.load(Ordering::Relaxed);
        
        // 前回の分析から十分な時間が経過したか確認
        if current_time >= last + config.analysis_interval_ns {
            // 自動分析を実行
            let _ = self.analyze_memory_access(current_time);
            
            // 最終分析時刻を更新
            self.last_analysis.store(current_time, Ordering::Relaxed);
        }
    }

    /// メモリアクセスパターンを分析
    pub fn analyze_memory_access(&self, current_time: u64) -> HotspotAnalysis {
        let config = self.config.read();
        let stats = self.page_stats.read();
        
        // 分析結果の初期化
        let mut hot_pages = Vec::new();
        let mut fault_prone_pages = Vec::new();
        let mut pattern_distribution = BTreeMap::new();
        
        // 前回の分析からの期間
        let last_analysis = self.last_analysis.load(Ordering::Relaxed);
        let period = if last_analysis > 0 {
            current_time - last_analysis
        } else {
            config.analysis_interval_ns
        };
        
        // すべてのページの統計を分析
        for (addr, stat) in stats.iter() {
            // ホットページの検出
            if stat.is_hot(config.hot_page_threshold, config.access_window_ns, current_time) {
                hot_pages.push((*addr, stat.total_accesses()));
            }
            
            // フォルトが多いページの検出
            if stat.fault_count > 0 {
                fault_prone_pages.push((*addr, stat.fault_count));
            }
            
            // アクセスパターンの集計
            if let Some(pattern) = stat.pattern {
                *pattern_distribution.entry(pattern).or_insert(0) += 1;
            }
        }
        
        // ホットページを降順にソート
        hot_pages.sort_by(|a, b| b.1.cmp(&a.1));
        
        // フォルトが多いページを降順にソート
        fault_prone_pages.sort_by(|a, b| b.1.cmp(&a.1));
        
        // 上位のみ保持
        if hot_pages.len() > 100 {
            hot_pages.truncate(100);
        }
        
        if fault_prone_pages.len() > 100 {
            fault_prone_pages.truncate(100);
        }
        
        // ヒートマップを更新
        self.update_heatmap(&hot_pages);
        
        // 分析済みイベント数を更新
        let total = self.total_events.load(Ordering::Relaxed);
        self.analyzed_events.store(total, Ordering::Relaxed);
        
        // 分析結果を作成
        let analysis = HotspotAnalysis {
            hot_pages,
            fault_prone_pages,
            pattern_distribution,
            timestamp: current_time,
            period_ns: period,
        };
        
        // 分析結果をログに出力
        info!("メモリアクセス分析完了: ホットページ数={}, フォルト多発ページ数={}", 
              analysis.hot_pages.len(), analysis.fault_prone_pages.len());
        
        analysis
    }

    /// ヒートマップの更新
    fn update_heatmap(&self, hot_pages: &[(usize, u64)]) {
        // 総アクセス数を計算
        let total_accesses: u64 = hot_pages.iter().map(|(_, count)| count).sum();
        
        if total_accesses == 0 {
            return;
        }
        
        // ヒートマップを更新
        let mut heatmap = self.heatmap.write();
        heatmap.clear();
        
        for (addr, count) in hot_pages {
            // 相対的な熱度（0.0～1.0）
            let heat = *count as f64 / total_accesses as f64;
            heatmap.insert(*addr, heat);
        }
    }

    /// ホットページのリストを取得
    pub fn get_hot_pages(&self, limit: usize) -> Vec<(usize, u64)> {
        let stats = self.page_stats.read();
        let config = self.config.read();
        let current_time = Self::get_current_time();
        
        let mut hot_pages = Vec::new();
        
        for (addr, stat) in stats.iter() {
            if stat.is_hot(config.hot_page_threshold, config.access_window_ns, current_time) {
                hot_pages.push((*addr, stat.total_accesses()));
            }
        }
        
        // ホットページを降順にソート
        hot_pages.sort_by(|a, b| b.1.cmp(&a.1));
        
        // 指定された数に制限
        if hot_pages.len() > limit {
            hot_pages.truncate(limit);
        }
        
        hot_pages
    }

    /// フォールトが多いページのリストを取得
    pub fn get_fault_prone_pages(&self, limit: usize) -> Vec<(usize, u64)> {
        let stats = self.page_stats.read();
        
        let mut fault_pages = Vec::new();
        
        for (addr, stat) in stats.iter() {
            if stat.fault_count > 0 {
                fault_pages.push((*addr, stat.fault_count));
            }
        }
        
        // フォルト数で降順にソート
        fault_pages.sort_by(|a, b| b.1.cmp(&a.1));
        
        // 指定された数に制限
        if fault_pages.len() > limit {
            fault_pages.truncate(limit);
        }
        
        fault_pages
    }

    /// 特定ページの統計情報を取得
    pub fn get_page_stats(&self, page_addr: usize) -> Option<PageAccessStats> {
        let stats = self.page_stats.read();
        stats.get(&page_addr).cloned()
    }

    /// 最近のアクセスイベントを取得
    pub fn get_recent_events(&self, limit: usize) -> Vec<AccessEvent> {
        let history = self.access_history.read();
        let start_idx = if history.len() > limit {
            history.len() - limit
        } else {
            0
        };
        
        history.iter().skip(start_idx).cloned().collect()
    }

    /// 現在時刻を取得（ナノ秒）
    fn get_current_time() -> u64 {
        arch::current_time_ns()
    }

    /// ページ統計のクリーンアップ（古いエントリの削除）
    pub fn cleanup_stats(&self, max_age_ns: u64) {
        let current_time = Self::get_current_time();
        let mut stats = self.page_stats.write();
        
        // 古いエントリを削除
        stats.retain(|_, stat| {
            current_time - stat.last_access < max_age_ns
        });
        
        debug!("ページ統計クリーンアップ完了: 残りエントリ数={}", stats.len());
    }

    /// オブザーバーの有効/無効を設定
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// 設定を更新
    pub fn update_config(&self, config: MemoryObserverConfig) {
        let mut cfg = self.config.write();
        *cfg = config;
    }

    /// 統計情報のレポートを生成
    pub fn generate_report(&self) -> String {
        let stats = self.page_stats.read();
        let total_events = self.total_events.load(Ordering::Relaxed);
        let analyzed_events = self.analyzed_events.load(Ordering::Relaxed);
        
        let mut report = alloc::format!(
            "メモリオブザーバーレポート:\n\
             総イベント数: {}\n\
             分析済みイベント数: {}\n\
             追跡ページ数: {}\n\n",
            total_events, analyzed_events, stats.len()
        );
        
        // ホットページのレポート
        let hot_pages = self.get_hot_pages(10);
        report.push_str("ホットページ (上位10件):\n");
        for (i, (addr, count)) in hot_pages.iter().enumerate() {
            report.push_str(&alloc::format!("  {}. アドレス={:#x}, アクセス数={}\n", i + 1, addr, count));
        }
        
        // フォルト多発ページのレポート
        let fault_pages = self.get_fault_prone_pages(10);
        report.push_str("\nフォルト多発ページ (上位10件):\n");
        for (i, (addr, count)) in fault_pages.iter().enumerate() {
            report.push_str(&alloc::format!("  {}. アドレス={:#x}, フォルト数={}\n", i + 1, addr, count));
        }
        
        report
    }
} 