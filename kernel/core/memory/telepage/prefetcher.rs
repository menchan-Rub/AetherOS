// AetherOS テレページングプリフェッチャー
//
// このモジュールは予測されたページアクセスパターンに基づいて
// 事前にページをメモリに読み込む機能を提供します。

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use log::{debug, trace, warn};
use spin::RwLock;

use super::predictor::AccessPattern;

/// プリフェッチポリシー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefetchPolicy {
    /// 無効
    Disabled,
    /// 保守的（最小限のプリフェッチ）
    Conservative,
    /// 標準
    Standard,
    /// 積極的（最大限のプリフェッチ）
    Aggressive,
    /// 適応型（負荷に応じて動的に調整）
    Adaptive,
}

impl Default for PrefetchPolicy {
    fn default() -> Self {
        Self::Standard
    }
}

/// プリフェッチ優先度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrefetchPriority {
    /// 低（バックグラウンド処理で時間がある時）
    Low,
    /// 中（通常の処理と同程度）
    Medium,
    /// 高（優先的に処理）
    High,
    /// 緊急（即時処理）
    Critical,
}

/// プリフェッチリクエスト
#[derive(Debug, Clone)]
pub struct PrefetchRequest {
    /// 対象ページアドレス
    page_addr: usize,
    /// リクエスト発行時刻
    timestamp: u64,
    /// 優先度
    priority: PrefetchPriority,
    /// アクセスパターン
    pattern: AccessPattern,
    /// 予測信頼度（0-100）
    confidence: u8,
    /// ソースページ（このページから予測された）
    source_page: Option<usize>,
}

/// プリフェッチ結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefetchResult {
    /// 成功
    Success,
    /// 既にメモリ内
    AlreadyInMemory,
    /// ページフォルト（失敗）
    Fault,
    /// リソース不足（メモリ不足など）
    ResourceExhausted,
    /// キャンセル（他の処理に割り込まれた）
    Cancelled,
    /// タイムアウト
    Timeout,
}

/// プリフェッチ統計情報
#[derive(Debug, Clone)]
pub struct PrefetchStats {
    /// 総リクエスト数
    total_requests: usize,
    /// 処理完了数
    completed: usize,
    /// 成功数
    successes: usize,
    /// ヒット数（プリフェッチされたページが実際にアクセスされた）
    hits: usize,
    /// ページフォルトの回避数
    faults_avoided: usize,
    /// メモリ使用量（バイト）
    memory_used: usize,
    /// 平均レイテンシ（ナノ秒）
    avg_latency: u64,
}

/// プリフェッチャーコンフィグ
#[derive(Debug, Clone)]
pub struct PrefetcherConfig {
    /// プリフェッチポリシー
    policy: PrefetchPolicy,
    /// 最大同時プリフェッチ数
    max_concurrent: usize,
    /// プリフェッチウィンドウサイズ（先読みするページ数）
    window_size: usize,
    /// 最小信頼度しきい値（0-100）
    min_confidence: u8,
    /// プリフェッチタイムアウト（ナノ秒）
    timeout_ns: u64,
    /// プリフェッチに割り当てる最大メモリ（バイト）
    max_memory: usize,
    /// バックグラウンドモード有効化
    background_mode: bool,
    /// 省電力モード有効化（バッテリー駆動時用）
    power_saving: bool,
}

impl Default for PrefetcherConfig {
    fn default() -> Self {
        Self {
            policy: PrefetchPolicy::Standard,
            max_concurrent: 4,
            window_size: 16,
            min_confidence: 70,
            timeout_ns: 1_000_000, // 1ms
            max_memory: 4 * 1024 * 1024, // 4MB
            background_mode: true,
            power_saving: false,
        }
    }
}

/// テレページプリフェッチャー
pub struct PagePrefetcher {
    /// 有効状態
    enabled: AtomicBool,
    /// 設定
    config: RwLock<PrefetcherConfig>,
    /// 統計情報
    stats: RwLock<PrefetchStats>,
    /// リクエストキュー
    request_queue: RwLock<VecDeque<PrefetchRequest>>,
    /// 処理中リクエスト
    in_progress: RwLock<BTreeMap<usize, PrefetchRequest>>,
    /// プリフェッチ済みページセット
    prefetched_pages: RwLock<BTreeMap<usize, u64>>, // page_addr -> timestamp
    /// 使用中メモリサイズ（バイト）
    memory_used: AtomicUsize,
    /// 現在の同時処理数
    concurrent_count: AtomicU32,
    /// カスタムページフォールトハンドラ
    fault_handler: Option<Arc<dyn Fn(usize) -> bool + Send + Sync>>,
}

impl PagePrefetcher {
    /// 新しいプリフェッチャーを作成
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(true),
            config: RwLock::new(PrefetcherConfig::default()),
            stats: RwLock::new(PrefetchStats {
                total_requests: 0,
                completed: 0,
                successes: 0,
                hits: 0,
                faults_avoided: 0,
                memory_used: 0,
                avg_latency: 0,
            }),
            request_queue: RwLock::new(VecDeque::with_capacity(32)),
            in_progress: RwLock::new(BTreeMap::new()),
            prefetched_pages: RwLock::new(BTreeMap::new()),
            memory_used: AtomicUsize::new(0),
            concurrent_count: AtomicU32::new(0),
            fault_handler: None,
        }
    }

    /// プリフェッチャーを初期化
    pub fn init(&mut self) {
        let mut stats = self.stats.write();
        stats.total_requests = 0;
        stats.completed = 0;
        stats.successes = 0;
        stats.hits = 0;
        stats.faults_avoided = 0;
        stats.memory_used = 0;
        stats.avg_latency = 0;

        self.request_queue.write().clear();
        self.in_progress.write().clear();
        self.prefetched_pages.write().clear();
        self.memory_used.store(0, Ordering::Relaxed);
        self.concurrent_count.store(0, Ordering::Relaxed);
        
        self.enabled.store(true, Ordering::Relaxed);
    }

    /// プリフェッチリクエストを追加
    pub fn request_prefetch(&self, page_addr: usize, priority: PrefetchPriority, pattern: AccessPattern, confidence: u8, source_page: Option<usize>, timestamp: u64) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        let config = self.config.read();
        
        // ポリシーがDisabledなら何もしない
        if config.policy == PrefetchPolicy::Disabled {
            return;
        }
        
        // 信頼度が低すぎる場合はスキップ
        if confidence < config.min_confidence {
            trace!("プリフェッチスキップ: 信頼度不足 アドレス={:#x}, 信頼度={}", page_addr, confidence);
            return;
        }
        
        // 既にプリフェッチされているか確認
        {
            let prefetched = self.prefetched_pages.read();
            if prefetched.contains_key(&page_addr) {
                trace!("プリフェッチスキップ: 既にプリフェッチ済み アドレス={:#x}", page_addr);
                return;
            }
        }
        
        // 既にキューに入っているか確認
        {
            let queue = self.request_queue.read();
            for req in queue.iter() {
                if req.page_addr == page_addr {
                    trace!("プリフェッチスキップ: 既にキュー内 アドレス={:#x}", page_addr);
                    return;
                }
            }
        }
        
        // 処理中のリクエストにないか確認
        {
            let in_progress = self.in_progress.read();
            if in_progress.contains_key(&page_addr) {
                trace!("プリフェッチスキップ: 処理中 アドレス={:#x}", page_addr);
                return;
            }
        }
        
        // 新しいリクエストを作成
        let request = PrefetchRequest {
            page_addr,
            timestamp,
            priority,
            pattern,
            confidence,
            source_page,
        };
        
        // 統計情報を更新
        {
            let mut stats = self.stats.write();
            stats.total_requests += 1;
        }
        
        // キューに追加
        {
            let mut queue = self.request_queue.write();
            queue.push_back(request);
            
            // 優先度順にソート
            self.sort_queue();
        }
        
        trace!("プリフェッチリクエスト追加: アドレス={:#x}, 優先度={:?}, 信頼度={}", page_addr, priority, confidence);
    }

    /// プリフェッチリクエストキューを処理
    pub fn process_queue(&self) -> usize {
        if !self.enabled.load(Ordering::Relaxed) {
            return 0;
        }
        
        let config = self.config.read();
        let max_concurrent = config.max_concurrent;
        let current_concurrent = self.concurrent_count.load(Ordering::Relaxed) as usize;
        
        // 同時処理数の上限に達していたら何もしない
        if current_concurrent >= max_concurrent {
            return 0;
        }
        
        let available_slots = max_concurrent - current_concurrent;
        let mut processed = 0;
        
        // キューから取り出して処理
        while processed < available_slots {
            let request = {
                let mut queue = self.request_queue.write();
                if queue.is_empty() {
                    break;
                }
                queue.pop_front()
            };
            
            if let Some(req) = request {
                // 処理中リストに追加
                {
                    let mut in_progress = self.in_progress.write();
                    in_progress.insert(req.page_addr, req.clone());
                }
                
                // 同時処理数をインクリメント
                self.concurrent_count.fetch_add(1, Ordering::Relaxed);
                
                // プリフェッチを実行
                self.prefetch_page(req);
                
                processed += 1;
            } else {
                break;
            }
        }
        
        processed
    }

    /// 単一ページのプリフェッチを実行
    fn prefetch_page(&self, request: PrefetchRequest) -> PrefetchResult {
        if !self.enabled.load(Ordering::Relaxed) {
            self.finish_request(request.page_addr, PrefetchResult::Cancelled);
            return PrefetchResult::Cancelled;
        }
        
        let page_size = 4096; // 4KB
        let config = self.config.read();
        
        // メモリ制限をチェック
        let current_memory = self.memory_used.load(Ordering::Relaxed);
        if current_memory + page_size > config.max_memory {
            // メモリ不足、低優先度のリクエストならキャンセル
            if request.priority == PrefetchPriority::Low {
                debug!("プリフェッチキャンセル: メモリ制限 アドレス={:#x}", request.page_addr);
                self.finish_request(request.page_addr, PrefetchResult::ResourceExhausted);
                return PrefetchResult::ResourceExhausted;
            }
            
            // 高優先度なら古いページを解放して続行
            self.evict_old_pages(page_size);
        }
        
        // ページをメモリに読み込む（実際のOSではここでページフォールトハンドラを呼ぶ）
        let result = if let Some(handler) = &self.fault_handler {
            if handler(request.page_addr) {
                PrefetchResult::Success
            } else {
                PrefetchResult::Fault
            }
        } else {
            // ハンドラが設定されていない場合は成功と仮定
            PrefetchResult::Success
        };
        
        // 結果に応じた処理
        match result {
            PrefetchResult::Success => {
                // メモリ使用量を更新
                self.memory_used.fetch_add(page_size, Ordering::Relaxed);
                
                // プリフェッチ済みマップに追加
                {
                    let mut prefetched = self.prefetched_pages.write();
                    prefetched.insert(request.page_addr, request.timestamp);
                }
                
                // 統計情報を更新
                {
                    let mut stats = self.stats.write();
                    stats.successes += 1;
                    stats.memory_used = self.memory_used.load(Ordering::Relaxed);
                }
                
                debug!("プリフェッチ成功: アドレス={:#x}, パターン={:?}", request.page_addr, request.pattern);
            },
            PrefetchResult::Fault => {
                warn!("プリフェッチ失敗: ページフォルト アドレス={:#x}", request.page_addr);
            },
            _ => {
                // その他の結果
                trace!("プリフェッチ中断: アドレス={:#x}, 結果={:?}", request.page_addr, result);
            }
        }
        
        // リクエスト完了処理
        self.finish_request(request.page_addr, result);
        
        result
    }

    /// リクエスト完了時の処理
    fn finish_request(&self, page_addr: usize, result: PrefetchResult) {
        // 処理中リストから削除
        {
            let mut in_progress = self.in_progress.write();
            in_progress.remove(&page_addr);
        }
        
        // 統計情報を更新
        {
            let mut stats = self.stats.write();
            stats.completed += 1;
        }
        
        // 同時処理数をデクリメント
        self.concurrent_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// 古いページを解放
    fn evict_old_pages(&self, required_space: usize) {
        let mut space_freed = 0;
        let page_size = 4096; // 4KB
        
        // プリフェッチページのタイムスタンプでソートしたリスト
        let mut pages_by_age = {
            let prefetched = self.prefetched_pages.read();
            let mut pages: Vec<(usize, u64)> = prefetched.iter().map(|(&k, &v)| (k, v)).collect();
            pages.sort_by_key(|&(_, timestamp)| timestamp);
            pages
        };
        
        // 必要な分だけ古いページから解放
        let mut evicted = Vec::new();
        
        for (page_addr, _) in pages_by_age {
            if space_freed >= required_space {
                break;
            }
            
            evicted.push(page_addr);
            space_freed += page_size;
            
            trace!("プリフェッチページ解放: アドレス={:#x}", page_addr);
        }
        
        // 解放したページをマップから削除
        if !evicted.is_empty() {
            let mut prefetched = self.prefetched_pages.write();
            for page_addr in evicted {
                prefetched.remove(&page_addr);
            }
            
            // メモリ使用量を更新
            self.memory_used.fetch_sub(space_freed, Ordering::Relaxed);
            
            // 統計情報を更新
            {
                let mut stats = self.stats.write();
                stats.memory_used = self.memory_used.load(Ordering::Relaxed);
            }
        }
    }

    /// ページアクセスヒットを記録
    pub fn record_hit(&self, page_addr: usize) {
        let was_prefetched = {
            let mut prefetched = self.prefetched_pages.write();
            prefetched.remove(&page_addr).is_some()
        };
        
        if was_prefetched {
            // プリフェッチヒット統計を更新
            let mut stats = self.stats.write();
            stats.hits += 1;
            stats.faults_avoided += 1;
            
            // メモリ使用量を更新
            let page_size = 4096;
            self.memory_used.fetch_sub(page_size, Ordering::Relaxed);
            stats.memory_used = self.memory_used.load(Ordering::Relaxed);
            
            trace!("プリフェッチヒット: アドレス={:#x}", page_addr);
        }
    }

    /// リクエストキューを優先度順にソート
    fn sort_queue(&self) {
        let mut queue = self.request_queue.write();
        
        // 優先度が高いものを前に持ってくる
        queue.make_contiguous().sort_by(|a, b| {
            match a.priority.cmp(&b.priority) {
                core::cmp::Ordering::Equal => {
                    // 優先度が同じなら信頼度で比較
                    b.confidence.cmp(&a.confidence)
                },
                other => other.reverse() // 高優先度が前に来るように逆順
            }
        });
    }

    /// プリフェッチャーの有効/無効を設定
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
        
        if !enabled {
            // 無効化時は全リクエストをキャンセル
            self.cancel_all_requests();
        }
    }

    /// 全リクエストをキャンセル
    fn cancel_all_requests(&self) {
        // キューをクリア
        {
            let mut queue = self.request_queue.write();
            queue.clear();
        }
        
        // 処理中リクエストをキャンセル
        let in_progress_pages = {
            let in_progress = self.in_progress.read();
            in_progress.keys().cloned().collect::<Vec<_>>()
        };
        
        for page_addr in in_progress_pages {
            self.finish_request(page_addr, PrefetchResult::Cancelled);
        }
    }

    /// カスタムページフォールトハンドラを設定
    pub fn set_fault_handler<F>(&mut self, handler: F)
    where
        F: Fn(usize) -> bool + Send + Sync + 'static
    {
        self.fault_handler = Some(Arc::new(handler));
    }

    /// プリフェッチャー設定を更新
    pub fn update_config(&self, config: PrefetcherConfig) {
        let mut cfg = self.config.write();
        *cfg = config;
    }

    /// プリフェッチ統計情報を取得
    pub fn get_stats(&self) -> PrefetchStats {
        self.stats.read().clone()
    }

    /// キューの長さを取得
    pub fn queue_length(&self) -> usize {
        self.request_queue.read().len()
    }

    /// 処理中リクエスト数を取得
    pub fn in_progress_count(&self) -> usize {
        self.in_progress.read().len()
    }

    /// プリフェッチ済みページ数を取得
    pub fn prefetched_count(&self) -> usize {
        self.prefetched_pages.read().len()
    }

    /// プリフェッチメモリ使用量を取得
    pub fn memory_usage(&self) -> usize {
        self.memory_used.load(Ordering::Relaxed)
    }
} 