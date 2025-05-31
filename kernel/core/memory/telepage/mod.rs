// AetherOS TelePage モジュール
//
// このモジュールは高帯域メモリ(HBM)と標準DRAM間のインテリジェントなページ移動を実装します。
// メモリアクセスパターンを監視し、最も効率的なメモリ階層に自動的にデータを移動します。

use crate::core::memory::{hbm, MemoryTier, MemoryStats};
use crate::core::memory::locality::{self, AccessPattern, DataBlock};
use crate::core::memory::mm::{self, PageFlags, PhysicalAddress};
use crate::time;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// モジュールをエクスポート
pub mod config;
pub mod policy;
pub mod stats;

/// TelePageエンジン
pub struct TelePage {
    /// 有効化フラグ
    enabled: AtomicBool,
    /// アクセス追跡エンジン
    tracker: AccessTracker,
    /// 現在のポリシー
    policy: policy::PageMigrationPolicy,
    /// 統計情報
    stats: stats::TelePageStats,
    /// 設定情報
    config: config::TelePageConfig,
}

/// グローバルインスタンス
static mut TELEPAGE: Option<TelePage> = None;

/// モジュールの初期化
pub fn init() -> Result<(), &'static str> {
    let config = config::TelePageConfig::default();
    
    // HBMサポートを確認
    if !hbm::is_available() && config.require_hbm {
        log::warn!("HBMが利用できないためTelePageは無効になります");
        return Ok(());
    }
    
    log::info!("TelePageモジュールを初期化しています");
    
    // インスタンスを作成
    let telepage = TelePage {
        enabled: AtomicBool::new(config.enabled_by_default),
        tracker: AccessTracker::new(config.page_track_capacity),
        policy: policy::PageMigrationPolicy::new(),
        stats: stats::TelePageStats::new(),
        config,
    };
    
    // グローバルインスタンスを設定
    unsafe {
        TELEPAGE = Some(telepage);
    }
    
    // 定期的なスキャンタスクを登録
    if config.enabled_by_default {
        register_periodic_scan()?;
    }
    
    log::info!("TelePageモジュールの初期化が完了しました");
    Ok(())
}

/// TelePageを有効化
pub fn enable() -> Result<(), &'static str> {
    unsafe {
        if let Some(telepage) = TELEPAGE.as_mut() {
            if telepage.enabled.load(Ordering::Relaxed) {
                return Ok(());
            }
            
            telepage.enabled.store(true, Ordering::SeqCst);
            register_periodic_scan()?;
            log::info!("TelePageを有効化しました");
            Ok(())
        } else {
            Err("TelePageモジュールが初期化されていません")
        }
    }
}

/// TelePageを無効化
pub fn disable() -> Result<(), &'static str> {
    unsafe {
        if let Some(telepage) = TELEPAGE.as_mut() {
            telepage.enabled.store(false, Ordering::SeqCst);
            unregister_periodic_scan();
            log::info!("TelePageを無効化しました");
            Ok(())
        } else {
            Err("TelePageモジュールが初期化されていません")
        }
    }
}

/// 定期スキャンタスクを登録
fn register_periodic_scan() -> Result<(), &'static str> {
    crate::scheduling::register_periodic_task(
        scan_and_migrate_pages,
        "telepage_scan",
        unsafe { TELEPAGE.as_ref().unwrap().config.scan_interval_ms }
    )
}

/// 定期スキャンタスクの登録を解除
fn unregister_periodic_scan() {
    let _ = crate::scheduling::unregister_task_by_name("telepage_scan");
}

/// アクセス追跡エンジン
struct AccessTracker {
    /// 追跡中のページ
    tracked_pages: Vec<TrackedPage>,
    /// 最大容量
    capacity: usize,
}

impl AccessTracker {
    /// 新しいアクセス追跡エンジンを作成
    fn new(capacity: usize) -> Self {
        Self {
            tracked_pages: Vec::with_capacity(capacity),
            capacity,
        }
    }
    
    /// ページの追跡を開始
    fn track_page(&mut self, virt_addr: usize, phys_addr: PhysicalAddress, tier: MemoryTier) -> usize {
        // すでに追跡されているか確認
        for (idx, page) in self.tracked_pages.iter().enumerate() {
            if page.virtual_address == virt_addr {
                return idx;
            }
        }
        
        // 容量をチェック
        if self.tracked_pages.len() >= self.capacity {
            // 最も古いページを削除
            self.remove_least_accessed();
        }
        
        // 新しいページを追加
        let page_id = self.tracked_pages.len();
        
        // ページサイズを取得
        let page_size = mm::get_page_size();
        
        self.tracked_pages.push(TrackedPage {
            virtual_address: virt_addr,
            physical_address: phys_addr,
            current_tier: tier,
            last_access_time: time::current_time_ms(),
            access_count: AtomicUsize::new(0),
            hot_count: AtomicUsize::new(0),
            cold_count: AtomicUsize::new(0),
            block_id: locality::register_data_block(virt_addr, page_size, None),
            size: page_size,
        });
        
        page_id
    }
    
    /// 最もアクセスが少ないページを削除
    fn remove_least_accessed(&mut self) {
        if self.tracked_pages.is_empty() {
            return;
        }
        
        let current_time = time::current_time_ms();
        let mut least_score = f64::MAX;
        let mut least_idx = 0;
        
        // アクセス頻度とタイムスタンプの組み合わせでスコア計算
        for (idx, page) in self.tracked_pages.iter().enumerate() {
            let access_count = page.access_count.load(Ordering::Relaxed) as f64;
            let age_ms = current_time - page.last_access_time;
            
            // スコア = アクセス数 / 経過時間（ms） - 小さいほど削除候補
            let score = if age_ms > 0 {
                access_count / (age_ms as f64)
            } else {
                access_count
            };
            
            if score < least_score {
                least_score = score;
                least_idx = idx;
            }
        }
        
        // 最も低スコアのページを削除
        self.tracked_pages.remove(least_idx);
    }
    
    /// メモリアクセスを記録
    fn record_access(&mut self, virt_addr: usize) {
        // アドレスをページアラインする
        let page_size = mm::get_page_size();
        let page_addr = virt_addr & !(page_size - 1);
        
        // ページを探す
        for page in &self.tracked_pages {
            if page.virtual_address == page_addr {
                page.access_count.fetch_add(1, Ordering::Relaxed);
                
                // アクセスパターンを記録
                locality::record_memory_access(page.block_id, virt_addr - page_addr);
                
                // タイムスタンプを更新
                page.last_access_time = time::current_time_ms();
                return;
            }
        }
        
        // ページが見つからない場合 (まだ追跡されていないページへのアクセス)
        // 実際には、このようなアクセスはページフォールト等を経て、必要に応じて
        // tracker.track_page() が明示的に呼び出されることで追跡が開始されるべき。
        // record_access はあくまで「既に追跡中のページ」のアクセス情報を記録する。
        log::trace!("Access recorded for untracked page (virt_addr: {:#x}). Tracking will start upon explicit request (e.g., via page fault handler).");
    }
    
    /// ページアクセスを分析して移行候補を特定
    fn analyze_pages(&self) -> Vec<MigrationCandidate> {
        let mut candidates = Vec::new();
        let current_time = time::current_time_ms();
        
        for (idx, page) in self.tracked_pages.iter().enumerate() {
            // 最終アクセスからの経過時間をチェック
            let age_ms = current_time - page.last_access_time;
            
            // アクセスカウントを取得
            let access_count = page.access_count.load(Ordering::Relaxed);
            
            // アクセスパターンを取得
            let pattern = locality::get_block_pattern(page.block_id)
                .unwrap_or(AccessPattern::Random);
            
            // 最適なメモリ階層を判断
            let optimal_tier = determine_optimal_tier(access_count, age_ms, pattern);
            
            // 現在と異なる階層が最適な場合、移行候補に追加
            if optimal_tier != page.current_tier {
                candidates.push(MigrationCandidate {
                    page_idx: idx,
                    virtual_address: page.virtual_address,
                    physical_address: page.physical_address,
                    current_tier: page.current_tier,
                    target_tier: optimal_tier,
                    access_count,
                    age_ms,
                    pattern,
                    score: calculate_migration_score(access_count, age_ms, pattern, 
                                                     page.current_tier, optimal_tier),
                });
            }
        }
        
        // スコアでソート
        candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        
        candidates
    }
}

/// 追跡中のページ情報
struct TrackedPage {
    /// 仮想アドレス
    virtual_address: usize,
    /// 物理アドレス
    physical_address: PhysicalAddress,
    /// 現在のメモリ階層
    current_tier: MemoryTier,
    /// 最終アクセス時刻
    last_access_time: u64,
    /// アクセスカウント
    access_count: AtomicUsize,
    /// ホット判定回数
    hot_count: AtomicUsize,
    /// コールド判定回数
    cold_count: AtomicUsize,
    /// データブロックID
    block_id: usize,
    /// サイズ（通常はページサイズ）
    size: usize,
}

/// ページ移行候補
struct MigrationCandidate {
    /// ページインデックス
    page_idx: usize,
    /// 仮想アドレス
    virtual_address: usize,
    /// 物理アドレス
    physical_address: PhysicalAddress,
    /// 現在のメモリ階層
    current_tier: MemoryTier,
    /// ターゲットのメモリ階層
    target_tier: MemoryTier,
    /// アクセスカウント
    access_count: usize,
    /// 最終アクセスからの経過時間
    age_ms: u64,
    /// アクセスパターン
    pattern: AccessPattern,
    /// 移行スコア（高いほど優先）
    score: f64,
}

/// メモリ階層を判定
fn get_memory_tier(phys_addr: PhysicalAddress) -> MemoryTier {
    if hbm::is_hbm_address(phys_addr) {
        MemoryTier::HighBandwidthMemory
    } else {
        MemoryTier::StandardDRAM
    }
}

/// 最適なメモリ階層を判断
fn determine_optimal_tier(access_count: usize, age_ms: u64, pattern: AccessPattern) -> MemoryTier {
    // ポリシーベースの判断
    unsafe {
        if let Some(telepage) = TELEPAGE.as_ref() {
            return telepage.policy.determine_optimal_tier(access_count, age_ms, pattern);
        }
    }
    
    // デフォルト判断
    if age_ms < 1000 && access_count > 10 {
        // 直近でアクセスが多いページはHBMに
        match pattern {
            AccessPattern::Sequential | AccessPattern::Strided(_) => {
                // シーケンシャル/ストライドアクセスはHBMで高速化
                MemoryTier::HighBandwidthMemory
            }
            AccessPattern::Random => {
                // ランダムアクセスは帯域幅の恩恵を受けやすい
                if access_count > 100 {
                    MemoryTier::HighBandwidthMemory
        } else {
                    MemoryTier::StandardDRAM
                }
            }
            _ => MemoryTier::StandardDRAM,
        }
    } else {
        // アクセスが古いか少ないページはDRAM
        MemoryTier::StandardDRAM
    }
}

/// 移行スコアを計算
fn calculate_migration_score(access_count: usize, age_ms: u64, pattern: AccessPattern,
                            current_tier: MemoryTier, target_tier: MemoryTier) -> f64 {
    // ベーススコア: アクセス頻度
    let base_score = if age_ms > 0 {
        (access_count as f64) / ((age_ms as f64).max(1.0) / 1000.0)
        } else {
        access_count as f64
    };
    
    // パターン係数
    let pattern_factor = match pattern {
        AccessPattern::Sequential => 1.5, // シーケンシャルはHBMで大幅に高速化
        AccessPattern::Strided(_) => 1.3, // ストライドも高速化
        AccessPattern::Random => 1.2,     // ランダムも高速化
        _ => 1.0,
    };
    
    // 階層遷移係数
    let tier_factor = match (current_tier, target_tier) {
        (MemoryTier::StandardDRAM, MemoryTier::HighBandwidthMemory) => {
            // DRAMからHBMへのホット遷移
            1.0
        },
        (MemoryTier::HighBandwidthMemory, MemoryTier::StandardDRAM) => {
            // HBMからDRAMへのコールド遷移
            if age_ms > 5000 { // 5秒以上アクセスがない
                0.8
            } else {
                0.4 // HBMからの降格は慎重に
            }
        },
        _ => 0.0, // 同一階層への移動は意味がない
    };
    
    // 最終スコア計算
    base_score * pattern_factor * tier_factor
}

/// ページスキャンと移行
fn scan_and_migrate_pages() {
    unsafe {
        if let Some(telepage) = TELEPAGE.as_mut() {
            // 無効なら何もしない
            if !telepage.enabled.load(Ordering::Relaxed) {
            return;
        }
        
            // アクセスパターンを分析して移行候補を特定
            let candidates = telepage.tracker.analyze_pages();
            
            if candidates.is_empty() {
                return;
            }
            
            log::debug!("TelePage: {}個の移行候補を検出", candidates.len());
            
            // 一度の実行で移行するページ数を制限
            let max_migrations = telepage.config.max_migrations_per_scan;
            let migration_count = core::cmp::min(candidates.len(), max_migrations);
            
            // 最も優先度の高い候補から移行
            for i in 0..migration_count {
                let candidate = &candidates[i];
                
                match migrate_page(candidate, &telepage.config) {
                    Ok(()) => {
                        log::debug!("ページ移行成功: 0x{:x} ({:?} → {:?}), スコア={:.2}",
                                  candidate.virtual_address,
                                  candidate.current_tier,
                                  candidate.target_tier,
                                  candidate.score);
                        
                        // 統計情報を更新
                        telepage.stats.record_migration_success(
                            candidate.current_tier,
                            candidate.target_tier
                        );
                        
                        // 移行後にページの階層情報を更新
                        if let Some(page) = telepage.tracker.tracked_pages.get_mut(candidate.page_idx) {
                            page.current_tier = candidate.target_tier;
                            
                            // ホット/コールドカウントを更新
                            if candidate.target_tier == MemoryTier::HighBandwidthMemory {
                                page.hot_count.fetch_add(1, Ordering::Relaxed);
        } else {
                                page.cold_count.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    },
                    Err(e) => {
                        log::warn!("ページ移行失敗: 0x{:x} ({:?} → {:?}): {}",
                                 candidate.virtual_address,
                                 candidate.current_tier,
                                 candidate.target_tier,
                                 e);
                        
                        // 統計情報を更新
                        telepage.stats.record_migration_failure(
                            candidate.current_tier,
                            candidate.target_tier
                        );
                    }
                }
            }
        }
    }
}

/// ページを新しいメモリ階層に移行
fn migrate_page(candidate: &MigrationCandidate, config: &config::TelePageConfig) -> Result<(), &'static str> {
    let source_tier = candidate.current_tier;
    let target_tier = candidate.target_tier;
    
    log::debug!("ページ移行開始: アドレス=0x{:x}, {:?} -> {:?}", 
               candidate.virtual_address, source_tier, target_tier);
    
    // 1. ターゲット階層でページを割り当て
    let target_phys = allocate_page_in_tier(target_tier)?;
    
    // 2. データをコピー
    unsafe {
        let source_ptr = candidate.virtual_address as *const u8;
        let target_ptr = target_phys.as_u64() as *mut u8;
        core::ptr::copy_nonoverlapping(source_ptr, target_ptr, 4096);
    }
    
    // 3. ページテーブルを更新してVMAをアンマップしてから新しい物理アドレスにマップ
    // アトミックな操作でページフォルトを防ぐ
    let mut page_table = arch::get_current_page_table();
    page_table.unmap_page(candidate.virtual_address);
    page_table.map_page(candidate.virtual_address, target_phys, PageFlags::READABLE | PageFlags::WRITABLE);
    
    // 4. TLBフラッシュ
    arch::flush_tlb_page(candidate.virtual_address);
    
    // 5. 元のページを解放
    memory::deallocate_page_in_tier(candidate.physical_address, source_tier);
    
    log::debug!("ページ移行完了: アドレス=0x{:x}", candidate.virtual_address);
    Ok(())
}

/// 指定のメモリ階層にページを割り当て
fn allocate_page_in_tier(tier: MemoryTier) -> Result<PhysicalAddress, &'static str> {
    match tier {
        MemoryTier::HighBandwidthMemory => {
            // HBMから割り当て
            let page_size = mm::get_page_size();
            let hbm_ptr = hbm::allocate(page_size, hbm::HbmMemoryType::General, 0)
                .ok_or("HBMメモリの割り当てに失敗しました")?;
            Ok(hbm_ptr.as_ptr() as usize)
        },
        MemoryTier::StandardDRAM => {
            // 標準DRAMから割り当て
            mm::allocate_physical_page()
        },
        _ => {
            // その他のティアはサポート外
            Err("サポートされていないメモリ階層です")
        }
    }
}

/// 統計情報を取得
pub fn get_stats() -> stats::TelePageStats {
    unsafe {
        if let Some(telepage) = TELEPAGE.as_ref() {
            telepage.stats.clone()
        } else {
            stats::TelePageStats::new()
        }
    }
}

/// 現在の設定情報を取得
pub fn get_config() -> config::TelePageConfig {
    unsafe {
        if let Some(telepage) = TELEPAGE.as_ref() {
            telepage.config.clone()
        } else {
            config::TelePageConfig::default()
        }
    }
}
