// AetherOS 自己最適化メモリ管理サブシステム
//
// メモリ使用状況をリアルタイムで監視し、アプリケーションの
// パフォーマンスに応じてメモリ割り当てを動的に最適化

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::core::sync::{Mutex, RwLock, SpinLock};
use crate::core::memory::MemoryManager;
use crate::core::process::ProcessManager;
use crate::core::process::Process;

/// メモリプロファイルの種類
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemoryProfileType {
    /// 高パフォーマンス優先
    HighPerformance,
    /// バランス型
    Balanced,
    /// 省メモリ優先
    LowMemory,
    /// 省電力優先
    PowerSaving,
    /// リアルタイム処理優先
    RealTime,
    /// カスタム
    Custom,
}

/// メモリ使用傾向
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemoryUsagePattern {
    /// 連続大ブロック
    LargeBlocks,
    /// 散在小ブロック
    SmallFragments,
    /// 一時的な割り当て
    TransientAllocation,
    /// 長期保持
    LongTerm,
    /// キャッシュ集中
    CacheHeavy,
    /// 計算集中
    ComputeHeavy,
    /// 不明
    Unknown,
}

/// メモリ最適化アクション
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemoryOptimizationAction {
    /// キャッシュサイズ増加
    IncreaseCacheSize,
    /// キャッシュサイズ減少
    DecreaseCacheSize,
    /// 事前割り当て
    Preallocation,
    /// メモリ解放
    MemoryCompaction,
    /// スラブサイズ調整
    SlabSizeAdjustment,
    /// ページサイズ変更
    PageSizeChange,
    /// スワップポリシー変更
    SwapPolicyChange,
    /// 何もしない
    NoAction,
}

/// メモリ使用統計
pub struct MemoryUsageStats {
    /// プロセスID
    pub process_id: usize,
    /// 合計使用メモリ（バイト）
    pub total_memory: usize,
    /// 仮想メモリサイズ
    pub virtual_memory: usize,
    /// 物理メモリ使用量
    pub physical_memory: usize,
    /// 共有メモリ使用量
    pub shared_memory: usize,
    /// スワップ使用量
    pub swap_usage: usize,
    /// キャッシュメモリ
    pub cache_memory: usize,
    /// ピーク使用量
    pub peak_usage: usize,
    /// 平均割り当てサイズ
    pub avg_allocation_size: usize,
    /// 割り当て頻度（1秒あたり）
    pub allocation_rate: f32,
    /// 解放頻度（1秒あたり）
    pub deallocation_rate: f32,
    /// メモリ使用傾向
    pub usage_pattern: MemoryUsagePattern,
    /// 割り当て履歴
    pub allocation_history: Vec<(u64, usize)>, // (timestamp, size)
}

/// アプリケーションメモリプロファイル
pub struct AppMemoryProfile {
    /// プロファイルID
    pub id: usize,
    /// アプリケーション名
    pub app_name: String,
    /// メモリプロファイルタイプ
    pub profile_type: MemoryProfileType,
    /// 優先度（0-100）
    pub priority: u8,
    /// 最小メモリ割り当て
    pub min_memory: usize,
    /// 最大メモリ割り当て
    pub max_memory: usize,
    /// 推奨キャッシュサイズ
    pub recommended_cache: usize,
    /// 大きいページの使用
    pub use_large_pages: bool,
    /// メモリ圧縮の使用
    pub use_compression: bool,
    /// スワップ使用優先度（0-100, 低いほど遅くスワップアウト）
    pub swap_priority: u8,
    /// 過去の使用パターン
    pub usage_patterns: Vec<MemoryUsagePattern>,
    /// 最終更新時間
    pub last_updated: u64,
}

/// メモリ最適化イベント
pub struct OptimizationEvent {
    /// イベントID
    pub id: usize,
    /// タイムスタンプ
    pub timestamp: u64,
    /// プロセスID
    pub process_id: Option<usize>,
    /// 実行されたアクション
    pub action: MemoryOptimizationAction,
    /// 理由
    pub reason: String,
    /// 前のメモリ使用量
    pub previous_usage: usize,
    /// 新しいメモリ使用量
    pub new_usage: usize,
    /// パフォーマンス変化（%、+/-）
    pub performance_change: f32,
}

/// 自己最適化メモリマネージャ
pub struct AdaptiveMemoryManager {
    /// アプリケーションメモリプロファイル
    app_profiles: RwLock<BTreeMap<usize, AppMemoryProfile>>,
    /// プロセスIDからプロファイルIDへのマッピング
    process_to_profile: RwLock<BTreeMap<usize, usize>>,
    /// プロセスごとのメモリ使用統計
    memory_stats: RwLock<BTreeMap<usize, MemoryUsageStats>>,
    /// 最適化イベント履歴
    optimization_history: Mutex<VecDeque<OptimizationEvent>>,
    /// メモリプロファイル自動検出
    auto_profile_detection: AtomicBool,
    /// 最適化間隔（ミリ秒）
    optimization_interval_ms: AtomicUsize,
    /// 次のプロファイルID
    next_profile_id: AtomicUsize,
    /// 次のイベントID
    next_event_id: AtomicUsize,
    /// システム全体のメモリプロファイル
    system_profile: RwLock<MemoryProfileType>,
    /// メモリマネージャへの参照
    memory_manager: &'static MemoryManager,
    /// プロセスマネージャへの参照
    process_manager: &'static ProcessManager,
}

impl AdaptiveMemoryManager {
    /// 新しい自己最適化メモリマネージャを作成
    pub fn new(memory_manager: &'static MemoryManager, process_manager: &'static ProcessManager) -> Self {
        Self {
            app_profiles: RwLock::new(BTreeMap::new()),
            process_to_profile: RwLock::new(BTreeMap::new()),
            memory_stats: RwLock::new(BTreeMap::new()),
            optimization_history: Mutex::new(VecDeque::with_capacity(100)),
            auto_profile_detection: AtomicBool::new(true),
            optimization_interval_ms: AtomicUsize::new(1000), // デフォルト1秒
            next_profile_id: AtomicUsize::new(1),
            next_event_id: AtomicUsize::new(1),
            system_profile: RwLock::new(MemoryProfileType::Balanced),
            memory_manager,
            process_manager,
        }
    }
    
    /// アプリケーションメモリプロファイルを登録
    pub fn register_app_profile(&self, 
                              app_name: &str,
                              profile_type: MemoryProfileType,
                              priority: u8,
                              min_memory: usize,
                              max_memory: usize) -> Result<usize, &'static str> {
        if min_memory > max_memory {
            return Err("最小メモリ値は最大メモリ値より小さくなければなりません");
        }
        
        let profile_id = self.next_profile_id.fetch_add(1, Ordering::SeqCst);
        
        // デフォルト値の決定
        let recommended_cache = match profile_type {
            MemoryProfileType::HighPerformance => max_memory / 4,
            MemoryProfileType::Balanced => max_memory / 8,
            MemoryProfileType::LowMemory => max_memory / 16,
            MemoryProfileType::PowerSaving => max_memory / 32,
            MemoryProfileType::RealTime => max_memory / 2,
            MemoryProfileType::Custom => max_memory / 8,
        };
        
        let use_large_pages = match profile_type {
            MemoryProfileType::HighPerformance | MemoryProfileType::RealTime => true,
            _ => false,
        };
        
        let use_compression = match profile_type {
            MemoryProfileType::LowMemory | MemoryProfileType::PowerSaving => true,
            _ => false,
        };
        
        let swap_priority = match profile_type {
            MemoryProfileType::HighPerformance => 10, // 遅くスワップアウト
            MemoryProfileType::RealTime => 0,        // スワップアウトしない
            MemoryProfileType::LowMemory => 90,      // 早くスワップアウト
            _ => 50,                                 // 標準
        };
        
        // プロファイル作成
        let profile = AppMemoryProfile {
            id: profile_id,
            app_name: app_name.to_string(),
            profile_type,
            priority,
            min_memory,
            max_memory,
            recommended_cache,
            use_large_pages,
            use_compression,
            swap_priority,
            usage_patterns: Vec::new(),
            last_updated: crate::time::current_time_ms(),
        };
        
        // 保存
        let mut app_profiles = self.app_profiles.write().unwrap();
        app_profiles.insert(profile_id, profile);
        
        log::info!("アプリケーションメモリプロファイルを登録: {} (ID: {})", app_name, profile_id);
        
        Ok(profile_id)
    }
    
    /// プロセスにメモリプロファイルを適用
    pub fn apply_profile_to_process(&self, process_id: usize, profile_id: usize) -> Result<(), &'static str> {
        // プロファイル存在確認
        let app_profiles = self.app_profiles.read().unwrap();
        if !app_profiles.contains_key(&profile_id) {
            return Err("指定されたプロファイルが存在しません");
        }
        
        // プロセス存在確認
        if !self.process_manager.process_exists(process_id) {
            return Err("指定されたプロセスが存在しません");
        }
        
        // マッピング更新
        let mut process_to_profile = self.process_to_profile.write().unwrap();
        process_to_profile.insert(process_id, profile_id);
        
        // プロファイルに基づいてメモリ設定を適用
        let profile = &app_profiles[&profile_id];
        
        // 適切なプロファイルの設定を適用
        // ...（実際のメモリ設定適用処理）
        
        log::info!("プロセス {} にメモリプロファイル {} を適用しました", process_id, profile_id);
        
        Ok(())
    }
    
    /// メモリ使用状況の収集
    pub fn collect_memory_stats(&self, process_id: usize) -> Result<(), &'static str> {
        // プロセス存在確認
        if !self.process_manager.process_exists(process_id) {
            return Err("指定されたプロセスが存在しません");
        }
        
        // プロセスからメモリ使用状況を取得
        // ...（実際のメモリ統計収集処理）
        
        // テスト用ダミーデータ
        let stats = MemoryUsageStats {
            process_id,
            total_memory: 10 * 1024 * 1024, // 10MB
            virtual_memory: 20 * 1024 * 1024, // 20MB
            physical_memory: 8 * 1024 * 1024, // 8MB
            shared_memory: 2 * 1024 * 1024, // 2MB
            swap_usage: 0,
            cache_memory: 1 * 1024 * 1024, // 1MB
            peak_usage: 12 * 1024 * 1024, // 12MB
            avg_allocation_size: 4096, // 4KB
            allocation_rate: 100.0, // 1秒あたり100回
            deallocation_rate: 95.0, // 1秒あたり95回
            usage_pattern: MemoryUsagePattern::Unknown, // 初期値
            allocation_history: Vec::new(),
        };
        
        // 統計情報を保存
        let mut memory_stats = self.memory_stats.write().unwrap();
        memory_stats.insert(process_id, stats);
        
        Ok(())
    }
    
    /// メモリ使用パターンを分析
    pub fn analyze_usage_pattern(&self, process_id: usize) -> Result<MemoryUsagePattern, &'static str> {
        let memory_stats = self.memory_stats.read().unwrap();
        let stats = memory_stats.get(&process_id).ok_or("プロセスのメモリ統計がありません")?;
        
        // メモリ使用パターンを分析
        let pattern = if stats.avg_allocation_size > 1024 * 1024 {
            // 平均1MB以上の大きなブロック
            MemoryUsagePattern::LargeBlocks
        } else if stats.avg_allocation_size < 4096 {
            // 平均4KB未満の小さなブロック
            MemoryUsagePattern::SmallFragments
        } else if stats.allocation_rate - stats.deallocation_rate > 10.0 {
            // 割り当て頻度が解放頻度より10以上高い
            MemoryUsagePattern::LongTerm
        } else if (stats.allocation_rate - stats.deallocation_rate).abs() < 1.0 {
            // 割り当て頻度と解放頻度がほぼ同じ
            MemoryUsagePattern::TransientAllocation
        } else if stats.cache_memory > stats.physical_memory / 2 {
            // キャッシュが物理メモリの半分以上
            MemoryUsagePattern::CacheHeavy
        } else if stats.physical_memory > stats.total_memory * 90 / 100 {
            // 物理メモリが総メモリの90%以上
            MemoryUsagePattern::ComputeHeavy
        } else {
            MemoryUsagePattern::Unknown
        };
        
        // プロファイル更新
        if let Some(profile_id) = self.get_profile_for_process(process_id) {
            let mut app_profiles = self.app_profiles.write().unwrap();
            if let Some(profile) = app_profiles.get_mut(&profile_id) {
                profile.usage_patterns.push(pattern);
                // 履歴サイズを制限
                if profile.usage_patterns.len() > 10 {
                    profile.usage_patterns.remove(0);
                }
                profile.last_updated = crate::time::current_time_ms();
            }
        }
        
        Ok(pattern)
    }
    
    /// 最適化アクションを決定
    pub fn determine_optimization(&self, process_id: usize) -> Result<MemoryOptimizationAction, &'static str> {
        // プロセスのメモリ使用パターンを取得
        let pattern = self.analyze_usage_pattern(process_id)?;
        
        // プロファイルを取得
        let profile_id = self.get_profile_for_process(process_id).ok_or("プロセスにプロファイルが割り当てられていません")?;
        
        let app_profiles = self.app_profiles.read().unwrap();
        let profile = app_profiles.get(&profile_id).ok_or("プロファイルが見つかりません")?;
        
        // システム全体のメモリ状況を確認
        let system_memory_pressure = self.get_system_memory_pressure();
        
        // メモリパターンとシステム状況に基づいて最適化アクションを決定
        let action = match pattern {
            MemoryUsagePattern::LargeBlocks => {
                if system_memory_pressure < 50 {
                    // メモリ圧力が低い場合は事前割り当て
                    MemoryOptimizationAction::Preallocation
                } else {
                    // メモリ圧力が高い場合はページサイズ変更
                    MemoryOptimizationAction::PageSizeChange
                }
            },
            MemoryUsagePattern::SmallFragments => {
                // 断片化が進んでいるのでメモリ圧縮
                MemoryOptimizationAction::MemoryCompaction
            },
            MemoryUsagePattern::TransientAllocation => {
                // 一時的な割り当てが多いのでスラブサイズ調整
                MemoryOptimizationAction::SlabSizeAdjustment
            },
            MemoryUsagePattern::LongTerm => {
                if system_memory_pressure > 70 {
                    // メモリ圧力が高い場合はスワップポリシー変更
                    MemoryOptimizationAction::SwapPolicyChange
                } else {
                    // メモリ圧力が低い場合は何もしない
                    MemoryOptimizationAction::NoAction
                }
            },
            MemoryUsagePattern::CacheHeavy => {
                if system_memory_pressure > 80 {
                    // メモリ圧力が高い場合はキャッシュサイズ減少
                    MemoryOptimizationAction::DecreaseCacheSize
                } else if system_memory_pressure < 30 {
                    // メモリ圧力が低い場合はキャッシュサイズ増加
                    MemoryOptimizationAction::IncreaseCacheSize
                } else {
                    // 中程度のメモリ圧力の場合は何もしない
                    MemoryOptimizationAction::NoAction
                }
            },
            MemoryUsagePattern::ComputeHeavy => {
                if profile.profile_type == MemoryProfileType::HighPerformance {
                    // 高パフォーマンスプロファイルの場合は事前割り当て
                    MemoryOptimizationAction::Preallocation
                } else {
                    // その他のプロファイルの場合はスワップポリシー変更
                    MemoryOptimizationAction::SwapPolicyChange
                }
            },
            MemoryUsagePattern::Unknown => {
                // パターンが不明な場合は何もしない
                MemoryOptimizationAction::NoAction
            },
        };
        
        Ok(action)
    }
    
    /// 最適化アクションを適用
    pub fn apply_optimization(&self, process_id: usize, action: MemoryOptimizationAction) -> Result<(), &'static str> {
        let memory_stats = self.memory_stats.read().unwrap();
        let previous_usage = memory_stats.get(&process_id)
            .map(|stats| stats.physical_memory)
            .unwrap_or(0);
        
        // 最適化アクションを適用
        let reason = match action {
            MemoryOptimizationAction::IncreaseCacheSize => {
                // キャッシュサイズを増加
                // ...（実際のキャッシュサイズ増加処理）
                "キャッシュヒット率を向上させるためにキャッシュサイズを増加"
            },
            MemoryOptimizationAction::DecreaseCacheSize => {
                // キャッシュサイズを減少
                // ...（実際のキャッシュサイズ減少処理）
                "システムメモリ圧力を下げるためにキャッシュサイズを減少"
            },
            MemoryOptimizationAction::Preallocation => {
                // メモリの事前割り当て
                // ...（実際の事前割り当て処理）
                "パフォーマンス向上のためにメモリを事前割り当て"
            },
            MemoryOptimizationAction::MemoryCompaction => {
                // メモリ圧縮を実行
                // ...（実際のメモリ圧縮処理）
                "メモリ断片化を解消するために圧縮を実行"
            },
            MemoryOptimizationAction::SlabSizeAdjustment => {
                // スラブアロケータのサイズを調整
                // ...（実際のスラブサイズ調整処理）
                "割り当てパターンに合わせてスラブサイズを最適化"
            },
            MemoryOptimizationAction::PageSizeChange => {
                // ページサイズを変更
                // ...（実際のページサイズ変更処理）
                "大きいメモリブロック向けにページサイズを増加"
            },
            MemoryOptimizationAction::SwapPolicyChange => {
                // スワップポリシーを変更
                // ...（実際のスワップポリシー変更処理）
                "メモリ圧力に応じてスワップポリシーを調整"
            },
            MemoryOptimizationAction::NoAction => {
                // 何もしない
                return Ok(());
            },
        };
        
        // 最適化後のメモリ使用量を再取得
        self.collect_memory_stats(process_id)?;
        
        let memory_stats = self.memory_stats.read().unwrap();
        let new_usage = memory_stats.get(&process_id)
            .map(|stats| stats.physical_memory)
            .unwrap_or(0);
        
        // 変化率を計算 (変化がない場合は0%と見なす)
        let performance_change = if previous_usage > 0 {
            ((new_usage as f32 - previous_usage as f32) / previous_usage as f32) * 100.0
        } else {
            0.0
        };
        
        // 最適化イベントを記録
        let event = OptimizationEvent {
            id: self.next_event_id.fetch_add(1, Ordering::SeqCst),
            timestamp: crate::time::current_time_ms(),
            process_id: Some(process_id),
            action,
            reason: reason.to_string(),
            previous_usage,
            new_usage,
            performance_change,
        };
        
        let mut history = self.optimization_history.lock().unwrap();
        history.push_back(event);
        
        // 履歴が100件を超えたら古いものを削除
        if history.len() > 100 {
            history.pop_front();
        }
        
        log::info!("プロセス {} に最適化 {:?} を適用しました", process_id, action);
        
        Ok(())
    }
    
    /// 自動最適化ポーリングを開始
    pub fn start_auto_optimization(&self) -> Result<(), &'static str> {
        self.auto_profile_detection.store(true, Ordering::SeqCst);
        
        // バックグラウンドスレッドで定期的に最適化を実行
        // ...（実際のポーリング処理）
        
        log::info!("自動メモリ最適化を開始しました");
        
        Ok(())
    }
    
    /// 自動最適化ポーリングを停止
    pub fn stop_auto_optimization(&self) -> Result<(), &'static str> {
        self.auto_profile_detection.store(false, Ordering::SeqCst);
        
        log::info!("自動メモリ最適化を停止しました");
        
        Ok(())
    }
    
    /// 最適化間隔を設定
    pub fn set_optimization_interval(&self, interval_ms: usize) -> Result<(), &'static str> {
        if interval_ms < 100 {
            return Err("最適化間隔は最低100ミリ秒以上である必要があります");
        }
        
        self.optimization_interval_ms.store(interval_ms, Ordering::SeqCst);
        
        log::info!("メモリ最適化間隔を {}ms に設定しました", interval_ms);
        
        Ok(())
    }
    
    /// システム全体のメモリプロファイルを設定
    pub fn set_system_profile(&self, profile_type: MemoryProfileType) -> Result<(), &'static str> {
        let mut system_profile = self.system_profile.write().unwrap();
        *system_profile = profile_type;
        
        // システム全体のメモリパラメータを調整
        // ...（実際のシステム設定処理）
        
        log::info!("システム全体のメモリプロファイルを {:?} に設定しました", profile_type);
        
        Ok(())
    }
    
    /// システムのメモリ圧力を取得（0-100、高いほど圧力が高い）
    fn get_system_memory_pressure(&self) -> u8 {
        // メモリマネージャから現在のメモリ圧力を取得
        // ...（実際のメモリ圧力取得処理）
        
        // テスト用ダミーデータ
        50 // 50%のメモリ圧力
    }
    
    /// プロセスに割り当てられたプロファイルIDを取得
    fn get_profile_for_process(&self, process_id: usize) -> Option<usize> {
        let process_to_profile = self.process_to_profile.read().unwrap();
        process_to_profile.get(&process_id).copied()
    }
    
    /// プロセスのメモリ統計を取得
    pub fn get_process_memory_stats(&self, process_id: usize) -> Option<String> {
        let memory_stats = self.memory_stats.read().unwrap();
        let stats = memory_stats.get(&process_id)?;
        
        let info = format!(
            "プロセス {} のメモリ統計:\n\
             合計メモリ: {} バイト\n\
             仮想メモリ: {} バイト\n\
             物理メモリ: {} バイト\n\
             共有メモリ: {} バイト\n\
             スワップ使用量: {} バイト\n\
             キャッシュメモリ: {} バイト\n\
             ピーク使用量: {} バイト\n\
             平均割り当てサイズ: {} バイト\n\
             割り当て頻度: {}/秒\n\
             解放頻度: {}/秒\n\
             使用パターン: {:?}",
            stats.process_id, stats.total_memory, stats.virtual_memory,
            stats.physical_memory, stats.shared_memory, stats.swap_usage,
            stats.cache_memory, stats.peak_usage, stats.avg_allocation_size,
            stats.allocation_rate, stats.deallocation_rate, stats.usage_pattern
        );
        
        Some(info)
    }
    
    /// 最適化履歴を取得
    pub fn get_optimization_history(&self, limit: usize) -> Vec<OptimizationEvent> {
        let history = self.optimization_history.lock().unwrap();
        let limit = std::cmp::min(limit, history.len());
        
        history.iter().rev().take(limit).cloned().collect()
    }
}

/// グローバル自己最適化メモリマネージャ
static mut ADAPTIVE_MEMORY_MANAGER: Option<AdaptiveMemoryManager> = None;

/// 自己最適化メモリサブシステムを初期化
pub fn init(memory_manager: &'static MemoryManager, process_manager: &'static ProcessManager) -> Result<(), &'static str> {
    unsafe {
        if ADAPTIVE_MEMORY_MANAGER.is_some() {
            return Err("自己最適化メモリマネージャは既に初期化されています");
        }
        
        ADAPTIVE_MEMORY_MANAGER = Some(AdaptiveMemoryManager::new(memory_manager, process_manager));
    }
    
    // デフォルトプロファイルを登録
    register_default_profiles()?;
    
    // 自動最適化を開始
    get_memory_manager().start_auto_optimization()?;
    
    log::info!("自己最適化メモリサブシステムを初期化しました");
    
    Ok(())
}

/// グローバル自己最適化メモリマネージャを取得
pub fn get_memory_manager() -> &'static AdaptiveMemoryManager {
    unsafe {
        ADAPTIVE_MEMORY_MANAGER.as_ref().expect("自己最適化メモリマネージャが初期化されていません")
    }
}

/// デフォルトメモリプロファイルを登録
fn register_default_profiles() -> Result<(), &'static str> {
    let manager = get_memory_manager();
    
    // 高パフォーマンスプロファイル
    manager.register_app_profile(
        "high_performance",
        MemoryProfileType::HighPerformance,
        90, // 高優先度
        64 * 1024 * 1024, // 最小64MB
        1024 * 1024 * 1024, // 最大1GB
    )?;
    
    // バランス型プロファイル
    manager.register_app_profile(
        "balanced",
        MemoryProfileType::Balanced,
        50, // 中優先度
        32 * 1024 * 1024, // 最小32MB
        512 * 1024 * 1024, // 最大512MB
    )?;
    
    // 省メモリプロファイル
    manager.register_app_profile(
        "low_memory",
        MemoryProfileType::LowMemory,
        30, // 低優先度
        16 * 1024 * 1024, // 最小16MB
        128 * 1024 * 1024, // 最大128MB
    )?;
    
    // リアルタイムプロファイル
    manager.register_app_profile(
        "real_time",
        MemoryProfileType::RealTime,
        100, // 最高優先度
        128 * 1024 * 1024, // 最小128MB
        2048 * 1024 * 1024, // 最大2GB
    )?;
    
    Ok(())
}

/// アプリケーションメモリプロファイルを登録
pub fn register_app_profile(
    app_name: &str,
    profile_type: MemoryProfileType,
    priority: u8,
    min_memory: usize,
    max_memory: usize
) -> Result<usize, &'static str> {
    let manager = get_memory_manager();
    
    manager.register_app_profile(
        app_name,
        profile_type,
        priority,
        min_memory,
        max_memory
    )
}

/// プロセスにメモリプロファイルを適用
pub fn apply_profile_to_process(process_id: usize, profile_id: usize) -> Result<(), &'static str> {
    let manager = get_memory_manager();
    manager.apply_profile_to_process(process_id, profile_id)
}

/// メモリ使用状況の収集
pub fn collect_memory_stats(process_id: usize) -> Result<(), &'static str> {
    let manager = get_memory_manager();
    manager.collect_memory_stats(process_id)
}

/// メモリ使用パターンを分析
pub fn analyze_usage_pattern(process_id: usize) -> Result<MemoryUsagePattern, &'static str> {
    let manager = get_memory_manager();
    manager.analyze_usage_pattern(process_id)
}

/// 最適化アクションを決定
pub fn determine_optimization(process_id: usize) -> Result<MemoryOptimizationAction, &'static str> {
    let manager = get_memory_manager();
    manager.determine_optimization(process_id)
}

/// 最適化アクションを適用
pub fn apply_optimization(process_id: usize) -> Result<(), &'static str> {
    let manager = get_memory_manager();
    let action = manager.determine_optimization(process_id)?;
    
    if action != MemoryOptimizationAction::NoAction {
        manager.apply_optimization(process_id, action)
    } else {
        Ok(())
    }
}

/// システム全体のメモリプロファイルを設定
pub fn set_system_profile(profile_type: MemoryProfileType) -> Result<(), &'static str> {
    let manager = get_memory_manager();
    manager.set_system_profile(profile_type)
}

/// 最適化間隔を設定
pub fn set_optimization_interval(interval_ms: usize) -> Result<(), &'static str> {
    let manager = get_memory_manager();
    manager.set_optimization_interval(interval_ms)
}

/// 自動最適化を有効化/無効化
pub fn set_auto_optimization(enabled: bool) -> Result<(), &'static str> {
    let manager = get_memory_manager();
    
    if enabled {
        manager.start_auto_optimization()
    } else {
        manager.stop_auto_optimization()
    }
}

/// プロセスのメモリ統計を取得
pub fn get_process_memory_stats(process_id: usize) -> Option<String> {
    let manager = get_memory_manager();
    manager.get_process_memory_stats(process_id)
}

/// 最適化履歴を取得
pub fn get_optimization_history(limit: usize) -> Vec<OptimizationEvent> {
    let manager = get_memory_manager();
    manager.get_optimization_history(limit)
} 