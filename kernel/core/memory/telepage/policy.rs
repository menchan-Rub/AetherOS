// AetherOS TelePage ポリシーモジュール
//
// このモジュールはTelePageのメモリ階層間移行ポリシーを定義します。

use crate::core::memory::locality::AccessPattern;
use crate::core::memory::MemoryTier;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// ページ移行ポリシー
#[derive(Debug)]
pub struct PageMigrationPolicy {
    /// ホットページのアクセス頻度しきい値
    hot_access_threshold: AtomicUsize,
    
    /// コールドページの未アクセス時間しきい値（ミリ秒）
    cold_time_threshold: AtomicU64,
    
    /// DRAM→HBM移行係数（0-100）
    /// 大きいほど積極的に移行
    dram_to_hbm_factor: AtomicUsize,
    
    /// HBM→DRAM移行係数（0-100）
    /// 大きいほど積極的に移行
    hbm_to_dram_factor: AtomicUsize,
    
    /// パターン重み付け有効化
    pattern_weighting: bool,
    
    /// メモリ圧力考慮
    consider_memory_pressure: bool,
    
    /// システム負荷考慮
    consider_system_load: bool,
}

impl PageMigrationPolicy {
    /// 新しいポリシーを作成
    pub fn new() -> Self {
        Self {
            hot_access_threshold: AtomicUsize::new(10),
            cold_time_threshold: AtomicU64::new(5000),
            dram_to_hbm_factor: AtomicUsize::new(50),
            hbm_to_dram_factor: AtomicUsize::new(50),
            pattern_weighting: true,
            consider_memory_pressure: true,
            consider_system_load: true,
        }
    }
    
    /// ポリシーをカスタマイズ
    pub fn customize(
        &mut self,
        hot_threshold: usize,
        cold_threshold: u64,
        dram_to_hbm: usize,
        hbm_to_dram: usize,
        use_pattern_weighting: bool,
    ) {
        self.hot_access_threshold.store(hot_threshold, Ordering::Relaxed);
        self.cold_time_threshold.store(cold_threshold, Ordering::Relaxed);
        self.dram_to_hbm_factor.store(dram_to_hbm.min(100), Ordering::Relaxed);
        self.hbm_to_dram_factor.store(hbm_to_dram.min(100), Ordering::Relaxed);
        self.pattern_weighting = use_pattern_weighting;
    }
    
    /// 最適なメモリ階層を判断
    pub fn determine_optimal_tier(
        &self,
        access_count: usize,
        age_ms: u64,
        pattern: AccessPattern
    ) -> MemoryTier {
        // 現在のメモリ圧力を取得
        let hbm_pressure = self.get_hbm_memory_pressure();
        let dram_pressure = self.get_dram_memory_pressure();
        
        // 基本的なホット/コールド判定
        let hot_threshold = self.hot_access_threshold.load(Ordering::Relaxed);
        let cold_threshold = self.cold_time_threshold.load(Ordering::Relaxed);
        
        // パターン係数
        let pattern_factor = if self.pattern_weighting {
            match pattern {
                AccessPattern::Sequential => 1.5,  // シーケンシャルアクセスはHBMで大幅に高速化
                AccessPattern::Strided(_) => 1.3,  // ストライドアクセスも高速化
                AccessPattern::Random => 1.2,      // ランダムアクセスも高速化
                AccessPattern::Localized(_) => 1.1, // 局所的アクセス
                AccessPattern::TemporalLocality(_) => 1.4, // 時間的局所性は高速メモリに適合
                _ => 1.0,
            }
        } else {
            1.0
        };
        
        // DRAM→HBM移行判定
        let is_hot = (access_count as f64 * pattern_factor) >= hot_threshold as f64 && age_ms < 1000;
        
        // HBM→DRAM移行判定
        let is_cold = age_ms > cold_threshold;
        
        // メモリ圧力を考慮した調整
        let dram_to_hbm_factor = self.dram_to_hbm_factor.load(Ordering::Relaxed) as f64 / 100.0;
        let hbm_to_dram_factor = self.hbm_to_dram_factor.load(Ordering::Relaxed) as f64 / 100.0;
        
        // HBM圧力が高い場合は移行を抑制
        let hbm_pressure_adjusted = if self.consider_memory_pressure && hbm_pressure > 80 {
            dram_to_hbm_factor * (1.0 - ((hbm_pressure as f64 - 80.0) / 20.0))
        } else {
            dram_to_hbm_factor
        };
        
        // DRAM圧力が高い場合は移行を促進
        let dram_pressure_adjusted = if self.consider_memory_pressure && dram_pressure > 80 {
            hbm_to_dram_factor * (1.0 - ((dram_pressure as f64 - 80.0) / 20.0))
        } else {
            hbm_to_dram_factor
        };
        
        // システム負荷の取得
        let system_load = if self.consider_system_load {
            self.get_system_load()
        } else {
            0.5 // 中間値
        };
        
        // 最終判定
        if is_hot && self.should_move_to_hbm(hbm_pressure_adjusted, system_load) {
            MemoryTier::HighBandwidthMemory
        } else if is_cold && self.should_move_to_dram(dram_pressure_adjusted, system_load) {
            MemoryTier::StandardDRAM
        } else if is_hot && access_count > hot_threshold * 3 {
            // 非常に高頻度のアクセスがある場合は、圧力に関わらずHBMに移動
            MemoryTier::HighBandwidthMemory
        } else {
            // デフォルトではDRAM
            MemoryTier::StandardDRAM
        }
    }
    
    /// HBMへの移行判断
    fn should_move_to_hbm(&self, pressure_factor: f64, system_load: f64) -> bool {
        // 高負荷時は積極的にHBMを使用
        let load_factor = if system_load > 0.7 { 1.2 } else { 1.0 };
        
        // ランダム要素を加えて振動を防止
        let decision_factor = pressure_factor * load_factor;
        let random_factor = (crate::arch::rdrand() % 100) as f64 / 100.0;
        
        random_factor < decision_factor
    }
    
    /// DRAMへの移行判断
    fn should_move_to_dram(&self, pressure_factor: f64, system_load: f64) -> bool {
        // 低負荷時は積極的にDRAMを使用して省電力
        let load_factor = if system_load < 0.3 { 1.2 } else { 1.0 };
        
        // ランダム要素を加えて振動を防止
        let decision_factor = pressure_factor * load_factor;
        let random_factor = (crate::arch::rdrand() % 100) as f64 / 100.0;
        
        random_factor < decision_factor
    }
    
    /// HBMのメモリ圧力を取得（0-100%）
    fn get_hbm_memory_pressure(&self) -> usize {
        let stats = crate::core::memory::hbm::get_hbm_stats();
        stats.utilization_percent
    }
    
    /// DRAMのメモリ圧力を取得（0-100%）
    fn get_dram_memory_pressure(&self) -> usize {
        let total = crate::core::memory::get_total_physical();
        let available = crate::core::memory::get_available_physical();
        
        if total == 0 {
            return 0;
        }
        
        ((total - available) * 100) / total
    }
    
    /// システム負荷を取得（0.0-1.0）
    fn get_system_load(&self) -> f64 {
        match crate::scheduler::get_system_load() {
            Some(load) => load,
            None => 0.5,
        }
    }
    
    /// 現在のポリシー設定を取得
    pub fn get_settings(&self) -> PolicySettings {
        PolicySettings {
            hot_access_threshold: self.hot_access_threshold.load(Ordering::Relaxed),
            cold_time_threshold: self.cold_time_threshold.load(Ordering::Relaxed),
            dram_to_hbm_factor: self.dram_to_hbm_factor.load(Ordering::Relaxed),
            hbm_to_dram_factor: self.hbm_to_dram_factor.load(Ordering::Relaxed),
            pattern_weighting: self.pattern_weighting,
            consider_memory_pressure: self.consider_memory_pressure,
            consider_system_load: self.consider_system_load,
        }
    }
    
    /// ポリシー設定を更新
    pub fn update_settings(&mut self, settings: PolicySettings) {
        self.hot_access_threshold.store(settings.hot_access_threshold, Ordering::Relaxed);
        self.cold_time_threshold.store(settings.cold_time_threshold, Ordering::Relaxed);
        self.dram_to_hbm_factor.store(settings.dram_to_hbm_factor.min(100), Ordering::Relaxed);
        self.hbm_to_dram_factor.store(settings.hbm_to_dram_factor.min(100), Ordering::Relaxed);
        self.pattern_weighting = settings.pattern_weighting;
        self.consider_memory_pressure = settings.consider_memory_pressure;
        self.consider_system_load = settings.consider_system_load;
    }
}

/// ポリシー設定
#[derive(Debug, Clone, Copy)]
pub struct PolicySettings {
    /// ホットページのアクセス頻度しきい値
    pub hot_access_threshold: usize,
    
    /// コールドページの未アクセス時間しきい値（ミリ秒）
    pub cold_time_threshold: u64,
    
    /// DRAM→HBM移行係数（0-100）
    pub dram_to_hbm_factor: usize,
    
    /// HBM→DRAM移行係数（0-100）
    pub hbm_to_dram_factor: usize,
    
    /// パターン重み付け有効化
    pub pattern_weighting: bool,
    
    /// メモリ圧力考慮
    pub consider_memory_pressure: bool,
    
    /// システム負荷考慮
    pub consider_system_load: bool,
}

/// 事前定義ポリシー
pub enum PredefinedPolicy {
    /// 性能優先（積極的にHBMを使用）
    Performance,
    
    /// バランス（性能と省電力のバランス）
    Balanced,
    
    /// 省電力（HBMの使用を最小限に）
    PowerSaving,
}

impl PageMigrationPolicy {
    /// 事前定義ポリシーを適用
    pub fn apply_predefined(&mut self, policy: PredefinedPolicy) {
        match policy {
            PredefinedPolicy::Performance => {
                self.customize(5, 10000, 80, 20, true);
                self.consider_memory_pressure = true;
                self.consider_system_load = true;
            },
            PredefinedPolicy::Balanced => {
                self.customize(10, 5000, 50, 50, true);
                self.consider_memory_pressure = true;
                self.consider_system_load = true;
            },
            PredefinedPolicy::PowerSaving => {
                self.customize(20, 2000, 20, 80, true);
                self.consider_memory_pressure = true;
                self.consider_system_load = true;
            },
        }
    }
} 