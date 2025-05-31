// AetherOS TelePage 設定モジュール
//
// このモジュールはTelePageの設定オプションを定義します。

use alloc::string::String;

/// TelePage設定
#[derive(Debug, Clone)]
pub struct TelePageConfig {
    /// デフォルトで有効にするか
    pub enabled_by_default: bool,
    
    /// 追跡するページの最大数
    pub page_track_capacity: usize,
    
    /// スキャン間隔（ミリ秒）
    pub scan_interval_ms: u64,
    
    /// 一度のスキャンで移行するページの最大数
    pub max_migrations_per_scan: usize,
    
    /// HBMが必要かどうか
    pub require_hbm: bool,
    
    /// デバッグログの有効化
    pub debug_logging: bool,
    
    /// HBM→DRAM移行の経過時間しきい値（ミリ秒）
    /// この時間以上アクセスがないページはDRAMに降格
    pub cold_threshold_ms: u64,
    
    /// DRAM→HBM移行のアクセス頻度しきい値
    /// この頻度以上のアクセスがあるページはHBMに昇格
    pub hot_threshold_access_count: usize,
    
    /// 標準DRAMとHBM間のバッファ領域サイズ（バイト）
    /// この領域はHBMとDRAM間のページ転送に使用
    pub transfer_buffer_size: usize,
    
    /// プロファイルモード
    pub profile_mode: ProfileMode,
}

/// プロファイルモード
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProfileMode {
    /// 性能優先（より積極的にHBMを使用）
    Performance,
    
    /// バランス（性能と省電力のバランス）
    Balanced,
    
    /// 省電力（HBMの使用を最小限に）
    PowerSaving,
    
    /// カスタム（詳細設定を使用）
    Custom,
}

impl Default for TelePageConfig {
    fn default() -> Self {
        Self {
            enabled_by_default: true,
            page_track_capacity: 10000,
            scan_interval_ms: 1000,
            max_migrations_per_scan: 16,
            require_hbm: true,
            debug_logging: false,
            cold_threshold_ms: 5000,
            hot_threshold_access_count: 10,
            transfer_buffer_size: 4 * 1024 * 1024, // 4MB
            profile_mode: ProfileMode::Balanced,
        }
    }
}

impl TelePageConfig {
    /// 性能優先プロファイルを作成
    pub fn performance_profile() -> Self {
        Self {
            enabled_by_default: true,
            page_track_capacity: 20000,
            scan_interval_ms: 500,
            max_migrations_per_scan: 32,
            require_hbm: true,
            debug_logging: false,
            cold_threshold_ms: 10000,  // より長くHBMに保持
            hot_threshold_access_count: 5, // より少ないアクセスでもHBMに移動
            transfer_buffer_size: 8 * 1024 * 1024, // 8MB
            profile_mode: ProfileMode::Performance,
        }
    }
    
    /// 省電力プロファイルを作成
    pub fn power_saving_profile() -> Self {
        Self {
            enabled_by_default: true,
            page_track_capacity: 5000,
            scan_interval_ms: 2000,
            max_migrations_per_scan: 8,
            require_hbm: false,
            debug_logging: false,
            cold_threshold_ms: 2000,  // より早くDRAMに戻す
            hot_threshold_access_count: 20, // より多くのアクセスが必要
            transfer_buffer_size: 2 * 1024 * 1024, // 2MB
            profile_mode: ProfileMode::PowerSaving,
        }
    }
    
    /// カスタムプロファイルを作成
    pub fn custom(
        page_track_capacity: usize,
        scan_interval_ms: u64,
        max_migrations_per_scan: usize,
        cold_threshold_ms: u64,
        hot_threshold_access_count: usize
    ) -> Self {
        Self {
            enabled_by_default: true,
            page_track_capacity,
            scan_interval_ms,
            max_migrations_per_scan,
            require_hbm: true,
            debug_logging: false,
            cold_threshold_ms,
            hot_threshold_access_count,
            transfer_buffer_size: 4 * 1024 * 1024,
            profile_mode: ProfileMode::Custom,
        }
    }
    
    /// 設定を文字列として出力
    pub fn to_string(&self) -> String {
        alloc::format!(
            "TelePageConfig {{
  enabled_by_default: {},
  page_track_capacity: {},
  scan_interval_ms: {},
  max_migrations_per_scan: {},
  require_hbm: {},
  debug_logging: {},
  cold_threshold_ms: {},
  hot_threshold_access_count: {},
  transfer_buffer_size: {} KB,
  profile_mode: {:?}
}}",
            self.enabled_by_default,
            self.page_track_capacity,
            self.scan_interval_ms,
            self.max_migrations_per_scan,
            self.require_hbm,
            self.debug_logging,
            self.cold_threshold_ms,
            self.hot_threshold_access_count,
            self.transfer_buffer_size / 1024,
            self.profile_mode
        )
    }
} 