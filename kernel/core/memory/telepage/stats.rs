// AetherOS TelePage 統計情報モジュール
//
// このモジュールはTelePageの統計情報を追跡・管理します。

use crate::core::memory::MemoryTier;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::vec::Vec;
use alloc::string::String;

/// TelePage統計情報
#[derive(Debug, Clone)]
pub struct TelePageStats {
    /// 合計ページスキャン回数
    pub scan_count: AtomicU64,
    
    /// 合計ページ移行数
    pub total_migrations: AtomicU64,
    
    /// DRAM→HBM移行回数
    pub dram_to_hbm_migrations: AtomicU64,
    
    /// HBM→DRAM移行回数
    pub hbm_to_dram_migrations: AtomicU64,
    
    /// 移行成功回数
    pub successful_migrations: AtomicU64,
    
    /// 移行失敗回数
    pub failed_migrations: AtomicU64,
    
    /// 合計移行バイト数
    pub total_migrated_bytes: AtomicU64,
    
    /// 移行に要した合計時間（マイクロ秒）
    pub total_migration_time_us: AtomicU64,
    
    /// 最近の移行履歴
    pub recent_migrations: Vec<MigrationRecord>,
    
    /// 履歴の最大保持数
    max_history: usize,
}

/// 移行記録
#[derive(Debug, Clone)]
pub struct MigrationRecord {
    /// タイムスタンプ（ミリ秒）
    pub timestamp: u64,
    
    /// 仮想アドレス
    pub virtual_address: usize,
    
    /// 移行元階層
    pub source_tier: MemoryTier,
    
    /// 移行先階層
    pub target_tier: MemoryTier,
    
    /// アクセスカウント
    pub access_count: usize,
    
    /// 最終アクセスからの経過時間（ミリ秒）
    pub age_ms: u64,
    
    /// 移行時間（マイクロ秒）
    pub migration_time_us: u64,
}

impl TelePageStats {
    /// 新しい統計情報を作成
    pub fn new() -> Self {
        Self {
            scan_count: AtomicU64::new(0),
            total_migrations: AtomicU64::new(0),
            dram_to_hbm_migrations: AtomicU64::new(0),
            hbm_to_dram_migrations: AtomicU64::new(0),
            successful_migrations: AtomicU64::new(0),
            failed_migrations: AtomicU64::new(0),
            total_migrated_bytes: AtomicU64::new(0),
            total_migration_time_us: AtomicU64::new(0),
            recent_migrations: Vec::with_capacity(100),
            max_history: 100,
        }
    }
    
    /// スキャン回数を記録
    pub fn record_scan(&self) {
        self.scan_count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 移行成功を記録
    pub fn record_migration_success(&self, source: MemoryTier, target: MemoryTier) {
        self.successful_migrations.fetch_add(1, Ordering::Relaxed);
        self.total_migrations.fetch_add(1, Ordering::Relaxed);
        
        match (source, target) {
            (MemoryTier::StandardDRAM, MemoryTier::HighBandwidthMemory) => {
                self.dram_to_hbm_migrations.fetch_add(1, Ordering::Relaxed);
            },
            (MemoryTier::HighBandwidthMemory, MemoryTier::StandardDRAM) => {
                self.hbm_to_dram_migrations.fetch_add(1, Ordering::Relaxed);
            },
            _ => (),
        }
    }
    
    /// 移行失敗を記録
    pub fn record_migration_failure(&self, source: MemoryTier, target: MemoryTier) {
        self.failed_migrations.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 詳細な移行記録を追加
    pub fn add_migration_record(
        &mut self,
        virtual_address: usize,
        source_tier: MemoryTier,
        target_tier: MemoryTier,
        access_count: usize,
        age_ms: u64,
        migration_time_us: u64,
        migration_size: u64
    ) {
        // 移行バイト数を記録
        self.total_migrated_bytes.fetch_add(migration_size, Ordering::Relaxed);
        
        // 移行時間を記録
        self.total_migration_time_us.fetch_add(migration_time_us, Ordering::Relaxed);
        
        // 履歴の上限を確認
        if self.recent_migrations.len() >= self.max_history {
            self.recent_migrations.remove(0);
        }
        
        // 新しい記録を追加
        self.recent_migrations.push(MigrationRecord {
            timestamp: crate::time::current_time_ms(),
            virtual_address,
            source_tier,
            target_tier,
            access_count,
            age_ms,
            migration_time_us,
        });
    }
    
    /// 統計情報を文字列として出力
    pub fn to_string(&self) -> String {
        let scan_count = self.scan_count.load(Ordering::Relaxed);
        let total = self.total_migrations.load(Ordering::Relaxed);
        let dram_to_hbm = self.dram_to_hbm_migrations.load(Ordering::Relaxed);
        let hbm_to_dram = self.hbm_to_dram_migrations.load(Ordering::Relaxed);
        let success = self.successful_migrations.load(Ordering::Relaxed);
        let failed = self.failed_migrations.load(Ordering::Relaxed);
        let bytes = self.total_migrated_bytes.load(Ordering::Relaxed);
        let time_us = self.total_migration_time_us.load(Ordering::Relaxed);
        
        // 平均移行時間（マイクロ秒）
        let avg_time = if total > 0 {
            time_us / total
        } else {
            0
        };
        
        // 平均スループット（MB/秒）
        let throughput = if time_us > 0 {
            (bytes as f64 / 1024.0 / 1024.0) / (time_us as f64 / 1_000_000.0)
        } else {
            0.0
        };
        
        // 統計情報を整形
        alloc::format!(
            "TelePageStats {{
  scan_count: {},
  total_migrations: {},
  dram_to_hbm_migrations: {},
  hbm_to_dram_migrations: {},
  successful_migrations: {},
  failed_migrations: {},
  total_migrated_bytes: {} KB,
  avg_migration_time: {} µs,
  throughput: {:.2} MB/s,
  success_rate: {:.1}%
}}",
            scan_count,
            total,
            dram_to_hbm,
            hbm_to_dram,
            success,
            failed,
            bytes / 1024,
            avg_time,
            throughput,
            if total > 0 { (success as f64 / total as f64) * 100.0 } else { 0.0 }
        )
    }
    
    /// 概要統計情報を取得
    pub fn get_summary(&self) -> StatsSummary {
        let scan_count = self.scan_count.load(Ordering::Relaxed);
        let total = self.total_migrations.load(Ordering::Relaxed);
        let dram_to_hbm = self.dram_to_hbm_migrations.load(Ordering::Relaxed);
        let hbm_to_dram = self.hbm_to_dram_migrations.load(Ordering::Relaxed);
        let success = self.successful_migrations.load(Ordering::Relaxed);
        let failed = self.failed_migrations.load(Ordering::Relaxed);
        let bytes = self.total_migrated_bytes.load(Ordering::Relaxed);
        let time_us = self.total_migration_time_us.load(Ordering::Relaxed);
        
        StatsSummary {
            scan_count,
            total_migrations: total,
            dram_to_hbm_migrations: dram_to_hbm,
            hbm_to_dram_migrations: hbm_to_dram,
            success_rate: if total > 0 { (success as f64 / total as f64) * 100.0 } else { 0.0 },
            avg_migration_time_us: if total > 0 { time_us / total } else { 0 },
            throughput_mbps: if time_us > 0 {
                (bytes as f64 / 1024.0 / 1024.0) / (time_us as f64 / 1_000_000.0)
            } else {
                0.0
            },
        }
    }
    
    /// 履歴サイズを設定
    pub fn set_history_size(&mut self, max_size: usize) {
        self.max_history = max_size;
        
        // 現在の履歴が新しいサイズを超える場合は削減
        if self.recent_migrations.len() > max_size {
            let excess = self.recent_migrations.len() - max_size;
            self.recent_migrations.drain(0..excess);
        }
    }
    
    /// 統計情報をリセット
    pub fn reset(&mut self) {
        self.scan_count.store(0, Ordering::Relaxed);
        self.total_migrations.store(0, Ordering::Relaxed);
        self.dram_to_hbm_migrations.store(0, Ordering::Relaxed);
        self.hbm_to_dram_migrations.store(0, Ordering::Relaxed);
        self.successful_migrations.store(0, Ordering::Relaxed);
        self.failed_migrations.store(0, Ordering::Relaxed);
        self.total_migrated_bytes.store(0, Ordering::Relaxed);
        self.total_migration_time_us.store(0, Ordering::Relaxed);
        self.recent_migrations.clear();
    }
}

/// 統計情報の概要
#[derive(Debug, Clone, Copy)]
pub struct StatsSummary {
    /// スキャン回数
    pub scan_count: u64,
    
    /// 合計移行回数
    pub total_migrations: u64,
    
    /// DRAM→HBM移行回数
    pub dram_to_hbm_migrations: u64,
    
    /// HBM→DRAM移行回数
    pub hbm_to_dram_migrations: u64,
    
    /// 成功率（%）
    pub success_rate: f64,
    
    /// 平均移行時間（マイクロ秒）
    pub avg_migration_time_us: u64,
    
    /// スループット（MB/秒）
    pub throughput_mbps: f64,
}

/// 詳細統計情報
#[derive(Debug)]
pub struct DetailedStats {
    /// テラページ割り当て履歴
    terapage_allocs: SpinLock<Vec<TeraPageAllocation>>,
    
    /// リモートメモリ割り当て履歴
    remote_allocs: SpinLock<Vec<RemoteAllocation>>,
    
    /// リモート帯域使用履歴
    bandwidth_usage: SpinLock<Vec<BandwidthSample>>,
    
    /// ノードあたりの割り当て数
    per_node_allocs: [AtomicUsize; 64],
    
    /// ノードあたりの帯域使用量
    per_node_bandwidth: [AtomicUsize; 64],
}

/// テラページ割り当て情報
#[derive(Debug, Clone)]
pub struct TeraPageAllocation {
    /// 割り当てアドレス
    pub address: usize,
    
    /// 割り当てサイズ（テラページ数）
    pub pages: usize,
    
    /// 割り当て時刻
    pub timestamp: u64,
    
    /// NUMAノード
    pub numa_node: u8,
}

/// リモートメモリ割り当て情報
#[derive(Debug, Clone)]
pub struct RemoteAllocation {
    /// 割り当てアドレス
    pub address: usize,
    
    /// 割り当てサイズ（ページ数）
    pub pages: usize,
    
    /// 割り当て時刻
    pub timestamp: u64,
    
    /// リモートノードID
    pub node_id: usize,
    
    /// レイテンシ（ナノ秒）
    pub latency_ns: u64,
}

/// 帯域使用サンプル
#[derive(Debug, Clone)]
pub struct BandwidthSample {
    /// サンプル時刻
    pub timestamp: u64,
    
    /// 帯域使用量（バイト/秒）
    pub bandwidth: usize,
    
    /// ノードID
    pub node_id: usize,
}

/// 詳細統計の保持
static mut DETAILED_STATS: Option<DetailedStats> = None;

/// 詳細統計の初期化
pub fn init() {
    unsafe {
        DETAILED_STATS = Some(DetailedStats {
            terapage_allocs: SpinLock::new(Vec::new()),
            remote_allocs: SpinLock::new(Vec::new()),
            bandwidth_usage: SpinLock::new(Vec::new()),
            per_node_allocs: [AtomicUsize::new(0); 64],
            per_node_bandwidth: [AtomicUsize::new(0); 64],
        });
    }
}

/// テラページ割り当てを記録
pub fn record_terapage_allocation(address: usize, pages: usize, numa_node: u8) {
    let timestamp = get_timestamp();
    
    unsafe {
        if let Some(stats) = DETAILED_STATS.as_mut() {
            let mut allocs = stats.terapage_allocs.lock();
            
            // 記録サイズ制限
            if allocs.len() >= 100 {
                allocs.remove(0);
            }
            
            allocs.push(TeraPageAllocation {
                address,
                pages,
                timestamp,
                numa_node,
            });
        }
    }
}

/// リモートメモリ割り当てを記録
pub fn record_remote_allocation(address: usize, pages: usize, node_id: usize, latency_ns: u64) {
    let timestamp = get_timestamp();
    
    unsafe {
        if let Some(stats) = DETAILED_STATS.as_mut() {
            let mut allocs = stats.remote_allocs.lock();
            
            // 記録サイズ制限
            if allocs.len() >= 100 {
                allocs.remove(0);
            }
            
            allocs.push(RemoteAllocation {
                address,
                pages,
                timestamp,
                node_id,
                latency_ns,
            });
            
            // ノードごとの統計を更新
            if node_id < 64 {
                stats.per_node_allocs[node_id].fetch_add(pages, Ordering::Relaxed);
            }
        }
    }
}

/// 帯域使用を記録
pub fn record_bandwidth_usage(node_id: usize, bandwidth: usize) {
    let timestamp = get_timestamp();
    
    unsafe {
        if let Some(stats) = DETAILED_STATS.as_mut() {
            let mut usage = stats.bandwidth_usage.lock();
            
            // 記録サイズ制限
            if usage.len() >= 100 {
                usage.remove(0);
            }
            
            usage.push(BandwidthSample {
                timestamp,
                bandwidth,
                node_id,
            });
            
            // ノードごとの統計を更新
            if node_id < 64 {
                stats.per_node_bandwidth[node_id].store(bandwidth, Ordering::Relaxed);
            }
        }
    }
}

/// ノードごとの割り当て統計を取得
pub fn get_node_allocation_stats(node_id: usize) -> usize {
    if node_id >= 64 {
        return 0;
    }
    
    unsafe {
        if let Some(stats) = DETAILED_STATS.as_ref() {
            return stats.per_node_allocs[node_id].load(Ordering::Relaxed);
        }
    }
    
    0
}

/// ノードごとの帯域使用統計を取得
pub fn get_node_bandwidth_stats(node_id: usize) -> usize {
    if node_id >= 64 {
        return 0;
    }
    
    unsafe {
        if let Some(stats) = DETAILED_STATS.as_ref() {
            return stats.per_node_bandwidth[node_id].load(Ordering::Relaxed);
        }
    }
    
    0
}

/// 現在のタイムスタンプを取得
fn get_timestamp() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    {
        0 // 他のアーキテクチャでの実装
    }
} 