// AetherOS TelePage API モジュール
//
// このモジュールはTelePageの外部向けAPIを提供します。

use crate::core::memory::{MemoryTier, hbm};
use crate::core::memory::locality::{self, AccessPattern};
use crate::core::memory::mm;
use crate::core::memory::telepage::{self, policy};
use crate::time;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// ホットページヒント（HBMへの移動候補）
pub fn hint_hot_pages(addr: usize, size: usize, priority: u8) -> Result<(), &'static str> {
    // TelePageが初期化されているかチェック
    if !is_telepage_initialized() {
        return Err("TelePageが初期化されていません");
    }
    
    // アドレスとサイズをページサイズにアライン
    let page_size = mm::get_page_size();
    let start_addr = addr & !(page_size - 1);
    let end_addr = (addr + size + page_size - 1) & !(page_size - 1);
    let aligned_size = end_addr - start_addr;
    
    // 各ページについて処理
    let mut success_count = 0;
    let mut page_addr = start_addr;
    
    while page_addr < end_addr {
        // 物理アドレスを取得
        if let Some(phys_addr) = mm::get_physical_address(page_addr) {
            // 現在のメモリ階層を判定
            let current_tier = if hbm::is_hbm_address(phys_addr) {
                MemoryTier::HighBandwidthMemory
            } else {
                MemoryTier::StandardDRAM
            };
            
            // 既にHBMにある場合はスキップ
            if current_tier == MemoryTier::HighBandwidthMemory {
                page_addr += page_size;
                continue;
            }
            
            // アクセスパターンを検出してヒントとして登録
            let block_id = locality::register_data_block(page_addr, page_size, None);
            let pattern = locality::get_block_pattern(block_id)
                .unwrap_or(AccessPattern::Unknown);
            
            // ヒントを記録
            record_hot_hint(page_addr, phys_addr, pattern, priority);
            success_count += 1;
        }
        
        page_addr += page_size;
    }
    
    if success_count > 0 {
        Ok(())
    } else {
        Err("有効なページが見つかりませんでした")
    }
}

/// コールドページヒント（DRAMへの移動候補）
pub fn hint_cold_pages(addr: usize, size: usize) -> Result<(), &'static str> {
    // TelePageが初期化されているかチェック
    if !is_telepage_initialized() {
        return Err("TelePageが初期化されていません");
    }
    
    // アドレスとサイズをページサイズにアライン
    let page_size = mm::get_page_size();
    let start_addr = addr & !(page_size - 1);
    let end_addr = (addr + size + page_size - 1) & !(page_size - 1);
    let aligned_size = end_addr - start_addr;
    
    // 各ページについて処理
    let mut success_count = 0;
    let mut page_addr = start_addr;
    
    while page_addr < end_addr {
        // 物理アドレスを取得
        if let Some(phys_addr) = mm::get_physical_address(page_addr) {
            // 現在のメモリ階層を判定
            let current_tier = if hbm::is_hbm_address(phys_addr) {
                MemoryTier::HighBandwidthMemory
            } else {
                MemoryTier::StandardDRAM
            };
            
            // 既にDRAMにある場合はスキップ
            if current_tier != MemoryTier::HighBandwidthMemory {
                page_addr += page_size;
                continue;
            }
            
            // コールドヒントを記録
            record_cold_hint(page_addr, phys_addr);
            success_count += 1;
        }
        
        page_addr += page_size;
    }
    
    if success_count > 0 {
        Ok(())
    } else {
        Err("有効なページが見つかりませんでした")
    }
}

/// ホットヒントを記録
fn record_hot_hint(virt_addr: usize, phys_addr: usize, pattern: AccessPattern, priority: u8) {
    unsafe {
        if let Some(telepage) = telepage::TELEPAGE.as_mut() {
            // 追跡エンジンにページを登録
            let page_idx = telepage.tracker.track_page(
                virt_addr,
                phys_addr,
                MemoryTier::StandardDRAM
            );
            
            // 優先度に基づいてアクセスカウントを加算
            let access_boost = match priority {
                90..=100 => 100, // 非常に高い優先度
                70..=89 => 50,   // 高い優先度
                50..=69 => 20,   // 中程度の優先度
                _ => 10,         // 低い優先度
            };
            
            // アクセスカウントを人工的に増加させる
            if let Some(page) = telepage.tracker.tracked_pages.get(page_idx) {
                page.access_count.fetch_add(access_boost, Ordering::Relaxed);
                page.hot_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// コールドヒントを記録
fn record_cold_hint(virt_addr: usize, phys_addr: usize) {
    unsafe {
        if let Some(telepage) = telepage::TELEPAGE.as_mut() {
            // 追跡エンジンにページを登録
            let page_idx = telepage.tracker.track_page(
                virt_addr,
                phys_addr,
                MemoryTier::HighBandwidthMemory
            );
            
            // 最終アクセス時間を古くする（数秒前）
            if let Some(page) = telepage.tracker.tracked_pages.get_mut(page_idx) {
                let current_time = time::current_time_ms();
                page.last_access_time = current_time - 10000; // 10秒前
                page.cold_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// HBM状態の更新
pub fn update_hbm_state(
    total_bytes: usize,
    available_bytes: usize,
    utilization_percent: usize,
    power_saving_active: bool
) -> Result<(), &'static str> {
    unsafe {
        if let Some(telepage) = telepage::TELEPAGE.as_mut() {
            // HBM使用率に基づいて移行ポリシーを調整
            let settings = telepage.policy.get_settings();
            
            let new_settings = if power_saving_active {
                // 省電力モード: HBMへの移行を抑制
                policy::PolicySettings {
                    dram_to_hbm_factor: (settings.dram_to_hbm_factor / 2).max(10),
                    hbm_to_dram_factor: (settings.hbm_to_dram_factor * 2).min(90),
                    ..settings
                }
            } else if utilization_percent > 90 {
                // HBMがほぼ満杯: HBM→DRAM移行を促進
                policy::PolicySettings {
                    dram_to_hbm_factor: (settings.dram_to_hbm_factor / 2).max(10),
                    hbm_to_dram_factor: (settings.hbm_to_dram_factor * 15 / 10).min(90),
                    ..settings
                }
            } else if utilization_percent > 70 {
                // HBM使用率が高い: HBM→DRAM移行を若干促進
                policy::PolicySettings {
                    dram_to_hbm_factor: (settings.dram_to_hbm_factor * 7 / 10).max(10),
                    hbm_to_dram_factor: (settings.hbm_to_dram_factor * 12 / 10).min(90),
                    ..settings
                }
            } else if utilization_percent < 30 {
                // HBM使用率が低い: DRAM→HBM移行を促進
                policy::PolicySettings {
                    dram_to_hbm_factor: (settings.dram_to_hbm_factor * 12 / 10).min(90),
                    hbm_to_dram_factor: (settings.hbm_to_dram_factor * 7 / 10).max(10),
                    ..settings
                }
            } else {
                // 通常の使用率: デフォルト設定を維持
                settings
            };
            
            // 設定を更新
            telepage.policy.update_settings(new_settings);
            
            Ok(())
        } else {
            Err("TelePageが初期化されていません")
        }
    }
}

/// TelePageが初期化されているかチェック
fn is_telepage_initialized() -> bool {
    unsafe {
        telepage::TELEPAGE.is_some()
    }
}

/// プロセス優先度に基づいてTelePageポリシーを選択
pub fn select_policy_for_process(process_id: u64, priority: u8) -> Result<(), &'static str> {
    unsafe {
        if let Some(telepage) = telepage::TELEPAGE.as_mut() {
            // プロセス優先度に基づいてポリシーを選択
            match priority {
                0..=30 => {
                    // 低優先度プロセス: 省電力モード
                    telepage.policy.apply_predefined(policy::PredefinedPolicy::PowerSaving);
                },
                31..=70 => {
                    // 中優先度プロセス: バランスモード
                    telepage.policy.apply_predefined(policy::PredefinedPolicy::Balanced);
                },
                71..=100 => {
                    // 高優先度プロセス: 性能モード
                    telepage.policy.apply_predefined(policy::PredefinedPolicy::Performance);
                },
                _ => {
                    // デフォルト: バランスモード
                    telepage.policy.apply_predefined(policy::PredefinedPolicy::Balanced);
                }
            };
            
            Ok(())
        } else {
            Err("TelePageが初期化されていません")
        }
    }
}

/// TelePageのパフォーマンスプロファイルを設定
pub fn set_performance_profile() -> Result<(), &'static str> {
    unsafe {
        if let Some(telepage) = telepage::TELEPAGE.as_mut() {
            // 性能優先プロファイルを適用
            let config = telepage::config::TelePageConfig::performance_profile();
            
            // 設定を更新
            telepage.config = config.clone();
            telepage.policy.apply_predefined(policy::PredefinedPolicy::Performance);
            
            log::info!("TelePageを性能優先プロファイルに設定しました");
            Ok(())
        } else {
            Err("TelePageが初期化されていません")
        }
    }
}

/// TelePageの省電力プロファイルを設定
pub fn set_power_saving_profile() -> Result<(), &'static str> {
    unsafe {
        if let Some(telepage) = telepage::TELEPAGE.as_mut() {
            // 省電力プロファイルを適用
            let config = telepage::config::TelePageConfig::power_saving_profile();
            
            // 設定を更新
            telepage.config = config.clone();
            telepage.policy.apply_predefined(policy::PredefinedPolicy::PowerSaving);
            
            log::info!("TelePageを省電力プロファイルに設定しました");
            Ok(())
        } else {
            Err("TelePageが初期化されていません")
        }
    }
}

/// TelePageのバランスプロファイルを設定
pub fn set_balanced_profile() -> Result<(), &'static str> {
    unsafe {
        if let Some(telepage) = telepage::TELEPAGE.as_mut() {
            // バランスプロファイルを適用
            let config = telepage::config::TelePageConfig::default();
            
            // 設定を更新
            telepage.config = config.clone();
            telepage.policy.apply_predefined(policy::PredefinedPolicy::Balanced);
            
            log::info!("TelePageをバランスプロファイルに設定しました");
            Ok(())
        } else {
            Err("TelePageが初期化されていません")
        }
    }
}

/// ホットページを即時移行（緊急時用）
pub fn migrate_hot_page_now(virt_addr: usize) -> Result<(), &'static str> {
    // アドレスをページアラインする
    let page_size = mm::get_page_size();
    let page_addr = virt_addr & !(page_size - 1);
    
    // 物理アドレスを取得
    let phys_addr = mm::get_physical_address(page_addr)
        .ok_or("物理アドレスが見つかりません")?;
    
    // 現在のメモリ階層を判定
    let current_tier = if hbm::is_hbm_address(phys_addr) {
        MemoryTier::HighBandwidthMemory
    } else {
        MemoryTier::StandardDRAM
    };
    
    // 既にHBMにある場合は何もしない
    if current_tier == MemoryTier::HighBandwidthMemory {
        return Ok(());
    }
    
    // HBMに新しいページを割り当て
    let new_phys_addr = telepage::allocate_page_in_tier(MemoryTier::HighBandwidthMemory)?;
    
    // ページの内容をコピー
    hbm::optimized_memory_transfer(page_addr, new_phys_addr, page_size)?;
    
    // ページテーブルを更新
    mm::remap_page(page_addr, new_phys_addr, mm::PageFlags::default())?;
    
    // 古いページを解放
    mm::free_physical_page(phys_addr)?;
    
    Ok(())
}

/// コールドページを即時移行（緊急時用）
pub fn migrate_cold_page_now(virt_addr: usize) -> Result<(), &'static str> {
    // アドレスをページアラインする
    let page_size = mm::get_page_size();
    let page_addr = virt_addr & !(page_size - 1);
    
    // 物理アドレスを取得
    let phys_addr = mm::get_physical_address(page_addr)
        .ok_or("物理アドレスが見つかりません")?;
    
    // 現在のメモリ階層を判定
    let current_tier = if hbm::is_hbm_address(phys_addr) {
        MemoryTier::HighBandwidthMemory
    } else {
        MemoryTier::StandardDRAM
    };
    
    // 既にDRAMにある場合は何もしない
    if current_tier != MemoryTier::HighBandwidthMemory {
        return Ok(());
    }
    
    // DRAMに新しいページを割り当て
    let new_phys_addr = telepage::allocate_page_in_tier(MemoryTier::StandardDRAM)?;
    
    // ページの内容をコピー
    hbm::optimized_memory_transfer(page_addr, new_phys_addr, page_size)?;
    
    // ページテーブルを更新
    mm::remap_page(page_addr, new_phys_addr, mm::PageFlags::default())?;
    
    // 古いページを解放
    mm::free_physical_page(phys_addr)?;
    
    Ok(())
} 