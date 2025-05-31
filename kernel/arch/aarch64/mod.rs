// AetherOS AArch64 アーキテクチャサブシステム
//
// ARM 64ビットアーキテクチャのサポートを提供します。

pub mod boot;
pub mod cpu;
pub mod interrupts;
pub mod mm;

use crate::arch::{ArchitectureInfo, CpuFeatures, Endian, MemoryModel, MmuFeatures, MemoryBarrierType, CpuPowerMode, TeeSupportInfo, TeeType, CacheOperation, PerformanceCounterType, PageSize};

/// アーキテクチャの初期化
pub fn init() {
    // ブートサブシステムの初期化
    boot::init();
    
    // CPUサブシステムの初期化
    cpu::init();
    
    // メモリ管理サブシステムの初期化
    mm::init();
    
    // 割り込みサブシステムの初期化
    interrupts::init();
    
    log::info!("AArch64 アーキテクチャ初期化完了");
}

/// アーキテクチャ情報の取得
pub fn get_architecture_info() -> ArchitectureInfo {
    let arch_info = ArchitectureInfo {
        name: "AArch64",
        version: "ARMv8.5-A",
        bits: 64,
        endian: Endian::Little,
        page_sizes: vec![4096, 16384, 65536, 2 * 1024 * 1024, 512 * 1024 * 1024, 1024 * 1024 * 1024],
        instruction_set_features: get_instruction_set_features(),
        mmu_features: get_mmu_features(),
        cpu_features: cpu::get_cpu_features(),
        memory_model: MemoryModel::WeaklyConsistent,
    };
    
    arch_info
}

/// 命令セット特徴の取得
fn get_instruction_set_features() -> Vec<String> {
    let mut features = Vec::new();
    
    // ARMアーキテクチャの機能フラグを取得
    let arm_features = cpu::detect_features();
    
    // 基本命令セット
    features.push("AArch64".to_string());
    features.push("NEON".to_string());
    features.push("FP".to_string());
    
    // 各種拡張命令セット
    if cpu::cpu_has_feature(&arm_features, "SVE") {
        features.push("SVE".to_string());
    }
    
    if cpu::cpu_has_feature(&arm_features, "SVE2") {
        features.push("SVE2".to_string());
    }
    
    if cpu::cpu_has_feature(&arm_features, "AES") {
        features.push("AES".to_string());
    }
    
    if cpu::cpu_has_feature(&arm_features, "SHA1") {
        features.push("SHA1".to_string());
    }
    
    if cpu::cpu_has_feature(&arm_features, "SHA2") {
        features.push("SHA2".to_string());
    }
    
    if cpu::cpu_has_feature(&arm_features, "CRC32") {
        features.push("CRC32".to_string());
    }
    
    if cpu::cpu_has_feature(&arm_features, "ATOMICS") {
        features.push("LSE".to_string()); // Load/Store Exclusive
    }
    
    if cpu::cpu_has_feature(&arm_features, "RDM") {
        features.push("RDM".to_string()); // Rounding Doubling Multiply
    }
    
    if cpu::cpu_has_feature(&arm_features, "DOTPROD") {
        features.push("DOTPROD".to_string());
    }
    
    if cpu::cpu_has_feature(&arm_features, "FP16") {
        features.push("FP16".to_string());
    }
    
    if cpu::cpu_has_feature(&arm_features, "BF16") {
        features.push("BF16".to_string());
    }
    
    if cpu::cpu_has_feature(&arm_features, "MTE") {
        features.push("MTE".to_string());
    }
    
    if cpu::cpu_has_feature(&arm_features, "BTI") {
        features.push("BTI".to_string());
    }
    
    features
}

/// MMU特性の取得
fn get_mmu_features() -> MmuFeatures {
    MmuFeatures {
        page_table_levels: 4,          // ARMv8は4レベル（ARMv8.2-LPA拡張で5レベル対応）
        virtual_address_bits: 48,      // 標準的なARMv8は48ビット仮想アドレス（ARMv8.2-LVAは52ビット）
        physical_address_bits: 48,     // 標準的なARMv8は48ビット物理アドレス
        context_ids_supported: true,   // ASIDサポート
        multi_level_tlb: true,
        shared_tlb_entries: true,
        global_pages: true,
        hw_page_table_walker: true,
    }
}

/// メモリバリアの実行
pub fn memory_barrier(barrier_type: MemoryBarrierType) {
    match barrier_type {
        MemoryBarrierType::DataSynchronization => {
            unsafe { core::arch::asm!("dsb sy"); }
        },
        MemoryBarrierType::DataMemory => {
            unsafe { core::arch::asm!("dmb sy"); }
        },
        MemoryBarrierType::InstructionSynchronization => {
            unsafe { core::arch::asm!("isb"); }
        },
        MemoryBarrierType::Full => {
            unsafe {
                core::arch::asm!("dsb sy");
                core::arch::asm!("isb");
            }
        },
        MemoryBarrierType::StoreStore => {
            unsafe { core::arch::asm!("dmb st"); }
        },
        MemoryBarrierType::LoadLoad => {
            unsafe { core::arch::asm!("dmb ld"); }
        },
        MemoryBarrierType::StoreLoad => {
            unsafe { core::arch::asm!("dmb sy"); }
        },
        MemoryBarrierType::LoadStore => {
            unsafe { core::arch::asm!("dmb sy"); }
        },
    }
}

/// CPUのパワーモード設定
pub fn set_cpu_power_mode(cpu_id: usize, mode: CpuPowerMode) -> Result<(), &'static str> {
    if cpu_id >= cpu::get_cpu_count() {
        return Err("無効なCPU ID");
    }
    
    match mode {
        CpuPowerMode::Performance => {
            // ARM CPUFREQドライバまたはOPP (Operating Performance Points) を使用して設定
            // プラットフォーム固有の実装が必要
            // 例: CPCRレジスタを使用して周波数を最大に設定
        },
        CpuPowerMode::Balanced => {
            // バランス設定
            // 周波数を中間に設定
        },
        CpuPowerMode::PowerSaving => {
            // 省電力設定
            // 周波数を最小に設定
            // PSCI (Power State Coordination Interface) を使用してコア電力状態を制御
        },
        CpuPowerMode::CustomFrequency(freq) => {
            // カスタム周波数設定
            if freq == 0 {
                return Err("無効な周波数");
            }
            // DVFS (Dynamic Voltage and Frequency Scaling) ドライバを通じて設定
        },
        CpuPowerMode::DeepSleep => {
            // ディープスリープ設定
            if cpu_id == cpu::get_current_cpu_id() {
                // PSCI CPU_SUSPEND APIを使用
                // WFI命令でスリープ
            } else {
                // PSCI CPU_OFF APIを使用して他のCPUをオフにする
            }
        },
    }
    
    Ok(())
}

/// パフォーマンスカウンタの設定
pub fn setup_performance_counters(counters: &[PerformanceCounterType]) -> Result<(), &'static str> {
    // PMU (Performance Monitoring Unit) の初期化
    // PMCR_EL0レジスタを設定してPMUを有効化
    
    unsafe {
        let mut pmcr: u64;
        core::arch::asm!(
            "mrs {}, pmcr_el0",
            out(reg) pmcr
        );
        
        // PMUをリセットして有効化
        pmcr |= 1; // ビット0: 有効化
        pmcr |= 2; // ビット1: イベントカウンタリセット
        
        core::arch::asm!(
            "msr pmcr_el0, {}",
            in(reg) pmcr
        );
        
        // PMCNTENSET_EL0に設定して特定のカウンタを有効化
        let mut pmcntenset: u64 = 0;
        
        // PMINTENSET_EL1に設定して割り込みを有効化
        let mut pmintenset: u64 = 0;
        
        for counter in counters {
            match counter {
                PerformanceCounterType::Cycles => {
                    // サイクルカウンタを有効化
                    pmcntenset |= 1 << 31;
                    pmintenset |= 1 << 31;
                },
                PerformanceCounterType::Instructions => {
                    // 命令カウンタ用のイベントを設定（イベントタイプ0x08: 実行された命令数）
                    configure_event_counter(0, 0x08);
                    pmcntenset |= 1 << 0;
                    pmintenset |= 1 << 0;
                },
                PerformanceCounterType::CacheMissesL1 => {
                    // L1キャッシュミス用のイベントを設定（イベントタイプ0x03: L1Dキャッシュリファレンス）
                    configure_event_counter(1, 0x03);
                    pmcntenset |= 1 << 1;
                    pmintenset |= 1 << 1;
                },
                PerformanceCounterType::BranchMispredictions => {
                    // 分岐予測ミス用のイベントを設定（イベントタイプ0x10: 分岐予測ミス）
                    configure_event_counter(2, 0x10);
                    pmcntenset |= 1 << 2;
                    pmintenset |= 1 << 2;
                },
                _ => { /* 他のカウンタは必要に応じて設定 */ }
            }
        }
        
        // カウンタを有効化
        core::arch::asm!(
            "msr pmcntenset_el0, {}",
            in(reg) pmcntenset
        );
        
        // 割り込みを有効化（必要に応じて）
        core::arch::asm!(
            "msr pmintenset_el1, {}",
            in(reg) pmintenset
        );
    }
    
    Ok(())
}

/// イベントカウンタの設定
fn configure_event_counter(counter_idx: u32, event_type: u32) {
    unsafe {
        // PMEVTYPERを選択
        core::arch::asm!(
            "msr pmselr_el0, {}",
            in(reg) counter_idx
        );
        
        // イベントタイプを設定
        core::arch::asm!(
            "msr pmxevtyper_el0, {}",
            in(reg) event_type
        );
    }
}

/// パフォーマンスカウンタの読み取り
pub fn read_performance_counter(counter_type: PerformanceCounterType) -> Result<u64, &'static str> {
    match counter_type {
        PerformanceCounterType::Cycles => {
            // サイクルカウンタを読み取り
            let count: u64;
            unsafe {
                core::arch::asm!(
                    "mrs {}, pmccntr_el0",
                    out(reg) count
                );
            }
            Ok(count)
        },
        PerformanceCounterType::Instructions => {
            // イベントカウンタ0（命令数用）を読み取り
            read_event_counter(0)
        },
        PerformanceCounterType::CacheMissesL1 => {
            // イベントカウンタ1（L1キャッシュミス用）を読み取り
            read_event_counter(1)
        },
        PerformanceCounterType::BranchMispredictions => {
            // イベントカウンタ2（分岐予測ミス用）を読み取り
            read_event_counter(2)
        },
        PerformanceCounterType::Custom(id) => {
            if id >= 32 {
                return Err("無効なカスタムカウンタID");
            }
            read_event_counter(id as u32)
        },
        _ => {
            Err("サポートされていないパフォーマンスカウンタタイプ")
        }
    }
}

/// イベントカウンタの読み取り
fn read_event_counter(counter_idx: u32) -> Result<u64, &'static str> {
    let count: u64;
    unsafe {
        // カウンタを選択
        core::arch::asm!(
            "msr pmselr_el0, {}",
            in(reg) counter_idx
        );
        
        // カウンタ値を読み取り
        core::arch::asm!(
            "mrs {}, pmxevcntr_el0",
            out(reg) count
        );
    }
    Ok(count)
}

/// TEE（トラステッド実行環境）のサポートチェック
pub fn check_tee_support() -> TeeSupportInfo {
    // ARM TrustZoneを検出
    
    let mut features = Vec::new();
    let id_aa64pfr0: u64;
    
    unsafe {
        core::arch::asm!(
            "mrs {}, id_aa64pfr0_el1",
            out(reg) id_aa64pfr0
        );
    }
    
    // EL3のサポートをチェック (ビット12-15)
    let el3_support = (id_aa64pfr0 >> 12) & 0xF;
    let secure_el2_support = (id_aa64pfr0 >> 36) & 0xF;
    
    let supported = el3_support != 0;
    
    if supported {
        features.push("TrustZone".to_string());
        
        if secure_el2_support != 0 {
            features.push("SecureEL2".to_string());
        }
        
        // その他の安全機能があれば追加
        features.push("SecureMonitor".to_string());
    }
    
    TeeSupportInfo {
        supported,
        tee_type: if supported { TeeType::ArmTrustZone } else { TeeType::None },
        secure_memory_size: if supported { 128 * 1024 * 1024 } else { 0 }, // 128MB（仮定）
        features,
    }
}

/// キャッシュ操作の実行
pub fn cache_operation(op: CacheOperation, addr: usize, size: usize) -> Result<(), &'static str> {
    if size == 0 {
        return Ok(());
    }
    
    match op {
        CacheOperation::Flush => {
            // キャッシュフラッシュ
            // データキャッシュをクリーン（ライトバック）して無効化
            cache_clean_invalidate_region(addr, size)?;
        },
        CacheOperation::Clean => {
            // キャッシュクリーン
            // データキャッシュをクリーン（ライトバック）
            cache_clean_region(addr, size)?;
        },
        CacheOperation::Invalidate => {
            // キャッシュ無効化
            // データキャッシュを無効化
            cache_invalidate_region(addr, size)?;
        },
        CacheOperation::Prefetch => {
            // プリフェッチ
            cache_prefetch_region(addr, size)?;
        },
    }
    
    Ok(())
}

/// キャッシュをクリーンして無効化（ライトバック＋無効化）
fn cache_clean_invalidate_region(addr: usize, size: usize) -> Result<(), &'static str> {
    // キャッシュラインサイズを取得
    let cache_line_size = get_cache_line_size();
    
    // アドレスを調整してキャッシュラインの開始点で始める
    let start_addr = addr & !(cache_line_size - 1);
    let end_addr = addr + size;
    
    // 各キャッシュラインに対して操作を実行
    let mut current_addr = start_addr;
    while current_addr < end_addr {
        unsafe {
            core::arch::asm!(
                "dc civac, {}",
                in(reg) current_addr
            );
        }
        current_addr += cache_line_size;
    }
    
    // DSBバリアを実行して操作完了を保証
    unsafe {
        core::arch::asm!("dsb sy");
    }
    
    Ok(())
}

/// キャッシュをクリーン（ライトバック）
fn cache_clean_region(addr: usize, size: usize) -> Result<(), &'static str> {
    let cache_line_size = get_cache_line_size();
    let start_addr = addr & !(cache_line_size - 1);
    let end_addr = addr + size;
    
    let mut current_addr = start_addr;
    while current_addr < end_addr {
        unsafe {
            core::arch::asm!(
                "dc cvac, {}",
                in(reg) current_addr
            );
        }
        current_addr += cache_line_size;
    }
    
    unsafe {
        core::arch::asm!("dsb sy");
    }
    
    Ok(())
}

/// キャッシュを無効化
fn cache_invalidate_region(addr: usize, size: usize) -> Result<(), &'static str> {
    let cache_line_size = get_cache_line_size();
    let start_addr = addr & !(cache_line_size - 1);
    let end_addr = addr + size;
    
    let mut current_addr = start_addr;
    while current_addr < end_addr {
        unsafe {
            core::arch::asm!(
                "dc ivac, {}",
                in(reg) current_addr
            );
        }
        current_addr += cache_line_size;
    }
    
    unsafe {
        core::arch::asm!("dsb sy");
    }
    
    Ok(())
}

/// プリフェッチ操作
fn cache_prefetch_region(addr: usize, size: usize) -> Result<(), &'static str> {
    let cache_line_size = get_cache_line_size();
    let start_addr = addr & !(cache_line_size - 1);
    let end_addr = addr + size;
    
    let mut current_addr = start_addr;
    while current_addr < end_addr {
        unsafe {
            core::arch::asm!(
                "prfm pldl1keep, [{}]",
                in(reg) current_addr
            );
        }
        current_addr += cache_line_size;
    }
    
    Ok(())
}

/// キャッシュラインサイズを取得
fn get_cache_line_size() -> usize {
    let ctr_el0: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, ctr_el0",
            out(reg) ctr_el0
        );
    }
    
    // CTR_EL0からDCacheLさびを抽出（ビット16-19）
    let dcache_line_size_log2 = ((ctr_el0 >> 16) & 0xF) as usize;
    
    // 2^DミまぶDなOぐいヘ（典型的には64バイト）
    1 << dcache_line_size_log2
}

/// すべてのCPU機能を有効化
pub fn enable_all_cpu_features() {
    cpu::enable_all_cpu_features();
}

/// ベクトルユニットの初期化
pub fn initialize_vector_unit(vector_length: Option<usize>) -> Result<(), &'static str> {
    // Vector Length (VL) を設定
    
    // ベクトル拡張のサポートをチェック
    let arm_features = cpu::detect_features();
    
    // SVEのサポートをチェック
    if !cpu::cpu_has_feature(&arm_features, "SVE") {
        // SVEがサポートされていない場合はNEONのみを有効化
        unsafe {
            // CPACR_EL1のFPENビットを設定
            let mut cpacr: u64;
            core::arch::asm!(
                "mrs {}, cpacr_el1",
                out(reg) cpacr
            );
            
            // FPENビットを設定 (ビット20-21を11に)
            cpacr |= 3 << 20;
            
            core::arch::asm!(
                "msr cpacr_el1, {}",
                in(reg) cpacr
            );
            
            // ISBバリア
            core::arch::asm!("isb");
        }
        
        return Ok(());
    }
    
    // SVEを有効化（CPUがサポートする場合）
    unsafe {
        // CPACR_EL1のFPENとZENビットを設定
        let mut cpacr: u64;
        core::arch::asm!(
            "mrs {}, cpacr_el1",
            out(reg) cpacr
        );
        
        // FPENビットを設定 (ビット20-21を11に)
        // ZENビットを設定 (ビット16-17を11に)
        cpacr |= (3 << 20) | (3 << 16);
        
        core::arch::asm!(
            "msr cpacr_el1, {}",
            in(reg) cpacr
        );
        
        // ISBバリア
        core::arch::asm!("isb");
        
        // ベクトル長を設定（SVE）
        if let Some(vlen) = vector_length {
            // ZCR_EL1のLENフィールドを設定してSVEベクトル長を構成
            // 実際の値は (vlen / 128) - 1
            let len = if vlen < 128 {
                0 // 最小のベクトル長（128ビット）
            } else if vlen > 2048 {
                15 // 最大のベクトル長（2048ビット）
            } else {
                ((vlen / 128) - 1) as u64
            };
            
            // ZCR_EL1のLENフィールドを設定
            let zcr = len << 0;
            core::arch::asm!(
                "msr zcr_el1, {}",
                in(reg) zcr
            );
        }
    }
    
    Ok(())
}

/// ページサイズの取得
pub fn available_page_sizes() -> &'static [PageSize] {
    static PAGE_SIZES: [PageSize; 3] = [
        PageSize::Size4KB,
        PageSize::Size2MB,
        PageSize::Size1GB,
    ];
    &PAGE_SIZES
} 