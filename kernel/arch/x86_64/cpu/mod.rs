// AetherOS x86_64 CPU管理サブシステム
//
// x86_64アーキテクチャのCPU管理機能を提供します。
// コアの検出、初期化、機能拡張の有効化などを行います。

use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::arch::{CpuFeatures, CoreType};

// 初期化モジュール
pub mod init;
// 高度なCPU拡張機能サポートモジュール
pub mod advanced_extensions;
pub mod io;

/// CPUコア数の最大値
pub const MAX_CPU_CORES: usize = 1024;

/// CPUコア数のデフォルト値
pub const DEFAULT_CPU_CORES: usize = 16;

/// CPU情報構造体
#[derive(Debug, Clone)]
pub struct CpuInfo {
    /// コアID
    pub core_id: usize,
    /// 物理パッケージID
    pub package_id: usize,
    /// ダイID (CCX/CCDなど)
    pub die_id: usize,
    /// NUMAノードID
    pub numa_node: usize,
    /// コアタイプ (P-core, E-coreなど)
    pub core_type: CoreType,
    /// 現在の動作周波数 (MHz)
    pub current_freq_mhz: u32,
    /// 最大動作周波数 (MHz)
    pub max_freq_mhz: u32,
    /// 基本動作周波数 (MHz)
    pub base_freq_mhz: u32,
    /// 製造元
    pub vendor: String,
    /// マイクロアーキテクチャ名
    pub microarch: String,
    /// CPU機能フラグ
    pub features: CpuFeatures,
    /// 高度なCPU機能フラグ
    pub advanced_features: advanced_extensions::AdvancedCpuFeatures,
    /// キャッシュライン長 (バイト)
    pub cache_line_size: usize,
    /// 現在の電力状態
    pub power_state: PowerState,
    /// このコアは有効か
    pub active: bool,
}

/// CPU電力状態の列挙型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    /// フル稼働
    Running,
    /// 省電力C1
    C1,
    /// 省電力C2
    C2,
    /// 省電力C3
    C3,
    /// 省電力C4以上の深いスリープ状態
    DeepSleep,
}

// CPUは初期化されたか
static INITIALIZED: AtomicBool = AtomicBool::new(false);

// 検出されたCPUコア数
static CPU_CORE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// CPUコア数を取得
#[inline]
pub fn get_cpu_count() -> usize {
    let count = CPU_CORE_COUNT.load(Ordering::Relaxed);
    if count > 0 {
        count
    } else {
        DEFAULT_CPU_CORES
    }
}

/// CPU機能が利用可能か確認する
#[inline]
pub fn has_feature(feature: CpuFeatures) -> bool {
    let detected = init::detect_cpu_features();
    match feature {
        CpuFeatures::Sse => detected.sse,
        CpuFeatures::Avx => detected.avx,
        CpuFeatures::Avx2 => detected.avx2,
        _ => false,
    }
}

/// 高度なCPU機能が利用可能か確認する
#[inline]
pub fn has_advanced_feature(feature: &str) -> bool {
    let detected = advanced_extensions::detect_advanced_features();
    match feature {
        "avx512f" => detected.avx512f,
        "avx512bw" => detected.avx512bw,
        "avx512dq" => detected.avx512dq,
        "avx512vl" => detected.avx512vl,
        "amx_tile" => detected.amx_tile,
        "amx_bf16" => detected.amx_bf16,
        "amx_int8" => detected.amx_int8,
        "cet_ss" => detected.cet_ss,
        "cet_ibt" => detected.cet_ibt,
        "vaes" => detected.vaes,
        "gfni" => detected.gfni,
        _ => false,
    }
}

/// 現在実行中のCPUコアのIDを取得
#[inline]
pub fn get_current_cpu_id() -> usize {
    #[cfg(target_os = "none")]
    unsafe {
        // APIC IDを使用してCPU IDを取得 (簡易実装)
        if has_feature(CpuFeatures::X2apic) {
            // x2APICの場合はMSRから直接読み取る
            let msr = x86_64::registers::model_specific::Msr::new(0x802);
            (msr.read() as usize) & 0xFF
        } else {
            // 通常のAPICの場合はMMIOから読み取る
            let apic_base = 0xFEE00000 as *const u32;
            ((*(apic_base.offset(0x20 / 4)) >> 24) & 0xFF) as usize
        }
    }
    
    #[cfg(not(target_os = "none"))]
    {
        // ホストOS上でのフォールバック実装
        0
    }
}

/// CPUサブシステムの初期化
pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }
    
    // 基本的なCPU初期化
    init::init_cpu(&crate::arch::x86_64::boot::get_boot_info())?;
    
    // 高度なCPU機能の初期化
    advanced_extensions::init_advanced_features();
    
    // トポロジーの検出とCPUコア数のカウント
    let core_count = detect_topology();
    CPU_CORE_COUNT.store(core_count, Ordering::SeqCst);
    
    INITIALIZED.store(true, Ordering::SeqCst);
    Ok(())
}

/// CPUトポロジーを検出し、コア数を返す
fn detect_topology() -> usize {
    use x86_64::instructions::cpuid::{CpuId, TopologyType};
    
    let cpuid = CpuId::new();
    
    // トポロジー情報の取得を試みる
    if let Some(topo) = cpuid.get_extended_topology_info() {
        let mut max_cores = 0;
        
        // 各レベルのトポロジー情報を確認
        for level in topo {
            if level.level_type() == TopologyType::Core {
                // 論理プロセッサ数を取得
                let processors = level.processors();
                if processors > max_cores {
                    max_cores = processors;
                }
            }
        }
        
        if max_cores > 0 {
            return max_cores.min(MAX_CPU_CORES);
        }
    }
    
    // フォールバック: レガシーな方法でコア数を推定
    if let Some(info) = cpuid.get_feature_info() {
        let logical_processors = ((info.ebx() >> 16) & 0xFF) as usize;
        if logical_processors > 0 {
            return logical_processors.min(MAX_CPU_CORES);
        }
    }
    
    // デフォルト値を返す
    DEFAULT_CPU_CORES
}

/// CPUベンダーを文字列で取得
pub fn get_cpu_vendor() -> String {
    use x86_64::instructions::cpuid::CpuId;
    
    let cpuid = CpuId::new();
    if let Some(vendor) = cpuid.get_vendor_info() {
        match vendor.as_str() {
            "GenuineIntel" => "Intel",
            "AuthenticAMD" => "AMD",
            "CentaurHauls" => "VIA",
            _ => "Unknown",
        }.to_string()
    } else {
        "Unknown".to_string()
    }
}

/// CPUモデル名を取得
pub fn get_cpu_model() -> String {
    use x86_64::instructions::cpuid::CpuId;
    
    let cpuid = CpuId::new();
    if let Some(brand) = cpuid.get_processor_brand_string() {
        brand.as_str().trim().to_string()
    } else {
        "Unknown CPU".to_string()
    }
}

/// CPU情報を文字列形式で取得
pub fn cpu_info_string() -> String {
    use alloc::format;
    
    let vendor = get_cpu_vendor();
    let model = get_cpu_model();
    let cores = get_cpu_count();
    let current_id = get_current_cpu_id();
    
    let mut features = Vec::new();
    if has_feature(CpuFeatures::Sse) { features.push("SSE"); }
    if has_feature(CpuFeatures::Sse2) { features.push("SSE2"); }
    if has_feature(CpuFeatures::Avx) { features.push("AVX"); }
    if has_feature(CpuFeatures::Avx2) { features.push("AVX2"); }
    if has_advanced_feature("avx512f") { features.push("AVX512F"); }
    if has_advanced_feature("amx_tile") { features.push("AMX"); }
    
    format!(
        "CPU: {} {}\nコア数: {}\n現在のコア: {}\n機能: {}\n",
        vendor,
        model,
        cores,
        current_id,
        features.join(", ")
    )
}

/// 指定されたCPUコアにスレッドアフィニティを設定
pub fn set_affinity(core_id: usize) -> Result<(), &'static str> {
    if core_id >= get_cpu_count() {
        return Err("無効なCPUコアIDです");
    }
    
    // 現在のプロセス/スレッドのアフィニティマスクを設定
    unsafe {
        // x86_64のAPIC IDを使用してCPUコアを特定
        let apic_id = get_apic_id_for_core(core_id)?;
        
        // スケジューラにアフィニティ変更を通知
        crate::scheduler::set_current_thread_affinity(core_id)?;
        
        // ハードウェアレベルでのCPU移行を実行
        migrate_to_cpu(apic_id)?;
        
        log::debug!("CPUコア{}にアフィニティを設定完了", core_id);
    }
    
    Ok(())
}

/// 指定されたCPUコアのAPIC IDを取得
fn get_apic_id_for_core(core_id: usize) -> Result<u32, &'static str> {
    // CPU情報テーブルからAPIC IDを検索
    static mut CPU_APIC_MAP: [u32; MAX_CPU_CORES] = [0; MAX_CPU_CORES];
    static mut MAP_INITIALIZED: bool = false;
    
    unsafe {
        if !MAP_INITIALIZED {
            init_apic_map()?;
            MAP_INITIALIZED = true;
        }
        
        if core_id < MAX_CPU_CORES {
            Ok(CPU_APIC_MAP[core_id])
        } else {
            Err("CPUコアIDが範囲外です")
        }
    }
}

/// APIC IDマップを初期化
unsafe fn init_apic_map() -> Result<(), &'static str> {
    use x86_64::instructions::cpuid::CpuId;
    
    let cpuid = CpuId::new();
    
    // 各CPUコアのAPIC IDを収集
    for core_id in 0..get_cpu_count() {
        // CPUIDを使用してAPIC IDを取得
        if let Some(feature_info) = cpuid.get_feature_info() {
            let apic_id = feature_info.initial_local_apic_id();
            CPU_APIC_MAP[core_id] = apic_id as u32;
        } else {
            return Err("CPUID機能情報を取得できません");
        }
    }
    
    Ok(())
}

/// 指定されたCPUに実際に移行
unsafe fn migrate_to_cpu(apic_id: u32) -> Result<(), &'static str> {
    // Local APICを使用してCPU間移行を実行
    let apic_base = read_msr(0x1B) & 0xFFFFF000;
    
    // ICR (Interrupt Command Register) を使用してIPI送信
    let icr_low = apic_base + 0x300;
    let icr_high = apic_base + 0x310;
    
    // 移行先CPUにIPI送信
    core::ptr::write_volatile(icr_high as *mut u32, (apic_id << 24));
    core::ptr::write_volatile(icr_low as *mut u32, 0x4500); // INIT IPI
    
    // 短時間待機
    for _ in 0..1000 {
        core::hint::spin_loop();
    }
    
    // SIPI (Startup IPI) 送信
    core::ptr::write_volatile(icr_low as *mut u32, 0x4600); // SIPI
    
    Ok(())
}

/// CPU温度を取得（対応している場合）
pub fn get_cpu_temperature() -> Option<f32> {
    use x86_64::instructions::cpuid::CpuId;
    
    let cpuid = CpuId::new();
    
    // Intel Digital Thermal Sensorをチェック
    if let Some(thermal) = cpuid.get_thermal_power_info() {
        if thermal.has_dts() {
            // MSR 0x19Cから温度を読み取り
            unsafe {
                let msr = x86_64::registers::model_specific::Msr::new(0x19C);
                let raw_temp = msr.read();
                
                // ビット22-16がデジタル読み値
                let digital_readout = ((raw_temp >> 16) & 0x7F) as u32;
                
                // ビット31が有効ビット
                if (raw_temp & (1 << 31)) != 0 {
                    // TJmax（通常85°Cまたは100°C）から引いて実際の温度を計算
                    let tjmax = 100.0; // 仮定値
                    return Some(tjmax - digital_readout as f32);
                }
            }
        }
    }
    
    // AMDのセンサーをチェック
    if get_cpu_vendor() == "AMD" {
        // AMD温度センサーの実装
        unsafe {
            // ファミリー17h以降のAMDプロセッサの場合
            let temp_msr = x86_64::registers::model_specific::Msr::new(0xC0010059);
            let raw_temp = temp_msr.read();
            
            // ビット20-11が温度データ
            let temp_data = ((raw_temp >> 11) & 0x3FF) as u32;
            
            if temp_data != 0 {
                // AMDの温度計算式
                let temperature = (temp_data as f32 * 0.125) - 49.0;
                return Some(temperature);
            }
        }
    }
    
    // 温度センサーが利用できない
    None
}

/// CPU周波数を取得
pub fn get_cpu_frequency() -> Option<u32> {
    use x86_64::instructions::cpuid::CpuId;
    
    let cpuid = CpuId::new();
    
    // プロセッサー周波数情報を取得
    if let Some(freq_info) = cpuid.get_processor_frequency_info() {
        let base_freq = freq_info.processor_base_frequency();
        if base_freq > 0 {
            return Some(base_freq as u32);
        }
    }
    
    // TSC周波数から推定
    if let Some(tsc_info) = cpuid.get_tsc_info() {
        if let Some(freq_info) = cpuid.get_processor_frequency_info() {
            let crystal_freq = tsc_info.tsc_frequency();
            if crystal_freq > 0 {
                return Some((crystal_freq / 1_000_000) as u32); // MHz単位
            }
        }
    }
    
    None
}

/// CPU電力管理機能を有効化
pub fn enable_power_management() -> Result<(), &'static str> {
    unsafe {
        // Enhanced Intel SpeedStep (EIST) を有効化
        let msr = x86_64::registers::model_specific::Msr::new(0x1A0); // IA32_MISC_ENABLE
        let misc_enable = msr.read();
        
        // ビット16がEIST有効化ビット
        if (misc_enable & (1 << 16)) == 0 {
            msr.write(misc_enable | (1 << 16));
            log::info!("Enhanced Intel SpeedStepを有効化");
        }
        
        // Turbo Boost を有効化
        let turbo_msr = x86_64::registers::model_specific::Msr::new(0x1A0);
        let turbo_control = turbo_msr.read();
        
        // ビット38がTurbo Boost無効化ビット（0で有効）
        if (turbo_control & (1 << 38)) != 0 {
            turbo_msr.write(turbo_control & !(1 << 38));
            log::info!("Turbo Boostを有効化");
        }
    }
    
    Ok(())
}

/// CPU性能カウンタを初期化
pub fn init_performance_counters() -> Result<(), &'static str> {
    use x86_64::instructions::cpuid::CpuId;
    
    let cpuid = CpuId::new();
    
    // Performance Monitoring Unit (PMU) の機能をチェック
    if let Some(pmu) = cpuid.get_performance_monitoring_info() {
        let num_counters = pmu.number_of_counters();
        let counter_width = pmu.counter_bit_width();
        
        log::info!("PMU検出: {}個のカウンタ（{}ビット幅）", num_counters, counter_width);
        
        unsafe {
            // 各パフォーマンスカウンタを初期化
            for i in 0..num_counters {
                // カウンタ選択レジスタ (IA32_PERFEVTSEL0-3)
                let perfevtsel_msr = x86_64::registers::model_specific::Msr::new(0x186 + i as u32);
                
                // カウンタをリセット
                perfevtsel_msr.write(0);
                
                // カウンタ値レジスタ (IA32_PMC0-3)
                let pmc_msr = x86_64::registers::model_specific::Msr::new(0xC1 + i as u32);
                pmc_msr.write(0);
            }
        }
        
        return Ok(());
    }
    
    Err("Performance Monitoring Unitが利用できません")
}

/// CPUキャッシュ情報を取得
pub fn get_cache_info() -> Vec<CacheInfo> {
    use x86_64::instructions::cpuid::CpuId;
    
    let mut caches = Vec::new();
    let cpuid = CpuId::new();
    
    // キャッシュ情報を取得
    if let Some(cache_info) = cpuid.get_cache_info() {
        for cache in cache_info {
            caches.push(CacheInfo {
                level: cache.level(),
                cache_type: match cache.cache_type() {
                    x86_64::instructions::cpuid::CacheType::Data => CacheType::Data,
                    x86_64::instructions::cpuid::CacheType::Instruction => CacheType::Instruction,
                    x86_64::instructions::cpuid::CacheType::Unified => CacheType::Unified,
                    _ => CacheType::Unknown,
                },
                size_kb: cache.size() / 1024,
                line_size: cache.coherency_line_size(),
                associativity: cache.associativity(),
            });
        }
    }
    
    caches
}

/// キャッシュ情報構造体
#[derive(Debug, Clone)]
pub struct CacheInfo {
    /// キャッシュレベル (L1, L2, L3など)
    pub level: u8,
    /// キャッシュタイプ
    pub cache_type: CacheType,
    /// サイズ (KB)
    pub size_kb: usize,
    /// ライン長 (バイト)
    pub line_size: usize,
    /// 連想度
    pub associativity: usize,
}

/// キャッシュタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheType {
    /// データキャッシュ
    Data,
    /// 命令キャッシュ
    Instruction,
    /// 統合キャッシュ
    Unified,
    /// 不明
    Unknown,
}

/// CPUのハードウェア乱数生成器を使用
pub fn get_hardware_random() -> Option<u64> {
    unsafe {
        // RDRANDまたはRDSEED命令を使用
        if has_advanced_feature("rdrand") {
            let mut result: u64;
            let success: u8;
            
            asm!(
                "rdrand {}",
                "setc {}",
                out(reg) result,
                out(reg_byte) success,
                options(nomem, nostack)
            );
            
            if success != 0 {
                return Some(result);
            }
        }
        
        if has_advanced_feature("rdseed") {
            let mut result: u64;
            let success: u8;
            
            asm!(
                "rdseed {}",
                "setc {}",
                out(reg) result,
                out(reg_byte) success,
                options(nomem, nostack)
            );
            
            if success != 0 {
                return Some(result);
            }
        }
    }
    
    None
}

/// システム負荷の平均を取得
pub fn get_average_system_load() -> Option<u8> {
    // パフォーマンスカウンタを使用してCPU使用率を計算
    unsafe {
        // TSC (Time Stamp Counter) を使用して時間を測定
        let start_tsc = read_tsc();
        let start_idle = read_idle_cycles();
        
        // 短時間待機してサンプリング
        for _ in 0..100000 {
            core::hint::spin_loop();
        }
        
        let end_tsc = read_tsc();
        let end_idle = read_idle_cycles();
        
        // 使用率を計算
        let total_cycles = end_tsc - start_tsc;
        let idle_cycles = end_idle - start_idle;
        
        if total_cycles > 0 {
            let usage_percent = ((total_cycles - idle_cycles) * 100) / total_cycles;
            Some(usage_percent.min(100) as u8)
        } else {
            Some(0)
        }
    }
}

/// TSC (Time Stamp Counter) を読み取り
unsafe fn read_tsc() -> u64 {
    let mut low: u32;
    let mut high: u32;
    
    asm!(
        "rdtsc",
        out("eax") low,
        out("edx") high,
        options(nomem, nostack)
    );
    
    ((high as u64) << 32) | (low as u64)
}

/// アイドルサイクル数を取得
unsafe fn read_idle_cycles() -> u64 {
    // MPERF/APERF MSRを使用してアイドル時間を推定
    if has_advanced_feature("mperf") {
        let mperf = read_msr(0xE7); // IA32_MPERF
        let aperf = read_msr(0xE8); // IA32_APERF
        
        // APERFはアクティブサイクル、MPERFは最大サイクル
        if mperf > aperf {
            mperf - aperf
        } else {
            0
        }
    } else {
        // フォールバック: C-state residency countersを使用
        let c1_residency = read_msr(0x3FA).unwrap_or(0); // MSR_CORE_C1_RES
        c1_residency
    }
}

/// 詳細なCPU使用率統計を取得
pub fn get_detailed_cpu_usage() -> CpuUsageStats {
    unsafe {
        let user_time = get_user_mode_cycles();
        let kernel_time = get_kernel_mode_cycles();
        let idle_time = read_idle_cycles();
        let iowait_time = get_iowait_cycles();
        
        let total_time = user_time + kernel_time + idle_time + iowait_time;
        
        CpuUsageStats {
            user_percent: if total_time > 0 { (user_time * 100 / total_time) as u8 } else { 0 },
            kernel_percent: if total_time > 0 { (kernel_time * 100 / total_time) as u8 } else { 0 },
            idle_percent: if total_time > 0 { (idle_time * 100 / total_time) as u8 } else { 100 },
            iowait_percent: if total_time > 0 { (iowait_time * 100 / total_time) as u8 } else { 0 },
            total_cycles: total_time,
        }
    }
}

/// ユーザーモードサイクル数を取得
unsafe fn get_user_mode_cycles() -> u64 {
    // Ring 3での実行時間を測定
    if let Some(pmu_data) = get_pmu_counter(0) {
        pmu_data
    } else {
        0
    }
}

/// カーネルモードサイクル数を取得
unsafe fn get_kernel_mode_cycles() -> u64 {
    // Ring 0での実行時間を測定
    if let Some(pmu_data) = get_pmu_counter(1) {
        pmu_data
    } else {
        0
    }
}

/// I/O待機サイクル数を取得
unsafe fn get_iowait_cycles() -> u64 {
    // I/O待機時間を測定
    if let Some(pmu_data) = get_pmu_counter(2) {
        pmu_data
    } else {
        0
    }
}

/// PMUカウンタから値を取得
unsafe fn get_pmu_counter(counter_id: u32) -> Option<u64> {
    if counter_id < 4 {
        let pmc_msr = x86_64::registers::model_specific::Msr::new(0xC1 + counter_id);
        Some(pmc_msr.read())
    } else {
        None
    }
}

/// CPU使用率統計構造体
#[derive(Debug, Clone)]
pub struct CpuUsageStats {
    /// ユーザーモード使用率 (%)
    pub user_percent: u8,
    /// カーネルモード使用率 (%)
    pub kernel_percent: u8,
    /// アイドル時間 (%)
    pub idle_percent: u8,
    /// I/O待機時間 (%)
    pub iowait_percent: u8,
    /// 総サイクル数
    pub total_cycles: u64,
}

/// 指定されたMSRを読み取り
pub unsafe fn read_msr(msr: u32) -> u64 {
    let msr_reg = x86_64::registers::model_specific::Msr::new(msr);
    msr_reg.read()
}

/// 指定されたMSRに書き込み
pub unsafe fn write_msr(msr: u32, value: u64) {
    let msr_reg = x86_64::registers::model_specific::Msr::new(msr);
    msr_reg.write(value);
}

/// CPUID命令の実行
pub fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let mut eax: u32;
    let mut ebx: u32;
    let mut ecx: u32;
    let mut edx: u32;
    
    unsafe {
        asm!(
            "cpuid",
            inout("eax") leaf => eax,
            out("ebx") ebx,
            inout("ecx") 0u32 => ecx,
            out("edx") edx,
            options(nomem, nostack)
        );
    }
    
    (eax, ebx, ecx, edx)
} 