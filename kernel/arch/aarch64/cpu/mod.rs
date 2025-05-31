// AetherOS ARM64 CPU サブシステム
//
// AArch64 アーキテクチャのCPU管理機能を提供します。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::arch::{CpuFeatures, CoreType};

// 最新コアサポートモジュール
pub mod modern_cores;

/// CPUコア数の最大値
pub const MAX_CPU_CORES: usize = 256;

/// CPU情報
pub struct CpuInfo {
    /// コアID
    pub core_id: usize,
    /// クラスタID
    pub cluster_id: usize,
    /// 実行中かどうか
    pub active: bool,
    /// 周波数 (MHz)
    pub frequency_mhz: u32,
    /// マイクロアーキテクチャ情報
    pub microarch: &'static str,
    /// 実装者情報
    pub implementer: u8,
    /// アーキテクチャバージョン
    pub architecture: u8,
    /// パート番号
    pub part_number: u16,
    /// バリアント
    pub variant: u8,
    /// リビジョン
    pub revision: u8,
    /// コアタイプ
    pub core_type: CoreType,
    /// 現在の例外レベル
    pub current_el: ExceptionLevel,
    /// 現在の電力状態
    pub power_state: PowerState,
    /// サポートされている機能
    pub features: Vec<ArmFeature>,
}

/// 例外レベル
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionLevel {
    /// EL0 (ユーザーモード)
    El0,
    /// EL1 (カーネルモード)
    El1,
    /// EL2 (ハイパーバイザーモード)
    El2,
    /// EL3 (セキュアモニターモード)
    El3,
}

/// 電力状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    /// 実行中
    Running,
    /// WFI状態
    WaitForInterrupt,
    /// 電力制限
    PowerGated,
    /// クロック停止
    ClockGated,
    /// ディープスリープ
    DeepSleep,
    /// 停止
    Offline,
}

/// ARM機能
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmFeature {
    /// 浮動小数点
    Fp,
    /// SIMD (NEON)
    Simd,
    /// ARMv8.1-A
    Armv81a,
    /// ARMv8.2-A 
    Armv82a,
    /// ARMv8.3-A
    Armv83a,
    /// ARMv8.4-A
    Armv84a,
    /// ARMv8.5-A
    Armv85a,
    /// SVE (Scalable Vector Extension)
    Sve,
    /// SVE2
    Sve2,
    /// セキュアEL2
    SecEL2,
    /// 物理カウンタ
    PmuV3,
    /// 仮想化
    Vhe,
    /// 複製例外
    RAS,
    /// アトミック操作
    LSE,
    /// フラッグ操作
    FlagM,
    /// 暗号化拡張 (AES)
    Aes,
    /// 暗号化拡張 (SHA)
    Sha,
    /// 暗号化拡張 (高度なSIMD)
    Sha3,
    /// MPAM (メモリ帯域管理)
    Mpam,
    /// DIT (データ独立タイミング)
    DIT,
    /// BTI (分岐ターゲット識別)
    BTI,
    /// トレース
    Trace,
    /// メモリタギング拡張 (MTE)
    MTE,
    /// ポインタ認証
    PAuth,
    /// RDMA拡張
    RDMA,
    /// SIMD FPバリアント
    FpVariant,
    /// SPE (統計プロファイリング拡張)
    SPE,
    /// SVE (スケーラブルベクトル拡張)
    SME,
}

/// 実行中のCPUコア数
static ACTIVE_CPU_COUNT: AtomicUsize = AtomicUsize::new(1);

/// CPU情報テーブル
static mut CPU_INFO: [Option<CpuInfo>; MAX_CPU_CORES] = [None; MAX_CPU_CORES];

/// 初期化完了フラグ
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// CPUサブシステムの初期化
pub fn init() {
    if INITIALIZED.load(Ordering::SeqCst) {
        return;
    }

    // 現在のコアIDを取得
    let core_id = get_current_cpu_id();
    
    // コアの基本情報を設定
    let mut info = CpuInfo {
        core_id,
        cluster_id: core_id / 4, // 仮定：4コアあたり1クラスタ
        active: true,
        frequency_mhz: 2000, // 仮定値：2GHz
        microarch: "Unknown",
        implementer: 0,
        architecture: 0,
        part_number: 0,
        variant: 0,
        revision: 0,
        core_type: CoreType::General,
        current_el: detect_exception_level(),
        power_state: PowerState::Running,
        features: detect_features(),
    };
    
    // システムレジスタからCPU情報を取得
    let midr_el1 = read_midr_el1();
    info.implementer = ((midr_el1 >> 24) & 0xFF) as u8;
    info.architecture = ((midr_el1 >> 16) & 0xF) as u8;
    info.variant = ((midr_el1 >> 20) & 0xF) as u8;
    info.part_number = ((midr_el1 >> 4) & 0xFFF) as u16;
    info.revision = (midr_el1 & 0xF) as u8;
    
    // 実装者IDに基づいてマイクロアーキテクチャを設定
    match info.implementer {
        0x41 => { // ARM Ltd
            match info.part_number {
                0xD03 => {
                    info.microarch = "Cortex-A53";
                    info.core_type = CoreType::Efficiency;
                },
                0xD07 => {
                    info.microarch = "Cortex-A57";
                    info.core_type = CoreType::Performance;
                },
                0xD08 => {
                    info.microarch = "Cortex-A72";
                    info.core_type = CoreType::Performance;
                },
                0xD09 => {
                    info.microarch = "Cortex-A73";
                    info.core_type = CoreType::Performance;
                },
                0xD0A => {
                    info.microarch = "Cortex-A75";
                    info.core_type = CoreType::Performance;
                },
                0xD0B => {
                    info.microarch = "Cortex-A76";
                    info.core_type = CoreType::Performance;
                },
                0xD0C => {
                    info.microarch = "Neoverse-N1";
                    info.core_type = CoreType::Performance;
                },
                0xD0D => {
                    info.microarch = "Cortex-A77";
                    info.core_type = CoreType::Performance;
                },
                0xD0E => {
                    info.microarch = "Cortex-A78";
                    info.core_type = CoreType::Performance;
                },
                0xD40 => {
                    info.microarch = "Neoverse-V1";
                    info.core_type = CoreType::Performance;
                },
                0xD49 => {
                    info.microarch = "Neoverse-N2";
                    info.core_type = CoreType::Performance;
                },
                _ => {
                    // 最新コアの検出を試みる
                    modern_cores::update_modern_core_info(&mut info);
                    if info.microarch == "Unknown" {
                        info.microarch = "ARM Generic";
                    }
                }
            }
        },
        0x42 => { // Broadcom
            info.microarch = "Broadcom";
        },
        0x43 => { // Cavium
            match info.part_number {
                0xA1 => {
                    info.microarch = "ThunderX";
                },
                0xA2 => {
                    info.microarch = "ThunderX2";
                },
                0xB4 => {
                    info.microarch = "ThunderX3";
                },
                _ => {
                    info.microarch = "Cavium";
                }
            }
        },
        0x50 => { // Apple
            match info.part_number {
                0x00 => {
                    info.microarch = "Apple Firestorm";
                    info.core_type = CoreType::Performance;
                },
                0x01 => {
                    info.microarch = "Apple Icestorm";
                    info.core_type = CoreType::Efficiency;
                },
                0x02 => {
                    info.microarch = "Apple Avalanche";
                    info.core_type = CoreType::Performance;
                },
                0x03 => {
                    info.microarch = "Apple Blizzard";
                    info.core_type = CoreType::Efficiency;
                },
                _ => {
                    info.microarch = "Apple";
                }
            }
        },
        0x51 => { // Qualcomm
            match info.part_number {
                0x800 => {
                    info.microarch = "Kryo";
                },
                0x802 => {
                    info.microarch = "Kryo 2xx Gold";
                    info.core_type = CoreType::Performance;
                },
                0x803 => {
                    info.microarch = "Kryo 2xx Silver";
                    info.core_type = CoreType::Efficiency;
                },
                0x804 => {
                    info.microarch = "Kryo 3xx Gold";
                    info.core_type = CoreType::Performance;
                },
                0x805 => {
                    info.microarch = "Kryo 3xx Silver";
                    info.core_type = CoreType::Efficiency;
                },
                _ => {
                    info.microarch = "Qualcomm";
                }
            }
        },
        _ => {
            // 最新コアの検出を試みる
            modern_cores::update_modern_core_info(&mut info);
        }
    }
    
    // 初期化したCPU情報を保存
    unsafe {
        CPU_INFO[core_id] = Some(info);
    }
    
    // 他のコアを検出して初期化
    discover_other_cores();
    
    // 最新のベクトル拡張機能を有効化
    let _ = modern_cores::enable_advanced_vector_extensions();
    
    INITIALIZED.store(true, Ordering::SeqCst);
    
    log::info!("AArch64 CPUサブシステム初期化完了: {} ({}, {}クラスタ)", 
               info.microarch, core_id, info.cluster_id);
}

/// 現在の例外レベルを検出
fn detect_exception_level() -> ExceptionLevel {
    let current_el: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, CurrentEL",
            out(reg) current_el
        );
    }
    
    match (current_el >> 2) & 0x3 {
        3 => ExceptionLevel::El3,
        2 => ExceptionLevel::El2,
        1 => ExceptionLevel::El1,
        _ => ExceptionLevel::El0,
    }
}

/// MIDR_EL1レジスタを読み取る
fn read_midr_el1() -> u64 {
    let midr: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, midr_el1",
            out(reg) midr
        );
    }
    midr
}

/// ARM機能フラグを検出
fn detect_features() -> Vec<ArmFeature> {
    let mut features = Vec::new();
    
    // ID_AA64PFR0_EL1を読み取り
    let pfr0: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, id_aa64pfr0_el1",
            out(reg) pfr0
        );
    }
    
    // ID_AA64PFR1_EL1を読み取り
    let pfr1: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, id_aa64pfr1_el1",
            out(reg) pfr1
        );
    }
    
    // ID_AA64ISAR0_EL1を読み取り
    let isar0: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, id_aa64isar0_el1",
            out(reg) isar0
        );
    }
    
    // ID_AA64ISAR1_EL1を読み取り
    let isar1: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, id_aa64isar1_el1",
            out(reg) isar1
        );
    }
    
    // FP/SIMDサポートチェック
    if ((pfr0 >> 16) & 0xF) != 0xF {
        features.push(ArmFeature::Fp);
        features.push(ArmFeature::Simd);
    }
    
    // SVEサポートチェック
    if ((pfr0 >> 32) & 0xF) != 0 {
        features.push(ArmFeature::Sve);
    }
    
    // AESサポートチェック
    if ((isar0 >> 4) & 0xF) != 0 {
        features.push(ArmFeature::Aes);
    }
    
    // SHA1/SHA2サポートチェック
    if ((isar0 >> 8) & 0xF) != 0 {
        features.push(ArmFeature::Sha);
    }
    
    // LSEサポートチェック (atomic)
    if ((isar0 >> 20) & 0xF) != 0 {
        features.push(ArmFeature::LSE);
    }
    
    // RASサポートチェック
    if ((pfr0 >> 28) & 0xF) != 0 {
        features.push(ArmFeature::RAS);
    }
    
    // ARMv8.1-Aサポートチェック
    if ((pfr0 >> 28) & 0xF) >= 1 {
        features.push(ArmFeature::Armv81a);
    }
    
    // PointerAuth (ARMv8.3-A)サポートチェック
    if ((isar1 >> 4) & 0xF) != 0 {
        features.push(ArmFeature::PAuth);
        features.push(ArmFeature::Armv83a);
    }
    
    // 仮想化サポートチェック
    if ((pfr0 >> 8) & 0xF) != 0 {
        features.push(ArmFeature::Vhe);
    }
    
    // MPAM (ARMv8.4-A)サポートチェック
    if ((pfr0 >> 40) & 0xF) != 0 {
        features.push(ArmFeature::Mpam);
        features.push(ArmFeature::Armv84a);
    }
    
    // MTEサポートチェック (ARMv8.5-A)
    if ((pfr1 >> 8) & 0xF) != 0 {
        features.push(ArmFeature::MTE);
        features.push(ArmFeature::Armv85a);
    }
    
    features
}

/// 他のコアを検出
fn discover_other_cores() {
    // DTBやACPIテーブルから他のコア情報を取得
    // ここではダミー実装として、8コアシステムと仮定
    
    let total_cores = 8;
    ACTIVE_CPU_COUNT.store(total_cores, Ordering::SeqCst);
    
    // 追加コアの情報を設定
    for core_id in 1..total_cores {
        let cluster_id = core_id / 4;
        
        let info = CpuInfo {
            core_id,
            cluster_id,
            active: false, // 初期状態ではスタンバイ
            frequency_mhz: if cluster_id == 0 { 1800 } else { 2400 },
            microarch: if cluster_id == 0 { "Cortex-A55" } else { "Cortex-A76" },
            implementer: 0x41, // ARM
            architecture: 8, // ARMv8
            part_number: if cluster_id == 0 { 0xD03 } else { 0xD0B },
            variant: 0,
            revision: 0,
            core_type: if cluster_id == 0 { CoreType::Efficiency } else { CoreType::Performance },
            current_el: ExceptionLevel::El1,
            power_state: PowerState::Offline,
            features: detect_features(),
        };
        
        unsafe {
            CPU_INFO[core_id] = Some(info);
        }
    }
}

/// 現在のCPU IDを取得
pub fn get_current_cpu_id() -> usize {
    let core_id: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, mpidr_el1",
            out(reg) core_id
        );
    }
    
    // MPIDR_EL1からCPU IDを抽出
    // Aff0フィールドのみ使用（単一クラスタの場合）
    (core_id & 0xFF) as usize
}

/// 指定したCPU IDのCPU情報を取得
pub fn get_cpu_info(cpu_id: usize) -> Option<CpuInfo> {
    if cpu_id >= MAX_CPU_CORES {
        return None;
    }
    
    unsafe { CPU_INFO[cpu_id].clone() }
}

/// 現在のCPUのCPU情報を取得
pub fn get_current_cpu_info() -> Option<CpuInfo> {
    let cpu_id = get_current_cpu_id();
    get_cpu_info(cpu_id)
}

/// 利用可能なCPUコア数を取得
pub fn get_cpu_count() -> usize {
    ACTIVE_CPU_COUNT.load(Ordering::SeqCst)
}

/// CPU機能情報を取得
pub fn get_cpu_features() -> CpuFeatures {
    let mut features = CpuFeatures {
        vector_extensions: false,
        crypto_acceleration: false,
        trusted_execution: false,
        heterogeneous_cores: false,
        virtualization_support: false,
        extended_instructions: Vec::new(),
        debug_features: true,
        power_management: true,
        performance_monitoring: true,
    };
    
    // 検出した機能に基づいて設定
    let arm_features = detect_features();
    
    // ベクトル拡張のサポートチェック
    if arm_features.contains(&ArmFeature::Simd) {
        features.vector_extensions = true;
    }
    
    // SVEのサポートチェック
    if arm_features.contains(&ArmFeature::Sve) {
        features.vector_extensions = true;
    }
    
    // 暗号化拡張のサポートチェック
    if arm_features.contains(&ArmFeature::Aes) || arm_features.contains(&ArmFeature::Sha) {
        features.crypto_acceleration = true;
    }
    
    // 仮想化のサポートチェック
    if arm_features.contains(&ArmFeature::Vhe) {
        features.virtualization_support = true;
    }
    
    // ヘテロジニアスコアのチェック
    let mut found_perf = false;
    let mut found_eff = false;
    
    for core_id in 0..get_cpu_count() {
        if let Some(info) = get_cpu_info(core_id) {
            match info.core_type {
                CoreType::Performance => found_perf = true,
                CoreType::Efficiency => found_eff = true,
                _ => {}
            }
        }
    }
    
    features.heterogeneous_cores = found_perf && found_eff;
    
    // ARM機能名のリストを作成
    let mut extension_names = Vec::new();
    for feature in arm_features {
        extension_names.push(format!("{:?}", feature));
    }
    
    features.extended_instructions = extension_names;
    
    features
}

/// 特定のCPUに対するIPCを送信
pub fn send_ipc(target_cpu: usize) -> Result<(), &'static str> {
    // SGIを使用してIPIを送信（GIC本番実装）
    gic::send_sgi(target_cpu, 1);
    
    Ok(())
}

/// 現在のCPUを停止
pub fn halt_current_cpu() -> ! {
    let cpu_id = get_current_cpu_id();
    
    // 現在のCPUを非アクティブとしてマーク
    if let Some(info) = unsafe { CPU_INFO[cpu_id].as_mut() } {
        info.active = false;
        info.power_state = PowerState::Offline;
    }
    
    // WFIループに入る
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

/// CPUの拡張機能を全て有効化
pub fn enable_all_cpu_features() {
    // 従来の機能を有効化
    enable_fp_simd();
    
    if let Some(info) = get_current_cpu_info() {
        // SVE有効化
        if info.features.contains(&ArmFeature::Sve) {
            enable_sve();
        }
        
        // ARMv9最新機能の有効化
        let _ = modern_cores::enable_advanced_vector_extensions();
    }
}

/// FP/SIMDの有効化
fn enable_fp_simd() {
    unsafe {
        // CPACRレジスタを読み取り
        let mut cpacr: u64;
        core::arch::asm!(
            "mrs {}, cpacr_el1",
            out(reg) cpacr
        );
        
        // FPENビットを設定 (ビット20-21を11に)
        cpacr |= 3 << 20;
        
        // CPACRレジスタを書き込み
        core::arch::asm!(
            "msr cpacr_el1, {}",
            in(reg) cpacr
        );
        
        // ISBバリア
        core::arch::asm!("isb");
    }
    
    log::debug!("FP/SIMD有効化完了");
}

/// SVE (Scalable Vector Extension) の有効化
fn enable_sve() {
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
    }
    
    log::debug!("SVE有効化完了");
} 