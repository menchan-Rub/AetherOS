// AetherOS RISC-V CPU サブシステム
//
// RISC-V 64ビットアーキテクチャのCPU管理機能を提供します。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::arch::{CpuFeatures, CoreType};

// 最新のRISC-V拡張命令セットサポートモジュール
pub mod extensions;

/// CPUコア数の最大値
pub const MAX_CPU_CORES: usize = 256;

/// CPU情報
pub struct CpuInfo {
    /// コアID
    pub hart_id: usize,
    /// 実行中かどうか
    pub active: bool,
    /// 周波数 (MHz)
    pub frequency_mhz: u32,
    /// サポートされている拡張命令セット
    pub extensions: Vec<String>,
    /// ベンダー情報
    pub vendor: &'static str,
    /// マイクロアーキテクチャ情報
    pub microarch: &'static str,
    /// コアタイプ
    pub core_type: CoreType,
    /// 最大特権モード
    pub max_privilege: PrivilegeMode,
    /// コアローカル割り込みID
    pub local_int_id: usize,
    /// 現在の電力状態
    pub power_state: PowerState,
}

/// 特権モード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeMode {
    /// ユーザーモード
    User,
    /// スーパーバイザーモード
    Supervisor,
    /// ハイパーバイザーモード
    Hypervisor,
    /// マシンモード
    Machine,
}

/// 電力状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    /// 実行中
    Running,
    /// WFI状態
    WaitForInterrupt,
    /// ディープスリープ
    DeepSleep,
    /// 停止
    Offline,
}

/// 実行中のCPUコア数
static ACTIVE_CPU_COUNT: AtomicUsize = AtomicUsize::new(1);

/// CPU情報テーブル
static mut CPU_INFO: [Option<CpuInfo>; MAX_CPU_CORES] = [None; MAX_CPU_CORES];

/// 初期化完了フラグ
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// RISC-V拡張命令セット識別子
pub enum RiscvExtension {
    /// 整数命令セット
    I,
    /// 乗算・除算
    M,
    /// アトミック命令
    A,
    /// 単精度浮動小数点
    F,
    /// 倍精度浮動小数点
    D,
    /// 圧縮命令
    C,
    /// ビット操作
    B,
    /// ベクトル演算
    V,
    /// スーパーバイザーモード
    S,
    /// ハイパーバイザー
    H,
    /// ユーザーレベル割り込み
    N,
    /// パフォーマンスカウンタ
    Zicntr,
    /// タイマー
    Zihpm,
    /// キャッシュ管理操作
    Zicbom,
    /// 暗号化
    K,
    /// カスタム拡張
    X(String),
}

impl RiscvExtension {
    /// 文字列表現を取得
    pub fn as_str(&self) -> String {
        match self {
            RiscvExtension::I => "I".to_string(),
            RiscvExtension::M => "M".to_string(),
            RiscvExtension::A => "A".to_string(),
            RiscvExtension::F => "F".to_string(),
            RiscvExtension::D => "D".to_string(),
            RiscvExtension::C => "C".to_string(),
            RiscvExtension::B => "B".to_string(),
            RiscvExtension::V => "V".to_string(),
            RiscvExtension::S => "S".to_string(),
            RiscvExtension::H => "H".to_string(),
            RiscvExtension::N => "N".to_string(),
            RiscvExtension::Zicntr => "Zicntr".to_string(),
            RiscvExtension::Zihpm => "Zihpm".to_string(),
            RiscvExtension::Zicbom => "Zicbom".to_string(),
            RiscvExtension::K => "K".to_string(),
            RiscvExtension::X(ref name) => format!("X{}", name),
        }
    }
}

/// CPUサブシステムの初期化
pub fn init() {
    if INITIALIZED.load(Ordering::SeqCst) {
        return;
    }

    // 現在のハートIDを取得
    let hart_id = get_current_hart_id();
    
    // ハートの基本情報を設定
    let mut info = CpuInfo {
        hart_id,
        active: true,
        frequency_mhz: 1000, // 仮定値：1GHz
        extensions: detect_extensions(),
        vendor: detect_vendor(),
        microarch: "Unknown",
        core_type: CoreType::General,
        max_privilege: PrivilegeMode::Machine,
        local_int_id: hart_id,
        power_state: PowerState::Running,
    };
    
    // マイクロアーキテクチャ情報を取得
    match detect_microarch() {
        "SiFive" => {
            info.microarch = "SiFive U74";
            info.core_type = CoreType::Performance;
            info.frequency_mhz = 1400;
        },
        "Rocket" => {
            info.microarch = "Rocket";
            info.core_type = CoreType::General;
        },
        "BOOM" => {
            info.microarch = "BOOM";
            info.core_type = CoreType::Performance;
            info.frequency_mhz = 1800;
        },
        "E-Series" => {
            info.microarch = "E-Series";
            info.core_type = CoreType::Efficiency;
            info.frequency_mhz = 800;
        },
        _ => {
            info.microarch = "Generic RISC-V";
        }
    }
    
    // 最新の拡張命令セット情報を追加
    extensions::update_cpu_info_with_extensions(&mut info);
    
    // 初期化したCPU情報を保存
    unsafe {
        CPU_INFO[hart_id] = Some(info);
    }
    
    // 他のハートを検出して初期化（SBIまたはDTBから情報取得）
    discover_other_harts();
    
    // 利用可能な拡張機能を有効化
    let _ = extensions::enable_all_extensions();
    
    INITIALIZED.store(true, Ordering::SeqCst);
    
    log::info!("RISC-V CPUサブシステム初期化完了: マイクロアーキテクチャ: {}, ハートID: {}", 
               info.microarch, hart_id);
}

/// 現在のハートIDを取得
pub fn get_current_hart_id() -> usize {
    let hart_id: usize;
    unsafe {
        core::arch::asm!("csrr {}, mhartid", out(reg) hart_id);
    }
    hart_id
}

/// 現在の特権モードを取得
pub fn get_current_privilege_mode() -> PrivilegeMode {
    // status CSRからMPP/SPPフィールドを読み取って判断
    // ここでは簡略化のため、マシンモードと仮定
    PrivilegeMode::Machine
}

/// 特権モードを文字列に変換
pub fn privilege_mode_to_string(mode: PrivilegeMode) -> &'static str {
    match mode {
        PrivilegeMode::User => "ユーザー",
        PrivilegeMode::Supervisor => "スーパーバイザー",
        PrivilegeMode::Hypervisor => "ハイパーバイザー",
        PrivilegeMode::Machine => "マシン",
    }
}

/// RISC-V拡張命令セットを検出
fn detect_extensions() -> Vec<String> {
    let mut extensions = Vec::new();
    
    // misa CSRから拡張命令セット情報を読み取る
    let misa: usize;
    unsafe {
        core::arch::asm!("csrr {}, misa", out(reg) misa);
    }
    
    // 基本セット
    extensions.push(RiscvExtension::I.as_str());
    
    // 拡張セットをビットマスクから検出
    if misa & (1 << ('M' as usize - 'A' as usize)) != 0 {
        extensions.push(RiscvExtension::M.as_str());
    }
    if misa & (1 << ('A' as usize - 'A' as usize)) != 0 {
        extensions.push(RiscvExtension::A.as_str());
    }
    if misa & (1 << ('F' as usize - 'A' as usize)) != 0 {
        extensions.push(RiscvExtension::F.as_str());
    }
    if misa & (1 << ('D' as usize - 'A' as usize)) != 0 {
        extensions.push(RiscvExtension::D.as_str());
    }
    if misa & (1 << ('C' as usize - 'A' as usize)) != 0 {
        extensions.push(RiscvExtension::C.as_str());
    }
    if misa & (1 << ('S' as usize - 'A' as usize)) != 0 {
        extensions.push(RiscvExtension::S.as_str());
    }
    if misa & (1 << ('V' as usize - 'A' as usize)) != 0 {
        extensions.push(RiscvExtension::V.as_str());
    }
    
    // カスタム拡張も検出可能（実際のハードウェアによる）
    
    extensions
}

/// CPUベンダー情報の検出
fn detect_vendor() -> &'static str {
    // marchid, mvendorid CSRから取得（実際はこれらのCSRを読む）
    // ここではダミー実装
    "RISC-V International"
}

/// マイクロアーキテクチャの検出
fn detect_microarch() -> &'static str {
    // marchid CSRから取得
    // ここではダミー実装
    "Generic"
}

/// 他のハートの検出
fn discover_other_harts() {
    // DTBまたはSBIから他のハート情報を取得
    // ここではダミー実装として、4コアシステムと仮定
    
    let total_harts = 4;
    ACTIVE_CPU_COUNT.store(total_harts, Ordering::SeqCst);
    
    // 追加ハートの情報を設定
    for hart_id in 1..total_harts {
        let info = CpuInfo {
            hart_id,
            active: false, // 初期状態ではスタンバイ
            frequency_mhz: 1000,
            extensions: detect_extensions(),
            vendor: detect_vendor(),
            microarch: "Generic RISC-V",
            core_type: if hart_id % 2 == 0 { CoreType::Performance } else { CoreType::Efficiency },
            max_privilege: PrivilegeMode::Machine,
            local_int_id: hart_id,
            power_state: PowerState::Offline,
        };
        
        unsafe {
            CPU_INFO[hart_id] = Some(info);
        }
    }
}

/// 指定したハートIDのCPU情報を取得
pub fn get_cpu_info(hart_id: usize) -> Option<CpuInfo> {
    if hart_id >= MAX_CPU_CORES {
        return None;
    }
    
    unsafe { CPU_INFO[hart_id].clone() }
}

/// 現在のハートのCPU情報を取得
pub fn get_current_cpu_info() -> Option<CpuInfo> {
    let hart_id = get_current_hart_id();
    get_cpu_info(hart_id)
}

/// 利用可能なCPUコア数を取得
pub fn get_cpu_count() -> usize {
    ACTIVE_CPU_COUNT.load(Ordering::SeqCst)
}

/// CPU機能情報を取得
pub fn get_cpu_features() -> CpuFeatures {
    let info = get_current_cpu_info().unwrap_or_else(|| {
        // デフォルト情報を返す
        CpuInfo {
            hart_id: 0,
            active: true,
            frequency_mhz: 1000,
            extensions: Vec::new(),
            vendor: "Unknown",
            microarch: "Generic RISC-V",
            core_type: CoreType::General,
            max_privilege: PrivilegeMode::Machine,
            local_int_id: 0,
            power_state: PowerState::Running,
        }
    });
    
    let mut features = CpuFeatures {
        vector_extensions: info.extensions.contains(&"V".to_string()),
        crypto_acceleration: info.extensions.contains(&"Zk".to_string()) || 
                           info.extensions.contains(&"Zkn".to_string()) || 
                           info.extensions.contains(&"Zks".to_string()),
        trusted_execution: false, // RISCVのTEEは実装依存
        heterogeneous_cores: false, // SMP/AMP設定に依存
        virtualization_support: info.extensions.contains(&"H".to_string()),
        extended_instructions: info.extensions.clone(),
        debug_features: true,
        power_management: true,
        performance_monitoring: info.extensions.contains(&"Zicntr".to_string()),
    };
    
    // 最新拡張命令に基づいて機能を更新
    if info.extensions.contains(&"Zvkned".to_string()) || 
       info.extensions.contains(&"Zvknha".to_string()) || 
       info.extensions.contains(&"Zvksed".to_string()) || 
       info.extensions.contains(&"Zvksh".to_string()) {
        features.crypto_acceleration = true;
    }
    
    features
}

/// 特定のハートに対するIPI (Inter-Processor Interrupt) を送信
pub fn send_ipi(target_hart: usize) -> Result<(), &'static str> {
    // SBIを使用してIPIを送信する実装
    // sbi_send_ipi SBI呼び出しを使用
    
    // 簡略化した実装（実際にはSBI呼び出しが必要）
    if target_hart >= get_cpu_count() {
        return Err("無効なハートID");
    }
    
    Ok(())
}

/// 現在のハートを停止
pub fn halt_current_hart() -> ! {
    let hart_id = get_current_hart_id();
    
    // 現在のハートを非アクティブとしてマーク
    if let Some(info) = unsafe { CPU_INFO[hart_id].as_mut() } {
        info.active = false;
        info.power_state = PowerState::Offline;
    }
    
    // SBIを使用してハートを停止する
    // WFIループに入る
    loop {
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

/// CPUの全拡張機能を有効化
pub fn enable_all_cpu_features() {
    // 基本拡張機能を有効化
    enable_vector_extension();
    
    // 最新の拡張機能を有効化
    let result = extensions::enable_all_extensions();
    if let Err(e) = result {
        log::warn!("一部の拡張機能の有効化に失敗しました: {}", e);
    }
    
    log::info!("すべての利用可能なCPU機能を有効化しました");
}

/// ベクトル拡張の有効化
fn enable_vector_extension() {
    // vscaleとvlenの設定（実際のハードウェアによる）
    unsafe {
        // vstartをゼロにリセット
        core::arch::asm!("csrw vstart, zero");
        
        // vxrm, vxsatをゼロにリセット
        core::arch::asm!("csrw vcsr, zero");
        
        // vtype、vlの設定
        // 例: LMUL=1, SEW=64、テール無し、マスク無し
        core::arch::asm!("vsetvli zero, zero, e64, m1, ta, ma");
    }
    
    log::info!("RISC-V ベクトル拡張を有効化しました");
} 