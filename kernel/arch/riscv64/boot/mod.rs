// AetherOS RISC-V ブートサブシステム
//
// RISC-V 64ビットアーキテクチャのブートプロセスを管理します。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::arch::riscv64::mm::memory_types::{PhysAddr, VirtAddr};

/// ブート情報
pub struct BootInfo {
    /// カーネルのベースアドレス (物理)
    pub kernel_base_phys: PhysAddr,
    /// カーネルのベースアドレス (仮想)
    pub kernel_base_virt: VirtAddr,
    /// カーネルのサイズ (バイト)
    pub kernel_size: usize,
    /// 初期RAMディスクの物理アドレス
    pub initrd_base: PhysAddr,
    /// 初期RAMディスクのサイズ
    pub initrd_size: usize,
    /// コマンドラインパラメータ
    pub cmdline: &'static str,
    /// DTB (Device Tree Blob) アドレス
    pub dtb_addr: PhysAddr,
    /// メモリマップ
    pub memory_map: Vec<MemoryMapEntry>,
    /// ブートハートID
    pub boot_hart_id: usize,
}

/// メモリマップエントリ
#[derive(Debug, Clone)]
pub struct MemoryMapEntry {
    /// 開始アドレス
    pub base: PhysAddr,
    /// サイズ（バイト）
    pub size: usize,
    /// メモリタイプ
    pub mem_type: MemoryType,
}

/// メモリタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    /// 通常のRAM
    Ram,
    /// 予約済み
    Reserved,
    /// ACPI再利用可能
    AcpiReclaimable,
    /// NVS (Non-Volatile Storage)
    AcpiNvs,
    /// MMIO領域
    Mmio,
    /// 不良メモリ
    BadMemory,
    /// プログラマブルロジック（FPGA）
    ProgrammableLogic,
    /// 永続メモリ（PMEM）
    PersistentMemory,
}

/// 現在のブート情報
static mut BOOT_INFO: Option<BootInfo> = None;

/// ブート情報が有効かどうか
static BOOT_INFO_VALID: AtomicBool = AtomicBool::new(false);

/// ブートサブシステムの初期化
pub fn init() {
    // フェーズ1：DTBからブート情報を解析
    let dtb_addr = get_dtb_addr();
    if let Some(dtb) = get_dtb() {
        let boot_info = parse_boot_info(dtb_addr);
        
        // ブート情報を保存
        unsafe {
            BOOT_INFO = Some(boot_info);
        }
        
        BOOT_INFO_VALID.store(true, Ordering::SeqCst);
    } else {
        unimplemented!("DTB未取得。ブート情報抽出未対応");
    }
    
    // フェーズ2：マルチコア初期化
    init_secondary_harts();
    
    log::info!("RISC-V ブートサブシステム初期化完了");
}

/// ブート情報の取得
pub fn get_boot_info() -> Option<&'static BootInfo> {
    if !BOOT_INFO_VALID.load(Ordering::SeqCst) {
        return None;
    }
    
    unsafe { BOOT_INFO.as_ref() }
}

/// DTBアドレスの取得
fn get_dtb_addr() -> PhysAddr {
    // a1レジスタにはDTBアドレスが格納されている
    let dtb_addr: usize;
    unsafe {
        core::arch::asm!(
            "mv {}, a1",
            out(reg) dtb_addr
        );
    }
    
    PhysAddr::new(dtb_addr as u64)
}

/// ブート情報のパース
fn parse_boot_info(dtb_addr: PhysAddr) -> BootInfo {
    // DTBからブート情報を抽出する（本番実装）
    if let Some(dtb) = get_dtb() {
        parse_boot_info_from_dtb(dtb)
    } else {
        unimplemented!("DTB未取得。ブート情報抽出未対応");
    }
}

/// ダミーメモリマップの作成
fn create_dummy_memory_map() -> Vec<MemoryMapEntry> {
    let mut map = Vec::new();
    
    // メインメモリ
    map.push(MemoryMapEntry {
        base: PhysAddr::new(0x80000000),
        size: 1024 * 1024 * 1024, // 1GB
        mem_type: MemoryType::Ram,
    });
    
    // 拡張メモリ
    map.push(MemoryMapEntry {
        base: PhysAddr::new(0xC0000000),
        size: 1024 * 1024 * 1024, // 1GB
        mem_type: MemoryType::Ram,
    });
    
    // MMIO領域
    map.push(MemoryMapEntry {
        base: PhysAddr::new(0xF0000000),
        size: 256 * 1024 * 1024, // 256MB
        mem_type: MemoryType::Mmio,
    });
    
    map
}

/// 2次ハートの初期化
fn init_secondary_harts() {
    // SBIを使用して他のハートを起動（本番実装）
    if let Err(e) = crate::arch::riscv64::sbi::start_secondary_harts() {
        log::error!("SBI hart_start失敗: {}", e);
        unimplemented!("SBI hart_start失敗");
    }
}

/// セカンダリハートのエントリポイント
#[no_mangle]
pub extern "C" fn secondary_hart_entry() -> ! {
    // 2次ハートの初期化
    crate::arch::riscv64::cpu::init();
    
    // メモリ管理サブシステムの初期化
    crate::arch::riscv64::mm::init();
    
    // 割り込みサブシステムの初期化
    crate::arch::riscv64::interrupts::init();
    
    // スケジューラにこのハートを追加
    crate::core::process::scheduler::register_cpu();
    
    // スケジューラの実行
    crate::core::process::scheduler::run();
    
    // 決して到達しないはず
    unreachable!();
}

/// 現在の実行モードを取得
pub fn get_execution_mode() -> ExecutionMode {
    // mstatusレジスタを読み取り、現在の特権モードを判断
    // 簡略化のためSモードと仮定
    ExecutionMode::SupervisorMode
}

/// カーネル実行モード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    /// マシンモード (M-Mode)
    MachineMode,
    /// スーパーバイザーモード (S-Mode)
    SupervisorMode,
    /// ハイパーバイザーモード (H-Mode)
    HypervisorMode,
}

/// 現在の実行ステージを取得
pub fn get_boot_stage() -> BootStage {
    // ブート情報の有効性に基づいてステージを判断
    if BOOT_INFO_VALID.load(Ordering::SeqCst) {
        BootStage::Late
    } else {
        BootStage::Early
    }
}

/// ブートステージ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootStage {
    /// 早期ブート (初期化前)
    Early,
    /// 後期ブート (初期化後)
    Late,
}

/// ハードウェア情報をダンプ
pub fn dump_hardware_info() {
    if let Some(boot_info) = get_boot_info() {
        log::info!("カーネルベース (物理): {:?}", boot_info.kernel_base_phys);
        log::info!("カーネルベース (仮想): {:?}", boot_info.kernel_base_virt);
        log::info!("カーネルサイズ: {} バイト", boot_info.kernel_size);
        log::info!("初期RAMディスク: {:?} ({} バイト)", boot_info.initrd_base, boot_info.initrd_size);
        log::info!("コマンドライン: {}", boot_info.cmdline);
        log::info!("メモリマップ:");
        
        for (i, entry) in boot_info.memory_map.iter().enumerate() {
            log::info!("  領域 {}: {:?} - {:?} ({:?})",
                i,
                entry.base,
                PhysAddr::new(entry.base.as_u64() + entry.size as u64),
                entry.mem_type
            );
        }
    } else {
        log::warn!("有効なブート情報がありません");
    }
} 