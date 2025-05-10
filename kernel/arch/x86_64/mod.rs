// AetherOS x86_64アーキテクチャサポート
//
// x86_64アーキテクチャ固有の機能を実装します。

pub mod boot;       // ブート関連コード
pub mod mm;         // メモリ管理
pub mod interrupts; // 割り込み管理
pub mod debug;      // デバッグサポート
pub mod cpu;        // CPU固有コード
pub mod acpi;       // ACPIサポート
pub mod pci;        // PCIバスサポート
pub mod io;         // I/Oポートアクセス
pub mod msr;        // モデル固有レジスタ
pub mod fpu;        // 浮動小数点ユニット
pub mod tsc;        // タイムスタンプカウンタ
pub mod apic;       // 割り込みコントローラ
pub mod smp;        // 対称型マルチプロセッシング
pub mod vmm;        // 仮想マシンモニタ
pub mod syscall;    // システムコール実装

use crate::arch::ThreadContext;
use core::sync::atomic::{AtomicUsize, Ordering};

/// CPU状態構造体
#[repr(C)]
pub struct CpuState {
    /// 汎用レジスタ
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    
    /// プログラムカウンタ
    pub rip: u64,
    /// コードセグメント
    pub cs: u64,
    /// フラグレジスタ
    pub rflags: u64,
    /// スタックポインタ
    pub rsp: u64,
    /// スタックセグメント
    pub ss: u64,
    
    /// FPU/SIMD状態（512バイトアライメント要）
    /// 実際の実装ではここにxsaveエリアが配置される
    /// アライメントの問題を回避するために、ここでは代わりにポインタを使用
    pub fpu_state: *mut u8,
}

/// スレッドコンテキスト
#[repr(C)]
pub struct ThreadContextImpl {
    /// カーネルモードスタックポインタ
    pub kernel_rsp: u64,
    /// ユーザーモードスタックポインタ
    pub user_rsp: u64,
    /// CR3（ページテーブルベースレジスタ）
    pub cr3: u64,
    /// CPU状態
    pub cpu_state: *mut CpuState,
}

/// CPUカウント（検出されたCPUコア数）
static CPU_COUNT: AtomicUsize = AtomicUsize::new(1);

/// 初期化関数
pub fn init() {
    // サブモジュールの初期化
    boot::init();
    mm::init();
    debug::init();
    interrupts::init();
    cpu::init();
    acpi::init();
    pci::init();
    io::init();
    msr::init();
    fpu::init();
    tsc::init();
    apic::init();
    smp::init();
    vmm::init();
    syscall::init();
    
    // CPUコア数の検出と設定
    let cpu_count = detect_cpu_count();
    CPU_COUNT.store(cpu_count, Ordering::SeqCst);
    
    log::info!("x86_64アーキテクチャ初期化完了: {}コア検出", cpu_count);
}

/// CPUコア数を検出
fn detect_cpu_count() -> usize {
    // ACPIからCPUコア数を検出
    // ここでは簡略化のため、単一コアを想定
    acpi::get_cpu_count().unwrap_or(1)
}

/// CPUコア数を取得
pub fn get_cpu_count() -> usize {
    CPU_COUNT.load(Ordering::SeqCst)
}

/// 現在のCPU IDを取得
pub fn get_current_cpu_id() -> usize {
    // APICからCPU IDを取得
    // ブートストラップ段階では0を返す
    apic::get_current_cpu_id().unwrap_or(0)
}

/// メモリ情報を取得
pub fn get_memory_info() -> crate::arch::MemoryInfo {
    mm::get_memory_info()
}

/// CPUを停止
pub fn halt() {
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack));
    }
}

/// 割り込みを有効化
pub fn enable_interrupts() {
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack));
    }
}

/// 割り込みを無効化
pub fn disable_interrupts() {
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }
}

/// タイマーハンドラを設定
pub fn set_timer_handler(handler: fn()) {
    interrupts::set_timer_handler(handler);
}

/// 初期スレッドスイッチ
pub fn first_thread_switch(stack_top: usize) {
    // アセンブリでスタックをセットして最初のスレッドにジャンプ
    unsafe {
        // スタックポインタを設定してretを実行
        // これにより、スタックの先頭に格納されたアドレスにジャンプする
        core::arch::asm!(
            "mov rsp, {}",
            "xor rbp, rbp", // ベースポインタをクリア
            "ret",          // スタックからリターンアドレスをポップしてジャンプ
            in(reg) stack_top,
            options(noreturn)
        );
    }
}

/// コンテキストスイッチ
pub fn context_switch(current: *mut ThreadContext, next: *mut ThreadContext) {
    unsafe {
        // 現在のRSPを保存し、次のRSPをロード
        // 実際の実装では、さらに多くのレジスタを保存/復元する必要がある
        let current_impl = current as *mut ThreadContextImpl;
        let next_impl = next as *mut ThreadContextImpl;
        
        core::arch::asm!(
            // 現在のコンテキストを保存
            "push rbp",
            "push rbx",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            
            // 現在のRSPを保存
            "mov [{}], rsp",
            
            // 次のRSPをロード
            "mov rsp, [{}]",
            
            // 次のコンテキストを復元
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rbx",
            "pop rbp",
            
            in(reg) &(*current_impl).kernel_rsp,
            in(reg) &(*next_impl).kernel_rsp,
            options(preserves_flags)
        );
    }
} 