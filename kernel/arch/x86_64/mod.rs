// AetherOS x86_64アーキテクチャサポート
//
// x86_64アーキテクチャ固有の機能を実装します。

pub mod boot;       // ブート関連コード
pub mod cpu;        // CPU固有コード
pub mod interrupts; // 割り込み管理
pub mod mm;         // メモリ管理
pub mod debug;      // デバッグサポート
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
use crate::arch::ArchInit;

/// x86_64 XSAVE Area (FPU/SIMD/AVX状態保存用)
/// Intel SDM Vol 1, Chapter 13 XSAVE Feature Set
/// 少なくとも512バイトが必要（XSAVE Legacy Region）。AVX有効時はさらに256バイト。
/// AVX-512有効時はさらに大きな領域が必要になる。
/// ここでは基本的なXSAVE Legacy + AVX (FXSAVE + YMMH) を想定し、
/// 512 (FXSAVE) + 256 (YMM_Hi128 * 16 / 16) = 768バイト。
/// しかし、アライメントや将来の拡張性を考慮し、余裕を持ったサイズにするか、
/// CPUIDで必要なサイズを確認して動的に確保するのが望ましい。
/// 一旦、固定サイズで定義するが、実際にはcpuidで確認したサイズに基づき確保すべき。
#[repr(C, align(64))] // XSAVE Areaは64バイトアライメントが必要
pub struct XSaveArea {
    data: [u8; 1024], // サイズは将来の拡張やAVX512も考慮して余裕を持たせる (例: 1024)
    // cpuid.(eax=0xD,ecx=0):ebx で必要なサイズを取得できる
}

impl Default for XSaveArea {
    fn default() -> Self {
        XSaveArea { data: [0; 1024] }
    }
}

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
    
    /// FPU/SIMD/AVX状態（XSAVEエリア）
    /// 64バイトアライメントで確保されたXSAVE/FXSAVE互換領域へのポインタ。
    /// CPUID経由で必要なサイズを確認し、適切に割り当てる必要がある。
    xsave_area: *mut XSaveArea,
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
    cpu::init();
    interrupts::init();
    mm::init_memory(); 
    debug::init();
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
    
    let cpu_count = detect_cpu_count();
    CPU_COUNT.store(cpu_count, Ordering::SeqCst);
    
    // シリアル出力には crate::core::debug::serial_println を使用
    crate::core::debug::serial_println!("x86_64アーキテクチャ初期化完了: {}コア検出", cpu_count);
}

/// CPUコア数を検出
fn detect_cpu_count() -> usize {
    acpi::get_cpu_count().unwrap_or(1)
}

/// CPUコア数を取得
pub fn get_cpu_count() -> usize {
    CPU_COUNT.load(Ordering::SeqCst)
}

/// 現在のCPU IDを取得
pub fn get_current_cpu_id() -> usize {
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
    unsafe {
        core::arch::asm!(
            "mov rsp, {}",
            "xor rbp, rbp", 
            "ret",          
            in(reg) stack_top,
            options(noreturn)
        );
    }
}

/// 現在のスレッドコンテキストを保存し、次のスレッドコンテキストを復元
pub fn context_switch(current: *mut ThreadContext, next: *mut ThreadContext) {
    unsafe {
        core::hint::spin_loop(); 
    }
}

/// アイドル状態。割り込みを待ち続ける。
pub fn idle() -> ! {
    loop {
        unsafe {
            core::arch::asm!("sti"); 
            core::arch::asm!("hlt"); 
            core::arch::asm!("cli"); 
        }
    }
}

pub struct x86_64;

impl ArchInit for x86_64 {
    fn init() {
        self::init(); 
    }

    fn idle() -> ! {
        self::idle(); 
    }
} 