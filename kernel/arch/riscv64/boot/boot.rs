// AetherOS RISC-V ブートコード
//
// RISC-V 64ビットアーキテクチャ用の起動処理を実装

use crate::arch::riscv64::mm::PageTable;
use crate::bootloader::BootInfo;
use core::arch::asm;

#[link_section = ".text.boot"]
#[no_mangle]
#[naked]
pub unsafe extern "C" fn _start() -> ! {
    // ASMでブートストラップを実装
    asm!(
        // スタックポインタの設定
        "la sp, boot_stack_top",
        
        // ハートIDを取得してa0レジスタに保存
        "csrr a0, mhartid",
        
        // ハートID 0のみが初期化処理を行う
        "bnez a0, 3f",
        
        // BSS領域をクリア
        "la a1, bss_start",
        "la a2, bss_end",
        "bgeu a1, a2, 2f",
        "1:",
        "sd zero, (a0)",
        "addi a0, a0, 8",
        "bltu a0, a2, 1b",
        "2:",
        
        // ハードウェア初期化関数を呼び出す
        "call setup_hardware",
        
        // カーネルモードに移行
        "call switch_to_supervisor_mode",
        
        // 他のハートの待機ループ
        "3:",
        "wfi",
        "j 3b",
        
        options(noreturn)
    );
}

/// スーパーバイザモードに切り替え
#[no_mangle]
pub unsafe extern "C" fn switch_to_supervisor_mode() -> ! {
    // M-modeからS-modeへの切り替え処理
    let satp_value = PageTable::create_initial_mapping();
    
    // スーパーバイザモードに切り替えるための準備
    // MPPをスーパーバイザモードに設定
    let mut mstatus: usize;
    asm!("csrr {}, mstatus", out(reg) mstatus);
    mstatus &= !0x1800;
    mstatus |= 0x800; // MPP = 01 (Supervisor)
    asm!("csrw mstatus, {}", in(reg) mstatus);
    
    // MEPCにカーネルエントリポイントを設定
    asm!("csrw mepc, {}", in(reg) supervisor_entry as usize);
    
    // 割り込み設定
    asm!("csrw mie, {}", in(reg) 0);
    
    // スーパーバイザモードに切り替え
    asm!("mret", options(noreturn));
}

/// スーパーバイザモードでの初期化処理
#[no_mangle]
pub extern "C" fn supervisor_entry() -> ! {
    // ブート情報の構築
    let boot_info = BootInfo {
        memory_map_addr: 0,
        memory_map_size: 0,
        framebuffer_addr: 0,
        framebuffer_width: 0,
        framebuffer_height: 0,
        framebuffer_pitch: 0,
        command_line: b"",
        ramdisk_addr: 0,
        ramdisk_size: 0,
        architecture: 2, // RISC-V
    };
    
    // カーネルメイン関数を呼び出し
    unsafe {
        crate::kernel_main(&boot_info);
    }
}

/// ハードウェア初期化
#[no_mangle]
pub extern "C" fn setup_hardware() {
    // クロック初期化
    init_clocks();
    
    // PLIC (Platform-Level Interrupt Controller) の初期化
    init_plic();
    
    // メモリ検出
    detect_memory();
}

// 基本的なクロック初期化
fn init_clocks() {
    // RISC-V SoC固有のクロック初期化処理
}

// PLIC初期化
fn init_plic() {
    // 割り込みコントローラの初期化
}

// メモリ検出
fn detect_memory() {
    // 利用可能なメモリ範囲を検出
}

// ブートスタックはリンカスクリプトで定義された領域を使用
extern "C" {
    static boot_stack_top: u8;
    static bss_start: u8;
    static bss_end: u8;
} 