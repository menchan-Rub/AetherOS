//! 割り込みディスクリプタテーブル（IDT）
//!
//! x86_64アーキテクチャのIDTを初期化・管理します。
//! IDTは例外処理や割り込み処理のエントリポイントを定義します。

use core::sync::atomic::{AtomicBool, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use x86_64::registers::control::Cr2;
use crate::arch::x86_64::gdt;
use crate::arch::x86_64::interrupts::apic;
use crate::arch::x86_64::interrupts::handlers;
use crate::println;

/// CPU例外の種類を表す列挙型
#[derive(Debug, Clone, Copy)]
pub enum ExceptionType {
    /// 0 - 除算エラー
    DivideError,
    /// 1 - デバッグ例外
    DebugException,
    /// 2 - NMI（ノンマスカブル割り込み）
    NMI,
    /// 3 - ブレークポイント
    Breakpoint,
    /// 4 - オーバーフロー
    Overflow,
    /// 5 - BOUND命令の範囲外
    BoundRangeExceeded,
    /// 6 - 無効オペコード
    InvalidOpcode,
    /// 7 - デバイスが利用不可
    DeviceNotAvailable,
    /// 8 - ダブルフォルト
    DoubleFault,
    /// 9 - コプロセッサセグメントオーバーラン
    CoprocessorSegmentOverrun,
    /// 10 - 無効なTSS
    InvalidTSS,
    /// 11 - セグメント不在
    SegmentNotPresent,
    /// 12 - スタックセグメントフォルト
    StackSegmentFault,
    /// 13 - 一般保護例外
    GeneralProtectionFault,
    /// 14 - ページフォルト
    PageFault,
    /// 16 - x87 FPU浮動小数点エラー
    FloatingPointError,
    /// 17 - アラインメントチェック
    AlignmentCheck,
    /// 18 - マシンチェック
    MachineCheck,
    /// 19 - SIMD浮動小数点例外
    SimdFloatingPointException,
    /// 20 - 仮想化例外
    VirtualizationException,
    /// 21 - コントロールプロテクション例外
    ControlProtectionException,
}

/// 割り込みが有効かどうかを保存する変数
static INTERRUPTS_ENABLED: AtomicBool = AtomicBool::new(false);

/// エラーコードを持つかどうかを返す
pub fn has_error_code(exception: ExceptionType) -> bool {
    use ExceptionType::*;
    match exception {
        DoubleFault | InvalidTSS | SegmentNotPresent | StackSegmentFault |
        GeneralProtectionFault | PageFault | AlignmentCheck => true,
        _ => false,
    }
}

// IDTの定義（遅延初期化）
lazy_static! {
    /// 割り込みディスクリプタテーブル
    static ref IDT: Mutex<InterruptDescriptorTable> = {
        let mut idt = InterruptDescriptorTable::new();
        
        // CPU例外ハンドラの設定
        idt.divide_error.set_handler_fn(divide_error_handler);
        idt.debug.set_handler_fn(debug_handler);
        idt.non_maskable_interrupt.set_handler_fn(nmi_handler)
            .set_stack_index(gdt::NMI_IST_INDEX);
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.overflow.set_handler_fn(overflow_handler);
        idt.bound_range_exceeded.set_handler_fn(bound_range_exceeded_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        idt.device_not_available.set_handler_fn(device_not_available_handler);
        
        unsafe {
            idt.double_fault.set_handler_fn(double_fault_handler)
                .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        }
        
        idt.invalid_tss.set_handler_fn(invalid_tss_handler);
        idt.segment_not_present.set_handler_fn(segment_not_present_handler);
        
        unsafe {
            idt.stack_segment_fault.set_handler_fn(stack_segment_fault_handler)
                .set_stack_index(gdt::STACK_FAULT_IST_INDEX);
        }
        
        unsafe {
            idt.general_protection_fault.set_handler_fn(general_protection_fault_handler)
                .set_stack_index(gdt::GENERAL_PROTECTION_FAULT_IST_INDEX);
        }
        
        unsafe {
            idt.page_fault.set_handler_fn(page_fault_handler)
                .set_stack_index(gdt::PAGE_FAULT_IST_INDEX);
        }
        
        idt.x87_floating_point.set_handler_fn(floating_point_error_handler);
        idt.alignment_check.set_handler_fn(alignment_check_handler);
        idt.machine_check.set_handler_fn(machine_check_handler);
        idt.simd_floating_point.set_handler_fn(simd_floating_point_exception_handler);
        idt.virtualization.set_handler_fn(virtualization_exception_handler);
        
        // 外部割り込みハンドラの設定（IRQ 0-15）
        idt[32].set_handler_fn(handlers::irq0_handler); // タイマー割り込み
        idt[33].set_handler_fn(handlers::irq1_handler); // キーボード割り込み
        idt[34].set_handler_fn(handlers::irq2_handler);
        idt[35].set_handler_fn(handlers::irq3_handler);
        idt[36].set_handler_fn(handlers::irq4_handler);
        idt[37].set_handler_fn(handlers::irq5_handler);
        idt[38].set_handler_fn(handlers::irq6_handler);
        idt[39].set_handler_fn(handlers::irq7_handler);
        idt[40].set_handler_fn(handlers::irq8_handler); // リアルタイムクロック
        idt[41].set_handler_fn(handlers::irq9_handler);
        idt[42].set_handler_fn(handlers::irq10_handler);
        idt[43].set_handler_fn(handlers::irq11_handler);
        idt[44].set_handler_fn(handlers::irq12_handler); // PS/2マウス
        idt[45].set_handler_fn(handlers::irq13_handler);
        idt[46].set_handler_fn(handlers::irq14_handler); // プライマリATA
        idt[47].set_handler_fn(handlers::irq15_handler); // セカンダリATA
        
        // APICタイマー割り込み（例：ベクタ番号240）
        idt[240].set_handler_fn(apic::timer_handler);
        
        // スプリアス割り込み（例：ベクタ番号255）
        idt[255].set_handler_fn(apic::spurious_handler);
        
        Mutex::new(idt)
    };
}

// 以下、各例外ハンドラの実装

/// 0 - 除算エラーハンドラ
extern "x86-interrupt" fn divide_error_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: DIVIDE ERROR\n{:#?}", stack_frame);
}

/// 1 - デバッグ例外ハンドラ
extern "x86-interrupt" fn debug_handler(stack_frame: InterruptStackFrame) {
    println!("EXCEPTION: DEBUG\n{:#?}", stack_frame);
}

/// 2 - NMI（ノンマスカブル割り込み）ハンドラ
extern "x86-interrupt" fn nmi_handler(stack_frame: InterruptStackFrame) {
    println!("EXCEPTION: NMI\n{:#?}", stack_frame);
}

/// 3 - ブレークポイントハンドラ
extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

/// 4 - オーバーフローハンドラ
extern "x86-interrupt" fn overflow_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: OVERFLOW\n{:#?}", stack_frame);
}

/// 5 - BOUND命令の範囲外ハンドラ
extern "x86-interrupt" fn bound_range_exceeded_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: BOUND RANGE EXCEEDED\n{:#?}", stack_frame);
}

/// 6 - 無効オペコードハンドラ
extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: INVALID OPCODE\n{:#?}", stack_frame);
}

/// 7 - デバイスが利用不可ハンドラ
extern "x86-interrupt" fn device_not_available_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: DEVICE NOT AVAILABLE\n{:#?}", stack_frame);
}

/// 8 - ダブルフォルトハンドラ
extern "x86-interrupt" fn double_fault_handler(stack_frame: InterruptStackFrame, error_code: u64) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT (error code: {})\n{:#?}", error_code, stack_frame);
}

/// 10 - 無効なTSSハンドラ
extern "x86-interrupt" fn invalid_tss_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    panic!("EXCEPTION: INVALID TSS (error code: {})\n{:#?}", error_code, stack_frame);
}

/// 11 - セグメント不在ハンドラ
extern "x86-interrupt" fn segment_not_present_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    panic!("EXCEPTION: SEGMENT NOT PRESENT (error code: {})\n{:#?}", error_code, stack_frame);
}

/// 12 - スタックセグメントフォルトハンドラ
extern "x86-interrupt" fn stack_segment_fault_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    panic!("EXCEPTION: STACK SEGMENT FAULT (error code: {})\n{:#?}", error_code, stack_frame);
}

/// 13 - 一般保護例外ハンドラ
extern "x86-interrupt" fn general_protection_fault_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    panic!("EXCEPTION: GENERAL PROTECTION FAULT (error code: {})\n{:#?}", error_code, stack_frame);
}

/// 14 - ページフォルトハンドラ
extern "x86-interrupt" fn page_fault_handler(stack_frame: InterruptStackFrame, error_code: PageFaultErrorCode) {
    println!("EXCEPTION: PAGE FAULT");
    println!("Accessed Address: {:?}", Cr2::read());
    println!("Error Code: {:?}", error_code);
    println!("{:#?}", stack_frame);
    
    // ページフォルトの処理（MMUモジュールで処理できるか試みる）
    // 処理できなければパニック
    panic!("Unhandled page fault");
}

/// 16 - x87 FPU浮動小数点エラーハンドラ
extern "x86-interrupt" fn floating_point_error_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: FLOATING POINT ERROR\n{:#?}", stack_frame);
}

/// 17 - アラインメントチェックハンドラ
extern "x86-interrupt" fn alignment_check_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    panic!("EXCEPTION: ALIGNMENT CHECK (error code: {})\n{:#?}", error_code, stack_frame);
}

/// 18 - マシンチェックハンドラ
extern "x86-interrupt" fn machine_check_handler(stack_frame: InterruptStackFrame) -> ! {
    panic!("EXCEPTION: MACHINE CHECK\n{:#?}", stack_frame);
}

/// 19 - SIMD浮動小数点例外ハンドラ
extern "x86-interrupt" fn simd_floating_point_exception_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: SIMD FLOATING POINT EXCEPTION\n{:#?}", stack_frame);
}

/// 20 - 仮想化例外ハンドラ
extern "x86-interrupt" fn virtualization_exception_handler(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: VIRTUALIZATION EXCEPTION\n{:#?}", stack_frame);
}

/// IDTを初期化する
pub fn init_idt() {
    IDT.lock().load();
}

/// 割り込みを有効にする
pub fn enable_interrupts() {
    if !INTERRUPTS_ENABLED.load(Ordering::Relaxed) {
        unsafe { x86_64::instructions::interrupts::enable(); }
        INTERRUPTS_ENABLED.store(true, Ordering::Relaxed);
    }
}

/// 割り込みを無効にする
pub fn disable_interrupts() {
    if INTERRUPTS_ENABLED.load(Ordering::Relaxed) {
        unsafe { x86_64::instructions::interrupts::disable(); }
        INTERRUPTS_ENABLED.store(false, Ordering::Relaxed);
    }
}

/// 割り込みが有効かどうかを返す
pub fn are_interrupts_enabled() -> bool {
    INTERRUPTS_ENABLED.load(Ordering::Relaxed)
}

/// 他の割り込みをすべて無効にして指定した処理を行う
/// クリティカルセクション用
pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R
{
    x86_64::instructions::interrupts::without_interrupts(f)
} 