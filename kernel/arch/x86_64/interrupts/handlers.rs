//! IRQ割り込みハンドラ
//!
//! IRQ 0-15の割り込みハンドラを実装します。

use x86_64::structures::idt::InterruptStackFrame;
use crate::arch::x86_64::interrupts::pic;
use crate::println;

/// IRQ 0: システムタイマー割り込みハンドラ
pub extern "x86-interrupt" fn irq0_handler(stack_frame: InterruptStackFrame) {
    // タイマー割り込み処理（現在は最小限の実装）
    
    // 割り込み完了を通知
    unsafe {
        pic::send_eoi(0);
    }
}

/// IRQ 1: キーボード割り込みハンドラ
pub extern "x86-interrupt" fn irq1_handler(stack_frame: InterruptStackFrame) {
    use x86_64::instructions::port::Port;
    
    // PS/2キーボードからデータを読み取り
    let mut keyboard_port = Port::new(0x60);
    let scancode: u8 = unsafe { keyboard_port.read() };
    
    // スキャンコードを処理（後でキーボードドライバが処理）
    crate::device::ps2::keyboard::handle_scancode(scancode);
    
    // 割り込み完了を通知
    unsafe {
        pic::send_eoi(1);
    }
}

/// IRQ 2: カスケードハンドラ（スレーブPICへの接続）
pub extern "x86-interrupt" fn irq2_handler(stack_frame: InterruptStackFrame) {
    // 通常はこの割り込みは発生しない（PIC内部で処理される）
    println!("IRQ 2: Cascade interrupt");
    
    // 割り込み完了を通知
    unsafe {
        pic::send_eoi(2);
    }
}

/// IRQ 3: シリアルポート2割り込みハンドラ
pub extern "x86-interrupt" fn irq3_handler(stack_frame: InterruptStackFrame) {
    // シリアルポート2の割り込み処理
    
    // 割り込み完了を通知
    unsafe {
        pic::send_eoi(3);
    }
}

/// IRQ 4: シリアルポート1割り込みハンドラ
pub extern "x86-interrupt" fn irq4_handler(stack_frame: InterruptStackFrame) {
    // シリアルポート1の割り込み処理
    
    // 割り込み完了を通知
    unsafe {
        pic::send_eoi(4);
    }
}

/// IRQ 5: 汎用割り込みハンドラ（通常はLPT2を使用）
pub extern "x86-interrupt" fn irq5_handler(stack_frame: InterruptStackFrame) {
    println!("IRQ 5: LPT2/Sound Card");
    
    // 割り込み完了を通知
    unsafe {
        pic::send_eoi(5);
    }
}

/// IRQ 6: フロッピーディスク割り込みハンドラ
pub extern "x86-interrupt" fn irq6_handler(stack_frame: InterruptStackFrame) {
    println!("IRQ 6: Floppy Disk");
    
    // 割り込み完了を通知
    unsafe {
        pic::send_eoi(6);
    }
}

/// IRQ 7: 汎用割り込みハンドラ（通常はLPT1を使用）
pub extern "x86-interrupt" fn irq7_handler(stack_frame: InterruptStackFrame) {
    println!("IRQ 7: LPT1/Spurious Interrupt");
    
    // スプリアス割り込みの場合はEOIを送らない
    // マスタPICのIRQ7がスプリアス割り込みかどうかをチェック
    if !pic::is_spurious_irq(7) {
        unsafe {
            pic::send_eoi(7);
        }
    }
}

/// IRQ 8: リアルタイムクロック（RTC）割り込みハンドラ
pub extern "x86-interrupt" fn irq8_handler(stack_frame: InterruptStackFrame) {
    // RTCの割り込み処理
    
    // 割り込み完了を通知（スレーブPICのIRQ）
    unsafe {
        pic::send_eoi(8);
    }
}

/// IRQ 9: リダイレクトCMOS割り込みハンドラ
pub extern "x86-interrupt" fn irq9_handler(stack_frame: InterruptStackFrame) {
    println!("IRQ 9: ACPI/Free IRQ");
    
    // 割り込み完了を通知
    unsafe {
        pic::send_eoi(9);
    }
}

/// IRQ 10: 予約済み割り込みハンドラ
pub extern "x86-interrupt" fn irq10_handler(stack_frame: InterruptStackFrame) {
    println!("IRQ 10: Free IRQ");
    
    // 割り込み完了を通知
    unsafe {
        pic::send_eoi(10);
    }
}

/// IRQ 11: 予約済み割り込みハンドラ
pub extern "x86-interrupt" fn irq11_handler(stack_frame: InterruptStackFrame) {
    println!("IRQ 11: Free IRQ");
    
    // 割り込み完了を通知
    unsafe {
        pic::send_eoi(11);
    }
}

/// IRQ 12: PS/2マウス割り込みハンドラ
pub extern "x86-interrupt" fn irq12_handler(stack_frame: InterruptStackFrame) {
    use x86_64::instructions::port::Port;
    
    // PS/2マウスからデータを読み取り
    let mut mouse_port = Port::new(0x60);
    let data: u8 = unsafe { mouse_port.read() };
    
    // マウスデータを処理（後でマウスドライバが処理）
    crate::device::ps2::mouse::handle_mouse_data(data);
    
    // 割り込み完了を通知
    unsafe {
        pic::send_eoi(12);
    }
}

/// IRQ 13: FPU/Coprocessor割り込みハンドラ
pub extern "x86-interrupt" fn irq13_handler(stack_frame: InterruptStackFrame) {
    println!("IRQ 13: FPU/Coprocessor");
    
    // 割り込み完了を通知
    unsafe {
        pic::send_eoi(13);
    }
}

/// IRQ 14: プライマリATAチャネル割り込みハンドラ
pub extern "x86-interrupt" fn irq14_handler(stack_frame: InterruptStackFrame) {
    // ATA割り込み処理
    crate::device::ata::handle_primary_irq();
    
    // 割り込み完了を通知
    unsafe {
        pic::send_eoi(14);
    }
}

/// IRQ 15: セカンダリATAチャネル割り込みハンドラ
pub extern "x86-interrupt" fn irq15_handler(stack_frame: InterruptStackFrame) {
    // ATA割り込み処理
    crate::device::ata::handle_secondary_irq();
    
    // スプリアス割り込みの場合はEOIを送らない
    // スレーブPICのIRQ7（IRQ15）がスプリアス割り込みかどうかをチェック
    if !pic::is_spurious_irq(15) {
        unsafe {
            pic::send_eoi(15);
        }
    }
} 