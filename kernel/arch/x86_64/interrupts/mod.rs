//! 割り込み処理
//!
//! x86_64アーキテクチャの割り込み処理に関する機能を提供します。
//! これには、割り込みコントローラ（PIC, APIC）の初期化、
//! 割り込みハンドラの設定、割り込みの有効化・無効化などが含まれます。

pub mod pic;
pub mod apic;
pub mod handlers;

use crate::arch::x86_64::idt;
use crate::println;

/// 割り込みの初期化
pub fn init() {
    println!("Initializing interrupt controllers...");
    
    // PICを初期化
    pic::init();
    
    // 高度な割り込みコントローラがサポートされているか確認
    if apic::is_apic_available() {
        println!("APIC is available");
        
        // Local APICを初期化
        match apic::init_local_apic() {
            Ok(_) => {
                // PICの割り込みをすべてマスク
                pic::mask_all();
                println!("Local APIC initialized, PIC masked");
                
                // I/O APICの初期化（複雑なのでエラーは無視）
                let _ = apic::init_io_apic();
            }
            Err(e) => {
                println!("Failed to initialize Local APIC: {}", e);
                println!("Falling back to PIC");
                // PICフォールバック: 必要なIRQを有効化
                pic::enable_irq(1); // キーボード
                pic::enable_irq(12); // PS/2マウス
            }
        }
    } else {
        println!("APIC not available, using PIC");
        // PICを使用: 必要なIRQを有効化
        pic::enable_irq(1); // キーボード
        pic::enable_irq(12); // PS/2マウス
    }
    
    // 割り込みを有効化
    idt::enable_interrupts();
    println!("Interrupts enabled");
}

/// 割り込みを無効化（クリティカルセクション用）
pub fn disable() {
    idt::disable_interrupts();
}

/// 割り込みを有効化
pub fn enable() {
    idt::enable_interrupts();
}

/// 割り込みが有効かどうかを確認
pub fn are_enabled() -> bool {
    idt::are_interrupts_enabled()
}

/// 割り込みを無効にして関数を実行
pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R
{
    idt::without_interrupts(f)
} 