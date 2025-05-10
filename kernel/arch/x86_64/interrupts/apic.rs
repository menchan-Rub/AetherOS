//! Advanced Programmable Interrupt Controller (APIC)
//!
//! LocalAPICとI/O APICを初期化・管理します。
//! 現代のx86_64システムではPICの代わりにAPICが使用されます。

use core::ptr::{read_volatile, write_volatile};
use x86_64::structures::idt::InterruptStackFrame;
use x86_64::registers::model_specific::{Msr, IA32_APIC_BASE};
use x86_64::PhysAddr;
use crate::memory::addr::{phys_to_virt, VirtAddr};
use crate::println;

// Local APICレジスタのオフセット（ベースアドレスからの相対位置）
const LAPIC_ID: u32 = 0x20;             // ローカルAPIC IDレジスタ
const LAPIC_VERSION: u32 = 0x30;        // ローカルAPIC バージョンレジスタ
const LAPIC_TPR: u32 = 0x80;            // タスク優先度レジスタ
const LAPIC_APR: u32 = 0x90;            // 調停優先度レジスタ
const LAPIC_PPR: u32 = 0xA0;            // プロセッサ優先度レジスタ
const LAPIC_EOI: u32 = 0xB0;            // EOIレジスタ
const LAPIC_RRD: u32 = 0xC0;            // リモート読み取りレジスタ
const LAPIC_LDR: u32 = 0xD0;            // 論理的送信先レジスタ
const LAPIC_DFR: u32 = 0xE0;            // 送信先フォーマットレジスタ
const LAPIC_SVR: u32 = 0xF0;            // スプリアス割り込みベクターレジスタ
const LAPIC_ISR: u32 = 0x100;           // サービス中レジスタ
const LAPIC_TMR: u32 = 0x180;           // トリガーモードレジスタ
const LAPIC_IRR: u32 = 0x200;           // 割り込み要求レジスタ
const LAPIC_ESR: u32 = 0x280;           // エラーステータスレジスタ
const LAPIC_ICRL: u32 = 0x300;          // 割り込みコマンドレジスタ（下位）
const LAPIC_ICRH: u32 = 0x310;          // 割り込みコマンドレジスタ（上位）
const LAPIC_TIMER: u32 = 0x320;         // タイマーレジスタ
const LAPIC_THERMAL: u32 = 0x330;       // サーマルレジスタ
const LAPIC_PERF: u32 = 0x340;          // パフォーマンスカウンタレジスタ
const LAPIC_LINT0: u32 = 0x350;         // ローカル割り込み0レジスタ
const LAPIC_LINT1: u32 = 0x360;         // ローカル割り込み1レジスタ
const LAPIC_ERROR: u32 = 0x370;         // エラーレジスタ
const LAPIC_TIMER_ICR: u32 = 0x380;     // タイマー初期カウントレジスタ
const LAPIC_TIMER_CCR: u32 = 0x390;     // タイマー現在カウントレジスタ
const LAPIC_TIMER_DCR: u32 = 0x3E0;     // タイマー分周設定レジスタ

// APIC SVRレジスタのビット
const LAPIC_SVR_ENABLE: u32 = 0x100;    // APICを有効化

// APIC タイマーレジスタのビット
const LAPIC_TIMER_PERIODIC: u32 = 0x20000; // 周期モード
const LAPIC_TIMER_MASKED: u32 = 0x10000;   // タイマーをマスク

// APIC タイマー分周設定レジスタの値
const LAPIC_TIMER_DIV_1: u32 = 0xB;     // 分周なし（1:1）
const LAPIC_TIMER_DIV_2: u32 = 0x0;     // 2で分周
const LAPIC_TIMER_DIV_4: u32 = 0x1;     // 4で分周
const LAPIC_TIMER_DIV_8: u32 = 0x2;     // 8で分周
const LAPIC_TIMER_DIV_16: u32 = 0x3;    // 16で分周
const LAPIC_TIMER_DIV_32: u32 = 0x8;    // 32で分周
const LAPIC_TIMER_DIV_64: u32 = 0x9;    // 64で分周
const LAPIC_TIMER_DIV_128: u32 = 0xA;   // 128で分周

// APIC ICRレジスタのビット
const LAPIC_ICR_DELIVERY_FIXED: u32 = 0x000; // 固定配信モード
const LAPIC_ICR_DELIVERY_INIT: u32 = 0x500;  // INIT配信モード
const LAPIC_ICR_DELIVERY_STARTUP: u32 = 0x600; // STARTUP配信モード
const LAPIC_ICR_LEVEL_ASSERT: u32 = 0x4000;  // レベルアサート
const LAPIC_ICR_DEST_ALL: u32 = 0x80000;     // すべてのCPUに送信
const LAPIC_ICR_DEST_SELF: u32 = 0x40000;    // 自分自身に送信

// APICタイマーのベクタ番号
const APIC_TIMER_VECTOR: u8 = 240;
// スプリアス割り込みのベクタ番号
const APIC_SPURIOUS_VECTOR: u8 = 255;

// ローカルAPICのベースアドレス（仮想アドレス）
static mut LAPIC_BASE: VirtAddr = VirtAddr::new(0);

/// APICが利用可能かどうかを確認
pub fn is_apic_available() -> bool {
    use x86_64::instructions::cpuid::{CpuId, Feature};
    
    // CPUIDでAPICサポートをチェック
    CpuId::new().get_feature_info()
        .map_or(false, |f| f.has_feature(Feature::APIC))
}

/// ローカルAPICを初期化
pub fn init_local_apic() -> Result<(), &'static str> {
    if !is_apic_available() {
        return Err("APIC is not available on this CPU");
    }
    
    // MSRからAPICベースアドレスを取得
    let apic_base_msr = IA32_APIC_BASE.read();
    let apic_base_addr = PhysAddr::new(apic_base_msr & 0xFFFF_F000);
    
    // 物理アドレスを仮想アドレスに変換
    // 注: この変換にはメモリマッピングが必要
    let virt_base = phys_to_virt(apic_base_addr);
    
    unsafe {
        // ローカルAPICのベースアドレスを保存
        LAPIC_BASE = virt_base;
        
        // タスク優先度を0に設定（すべての割り込みを許可）
        write_lapic(LAPIC_TPR, 0);
        
        // スプリアス割り込みベクタを設定し、APICを有効化
        write_lapic(LAPIC_SVR, LAPIC_SVR_ENABLE | APIC_SPURIOUS_VECTOR as u32);
        
        // 論理的送信先レジスタを設定
        write_lapic(LAPIC_LDR, 0x01000000); // CPUを論理的CPU 1に設定
        
        // 送信先フォーマットレジスタを設定（フラットモード）
        write_lapic(LAPIC_DFR, 0xFFFFFFFF);
        
        // LINT0（ローカル割り込み0）を無効化
        write_lapic(LAPIC_LINT0, 0x10000);
        
        // LINT1（ローカル割り込み1、通常はNMI用）を無効化
        write_lapic(LAPIC_LINT1, 0x10000);
        
        // エラー割り込みを設定
        write_lapic(LAPIC_ERROR, 0x10000);
        
        // APIC Timer を設定
        configure_apic_timer();
    }
    
    Ok(())
}

/// ローカルAPICにデータを書き込む
unsafe fn write_lapic(reg: u32, value: u32) {
    let addr = LAPIC_BASE.as_u64() + reg as u64;
    write_volatile(addr as *mut u32, value);
}

/// ローカルAPICからデータを読み取る
unsafe fn read_lapic(reg: u32) -> u32 {
    let addr = LAPIC_BASE.as_u64() + reg as u64;
    read_volatile(addr as *const u32)
}

/// APICタイマーを設定
fn configure_apic_timer() {
    unsafe {
        // タイマーを分周1で設定
        write_lapic(LAPIC_TIMER_DCR, LAPIC_TIMER_DIV_1);
        
        // タイマーを周期モードに設定し、割り込みベクタを指定
        write_lapic(LAPIC_TIMER, LAPIC_TIMER_PERIODIC | APIC_TIMER_VECTOR as u32);
        
        // 初期カウント値を設定（タイマー周期を決定）
        // 実際の実装では、PIT等を使用してカウント値を調整する必要がある
        write_lapic(LAPIC_TIMER_ICR, 10000000); // 適当な値（実際には調整が必要）
    }
}

/// EOI（割り込み完了）信号を送信
pub fn send_eoi() {
    unsafe {
        write_lapic(LAPIC_EOI, 0);
    }
}

/// 指定されたCPUに割り込みを送信
pub fn send_ipi(cpu_id: u8, vector: u8) {
    unsafe {
        // 高位32ビットに送信先CPUを設定
        write_lapic(LAPIC_ICRH, (cpu_id as u32) << 24);
        // 低位32ビットに割り込みベクターとデリバリーモードを設定
        write_lapic(LAPIC_ICRL, vector as u32);
    }
}

/// 現在のCPU ID（APIC ID）を取得
pub fn get_current_cpu_id() -> u8 {
    unsafe {
        (read_lapic(LAPIC_ID) >> 24) as u8
    }
}

/// APICタイマー割り込みハンドラ
pub extern "x86-interrupt" fn timer_handler(_stack_frame: InterruptStackFrame) {
    // タイマー割り込み処理
    // println!("APIC Timer tick");
    
    // EOI信号を送信
    send_eoi();
}

/// APICスプリアス割り込みハンドラ
pub extern "x86-interrupt" fn spurious_handler(_stack_frame: InterruptStackFrame) {
    println!("APIC: Spurious interrupt received");
    // スプリアス割り込みではEOIを送信する必要がない
}

/// I/O APIC を初期化
pub fn init_io_apic() -> Result<(), &'static str> {
    // I/O APICの初期化はさらに複雑であり、MPテーブルやACPIテーブルの解析が必要
    // ここでは実装を省略
    
    Ok(())
} 