//! プログラマブル割り込みコントローラ (PIC)
//!
//! 8259 PICを初期化し、IRQを管理します。
//! PICは従来のx86アーキテクチャの割り込みコントローラで、
//! 現代のシステムではAPICに置き換えられつつありますが、
//! 互換性のために残されています。

use x86_64::instructions::port::Port;
use core::sync::atomic::{AtomicU16, Ordering};
use spin::Mutex;

// PIC I/Oポート番号
const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

// PICコマンド
const ICW1_ICW4: u8 = 0x01;      // ICW4が存在する
const ICW1_SINGLE: u8 = 0x02;    // シングルモード
const ICW1_INTERVAL4: u8 = 0x04; // コール間隔4
const ICW1_LEVEL: u8 = 0x08;     // レベルトリガーモード
const ICW1_INIT: u8 = 0x10;      // 初期化コマンド

const ICW4_8086: u8 = 0x01;      // 8086/88モード
const ICW4_AUTO: u8 = 0x02;      // 自動EOIモード
const ICW4_BUF_SLAVE: u8 = 0x08; // バッファードモード（スレーブ）
const ICW4_BUF_MASTER: u8 = 0x0C; // バッファードモード（マスター）
const ICW4_SFNM: u8 = 0x10;       // 特殊完全入れ子モード

// PICコマンド
const PIC_READ_IRR: u8 = 0x0A;    // 割り込み要求レジスタ読み取り
const PIC_READ_ISR: u8 = 0x0B;    // サービス中レジスタ読み取り
const PIC_EOI: u8 = 0x20;         // End-of-Interrupt

// 割り込みベクトルの開始点（IDTのオフセット）
const PIC1_OFFSET: u8 = 32;
const PIC2_OFFSET: u8 = 40;

// 現在の割り込みマスク
static IRQ_MASK: AtomicU16 = AtomicU16::new(0xFFFF); // 初期状態ですべて無効

// PICポートの安全な操作のためのMutex
lazy_static::lazy_static! {
    static ref PIC_PORTS: Mutex<PicPorts> = Mutex::new(PicPorts::new());
}

// PICポート構造体
struct PicPorts {
    pic1_command: Port<u8>,
    pic1_data: Port<u8>,
    pic2_command: Port<u8>,
    pic2_data: Port<u8>,
}

impl PicPorts {
    const fn new() -> Self {
        PicPorts {
            pic1_command: Port::new(PIC1_COMMAND),
            pic1_data: Port::new(PIC1_DATA),
            pic2_command: Port::new(PIC2_COMMAND),
            pic2_data: Port::new(PIC2_DATA),
        }
    }
}

/// PICを初期化する
pub fn init() {
    let mut ports = PIC_PORTS.lock();
    
    // 現在のマスク値を保存
    let mask1: u8;
    let mask2: u8;
    
    unsafe {
        mask1 = ports.pic1_data.read();
        mask2 = ports.pic2_data.read();
    }
    
    // ICW1: 初期化開始
    unsafe {
        ports.pic1_command.write(ICW1_INIT | ICW1_ICW4);
        io_wait();
        ports.pic2_command.write(ICW1_INIT | ICW1_ICW4);
        io_wait();
        
        // ICW2: ベクトルオフセット
        ports.pic1_data.write(PIC1_OFFSET);
        io_wait();
        ports.pic2_data.write(PIC2_OFFSET);
        io_wait();
        
        // ICW3: カスケード設定
        // マスターPICにスレーブPICが接続されているIRQラインを設定（ビット2 = IRQ2）
        ports.pic1_data.write(4);
        io_wait();
        // スレーブPICのカスケードID設定（ID = 2）
        ports.pic2_data.write(2);
        io_wait();
        
        // ICW4: モード設定
        ports.pic1_data.write(ICW4_8086);
        io_wait();
        ports.pic2_data.write(ICW4_8086);
        io_wait();
        
        // 元のマスクを復元
        ports.pic1_data.write(mask1);
        io_wait();
        ports.pic2_data.write(mask2);
        io_wait();
    }
    
    // デフォルトの割り込みマスクを設定
    set_default_mask();
}

/// I/O待機のための短い遅延を挿入する
fn io_wait() {
    // 未使用ポートに書き込むことで遅延を発生させる
    unsafe {
        Port::new(0x80).write(0_u8);
    }
}

/// デフォルトの割り込みマスクを設定する
fn set_default_mask() {
    // すべての割り込みをマスク（無効化）する
    // 必要に応じて個別のIRQを有効にする
    disable_all_irqs();
}

/// 指定したIRQを有効にする
pub fn enable_irq(irq: u8) {
    let irq = irq & 0xF; // IRQ番号を0-15に制限
    
    let mut mask = IRQ_MASK.load(Ordering::Relaxed);
    mask &= !(1 << irq);
    IRQ_MASK.store(mask, Ordering::Relaxed);
    
    apply_mask();
}

/// 指定したIRQを無効にする
pub fn disable_irq(irq: u8) {
    let irq = irq & 0xF; // IRQ番号を0-15に制限
    
    let mut mask = IRQ_MASK.load(Ordering::Relaxed);
    mask |= 1 << irq;
    IRQ_MASK.store(mask, Ordering::Relaxed);
    
    apply_mask();
}

/// すべてのIRQを有効にする
pub fn enable_all_irqs() {
    IRQ_MASK.store(0, Ordering::Relaxed);
    apply_mask();
}

/// すべてのIRQを無効にする
pub fn disable_all_irqs() {
    IRQ_MASK.store(0xFFFF, Ordering::Relaxed);
    apply_mask();
}

/// 現在の割り込みマスクを適用する
fn apply_mask() {
    let mask = IRQ_MASK.load(Ordering::Relaxed);
    let mut ports = PIC_PORTS.lock();
    
    unsafe {
        ports.pic1_data.write((mask & 0xFF) as u8);
        io_wait();
        ports.pic2_data.write((mask >> 8) as u8);
        io_wait();
    }
}

/// End-of-Interrupt信号を送信する
///
/// # Safety
///
/// この関数は割り込みハンドラの最後に呼び出す必要があり、
/// 不適切な使用はシステムクラッシュを引き起こす可能性があります。
pub unsafe fn send_eoi(irq: u8) {
    let irq = irq & 0xF; // IRQ番号を0-15に制限
    
    let mut ports = PIC_PORTS.lock();
    
    // IRQ 8-15はスレーブPICを経由するため、
    // スレーブPICにもEOIを送信する必要がある
    if irq >= 8 {
        ports.pic2_command.write(PIC_EOI);
        io_wait();
    }
    
    // マスターPICに常にEOIを送信
    ports.pic1_command.write(PIC_EOI);
}

/// 割り込み要求レジスタ（IRR）を読み取る
fn read_irr() -> u16 {
    let mut ports = PIC_PORTS.lock();
    
    unsafe {
        ports.pic1_command.write(PIC_READ_IRR);
        ports.pic2_command.write(PIC_READ_IRR);
        io_wait();
        
        let irr1 = ports.pic1_command.read();
        let irr2 = ports.pic2_command.read();
        
        return (irr1 as u16) | ((irr2 as u16) << 8);
    }
}

/// サービス中レジスタ（ISR）を読み取る
fn read_isr() -> u16 {
    let mut ports = PIC_PORTS.lock();
    
    unsafe {
        ports.pic1_command.write(PIC_READ_ISR);
        ports.pic2_command.write(PIC_READ_ISR);
        io_wait();
        
        let isr1 = ports.pic1_command.read();
        let isr2 = ports.pic2_command.read();
        
        return (isr1 as u16) | ((isr2 as u16) << 8);
    }
}

/// 指定したIRQがスプリアス（偽の）割り込みかどうかを判定する
pub fn is_spurious_irq(irq: u8) -> bool {
    let irq = irq & 0xF; // IRQ番号を0-15に制限
    
    // IRQがIRQ7またはIRQ15（PICの最後のIRQ）でない場合は確実にスプリアスではない
    if irq != 7 && irq != 15 {
        return false;
    }
    
    // ISRを読み取り、割り込みビットが設定されているかチェック
    let isr = read_isr();
    let bit = 1 << irq;
    
    // IRQ7の場合はマスターPICのISRビット、IRQ15の場合はスレーブPICのISRビットをチェック
    if (isr & bit) == 0 {
        // ISRビットが設定されていない場合はスプリアス
        return true;
    }
    
    // ISRビットが設定されている場合は本物の割り込み
    false
}

/// PICをマスク（すべての割り込みを無効化）する
///
/// APIモード使用時に呼び出される
pub fn mask_all() {
    let mut ports = PIC_PORTS.lock();
    
    unsafe {
        // すべての割り込みをマスク
        ports.pic1_data.write(0xFF);
        io_wait();
        ports.pic2_data.write(0xFF);
        io_wait();
    }
}

/// PICが使用する割り込みベクターの範囲をチェック
/// 指定されたベクター番号がPICの範囲内かどうかを返す
pub fn is_pic_vector(vector: u8) -> bool {
    vector >= PIC1_OFFSET && vector < PIC1_OFFSET + 16
}

/// IRQ番号をIDTベクター番号に変換
pub fn irq_to_vector(irq: u8) -> u8 {
    let irq = irq & 0xF; // IRQ番号を0-15に制限
    
    if irq < 8 {
        PIC1_OFFSET + irq
    } else {
        PIC2_OFFSET + (irq - 8)
    }
} 