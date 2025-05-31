use core::fmt;
// アーキテクチャ依存のI/O関数をインポート
// TODO: このパスはビルドターゲットによって条件付きで変更する必要があるかもしれない
use crate::arch::x86_64::cpu::io::{inb, outb};

const DEFAULT_SERIAL_PORT: u16 = 0x3F8; // COM1

/// シリアルポートを初期化します。
/// ボーレートなどを設定します。
pub fn init_serial_port() {
    init_specific_serial_port(DEFAULT_SERIAL_PORT);
}

/// 指定されたポート番号のシリアルポートを初期化します。
pub fn init_specific_serial_port(port: u16) {
    unsafe {
        // ボーレート設定: 115200 bps (標準的な設定)
        outb(port + 1, 0x00);    // 割り込み無効 (IIR)
        outb(port + 3, 0x80);    // DLAB (Divisor Latch Access Bit) をセット (LCR)
        outb(port + 0, 0x01);    // ボーレート除数の下位バイト (DLL)。115200 / 115200 = 1
        outb(port + 1, 0x00);    // ボーレート除数の上位バイト (DLM)
        outb(port + 3, 0x03);    // 8ビット、ノーパリティ、1ストップビット (8N1) (LCR)
        outb(port + 2, 0xC7);    // FIFO有効化、送受信FIFOクリア、14バイト閾値 (FCR)
        outb(port + 4, 0x0B);    // IRQ有効化、RTS/DTRセット (MCR)
        // ループバックテストのために追加の初期化を行う場合がある
        // outb(port + 4, 0x1E); // Set in loopback mode, test the serial chip
        // outb(port + 0, 0xAE); // Test serial chip (send byte 0xAE and check if serial returns same byte)
        // if inb(port + 0) != 0xAE {
        //     // ループバックテスト失敗 (panicするかエラーを返す)
        // }
        // // 通常モードに戻す
        // outb(port + 4, 0x0F); 
    }
}

/// シリアルポートに1文字出力します。
fn serial_putchar(port: u16, c: u8) {
    unsafe {
        // 送信バッファが空になるまで待機 (LSRのTHREビットが1になるまで)
        while (inb(port + 5) & 0x20) == 0 {}
        outb(port, c); // THRに文字を書き込む
    }
}

/// シリアルポートに文字列を出力します。
/// 改行文字 `\n` は `\r\n` に変換して出力します。
fn serial_puts(port: u16, s: &str) {
    for byte in s.bytes() {
        if byte == b'\n' {
            serial_putchar(port, b'\r');
            serial_putchar(port, b'\n');
        } else if byte == b'\r' {
            // そのまま出力 (CRLFの重複を避けるためLFは追加しない)
            serial_putchar(port, b'\r');
        } else {
            serial_putchar(port, byte);
        }
    }
}

/// シリアルポートへの出力をラップする構造体。
/// `core::fmt::Write` トレイトを実装し、`write!` マクロなどで利用可能にする。
pub struct SerialPort(u16);

impl SerialPort {
    pub fn new(port_address: u16) -> Self {
        SerialPort(port_address)
    }

    pub fn default_com1() -> Self {
        SerialPort(DEFAULT_SERIAL_PORT)
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        serial_puts(self.0, s);
        Ok(())
    }
}

/// シリアルポートに書式指定で出力するマクロ (改行なし)。
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => ($crate::core::debug::serial::_print(format_args!($($arg)*)));
}

/// シリアルポートに書式指定で出力するマクロ (改行あり)。
#[macro_export]
macro_rules! serial_println {
    () => (serial_print!("\n"));
    ($fmt:expr) => (serial_print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (serial_print!(concat!($fmt, "\n"), $($arg)*));
}

/// `serial_print!` マクロから内部的に呼び出される関数。
/// グローバルなシリアルポート（またはデフォルトポート）を使用する。
#[doc(hidden)]
pub(crate) fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    // ここでデフォルトのシリアルポートを取得または初期化する。
    // 簡単のため、毎回COM1を使う。
    // 本格的な実装では、初期化済みのグローバルなSerialPortインスタンスを使うべき。
    let mut writer = SerialPort::default_com1();
    // シリアルポートが初期化されていることを保証する (通常はブート時に一度だけ行う)
    // init_serial_port(); // _printが呼ばれるたびに初期化するのは非効率。
    // 事前に初期化されている前提とするか、OnceCellなどで初期化を保証する。
    writer.write_fmt(args).unwrap();
}

/// デバッグコンソール（シリアルポートなど）を初期化する関数。
/// この関数はカーネルの早い段階で一度だけ呼び出されることを想定。
pub fn init_debug_port() {
    init_serial_port(); // デフォルトのシリアルポートを初期化
    serial_println!("[SERIAL] Debug serial port initialized (COM1 @ 115200 baud).");
} 