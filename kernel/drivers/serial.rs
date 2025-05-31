// シリアルポートドライバ
//
// 16550A UARTシリアルポートデバイスドライバ実装

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use alloc::sync::Arc;
use alloc::vec::Vec;
use super::{DriverInfo, DriverType, DriverInitState};

/// シリアルポートのベースアドレス (I/Oポート)
const COM1_PORT: u16 = 0x3F8;
const COM2_PORT: u16 = 0x2F8;
const COM3_PORT: u16 = 0x3E8;
const COM4_PORT: u16 = 0x2E8;

/// UARTレジスタオフセット
const REG_DATA: u16 = 0;        // データレジスタ (RW)
const REG_INT_ENABLE: u16 = 1;  // 割り込み有効レジスタ (RW)
const REG_INT_ID: u16 = 2;      // 割り込みIDレジスタ (R)
const REG_FIFO_CTRL: u16 = 2;   // FIFOコントロールレジスタ (W)
const REG_LINE_CTRL: u16 = 3;   // ライン制御レジスタ (RW)
const REG_MODEM_CTRL: u16 = 4;  // モデム制御レジスタ (RW)
const REG_LINE_STATUS: u16 = 5; // ラインステータスレジスタ (R)
const REG_MODEM_STATUS: u16 = 6;// モデムステータスレジスタ (R)
const REG_SCRATCH: u16 = 7;     // スクラッチレジスタ (RW)

/// ラインステータスレジスタビット
const LSR_DATA_READY: u8 = 0x01;     // データ受信準備完了
const LSR_OVERRUN_ERROR: u8 = 0x02;  // オーバーランエラー
const LSR_PARITY_ERROR: u8 = 0x04;   // パリティエラー
const LSR_FRAMING_ERROR: u8 = 0x08;  // フレーミングエラー
const LSR_BREAK_INDICATOR: u8 = 0x10;// 中断インジケータ
const LSR_THR_EMPTY: u8 = 0x20;      // 送信ホールディングレジスタ空
const LSR_TRANSMITTER_EMPTY: u8 = 0x40; // 送信シフトレジスタとTHR両方空
const LSR_FIFO_ERROR: u8 = 0x80;     // FIFOエラー

/// シリアルポート列挙型
#[derive(Debug, Clone, Copy)]
pub enum SerialPort {
    Com1,
    Com2,
    Com3,
    Com4,
    Custom(u16),
}

impl SerialPort {
    /// ポートのI/Oアドレスを取得
    pub fn port_address(&self) -> u16 {
        match *self {
            SerialPort::Com1 => COM1_PORT,
            SerialPort::Com2 => COM2_PORT,
            SerialPort::Com3 => COM3_PORT, 
            SerialPort::Com4 => COM4_PORT,
            SerialPort::Custom(addr) => addr,
        }
    }
}

/// シリアルデバイスの設定
#[derive(Debug, Clone, Copy)]
pub struct SerialConfig {
    /// ボーレート
    pub baud_rate: u32,
    /// データビット (5-8)
    pub data_bits: u8,
    /// パリティビット
    pub parity: Parity,
    /// ストップビット
    pub stop_bits: StopBits,
    /// ハードウェアフロー制御
    pub hardware_flow_control: bool,
    /// FIFO有効化
    pub enable_fifo: bool,
    /// 割り込み有効化
    pub enable_interrupts: bool,
}

impl Default for SerialConfig {
    fn default() -> Self {
        Self {
            baud_rate: 115200,
            data_bits: 8,
            parity: Parity::None,
            stop_bits: StopBits::One,
            hardware_flow_control: false,
            enable_fifo: true,
            enable_interrupts: false,
        }
    }
}

/// パリティ設定
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    /// パリティなし
    None,
    /// 奇数パリティ
    Odd,
    /// 偶数パリティ
    Even,
    /// マークパリティ (常に1)
    Mark,
    /// スペースパリティ (常に0)
    Space,
}

/// ストップビット設定
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopBits {
    /// 1ストップビット
    One,
    /// 1.5ストップビット (5ビットデータの場合)
    OnePointFive,
    /// 2ストップビット
    Two,
}

/// シリアルポートドライバ
pub struct SerialDriver {
    /// ポート指定
    port: SerialPort,
    /// ベースポートアドレス
    base_address: u16,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// 現在の設定
    config: Mutex<SerialConfig>,
}

impl SerialDriver {
    /// 新しいシリアルドライバを作成
    pub fn new(port: SerialPort) -> Self {
        let base_address = port.port_address();
        Self {
            port,
            base_address,
            initialized: AtomicBool::new(false),
            config: Mutex::new(SerialConfig::default()),
        }
    }

    /// シリアルポートを初期化
    pub fn initialize(&self, config: SerialConfig) -> Result<(), &'static str> {
        if self.initialized.load(Ordering::SeqCst) {
            return Ok(());
        }

        unsafe {
            // 割り込みを無効化
            self.write_register(REG_INT_ENABLE, 0x00);

            // DLAB（除数ラッチアクセスビット）を設定
            self.write_register(REG_LINE_CTRL, 0x80);

            // ボーレートを設定（除数ラッチ設定）
            let divisor = 115200 / config.baud_rate;
            self.write_register(REG_DATA, (divisor & 0xFF) as u8);
            self.write_register(REG_INT_ENABLE, ((divisor >> 8) & 0xFF) as u8);

            // データビット、パリティ、ストップビットを設定
            let mut line_config: u8 = 0;
            
            // データビット数を設定
            match config.data_bits {
                5 => line_config |= 0x00,
                6 => line_config |= 0x01,
                7 => line_config |= 0x02,
                8 => line_config |= 0x03,
                _ => return Err("無効なデータビット数です"),
            }
            
            // パリティを設定
            match config.parity {
                Parity::None => line_config |= 0x00,
                Parity::Odd => line_config |= 0x08,
                Parity::Even => line_config |= 0x18,
                Parity::Mark => line_config |= 0x28,
                Parity::Space => line_config |= 0x38,
            }
            
            // ストップビットを設定
            match config.stop_bits {
                StopBits::One => line_config |= 0x00,
                StopBits::OnePointFive => line_config |= 0x04, // 5ビットデータの場合のみ
                StopBits::Two => line_config |= 0x04,
            }
            
            // DLAB（除数ラッチアクセスビット）を解除し、ラインコントロールを設定
            self.write_register(REG_LINE_CTRL, line_config);

            // FIFOを有効化（64バイトトリガレベル）
            if config.enable_fifo {
                self.write_register(REG_FIFO_CTRL, 0xC7);
            } else {
                self.write_register(REG_FIFO_CTRL, 0x00);
            }

            // モデム制御レジスタ設定
            let mut modem_config: u8 = 0x03; // RTS/DTR有効化
            if config.hardware_flow_control {
                modem_config |= 0x10; // 自動フロー制御有効化
            }
            self.write_register(REG_MODEM_CTRL, modem_config);

            // 割り込み有効化設定
            if config.enable_interrupts {
                let int_flags = 0x0F; // すべての割り込みを有効化
                self.write_register(REG_INT_ENABLE, int_flags);
            }
        }

        // 現在の設定を保存
        *self.config.lock() = config;
        self.initialized.store(true, Ordering::SeqCst);

        // デバッグ出力
        log::debug!(
            "シリアルポート初期化: {:?}, ボーレート: {}, データビット: {}, パリティ: {:?}, ストップビット: {:?}",
            self.port, config.baud_rate, config.data_bits, config.parity, config.stop_bits
        );

        Ok(())
    }

    /// レジスタから読み取り
    unsafe fn read_register(&self, reg: u16) -> u8 {
        let port = self.base_address + reg;
        let value: u8;
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
        value
    }

    /// レジスタに書き込み
    unsafe fn write_register(&self, reg: u16, value: u8) {
        let port = self.base_address + reg;
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }

    /// シリアルポートが利用可能かテスト
    pub fn test(&self) -> bool {
        unsafe {
            // スクラッチレジスタにテストパターンを書き込み
            self.write_register(REG_SCRATCH, 0x55);
            let v1 = self.read_register(REG_SCRATCH);
            
            self.write_register(REG_SCRATCH, 0xAA);
            let v2 = self.read_register(REG_SCRATCH);
            
            // テストパターンと一致するか確認
            v1 == 0x55 && v2 == 0xAA
        }
    }

    /// 受信バッファに文字があるかチェック
    pub fn can_read(&self) -> bool {
        unsafe {
            let status = self.read_register(REG_LINE_STATUS);
            (status & LSR_DATA_READY) != 0
        }
    }

    /// 送信可能かチェック（送信バッファが空）
    pub fn can_write(&self) -> bool {
        unsafe {
            let status = self.read_register(REG_LINE_STATUS);
            (status & LSR_THR_EMPTY) != 0
        }
    }

    /// 1文字受信（ブロッキング）
    pub fn read_byte(&self) -> u8 {
        // データが利用可能になるまで待機
        while !self.can_read() {
            core::hint::spin_loop();
        }
        
        // データを読み取り
        unsafe { self.read_register(REG_DATA) }
    }

    /// 1文字受信（ノンブロッキング）
    pub fn try_read_byte(&self) -> Option<u8> {
        if self.can_read() {
            Some(unsafe { self.read_register(REG_DATA) })
        } else {
            None
        }
    }

    /// 1文字送信
    pub fn write_byte(&self, byte: u8) {
        // 送信バッファが空くまで待機
        while !self.can_write() {
            core::hint::spin_loop();
        }
        
        // データを送信
        unsafe { self.write_register(REG_DATA, byte) }
    }

    /// 文字列送信
    pub fn write_string(&self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }
    
    /// ラインステータスを取得
    pub fn get_line_status(&self) -> u8 {
        unsafe { self.read_register(REG_LINE_STATUS) }
    }
    
    /// エラーチェック
    pub fn check_errors(&self) -> Option<&'static str> {
        let status = self.get_line_status();
        
        if (status & LSR_OVERRUN_ERROR) != 0 {
            Some("オーバーランエラー")
        } else if (status & LSR_PARITY_ERROR) != 0 {
            Some("パリティエラー")
        } else if (status & LSR_FRAMING_ERROR) != 0 {
            Some("フレーミングエラー")
        } else if (status & LSR_BREAK_INDICATOR) != 0 {
            Some("中断インジケータ")
        } else if (status & LSR_FIFO_ERROR) != 0 {
            Some("FIFOエラー")
        } else {
            None
        }
    }
    
    /// 割り込み有効/無効切り替え
    pub fn set_interrupts_enabled(&self, enabled: bool) {
        unsafe {
            if enabled {
                // すべての割り込みを有効化
                self.write_register(REG_INT_ENABLE, 0x0F);
            } else {
                // すべての割り込みを無効化
                self.write_register(REG_INT_ENABLE, 0x00);
            }
        }
        
        // 設定を更新
        let mut config = self.config.lock();
        config.enable_interrupts = enabled;
    }
}

impl fmt::Write for SerialDriver {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

/// グローバルなシリアルポートインスタンス
static SERIAL1: spin::Once<SerialDriver> = spin::Once::new();

/// COM1シリアルポートの取得
pub fn com1() -> &'static SerialDriver {
    SERIAL1.call_once(|| {
        let driver = SerialDriver::new(SerialPort::Com1);
        let config = SerialConfig::default();
        driver.initialize(config).expect("COM1の初期化に失敗しました");
        driver
    })
}

/// COM1の初期化
pub fn init(port_base: u16) -> Result<(), &'static str> {
    let port = if port_base == COM1_PORT {
        SerialPort::Com1
    } else if port_base == COM2_PORT {
        SerialPort::Com2 
    } else if port_base == COM3_PORT {
        SerialPort::Com3
    } else if port_base == COM4_PORT {
        SerialPort::Com4
    } else {
        SerialPort::Custom(port_base)
    };
    
    let config = SerialConfig {
        baud_rate: 115200,
        data_bits: 8,
        parity: Parity::None,
        stop_bits: StopBits::One,
        hardware_flow_control: false,
        enable_fifo: true,
        enable_interrupts: false,
    };
    
    let driver = SerialDriver::new(port);
    driver.initialize(config)?;
    
    // グローバルインスタンスとして設定（COM1の場合のみ）
    if port_base == COM1_PORT {
        SERIAL1.call_once(|| driver);
    }
    
    // ドライバー情報をドライバーマネージャーに登録
    let mut driver_info = DriverInfo::new(
        "serial",
        DriverType::Char,
        "1.0.0",
        "AetherOSチーム",
        "16550A UARTシリアルポートドライバ",
    );
    driver_info.state = DriverInitState::Initialized;
    
    // ドライバーマネージャーがすでに初期化されている場合は登録
    if let Some(driver_manager) = super::DriverManager::INSTANCE.get() {
        driver_manager.register_driver(driver_info);
    }
    
    Ok(())
}

/// シリアルポートにメッセージを出力
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => ({
        use core::fmt::Write;
        let _ = write!($crate::drivers::serial::com1(), $($arg)*);
    });
}

/// シリアルポートに改行付きメッセージを出力
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($fmt:expr) => ($crate::serial_print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::serial_print!(concat!($fmt, "\n"), $($arg)*));
}

/// シリアルポートハンドラー構造体
pub struct SerialHandler {
    /// COM1ドライバ
    driver: &'static SerialDriver,
}

impl SerialHandler {
    /// 新しいシリアルハンドラーを作成
    pub fn new() -> Self {
        Self {
            driver: com1(),
        }
    }
    
    /// 文字列を送信
    pub fn write(&self, data: &str) {
        self.driver.write_string(data);
    }
    
    /// バイトデータを送信
    pub fn write_bytes(&self, data: &[u8]) {
        for &byte in data {
            self.driver.write_byte(byte);
        }
    }
    
    /// 1文字受信（ブロッキング）
    pub fn read_byte(&self) -> u8 {
        self.driver.read_byte()
    }
    
    /// 利用可能なすべての文字を読み取り
    pub fn read_available(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        
        while let Some(byte) = self.driver.try_read_byte() {
            buffer.push(byte);
            
            // 大量の入力がある場合のために最大サイズを制限
            if buffer.len() >= 1024 {
                break;
            }
        }
        
        buffer
    }
    
    /// 割り込み処理
    pub fn handle_interrupt(&self) {
        // 割り込み原因を確認
        let int_id = unsafe { self.driver.read_register(REG_INT_ID) & 0x0F };
        
        match int_id {
            0x04 => {
                // 受信データ割り込み
                if let Some(byte) = self.driver.try_read_byte() {
                    // ここで受信データを処理
                    // 例: 入力バッファに追加
                }
            },
            0x02 => {
                // 送信完了割り込み
                // 送信バッファから次のデータを送信
            },
            0x0C => {
                // ラインステータス割り込み
                if let Some(err) = self.driver.check_errors() {
                    log::warn!("シリアルポートエラー: {}", err);
                }
            },
            _ => {
                // その他の割り込み
            }
        }
    }
} 