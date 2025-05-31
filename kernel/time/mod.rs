// AetherOS カーネル - 時間管理モジュール
//
// このモジュールは、システム時間の管理、タイマー機能、
// 高精度時間測定などの時間関連機能を提供します。

use core::sync::atomic::{AtomicU64, Ordering};
use crate::arch;

/// システム起動からの経過時間（ナノ秒）
static SYSTEM_UPTIME_NS: AtomicU64 = AtomicU64::new(0);

/// システム起動時のタイムスタンプ（UNIX時間、ナノ秒）
static BOOT_TIMESTAMP_NS: AtomicU64 = AtomicU64::new(0);

/// 時間の単位
pub const NANOSECONDS_PER_MICROSECOND: u64 = 1_000;
pub const NANOSECONDS_PER_MILLISECOND: u64 = 1_000_000;
pub const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

/// システム起動時刻（ナノ秒）
static BOOT_TIME_NS: AtomicU64 = AtomicU64::new(0);

/// システム起動時のUNIX時刻（ナノ秒）
static BOOT_UNIX_TIME_NS: AtomicU64 = AtomicU64::new(0);

/// 時間管理の初期化
pub fn init() {
    log::info!("時間管理システムを初期化中...");
    
    // アーキテクチャ固有のタイマー初期化
    arch::timer::init();
    
    // システム起動時刻を記録
    let boot_timestamp = arch::timer::read_tsc();
    BOOT_TIME_NS.store(boot_timestamp, Ordering::SeqCst);
    
    // UNIX時刻を取得して記録
    let unix_timestamp = get_rtc_unix_timestamp();
    BOOT_UNIX_TIME_NS.store(unix_timestamp, Ordering::SeqCst);
    
    log::info!("時間管理システム初期化完了");
    log::debug!("システム起動時刻: {}ns", boot_timestamp);
    log::debug!("UNIX起動時刻: {}ns", unix_timestamp);
}

/// RTCからUNIX時刻を取得
fn get_rtc_unix_timestamp() -> u64 {
    // アーキテクチャ固有のRTC読み取り
    #[cfg(target_arch = "x86_64")]
    {
        // CMOS RTCから時刻を読み取り
        unsafe {
            // 秒
            let seconds = read_cmos_register(0x00);
            // 分
            let minutes = read_cmos_register(0x02);
            // 時
            let hours = read_cmos_register(0x04);
            // 日
            let day = read_cmos_register(0x07);
            // 月
            let month = read_cmos_register(0x08);
            // 年
            let year = read_cmos_register(0x09);
            
            // BCD形式から10進数に変換
            let seconds = bcd_to_decimal(seconds);
            let minutes = bcd_to_decimal(minutes);
            let hours = bcd_to_decimal(hours);
            let day = bcd_to_decimal(day);
            let month = bcd_to_decimal(month);
            let year = 2000 + bcd_to_decimal(year); // 2000年代と仮定
            
            // UNIX時刻に変換（1970年1月1日からの秒数）
            let unix_seconds = calculate_unix_timestamp(year, month, day, hours, minutes, seconds);
            unix_seconds * NANOSECONDS_PER_SECOND
        }
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    {
        // 他のアーキテクチャでは適切なRTCアクセスを実装
        #[cfg(target_arch = "aarch64")]
        {
            // AArch64のRTCアクセス
            get_aarch64_rtc_time()
        }
        
        #[cfg(target_arch = "riscv64")]
        {
            // RISC-VのRTCアクセス
            get_riscv64_rtc_time()
        }
        
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        {
            // その他のアーキテクチャでは固定値を返す
            1_700_000_000_000_000_000u64 // 2023年頃のタイムスタンプ（ナノ秒）
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn read_cmos_register(register: u8) -> u8 {
    use core::arch::asm;
    
    // CMOSレジスタアドレスを設定
    asm!("out 0x70, al", in("al") register, options(nostack, preserves_flags));
    
    // 短時間待機
    for _ in 0..100 {
        core::hint::spin_loop();
    }
    
    // CMOSデータを読み取り
    let mut value: u8;
    asm!("in al, 0x71", out("al") value, options(nostack, preserves_flags));
    
    value
}

#[cfg(target_arch = "x86_64")]
fn bcd_to_decimal(bcd: u8) -> u32 {
    ((bcd >> 4) * 10 + (bcd & 0x0F)) as u32
}

fn calculate_unix_timestamp(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> u64 {
    // 簡易的なUNIX時刻計算（うるう年は考慮しない簡略版）
    let days_per_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    
    let mut total_days = 0u64;
    
    // 1970年からの年数を計算
    for y in 1970..year {
        total_days += if is_leap_year(y) { 366 } else { 365 };
    }
    
    // 今年の月数を計算
    for m in 1..month {
        total_days += days_per_month[(m - 1) as usize] as u64;
        if m == 2 && is_leap_year(year) {
            total_days += 1; // うるう年の2月
        }
    }
    
    // 日数を追加
    total_days += (day - 1) as u64;
    
    // 秒に変換
    let total_seconds = total_days * 24 * 60 * 60 + 
                       hour as u64 * 60 * 60 + 
                       minute as u64 * 60 + 
                       second as u64;
    
    total_seconds
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// 現在時刻をナノ秒で取得
pub fn current_time_ns() -> u64 {
    let boot_time = BOOT_TIME_NS.load(Ordering::Relaxed);
    let current_tsc = arch::timer::read_tsc();
    
    if current_tsc >= boot_time {
        current_tsc - boot_time
    } else {
        // TSCがオーバーフローした場合の処理
        0
    }
}

/// システム稼働時間をナノ秒で取得
pub fn get_uptime_ns() -> u64 {
    current_time_ns()
}

/// システム稼働時間をマイクロ秒で取得
pub fn get_uptime_us() -> u64 {
    get_uptime_ns() / NANOSECONDS_PER_MICROSECOND
}

/// システム稼働時間をミリ秒で取得
pub fn get_uptime_ms() -> u64 {
    get_uptime_ns() / NANOSECONDS_PER_MILLISECOND
}

/// システム稼働時間を秒で取得
pub fn get_uptime_s() -> u64 {
    get_uptime_ns() / NANOSECONDS_PER_SECOND
}

/// 現在のタイマーティック数を取得
pub fn get_current_ticks() -> u64 {
    arch::timer::get_ticks()
}

/// タイマー周波数を取得
pub fn get_timer_frequency() -> u64 {
    arch::timer::get_frequency()
}

/// ナノ秒をティック数に変換
pub fn ns_to_ticks(ns: u64) -> u64 {
    let frequency = get_timer_frequency();
    (ns * frequency) / NANOSECONDS_PER_SECOND
}

/// ティック数をナノ秒に変換
pub fn ticks_to_ns(ticks: u64) -> u64 {
    let frequency = get_timer_frequency();
    (ticks * NANOSECONDS_PER_SECOND) / frequency
}

/// 指定されたナノ秒だけ遅延
pub fn delay_ns(ns: u64) {
    let start_time = current_time_ns();
    let target_time = start_time + ns;
    
    while current_time_ns() < target_time {
        arch::timer::pause();
    }
}

/// 指定されたマイクロ秒だけ遅延
pub fn delay_us(us: u64) {
    delay_ns(us * NANOSECONDS_PER_MICROSECOND);
}

/// 指定されたミリ秒だけ遅延
pub fn delay_ms(ms: u64) {
    delay_ns(ms * NANOSECONDS_PER_MILLISECOND);
}

/// 現在のUNIX時刻をナノ秒で取得
pub fn get_current_unix_time_ns() -> u64 {
    let boot_unix_time = BOOT_UNIX_TIME_NS.load(Ordering::Relaxed);
    let uptime = get_uptime_ns();
    boot_unix_time + uptime
}

/// 現在のUNIX時刻をミリ秒で取得
pub fn current_time_ms() -> u64 {
    get_current_unix_time_ns() / NANOSECONDS_PER_MILLISECOND
}

/// 高精度タイマーのカウンタ値を取得
pub fn get_current_ticks() -> u64 {
    arch::timer::get_ticks()
}

/// タイマー周波数を取得（Hz）
pub fn get_timer_frequency() -> u64 {
    arch::timer::get_frequency()
}

/// ナノ秒をタイマーティックに変換
pub fn ns_to_ticks(ns: u64) -> u64 {
    let freq = get_timer_frequency();
    (ns * freq) / NANOSECONDS_PER_SECOND
}

/// タイマーティックをナノ秒に変換
pub fn ticks_to_ns(ticks: u64) -> u64 {
    let freq = get_timer_frequency();
    (ticks * NANOSECONDS_PER_SECOND) / freq
}

/// 指定した時間だけ待機（ナノ秒）
pub fn delay_ns(ns: u64) {
    let start = get_current_ticks();
    let target_ticks = ns_to_ticks(ns);
    
    while get_current_ticks() - start < target_ticks {
        arch::cpu::pause();
    }
}

/// 指定した時間だけ待機（マイクロ秒）
pub fn delay_us(us: u64) {
    delay_ns(us * NANOSECONDS_PER_MICROSECOND);
}

/// 指定した時間だけ待機（ミリ秒）
pub fn delay_ms(ms: u64) {
    delay_ns(ms * NANOSECONDS_PER_MILLISECOND);
}

/// タイムスタンプ構造体
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    /// ナノ秒単位のタイムスタンプ
    pub ns: u64,
}

impl Timestamp {
    /// 現在時刻のタイムスタンプを作成
    pub fn now() -> Self {
        Self {
            ns: current_time_ns(),
        }
    }
    
    /// システム起動時からの経過時間でタイムスタンプを作成
    pub fn from_uptime() -> Self {
        Self {
            ns: get_uptime_ns(),
        }
    }
    
    /// ナノ秒からタイムスタンプを作成
    pub fn from_ns(ns: u64) -> Self {
        Self { ns }
    }
    
    /// 経過時間を計算（ナノ秒）
    pub fn elapsed_since(&self, other: &Timestamp) -> u64 {
        if self.ns >= other.ns {
            self.ns - other.ns
        } else {
            0
        }
    }
    
    /// 現在時刻からの経過時間を計算（ナノ秒）
    pub fn elapsed(&self) -> u64 {
        let now = Timestamp::now();
        now.elapsed_since(self)
    }
}

/// 時間測定用のストップウォッチ
#[derive(Debug)]
pub struct Stopwatch {
    start_time: Option<Timestamp>,
    elapsed_ns: u64,
}

impl Stopwatch {
    /// 新しいストップウォッチを作成
    pub fn new() -> Self {
        Self {
            start_time: None,
            elapsed_ns: 0,
        }
    }
    
    /// 計測を開始
    pub fn start(&mut self) {
        self.start_time = Some(Timestamp::now());
    }
    
    /// 計測を停止
    pub fn stop(&mut self) {
        if let Some(start) = self.start_time.take() {
            self.elapsed_ns += start.elapsed();
        }
    }
    
    /// 計測をリセット
    pub fn reset(&mut self) {
        self.start_time = None;
        self.elapsed_ns = 0;
    }
    
    /// 経過時間を取得（ナノ秒）
    pub fn elapsed_ns(&self) -> u64 {
        let mut total = self.elapsed_ns;
        if let Some(start) = &self.start_time {
            total += start.elapsed();
        }
        total
    }
    
    /// 経過時間を取得（マイクロ秒）
    pub fn elapsed_us(&self) -> u64 {
        self.elapsed_ns() / NANOSECONDS_PER_MICROSECOND
    }
    
    /// 経過時間を取得（ミリ秒）
    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed_ns() / NANOSECONDS_PER_MILLISECOND
    }
    
    /// 実行中かどうか
    pub fn is_running(&self) -> bool {
        self.start_time.is_some()
    }
}

impl Default for Stopwatch {
    fn default() -> Self {
        Self::new()
    }
}

/// 高精度遅延（アーキテクチャ固有の最適化を使用）
pub fn precise_delay_ns(ns: u64) {
    arch::timer::precise_delay_ns(ns);
}

/// 時間統計情報
#[derive(Debug, Default)]
pub struct TimeStats {
    /// タイマー割り込み回数
    pub timer_interrupts: u64,
    /// 時刻同期回数
    pub time_sync_count: u64,
    /// 最大遅延誤差（ナノ秒）
    pub max_delay_error_ns: u64,
    /// 平均遅延誤差（ナノ秒）
    pub avg_delay_error_ns: u64,
}

/// グローバル時間統計
static mut TIME_STATS: TimeStats = TimeStats {
    timer_interrupts: 0,
    time_sync_count: 0,
    max_delay_error_ns: 0,
    avg_delay_error_ns: 0,
};

/// 時間統計を取得
pub fn get_time_stats() -> TimeStats {
    unsafe { TIME_STATS }
}

/// タイマー割り込みを記録
pub fn record_timer_interrupt() {
    unsafe {
        TIME_STATS.timer_interrupts += 1;
    }
}

/// 時刻同期を記録
pub fn record_time_sync() {
    unsafe {
        TIME_STATS.time_sync_count += 1;
    }
}

/// 遅延誤差を記録
pub fn record_delay_error(error_ns: u64) {
    unsafe {
        if error_ns > TIME_STATS.max_delay_error_ns {
            TIME_STATS.max_delay_error_ns = error_ns;
        }
        
        // 移動平均で平均誤差を更新
        if TIME_STATS.avg_delay_error_ns == 0 {
            TIME_STATS.avg_delay_error_ns = error_ns;
        } else {
            TIME_STATS.avg_delay_error_ns = 
                (TIME_STATS.avg_delay_error_ns * 15 + error_ns) / 16;
        }
    }
}

/// 時間管理システムの診断
pub fn diagnose_time_system() {
    let stats = get_time_stats();
    
    log::info!("=== 時間管理システム診断 ===");
    log::info!("システム稼働時間: {}秒", get_uptime_s());
    log::info!("タイマー周波数: {}Hz", get_timer_frequency());
    log::info!("タイマー割り込み回数: {}", stats.timer_interrupts);
    log::info!("時刻同期回数: {}", stats.time_sync_count);
    log::info!("最大遅延誤差: {}ns", stats.max_delay_error_ns);
    log::info!("平均遅延誤差: {}ns", stats.avg_delay_error_ns);
    
    // 時刻精度テスト
    let test_start = Timestamp::now();
    delay_us(1000); // 1ms遅延
    let test_end = Timestamp::now();
    let actual_delay = test_end.elapsed_since(&test_start);
    let expected_delay = 1_000_000; // 1ms in ns
    let error = if actual_delay > expected_delay {
        actual_delay - expected_delay
    } else {
        expected_delay - actual_delay
    };
    
    log::info!("遅延精度テスト: 期待値={}ns, 実測値={}ns, 誤差={}ns", 
              expected_delay, actual_delay, error);
    
    if error > 100_000 { // 100μs以上の誤差
        log::warn!("時間精度が低下しています");
    }
}

/// 一意IDを生成
pub fn generate_unique_id() -> u128 {
    let timestamp = get_unix_time_ns();
    let uptime = get_uptime_ns();
    
    // 高精度タイムスタンプとシステム稼働時間を組み合わせてUUIDを生成
    // RFC 4122のVersion 1 UUIDに類似した形式
    
    // タイムスタンプの上位64ビット
    let time_high = (timestamp >> 32) as u64;
    let time_low = (timestamp & 0xFFFFFFFF) as u64;
    
    // システム稼働時間とカウンターを組み合わせ
    static COUNTER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    let counter = COUNTER.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    
    // ノードID（MACアドレスの代替として、システム固有の値を使用）
    let node_id = get_system_node_id();
    
    // UUID形式で組み合わせ
    let uuid_high = (time_high << 32) | (time_low & 0xFFFFFFFF);
    let uuid_low = ((uptime as u64) << 32) | ((node_id as u64) << 16) | (counter as u64);
    
    ((uuid_high as u128) << 64) | (uuid_low as u128)
}

/// システム固有のノードIDを取得
fn get_system_node_id() -> u16 {
    // CPUのシリアル番号やシステム固有の情報から生成
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            let mut eax: u32;
            let mut ebx: u32;
            let mut ecx: u32;
            let mut edx: u32;
            
            // CPUID命令でプロセッサ情報を取得
            core::arch::asm!(
                "cpuid",
                inout("eax") 1u32 => eax,
                out("ebx") ebx,
                out("ecx") ecx,
                out("edx") edx,
            );
            
            // プロセッサ情報をハッシュしてノードIDを生成
            ((eax ^ ebx ^ ecx ^ edx) & 0xFFFF) as u16
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        unsafe {
            let mut midr: u64;
            core::arch::asm!("mrs {}, midr_el1", out(reg) midr);
            (midr & 0xFFFF) as u16
        }
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        unsafe {
            let mut mhartid: u64;
            core::arch::asm!("csrr {}, mhartid", out(reg) mhartid);
            (mhartid & 0xFFFF) as u16
        }
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
    {
        0x1234 // デフォルト値
    }
}

#[cfg(target_arch = "aarch64")]
fn get_aarch64_rtc_time() -> u64 {
    // AArch64のGeneric Timerを使用
    unsafe {
        let mut counter: u64;
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) counter);
        
        // カウンターを時間に変換（24MHzクロックを仮定）
        let frequency = 24_000_000u64; // 24MHz
        let seconds = counter / frequency;
        let nanoseconds = ((counter % frequency) * 1_000_000_000) / frequency;
        
        // UNIX時間に変換（2000年1月1日からの経過時間を仮定）
        let unix_epoch_offset = 946_684_800u64; // 2000年1月1日のUNIX時間
        (seconds + unix_epoch_offset) * 1_000_000_000 + nanoseconds
    }
}

#[cfg(target_arch = "riscv64")]
fn get_riscv64_rtc_time() -> u64 {
    // RISC-VのTIME CSRを使用
    unsafe {
        let mut time: u64;
        core::arch::asm!("csrr {}, time", out(reg) time);
        
        // TIMEレジスタを時間に変換（1MHzクロックを仮定）
        let frequency = 1_000_000u64; // 1MHz
        let seconds = time / frequency;
        let nanoseconds = ((time % frequency) * 1_000_000_000) / frequency;
        
        // UNIX時間に変換
        let unix_epoch_offset = 946_684_800u64; // 2000年1月1日のUNIX時間
        (seconds + unix_epoch_offset) * 1_000_000_000 + nanoseconds
    }
} 