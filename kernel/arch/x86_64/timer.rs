// AetherOS x86_64 タイマー実装
//
// 高精度タイマー、TSC、APIC、PIT、RTCの包括的実装

use core::sync::atomic::{AtomicU64, Ordering};
use core::arch::asm;

/// TSC周波数（Hz）
static TSC_FREQUENCY: AtomicU64 = AtomicU64::new(0);

/// システム起動時のTSC値
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

/// APIC周波数（Hz）
static APIC_FREQUENCY: AtomicU64 = AtomicU64::new(0);

/// タイマー統計
static TIMER_INTERRUPTS: AtomicU64 = AtomicU64::new(0);

/// MSRレジスタ定数
const MSR_IA32_TSC: u32 = 0x10;
const MSR_IA32_APIC_BASE: u32 = 0x1B;
const MSR_IA32_THERM_STATUS: u32 = 0x19C;
const MSR_TEMPERATURE_TARGET: u32 = 0x1A2;
const MSR_PLATFORM_INFO: u32 = 0xCE;

/// APIC レジスタオフセット
const APIC_LVT_TIMER: usize = 0x320;
const APIC_TIMER_INITIAL_COUNT: usize = 0x380;
const APIC_TIMER_CURRENT_COUNT: usize = 0x390;
const APIC_TIMER_DIVIDE_CONFIG: usize = 0x3E0;

/// x86_64タイマーシステムの初期化
pub fn init() {
    log::info!("x86_64タイマーシステムを初期化中...");
    
    // TSC周波数を測定
    let tsc_freq = measure_tsc_frequency();
    TSC_FREQUENCY.store(tsc_freq, Ordering::SeqCst);
    
    // システム起動時のTSCを記録
    let boot_tsc = read_tsc();
    BOOT_TSC.store(boot_tsc, Ordering::SeqCst);
    
    // APIC タイマーを初期化
    init_apic_timer();
    
    log::info!("x86_64タイマー初期化完了: TSC周波数={}MHz", tsc_freq / 1_000_000);
}

/// TSC（Time Stamp Counter）を読み取り
pub fn read_tsc() -> u64 {
    unsafe {
        let mut low: u32;
        let mut high: u32;
        
        asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
        
        ((high as u64) << 32) | (low as u64)
    }
}

/// シリアライズ付きTSC読み取り（より正確）
pub fn read_tsc_serialized() -> u64 {
    unsafe {
        let mut low: u32;
        let mut high: u32;
        let mut _eax: u32;
        let mut _ebx: u32;
        let mut _ecx: u32;
        let mut _edx: u32;
        
        // CPUIDでシリアライズ
        asm!(
            "cpuid",
            "rdtsc",
            inout("eax") 0 => _eax,
            out("ebx") _ebx,
            out("ecx") _ecx,
            inout("edx") 0 => _edx,
            options(nostack, preserves_flags)
        );
        
        asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
        
        ((high as u64) << 32) | (low as u64)
    }
}

/// 現在のタイマーティック数を取得
pub fn get_ticks() -> u64 {
    let current_tsc = read_tsc();
    let boot_tsc = BOOT_TSC.load(Ordering::Relaxed);
    
    if current_tsc >= boot_tsc {
        current_tsc - boot_tsc
    } else {
        // TSCオーバーフロー処理
        (u64::MAX - boot_tsc) + current_tsc
    }
}

/// タイマー周波数を取得（Hz）
pub fn get_frequency() -> u64 {
    TSC_FREQUENCY.load(Ordering::Relaxed)
}

/// システム稼働時間をナノ秒で取得
pub fn get_uptime_ns() -> u64 {
    let ticks = get_ticks();
    let frequency = get_frequency();
    
    if frequency > 0 {
        (ticks * 1_000_000_000) / frequency
    } else {
        0
    }
}

/// UNIX時刻をナノ秒で取得
pub fn get_unix_timestamp_ns() -> u64 {
    // RTCから基準時刻を取得し、稼働時間を加算
    let rtc_timestamp = read_rtc_unix_timestamp();
    let uptime = get_uptime_ns();
    rtc_timestamp + uptime
}

/// TSC周波数を測定
fn measure_tsc_frequency() -> u64 {
    // CPUIDから周波数を取得を試行
    if let Some(freq) = get_tsc_frequency_from_cpuid() {
        log::debug!("CPUID経由でTSC周波数取得: {}Hz", freq);
        return freq;
    }
    
    // PITを使用して測定
    let freq = measure_tsc_frequency_with_pit();
    log::debug!("PIT測定によるTSC周波数: {}Hz", freq);
    freq
}

/// CPUIDからTSC周波数を取得
fn get_tsc_frequency_from_cpuid() -> Option<u64> {
    unsafe {
        let mut eax: u32;
        let mut ebx: u32;
        let mut ecx: u32;
        let mut edx: u32;
        
        // CPUID.15H: TSC/Core Crystal Clock Information
        asm!(
            "cpuid",
            inout("eax") 0x15 => eax,
            out("ebx") ebx,
            out("ecx") ecx,
            out("edx") edx,
            options(nostack, preserves_flags)
        );
        
        if eax != 0 && ebx != 0 {
            if ecx != 0 {
                // 基準周波数が提供されている場合
                let tsc_freq = ((ecx as u64) * (ebx as u64)) / (eax as u64);
                return Some(tsc_freq);
            }
        }
        
        // CPUID.16H: Processor Frequency Information
        asm!(
            "cpuid",
            inout("eax") 0x16 => eax,
            out("ebx") ebx,
            out("ecx") ecx,
            out("edx") edx,
            options(nostack, preserves_flags)
        );
        
        if eax != 0 {
            // ベース周波数（MHz）
            let base_freq_mhz = eax & 0xFFFF;
            if base_freq_mhz > 0 {
                return Some((base_freq_mhz as u64) * 1_000_000);
            }
        }
        
        None
    }
}

/// PITを使用してTSC周波数を測定
fn measure_tsc_frequency_with_pit() -> u64 {
    log::debug!("PIT使用TSC周波数測定開始");
    
    // PITの設定
    // チャンネル2を使用（スピーカー制御用、通常は未使用）
    // モード0（割り込み時カウント）、16ビットバイナリ
    
    // 1. PITコマンドレジスタ設定 (0x43)
    // ビット7-6: チャンネル選択 (10 = チャンネル2)
    // ビット5-4: アクセスモード (11 = LSB/MSB)
    // ビット3-1: 動作モード (000 = モード0)
    // ビット0: BCD/バイナリ (0 = 16ビットバイナリ)
    let pit_command = 0b10110000; // 0xB0
    
    unsafe {
        // PITを無効化
        outb(0x43, pit_command);
        
        // 10ms測定用の初期値設定
        // PIT基準周波数: 1.193182 MHz
        // 10ms = 0.01秒 → カウント値 = 1193182 * 0.01 = 11931.82 ≈ 11932
        let pit_count = 11932u16;
        
        // LSB, MSBの順でカウント値を設定
        outb(0x42, (pit_count & 0xFF) as u8);        // LSB
        outb(0x42, ((pit_count >> 8) & 0xFF) as u8); // MSB
        
        // PITの準備完了まで少し待機
        for _ in 0..100 {
            inb(0x61); // ダミーリード
        }
    }
    
    // 2. TSC測定開始
    let tsc_start = read_tsc_serialized();
    
    // 3. PITカウンタ開始
    unsafe {
        // ゲート制御レジスタ (0x61) でPITチャンネル2を有効化
        let gate_control = inb(0x61);
        outb(0x61, gate_control | 0x01); // ビット0でゲート有効
    }
    
    // 4. PITカウンタが0になるまで待機
    let mut timeout_counter = 0u32;
    const MAX_TIMEOUT: u32 = 1_000_000; // タイムアウト防止
    
    loop {
        unsafe {
            // PITカウンタ値を読み取り
            outb(0x43, 0b11000000); // チャンネル2ラッチコマンド
            
            let low = inb(0x42) as u16;
            let high = inb(0x42) as u16;
            let current_count = (high << 8) | low;
            
            // カウンタが0に近づいたら終了
            if current_count <= 10 {
                break;
            }
        }
        
        timeout_counter += 1;
        if timeout_counter > MAX_TIMEOUT {
            log::warn!("PIT測定タイムアウト");
            break;
        }
        
        // CPUを少し休ませる
        pause();
    }
    
    // 5. TSC測定終了
    let tsc_end = read_tsc_serialized();
    
    // 6. PITを無効化
    unsafe {
        let gate_control = inb(0x61);
        outb(0x61, gate_control & !0x01); // ゲート無効
    }
    
    // 7. TSC差分計算
    let tsc_diff = if tsc_end > tsc_start {
        tsc_end - tsc_start
    } else {
        // TSCオーバーフロー処理
        log::warn!("TSCオーバーフロー検出");
        (u64::MAX - tsc_start) + tsc_end + 1
    };
    
    // 8. 周波数計算
    // 10ms間のTSCカウント → 1秒間のTSCカウント（周波数）
    let frequency = tsc_diff * 100; // 10ms → 1秒 (×100)
    
    log::debug!("PIT測定結果: TSC差分={}, 周波数={} Hz", tsc_diff, frequency);
    
    // 9. 妥当性チェック
    if frequency < 100_000_000 || frequency > 10_000_000_000 {
        log::warn!("測定された周波数が異常: {} Hz", frequency);
        // フォールバック値を返す
        return 2_000_000_000; // 2GHz
    }
    
    // 10. 複数回測定して平均を取る
    let mut measurements = vec![frequency];
    
    for i in 1..5 {
        log::trace!("追加測定 {}/4", i);
        
        // 少し待機してから再測定
        for _ in 0..10000 {
            pause();
        }
        
        unsafe {
            // PIT再設定
            outb(0x43, pit_command);
            outb(0x42, (pit_count & 0xFF) as u8);
            outb(0x42, ((pit_count >> 8) & 0xFF) as u8);
            
            for _ in 0..100 {
                inb(0x61);
            }
        }
        
        let tsc_start = read_tsc_serialized();
        
        unsafe {
            let gate_control = inb(0x61);
            outb(0x61, gate_control | 0x01);
        }
        
        let mut timeout_counter = 0u32;
        loop {
            unsafe {
                outb(0x43, 0b11000000);
                let low = inb(0x42) as u16;
                let high = inb(0x42) as u16;
                let current_count = (high << 8) | low;
                
                if current_count <= 10 {
                    break;
                }
            }
            
            timeout_counter += 1;
            if timeout_counter > MAX_TIMEOUT {
                break;
            }
            
            pause();
        }
        
        let tsc_end = read_tsc_serialized();
        
        unsafe {
            let gate_control = inb(0x61);
            outb(0x61, gate_control & !0x01);
        }
        
        let tsc_diff = if tsc_end > tsc_start {
            tsc_end - tsc_start
        } else {
            (u64::MAX - tsc_start) + tsc_end + 1
        };
        
        let freq = tsc_diff * 100;
        
        if freq >= 100_000_000 && freq <= 10_000_000_000 {
            measurements.push(freq);
        }
    }
    
    // 11. 平均値計算（外れ値除去）
    if measurements.len() >= 3 {
        measurements.sort();
        
        // 中央値付近の値を使用
        let start_idx = measurements.len() / 4;
        let end_idx = measurements.len() * 3 / 4;
        let filtered: Vec<u64> = measurements[start_idx..end_idx].to_vec();
        
        let average = filtered.iter().sum::<u64>() / filtered.len() as u64;
        
        log::info!("PIT測定完了: 平均周波数={} Hz ({} 回測定)", average, filtered.len());
        average
    } else {
        log::warn!("測定回数不足、最初の値を使用: {} Hz", frequency);
        frequency
    }
}

// I/Oポート操作関数
unsafe fn outb(port: u16, value: u8) {
    asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
}

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
    value
}

/// RTCからUNIX時刻を読み取り（完全実装）
fn read_rtc_unix_timestamp() -> u64 {
    log::trace!("RTC UNIX時刻読み取り開始");
    
    // RTCレジスタアドレス
    const RTC_SECONDS: u8 = 0x00;
    const RTC_MINUTES: u8 = 0x02;
    const RTC_HOURS: u8 = 0x04;
    const RTC_DAY: u8 = 0x07;
    const RTC_MONTH: u8 = 0x08;
    const RTC_YEAR: u8 = 0x09;
    const RTC_CENTURY: u8 = 0x32; // 一部のRTCで利用可能
    const RTC_STATUS_A: u8 = 0x0A;
    const RTC_STATUS_B: u8 = 0x0B;
    
    // 複数回読み取って一貫性を確保
    let mut attempts = 0;
    const MAX_ATTEMPTS: u32 = 10;
    
    loop {
        attempts += 1;
        if attempts > MAX_ATTEMPTS {
            log::error!("RTC読み取り試行回数上限に達しました");
            // フォールバック: 現在時刻の概算値を返す
            return 1640995200; // 2022-01-01 00:00:00 UTC
        }
        
        // 1. 更新中フラグをチェック
        let mut update_in_progress = true;
        let mut timeout = 0;
        
        while update_in_progress && timeout < 1000 {
            unsafe {
                let status_a = read_cmos_register(RTC_STATUS_A);
                update_in_progress = (status_a & 0x80) != 0; // UIP (Update In Progress) ビット
            }
            timeout += 1;
            
            if update_in_progress {
                // 少し待機
                for _ in 0..1000 {
                    pause();
                }
            }
        }
        
        if update_in_progress {
            log::warn!("RTC更新中フラグがクリアされません（試行 {}）", attempts);
            continue;
        }
        
        // 2. 時刻データを読み取り
        let seconds1 = unsafe { read_cmos_register(RTC_SECONDS) };
        let minutes1 = unsafe { read_cmos_register(RTC_MINUTES) };
        let hours1 = unsafe { read_cmos_register(RTC_HOURS) };
        let day1 = unsafe { read_cmos_register(RTC_DAY) };
        let month1 = unsafe { read_cmos_register(RTC_MONTH) };
        let year1 = unsafe { read_cmos_register(RTC_YEAR) };
        
        // 3. 再度読み取って一貫性をチェック
        let seconds2 = unsafe { read_cmos_register(RTC_SECONDS) };
        let minutes2 = unsafe { read_cmos_register(RTC_MINUTES) };
        let hours2 = unsafe { read_cmos_register(RTC_HOURS) };
        let day2 = unsafe { read_cmos_register(RTC_DAY) };
        let month2 = unsafe { read_cmos_register(RTC_MONTH) };
        let year2 = unsafe { read_cmos_register(RTC_YEAR) };
        
        // 4. 一貫性チェック
        if seconds1 == seconds2 && minutes1 == minutes2 && hours1 == hours2 &&
           day1 == day2 && month1 == month2 && year1 == year2 {
            
            // 5. ステータスレジスタBを読み取り、フォーマット情報を取得
            let status_b = unsafe { read_cmos_register(RTC_STATUS_B) };
            let is_24_hour = (status_b & 0x02) != 0;
            let is_binary = (status_b & 0x04) != 0;
            
            log::trace!("RTC設定: 24時間={}, バイナリ={}", is_24_hour, is_binary);
            
            // 6. データ形式変換
            let seconds = if is_binary { seconds1 } else { bcd_to_decimal(seconds1) as u8 };
            let minutes = if is_binary { minutes1 } else { bcd_to_decimal(minutes1) as u8 };
            let mut hours = if is_binary { hours1 } else { bcd_to_decimal(hours1) as u8 };
            let day = if is_binary { day1 } else { bcd_to_decimal(day1) as u8 };
            let month = if is_binary { month1 } else { bcd_to_decimal(month1) as u8 };
            let year = if is_binary { year1 } else { bcd_to_decimal(year1) as u8 };
            
            // 7. 12時間形式の場合、24時間形式に変換
            if !is_24_hour {
                let pm = (hours1 & 0x80) != 0; // PM ビット
                hours = hours & 0x7F; // PM ビットを除去
                
                if hours == 12 {
                    hours = if pm { 12 } else { 0 };
                } else if pm {
                    hours += 12;
                }
            }
            
            // 8. 世紀情報を取得（利用可能な場合）
            let century = unsafe {
                // 世紀レジスタが利用可能かチェック
                let century_raw = read_cmos_register(RTC_CENTURY);
                if century_raw != 0xFF && century_raw != 0x00 {
                    if is_binary { century_raw } else { bcd_to_decimal(century_raw) as u8 }
                } else {
                    // 世紀レジスタが利用不可の場合、年から推定
                    if year >= 70 { 19 } else { 20 } // 1970-1999 or 2000-2069
                }
            };
            
            let full_year = (century as u32) * 100 + (year as u32);
            
            // 9. 妥当性チェック
            if seconds > 59 || minutes > 59 || hours > 23 || 
               day == 0 || day > 31 || month == 0 || month > 12 ||
               full_year < 1970 || full_year > 2100 {
                log::warn!("RTC時刻データが無効: {}-{:02}-{:02} {:02}:{:02}:{:02}", 
                          full_year, month, day, hours, minutes, seconds);
                continue;
            }
            
            log::trace!("RTC時刻: {}-{:02}-{:02} {:02}:{:02}:{:02}", 
                       full_year, month, day, hours, minutes, seconds);
            
            // 10. UNIX時刻に変換
            let unix_timestamp = calculate_unix_timestamp(
                full_year, month as u32, day as u32, 
                hours as u32, minutes as u32, seconds as u32
            );
            
            log::trace!("UNIX時刻: {}", unix_timestamp);
            return unix_timestamp;
        } else {
            log::trace!("RTC読み取り不一致、再試行 {}", attempts);
            
            // 少し待機してから再試行
            for _ in 0..10000 {
                pause();
            }
        }
    }
}

/// UNIX時刻計算（うるう年対応）
fn calculate_unix_timestamp(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> u64 {
    log::trace!("UNIX時刻計算: {}-{:02}-{:02} {:02}:{:02}:{:02}", 
               year, month, day, hour, minute, second);
    
    // UNIX時刻の基準: 1970年1月1日 00:00:00 UTC
    const UNIX_EPOCH_YEAR: u32 = 1970;
    
    if year < UNIX_EPOCH_YEAR {
        log::error!("年がUNIX時刻基準より前です: {}", year);
        return 0;
    }
    
    // 各月の日数（平年）
    const DAYS_IN_MONTH: [u32; 12] = [
        31, 28, 31, 30, 31, 30,  // 1月-6月
        31, 31, 30, 31, 30, 31   // 7月-12月
    ];
    
    let mut total_days = 0u64;
    
    // 1. 1970年から指定年の前年までの日数を計算
    for y in UNIX_EPOCH_YEAR..year {
        if is_leap_year(y) {
            total_days += 366;
        } else {
            total_days += 365;
        }
    }
    
    log::trace!("1970年から{}年まで: {} 日", year - 1, total_days);
    
    // 2. 指定年の1月から指定月の前月までの日数を計算
    for m in 1..month {
        let days_in_this_month = if m == 2 && is_leap_year(year) {
            29 // うるう年の2月
        } else {
            DAYS_IN_MONTH[(m - 1) as usize]
        };
        total_days += days_in_this_month as u64;
    }
    
    log::trace!("{}年1月から{}月まで: +{} 日", year, month - 1, 
               total_days - (year - UNIX_EPOCH_YEAR) as u64 * 365);
    
    // 3. 指定月の日数を加算（1日から指定日の前日まで）
    total_days += (day - 1) as u64;
    
    log::trace!("総日数: {} 日", total_days);
    
    // 4. 日数を秒に変換
    let mut total_seconds = total_days * 24 * 60 * 60;
    
    // 5. 時、分、秒を加算
    total_seconds += hour as u64 * 60 * 60;
    total_seconds += minute as u64 * 60;
    total_seconds += second as u64;
    
    log::trace!("総秒数: {} 秒", total_seconds);
    
    // 6. 妥当性チェック
    // 2024年1月1日 00:00:00 UTC ≈ 1704067200
    // 2030年1月1日 00:00:00 UTC ≈ 1893456000
    if total_seconds > 2000000000 { // 2033年頃
        log::warn!("計算されたUNIX時刻が将来すぎます: {}", total_seconds);
    }
    
    if total_seconds < 946684800 { // 2000年1月1日
        log::warn!("計算されたUNIX時刻が古すぎます: {}", total_seconds);
    }
    
    total_seconds
}

/// うるう年判定
fn is_leap_year(year: u32) -> bool {
    // グレゴリオ暦のうるう年ルール
    // 1. 4で割り切れる年はうるう年
    // 2. ただし100で割り切れる年は平年
    // 3. ただし400で割り切れる年はうるう年
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// CMOSレジスタを読み取り
unsafe fn read_cmos_register(register: u8) -> u8 {
    // CMOSアドレスレジスタ（0x70）に読み取りたいレジスタ番号を書き込み
    asm!(
        "out 0x70, al",
        in("al") register,
        options(nostack, preserves_flags)
    );
    
    // 短い遅延（CMOSアクセス時間を確保）
    asm!("nop", options(nostack, preserves_flags));
    asm!("nop", options(nostack, preserves_flags));
    
    // CMOSデータレジスタ（0x71）からデータを読み取り
    let mut value: u8;
    asm!(
        "in al, 0x71",
        out("al") value,
        options(nostack, preserves_flags)
    );
    
    value
}

/// BCD（Binary Coded Decimal）を10進数に変換
fn bcd_to_decimal(bcd: u8) -> u32 {
    ((bcd >> 4) * 10 + (bcd & 0x0F)) as u32
}

/// CPU一時停止
pub fn pause() {
    unsafe {
        asm!("pause", options(nostack, preserves_flags));
    }
}

/// 高精度遅延（ナノ秒）
pub fn precise_delay_ns(ns: u64) {
    let frequency = get_frequency();
    if frequency == 0 {
        return;
    }
    
    let target_ticks = (ns * frequency) / 1_000_000_000;
    let start_tsc = read_tsc();
    
    while read_tsc() - start_tsc < target_ticks {
        pause();
    }
}

/// APIC タイマーの初期化
pub fn init_apic_timer() {
    log::debug!("APIC タイマーを初期化中...");
    
    // APIC ベースアドレスを取得
    let apic_base = get_apic_base_address();
    
    if apic_base == 0 {
        log::warn!("APIC が利用できません");
        return;
    }
    
    // APIC タイマー周波数を測定
    let apic_freq = measure_apic_timer_frequency();
    APIC_FREQUENCY.store(apic_freq, Ordering::SeqCst);
    
    // APIC タイマーを設定
    unsafe {
        // 分周比を設定（1:1）
        write_apic_register(apic_base, APIC_TIMER_DIVIDE_CONFIG, 0x0B);
        
        // LVT タイマーエントリを設定（ベクタ32、周期モード）
        write_apic_register(apic_base, APIC_LVT_TIMER, 0x20020);
        
        // 初期カウント値を設定（1ms間隔）
        let initial_count = apic_freq / 1000; // 1ms
        write_apic_register(apic_base, APIC_TIMER_INITIAL_COUNT, initial_count as u32);
    }
    
    log::info!("APIC タイマー初期化完了: 周波数={}MHz", apic_freq / 1_000_000);
}

/// APIC ベースアドレスを取得
fn get_apic_base_address() -> u64 {
    let msr_value = read_msr(MSR_IA32_APIC_BASE);
    msr_value & 0xFFFF_FFFF_F000 // 下位12ビットをマスク
}

/// APIC タイマー周波数を測定
fn measure_apic_timer_frequency() -> u64 {
    let apic_base = get_apic_base_address();
    if apic_base == 0 {
        return 0;
    }
    
    unsafe {
        // APIC タイマーを一時停止
        write_apic_register(apic_base, APIC_LVT_TIMER, 0x10000);
        
        // 分周比を1:1に設定
        write_apic_register(apic_base, APIC_TIMER_DIVIDE_CONFIG, 0x0B);
        
        // 最大カウント値を設定
        write_apic_register(apic_base, APIC_TIMER_INITIAL_COUNT, 0xFFFFFFFF);
        
        // TSCで時間測定開始
        let start_tsc = read_tsc_serialized();
        let start_apic = read_apic_register(apic_base, APIC_TIMER_CURRENT_COUNT);
        
        // 約10ms待機
        let delay_ns = 10_000_000; // 10ms
        precise_delay_ns(delay_ns);
        
        // 測定終了
        let end_tsc = read_tsc_serialized();
        let end_apic = read_apic_register(apic_base, APIC_TIMER_CURRENT_COUNT);
        
        // APIC タイマーを停止
        write_apic_register(apic_base, APIC_TIMER_INITIAL_COUNT, 0);
        
        // 周波数を計算
        let tsc_diff = end_tsc - start_tsc;
        let apic_diff = start_apic - end_apic; // APIC は減算カウンタ
        let tsc_freq = get_frequency();
        
        if apic_diff > 0 && tsc_freq > 0 {
            (apic_diff as u64 * tsc_freq) / tsc_diff
        } else {
            100_000_000 // デフォルト100MHz
        }
    }
}

/// APIC レジスタを読み取り
unsafe fn read_apic_register(apic_base: u64, offset: usize) -> u32 {
    let addr = (apic_base as usize + offset) as *const u32;
    core::ptr::read_volatile(addr)
}

/// APIC レジスタに書き込み
unsafe fn write_apic_register(apic_base: u64, offset: usize, value: u32) {
    let addr = (apic_base as usize + offset) as *mut u32;
    core::ptr::write_volatile(addr, value);
}

/// MSR（Model Specific Register）を読み取り
pub fn read_msr(msr: u32) -> u64 {
    unsafe {
        let mut low: u32;
        let mut high: u32;
        
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
        
        ((high as u64) << 32) | (low as u64)
    }
}

/// MSR（Model Specific Register）に書き込み
pub fn write_msr(msr: u32, value: u64) {
    unsafe {
        let low = value as u32;
        let high = (value >> 32) as u32;
        
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nostack, preserves_flags)
        );
    }
}

/// CPU周波数を取得
pub fn get_cpu_frequency() -> u64 {
    get_frequency()
}

/// CPU温度を取得（摂氏）
pub fn get_cpu_temperature() -> f32 {
    // 温度ターゲットMSRを読み取り
    let temp_target = read_msr(MSR_TEMPERATURE_TARGET);
    let target_temp = ((temp_target >> 16) & 0xFF) as f32;
    
    // 現在の温度状態を読み取り
    let therm_status = read_msr(MSR_IA32_THERM_STATUS);
    
    if (therm_status & (1 << 31)) != 0 {
        // Digital Readout が有効
        let digital_readout = ((therm_status >> 16) & 0x7F) as f32;
        target_temp - digital_readout
    } else {
        // 温度情報が利用できない場合のデフォルト値
        50.0
    }
}

/// タイマー統計情報
#[derive(Debug, Clone)]
pub struct TimerStats {
    pub tsc_frequency: u64,
    pub apic_frequency: u64,
    pub uptime_ns: u64,
    pub timer_interrupts: u64,
}

/// タイマー統計を取得
pub fn get_timer_stats() -> TimerStats {
    TimerStats {
        tsc_frequency: TSC_FREQUENCY.load(Ordering::Relaxed),
        apic_frequency: APIC_FREQUENCY.load(Ordering::Relaxed),
        uptime_ns: get_uptime_ns(),
        timer_interrupts: TIMER_INTERRUPTS.load(Ordering::Relaxed),
    }
}

/// タイマー割り込みを記録
pub fn record_timer_interrupt() {
    TIMER_INTERRUPTS.fetch_add(1, Ordering::Relaxed);
} 