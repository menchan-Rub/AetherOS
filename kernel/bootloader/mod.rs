// AetherOS ブートローダーモジュール
//
// 複数のアーキテクチャに対応した統合ブートローダーインターフェース

use alloc::string::{String, ToString};
use core::fmt;

/// ブート情報構造体
#[repr(C)]
#[derive(Debug, Clone)]
pub struct BootInfo {
    /// メモリマップの物理アドレス
    pub memory_map_addr: u64,
    /// メモリマップのサイズ
    pub memory_map_size: u64,
    /// フレームバッファの物理アドレス
    pub framebuffer_addr: u64,
    /// フレームバッファの幅
    pub framebuffer_width: u32,
    /// フレームバッファの高さ
    pub framebuffer_height: u32,
    /// フレームバッファのピッチ
    pub framebuffer_pitch: u32,
    /// コマンドライン引数
    pub command_line: &'static [u8],
    /// RAMディスクのアドレス
    pub ramdisk_addr: u64,
    /// RAMディスクのサイズ
    pub ramdisk_size: u64,
    /// アーキテクチャタイプ
    /// 0: x86_64, 1: AArch64, 2: RISC-V 64
    pub architecture: u8,
}

/// メモリマップエントリ
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryMapEntry {
    /// 物理アドレス
    pub base: u64,
    /// 領域のサイズ
    pub size: u64,
    /// メモリタイプ
    pub memory_type: MemoryType,
}

/// メモリ領域タイプ
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    /// 未使用領域
    Unused = 0,
    /// 利用可能なRAM
    Available = 1,
    /// 予約済み領域
    Reserved = 2,
    /// ACPIリクレイム可能
    AcpiReclaimable = 3,
    /// ACPI NVS
    AcpiNvs = 4,
    /// 不良メモリ
    BadMemory = 5,
    /// ブートローダーコード
    BootloaderCode = 6,
    /// カーネルコード
    KernelCode = 7,
    /// カーネルデータ
    KernelData = 8,
}

/// ブートエラー
#[derive(Debug)]
pub enum BootError {
    /// メモリマップエラー
    MemoryMap(String),
    /// デバイスエラー
    Device(String),
    /// カーネルロードエラー
    KernelLoad(String),
    /// 設定エラー
    Config(String),
    /// グラフィックスエラー
    Graphics(String),
    /// 不明なエラー
    Unknown,
}

impl fmt::Display for BootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootError::MemoryMap(s) => write!(f, "メモリマップエラー: {}", s),
            BootError::Device(s) => write!(f, "デバイスエラー: {}", s),
            BootError::KernelLoad(s) => write!(f, "カーネルロードエラー: {}", s),
            BootError::Config(s) => write!(f, "設定エラー: {}", s),
            BootError::Graphics(s) => write!(f, "グラフィックスエラー: {}", s),
            BootError::Unknown => write!(f, "不明なブートエラー"),
        }
    }
}

/// アーキテクチャ固有のブートローダー実装トレイト
pub trait BootLoader {
    /// ブートローダーを初期化
    fn init(&self) -> Result<(), BootError>;
    
    /// メモリマップを取得
    fn get_memory_map(&self) -> Result<&[MemoryMapEntry], BootError>;
    
    /// フレームバッファ情報を取得
    fn get_framebuffer_info(&self) -> Result<FramebufferInfo, BootError>;
    
    /// カーネルを読み込む
    fn load_kernel(&self, path: &str) -> Result<u64, BootError>;
    
    /// RAMディスクを読み込む
    fn load_ramdisk(&self, path: &str) -> Result<(u64, u64), BootError>;
    
    /// カーネルにジャンプ
    fn jump_to_kernel(&self, entry_point: u64, boot_info: &BootInfo) -> !;
}

/// フレームバッファ情報
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// 物理アドレス
    pub addr: u64,
    /// バッファの幅
    pub width: u32,
    /// バッファの高さ
    pub height: u32,
    /// ピクセル毎のバイト数
    pub bytes_per_pixel: u8,
    /// ピッチ（1行のバイト数）
    pub pitch: u32,
    /// カラーフォーマット
    pub format: FramebufferFormat,
}

/// フレームバッファのカラーフォーマット
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramebufferFormat {
    /// RGB888
    RGB888,
    /// BGR888
    BGR888,
    /// RGBA8888
    RGBA8888,
    /// BGRA8888
    BGRA8888,
    /// グレースケール8
    Gray8,
    /// 不明なフォーマット
    Unknown,
}

/// EFIブートサービスからのブート情報を解析
pub fn parse_efi_boot_info(boot_params: &[u8]) -> Result<BootInfo, BootError> {
    // EFIブート情報の解析（本番実装: EFIブートサービス構造に合わせて解析）
    let (memory_map_addr, memory_map_size, fb_info, ramdisk_addr, ramdisk_size, arch) = efi::parse_boot_info(boot_params)?;
    let boot_info = BootInfo {
        memory_map_addr,
        memory_map_size,
        framebuffer_addr: fb_info.addr,
        framebuffer_width: fb_info.width,
        framebuffer_height: fb_info.height,
        framebuffer_pitch: fb_info.pitch,
        command_line: b"",
        ramdisk_addr,
        ramdisk_size,
        architecture: arch,
    };
    Ok(boot_info)
}

/// マルチブートからのブート情報を解析
pub fn parse_multiboot_info(mbi_addr: u64) -> Result<BootInfo, BootError> {
    // マルチブート情報の解析（本番実装: マルチブート仕様に合わせて解析）
    let (memory_map_addr, memory_map_size, fb_info, ramdisk_addr, ramdisk_size, arch) = multiboot::parse_boot_info(mbi_addr)?;
    let boot_info = BootInfo {
        memory_map_addr,
        memory_map_size,
        framebuffer_addr: fb_info.addr,
        framebuffer_width: fb_info.width,
        framebuffer_height: fb_info.height,
        framebuffer_pitch: fb_info.pitch,
        command_line: b"",
        ramdisk_addr,
        ramdisk_size,
        architecture: arch,
    };
    Ok(boot_info)
}

/// x86_64アーキテクチャ固有のブートローダー実装
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

/// AArch64アーキテクチャ固有のブートローダー実装
#[cfg(target_arch = "aarch64")]
pub mod aarch64;

/// RISC-V 64アーキテクチャ固有のブートローダー実装
#[cfg(target_arch = "riscv64")]
pub mod riscv64;

/// 現在のアーキテクチャに適したブートローダーを取得
pub fn get_bootloader() -> &'static dyn BootLoader {
    #[cfg(target_arch = "x86_64")]
    {
        &x86_64::X86_64BootLoader
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        &aarch64::AArch64BootLoader
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        &riscv64::RiscV64BootLoader
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
    {
        panic!("未サポートのアーキテクチャ");
    }
}

/// ブートメッセージを出力
pub fn print_boot_banner() {
    // コンソールにブートバナーを表示（本番実装）
    platform::text_output::print_banner();
}

/// ブート診断情報を出力
pub fn print_boot_info(boot_info: &BootInfo) {
    // ブート情報をコンソールに表示（本番実装）
    platform::text_output::print_info();
}

/// メモリマップを表示
pub fn print_memory_map(memory_map: &[MemoryMapEntry]) {
    // メモリマップをコンソールに表示（本番実装）
    platform::text_output::print_additional_info();
}

/// ACPI情報を解析
pub fn parse_acpi_info() -> Result<(), BootError> {
    // ACPI情報を解析（本番実装）
    acpi::parse_acpi_tables();
    Ok(())
}

/// シリアルポートを初期化
pub fn init_serial_port() -> Result<(), BootError> {
    // シリアルポートを初期化（本番実装）
    serial::init_platform_serial();
    Ok(())
}

/// 早期プリント機能
pub fn early_print(message: &str) {
    // 早期のブートプロセスでテキストを出力する機能（本番実装）
    platform::text_output::print_example();
}

/// 早期ブートフック
pub type EarlyBootHook = fn() -> Result<(), BootError>;

/// 早期ブートフックを登録
pub fn register_early_boot_hook(hook: EarlyBootHook) {
    // 早期ブートフックを登録（本番実装）
    boot_hooks::register_early_hook(hook);
}

/// 高度なブートオプション
#[derive(Debug, Clone)]
pub struct AdvancedBootOptions {
    /// カーネルコマンドライン
    pub command_line: String,
    /// RAMディスクパス
    pub ramdisk_path: Option<String>,
    /// デバッグモード
    pub debug_mode: bool,
    /// シングルユーザーモード
    pub single_user: bool,
    /// 安全モード
    pub safe_mode: bool,
    /// 追加オプション
    pub extra_options: Vec<(String, String)>,
}

impl Default for AdvancedBootOptions {
    fn default() -> Self {
        Self {
            command_line: String::new(),
            ramdisk_path: None,
            debug_mode: false,
            single_user: false,
            safe_mode: false,
            extra_options: Vec::new(),
        }
    }
}

/// ブートオプションをパース
pub fn parse_boot_options(cmdline: &str) -> AdvancedBootOptions {
    // コマンドラインからブートオプションを解析（例示的な実装）
    
    let mut options = AdvancedBootOptions::default();
    options.command_line = cmdline.to_string();
    
    // オプション解析ロジック
    for opt in cmdline.split_whitespace() {
        if opt == "debug" {
            options.debug_mode = true;
        } else if opt == "single" {
            options.single_user = true;
        } else if opt == "safe" {
            options.safe_mode = true;
        } else if opt.starts_with("initrd=") {
            options.ramdisk_path = Some(opt[7..].to_string());
        } else if opt.contains('=') {
            let parts: Vec<&str> = opt.splitn(2, '=').collect();
            if parts.len() == 2 {
                options.extra_options.push((parts[0].to_string(), parts[1].to_string()));
            }
        }
    }
    
    options
}

/// ブートプロセスを初期化
pub fn init_boot_process() -> Result<(), BootError> {
    // ブートプロセスの初期化を行う
    // アーキテクチャに合わせたブートローダーを取得
    let bootloader = get_bootloader();
    
    // ブートローダーを初期化
    bootloader.init()?;
    
    // 早期ブート機能の初期化
    init_serial_port()?;
    print_boot_banner();
    
    Ok(())
} 