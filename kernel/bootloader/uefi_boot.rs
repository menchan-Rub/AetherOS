// UEFIブートローダーモジュール
//
// UEFI環境でカーネルを起動するブートローダー実装

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ptr;
use core::mem;
use core::slice;
use super::boot_info::BootInfo;
use super::memory_map::{MemoryMap, MemoryRegion, MemoryType};
use super::graphics::{FramebufferInfo, GraphicsMode, set_graphics_mode_uefi};

// この変数はUEFIランタイムサービスへのアクセスを保持するために使用
static mut UEFI_SYSTEM_TABLE: Option<&'static uefi::prelude::SystemTable<uefi::table::Runtime>> = None;

/// UEFIが利用可能かチェック
pub fn check_uefi_available() -> Result<bool, &'static str> {
    // UEFIシステムテーブルが初期化されているかどうかをチェック
    unsafe {
        Ok(UEFI_SYSTEM_TABLE.is_some())
    }
}

/// UEFI環境情報を初期化
fn init_uefi_info(
    system_table: &mut uefi::prelude::SystemTable<uefi::prelude::Boot>,
) -> Result<(), &'static str> {
    // UEFIサービスを初期化（uefi-rsクレートのヘルパー関数）
    uefi_services::init(system_table).map_err(|_| "UEFIサービスの初期化に失敗しました")?;
    
    // ロギングを初期化
    log::set_logger(&UEFI_LOGGER).map_err(|_| "UEFIロガーの設定に失敗しました")?;
    log::set_max_level(log::LevelFilter::Info);
    
    // 出力デバイスをクリア
    system_table.stdout().clear().map_err(|_| "画面のクリアに失敗しました")?;
    
    Ok(())
}

/// ELFファイルをロード
fn load_elf_kernel(
    boot_services: &uefi::prelude::BootServices,
    kernel_path: &str,
) -> Result<(usize, usize, usize), &'static str> {
    // EFIファイルシステムプロトコルを取得
    let fs = boot_services
        .locate_protocol::<uefi::proto::media::fs::SimpleFileSystem>()
        .map_err(|_| "ファイルシステムプロトコルの取得に失敗しました")?
        .get();
    
    // ルートディレクトリを開く
    let mut root = unsafe { &mut *fs }.open_volume()
        .map_err(|_| "ルートボリュームのオープンに失敗しました")?;
    
    // カーネルファイルを開く
    let handle = root.open(
        kernel_path,
        uefi::proto::media::file::FileMode::Read,
        uefi::proto::media::file::FileAttribute::empty(),
    ).map_err(|_| "カーネルファイルのオープンに失敗しました")?;
    
    let mut file = match handle.into_type().map_err(|_| "ファイルタイプの変換に失敗しました")? {
        uefi::proto::media::file::FileType::Regular(file) => file,
        _ => return Err("カーネルは通常のファイルである必要があります"),
    };
    
    // ファイルサイズを取得
    let file_size = file.get_info::<uefi::proto::media::file::FileInfo>()
        .map_err(|_| "ファイル情報の取得に失敗しました")?
        .file_size() as usize;
    
    // カーネルファイルを読み込むためのバッファを確保
    let buffer_size = (file_size + 0xFFF) & !0xFFF; // 4KBでアラインメント
    
    let kernel_buffer = boot_services
        .allocate_pool(uefi::table::boot::MemoryType::LOADER_DATA, buffer_size)
        .map_err(|_| "カーネルバッファの確保に失敗しました")?;
    
    // ファイルを読み込み
    let mut read_size = file_size;
    file.read(&mut unsafe { slice::from_raw_parts_mut(kernel_buffer, file_size) })
        .map_err(|_| "カーネルファイルの読み込みに失敗しました")?
        .map(|size| read_size = size)
        .unwrap_or(());
    
    if read_size != file_size {
        return Err("カーネルファイルの読み込みサイズが不一致です");
    }
    
    // ELFヘッダの解析
    let elf_header = unsafe { &*(kernel_buffer as *const elf::file::Header) };
    
    // マジックナンバーをチェック
    if !elf_header.is_valid() {
        return Err("無効なELFファイルです");
    }
    
    // プログラムヘッダをロード
    let ph_offset = elf_header.ph_offset as usize;
    let ph_size = elf_header.ph_entry_size as usize;
    let ph_count = elf_header.ph_count as usize;
    
    // エントリーポイントアドレス
    let entry_point = elf_header.entry_point as usize;
    
    // カーネルのロード範囲を記録
    let mut kernel_start = usize::MAX;
    let mut kernel_end = 0;
    
    // プログラムヘッダを処理
    for i in 0..ph_count {
        let ph_addr = kernel_buffer as usize + ph_offset + i * ph_size;
        let ph = unsafe { &*(ph_addr as *const elf::program::ProgramHeader) };
        
        // ロード可能なセグメントのみ処理
        if ph.p_type != elf::program::Type::Load {
            continue;
        }
        
        // セグメントのメモリ範囲
        let seg_start = ph.p_vaddr as usize;
        let seg_size = ph.p_memsz as usize;
        let seg_file_size = ph.p_filesz as usize;
        let seg_file_offset = ph.p_offset as usize;
        let seg_end = seg_start + seg_size;
        
        // カーネル範囲を更新
        kernel_start = core::cmp::min(kernel_start, seg_start);
        kernel_end = core::cmp::max(kernel_end, seg_end);
        
        // セグメント用のメモリを確保
        let pages = (seg_size + 0xFFF) / 0x1000;
        let seg_addr = boot_services
            .allocate_pages(
                uefi::table::boot::AllocateType::Address(seg_start),
                uefi::table::boot::MemoryType::LOADER_DATA,
                pages,
            )
            .map_err(|_| "カーネルセグメント用のメモリ確保に失敗しました")?;
        
        // メモリをゼロクリア
        unsafe {
            ptr::write_bytes(seg_addr as *mut u8, 0, seg_size);
        }
        
        // ファイルからのデータをコピー
        if seg_file_size > 0 {
            unsafe {
                ptr::copy_nonoverlapping(
                    (kernel_buffer as usize + seg_file_offset) as *const u8,
                    seg_addr as *mut u8,
                    seg_file_size,
                );
            }
        }
    }
    
    // カーネルバッファを解放（セグメントはすでにコピー済み）
    boot_services
        .free_pool(kernel_buffer)
        .map_err(|_| "カーネルバッファの解放に失敗しました")?;
    
    Ok((entry_point, kernel_start, kernel_end))
}

/// ACPIテーブルのRSDP（Root System Description Pointer）を取得
fn get_acpi_rsdp(system_table: &uefi::prelude::SystemTable<uefi::prelude::Boot>) -> Option<usize> {
    // UEFIシステムテーブルからACPIテーブルを取得
    let acpi = system_table.config_table()
        .iter()
        .find(|entry| entry.guid == uefi::table::cfg::ACPI2_GUID || entry.guid == uefi::table::cfg::ACPI_GUID)
        .map(|entry| entry.address as usize);
    
    acpi
}

/// UEFI環境からブート
pub fn boot() -> Result<super::BootInfo, &'static str> {
    // UEFIブートローダーは `efi_main` エントリーポイントから呼び出される前提
    // ここではすでにグローバルなUEFIハンドルとシステムテーブルが設定されていると仮定
    
    let uefi_system_table = uefi_services::system_table();
    let boot_services = uefi_system_table.boot_services();
    
    // UEFIログとプロトコルを初期化
    init_uefi_info(uefi_system_table).map_err(|_| "UEFIの初期化に失敗しました")?;
    
    // ブート情報
    log::info!("AetherOS UEFI ブートローダーを開始します");
    log::info!("UEFI バージョン: {}.{}", 
               uefi_system_table.uefi_revision().major(), 
               uefi_system_table.uefi_revision().minor());
    
    // グラフィックモードを設定
    let mut framebuffer = None;
    if let Ok(gop) = boot_services.locate_protocol::<uefi::proto::console::gop::GraphicsOutput>() {
        let gop = unsafe { &mut *gop.get() };
        match set_graphics_mode_uefi(gop, Some(GraphicsMode::default())) {
            Ok(fb) => {
                log::info!("グラフィックモード設定: {}x{}", fb.width, fb.height);
                framebuffer = Some(fb);
            },
            Err(e) => {
                log::warn!("グラフィックモード設定に失敗: {}", e);
            }
        }
    }
    
    // カーネルをロード
    let (entry_point, kernel_start, kernel_end) = load_elf_kernel(boot_services, "\\EFI\\AetherOS\\kernel.elf")
        .map_err(|e| {
            log::error!("カーネルのロードに失敗: {}", e);
            e
        })?;
    
    log::info!("カーネルロード: 開始={:#x}, 終了={:#x}, エントリポイント={:#x}", 
              kernel_start, kernel_end, entry_point);
    
    // ACPIテーブルのRSDPアドレスを取得
    let acpi_rsdp = get_acpi_rsdp(uefi_system_table);
    if let Some(rsdp) = acpi_rsdp {
        log::info!("ACPI RSDP: {:#x}", rsdp);
    } else {
        log::warn!("ACPI RSDPが見つかりませんでした");
    }
    
    // コマンドライン引数（存在する場合）
    let cmdline = String::from("console=tty0 loglevel=4");
    
    // メモリマップを取得
    let mut memory_map_buf = [0u8; 4096 * 4]; // 16KBのバッファ
    let memory_map_info = boot_services
        .memory_map(&mut memory_map_buf)
        .map_err(|_| "メモリマップの取得に失敗しました")?;
    
    // メモリマップを変換
    let memory_map = MemoryMap::from_uefi(&memory_map_buf[..memory_map_info.map_size], memory_map_info.entry_size);
    
    // ブート情報を作成
    let mut boot_info = BootInfo::from_uefi(
        memory_map,
        framebuffer,
        acpi_rsdp,
        cmdline,
    );
    
    // カーネル物理メモリ範囲を設定
    boot_info.set_kernel_physical_range(kernel_start, kernel_end);
    
    // ブートサービスの終了前にランタイムサービスを保存
    let runtime_services = unsafe {
        let rt = uefi_system_table.runtime_services().clone();
        // グローバル変数にランタイムサービスを保存
        UEFI_SYSTEM_TABLE = Some(core::mem::transmute(rt));
        UEFI_SYSTEM_TABLE.unwrap()
    };
    
    // ブートサービスを終了
    let (_runtime, memory_map_buf) = uefi_system_table
        .exit_boot_services(uefi_services::handles().image, &mut memory_map_buf)
        .map_err(|_| "ブートサービスの終了に失敗しました")?;
    
    // この時点でUEFIブートサービスは使用不可、
    // ランタイムサービスのみ使用可能
    
    // 仮想メモリを設定
    // ... (次のステップでカーネルに制御を渡す)
    
    Ok(boot_info)
}

/// UEFIロガー（シンプルなロギング実装）
static UEFI_LOGGER: UefiLogger = UefiLogger;

struct UefiLogger;

impl log::Log for UefiLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            // UEFIコンソールに出力
            let system_table = uefi_services::system_table();
            let _ = system_table.stdout().write_fmt(format_args!(
                "[{:>5}] {}\r\n",
                record.level(),
                record.args()
            ));
        }
    }

    fn flush(&self) {}
} 