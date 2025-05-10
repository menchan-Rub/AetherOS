// AetherOS カーネルエントリーポイント
// 
// AetherOSは次世代の適応型ハイブリッドカーネルを実装し、
// 負荷に応じてマイクロカーネルとモノリシックカーネルの特性を
// 動的に最適化します。

#![no_std]
#![no_main]
#![feature(asm_const)]
#![feature(naked_functions)]
#![feature(alloc_error_handler)]
#![feature(core_intrinsics)]
#![feature(let_chains)]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

mod arch;
mod memory;
mod process;
mod sync;
mod ipc;
mod time;
mod drivers;
mod fs;
mod net;
mod security;
mod power;

/// カーネルの初期化が完了したかどうかを示すフラグ
static KERNEL_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// カーネルパニックハンドラ
/// 
/// カーネルでパニックが発生した場合、この関数が呼び出されます。
/// デバッグ情報を表示し、システムを安全な状態に遷移させます。
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // パニック情報を表示
    if let Some(location) = info.location() {
        arch::debug::println!(
            "カーネルパニック at {}:{}: {}",
            location.file(),
            location.line(),
            info.message().unwrap_or(&format_args!("情報なし"))
        );
    } else {
        arch::debug::println!("カーネルパニック: {}", info.message().unwrap_or(&format_args!("情報なし")));
    }

    // カーネル初期化済みの場合は、システムをクラッシュ回復モードに遷移
    if KERNEL_INITIALIZED.load(Ordering::SeqCst) {
        security::crash_recovery::enter_recovery_mode();
    }

    // それ以外の場合は単純に停止
    arch::halt();
    loop {
        // ハードウェア割り込みが有効な場合のために無限ループ
        arch::halt();
    }
}

/// カーネルメインエントリーポイント
/// 
/// ブートローダからの制御移譲後に呼び出される最初の関数です。
#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // アーキテクチャ固有の初期化
    arch::init();
    
    // 早期コンソール初期化
    arch::debug::init_early_console();
    arch::debug::println!("AetherOS カーネル起動中...");
    
    // メモリサブシステム初期化
    memory::init();
    
    // 割り込みとタイマー初期化
    arch::interrupts::init();
    time::init();
    
    // プロセス管理初期化
    process::init();
    
    // デバイスドライバ初期化
    drivers::init();
    
    // ファイルシステム初期化
    fs::init();
    
    // ネットワーク初期化
    net::init();
    
    // セキュリティサブシステム初期化
    security::init();
    
    // 電力管理初期化
    power::init();
    
    // カーネル初期化完了
    KERNEL_INITIALIZED.store(true, Ordering::SeqCst);
    arch::debug::println!("AetherOS カーネル初期化完了");
    
    // システムプロセス起動
    process::spawn_init_process();
    
    // スケジューラに制御を移譲（戻らない）
    process::scheduler::start()
}

/// アロケーションエラーハンドラ
/// 
/// メモリ割り当てが失敗した場合に呼び出されます。
#[alloc_error_handler]
fn alloc_error_handler(layout: core::alloc::Layout) -> ! {
    arch::debug::println!("メモリ割り当てエラー: {:?}", layout);
    panic!("メモリ割り当てに失敗しました");
} 