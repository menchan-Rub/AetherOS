// AetherOS カーネルコアモジュール
//
// カーネルの中核機能を提供するサブシステム

pub mod memory;
pub mod process;
pub mod fs;
pub mod network;
pub mod graphics;
pub mod sync;
pub mod time;
pub mod security;
pub mod distributed;
pub mod auto_healing;
pub mod debug;

use alloc::sync::Arc;
use alloc::format;
use sync::{Mutex, RwLock};

/// カーネルコア初期化
pub fn init() -> Result<(), &'static str> {
    // 基本サブシステムを初期化
    time::init()?;
    sync::init()?;
    
    // メモリ管理を初期化
    memory::init(0x10000000, 0x100000000); // 例：256MB RAM、実際の値はブートローダから取得
    
    // プロセス管理を初期化
    process::init()?;
    
    // ファイルシステムを初期化
    fs::init()?;
    
    // ネットワークを初期化
    network::init()?;
    
    // グラフィックスを初期化
    graphics::init()?;
    
    // セキュリティサブシステムを初期化
    security::init()?;
    
    // 分散システムモジュールを初期化
    distributed::init()?;

    // テレページングの初期化（分散メモリシステム）
    init_telepaging()?;
    
    // 自己修復モジュールを初期化
    auto_healing::init()?;
    
    log::info!("カーネルコア初期化完了");
    Ok(())
}

/// テレページングを初期化
fn init_telepaging() -> Result<(), &'static str> {
    // 分散クラスタとネットワークマネージャのインスタンスを取得
    let network_manager = network::get_global_manager();
    let cluster_manager = distributed::get_global_cluster();
    
    // テレページングシステムを初期化
    memory::init_telepaging(
        Arc::clone(&network_manager),
        Arc::clone(&cluster_manager)
    );
    
    log::info!("テレページング初期化完了");
    Ok(())
}

/// カーネルバナーを表示
pub fn print_banner() {
    let banner = r#"
    █████╗ ███████╗████████╗██╗  ██╗███████╗██████╗  ██████╗ ███████╗
   ██╔══██╗██╔════╝╚══██╔══╝██║  ██║██╔════╝██╔══██╗██╔═══██╗██╔════╝
   ███████║█████╗     ██║   ███████║█████╗  ██████╔╝██║   ██║███████╗
   ██╔══██║██╔══╝     ██║   ██╔══██║██╔══╝  ██╔══██╗██║   ██║╚════██║
   ██║  ██║███████╗   ██║   ██║  ██║███████╗██║  ██║╚██████╔╝███████║
   ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
                             次世代OS
    "#;
    
    println!("{}", banner);
    println!("バージョン: {}", crate::VERSION);
    println!("構築日時: {}", crate::BUILD_DATE);
    println!("");
}

/// カーネルシャットダウン
pub fn shutdown() -> ! {
    log::info!("カーネルシャットダウン開始");
    
    // 各サブシステムをシャットダウン（逆順）
    auto_healing::shutdown();
    distributed::shutdown();
    security::shutdown();
    graphics::shutdown();
    network::shutdown();
    fs::shutdown();
    process::shutdown();
    memory::shutdown();
    
    log::info!("カーネルシャットダウン完了");
    
    // システムの電源オフ
    crate::arch::power_off();
    
    // 万が一電源オフに失敗した場合
    loop {
        crate::arch::cpu::halt();
    }
} 