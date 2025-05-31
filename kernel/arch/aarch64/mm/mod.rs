// AetherOS AArch64 メモリ管理サブシステム
//
// ARMv8-A アーキテクチャのメモリ管理機能を実装します。

pub mod page_table;
pub mod memory_types;

/// メモリ管理サブシステムを初期化
pub fn init() {
    // メモリタイプの初期化
    memory_types::init();
    
    // ページテーブルの初期化
    page_table::init();
    
    log::info!("AArch64メモリ管理サブシステム初期化完了");
} 