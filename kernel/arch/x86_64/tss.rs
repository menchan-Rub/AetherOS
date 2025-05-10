//! タスクステートセグメント（TSS）
//!
//! x86_64アーキテクチャのTSSを管理します。
//! TSSは特権レベル切り替え時のスタック情報や
//! 割り込み処理用の専用スタック（IST）を保持します。

use x86_64::VirtAddr;
use x86_64::structures::tss::TaskStateSegment;

/// TSSを初期化
pub fn init_tss() {
    // 実際のTSS初期化はGDT初期化時に行われる
    // GDTモジュールで既にTSSは初期化されているため、
    // ここでは追加の初期化が必要な場合のみ処理を行う
}

/// 特権レベル0用のスタックポインタを設定
pub fn set_kernel_stack(stack_ptr: VirtAddr) {
    // GDTモジュールの関数を利用
    crate::arch::x86_64::gdt::set_tss_rsp0(stack_ptr);
}

/// 指定したISTエントリにスタックポインタを設定
pub fn set_ist_stack(ist_index: usize, stack_ptr: VirtAddr) {
    // 範囲チェック（x86_64のISTは0-6の7エントリ）
    if ist_index < 7 {
        // GDTモジュールの関数を利用
        crate::arch::x86_64::gdt::set_tss_ist(ist_index, stack_ptr);
    }
}

/// カレントCPUのIDを取得（将来的な拡張用）
pub fn get_current_cpu_id() -> u32 {
    // 現在は単一CPUを想定
    0
} 