//! グローバルディスクリプタテーブル（GDT）
//!
//! x86_64アーキテクチャのGDTを初期化・管理します。
//! GDTはセグメンテーションに使用される重要なデータ構造です。
//! x86_64ではページングが主なメモリ保護メカニズムですが、
//! GDTは特権レベルの管理やTSSのために必要です。

use core::mem::size_of;
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

/// カーネルコードセグメントのインデックス
pub const KERNEL_CODE_SELECTOR: u16 = 1;
/// カーネルデータセグメントのインデックス
pub const KERNEL_DATA_SELECTOR: u16 = 2;
/// ユーザコードセグメントのインデックス（64ビットモード用）
pub const USER_CODE_SELECTOR: u16 = 3;
/// ユーザデータセグメントのインデックス
pub const USER_DATA_SELECTOR: u16 = 4;
/// TSSセレクタのインデックス
pub const TSS_SELECTOR: u16 = 5;

/// ダブルフォルト用のISTスタックのインデックス
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
/// NMI用のISTスタックのインデックス
pub const NMI_IST_INDEX: u16 = 1;
/// ページフォルト用のISTスタックのインデックス
pub const PAGE_FAULT_IST_INDEX: u16 = 2;
/// 一般保護例外用のISTスタックのインデックス
pub const GENERAL_PROTECTION_FAULT_IST_INDEX: u16 = 3;
/// スタックフォルト用のISTスタックのインデックス
pub const STACK_FAULT_IST_INDEX: u16 = 4;

/// スタック専用のセクションを宣言
#[cfg(not(test))]
#[link_section = ".interrupt_stacks"]
static mut INTERRUPT_STACKS: [[u8; STACK_SIZE]; 5] = [[0; STACK_SIZE]; 5];

/// 割り込みスタックのサイズ（16KiB）
const STACK_SIZE: usize = 16 * 1024;

/// セグメントセレクタの構造体
pub struct Selectors {
    /// カーネルコード用のセレクタ
    pub kernel_code: SegmentSelector,
    /// カーネルデータ用のセレクタ
    pub kernel_data: SegmentSelector,
    /// ユーザコード用のセレクタ
    pub user_code: SegmentSelector,
    /// ユーザデータ用のセレクタ
    pub user_data: SegmentSelector,
    /// TSS用のセレクタ
    pub tss: SegmentSelector,
}

lazy_static! {
    /// TSSの静的インスタンス
    static ref TSS: Mutex<TaskStateSegment> = {
        let mut tss = TaskStateSegment::new();
        
        // 特殊な例外処理用のスタックを設定
        #[cfg(not(test))]
        unsafe {
            tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
                let stack_top = &INTERRUPT_STACKS[DOUBLE_FAULT_IST_INDEX as usize];
                let stack_top = stack_top.as_ptr() as u64 + STACK_SIZE as u64;
                VirtAddr::new(stack_top)
            };
            
            tss.interrupt_stack_table[NMI_IST_INDEX as usize] = {
                let stack_top = &INTERRUPT_STACKS[NMI_IST_INDEX as usize];
                let stack_top = stack_top.as_ptr() as u64 + STACK_SIZE as u64;
                VirtAddr::new(stack_top)
            };
            
            tss.interrupt_stack_table[PAGE_FAULT_IST_INDEX as usize] = {
                let stack_top = &INTERRUPT_STACKS[PAGE_FAULT_IST_INDEX as usize];
                let stack_top = stack_top.as_ptr() as u64 + STACK_SIZE as u64;
                VirtAddr::new(stack_top)
            };
            
            tss.interrupt_stack_table[GENERAL_PROTECTION_FAULT_IST_INDEX as usize] = {
                let stack_top = &INTERRUPT_STACKS[GENERAL_PROTECTION_FAULT_IST_INDEX as usize];
                let stack_top = stack_top.as_ptr() as u64 + STACK_SIZE as u64;
                VirtAddr::new(stack_top)
            };
            
            tss.interrupt_stack_table[STACK_FAULT_IST_INDEX as usize] = {
                let stack_top = &INTERRUPT_STACKS[STACK_FAULT_IST_INDEX as usize];
                let stack_top = stack_top.as_ptr() as u64 + STACK_SIZE as u64;
                VirtAddr::new(stack_top)
            };
        }
        
        Mutex::new(tss)
    };
    
    /// GDTの静的インスタンス
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();
        
        // セグメントディスクリプタを追加
        // 1: nullディスクリプタ（自動的に追加される）
        let kernel_code = gdt.add_entry(Descriptor::kernel_code_segment());
        let kernel_data = gdt.add_entry(Descriptor::kernel_data_segment());
        let user_code = gdt.add_entry(Descriptor::user_code_segment());
        let user_data = gdt.add_entry(Descriptor::user_data_segment());
        let tss = gdt.add_entry(Descriptor::tss_segment(&TSS.lock()));
        
        // セレクタを保存
        let selectors = Selectors {
            kernel_code,
            kernel_data,
            user_code,
            user_data,
            tss,
        };
        
        (gdt, selectors)
    };
}

/// GDTを初期化
pub fn init_gdt() {
    use x86_64::instructions::segmentation::{Segment, CS, DS, ES, FS, GS, SS};
    use x86_64::instructions::tables::load_tss;
    use x86_64::PrivilegeLevel;
    
    // GDTをロード
    GDT.0.load();
    
    // セグメントレジスタを設定
    unsafe {
        // カーネルコードセグメントをCS（コードセグメント）にロード
        CS::set_reg(GDT.1.kernel_code);
        
        // データセグメントレジスタを設定
        DS::set_reg(GDT.1.kernel_data);
        ES::set_reg(GDT.1.kernel_data);
        FS::set_reg(GDT.1.kernel_data);
        GS::set_reg(GDT.1.kernel_data);
        SS::set_reg(GDT.1.kernel_data);
        
        // TSSをロード
        load_tss(GDT.1.tss);
    }
}

/// TSSのRSP0フィールドを設定
///
/// 割り込みやシステムコールでの特権レベル切り替え時に
/// 使用されるカーネルスタックポインタを設定します。
pub fn set_tss_rsp0(stack_pointer: VirtAddr) {
    TSS.lock().privilege_stack_table[0] = stack_pointer;
}

/// TSSのISTエントリを設定
///
/// 指定されたインデックスのISTエントリに新しいスタックポインタを設定します。
/// ISTエントリはCPU例外や割り込み用の専用スタックを提供します。
pub fn set_tss_ist(index: usize, stack_pointer: VirtAddr) {
    if index < 7 {
        TSS.lock().interrupt_stack_table[index] = stack_pointer;
    }
}

/// GDTから指定されたインデックスのセグメントセレクタを取得
pub fn get_segment_selector(index: u16) -> SegmentSelector {
    match index {
        KERNEL_CODE_SELECTOR => GDT.1.kernel_code,
        KERNEL_DATA_SELECTOR => GDT.1.kernel_data,
        USER_CODE_SELECTOR => GDT.1.user_code,
        USER_DATA_SELECTOR => GDT.1.user_data,
        TSS_SELECTOR => GDT.1.tss,
        _ => panic!("Invalid segment selector index: {}", index),
    }
} 