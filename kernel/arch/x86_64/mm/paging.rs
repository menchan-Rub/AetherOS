use core::arch::asm;
use crate::core::debug::serial::serial_println;

// GDTモジュールからインポート
use crate::arch::x86_64::mm::gdt::{self, KERNEL_CODE_SELECTOR, KERNEL_DATA_SELECTOR};

// page_table.rs から必要なものをインポート
use crate::arch::x86_64::mm::page_table::{
    Pml4Entry, PdptEntry, PdEntry, PtEntry, PageTableEntry
};
// page_table/flag.rs からフラグをインポート
use crate::arch::x86_64::mm::page_table::flag::PageTableFlags;

use crate::arch::x86_64::mm::memory_types::PhysAddr; // PhysAddr をインポート

// ページング関連のエラー型
#[derive(Debug)]
pub enum PagingError {
    GdtError(&'static str),
    PageTableError(&'static str),
    RegisterError(&'static str),
    PhysicalMemoryAllocationError(&'static str),
}

// ページテーブル用の静的領域 (仮配置)
// これらのテーブルは4KBアライメントされている必要がある。
// リンカスクリプトで適切に配置するか、物理メモリアロケータから取得する。
// ここでは簡単のため、BSSセクションに配置されると仮定し、mut static で宣言。
// 安全な初期化は `Once` やブート時アロケータで行う。
#[repr(align(4096))]
struct PageTableAligned<T>([T; 512]);

// グローバルにアクセス可能なページテーブル構造体 (ブート時初期化)
// 注意: `static mut` は本番コードでは避けるべき。物理メモリアロケータ導入までの仮措置。
static mut KERNEL_PML4_TABLE: PageTableAligned<Pml4Entry> = PageTableAligned([Pml4Entry::new_empty(); 512]);
static mut KERNEL_PDPT_TABLE: PageTableAligned<PdptEntry> = PageTableAligned([PdptEntry::new_empty(); 512]);
// 最初のPDと、最初の数MiBをカバーするためのPTをいくつか静的に確保
// 例: 最初の4MiBを4KBページでマッピングする場合: 1つのPD + 2つのPT (1PDは512エントリで2MiB、1PTは512エントリで2MiB)
// もし2MiBページを使うなら、PDのみでPTは不要になる箇所もある。
static mut KERNEL_PD_TABLES: [PageTableAligned<PdEntry>; 1] = [PageTableAligned([PdEntry::new_empty(); 512])]; // 1つのPDで 512 * 2MiB = 1GiB (2MiBページ) or 512 * 512 * 4KiB = 1GiB (4KiBページ)
static mut KERNEL_PT_TABLES: [PageTableAligned<PtEntry>; 2] = [ // 2つのPTで 2 * 512 * 4KiB = 4MiB
    PageTableAligned([PtEntry::new_empty(); 512]),
    PageTableAligned([PtEntry::new_empty(); 512]),
];

/// x86_64アーキテクチャにおけるページングと保護モードの初期化
///
/// # Safety
/// この関数はハードウェアレジスタを直接操作し、システムのメモリマッピングを根本的に変更するため、
/// 呼び出し元は細心の注意を払う必要があります。誤った設定はシステムクラッシュに繋がります。
pub unsafe fn init() -> Result<(), PagingError> {
    serial_println!("Initializing GDT for x86_64...");
    gdt::init_gdt(); // GDTモジュールの初期化関数を呼び出す
    serial_println!("GDT initialized.");

    serial_println!("Initializing page tables (identity mapping kernel)...");
    let pml4_physical_addr = setup_identity_page_tables()?;
    serial_println!("Page tables initialized. PML4 at: {:#x}", pml4_physical_addr.as_u64());

    serial_println!("Loading PML4 address into CR3...");
    load_pml4(pml4_physical_addr);
    serial_println!("CR3 loaded.");

    serial_println!("Enabling paging features in CR0 and CR4...");
    enable_paging_features();
    serial_println!("Paging features enabled.");

    serial_println!("Reloading segment registers...");
    reload_segment_registers();
    serial_println!("Segment registers reloaded.");

    // 新しいスタックポインタの設定は、この関数の呼び出し後、
    // ロングモードへのジャンプと共に行われるのが一般的。
    // ここではその準備が整ったことを示す。

    Ok(())
}

/// ページテーブルの構築 (カーネル領域のアイデンティティマッピング)
/// PML4テーブルの物理アドレスを返す
unsafe fn setup_identity_page_tables() -> Result<PhysAddr, PagingError> {
    serial_println!("  Setting up identity page tables...");

    // 静的領域の物理アドレスを取得 (仮実装: アドレスを直接キャスト)
    // 本来はリンカからシンボルアドレスを取得するか、アロケータから確保する。
    let pml4_addr = PhysAddr::new(&KERNEL_PML4_TABLE as *const _ as u64);
    let pdpt_addr = PhysAddr::new(&KERNEL_PDPT_TABLE as *const _ as u64);
    let pd0_addr  = PhysAddr::new(&KERNEL_PD_TABLES[0] as *const _ as u64);
    let pt0_addr  = PhysAddr::new(&KERNEL_PT_TABLES[0] as *const _ as u64);
    let pt1_addr  = PhysAddr::new(&KERNEL_PT_TABLES[1] as *const _ as u64);

    serial_println!("    PML4: {:#x}, PDPT: {:#x}, PD0: {:#x}, PT0: {:#x}, PT1: {:#x}",
        pml4_addr.as_u64(), pdpt_addr.as_u64(), pd0_addr.as_u64(), pt0_addr.as_u64(), pt1_addr.as_u64());

    // PML4テーブルの最初のエントリを設定
    // PML4[0] -> PDPT
    let pml4_entry = Pml4Entry::new(pdpt_addr, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
    KERNEL_PML4_TABLE.0[0] = pml4_entry;

    // PDPTの最初のエントリを設定
    // PDPT[0] -> PD0 (最初のページディレクトリ)
    let pdpt_entry = PdptEntry::new(pd0_addr, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
    KERNEL_PDPT_TABLE.0[0] = pdpt_entry;

    // 最初の4MiBをアイデンティティマッピングする (4KBページを使用)
    // PD0[0] -> PT0 (0 - 2MiB)
    // PD0[1] -> PT1 (2MiB - 4MiB)
    let pd0_entry_for_pt0 = PdEntry::new(pt0_addr, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
    KERNEL_PD_TABLES[0].0[0] = pd0_entry_for_pt0;

    let pd0_entry_for_pt1 = PdEntry::new(pt1_addr, PageTableFlags::PRESENT | PageTableFlags::WRITABLE);
    KERNEL_PD_TABLES[0].0[1] = pd0_entry_for_pt1;

    // PT0 と PT1 のエントリを設定 (0 - 4MiB)
    for i in 0..512 { // PT0: 0 to 2MiB-4KB
        let phys_addr = PhysAddr::new((i * 0x1000) as u64); // 4KBページサイズ
        let pt_entry = PtEntry::new(phys_addr, PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE); // データ領域はNXビットを立てる
        KERNEL_PT_TABLES[0].0[i] = pt_entry;
    }
    for i in 0..512 { // PT1: 2MiB to 4MiB-4KB
        let phys_addr = PhysAddr::new(((i + 512) * 0x1000) as u64);
        let pt_entry = PtEntry::new(phys_addr, PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE);
        KERNEL_PT_TABLES[1].0[i] = pt_entry;
    }
    
    // より広範囲（例: 最初の1GiB）を2MiBページでアイデンティティマッピングする場合
    // KERNEL_PD_TABLES[0] の残りのエントリを使用
    for i in 2..512 { // PD0 のエントリ 2 から (4MiB以降)
        // 2MiBページでマッピング
        let base_phys_addr_2mib = (i * 0x200000) as u64; // 2MiB境界
        let pd_entry_2mib = PdEntry::new_2mb_page(
            PhysAddr::new(base_phys_addr_2mib),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE | PageTableFlags::HUGE_PAGE
        );
        KERNEL_PD_TABLES[0].0[i] = pd_entry_2mib;
        if i < 5 { // 最初の数エントリだけログ出力
             serial_println!("    PD0[{}] Mapped 2MiB page at {:#x}", i, base_phys_addr_2mib);
        }
    }

    serial_println!("  Identity page tables set up for the first 1GiB (mixed 4KB and 2MB pages).");
    Ok(pml4_addr)
}

/// CR3レジスタにPML4テーブルの物理アドレスをロード
unsafe fn load_pml4(pml4_physical_addr: PhysAddr) {
    asm!("mov cr3, {}", in(reg) pml4_physical_addr.as_u64(), options(nostack, preserves_flags));
}

/// CR0およびCR4レジスタのページング関連ビットを有効化
unsafe fn enable_paging_features() {
    // CR0: PG (Paging) と PE (Protection Enable) を有効化
    let mut cr0: u64;
    asm!("mov {}, cr0", out(reg) cr0);
    cr0 |= 0x80000001; // PG (bit 31), PE (bit 0)
    asm!("mov cr0, {}", in(reg) cr0);

    // CR4: PAE (Physical Address Extension) を有効化 (ロングモードでは必須)
    //      PGE (Page Global Enable) を有効化 (パフォーマンス向上のため推奨)
    //      OSFXSR (OS Support for FXSAVE/FXRSTOR) と OSXMMEXCPT (OS Support for SSE Exceptions) も
    //      SSEなどを使用する場合は有効にするのが一般的。
    let mut cr4: u64;
    asm!("mov {}, cr4", out(reg) cr4);
    cr4 |= 0x00000020; // PAE (bit 5)
    cr4 |= 0x00000080; // PGE (bit 7)
    // cr4 |= 0x00000200; // OSFXSR (bit 9)
    // cr4 |= 0x00000400; // OSXMMEXCPT (bit 10)
    asm!("mov cr4, {}", in(reg) cr4);

    // EFER (Extended Feature Enable Register) MSR:
    // LME (Long Mode Enable) を有効化
    // SCE (System Call Extensions) を有効化 (syscall/sysret命令用)
    // NXE (No-Execute Enable) を有効化 (セキュリティ向上のため推奨)
    let efer_msr_addr: u32 = 0xC0000080;
    let mut eax_val: u32;
    let mut edx_val: u32;
    asm!("rdmsr", in("ecx") efer_msr_addr, out("eax") eax_val, out("edx") edx_val);
    let mut efer_val = ((edx_val as u64) << 32) | (eax_val as u64);

    efer_val |= (1 << 8);  // LME (bit 8)
    efer_val |= (1 << 0);  // SCE (bit 0)
    efer_val |= (1 << 11); // NXE (bit 11)

    let eax_val_new = efer_val as u32;
    let edx_val_new = (efer_val >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") efer_msr_addr,
        in("eax") eax_val_new,
        in("edx") edx_val_new,
        options(nostack, preserves_flags)
    );

    serial_println!("  CR0, CR4, EFER updated for paging.");
}

/// セグメントレジスタのリロード
unsafe fn reload_segment_registers() {
    // CSレジスタはロングモード用のGDTセレクタでリロード
    // retfq (far return) を使用してCSとRIPを同時に設定
    asm!(
        "push {sel}",      // 新しいコードセグメントセレクタ (KERNEL_CODE_SELECTOR)
        "lea {tmp}, [1f + rip]", // 次の命令(1f)のRIP相対アドレスを計算
        "push {tmp}",      // リターンアドレスとしてプッシュ
        "retfq",           // far return: スタックからRIPとCSをポップしてロード
        "1:",              // ラベル
        sel = const KERNEL_CODE_SELECTOR,
        tmp = lateout(reg) _, // 一時レジスタ
        options(nostack, preserves_flags)
    );

    // データセグメントレジスタ (DS, ES, SS) を新しいGDTセレクタでリロード
    // FS, GS は通常0に設定するか、特定の目的 (例: TLS) で使用
    asm!(
        "mov ds, {sel}",
        "mov es, {sel}",
        "mov ss, {sel}",
        // "mov fs, {zero}", // 必要に応じて
        // "mov gs, {zero}", // 必要に応じて
        sel = in(reg) KERNEL_DATA_SELECTOR as u16, // セレクタはu16
        // zero = const 0u16, // FS/GSを0にする場合
        options(nostack, preserves_flags)
    );
    serial_println!("  Segment registers (CS, DS, ES, SS) reloaded.");
}

// シリアルポートへの簡易出力マクロ（デバッグ用）
// 実際には`kernel/bootloader/legacy_boot.rs`のような共有の出力機構を使うべき
macro_rules! print_serial {
    ($($arg:tt)*) => {
        // ここでは何もしない。実際のプロジェクトではシリアル出力関数を呼び出す。
        // 例: crate::drivers::serial::serial_println!($($arg)*);
    };
} 