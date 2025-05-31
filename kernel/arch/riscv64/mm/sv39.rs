// AetherOS RISC-V Sv39ページングモード実装
//
// RISC-V Sv39仮想メモリ実装（3レベルページテーブル、39ビット仮想アドレス）

use crate::arch::riscv64::mm::memory_types::{PhysAddr, VirtAddr, PageSize};
use crate::arch::riscv64::mm::page_table::{PageTable, PageTableEntry, PteFlag, Permission};
use core::ptr::{read_volatile, write_volatile};
use alloc::vec::Vec;
use core::mem::size_of;

/// Sv39定数
pub const SV39_VA_BITS: usize = 39;
pub const SV39_LEVELS: usize = 3;
pub const SV39_PAGE_SIZE: usize = 4096; // 4KB
pub const SV39_PAGE_TABLE_ENTRIES: usize = 512;
pub const SV39_MEGA_PAGE_SIZE: usize = SV39_PAGE_SIZE * SV39_PAGE_TABLE_ENTRIES; // 2MB
pub const SV39_GIGA_PAGE_SIZE: usize = SV39_MEGA_PAGE_SIZE * SV39_PAGE_TABLE_ENTRIES; // 1GB

/// カーネルページテーブル
static mut KERNEL_PAGE_TABLE: Option<PageTable> = None;

/// Sv39ページングの初期化
pub fn init() {
    // カーネルページテーブルの作成
    unsafe {
        KERNEL_PAGE_TABLE = Some(create_kernel_page_table());
        
        // MMUを有効化
        if let Some(ref table) = KERNEL_PAGE_TABLE {
            table.activate();
        }
    }
    
    log::info!("RISC-V Sv39ページングモード初期化完了");
}

/// カーネルページテーブルを作成
fn create_kernel_page_table() -> PageTable {
    let mode = crate::arch::riscv64::mm::PageTableMode::Sv39;
    let mut table = PageTable::new(mode).expect("カーネルページテーブルの作成に失敗");
    
    // カーネル用の恒等マッピングを作成
    if let Some(dtb) = crate::arch::riscv64::boot::get_dtb() {
        crate::arch::riscv64::boot::parse_kernel_identity_map_from_dtb(dtb);
    } else {
        unimplemented!("DTB未取得。恒等マッピング未対応");
    }
    
    // カーネルコードおよびデータ領域のマッピング（物理0x80000000を0xFFFFFFFF80000000にマップ）
    let virt_base = VirtAddr(0xFFFFFFFF80000000);
    let phys_base = PhysAddr(0x80000000);
    
    // カーネル用権限設定
    let kernel_flags = [
        PteFlag::Valid,
        PteFlag::Read,
        PteFlag::Write,
        PteFlag::Execute,
        PteFlag::Global,
        PteFlag::Accessed,
        PteFlag::Dirty,
    ];
    
    // 1GBページでカーネル領域をマッピング
    table.map(virt_base, phys_base, PageSize::Size1GB, &kernel_flags)
        .expect("カーネル領域のマッピングに失敗");
        
    // 物理メモリ直接マッピング領域（0x0〜物理メモリ最大）
    // 物理メモリを仮想アドレス空間の高位にマッピング
    let phys_map_base = VirtAddr(0xFFFFFC0000000000);
    let phys_mem_size = 16 * 1024 * 1024 * 1024; // 16GB (仮定)
    
    for i in 0..(phys_mem_size / SV39_GIGA_PAGE_SIZE) {
        let virt = VirtAddr(phys_map_base.as_u64() + (i * SV39_GIGA_PAGE_SIZE) as u64);
        let phys = PhysAddr((i * SV39_GIGA_PAGE_SIZE) as u64);
        
        // 読み書き可能だが実行不可の直接マッピング
        let phys_map_flags = [
            PteFlag::Valid,
            PteFlag::Read,
            PteFlag::Write,
            PteFlag::Global,
            PteFlag::Accessed,
            PteFlag::Dirty,
        ];
        
        table.map(virt, phys, PageSize::Size1GB, &phys_map_flags)
            .expect("物理メモリ直接マッピングに失敗");
    }
    
    // MMIO領域のマッピング
    let mmio_base = VirtAddr(0xFFFFFFFFF0000000);
    let mmio_phys_base = PhysAddr(0xF0000000);
    let mmio_size = 256 * 1024 * 1024; // 256MB
    
    // MMIO用の権限設定（キャッシュ不可）
    let mmio_flags = [
        PteFlag::Valid,
        PteFlag::Read,
        PteFlag::Write,
        PteFlag::Global,
        PteFlag::Accessed,
        PteFlag::Dirty,
    ];
    
    for i in 0..(mmio_size / SV39_MEGA_PAGE_SIZE) {
        let virt = VirtAddr(mmio_base.as_u64() + (i * SV39_MEGA_PAGE_SIZE) as u64);
        let phys = PhysAddr(mmio_phys_base.as_u64() + (i * SV39_MEGA_PAGE_SIZE) as u64);
        
        table.map(virt, phys, PageSize::Size2MB, &mmio_flags)
            .expect("MMIO領域のマッピングに失敗");
    }
    
    table
}

/// アドレス変換関数（物理から仮想へ）
pub fn phys_to_virt(phys_addr: usize) -> usize {
    // 物理アドレスを仮想アドレス空間内の直接マッピング領域のアドレスに変換
    const PHYS_MAP_BASE: usize = 0xFFFFFC0000000000;
    PHYS_MAP_BASE + phys_addr
}

/// アドレス変換関数（仮想から物理へ）
pub fn virt_to_phys(virt_addr: usize) -> Option<usize> {
    // 現在アクティブなページテーブルを使用して変換
    let virt = VirtAddr(virt_addr as u64);
    
    unsafe {
        if let Some(ref table) = KERNEL_PAGE_TABLE {
            table.translate(virt).map(|phys| phys.as_usize())
        } else {
            // ページングが初期化される前は恒等マッピングを仮定
            Some(virt_addr)
        }
    }
}

/// カーネルアドレス空間にページをマッピング
pub fn map_kernel_page(virt_addr: VirtAddr, phys_addr: PhysAddr, size: PageSize, perm: Permission) -> Result<(), &'static str> {
    let flags = perm.to_pte_flags(false); // カーネル空間なのでユーザーフラグはfalse
    
    unsafe {
        if let Some(ref mut table) = KERNEL_PAGE_TABLE {
            table.map(virt_addr, phys_addr, size, &flags)
                .map_err(|_| "カーネル空間マッピングに失敗しました")?;
            
            // TLBフラッシュ
            crate::arch::riscv64::mm::page_table::flush_tlb_page(virt_addr);
            
            Ok(())
        } else {
            Err("カーネルページテーブルが初期化されていません")
        }
    }
}

/// カーネルアドレス空間からページをアンマッピング
pub fn unmap_kernel_page(virt_addr: VirtAddr, size: PageSize) -> Result<PhysAddr, &'static str> {
    unsafe {
        if let Some(ref mut table) = KERNEL_PAGE_TABLE {
            let phys = table.unmap(virt_addr, size)
                .map_err(|_| "カーネル空間のアンマッピングに失敗しました")?;
            
            // TLBフラッシュ
            crate::arch::riscv64::mm::page_table::flush_tlb_page(virt_addr);
            
            Ok(phys)
        } else {
            Err("カーネルページテーブルが初期化されていません")
        }
    }
}

/// 現在のアクティブなページテーブルを取得
pub fn get_active_page_table() -> Option<&'static PageTable> {
    unsafe {
        KERNEL_PAGE_TABLE.as_ref()
    }
} 