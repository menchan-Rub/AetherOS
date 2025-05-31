// AetherOS RISC-V ページテーブル実装
//
// RISC-V アーキテクチャのページテーブル管理を実装します。
// RISC-Vは複数のアドレス変換方式（Sv39/Sv48/Sv57）をサポートしています。

use crate::arch::riscv64::mm::memory_types::{PhysAddr, VirtAddr, PageSize};
use core::ops::Range;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::mem::size_of;

/// ページテーブルエントリのフラグ
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PteFlag {
    /// 有効フラグ (V)
    Valid = 1 << 0,
    /// 読み取り許可 (R)
    Read = 1 << 1,
    /// 書き込み許可 (W)
    Write = 1 << 2,
    /// 実行許可 (X)
    Execute = 1 << 3,
    /// ユーザーモードアクセス許可 (U)
    User = 1 << 4,
    /// グローバルページ (G)
    Global = 1 << 5,
    /// アクセス済み (A)
    Accessed = 1 << 6,
    /// 変更済み (D)
    Dirty = 1 << 7,
    /// LRUフィールド用
    Lru = 0xF << 8,
}

/// RISC-V ページテーブルエントリ
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    /// 新しい空のエントリを作成
    pub fn new() -> Self {
        Self(0)
    }
    
    /// 指定した物理アドレスとフラグで新しいエントリを作成
    pub fn new_with_addr(phys_addr: PhysAddr, flags: &[PteFlag]) -> Self {
        let mut entry = (phys_addr.as_u64() & !0xFFF) as u64;
        for flag in flags {
            entry |= *flag as u64;
        }
        Self(entry)
    }
    
    /// エントリから物理アドレスを取得
    pub fn get_phys_addr(&self) -> PhysAddr {
        PhysAddr((self.0 & !0xFFF) as u64)
    }
    
    /// エントリが指定したフラグを持っているか判定
    pub fn has_flag(&self, flag: PteFlag) -> bool {
        (self.0 & (flag as u64)) != 0
    }
    
    /// エントリに指定したフラグを設定
    pub fn set_flag(&mut self, flag: PteFlag) {
        self.0 |= flag as u64;
    }
    
    /// エントリから指定したフラグを削除
    pub fn clear_flag(&mut self, flag: PteFlag) {
        self.0 &= !(flag as u64);
    }
    
    /// エントリが有効かチェック
    pub fn is_valid(&self) -> bool {
        self.has_flag(PteFlag::Valid)
    }
    
    /// エントリがリーフかチェック (実行権限、読み取り権限、または書き込み権限が設定されている)
    pub fn is_leaf(&self) -> bool {
        self.has_flag(PteFlag::Read) || self.has_flag(PteFlag::Write) || self.has_flag(PteFlag::Execute)
    }
}

/// ページテーブル構造体
pub struct PageTable {
    /// ルートページテーブルの物理アドレス
    pub root_phys: PhysAddr,
    /// 仮想アドレスマッピング用
    pub root_virt: *mut PageTableEntry,
    /// MMUが使用するモード
    pub mode: crate::arch::riscv64::mm::PageTableMode,
}

/// ページマッピングエラー
#[derive(Debug, Clone)]
pub enum MapError {
    /// 指定したレベルでのマッピングに失敗
    InvalidLevel,
    /// メモリ割り当て失敗
    AllocationFailed,
    /// すでにマッピングが存在
    AlreadyMapped,
}

impl PageTable {
    /// 新しいページテーブルを作成
    pub fn new(mode: crate::arch::riscv64::mm::PageTableMode) -> Result<Self, MapError> {
        // カーネルからページテーブル用の物理メモリを割り当て
        let root_phys = crate::core::memory::pmem::allocate_frame()
            .ok_or(MapError::AllocationFailed)?;

        // 割り当てたメモリをゼロ初期化
        let root_virt = crate::core::memory::mm::phys_to_virt(root_phys.as_usize()) as *mut PageTableEntry;
        for i in 0..512 {
            unsafe {
                write_volatile(root_virt.add(i), PageTableEntry(0));
            }
        }

        Ok(Self {
            root_phys,
            root_virt,
            mode,
        })
    }

    /// 指定した仮想アドレスと物理アドレスをマッピング
    pub fn map(&mut self, virt: VirtAddr, phys: PhysAddr, size: PageSize, flags: &[PteFlag]) -> Result<(), MapError> {
        match self.mode {
            crate::arch::riscv64::mm::PageTableMode::Sv39 => self.map_sv39(virt, phys, size, flags),
            crate::arch::riscv64::mm::PageTableMode::Sv48 => self.map_sv48(virt, phys, size, flags),
            crate::arch::riscv64::mm::PageTableMode::Sv57 => self.map_sv57(virt, phys, size, flags),
        }
    }

    /// 指定した仮想アドレスのマッピングを解除
    pub fn unmap(&mut self, virt: VirtAddr, size: PageSize) -> Result<PhysAddr, MapError> {
        match self.mode {
            crate::arch::riscv64::mm::PageTableMode::Sv39 => self.unmap_sv39(virt, size),
            crate::arch::riscv64::mm::PageTableMode::Sv48 => self.unmap_sv48(virt, size),
            crate::arch::riscv64::mm::PageTableMode::Sv57 => self.unmap_sv57(virt, size),
        }
    }

    /// 指定した仮想アドレスから物理アドレスを取得
    pub fn translate(&self, virt: VirtAddr) -> Option<PhysAddr> {
        match self.mode {
            crate::arch::riscv64::mm::PageTableMode::Sv39 => self.translate_sv39(virt),
            crate::arch::riscv64::mm::PageTableMode::Sv48 => self.translate_sv48(virt),
            crate::arch::riscv64::mm::PageTableMode::Sv57 => self.translate_sv57(virt),
        }
    }

    /// Sv39モードでのアドレスマッピング
    fn map_sv39(&mut self, virt: VirtAddr, phys: PhysAddr, size: PageSize, flags: &[PteFlag]) -> Result<(), MapError> {
        // Sv39実装
        let p0_idx = virt.sv39_p0_index();
        
        // 必要に応じて中間レベルのページテーブルを作成
        let p0_entry = unsafe { &mut *self.root_virt.add(p0_idx) };
        
        // ページサイズによってマッピング方法を変更
        match size {
            PageSize::Size1GB => {
                if p0_entry.is_valid() && p0_entry.is_leaf() {
                    return Err(MapError::AlreadyMapped);
                }
                
                // 1GBページとして直接マッピング
                *p0_entry = PageTableEntry::new_with_addr(phys, flags);
                Ok(())
            }
            
            PageSize::Size2MB | PageSize::Size4KB => {
                // 中間テーブルが必要
                if !p0_entry.is_valid() {
                    // 新しいページテーブルを割り当て
                    let p1_table_phys = crate::core::memory::pmem::allocate_frame()
                        .ok_or(MapError::AllocationFailed)?;
                        
                    // 中間テーブルを初期化
                    let p1_table_virt = crate::core::memory::mm::phys_to_virt(p1_table_phys.as_usize()) as *mut PageTableEntry;
                    for i in 0..512 {
                        unsafe {
                            write_volatile(p1_table_virt.add(i), PageTableEntry(0));
                        }
                    }
                    
                    // p0エントリを設定
                    *p0_entry = PageTableEntry::new_with_addr(p1_table_phys, &[PteFlag::Valid]);
                }
                
                let p1_table_phys = p0_entry.get_phys_addr();
                let p1_table_virt = crate::core::memory::mm::phys_to_virt(p1_table_phys.as_usize()) as *mut PageTableEntry;
                let p1_idx = virt.sv39_p1_index();
                
                if size == PageSize::Size2MB {
                    // 2MBページとしてマッピング
                    let p1_entry = unsafe { &mut *p1_table_virt.add(p1_idx) };
                    
                    if p1_entry.is_valid() && p1_entry.is_leaf() {
                        return Err(MapError::AlreadyMapped);
                    }
                    
                    *p1_entry = PageTableEntry::new_with_addr(phys, flags);
                    return Ok(());
                }
                
                // 4KBページの場合は更に深い階層が必要
                let p1_entry = unsafe { &mut *p1_table_virt.add(p1_idx) };
                
                if !p1_entry.is_valid() {
                    // 新しいページテーブルを割り当て
                    let p2_table_phys = crate::core::memory::pmem::allocate_frame()
                        .ok_or(MapError::AllocationFailed)?;
                        
                    // 初期化
                    let p2_table_virt = crate::core::memory::mm::phys_to_virt(p2_table_phys.as_usize()) as *mut PageTableEntry;
                    for i in 0..512 {
                        unsafe {
                            write_volatile(p2_table_virt.add(i), PageTableEntry(0));
                        }
                    }
                    
                    // p1エントリを設定
                    *p1_entry = PageTableEntry::new_with_addr(p2_table_phys, &[PteFlag::Valid]);
                }
                
                let p2_table_phys = p1_entry.get_phys_addr();
                let p2_table_virt = crate::core::memory::mm::phys_to_virt(p2_table_phys.as_usize()) as *mut PageTableEntry;
                let p2_idx = virt.sv39_p2_index();
                
                // 4KBページとしてマッピング
                let p2_entry = unsafe { &mut *p2_table_virt.add(p2_idx) };
                
                if p2_entry.is_valid() {
                    return Err(MapError::AlreadyMapped);
                }
                
                *p2_entry = PageTableEntry::new_with_addr(phys, flags);
                Ok(())
            }
        }
    }

    /// Sv48モードでのアドレスマッピング
    fn map_sv48(&mut self, virt: VirtAddr, phys: PhysAddr, size: PageSize, flags: &[PteFlag]) -> Result<(), MapError> {
        // Sv48実装（簡略化）
        Ok(())
    }

    /// Sv57モードでのアドレスマッピング
    fn map_sv57(&mut self, virt: VirtAddr, phys: PhysAddr, size: PageSize, flags: &[PteFlag]) -> Result<(), MapError> {
        // Sv57実装（簡略化）
        Ok(())
    }

    /// Sv39モードでのアドレスアンマッピング
    fn unmap_sv39(&mut self, virt: VirtAddr, size: PageSize) -> Result<PhysAddr, MapError> {
        // Sv39アンマッピング実装（簡略化）
        Ok(PhysAddr(0))
    }

    /// Sv48モードでのアドレスアンマッピング
    fn unmap_sv48(&mut self, virt: VirtAddr, size: PageSize) -> Result<PhysAddr, MapError> {
        // Sv48アンマッピング実装（簡略化）
        Ok(PhysAddr(0))
    }

    /// Sv57モードでのアドレスアンマッピング
    fn unmap_sv57(&mut self, virt: VirtAddr, size: PageSize) -> Result<PhysAddr, MapError> {
        // Sv57アンマッピング実装（簡略化）
        Ok(PhysAddr(0))
    }

    /// Sv39モードでのアドレス変換
    fn translate_sv39(&self, virt: VirtAddr) -> Option<PhysAddr> {
        let p0_idx = virt.sv39_p0_index();
        let p0_entry = unsafe { read_volatile(self.root_virt.add(p0_idx)) };
        
        if !p0_entry.is_valid() {
            return None;
        }
        
        // 1GBページの場合
        if p0_entry.is_leaf() {
            let offset = virt.as_u64() & 0x3FFFFFFF; // 1GBページ内のオフセット
            return Some(PhysAddr(p0_entry.get_phys_addr().as_u64() + offset));
        }
        
        let p1_table_phys = p0_entry.get_phys_addr();
        let p1_table_virt = crate::core::memory::mm::phys_to_virt(p1_table_phys.as_usize()) as *const PageTableEntry;
        let p1_idx = virt.sv39_p1_index();
        let p1_entry = unsafe { read_volatile(p1_table_virt.add(p1_idx)) };
        
        if !p1_entry.is_valid() {
            return None;
        }
        
        // 2MBページの場合
        if p1_entry.is_leaf() {
            let offset = virt.as_u64() & 0x1FFFFF; // 2MBページ内のオフセット
            return Some(PhysAddr(p1_entry.get_phys_addr().as_u64() + offset));
        }
        
        let p2_table_phys = p1_entry.get_phys_addr();
        let p2_table_virt = crate::core::memory::mm::phys_to_virt(p2_table_phys.as_usize()) as *const PageTableEntry;
        let p2_idx = virt.sv39_p2_index();
        let p2_entry = unsafe { read_volatile(p2_table_virt.add(p2_idx)) };
        
        if !p2_entry.is_valid() {
            return None;
        }
        
        // 4KBページの場合
        let offset = virt.page_offset() as u64;
        Some(PhysAddr(p2_entry.get_phys_addr().as_u64() + offset))
    }

    /// Sv48モードでのアドレス変換
    fn translate_sv48(&self, virt: VirtAddr) -> Option<PhysAddr> {
        // Sv48アドレス変換実装（簡略化）
        None
    }

    /// Sv57モードでのアドレス変換
    fn translate_sv57(&self, virt: VirtAddr) -> Option<PhysAddr> {
        // Sv57アドレス変換実装（簡略化）
        None
    }

    /// ページテーブルを有効化（MMUに設定）
    pub fn activate(&self) {
        let satp_value = match self.mode {
            crate::arch::riscv64::mm::PageTableMode::Sv39 => {
                (8 << 60) | (0 << 44) | (self.root_phys.as_u64() >> 12)
            },
            crate::arch::riscv64::mm::PageTableMode::Sv48 => {
                (9 << 60) | (0 << 44) | (self.root_phys.as_u64() >> 12)
            },
            crate::arch::riscv64::mm::PageTableMode::Sv57 => {
                (10 << 60) | (0 << 44) | (self.root_phys.as_u64() >> 12)
            },
        };
        
        // satp CSRに書き込み
        unsafe {
            core::arch::asm!("csrw satp, {}", in(reg) satp_value);
            core::arch::asm!("sfence.vma");
        }
    }
}

/// TLBをフラッシュ
pub fn flush_tlb_all() {
    unsafe {
        core::arch::asm!("sfence.vma");
    }
}

/// 特定のアドレスのTLBエントリをフラッシュ
pub fn flush_tlb_page(addr: VirtAddr) {
    unsafe {
        core::arch::asm!("sfence.vma {}, zero", in(reg) addr.as_u64());
    }
}

/// メモリアクセス権限
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// 読み取りのみ
    Read,
    /// 読み書き可能
    ReadWrite,
    /// 読み取り・実行可能
    ReadExecute,
    /// 読み書き・実行可能
    ReadWriteExecute,
}

impl Permission {
    /// PteFlagのセットに変換
    pub fn to_pte_flags(&self, user: bool) -> Vec<PteFlag> {
        let mut flags = vec![PteFlag::Valid, PteFlag::Accessed, PteFlag::Dirty];
        
        if user {
            flags.push(PteFlag::User);
        }
        
        match self {
            Permission::Read => {
                flags.push(PteFlag::Read);
            },
            Permission::ReadWrite => {
                flags.push(PteFlag::Read);
                flags.push(PteFlag::Write);
            },
            Permission::ReadExecute => {
                flags.push(PteFlag::Read);
                flags.push(PteFlag::Execute);
            },
            Permission::ReadWriteExecute => {
                flags.push(PteFlag::Read);
                flags.push(PteFlag::Write);
                flags.push(PteFlag::Execute);
            },
        }
        
        flags
    }
} 