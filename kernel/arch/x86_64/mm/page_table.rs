// AetherOS x86_64ページテーブル実装
//
// x86_64アーキテクチャの4階層ページングシステムを管理します。
// 通常の4KBページに加え、2MB/1GBの大きなページにも対応します。

use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::arch::x86_64::mm::memory_types::{PhysAddr, VirtAddr, PageSize};
use crate::memory::allocator::{PhysicalAllocator, PHYS_ALLOCATOR};
use crate::sync::{SpinLock, RwLock};
use alloc::vec::Vec;

/// PML4テーブルエントリ（ページマップレベル4）
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Pml4Entry(AtomicU64);

/// PDPTエントリ（ページディレクトリポインタテーブル）
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PdptEntry(AtomicU64);

/// PDエントリ（ページディレクトリ）
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PdEntry(AtomicU64);

/// PTエントリ（ページテーブル）
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PtEntry(AtomicU64);

/// ページエントリ共通フラグ
pub mod flag {
    /// ページが存在する
    pub const PRESENT:       u64 = 1 << 0;
    /// 書き込み可能
    pub const WRITABLE:      u64 = 1 << 1;
    /// ユーザーモードからアクセス可能
    pub const USER:          u64 = 1 << 2;
    /// ライトスルーキャッシング
    pub const WRITE_THROUGH: u64 = 1 << 3;
    /// キャッシュ無効
    pub const NO_CACHE:      u64 = 1 << 4;
    /// アクセス済みフラグ
    pub const ACCESSED:      u64 = 1 << 5;
    /// 書き込み済みフラグ（PTエントリのみ）
    pub const DIRTY:         u64 = 1 << 6;
    /// 大きなページ/1GBページフラグ（PD/PDPTエントリ）
    pub const HUGE_PAGE:     u64 = 1 << 7;
    /// グローバルページ（PTエントリのみ）
    pub const GLOBAL:        u64 = 1 << 8;
    /// ソフトウェア用ビット1
    pub const SOFTWARE_1:    u64 = 1 << 9;
    /// ソフトウェア用ビット2
    pub const SOFTWARE_2:    u64 = 1 << 10;
    /// ソフトウェア用ビット3
    pub const SOFTWARE_3:    u64 = 1 << 11;
    /// ページフレームアドレスのマスク（12ビット目から始まる）
    pub const ADDR_MASK:     u64 = 0x000f_ffff_ffff_f000;
    /// 実行禁止（NXビット、63ビット目）
    pub const NO_EXECUTE:    u64 = 1 << 63;
}

/// ページテーブル操作のトレイト
trait PageTableEntry {
    /// エントリの値を取得
    fn get_value(&self) -> u64;
    
    /// エントリに値を設定
    fn set_value(&self, value: u64);
    
    /// エントリが存在するかチェック
    fn is_present(&self) -> bool {
        self.get_value() & flag::PRESENT != 0
    }
    
    /// 物理アドレスを取得
    fn get_address(&self) -> PhysAddr {
        PhysAddr::new(self.get_value() & flag::ADDR_MASK)
    }
    
    /// 物理アドレスを設定（フラグは保持）
    fn set_address(&self, addr: PhysAddr) {
        let flags = self.get_value() & !flag::ADDR_MASK;
        self.set_value(flags | (addr.as_u64() & flag::ADDR_MASK));
    }
    
    /// フラグを設定
    fn set_flags(&self, flags: u64) {
        let addr = self.get_value() & flag::ADDR_MASK;
        self.set_value(addr | flags);
    }
    
    /// フラグをクリア
    fn clear_flags(&self, flags: u64) {
        let value = self.get_value();
        self.set_value(value & !flags);
    }
    
    /// 特定のフラグが設定されているかチェック
    fn has_flag(&self, flag: u64) -> bool {
        self.get_value() & flag != 0
    }
}

impl PageTableEntry for Pml4Entry {
    fn get_value(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    
    fn set_value(&self, value: u64) {
        self.0.store(value, Ordering::Relaxed);
    }
}

impl PageTableEntry for PdptEntry {
    fn get_value(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    
    fn set_value(&self, value: u64) {
        self.0.store(value, Ordering::Relaxed);
    }
}

impl PageTableEntry for PdEntry {
    fn get_value(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    
    fn set_value(&self, value: u64) {
        self.0.store(value, Ordering::Relaxed);
    }
}

impl PageTableEntry for PtEntry {
    fn get_value(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    
    fn set_value(&self, value: u64) {
        self.0.store(value, Ordering::Relaxed);
    }
}

// ページテーブル型の実装

impl Pml4Entry {
    /// 新しい空のPML4エントリを作成
    pub fn new_empty() -> Self {
        Self(AtomicU64::new(0))
    }
    
    /// PDPTテーブルへのポインタとフラグを持つエントリを作成
    pub fn new(pdpt_addr: PhysAddr, flags: u64) -> Self {
        Self(AtomicU64::new((pdpt_addr.as_u64() & flag::ADDR_MASK) | flags))
    }
}

impl PdptEntry {
    /// 新しい空のPDPTエントリを作成
    pub fn new_empty() -> Self {
        Self(AtomicU64::new(0))
    }
    
    /// PDへのポインタとフラグを持つエントリを作成
    pub fn new(pd_addr: PhysAddr, flags: u64) -> Self {
        Self(AtomicU64::new((pd_addr.as_u64() & flag::ADDR_MASK) | flags))
    }
    
    /// 1GBページを直接マップするエントリを作成
    pub fn new_1gb_page(phys_addr: PhysAddr, flags: u64) -> Self {
        Self(AtomicU64::new((phys_addr.as_u64() & flag::ADDR_MASK) | flags | flag::HUGE_PAGE))
    }
    
    /// 1GBページとしてマッピングされているかチェック
    pub fn is_huge(&self) -> bool {
        self.has_flag(flag::HUGE_PAGE)
    }
}

impl PdEntry {
    /// 新しい空のPDエントリを作成
    pub fn new_empty() -> Self {
        Self(AtomicU64::new(0))
    }
    
    /// PTへのポインタとフラグを持つエントリを作成
    pub fn new(pt_addr: PhysAddr, flags: u64) -> Self {
        Self(AtomicU64::new((pt_addr.as_u64() & flag::ADDR_MASK) | flags))
    }
    
    /// 2MBページを直接マッピングするエントリを作成
    pub fn new_2mb_page(phys_addr: PhysAddr, flags: u64) -> Self {
        Self(AtomicU64::new((phys_addr.as_u64() & flag::ADDR_MASK) | flags | flag::HUGE_PAGE))
    }
    
    /// 2MBページとしてマッピングされているかチェック
    pub fn is_huge(&self) -> bool {
        self.has_flag(flag::HUGE_PAGE)
    }
}

impl PtEntry {
    /// 新しい空のPTエントリを作成
    pub fn new_empty() -> Self {
        Self(AtomicU64::new(0))
    }
    
    /// 4KBページをマッピングするエントリを作成
    pub fn new(page_addr: PhysAddr, flags: u64) -> Self {
        Self(AtomicU64::new((page_addr.as_u64() & flag::ADDR_MASK) | flags))
    }
}

/// メモリアクセス権
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAccess {
    /// 読み取り可能
    pub read: bool,
    /// 書き込み可能
    pub write: bool,
    /// 実行可能
    pub execute: bool,
    /// ユーザーモードからアクセス可能
    pub user: bool,
}

impl MemoryAccess {
    /// フラグに変換
    pub fn to_flags(&self) -> u64 {
        let mut flags = flag::PRESENT; // 存在フラグは常に設定
        
        if self.write {
            flags |= flag::WRITABLE;
        }
        
        if self.user {
            flags |= flag::USER;
        }
        
        if !self.execute {
            flags |= flag::NO_EXECUTE;
        }
        
        flags
    }
}

impl Default for MemoryAccess {
    fn default() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
            user: false,
        }
    }
}

/// ページテーブル構造体（CR3レジスタがポイントするもの）
#[repr(align(4096))]
pub struct PageTable {
    /// PML4テーブルエントリ（512個）
    entries: [Pml4Entry; 512],
}

impl PageTable {
    /// 新しい空のページテーブルを作成
    pub fn new() -> Self {
        let mut entries = [Pml4Entry::new_empty(); 512];
        
        // 再帰マッピングを設定（最後のエントリ）
        // これにより、ページテーブル自身へのアクセスが可能になる
        let phys_addr = PhysAddr::new(self as *const _ as u64);
        entries[511] = Pml4Entry::new(phys_addr, flag::PRESENT | flag::WRITABLE);
        
        Self { entries }
    }
    
    /// 物理アドレスを取得
    pub fn physical_address(&self) -> PhysAddr {
        PhysAddr::new(self as *const _ as u64)
    }
    
    /// ページをマッピング
    pub fn map(&mut self, virt: VirtAddr, phys: PhysAddr, access: MemoryAccess, page_size: PageSize) -> bool {
        let flags = access.to_flags();
        
        match page_size {
            PageSize::Size4KB => self.map_4kb(virt, phys, flags),
            PageSize::Size2MB => self.map_2mb(virt, phys, flags),
            PageSize::Size1GB => self.map_1gb(virt, phys, flags),
        }
    }
    
    /// 4KBページをマッピング
    fn map_4kb(&mut self, virt: VirtAddr, phys: PhysAddr, flags: u64) -> bool {
        // 各レベルのインデックスを計算
        let pml4_idx = (virt.as_u64() >> 39) & 0x1FF;
        let pdpt_idx = (virt.as_u64() >> 30) & 0x1FF;
        let pd_idx = (virt.as_u64() >> 21) & 0x1FF;
        let pt_idx = (virt.as_u64() >> 12) & 0x1FF;
        
        // PML4エントリ
        let pml4e = &self.entries[pml4_idx];
        
        // PDPTテーブルを取得または作成
        let pdpt = if pml4e.is_present() {
            // 既存のPDPTテーブルを使用
            unsafe { &mut *(pml4e.get_address().as_u64() as *mut [PdptEntry; 512]) }
        } else {
            // 新しいPDPTテーブルを割り当て
            let pdpt_phys = Self::allocate_table();
            pml4e.set_value((pdpt_phys.as_u64() & flag::ADDR_MASK) | flag::PRESENT | flag::WRITABLE | flag::USER);
            unsafe { &mut *(pdpt_phys.as_u64() as *mut [PdptEntry; 512]) }
        };
        
        // PDPTエントリ
        let pdpte = &pdpt[pdpt_idx];
        
        // PDテーブルを取得または作成
        let pd = if pdpte.is_present() && !pdpte.is_huge() {
            // 既存のPDテーブルを使用
            unsafe { &mut *(pdpte.get_address().as_u64() as *mut [PdEntry; 512]) }
        } else if pdpte.is_present() && pdpte.is_huge() {
            // 1GBページが既にマッピングされている場合は失敗
            return false;
        } else {
            // 新しいPDテーブルを割り当て
            let pd_phys = Self::allocate_table();
            pdpte.set_value((pd_phys.as_u64() & flag::ADDR_MASK) | flag::PRESENT | flag::WRITABLE | flag::USER);
            unsafe { &mut *(pd_phys.as_u64() as *mut [PdEntry; 512]) }
        };
        
        // PDエントリ
        let pde = &pd[pd_idx];
        
        // PTテーブルを取得または作成
        let pt = if pde.is_present() && !pde.is_huge() {
            // 既存のPTテーブルを使用
            unsafe { &mut *(pde.get_address().as_u64() as *mut [PtEntry; 512]) }
        } else if pde.is_present() && pde.is_huge() {
            // 2MBページが既にマッピングされている場合は失敗
            return false;
        } else {
            // 新しいPTテーブルを割り当て
            let pt_phys = Self::allocate_table();
            pde.set_value((pt_phys.as_u64() & flag::ADDR_MASK) | flag::PRESENT | flag::WRITABLE | flag::USER);
            unsafe { &mut *(pt_phys.as_u64() as *mut [PtEntry; 512]) }
        };
        
        // PTエントリ
        let pte = &pt[pt_idx];
        
        if pte.is_present() {
            // 既にマッピングされている場合は失敗
            return false;
        }
        
        // 4KBページをマッピング
        pte.set_value((phys.as_u64() & flag::ADDR_MASK) | flags);
        
        // TLBをフラッシュ
        unsafe {
            core::arch::asm!("invlpg [{}]", in(reg) virt.as_u64(), options(nostack));
        }
        
        true
    }
    
    /// 2MBページをマッピング
    fn map_2mb(&mut self, virt: VirtAddr, phys: PhysAddr, flags: u64) -> bool {
        // 2MBアライメントをチェック
        if virt.as_u64() & 0x1FFFFF != 0 || phys.as_u64() & 0x1FFFFF != 0 {
            return false;
        }
        
        // 各レベルのインデックスを計算
        let pml4_idx = (virt.as_u64() >> 39) & 0x1FF;
        let pdpt_idx = (virt.as_u64() >> 30) & 0x1FF;
        let pd_idx = (virt.as_u64() >> 21) & 0x1FF;
        
        // PML4エントリ
        let pml4e = &self.entries[pml4_idx];
        
        // PDPTテーブルを取得または作成
        let pdpt = if pml4e.is_present() {
            // 既存のPDPTテーブルを使用
            unsafe { &mut *(pml4e.get_address().as_u64() as *mut [PdptEntry; 512]) }
        } else {
            // 新しいPDPTテーブルを割り当て
            let pdpt_phys = Self::allocate_table();
            pml4e.set_value((pdpt_phys.as_u64() & flag::ADDR_MASK) | flag::PRESENT | flag::WRITABLE | flag::USER);
            unsafe { &mut *(pdpt_phys.as_u64() as *mut [PdptEntry; 512]) }
        };
        
        // PDPTエントリ
        let pdpte = &pdpt[pdpt_idx];
        
        // PDテーブルを取得または作成
        let pd = if pdpte.is_present() && !pdpte.is_huge() {
            // 既存のPDテーブルを使用
            unsafe { &mut *(pdpte.get_address().as_u64() as *mut [PdEntry; 512]) }
        } else if pdpte.is_present() && pdpte.is_huge() {
            // 1GBページが既にマッピングされている場合は失敗
            return false;
        } else {
            // 新しいPDテーブルを割り当て
            let pd_phys = Self::allocate_table();
            pdpte.set_value((pd_phys.as_u64() & flag::ADDR_MASK) | flag::PRESENT | flag::WRITABLE | flag::USER);
            unsafe { &mut *(pd_phys.as_u64() as *mut [PdEntry; 512]) }
        };
        
        // PDエントリで2MBページをマッピング
        let pde = &pd[pd_idx];
        
        if pde.is_present() {
            // 既にマッピングされている場合は失敗
            return false;
        }
        
        // 2MBページをマッピング
        pde.set_value((phys.as_u64() & flag::ADDR_MASK) | flags | flag::HUGE_PAGE);
        
        // TLBをフラッシュ
        unsafe {
            core::arch::asm!("invlpg [{}]", in(reg) virt.as_u64(), options(nostack));
        }
        
        true
    }
    
    /// 1GBページをマッピング
    fn map_1gb(&mut self, virt: VirtAddr, phys: PhysAddr, flags: u64) -> bool {
        // 1GBアライメントをチェック
        if virt.as_u64() & 0x3FFFFFFF != 0 || phys.as_u64() & 0x3FFFFFFF != 0 {
            return false;
        }
        
        // 各レベルのインデックスを計算
        let pml4_idx = (virt.as_u64() >> 39) & 0x1FF;
        let pdpt_idx = (virt.as_u64() >> 30) & 0x1FF;
        
        // PML4エントリ
        let pml4e = &self.entries[pml4_idx];
        
        // PDPTテーブルを取得または作成
        let pdpt = if pml4e.is_present() {
            // 既存のPDPTテーブルを使用
            unsafe { &mut *(pml4e.get_address().as_u64() as *mut [PdptEntry; 512]) }
        } else {
            // 新しいPDPTテーブルを割り当て
            let pdpt_phys = Self::allocate_table();
            pml4e.set_value((pdpt_phys.as_u64() & flag::ADDR_MASK) | flag::PRESENT | flag::WRITABLE | flag::USER);
            unsafe { &mut *(pdpt_phys.as_u64() as *mut [PdptEntry; 512]) }
        };
        
        // PDPTエントリで1GBページをマッピング
        let pdpte = &pdpt[pdpt_idx];
        
        if pdpte.is_present() {
            // 既にマッピングされている場合は失敗
            return false;
        }
        
        // 1GBページをマッピング
        pdpte.set_value((phys.as_u64() & flag::ADDR_MASK) | flags | flag::HUGE_PAGE);
        
        // TLBをフラッシュ
        unsafe {
            core::arch::asm!("invlpg [{}]", in(reg) virt.as_u64(), options(nostack));
        }
        
        true
    }
    
    /// ページをアンマップ
    pub fn unmap(&mut self, virt: VirtAddr) -> bool {
        // 各レベルのインデックスを計算
        let pml4_idx = (virt.as_u64() >> 39) & 0x1FF;
        let pdpt_idx = (virt.as_u64() >> 30) & 0x1FF;
        let pd_idx = (virt.as_u64() >> 21) & 0x1FF;
        let pt_idx = (virt.as_u64() >> 12) & 0x1FF;
        
        // PML4エントリ
        let pml4e = &self.entries[pml4_idx];
        if !pml4e.is_present() {
            return false;
        }
        
        // PDPTテーブル
        let pdpt = unsafe { &mut *(pml4e.get_address().as_u64() as *mut [PdptEntry; 512]) };
        let pdpte = &pdpt[pdpt_idx];
        if !pdpte.is_present() {
            return false;
        }
        
        // 1GBページの場合
        if pdpte.is_huge() {
            pdpte.set_value(0);
            unsafe {
                core::arch::asm!("invlpg [{}]", in(reg) virt.as_u64(), options(nostack));
            }
            return true;
        }
        
        // PDテーブル
        let pd = unsafe { &mut *(pdpte.get_address().as_u64() as *mut [PdEntry; 512]) };
        let pde = &pd[pd_idx];
        if !pde.is_present() {
            return false;
        }
        
        // 2MBページの場合
        if pde.is_huge() {
            pde.set_value(0);
            unsafe {
                core::arch::asm!("invlpg [{}]", in(reg) virt.as_u64(), options(nostack));
            }
            return true;
        }
        
        // PTテーブル
        let pt = unsafe { &mut *(pde.get_address().as_u64() as *mut [PtEntry; 512]) };
        let pte = &pt[pt_idx];
        if !pte.is_present() {
            return false;
        }
        
        // 4KBページをアンマップ
        pte.set_value(0);
        unsafe {
            core::arch::asm!("invlpg [{}]", in(reg) virt.as_u64(), options(nostack));
        }
        
        true
    }
    
    /// 指定した仮想アドレスの物理アドレスを取得
    pub fn translate(&self, virt: VirtAddr) -> Option<PhysAddr> {
        // 各レベルのインデックスを計算
        let pml4_idx = (virt.as_u64() >> 39) & 0x1FF;
        let pdpt_idx = (virt.as_u64() >> 30) & 0x1FF;
        let pd_idx = (virt.as_u64() >> 21) & 0x1FF;
        let pt_idx = (virt.as_u64() >> 12) & 0x1FF;
        let offset = virt.as_u64() & 0xFFF;
        
        // PML4エントリ
        let pml4e = &self.entries[pml4_idx];
        if !pml4e.is_present() {
            return None;
        }
        
        // PDPTテーブル
        let pdpt = unsafe { &*(pml4e.get_address().as_u64() as *const [PdptEntry; 512]) };
        let pdpte = &pdpt[pdpt_idx];
        if !pdpte.is_present() {
            return None;
        }
        
        // 1GBページの場合
        if pdpte.is_huge() {
            let phys_base = pdpte.get_address().as_u64() & !0x3FFFFFFF;
            let offset_1gb = virt.as_u64() & 0x3FFFFFFF;
            return Some(PhysAddr::new(phys_base + offset_1gb));
        }
        
        // PDテーブル
        let pd = unsafe { &*(pdpte.get_address().as_u64() as *const [PdEntry; 512]) };
        let pde = &pd[pd_idx];
        if !pde.is_present() {
            return None;
        }
        
        // 2MBページの場合
        if pde.is_huge() {
            let phys_base = pde.get_address().as_u64() & !0x1FFFFF;
            let offset_2mb = virt.as_u64() & 0x1FFFFF;
            return Some(PhysAddr::new(phys_base + offset_2mb));
        }
        
        // PTテーブル
        let pt = unsafe { &*(pde.get_address().as_u64() as *const [PtEntry; 512]) };
        let pte = &pt[pt_idx];
        if !pte.is_present() {
            return None;
        }
        
        // 4KBページの場合
        let phys_base = pte.get_address().as_u64() & !0xFFF;
        Some(PhysAddr::new(phys_base + offset))
    }
    
    /// アクセス権を取得
    pub fn get_access(&self, virt: VirtAddr) -> Option<MemoryAccess> {
        // 各レベルのインデックスを計算
        let pml4_idx = (virt.as_u64() >> 39) & 0x1FF;
        let pdpt_idx = (virt.as_u64() >> 30) & 0x1FF;
        let pd_idx = (virt.as_u64() >> 21) & 0x1FF;
        let pt_idx = (virt.as_u64() >> 12) & 0x1FF;
        
        // PML4エントリ
        let pml4e = &self.entries[pml4_idx];
        if !pml4e.is_present() {
            return None;
        }
        
        // PDPTテーブル
        let pdpt = unsafe { &*(pml4e.get_address().as_u64() as *const [PdptEntry; 512]) };
        let pdpte = &pdpt[pdpt_idx];
        if !pdpte.is_present() {
            return None;
        }
        
        // 1GBページの場合
        if pdpte.is_huge() {
            let flags = pdpte.get_value();
            return Some(MemoryAccess {
                read: true,
                write: flags & flag::WRITABLE != 0,
                execute: flags & flag::NO_EXECUTE == 0,
                user: flags & flag::USER != 0,
            });
        }
        
        // PDテーブル
        let pd = unsafe { &*(pdpte.get_address().as_u64() as *const [PdEntry; 512]) };
        let pde = &pd[pd_idx];
        if !pde.is_present() {
            return None;
        }
        
        // 2MBページの場合
        if pde.is_huge() {
            let flags = pde.get_value();
            return Some(MemoryAccess {
                read: true,
                write: flags & flag::WRITABLE != 0,
                execute: flags & flag::NO_EXECUTE == 0,
                user: flags & flag::USER != 0,
            });
        }
        
        // PTテーブル
        let pt = unsafe { &*(pde.get_address().as_u64() as *const [PtEntry; 512]) };
        let pte = &pt[pt_idx];
        if !pte.is_present() {
            return None;
        }
        
        // 4KBページの場合
        let flags = pte.get_value();
        Some(MemoryAccess {
            read: true,
            write: flags & flag::WRITABLE != 0,
            execute: flags & flag::NO_EXECUTE == 0,
            user: flags & flag::USER != 0,
        })
    }
    
    /// ページテーブル用に4KBの物理メモリを割り当てる
    fn allocate_table() -> PhysAddr {
        // 物理メモリアロケータから4KBページを割り当て
        let phys_addr = unsafe { PHYS_ALLOCATOR.lock().allocate_page() }
            .expect("ページテーブル用のメモリ割り当てに失敗");
        
        // メモリをゼロで初期化
        unsafe {
            ptr::write_bytes(phys_addr.as_u64() as *mut u8, 0, 4096);
        }
        
        phys_addr
    }
}

/// システム全体で使用するページテーブル
static KERNEL_PAGE_TABLE: RwLock<Option<PageTable>> = RwLock::new(None);

/// カーネルページテーブルを初期化
pub fn init_kernel_page_table() {
    let mut table = PageTable::new();
    
    // カーネル用の初期マッピング設定
    // カーネルの物理アドレス空間を仮想アドレス空間の高位にマッピング
    let kernel_phys_start = crate::KERNEL_PHYSICAL_START;
    let kernel_virt_start = crate::KERNEL_VIRTUAL_START;
    let kernel_size = crate::KERNEL_SIZE;
    
    // カーネルコードセクションのマッピング（読み取り専用、実行可能）
    let code_phys_start = kernel_phys_start;
    let code_virt_start = kernel_virt_start;
    let code_size = crate::KERNEL_CODE_SIZE;
    
    for i in 0..(code_size / PAGE_SIZE) {
        let phys_addr = code_phys_start + i * PAGE_SIZE;
        let virt_addr = code_virt_start + i * PAGE_SIZE;
        
        map_page(
            p4_table, 
            virt_addr as u64, 
            phys_addr as u64, 
            PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE | PageTableFlags::GLOBAL
        );
    }
    
    // カーネルデータセクションのマッピング（読み書き可能）
    let data_phys_start = code_phys_start + code_size;
    let data_virt_start = code_virt_start + code_size;
    let data_size = kernel_size - code_size;
    
    for i in 0..(data_size / PAGE_SIZE) {
        let phys_addr = data_phys_start + i * PAGE_SIZE;
        let virt_addr = data_virt_start + i * PAGE_SIZE;
        
        map_page(
            p4_table, 
            virt_addr as u64, 
            phys_addr as u64, 
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE | PageTableFlags::GLOBAL
        );
    }
    
    // フレームバッファとIOMMUのマッピング
    if let Some(framebuffer) = framebuffer_info {
        let fb_phys_start = framebuffer.address as usize;
        let fb_size = framebuffer.pitch as usize * framebuffer.height as usize;
        
        // フレームバッファを専用の仮想アドレス範囲にマッピング
        let fb_virt_start = FRAMEBUFFER_VIRTUAL_BASE;
        
        for i in 0..((fb_size + PAGE_SIZE - 1) / PAGE_SIZE) {
            let phys_addr = fb_phys_start + i * PAGE_SIZE;
            let virt_addr = fb_virt_start + i * PAGE_SIZE;
            
            map_page(
                p4_table, 
                virt_addr as u64, 
                phys_addr as u64, 
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE | 
                PageTableFlags::WRITE_THROUGH | PageTableFlags::CACHE_DISABLE
            );
        }
    }
    
    // MMIO領域のマッピング
    let mmio_regions = [
        // APICレジスタ
        (APIC_BASE, APIC_SIZE),
        // IOAPICレジスタ
        (IOAPIC_BASE, IOAPIC_SIZE),
        // PCIコンフィグレーション空間
        (PCI_CONFIG_BASE, PCI_CONFIG_SIZE),
    ];
    
    for &(base, size) in &mmio_regions {
        let phys_start = base;
        let virt_start = MMIO_VIRTUAL_BASE + (base - MMIO_REGIONS_START);
        
        for i in 0..((size + PAGE_SIZE - 1) / PAGE_SIZE) {
            let phys_addr = phys_start + i * PAGE_SIZE;
            let virt_addr = virt_start + i * PAGE_SIZE;
            
            map_page(
                p4_table, 
                virt_addr as u64, 
                phys_addr as u64, 
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE | 
                PageTableFlags::WRITE_THROUGH | PageTableFlags::CACHE_DISABLE
            );
        }
    }
    
    // カーネルページテーブルを設定
    *KERNEL_PAGE_TABLE.write() = Some(table);
}

/// カーネルページテーブルを取得
pub fn get_kernel_page_table() -> &'static PageTable {
    KERNEL_PAGE_TABLE.read().as_ref().expect("カーネルページテーブルが初期化されていません")
}

/// 現在のページテーブルをロード
pub fn load_page_table(table: &PageTable) {
    let phys_addr = table.physical_address().as_u64();
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) phys_addr, options(nostack));
    }
}

/// 現在のページテーブルをフラッシュ（再ロード）
pub fn flush_current_page_table() {
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack));
    }
}

/// 特定の仮想アドレスのTLBエントリをフラッシュ
pub fn flush_tlb_entry(virt: VirtAddr) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) virt.as_u64(), options(nostack));
    }
} 