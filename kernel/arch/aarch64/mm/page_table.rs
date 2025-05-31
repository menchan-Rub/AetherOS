// AetherOS AArch64 ページテーブル実装
//
// ARMv8-A アーキテクチャの4階層ページングシステムを管理します。
// 通常の4KBページに加え、2MB/1GBの大きなページにも対応します。

use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::arch::aarch64::mm::memory_types::{PhysAddr, VirtAddr, PageSize};
use crate::memory::allocator::{PhysicalAllocator, PHYS_ALLOCATOR};
use crate::sync::{SpinLock, RwLock};
use alloc::vec::Vec;

/// ページテーブルエントリのサイズ（バイト）
pub const PAGE_TABLE_ENTRY_SIZE: usize = 8;

/// TTBRレジスタビットフィールド
pub mod ttbr {
    /// 非安全メモリ属性
    pub const NON_SECURE: u64 = 1 << 0;
    /// 共有可能属性
    pub const SHARED: u64 = 1 << 1;
    /// アウターキャッシュポリシー
    pub const OUTER_WB: u64 = 0b11 << 2;
    /// インナーキャッシュポリシー
    pub const INNER_WB: u64 = 0b11 << 4;
}

/// ページテーブルエントリ共通フラグ
pub mod flag {
    /// ページが存在する（有効）
    pub const VALID: u64 = 1 << 0;
    /// ページテーブルエントリ（次のレベルへのポインタ）
    pub const TABLE: u64 = 1 << 1;
    /// アクセス済みフラグ
    pub const ACCESSED: u64 = 1 << 10;
    
    // メモリ属性インデックス
    /// 通常メモリ（キャッシュ可能）
    pub const MAIR_NORMAL: u64 = 0 << 2;
    /// デバイスメモリ（キャッシュ不可）
    pub const MAIR_DEVICE: u64 = 1 << 2;
    /// 非キャッシュメモリ
    pub const MAIR_UNCACHED: u64 = 2 << 2;
    
    // アクセス許可
    /// カーネルモードのみ読み取り可能
    pub const AP_KERNEL_READ: u64 = 0 << 6;
    /// カーネルモードのみ読み書き可能
    pub const AP_KERNEL_RW: u64 = 1 << 6;
    /// すべてのモードで読み取り可能
    pub const AP_ALL_READ: u64 = 2 << 6;
    /// すべてのモードで読み書き可能
    pub const AP_ALL_RW: u64 = 3 << 6;
    
    // 共有属性
    /// 非共有
    pub const NON_SHARED: u64 = 0 << 8;
    /// 外部共有
    pub const OUTER_SHARED: u64 = 2 << 8;
    /// 内部共有
    pub const INNER_SHARED: u64 = 3 << 8;
    
    /// 非実行フラグ（UXN, PXN）
    pub const NON_EXECUTABLE: u64 = 1 << 54;
    
    /// ブロックエントリ（大きなページをマッピング）
    pub const BLOCK: u64 = 0 << 1;
    
    /// ページフレームアドレスのマスク（12ビット目から始まる）
    pub const ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;
}

/// ページテーブルエントリ
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(AtomicU64);

impl PageTableEntry {
    /// 新しい空のページテーブルエントリを作成
    pub fn new_empty() -> Self {
        Self(AtomicU64::new(0))
    }
    
    /// テーブルエントリ（次のレベルへのポインタ）を作成
    pub fn new_table(next_table_addr: PhysAddr) -> Self {
        Self(AtomicU64::new((next_table_addr.as_u64() & flag::ADDR_MASK) | flag::VALID | flag::TABLE))
    }
    
    /// 4KBページをマッピングするエントリを作成
    pub fn new_page(page_addr: PhysAddr, flags: u64) -> Self {
        Self(AtomicU64::new((page_addr.as_u64() & flag::ADDR_MASK) | flags | flag::VALID))
    }
    
    /// 2MBブロックをマッピングするエントリを作成
    pub fn new_block_2mb(block_addr: PhysAddr, flags: u64) -> Self {
        Self(AtomicU64::new((block_addr.as_u64() & 0x0000_ffff_ffff_e000) | flags | flag::VALID | flag::BLOCK))
    }
    
    /// 1GBブロックをマッピングするエントリを作成
    pub fn new_block_1gb(block_addr: PhysAddr, flags: u64) -> Self {
        Self(AtomicU64::new((block_addr.as_u64() & 0x0000_ffff_ffe0_0000) | flags | flag::VALID | flag::BLOCK))
    }
    
    /// エントリの値を取得
    pub fn get_value(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    
    /// エントリに値を設定
    pub fn set_value(&self, value: u64) {
        self.0.store(value, Ordering::Relaxed);
    }
    
    /// エントリが有効かチェック
    pub fn is_valid(&self) -> bool {
        self.get_value() & flag::VALID != 0
    }
    
    /// テーブルエントリかチェック（次のレベルへのポインタ）
    pub fn is_table(&self) -> bool {
        (self.get_value() & (flag::VALID | flag::TABLE)) == (flag::VALID | flag::TABLE)
    }
    
    /// ブロックエントリかチェック（大きなページ）
    pub fn is_block(&self) -> bool {
        (self.get_value() & (flag::VALID | flag::TABLE)) == flag::VALID
    }
    
    /// 物理アドレスを取得
    pub fn get_address(&self) -> PhysAddr {
        if self.is_table() {
            PhysAddr::new(self.get_value() & flag::ADDR_MASK)
        } else if self.is_block() {
            let value = self.get_value();
            // テーブルレベルによって異なるマスクが必要だが、呼び出し元で適切に処理する
            PhysAddr::new(value & flag::ADDR_MASK)
        } else {
            PhysAddr::new(0)
        }
    }
    
    /// 物理アドレスを設定（フラグは保持）
    pub fn set_address(&self, addr: PhysAddr) {
        let flags = self.get_value() & !flag::ADDR_MASK;
        self.set_value(flags | (addr.as_u64() & flag::ADDR_MASK));
    }
    
    /// フラグを設定
    pub fn set_flags(&self, flags: u64) {
        let addr = self.get_value() & flag::ADDR_MASK;
        self.set_value(addr | flags);
    }
    
    /// フラグをクリア
    pub fn clear_flags(&self, flags: u64) {
        let value = self.get_value();
        self.set_value(value & !flags);
    }
    
    /// 特定のフラグが設定されているかチェック
    pub fn has_flag(&self, flag: u64) -> bool {
        self.get_value() & flag != 0
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
        let mut flags = flag::VALID; // 有効フラグは常に設定
        
        // アクセス許可設定
        if self.user {
            if self.write {
                flags |= flag::AP_ALL_RW;
            } else {
                flags |= flag::AP_ALL_READ;
            }
        } else {
            if self.write {
                flags |= flag::AP_KERNEL_RW;
            } else {
                flags |= flag::AP_KERNEL_READ;
            }
        }
        
        // 実行不可設定
        if !self.execute {
            flags |= flag::NON_EXECUTABLE;
        }
        
        // 共有およびキャッシュ属性
        flags |= flag::INNER_SHARED;
        flags |= flag::MAIR_NORMAL;
        
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

/// ページテーブル構造体
#[repr(align(4096))]
pub struct PageTable {
    /// レベル0テーブルエントリ（512個）
    entries: [PageTableEntry; 512],
}

impl PageTable {
    /// 新しい空のページテーブルを作成
    pub fn new() -> Self {
        Self {
            entries: [PageTableEntry::new_empty(); 512],
        }
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
        let p0_idx = virt.p0_index();
        let p1_idx = virt.p1_index();
        let p2_idx = virt.p2_index();
        let p3_idx = virt.p3_index();
        
        // レベル0テーブルエントリ
        let p0e = &self.entries[p0_idx];
        
        // レベル1テーブルを取得または作成
        let p1 = if p0e.is_valid() && p0e.is_table() {
            // 既存のレベル1テーブルを使用
            unsafe { &mut *(p0e.get_address().as_u64() as *mut [PageTableEntry; 512]) }
        } else {
            // 新しいレベル1テーブルを割り当て
            let p1_phys = Self::allocate_table();
            p0e.set_value((p1_phys.as_u64() & flag::ADDR_MASK) | flag::VALID | flag::TABLE);
            unsafe { &mut *(p1_phys.as_u64() as *mut [PageTableEntry; 512]) }
        };
        
        // レベル1テーブルエントリ
        let p1e = &p1[p1_idx];
        
        // レベル2テーブルを取得または作成
        let p2 = if p1e.is_valid() && p1e.is_table() {
            // 既存のレベル2テーブルを使用
            unsafe { &mut *(p1e.get_address().as_u64() as *mut [PageTableEntry; 512]) }
        } else if p1e.is_valid() && p1e.is_block() {
            // 1GBブロックが既にマッピングされている場合は失敗
            return false;
        } else {
            // 新しいレベル2テーブルを割り当て
            let p2_phys = Self::allocate_table();
            p1e.set_value((p2_phys.as_u64() & flag::ADDR_MASK) | flag::VALID | flag::TABLE);
            unsafe { &mut *(p2_phys.as_u64() as *mut [PageTableEntry; 512]) }
        };
        
        // レベル2テーブルエントリ
        let p2e = &p2[p2_idx];
        
        // レベル3テーブルを取得または作成
        let p3 = if p2e.is_valid() && p2e.is_table() {
            // 既存のレベル3テーブルを使用
            unsafe { &mut *(p2e.get_address().as_u64() as *mut [PageTableEntry; 512]) }
        } else if p2e.is_valid() && p2e.is_block() {
            // 2MBブロックが既にマッピングされている場合は失敗
            return false;
        } else {
            // 新しいレベル3テーブルを割り当て
            let p3_phys = Self::allocate_table();
            p2e.set_value((p3_phys.as_u64() & flag::ADDR_MASK) | flag::VALID | flag::TABLE);
            unsafe { &mut *(p3_phys.as_u64() as *mut [PageTableEntry; 512]) }
        };
        
        // レベル3テーブルエントリ（4KBページ）
        let p3e = &p3[p3_idx];
        
        if p3e.is_valid() {
            // 既にマッピングされている場合は失敗
            return false;
        }
        
        // 4KBページをマッピング
        p3e.set_value((phys.as_u64() & flag::ADDR_MASK) | flags);
        
        // TLBをフラッシュ
        Self::flush_tlb_entry(virt);
        
        true
    }
    
    /// 2MBページ（ブロック）をマッピング
    fn map_2mb(&mut self, virt: VirtAddr, phys: PhysAddr, flags: u64) -> bool {
        // 2MBアライメントをチェック
        if virt.as_u64() & 0x1FFFFF != 0 || phys.as_u64() & 0x1FFFFF != 0 {
            return false;
        }
        
        // 各レベルのインデックスを計算
        let p0_idx = virt.p0_index();
        let p1_idx = virt.p1_index();
        let p2_idx = virt.p2_index();
        
        // レベル0テーブルエントリ
        let p0e = &self.entries[p0_idx];
        
        // レベル1テーブルを取得または作成
        let p1 = if p0e.is_valid() && p0e.is_table() {
            // 既存のレベル1テーブルを使用
            unsafe { &mut *(p0e.get_address().as_u64() as *mut [PageTableEntry; 512]) }
        } else {
            // 新しいレベル1テーブルを割り当て
            let p1_phys = Self::allocate_table();
            p0e.set_value((p1_phys.as_u64() & flag::ADDR_MASK) | flag::VALID | flag::TABLE);
            unsafe { &mut *(p1_phys.as_u64() as *mut [PageTableEntry; 512]) }
        };
        
        // レベル1テーブルエントリ
        let p1e = &p1[p1_idx];
        
        // レベル2テーブルを取得または作成
        let p2 = if p1e.is_valid() && p1e.is_table() {
            // 既存のレベル2テーブルを使用
            unsafe { &mut *(p1e.get_address().as_u64() as *mut [PageTableEntry; 512]) }
        } else if p1e.is_valid() && p1e.is_block() {
            // 1GBブロックが既にマッピングされている場合は失敗
            return false;
        } else {
            // 新しいレベル2テーブルを割り当て
            let p2_phys = Self::allocate_table();
            p1e.set_value((p2_phys.as_u64() & flag::ADDR_MASK) | flag::VALID | flag::TABLE);
            unsafe { &mut *(p2_phys.as_u64() as *mut [PageTableEntry; 512]) }
        };
        
        // レベル2テーブルエントリ（2MBブロック）
        let p2e = &p2[p2_idx];
        
        if p2e.is_valid() {
            // 既にマッピングされている場合は失敗
            return false;
        }
        
        // 2MBブロックをマッピング
        p2e.set_value((phys.as_u64() & 0x0000_ffff_ffff_e000) | flags | flag::VALID | flag::BLOCK);
        
        // TLBをフラッシュ
        Self::flush_tlb_entry(virt);
        
        true
    }
    
    /// 1GBページ（ブロック）をマッピング
    fn map_1gb(&mut self, virt: VirtAddr, phys: PhysAddr, flags: u64) -> bool {
        // 1GBアライメントをチェック
        if virt.as_u64() & 0x3FFFFFFF != 0 || phys.as_u64() & 0x3FFFFFFF != 0 {
            return false;
        }
        
        // 各レベルのインデックスを計算
        let p0_idx = virt.p0_index();
        let p1_idx = virt.p1_index();
        
        // レベル0テーブルエントリ
        let p0e = &self.entries[p0_idx];
        
        // レベル1テーブルを取得または作成
        let p1 = if p0e.is_valid() && p0e.is_table() {
            // 既存のレベル1テーブルを使用
            unsafe { &mut *(p0e.get_address().as_u64() as *mut [PageTableEntry; 512]) }
        } else {
            // 新しいレベル1テーブルを割り当て
            let p1_phys = Self::allocate_table();
            p0e.set_value((p1_phys.as_u64() & flag::ADDR_MASK) | flag::VALID | flag::TABLE);
            unsafe { &mut *(p1_phys.as_u64() as *mut [PageTableEntry; 512]) }
        };
        
        // レベル1テーブルエントリ（1GBブロック）
        let p1e = &p1[p1_idx];
        
        if p1e.is_valid() {
            // 既にマッピングされている場合は失敗
            return false;
        }
        
        // 1GBブロックをマッピング
        p1e.set_value((phys.as_u64() & 0x0000_ffff_ffe0_0000) | flags | flag::VALID | flag::BLOCK);
        
        // TLBをフラッシュ
        Self::flush_tlb_entry(virt);
        
        true
    }
    
    /// ページをアンマップ
    pub fn unmap(&mut self, virt: VirtAddr) -> bool {
        // 各レベルのインデックスを計算
        let p0_idx = virt.p0_index();
        let p1_idx = virt.p1_index();
        let p2_idx = virt.p2_index();
        let p3_idx = virt.p3_index();
        
        // レベル0テーブルエントリ
        let p0e = &self.entries[p0_idx];
        
        if !p0e.is_valid() || !p0e.is_table() {
            return false;
        }
        
        // レベル1テーブル
        let p1 = unsafe { &mut *(p0e.get_address().as_u64() as *mut [PageTableEntry; 512]) };
        let p1e = &p1[p1_idx];
        
        if !p1e.is_valid() {
            return false;
        }
        
        // 1GBブロックの場合
        if p1e.is_block() {
            p1e.set_value(0);
            Self::flush_tlb_entry(virt);
            return true;
        }
        
        if !p1e.is_table() {
            return false;
        }
        
        // レベル2テーブル
        let p2 = unsafe { &mut *(p1e.get_address().as_u64() as *mut [PageTableEntry; 512]) };
        let p2e = &p2[p2_idx];
        
        if !p2e.is_valid() {
            return false;
        }
        
        // 2MBブロックの場合
        if p2e.is_block() {
            p2e.set_value(0);
            Self::flush_tlb_entry(virt);
            return true;
        }
        
        if !p2e.is_table() {
            return false;
        }
        
        // レベル3テーブル
        let p3 = unsafe { &mut *(p2e.get_address().as_u64() as *mut [PageTableEntry; 512]) };
        let p3e = &p3[p3_idx];
        
        if !p3e.is_valid() {
            return false;
        }
        
        // 4KBページをアンマップ
        p3e.set_value(0);
        Self::flush_tlb_entry(virt);
        
        true
    }
    
    /// 指定した仮想アドレスの物理アドレスを取得
    pub fn translate(&self, virt: VirtAddr) -> Option<PhysAddr> {
        // 各レベルのインデックスを計算
        let p0_idx = virt.p0_index();
        let p1_idx = virt.p1_index();
        let p2_idx = virt.p2_index();
        let p3_idx = virt.p3_index();
        let offset = virt.page_offset();
        
        // レベル0テーブルエントリ
        let p0e = &self.entries[p0_idx];
        
        if !p0e.is_valid() || !p0e.is_table() {
            return None;
        }
        
        // レベル1テーブル
        let p1 = unsafe { &*(p0e.get_address().as_u64() as *const [PageTableEntry; 512]) };
        let p1e = &p1[p1_idx];
        
        if !p1e.is_valid() {
            return None;
        }
        
        // 1GBブロックの場合
        if p1e.is_block() {
            let phys_base = p1e.get_address().as_u64() & 0x0000_ffff_ffe0_0000;
            let offset_1gb = virt.as_u64() & 0x3FFFFFFF;
            return Some(PhysAddr::new(phys_base + offset_1gb));
        }
        
        if !p1e.is_table() {
            return None;
        }
        
        // レベル2テーブル
        let p2 = unsafe { &*(p1e.get_address().as_u64() as *const [PageTableEntry; 512]) };
        let p2e = &p2[p2_idx];
        
        if !p2e.is_valid() {
            return None;
        }
        
        // 2MBブロックの場合
        if p2e.is_block() {
            let phys_base = p2e.get_address().as_u64() & 0x0000_ffff_ffff_e000;
            let offset_2mb = virt.as_u64() & 0x1FFFFF;
            return Some(PhysAddr::new(phys_base + offset_2mb));
        }
        
        if !p2e.is_table() {
            return None;
        }
        
        // レベル3テーブル
        let p3 = unsafe { &*(p2e.get_address().as_u64() as *const [PageTableEntry; 512]) };
        let p3e = &p3[p3_idx];
        
        if !p3e.is_valid() {
            return None;
        }
        
        // 4KBページの場合
        let phys_base = p3e.get_address().as_u64() & flag::ADDR_MASK;
        Some(PhysAddr::new(phys_base + offset as u64))
    }
    
    /// アクセス権を取得
    pub fn get_access(&self, virt: VirtAddr) -> Option<MemoryAccess> {
        // 各レベルのインデックスを計算
        let p0_idx = virt.p0_index();
        let p1_idx = virt.p1_index();
        let p2_idx = virt.p2_index();
        let p3_idx = virt.p3_index();
        
        // レベル0テーブルエントリ
        let p0e = &self.entries[p0_idx];
        
        if !p0e.is_valid() || !p0e.is_table() {
            return None;
        }
        
        // レベル1テーブル
        let p1 = unsafe { &*(p0e.get_address().as_u64() as *const [PageTableEntry; 512]) };
        let p1e = &p1[p1_idx];
        
        if !p1e.is_valid() {
            return None;
        }
        
        // 1GBブロックの場合
        if p1e.is_block() {
            let flags = p1e.get_value();
            return Some(Self::flags_to_access(flags));
        }
        
        if !p1e.is_table() {
            return None;
        }
        
        // レベル2テーブル
        let p2 = unsafe { &*(p1e.get_address().as_u64() as *const [PageTableEntry; 512]) };
        let p2e = &p2[p2_idx];
        
        if !p2e.is_valid() {
            return None;
        }
        
        // 2MBブロックの場合
        if p2e.is_block() {
            let flags = p2e.get_value();
            return Some(Self::flags_to_access(flags));
        }
        
        if !p2e.is_table() {
            return None;
        }
        
        // レベル3テーブル
        let p3 = unsafe { &*(p2e.get_address().as_u64() as *const [PageTableEntry; 512]) };
        let p3e = &p3[p3_idx];
        
        if !p3e.is_valid() {
            return None;
        }
        
        // 4KBページの場合
        let flags = p3e.get_value();
        Some(Self::flags_to_access(flags))
    }
    
    /// フラグからアクセス権情報に変換
    fn flags_to_access(flags: u64) -> MemoryAccess {
        let ap = (flags >> 6) & 0x3;
        
        let (user, write) = match ap {
            0 => (false, false), // カーネル読み取り専用
            1 => (false, true),  // カーネル読み書き
            2 => (true, false),  // すべて読み取り専用
            3 => (true, true),   // すべて読み書き
            _ => unreachable!(),
        };
        
        MemoryAccess {
            read: true, // 読み取りは常に許可
            write,
            execute: flags & flag::NON_EXECUTABLE == 0,
            user,
        }
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
    
    /// 特定の仮想アドレスのTLBエントリをフラッシュ
    fn flush_tlb_entry(virt: VirtAddr) {
        unsafe {
            core::arch::asm!("tlbi vaae1is, {}", in(reg) virt.as_u64() >> 12);
            core::arch::asm!("dsb ish");
            core::arch::asm!("isb");
        }
    }
    
    /// 現在のTTBRを取得
    #[inline(always)]
    pub unsafe fn read_ttbr0_el1() -> u64 {
        let value: u64;
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) value);
        value
    }
    
    /// TTBR0_EL1を設定（ユーザーページテーブル）
    #[inline(always)]
    pub unsafe fn write_ttbr0_el1(value: u64) {
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) value);
        core::arch::asm!("isb");
    }
    
    /// TTBR1_EL1を設定（カーネルページテーブル）
    #[inline(always)]
    pub unsafe fn write_ttbr1_el1(value: u64) {
        core::arch::asm!("msr ttbr1_el1, {}", in(reg) value);
        core::arch::asm!("isb");
    }
}

/// システム全体で使用するページテーブル
static KERNEL_PAGE_TABLE: RwLock<Option<PageTable>> = RwLock::new(None);

/// カーネルページテーブルを初期化
pub fn init_kernel_page_table() {
    let mut table = PageTable::new();
    
    // AArch64用のカーネル初期マッピング設定
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
            ttbr1_table, 
            virt_addr as u64, 
            phys_addr as u64, 
            PageAttributes::new()
                .with_access_flag(true)
                .with_shareability(Shareability::InnerShareable)
                .with_access_permissions(AccessPermissions::ReadOnly)
                .with_execute_never(false) // 実行可能
                .with_memory_attributes(MemoryAttributes::Normal)
                .with_privileged(true)
        );
    }
    
    // カーネルデータセクションのマッピング（読み書き可能、実行不可）
    let data_phys_start = code_phys_start + code_size;
    let data_virt_start = code_virt_start + code_size;
    let data_size = kernel_size - code_size;
    
    for i in 0..(data_size / PAGE_SIZE) {
        let phys_addr = data_phys_start + i * PAGE_SIZE;
        let virt_addr = data_virt_start + i * PAGE_SIZE;
        
        map_page(
            ttbr1_table, 
            virt_addr as u64, 
            phys_addr as u64, 
            PageAttributes::new()
                .with_access_flag(true)
                .with_shareability(Shareability::InnerShareable)
                .with_access_permissions(AccessPermissions::ReadWrite)
                .with_execute_never(true) // 実行不可
                .with_memory_attributes(MemoryAttributes::Normal)
                .with_privileged(true)
        );
    }
    
    // デバイスマッピング（フレームバッファなど）
    if let Some(framebuffer) = framebuffer_info {
        let fb_phys_start = framebuffer.address as usize;
        let fb_size = framebuffer.pitch as usize * framebuffer.height as usize;
        
        // フレームバッファを専用の仮想アドレス範囲にマッピング
        let fb_virt_start = FRAMEBUFFER_VIRTUAL_BASE;
        
        for i in 0..((fb_size + PAGE_SIZE - 1) / PAGE_SIZE) {
            let phys_addr = fb_phys_start + i * PAGE_SIZE;
            let virt_addr = fb_virt_start + i * PAGE_SIZE;
            
            map_page(
                ttbr1_table,
                virt_addr as u64, 
                phys_addr as u64, 
                PageAttributes::new()
                    .with_access_flag(true)
                    .with_shareability(Shareability::OuterShareable)
                    .with_access_permissions(AccessPermissions::ReadWrite)
                    .with_execute_never(true)
                    .with_memory_attributes(MemoryAttributes::Device)
                    .with_privileged(true)
            );
        }
    }
    
    // MMIO領域のマッピング
    let mmio_regions = [
        // GICレジスタ
        (GIC_DISTRIBUTOR_BASE, GIC_DISTRIBUTOR_SIZE),
        // GIC CPUインタフェース
        (GIC_CPU_INTERFACE_BASE, GIC_CPU_INTERFACE_SIZE),
        // UARTコントローラ
        (UART_BASE, UART_SIZE),
        // タイマー
        (TIMER_BASE, TIMER_SIZE),
    ];
    
    for &(base, size) in &mmio_regions {
        let phys_start = base;
        let virt_start = MMIO_VIRTUAL_BASE + (base - MMIO_REGIONS_START);
        
        for i in 0..((size + PAGE_SIZE - 1) / PAGE_SIZE) {
            let phys_addr = phys_start + i * PAGE_SIZE;
            let virt_addr = virt_start + i * PAGE_SIZE;
            
            map_page(
                ttbr1_table,
                virt_addr as u64, 
                phys_addr as u64, 
                PageAttributes::new()
                    .with_access_flag(true)
                    .with_shareability(Shareability::OuterShareable)
                    .with_access_permissions(AccessPermissions::ReadWrite)
                    .with_execute_never(true)
                    .with_memory_attributes(MemoryAttributes::Device)
                    .with_privileged(true)
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

/// 現在のページテーブルをロード（カーネルのTTBR1_EL1用）
pub fn load_kernel_page_table(table: &PageTable) {
    let phys_addr = table.physical_address().as_u64();
    unsafe {
        PageTable::write_ttbr1_el1(phys_addr | ttbr::SHARED | ttbr::OUTER_WB | ttbr::INNER_WB);
    }
}

/// ページテーブルサブシステムを初期化
pub fn init() {
    // カーネルページテーブルを初期化
    init_kernel_page_table();
    
    // カーネルページテーブルをロード
    let kernel_table = get_kernel_page_table();
    load_kernel_page_table(kernel_table);
    
    log::info!("AArch64ページテーブル初期化完了");
} 