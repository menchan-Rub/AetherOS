// AetherOS AArch64 メモリタイプ定義
//
// ARMv8-A アーキテクチャ用のメモリアドレスとサイズの型定義を提供します。

use core::fmt;
use core::ops::{Add, AddAssign, Sub, SubAssign};

/// 物理アドレス
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysAddr(pub u64);

/// 仮想アドレス
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtAddr(pub u64);

/// ページサイズ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    /// 4KBページ
    Size4KB,
    /// 2MBページ（Large Page）
    Size2MB,
    /// 1GBページ（Huge Page）
    Size1GB,
}

impl PageSize {
    /// ページサイズをバイト単位で取得
    pub fn size_in_bytes(&self) -> usize {
        match self {
            PageSize::Size4KB => 4096,
            PageSize::Size2MB => 2 * 1024 * 1024,
            PageSize::Size1GB => 1024 * 1024 * 1024,
        }
    }
}

impl PhysAddr {
    /// 新しい物理アドレスを作成
    pub fn new(addr: u64) -> Self {
        Self(addr)
    }
    
    /// u64としての値を取得
    pub fn as_u64(&self) -> u64 {
        self.0
    }
    
    /// usize値としての値を取得
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
    
    /// 指定したオフセットを加算した新しいアドレスを返す
    pub fn offset(&self, offset: usize) -> Self {
        Self(self.0 + offset as u64)
    }
    
    /// このアドレスが指定したアライメントに合っているかチェック
    pub fn is_aligned(&self, alignment: usize) -> bool {
        assert!(alignment.is_power_of_two(), "アライメントは2の累乗である必要があります");
        self.0 & (alignment as u64 - 1) == 0
    }
    
    /// 指定したページサイズのアライメントに切り上げ
    pub fn page_align_up(&self, page_size: PageSize) -> Self {
        let size = page_size.size_in_bytes() as u64;
        Self((self.0 + size - 1) & !(size - 1))
    }
    
    /// 指定したページサイズのアライメントに切り捨て
    pub fn page_align_down(&self, page_size: PageSize) -> Self {
        let size = page_size.size_in_bytes() as u64;
        Self(self.0 & !(size - 1))
    }
}

impl VirtAddr {
    /// 新しい仮想アドレスを作成
    pub fn new(addr: u64) -> Self {
        Self(addr)
    }
    
    /// u64としての値を取得
    pub fn as_u64(&self) -> u64 {
        self.0
    }
    
    /// usize値としての値を取得
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
    
    /// 指定したオフセットを加算した新しいアドレスを返す
    pub fn offset(&self, offset: usize) -> Self {
        Self(self.0 + offset as u64)
    }
    
    /// このアドレスが指定したアライメントに合っているかチェック
    pub fn is_aligned(&self, alignment: usize) -> bool {
        assert!(alignment.is_power_of_two(), "アライメントは2の累乗である必要があります");
        self.0 & (alignment as u64 - 1) == 0
    }
    
    /// 指定したページサイズのアライメントに切り上げ
    pub fn page_align_up(&self, page_size: PageSize) -> Self {
        let size = page_size.size_in_bytes() as u64;
        Self((self.0 + size - 1) & !(size - 1))
    }
    
    /// 指定したページサイズのアライメントに切り捨て
    pub fn page_align_down(&self, page_size: PageSize) -> Self {
        let size = page_size.size_in_bytes() as u64;
        Self(self.0 & !(size - 1))
    }
    
    /// ページテーブルインデックスを取得（レベル0）
    pub fn p0_index(&self) -> usize {
        ((self.0 >> 39) & 0x1FF) as usize
    }
    
    /// ページテーブルインデックスを取得（レベル1）
    pub fn p1_index(&self) -> usize {
        ((self.0 >> 30) & 0x1FF) as usize
    }
    
    /// ページテーブルインデックスを取得（レベル2）
    pub fn p2_index(&self) -> usize {
        ((self.0 >> 21) & 0x1FF) as usize
    }
    
    /// ページテーブルインデックスを取得（レベル3）
    pub fn p3_index(&self) -> usize {
        ((self.0 >> 12) & 0x1FF) as usize
    }
    
    /// ページオフセットを取得
    pub fn page_offset(&self) -> usize {
        (self.0 & 0xFFF) as usize
    }
}

// 演算子のオーバーロード実装

impl Add<usize> for PhysAddr {
    type Output = Self;
    
    fn add(self, rhs: usize) -> Self::Output {
        PhysAddr(self.0 + rhs as u64)
    }
}

impl AddAssign<usize> for PhysAddr {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs as u64;
    }
}

impl Sub<usize> for PhysAddr {
    type Output = Self;
    
    fn sub(self, rhs: usize) -> Self::Output {
        PhysAddr(self.0 - rhs as u64)
    }
}

impl SubAssign<usize> for PhysAddr {
    fn sub_assign(&mut self, rhs: usize) {
        self.0 -= rhs as u64;
    }
}

impl Add<usize> for VirtAddr {
    type Output = Self;
    
    fn add(self, rhs: usize) -> Self::Output {
        VirtAddr(self.0 + rhs as u64)
    }
}

impl AddAssign<usize> for VirtAddr {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs as u64;
    }
}

impl Sub<usize> for VirtAddr {
    type Output = Self;
    
    fn sub(self, rhs: usize) -> Self::Output {
        VirtAddr(self.0 - rhs as u64)
    }
}

impl SubAssign<usize> for VirtAddr {
    fn sub_assign(&mut self, rhs: usize) {
        self.0 -= rhs as u64;
    }
}

// フォーマット実装

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#x})", self.0)
    }
}

impl fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VirtAddr({:#x})", self.0)
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// メモリタイプ定義を初期化
pub fn init() {
    // 特に初期化処理は必要ありませんが、将来の拡張性のために関数を用意
    log::trace!("AArch64メモリタイプ定義初期化完了");
} 