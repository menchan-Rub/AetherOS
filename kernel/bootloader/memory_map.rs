// メモリマップモジュール
//
// 物理メモリ領域の情報を管理する構造体

use alloc::vec::Vec;
use core::fmt;

/// メモリ領域タイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    /// 未定義/不明領域
    Unknown,
    /// 使用可能領域
    Available,
    /// 予約領域
    Reserved,
    /// ACPI再利用可能領域
    AcpiReclaimable,
    /// ACPI NVS領域
    AcpiNvs,
    /// 不良領域
    BadMemory,
    /// ブートローダーコード領域
    BootloaderCode,
    /// カーネルコード領域
    KernelCode,
    /// カーネルデータ領域
    KernelData,
    /// 初期RAMディスク領域
    Initrd,
}

impl MemoryType {
    /// UEFIメモリタイプからの変換
    pub fn from_uefi(memory_type: u32) -> Self {
        match memory_type {
            0 => Self::Unknown,
            1 => Self::Available,
            2 => Self::Reserved,
            3 => Self::AcpiReclaimable,
            4 => Self::AcpiNvs,
            5 => Self::BadMemory,
            _ => Self::Reserved,
        }
    }
    
    /// マルチブートメモリタイプからの変換
    pub fn from_multiboot(memory_type: u32) -> Self {
        match memory_type {
            1 => Self::Available,
            3 => Self::AcpiReclaimable,
            4 => Self::Reserved,
            5 => Self::AcpiNvs,
            6 => Self::BadMemory,
            _ => Self::Reserved,
        }
    }
}

/// メモリ領域情報
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    /// 開始物理アドレス
    pub base: usize,
    /// バイト単位のサイズ
    pub length: usize,
    /// メモリタイプ
    pub memory_type: MemoryType,
}

impl MemoryRegion {
    /// この領域が使用可能かどうか
    pub fn is_usable(&self) -> bool {
        self.memory_type == MemoryType::Available
    }
    
    /// この領域がACPIデータ用に再利用可能かどうか
    pub fn is_acpi_reclaimable(&self) -> bool {
        self.memory_type == MemoryType::AcpiReclaimable
    }
    
    /// 終了アドレス（最後のバイトを含む）
    pub fn end(&self) -> usize {
        self.base + self.length - 1
    }
    
    /// この領域が与えられたアドレスを含むかどうか
    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.base && addr <= self.end()
    }
}

impl fmt::Debug for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemoryRegion {{ base: {:#x}, end: {:#x}, size: {} KiB, type: {:?} }}",
            self.base,
            self.end(),
            self.length / 1024,
            self.memory_type
        )
    }
}

/// メモリマップ構造体
#[derive(Debug, Clone)]
pub struct MemoryMap {
    /// メモリ領域の配列
    regions: Vec<MemoryRegion>,
}

impl MemoryMap {
    /// 新しい空のメモリマップを作成
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }
    
    /// 領域を追加
    pub fn add_region(&mut self, region: MemoryRegion) {
        // 0サイズの領域はスキップ
        if region.length == 0 {
            return;
        }
        
        // 領域を追加
        self.regions.push(region);
        
        // ベースアドレスでソート
        self.regions.sort_by_key(|r| r.base);
        
        // 隣接/重複する同じタイプの領域をマージ
        self.merge_regions();
    }
    
    /// 隣接/重複する同じタイプの領域をマージ
    fn merge_regions(&mut self) {
        if self.regions.is_empty() {
            return;
        }
        
        let mut merged_regions = Vec::new();
        let mut current_region = self.regions[0];
        
        for i in 1..self.regions.len() {
            let region = self.regions[i];
            
            // 現在の領域と重複または隣接しており、同じタイプの場合はマージ
            if region.memory_type == current_region.memory_type && 
               region.base <= current_region.end() + 1 
            {
                // 現在の領域を拡張
                let new_end = core::cmp::max(current_region.end(), region.end());
                current_region.length = new_end - current_region.base + 1;
            } else {
                // 現在の領域を保存して新しい領域を開始
                merged_regions.push(current_region);
                current_region = region;
            }
        }
        
        // 最後の領域を追加
        merged_regions.push(current_region);
        
        // マージされた領域で置き換え
        self.regions = merged_regions;
    }
    
    /// 全メモリ領域を取得
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }
    
    /// 使用可能なメモリ領域のみ取得
    pub fn available_regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.regions.iter().filter(|r| r.is_usable())
    }
    
    /// 指定されたアドレス範囲のメモリタイプを取得
    pub fn get_type(&self, addr: usize) -> MemoryType {
        for region in &self.regions {
            if region.contains(addr) {
                return region.memory_type;
            }
        }
        
        // 見つからない場合は予約済みとみなす
        MemoryType::Reserved
    }
    
    /// 指定されたサイズに合う最初の使用可能メモリ領域を検索
    pub fn find_free_region(&self, size: usize, alignment: usize) -> Option<usize> {
        for region in self.available_regions() {
            // アラインメントを考慮した開始アドレス
            let aligned_base = (region.base + alignment - 1) & !(alignment - 1);
            
            // この領域が十分な大きさを持っているか確認
            if aligned_base + size <= region.base + region.length {
                return Some(aligned_base);
            }
        }
        
        None
    }
    
    /// 使用可能な合計メモリ量（バイト単位）
    pub fn total_available_memory(&self) -> usize {
        self.available_regions()
            .map(|r| r.length)
            .sum()
    }
    
    /// メモリの詳細な統計情報を表示
    pub fn print_stats(&self) {
        let total_memory = self.regions.iter().map(|r| r.length).sum::<usize>();
        let available_memory = self.available_regions().map(|r| r.length).sum::<usize>();
        
        log::info!("メモリマップ統計:");
        log::info!("  合計メモリ: {} MiB", total_memory / (1024 * 1024));
        log::info!("  利用可能メモリ: {} MiB", available_memory / (1024 * 1024));
        log::info!("  領域数: {}", self.regions.len());
        
        for (i, region) in self.regions.iter().enumerate() {
            log::info!(
                "  領域 {}: {:#x} - {:#x} ({} KiB) {:?}",
                i,
                region.base,
                region.end(),
                region.length / 1024,
                region.memory_type
            );
        }
    }
    
    /// UEFIメモリマップから変換
    pub fn from_uefi(uefi_memory_map: &[u8], descriptor_size: usize) -> Self {
        let mut memory_map = Self::new();
        
        let mut i = 0;
        while i + descriptor_size <= uefi_memory_map.len() {
            // UEFIメモリディスクリプタを解析
            // ここでは簡易的な実装
            let base = u64::from_le_bytes([
                uefi_memory_map[i],
                uefi_memory_map[i + 1],
                uefi_memory_map[i + 2],
                uefi_memory_map[i + 3],
                uefi_memory_map[i + 4],
                uefi_memory_map[i + 5],
                uefi_memory_map[i + 6],
                uefi_memory_map[i + 7],
            ]) as usize;
            
            let page_count = u64::from_le_bytes([
                uefi_memory_map[i + 8],
                uefi_memory_map[i + 9],
                uefi_memory_map[i + 10],
                uefi_memory_map[i + 11],
                uefi_memory_map[i + 12],
                uefi_memory_map[i + 13],
                uefi_memory_map[i + 14],
                uefi_memory_map[i + 15],
            ]) as usize;
            
            let uefi_type = u32::from_le_bytes([
                uefi_memory_map[i + 16],
                uefi_memory_map[i + 17],
                uefi_memory_map[i + 18],
                uefi_memory_map[i + 19],
            ]);
            
            let length = page_count * 4096; // UEFIのページサイズは4KB
            
            memory_map.add_region(MemoryRegion {
                base,
                length,
                memory_type: MemoryType::from_uefi(uefi_type),
            });
            
            i += descriptor_size;
        }
        
        memory_map
    }
    
    /// マルチブートメモリマップから変換（レガシーブート用）
    pub fn from_multiboot(mmap_addr: usize, mmap_length: usize) -> Self {
        let mut memory_map = Self::new();
        
        let mmap_end = mmap_addr + mmap_length;
        let mut current_addr = mmap_addr;
        
        while current_addr < mmap_end {
            // マルチブートメモリマップエントリを解析
            // マルチブートメモリマップエントリは20バイト
            let entry_size = unsafe { *(current_addr as *const u32) } as usize;
            let base = unsafe { *((current_addr + 4) as *const u64) } as usize;
            let length = unsafe { *((current_addr + 12) as *const u64) } as usize;
            let mb_type = unsafe { *((current_addr + 20) as *const u32) };
            
            memory_map.add_region(MemoryRegion {
                base,
                length,
                memory_type: MemoryType::from_multiboot(mb_type),
            });
            
            current_addr += entry_size + 4; // エントリサイズ + サイズフィールド
        }
        
        memory_map
    }
    
    /// 指定された物理アドレス範囲をカーネル用として予約
    pub fn reserve_kernel_memory(&mut self, start: usize, end: usize) {
        // 現在の領域を保存
        let current_regions = self.regions.clone();
        self.regions.clear();
        
        for region in current_regions {
            // カーネル領域と重複しない場合はそのまま追加
            if region.end() < start || region.base > end {
                self.regions.push(region);
                continue;
            }
            
            // カーネル領域の前の部分
            if region.base < start {
                self.regions.push(MemoryRegion {
                    base: region.base,
                    length: start - region.base,
                    memory_type: region.memory_type,
                });
            }
            
            // カーネル領域と重複する部分
            let overlap_start = core::cmp::max(region.base, start);
            let overlap_end = core::cmp::min(region.end(), end);
            
            if overlap_start <= overlap_end {
                self.regions.push(MemoryRegion {
                    base: overlap_start,
                    length: overlap_end - overlap_start + 1,
                    memory_type: MemoryType::KernelCode, // カーネルとして予約
                });
            }
            
            // カーネル領域の後の部分
            if region.end() > end {
                self.regions.push(MemoryRegion {
                    base: end + 1,
                    length: region.end() - end,
                    memory_type: region.memory_type,
                });
            }
        }
        
        // ベースアドレスでソート
        self.regions.sort_by_key(|r| r.base);
        
        // 隣接/重複する同じタイプの領域をマージ
        self.merge_regions();
    }
} 