// AetherOS ハイパーページ（大規模ページ）サポート
//
// このモジュールは、2MB/1GBなどの大規模ページをサポートし、
// TLBミスを減らし、大規模メモリアクセスのパフォーマンスを向上させます。

use crate::arch::{PhysicalAddress, VirtualAddress, PAGE_SIZE};
use crate::core::memory::mm::page::api as page_api;
use crate::core::memory::mm::paging;
use crate::core::memory::mm::{PageTable, VmaType, VirtualMemoryArea, CachePolicy};
use crate::core::memory::mm::vma::api as vma_api;
use crate::error::{Error, Result};
use crate::sync::Mutex;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::ops::Range;
use log::{debug, error, info, warn};
use spin::Once;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

/// ハイパーページマネージャー
static HUGEPAGE_MANAGER: Once<Mutex<HugePageManager>> = Once::new();

/// ハイパーページサイズ（2MB）
const HUGE_PAGE_SIZE_2MB: usize = 2 * 1024 * 1024;

/// ハイパーページサイズ（1GB）
const HUGE_PAGE_SIZE_1GB: usize = 1024 * 1024 * 1024;

/// ハイパーページの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HugePageSize {
    /// 2MBページ
    Size2MB,
    /// 1GBページ
    Size1GB,
}

impl HugePageSize {
    /// ページサイズを取得
    pub fn size(&self) -> usize {
        match self {
            HugePageSize::Size2MB => HUGE_PAGE_SIZE_2MB,
            HugePageSize::Size1GB => HUGE_PAGE_SIZE_1GB,
        }
    }
    
    /// ページテーブルのレベルを取得
    pub fn page_level(&self) -> usize {
        match self {
            HugePageSize::Size2MB => 1, // L2レベル（4段階ページング）
            HugePageSize::Size1GB => 2, // L3レベル（4段階ページング）
        }
    }
    
    /// アーキテクチャ固有のフラグを取得
    pub fn arch_flags(&self) -> usize {
        match self {
            HugePageSize::Size2MB => 0x80, // ビット7: PSE (Page Size Extension)
            HugePageSize::Size1GB => 0x80, // ビット7: PSE (Page Size Extension)
        }
    }
}

/// ハイパーページ領域情報
#[derive(Debug)]
struct HugePageRegion {
    /// 物理ページのベースアドレス
    physical_base: PhysicalAddress,
    /// 領域サイズ
    size: usize,
    /// ページサイズ
    page_size: HugePageSize,
    /// カーネルでの仮想マッピングアドレス（存在する場合）
    kernel_vaddr: Option<VirtualAddress>,
    /// 仮想マッピング情報（プロセスID, 仮想アドレス）
    virtual_mappings: BTreeMap<usize, VirtualAddress>,
    /// 領域名（デバッグ用）
    name: String,
}

/// ハイパーページマネージャー
struct HugePageManager {
    /// 全ハイパーページ領域
    regions: Vec<HugePageRegion>,
    /// プロセスごとの領域インデックスリスト
    process_regions: BTreeMap<usize, Vec<usize>>,
}

impl HugePageManager {
    /// 新しいハイパーページマネージャーを作成
    fn new() -> Self {
        HugePageManager {
            regions: Vec::new(),
            process_regions: BTreeMap::new(),
        }
    }
    
    /// 新しいハイパーページ領域を予約
    fn allocate_region(
        &mut self,
        size: usize,
        page_size: HugePageSize,
        name: &str,
    ) -> Result<usize> {
        // サイズバリデーション
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        
        // ページサイズにアラインメント
        let huge_size = page_size.size();
        let aligned_size = (size + huge_size - 1) & !(huge_size - 1);
        let num_pages = aligned_size / huge_size;
        
        if num_pages == 0 {
            return Err(Error::InvalidArgument);
        }
        
        // 連続した物理ページを割り当て
        let contiguous_size = aligned_size;
        let physical_base = match page_api::alloc_contiguous_pages(contiguous_size / PAGE_SIZE) {
            Some(addr) => addr,
            None => return Err(Error::OutOfMemory),
        };
        
        // 領域を作成
        let region = HugePageRegion {
            physical_base,
            size: aligned_size,
            page_size,
            kernel_vaddr: None,
            virtual_mappings: BTreeMap::new(),
            name: name.to_string(),
        };
        
        // 領域リストに追加
        let region_index = self.regions.len();
        self.regions.push(region);
        
        info!("ハイパーページ: 領域を確保: インデックス={}, サイズ={}MB, ページサイズ={:?}",
             region_index, aligned_size / (1024 * 1024), page_size);
        
        Ok(region_index)
    }
    
    /// ハイパーページ領域をカーネル空間にマッピング
    fn map_to_kernel(&mut self, region_index: usize, cache_policy: CachePolicy) -> Result<VirtualAddress> {
        // 領域情報を取得
        let region = match self.regions.get_mut(region_index) {
            Some(r) => r,
            None => return Err(Error::InvalidArgument),
        };
        
        // すでにマッピング済みの場合はそのアドレスを返す
        if let Some(vaddr) = region.kernel_vaddr {
            return Ok(vaddr);
        }
        
        // カーネルページテーブルを取得
        let kernel_page_table = PageTable::get_kernel_table();
        
        // MMUフラグを設定（常に読み書き可能）
        let mut mmu_flags = 0x3; // 読み書き
        mmu_flags |= region.page_size.arch_flags(); // ハイパーページフラグ
        
        // 連続した物理ページを一時的な仮想アドレスにマッピング
        let size = region.size;
        let huge_size = region.page_size.size();
        let vaddr = match vma_api::find_free_region(kernel_page_table, size, huge_size) {
            Some(addr) => addr,
            None => return Err(Error::OutOfMemory),
        };
        
        // VMAを作成
        let vma = VirtualMemoryArea {
            range: vaddr..(vaddr + size),
            physical_mapping: None, // 物理ページは直接マッピングするので不要
            vma_type: VmaType::KernelMapped,
            permissions: mmu_flags,
            cache_policy,
            file_descriptor: None,
            file_offset: 0,
            name: Some(format!("hugepage:{}", region.name)),
        };
        
        // VMAをページテーブルに追加
        if !vma_api::add_vma(kernel_page_table, vma) {
            return Err(Error::OutOfMemory);
        }
        
        // ハイパーページをマッピング
        let page_level = region.page_size.page_level();
        let num_pages = region.size / huge_size;
        
        for i in 0..num_pages {
            let page_vaddr = vaddr + (i * huge_size);
            let page_paddr = region.physical_base + (i * huge_size);
            
            if !paging::map_huge_page(
                kernel_page_table.get_root(),
                page_vaddr,
                page_paddr,
                mmu_flags,
                page_level,
            ) {
                // マッピング失敗、ここまでのマッピングを解除
                paging::unmap_huge_pages(
                    kernel_page_table.get_root(),
                    vaddr,
                    i,
                    huge_size,
                    page_level,
                );
                
                vma_api::remove_vma(kernel_page_table, vaddr);
                return Err(Error::MemoryMapFailed);
            }
        }
        
        // カーネル仮想アドレスを保存
        region.kernel_vaddr = Some(vaddr);
        
        debug!("ハイパーページ: カーネルにマッピング: インデックス={}, アドレス={:#x}", region_index, vaddr);
        
        Ok(vaddr)
    }
    
    /// ハイパーページをユーザープロセスにマッピング
    fn map_to_user(
        &mut self,
        region_index: usize,
        process_id: usize,
        page_table: &PageTable,
        vaddr: Option<VirtualAddress>,
        permissions: usize,
        cache_policy: CachePolicy,
    ) -> Result<VirtualAddress> {
        // 領域情報を取得
        let region = match self.regions.get_mut(region_index) {
            Some(r) => r,
            None => return Err(Error::InvalidArgument),
        };
        
        // すでにマッピング済みの場合はエラー
        if region.virtual_mappings.contains_key(&process_id) {
            return Err(Error::AlreadyExists);
        }
        
        // MMUフラグを設定
        let mut mmu_flags = permissions & 0x7; // 権限ビット
        mmu_flags |= region.page_size.arch_flags(); // ハイパーページフラグ
        
        // 仮想アドレスが指定されていない場合は自動割り当て
        let size = region.size;
        let huge_size = region.page_size.size();
        let user_vaddr = if let Some(addr) = vaddr {
            // 指定されたアドレスがアラインメントされているか確認
            if addr % huge_size != 0 {
                return Err(Error::InvalidArgument);
            }
            addr
        } else {
            match vma_api::find_free_region(page_table, size, huge_size) {
                Some(addr) => addr,
                None => return Err(Error::OutOfMemory),
            }
        };
        
        // VMAを作成
        let vma = VirtualMemoryArea {
            range: user_vaddr..(user_vaddr + size),
            physical_mapping: None, // 物理ページは直接マッピングするので不要
            vma_type: VmaType::AnonymousMapping,
            permissions: mmu_flags,
            cache_policy,
            file_descriptor: None,
            file_offset: 0,
            name: Some(format!("hugepage:{}", region.name)),
        };
        
        // VMAをページテーブルに追加
        if !vma_api::add_vma(page_table, vma) {
            return Err(Error::OutOfMemory);
        }
        
        // ハイパーページをマッピング
        let page_level = region.page_size.page_level();
        let num_pages = region.size / huge_size;
        
        for i in 0..num_pages {
            let page_vaddr = user_vaddr + (i * huge_size);
            let page_paddr = region.physical_base + (i * huge_size);
            
            if !paging::map_huge_page(
                page_table.get_root(),
                page_vaddr,
                page_paddr,
                mmu_flags,
                page_level,
            ) {
                // マッピング失敗、ここまでのマッピングを解除
                paging::unmap_huge_pages(
                    page_table.get_root(),
                    user_vaddr,
                    i,
                    huge_size,
                    page_level,
                );
                
                vma_api::remove_vma(page_table, user_vaddr);
                return Err(Error::MemoryMapFailed);
            }
        }
        
        // ユーザー仮想アドレスとプロセスIDを保存
        region.virtual_mappings.insert(process_id, user_vaddr);
        
        // プロセスの領域リストに追加
        let process_regions = self.process_regions
            .entry(process_id)
            .or_insert_with(Vec::new);
        
        if !process_regions.contains(&region_index) {
            process_regions.push(region_index);
        }
        
        info!("ハイパーページ: ユーザーにマッピング: インデックス={}, プロセス={}, アドレス={:#x}",
             region_index, process_id, user_vaddr);
        
        Ok(user_vaddr)
    }
    
    /// ハイパーページをユーザープロセスからアンマッピング
    fn unmap_from_user(&mut self, region_index: usize, process_id: usize, page_table: &PageTable) -> Result<()> {
        // 領域情報を取得
        let region = match self.regions.get_mut(region_index) {
            Some(r) => r,
            None => return Err(Error::InvalidArgument),
        };
        
        // プロセスIDと仮想アドレスをチェック
        match region.virtual_mappings.remove(&process_id) {
            Some(vaddr) => {
                // VMAを削除
                if !vma_api::remove_vma(page_table, vaddr) {
                    warn!("ハイパーページ: VMA削除失敗: インデックス={}, プロセス={}", region_index, process_id);
                    // 続行
                }
                
                // ページをアンマッピング
                let huge_size = region.page_size.size();
                let page_level = region.page_size.page_level();
                let num_pages = region.size / huge_size;
                
                if !paging::unmap_huge_pages(
                    page_table.get_root(),
                    vaddr,
                    num_pages,
                    huge_size,
                    page_level,
                ) {
                    warn!("ハイパーページ: ページアンマッピング失敗: インデックス={}, プロセス={}", region_index, process_id);
                    // 続行
                }
                
                // プロセスの領域リストから削除
                if let Some(regions) = self.process_regions.get_mut(&process_id) {
                    if let Some(pos) = regions.iter().position(|&r| r == region_index) {
                        regions.remove(pos);
                    }
                    
                    // リストが空になった場合はエントリを削除
                    if regions.is_empty() {
                        self.process_regions.remove(&process_id);
                    }
                }
                
                info!("ハイパーページ: ユーザーからアンマッピング: インデックス={}, プロセス={}", region_index, process_id);
                
                Ok(())
            },
            None => {
                warn!("ハイパーページ: マッピングなし: インデックス={}, プロセス={}", region_index, process_id);
                Err(Error::InvalidArgument)
            }
        }
    }
    
    /// ハイパーページをカーネルからアンマッピング
    fn unmap_from_kernel(&mut self, region_index: usize) -> Result<()> {
        // 領域情報を取得
        let region = match self.regions.get_mut(region_index) {
            Some(r) => r,
            None => return Err(Error::InvalidArgument),
        };
        
        // カーネル仮想アドレスをチェック
        if let Some(vaddr) = region.kernel_vaddr.take() {
            // カーネルページテーブルを取得
            let kernel_page_table = PageTable::get_kernel_table();
            
            // VMAを削除
            if !vma_api::remove_vma(kernel_page_table, vaddr) {
                warn!("ハイパーページ: カーネルVMA削除失敗: インデックス={}", region_index);
                // 続行
            }
            
            // ページをアンマッピング
            let huge_size = region.page_size.size();
            let page_level = region.page_size.page_level();
            let num_pages = region.size / huge_size;
            
            if !paging::unmap_huge_pages(
                kernel_page_table.get_root(),
                vaddr,
                num_pages,
                huge_size,
                page_level,
            ) {
                warn!("ハイパーページ: カーネルページアンマッピング失敗: インデックス={}", region_index);
                // 続行
            }
            
            debug!("ハイパーページ: カーネルからアンマッピング: インデックス={}", region_index);
            
            Ok(())
        } else {
            warn!("ハイパーページ: カーネルマッピングなし: インデックス={}", region_index);
            Err(Error::InvalidArgument)
        }
    }
    
    /// ハイパーページ領域を解放
    fn free_region(&mut self, region_index: usize) -> Result<()> {
        // 領域情報を取得
        if region_index >= self.regions.len() {
            return Err(Error::InvalidArgument);
        }
        
        // ユーザー空間にマッピングされている場合はエラー
        let region = &self.regions[region_index];
        if !region.virtual_mappings.is_empty() {
            warn!("ハイパーページ: ユーザーマッピング中の領域は解放できません: インデックス={}", region_index);
            return Err(Error::ResourceBusy);
        }
        
        // カーネル空間にマッピングされている場合はアンマッピング
        if region.kernel_vaddr.is_some() {
            // エラーは無視してできる限り解放する
            let _ = self.unmap_from_kernel(region_index);
        }
        
        // 領域情報を取得（再度取得）
        let region = self.regions.remove(region_index);
        
        // 物理ページを解放
        let num_pages = region.size / PAGE_SIZE;
        page_api::free_pages(region.physical_base, num_pages);
        
        info!("ハイパーページ: 領域を解放: インデックス={}, サイズ={}MB",
             region_index, region.size / (1024 * 1024));
        
        // 後続の領域の参照を更新（プロセスマップ）
        for process_regions in self.process_regions.values_mut() {
            for idx in process_regions.iter_mut() {
                if *idx > region_index {
                    *idx -= 1;
                }
            }
        }
        
        Ok(())
    }
    
    /// プロセス終了時の処理
    fn handle_process_exit(&mut self, process_id: usize) {
        // プロセスの領域リストを取得
        if let Some(region_indices) = self.process_regions.remove(&process_id) {
            info!("ハイパーページ: プロセス終了処理: プロセス={}, 領域数={}", process_id, region_indices.len());
            
            // 各領域のユーザーマッピング情報をクリア
            for &index in region_indices.iter() {
                if let Some(region) = self.regions.get_mut(index) {
                    region.virtual_mappings.remove(&process_id);
                    debug!("ハイパーページ: プロセス終了によりマッピング解除: インデックス={}", index);
                }
            }
        }
    }
    
    /// 領域情報をダンプ（デバッグ用）
    fn dump_regions(&self) {
        info!("=== ハイパーページ領域リスト ===");
        info!("領域数: {}", self.regions.len());
        
        for (i, region) in self.regions.iter().enumerate() {
            info!("  インデックス={}, 名前={}, サイズ={}MB, ページサイズ={:?}",
                 i, region.name, region.size / (1024 * 1024), region.page_size);
            
            if let Some(kernel_vaddr) = region.kernel_vaddr {
                info!("    カーネルマッピング: {:#x}", kernel_vaddr);
            }
            
            if !region.virtual_mappings.is_empty() {
                info!("    ユーザーマッピング数: {}", region.virtual_mappings.len());
                for (pid, vaddr) in region.virtual_mappings.iter() {
                    info!("      プロセス={}, アドレス={:#x}", pid, vaddr);
                }
            }
        }
        
        info!("プロセス領域マップ:");
        for (pid, regions) in self.process_regions.iter() {
            info!("  プロセス={}, 領域数={}: {:?}", pid, regions.len(), regions);
        }
        
        info!("================================");
    }
}

/// ハイパーページサブシステムの初期化
pub fn init() {
    info!("ハイパーページマネージャーを初期化中");
    
    // グローバルインスタンスを初期化
    HUGEPAGE_MANAGER.call_once(|| {
        Mutex::new(HugePageManager::new())
    });
    
    info!("ハイパーページマネージャーの初期化が完了しました");
}

// 公開API

/// 新しいハイパーページ領域を予約
///
/// # 引数
/// * `size` - 領域のサイズ（バイト単位）
/// * `page_size` - ハイパーページサイズ
/// * `name` - 領域の名前（デバッグ用）
///
/// # 戻り値
/// * 成功した場合は領域インデックス、失敗した場合はエラー
pub fn allocate_region(
    size: usize,
    page_size: HugePageSize,
    name: &str,
) -> Result<usize> {
    let mut manager = HUGEPAGE_MANAGER.get().unwrap().lock();
    manager.allocate_region(size, page_size, name)
}

/// ハイパーページ領域を解放
///
/// # 引数
/// * `region_index` - 解放する領域インデックス
///
/// # 戻り値
/// * 成功した場合は`Ok(())`、失敗した場合はエラー
pub fn free_region(region_index: usize) -> Result<()> {
    let mut manager = HUGEPAGE_MANAGER.get().unwrap().lock();
    manager.free_region(region_index)
}

/// ハイパーページ領域をカーネル空間にマッピング
///
/// # 引数
/// * `region_index` - マッピングする領域インデックス
/// * `cache_policy` - キャッシュポリシー
///
/// # 戻り値
/// * 成功した場合はカーネル仮想アドレス、失敗した場合はエラー
pub fn map_to_kernel(region_index: usize, cache_policy: CachePolicy) -> Result<VirtualAddress> {
    let mut manager = HUGEPAGE_MANAGER.get().unwrap().lock();
    manager.map_to_kernel(region_index, cache_policy)
}

/// ハイパーページ領域をユーザープロセスにマッピング
///
/// # 引数
/// * `region_index` - マッピングする領域インデックス
/// * `process_id` - プロセスID
/// * `page_table` - プロセスのページテーブル
/// * `vaddr` - マッピング先の仮想アドレス（Noneの場合は自動割り当て）
/// * `permissions` - メモリ保護フラグ
/// * `cache_policy` - キャッシュポリシー
///
/// # 戻り値
/// * 成功した場合はユーザー仮想アドレス、失敗した場合はエラー
pub fn map_to_user(
    region_index: usize,
    process_id: usize,
    page_table: &PageTable,
    vaddr: Option<VirtualAddress>,
    permissions: usize,
    cache_policy: CachePolicy,
) -> Result<VirtualAddress> {
    let mut manager = HUGEPAGE_MANAGER.get().unwrap().lock();
    manager.map_to_user(region_index, process_id, page_table, vaddr, permissions, cache_policy)
}

/// ハイパーページ領域をユーザープロセスからアンマッピング
///
/// # 引数
/// * `region_index` - アンマッピングする領域インデックス
/// * `process_id` - プロセスID
/// * `page_table` - プロセスのページテーブル
///
/// # 戻り値
/// * 成功した場合は`Ok(())`、失敗した場合はエラー
pub fn unmap_from_user(region_index: usize, process_id: usize, page_table: &PageTable) -> Result<()> {
    let mut manager = HUGEPAGE_MANAGER.get().unwrap().lock();
    manager.unmap_from_user(region_index, process_id, page_table)
}

/// ハイパーページ領域をカーネルからアンマッピング
///
/// # 引数
/// * `region_index` - アンマッピングする領域インデックス
///
/// # 戻り値
/// * 成功した場合は`Ok(())`、失敗した場合はエラー
pub fn unmap_from_kernel(region_index: usize) -> Result<()> {
    let mut manager = HUGEPAGE_MANAGER.get().unwrap().lock();
    manager.unmap_from_kernel(region_index)
}

/// プロセス終了時の処理
///
/// # 引数
/// * `process_id` - 終了したプロセスID
pub fn handle_process_exit(process_id: usize) {
    let mut manager = HUGEPAGE_MANAGER.get().unwrap().lock();
    manager.handle_process_exit(process_id);
}

/// 領域情報をダンプ（デバッグ用）
pub fn dump_regions() {
    let manager = HUGEPAGE_MANAGER.get().unwrap().lock();
    manager.dump_regions();
}

/// ハイパーページのサポート状況を確認
pub fn is_supported(page_size: HugePageSize) -> bool {
    // ここでアーキテクチャ固有のチェックを行う
    // 例: CPUの機能フラグを確認するなど
    match page_size {
        HugePageSize::Size2MB => true,  // 多くのx86_64 CPUは2MBをサポート
        HugePageSize::Size1GB => false, // 1GBは新しいCPUでのみサポート（実装依存）
    }
}

/// ハイパーページのデフォルトサイズを取得
pub fn get_default_size() -> HugePageSize {
    // サポート状況に応じて最適なサイズを返す
    if is_supported(HugePageSize::Size1GB) {
        HugePageSize::Size1GB
    } else {
        HugePageSize::Size2MB
    }
}

/// 指定されたサイズに適したハイパーページサイズを推奨
pub fn recommend_page_size(size: usize) -> HugePageSize {
    if size >= HUGE_PAGE_SIZE_1GB && is_supported(HugePageSize::Size1GB) {
        HugePageSize::Size1GB
    } else {
        HugePageSize::Size2MB
    }
} 