// AetherOS メモリマッピングサブシステム
//
// このモジュールはプロセスの仮想アドレス空間へのメモリマッピングを管理します。
// ファイル、デバイス、物理メモリ等を仮想アドレス空間にマッピングする機能を提供します。

use crate::arch::{PageSize, VirtualAddress, PhysicalAddress};
use crate::core::memory::mm::{PageTable, VmaType, VirtualMemoryArea, CachePolicy};
use crate::core::memory::mm::paging;
use crate::core::memory::mm::page::api as page_api;
use crate::core::memory::mm::vma::api as vma_api;
use crate::core::memory::mm::slub::api as slub_api;
use crate::core::process::Process;
use crate::fs::FileDescriptor;
use alloc::vec::Vec;
use log::{debug, error, info, warn, trace};
use spin::Mutex;
use alloc::string::String;
use alloc::sync::Arc;
use core::ops::Range;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::core::sync::RwLock;
use crate::core::memory::mm::slab::SlabCache;
use crate::core::fs::vfs;
use crate::core::fs::ext4::Ext4FileSystem;
use crate::core::fs::fat32::Fat32FileSystem;
use crate::core::fs::ntfs::NtfsFileSystem;
use core::sync::Once;

/// メモリマッピングの保護フラグ
pub mod prot {
    /// 読み取り可能
    pub const READ: u32 = 1 << 0;
    /// 書き込み可能
    pub const WRITE: u32 = 1 << 1;
    /// 実行可能
    pub const EXEC: u32 = 1 << 2;
    /// アクセス不可（保護用）
    pub const NONE: u32 = 0;
}

/// メモリマッピングのフラグ
pub mod flags {
    /// 共有マッピング
    pub const SHARED: u32 = 1 << 0;
    /// プライベートマッピング（コピーオンライト）
    pub const PRIVATE: u32 = 1 << 1;
    /// 固定アドレスにマッピング
    pub const FIXED: u32 = 1 << 2;
    /// アドレス指定なしでマッピング
    pub const ANONYMOUS: u32 = 1 << 3;
    /// マッピング時に先行してページを割り当て
    pub const POPULATE: u32 = 1 << 4;
    /// 大ページを使用
    pub const HUGETLB: u32 = 1 << 5;
    /// スタック用のマッピング
    pub const STACK: u32 = 1 << 6;
    /// 共有メモリマッピング
    pub const SHARED_MEMORY: u32 = 1 << 7;
    /// デバイスメモリマッピング
    pub const DEVICE_MEMORY: u32 = 1 << 8;
    /// Writeバック
    pub const CACHE_WB: u32 = 1 << 9;
    /// Write-through
    pub const CACHE_WT: u32 = 1 << 10;
    /// キャッシュなし
    pub const CACHE_UC: u32 = 1 << 11;
}

/// マッピング結果の構造体
pub struct MappingResult {
    /// マッピングされた仮想アドレス
    pub vaddr: VirtualAddress,
    /// マッピングのサイズ
    pub size: usize,
    /// 実際にマッピングされたページ数
    pub mapped_pages: usize,
}

/// メモリマッピングサブシステムの初期化
pub fn init() {
    info!("メモリマッピングサブシステムを初期化しています");
    // 初期化コードは必要に応じて追加
    info!("メモリマッピングサブシステムの初期化が完了しました");
}

/// 仮想アドレス空間にメモリをマッピング
///
/// # 引数
/// * `page_table` - ページテーブル
/// * `vaddr` - マッピングする仮想アドレス（NULLの場合は自動割り当て）
/// * `size` - マッピングするサイズ（バイト）
/// * `prot` - 保護フラグ（読み取り/書き込み/実行）
/// * `flags` - マッピングフラグ
/// * `fd` - ファイルディスクリプタ（ファイルマッピングの場合）
/// * `offset` - ファイル内のオフセット
///
/// # 戻り値
/// * 成功した場合はマッピング結果、失敗した場合はNone
pub fn mmap(
    page_table: &mut PageTable,
    vaddr: Option<VirtualAddress>,
    size: usize,
    prot: u32,
    flags: u32,
    fd: Option<FileDescriptor>,
    offset: usize,
) -> Option<MappingResult> {
    if size == 0 {
        warn!("mmap: サイズが0のマッピングは無効です");
        return None;
    }

    // サイズをページサイズにアラインメント
    let page_size = if flags & flags::HUGETLB != 0 {
        PageSize::Huge as usize
    } else {
        PageSize::Default as usize
    };
    
    let aligned_size = (size + page_size - 1) & !(page_size - 1);
    
    // VMAタイプを決定
    let vma_type = determine_vma_type(prot, flags);
    
    // キャッシュポリシーを決定
    let cache_policy = determine_cache_policy(flags);
    
    // マッピングアドレスを決定
    let mapping_addr = match vaddr {
        Some(addr) if flags & flags::FIXED != 0 => {
            // 固定アドレスの場合、既存のマッピングがあれば解除
            let aligned_addr = addr & !(page_size - 1);
            if unmap(page_table, aligned_addr, aligned_size).is_none() {
                warn!("mmap: 既存マッピングの解除に失敗しました");
                return None;
            }
            aligned_addr
        },
        Some(addr) => {
            // 推奨アドレスが指定されている場合
            let aligned_addr = addr & !(page_size - 1);
            if vma_api::is_region_free(page_table, aligned_addr, aligned_size) {
                aligned_addr
            } else {
                // 指定されたアドレスが使用中なら自動割り当て
                vma_api::find_free_region(page_table, aligned_size, page_size)?
            }
        },
        None => {
            // アドレス自動割り当て
            vma_api::find_free_region(page_table, aligned_size, page_size)?
        }
    };
    
    // ファイルマッピングかアノニマスマッピングかを決定
    if flags & flags::ANONYMOUS != 0 || fd.is_none() {
        // アノニマスマッピング
        anon_mmap(page_table, mapping_addr, aligned_size, prot, flags, vma_type, cache_policy)
    } else {
        // ファイルマッピング
        file_mmap(page_table, mapping_addr, aligned_size, prot, flags, fd.unwrap(), offset, vma_type, cache_policy)
    }
}

/// アノニマスメモリマッピング（ファイルなし）
fn anon_mmap(
    page_table: &mut PageTable,
    vaddr: VirtualAddress,
    size: usize,
    prot: u32,
    flags: u32,
    vma_type: VmaType,
    cache_policy: CachePolicy,
) -> Option<MappingResult> {
    let page_size = if flags & flags::HUGETLB != 0 {
        PageSize::Huge
    } else {
        PageSize::Default
    };
    
    // VMAを作成
    let vma = VirtualMemoryArea {
        range: vaddr..(vaddr + size),
        physical_mapping: None,  // マッピングはオンデマンドで行う
        vma_type,
        permissions: prot,
        cache_policy,
        file_descriptor: None,
        file_offset: 0,
        name: Some("anon_map"),
    };
    
    if !vma_api::add_vma(page_table, vma) {
        warn!("anon_mmap: VMAの追加に失敗しました: vaddr={:#x}, size={}", vaddr, size);
        return None;
    }
    
    // POPULATE フラグが設定されている場合は、すぐにページを割り当てる
    let mut mapped_pages = 0;
    if flags & flags::POPULATE != 0 {
        let num_pages = size / (page_size as usize);
        for i in 0..num_pages {
            let curr_vaddr = vaddr + i * (page_size as usize);
            if let Some(phys_addr) = page_api::alloc_pages(1) {
                if paging::map_pages(
                    page_table.get_root(),
                    curr_vaddr,
                    phys_addr,
                    1,
                    page_size,
                    prot,
                ) {
                    mapped_pages += 1;
                } else {
                    page_api::free_pages(phys_addr, 1);
                    warn!("anon_mmap: ページのマッピングに失敗しました: vaddr={:#x}", curr_vaddr);
                }
            }
        }
    }
    
    Some(MappingResult {
        vaddr,
        size,
        mapped_pages,
    })
}

/// ファイルベースのメモリマッピング
fn file_mmap(
    page_table: &mut PageTable,
    vaddr: VirtualAddress,
    size: usize,
    prot: u32,
    flags: u32,
    fd: FileDescriptor,
    offset: usize,
    vma_type: VmaType,
    cache_policy: CachePolicy,
) -> Option<MappingResult> {
    // ファイルサイズを確認
    let file_size = fd.get_size();
    if offset >= file_size {
        warn!("file_mmap: オフセットがファイルサイズを超えています: offset={}, file_size={}", offset, file_size);
        return None;
    }
    
    // マッピングサイズをファイルサイズ範囲内に制限
    let effective_size = core::cmp::min(size, file_size - offset);
    if effective_size == 0 {
        warn!("file_mmap: 有効なマッピングサイズが0です");
        return None;
    }
    
    // VMAを作成
    let vma = VirtualMemoryArea {
        range: vaddr..(vaddr + size),
        physical_mapping: None,  // ファイルマッピングの場合はオンデマンドでページを割り当て
        vma_type,
        permissions: prot,
        cache_policy,
        file_descriptor: Some(fd.clone()),
        file_offset: offset,
        name: Some("file_map"),
    };
    
    if !vma_api::add_vma(page_table, vma) {
        warn!("file_mmap: VMAの追加に失敗しました: vaddr={:#x}, size={}", vaddr, size);
        return None;
    }
    
    // マッピング結果を返す
    Some(MappingResult {
        vaddr,
        size: effective_size,
        mapped_pages: 0,  // 実際のマッピングはページフォルト時に行われる
    })
}

/// メモリマッピングの解除
///
/// # 引数
/// * `page_table` - ページテーブル
/// * `vaddr` - 解除する仮想アドレス
/// * `size` - 解除するサイズ（バイト）
///
/// # 戻り値
/// * 成功した場合は解除されたバイト数、失敗した場合はNone
pub fn unmap(page_table: &mut PageTable, vaddr: VirtualAddress, size: usize) -> Option<usize> {
    if size == 0 {
        return Some(0);
    }
    
    // アドレスとサイズをページサイズにアラインメント
    let page_size = PageSize::Default as usize;
    let aligned_vaddr = vaddr & !(page_size - 1);
    let aligned_size = (size + (vaddr - aligned_vaddr) + page_size - 1) & !(page_size - 1);
    
    // 対象範囲のVMAを取得
    let vmas = vma_api::find_vmas_in_range(page_table, aligned_vaddr, aligned_size);
    if vmas.is_empty() {
        warn!("unmap: 指定範囲にVMAが見つかりません: vaddr={:#x}, size={}", aligned_vaddr, aligned_size);
        return None;
    }
    
    // 各VMAに対してマッピング解除を行う
    for vma in vmas {
        let vma_start = vma.range.start;
        let vma_end = vma.range.end;
        let vma_size = vma_end - vma_start;
        
        // VMAが完全に含まれる場合は削除
        if vma_start >= aligned_vaddr && vma_end <= aligned_vaddr + aligned_size {
            if !vma_api::remove_vma(page_table, vma_start) {
                warn!("unmap: VMAの削除に失敗しました: vaddr={:#x}", vma_start);
                continue;
            }
            
            // 物理ページの解放とマッピング解除
            paging::unmap_pages(
                page_table.get_root(),
                vma_start,
                vma_size / page_size,
                PageSize::Default
            );
        }
        // VMAが部分的に含まれる場合は分割
        else {
            // 分割や縮小の処理（複雑なケース）
            // ここでは省略して、基本的な完全削除のみ対応
            warn!("unmap: 部分的なVMA解除は現在サポートされていません");
        }
    }
    
    Some(aligned_size)
}

/// プロセスのメモリマッピングを管理
pub fn handle_page_fault(
    process: &mut Process,
    fault_addr: VirtualAddress,
    is_write: bool,
) -> bool {
    let page_table = &mut process.page_table;
    
    // VMAを検索
    if let Some(vma) = vma_api::find_vma_containing(page_table, fault_addr) {
        // 書き込みアクセスに対する権限チェック
        if is_write && vma.permissions & prot::WRITE == 0 {
            error!("handle_page_fault: 書き込み保護違反: addr={:#x}, pid={}", fault_addr, process.id);
            return false;
        }
        
        // ファイルマッピングかアノニマスマッピングかで処理を分ける
        if vma.file_descriptor.is_some() {
            return handle_file_fault(page_table, &vma, fault_addr);
        } else {
            return handle_anon_fault(page_table, &vma, fault_addr);
        }
    }
    
    warn!("handle_page_fault: VMAが見つかりません: addr={:#x}, pid={}", fault_addr, process.id);
    false
}

/// アノニマスマッピングのページフォルト処理
fn handle_anon_fault(
    page_table: &mut PageTable,
    vma: &VirtualMemoryArea,
    fault_addr: VirtualAddress,
) -> bool {
    let page_size = PageSize::Default;
    let page_size_bytes = page_size as usize;
    let aligned_addr = fault_addr & !(page_size_bytes - 1);
    
    // 物理ページを割り当て
    if let Some(phys_addr) = page_api::alloc_pages(1) {
        // ページをゼロクリア
        unsafe {
            let ptr = phys_addr as *mut u8;
            for i in 0..page_size_bytes {
                ptr.add(i).write_volatile(0);
            }
        }
        
        // マッピングを作成
        if paging::map_pages(
            page_table.get_root(),
            aligned_addr,
            phys_addr,
            1,
            page_size,
            vma.permissions,
        ) {
            debug!("handle_anon_fault: ページを割り当てました: vaddr={:#x}, paddr={:#x}", aligned_addr, phys_addr);
            return true;
        } else {
            // マッピングに失敗した場合は物理ページを解放
            page_api::free_pages(phys_addr, 1);
            error!("handle_anon_fault: ページマッピングに失敗しました: vaddr={:#x}", aligned_addr);
        }
    } else {
        error!("handle_anon_fault: 物理ページの割り当てに失敗しました");
    }
    
    false
}

/// ファイルマッピングのページフォルト処理
fn handle_file_fault(
    page_table: &mut PageTable,
    vma: &VirtualMemoryArea,
    fault_addr: VirtualAddress,
) -> bool {
    let page_size = PageSize::Default as usize;
    // フォルトアドレスをページ境界にアライン
    let page_addr = fault_addr & !(page_size - 1);

    // VMA 内のページオフセットを計算
    let page_offset_in_vma = page_addr.as_usize().saturating_sub(vma.range.start.as_usize());

    // ファイル内の読み込み開始オフセットを計算
    let file_read_offset = vma.file_offset + page_offset_in_vma;

    // ファイルディスクリプタを取得
    let fd = match vma.file_descriptor {
        Some(ref fd_ref) => fd_ref,
        None => {
            error!("handle_file_fault: VMA にファイルディスクリプタがありません: {:#x}", fault_addr);
            return false;
        }
    };

    // 物理ページを割り当て
    let phys_addr = match page_api::alloc_pages(1) {
        Some(p) => p,
        None => {
            error!("handle_file_fault: 物理ページの割り当てに失敗しました: {:#x}", fault_addr);
            return false;
        }
    };

    // 物理ページを一時的にマップしてファイルデータを読み込むバッファを取得
    // (カーネル空間にマップするなど、安全な方法で物理ページにアクセスする)
    // ここでは、物理アドレスを直接ポインタにキャストする代わりに、
    // 一時的なカーネルマッピングを作成するAPIの呼び出しを想定 (例: mm::map_physical_page_to_kernel_temp)
    // もしそのようなAPIがなければ、物理ページを指す可変スライスを安全に取得する方法が必要。
    // 以下は簡略化のため、物理アドレスを直接使っているように見えますが、実際にはより安全な方法が必要です。
    let temp_kernel_mapping = match paging::map_temporary_page(phys_addr, page_size) {
        Ok(ptr) => ptr as *mut u8,
        Err(_) => {
            error!("handle_file_fault: 物理ページの一時マッピングに失敗: {:#x}", phys_addr);
            page_api::free_pages(phys_addr, 1);
            return false;
        }
    };
    
    let buffer = unsafe { core::slice::from_raw_parts_mut(temp_kernel_mapping, page_size) };

    // ファイルシステムからデータをロード
    match fd.read_at(buffer, file_read_offset) {
        Ok(bytes_read) => {
            if bytes_read < page_size {
                // ファイルの終端に達した場合、残りのバッファをゼロクリア
                for i in bytes_read..page_size {
                    buffer[i] = 0;
                }
            }
            // 読み込み成功
        }
        Err(e) => {
            error!("handle_file_fault: ファイルデータの読み込みに失敗しました: {:?}, offset={}", e, file_read_offset);
            paging::unmap_temporary_page(temp_kernel_mapping as usize, page_size); // 一時マッピングを解除
            page_api::free_pages(phys_addr, 1);
            return false;
        }
    }
    
    // 一時マッピングを解除
    paging::unmap_temporary_page(temp_kernel_mapping as usize, page_size);

    // ページテーブルに新しいマッピングを作成
    if !paging::map_pages(
        page_table.get_root(),
        page_addr, // フォルトしたページのアドレス
        phys_addr, // 割り当てた物理ページ
        1,         // ページ数
        PageSize::Default,
        vma.permissions, // VMAの権限を使用
    ) {
        error!("handle_file_fault: ページのマッピングに失敗しました: vaddr={:#x}, paddr={:#x}", page_addr, phys_addr);
        page_api::free_pages(phys_addr, 1);
        return false;
    }

    debug!(
        "File fault handled: mapped {:#x} -> {:#x} (file offset {})",
        page_addr.as_usize(),
        phys_addr.as_usize(),
        file_read_offset
    );
    true
}

/// VMAタイプを決定
fn determine_vma_type(prot: u32, flags: u32) -> VmaType {
    if flags & flags::DEVICE_MEMORY != 0 {
        VmaType::DeviceMemory
    } else if flags & flags::SHARED_MEMORY != 0 {
        VmaType::Shared
    } else if flags & flags::STACK != 0 {
        VmaType::Stack
    } else if prot & prot::EXEC != 0 {
        VmaType::Executable
    } else if prot & prot::WRITE == 0 {
        VmaType::ReadOnly
    } else if flags & flags::PRIVATE == 0 && flags & flags::SHARED != 0 {
        VmaType::Shared
    } else if flags & flags::ANONYMOUS == 0 {
        VmaType::FileMapped
    } else {
        VmaType::Regular
    }
}

/// キャッシュポリシーを決定
fn determine_cache_policy(flags: u32) -> CachePolicy {
    if flags & flags::DEVICE_MEMORY != 0 {
        CachePolicy::DeviceMemory
    } else if flags & flags::CACHE_UC != 0 {
        CachePolicy::Uncacheable
    } else if flags & flags::CACHE_WT != 0 {
        CachePolicy::WriteThrough
    } else if flags & flags::CACHE_WB != 0 {
        CachePolicy::WriteBack
    } else {
        // デフォルトはWriteBack
        CachePolicy::WriteBack
    }
}

/// プロセスの終了時に全てのマッピングを解放
pub fn cleanup_process_mappings(process: &mut Process) {
    debug!("cleanup_process_mappings: pid={} のマッピングをクリーンアップします", process.id);
    
    // VMAのリストを取得
    let vmas = vma_api::get_all_vmas(&process.page_table);
    
    // 各VMAを解放
    for vma in vmas {
        let vma_start = vma.range.start;
        let vma_size = vma.range.end - vma.range.start;
        
        // マッピングを解除
        unmap(&mut process.page_table, vma_start, vma_size);
    }
}

/// メモリマッピングのフラグ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmapFlags {
    /// 共有マッピング
    pub shared: bool,
    /// プライベートマッピング（Copy-on-Write）
    pub private: bool,
    /// 固定マッピング（ページングアウト不可）
    pub fixed: bool,
    /// ヒント（要求されたアドレスが利用できない場合、カーネルが別のアドレスを選択可能）
    pub hint: bool,
    /// 匿名マッピング
    pub anonymous: bool,
}

impl MmapFlags {
    /// デフォルトのマッピングフラグ（プライベート・匿名）
    pub const fn default() -> Self {
        Self {
            shared: false,
            private: true,
            fixed: false,
            hint: false,
            anonymous: true,
        }
    }

    /// 共有マッピングフラグを作成
    pub const fn shared() -> Self {
        Self {
            shared: true,
            private: false,
            fixed: false,
            hint: false,
            anonymous: false,
        }
    }

    /// プライベートマッピングフラグを作成
    pub const fn private() -> Self {
        Self {
            shared: false,
            private: true,
            fixed: false,
            hint: false,
            anonymous: false,
        }
    }

    /// 固定マッピングフラグを作成
    pub const fn fixed() -> Self {
        Self {
            shared: false,
            private: true,
            fixed: true,
            hint: false,
            anonymous: true,
        }
    }
}

/// メモリマッピングエラー
#[derive(Debug)]
pub enum MmapError {
    /// アドレス範囲が無効
    InvalidRange,
    /// メモリ不足
    OutOfMemory,
    /// アライメントエラー
    AlignmentError,
    /// 権限エラー
    PermissionDenied,
    /// 仮想アドレス空間の競合
    AddressConflict,
    /// VMA関連エラー
    VmaError(VmaError),
    /// ページテーブル操作エラー
    PageTableError,
    /// その他のエラー
    Other(&'static str),
}

impl From<VmaError> for MmapError {
    fn from(err: VmaError) -> Self {
        MmapError::VmaError(err)
    }
}

/// 物理メモリのアロケーションと仮想メモリへのマッピングを行う
pub fn map_pages(
    page_table: &mut PageTable,
    virt_start: VirtAddr,
    size: usize,
    flags: PageTableFlags,
    alloc_flags: AllocFlags,
) -> Result<(), MmapError> {
    // サイズが0の場合は何もしない
    if size == 0 {
        return Ok(());
    }

    // アライメントチェック
    if virt_start.as_usize() % PAGE_SIZE != 0 {
        return Err(MmapError::AlignmentError);
    }

    let num_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE; // 切り上げ
    let page_allocator = PageAllocator::get_instance();

    for i in 0..num_pages {
        let virt_addr = VirtAddr::new(virt_start.as_usize() + i * PAGE_SIZE);
        
        // 物理ページを割り当て
        let phys_page = page_allocator.alloc_pages(1, alloc_flags)
            .ok_or(MmapError::OutOfMemory)?;
            
        // 割り当てたページをゼロクリア
        unsafe {
            core::ptr::write_bytes(phys_page.as_usize() as *mut u8, 0, PAGE_SIZE);
        }
        
        // 物理ページを仮想アドレスにマッピング
        page_table.map(virt_addr, phys_page, flags)
            .map_err(|_| MmapError::PageTableError)?;
    }

    Ok(())
}

/// 既存の物理メモリを仮想メモリにマッピングする
pub fn map_phys_region(
    page_table: &mut PageTable,
    virt_start: VirtAddr,
    phys_start: PhysAddr,
    size: usize,
    flags: PageTableFlags,
) -> Result<(), MmapError> {
    // サイズが0の場合は何もしない
    if size == 0 {
        return Ok(());
    }

    // アライメントチェック
    if virt_start.as_usize() % PAGE_SIZE != 0 || phys_start.as_usize() % PAGE_SIZE != 0 {
        return Err(MmapError::AlignmentError);
    }

    let num_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE; // 切り上げ

    for i in 0..num_pages {
        let virt_addr = VirtAddr::new(virt_start.as_usize() + i * PAGE_SIZE);
        let phys_addr = PhysAddr::new(phys_start.as_usize() + i * PAGE_SIZE);
        
        // 物理アドレスを仮想アドレスにマッピング
        page_table.map(virt_addr, phys_addr, flags)
            .map_err(|_| MmapError::PageTableError)?;
    }

    Ok(())
}

/// 指定した仮想アドレス範囲のマッピングを解除する
pub fn unmap_region(
    page_table: &mut PageTable,
    virt_start: VirtAddr,
    size: usize,
) -> Result<(), MmapError> {
    // サイズが0の場合は何もしない
    if size == 0 {
        return Ok(());
    }

    // アライメントチェック
    if virt_start.as_usize() % PAGE_SIZE != 0 {
        return Err(MmapError::AlignmentError);
    }

    let num_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE; // 切り上げ

    for i in 0..num_pages {
        let virt_addr = VirtAddr::new(virt_start.as_usize() + i * PAGE_SIZE);
        
        // ページをアンマップする前に物理ページを取得
        if let Some(phys_addr) = page_table.translate(virt_addr) {
            // マッピングを解除
            page_table.unmap(virt_addr)
                .map_err(|_| MmapError::PageTableError)?;
                
            // 物理ページを解放
            let page_allocator = PageAllocator::get_instance();
            page_allocator.free_pages(phys_addr, 1);
        }
    }

    Ok(())
}

/// メモリマッピングを作成する（高レベルAPI）
pub fn mmap(
    page_table: &mut PageTable,
    vma_manager: &mut VmaManager,
    addr_hint: Option<VirtAddr>,
    size: usize,
    perm: VmaPerm,
    flags: MmapFlags,
    name: Option<String>,
) -> Result<VirtAddr, MmapError> {
    // サイズチェック
    if size == 0 {
        return Err(MmapError::InvalidRange);
    }

    // サイズをページサイズにアライン
    let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    
    // アドレスの決定
    let start_addr = if let Some(addr) = addr_hint {
        // アドレスがページアライメントされているか確認
        if addr.as_usize() % PAGE_SIZE != 0 {
            return Err(MmapError::AlignmentError);
        }
        
        // fixed フラグが設定されている場合、指定されたアドレスを使用する必要がある
        if flags.fixed {
            // アドレス範囲が既に使用されているか確認
            let range = Range {
                start: addr,
                end: VirtAddr::new(addr.as_usize() + aligned_size),
            };
            
            let overlapping = vma_manager.find_overlapping_vmas(&range);
            if !overlapping.is_empty() {
                return Err(MmapError::AddressConflict);
            }
            
            addr
        } else {
            // ヒントモードの場合、指定されたアドレスが使用可能であれば使用
            // そうでなければ、別のアドレスを探す
            find_free_region(vma_manager, aligned_size, Some(addr))
                .ok_or(MmapError::OutOfMemory)?
        }
    } else {
        // アドレスヒントがない場合は自動的に空き領域を探す
        find_free_region(vma_manager, aligned_size, None)
            .ok_or(MmapError::OutOfMemory)?
    };
    
    let end_addr = VirtAddr::new(start_addr.as_usize() + aligned_size);
    
    // VMA タイプを決定
    let vma_type = if flags.anonymous {
        VmaType::Anonymous
    } else {
        VmaType::FileBacked
    };
    
    // VMA を作成
    let mut vma = Vma::new(start_addr, end_addr, None, perm, vma_type, name);
    vma.is_cow = flags.private;
    vma.is_shared = flags.shared;
    
    // VMA をマネージャに追加
    let vma_arc = vma_manager.add_vma(vma)?;
    
    // 物理メモリの割り当てとマッピング
    let page_table_flags = perm.to_page_table_flags();
    let alloc_flags = if flags.fixed {
        AllocFlags::FIXED
    } else {
        AllocFlags::NONE
    };
    
    map_pages(page_table, start_addr, aligned_size, page_table_flags, alloc_flags)?;
    
    Ok(start_addr)
}

/// メモリマッピングを解除する（高レベルAPI）
pub fn munmap(
    page_table: &mut PageTable,
    vma_manager: &mut VmaManager,
    addr: VirtAddr,
    size: usize,
) -> Result<(), MmapError> {
    // サイズチェック
    if size == 0 {
        return Err(MmapError::InvalidRange);
    }

    // アドレスがページアライメントされているか確認
    if addr.as_usize() % PAGE_SIZE != 0 {
        return Err(MmapError::AlignmentError);
    }

    // サイズをページサイズにアライン
    let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let end_addr = VirtAddr::new(addr.as_usize() + aligned_size);
    
    // アンマップするアドレス範囲
    let unmap_range = Range {
        start: addr,
        end: end_addr,
    };
    
    // 範囲内のすべてのVMAを取得
    let vmas = vma_manager.find_overlapping_vmas(&unmap_range);
    
    if vmas.is_empty() {
        // マッピングが存在しない場合は何もしない
        return Ok(());
    }
    
    // 各VMAを処理
    for vma in vmas {
        let vma_range = vma.range.clone();
        
        // VMAとアンマップ範囲の重なりを計算
        let overlap_start = vma_range.start.max(unmap_range.start);
        let overlap_end = vma_range.end.min(unmap_range.end);
        let overlap_size = overlap_end.as_usize() - overlap_start.as_usize();
        
        // 重なっている部分をアンマップ
        unmap_region(page_table, overlap_start, overlap_size)?;
        
        // VMAを削除または分割
        if vma_range.start == unmap_range.start && vma_range.end == unmap_range.end {
            // 完全に一致する場合はVMAを削除
            vma_manager.remove_vma(&vma_range)?;
        } else if vma_range.start == unmap_range.start {
            // 前半部分がアンマップされる場合
            let new_start = overlap_end;
            let new_vma = Vma {
                range: Range { start: new_start, end: vma_range.end },
                ..(*vma).clone()
            };
            vma_manager.remove_vma(&vma_range)?;
            vma_manager.add_vma(new_vma)?;
        } else if vma_range.end == unmap_range.end {
            // 後半部分がアンマップされる場合
            let new_end = overlap_start;
            let new_vma = Vma {
                range: Range { start: vma_range.start, end: new_end },
                ..(*vma).clone()
            };
            vma_manager.remove_vma(&vma_range)?;
            vma_manager.add_vma(new_vma)?;
        } else {
            // 中間部分がアンマップされる場合、VMAを2つに分割
            let first_vma = Vma {
                range: Range { start: vma_range.start, end: overlap_start },
                ..(*vma).clone()
            };
            let second_vma = Vma {
                range: Range { start: overlap_end, end: vma_range.end },
                ..(*vma).clone()
            };
            vma_manager.remove_vma(&vma_range)?;
            vma_manager.add_vma(first_vma)?;
            vma_manager.add_vma(second_vma)?;
        }
    }
    
    Ok(())
}

/// メモリマッピングの権限を変更する（高レベルAPI）
pub fn mprotect(
    page_table: &mut PageTable,
    vma_manager: &mut VmaManager,
    addr: VirtAddr,
    size: usize,
    new_perm: VmaPerm,
) -> Result<(), MmapError> {
    // サイズチェック
    if size == 0 {
        return Err(MmapError::InvalidRange);
    }

    // アドレスがページアライメントされているか確認
    if addr.as_usize() % PAGE_SIZE != 0 {
        return Err(MmapError::AlignmentError);
    }

    // サイズをページサイズにアライン
    let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let end_addr = VirtAddr::new(addr.as_usize() + aligned_size);
    
    // 対象のアドレス範囲
    let target_range = Range {
        start: addr,
        end: end_addr,
    };
    
    // 範囲内のすべてのVMAを取得
    let vmas = vma_manager.find_overlapping_vmas(&target_range);
    
    if vmas.is_empty() {
        // マッピングが存在しない場合はエラー
        return Err(MmapError::InvalidRange);
    }
    
    // 各VMAを処理
    for vma in vmas {
        let vma_range = vma.range.clone();
        
        // VMAと対象範囲の重なりを計算
        let overlap_start = vma_range.start.max(target_range.start);
        let overlap_end = vma_range.end.min(target_range.end);
        
        if overlap_start >= overlap_end {
            continue;
        }
        
        let overlap_range = Range {
            start: overlap_start,
            end: overlap_end,
        };
        
        // 重なっている部分の権限を変更
        let page_table_flags = new_perm.to_page_table_flags();
        let num_pages = (overlap_end.as_usize() - overlap_start.as_usize()) / PAGE_SIZE;
        
        for i in 0..num_pages {
            let page_addr = VirtAddr::new(overlap_start.as_usize() + i * PAGE_SIZE);
            
            // ページの権限を変更
            if let Some(phys_addr) = page_table.translate(page_addr) {
                page_table.unmap(page_addr)
                    .map_err(|_| MmapError::PageTableError)?;
                    
                page_table.map(page_addr, phys_addr, page_table_flags)
                    .map_err(|_| MmapError::PageTableError)?;
            }
        }
        
        // VMAを分割または更新
        if vma_range == overlap_range {
            // 完全に一致する場合はVMAの権限を更新
            vma_manager.change_vma_perm(&vma_range, new_perm)?;
        } else {
            // 部分的に重なる場合、VMAを分割して権限を更新
            if vma_range.start < overlap_range.start {
                // 前半部分
                let first_vma = Vma {
                    range: Range { start: vma_range.start, end: overlap_range.start },
                    ..(*vma).clone()
                };
                vma_manager.add_vma(first_vma)?;
            }
            
            // 重なる部分
            let middle_vma = Vma {
                range: overlap_range.clone(),
                perm: new_perm,
                ..(*vma).clone()
            };
            vma_manager.add_vma(middle_vma)?;
            
            if overlap_range.end < vma_range.end {
                // 後半部分
                let last_vma = Vma {
                    range: Range { start: overlap_range.end, end: vma_range.end },
                    ..(*vma).clone()
                };
                vma_manager.add_vma(last_vma)?;
            }
            
            // 元のVMAを削除
            vma_manager.remove_vma(&vma_range)?;
        }
    }
    
    Ok(())
}

/// メモリを物理メモリにロックする（ページングアウト防止）
pub fn mlock(
    page_table: &mut PageTable,
    addr: VirtAddr,
    size: usize,
) -> Result<(), MmapError> {
    // サイズチェック
    if size == 0 {
        return Err(MmapError::InvalidRange);
    }

    // アドレスがページアライメントされているか確認
    if addr.as_usize() % PAGE_SIZE != 0 {
        return Err(MmapError::AlignmentError);
    }

    // サイズをページサイズにアライン
    let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let num_pages = aligned_size / PAGE_SIZE;
    
    // 各ページをロック
    for i in 0..num_pages {
        let page_addr = VirtAddr::new(addr.as_usize() + i * PAGE_SIZE);
        
        if let Some(phys_addr) = page_table.translate(page_addr) {
            // 将来的にはここでページをロックする処理を実装
            // 今のところは単にページが存在することを確認するだけ
        } else {
            return Err(MmapError::InvalidRange);
        }
    }
    
    Ok(())
}

/// 共有メモリ領域を作成する
pub fn shmem_create(
    page_table: &mut PageTable,
    vma_manager: &mut VmaManager,
    size: usize,
    perm: VmaPerm,
    name: Option<String>,
) -> Result<VirtAddr, MmapError> {
    // 共有メモリ用のマッピングフラグを作成
    let flags = MmapFlags {
        shared: true,
        private: false,
        fixed: false,
        hint: false,
        anonymous: true,
    };
    
    // 共有メモリ領域を作成
    mmap(page_table, vma_manager, None, size, perm, flags, name)
}

/// 空き仮想アドレス領域を探す補助関数
fn find_free_region(
    vma_manager: &VmaManager,
    size: usize,
    hint: Option<VirtAddr>,
) -> Option<VirtAddr> {
    // サイズをページサイズにアライン
    let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    
    // すべてのVMAを取得
    let vmas = vma_manager.get_all_vmas();
    
    if vmas.is_empty() {
        // VMAがない場合はデフォルトのアドレスから開始
        return Some(VirtAddr::new(0x1000_0000)); // 例: 256MB
    }
    
    // ヒントがある場合、まずそのアドレスを試す
    if let Some(hint_addr) = hint {
        let end_addr = VirtAddr::new(hint_addr.as_usize() + aligned_size);
        let hint_range = Range {
            start: hint_addr,
            end: end_addr,
        };
        
        // ヒントアドレスが使用可能かチェック
        let overlapping = vma_manager.find_overlapping_vmas(&hint_range);
        if overlapping.is_empty() {
            return Some(hint_addr);
        }
    }
    
    // ギャップを探索
    let mut last_end = VirtAddr::new(0x1000_0000); // デフォルトの開始アドレス
    
    // VMAをソート
    let mut sorted_vmas = vmas.clone();
    sorted_vmas.sort_by_key(|vma| vma.range.start);
    
    for vma in sorted_vmas {
        if vma.range.start.as_usize() >= last_end.as_usize() + aligned_size {
            // 十分な大きさのギャップが見つかった
            return Some(last_end);
        }
        
        last_end = VirtAddr::new(vma.range.end.as_usize());
    }
    
    // 最後のVMAの後にも空き領域を確認
    Some(last_end)
}

/// マッピング権限フラグ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub user: bool,
    pub cacheable: bool,
}

impl MapPermissions {
    /// 読み取り専用パーミッション
    pub const fn readonly() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
            user: false,
            cacheable: true,
        }
    }

    /// 読み書き可能パーミッション
    pub const fn readwrite() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
            user: false,
            cacheable: true,
        }
    }

    /// ユーザーモード読み取り専用パーミッション
    pub const fn user_readonly() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
            user: true,
            cacheable: true,
        }
    }

    /// ユーザーモード読み書き可能パーミッション
    pub const fn user_readwrite() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
            user: true,
            cacheable: true,
        }
    }

    /// 実行可能パーミッション
    pub const fn executable() -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
            user: false,
            cacheable: true,
        }
    }

    /// ユーザーモード実行可能パーミッション
    pub const fn user_executable() -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
            user: true,
            cacheable: true,
        }
    }

    /// デバイスマッピング用パーミッション（キャッシュ無効）
    pub const fn device() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
            user: false,
            cacheable: false,
        }
    }
}

/// マッピングタイプ
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapType {
    /// 通常のRAMマッピング
    Ram {
        phys_addr: PhysAddr,
    },
    /// ファイルマッピング
    File {
        file_id: usize,
        offset: usize,
        file_perms: FilePermissions,
    },
    /// 匿名マッピング（ヒープ、スタックなど）
    Anonymous {
        zero_on_demand: bool,
    },
    /// デバイスマッピング（MMIOなど）
    Device {
        phys_addr: PhysAddr,
    },
    /// 共有メモリマッピング
    Shared {
        shared_id: usize,
        offset: usize,
    },
    /// テレページマッピング（リモートメモリ）
    TelePage {
        node_id: usize,
        remote_phys_addr: PhysAddr,
    },
}

/// ファイルマッピングパーミッション
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilePermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// 仮想メモリ領域（VMA）
#[derive(Debug)]
pub struct VirtualMemoryArea {
    /// 開始アドレス
    pub start: VirtAddr,
    /// 終了アドレス
    pub end: VirtAddr,
    /// マッピングパーミッション
    pub permissions: MapPermissions,
    /// マッピングタイプ
    pub map_type: MapType,
    /// このVMAがマップされているかどうか
    pub mapped: AtomicBool,
    /// アクセスカウンター（ページングポリシー用）
    pub access_count: AtomicUsize,
}

impl VirtualMemoryArea {
    /// 新しい仮想メモリ領域を作成
    pub fn new(
        start: VirtAddr,
        end: VirtAddr,
        permissions: MapPermissions,
        map_type: MapType,
    ) -> Self {
        Self {
            start,
            end,
            permissions,
            map_type,
            mapped: AtomicBool::new(false),
            access_count: AtomicUsize::new(0),
        }
    }

    /// VMAのサイズを取得
    pub fn size(&self) -> usize {
        self.end.as_usize() - self.start.as_usize()
    }

    /// このVMAに指定アドレスが含まれているか確認
    pub fn contains(&self, addr: VirtAddr) -> bool {
        addr >= self.start && addr < self.end
    }

    /// このVMAに指定範囲が完全に含まれているか確認
    pub fn contains_range(&self, range: Range<VirtAddr>) -> bool {
        range.start >= self.start && range.end <= self.end
    }

    /// VMAがマップされていることをマーク
    pub fn mark_mapped(&self) {
        self.mapped.store(true, Ordering::SeqCst);
    }

    /// VMAがアンマップされていることをマーク
    pub fn mark_unmapped(&self) {
        self.mapped.store(false, Ordering::SeqCst);
    }

    /// VMAがマップされているか確認
    pub fn is_mapped(&self) -> bool {
        self.mapped.load(Ordering::SeqCst)
    }

    /// アクセスカウンターをインクリメント
    pub fn increment_access(&self) {
        self.access_count.fetch_add(1, Ordering::Relaxed);
    }

    /// アクセスカウンターを取得
    pub fn get_access_count(&self) -> usize {
        self.access_count.load(Ordering::Relaxed)
    }
}

/// アドレス空間マネージャ
#[derive(Debug)]
pub struct AddressSpace {
    /// VMAのリスト（アドレス順）
    vmas: RwLock<BTreeMap<VirtAddr, VirtualMemoryArea>>,
    /// このアドレス空間に関連付けられたページテーブル
    page_table: Arc<Mutex<PageTable>>,
    /// プロセスへの弱参照（循環参照を防ぐ）
    process: Option<Arc<Process>>,
    /// アドレス空間ID
    id: usize,
    /// マップされた領域のカウント
    mapped_regions_count: AtomicUsize,
    /// マップされたページの総数
    mapped_pages_count: AtomicUsize,
}

impl AddressSpace {
    /// 新しいアドレス空間を作成
    pub fn new(page_table: Arc<Mutex<PageTable>>, id: usize) -> Self {
        Self {
            vmas: RwLock::new(BTreeMap::new()),
            page_table,
            process: None,
            id,
            mapped_regions_count: AtomicUsize::new(0),
            mapped_pages_count: AtomicUsize::new(0),
        }
    }

    /// プロセスを設定
    pub fn set_process(&mut self, process: Arc<Process>) {
        self.process = Some(process);
    }

    /// 新しいVMAを作成し追加
    pub fn add_vma(
        &self,
        start: VirtAddr,
        size: usize,
        permissions: MapPermissions,
        map_type: MapType,
    ) -> Result<VirtAddr, MmapError> {
        // サイズをページサイズにアライン
        let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        
        // 終了アドレスを計算
        let end = VirtAddr::new(start.as_usize() + aligned_size);
        
        // 新しいVMAを作成
        let vma = VirtualMemoryArea::new(start, end, permissions, map_type);
        
        // VMAを追加
        let mut vmas = self.vmas.write();
        
        // 競合チェック - 既存のVMAと重複していないか確認
        for (_, existing_vma) in vmas.iter() {
            if !(end <= existing_vma.start || start >= existing_vma.end) {
                return Err(MmapError::AddressConflict);
            }
        }
        
        vmas.insert(start, vma);
        Ok(start)
    }

    /// 指定範囲のVMAを削除
    pub fn remove_vma(&self, start: VirtAddr, end: VirtAddr) -> Result<(), MmapError> {
        let mut vmas = self.vmas.write();
        
        // 完全一致するVMAを探す
        if let Some(vma) = vmas.get(&start) {
            if vma.end == end {
                // VMAが見つかったら削除
                vmas.remove(&start);
                return Ok(());
            }
        }
        
        // 範囲内に収まるVMAを探す
        let mut to_remove = Vec::new();
        let mut to_add = Vec::new();
        
        for (vma_start, vma) in vmas.iter() {
            if vma.start < end && vma.end > start {
                to_remove.push(*vma_start);
                
                // 開始部分が範囲外なら新しいVMAを作成
                if vma.start < start {
                    let new_vma = VirtualMemoryArea::new(
                        vma.start,
                        start,
                        vma.permissions,
                        vma.map_type.clone(),
                    );
                    to_add.push(new_vma);
                }
                
                // 終了部分が範囲外なら新しいVMAを作成
                if vma.end > end {
                    let new_vma = VirtualMemoryArea::new(
                        end,
                        vma.end,
                        vma.permissions,
                        vma.map_type.clone(),
                    );
                    to_add.push(new_vma);
                }
            }
        }
        
        // 該当するVMAが見つからなかった場合はエラー
        if to_remove.is_empty() {
            return Err(MmapError::RegionNotFound);
        }
        
        // 古いVMAを削除
        for addr in to_remove {
            vmas.remove(&addr);
        }
        
        // 新しいVMAを追加
        for vma in to_add {
            vmas.insert(vma.start, vma);
        }
        
        Ok(())
    }

    /// 指定アドレスを含むVMAを探す
    pub fn find_vma(&self, addr: VirtAddr) -> Option<VirtualMemoryArea> {
        let vmas = self.vmas.read();
        
        for (_, vma) in vmas.iter() {
            if vma.contains(addr) {
                return Some(vma.clone());
            }
        }
        
        None
    }

    /// 指定範囲を含むVMAのリストを取得
    pub fn find_vmas_in_range(&self, start: VirtAddr, end: VirtAddr) -> Vec<VirtualMemoryArea> {
        let vmas = self.vmas.read();
        let mut result = Vec::new();
        
        for (_, vma) in vmas.iter() {
            if vma.start < end && vma.end > start {
                result.push(vma.clone());
            }
        }
        
        result
    }

    /// メモリ領域をマップ
    pub fn map(&self, addr: VirtAddr, size: usize, permissions: MapPermissions, map_type: MapType) 
        -> Result<VirtAddr, MmapError> {
        // 新しいVMAを追加
        let start_addr = self.add_vma(addr, size, permissions, map_type.clone())?;
        let end_addr = VirtAddr::new(start_addr.as_usize() + size);
        
        // マッピングタイプに基づいて実際のマッピングを行う
        match &map_type {
            MapType::Ram { phys_addr } => {
                let mut current_vaddr = start_addr;
                let mut current_paddr = *phys_addr;
                
                while current_vaddr < end_addr {
                    let mut page_table = self.page_table.lock();
                    page_table.map(
                        current_vaddr,
                        current_paddr,
                        PageSize::Size4KiB,
                        convert_to_arch_permissions(permissions),
                    )?;
                    
                    current_vaddr = VirtAddr::new(current_vaddr.as_usize() + PAGE_SIZE);
                    current_paddr = PhysAddr::new(current_paddr.as_usize() + PAGE_SIZE);
                }
            },
            MapType::Anonymous { zero_on_demand } => {
                if !*zero_on_demand {
                    // 即時にゼロページを割り当て
                    let mut current_vaddr = start_addr;
                    
                    while current_vaddr < end_addr {
                        // 新しいページを割り当て
                        let page = Page::alloc(AllocFlags::ZERO)?;
                        
                        // ページテーブルにマップ
                        let mut page_table = self.page_table.lock();
                        page_table.map(
                            current_vaddr,
                            page.phys_addr(),
                            PageSize::Size4KiB,
                            convert_to_arch_permissions(permissions),
                        )?;
                        
                        current_vaddr = VirtAddr::new(current_vaddr.as_usize() + PAGE_SIZE);
                    }
                }
                // zero_on_demand = trueの場合は、ページフォルト時に割り当て
            },
            MapType::Device { phys_addr } => {
                // デバイスメモリのマッピング
                let mut current_vaddr = start_addr;
                let mut current_paddr = *phys_addr;
                
                while current_vaddr < end_addr {
                    let mut page_table = self.page_table.lock();
                    page_table.map(
                        current_vaddr,
                        current_paddr,
                        PageSize::Size4KiB,
                        convert_to_arch_permissions(permissions),
                    )?;
                    
                    current_vaddr = VirtAddr::new(current_vaddr.as_usize() + PAGE_SIZE);
                    current_paddr = PhysAddr::new(current_paddr.as_usize() + PAGE_SIZE);
                }
            },
            // ファイルマッピング、共有メモリ、テレページは遅延ロード
            _ => {
                // 遅延ロードのためにVMAをマークするだけ
                // 実際のマッピングはページフォルトハンドラで行う
            }
        }
        
        // VMAをマップ済みとしてマーク
        if let Some(vma) = self.find_vma(start_addr) {
            vma.mark_mapped();
        }
        
        // カウンタを更新
        self.mapped_regions_count.fetch_add(1, Ordering::SeqCst);
        let pages_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        self.mapped_pages_count.fetch_add(pages_count, Ordering::SeqCst);
        
        Ok(start_addr)
    }

    /// 指定範囲のメモリをアンマップ
    pub fn unmap(&self, addr: VirtAddr, size: usize) -> Result<(), MmapError> {
        let end_addr = VirtAddr::new(addr.as_usize() + size);
        
        // 範囲内のVMAを取得
        let vmas = self.find_vmas_in_range(addr, end_addr);
        
        if vmas.is_empty() {
            return Err(MmapError::RegionNotFound);
        }
        
        // 各VMAのページをアンマップ
        for vma in &vmas {
            // 対象範囲の開始と終了を計算
            let unmap_start = if addr > vma.start { addr } else { vma.start };
            let unmap_end = if end_addr < vma.end { end_addr } else { vma.end };
            
            // アライメント調整
            let aligned_start = VirtAddr::new(unmap_start.as_usize() & !(PAGE_SIZE - 1));
            let aligned_end = VirtAddr::new((unmap_end.as_usize() + PAGE_SIZE - 1) & !(PAGE_SIZE - 1));
            
            // ページテーブルからページをアンマップ
            let mut current_addr = aligned_start;
            while current_addr < aligned_end {
                let mut page_table = self.page_table.lock();
                if let Err(e) = page_table.unmap(current_addr) {
                    // エラーをログに記録するが処理は継続
                    log::warn!("Failed to unmap page at {:?}: {:?}", current_addr, e);
                }
                
                current_addr = VirtAddr::new(current_addr.as_usize() + PAGE_SIZE);
            }
            
            // VMAをアンマップ済みとしてマーク
            vma.mark_unmapped();
        }
        
        // VMAを削除
        self.remove_vma(addr, end_addr)?;
        
        // カウンタを更新
        self.mapped_regions_count.fetch_sub(1, Ordering::SeqCst);
        let pages_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        self.mapped_pages_count.fetch_sub(pages_count, Ordering::SeqCst);
        
        Ok(())
    }

    /// ページフォルトハンドラ
    pub fn handle_page_fault(&self, fault_addr: VirtAddr, write_access: bool, instruction_fetch: bool) 
        -> Result<(), MmapError> {
        // フォルトアドレスを含むVMAを検索
        let vma = match self.find_vma(fault_addr) {
            Some(vma) => vma,
            None => return Err(MmapError::InvalidAddress),
        };
        
        // アクセス権チェック
        if write_access && !vma.permissions.write {
            return Err(MmapError::PermissionDenied);
        }
        
        if instruction_fetch && !vma.permissions.execute {
            return Err(MmapError::PermissionDenied);
        }
        
        // アドレスをページ境界にアライン
        let page_addr = VirtAddr::new(fault_addr.as_usize() & !(PAGE_SIZE - 1));
        
        // VMAタイプに基づいてページをマップ
        match &vma.map_type {
            MapType::Ram { phys_addr } => {
                // 物理アドレスのオフセットを計算
                let offset = page_addr.as_usize() - vma.start.as_usize();
                let phys_page_addr = PhysAddr::new(phys_addr.as_usize() + offset);
                
                // ページテーブルにマップ
                let mut page_table = self.page_table.lock();
                page_table.map(
                    page_addr,
                    phys_page_addr,
                    PageSize::Size4KiB,
                    convert_to_arch_permissions(vma.permissions),
                )?;
            },
            MapType::Anonymous { zero_on_demand } => {
                // 新しいページを割り当て
                let page = if *zero_on_demand {
                    Page::alloc(AllocFlags::ZERO)?
                } else {
                    Page::alloc(AllocFlags::NONE)?
                };
                
                // ページテーブルにマップ
                let mut page_table = self.page_table.lock();
                page_table.map(
                    page_addr,
                    page.phys_addr(),
                    PageSize::Size4KiB,
                    convert_to_arch_permissions(vma.permissions),
                )?;
            },
            MapType::File { file_id, offset, file_perms } => {
                // ファイルからページをロード
                let page = Page::alloc(AllocFlags::NONE)?;
                
                // ファイルシステムからデータをロード（実際の実装はファイルシステムモジュールに依存）
                let page_offset_in_file = (page_addr.as_usize() - vma.start.as_usize()) + offset;
                let mut page_data = vec![0u8; PAGE_SIZE]; // ページサイズのバッファ
                
                // ファイルシステムマネージャーからファイルを読み込み
                let bytes_read = match self.read_file_data_with_caching(file_id, page_offset_in_file, &mut page_data) {
                    Ok(size) => size,
                    Err(e) => {
                        log::error!("ファイルページ読み込み失敗: {:?}", e);
                        return Err(MmapError::FileError);
                    }
                };
                
                // ページにデータをコピー
                unsafe {
                    let page_ptr = page.phys_addr().as_mut_ptr::<u8>();
                    core::ptr::copy_nonoverlapping(
                        page_data.as_ptr(), 
                        page_ptr, 
                        core::cmp::min(bytes_read, PAGE_SIZE)
                    );
                    
                    // 残りの部分をゼロ埋め
                    if bytes_read < PAGE_SIZE {
                        core::ptr::write_bytes(
                            page_ptr.add(bytes_read), 
                            0, 
                            PAGE_SIZE - bytes_read
                        );
                    }
                }
                
                log::trace!("ファイルページロード完了: VMA=0x{:x}, ページ=0x{:x}, 読み込み={}バイト", 
                           vma.start.as_usize(), page_addr.as_usize(), bytes_read);
                
                // ページをVMAにマッピング
                self.map_page_to_vma(page_addr, page.phys_addr(), vma.flags)?;
            },
            MapType::Shared { shared_id, offset } => {
                // 共有メモリからページをロード
                let page_offset = page_addr.as_usize() - vma.start.as_usize();
                let phys_addr = get_shared_memory_page(*shared_id, page_offset + offset)?;
                
                // ページテーブルにマップ
                let mut page_table = self.page_table.lock();
                page_table.map(
                    page_addr,
                    phys_addr,
                    PageSize::Size4KiB,
                    convert_to_arch_permissions(vma.permissions),
                )?;
            },
            MapType::TelePage { node_id, remote_phys_addr } => {
                // テレページをロード
                let page_offset = page_addr.as_usize() - vma.start.as_usize();
                let local_page = fetch_telepage(*node_id, PhysAddr::new(remote_phys_addr.as_usize() + page_offset))?;
                
                // ページテーブルにマップ
                let mut page_table = self.page_table.lock();
                page_table.map(
                    page_addr,
                    local_page.phys_addr(),
                    PageSize::Size4KiB,
                    convert_to_arch_permissions(vma.permissions),
                )?;
            },
            MapType::Device { phys_addr } => {
                // デバイスメモリのオフセットを計算
                let offset = page_addr.as_usize() - vma.start.as_usize();
                let phys_page_addr = PhysAddr::new(phys_addr.as_usize() + offset);
                
                // ページテーブルにマップ
                let mut page_table = self.page_table.lock();
                page_table.map(
                    page_addr,
                    phys_page_addr,
                    PageSize::Size4KiB,
                    convert_to_arch_permissions(vma.permissions),
                )?;
            },
        }
        
        // アクセスカウンターを更新
        vma.increment_access();
        
        Ok(())
    }

    /// 現在のVMA数を取得
    pub fn vma_count(&self) -> usize {
        self.vmas.read().len()
    }

    /// マップされた領域数を取得
    pub fn mapped_regions_count(&self) -> usize {
        self.mapped_regions_count.load(Ordering::SeqCst)
    }

    /// マップされたページ数を取得
    pub fn mapped_pages_count(&self) -> usize {
        self.mapped_pages_count.load(Ordering::SeqCst)
    }

    /// アドレス空間IDを取得
    pub fn id(&self) -> usize {
        self.id
    }
    
    /// ファイルからデータを読み込み
    fn read_file_data(&self, inode_id: usize, offset: usize, buffer: &mut [u8]) -> Result<usize, MmapError> {
        // ファイルシステムマネージャーからファイルシステムを取得
        let fs = crate::core::fs::manager::get_filesystem_by_inode_id(inode_id)
            .ok_or(MmapError::FileError)?;
        
        // ファイルからデータを読み込み
        match fs.read_file_data(inode_id, offset, buffer) {
            Ok(bytes_read) => {
                log::trace!("ファイル読み込み成功: inode={}, offset={}, bytes={}", 
                           inode_id, offset, bytes_read);
                Ok(bytes_read)
            },
            Err(fs_error) => {
                log::error!("ファイル読み込みエラー: inode={}, error={:?}", inode_id, fs_error);
                Err(MmapError::FileError)
            }
        }
    }

    /// ファイルからデータを読み込み（キャッシュあり）
    fn read_file_data_with_caching(&self, file_id: usize, offset: usize, buffer: &mut [u8]) -> Result<usize, MmapError> {
        // ファイルシステムマネージャーから適切なファイルシステムを取得
        let filesystem = self.get_filesystem_for_file(file_id)?;
        
        // ページアラインされたオフセットであることを確認
        if offset % PAGE_SIZE != 0 {
            log::warn!("ページアラインされていないオフセット: {}", offset);
            return Err(MmapError::InvalidArgument);
        }
        
        // キャッシュチェック
        if let Some(cached_page) = self.check_file_cache(file_id, offset) {
            let copy_size = core::cmp::min(buffer.len(), PAGE_SIZE);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    cached_page.as_ptr(),
                    buffer.as_mut_ptr(),
                    copy_size
                );
            }
            log::trace!("ファイルデータキャッシュヒット: file_id={}, offset=0x{:x}", file_id, offset);
            return Ok(copy_size);
        }
        
        // ファイルシステムから実際にデータを読み込み
        let mut file_buffer = vec![0u8; PAGE_SIZE];
        let bytes_read = match filesystem.read_file_at_offset(file_id, offset, &mut file_buffer) {
            Ok(size) => size,
            Err(e) => {
                log::error!("ファイル読み込み失敗: file_id={}, offset=0x{:x}, error={:?}", file_id, offset, e);
                return Err(MmapError::FileError);
            }
        };
        
        // 読み込んだデータをバッファにコピー
        let copy_size = core::cmp::min(buffer.len(), bytes_read);
        buffer[..copy_size].copy_from_slice(&file_buffer[..copy_size]);
        
        // キャッシュに保存
        self.cache_file_data(file_id, offset, &file_buffer[..bytes_read]);
        
        log::trace!("ファイルデータ読み込み完了: file_id={}, offset=0x{:x}, size={}", 
                   file_id, offset, bytes_read);
        
        Ok(copy_size)
    }
    
    fn get_filesystem_for_file(&self, file_id: usize) -> Result<Arc<dyn FileSystem>, MmapError> {
        // ファイルディスクリプタテーブルからファイルシステムを特定
        let fd_table = crate::core::fs::manager::get_file_descriptor_table()
            .ok_or(MmapError::FileError)?;
        
        let file_info = fd_table.get_file_info(file_id)
            .ok_or(MmapError::FileError)?;
        
        match file_info.filesystem_type {
            FilesystemType::Ext4 => {
                let ext4_fs = crate::core::fs::ext4::Ext4FileSystem::new(file_info.device_id)
                    .map_err(|_| MmapError::FileError)?;
                Ok(Arc::new(ext4_fs))
            },
            FilesystemType::Fat32 => {
                let fat32_fs = crate::core::fs::fat32::Fat32FileSystem::new(file_info.device_id)
                    .map_err(|_| MmapError::FileError)?;
                Ok(Arc::new(fat32_fs))
            },
            FilesystemType::Ntfs => {
                let ntfs_fs = crate::core::fs::ntfs::NtfsFileSystem::new(file_info.device_id)
                    .map_err(|_| MmapError::FileError)?;
                Ok(Arc::new(ntfs_fs))
            },
            FilesystemType::ExFat => {
                let exfat_fs = crate::core::fs::exfat::ExFatFileSystem::new(file_info.device_id)
                    .map_err(|_| MmapError::FileError)?;
                Ok(Arc::new(exfat_fs))
            },
        }
    }
    
    fn check_file_cache(&self, file_id: usize, offset: usize) -> Option<Vec<u8>> {
        // 効率的なLRUファイルページキャッシュ実装
        static GLOBAL_FILE_CACHE: Once<GlobalFileDataCache> = Once::new();
        
        let cache = GLOBAL_FILE_CACHE.call_once(|| {
            GlobalFileDataCache::new(1000) // 最大1000エントリ
        });
        
        cache.get(file_id, offset)
    }
    
    fn cache_file_data(&self, file_id: usize, offset: usize, data: &[u8]) {
        // グローバルファイルキャッシュにデータを保存
        static GLOBAL_FILE_CACHE: Once<GlobalFileDataCache> = Once::new();
        
        let cache = GLOBAL_FILE_CACHE.call_once(|| {
            GlobalFileDataCache::new(1000) // 最大1000エントリ
        });
        
        // データが1ページより大きい場合は先頭ページのみキャッシュ
        let cache_data = if data.len() > PAGE_SIZE {
            data[..PAGE_SIZE].to_vec()
        } else {
            data.to_vec()
        };
        
        cache.insert(file_id, offset, cache_data);
        
        log::trace!("ファイルデータキャッシュ保存: file_id={}, offset=0x{:x}, size={}", 
                   file_id, offset, data.len());
    }
    
    /// 仮想メモリアドレスを物理アドレスに変換してページをマップ
            None
        }
    }
    
    fn insert(&self, file_id: usize, offset: usize, data: Vec<u8>) {
        let current_time = self.get_current_time();
        
        // キャッシュ容量チェック
        if self.current_entries.load(Ordering::Relaxed) >= self.max_entries {
            self.evict_oldest_entries();
        }
        
        let cached_page = CachedPage {
            data,
            timestamp: current_time,
            access_count: AtomicUsize::new(1),
        };
        
        let mut cache = self.cache.write();
        if cache.insert((file_id, offset), cached_page).is_none() {
            self.current_entries.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    fn evict_oldest_entries(&self) {
        let mut cache = self.cache.write();
        
        // 最も古いエントリを削除（LRU）
        let target_count = self.max_entries / 4; // 25%削除
        let mut entries_to_remove = Vec::new();
        
        // タイムスタンプでソートして古いものを特定
        let mut sorted_entries: Vec<_> = cache.iter()
            .map(|(key, page)| (*key, page.timestamp))
            .collect();
        sorted_entries.sort_by_key(|(_, timestamp)| *timestamp);
        
        for (key, _) in sorted_entries.iter().take(target_count) {
            entries_to_remove.push(*key);
        }
        
        // エントリを削除
        for key in entries_to_remove {
            cache.remove(&key);
            self.current_entries.fetch_sub(1, Ordering::Relaxed);
        }
        
        log::debug!("キャッシュエビクション完了: {}エントリ削除", target_count);
    }
    
    fn get_current_time(&self) -> u64 {
        // タイムスタンプ取得（簡易実装）
        crate::core::time::get_timestamp_ns()
    }
}

// グローバルキャッシュインスタンス
static GLOBAL_FILE_DATA_CACHE: GlobalFileDataCache = GlobalFileDataCache::new(1024);

/// ファイルシステムタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilesystemType {
    Ext4,
    Fat32,
    Ntfs,
    ExFat,
}

/// VMAフラグ
bitflags::bitflags! {
    pub struct VmaFlags: u32 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC = 1 << 2;
        const USER = 1 << 3;
        const CACHE_DISABLE = 1 << 4;
        const WRITE_THROUGH = 1 << 5;
        const WRITE_COMBINING = 1 << 6;
    }
}

const PAGE_SIZE: usize = 4096;
    
    /// 共有メモリページを取得
    fn get_shared_memory_page(shared_id: usize, offset: usize) -> Result<PhysAddr, MmapError> {
        // 共有メモリオブジェクトから指定されたオフセットの物理ページアドレスを取得します。
        // この関数は共有メモリ管理モジュール (例: crate::core::ipc::shmem) と連携する必要があります。
        // 共有オブジェクトが存在しない、オフセットが範囲外などのエラー処理も必要です。
        Err(MmapError::SharedMemoryError)
    }

    /// テレページをフェッチ
    fn fetch_telepage(node_id: usize, remote_phys_addr: PhysAddr) -> Result<Page, MmapError> {
        // リモートノードからテレページをフェッチし、ローカルに物理ページを割り当てて内容をコピーします。
        // この関数はテレページ管理モジュール (例: crate::core::memory::telepage) と連携し、
        // ネットワーク通信を介してリモートノードからデータを取得する必要があります。
        Err(MmapError::TelePageError)
    }

    /// グローバルなVMAキャッシュ
    pub static VMA_CACHE: Mutex<Option<SlabCache>> = Mutex::new(None);

    /// メモリマッピングサブシステムを初期化
    pub fn init_mmap() {
        let mut cache_lock = VMA_CACHE.lock();
        *cache_lock = Some(SlabCache::new("vma_cache", core::mem::size_of::<VirtualMemoryArea>(), 8));
    }

    // グローバルAPI関数
    // これらの関数はカーネル内の他のモジュールから呼び出される

    /// 物理メモリ領域を指定アドレスにマップ
    pub fn map_physical(
        addr_space: &AddressSpace,
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        size: usize,
        permissions: MapPermissions,
    ) -> Result<VirtAddr, MmapError> {
        addr_space.map(
            virt_addr,
            size,
            permissions,
            MapType::Ram { phys_addr },
        )
    }

    /// 匿名メモリ領域を指定アドレスにマップ
    pub fn map_anonymous(
        addr_space: &AddressSpace,
        virt_addr: VirtAddr,
        size: usize,
        permissions: MapPermissions,
        zero_on_demand: bool,
    ) -> Result<VirtAddr, MmapError> {
        addr_space.map(
            virt_addr,
            size,
            permissions,
            MapType::Anonymous { zero_on_demand },
        )
    }

    /// デバイスメモリを指定アドレスにマップ
    pub fn map_device(
        addr_space: &AddressSpace,
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        size: usize,
    ) -> Result<VirtAddr, MmapError> {
        addr_space.map(
            virt_addr,
            size,
            MapPermissions::device(),
            MapType::Device { phys_addr },
        )
    }

    /// ファイルを指定アドレスにマップ
    pub fn map_file(
        addr_space: &AddressSpace,
        virt_addr: VirtAddr,
        file_id: usize,
        offset: usize,
        size: usize,
        permissions: MapPermissions,
        file_perms: FilePermissions,
    ) -> Result<VirtAddr, MmapError> {
        addr_space.map(
            virt_addr,
            size,
            permissions,
            MapType::File {
                file_id,
                offset,
                file_perms,
            },
        )
    }

    /// 共有メモリを指定アドレスにマップ
    pub fn map_shared(
        addr_space: &AddressSpace,
        virt_addr: VirtAddr,
        shared_id: usize,
        offset: usize,
        size: usize,
        permissions: MapPermissions,
    ) -> Result<VirtAddr, MmapError> {
        addr_space.map(
            virt_addr,
            size,
            permissions,
            MapType::Shared {
                shared_id,
                offset,
            },
        )
    }

    /// テレページを指定アドレスにマップ
    pub fn map_telepage(
        addr_space: &AddressSpace,
        virt_addr: VirtAddr,
        node_id: usize,
        remote_phys_addr: PhysAddr,
        size: usize,
        permissions: MapPermissions,
    ) -> Result<VirtAddr, MmapError> {
        addr_space.map(
            virt_addr,
            size,
            permissions,
            MapType::TelePage {
                node_id,
                remote_phys_addr,
            },
        )
    }

    /// 指定範囲のメモリをアンマップ
    pub fn unmap(
        addr_space: &AddressSpace,
        virt_addr: VirtAddr,
        size: usize,
    ) -> Result<(), MmapError> {
        addr_space.unmap(virt_addr, size)
    }

    /// ページフォルトを処理
    pub fn handle_page_fault(
        addr_space: &AddressSpace,
        fault_addr: VirtAddr,
        write_access: bool,
        instruction_fetch: bool,
    ) -> Result<(), MmapError> {
        addr_space.handle_page_fault(fault_addr, write_access, instruction_fetch)
    }

    /// SLUB支援マッピングの作成
    /// 
    /// SLUBアロケータを使用して小さいオブジェクトを効率的に管理するための
    /// メモリマッピングを作成します。
    /// 
    /// # 引数
    /// * `page_table` - ページテーブル
    /// * `vaddr` - マッピングする仮想アドレス（NULLの場合は自動割り当て）
    /// * `object_size` - 各オブジェクトのサイズ（バイト）
    /// * `alignment` - アラインメント要件（バイト）
    /// * `prot` - 保護フラグ（読み取り/書き込み/実行）
    /// * `flags` - マッピングフラグ
    /// 
    /// # 戻り値
    /// * 成功した場合はマッピング結果、失敗した場合はNone
    pub fn slub_mmap(
        page_table: &mut PageTable,
        vaddr: Option<VirtualAddress>,
        object_size: usize,
        alignment: usize,
        count: usize,
        prot: u32,
        flags: u32,
    ) -> Option<MappingResult> {
        // サイズが0またはオブジェクト数が0の場合は無効
        if object_size == 0 || count == 0 {
            warn!("slub_mmap: オブジェクトサイズまたは数が0のマッピングは無効です");
            return None;
        }
        
        // SLUBキャッシュ名を生成
        let cache_name = match object_size {
            8 => "size-8",
            16 => "size-16",
            32 => "size-32",
            64 => "size-64",
            128 => "size-128",
            256 => "size-256",
            512 => "size-512",
            1024 => "size-1024",
            2048 => "size-2048",
            4096 => "size-4096",
            _ => {
                // 標準サイズ以外は独自のキャッシュを作成
                let custom_name = format!("mmap-{}", object_size);
                let static_name = Box::leak(custom_name.into_boxed_str());
                
                // キャッシュが存在しない場合は作成
                slub_api::create_cache(static_name, object_size, alignment);
                static_name
            }
        };
        
        // 必要なサイズを計算
        let total_size = object_size * count;
        let aligned_size = (total_size + page_api::PAGE_SIZE - 1) & !(page_api::PAGE_SIZE - 1);
        
        // VMAタイプを決定
        let vma_type = determine_vma_type(prot, flags);
        
        // キャッシュポリシーを決定
        let cache_policy = determine_cache_policy(flags);
        
        // マッピングアドレスを決定
        let mapping_addr = match vaddr {
            Some(addr) if flags & flags::FIXED != 0 => {
                // 固定アドレスの場合、既存のマッピングがあれば解除
                let aligned_addr = addr & !(page_api::PAGE_SIZE - 1);
                if unmap(page_table, aligned_addr, aligned_size).is_none() {
                    warn!("slub_mmap: 既存マッピングの解除に失敗しました");
                    return None;
                }
                aligned_addr
            },
            Some(addr) => {
                // 推奨アドレスが指定されている場合
                let aligned_addr = addr & !(page_api::PAGE_SIZE - 1);
                if vma_api::is_region_free(page_table, aligned_addr, aligned_size) {
                    aligned_addr
                } else {
                    // 指定されたアドレスが使用中なら自動割り当て
                    vma_api::find_free_region(page_table, aligned_size, page_api::PAGE_SIZE)?
                }
            },
            None => {
                // アドレス自動割り当て
                vma_api::find_free_region(page_table, aligned_size, page_api::PAGE_SIZE)?
            }
        };
        
        // VMAを作成
        let vma = VirtualMemoryArea {
            range: mapping_addr..(mapping_addr + aligned_size),
            physical_mapping: None,  // マッピングはSLUBで管理
            vma_type,
        permissions: prot,
        cache_policy,
        file_descriptor: None,
        file_offset: 0,
        name: Some("slub_map"),
    };
    
    if !vma_api::add_vma(page_table, vma) {
        warn!("slub_mmap: VMAの追加に失敗しました: vaddr={:#x}, size={}", mapping_addr, aligned_size);
        return None;
    }
    
    // POPULATE フラグが設定されている場合は、すぐにオブジェクトを確保
    let mut mapped_pages = 0;
    let page_count = aligned_size / page_api::PAGE_SIZE;
    
    if flags & flags::POPULATE != 0 {
        // SLUBからオブジェクトを事前確保
        for _ in 0..count {
            if let Some(_) = slub_api::alloc_from(cache_name) {
                // 正常に確保
            } else {
                warn!("slub_mmap: オブジェクトの事前確保に失敗しました");
                break;
            }
        }
        
        mapped_pages = page_count;
    }
    
    Some(MappingResult {
        vaddr: mapping_addr,
        size: aligned_size,
        mapped_pages,
    })
}

/// マッピングページフォルトの処理（SLUB使用時）
fn handle_slub_fault(
    page_table: &mut PageTable,
    vma: &VirtualMemoryArea,
    fault_addr: VirtualAddress,
) -> bool {
    // フォルトアドレスがVMA内にあることを確認
    if !vma.range.contains(&fault_addr) {
        return false;
    }
    
    // VMAがSLUB用であるか確認
    if !vma.name.map_or(false, |name| name == "slub_map") {
        return false;
    }
    
    // SLUB対応のオンデマンドページング実装
    // オブジェクトサイズを判断し、適切なSLUBキャッシュから割り当て
    
    // フォルトが発生したページのベースアドレス
    let page_base = fault_addr & !(page_api::PAGE_SIZE - 1);
    
    // 物理ページを確保
    let phys_addr = match page_api::alloc_pages(1) {
        Some(addr) => addr,
        None => {
            error!("handle_slub_fault: 物理ページの確保に失敗しました");
            return false;
        }
    };
    
    // ページテーブルにマッピング
    let success = paging::map_page(
        page_table.get_root(),
        page_base,
        phys_addr,
        vma.permissions,
    );
    
    if !success {
        page_api::free_pages(phys_addr, 1);
        error!("handle_slub_fault: ページマッピングに失敗しました");
        return false;
    }
    
    // ページをゼロクリア
    unsafe {
        let ptr = phys_addr as *mut u8;
        core::ptr::write_bytes(ptr, 0, page_api::PAGE_SIZE);
    }
    
    true
} 