// AetherOS ページングサブシステム
//
// アーキテクチャに依存しないページングインターフェースを提供します
// 各アーキテクチャ（x86_64、AArch64、RISC-V）固有のページテーブル操作は
// 対応するアーキテクチャモジュールによって実装されます

use crate::arch::{MemoryInfo, PageSize, VirtualAddress, PhysicalAddress};
use crate::arch::paging as arch_paging;
use log::debug;

/// ページングサブシステムの初期化
pub fn init(mem_info: &MemoryInfo) {
    debug!("ページングサブシステム初期化中");
    
    // アーキテクチャ固有の初期化を呼び出す
    arch_paging::init(mem_info);
    
    debug!("ページングサブシステム初期化完了");
}

/// 仮想アドレスから物理アドレスへの変換
pub fn translate(page_table_root: PhysicalAddress, vaddr: VirtualAddress) -> Option<PhysicalAddress> {
    arch_paging::translate(page_table_root, vaddr)
}

/// ページのマッピング
pub fn map_pages(
    page_table_root: PhysicalAddress,
    virt_start: VirtualAddress,
    phys_start: PhysicalAddress,
    num_pages: usize,
    page_size: PageSize,
    permissions: u32,
) -> bool {
    arch_paging::map_pages(
        page_table_root,
        virt_start,
        phys_start,
        num_pages,
        page_size,
        permissions,
    )
}

/// ページのマッピング解除
pub fn unmap_pages(
    page_table_root: PhysicalAddress,
    virt_start: VirtualAddress,
    num_pages: usize,
    page_size: PageSize,
) -> bool {
    arch_paging::unmap_pages(page_table_root, virt_start, num_pages, page_size)
}

/// ページの権限変更
pub fn change_permissions(
    page_table_root: PhysicalAddress,
    virt_start: VirtualAddress,
    num_pages: usize,
    page_size: PageSize,
    new_permissions: u32,
) -> bool {
    arch_paging::change_permissions(
        page_table_root,
        virt_start,
        num_pages,
        page_size,
        new_permissions,
    )
}

/// ページのキャッシュ属性変更
pub fn change_cache_attributes(
    page_table_root: PhysicalAddress,
    virt_start: VirtualAddress,
    num_pages: usize,
    page_size: PageSize,
    cache_type: u8,
) -> bool {
    arch_paging::change_cache_attributes(
        page_table_root,
        virt_start,
        num_pages,
        page_size,
        cache_type,
    )
}

/// ページテーブルのダンプ（デバッグ用）
pub fn dump_page_table(page_table_root: PhysicalAddress, start_vaddr: VirtualAddress, end_vaddr: VirtualAddress) {
    arch_paging::dump_page_table(page_table_root, start_vaddr, end_vaddr);
}

/// 指定された仮想アドレス範囲が有効かどうかチェック
pub fn is_range_valid(
    page_table_root: PhysicalAddress,
    virt_start: VirtualAddress,
    size: usize,
) -> bool {
    let page_size = PageSize::Default as usize;
    let num_pages = (size + page_size - 1) / page_size;
    let end_vaddr = virt_start + size - 1;
    
    // 各ページについてチェック
    for i in 0..num_pages {
        let current_vaddr = virt_start + i * page_size;
        if current_vaddr <= end_vaddr {
            if translate(page_table_root, current_vaddr).is_none() {
                return false;
            }
        }
    }
    
    true
}

/// 指定された仮想アドレス範囲が指定された権限を持っているかチェック
pub fn has_permissions(
    page_table_root: PhysicalAddress,
    virt_start: VirtualAddress,
    size: usize,
    required_permissions: u32,
) -> bool {
    arch_paging::check_permissions(
        page_table_root,
        virt_start,
        size,
        required_permissions,
    )
}

/// ページテーブルのクローン（親プロセスから子プロセスへのフォーク時など）
pub fn clone_page_table(
    src_root: PhysicalAddress,
    is_cow: bool,
    user_only: bool,
) -> PhysicalAddress {
    arch_paging::clone_page_table(src_root, is_cow, user_only)
}

/// ページテーブルの破棄
pub fn destroy_page_table(root: PhysicalAddress) {
    arch_paging::destroy_page_table(root);
}

/// 現在のページテーブルを取得（アクティブなCPUコア用）
pub fn get_current_page_table() -> PhysicalAddress {
    arch_paging::get_current_page_table()
}

/// ページテーブルを切り替え
pub fn switch_page_table(new_root: PhysicalAddress) {
    arch_paging::switch_page_table(new_root);
}

/// ページテーブルの再帰的マッピングを設定（自己参照用）
/// これはx86_64でよく使用される手法
pub fn setup_recursive_mapping(root: PhysicalAddress, index: usize) -> bool {
    arch_paging::setup_recursive_mapping(root, index)
}

/// 物理メモリ全体を一時的にマッピングするための恒久的なマッピング領域を設定
pub fn setup_permanent_mappings(root: PhysicalAddress) -> bool {
    arch_paging::setup_permanent_mappings(root)
}

/// 物理アドレスを一時的に仮想アドレス空間にマッピング
/// 非常に大きな物理メモリ領域にアクセスする必要がある場合に使用
pub fn map_temporary(
    phys_addr: PhysicalAddress,
    size: usize,
) -> Option<VirtualAddress> {
    arch_paging::map_temporary(phys_addr, size)
}

/// 一時的なマッピングを解除
pub fn unmap_temporary(virt_addr: VirtualAddress) {
    arch_paging::unmap_temporary(virt_addr);
}

/// メモリ保護機能が有効かどうかチェック
pub fn is_memory_protection_enabled() -> bool {
    arch_paging::is_memory_protection_enabled()
}

/// カーネル空間と分離されたユーザー空間が有効かどうかチェック
pub fn is_user_isolation_enabled() -> bool {
    arch_paging::is_user_isolation_enabled()
}

/// ページサイズをアーキテクチャがサポートしているかチェック
pub fn is_page_size_supported(size: PageSize) -> bool {
    arch_paging::is_page_size_supported(size)
}

/// ページテーブルエントリのリファレンスカウントを増加（共有ページ用）
pub fn increment_page_refcount(phys_addr: PhysicalAddress) {
    arch_paging::increment_page_refcount(phys_addr);
}

/// ページテーブルエントリのリファレンスカウントを減少（共有ページ用）
pub fn decrement_page_refcount(phys_addr: PhysicalAddress) -> bool {
    arch_paging::decrement_page_refcount(phys_addr)
}

/// ページテーブルエントリに対してCOW（コピーオンライト）フラグを設定
pub fn set_cow_flag(
    page_table_root: PhysicalAddress,
    virt_addr: VirtualAddress,
    is_cow: bool,
) -> bool {
    arch_paging::set_cow_flag(page_table_root, virt_addr, is_cow)
}

/// ページが現在COW状態かどうかチェック
pub fn is_cow_page(
    page_table_root: PhysicalAddress,
    virt_addr: VirtualAddress,
) -> bool {
    arch_paging::is_cow_page(page_table_root, virt_addr)
}

/// NUMA最適化のためにページにNODEヒントを設定
pub fn set_numa_hint(
    page_table_root: PhysicalAddress,
    virt_addr: VirtualAddress,
    node_id: u8,
) -> bool {
    arch_paging::set_numa_hint(page_table_root, virt_addr, node_id)
}

/// ページ変換キャッシュ（TLB）をフラッシュ
pub fn flush_tlb(virt_addr: Option<VirtualAddress>, is_global: bool) {
    arch_paging::flush_tlb(virt_addr, is_global);
}

/// アドレス範囲に対するTLBフラッシュを実行
pub fn flush_tlb_range(
    virt_start: VirtualAddress,
    virt_end: VirtualAddress,
) {
    let page_size = PageSize::Default as usize;
    
    // ページ単位でTLBエントリをフラッシュ
    let mut current = virt_start & !(page_size - 1); // ページ境界に合わせる
    let end = (virt_end + page_size - 1) & !(page_size - 1);
    
    while current < end {
        arch_paging::flush_tlb(Some(current), false);
        current += page_size;
    }
}

/// 全てのCPUコアのTLBをフラッシュするIPIを送信
pub fn flush_tlb_all_cpus(virt_addr: Option<VirtualAddress>, is_global: bool) {
    arch_paging::flush_tlb_all_cpus(virt_addr, is_global);
} 