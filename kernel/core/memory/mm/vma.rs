// AetherOS 仮想メモリ領域 (VMA) 管理
//
// このモジュールはプロセスの仮想メモリ領域を管理します。
// VMAはプロセスのアドレス空間内の連続した領域を表し、
// メモリマッピングの基本単位として使用されます。

use crate::arch::{PageSize, VirtualAddress, PhysicalAddress};
use crate::core::memory::mm::{PageTable, VmaType, VirtualMemoryArea, CachePolicy};
use alloc::vec::Vec;
use core::ops::Range;
use log::{debug, warn};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use crate::arch::mmu::PageTableFlags;
use crate::core::memory::mm::page::{PhysAddr, VirtAddr};
use crate::core::sync::mutex::Mutex;

/// VMA関連の公開API
pub mod api {
    use super::*;

    /// 指定されたページテーブルに新しいVMAを追加
    ///
    /// # 引数
    /// * `page_table` - VMAを追加するページテーブル
    /// * `vma` - 追加する仮想メモリ領域
    ///
    /// # 戻り値
    /// * 成功した場合は `true`、失敗した場合は `false`
    pub fn add_vma(page_table: &mut PageTable, vma: VirtualMemoryArea) -> bool {
        // VMAの範囲が有効かチェック
        if vma.range.start >= vma.range.end {
            warn!("add_vma: 無効なVMA範囲: {:?}", vma.range);
            return false;
        }

        // 既存のVMAと重複していないかチェック
        if has_overlapping_vma(page_table, &vma.range) {
            warn!("add_vma: 重複するVMAが存在します: {:?}", vma.range);
            return false;
        }

        // VMAをページテーブルに追加
        debug!("新しいVMAを追加: 範囲={:?}, タイプ={:?}", vma.range, vma.vma_type);
        page_table.vmas.push(vma);
        true
    }

    /// 指定されたアドレスを含むVMAを検索
    ///
    /// # 引数
    /// * `page_table` - 検索対象のページテーブル
    /// * `addr` - 検索する仮想アドレス
    ///
    /// # 戻り値
    /// * アドレスを含むVMAが見つかった場合はSome(VMA)、見つからなかった場合はNone
    pub fn find_vma_containing(page_table: &PageTable, addr: VirtualAddress) -> Option<VirtualMemoryArea> {
        page_table.vmas.iter()
            .find(|vma| addr >= vma.range.start && addr < vma.range.end)
            .cloned()
    }

    /// 指定された範囲に重なるVMAのリストを取得
    ///
    /// # 引数
    /// * `page_table` - 検索対象のページテーブル
    /// * `start` - 範囲の開始アドレス
    /// * `size` - 範囲のサイズ（バイト）
    ///
    /// # 戻り値
    /// * 範囲と重なるVMAのベクター
    pub fn find_vmas_in_range(page_table: &PageTable, start: VirtualAddress, size: usize) -> Vec<VirtualMemoryArea> {
        if size == 0 {
            return Vec::new();
        }

        let end = start + size;
        page_table.vmas.iter()
            .filter(|vma| {
                // VMAと指定範囲が重なるかチェック
                !(vma.range.end <= start || vma.range.start >= end)
            })
            .cloned()
            .collect()
    }

    /// 指定されたアドレスから始まるVMAを削除
    ///
    /// # 引数
    /// * `page_table` - VMAを削除するページテーブル
    /// * `start_addr` - 削除するVMAの開始アドレス
    ///
    /// # 戻り値
    /// * 成功した場合は `true`、失敗した場合は `false`
    pub fn remove_vma(page_table: &mut PageTable, start_addr: VirtualAddress) -> bool {
        let initial_count = page_table.vmas.len();
        
        page_table.vmas.retain(|vma| vma.range.start != start_addr);
        
        let new_count = page_table.vmas.len();
        if new_count < initial_count {
            debug!("VMAを削除: 開始アドレス={:#x}", start_addr);
            true
        } else {
            warn!("remove_vma: 指定されたアドレスのVMAが見つかりません: {:#x}", start_addr);
            false
        }
    }

    /// 指定された範囲のVMAを分割
    ///
    /// # 引数
    /// * `page_table` - 対象のページテーブル
    /// * `addr` - 分割する位置のアドレス
    ///
    /// # 戻り値
    /// * 成功した場合は `true`、失敗した場合は `false`
    pub fn split_vma(page_table: &mut PageTable, addr: VirtualAddress) -> bool {
        // 分割位置が含まれるVMAを検索
        if let Some(vma_index) = page_table.vmas.iter().position(|vma| {
            addr > vma.range.start && addr < vma.range.end
        }) {
            let vma = page_table.vmas[vma_index].clone();
            
            // 最初の部分（元のVMAを更新）
            page_table.vmas[vma_index].range = vma.range.start..addr;
            
            // 2つ目の部分（新しいVMAを作成）
            let second_part = VirtualMemoryArea {
                range: addr..vma.range.end,
                physical_mapping: vma.physical_mapping.map(|addr| {
                    // 物理マッピングがある場合は適切にオフセットを計算
                    let offset = addr - vma.range.start;
                    addr + offset
                }),
                vma_type: vma.vma_type,
                permissions: vma.permissions,
                cache_policy: vma.cache_policy,
                file_descriptor: vma.file_descriptor.clone(),
                file_offset: vma.file_offset + (addr - vma.range.start),
                name: vma.name,
            };
            
            page_table.vmas.push(second_part);
            debug!("VMAを分割: アドレス={:#x}", addr);
            true
        } else {
            warn!("split_vma: 分割位置 {:#x} を含むVMAが見つかりません", addr);
            false
        }
    }

    /// 全てのVMAのリストを取得
    ///
    /// # 引数
    /// * `page_table` - 対象のページテーブル
    ///
    /// # 戻り値
    /// * ページテーブル内の全VMAのクローン
    pub fn get_all_vmas(page_table: &PageTable) -> Vec<VirtualMemoryArea> {
        page_table.vmas.clone()
    }

    /// 指定した種類のVMAをすべて取得
    ///
    /// # 引数
    /// * `page_table` - 対象のページテーブル
    /// * `vma_type` - 検索するVMAの種類
    ///
    /// # 戻り値
    /// * 指定した種類のVMAのベクター
    pub fn get_vmas_by_type(page_table: &PageTable, vma_type: VmaType) -> Vec<VirtualMemoryArea> {
        page_table.vmas.iter()
            .filter(|vma| vma.vma_type == vma_type)
            .cloned()
            .collect()
    }

    /// 指定した名前のVMAをすべて取得
    ///
    /// # 引数
    /// * `page_table` - 対象のページテーブル
    /// * `name` - 検索するVMAの名前
    ///
    /// # 戻り値
    /// * 指定した名前のVMAのベクター
    pub fn get_vmas_by_name(page_table: &PageTable, name: &str) -> Vec<VirtualMemoryArea> {
        page_table.vmas.iter()
            .filter(|vma| vma.name.is_some() && vma.name.unwrap() == name)
            .cloned()
            .collect()
    }

    /// 指定された範囲が既存のVMAと重ならないかチェック
    ///
    /// # 引数
    /// * `page_table` - 対象のページテーブル
    /// * `range` - チェックする範囲
    ///
    /// # 戻り値
    /// * 重なるVMAがある場合は `true`、ない場合は `false`
    pub fn has_overlapping_vma(page_table: &PageTable, range: &Range<VirtualAddress>) -> bool {
        if range.start >= range.end {
            return false;
        }

        page_table.vmas.iter().any(|vma| {
            // 範囲が重なるかチェック
            !(vma.range.end <= range.start || vma.range.start >= range.end)
        })
    }

    /// 指定された領域が空き（VMAが割り当てられていない）かチェック
    ///
    /// # 引数
    /// * `page_table` - 対象のページテーブル
    /// * `addr` - チェックする開始アドレス
    /// * `size` - チェックするサイズ（バイト）
    ///
    /// # 戻り値
    /// * 領域が空いている場合は `true`、VMAが割り当てられている場合は `false`
    pub fn is_region_free(page_table: &PageTable, addr: VirtualAddress, size: usize) -> bool {
        if size == 0 {
            return true;
        }

        !has_overlapping_vma(page_table, &(addr..(addr + size)))
    }

    /// 指定されたサイズの空き領域を検索
    ///
    /// # 引数
    /// * `page_table` - 対象のページテーブル
    /// * `size` - 必要なサイズ（バイト）
    /// * `alignment` - アラインメント要件（バイト）
    ///
    /// # 戻り値
    /// * 空き領域の開始アドレス、見つからなかった場合は `None`
    pub fn find_free_region(page_table: &PageTable, size: usize, alignment: usize) -> Option<VirtualAddress> {
        if size == 0 {
            return None;
        }

        // アーキテクチャによって異なるアドレス空間制限を考慮
        let user_space_start = 0x10000; // 通常、最初の64KBは予約
        let user_space_end = 0x7FFF_FFFF_FFFF; // ユーザー空間の上限（例: x86_64）

        // VMAをアドレス順にソート
        let mut sorted_vmas = page_table.vmas.clone();
        sorted_vmas.sort_by_key(|vma| vma.range.start);

        // アラインメントされた開始アドレスから検索
        let aligned_start = (user_space_start + alignment - 1) & !(alignment - 1);
        let mut current = aligned_start;

        // 各VMA間のギャップをチェック
        for vma in &sorted_vmas {
            if current + size <= vma.range.start {
                // 十分な空きスペースが見つかった
                return Some(current);
            }
            // 次の候補位置を計算（VMAの終了後にアラインメント）
            current = (vma.range.end + alignment - 1) & !(alignment - 1);
        }

        // 最後のVMAの後にスペースがあるかチェック
        if current + size <= user_space_end {
            return Some(current);
        }

        // 適切な空き領域が見つからなかった
        None
    }

    /// VMAの権限を変更
    ///
    /// # 引数
    /// * `page_table` - 対象のページテーブル
    /// * `addr` - VMAを特定するアドレス
    /// * `new_perm` - 新しい権限
    ///
    /// # 戻り値
    /// * 成功した場合は `true`、失敗した場合は `false`
    pub fn change_vma_permissions(page_table: &mut PageTable, addr: VirtualAddress, new_perm: u32) -> bool {
        let vma_index = page_table.vmas.iter().position(|vma| {
            addr >= vma.range.start && addr < vma.range.end
        });

        if let Some(index) = vma_index {
            // VMAの権限を更新
            page_table.vmas[index].permissions = new_perm;
            
            // このVMAに対応する実際のページマッピングの権限も更新
            let vma = &page_table.vmas[index];
            let start = vma.range.start;
            let size = vma.range.end - vma.range.start;
            let page_size = PageSize::Default;
            
            // ページングサブシステムを使用して物理ページの権限を変更
            crate::core::memory::mm::paging::change_permissions(
                page_table.get_root(),
                start,
                size / (page_size as usize),
                page_size,
                new_perm
            );
            
            debug!("VMA権限を変更: アドレス={:#x}, 新権限={:#x}", addr, new_perm);
            true
        } else {
            warn!("change_vma_permissions: アドレス {:#x} を含むVMAが見つかりません", addr);
            false
        }
    }

    /// VMAのキャッシュポリシーを変更
    ///
    /// # 引数
    /// * `page_table` - 対象のページテーブル
    /// * `addr` - VMAを特定するアドレス
    /// * `new_policy` - 新しいキャッシュポリシー
    ///
    /// # 戻り値
    /// * 成功した場合は `true`、失敗した場合は `false`
    pub fn change_vma_cache_policy(page_table: &mut PageTable, addr: VirtualAddress, new_policy: CachePolicy) -> bool {
        let vma_index = page_table.vmas.iter().position(|vma| {
            addr >= vma.range.start && addr < vma.range.end
        });

        if let Some(index) = vma_index {
            // VMAのキャッシュポリシーを更新
            page_table.vmas[index].cache_policy = new_policy;
            
            // このVMAに対応する実際のページマッピングのキャッシュ属性も更新
            let vma = &page_table.vmas[index];
            let start = vma.range.start;
            let size = vma.range.end - vma.range.start;
            let page_size = PageSize::Default;
            
            // キャッシュポリシーをアーキテクチャ固有の値に変換
            let cache_type = match new_policy {
                CachePolicy::Cacheable => 1,
                CachePolicy::Uncacheable => 0,
                CachePolicy::WriteThrough => 2,
                CachePolicy::WriteBack => 3,
                CachePolicy::DeviceMemory => 4,
            };
            
            // ページングサブシステムを使用して物理ページのキャッシュ属性を変更
            crate::core::memory::mm::paging::change_cache_attributes(
                page_table.get_root(),
                start,
                size / (page_size as usize),
                page_size,
                cache_type
            );
            
            debug!("VMAキャッシュポリシーを変更: アドレス={:#x}, 新ポリシー={:?}", addr, new_policy);
            true
        } else {
            warn!("change_vma_cache_policy: アドレス {:#x} を含むVMAが見つかりません", addr);
            false
        }
    }

    /// VMAを結合（可能な場合）
    ///
    /// # 引数
    /// * `page_table` - 対象のページテーブル
    ///
    /// # 戻り値
    /// * 結合されたVMAの数
    pub fn merge_adjacent_vmas(page_table: &mut PageTable) -> usize {
        let initial_count = page_table.vmas.len();
        if initial_count <= 1 {
            return 0;
        }

        // VMAをアドレス順にソート
        page_table.vmas.sort_by_key(|vma| vma.range.start);

        // 隣接するVMAを結合する
        let mut i = 0;
        while i < page_table.vmas.len() - 1 {
            let current = &page_table.vmas[i];
            let next = &page_table.vmas[i + 1];

            // 結合可能な条件チェック:
            // 1. 範囲が連続している
            // 2. 同じタイプ、権限、キャッシュポリシー
            // 3. 物理マッピングの連続性（物理マッピングがある場合）
            if current.range.end == next.range.start &&
               current.vma_type == next.vma_type &&
               current.permissions == next.permissions &&
               current.cache_policy == next.cache_policy &&
               current.name == next.name
            {
                // 物理マッピングのチェック
                let can_merge = match (current.physical_mapping, next.physical_mapping) {
                    (Some(curr_phys), Some(next_phys)) => {
                        // 物理アドレスが連続しているか
                        curr_phys + (current.range.end - current.range.start) == next_phys
                    },
                    (None, None) => true,
                    _ => false
                };

                // ファイルマッピングのチェック
                let file_check = match (&current.file_descriptor, &next.file_descriptor) {
                    (Some(curr_fd), Some(next_fd)) => {
                        // 同じファイルで、オフセットが連続しているか
                        curr_fd == next_fd && 
                        current.file_offset + (current.range.end - current.range.start) == next.file_offset
                    },
                    (None, None) => true,
                    _ => false
                };

                if can_merge && file_check {
                    // 結合可能なので、現在のVMAを拡張
                    page_table.vmas[i].range.end = next.range.end;
                    
                    // 次のVMAを削除
                    page_table.vmas.remove(i + 1);
                    
                    debug!("隣接するVMAを結合: 範囲={:?}", page_table.vmas[i].range);
                    // インデックスを増やさない（次の要素がシフトされるため）
                } else {
                    // 結合できない場合は次へ
                    i += 1;
                }
            } else {
                // 結合条件を満たさない場合は次へ
                i += 1;
            }
        }

        let final_count = page_table.vmas.len();
        initial_count - final_count
    }

    /// VMAの情報を表示（デバッグ用）
    ///
    /// # 引数
    /// * `page_table` - 対象のページテーブル
    pub fn dump_vmas(page_table: &PageTable) {
        debug!("=== VMA ダンプ - エントリ数: {} ===", page_table.vmas.len());
        
        for (i, vma) in page_table.vmas.iter().enumerate() {
            let name = vma.name.unwrap_or("unnamed");
            let phys_mapping = match vma.physical_mapping {
                Some(addr) => format!("{:#x}", addr),
                None => "なし".to_string()
            };
            
            debug!("VMA #{}: 名前={}, 範囲={:#x}-{:#x}, サイズ={}KB, タイプ={:?}, 権限={:#x}, 物理マッピング={}",
                  i, name, vma.range.start, vma.range.end,
                  (vma.range.end - vma.range.start) / 1024,
                  vma.vma_type, vma.permissions, phys_mapping);
        }
        
        debug!("==============================");
    }
}

// 内部ヘルパー関数

/// 指定された範囲が既存のVMAと重ならないかチェック（内部使用）
fn has_overlapping_vma(page_table: &PageTable, range: &Range<VirtualAddress>) -> bool {
    api::has_overlapping_vma(page_table, range)
}

/// 仮想メモリ領域の権限フラグ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmaPerm {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub user: bool,
}

impl VmaPerm {
    /// 読み取り専用のパーミッション
    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            exec: false,
            user: false,
        }
    }

    /// 読み書き可能なパーミッション
    pub const fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            exec: false,
            user: false,
        }
    }

    /// 実行可能なパーミッション
    pub const fn executable() -> Self {
        Self {
            read: true,
            write: false,
            exec: true,
            user: false,
        }
    }

    /// ユーザーモード用パーミッション
    pub const fn user_mode() -> Self {
        Self {
            read: true,
            write: false,
            exec: false,
            user: true,
        }
    }

    /// カスタムパーミッションの作成
    pub const fn new(read: bool, write: bool, exec: bool, user: bool) -> Self {
        Self {
            read,
            write,
            exec,
            user,
        }
    }

    /// ページテーブルフラグに変換
    pub fn to_page_table_flags(&self) -> PageTableFlags {
        let mut flags = PageTableFlags::PRESENT;
        
        if self.read {
            flags |= PageTableFlags::READABLE;
        }
        
        if self.write {
            flags |= PageTableFlags::WRITABLE;
        }
        
        if self.exec {
            // 実行不可の場合はNX（No Execute）フラグを設定
            // アーキテクチャによって異なる場合があるため、アーキテクチャ固有のコードで処理
        } else {
            flags |= PageTableFlags::NO_EXECUTE;
        }
        
        if self.user {
            flags |= PageTableFlags::USER_ACCESSIBLE;
        }
        
        flags
    }
}

/// 仮想メモリ領域の種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmaType {
    /// 匿名メモリ領域（例：スタック、ヒープ）
    Anonymous,
    /// ファイルマッピング
    FileBacked,
    /// デバイスメモリ
    Device,
    /// 共有メモリ
    Shared,
}

/// 仮想メモリ領域（VMA）の構造体
#[derive(Debug)]
pub struct Vma {
    /// 仮想アドレス範囲
    pub range: Range<VirtAddr>,
    /// 物理アドレスとのマッピング（オプション）
    pub phys_mapping: Option<PhysAddr>,
    /// 権限フラグ
    pub perm: VmaPerm,
    /// 領域の種類
    pub vma_type: VmaType,
    /// 領域の名前（デバッグ用）
    pub name: Option<String>,
    /// このVMAが属するスレッドのTID（該当する場合）
    pub owner_tid: Option<u64>,
    /// このVMAに関連付けられたファイル記述子（ファイルバックの場合）
    pub fd: Option<u64>,
    /// マッピングのオフセット（ファイルバックの場合）
    pub offset: Option<u64>,
    /// このVMAがCoWマッピングかどうか
    pub is_cow: bool,
    /// 共有されたVMAかどうか
    pub is_shared: bool,
}

impl Vma {
    /// 新しい仮想メモリ領域を作成
    pub fn new(
        start: VirtAddr,
        end: VirtAddr,
        phys_mapping: Option<PhysAddr>,
        perm: VmaPerm,
        vma_type: VmaType,
        name: Option<String>,
    ) -> Self {
        Self {
            range: Range { start, end },
            phys_mapping,
            perm,
            vma_type,
            name,
            owner_tid: None,
            fd: None,
            offset: None,
            is_cow: false,
            is_shared: false,
        }
    }

    /// 匿名メモリ領域を作成
    pub fn new_anonymous(start: VirtAddr, end: VirtAddr, perm: VmaPerm, name: Option<String>) -> Self {
        Self::new(start, end, None, perm, VmaType::Anonymous, name)
    }

    /// ファイルバックメモリ領域を作成
    pub fn new_file_backed(
        start: VirtAddr,
        end: VirtAddr,
        perm: VmaPerm,
        fd: u64,
        offset: u64,
        name: Option<String>,
    ) -> Self {
        let mut vma = Self::new(start, end, None, perm, VmaType::FileBacked, name);
        vma.fd = Some(fd);
        vma.offset = Some(offset);
        vma
    }

    /// デバイスメモリ領域を作成
    pub fn new_device(
        start: VirtAddr,
        end: VirtAddr,
        phys_addr: PhysAddr,
        perm: VmaPerm,
        name: Option<String>,
    ) -> Self {
        Self::new(start, end, Some(phys_addr), perm, VmaType::Device, name)
    }

    /// 共有メモリ領域を作成
    pub fn new_shared(start: VirtAddr, end: VirtAddr, perm: VmaPerm, name: Option<String>) -> Self {
        let mut vma = Self::new(start, end, None, perm, VmaType::Shared, name);
        vma.is_shared = true;
        vma
    }

    /// VMAのサイズを取得
    pub fn size(&self) -> usize {
        (self.range.end.as_usize() - self.range.start.as_usize())
    }

    /// 指定されたアドレスがこのVMA内にあるかどうかを確認
    pub fn contains(&self, addr: VirtAddr) -> bool {
        self.range.start <= addr && addr < self.range.end
    }

    /// 指定されたアドレス範囲がこのVMA内に完全に含まれるかどうかを確認
    pub fn contains_range(&self, range: &Range<VirtAddr>) -> bool {
        self.range.start <= range.start && range.end <= self.range.end
    }

    /// 指定されたアドレス範囲がこのVMAと重なるかどうかを確認
    pub fn overlaps(&self, range: &Range<VirtAddr>) -> bool {
        self.range.start < range.end && range.start < self.range.end
    }
}

/// 仮想メモリ領域管理エラー
#[derive(Debug)]
pub enum VmaError {
    /// 無効なアドレス範囲
    InvalidRange,
    /// アドレス範囲の重複
    Overlap,
    /// 領域が見つからない
    NotFound,
    /// メモリ不足
    OutOfMemory,
    /// 権限エラー
    PermissionDenied,
    /// アライメントエラー
    AlignmentError,
    /// その他のエラー
    Other(&'static str),
}

/// 仮想メモリ領域マネージャ
#[derive(Debug)]
pub struct VmaManager {
    /// 仮想メモリ領域のマップ（開始アドレスでソート）
    areas: BTreeMap<VirtAddr, Arc<Vma>>,
    /// 次の利用可能なVMA ID
    next_id: AtomicU64,
}

impl VmaManager {
    /// 新しいVMAマネージャを作成
    pub fn new() -> Self {
        Self {
            areas: BTreeMap::new(),
            next_id: AtomicU64::new(1),
        }
    }

    /// 新しい仮想メモリ領域を追加
    pub fn add_vma(&mut self, vma: Vma) -> Result<Arc<Vma>, VmaError> {
        // 重複チェック
        for (_, existing_vma) in self.areas.iter() {
            if existing_vma.overlaps(&vma.range) {
                return Err(VmaError::Overlap);
            }
        }

        // 範囲チェック
        if vma.range.start >= vma.range.end {
            return Err(VmaError::InvalidRange);
        }

        let vma_arc = Arc::new(vma);
        self.areas.insert(vma_arc.range.start, vma_arc.clone());
        Ok(vma_arc)
    }

    /// 指定されたアドレス範囲の仮想メモリ領域を削除
    pub fn remove_vma(&mut self, range: &Range<VirtAddr>) -> Result<Arc<Vma>, VmaError> {
        if let Some(vma) = self.find_vma_by_range(range) {
            // 完全に一致する場合のみ削除
            if vma.range.start == range.start && vma.range.end == range.end {
                let removed = self.areas.remove(&range.start)
                    .ok_or(VmaError::NotFound)?;
                return Ok(removed);
            }
        }
        Err(VmaError::NotFound)
    }

    /// 指定されたアドレスを含むVMAを検索
    pub fn find_vma(&self, addr: VirtAddr) -> Option<Arc<Vma>> {
        // 指定されたアドレス以下の最大のキーを探す
        let entry = self.areas.range(..=addr).next_back();
        
        if let Some((_, vma)) = entry {
            if vma.contains(addr) {
                return Some(vma.clone());
            }
        }
        None
    }

    /// 指定されたアドレス範囲に完全に一致するVMAを検索
    pub fn find_vma_by_range(&self, range: &Range<VirtAddr>) -> Option<Arc<Vma>> {
        if let Some(vma) = self.areas.get(&range.start) {
            if vma.range.end == range.end {
                return Some(vma.clone());
            }
        }
        None
    }

    /// 指定されたアドレス範囲と重なるすべてのVMAを取得
    pub fn find_overlapping_vmas(&self, range: &Range<VirtAddr>) -> Vec<Arc<Vma>> {
        let mut result = Vec::new();
        
        // 開始アドレスが指定された範囲の終了アドレス未満のすべてのVMAを検索
        for (_, vma) in self.areas.range(..range.end) {
            if vma.overlaps(range) {
                result.push(vma.clone());
            }
        }
        
        result
    }

    /// 新しい名前付き匿名VMAを作成して追加
    pub fn create_anonymous_vma(
        &mut self,
        start: VirtAddr,
        size: usize,
        perm: VmaPerm,
        name: Option<String>,
    ) -> Result<Arc<Vma>, VmaError> {
        let end = VirtAddr::new(start.as_usize() + size);
        let vma = Vma::new_anonymous(start, end, perm, name);
        self.add_vma(vma)
    }

    /// VMAのサイズ変更
    pub fn resize_vma(
        &mut self,
        addr: VirtAddr,
        new_size: usize,
    ) -> Result<Arc<Vma>, VmaError> {
        let vma = self.find_vma(addr)
            .ok_or(VmaError::NotFound)?;
            
        // 同じサイズの場合は何もしない
        if vma.size() == new_size {
            return Ok(vma);
        }
        
        // 開始アドレスが一致していない場合はエラー
        if vma.range.start != addr {
            return Err(VmaError::InvalidRange);
        }
        
        let new_end = VirtAddr::new(addr.as_usize() + new_size);
        
        // 新しい範囲が他のVMAと重ならないことを確認
        let new_range = Range { start: addr, end: new_end };
        for (_, other_vma) in self.areas.iter() {
            if Arc::ptr_eq(&vma, other_vma) {
                continue;
            }
            
            if other_vma.overlaps(&new_range) {
                return Err(VmaError::Overlap);
            }
        }
        
        // 古いVMAを削除
        self.areas.remove(&vma.range.start);
        
        // 新しいVMAを作成して追加
        let mut new_vma = Vma {
            range: new_range,
            ..(*vma).clone()
        };
        
        let new_vma_arc = Arc::new(new_vma);
        self.areas.insert(new_vma_arc.range.start, new_vma_arc.clone());
        
        Ok(new_vma_arc)
    }

    /// VMAの権限を変更
    pub fn change_vma_perm(
        &mut self,
        range: &Range<VirtAddr>,
        perm: VmaPerm,
    ) -> Result<Arc<Vma>, VmaError> {
        let vma = self.find_vma_by_range(range)
            .ok_or(VmaError::NotFound)?;
            
        // 古いVMAを削除
        self.areas.remove(&vma.range.start);
        
        // 新しいVMAを作成して追加
        let mut new_vma = (*vma).clone();
        new_vma.perm = perm;
        
        let new_vma_arc = Arc::new(new_vma);
        self.areas.insert(new_vma_arc.range.start, new_vma_arc.clone());
        
        Ok(new_vma_arc)
    }

    /// すべてのVMAを取得
    pub fn get_all_vmas(&self) -> Vec<Arc<Vma>> {
        self.areas.values().cloned().collect()
    }
}

/// グローバルなVMAマネージャ
static GLOBAL_VMA_MANAGER: Mutex<Option<VmaManager>> = Mutex::new(None);

/// グローバルVMAマネージャを初期化
pub fn init_vma_manager() {
    let mut lock = GLOBAL_VMA_MANAGER.lock();
    if lock.is_none() {
        *lock = Some(VmaManager::new());
    }
}

/// グローバルVMAマネージャを取得
pub fn get_vma_manager() -> &'static Mutex<Option<VmaManager>> {
    &GLOBAL_VMA_MANAGER
} 