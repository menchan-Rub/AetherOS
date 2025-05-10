// AetherOS テレポートメモリ（プロセス間共有メモリ）
//
// このモジュールは、プロセス間で効率的にメモリを共有するためのメカニズムを提供します。
// "テレポート"という名前は、あるプロセスのメモリが別のプロセスに「テレポート」するという
// イメージに由来しています。

use crate::arch::{PhysicalAddress, VirtualAddress, PageSize};
use crate::core::memory::mm::{PageTable, VmaType, VirtualMemoryArea, CachePolicy};
use crate::core::memory::mm::page::api as page_api;
use crate::core::memory::mm::vma::api as vma_api;
use crate::core::memory::mm::paging;
use crate::core::process::Process;
use crate::sync::Mutex;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use log::{debug, error, info, warn};
use spin::Once;

/// グローバルテレページマネージャー
static TELEPORT_MANAGER: Once<Mutex<TeleportManager>> = Once::new();

/// テレページ識別子
type TeleportId = u64;

/// 次に割り当てられるテレページID
static NEXT_TELEPORT_ID: AtomicU64 = AtomicU64::new(1);

/// テレページのアクセス権限
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeleportPermission {
    /// 読み取り専用
    ReadOnly,
    /// 読み書き可能
    ReadWrite,
}

impl TeleportPermission {
    /// MMUフラグに変換
    fn to_mmu_flags(&self) -> u64 {
        match self {
            TeleportPermission::ReadOnly => 0x1,  // 読み取りのみ
            TeleportPermission::ReadWrite => 0x3, // 読み書き
        }
    }
}

/// テレページの共有状態
#[derive(Debug, Clone)]
struct TeleportRegion {
    /// テレポートID
    id: TeleportId,
    /// 領域名
    name: String,
    /// 物理ページのリスト
    physical_pages: Vec<PhysicalAddress>,
    /// ページサイズ
    page_size: PageSize,
    /// 合計サイズ（バイト単位）
    size: usize,
    /// アクセス権限
    permission: TeleportPermission,
    /// キャッシュポリシー
    cache_policy: CachePolicy,
    /// マッピング数
    usage_count: usize,
}

/// テレポートプロセスマッピング
#[derive(Debug, Clone)]
struct TeleportMapping {
    /// テレポートID
    teleport_id: TeleportId,
    /// プロセスID
    process_id: usize,
    /// マッピングされた仮想アドレス
    virtual_address: VirtualAddress,
    /// アクセス権限
    permission: TeleportPermission,
}

/// テレポートマネージャー
struct TeleportManager {
    /// テレポート領域（ID -> 領域情報）
    regions: BTreeMap<TeleportId, TeleportRegion>,
    /// プロセスごとのマッピング（プロセスID -> マッピングリスト）
    process_mappings: BTreeMap<usize, Vec<TeleportMapping>>,
}

impl TeleportManager {
    /// 新しいテレポートマネージャーを作成
    fn new() -> Self {
        TeleportManager {
            regions: BTreeMap::new(),
            process_mappings: BTreeMap::new(),
        }
    }

    /// 新しいテレポート領域を作成
    fn create_region(
        &mut self,
        name: &str,
        size: usize,
        permission: TeleportPermission,
        cache_policy: CachePolicy,
    ) -> Option<TeleportId> {
        // サイズをページサイズでアラインメント
        let page_size = PageSize::Default;
        let page_size_bytes = page_size as usize;
        let num_pages = (size + page_size_bytes - 1) / page_size_bytes;
        let aligned_size = num_pages * page_size_bytes;

        if num_pages == 0 {
            warn!("テレポート: 無効なサイズが指定されました: {}", size);
            return None;
        }

        // 物理ページを割り当て
        let mut physical_pages = Vec::with_capacity(num_pages);
        for _ in 0..num_pages {
            if let Some(page_addr) = page_api::alloc_pages(1) {
                physical_pages.push(page_addr);
                
                // ページをゼロクリア
                unsafe {
                    let ptr = page_addr as *mut u8;
                    for i in 0..page_size_bytes {
                        ptr.add(i).write_volatile(0);
                    }
                }
            } else {
                // 割り当て失敗、すでに割り当てたページを解放
                for page_addr in physical_pages.iter() {
                    page_api::free_pages(*page_addr, 1);
                }
                error!("テレポート: 物理ページの割り当てに失敗しました");
                return None;
            }
        }

        // 新しいIDを生成
        let id = NEXT_TELEPORT_ID.fetch_add(1, Ordering::SeqCst);

        // テレポート領域を作成
        let region = TeleportRegion {
            id,
            name: name.to_string(),
            physical_pages,
            page_size,
            size: aligned_size,
            permission,
            cache_policy,
            usage_count: 0,
        };

        // 領域を保存
        self.regions.insert(id, region);
        
        info!("テレポート領域を作成: ID={}, 名前={}, サイズ={}KB, ページ数={}", 
             id, name, aligned_size / 1024, num_pages);
        
        Some(id)
    }

    /// テレポート領域を削除
    fn delete_region(&mut self, id: TeleportId) -> bool {
        // 領域情報を取得
        let region = match self.regions.remove(&id) {
            Some(r) => r,
            None => {
                warn!("テレポート: 無効なIDが指定されました: {}", id);
                return false;
            }
        };

        // 使用中の場合は削除できない
        if region.usage_count > 0 {
            warn!("テレポート: 使用中の領域は削除できません: ID={}, 使用数={}", id, region.usage_count);
            // 領域情報を戻す
            self.regions.insert(id, region);
            return false;
        }

        // 物理ページを解放
        for page_addr in region.physical_pages.iter() {
            page_api::free_pages(*page_addr, 1);
        }

        info!("テレポート領域を削除: ID={}, 名前={}", id, region.name);
        
        true
    }

    /// プロセスにテレポート領域をマッピング
    fn map_to_process(
        &mut self,
        id: TeleportId,
        process: &Process,
        vaddr: Option<VirtualAddress>,
        permission: TeleportPermission,
    ) -> Option<VirtualAddress> {
        // 領域情報を取得
        let region = match self.regions.get_mut(&id) {
            Some(r) => r,
            None => {
                warn!("テレポート: 無効なIDが指定されました: {}", id);
                return None;
            }
        };

        // リクエストされた権限をチェック
        if permission == TeleportPermission::ReadWrite && region.permission == TeleportPermission::ReadOnly {
            warn!("テレポート: 読み取り専用領域に書き込み権限でマッピングできません: ID={}", id);
            return None;
        }

        // プロセスのページテーブルを取得
        let page_table = process.get_page_table();
        let process_id = process.get_id();

        // 仮想アドレスが指定されていない場合は自動割り当て
        let mapped_vaddr = if let Some(addr) = vaddr {
            addr
        } else {
            // 適切なサイズの空き領域を探す
            let vma_size = region.size;
            let alignment = region.page_size as usize;
            
            match vma_api::find_free_region(page_table, vma_size, alignment) {
                Some(addr) => addr,
                None => {
                    error!("テレポート: プロセス{}の空き領域が見つかりません", process_id);
                    return None;
                }
            }
        };

        // VMAを作成
        let vma = VirtualMemoryArea {
            range: mapped_vaddr..(mapped_vaddr + region.size),
            physical_mapping: None, // 物理ページは直接マッピングするので不要
            vma_type: VmaType::Shared,
            permissions: permission.to_mmu_flags(),
            cache_policy: region.cache_policy,
            file_descriptor: None,
            file_offset: 0,
            name: Some(format!("teleport:{}", region.name)),
        };

        // VMAをページテーブルに追加
        if !vma_api::add_vma(page_table, vma) {
            error!("テレポート: VMAの追加に失敗しました: プロセス={}, ID={}", process_id, id);
            return None;
        }

        // 物理ページをマッピング
        let mmu_flags = permission.to_mmu_flags();
        let page_size = region.page_size;
        let page_size_bytes = page_size as usize;
        
        for (i, &physical_addr) in region.physical_pages.iter().enumerate() {
            let page_vaddr = mapped_vaddr + (i * page_size_bytes);
            
            if !paging::map_pages(
                page_table.get_root(),
                page_vaddr,
                physical_addr,
                1,
                page_size,
                mmu_flags,
            ) {
                error!("テレポート: ページマッピングに失敗: プロセス={}, ID={}, ページ={}", 
                      process_id, id, i);
                
                // 失敗した場合はマッピング解除
                self.unmap_from_process(id, process);
                return None;
            }
        }

        // マッピング情報を保存
        let mapping = TeleportMapping {
            teleport_id: id,
            process_id,
            virtual_address: mapped_vaddr,
            permission,
        };
        
        // プロセスのマッピングリストを取得または作成
        let process_mappings = self.process_mappings
            .entry(process_id)
            .or_insert_with(Vec::new);
        
        process_mappings.push(mapping);
        
        // 使用カウントを増加
        region.usage_count += 1;
        
        info!("テレポート: 領域をマッピング: プロセス={}, ID={}, 名前={}, アドレス={:#x}", 
             process_id, id, region.name, mapped_vaddr);
        
        Some(mapped_vaddr)
    }

    /// プロセスからテレポート領域のマッピングを解除
    fn unmap_from_process(&mut self, id: TeleportId, process: &Process) -> bool {
        let process_id = process.get_id();
        
        // プロセスのマッピングリストを取得
        let process_mappings = match self.process_mappings.get_mut(&process_id) {
            Some(m) => m,
            None => {
                warn!("テレポート: プロセスにマッピングがありません: プロセス={}", process_id);
                return false;
            }
        };
        
        // マッピングを検索
        let mapping_index = process_mappings.iter().position(|m| m.teleport_id == id);
        
        if let Some(index) = mapping_index {
            let mapping = &process_mappings[index];
            let virtual_address = mapping.virtual_address;
            
            // 領域情報を取得
            let region = match self.regions.get_mut(&id) {
                Some(r) => r,
                None => {
                    warn!("テレポート: 無効なIDが指定されました: {}", id);
                    return false;
                }
            };
            
            // ページテーブルからVMAを削除
            let page_table = process.get_page_table();
            if !vma_api::remove_vma(page_table, virtual_address) {
                warn!("テレポート: VMAの削除に失敗: プロセス={}, ID={}", process_id, id);
                // 続行（可能な限り解放を試みる）
            }
            
            // 物理マッピングを解除
            let page_size = region.page_size;
            let num_pages = region.physical_pages.len();
            
            if !paging::unmap_pages(
                page_table.get_root(),
                virtual_address,
                num_pages,
                page_size
            ) {
                warn!("テレポート: マッピング解除に失敗: プロセス={}, ID={}", process_id, id);
                // 続行（可能な限り解放を試みる）
            }
            
            // マッピングリストから削除
            process_mappings.remove(index);
            
            // マッピングリストが空になった場合はエントリを削除
            if process_mappings.is_empty() {
                self.process_mappings.remove(&process_id);
            }
            
            // 使用カウントを減少
            region.usage_count -= 1;
            
            info!("テレポート: マッピング解除: プロセス={}, ID={}, 名前={}, アドレス={:#x}", 
                 process_id, id, region.name, virtual_address);
            
            true
        } else {
            warn!("テレポート: プロセスに指定されたマッピングがありません: プロセス={}, ID={}", 
                 process_id, id);
            false
        }
    }

    /// プロセス終了時の処理
    fn handle_process_exit(&mut self, process_id: usize) {
        // プロセスのマッピングリストを取得
        if let Some(mappings) = self.process_mappings.remove(&process_id) {
            // このプロセスの全てのマッピングを解除
            for mapping in mappings.iter() {
                let id = mapping.teleport_id;
                
                // 領域情報を取得
                if let Some(region) = self.regions.get_mut(&id) {
                    // 使用カウントを減少
                    region.usage_count -= 1;
                    
                    info!("テレポート: プロセス終了によるマッピング解除: プロセス={}, ID={}, 名前={}", 
                         process_id, id, region.name);
                }
            }
            
            info!("テレポート: プロセスの全マッピングを解除: プロセス={}, マッピング数={}", 
                 process_id, mappings.len());
        }
    }
    
    /// 全てのテレポート領域と使用状況を表示（デバッグ用）
    fn dump_regions(&self) {
        info!("=== テレポート領域リスト ===");
        info!("登録領域数: {}", self.regions.len());
        
        for (id, region) in self.regions.iter() {
            info!("  ID={}, 名前={}, サイズ={}KB, 権限={:?}, 使用数={}", 
                 id, region.name, region.size / 1024, region.permission, region.usage_count);
        }
        
        info!("プロセスマッピング数: {}", self.process_mappings.len());
        
        for (process_id, mappings) in self.process_mappings.iter() {
            info!("  プロセス={}, マッピング数={}", process_id, mappings.len());
            for (i, mapping) in mappings.iter().enumerate() {
                info!("    #{}: ID={}, アドレス={:#x}, 権限={:?}", 
                     i, mapping.teleport_id, mapping.virtual_address, mapping.permission);
            }
        }
        
        info!("=============================");
    }
}

/// テレポートサブシステムの初期化
pub fn init() {
    info!("テレポートメモリマネージャーを初期化中");
    
    // グローバルインスタンスを初期化
    TELEPORT_MANAGER.call_once(|| {
        Mutex::new(TeleportManager::new())
    });
    
    info!("テレポートメモリマネージャーの初期化が完了しました");
}

// 公開API

/// 新しいテレポート領域を作成
///
/// # 引数
/// * `name` - 領域の名前（識別用）
/// * `size` - 領域のサイズ（バイト）
/// * `permission` - アクセス権限
/// * `cache_policy` - キャッシュポリシー
///
/// # 戻り値
/// * 作成に成功した場合はテレポートID、失敗した場合は `None`
pub fn create_teleport(
    name: &str,
    size: usize,
    permission: TeleportPermission,
    cache_policy: CachePolicy,
) -> Option<TeleportId> {
    let mut manager = TELEPORT_MANAGER.get().unwrap().lock();
    manager.create_region(name, size, permission, cache_policy)
}

/// テレポート領域を削除
///
/// # 引数
/// * `id` - 削除するテレポートID
///
/// # 戻り値
/// * 削除に成功した場合は `true`、失敗した場合は `false`
pub fn delete_teleport(id: TeleportId) -> bool {
    let mut manager = TELEPORT_MANAGER.get().unwrap().lock();
    manager.delete_region(id)
}

/// プロセスにテレポート領域をマッピング
///
/// # 引数
/// * `id` - マッピングするテレポートID
/// * `process` - マッピング先のプロセス
/// * `vaddr` - マッピング先の仮想アドレス（None の場合は自動割り当て）
/// * `permission` - アクセス権限
///
/// # 戻り値
/// * マッピングに成功した場合は仮想アドレス、失敗した場合は `None`
pub fn map_teleport(
    id: TeleportId,
    process: &Process,
    vaddr: Option<VirtualAddress>,
    permission: TeleportPermission,
) -> Option<VirtualAddress> {
    let mut manager = TELEPORT_MANAGER.get().unwrap().lock();
    manager.map_to_process(id, process, vaddr, permission)
}

/// プロセスからテレポート領域のマッピングを解除
///
/// # 引数
/// * `id` - 解除するテレポートID
/// * `process` - 対象プロセス
///
/// # 戻り値
/// * 解除に成功した場合は `true`、失敗した場合は `false`
pub fn unmap_teleport(id: TeleportId, process: &Process) -> bool {
    let mut manager = TELEPORT_MANAGER.get().unwrap().lock();
    manager.unmap_from_process(id, process)
}

/// プロセス終了時の処理
///
/// # 引数
/// * `process_id` - 終了したプロセスID
pub fn handle_process_exit(process_id: usize) {
    let mut manager = TELEPORT_MANAGER.get().unwrap().lock();
    manager.handle_process_exit(process_id);
}

/// 全てのテレポート領域と使用状況を表示（デバッグ用）
pub fn dump_teleport_regions() {
    let manager = TELEPORT_MANAGER.get().unwrap().lock();
    manager.dump_regions();
}

/// テレポートIDから領域名を取得
pub fn get_teleport_name(id: TeleportId) -> Option<String> {
    let manager = TELEPORT_MANAGER.get().unwrap().lock();
    manager.regions.get(&id).map(|r| r.name.clone())
}

/// テレポートIDから領域サイズを取得
pub fn get_teleport_size(id: TeleportId) -> Option<usize> {
    let manager = TELEPORT_MANAGER.get().unwrap().lock();
    manager.regions.get(&id).map(|r| r.size)
}

/// テレポートIDから使用数を取得
pub fn get_teleport_usage_count(id: TeleportId) -> Option<usize> {
    let manager = TELEPORT_MANAGER.get().unwrap().lock();
    manager.regions.get(&id).map(|r| r.usage_count)
} 