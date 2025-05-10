// AetherOS ゼロコピーデータ転送モジュール
//
// このモジュールは、カーネルとユーザー空間間のデータコピーを最小限に抑えるための
// ゼロコピー転送機能を提供します。ページマッピングを活用することで、
// CPUを介したコピーを回避し、DMAなどの高速転送にも対応します。

use crate::arch::{PhysicalAddress, VirtualAddress, PAGE_SIZE};
use crate::core::memory::mm::page::api as page_api;
use crate::core::memory::mm::paging;
use crate::core::memory::mm::{PageTable, VmaType, VirtualMemoryArea, CachePolicy};
use crate::core::memory::mm::vma::api as vma_api;
use crate::core::process::Process;
use crate::error::{Error, Result};
use crate::sync::Mutex;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use core::mem::size_of;
use log::{debug, error, info, warn};
use spin::Once;

/// ゼロコピー転送マネージャー
static ZEROCOPY_MANAGER: Once<Mutex<ZeroCopyManager>> = Once::new();

/// ゼロコピー転送の識別子
type ZeroCopyId = u64;

/// ゼロコピー転送バッファの最大サイズ（32MB）
const MAX_ZEROCOPY_SIZE: usize = 32 * 1024 * 1024;

/// ゼロコピーバッファのアラインメント（通常はページサイズに合わせる）
const ZEROCOPY_ALIGNMENT: usize = PAGE_SIZE;

/// ゼロコピー転送の方向
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroCopyDirection {
    /// カーネルからユーザー空間へ
    KernelToUser,
    /// ユーザー空間からカーネルへ
    UserToKernel,
    /// 双方向（読み書き）
    Bidirectional,
}

/// ゼロコピー転送バッファ
#[derive(Debug)]
struct ZeroCopyBuffer {
    /// バッファID
    id: ZeroCopyId,
    /// 物理ページのリスト
    physical_pages: Vec<PhysicalAddress>,
    /// バッファサイズ
    size: usize,
    /// バッファ名（デバッグ用）
    name: String,
    /// 転送方向
    direction: ZeroCopyDirection,
    /// カーネル側の仮想アドレス
    kernel_vaddr: Option<VirtualAddress>,
    /// ユーザー側の仮想アドレス
    user_vaddr: Option<VirtualAddress>,
    /// 関連付けられたプロセスID
    process_id: Option<usize>,
    /// キャッシュポリシー
    cache_policy: CachePolicy,
}

/// ゼロコピーマネージャー
struct ZeroCopyManager {
    /// 次に割り当てるバッファID
    next_id: ZeroCopyId,
    /// 全バッファのマップ
    buffers: BTreeMap<ZeroCopyId, ZeroCopyBuffer>,
    /// プロセスごとのバッファIDリスト
    process_buffers: BTreeMap<usize, Vec<ZeroCopyId>>,
}

impl ZeroCopyManager {
    /// 新しいゼロコピーマネージャーを作成
    fn new() -> Self {
        ZeroCopyManager {
            next_id: 1,
            buffers: BTreeMap::new(),
            process_buffers: BTreeMap::new(),
        }
    }

    /// 新しいゼロコピーバッファを作成
    fn create_buffer(
        &mut self,
        size: usize,
        name: &str,
        direction: ZeroCopyDirection,
        cache_policy: CachePolicy,
    ) -> Result<ZeroCopyId> {
        // サイズバリデーション
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        
        if size > MAX_ZEROCOPY_SIZE {
            return Err(Error::OutOfMemory);
        }
        
        // ページサイズにアラインメント
        let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let num_pages = aligned_size / PAGE_SIZE;
        
        // 物理ページを割り当て
        let mut physical_pages = Vec::with_capacity(num_pages);
        for _ in 0..num_pages {
            if let Some(page) = page_api::alloc_pages(1) {
                physical_pages.push(page);
            } else {
                // 割り当て失敗、確保済みのページを解放
                for page in physical_pages.iter() {
                    page_api::free_pages(*page, 1);
                }
                return Err(Error::OutOfMemory);
            }
        }
        
        // バッファIDを割り当て
        let id = self.next_id;
        self.next_id += 1;
        
        // バッファオブジェクトを作成
        let buffer = ZeroCopyBuffer {
            id,
            physical_pages,
            size: aligned_size,
            name: name.to_string(),
            direction,
            kernel_vaddr: None,
            user_vaddr: None,
            process_id: None,
            cache_policy,
        };
        
        // バッファを保存
        self.buffers.insert(id, buffer);
        
        info!("ゼロコピー: バッファを作成: ID={}, 名前={}, サイズ={}KB",
             id, name, aligned_size / 1024);
        
        Ok(id)
    }
    
    /// ゼロコピーバッファをカーネル空間にマッピング
    fn map_to_kernel(&mut self, id: ZeroCopyId) -> Result<VirtualAddress> {
        // バッファ情報を取得
        let buffer = match self.buffers.get_mut(&id) {
            Some(b) => b,
            None => return Err(Error::InvalidArgument),
        };
        
        // すでにマッピング済みの場合はそのアドレスを返す
        if let Some(vaddr) = buffer.kernel_vaddr {
            return Ok(vaddr);
        }
        
        // カーネルページテーブルを取得
        let kernel_page_table = PageTable::get_kernel_table();
        
        // MMUフラグを設定（常に読み書き可能）
        let mmu_flags = 0x3; // 読み書き
        
        // 連続した物理ページを一時的な仮想アドレスにマッピング
        let size = buffer.size;
        let vaddr = match vma_api::find_free_region(kernel_page_table, size, ZEROCOPY_ALIGNMENT) {
            Some(addr) => addr,
            None => return Err(Error::OutOfMemory),
        };
        
        // VMAを作成
        let vma = VirtualMemoryArea {
            range: vaddr..(vaddr + size),
            physical_mapping: None, // 物理ページは直接マッピングするので不要
            vma_type: VmaType::KernelMapped,
            permissions: mmu_flags,
            cache_policy: buffer.cache_policy,
            file_descriptor: None,
            file_offset: 0,
            name: Some(format!("zerocopy:{}", buffer.name)),
        };
        
        // VMAをページテーブルに追加
        if !vma_api::add_vma(kernel_page_table, vma) {
            return Err(Error::OutOfMemory);
        }
        
        // 物理ページをマッピング
        for (i, &phys_addr) in buffer.physical_pages.iter().enumerate() {
            let page_vaddr = vaddr + (i * PAGE_SIZE);
            
            if !paging::map_page(
                kernel_page_table.get_root(),
                page_vaddr,
                phys_addr,
                mmu_flags,
            ) {
                // マッピング失敗、ここまでのマッピングを解除
                paging::unmap_pages(
                    kernel_page_table.get_root(),
                    vaddr,
                    i,
                    PAGE_SIZE,
                );
                
                vma_api::remove_vma(kernel_page_table, vaddr);
                return Err(Error::MemoryMapFailed);
            }
        }
        
        // カーネル仮想アドレスを保存
        buffer.kernel_vaddr = Some(vaddr);
        
        debug!("ゼロコピー: カーネルにマッピング: ID={}, アドレス={:#x}", id, vaddr);
        
        Ok(vaddr)
    }
    
    /// ゼロコピーバッファをユーザープロセスにマッピング
    fn map_to_user(
        &mut self,
        id: ZeroCopyId,
        process: &Process,
        vaddr: Option<VirtualAddress>,
    ) -> Result<VirtualAddress> {
        // バッファ情報を取得
        let buffer = match self.buffers.get_mut(&id) {
            Some(b) => b,
            None => return Err(Error::InvalidArgument),
        };
        
        // すでに別のプロセスにマッピングされている場合はエラー
        if let Some(pid) = buffer.process_id {
            if pid != process.get_id() {
                return Err(Error::PermissionDenied);
            }
        }
        
        // プロセスのページテーブルを取得
        let process_id = process.get_id();
        let page_table = process.get_page_table();
        
        // MMUフラグを設定（転送方向に基づく）
        let mmu_flags = match buffer.direction {
            ZeroCopyDirection::KernelToUser => 0x1,      // 読み取りのみ
            ZeroCopyDirection::UserToKernel => 0x2,      // 書き込みのみ
            ZeroCopyDirection::Bidirectional => 0x3,     // 読み書き
        };
        
        // 仮想アドレスが指定されていない場合は自動割り当て
        let size = buffer.size;
        let user_vaddr = if let Some(addr) = vaddr {
            addr
        } else {
            match vma_api::find_free_region(page_table, size, ZEROCOPY_ALIGNMENT) {
                Some(addr) => addr,
                None => return Err(Error::OutOfMemory),
            }
        };
        
        // VMAを作成
        let vma = VirtualMemoryArea {
            range: user_vaddr..(user_vaddr + size),
            physical_mapping: None, // 物理ページは直接マッピングするので不要
            vma_type: VmaType::DeviceMapping,
            permissions: mmu_flags,
            cache_policy: buffer.cache_policy,
            file_descriptor: None,
            file_offset: 0,
            name: Some(format!("zerocopy:{}", buffer.name)),
        };
        
        // VMAをページテーブルに追加
        if !vma_api::add_vma(page_table, vma) {
            return Err(Error::OutOfMemory);
        }
        
        // 物理ページをマッピング
        for (i, &phys_addr) in buffer.physical_pages.iter().enumerate() {
            let page_vaddr = user_vaddr + (i * PAGE_SIZE);
            
            if !paging::map_page(
                page_table.get_root(),
                page_vaddr,
                phys_addr,
                mmu_flags,
            ) {
                // マッピング失敗、ここまでのマッピングを解除
                paging::unmap_pages(
                    page_table.get_root(),
                    user_vaddr,
                    i,
                    PAGE_SIZE,
                );
                
                vma_api::remove_vma(page_table, user_vaddr);
                return Err(Error::MemoryMapFailed);
            }
        }
        
        // ユーザー仮想アドレスとプロセスIDを保存
        buffer.user_vaddr = Some(user_vaddr);
        buffer.process_id = Some(process_id);
        
        // プロセスのバッファリストに追加
        let process_buffers = self.process_buffers
            .entry(process_id)
            .or_insert_with(Vec::new);
        
        if !process_buffers.contains(&id) {
            process_buffers.push(id);
        }
        
        info!("ゼロコピー: ユーザーにマッピング: ID={}, プロセス={}, アドレス={:#x}",
             id, process_id, user_vaddr);
        
        Ok(user_vaddr)
    }
    
    /// ゼロコピーバッファをユーザープロセスからアンマッピング
    fn unmap_from_user(&mut self, id: ZeroCopyId, process: &Process) -> Result<()> {
        // バッファ情報を取得
        let buffer = match self.buffers.get_mut(&id) {
            Some(b) => b,
            None => return Err(Error::InvalidArgument),
        };
        
        // プロセスIDとユーザー仮想アドレスをチェック
        let process_id = process.get_id();
        
        match (buffer.process_id, buffer.user_vaddr) {
            (Some(pid), Some(vaddr)) if pid == process_id => {
                // ページテーブルを取得
                let page_table = process.get_page_table();
                
                // VMAを削除
                if !vma_api::remove_vma(page_table, vaddr) {
                    warn!("ゼロコピー: VMA削除失敗: ID={}, プロセス={}", id, process_id);
                    // 続行
                }
                
                // ページをアンマッピング
                let num_pages = buffer.physical_pages.len();
                
                if !paging::unmap_pages(
                    page_table.get_root(),
                    vaddr,
                    num_pages,
                    PAGE_SIZE,
                ) {
                    warn!("ゼロコピー: ページアンマッピング失敗: ID={}, プロセス={}", id, process_id);
                    // 続行
                }
                
                // バッファ情報をクリア
                buffer.user_vaddr = None;
                buffer.process_id = None;
                
                // プロセスのバッファリストから削除
                if let Some(buffers) = self.process_buffers.get_mut(&process_id) {
                    if let Some(pos) = buffers.iter().position(|&b| b == id) {
                        buffers.remove(pos);
                    }
                    
                    // リストが空になった場合はエントリを削除
                    if buffers.is_empty() {
                        self.process_buffers.remove(&process_id);
                    }
                }
                
                info!("ゼロコピー: ユーザーからアンマッピング: ID={}, プロセス={}", id, process_id);
                
                Ok(())
            },
            _ => {
                warn!("ゼロコピー: 無効なプロセスまたはマッピングなし: ID={}, プロセス={}", id, process_id);
                Err(Error::InvalidArgument)
            }
        }
    }
    
    /// ゼロコピーバッファをカーネルからアンマッピング
    fn unmap_from_kernel(&mut self, id: ZeroCopyId) -> Result<()> {
        // バッファ情報を取得
        let buffer = match self.buffers.get_mut(&id) {
            Some(b) => b,
            None => return Err(Error::InvalidArgument),
        };
        
        // カーネル仮想アドレスをチェック
        if let Some(vaddr) = buffer.kernel_vaddr {
            // カーネルページテーブルを取得
            let kernel_page_table = PageTable::get_kernel_table();
            
            // VMAを削除
            if !vma_api::remove_vma(kernel_page_table, vaddr) {
                warn!("ゼロコピー: カーネルVMA削除失敗: ID={}", id);
                // 続行
            }
            
            // ページをアンマッピング
            let num_pages = buffer.physical_pages.len();
            
            if !paging::unmap_pages(
                kernel_page_table.get_root(),
                vaddr,
                num_pages,
                PAGE_SIZE,
            ) {
                warn!("ゼロコピー: カーネルページアンマッピング失敗: ID={}", id);
                // 続行
            }
            
            // カーネル仮想アドレスをクリア
            buffer.kernel_vaddr = None;
            
            debug!("ゼロコピー: カーネルからアンマッピング: ID={}", id);
            
            Ok(())
        } else {
            warn!("ゼロコピー: カーネルマッピングなし: ID={}", id);
            Err(Error::InvalidArgument)
        }
    }
    
    /// ゼロコピーバッファを削除
    fn destroy_buffer(&mut self, id: ZeroCopyId) -> Result<()> {
        // バッファ情報を取得
        let buffer = match self.buffers.remove(&id) {
            Some(b) => b,
            None => return Err(Error::InvalidArgument),
        };
        
        // ユーザー空間にマッピングされている場合はエラー
        if buffer.process_id.is_some() {
            warn!("ゼロコピー: ユーザーマッピング中のバッファは削除できません: ID={}", id);
            // バッファ情報を戻す
            self.buffers.insert(id, buffer);
            return Err(Error::ResourceBusy);
        }
        
        // カーネル空間にマッピングされている場合はアンマッピング
        if buffer.kernel_vaddr.is_some() {
            // エラーは無視してできる限り解放する
            let _ = self.unmap_from_kernel(id);
            // バッファはすでにremoveしているので、再挿入
            self.buffers.insert(id, buffer);
            // 再度取得
            let buffer = self.buffers.remove(&id).unwrap();
        }
        
        // 物理ページを解放
        for page in buffer.physical_pages.iter() {
            page_api::free_pages(*page, 1);
        }
        
        info!("ゼロコピー: バッファを削除: ID={}, 名前={}", id, buffer.name);
        
        Ok(())
    }
    
    /// プロセス終了時の処理
    fn handle_process_exit(&mut self, process_id: usize) {
        // プロセスのバッファリストを取得
        if let Some(buffer_ids) = self.process_buffers.remove(&process_id) {
            info!("ゼロコピー: プロセス終了処理: プロセス={}, バッファ数={}", process_id, buffer_ids.len());
            
            // 各バッファのユーザーマッピング情報をクリア
            for id in buffer_ids.iter() {
                if let Some(buffer) = self.buffers.get_mut(id) {
                    buffer.user_vaddr = None;
                    buffer.process_id = None;
                    
                    debug!("ゼロコピー: プロセス終了によりマッピング解除: ID={}", *id);
                }
            }
        }
    }
    
    /// バッファ情報をダンプ（デバッグ用）
    fn dump_buffers(&self) {
        info!("=== ゼロコピーバッファリスト ===");
        info!("バッファ数: {}", self.buffers.len());
        
        for (id, buffer) in self.buffers.iter() {
            info!("  ID={}, 名前={}, サイズ={}KB, 方向={:?}, キャッシュ={:?}",
                 id, buffer.name, buffer.size / 1024, buffer.direction, buffer.cache_policy);
            
            if let Some(kernel_vaddr) = buffer.kernel_vaddr {
                info!("    カーネルマッピング: {:#x}", kernel_vaddr);
            }
            
            if let (Some(process_id), Some(user_vaddr)) = (buffer.process_id, buffer.user_vaddr) {
                info!("    ユーザーマッピング: プロセス={}, アドレス={:#x}", process_id, user_vaddr);
            }
        }
        
        info!("プロセスバッファマップ:");
        for (pid, buffers) in self.process_buffers.iter() {
            info!("  プロセス={}, バッファ数={}: {:?}", pid, buffers.len(), buffers);
        }
        
        info!("================================");
    }
}

/// ゼロコピーサブシステムの初期化
pub fn init() {
    info!("ゼロコピーマネージャーを初期化中");
    
    // グローバルインスタンスを初期化
    ZEROCOPY_MANAGER.call_once(|| {
        Mutex::new(ZeroCopyManager::new())
    });
    
    info!("ゼロコピーマネージャーの初期化が完了しました");
}

// 公開API

/// 新しいゼロコピーバッファを作成
///
/// # 引数
/// * `size` - バッファのサイズ（バイト単位）
/// * `name` - バッファの名前（デバッグ用）
/// * `direction` - データ転送の方向
/// * `cache_policy` - キャッシュポリシー
///
/// # 戻り値
/// * 成功した場合はバッファID、失敗した場合はエラー
pub fn create_buffer(
    size: usize,
    name: &str,
    direction: ZeroCopyDirection,
    cache_policy: CachePolicy,
) -> Result<ZeroCopyId> {
    let mut manager = ZEROCOPY_MANAGER.get().unwrap().lock();
    manager.create_buffer(size, name, direction, cache_policy)
}

/// ゼロコピーバッファを削除
///
/// # 引数
/// * `id` - 削除するバッファID
///
/// # 戻り値
/// * 成功した場合は`Ok(())`、失敗した場合はエラー
pub fn destroy_buffer(id: ZeroCopyId) -> Result<()> {
    let mut manager = ZEROCOPY_MANAGER.get().unwrap().lock();
    manager.destroy_buffer(id)
}

/// ゼロコピーバッファをカーネル空間にマッピング
///
/// # 引数
/// * `id` - マッピングするバッファID
///
/// # 戻り値
/// * 成功した場合はカーネル仮想アドレス、失敗した場合はエラー
pub fn map_to_kernel(id: ZeroCopyId) -> Result<VirtualAddress> {
    let mut manager = ZEROCOPY_MANAGER.get().unwrap().lock();
    manager.map_to_kernel(id)
}

/// ゼロコピーバッファをユーザープロセスにマッピング
///
/// # 引数
/// * `id` - マッピングするバッファID
/// * `process` - マッピング先のプロセス
/// * `vaddr` - マッピング先の仮想アドレス（Noneの場合は自動割り当て）
///
/// # 戻り値
/// * 成功した場合はユーザー仮想アドレス、失敗した場合はエラー
pub fn map_to_user(
    id: ZeroCopyId,
    process: &Process,
    vaddr: Option<VirtualAddress>,
) -> Result<VirtualAddress> {
    let mut manager = ZEROCOPY_MANAGER.get().unwrap().lock();
    manager.map_to_user(id, process, vaddr)
}

/// ゼロコピーバッファをカーネルからアンマッピング
///
/// # 引数
/// * `id` - アンマッピングするバッファID
///
/// # 戻り値
/// * 成功した場合は`Ok(())`、失敗した場合はエラー
pub fn unmap_from_kernel(id: ZeroCopyId) -> Result<()> {
    let mut manager = ZEROCOPY_MANAGER.get().unwrap().lock();
    manager.unmap_from_kernel(id)
}

/// ゼロコピーバッファをユーザープロセスからアンマッピング
///
/// # 引数
/// * `id` - アンマッピングするバッファID
/// * `process` - プロセス
///
/// # 戻り値
/// * 成功した場合は`Ok(())`、失敗した場合はエラー
pub fn unmap_from_user(id: ZeroCopyId, process: &Process) -> Result<()> {
    let mut manager = ZEROCOPY_MANAGER.get().unwrap().lock();
    manager.unmap_from_user(id, process)
}

/// プロセス終了時の処理
///
/// # 引数
/// * `process_id` - 終了したプロセスID
pub fn handle_process_exit(process_id: usize) {
    let mut manager = ZEROCOPY_MANAGER.get().unwrap().lock();
    manager.handle_process_exit(process_id);
}

/// バッファ情報をダンプ（デバッグ用）
pub fn dump_buffers() {
    let manager = ZEROCOPY_MANAGER.get().unwrap().lock();
    manager.dump_buffers();
}

/// カーネルとの間でデータをコピー（ヘルパー関数）
///
/// # 引数
/// * `id` - バッファID
/// * `data` - コピーするデータへの参照またはポインタ
/// * `size` - コピーするサイズ（バイト単位）
/// * `offset` - バッファ内のオフセット
/// * `is_write` - trueの場合はバッファに書き込み、falseの場合はバッファから読み込み
///
/// # 戻り値
/// * 成功した場合はコピーしたバイト数、失敗した場合はエラー
pub fn copy_data<T>(
    id: ZeroCopyId,
    data: *const T,
    size: usize,
    offset: usize,
    is_write: bool,
) -> Result<usize> {
    // ゼロコピーバッファをカーネルにマッピング
    let vaddr = map_to_kernel(id)?;
    
    // バッファ情報を取得
    let manager = ZEROCOPY_MANAGER.get().unwrap().lock();
    let buffer = match manager.buffers.get(&id) {
        Some(b) => b,
        None => return Err(Error::InvalidArgument),
    };
    
    // オフセットとサイズの検証
    if offset >= buffer.size {
        return Err(Error::InvalidArgument);
    }
    
    let max_size = buffer.size - offset;
    let copy_size = size.min(max_size);
    
    // 実際のコピー操作
    unsafe {
        let buffer_ptr = (vaddr + offset) as *mut u8;
        let data_ptr = data as *const u8;
        
        if is_write {
            // データからバッファへ
            core::ptr::copy_nonoverlapping(data_ptr, buffer_ptr, copy_size);
        } else {
            // バッファからデータへ
            core::ptr::copy_nonoverlapping(buffer_ptr, data_ptr as *mut u8, copy_size);
        }
    }
    
    // ドロップ（自動アンマップはしない）
    drop(manager);
    
    Ok(copy_size)
}

/// バッファに書き込み
///
/// # 引数
/// * `id` - バッファID
/// * `data` - 書き込むデータへの参照
/// * `size` - 書き込むサイズ（バイト単位）
/// * `offset` - バッファ内のオフセット
///
/// # 戻り値
/// * 成功した場合は書き込んだバイト数、失敗した場合はエラー
pub fn write_to_buffer<T>(
    id: ZeroCopyId,
    data: *const T,
    size: usize,
    offset: usize,
) -> Result<usize> {
    copy_data(id, data, size, offset, true)
}

/// バッファから読み込み
///
/// # 引数
/// * `id` - バッファID
/// * `data` - 読み込み先バッファへの参照
/// * `size` - 読み込むサイズ（バイト単位）
/// * `offset` - バッファ内のオフセット
///
/// # 戻り値
/// * 成功した場合は読み込んだバイト数、失敗した場合はエラー
pub fn read_from_buffer<T>(
    id: ZeroCopyId,
    data: *mut T,
    size: usize,
    offset: usize,
) -> Result<usize> {
    copy_data(id, data as *const T, size, offset, false)
}

/// ゼロコピーバッファをゼロクリア
///
/// # 引数
/// * `id` - ゼロクリアするバッファID
///
/// # 戻り値
/// * 成功した場合は`Ok(())`、失敗した場合はエラー
pub fn clear_buffer(id: ZeroCopyId) -> Result<()> {
    // ゼロコピーバッファをカーネルにマッピング
    let vaddr = map_to_kernel(id)?;
    
    // バッファ情報を取得
    let manager = ZEROCOPY_MANAGER.get().unwrap().lock();
    let buffer = match manager.buffers.get(&id) {
        Some(b) => b,
        None => return Err(Error::InvalidArgument),
    };
    
    // バッファをゼロクリア
    unsafe {
        let buffer_ptr = vaddr as *mut u8;
        for i in 0..buffer.size {
            buffer_ptr.add(i).write_volatile(0);
        }
    }
    
    // ドロップ（自動アンマップはしない）
    drop(manager);
    
    Ok(())
} 