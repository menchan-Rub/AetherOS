use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::ops::Range;

use crate::arch::mmu::{PageTable, PageTableFlags, PAGE_SIZE};
use crate::core::memory::mm::page::{PhysAddr, VirtAddr, PageAllocator, AllocFlags};
use crate::core::memory::mm::vma::{VmaManager, Vma, VmaPerm, VmaType};
use crate::core::sync::mutex::Mutex;
use crate::core::sync::rwlock::RwLock;

/// テレページエラー
#[derive(Debug)]
pub enum TelePageError {
    /// メモリ不足
    OutOfMemory,
    /// 無効なサイズ
    InvalidSize,
    /// アライメントエラー
    AlignmentError,
    /// VMAエラー
    VmaError,
    /// ページテーブルエラー
    PageTableError,
    /// リモートノードが見つからない
    NodeNotFound,
    /// リモートノードが応答しない
    NodeNotResponding,
    /// リモートメモリにアクセスできない
    RemoteMemoryAccessError,
    /// その他のエラー
    Other(&'static str),
}

/// テレページディスクリプタ
/// リモートメモリへの参照を保持する
#[derive(Debug, Clone)]
pub struct TelePageDescriptor {
    /// リモートノードID
    pub node_id: usize,
    /// リモートノード上の物理アドレス
    pub remote_phys_addr: PhysAddr,
    /// マッピングされたローカルの仮想アドレス
    pub local_virt_addr: VirtAddr,
    /// テレページのサイズ
    pub size: usize,
    /// アクセス権限
    pub perm: VmaPerm,
    /// 最後のアクセス時間（ティック数）
    pub last_access: AtomicUsize,
    /// アクセスカウント
    pub access_count: AtomicUsize,
}

impl TelePageDescriptor {
    /// 新しいテレページディスクリプタを作成
    pub fn new(
        node_id: usize,
        remote_phys_addr: PhysAddr,
        local_virt_addr: VirtAddr,
        size: usize,
        perm: VmaPerm,
    ) -> Self {
        Self {
            node_id,
            remote_phys_addr,
            local_virt_addr,
            size,
            perm,
            last_access: AtomicUsize::new(0),
            access_count: AtomicUsize::new(0),
        }
    }

    /// アクセス時間を更新
    pub fn update_access(&self, current_tick: usize) {
        self.last_access.store(current_tick, Ordering::SeqCst);
        self.access_count.fetch_add(1, Ordering::SeqCst);
    }

    /// テレページのフルサイズを取得
    pub fn get_full_size(&self) -> usize {
        self.size
    }
}

/// テレページマネージャ
#[derive(Debug)]
pub struct TelePageManager {
    /// テレページディスクリプタリスト
    descriptors: Vec<TelePageDescriptor>,
    /// 現在のティック数
    current_tick: AtomicUsize,
    /// テレページアクセスのためのロック
    access_lock: RwLock<()>,
}

impl TelePageManager {
    /// 新しいテレページマネージャを作成
    pub fn new() -> Self {
        Self {
            descriptors: Vec::new(),
            current_tick: AtomicUsize::new(0),
            access_lock: RwLock::new(()),
        }
    }

    /// ティックを更新
    pub fn tick(&self) {
        self.current_tick.fetch_add(1, Ordering::SeqCst);
    }

    /// リモートメモリをマップ
    pub fn map_remote_memory(
        &mut self,
        node_id: usize,
        remote_phys_addr: PhysAddr,
        size: usize,
        perm: VmaPerm,
        page_table: &mut PageTable,
        vma_manager: &mut VmaManager,
    ) -> Result<VirtAddr, TelePageError> {
        // サイズチェック
        if size == 0 {
            return Err(TelePageError::InvalidSize);
        }

        // アライメントチェック
        if remote_phys_addr.as_usize() % PAGE_SIZE != 0 {
            return Err(TelePageError::AlignmentError);
        }

        // サイズをページサイズにアライン
        let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        // ノードとの接続を確立
        if !self.check_node_connectivity(node_id) {
            return Err(TelePageError::NodeNotFound);
        }

        // VMAを探してローカルの仮想アドレスを取得
        let local_virt_addr = self.find_free_vma_region(aligned_size, vma_manager)
            .ok_or(TelePageError::OutOfMemory)?;
        
        let local_end_addr = VirtAddr::new(local_virt_addr.as_usize() + aligned_size);

        // VMAを作成してマッピング
        let vma = Vma::new(
            local_virt_addr,
            local_end_addr,
            Some(remote_phys_addr),
            perm,
            VmaType::TelePage,
            Some(alloc::string::String::from("telepage")),
        );

        vma_manager.add_vma(vma)
            .map_err(|_| TelePageError::VmaError)?;

        // テレページディスクリプタを作成
        let descriptor = TelePageDescriptor::new(
            node_id,
            remote_phys_addr,
            local_virt_addr,
            aligned_size,
            perm,
        );

        // リモートメモリとの通信を設定
        self.setup_remote_memory_access(node_id, remote_phys_addr, local_virt_addr, aligned_size, page_table)
            .map_err(|_| TelePageError::RemoteMemoryAccessError)?;

        // ディスクリプタを保存
        self.descriptors.push(descriptor);

        Ok(local_virt_addr)
    }

    /// リモートメモリをアンマップ
    pub fn unmap_remote_memory(
        &mut self,
        local_virt_addr: VirtAddr,
        page_table: &mut PageTable,
        vma_manager: &mut VmaManager,
    ) -> Result<(), TelePageError> {
        // ディスクリプタを探して削除
        let idx = self.descriptors.iter().position(|desc| desc.local_virt_addr == local_virt_addr);
        
        if let Some(idx) = idx {
            let descriptor = self.descriptors.remove(idx);
            
            // VMAを検索して削除
            let vma_range = Range {
                start: descriptor.local_virt_addr,
                end: VirtAddr::new(descriptor.local_virt_addr.as_usize() + descriptor.size),
            };
            
            vma_manager.remove_vma(&vma_range)
                .map_err(|_| TelePageError::VmaError)?;
            
            // リモートメモリへのアクセスを解除
            self.teardown_remote_memory_access(
                descriptor.node_id,
                descriptor.remote_phys_addr,
                descriptor.local_virt_addr,
                descriptor.size,
                page_table,
            )?;
            
            Ok(())
        } else {
            Err(TelePageError::Other("Telepage mapping not found"))
        }
    }

    /// テレページオブジェクトに読み込みアクセス
    pub fn read<T>(&self, addr: VirtAddr) -> Result<T, TelePageError>
    where
        T: Copy,
    {
        let _guard = self.access_lock.read();
        
        // アドレスがテレページ内にあるか確認
        if let Some(descriptor) = self.find_descriptor_by_addr(addr) {
            // アクセス統計を更新
            descriptor.update_access(self.current_tick.load(Ordering::SeqCst));
            
            // メモリを読み込み
            let ptr = addr.as_usize() as *const T;
            let value = unsafe { *ptr };
            
            Ok(value)
        } else {
            Err(TelePageError::Other("Address not in telepage range"))
        }
    }

    /// テレページオブジェクトに書き込みアクセス
    pub fn write<T>(&self, addr: VirtAddr, value: T) -> Result<(), TelePageError>
    where
        T: Copy,
    {
        let _guard = self.access_lock.write();
        
        // アドレスがテレページ内にあるか確認
        if let Some(descriptor) = self.find_descriptor_by_addr(addr) {
            // 書き込み権限をチェック
            if !descriptor.perm.writable {
                return Err(TelePageError::Other("Write permission denied"));
            }
            
            // アクセス統計を更新
            descriptor.update_access(self.current_tick.load(Ordering::SeqCst));
            
            // メモリに書き込み
            let ptr = addr.as_usize() as *mut T;
            unsafe { *ptr = value };
            
            Ok(())
        } else {
            Err(TelePageError::Other("Address not in telepage range"))
        }
    }

    /// アドレスからディスクリプタを検索
    fn find_descriptor_by_addr(&self, addr: VirtAddr) -> Option<&TelePageDescriptor> {
        self.descriptors.iter().find(|desc| {
            let start = desc.local_virt_addr;
            let end = VirtAddr::new(start.as_usize() + desc.size);
            addr >= start && addr < end
        })
    }

    /// ノードの接続性を確認
    fn check_node_connectivity(&self, node_id: usize) -> bool {
        // 実装は実際のシステムによって異なります
        // ここではシミュレーションとしてノードIDが有効範囲内にあるかどうかをチェック
        node_id < 16 // 例: 最大16ノード
    }

    /// リモートメモリアクセスの設定
    fn setup_remote_memory_access(
        &self,
        node_id: usize,
        remote_phys_addr: PhysAddr,
        local_virt_addr: VirtAddr,
        size: usize,
        page_table: &mut PageTable,
    ) -> Result<(), TelePageError> {
        // 実際の実装はハードウェアとネットワークプロトコルに依存します
        // ここではシミュレーションとして、各テレページに対応するローカルページを割り当て
        
        let num_pages = size / PAGE_SIZE;
        let page_allocator = PageAllocator::get_instance();
        
        for i in 0..num_pages {
            let local_addr = VirtAddr::new(local_virt_addr.as_usize() + i * PAGE_SIZE);
            
            // テレページ用のローカルページを割り当て
            let phys_page = page_allocator.alloc_pages(1, AllocFlags::NONE)
                .ok_or(TelePageError::OutOfMemory)?;
                
            // 初期データをリモートから取得（シミュレーション）
            let remote_data = self.fetch_remote_page(
                node_id,
                PhysAddr::new(remote_phys_addr.as_usize() + i * PAGE_SIZE),
            )?;
            
            // ローカルページに初期データをコピー
            unsafe {
                let dest = phys_page.as_usize() as *mut u8;
                core::ptr::copy_nonoverlapping(remote_data.as_ptr(), dest, PAGE_SIZE);
            }
            
            // ページをマッピング
            page_table.map(
                local_addr,
                phys_page,
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::GLOBAL,
            ).map_err(|_| TelePageError::PageTableError)?;
        }
        
        Ok(())
    }

    /// リモートメモリアクセスの解除
    fn teardown_remote_memory_access(
        &self,
        node_id: usize,
        remote_phys_addr: PhysAddr,
        local_virt_addr: VirtAddr,
        size: usize,
        page_table: &mut PageTable,
    ) -> Result<(), TelePageError> {
        let num_pages = size / PAGE_SIZE;
        let page_allocator = PageAllocator::get_instance();
        
        for i in 0..num_pages {
            let local_addr = VirtAddr::new(local_virt_addr.as_usize() + i * PAGE_SIZE);
            
            // 変更があった場合はリモートに書き戻し（シミュレーション）
            if let Some(phys_addr) = page_table.translate(local_addr) {
                let remote_addr = PhysAddr::new(remote_phys_addr.as_usize() + i * PAGE_SIZE);
                
                // ローカルページの内容をリモートに書き戻し
                self.write_back_remote_page(node_id, remote_addr, phys_addr)?;
                
                // マッピングを解除
                page_table.unmap(local_addr)
                    .map_err(|_| TelePageError::PageTableError)?;
                    
                // 物理ページを解放
                page_allocator.free_pages(phys_addr, 1);
            }
        }
        
        Ok(())
    }

    /// リモートページからデータを取得（シミュレーション）
    fn fetch_remote_page(&self, node_id: usize, remote_addr: PhysAddr) -> Result<&[u8], TelePageError> {
        // 実際の実装ではネットワーク経由でリモートからデータを取得
        // シミュレーションとしてダミーデータを返す
        static DUMMY_PAGE: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
        Ok(&DUMMY_PAGE)
    }

    /// リモートページにデータを書き戻し（シミュレーション）
    fn write_back_remote_page(
        &self,
        node_id: usize,
        remote_addr: PhysAddr,
        local_phys_addr: PhysAddr,
    ) -> Result<(), TelePageError> {
        // 実際の実装ではネットワーク経由でリモートにデータを送信
        // シミュレーションとして常に成功を返す
        Ok(())
    }

    /// 空きVMA領域を検索
    fn find_free_vma_region(&self, size: usize, vma_manager: &VmaManager) -> Option<VirtAddr> {
        // テレページ用の専用アドレス範囲
        const TELEPAGE_START: usize = 0xF000_0000; // 3.75GB
        const TELEPAGE_END: usize = 0xFFF0_0000;   // 約4GB
        
        // サイズをページサイズにアライン
        let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        
        // すべてのVMAを取得
        let vmas = vma_manager.get_all_vmas();
        
        // テレページ範囲内のVMAをフィルタリング
        let telepage_vmas: Vec<_> = vmas.iter()
            .filter(|vma| {
                vma.range.start.as_usize() >= TELEPAGE_START &&
                vma.range.end.as_usize() <= TELEPAGE_END
            })
            .collect();
        
        if telepage_vmas.is_empty() {
            // テレページVMAがない場合は先頭から開始
            return Some(VirtAddr::new(TELEPAGE_START));
        }
        
        // テレページVMAをソート
        let mut sorted_vmas = telepage_vmas.clone();
        sorted_vmas.sort_by_key(|vma| vma.range.start);
        
        // 空き領域を探す
        let mut last_end = VirtAddr::new(TELEPAGE_START);
        
        for vma in sorted_vmas {
            if vma.range.start.as_usize() >= last_end.as_usize() + aligned_size {
                // 十分な空き領域がある
                return Some(last_end);
            }
            
            last_end = VirtAddr::new(vma.range.end.as_usize());
        }
        
        // 最後のVMAの後にも空き領域を確認
        if last_end.as_usize() + aligned_size <= TELEPAGE_END {
            return Some(last_end);
        }
        
        None
    }

    /// 統計情報を取得
    pub fn get_stats(&self) -> TelePageStats {
        let total_pages = self.descriptors.iter()
            .map(|desc| desc.size / PAGE_SIZE)
            .sum();
            
        let total_memory = self.descriptors.iter()
            .map(|desc| desc.size)
            .sum();
            
        let active_descriptors = self.descriptors.len();
        
        TelePageStats {
            total_pages,
            total_memory,
            active_descriptors,
        }
    }
}

/// テレページ統計情報
#[derive(Debug, Clone, Copy)]
pub struct TelePageStats {
    /// テレページの総数
    pub total_pages: usize,
    /// テレページの総メモリサイズ
    pub total_memory: usize,
    /// アクティブなディスクリプタ数
    pub active_descriptors: usize,
}

/// グローバルテレページマネージャ
static GLOBAL_TELEPAGE_MANAGER: Mutex<Option<TelePageManager>> = Mutex::new(None);

/// テレページマネージャを初期化
pub fn init_telepages() {
    let mut lock = GLOBAL_TELEPAGE_MANAGER.lock();
    if lock.is_none() {
        *lock = Some(TelePageManager::new());
    }
}

/// グローバルテレページマネージャを取得
pub fn get_telepage_manager() -> &'static Mutex<Option<TelePageManager>> {
    &GLOBAL_TELEPAGE_MANAGER
}

/// リモートメモリをマップするグローバル関数
pub fn map_remote_memory(
    node_id: usize,
    remote_phys_addr: PhysAddr,
    size: usize,
    perm: VmaPerm,
    page_table: &mut PageTable,
    vma_manager: &mut VmaManager,
) -> Result<VirtAddr, TelePageError> {
    let mut manager = GLOBAL_TELEPAGE_MANAGER.lock();
    if let Some(telepage_manager) = manager.as_mut() {
        telepage_manager.map_remote_memory(
            node_id,
            remote_phys_addr,
            size,
            perm,
            page_table,
            vma_manager,
        )
    } else {
        Err(TelePageError::Other("Telepage manager not initialized"))
    }
}

/// リモートメモリをアンマップするグローバル関数
pub fn unmap_remote_memory(
    local_virt_addr: VirtAddr,
    page_table: &mut PageTable,
    vma_manager: &mut VmaManager,
) -> Result<(), TelePageError> {
    let mut manager = GLOBAL_TELEPAGE_MANAGER.lock();
    if let Some(telepage_manager) = manager.as_mut() {
        telepage_manager.unmap_remote_memory(
            local_virt_addr,
            page_table,
            vma_manager,
        )
    } else {
        Err(TelePageError::Other("Telepage manager not initialized"))
    }
}

/// テレページから読み込むグローバル関数
pub fn telepage_read<T>(addr: VirtAddr) -> Result<T, TelePageError>
where
    T: Copy,
{
    let manager = GLOBAL_TELEPAGE_MANAGER.lock();
    if let Some(telepage_manager) = manager.as_ref() {
        telepage_manager.read(addr)
    } else {
        Err(TelePageError::Other("Telepage manager not initialized"))
    }
}

/// テレページに書き込むグローバル関数
pub fn telepage_write<T>(addr: VirtAddr, value: T) -> Result<(), TelePageError>
where
    T: Copy,
{
    let manager = GLOBAL_TELEPAGE_MANAGER.lock();
    if let Some(telepage_manager) = manager.as_ref() {
        telepage_manager.write(addr, value)
    } else {
        Err(TelePageError::Other("Telepage manager not initialized"))
    }
}

/// テレページ統計情報を取得するグローバル関数
pub fn get_telepage_stats() -> Result<TelePageStats, TelePageError> {
    let manager = GLOBAL_TELEPAGE_MANAGER.lock();
    if let Some(telepage_manager) = manager.as_ref() {
        Ok(telepage_manager.get_stats())
    } else {
        Err(TelePageError::Other("Telepage manager not initialized"))
    }
} 