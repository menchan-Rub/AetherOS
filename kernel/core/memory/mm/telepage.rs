// AetherOS カーネル - Telepageモジュール
//
// Telepageは、プロセス間で高速に状態を共有するための特殊なメモリページです。
// 複数のプロセスが同じ物理ページを異なる仮想アドレスにマッピングすることで、
// システムコールを介さずに直接メモリを共有できます。

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;

use crate::core::arch::paging::{PageSize, PageTable, PhysAddr, VirtAddr};
use crate::core::memory::mm::mmap::{AddressSpace, MapPermissions, MmapError};
use crate::core::memory::mm::page::{AllocFlags, Page, PAGE_SIZE};
use crate::core::process::{Pid, ProcessId};
use crate::core::sync::RwLock;
use crate::time;

/// テレページのメタデータヘッダ
/// 共有メモリページの先頭に配置され、制御と同期に使用される
#[repr(C)]
pub struct TelepageHeader {
    /// マジックナンバー（有効なテレページかを確認）
    magic: AtomicU64,
    /// 現在のバージョン番号（更新の検出に使用）
    version: AtomicU64,
    /// ページの状態フラグ
    flags: AtomicU32,
    /// 作成者のプロセスID
    creator_pid: AtomicU32,
    /// アクティブな読み取りカウント
    readers: AtomicUsize,
    /// アクティブな書き込みカウント（通常は0または1）
    writers: AtomicUsize,
    /// ロック状態（0=アンロック、1=ロック中）
    lock: AtomicU32,
    /// 最後に更新したプロセスID
    last_writer_pid: AtomicU32,
    /// 最後の更新タイムスタンプ
    last_update_timestamp: AtomicU64,
    /// ユーザー定義のフラグ（アプリケーション固有の用途で使用可能）
    user_flags: AtomicU64,
    /// テレページの名前（識別用）
    name: [u8; 32],
    /// 予約領域（将来の拡張用）
    _reserved: [u8; 16],
}

/// テレページのフラグ定数
pub mod flags {
    /// 通常の読み書き可能なテレページ
    pub const NORMAL: u32 = 0;
    /// 読み取り専用テレページ（システム情報など）
    pub const READ_ONLY: u32 = 1;
    /// ライトスルーモード（書き込み時に即座に他のプロセスに反映）
    pub const WRITE_THROUGH: u32 = 2;
    /// ロギングモード（書き込み操作を記録）
    pub const LOGGING: u32 = 4;
    /// 自動バージョニング（書き込み時に自動的にバージョンを増加）
    pub const AUTO_VERSIONING: u32 = 8;
    /// キャッシュ不可（常に物理メモリから直接読み書き）
    pub const UNCACHEABLE: u32 = 16;
}

/// テレページの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelepageType {
    /// 通常の共有メモリ
    Normal,
    /// システム情報用（読み取り専用）
    SystemInfo,
    /// メッセージパッシング用
    MessagePassing,
    /// ロックフリーキュー用
    LockFreeQueue,
}

impl TelepageType {
    /// テレページタイプからフラグを取得
    fn to_flags(self) -> u32 {
        match self {
            TelepageType::Normal => flags::NORMAL,
            TelepageType::SystemInfo => flags::READ_ONLY,
            TelepageType::MessagePassing => flags::WRITE_THROUGH | flags::AUTO_VERSIONING,
            TelepageType::LockFreeQueue => flags::WRITE_THROUGH | flags::UNCACHEABLE,
        }
    }
}

/// テレページのマジックナンバー
const TELEPAGE_MAGIC: u64 = 0x5445_4C45_5041_4745; // "TELEPAGE" in ASCII

/// テレページエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelepageError {
    /// メモリ不足
    OutOfMemory,
    /// 無効なアドレス
    InvalidAddress,
    /// 無効な名前
    InvalidName,
    /// 既に存在する名前
    NameAlreadyExists,
    /// テレページが見つからない
    NotFound,
    /// アクセス権限エラー
    PermissionDenied,
    /// 無効なテレページ（マジックナンバーが一致しない）
    InvalidTelepage,
    /// マッピングエラー
    MappingError,
    /// テレページがロックされている
    Locked,
}

/// テレページマネージャ
pub struct TelepageManager {
    /// 名前からテレページIDへのマッピング
    name_to_id: RwLock<BTreeMap<String, TelepageId>>,
    /// テレページIDから物理ページへのマッピング
    pages: RwLock<BTreeMap<TelepageId, Arc<TelepageMeta>>>,
    /// プロセスごとのテレページマッピング
    process_mappings: RwLock<BTreeMap<ProcessId, BTreeSet<TelepageId>>>,
    /// 次のテレページID
    next_id: AtomicUsize,
}

/// テレページID
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TelepageId(pub usize);

/// テレページのメタデータ
pub struct TelepageMeta {
    /// テレページID
    id: TelepageId,
    /// テレページの名前
    name: String,
    /// 物理ページ
    page: Arc<Page>,
    /// 作成者のプロセスID
    creator_pid: ProcessId,
    /// テレページの種類
    telepage_type: TelepageType,
    /// 参照カウント
    ref_count: AtomicUsize,
}

impl TelepageManager {
    /// 新しいTelepageManagerを作成
    pub fn new() -> Self {
        Self {
            name_to_id: RwLock::new(BTreeMap::new()),
            pages: RwLock::new(BTreeMap::new()),
            process_mappings: RwLock::new(BTreeMap::new()),
            next_id: AtomicUsize::new(1),
        }
    }

    /// 新しいテレページを作成
    pub fn create_telepage(
        &self,
        name: &str,
        creator_pid: ProcessId,
        telepage_type: TelepageType,
    ) -> Result<TelepageId, TelepageError> {
        // 名前の長さチェック
        if name.len() > 31 {
            return Err(TelepageError::InvalidName);
        }

        // 名前の重複チェック
        {
            let name_map = self.name_to_id.read();
            if name_map.contains_key(name) {
                return Err(TelepageError::NameAlreadyExists);
            }
        }

        // 新しいIDを割り当て
        let id = TelepageId(self.next_id.fetch_add(1, Ordering::SeqCst));

        // 物理ページを割り当て
        let page = Arc::new(Page::alloc(AllocFlags::ZERO)
            .map_err(|_| TelepageError::OutOfMemory)?);

        // テレページヘッダを初期化
        self.initialize_header(page.clone(), name, creator_pid, telepage_type)?;

        // メタデータを作成
        let meta = Arc::new(TelepageMeta {
            id,
            name: name.to_string(),
            page,
            creator_pid,
            telepage_type,
            ref_count: AtomicUsize::new(1),
        });

        // マッピングを保存
        {
            let mut name_map = self.name_to_id.write();
            let mut pages_map = self.pages.write();
            let mut process_map = self.process_mappings.write();

            name_map.insert(name.to_string(), id);
            pages_map.insert(id, meta);

            // プロセスマッピングを更新
            let process_pages = process_map.entry(creator_pid).or_insert_with(BTreeSet::new);
            process_pages.insert(id);
        }

        Ok(id)
    }

    /// テレページを名前で検索
    pub fn find_by_name(&self, name: &str) -> Option<TelepageId> {
        let name_map = self.name_to_id.read();
        name_map.get(name).copied()
    }

    /// テレページをIDで取得
    pub fn get_telepage(&self, id: TelepageId) -> Option<Arc<TelepageMeta>> {
        let pages_map = self.pages.read();
        pages_map.get(&id).cloned()
    }

    /// プロセスにテレページをマッピング
    pub fn map_telepage(
        &self,
        id: TelepageId,
        pid: ProcessId,
        address_space: &AddressSpace,
        vaddr: Option<VirtAddr>,
    ) -> Result<VirtAddr, TelepageError> {
        // テレページのメタデータを取得
        let meta = self.get_telepage(id).ok_or(TelepageError::NotFound)?;

        // 参照カウントを増加
        meta.ref_count.fetch_add(1, Ordering::SeqCst);

        // マッピングするアドレスを決定
        let map_addr = if let Some(addr) = vaddr {
            addr
        } else {
            // アドレス空間から適切なアドレスを取得
            address_space.find_free_region(PAGE_SIZE, PAGE_SIZE)
                .map_err(|_| TelepageError::OutOfMemory)?
        };

        // マッピング権限を設定
        let mut permissions = MapPermissions::readwrite();
        if meta.telepage_type == TelepageType::SystemInfo {
            permissions = MapPermissions::readonly();
        }
        if meta.telepage_type == TelepageType::LockFreeQueue {
            permissions.cacheable = false;
        }

        // ページをマッピング
        address_space.map(map_addr, meta.page.phys_addr(), permissions)
            .map_err(|_| TelepageError::MappingError)?;

        // プロセスマッピングを更新
        {
            let mut process_map = self.process_mappings.write();
            let process_pages = process_map.entry(pid).or_insert_with(BTreeSet::new);
            process_pages.insert(id);
        }

        Ok(map_addr)
    }

    /// プロセスからテレページをアンマッピング
    pub fn unmap_telepage(
        &self,
        id: TelepageId,
        pid: ProcessId,
        address_space: &AddressSpace,
        vaddr: VirtAddr,
    ) -> Result<(), TelepageError> {
        // テレページのメタデータを取得
        let meta = self.get_telepage(id).ok_or(TelepageError::NotFound)?;

        // ページをアンマッピング
        address_space.unmap(vaddr, PAGE_SIZE)
            .map_err(|_| TelepageError::MappingError)?;

        // プロセスマッピングを更新
        {
            let mut process_map = self.process_mappings.write();
            if let Some(process_pages) = process_map.get_mut(&pid) {
                process_pages.remove(&id);
                
                // セットが空になった場合はエントリを削除
                if process_pages.is_empty() {
                    process_map.remove(&pid);
                }
            }
        }

        // 参照カウントを減少
        let prev_count = meta.ref_count.fetch_sub(1, Ordering::SeqCst);
        
        // 最後の参照が削除された場合、テレページも削除
        if prev_count == 1 {
            self.delete_telepage(id)?;
        }

        Ok(())
    }

    /// テレページを削除
    pub fn delete_telepage(&self, id: TelepageId) -> Result<(), TelepageError> {
        let mut pages_map = self.pages.write();
        let meta = pages_map.remove(&id).ok_or(TelepageError::NotFound)?;

        // 名前マッピングからも削除
        let mut name_map = self.name_to_id.write();
        name_map.remove(&meta.name);

        // このテレページを参照しているすべてのプロセスのマッピングを更新
        let mut process_map = self.process_mappings.write();
        for (_, process_pages) in process_map.iter_mut() {
            process_pages.remove(&id);
        }

        // 空のセットを持つプロセスエントリを削除
        process_map.retain(|_, pages| !pages.is_empty());

        Ok(())
    }

    /// プロセスが終了したときの処理
    pub fn process_exit(&self, pid: ProcessId, address_space: &AddressSpace) {
        let mut process_map = self.process_mappings.write();
        
        // プロセスが所有していたテレページのセットを取得
        if let Some(pages) = process_map.remove(&pid) {
            // 各テレページの参照カウントを減少
            let pages_map = self.pages.read();
            for id in pages {
                if let Some(meta) = pages_map.get(&id) {
                    meta.ref_count.fetch_sub(1, Ordering::SeqCst);
                    
                    // 作成者が終了する場合、テレページを削除
                    if meta.creator_pid == pid {
                        drop(pages_map);
                        let _ = self.delete_telepage(id);
                        break;
                    }
                }
            }
        }
    }

    /// テレページヘッダを初期化
    fn initialize_header(
        &self,
        page: Arc<Page>,
        name: &str,
        creator_pid: ProcessId,
        telepage_type: TelepageType,
    ) -> Result<(), TelepageError> {
        // ページの先頭をTelepageHeaderとして扱う
        let header_ptr = page.virt_addr().as_usize() as *mut TelepageHeader;
        
        unsafe {
            // ヘッダを初期化
            let header = &mut *header_ptr;
            
            header.magic.store(TELEPAGE_MAGIC, Ordering::SeqCst);
            header.version.store(1, Ordering::SeqCst);
            header.flags.store(telepage_type.to_flags(), Ordering::SeqCst);
            header.creator_pid.store(creator_pid.as_u32(), Ordering::SeqCst);
            header.readers.store(0, Ordering::SeqCst);
            header.writers.store(0, Ordering::SeqCst);
            header.lock.store(0, Ordering::SeqCst);
            header.last_writer_pid.store(creator_pid.as_u32(), Ordering::SeqCst);
            header.last_update_timestamp.store(0, Ordering::SeqCst);
            header.user_flags.store(0, Ordering::SeqCst);
            
            // 名前をコピー
            let name_bytes = name.as_bytes();
            let len = core::cmp::min(name_bytes.len(), 31);
            header.name[..len].copy_from_slice(&name_bytes[..len]);
            if len < 32 {
                header.name[len] = 0; // NULL終端
            }
        }

        Ok(())
    }

    /// システム情報用のテレページを作成
    pub fn create_system_info_page(&self, name: &str) -> Result<TelepageId, TelepageError> {
        self.create_telepage(name, ProcessId::new(0), TelepageType::SystemInfo)
    }

    /// メッセージパッシング用のテレページを作成
    pub fn create_message_passing_page(
        &self,
        name: &str,
        creator_pid: ProcessId,
    ) -> Result<TelepageId, TelepageError> {
        self.create_telepage(name, creator_pid, TelepageType::MessagePassing)
    }

    /// ロックフリーキュー用のテレページを作成
    pub fn create_lock_free_queue_page(
        &self,
        name: &str,
        creator_pid: ProcessId,
    ) -> Result<TelepageId, TelepageError> {
        self.create_telepage(name, creator_pid, TelepageType::LockFreeQueue)
    }

    /// テレページの統計情報を取得
    pub fn get_stats(&self) -> TelepageStats {
        let pages_map = self.pages.read();
        let process_map = self.process_mappings.read();
        
        TelepageStats {
            total_pages: pages_map.len(),
            total_mappings: process_map.values().map(|set| set.len()).sum(),
            active_processes: process_map.len(),
        }
    }
}

/// テレページ統計情報
#[derive(Debug, Clone, Copy)]
pub struct TelepageStats {
    /// 合計テレページ数
    pub total_pages: usize,
    /// 合計マッピング数
    pub total_mappings: usize,
    /// アクティブなプロセス数
    pub active_processes: usize,
}

impl TelepageMeta {
    /// テレページの物理アドレスを取得
    pub fn phys_addr(&self) -> PhysAddr {
        self.page.phys_addr()
    }

    /// テレページヘッダへの参照を取得
    pub fn header(&self) -> &TelepageHeader {
        unsafe { &*(self.page.virt_addr().as_usize() as *const TelepageHeader) }
    }

    /// テレページヘッダへの可変参照を取得
    pub fn header_mut(&self) -> &mut TelepageHeader {
        unsafe { &mut *(self.page.virt_addr().as_usize() as *mut TelepageHeader) }
    }

    /// テレページのデータ部分へのポインタを取得
    pub fn data_ptr(&self) -> *mut u8 {
        unsafe {
            (self.page.virt_addr().as_usize() as *mut u8).add(core::mem::size_of::<TelepageHeader>())
        }
    }

    /// テレページのデータサイズを取得
    pub fn data_size(&self) -> usize {
        PAGE_SIZE - core::mem::size_of::<TelepageHeader>()
    }

    /// テレページの参照カウントを取得
    pub fn ref_count(&self) -> usize {
        self.ref_count.load(Ordering::SeqCst)
    }

    /// テレページの種類を取得
    pub fn telepage_type(&self) -> TelepageType {
        self.telepage_type
    }

    /// テレページの名前を取得
    pub fn name(&self) -> &str {
        &self.name
    }

    /// テレページの作成者PIDを取得
    pub fn creator_pid(&self) -> ProcessId {
        self.creator_pid
    }

    /// テレページのバージョンを取得
    pub fn version(&self) -> u64 {
        self.header().version.load(Ordering::SeqCst)
    }

    /// テレページのバージョンを増加
    pub fn increment_version(&self) -> u64 {
        self.header().version.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// テレページをロック
    pub fn lock(&self) -> Result<(), TelepageError> {
        let header = self.header_mut();
        
        // ロック操作（0を1に交換）
        let was_locked = header.lock.compare_exchange(
            0, 1, Ordering::SeqCst, Ordering::SeqCst
        ).is_err();
        
        if was_locked {
            Err(TelepageError::Locked)
        } else {
            Ok(())
        }
    }

    /// テレページをアンロック
    pub fn unlock(&self) {
        let header = self.header_mut();
        header.lock.store(0, Ordering::SeqCst);
    }

    /// 書き込みアクセスを開始
    pub fn begin_write(&self) -> Result<(), TelepageError> {
        let header = self.header_mut();
        
        // 読み取り専用テレページへの書き込みを禁止
        if header.flags.load(Ordering::SeqCst) & flags::READ_ONLY != 0 {
            return Err(TelepageError::PermissionDenied);
        }
        
        // 書き込みカウントを増加
        header.writers.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// 書き込みアクセスを終了
    pub fn end_write(&self, pid: ProcessId) {
        let header = self.header_mut();
        
        // 書き込みカウントを減少
        header.writers.fetch_sub(1, Ordering::SeqCst);
        
        // 最終更新情報を更新
        header.last_writer_pid.store(pid.as_u32(), Ordering::SeqCst);
        header.last_update_timestamp.store(get_timestamp(), Ordering::SeqCst);
        
        // 自動バージョニングが有効なら、バージョンを増加
        if header.flags.load(Ordering::SeqCst) & flags::AUTO_VERSIONING != 0 {
            self.increment_version();
        }
    }

    /// 読み取りアクセスを開始
    pub fn begin_read(&self) {
        let header = self.header_mut();
        header.readers.fetch_add(1, Ordering::SeqCst);
    }

    /// 読み取りアクセスを終了
    pub fn end_read(&self) {
        let header = self.header_mut();
        header.readers.fetch_sub(1, Ordering::SeqCst);
    }
}

/// 現在のタイムスタンプを取得
fn get_timestamp() -> u64 {
    // システムの現在時刻をナノ秒精度で取得
    crate::time::get_current_time().as_nanos()
}

impl ProcessId {
    /// u32からプロセスIDを作成
    fn as_u32(&self) -> u32 {
        // プロセスIDを32ビット値として取得
        // 内部実装がu64の場合は下位32ビットのみ使用
        match self.0 {
            Pid::Kernel(id) => (id & 0xFFFFFFFF) as u32,
            Pid::User(id) => (id & 0xFFFFFFFF) as u32,
        }
    }
}

/// グローバルテレページマネージャ
pub static TELEPAGE_MANAGER: Mutex<Option<TelepageManager>> = Mutex::new(None);

/// テレページマネージャを初期化
pub fn init_telepage_manager() {
    let mut manager = TELEPAGE_MANAGER.lock();
    *manager = Some(TelepageManager::new());
}

/// テレページを作成
pub fn create_telepage(
    name: &str,
    creator_pid: ProcessId,
    telepage_type: TelepageType,
) -> Result<TelepageId, TelepageError> {
    TELEPAGE_MANAGER.lock()
        .as_ref()
        .ok_or(TelepageError::OutOfMemory)?
        .create_telepage(name, creator_pid, telepage_type)
}

/// テレページを名前で検索
pub fn find_telepage_by_name(name: &str) -> Option<TelepageId> {
    TELEPAGE_MANAGER.lock()
        .as_ref()?
        .find_by_name(name)
}

/// テレページをマッピング
pub fn map_telepage(
    id: TelepageId,
    pid: ProcessId,
    address_space: &AddressSpace,
    vaddr: Option<VirtAddr>,
) -> Result<VirtAddr, TelepageError> {
    TELEPAGE_MANAGER.lock()
        .as_ref()
        .ok_or(TelepageError::OutOfMemory)?
        .map_telepage(id, pid, address_space, vaddr)
}

/// テレページをアンマッピング
pub fn unmap_telepage(
    id: TelepageId,
    pid: ProcessId,
    address_space: &AddressSpace,
    vaddr: VirtAddr,
) -> Result<(), TelepageError> {
    TELEPAGE_MANAGER.lock()
        .as_ref()
        .ok_or(TelepageError::OutOfMemory)?
        .unmap_telepage(id, pid, address_space, vaddr)
}

/// システム情報用のテレページを作成
pub fn create_system_info_page(name: &str) -> Result<TelepageId, TelepageError> {
    TELEPAGE_MANAGER.lock()
        .as_ref()
        .ok_or(TelepageError::OutOfMemory)?
        .create_system_info_page(name)
}

/// プロセス終了時の処理
pub fn process_exit(pid: ProcessId, address_space: &AddressSpace) {
    if let Some(manager) = TELEPAGE_MANAGER.lock().as_ref() {
        manager.process_exit(pid, address_space);
    }
}

/// テレページの統計情報を取得
pub fn telepage_stats() -> Option<TelepageStats> {
    TELEPAGE_MANAGER.lock()
        .as_ref()
        .map(|m| m.get_stats())
} 