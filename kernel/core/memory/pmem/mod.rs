// AetherOS 不揮発性メモリ管理モジュール
//
// このモジュールは不揮発性メモリ（PMEM）を管理します。
// インテルOptane PMEMやNVDIMMなどのパーシステントメモリを
// 効率的に活用するための機能を提供します。

mod allocator;
mod region;
pub mod api;
mod utils;

pub use allocator::{PmemAllocator, PmemAllocFlags};
pub use region::{PmemRegion, PmemRegionType, PmemRegionInfo, PmemRegionDetector, PmemRegionUtils};
pub use api::{PmemApi, PmemHandle, PmemError, pmem, init_pmem, pmem_alloc, pmem_free, pmem_read, pmem_write};
pub use utils::{PmemPersistence, PmemChecksum, PmemAtomic, PmemResilience, PmemSecurity, PmemAtomicity, pmem_backup, pmem_restore, pmem_verify, pmem_secure_erase};

use crate::core::sync::{RwLock, Mutex};
use alloc::vec::Vec;
use alloc::string::{String, ToString};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use log::{debug, info, warn, error, trace};

/// 不揮発性メモリのデータ永続化モード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceMode {
    /// 即時永続化（即座にフラッシュ）
    Immediate,
    /// 遅延永続化（バッチ処理でフラッシュ）
    Deferred,
    /// プログラム制御（アプリケーションがフラッシュを制御）
    Programmatic,
}

/// 不揮発性メモリの永続性保証レベル
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityLevel {
    /// 電源障害でも保証（フルフラッシュ）
    PowerFailSafe,
    /// クラッシュでのみ保証（部分フラッシュ）
    CrashConsistent,
    /// ベストエフォート（パフォーマンス優先）
    BestEffort,
}

/// PMEM領域の状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmemState {
    /// 利用可能
    Available,
    /// マウント済み
    Mounted,
    /// オフライン
    Offline,
    /// エラー状態
    Error,
}

/// PMEMデバイスの情報
#[derive(Debug, Clone)]
pub struct PmemDeviceInfo {
    /// デバイス名
    pub name: String,
    /// 開始物理アドレス
    pub phys_addr: usize,
    /// サイズ（バイト）
    pub size: usize,
    /// インターリーブされているか
    pub is_interleaved: bool,
    /// NUMAノードID
    pub numa_node: usize,
    /// 現在の状態
    pub state: PmemState,
}

/// PMEMマウントオプション
#[derive(Debug, Clone)]
pub struct PmemMountOptions {
    /// マウントポイント（仮想アドレス）
    pub virt_addr: usize,
    /// 永続化モード
    pub persistence_mode: PersistenceMode,
    /// 永続性保証レベル
    pub durability_level: DurabilityLevel,
    /// 読み取り専用モード
    pub read_only: bool,
    /// マウント名
    pub name: String,
}

impl Default for PmemMountOptions {
    fn default() -> Self {
        Self {
            virt_addr: 0,
            persistence_mode: PersistenceMode::Deferred,
            durability_level: DurabilityLevel::CrashConsistent,
            read_only: false,
            name: "pmem0".to_string(),
        }
    }
}

/// PMEMマウント情報
#[derive(Debug)]
pub struct PmemMount {
    /// マウントID
    pub id: usize,
    /// デバイス情報
    pub device: PmemDeviceInfo,
    /// マウントオプション
    pub options: PmemMountOptions,
    /// マウント時間（起動からの秒数）
    pub mount_time: u64,
}

/// PMEM管理システム
pub struct PmemManager {
    /// 検出されたPMEMデバイスのリスト
    devices: RwLock<Vec<PmemDeviceInfo>>,
    /// マウントされたPMEM領域
    mounts: RwLock<Vec<PmemMount>>,
    /// PMEMアロケータ
    allocator: Mutex<PmemAllocator>,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// マウントカウンタ
    mount_counter: AtomicUsize,
    /// 書き込みバッファリングが有効かどうか
    write_buffering_enabled: AtomicBool,
    /// バッファフラッシュのスレッショルド（バイト）
    flush_threshold: AtomicUsize,
}

/// グローバルPMEM管理システムへの参照
static mut PMEM_MANAGER: Option<PmemManager> = None;

/// PMEM検出イベントハンドラ
pub type PmemDetectionHandler = fn(&PmemDeviceInfo) -> Result<(), &'static str>;

/// PMEM機能フラグ
bitflags::bitflags! {
    pub struct PmemFeatureFlags: u32 {
        /// ダイレクトアクセスサポート
        const DIRECT_ACCESS     = 0b0000_0001;
        /// ハードウェア暗号化サポート
        const HW_ENCRYPTION     = 0b0000_0010;
        /// ハードウェアECCサポート
        const HW_ECC            = 0b0000_0100;
        /// 大ページサポート
        const HUGE_PAGES        = 0b0000_1000;
        /// アトミック操作サポート
        const ATOMIC_OPS        = 0b0001_0000;
        /// NVDIMMコマンドサポート
        const NVDIMM_CMDS       = 0b0010_0000;
        /// SMARTモニタリングサポート
        const SMART_MONITORING  = 0b0100_0000;
        /// NUMA対応
        const NUMA_AWARE        = 0b1000_0000;
    }
}

/// PMEMデバイスの詳細情報
#[derive(Debug, Clone)]
pub struct PmemDeviceDetails {
    /// 機能フラグ
    pub features: PmemFeatureFlags,
    /// 製造元
    pub manufacturer: String,
    /// モデル番号
    pub model: String,
    /// シリアル番号
    pub serial: String,
    /// ファームウェアバージョン
    pub firmware_version: String,
    /// アラインメント要件
    pub alignment: usize,
    /// メディア寿命（残り書き込み可能な推定割合）
    pub media_life_remaining: Option<u8>,
    /// 最大電力消費量（mW）
    pub max_power_consumption: Option<u32>,
}

impl Default for PmemDeviceDetails {
    fn default() -> Self {
        Self {
            features: PmemFeatureFlags::DIRECT_ACCESS | PmemFeatureFlags::HW_ECC,
            manufacturer: "Unknown".to_string(),
            model: "Generic PMEM".to_string(),
            serial: "N/A".to_string(),
            firmware_version: "1.0".to_string(),
            alignment: 64,  // 一般的なPMEM行サイズ
            media_life_remaining: None,
            max_power_consumption: None,
        }
    }
}

impl PmemManager {
    /// 新しいPMEM管理システムを作成
    pub fn new() -> Self {
        let allocator = PmemAllocator::new();
        
        Self {
            devices: RwLock::new(Vec::new()),
            mounts: RwLock::new(Vec::new()),
            allocator: Mutex::new(allocator),
            initialized: AtomicBool::new(false),
            mount_counter: AtomicUsize::new(0),
            write_buffering_enabled: AtomicBool::new(true),
            flush_threshold: AtomicUsize::new(4 * 1024 * 1024), // 4MB
        }
    }
    
    /// PMEM管理システムを初期化
    pub fn init(&self) -> Result<(), &'static str> {
        if self.initialized.load(Ordering::Acquire) {
            return Ok(());
        }
        
        // PMEMデバイスを検出
        self.detect_pmem_devices()?;
        
        // PMEMアロケータを初期化
        let mut allocator = self.allocator.lock();
        allocator.init()?;
        drop(allocator);
        
        self.initialized.store(true, Ordering::Release);
        info!("PMEM管理システムが初期化されました");
        
        Ok(())
    }
    
    /// PMEMデバイスを検出
    fn detect_pmem_devices(&self) -> Result<(), &'static str> {
        // ここで実際のシステムのPMEMデバイスを検出
        // ACPIテーブルや/sys/bus/nd/devicesなどからデバイス情報を取得
        
        // 簡単な実装として、ダミーのデバイスを作成
        let dummy_device = PmemDeviceInfo {
            name: "pmem0".to_string(),
            phys_addr: 0x100000000, // 4GB以降
            size: 16 * 1024 * 1024 * 1024, // 16GB
            is_interleaved: false,
            numa_node: 0,
            state: PmemState::Available,
        };
        
        let mut devices = self.devices.write().map_err(|_| "デバイスリストのロック取得に失敗")?;
        devices.push(dummy_device);
        
        info!("{}個のPMEMデバイスが検出されました", devices.len());
        
        Ok(())
    }
    
    /// PMEMデバイスをマウント
    pub fn mount_pmem_device(&self, device_name: &str, options: PmemMountOptions) -> Result<usize, &'static str> {
        if !self.initialized.load(Ordering::Acquire) {
            return Err("PMEM管理システムが初期化されていません");
        }
        
        // デバイスを検索
        let devices = self.devices.read().map_err(|_| "デバイスリストのロック取得に失敗")?;
        let device = devices.iter().find(|dev| dev.name == device_name).cloned();
        
        drop(devices);
        
        let device = match device {
            Some(dev) => {
                if dev.state != PmemState::Available {
                    return Err("PMEMデバイスは既にマウントされているか使用できません");
                }
                dev
            },
            None => return Err("指定されたPMEMデバイスが見つかりません"),
        };
        
        // デバイスの状態を更新
        {
            let mut devices = self.devices.write().map_err(|_| "デバイスリストのロック取得に失敗")?;
            if let Some(dev) = devices.iter_mut().find(|d| d.name == device_name) {
                dev.state = PmemState::Mounted;
            }
        }
        
        // 新しいマウントIDを生成
        let mount_id = self.mount_counter.fetch_add(1, Ordering::Relaxed);
        
        // マウント情報を作成
        let mount = PmemMount {
            id: mount_id,
            device: device.clone(),
            options: options.clone(),
            mount_time: self.get_current_time(),
        };
        
        // マウントリストに追加
        let mut mounts = self.mounts.write().map_err(|_| "マウントリストのロック取得に失敗")?;
        mounts.push(mount);
        
        info!("PMEMデバイス{}をマウント: ID={}", device_name, mount_id);
        
        Ok(mount_id)
    }
    
    /// PMEMデバイスをアンマウント
    pub fn unmount_pmem_device(&self, mount_id: usize) -> Result<(), &'static str> {
        if !self.initialized.load(Ordering::Acquire) {
            return Err("PMEM管理システムが初期化されていません");
        }
        
        // マウント情報を検索
        let mut mounts = self.mounts.write().map_err(|_| "マウントリストのロック取得に失敗")?;
        let mount_index = mounts.iter().position(|m| m.id == mount_id);
        
        match mount_index {
            Some(index) => {
                let mount = mounts.remove(index);
                
                // デバイスの状態を更新
                let mut devices = self.devices.write().map_err(|_| "デバイスリストのロック取得に失敗")?;
                if let Some(dev) = devices.iter_mut().find(|d| d.name == mount.device.name) {
                    dev.state = PmemState::Available;
                }
                
                info!("PMEMデバイス{}をアンマウント: ID={}", mount.device.name, mount_id);
                
                Ok(())
            },
            None => Err("指定されたマウントIDが見つかりません"),
        }
    }
    
    /// PMEMデバイスからメモリを割り当て
    pub fn allocate_pmem(&self, size: usize, alignment: usize) -> Result<usize, &'static str> {
        if !self.initialized.load(Ordering::Acquire) {
            return Err("PMEM管理システムが初期化されていません");
        }
        
        let mut allocator = self.allocator.lock();
        allocator.allocate(size, alignment)
    }
    
    /// PMEMデバイスのメモリを解放
    pub fn free_pmem(&self, addr: usize, size: usize) -> Result<(), &'static str> {
        if !self.initialized.load(Ordering::Acquire) {
            return Err("PMEM管理システムが初期化されていません");
        }
        
        let mut allocator = self.allocator.lock();
        allocator.free(addr, size)
    }
    
    /// メモリをパーシステントメモリにフラッシュ
    pub fn flush_memory(&self, addr: usize, size: usize) -> Result<(), &'static str> {
        if !self.initialized.load(Ordering::Acquire) {
            return Err("PMEM管理システムが初期化されていません");
        }
        
        // アドレスがPMEM領域内にあるか確認
        self.check_pmem_address(addr, size)?;
        
        // メモリをフラッシュ
        // 実際の実装では、CACHECLFLUSHやclflushopmなどの命令を使用
        unsafe {
            self.flush_pmem_range(addr, size);
        }
        
        trace!("PMEMフラッシュ: アドレス={:#x}, サイズ={}", addr, size);
        
        Ok(())
    }
    
    /// メモリバリアを実行（永続性保証）
    pub fn memory_barrier(&self) -> Result<(), &'static str> {
        if !self.initialized.load(Ordering::Acquire) {
            return Err("PMEM管理システムが初期化されていません");
        }
        
        // メモリバリアを実行
        // 実際の実装では、SFENCEやMFENCE命令を使用
        unsafe {
            self.pmem_sfence();
        }
        
        trace!("PMEMメモリバリア実行");
        
        Ok(())
    }
    
    /// アドレスがPMEM領域内にあるかチェック
    fn check_pmem_address(&self, addr: usize, size: usize) -> Result<(), &'static str> {
        let mounts = self.mounts.read().map_err(|_| "マウントリストのロック取得に失敗")?;
        
        for mount in mounts.iter() {
            let virt_addr = mount.options.virt_addr;
            let pmem_size = mount.device.size;
            
            if addr >= virt_addr && addr + size <= virt_addr + pmem_size {
                return Ok(());
            }
        }
        
        Err("指定されたアドレスはPMEM領域内にありません")
    }
    
    /// PMEM領域をフラッシュ（低レベル操作）
    unsafe fn flush_pmem_range(&self, addr: usize, size: usize) {
        // アラインメントと最適なフラッシュ方法を考慮
        // 実際の実装では、clflush/clflushopt/clwbなどの命令を使用
        
        // 簡易実装
        let ptr = addr as *const u8;
        let cache_line_size = 64; // 一般的なキャッシュラインサイズ
        
        for offset in (0..size).step_by(cache_line_size) {
            let line_ptr = ptr.add(offset);
            // clflushopt相当の命令を実行（アーキテクチャ依存）
            // ここではダミー実装
        }
        
        // メモリフェンス（SFENCE相当）を実行
        self.pmem_sfence();
    }
    
    /// PMEMストアフェンス（低レベル操作）
    unsafe fn pmem_sfence(&self) {
        // SFENCEまたは同等の命令を実行
        // ここではダミー実装
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    
    /// 現在時間を取得（起動からの秒数）
    fn get_current_time(&self) -> u64 {
        // 実装依存の時間取得
        // 簡易実装としてダミー値を返す
        0
    }
    
    /// PMEM領域にデータを永続化
    pub fn persist_data(&self, addr: usize, data: &[u8], size: usize) -> Result<(), &'static str> {
        // 有効なPMEM領域内かチェック
        self.check_pmem_address(addr, size)?;

        // データをコピー
        unsafe {
            let dest = addr as *mut u8;
            core::ptr::copy_nonoverlapping(data.as_ptr(), dest, core::cmp::min(data.len(), size));
        }

        // 領域をフラッシュして永続化
        self.flush_memory(addr, size)
    }
    
    /// PMEM領域の詳細情報を取得
    pub fn get_device_details(&self, device_name: &str) -> Result<PmemDeviceDetails, &'static str> {
        let devices = self.devices.read().map_err(|_| "デバイスリストのロック取得に失敗")?;
        let device = devices.iter().find(|dev| dev.name == device_name);
        
        match device {
            Some(_) => {
                // 実際のシステムでは、デバイス固有の詳細を収集
                // ここではデフォルト値を返す
                Ok(PmemDeviceDetails::default())
            },
            None => Err("指定されたPMEMデバイスが見つかりません"),
        }
    }
    
    /// PMEMデバイス検出ハンドラを登録
    pub fn register_detection_handler(&self, handler: PmemDetectionHandler) -> Result<(), &'static str> {
        // 通常は内部リストにハンドラを保存
        // 簡易実装として、登録はするが呼び出さない
        info!("PMEMデバイス検出ハンドラが登録されました");
        
        // 既存のデバイスに対して即座にハンドラを呼び出す
        let devices = self.devices.read().map_err(|_| "デバイスリストのロック取得に失敗")?;
        for device in devices.iter() {
            if let Err(e) = handler(device) {
                warn!("PMEMデバイス{}のハンドラ呼び出しに失敗: {}", device.name, e);
            }
        }
        
        Ok(())
    }
    
    /// PMEM領域のヘルスチェック実行
    pub fn check_pmem_health(&self, device_name: &str) -> Result<bool, &'static str> {
        // 実際のシステムでは、NVDIMMコマンドなどを使用してヘルスチェック
        // ここではシミュレーション
        let devices = self.devices.read().map_err(|_| "デバイスリストのロック取得に失敗")?;
        let device = devices.iter().find(|dev| dev.name == device_name);
        
        match device {
            Some(dev) => {
                if dev.state == PmemState::Error {
                    warn!("PMEMデバイス{}はエラー状態です", device_name);
                    return Ok(false);
                }
                
                info!("PMEMデバイス{}のヘルスチェック成功", device_name);
                Ok(true)
            },
            None => Err("指定されたPMEMデバイスが見つかりません"),
        }
    }
    
    /// PMEM領域の統計情報を取得
    pub fn get_pmem_stats(&self) -> Result<(usize, usize, usize, f32), &'static str> {
        if !self.initialized.load(Ordering::Acquire) {
            return Err("PMEM管理システムが初期化されていません");
        }
        
        let mut total_size = 0;
        let mut total_used = 0;
        
        let devices = self.devices.read().map_err(|_| "デバイスリストのロック取得に失敗")?;
        for device in devices.iter() {
            total_size += device.size;
        }
        
        // 使用状況を取得（実装を単純化）
        let allocator = self.allocator.lock();
        let stats = allocator.get_stats();
        total_used = stats.1; // 使用サイズ
        
        let free_size = total_size - total_used;
        let usage_percent = if total_size > 0 {
            (total_used as f32 / total_size as f32) * 100.0
        } else {
            0.0
        };
        
        Ok((total_size, total_used, free_size, usage_percent))
    }
}

/// グローバルPMEM管理システムを取得
pub fn get_pmem_manager() -> &'static PmemManager {
    unsafe {
        if PMEM_MANAGER.is_none() {
            PMEM_MANAGER = Some(PmemManager::new());
        }
        PMEM_MANAGER.as_ref().unwrap()
    }
}

/// PMEM管理システムを初期化
pub fn init() -> Result<(), &'static str> {
    let manager = get_pmem_manager();
    manager.init()?;
    
    // APIレイヤも初期化
    let _ = api::init_pmem().map_err(|_| "PMEM APIの初期化に失敗")?;
    
    Ok(())
} 