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
use crate::core::memory::PageSize;
use crate::core::memory::buddy::BuddyAllocator;

/// ブートローダーから渡される情報 (仮定義)
#[derive(Debug, Clone, Copy)]
pub struct BootInfo {
    pub memory_map_addr: usize,
    pub memory_map_len: usize,
    // 他のブート情報（例：ACPI RSDPポインタ、カーネルコマンドラインなど）
}

/// メモリマップエントリ構造体 (仮定義、E820等を模倣)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryMapEntry {
    pub base_addr: u64,
    pub length: u64,
    /// メモリタイプ (例: 1 = Usable RAM, その他 = Reserved, ACPI, NVSなど)
    pub entry_type: u32,
    /// ACPI 3.0+ 拡張属性
    pub acpi_extended_attributes: u32,
}

// 仮のグローバル変数 (実際にはブートローダーがカーネルエントリ時に設定する)
// これは設計として理想的ではないが、関数のシグネチャを変更せずに
// parse_memory_map 内で情報を受け取るための一時的な手段。
static mut GLOBAL_BOOT_INFO: Option<BootInfo> = None;

/// ブート情報を設定する (カーネル初期化の最初期に呼び出される想定)
pub unsafe fn set_global_boot_info(boot_info: BootInfo) {
    GLOBAL_BOOT_INFO = Some(boot_info);
}

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
        // TODO: アーキテクチャ固有のキャッシュフラッシュ命令 (例: CLFLUSH, CLFLUSHOPT, DC CIVAC) を使用して
        //       指定されたメモリアドレス範囲 (`start_line` から `end_addr` まで) をキャッシュからフラッシュする。
        //       `arch::pmem_flush_cache_range(start_line, end_addr - start_line);` のようなヘルパー関数を想定。
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
        // TODO: アーキテクチャ固有のメモリバリア命令 (例: SFENCE, MFENCE, DSB ISH) を実行して、
        //       フラッシュ操作が完了するのを保証する。
        //       `arch::pmem_memory_barrier();` のようなヘルパー関数を想定。
        unsafe {
            arch::asm::sfence();
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
        // TODO: この関数は `flush_pmem_range_internal` を使用するか、あるいは直接
        //       アーキテクチャ固有のキャッシュフラッシュ命令とメモリバリアを呼び出す。
        //       `arch::pmem_flush_cache_range(addr, size);`
        //       `arch::pmem_memory_barrier();`
        //       のようなヘルパー関数を呼び出すことを想定。
        //       以下の実装はx86_64の例であり、アーキテクチャ中立な実装が必要。
        log::trace!("Flushing PMEM range: addr={:#x}, size={}", addr, size);
        self.flush_pmem_range_internal(addr, size);
    }
    
    fn flush_pmem_range_internal(&self, addr: usize, size: usize) {
        let start_line = addr & !(CACHE_LINE_SIZE - 1);
        let end_addr = addr + size;

        // アーキテクチャ固有のキャッシュフラッシュ命令を使用
        #[cfg(target_arch = "x86_64")]
        {
            unsafe {
                let mut current_addr = start_line;
                while current_addr < end_addr {
                    // CLFLUSHOPT命令を使用（利用可能な場合）
                    if self.has_clflushopt() {
                        core::arch::asm!(
                            "clflushopt ({})",
                            in(reg) current_addr,
                            options(nostack, preserves_flags)
                        );
                    } else {
                        // フォールバック：CLFLUSH命令
                        core::arch::asm!(
                            "clflush ({})",
                            in(reg) current_addr,
                            options(nostack, preserves_flags)
                        );
                    }
                    current_addr += CACHE_LINE_SIZE;
                }
                
                // SFENCE命令でメモリバリアを実行
                core::arch::asm!("sfence", options(nostack, preserves_flags));
            }
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            unsafe {
                let mut current_addr = start_line;
                while current_addr < end_addr {
                    // DC CIVAC命令（Clean and Invalidate by VA to PoC）
                    core::arch::asm!(
                        "dc civac, {}",
                        in(reg) current_addr,
                        options(nostack, preserves_flags)
                    );
                    current_addr += CACHE_LINE_SIZE;
                }
                
                // DSB ISH命令でメモリバリアを実行
                core::arch::asm!("dsb ish", options(nostack, preserves_flags));
            }
        }
        
        #[cfg(target_arch = "riscv64")]
        {
            unsafe {
                // RISC-V: FENCE命令でメモリバリアを実行
                // キャッシュフラッシュ命令は標準化されていないため、
                // システム固有の実装が必要
                core::arch::asm!(
                    "fence rw,rw",
                    options(nostack, preserves_flags)
                );
                
                // 可能であればCBO（Cache Block Operations）拡張を使用
                if self.has_cbo_extension() {
                    let mut current_addr = start_line;
                    while current_addr < end_addr {
                        // CBO.FLUSH命令（利用可能な場合）
                        core::arch::asm!(
                            ".insn r 0x0F, 0x2, 0x00, x0, {}, x0",
                            in(reg) current_addr,
                            options(nostack, preserves_flags)
                        );
                        current_addr += CACHE_LINE_SIZE;
                    }
                }
            }
        }
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
        {
            // 他のアーキテクチャ：汎用的なメモリバリア
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            log::warn!("アーキテクチャ固有のキャッシュフラッシュ命令が利用できません");
        }
    }
    
    /// CLFLUSHOPT命令が利用可能かチェック
    #[cfg(target_arch = "x86_64")]
    fn has_clflushopt(&self) -> bool {
        // CPUID命令でCLFLUSHOPT対応をチェック
        unsafe {
            let mut eax: u32;
            let mut ebx: u32;
            let mut ecx: u32;
            let mut edx: u32;
            
            // CPUID.07H:EBX.CLFLUSHOPT[bit 23]
            core::arch::asm!(
                "cpuid",
                inout("eax") 0x07u32 => eax,
                inout("ebx") 0u32 => ebx,
                inout("ecx") 0u32 => ecx,
                inout("edx") 0u32 => edx,
                options(nostack, preserves_flags)
            );
            
            (ebx & (1 << 23)) != 0
        }
    }
    
    /// CBO拡張が利用可能かチェック
    #[cfg(target_arch = "riscv64")]
    fn has_cbo_extension(&self) -> bool {
        // RISC-V ISA文字列またはデバイスツリーから確認
        // 簡略化実装：常にfalseを返す
        false
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

const MAX_MEMORY_REGIONS: usize = 32;

#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub start: usize,
    pub size: usize,
    pub available: bool,
}

pub struct PhysicalMemoryManager {
    memory_regions: [Option<MemoryRegion>; MAX_MEMORY_REGIONS],
    region_count: usize,
    buddy_allocator: BuddyAllocator,
    total_memory: usize,
    free_memory: usize,
}

impl PhysicalMemoryManager {
    pub fn new() -> Self {
        Self {
            memory_regions: [None; MAX_MEMORY_REGIONS],
            region_count: 0,
            buddy_allocator: BuddyAllocator::new(),
            total_memory: 0,
            free_memory: 0,
        }
    }
    
    pub fn init(&mut self) {
        // ブートローダーが提供したメモリマップを解析
        // ブートローダー（UEFI/BIOS）からの情報を取得し、
        // PMEMデバイスタイプ（NVDIMM、3D XPoint等）を識別
        // ACPI NFITテーブルも参照してPMEM領域を特定
        
        unsafe {
            if let Some(boot_info) = GLOBAL_BOOT_INFO.as_ref() {
                self.parse_acpi_nfit_table(boot_info)?;
                self.scan_memory_map_for_pmem(boot_info)?;
            } else {
                return Err("ブート情報が設定されていません");
            }
        }
        
        // バディアロケータを初期化
        self.init_buddy_allocator();
    }
    
    fn parse_acpi_nfit_table(&self, boot_info: &BootInfo) -> Result<(), &'static str> {
        // 実装は後で追加
        Ok(())
    }
    
    fn scan_memory_map_for_pmem(&self, boot_info: &BootInfo) -> Result<(), &'static str> {
        // 実装は後で追加
        Ok(())
    }
    
    fn add_memory_region(&mut self, start: usize, size: usize, available: bool) -> bool {
        if self.region_count >= MAX_MEMORY_REGIONS {
            return false;
        }
        
        let region = MemoryRegion {
            start,
            size,
            available,
        };
        
        self.memory_regions[self.region_count] = Some(region);
        self.region_count += 1;
        
        true
    }
    
    fn calculate_memory_totals(&mut self) {
        self.total_memory = 0;
        self.free_memory = 0;
        
        for i in 0..self.region_count {
            if let Some(region) = self.memory_regions[i] {
                self.total_memory += region.size;
                
                if region.available {
                    self.free_memory += region.size;
                }
            }
        }
    }
    
    fn init_buddy_allocator(&mut self) {
        // 利用可能なメモリ領域をバディアロケータに追加
        let mut available_regions = Vec::new();
        
        for i in 0..self.region_count {
            if let Some(region) = self.memory_regions[i] {
                if region.available {
                    available_regions.push(region);
                }
            }
        }
        
        self.buddy_allocator.init(available_regions);
    }
    
    pub fn allocate_page(&mut self, size: PageSize) -> Option<usize> {
        let bytes = size.bytes();
        self.buddy_allocator.allocate(bytes)
    }
    
    pub fn free_page(&mut self, addr: usize, size: PageSize) {
        let bytes = size.bytes();
        self.buddy_allocator.free(addr, bytes);
    }
    
    pub fn get_total_memory(&self) -> usize {
        self.total_memory
    }
    
    pub fn get_free_memory(&self) -> usize {
        self.free_memory
    }
} 