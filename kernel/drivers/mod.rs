// ドライバーサブシステムモジュール
// AetherOS用デバイスドライバーフレームワーク
// 作成者: AetherOSチーム

//! # デバイスドライバーサブシステム
//! 
//! このモジュールは、AetherOSのデバイスドライバーのフレームワークとドライバー実装を提供します。
//! 各種デバイスドライバーの構造化された実装と効率的なリソース管理を行います。
//! 
//! ## 特徴
//! 
//! - モジュール化された設計: 各デバイスタイプごとに独立したサブシステム
//! - プラグアンドプレイ: 動的なデバイス検出と設定
//! - ホットプラグ対応: デバイスの挿入/削除を動的に処理
//! - 電源管理: 省電力制御と管理
//! - 高性能I/O: 最適化されたデータ転送パス
//! - 安全性: メモリ安全なRustによる実装
//! - 拡張性: 新しいデバイスドライバーの追加が容易

use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::{Mutex, RwLock};

use crate::sync::OnceCell;
use crate::event::{EventManager, EventType, EventHandler};

pub mod pci;
pub mod usb;
pub mod block;
pub mod char;
pub mod gpu;
pub mod input;
pub mod net;
pub mod platform;
pub mod acpi;
pub mod nvme;
pub mod virtio;
pub mod scsi;
pub mod storage;
pub mod clock;

/// ドライバーの初期化状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverInitState {
    /// 未初期化
    NotInitialized,
    /// 初期化中
    Initializing,
    /// 初期化完了
    Initialized,
    /// 初期化失敗
    Failed,
}

/// ドライバーの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DriverType {
    /// バス制御ドライバー (PCI, USB等)
    Bus,
    /// ブロックデバイスドライバー (ディスク等)
    Block,
    /// キャラクタデバイスドライバー (シリアル等)
    Char,
    /// ネットワークデバイスドライバー
    Network,
    /// 入力デバイスドライバー (キーボード、マウス等)
    Input,
    /// グラフィックデバイスドライバー
    Graphics,
    /// オーディオデバイスドライバー
    Audio,
    /// 電源管理ドライバー
    Power,
    /// プラットフォーム依存ドライバー
    Platform,
    /// その他
    Other,
}

/// ドライバー情報
pub struct DriverInfo {
    /// ドライバー名
    pub name: String,
    /// ドライバーの種類
    pub driver_type: DriverType,
    /// ドライバーのバージョン
    pub version: String,
    /// ドライバーの作者
    pub author: String,
    /// ドライバーの説明
    pub description: String,
    /// ドライバーの初期化状態
    pub state: DriverInitState,
    /// ドライバーインスタンス (任意の型)
    pub instance: Option<Arc<dyn Any + Send + Sync>>,
}

impl DriverInfo {
    /// 新しいドライバー情報を作成
    pub fn new(
        name: &str,
        driver_type: DriverType,
        version: &str,
        author: &str,
        description: &str,
    ) -> Self {
        Self {
            name: String::from(name),
            driver_type,
            version: String::from(version),
            author: String::from(author),
            description: String::from(description),
            state: DriverInitState::NotInitialized,
            instance: None,
        }
    }
}

/// デバイス検出イベント
#[derive(Debug, Clone)]
pub enum DeviceEvent {
    /// デバイス追加
    Added(String),
    /// デバイス削除
    Removed(String),
    /// デバイス変更
    Changed(String),
}

/// ドライバーマネージャー
pub struct DriverManager {
    /// 初期化完了フラグ
    initialized: AtomicBool,
    /// 登録済みドライバー
    drivers: RwLock<BTreeMap<String, DriverInfo>>,
    /// デバイス検出カウンタ
    device_counter: AtomicU32,
    /// 最後のスキャン時間
    last_scan: AtomicU32,
    /// イベントハンドラーID
    event_handler_id: Mutex<Option<usize>>,
}

impl DriverManager {
    /// ドライバーマネージャーのグローバルインスタンス
    pub static INSTANCE: OnceCell<DriverManager> = OnceCell::new();
    
    /// 新しいドライバーマネージャーを作成
    pub fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            drivers: RwLock::new(BTreeMap::new()),
            device_counter: AtomicU32::new(0),
            last_scan: AtomicU32::new(0),
            event_handler_id: Mutex::new(None),
        }
    }
    
    /// ドライバーサブシステムを初期化
    pub fn initialize(&self) -> Result<(), &'static str> {
        if self.initialized.load(Ordering::SeqCst) {
            return Ok(());
        }
        
        log::info!("ドライバーマネージャーを初期化中...");
        
        // イベントハンドラーを登録
        self.register_event_handlers();

        log::info!("ACPIサブシステムを初期化中...");

        // ACPIサブシステムを初期化
        if let Err(e) = self.init_acpi() {
            // 世界一の実装を目指すなら、エラーの種類に応じて処理を分岐
            // 例: 致命的なエラー(テーブル破損など)であればパニックも検討
            // 軽微なエラー(一部機能の初期化失敗)であれば警告に留め、ログに詳細情報を記録
            log::error!("[DriverManager] ACPIサブシステムの初期化にエラーが発生しました: {}. 詳細情報: {:?}.", e, acpi::get_last_error_details()); 
            // 状況に応じて致命的エラーとして起動を停止するか判断
            // if acpi::is_error_fatal(&e) { 
            //     return Err("ACPIサブシステムのクリティカルな初期化に失敗しました。システム起動を継続できません。");
            // }
            return Err("ACPIサブシステムの初期化に失敗しました"); // 従来のエラー伝播
        }

        // ブロックデバイスサブシステムを初期化
        if let Err(e) = self.init_block_devices() {
            log::error!("ブロックデバイスサブシステムの初期化に失敗: {}", e);
            return Err("ブロックデバイスサブシステムの初期化に失敗しました");
        }
        
        // USBサブシステムを初期化
        if let Err(e) = self.init_usb() {
            log::warn!("USBサブシステムの初期化に失敗: {} (継続)", e);
            // USBは必須ではないため、警告に留める
        }
        
        // NVMeサブシステムを初期化
        if let Err(e) = self.init_nvme() {
            log::warn!("NVMeサブシステムの初期化に失敗: {} (継続)", e);
        }
        
        // 入力デバイスサブシステムを初期化
        if let Err(e) = self.init_input() {
            log::warn!("入力デバイスサブシステムの初期化に失敗: {} (継続)", e);
        }
        
        // グラフィックサブシステムを初期化
        if let Err(e) = self.init_graphics() {
            log::warn!("グラフィックサブシステムの初期化に失敗: {} (継続)", e);
        }
        
        // ネットワークサブシステムを初期化
        if let Err(e) = self.init_network() {
            log::warn!("ネットワークサブシステムの初期化に失敗: {} (継続)", e);
        }
        
        // プラットフォーム固有ドライバーを初期化
        if let Err(e) = self.init_platform() {
            log::warn!("プラットフォームドライバーの初期化に失敗: {} (継続)", e);
        }
        
        // 初期デバイススキャンを実行
        match self.scan_devices() {
            Ok(count) => log::info!("初期デバイススキャン完了: {}個のデバイスを検出", count),
            Err(e) => log::warn!("初期デバイススキャンでエラー: {}", e),
        }
        
        self.initialized.store(true, Ordering::SeqCst);
        log::info!("ドライバーマネージャーの初期化完了");
        
        Ok(())
    }
    
    /// イベントハンドラーを登録
    fn register_event_handlers(&self) {
        let handler = Arc::new(DeviceEventHandler::new());
        if let Some(event_manager) = EventManager::global() {
            let handler_id = event_manager.register_handler(EventType::DeviceAdded, handler.clone());
            *self.event_handler_id.lock() = Some(handler_id);
            log::debug!("デバイスイベントハンドラーを登録: ID={}", handler_id);
        }
    }
    
    /// PCIサブシステムの初期化
    fn init_pci(&self) -> Result<(), &'static str> {
        log::info!("PCIサブシステムを初期化中...");
        
        // PCIドライバーを登録
        let pci_driver = DriverInfo::new(
            "pci",
            DriverType::Bus,
            "1.0.0",
            "AetherOS Team",
            "PCI バス制御ドライバー"
        );
        
        self.register_driver(pci_driver);
        
        // PCIサブシステムを実際に初期化
        pci::init().map_err(|e| {
            log::error!("PCI初期化エラー: {}", e);
            "PCIサブシステムの初期化に失敗"
        })?;
        
        log::info!("PCIサブシステム初期化完了");
        Ok(())
    }
    
    /// USBサブシステムの初期化
    fn init_usb(&self) -> Result<(), &'static str> {
        log::info!("USBサブシステムを初期化中...");
        
        // USBドライバーを登録
        let usb_driver = DriverInfo::new(
            "usb",
            DriverType::Bus,
            "1.0.0",
            "AetherOS Team",
            "USB バス制御ドライバー"
        );
        
        self.register_driver(usb_driver);
        
        // USBサブシステムを実際に初期化
        usb::init().map_err(|e| {
            log::error!("USB初期化エラー: {}", e);
            "USBサブシステムの初期化に失敗"
        })?;
        
        // USB HOST コントローラーを検出・初期化
        let detected_controllers = usb::detect_controllers()?;
        log::info!("USB HOSTコントローラー検出: {}個", detected_controllers);
        
        for i in 0..detected_controllers {
            match usb::init_controller(i) {
                Ok(controller_type) => {
                    log::info!("USB HOSTコントローラー{}を初期化: {:?}", i, controller_type);
                },
                Err(e) => {
                    log::warn!("USB HOSTコントローラー{}の初期化に失敗: {}", i, e);
                }
            }
        }
        
        log::info!("USBサブシステム初期化完了");
        Ok(())
    }
    
    /// ブロックデバイスサブシステムの初期化
    fn init_block_devices(&self) -> Result<(), &'static str> {
        log::info!("ブロックデバイスサブシステムを初期化中...");
        
        // ブロックデバイスドライバーを登録
        let block_driver = DriverInfo::new(
            "block",
            DriverType::Block,
            "1.0.0",
            "AetherOS Team",
            "ブロックデバイス管理ドライバー"
        );
        
        self.register_driver(block_driver);
        
        // ブロックデバイスサブシステムを実際に初期化
        block::init().map_err(|e| {
            log::error!("ブロックデバイス初期化エラー: {}", e);
            "ブロックデバイスサブシステムの初期化に失敗"
        })?;
        
        // 一般的なストレージドライバーを初期化
        storage::init().map_err(|e| {
            log::error!("ストレージドライバー初期化エラー: {}", e);
            "ストレージドライバーの初期化に失敗"
        })?;
        
        // SCSIサブシステムを初期化
        scsi::init().map_err(|e| {
            log::warn!("SCSIサブシステム初期化エラー: {} (継続)", e);
            // SCSIは必須ではないため警告のみ
            "SCSI初期化失敗"
        }).ok();
        
        log::info!("ブロックデバイスサブシステム初期化完了");
        Ok(())
    }
    
    /// NVMeサブシステムの初期化
    fn init_nvme(&self) -> Result<(), &'static str> {
        log::info!("NVMeサブシステムを初期化中...");
        
        // NVMeドライバーを登録
        let nvme_driver = DriverInfo::new(
            "nvme",
            DriverType::Block,
            "1.0.0",
            "AetherOS Team",
            "NVMe SSDドライバー"
        );
        
        self.register_driver(nvme_driver);
        
        // NVMeサブシステムを実際に初期化
        nvme::init().map_err(|e| {
            log::error!("NVMe初期化エラー: {}", e);
            "NVMeサブシステムの初期化に失敗"
        })?;
        
        // NVMeデバイスをスキャン
        let nvme_devices = nvme::scan_devices()?;
        log::info!("NVMeデバイス検出: {}個", nvme_devices.len());
        
        for device in nvme_devices {
            match nvme::init_device(&device) {
                Ok(info) => {
                    log::info!("NVMeデバイス初期化完了: {} ({}GB)", 
                              device.name, info.capacity_gb);
                },
                Err(e) => {
                    log::warn!("NVMeデバイス{}の初期化に失敗: {}", device.name, e);
                }
            }
        }
        
        log::info!("NVMeサブシステム初期化完了");
        Ok(())
    }
    
    /// VirtIOサブシステムの初期化
    fn init_virtio(&self) -> Result<(), &'static str> {
        log::info!("VirtIOサブシステムを初期化中...");
        
        // VirtIOドライバーを登録
        let virtio_driver = DriverInfo::new(
            "virtio",
            DriverType::Platform,
            "1.0.0",
            "AetherOS Team",
            "VirtIO仮想化ドライバー"
        );
        
        self.register_driver(virtio_driver);
        
        // VirtIOサブシステムを実際に初期化
        virtio::init().map_err(|e| {
            log::error!("VirtIO初期化エラー: {}", e);
            "VirtIOサブシステムの初期化に失敗"
        })?;
        
        // VirtIOデバイスをスキャンして初期化
        let virtio_devices = virtio::scan_devices()?;
        log::info!("VirtIOデバイス検出: {}個", virtio_devices.len());
        
        for device in virtio_devices {
            match virtio::init_device(&device) {
                Ok(device_type) => {
                    log::info!("VirtIOデバイス初期化完了: {} (タイプ: {:?})", 
                              device.id, device_type);
                    
                    // デバイスタイプ別の追加初期化
                    match device_type {
                        virtio::DeviceType::Network => {
                            virtio::init_network_device(&device)?;
                        },
                        virtio::DeviceType::Block => {
                            virtio::init_block_device(&device)?;
                        },
                        virtio::DeviceType::Console => {
                            virtio::init_console_device(&device)?;
                        },
                        virtio::DeviceType::Gpu => {
                            virtio::init_gpu_device(&device)?;
                        },
                        _ => {
                            log::debug!("VirtIOデバイス{}のタイプ{:?}は特別な初期化不要", 
                                       device.id, device_type);
                        }
                    }
                },
                Err(e) => {
                    log::warn!("VirtIOデバイス{}の初期化に失敗: {}", device.id, e);
                }
            }
        }
        
        log::info!("VirtIOサブシステム初期化完了");
        Ok(())
    }
    
    /// 入力デバイスサブシステムの初期化
    fn init_input(&self) -> Result<(), &'static str> {
        log::info!("入力デバイスサブシステムを初期化中...");
        
        // 入力デバイスドライバーを登録
        let input_driver = DriverInfo::new(
            "input",
            DriverType::Input,
            "1.0.0",
            "AetherOS Team",
            "入力デバイス管理ドライバー"
        );
        
        self.register_driver(input_driver);
        
        // 入力デバイスサブシステムを実際に初期化
        input::init().map_err(|e| {
            log::error!("入力デバイス初期化エラー: {}", e);
            "入力デバイスサブシステムの初期化に失敗"
        })?;
        
        // PS/2キーボード・マウスドライバーを初期化
        match input::init_ps2() {
            Ok(devices) => {
                log::info!("PS/2デバイス初期化完了: {}個のデバイス", devices);
            },
            Err(e) => {
                log::warn!("PS/2デバイス初期化に失敗: {} (継続)", e);
            }
        }
        
        log::info!("入力デバイスサブシステム初期化完了");
        Ok(())
    }
    
    /// グラフィックサブシステムの初期化
    fn init_graphics(&self) -> Result<(), &'static str> {
        log::info!("グラフィックサブシステムを初期化中...");
        
        // グラフィックドライバーを登録
        let graphics_driver = DriverInfo::new(
            "graphics",
            DriverType::Graphics,
            "1.0.0",
            "AetherOS Team",
            "グラフィック管理ドライバー"
        );
        
        self.register_driver(graphics_driver);
        
        // グラフィックサブシステムを実際に初期化
        gpu::init().map_err(|e| {
            log::error!("グラフィック初期化エラー: {}", e);
            "グラフィックサブシステムの初期化に失敗"
        })?;
        
        // フレームバッファドライバーを初期化
        match gpu::init_framebuffer() {
            Ok(fb_info) => {
                log::info!("フレームバッファ初期化完了: {}x{} @ {}bpp", 
                          fb_info.width, fb_info.height, fb_info.bpp);
            },
            Err(e) => {
                log::warn!("フレームバッファ初期化に失敗: {}", e);
            }
        }
        
        log::info!("グラフィックサブシステム初期化完了");
        Ok(())
    }
    
    /// ネットワークサブシステムの初期化
    fn init_network(&self) -> Result<(), &'static str> {
        log::info!("ネットワークサブシステムを初期化中...");
        
        // ネットワークドライバーを登録
        let network_driver = DriverInfo::new(
            "network",
            DriverType::Network,
            "1.0.0",
            "AetherOS Team",
            "ネットワーク管理ドライバー"
        );
        
        self.register_driver(network_driver);
        
        // ネットワークサブシステムを実際に初期化
        net::init().map_err(|e| {
            log::error!("ネットワーク初期化エラー: {}", e);
            "ネットワークサブシステムの初期化に失敗"
        })?;
        
        // ネットワークデバイスをスキャン
        let network_devices = net::scan_devices()?;
        log::info!("ネットワークデバイス検出: {}個", network_devices.len());
        
        for device in network_devices {
            match net::init_device(&device) {
                Ok(info) => {
                    log::info!("ネットワークデバイス初期化完了: {} (MAC: {})", 
                              device.name, info.mac_address);
                },
                Err(e) => {
                    log::warn!("ネットワークデバイス{}の初期化に失敗: {}", device.name, e);
                }
            }
        }
        
        log::info!("ネットワークサブシステム初期化完了");
        Ok(())
    }
    
    /// プラットフォーム固有ドライバーの初期化
    fn init_platform(&self) -> Result<(), &'static str> {
        log::info!("プラットフォームドライバーを初期化中...");
        
        // プラットフォームドライバーを登録
        let platform_driver = DriverInfo::new(
            "platform",
            DriverType::Platform,
            "1.0.0",
            "AetherOS Team",
            "プラットフォーム固有ドライバー"
        );
        
        self.register_driver(platform_driver);
        
        // プラットフォーム固有の初期化
        platform::init().map_err(|e| {
            log::error!("プラットフォーム初期化エラー: {}", e);
            "プラットフォームドライバーの初期化に失敗"
        })?;
        
        // VirtIOサブシステムの初期化（仮想環境の場合）
        if platform::is_virtualized() {
            if let Err(e) = self.init_virtio() {
                log::warn!("VirtIO初期化に失敗: {} (継続)", e);
            }
        }
        
        // クロック・タイマードライバーを初期化
        match clock::init() {
            Ok(timer_sources) => {
                log::info!("タイマードライバー初期化完了: {}個のタイマーソース", timer_sources);
            },
            Err(e) => {
                log::warn!("タイマードライバー初期化に失敗: {}", e);
            }
        }
        
        log::info!("プラットフォームドライバー初期化完了");
        Ok(())
    }
    
    /// ドライバーを登録
    pub fn register_driver(&self, mut info: DriverInfo) {
        info.state = DriverInitState::Initializing;
        let name = info.name.clone();
        self.drivers.write().insert(name.clone(), info);
        log::debug!("ドライバー登録: {}", name);
    }
    
    /// 指定されたドライバーの情報を取得
    pub fn get_driver_info(&self, name: &str) -> Option<DriverInfo> {
        self.drivers.read().get(name).cloned()
    }
    
    /// 全ドライバーの情報を取得
    pub fn get_all_drivers(&self) -> Vec<DriverInfo> {
        self.drivers.read().values().cloned().collect()
    }
    
    /// 指定されたタイプのドライバー一覧を取得
    pub fn get_drivers_by_type(&self, driver_type: DriverType) -> Vec<DriverInfo> {
        self.drivers.read()
            .values()
            .filter(|info| info.driver_type == driver_type)
            .cloned()
            .collect()
    }
    
    /// デバイスイベントを処理
    pub fn handle_device_event(&self, event: DeviceEvent) {
        match event {
            DeviceEvent::Added(device) => {
                log::info!("デバイス追加: {}", device);
                self.load_driver_for_device(&device);
            },
            DeviceEvent::Removed(device) => {
                log::info!("デバイス削除: {}", device);
                self.unload_driver_for_device(&device);
            },
            DeviceEvent::Changed(device) => {
                log::info!("デバイス変更: {}", device);
                self.reload_driver_for_device(&device);
            },
        }
    }
    
    /// デバイス用ドライバーをロード
    fn load_driver_for_device(&self, device: &str) {
        log::debug!("デバイス{}用ドライバーをロード中...", device);
        
        // デバイス名からドライバータイプを推定
        let driver_type = if device.starts_with("pci:") {
            DriverType::Bus
        } else if device.starts_with("usb:") {
            DriverType::Bus
        } else if device.starts_with("nvme") {
            DriverType::Block
        } else if device.starts_with("sd") || device.starts_with("hd") {
            DriverType::Block
        } else if device.starts_with("eth") || device.starts_with("wlan") {
            DriverType::Network
        } else if device.starts_with("input") {
            DriverType::Input
        } else if device.starts_with("fb") || device.starts_with("drm") {
            DriverType::Graphics
        } else {
            DriverType::Other
        };
        
        // 適切なドライバーを探索してロード
        match driver_type {
            DriverType::Bus => {
                log::debug!("バスデバイス{}を検出", device);
                // バスドライバーは既に初期化済み
            },
            DriverType::Block => {
                log::debug!("ブロックデバイス{}を検出", device);
                if let Err(e) = block::add_device(device) {
                    log::warn!("ブロックデバイス{}の追加に失敗: {}", device, e);
                }
            },
            DriverType::Network => {
                log::debug!("ネットワークデバイス{}を検出", device);
                if let Err(e) = net::add_device(device) {
                    log::warn!("ネットワークデバイス{}の追加に失敗: {}", device, e);
                }
            },
            DriverType::Input => {
                log::debug!("入力デバイス{}を検出", device);
                if let Err(e) = input::add_device(device) {
                    log::warn!("入力デバイス{}の追加に失敗: {}", device, e);
                }
            },
            DriverType::Graphics => {
                log::debug!("グラフィックデバイス{}を検出", device);
                if let Err(e) = gpu::add_device(device) {
                    log::warn!("グラフィックデバイス{}の追加に失敗: {}", device, e);
                }
            },
            _ => {
                log::debug!("未知のデバイスタイプ: {}", device);
            }
        }
    }
    
    /// デバイス用ドライバーをアンロード
    fn unload_driver_for_device(&self, device: &str) {
        log::debug!("デバイス{}用ドライバーをアンロード中...", device);
        
        // デバイスタイプに応じてアンロード処理を実行
        if device.starts_with("nvme") || device.starts_with("sd") || device.starts_with("hd") {
            if let Err(e) = block::remove_device(device) {
                log::warn!("ブロックデバイス{}の削除に失敗: {}", device, e);
            }
        } else if device.starts_with("eth") || device.starts_with("wlan") {
            if let Err(e) = net::remove_device(device) {
                log::warn!("ネットワークデバイス{}の削除に失敗: {}", device, e);
            }
        } else if device.starts_with("input") {
            if let Err(e) = input::remove_device(device) {
                log::warn!("入力デバイス{}の削除に失敗: {}", device, e);
            }
        } else if device.starts_with("fb") || device.starts_with("drm") {
            if let Err(e) = gpu::remove_device(device) {
                log::warn!("グラフィックデバイス{}の削除に失敗: {}", device, e);
            }
        }
    }
    
    /// デバイス用ドライバーをリロード
    fn reload_driver_for_device(&self, device: &str) {
        log::debug!("デバイス{}用ドライバーをリロード中...", device);
        self.unload_driver_for_device(device);
        self.load_driver_for_device(device);
    }
    
    /// デバイスのスキャンを実行
    pub fn scan_devices(&self) -> Result<u32, &'static str> {
        let now = crate::time::current_unix_time();
        self.last_scan.store(now, Ordering::SeqCst);
        
        // デバイスカウンタをリセット
        self.device_counter.store(0, Ordering::SeqCst);
        
        // PCIデバイスをスキャン
        match pci::scan_devices() {
            Ok(pci_devices) => {
                for pci_device in pci_devices {
                    let device_path = format!("pci:{:04x}:{:04x}:{:02x}.{:02x}",
                                          pci_device.vendor_id,
                                          pci_device.device_id,
                                          pci_device.bus,
                                          pci_device.device);
                    
                    // デバイスの追加イベントを発行
                    let event = DeviceEvent::Added(device_path);
                    self.handle_device_event(event);
                    
                    // カウンタを増やす
                    self.device_counter.fetch_add(1, Ordering::SeqCst);
                }
            },
            Err(e) => {
                log::error!("PCIデバイスのスキャンに失敗: {}", e);
            }
        }

        // USBデバイスをスキャン
        match usb::scan_devices() {
            Ok(usb_devices) => {
                for usb_device in usb_devices {
                    let device_path = format!("usb:{:04x}:{:04x}",
                                          usb_device.vendor_id,
                                          usb_device.product_id);
                    
                    // デバイスの追加イベントを発行
                    let event = DeviceEvent::Added(device_path);
                    self.handle_device_event(event);
                    
                    // カウンタを増やす
                    self.device_counter.fetch_add(1, Ordering::SeqCst);
                }
            },
            Err(e) => {
                log::error!("USBデバイスのスキャンに失敗: {}", e);
            }
        }

        // ブロックデバイスをスキャン
        match block::scan_devices() {
            Ok(block_devices) => {
                for block_device in block_devices {
                    let device_path = format!("block:{}", block_device.name);
                    
                    // デバイスの追加イベントを発行
                    let event = DeviceEvent::Added(device_path);
                    self.handle_device_event(event);
                    
                    // カウンタを増やす
                    self.device_counter.fetch_add(1, Ordering::SeqCst);
                }
            },
            Err(e) => {
                log::error!("ブロックデバイスのスキャンに失敗: {}", e);
            }
        }

        // 入力デバイスをスキャン
        match input::scan_devices() {
            Ok(input_devices) => {
                for input_device in input_devices {
                    let device_path = format!("input:{}", input_device.name);
                    
                    // デバイスの追加イベントを発行
                    let event = DeviceEvent::Added(device_path);
                    self.handle_device_event(event);
                    
                    // カウンタを増やす
                    self.device_counter.fetch_add(1, Ordering::SeqCst);
                }
            },
            Err(e) => {
                log::error!("入力デバイスのスキャンに失敗: {}", e);
            }
        }
        
        // 検出されたデバイス総数を返す
        let count = self.device_counter.load(Ordering::SeqCst);
        Ok(count)
    }

    fn init_acpi(&self) -> Result<(), &'static str> {
        log::info!("ACPIサブシステムを初期化中...");
        
        // ACPI テーブルを検出
        let acpi_tables = match acpi::detect_tables() {
            Ok(tables) => tables,
            Err(e) => {
                log::warn!("ACPI テーブル検出に失敗: {:?}", e);
                return Err("ACPI テーブルを検出できませんでした");
            }
        };
        
        // ACPI テーブルをパース
        let acpi_info = match acpi::parse_tables(&acpi_tables) {
            Ok(info) => info,
            Err(e) => {
                log::warn!("ACPI テーブルの解析に失敗: {:?}", e);
                return Err("ACPI テーブルを解析できませんでした");
            }
        };
        
        // 電源管理サブシステムを初期化
        if let Err(e) = power::init_from_acpi(&acpi_info) {
            log::warn!("電源管理サブシステムの初期化に失敗: {:?}", e);
            // 電源管理は必須ではないので続行
        }
        
        // 温度管理サブシステムを初期化
        if let Err(e) = thermal::init_from_acpi(&acpi_info) {
            log::warn!("温度管理サブシステムの初期化に失敗: {:?}", e);
            // 温度管理は必須ではないので続行
        }
        
        // 割り込みコントローラの設定
        if let Err(e) = interrupts::configure_from_acpi(&acpi_info) {
            log::error!("割り込みコントローラの設定に失敗: {:?}", e);
            return Err("割り込みコントローラを設定できませんでした");
        }
        
        // ACPIイベントハンドラを登録
        acpi::register_event_handlers();
        
        log::info!("ACPIサブシステムの初期化に成功");
        Ok(())
    }
}

/// デバイスイベントハンドラー
struct DeviceEventHandler {
    id: AtomicU32,
}

impl DeviceEventHandler {
    /// 新しいデバイスイベントハンドラーを作成
    pub fn new() -> Self {
        Self {
            id: AtomicU32::new(0),
        }
    }
}

impl EventHandler for DeviceEventHandler {
    fn handle(&self, event_type: EventType, data: Arc<dyn Any + Send + Sync>) -> bool {
        if let EventType::Device = event_type {
            if let Some(event) = data.downcast_ref::<DeviceEvent>() {
                if let Some(manager) = DriverManager::INSTANCE.get() {
                    manager.handle_device_event(event.clone());
                    return true;
                }
            }
        }
        false
    }
    
    fn id(&self) -> u32 {
        self.id.load(Ordering::Relaxed)
    }
    
    fn set_id(&self, id: u32) {
        self.id.store(id, Ordering::Relaxed);
    }
}

/// ドライバーサブシステムの初期化
pub fn init() -> Result<(), &'static str> {
    let manager = DriverManager::new();
    manager.initialize()?;
    
    // グローバルインスタンスを設定
    DriverManager::INSTANCE.set(manager)
        .map_err(|_| "ドライバーマネージャーの初期化に失敗しました")?;
    
    Ok(())
}

/// ドライバーに関する診断情報を出力
pub fn print_diagnostic_info() {
    if let Some(manager) = DriverManager::INSTANCE.get() {
        let drivers = manager.get_all_drivers();
        
        log::info!("登録済みドライバー一覧 ({} 個):", drivers.len());
        
        for driver in &drivers {
            log::info!(
                "  {} ({:?}): バージョン {}, 状態: {:?}",
                driver.name,
                driver.driver_type,
                driver.version,
                driver.state
            );
        }
        
        // 各サブシステムの診断情報を出力
        pci::print_diagnostic_info();
        usb::hci::print_diagnostic_info();

        // 他のサブシステムの診断情報を出力
        block::print_diagnostic_info();
        nvme::print_diagnostic_info();
        virtio::print_diagnostic_info();
        net::print_diagnostic_info();
        gpu::print_diagnostic_info();
        input::print_diagnostic_info();
        platform::print_diagnostic_info();

        log::info!("サブシステム間の依存関係:");
        log::info!("  PCI <- [NVMe, VirtIO, GPU, Network]");
        log::info!("  USB <- [Input, Storage]");
        log::info!("  ACPI <- [Platform, Power Management]");
    } else {
        log::warn!("ドライバーマネージャーが初期化されていません");
    }
} 