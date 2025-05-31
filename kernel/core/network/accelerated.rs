// AetherOS ネットワークハードウェアアクセラレーション管理
//
// ネットワーク処理のハードウェアアクセラレーションを統合管理するサブシステム。
// SmartNIC、DPDK、RDMA、TOE (TCP Offload Engine)、暗号アクセラレータなどを活用し、
// 最高のパフォーマンスを実現します。

use crate::arch;
use crate::core::memory::{DmaBuffer, MemoryRegion, PhysicalAddress};
use crate::core::sync::{Mutex, RwLock, SpinLock, AtomicBool, AtomicU64, AtomicU32, AtomicUsize};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

/// グローバルアクセラレーションマネージャー
static mut ACCELERATION_MANAGER: Option<Arc<HardwareAccelerationManager>> = None;

/// アクセラレーション初期化済みフラグ
static ACCELERATION_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// アクセラレーションサブシステムの初期化
pub fn init() {
    log::info!("ネットワークハードウェアアクセラレーションを初期化しています...");
    
    // ハードウェア検出
    let devices = discover_acceleration_devices();
    
    // 設定の作成
    let config = AccelerationConfig {
        enable_smartnic: true,
        enable_rdma: true,
        enable_toe: true,
        enable_crypto_accel: true,
        enable_compression: true,
        enable_pattern_matching: true,
        zerocopy_mode: ZeroCopyMode::Optimal,
        scheduler_policy: SchedulerPolicy::Throughput,
    };
    
    // アクセラレーションマネージャーの作成
    let manager = Arc::new(HardwareAccelerationManager::new(devices, config));
    
    // グローバルインスタンスを設定
    unsafe {
        ACCELERATION_MANAGER = Some(manager);
    }
    
    // デバイスの初期化
    let manager = global_manager();
    for device in manager.devices.values() {
        if let Err(e) = device.initialize() {
            log::warn!("アクセラレーションデバイス初期化失敗: {:?}", e);
        }
    }
    
    ACCELERATION_INITIALIZED.store(true, Ordering::SeqCst);
    
    log::info!("ネットワークハードウェアアクセラレーションの初期化が完了しました");
}

/// アクセラレーションサブシステムのシャットダウン
pub fn shutdown() {
    log::info!("ネットワークハードウェアアクセラレーションをシャットダウンしています...");
    
    ACCELERATION_INITIALIZED.store(false, Ordering::SeqCst);
    
    unsafe {
        if let Some(manager) = ACCELERATION_MANAGER.as_ref() {
            // アクティブなリソースをクリーンアップ
            manager.cleanup();
        }
        
        ACCELERATION_MANAGER = None;
    }
    
    log::info!("ネットワークハードウェアアクセラレーションのシャットダウンが完了しました");
}

/// グローバルマネージャーを取得
pub fn global_manager() -> &'static HardwareAccelerationManager {
    unsafe {
        ACCELERATION_MANAGER.as_ref()
            .expect("ハードウェアアクセラレーションマネージャーが初期化されていません")
            .as_ref()
    }
}

/// アクセラレーションデバイスを検出
fn discover_acceleration_devices() -> BTreeMap<u32, Arc<dyn AccelerationDevice>> {
    let mut devices = BTreeMap::new();
    
    log::info!("ネットワークアクセラレーションデバイスを検索中...");
    
    // PCIバス上のアクセラレーションデバイスを検索
    for device_info in arch::pci::enumerate_devices() {
        match device_info.device_class {
            // ネットワークコントローラ
            0x02 => {
                if let Ok(device) = create_network_acceleration_device(device_info) {
                    log::info!("ネットワークアクセラレータを発見: {} (ID: {})", 
                              device.name(), device.id());
                    devices.insert(device.id(), device);
                }
            },
            // 暗号化プロセッサ
            0x10 => {
                if let Ok(device) = create_crypto_acceleration_device(device_info) {
                    log::info!("暗号化アクセラレータを発見: {} (ID: {})", 
                              device.name(), device.id());
                    devices.insert(device.id(), device);
                }
            },
            _ => {}
        }
    }
    
    // ソフトウェアフォールバックデバイスを追加
    if devices.is_empty() {
        log::warn!("ハードウェアアクセラレータが見つからないため、ソフトウェア実装を使用");
        let software_device = Arc::new(SoftwareAccelerationDevice::new());
        devices.insert(software_device.id(), software_device);
    }
    
    log::info!("{}個のアクセラレーションデバイスを検出", devices.len());
    devices
}

fn create_network_acceleration_device(device_info: arch::pci::DeviceInfo) -> Result<Arc<dyn AccelerationDevice>, AccelError> {
    // デバイス固有の機能を検出
    let capabilities = detect_network_capabilities(&device_info)?;
    
    Ok(Arc::new(SmartNicDevice::new(device_info)?))
}

fn create_crypto_acceleration_device(device_info: arch::pci::DeviceInfo) -> Result<Arc<dyn AccelerationDevice>, AccelError> {
    Ok(Arc::new(CryptoAccelerator::new(device_info)?))
}

fn detect_network_capabilities(device_info: &arch::pci::DeviceInfo) -> Result<Vec<AccelerationType>, AccelError> {
    let mut capabilities = Vec::new();
    
    // デバイス固有レジスタを読み取って機能を判定
    let feature_register = device_info.read_config_u32(0x80)?;
    
    if feature_register & 0x01 != 0 {
        capabilities.push(AccelerationType::TcpOffload);
    }
    if feature_register & 0x02 != 0 {
        capabilities.push(AccelerationType::Checksum);
    }
    if feature_register & 0x04 != 0 {
        capabilities.push(AccelerationType::Tso);
    }
    if feature_register & 0x08 != 0 {
        capabilities.push(AccelerationType::Lro);
    }
    if feature_register & 0x10 != 0 {
        capabilities.push(AccelerationType::RdmaOffload);
    }
    
    Ok(capabilities)
}

/// アクセラレーションタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccelerationType {
    /// TCP/IPオフロード
    TcpOffload,
    /// RDMAオフロード
    RdmaOffload,
    /// チェックサム計算
    Checksum,
    /// スキャッタギャザー
    ScatterGather,
    /// 暗号化/復号化
    Crypto,
    /// データ圧縮/展開
    Compression,
    /// パターンマッチング
    PatternMatching,
    /// パケットフィルタリング
    PacketFilter,
    /// 仮想化オフロード
    VirtualizationOffload,
    /// TCP Segmentation Offload
    Tso,
    /// Large Receive Offload
    Lro,
}

/// ゼロコピーモード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroCopyMode {
    /// 無効
    Disabled,
    /// 受信のみ
    RxOnly,
    /// 送信のみ
    TxOnly,
    /// 両方
    Full,
    /// 自動選択
    Optimal,
}

/// スケジューラポリシー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerPolicy {
    /// レイテンシ重視
    Latency,
    /// スループット重視
    Throughput,
    /// バランス
    Balanced,
    /// 省電力
    PowerEfficient,
}

/// オフロードポリシー
#[derive(Debug, Clone)]
pub struct OffloadPolicy {
    /// TSO有効
    pub enable_tso: bool,
    /// LRO有効
    pub enable_lro: bool,
    /// CSO（チェックサムオフロード）有効
    pub enable_cso: bool,
    /// RSS（Receive Side Scaling）有効
    pub enable_rss: bool,
    /// UFO（UDP Fragmentation Offload）有効
    pub enable_ufo: bool,
    /// GSO（Generic Segmentation Offload）有効
    pub enable_gso: bool,
    /// 暗号オフロード有効
    pub enable_crypto: bool,
    /// 圧縮オフロード有効
    pub enable_compression: bool,
}

impl Default for OffloadPolicy {
    fn default() -> Self {
        Self {
            enable_tso: true,
            enable_lro: true,
            enable_cso: true,
            enable_rss: true,
            enable_ufo: true,
            enable_gso: true,
            enable_crypto: true,
            enable_compression: true,
        }
    }
}

/// アクセラレーション設定
pub struct AccelerationConfig {
    /// SmartNIC有効
    pub enable_smartnic: bool,
    /// RDMA有効
    pub enable_rdma: bool,
    /// TOE有効
    pub enable_toe: bool,
    /// 暗号アクセラレータ有効
    pub enable_crypto_accel: bool,
    /// 圧縮アクセラレータ有効
    pub enable_compression: bool,
    /// パターンマッチング有効
    pub enable_pattern_matching: bool,
    /// ゼロコピーモード
    pub zerocopy_mode: ZeroCopyMode,
    /// スケジューラポリシー
    pub scheduler_policy: SchedulerPolicy,
}

/// ハードウェアアクセラレーションマネージャー
pub struct HardwareAccelerationManager {
    /// 利用可能なアクセラレーションデバイス
    devices: BTreeMap<u32, Arc<dyn AccelerationDevice>>,
    /// アクセラレーション設定
    config: AccelerationConfig,
    /// デフォルトオフロードポリシー
    offload_policy: OffloadPolicy,
    /// DMAエンジン
    dma_engine: DmaEngine,
    /// アクティブなオフロードタスク
    active_tasks: RwLock<BTreeMap<u64, OffloadTask>>,
    /// 次のタスクID
    next_task_id: AtomicU64,
    /// 統計情報
    stats: AccelerationStats,
}

impl HardwareAccelerationManager {
    /// 新しいアクセラレーションマネージャーを作成
    pub fn new(devices: BTreeMap<u32, Arc<dyn AccelerationDevice>>, config: AccelerationConfig) -> Self {
        Self {
            devices,
            config,
            offload_policy: OffloadPolicy::default(),
            dma_engine: DmaEngine::new(),
            active_tasks: RwLock::new(BTreeMap::new()),
            next_task_id: AtomicU64::new(1),
            stats: AccelerationStats::new(),
        }
    }
    
    /// オフロードポリシーを設定
    pub fn set_offload_policy(&mut self, policy: OffloadPolicy) {
        self.offload_policy = policy;
    }
    
    /// 指定されたタイプのアクセラレーションが利用可能か確認
    pub fn is_available(&self, accel_type: AccelerationType) -> bool {
        for device in self.devices.values() {
            if device.supports_acceleration(accel_type) {
                return true;
            }
        }
        false
    }
    
    /// タスクをオフロード
    pub fn offload_task(&self, task_type: AccelerationType, params: OffloadParams) -> Result<u64, AccelError> {
        // 適切なデバイスを検索
        let device = self.find_device_for_task(task_type)?;
        
        // タスクIDを割り当て
        let task_id = self.next_task_id.fetch_add(1, Ordering::SeqCst);
        
        // タスクを作成
        let task = OffloadTask {
            id: task_id,
            task_type,
            params: params.clone(),
            device_id: device.id(),
            status: TaskStatus::Submitted,
            result: None,
            submit_time: get_current_time(),
            complete_time: 0,
        };
        
        // タスクを登録
        {
            let mut tasks = self.active_tasks.write();
            tasks.insert(task_id, task);
        }
        
        // タスクをデバイスに送信
        device.submit_task(task_id, task_type, params)?;
        
        self.stats.total_tasks.fetch_add(1, Ordering::Relaxed);
        self.stats.active_tasks.fetch_add(1, Ordering::Relaxed);
        
        Ok(task_id)
    }
    
    /// タスク結果をポーリング
    pub fn poll_task(&self, task_id: u64) -> Result<TaskStatus, AccelError> {
        let tasks = self.active_tasks.read();
        
        if let Some(task) = tasks.get(&task_id) {
            return Ok(task.status);
        }
        
        Err(AccelError::InvalidTask)
    }
    
    /// タスク結果を待機
    pub fn wait_for_task(&self, task_id: u64) -> Result<TaskResult, AccelError> {
        log::debug!("タスク完了待機開始: ID={}", task_id);
        
        let start_time = get_current_time_ns();
        let timeout_duration = 30_000_000_000; // 30秒タイムアウト
        
        loop {
            // タスク状態を確認
            {
                let tasks = self.active_tasks.read();
                if let Some(task) = tasks.get(&task_id) {
                    match task.status {
                        TaskStatus::Completed => {
                            // タスク完了：結果を取得してタスクを削除
                            drop(tasks); // 読み取りロックを解放
                            let mut tasks_write = self.active_tasks.write();
                            if let Some(completed_task) = tasks_write.remove(&task_id) {
                                self.stats.active_tasks.fetch_sub(1, Ordering::Relaxed);
                                self.stats.completed_tasks.fetch_add(1, Ordering::Relaxed);
                                
                                log::debug!("タスク完了: ID={}", task_id);
                                return Ok(completed_task.result.unwrap_or(TaskResult::Success));
                            }
                            return Err(AccelError::InvalidTask);
                        },
                        TaskStatus::Failed => {
                            // タスク失敗：エラー情報を取得
                            drop(tasks);
                            let mut tasks_write = self.active_tasks.write();
                            if let Some(failed_task) = tasks_write.remove(&task_id) {
                                self.stats.active_tasks.fetch_sub(1, Ordering::Relaxed);
                                self.stats.failed_tasks.fetch_add(1, Ordering::Relaxed);
                                
                                log::warn!("タスク失敗: ID={}", task_id);
                                return Ok(failed_task.result.unwrap_or(TaskResult::Error(AccelError::TaskFailed)));
                            }
                            return Err(AccelError::InvalidTask);
                        },
                        TaskStatus::Cancelled => {
                            // タスクキャンセル
                            drop(tasks);
                            let mut tasks_write = self.active_tasks.write();
                            if let Some(_) = tasks_write.remove(&task_id) {
                                self.stats.active_tasks.fetch_sub(1, Ordering::Relaxed);
                                self.stats.cancelled_tasks.fetch_add(1, Ordering::Relaxed);
                            }
                            
                            log::debug!("タスクキャンセル済み: ID={}", task_id);
                            return Err(AccelError::TaskFailed);
                        },
                        _ => {
                            // まだ処理中：継続してポーリング
                        }
                    }
                } else {
                    // タスクが見つからない
                    return Err(AccelError::InvalidTask);
                }
            }
            
            // タイムアウトチェック
            let current_time = get_current_time_ns();
            if current_time - start_time > timeout_duration {
                log::warn!("タスク待機タイムアウト: ID={}", task_id);
                return Err(AccelError::Timeout);
            }
            
            // 少し待機してCPU使用率を下げる
            arch::cpu_relax();
            
            // 10ms待機
            arch::delay_ms(10);
        }
    }
    
    /// タスクをキャンセル
    pub fn cancel_task(&self, task_id: u64) -> Result<(), AccelError> {
        let tasks = self.active_tasks.read();
        
        if let Some(task) = tasks.get(&task_id) {
            let device_id = task.device_id;
            
            // デバイスにキャンセル要求を送信
            if let Some(device) = self.devices.get(&device_id) {
                device.cancel_task(task_id)?;
                
                // タスクを削除
                let mut tasks = self.active_tasks.write();
                tasks.remove(&task_id);
                
                self.stats.active_tasks.fetch_sub(1, Ordering::Relaxed);
                self.stats.cancelled_tasks.fetch_add(1, Ordering::Relaxed);
                
                return Ok(());
            }
        }
        
        Err(AccelError::InvalidTask)
    }
    
    /// 適切なデバイスを検索
    fn find_device_for_task(&self, task_type: AccelerationType) -> Result<&Arc<dyn AccelerationDevice>, AccelError> {
        // 要求されたタイプをサポートするデバイスを検索
        for device in self.devices.values() {
            if device.supports_acceleration(task_type) && device.is_available() {
                return Ok(device);
            }
        }
        
        Err(AccelError::NoSuitableDevice)
    }
    
    /// タスク完了通知（デバイスから呼び出される）
    pub fn notify_task_completion(&self, task_id: u64, result: TaskResult) {
        let mut tasks = self.active_tasks.write();
        
        if let Some(task) = tasks.get_mut(&task_id) {
            task.status = match &result {
                TaskResult::Success => TaskStatus::Completed,
                TaskResult::Error(_) => TaskStatus::Failed,
            };
            task.result = Some(result);
            task.complete_time = get_current_time();
        }
    }
    
    /// クリーンアップ処理
    pub fn cleanup(&self) {
        // すべてのアクティブなタスクをキャンセル
        let task_ids: Vec<u64> = {
            let tasks = self.active_tasks.read();
            tasks.keys().copied().collect()
        };
        
        for id in task_ids {
            let _ = self.cancel_task(id);
        }
        
        // すべてのデバイスをシャットダウン
        for device in self.devices.values() {
            let _ = device.shutdown();
        }
    }
    
    /// 統計情報を取得
    pub fn get_stats(&self) -> AccelerationStats {
        self.stats.clone()
    }
    
    /// アクティブかどうかを確認
    pub fn is_active(&self) -> bool {
        !self.devices.is_empty()
    }
}

/// アクセラレーションデバイスインターフェース
pub trait AccelerationDevice: Send + Sync {
    /// デバイスIDを取得
    fn id(&self) -> u32;
    
    /// デバイス名を取得
    fn name(&self) -> &str;
    
    /// デバイスタイプを取得
    fn device_type(&self) -> AccelerationType;
    
    /// デバイスを初期化
    fn initialize(&self) -> Result<(), AccelError>;
    
    /// デバイスをシャットダウン
    fn shutdown(&self) -> Result<(), AccelError>;
    
    /// 指定されたアクセラレーションタイプをサポートしているか確認
    fn supports_acceleration(&self, accel_type: AccelerationType) -> bool;
    
    /// デバイスが利用可能か確認
    fn is_available(&self) -> bool;
    
    /// タスクを送信
    fn submit_task(&self, task_id: u64, task_type: AccelerationType, params: OffloadParams) -> Result<(), AccelError>;
    
    /// タスクをキャンセル
    fn cancel_task(&self, task_id: u64) -> Result<(), AccelError>;
    
    /// デバイス固有の設定を適用
    fn apply_config(&self, config: &[u8]) -> Result<(), AccelError>;
    
    /// デバイス統計情報を取得
    fn get_stats(&self) -> DeviceStats;
}

/// SmartNICデバイス
pub struct SmartNicDevice {
    /// デバイスID
    id: u32,
    /// デバイス名
    name: String,
    /// サポートされる機能
    capabilities: Vec<AccelerationType>,
    /// デバイス状態
    state: AtomicU64,
    /// 統計情報
    stats: DeviceStats,
    /// デバイスタイプ
    device_type: NetworkAccelDeviceType,
    /// 重要レジスタモード
    critical_register_mode: bool,
    /// 最大DMAチャネル数
    max_dma_channels: u32,
}

impl SmartNicDevice {
    /// 新しいSmartNICデバイスを作成
    pub fn new(device_info: arch::AccelerationDeviceInfo) -> Result<Self, AccelError> {
        log::debug!("SmartNICデバイス初期化中: {}", device_info.name);
        
        // デバイス機能を検出
        let capabilities = Self::detect_capabilities(&device_info)?;
        
        // デバイス状態を初期化
        Ok(Self {
            id: device_info.device_id,
            name: device_info.name.clone(),
            capabilities,
            state: AtomicU64::new(0), // 停止状態
            stats: DeviceStats::new(),
            device_type: Self::detect_device_type(&device_info),
            critical_register_mode: false,
            max_dma_channels: 8,
        })
    }
    
    fn detect_capabilities(device_info: &arch::AccelerationDeviceInfo) -> Result<Vec<AccelerationType>, AccelError> {
        let mut capabilities = Vec::new();
        
        // ベンダーIDとデバイスIDに基づいて機能を判定
        match (device_info.vendor_id, device_info.device_id) {
            // Intel系ネットワークカード
            (0x8086, _) => {
                capabilities.extend_from_slice(&[
                    AccelerationType::TcpOffload,
                    AccelerationType::Checksum,
                    AccelerationType::Tso,
                    AccelerationType::Lro,
                ]);
            },
            // Mellanox ConnectX系
            (0x15b3, _) => {
                capabilities.extend_from_slice(&[
                    AccelerationType::RdmaOffload,
                    AccelerationType::Checksum,
                    AccelerationType::Crypto,
                ]);
            },
            // Broadcom系
            (0x14e4, _) => {
                capabilities.extend_from_slice(&[
                    AccelerationType::TcpOffload,
                    AccelerationType::Checksum,
                ]);
            },
            _ => {
                // 汎用的な機能のみ
                capabilities.push(AccelerationType::Checksum);
            }
        }
        
        Ok(capabilities)
    }
    
    /// デバイスタイプの検出
    fn detect_device_type(device_info: &arch::AccelerationDeviceInfo) -> NetworkAccelDeviceType {
        match device_info.vendor_id {
            0x8086 => NetworkAccelDeviceType::IntelE810,     // Intel
            0x15b3 => NetworkAccelDeviceType::MellanoxCX6,   // Mellanox
            0x14e4 => NetworkAccelDeviceType::BroadcomP5,    // Broadcom
            _ => NetworkAccelDeviceType::Generic,
        }
    }
}

impl AccelerationDevice for SmartNicDevice {
    fn id(&self) -> u32 {
        self.id
    }
    
    fn name(&self) -> &str {
        &self.name
    }
    
    fn device_type(&self) -> AccelerationType {
        AccelerationType::TcpOffload
    }
    
    fn initialize(&self) -> Result<(), AccelError> {
        // デバイス初期化
        self.state.store(1, Ordering::SeqCst); // 1 = 初期化済み
        Ok(())
    }
    
    fn shutdown(&self) -> Result<(), AccelError> {
        // デバイスのシャットダウン
        self.state.store(2, Ordering::SeqCst); // 2 = シャットダウン
        Ok(())
    }
    
    fn supports_acceleration(&self, accel_type: AccelerationType) -> bool {
        self.capabilities.contains(&accel_type)
    }
    
    fn is_available(&self) -> bool {
        self.state.load(Ordering::Relaxed) == 1
    }
    
    fn submit_task(&self, task_id: u64, task_type: AccelerationType, params: OffloadParams) -> Result<(), AccelError> {
        if !self.supports_acceleration(task_type) {
            return Err(AccelError::UnsupportedOperation);
        }
        
        log::debug!("SmartNICタスク送信: ID={}, タイプ={:?}", task_id, task_type);
        
        match task_type {
            AccelerationType::TcpOffload => self.submit_tcp_offload_task(task_id, params),
            AccelerationType::Checksum => self.submit_checksum_task(task_id, params),
            AccelerationType::Tso => self.submit_tso_task(task_id, params),
            AccelerationType::Lro => self.submit_lro_task(task_id, params),
            AccelerationType::RdmaOffload => self.submit_rdma_task(task_id, params),
            _ => Err(AccelError::UnsupportedOperation),
        }
    }
    
    fn cancel_task(&self, task_id: u64) -> Result<(), AccelError> {
        log::debug!("SmartNICタスクキャンセル: ID={}", task_id);
        
        // デバイス固有のキャンセル処理
        // ハードウェアレジスタに書き込んでタスクを停止
        self.write_control_register(0x10, task_id)?;
        self.write_control_register(0x14, 0x01); // キャンセルコマンド
        
        self.stats.cancelled_tasks.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    
    fn apply_config(&self, config: &[u8]) -> Result<(), AccelError> {
        log::debug!("SmartNIC設定適用: {}バイト", config.len());
        
        // 設定データを解析してデバイスに適用
        if config.len() < 4 {
            return Err(AccelError::InvalidParameter);
        }
        
        let config_version = u32::from_le_bytes([config[0], config[1], config[2], config[3]]);
        
        match config_version {
            1 => self.apply_config_v1(&config[4..]),
            2 => self.apply_config_v2(&config[4..]),
            _ => Err(AccelError::InvalidParameter),
        }
    }
}

impl SmartNicDevice {
    fn submit_tcp_offload_task(&self, task_id: u64, params: OffloadParams) -> Result<(), AccelError> {
        // TCP処理をハードウェアにオフロード
        if let OffloadParams::TcpOffload(tcp_params) = params {
            self.write_task_register(0x20, task_id)?;
            self.write_task_register(0x24, tcp_params.as_register_value())?;
            self.write_control_register(0x28, 0x01); // 開始コマンド
            
            self.stats.submitted_tasks.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err(AccelError::InvalidParameter)
        }
    }
    
    fn submit_checksum_task(&self, task_id: u64, params: OffloadParams) -> Result<(), AccelError> {
        // チェックサム計算をハードウェアにオフロード
        if let OffloadParams::Checksum(checksum_params) = params {
            self.write_task_register(0x30, task_id)?;
            self.write_task_register(0x34, checksum_params.as_register_value())?;
            self.write_control_register(0x38, 0x01); // 開始コマンド
            
            self.stats.submitted_tasks.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err(AccelError::InvalidParameter)
        }
    }
    
    fn write_control_register(&self, offset: u32, value: u64) -> Result<(), AccelError> {
        // レジスタ書き込み（MMIOアクセス実装）
        let mmio_base = self.get_mmio_base_address();
        
        // 安全性チェック
        if offset >= self.control_register_size() {
            return Err(AccelError::InvalidAddress);
        }
        
        // アライメントチェック
        if offset % 8 != 0 {
            return Err(AccelError::InvalidAlignment);
        }
        
        // MMIO書き込み実行
        unsafe {
            let register_addr = mmio_base + offset as usize;
            write_mmio_u64(register_addr, value);
            
            // 書き込み完了を確認するためのメモリバリア
            core::arch::asm!("mfence", options(nostack, preserves_flags));
            
            // 書き込み確認（オプション）
            if self.verify_register_write() {
                let read_back = read_mmio_u64(register_addr);
                if read_back != value {
                    log::warn!(
                        "レジスタ書き込み確認失敗: オフセット=0x{:x}, 期待値=0x{:x}, 実際値=0x{:x}",
                        offset, value, read_back
                    );
                    return Err(AccelError::WriteVerificationFailed);
                }
            }
        }
        
        log::trace!("制御レジスタ書き込み完了: オフセット=0x{:x}, 値=0x{:x}", offset, value);
        Ok(())
    }
    
    /// MMIOベースアドレスの取得
    fn get_mmio_base_address(&self) -> usize {
        // PCIコンフィギュレーション空間からMMIOベースアドレスを取得
        match self.get_pci_device_info() {
            Ok(pci_info) => {
                // BAR0からMMIOベースアドレスを取得
                let bar0 = pci_info.read_bar(0).unwrap_or(0);
                
                // メモリ型BARかチェック
                if (bar0 & 0x1) == 0 { // メモリ型
                    let base_addr = bar0 & !0xF; // 下位4ビットをマスク
                    base_addr as usize
                } else {
                    log::error!("BAR0がI/O型です。メモリ型が期待されています");
                    0xF0000000 // フォールバック
                }
            },
            Err(_) => {
                log::warn!("PCIデバイス情報の取得に失敗。デフォルトアドレスを使用");
                0xF0000000 // 仮のアドレス
            }
        }
    }
    
    /// 制御レジスタサイズの取得
    fn control_register_size(&self) -> u32 {
        // デバイス固有の制御レジスタサイズ
        // 実際の実装では、デバイスドライバから取得
        match self.device_type {
            NetworkAccelDeviceType::IntelE810 => 0x10000,   // 64KB
            NetworkAccelDeviceType::MellanoxCX6 => 0x20000, // 128KB
            NetworkAccelDeviceType::BroadcomP5 => 0x8000,   // 32KB
            _ => 0x1000, // 4KB (デフォルト)
        }
    }
    
    /// レジスタ書き込み確認が必要かチェック
    fn verify_register_write(&self) -> bool {
        // デバッグモードまたは重要なレジスタの場合のみ確認
        cfg!(debug_assertions) || self.critical_register_mode
    }
    
    /// PCIデバイス情報の取得
    fn get_pci_device_info(&self) -> Result<PciDeviceInfo, AccelError> {
        // PCIマネージャーからデバイス情報を取得
        if let Some(device_info) = crate::drivers::pci::get_device_by_id(self.device_id) {
            Ok(device_info)
        } else {
            Err(AccelError::DeviceNotFound)
        }
    }
    
    fn write_task_register(&self, offset: u32, value: u64) -> Result<(), AccelError> {
        // タスク関連レジスタへの書き込み
        unsafe {
            arch::write_mmio_u64(self.get_base_address() + offset as usize, value);
        }
        Ok(())
    }
    
    fn get_base_address(&self) -> usize {
        // デバイスのMMIOベースアドレスを取得
        // 実際の実装ではPCIコンフィグレーション空間から取得
        0xF0000000 // 仮のアドレス
    }
    
    fn apply_config_v1(&self, config_data: &[u8]) -> Result<(), AccelError> {
        log::debug!("設定v1適用中: {}バイト", config_data.len());
        
        // 設定データを8バイトずつ処理
        for chunk in config_data.chunks(8) {
            if chunk.len() >= 8 {
                // オフセットと値を抽出
                let offset = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                let value = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
                
                // レジスタアドレス範囲チェック
                if offset >= 0x1000 {
                    log::warn!("無効なレジスタオフセット: 0x{:x}", offset);
                    continue;
                }
                
                // レジスタに書き込み
                self.write_control_register(offset, value as u64)?;
                log::debug!("レジスタ設定: オフセット=0x{:x}, 値=0x{:x}", offset, value);
            }
        }
        
        // 設定適用完了を通知
        self.write_control_register(0x100, 0x01)?;
        
        log::info!("設定v1適用完了");
        Ok(())
    }
    
    fn apply_config_v2(&self, config_data: &[u8]) -> Result<(), AccelError> {
        log::debug!("設定v2適用中: {}バイト", config_data.len());
        
        if config_data.len() < 16 {
            return Err(AccelError::InvalidParameter);
        }
        
        // v2設定ヘッダーを解析
        let config_type = u32::from_le_bytes([config_data[0], config_data[1], config_data[2], config_data[3]]);
        let config_length = u32::from_le_bytes([config_data[4], config_data[5], config_data[6], config_data[7]]);
        let config_version = u32::from_le_bytes([config_data[8], config_data[9], config_data[10], config_data[11]]);
        let flags = u32::from_le_bytes([config_data[12], config_data[13], config_data[14], config_data[15]]);
        
        log::debug!("設定ヘッダー: タイプ={}, 長さ={}, バージョン={}, フラグ=0x{:x}", 
                   config_type, config_length, config_version, flags);
        
        // 設定タイプに基づいて処理
        match config_type {
            1 => self.apply_performance_config(&config_data[16..])?,
            2 => self.apply_security_config(&config_data[16..])?,
            3 => self.apply_power_config(&config_data[16..])?,
            _ => {
                log::warn!("未知の設定タイプ: {}", config_type);
                return Err(AccelError::InvalidParameter);
            }
        }
        
        log::info!("設定v2適用完了");
        Ok(())
    }
    
    fn apply_performance_config(&self, config_data: &[u8]) -> Result<(), AccelError> {
        log::debug!("パフォーマンス設定適用中");
        
        if config_data.len() >= 12 {
            // パフォーマンス関連設定
            let queue_depth = u32::from_le_bytes([config_data[0], config_data[1], config_data[2], config_data[3]]);
            let batch_size = u32::from_le_bytes([config_data[4], config_data[5], config_data[6], config_data[7]]);
            let timeout_ms = u32::from_le_bytes([config_data[8], config_data[9], config_data[10], config_data[11]]);
            
            // 設定値をレジスタに書き込み
            self.write_control_register(0x200, queue_depth as u64)?;
            self.write_control_register(0x204, batch_size as u64)?;
            self.write_control_register(0x208, timeout_ms as u64)?;
            
            log::debug!("パフォーマンス設定: キュー深度={}, バッチサイズ={}, タイムアウト={}ms", 
                       queue_depth, batch_size, timeout_ms);
        }
        
        Ok(())
    }
    
    fn apply_security_config(&self, config_data: &[u8]) -> Result<(), AccelError> {
        log::debug!("セキュリティ設定適用中");
        
        if config_data.len() >= 8 {
            // セキュリティ関連設定
            let encryption_enabled = config_data[0] != 0;
            let auth_required = config_data[1] != 0;
            let key_length = u32::from_le_bytes([config_data[4], config_data[5], config_data[6], config_data[7]]);
            
            // セキュリティ設定をレジスタに書き込み
            let security_flags = 
                (if encryption_enabled { 0x01 } else { 0x00 }) |
                (if auth_required { 0x02 } else { 0x00 });
            
            self.write_control_register(0x300, security_flags)?;
            self.write_control_register(0x304, key_length as u64)?;
            
            log::debug!("セキュリティ設定: 暗号化={}, 認証={}, キー長={}", 
                       encryption_enabled, auth_required, key_length);
        }
        
        Ok(())
    }
    
    fn apply_power_config(&self, config_data: &[u8]) -> Result<(), AccelError> {
        log::debug!("電力設定適用中");
        
        if config_data.len() >= 4 {
            // 電力管理設定
            let power_mode = config_data[0];
            let idle_timeout = u32::from_le_bytes([config_data[1], config_data[2], config_data[3], config_data[4]]);
            
            // 電力設定をレジスタに書き込み
            self.write_control_register(0x400, power_mode as u64)?;
            self.write_control_register(0x404, idle_timeout as u64)?;
            
            log::debug!("電力設定: モード={}, アイドルタイムアウト={}", power_mode, idle_timeout);
        }
        
        Ok(())
    }
    
    fn submit_tso_task(&self, task_id: u64, params: OffloadParams) -> Result<(), AccelError> {
        // TCP Segmentation Offloadをハードウェアにオフロード
        if let OffloadParams::TcpOffload(tcp_params) = params {
            log::debug!("TSO処理開始: タスクID={}", task_id);
            
            // TSO制御レジスタに設定
            self.write_task_register(0x40, task_id)?;
            self.write_task_register(0x44, tcp_params.as_register_value())?;
            
            // MSS（Maximum Segment Size）設定
            self.write_task_register(0x48, 1500)?; // 通常のMTU
            
            // TSO開始コマンド
            self.write_control_register(0x4C, 0x01)?;
            
            self.stats.submitted_tasks.fetch_add(1, Ordering::Relaxed);
            log::debug!("TSO処理開始完了: タスクID={}", task_id);
            
            Ok(())
        } else {
            Err(AccelError::InvalidParameter)
        }
    }
    
    fn submit_lro_task(&self, task_id: u64, params: OffloadParams) -> Result<(), AccelError> {
        // Large Receive Offloadをハードウェアにオフロード
        if let OffloadParams::TcpOffload(tcp_params) = params {
            log::debug!("LRO処理開始: タスクID={}", task_id);
            
            // LRO制御レジスタに設定
            self.write_task_register(0x50, task_id)?;
            self.write_task_register(0x54, tcp_params.as_register_value())?;
            
            // 最大集約サイズ設定
            self.write_task_register(0x58, 64000)?; // 64KB
            
            // LRO開始コマンド
            self.write_control_register(0x5C, 0x01)?;
            
            self.stats.submitted_tasks.fetch_add(1, Ordering::Relaxed);
            log::debug!("LRO処理開始完了: タスクID={}", task_id);
            
            Ok(())
        } else {
            Err(AccelError::InvalidParameter)
        }
    }
    
    fn submit_rdma_task(&self, task_id: u64, params: OffloadParams) -> Result<(), AccelError> {
        // RDMA処理をハードウェアにオフロード
        log::debug!("RDMA処理開始: タスクID={}", task_id);
        
        // RDMA制御レジスタに設定
        self.write_task_register(0x60, task_id)?;
        
        // パラメータに基づいてRDMA設定
        match params {
            OffloadParams::TcpOffload(tcp_params) => {
                self.write_task_register(0x64, tcp_params.as_register_value())?;
            },
            _ => {
                return Err(AccelError::InvalidParameter);
            }
        }
        
        // RDMAキューペア設定
        self.write_task_register(0x68, 1)?; // QP番号
        
        // RDMA開始コマンド
        self.write_control_register(0x6C, 0x01)?;
        
        self.stats.submitted_tasks.fetch_add(1, Ordering::Relaxed);
        log::debug!("RDMA処理開始完了: タスクID={}", task_id);
        
        Ok(())
    }
}

/// DMAエンジン
pub struct DmaEngine {
    /// アクティブな転送
    active_transfers: Mutex<BTreeMap<u64, DmaTransfer>>,
    /// 次の転送ID
    next_transfer_id: AtomicU64,
    /// 統計情報
    stats: DmaStats,
}

impl DmaEngine {
    /// 新しいDMAエンジンを作成
    pub fn new() -> Self {
        Self {
            active_transfers: Mutex::new(BTreeMap::new()),
            next_transfer_id: AtomicU64::new(1),
            stats: DmaStats::new(),
        }
    }
    
    /// DMA転送を開始
    pub fn start_transfer(&self, src: PhysicalAddress, dst: PhysicalAddress, size: usize) -> Result<u64, AccelError> {
        // 転送IDを割り当て
        let transfer_id = self.next_transfer_id.fetch_add(1, Ordering::SeqCst);
        
        // 転送を作成
        let transfer = DmaTransfer {
            id: transfer_id,
            source: src,
            destination: dst,
            size,
            status: TransferStatus::InProgress,
            submit_time: get_current_time(),
            complete_time: 0,
        };
        
        // 転送を登録
        let mut transfers = self.active_transfers.lock();
        transfers.insert(transfer_id, transfer);
        
        // 実際の実装ではDMAコントローラに転送要求を送信
        self.execute_dma_transfer(src, dst, size)?;
        
        self.stats.total_transfers.fetch_add(1, Ordering::Relaxed);
        self.stats.active_transfers.fetch_add(1, Ordering::Relaxed);
        self.stats.total_bytes.fetch_add(size as u64, Ordering::Relaxed);
        
        Ok(transfer_id)
    }
    
    /// 転送状態を確認
    pub fn check_transfer(&self, transfer_id: u64) -> Result<TransferStatus, AccelError> {
        let transfers = self.active_transfers.lock();
        
        if let Some(transfer) = transfers.get(&transfer_id) {
            return Ok(transfer.status);
        }
        
        Err(AccelError::InvalidTransfer)
    }
    
    /// DMA転送完了を待機
    pub fn wait_for_completion(&self, transfer_id: u64) -> Result<(), AccelError> {
        log::debug!("DMA転送完了待機開始: ID={}", transfer_id);
        
        let start_time = get_current_time_ns();
        let timeout_duration = 10_000_000_000; // 10秒タイムアウト
        
        loop {
            // 転送状態をチェック
            let status = self.check_transfer(transfer_id)?;
            
            match status {
                TransferStatus::Completed => {
                    // 転送完了：転送を削除
                    let mut transfers = self.active_transfers.lock();
                    if let Some(transfer) = transfers.remove(&transfer_id) {
                        self.stats.active_transfers.fetch_sub(1, Ordering::Relaxed);
                        
                        log::debug!("DMA転送完了: ID={}, サイズ={}バイト", 
                                   transfer_id, transfer.size);
                        return Ok(());
                    }
                    return Err(AccelError::InvalidTransfer);
                },
                TransferStatus::Error => {
                    // 転送エラー：転送を削除
                    let mut transfers = self.active_transfers.lock();
                    if let Some(transfer) = transfers.remove(&transfer_id) {
                        self.stats.active_transfers.fetch_sub(1, Ordering::Relaxed);
                        self.stats.failed_transfers.fetch_add(1, Ordering::Relaxed);
                        
                        log::error!("DMA転送エラー: ID={}", transfer_id);
                        return Err(AccelError::TransferFailed);
                    }
                    return Err(AccelError::InvalidTransfer);
                },
                _ => {
                    // まだ処理中：継続してポーリング
                }
            }
            
            // タイムアウトチェック
            let current_time = get_current_time_ns();
            if current_time - start_time > timeout_duration {
                log::warn!("DMA転送タイムアウト: ID={}", transfer_id);
                return Err(AccelError::Timeout);
            }
            
            // DMAコントローラの状態を更新（シミュレーション）
            self.simulate_dma_progress(transfer_id);
            
            // 少し待機
            arch::delay_ms(1);
        }
    }
    
    /// DMA進行状況をシミュレート
    fn simulate_dma_progress(&self, transfer_id: u64) {
        let mut transfers = self.active_transfers.lock();
        
        if let Some(transfer) = transfers.get_mut(&transfer_id) {
            if transfer.status == TransferStatus::InProgress {
                // 5%の確率で完了とする（シミュレーション）
                let random_value = (get_current_time_ns() % 100) as u8;
                if random_value < 5 {
                    transfer.status = TransferStatus::Completed;
                    transfer.complete_time = get_current_time();
                    log::debug!("DMA転送シミュレーション完了: ID={}", transfer_id);
                }
            }
        }
    }
    
    /// DMA転送の実行
    fn execute_dma_transfer(&self, src: PhysicalAddress, dst: PhysicalAddress, size: usize) -> Result<(), AccelError> {
        // DMAディスクリプタの設定
        let descriptor = self.create_dma_descriptor(src, dst, size)?;
        
        // DMAチャネルの確保
        let channel = self.allocate_dma_channel()?;
        
        // DMA転送の開始
        self.start_dma_transfer_internal(channel, &descriptor)?;
        
        log::debug!(
            "DMA転送開始: 送信元=0x{:x}, 宛先=0x{:x}, サイズ={}バイト, チャネル={}",
            src.as_u64(),
            dst.as_u64(),
            size,
            channel
        );
        
        Ok(())
    }
    
    /// DMAディスクリプタの作成
    fn create_dma_descriptor(&self, src: PhysicalAddress, dst: PhysicalAddress, size: usize) -> Result<DmaDescriptor, AccelError> {
        // ディスクリプタ構造体の初期化
        let mut descriptor = DmaDescriptor {
            source_address: src.as_u64(),
            dest_address: dst.as_u64(),
            transfer_size: size as u32,
            control_flags: 0,
            next_descriptor: 0,
            status: 0,
        };
        
        // 制御フラグの設定
        descriptor.control_flags |= DMA_CTRL_ENABLE;
        descriptor.control_flags |= DMA_CTRL_INTERRUPT_ON_COMPLETION;
        
        // アドレスが4KB境界を跨ぐ場合の処理
        if self.crosses_page_boundary(src.as_usize(), size) ||
           self.crosses_page_boundary(dst.as_usize(), size) {
            descriptor.control_flags |= DMA_CTRL_SCATTER_GATHER;
        }
        
        // キャッシュコヒーレンシーの設定
        descriptor.control_flags |= DMA_CTRL_COHERENT;
        
        // 転送方向の設定
        descriptor.control_flags |= DMA_CTRL_MEMORY_TO_MEMORY;
        
        Ok(descriptor)
    }
    
    /// DMAチャネルの確保
    fn allocate_dma_channel(&self) -> Result<u32, AccelError> {
        // 利用可能なDMAチャネルを検索
        for channel in 0..8 { // 最大8チャネル
            if self.is_dma_channel_free(channel) {
                self.mark_dma_channel_busy(channel);
                log::trace!("DMAチャネル {}を確保", channel);
                return Ok(channel);
            }
        }
        
        Err(AccelError::NoDmaChannelAvailable)
    }
    
    /// DMA転送の開始
    fn start_dma_transfer_internal(&self, channel: u32, descriptor: &DmaDescriptor) -> Result<(), AccelError> {
        // ディスクリプタをDMAコントローラに設定
        let descriptor_addr = self.get_descriptor_address(channel);
        
        unsafe {
            // ディスクリプタの書き込み
            write_mmio_u64(descriptor_addr, descriptor.source_address);
            write_mmio_u64(descriptor_addr + 8, descriptor.dest_address);
            write_mmio_u32(descriptor_addr + 16, descriptor.transfer_size);
            write_mmio_u32(descriptor_addr + 20, descriptor.control_flags);
            
            // DMA転送の開始
            let control_reg = self.get_dma_control_register(channel);
            write_mmio_u32(control_reg, DMA_START_TRANSFER);
            
            // メモリバリアで確実にレジスタに書き込まれるようにする
            core::arch::asm!("mfence", options(nostack, preserves_flags));
        }
        
        log::trace!("DMAチャネル {}で転送開始", channel);
        Ok(())
    }
    
    /// DMAチャネルが空いているかチェック
    fn is_dma_channel_free(&self, channel: u32) -> bool {
        let status_reg = self.get_dma_status_register(channel);
        let status = unsafe { read_mmio_u32(status_reg) };
        (status & DMA_STATUS_BUSY) == 0
    }
    
    /// DMAチャネルをビジー状態にマーク
    fn mark_dma_channel_busy(&self, channel: u32) {
        let control_reg = self.get_dma_control_register(channel);
        unsafe {
            let current = read_mmio_u32(control_reg);
            write_mmio_u32(control_reg, current | DMA_CTRL_BUSY);
        }
    }
    
    /// DMAチャネルを解放状態にマーク
    fn mark_dma_channel_free(&self, channel: u32) {
        let control_reg = self.get_dma_control_register(channel);
        unsafe {
            let current = read_mmio_u32(control_reg);
            write_mmio_u32(control_reg, current & !DMA_CTRL_BUSY);
        }
    }
    
    /// ページ境界をまたぐかチェック
    fn crosses_page_boundary(&self, addr: usize, size: usize) -> bool {
        const PAGE_SIZE: usize = 4096;
        let start_page = addr / PAGE_SIZE;
        let end_page = (addr + size - 1) / PAGE_SIZE;
        start_page != end_page
    }
    
    /// DMAディスクリプタアドレスの取得
    fn get_descriptor_address(&self, channel: u32) -> usize {
        self.get_mmio_base_address() + 0x1000 + (channel as usize * 0x40)
    }
    
    /// DMA制御レジスタアドレスの取得
    fn get_dma_control_register(&self, channel: u32) -> usize {
        self.get_mmio_base_address() + 0x2000 + (channel as usize * 0x10)
    }
    
    /// DMAステータスレジスタアドレスの取得
    fn get_dma_status_register(&self, channel: u32) -> usize {
        self.get_mmio_base_address() + 0x2004 + (channel as usize * 0x10)
    }
    
    /// 現在時刻の取得（ミリ秒）
    fn get_current_time_ms(&self) -> u64 {
        arch::get_timestamp() / 1_000_000
    }
    
    /// メモリチェックサムの計算
    fn calculate_memory_checksum(&self, addr: usize, size: usize) -> Result<u32, AccelError> {
        let mut checksum: u32 = 0;
        
        unsafe {
            let ptr = addr as *const u8;
            for i in 0..size {
                checksum = checksum.wrapping_add(*ptr.add(i) as u32);
                checksum = checksum.rotate_left(1);
            }
        }
        
        Ok(checksum)
    }
    
    /// CPU一時停止
    fn cpu_relax(&self) {
        arch::cpu_relax();
    }
}

/// DMA転送
pub struct DmaTransfer {
    /// 転送ID
    id: u64,
    /// ソースアドレス
    source: PhysicalAddress,
    /// 宛先アドレス
    destination: PhysicalAddress,
    /// サイズ
    size: usize,
    /// 転送状態
    status: TransferStatus,
    /// 送信時刻
    submit_time: u64,
    /// 完了時刻
    complete_time: u64,
}

/// 転送状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    /// 送信前
    Submitted,
    /// 処理中
    InProgress,
    /// 完了
    Completed,
    /// エラー
    Error,
}

/// オフロードタスク
pub struct OffloadTask {
    /// タスクID
    id: u64,
    /// タスクタイプ
    task_type: AccelerationType,
    /// パラメータ
    params: OffloadParams,
    /// デバイスID
    device_id: u32,
    /// タスク状態
    status: TaskStatus,
    /// タスク結果
    result: Option<TaskResult>,
    /// 送信時刻
    submit_time: u64,
    /// 完了時刻
    complete_time: u64,
}

/// タスク状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    /// 送信前
    Submitted,
    /// 処理中
    InProgress,
    /// 完了
    Completed,
    /// 失敗
    Failed,
    /// キャンセル
    Cancelled,
}

/// タスク結果
#[derive(Debug, Clone)]
pub enum TaskResult {
    /// 成功
    Success,
    /// エラー
    Error(AccelError),
}

/// オフロードパラメータ
#[derive(Debug, Clone)]
pub enum OffloadParams {
    /// TCP/IPオフロード
    TcpOffload(TcpOffloadParams),
    /// チェックサム計算
    Checksum(ChecksumParams),
    /// 暗号化/復号化
    Crypto(CryptoParams),
    /// データ圧縮/展開
    Compression(CompressionParams),
    /// パケットフィルタリング
    Filter(FilterParams),
}

// 各種パラメータ構造体の完全実装
#[derive(Debug, Clone)]
pub struct TcpOffloadParams {
    /// 送信元アドレス
    pub src_addr: u32,
    /// 宛先アドレス  
    pub dst_addr: u32,
    /// 送信元ポート
    pub src_port: u16,
    /// 宛先ポート
    pub dst_port: u16,
    /// シーケンス番号
    pub sequence_number: u32,
    /// 確認番号
    pub acknowledgment_number: u32,
    /// ウィンドウサイズ
    pub window_size: u16,
    /// MSS（Maximum Segment Size）
    pub mss: u16,
    /// TCPフラグ
    pub flags: u8,
    /// データ長
    pub data_length: u32,
    /// 優先度
    pub priority: u8,
}

impl TcpOffloadParams {
    /// 新しいTCPオフロードパラメータを作成
    pub fn new(src_addr: u32, dst_addr: u32, src_port: u16, dst_port: u16) -> Self {
        Self {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            sequence_number: 0,
            acknowledgment_number: 0,
            window_size: 65535,
            mss: 1460,
            flags: 0,
            data_length: 0,
            priority: 0,
        }
    }
    
    /// レジスタ値に変換
    fn as_register_value(&self) -> u64 {
        // 主要なパラメータをパックしてレジスタ値として返す
        ((self.src_addr as u64) << 32) | 
        ((self.dst_addr as u64) & 0xFFFFFFFF)
    }
}

#[derive(Debug, Clone)]
pub struct ChecksumParams {
    /// チェックサム対象のデータオフセット
    pub data_offset: u32,
    /// データ長
    pub data_length: u32,
    /// チェックサムタイプ（IP、TCP、UDP）
    pub checksum_type: ChecksumType,
    /// ハードウェアオフロード使用フラグ
    pub use_hardware: bool,
    /// 疑似ヘッダー情報
    pub pseudo_header: Option<PseudoHeader>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumType {
    /// IP チェックサム
    Ip,
    /// TCP チェックサム
    Tcp,
    /// UDP チェックサム
    Udp,
    /// ICMP チェックサム
    Icmp,
}

#[derive(Debug, Clone)]
pub struct PseudoHeader {
    /// 送信元IPアドレス
    pub src_ip: u32,
    /// 宛先IPアドレス
    pub dst_ip: u32,
    /// プロトコル番号
    pub protocol: u8,
    /// データ長
    pub length: u16,
}

impl ChecksumParams {
    /// 新しいチェックサムパラメータを作成
    pub fn new(data_offset: u32, data_length: u32, checksum_type: ChecksumType) -> Self {
        Self {
            data_offset,
            data_length,
            checksum_type,
            use_hardware: true,
            pseudo_header: None,
        }
    }
    
    /// レジスタ値に変換
    fn as_register_value(&self) -> u64 {
        let type_value = match self.checksum_type {
            ChecksumType::Ip => 1,
            ChecksumType::Tcp => 2,
            ChecksumType::Udp => 3,
            ChecksumType::Icmp => 4,
        };
        
        ((self.data_offset as u64) << 32) | 
        ((self.data_length as u64) << 16) |
        (type_value as u64)
    }
}

#[derive(Debug, Clone)]
pub struct CryptoParams {
    /// 暗号化アルゴリズム
    pub algorithm: CryptoAlgorithm,
    /// 暗号化キーID
    pub key_id: u32,
    /// 初期化ベクトル
    pub iv: Option<Vec<u8>>,
    /// 追加認証データ
    pub aad: Option<Vec<u8>>,
    /// 操作モード（暗号化/復号化）
    pub operation: CryptoOperation,
    /// データオフセット
    pub data_offset: u32,
    /// データ長
    pub data_length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    /// AES-128-GCM
    Aes128Gcm,
    /// AES-256-GCM
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    /// カスタム暗号
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoOperation {
    /// 暗号化
    Encrypt,
    /// 復号化
    Decrypt,
}

impl CryptoParams {
    /// 新しい暗号化パラメータを作成
    pub fn new(algorithm: CryptoAlgorithm, key_id: u32, operation: CryptoOperation) -> Self {
        Self {
            algorithm,
            key_id,
            iv: None,
            aad: None,
            operation,
            data_offset: 0,
            data_length: 0,
        }
    }
    
    /// レジスタ値に変換
    fn as_register_value(&self) -> u64 {
        let algo_value = match self.algorithm {
            CryptoAlgorithm::Aes128Gcm => 1,
            CryptoAlgorithm::Aes256Gcm => 2,
            CryptoAlgorithm::ChaCha20Poly1305 => 3,
            CryptoAlgorithm::Custom => 255,
        };
        
        let op_value = match self.operation {
            CryptoOperation::Encrypt => 1,
            CryptoOperation::Decrypt => 2,
        };
        
        ((self.key_id as u64) << 32) |
        ((algo_value as u64) << 16) |
        (op_value as u64)
    }
}

#[derive(Debug, Clone)]
pub struct CompressionParams {
    /// 圧縮アルゴリズム
    pub algorithm: CompressionAlgorithm,
    /// 圧縮レベル（1-9）
    pub level: u8,
    /// 操作モード（圧縮/展開）
    pub operation: CompressionOperation,
    /// 入力データオフセット
    pub input_offset: u32,
    /// 入力データ長
    pub input_length: u32,
    /// 出力バッファサイズ
    pub output_buffer_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    /// DEFLATE
    Deflate,
    /// LZ4
    Lz4,
    /// ZSTD
    Zstd,
    /// Snappy
    Snappy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionOperation {
    /// 圧縮
    Compress,
    /// 展開
    Decompress,
}

impl CompressionParams {
    /// 新しい圧縮パラメータを作成
    pub fn new(algorithm: CompressionAlgorithm, operation: CompressionOperation) -> Self {
        Self {
            algorithm,
            level: 6, // デフォルト圧縮レベル
            operation,
            input_offset: 0,
            input_length: 0,
            output_buffer_size: 0,
        }
    }
    
    /// レジスタ値に変換
    fn as_register_value(&self) -> u64 {
        let algo_value = match self.algorithm {
            CompressionAlgorithm::Deflate => 1,
            CompressionAlgorithm::Lz4 => 2,
            CompressionAlgorithm::Zstd => 3,
            CompressionAlgorithm::Snappy => 4,
        };
        
        let op_value = match self.operation {
            CompressionOperation::Compress => 1,
            CompressionOperation::Decompress => 2,
        };
        
        ((self.input_length as u64) << 32) |
        ((algo_value as u64) << 16) |
        ((self.level as u64) << 8) |
        (op_value as u64)
    }
}

#[derive(Debug, Clone)]
pub struct FilterParams {
    /// フィルタタイプ
    pub filter_type: FilterType,
    /// フィルタルール
    pub rules: Vec<FilterRule>,
    /// アクション（許可/拒否）
    pub default_action: FilterAction,
    /// 優先度
    pub priority: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterType {
    /// IPアドレスフィルタ
    IpAddress,
    /// ポートフィルタ
    Port,
    /// プロトコルフィルタ
    Protocol,
    /// ペイロードパターンマッチング
    PayloadPattern,
}

#[derive(Debug, Clone)]
pub struct FilterRule {
    /// マッチ条件
    pub condition: FilterCondition,
    /// アクション
    pub action: FilterAction,
}

#[derive(Debug, Clone)]
pub enum FilterCondition {
    /// IPアドレス範囲
    IpRange { start: u32, end: u32 },
    /// ポート範囲
    PortRange { start: u16, end: u16 },
    /// プロトコル番号
    Protocol(u8),
    /// ペイロードパターン
    PayloadPattern(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    /// 許可
    Allow,
    /// 拒否
    Deny,
    /// ログ記録
    Log,
    /// レート制限
    RateLimit,
}

impl FilterParams {
    /// 新しいフィルタパラメータを作成
    pub fn new(filter_type: FilterType) -> Self {
        Self {
            filter_type,
            rules: Vec::new(),
            default_action: FilterAction::Allow,
            priority: 100,
        }
    }
    
    /// フィルタルールを追加
    pub fn add_rule(&mut self, condition: FilterCondition, action: FilterAction) {
        self.rules.push(FilterRule { condition, action });
    }
    
    /// レジスタ値に変換
    fn as_register_value(&self) -> u64 {
        let type_value = match self.filter_type {
            FilterType::IpAddress => 1,
            FilterType::Port => 2,
            FilterType::Protocol => 3,
            FilterType::PayloadPattern => 4,
        };
        
        let action_value = match self.default_action {
            FilterAction::Allow => 1,
            FilterAction::Deny => 2,
            FilterAction::Log => 3,
            FilterAction::RateLimit => 4,
        };
        
        ((self.priority as u64) << 32) |
        ((type_value as u64) << 16) |
        (action_value as u64)
    }
}

// パケットプロセッサ設定
#[derive(Debug, Clone)]
pub struct PacketProcessorConfig {
    /// フィルターを有効化
    pub enable_filtering: bool,
    /// チェックサムを有効化
    pub enable_checksum: bool,
    /// 暗号化を有効化
    pub enable_encryption: bool,
    /// 圧縮を有効化
    pub enable_compression: bool,
    /// 最大並列処理数
    pub max_concurrent_packets: usize,
    /// バッファサイズ
    pub buffer_size: usize,
}

impl Default for PacketProcessorConfig {
    fn default() -> Self {
        Self {
            enable_filtering: true,
            enable_checksum: true,
            enable_encryption: false,
            enable_compression: false,
            max_concurrent_packets: 32,
            buffer_size: 65536,
        }
    }
}

// ソフトウェアアクセラレーションデバイスの修正
impl SoftwareAccelerationDevice {
    fn software_checksum(&self, task_id: u64, params: OffloadParams) -> Result<(), AccelError> {
        log::debug!("ソフトウェアチェックサム計算開始: タスクID={}", task_id);
        self.stats.submitted_tasks.fetch_add(1, Ordering::Relaxed);
        
        if let OffloadParams::Checksum(checksum_params) = params {
            // チェックサムタイプに基づいて計算
            match checksum_params.checksum_type {
                ChecksumType::Ip => {
                    log::debug!("IPチェックサム計算実行");
                    // IPヘッダーチェックサム計算をシミュレート
                    self.simulate_processing_delay(10);
                },
                ChecksumType::Tcp => {
                    log::debug!("TCPチェックサム計算実行");
                    // TCPチェックサム計算をシミュレート
                    self.simulate_processing_delay(20);
                },
                ChecksumType::Udp => {
                    log::debug!("UDPチェックサム計算実行");
                    // UDPチェックサム計算をシミュレート
                    self.simulate_processing_delay(15);
                },
                ChecksumType::Icmp => {
                    log::debug!("ICMPチェックサム計算実行");
                    // ICMPチェックサム計算をシミュレート
                    self.simulate_processing_delay(10);
                },
            }
        }
        
        self.stats.completed_tasks.fetch_add(1, Ordering::Relaxed);
        log::debug!("ソフトウェアチェックサム計算完了: タスクID={}", task_id);
        Ok(())
    }
    
    fn software_tcp_processing(&self, task_id: u64, params: OffloadParams) -> Result<(), AccelError> {
        log::debug!("ソフトウェアTCP処理開始: タスクID={}", task_id);
        self.stats.submitted_tasks.fetch_add(1, Ordering::Relaxed);
        
        if let OffloadParams::TcpOffload(tcp_params) = params {
            log::debug!("TCP処理実行: 送信元={}:{}, 宛先={}:{}", 
                       tcp_params.src_addr, tcp_params.src_port,
                       tcp_params.dst_addr, tcp_params.dst_port);
            
            // TCP状態管理をシミュレート
            self.simulate_tcp_state_processing(&tcp_params);
            
            // セグメンテーション処理をシミュレート
            if tcp_params.data_length > tcp_params.mss as u32 {
                self.simulate_tcp_segmentation(&tcp_params);
            }
        }
        
        self.stats.completed_tasks.fetch_add(1, Ordering::Relaxed);
        self.stats.processed_bytes.fetch_add(1500, Ordering::Relaxed); // 平均パケットサイズ
        
        log::debug!("ソフトウェアTCP処理完了: タスクID={}", task_id);
        Ok(())
    }
    
    fn software_crypto(&self, task_id: u64, params: OffloadParams) -> Result<(), AccelError> {
        log::debug!("ソフトウェア暗号処理開始: タスクID={}", task_id);
        self.stats.submitted_tasks.fetch_add(1, Ordering::Relaxed);
        
        if let OffloadParams::Crypto(crypto_params) = params {
            log::debug!("暗号処理実行: アルゴリズム={:?}, 操作={:?}", 
                       crypto_params.algorithm, crypto_params.operation);
            
            // 暗号化/復号化処理をシミュレート
            match crypto_params.algorithm {
                CryptoAlgorithm::Aes128Gcm => self.simulate_processing_delay(50),
                CryptoAlgorithm::Aes256Gcm => self.simulate_processing_delay(80),
                CryptoAlgorithm::ChaCha20Poly1305 => self.simulate_processing_delay(60),
                CryptoAlgorithm::Custom => self.simulate_processing_delay(100),
            }
            
            self.stats.processed_bytes.fetch_add(crypto_params.data_length as u64, Ordering::Relaxed);
        }
        
        self.stats.completed_tasks.fetch_add(1, Ordering::Relaxed);
        log::debug!("ソフトウェア暗号処理完了: タスクID={}", task_id);
        Ok(())
    }
    
    /// TCP状態処理をシミュレート
    fn simulate_tcp_state_processing(&self, params: &TcpOffloadParams) {
        log::trace!("TCP状態管理: フラグ=0x{:02x}, シーケンス={}", 
                   params.flags, params.sequence_number);
        self.simulate_processing_delay(30);
    }
    
    /// TCPセグメンテーションをシミュレート
    fn simulate_tcp_segmentation(&self, params: &TcpOffloadParams) {
        let segments = (params.data_length + params.mss as u32 - 1) / params.mss as u32;
        log::trace!("TCP セグメンテーション: データ長={}, MSS={}, セグメント数={}", 
                   params.data_length, params.mss, segments);
        self.simulate_processing_delay(segments as usize * 10);
    }
    
    /// 処理遅延をシミュレート
    fn simulate_processing_delay(&self, microseconds: usize) {
        // マイクロ秒単位の処理遅延をシミュレート
        for _ in 0..microseconds {
            arch::cpu_relax();
        }
    }
}

// 新しい列挙型とトレイト
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketType {
    Tcp,
    Udp,
    Icmp,
    Ipv6,
    Arp,
    Other,
}

// 時刻取得の実装改善
fn get_current_time() -> u64 {
    arch::get_timestamp()
}

fn get_current_time_ns() -> u64 {
    arch::get_timestamp()
}

// アーキテクチャ固有関数のモック
mod arch {
    pub fn cpu_relax() {
        // CPU緩和命令（x86のPAUSE等）
        core::hint::spin_loop();
    }
    
    pub fn delay_ms(ms: u64) {
        // ミリ秒待機（タイマーを使用した実装）
        let start_time = crate::time::current_time_us();
        let target_time = start_time + (ms * 1000);
        
        while crate::time::current_time_us() < target_time {
            // CPUに他のタスクの実行機会を与える
            core::hint::spin_loop();
            
            // より長い待機の場合はスケジューラーに制御を移す
            if ms > 10 {
                crate::scheduler::yield_now();
            }
        }
    }
    
    pub fn write_mmio_u64(addr: usize, value: u64) {
        // MMIOレジスタ書き込み（安全なポインタアクセス）
        log::trace!("MMIO書き込み: アドレス=0x{:x}, 値=0x{:x}", addr, value);
        
        // アドレスの検証
        if !is_valid_mmio_address(addr) {
            log::error!("不正なMMIOアドレス: 0x{:x}", addr);
            return;
        }
        
        unsafe {
            // 8バイト境界での書き込み
            let ptr = addr as *mut u64;
            core::ptr::write_volatile(ptr, value);
            
            // メモリバリアで書き込み完了を保証
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
    }
    
    pub fn read_mmio_u64(addr: usize) -> u64 {
        // MMIOレジスタ読み込み
        log::trace!("MMIO読み込み: アドレス=0x{:x}", addr);
        
        if !is_valid_mmio_address(addr) {
            log::error!("不正なMMIOアドレス: 0x{:x}", addr);
            return 0;
        }
        
        unsafe {
            let ptr = addr as *const u64;
            let value = core::ptr::read_volatile(ptr);
            
            // メモリバリア
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            
            log::trace!("MMIO読み込み結果: アドレス=0x{:x}, 値=0x{:x}", addr, value);
            value
        }
    }

    fn is_valid_mmio_address(addr: usize) -> bool {
        // MMIOアドレス範囲の検証
        match addr {
            // PCIe ECAM領域
            0xE000_0000..=0xEFFF_FFFF => true,
            // 従来のPCI設定空間
            0xF000_0000..=0xFEBF_FFFF => true,
            // LAPIC
            0xFEE0_0000..=0xFEE0_0FFF => true,
            // IOAPIC
            0xFEC0_0000..=0xFEC0_0FFF => true,
            // その他のプラットフォーム固有領域
            _ => {
                // ACPI MCFGテーブルで定義された領域をチェック
                check_acpi_mmio_range(addr)
            }
        }
    }

    fn check_acpi_mmio_range(addr: usize) -> bool {
        // ACPI MCFGテーブルからMMIO範囲を確認
        if let Some(mcfg) = crate::acpi::get_mcfg_table() {
            for config_region in mcfg.config_regions() {
                let start = config_region.base_address() as usize;
                let end = start + config_region.size();
                
                if addr >= start && addr < end {
                    return true;
                }
            }
        }
        false
    }

    // DMA転送の実際の実装
    fn execute_dma_transfer(&self, src: usize, dst: usize, size: usize) -> Result<(), AccelError> {
        log::debug!("DMA転送実行: src=0x{:x}, dst=0x{:x}, size=0x{:x}", src, dst, size);
        
        // DMAコントローラの初期化確認
        if !self.is_dma_controller_ready() {
            return Err(AccelError::DeviceNotReady);
        }
        
        // アライメントの確認
        if (src % 8) != 0 || (dst % 8) != 0 {
            return Err(AccelError::InvalidAlignment);
        }
        
        // サイズの確認
        if size == 0 || size > self.max_dma_transfer_size() {
            return Err(AccelError::InvalidSize);
        }
        
        // DMA記述子の準備
        let dma_descriptor = DmaDescriptor {
            source_address: src as u64,
            destination_address: dst as u64,
            transfer_size: size as u32,
            control_flags: DmaControlFlags::ENABLE | DmaControlFlags::INTERRUPT_ON_COMPLETION,
            next_descriptor: 0, // 単一転送
        };
        
        // DMA記述子をデバイスにセット
        self.program_dma_descriptor(&dma_descriptor)?;
        
        // DMA転送開始
        self.start_dma_transfer()?;
        
        // 転送完了待機
        self.wait_for_dma_completion()?;
        
        log::debug!("DMA転送完了");
        Ok(())
    }

    fn is_dma_controller_ready(&self) -> bool {
        // DMAコントローラの状態レジスタをチェック
        let base_addr = self.get_device_mmio_base();
        let status_reg = base_addr + DMA_STATUS_OFFSET;
        
        let status = read_mmio_u64(status_reg);
        (status & DMA_STATUS_READY) != 0
    }

    fn max_dma_transfer_size(&self) -> usize {
        // デバイス固有の最大転送サイズ
        match self.device_type {
            HardwareAccelType::SmartNIC => 64 * 1024 * 1024, // 64MB
            HardwareAccelType::DPU => 128 * 1024 * 1024,     // 128MB
            HardwareAccelType::CryptoAccel => 16 * 1024 * 1024, // 16MB
            HardwareAccelType::CompressionAccel => 32 * 1024 * 1024, // 32MB
        }
    }

    fn program_dma_descriptor(&self, descriptor: &DmaDescriptor) -> Result<(), AccelError> {
        let base_addr = self.get_device_mmio_base();
        
        // DMA記述子レジスタへの書き込み
        write_mmio_u64(base_addr + DMA_SRC_ADDR_OFFSET, descriptor.source_address);
        write_mmio_u64(base_addr + DMA_DST_ADDR_OFFSET, descriptor.destination_address);
        write_mmio_u64(base_addr + DMA_SIZE_OFFSET, descriptor.transfer_size as u64);
        write_mmio_u64(base_addr + DMA_CONTROL_OFFSET, descriptor.control_flags.bits());
        
        Ok(())
    }

    fn start_dma_transfer(&self) -> Result<(), AccelError> {
        let base_addr = self.get_device_mmio_base();
        let control_reg = base_addr + DMA_CONTROL_OFFSET;
        
        // DMA開始ビットをセット
        let control_value = read_mmio_u64(control_reg);
        write_mmio_u64(control_reg, control_value | DMA_CONTROL_START);
        
        Ok(())
    }

    fn wait_for_dma_completion(&self) -> Result<(), AccelError> {
        let base_addr = self.get_device_mmio_base();
        let status_reg = base_addr + DMA_STATUS_OFFSET;
        let timeout_us = 1_000_000; // 1秒タイムアウト
        let start_time = crate::time::current_time_us();
        
        loop {
            let status = read_mmio_u64(status_reg);
            
            // 完了フラグの確認
            if (status & DMA_STATUS_COMPLETE) != 0 {
                // エラーフラグの確認
                if (status & DMA_STATUS_ERROR) != 0 {
                    log::error!("DMA転送エラー: status=0x{:x}", status);
                    return Err(AccelError::TransferError);
                }
                return Ok(());
            }
            
            // タイムアウト確認
            if crate::time::current_time_us() - start_time > timeout_us {
                log::error!("DMA転送タイムアウト");
                return Err(AccelError::Timeout);
            }
            
            // 短時間待機
            core::hint::spin_loop();
        }
    }

    fn get_device_mmio_base(&self) -> usize {
        // デバイスのMMIOベースアドレスを取得
        // 実際の実装ではPCIコンフィグレーション空間のBAR（Base Address Register）から取得
        match self.device_id.vendor_id {
            0x8086 => 0xF000_0000, // Intel
            0x10DE => 0xF100_0000, // NVIDIA
            0x1002 => 0xF200_0000, // AMD
            0x14E4 => 0xF300_0000, // Broadcom
            _ => 0xF000_0000,      // デフォルト
        }
    }

// DMA関連の定数とデータ構造
const DMA_STATUS_OFFSET: usize = 0x00;
const DMA_CONTROL_OFFSET: usize = 0x08;
const DMA_SRC_ADDR_OFFSET: usize = 0x10;
const DMA_DST_ADDR_OFFSET: usize = 0x18;
const DMA_SIZE_OFFSET: usize = 0x20;

const DMA_STATUS_READY: u64 = 1 << 0;
const DMA_STATUS_COMPLETE: u64 = 1 << 1;
const DMA_STATUS_ERROR: u64 = 1 << 2;

const DMA_CONTROL_START: u64 = 1 << 0;

#[repr(C)]
struct DmaDescriptor {
    source_address: u64,
    destination_address: u64,
    transfer_size: u32,
    control_flags: DmaControlFlags,
    next_descriptor: u64,
}

bitflags::bitflags! {
    struct DmaControlFlags: u64 {
        const ENABLE = 1 << 0;
        const INTERRUPT_ON_COMPLETION = 1 << 1;
        const SCATTER_GATHER = 1 << 2;
        const BIDIRECTIONAL = 1 << 3;
    }
}
} 

/// パケットプロセッサ
pub struct PacketProcessor {
    /// 処理エンジン
    engine: Arc<dyn AccelerationDevice>,
    /// 設定
    config: PacketProcessorConfig,
    /// 統計情報
    stats: PacketProcessorStats,
}

impl PacketProcessor {
    /// 新しいパケットプロセッサを作成
    pub fn new(engine: Arc<dyn AccelerationDevice>, config: PacketProcessorConfig) -> Self {
        Self {
            engine,
            config,
            stats: PacketProcessorStats::new(),
        }
    }
    
    /// パケット処理をオフロード
    pub fn process_packet(&self, packet: &[u8]) -> Result<(), AccelError> {
        log::debug!("パケット処理開始: サイズ={}バイト", packet.len());
        
        // パケットタイプを判定
        let packet_type = self.analyze_packet_type(packet)?;
        
        // 設定に基づいて適切な処理を選択
        match packet_type {
            PacketType::Tcp => {
                if self.config.enable_checksum {
                    self.offload_tcp_checksum(packet)?;
                }
                if self.config.enable_filtering {
                    self.apply_tcp_filters(packet)?;
                }
            },
            PacketType::Udp => {
                if self.config.enable_checksum {
                    self.offload_udp_checksum(packet)?;
                }
            },
            PacketType::Icmp => {
                if self.config.enable_filtering {
                    self.apply_icmp_filters(packet)?;
                }
            },
            _ => {
                log::debug!("未サポートのパケットタイプ");
            }
        }
        
        // 暗号化が有効な場合
        if self.config.enable_encryption {
            self.offload_packet_encryption(packet)?;
        }
        
        self.stats.processed_packets.fetch_add(1, Ordering::Relaxed);
        self.stats.processed_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
        
        log::debug!("パケット処理完了");
        Ok(())
    }
    
    /// パケットタイプを解析
    fn analyze_packet_type(&self, packet: &[u8]) -> Result<PacketType, AccelError> {
        if packet.len() < 14 {
            return Err(AccelError::InvalidParameter);
        }
        
        // Ethernetヘッダーを解析
        let eth_type = u16::from_be_bytes([packet[12], packet[13]]);
        
        match eth_type {
            0x0800 => {
                // IPv4パケット
                if packet.len() >= 34 {
                    let ip_protocol = packet[23];
                    match ip_protocol {
                        6 => Ok(PacketType::Tcp),
                        17 => Ok(PacketType::Udp),
                        1 => Ok(PacketType::Icmp),
                        _ => Ok(PacketType::Other),
                    }
                } else {
                    Err(AccelError::InvalidParameter)
                }
            },
            0x86DD => Ok(PacketType::Ipv6),
            0x0806 => Ok(PacketType::Arp),
            _ => Ok(PacketType::Other),
        }
    }
    
    /// TCPチェックサムオフロード
    fn offload_tcp_checksum(&self, packet: &[u8]) -> Result<(), AccelError> {
        log::debug!("TCPチェックサムオフロード実行");
        
        // ハードウェアチェックサム計算をエンジンに送信
        let params = OffloadParams::Checksum(ChecksumParams::new(
            14 + 20, // IPヘッダー後のTCPヘッダー位置
            packet.len() as u32 - 34,
            ChecksumType::Tcp,
        ));
        
        self.engine.submit_task(
            get_current_time_ns(),
            AccelerationType::Checksum,
            params
        )?;
        
        Ok(())
    }
    
    /// UDPチェックサムオフロード
    fn offload_udp_checksum(&self, packet: &[u8]) -> Result<(), AccelError> {
        log::debug!("UDPチェックサムオフロード実行");
        
        let params = OffloadParams::Checksum(ChecksumParams::new(
            14 + 20, // IPヘッダー後のUDPヘッダー位置
            packet.len() as u32 - 34,
            ChecksumType::Udp,
        ));
        
        self.engine.submit_task(
            get_current_time_ns(),
            AccelerationType::Checksum,
            params
        )?;
        
        Ok(())
    }
    
    /// TCPフィルタ適用
    fn apply_tcp_filters(&self, packet: &[u8]) -> Result<(), AccelError> {
        log::debug!("TCPフィルタ適用");
        
        let mut filter_params = FilterParams::new(FilterType::Protocol);
        filter_params.add_rule(
            FilterCondition::Protocol(6), // TCP
            FilterAction::Allow
        );
        
        let params = OffloadParams::Filter(filter_params);
        self.engine.submit_task(
            get_current_time_ns(),
            AccelerationType::PacketFilter,
            params
        )?;
        
        self.stats.filtered_packets.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    
    /// ICMPフィルタ適用
    fn apply_icmp_filters(&self, packet: &[u8]) -> Result<(), AccelError> {
        log::debug!("ICMPフィルタ適用");
        
        let mut filter_params = FilterParams::new(FilterType::Protocol);
        filter_params.add_rule(
            FilterCondition::Protocol(1), // ICMP
            FilterAction::Allow
        );
        
        let params = OffloadParams::Filter(filter_params);
        self.engine.submit_task(
            get_current_time_ns(),
            AccelerationType::PacketFilter,
            params
        )?;
        
        self.stats.filtered_packets.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    
    /// パケット暗号化オフロード
    fn offload_packet_encryption(&self, packet: &[u8]) -> Result<(), AccelError> {
        log::debug!("パケット暗号化オフロード実行");
        
        let params = OffloadParams::Crypto(CryptoParams::new(
            CryptoAlgorithm::Aes256Gcm,
            1, // キーID
            CryptoOperation::Encrypt,
        ));
        
        self.engine.submit_task(
            get_current_time_ns(),
            AccelerationType::Crypto,
            params
        )?;
        
        self.stats.encrypted_packets.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

/// パケットプロセッサ統計情報
#[derive(Debug, Clone)]
pub struct PacketProcessorStats {
    /// 処理済みパケット数
    pub processed_packets: AtomicU64,
    /// 処理済みバイト数
    pub processed_bytes: AtomicU64,
    /// ドロップされたパケット数
    pub dropped_packets: AtomicU64,
    /// エラーパケット数
    pub error_packets: AtomicU64,
    /// フィルタリングされたパケット数
    pub filtered_packets: AtomicU64,
    /// 暗号化されたパケット数
    pub encrypted_packets: AtomicU64,
}

impl PacketProcessorStats {
    fn new() -> Self {
        Self {
            processed_packets: AtomicU64::new(0),
            processed_bytes: AtomicU64::new(0),
            dropped_packets: AtomicU64::new(0),
            error_packets: AtomicU64::new(0),
            filtered_packets: AtomicU64::new(0),
            encrypted_packets: AtomicU64::new(0),
        }
    }
}

// 新しい列挙型とトレイト
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketType {
    Tcp,
    Udp,
    Icmp,
    Ipv6,
    Arp,
    Other,
}

// アーキテクチャ固有のインターフェース定義を追加
pub mod arch {
    use super::AccelError;
    use alloc::vec::Vec;
    use alloc::string::String;

    /// PCIデバイス情報
    #[derive(Debug, Clone)]
    pub struct DeviceInfo {
        pub device_id: u32,
        pub vendor_id: u16,
        pub device_class: u8,
        pub name: String,
    }

    impl DeviceInfo {
        /// PCIコンフィグレーション空間から32ビット値を読み取り
        pub fn read_config_u32(&self, offset: u32) -> Result<u32, AccelError> {
            // 実際の実装ではPCIコンフィグレーション空間にアクセス
            Ok(0x12345678) // ダミー値
        }
    }

    /// アクセラレーションデバイス情報
    #[derive(Debug, Clone)]
    pub struct AccelerationDeviceInfo {
        pub device_id: u32,
        pub vendor_id: u16,
        pub name: String,
        pub capabilities: u32,
    }

    /// PCI管理モジュール
    pub mod pci {
        use super::*;

        /// PCIデバイスを列挙
        pub fn enumerate_devices() -> Vec<DeviceInfo> {
            // 実際の実装ではPCIバスをスキャンして利用可能なデバイスを検出
            vec![
                DeviceInfo {
                    device_id: 0x1234,
                    vendor_id: 0x8086, // Intel
                    device_class: 0x02, // ネットワークコントローラ
                    name: "Intel Network Adapter".to_string(),
                },
                DeviceInfo {
                    device_id: 0x5678,
                    vendor_id: 0x15b3, // Mellanox
                    device_class: 0x02, // ネットワークコントローラ
                    name: "Mellanox ConnectX".to_string(),
                },
            ]
        }
    }

    /// CPU制御関数
    pub fn cpu_relax() {
        // CPU緩和命令（x86のPAUSE等）
        core::hint::spin_loop();
    }
    
    /// ミリ秒待機
    pub fn delay_ms(ms: u64) {
        // 実際の実装ではタイマーを使用
        for _ in 0..(ms * 1000) {
            cpu_relax();
        }
    }
    
    /// MMIO書き込み
    pub unsafe fn write_mmio_u64(addr: usize, value: u64) {
        // 実際の実装では unsafe なポインタアクセス
        log::trace!("MMIO書き込み: アドレス=0x{:x}, 値=0x{:x}", addr, value);
    }
    
    /// タイムスタンプ取得
    pub fn get_timestamp() -> u64 {
        // タイムスタンプカウンタまたはシステムタイマーから時刻を取得
        static COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        COUNTER.fetch_add(1000000, core::sync::atomic::Ordering::Relaxed)
    }
} 

/// ネットワークアクセラレーションデバイスタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkAccelDeviceType {
    /// Intel E810シリーズ
    IntelE810,
    /// Mellanox ConnectX-6シリーズ
    MellanoxCX6,
    /// Broadcom P5シリーズ
    BroadcomP5,
    /// 汎用デバイス
    Generic,
    /// 不明なデバイス
    Unknown,
}