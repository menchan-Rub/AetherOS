// AetherOS PCIデバイス列挙
//
// このファイルはPCIデバイスの列挙と探索機能を提供します。
// システム内のPCIデバイスを検出し、デバイスツリーを構築します。

use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::format;
use core::sync::atomic::{AtomicBool, Ordering};
use alloc::collections::BTreeMap;
use spin::RwLock;

use crate::core::log;
use crate::core::sync::SpinLock;

use super::{
    PciAddress, PciDeviceInfo, PciDevice,
    get_manager, PciResourceType, PciClass, PciSubclass
};

use crate::drivers::pci::config::{
    PciConfigAccess, CONFIG_VENDOR_ID, CONFIG_DEVICE_ID, CONFIG_CLASS_CODE,
    CONFIG_HEADER_TYPE, CONFIG_SECONDARY_BUS, CONFIG_SUBORDINATE_BUS,
    PciConfigError
};

/// PCIバスデバイス列挙型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciBusLevel {
    /// ルートバス (通常はバス0)
    Root,
    /// セカンダリバス (PCI-PCIブリッジの下流側)
    Secondary,
    /// サブオーディネートバス (PCI-PCIブリッジの再帰的に下流側)
    Subordinate,
}

/// PCIバス列挙オプション
#[derive(Debug, Clone)]
pub struct PciBusEnumerationOptions {
    /// 非表示デバイスも列挙する (通常は無効)
    pub include_hidden: bool,
    /// プラグ＆プレイOS情報を設定する
    pub set_pnp_os: bool,
    /// 列挙中にデバイスを有効化する
    pub enable_devices: bool,
    /// バスマスタリングを有効化する
    pub enable_bus_mastering: bool,
    /// 列挙ログの詳細レベル (0=なし, 1=基本, 2=詳細, 3=すべて)
    pub verbosity: u8,
}

impl Default for PciBusEnumerationOptions {
    fn default() -> Self {
        Self {
            include_hidden: false,
            set_pnp_os: true,
            enable_devices: true,
            enable_bus_mastering: true,
            verbosity: 1,
        }
    }
}

/// PCIバス列挙カウンタ
#[derive(Debug, Default, Clone)]
pub struct PciBusEnumerationStats {
    /// 検出されたバスの総数
    pub buses: usize,
    /// 検出されたデバイスの総数
    pub devices: usize,
    /// 検出されたファンクションの総数
    pub functions: usize,
    /// 検出されたPCI-PCIブリッジの数
    pub bridges: usize,
    /// エラーの数
    pub errors: usize,
}

impl PciBusEnumerationStats {
    /// 新しい列挙統計を作成
    pub fn new() -> Self {
        Default::default()
    }
    
    /// 別の統計オブジェクトと結合する
    pub fn merge(&mut self, other: &Self) {
        self.buses += other.buses;
        self.devices += other.devices;
        self.functions += other.functions;
        self.bridges += other.bridges;
        self.errors += other.errors;
    }
}

/// PCIバス列挙
pub struct PciBusEnumerator {
    /// 列挙プロセスが完了したかどうか
    completed: AtomicBool,
    /// 列挙オプション
    options: PciBusEnumerationOptions,
    /// 列挙統計
    stats: SpinLock<PciBusEnumerationStats>,
    /// 検出されたデバイスリスト
    devices: SpinLock<Vec<Box<PciDevice>>>,
}

impl PciBusEnumerator {
    /// 新しいPCIバス列挙オブジェクトを作成
    pub fn new(options: PciBusEnumerationOptions) -> Self {
        Self {
            completed: AtomicBool::new(false),
            options,
            stats: SpinLock::new(PciBusEnumerationStats::new()),
            devices: SpinLock::new(Vec::new()),
        }
    }
    
    /// システム内のすべてのPCIデバイスを列挙
    pub fn enumerate_all(&self) -> PciBusEnumerationStats {
        // 既に列挙が完了している場合は早期リターン
        if self.completed.load(Ordering::SeqCst) {
            return self.stats.lock().clone();
        }
        
        // ルートPCIセグメントとバスを列挙
        let mut segment: u16 = 0;
        let mut stats = PciBusEnumerationStats::new();
        
        // セグメント0のルートバスから開始
        while self.probe_segment_exists(segment) {
            let segment_stats = self.enumerate_segment(segment);
            stats.merge(&segment_stats);
            
            // 次のセグメントを試す
            segment += 1;
            
            // 安全のため、最大8セグメントに制限
            if segment >= 8 {
                break;
            }
        }
        
        // 列挙統計を更新
        *self.stats.lock() = stats.clone();
        
        // 列挙完了フラグを設定
        self.completed.store(true, Ordering::SeqCst);
        
        // PCIツリーを表示（オプションの詳細レベルに応じて）
        if self.options.verbosity >= 2 {
            self.print_pci_tree();
        }
        
        stats
    }
    
    /// 特定のPCIセグメントを列挙
    pub fn enumerate_segment(&self, segment: u16) -> PciBusEnumerationStats {
        let mut stats = PciBusEnumerationStats::new();
        
        // セグメントのルートバスを列挙
        self.enumerate_bus(segment, 0, PciBusLevel::Root, &mut stats);
        
        stats
    }
    
    /// 特定のPCIバスを列挙
    pub fn enumerate_bus(&self, segment: u16, bus: u8, level: PciBusLevel, stats: &mut PciBusEnumerationStats) {
        if self.options.verbosity >= 2 {
            match level {
                PciBusLevel::Root => log::debug!("PCIバス列挙: セグメント{:04x}のルートバス{:02x}をスキャン", segment, bus),
                PciBusLevel::Secondary => log::debug!("PCIバス列挙: セグメント{:04x}のセカンダリバス{:02x}をスキャン", segment, bus),
                PciBusLevel::Subordinate => log::debug!("PCIバス列挙: セグメント{:04x}のサブオーディネートバス{:02x}をスキャン", segment, bus),
            }
        }
        
        // バス数をインクリメント
        stats.buses += 1;
        
        // バス上のすべてのデバイスをスキャン
        for device in 0..32 {
            self.enumerate_device(segment, bus, device, stats);
        }
    }
    
    /// 特定のPCIデバイスを列挙
    pub fn enumerate_device(&self, segment: u16, bus: u8, device: u8, stats: &mut PciBusEnumerationStats) {
        // デバイス0のファンクション0をプローブ
        let address = PciAddress::new(segment, bus, device, 0);
        let manager = get_manager();
        
        // ベンダーIDを読み取り、デバイスが存在するか確認
        let vendor_id = manager.get_hw_ops().read_config(&address, 0, 16) as u16;
        
        // 無効なベンダーID（0xFFFF）はデバイスが存在しないことを示す
        if vendor_id == 0xFFFF {
            return;
        }
        
        // デバイス数をインクリメント
        stats.devices += 1;
        
        // デバイスの最初のファンクションを列挙
        self.enumerate_function(address, stats);
        
        // ヘッダータイプを読み取り、マルチファンクションデバイスかどうか確認
        let header_type = manager.get_hw_ops().read_config(&address, 0x0E, 8) as u8;
        let is_multifunction = (header_type & 0x80) != 0;
        
        // マルチファンクションデバイスの場合、残りのファンクションをスキャン
        if is_multifunction {
            for function in 1..8 {
                let address = PciAddress::new(segment, bus, device, function);
                
                // ベンダーIDを確認して、ファンクションが存在するか確認
                let vendor_id = manager.get_hw_ops().read_config(&address, 0, 16) as u16;
                if vendor_id != 0xFFFF {
                    self.enumerate_function(address, stats);
                }
            }
        }
    }
    
    /// 特定のPCIファンクションを列挙
    pub fn enumerate_function(&self, address: PciAddress, stats: &mut PciBusEnumerationStats) {
        // ファンクション数をインクリメント
        stats.functions += 1;
        
        let manager = get_manager();
        
        // ヘッダタイプを読み取る
        let header_type = manager.get_hw_ops().read_config(&address, 0x0E, 8) as u8 & 0x7F;
        
        // デバイス情報を作成
        let device_info = self.create_device_info(address);
        
        // デバイスオブジェクトを作成
        let device = Box::new(PciDevice::new(device_info.clone(), manager.get_hw_ops()));
        
        // デバイスリストに追加
        self.devices.lock().push(device);
        
        // オプションに応じてデバイスを有効化
        if self.options.enable_devices {
            // 有効化ロジックをここに実装...
        }
        
        // デバイス情報をログに記録
        if self.options.verbosity >= 1 {
            log::info!("PCI {:04x}:{:02x}:{:02x}.{:01x}: {:04x}:{:04x} [クラス {:02x}{:02x}] {}",
                     address.segment, address.bus, address.device, address.function,
                     device_info.vendor_id, device_info.device_id,
                     device_info.class_code, device_info.subclass_code,
                     self.get_device_description(&device_info));
        }
        
        // PCI-PCIブリッジの場合、セカンダリバスを列挙
        if header_type == 1 && device_info.is_pci_bridge() {
            stats.bridges += 1;
            
            // セカンダリバス番号を読み取る
            let secondary_bus = manager.get_hw_ops().read_config(&address, 0x19, 8) as u8;
            
            // セカンダリバスが有効な場合、そのバスを列挙
            if secondary_bus != 0 {
                self.enumerate_bus(address.segment, secondary_bus, PciBusLevel::Secondary, stats);
            }
            
            // サブオーディネートバス番号を読み取る
            let subordinate_bus = manager.get_hw_ops().read_config(&address, 0x1A, 8) as u8;
            
            // サブオーディネートバスとセカンダリバスが異なる場合、
            // セカンダリバスとサブオーディネートバスの間のすべてのバスを列挙
            if subordinate_bus > secondary_bus {
                for bus in (secondary_bus + 1)..=subordinate_bus {
                    self.enumerate_bus(address.segment, bus, PciBusLevel::Subordinate, stats);
                }
            }
        }
    }
    
    /// PCIセグメントが存在するかどうかを確認
    fn probe_segment_exists(&self, segment: u16) -> bool {
        // セグメント0は常に存在する
        if segment == 0 {
            return true;
        }
        
        // セグメントのルートバスのデバイス0をプローブして確認
        let address = PciAddress::new(segment, 0, 0, 0);
        let manager = get_manager();
        
        // ベンダーIDを読み取り
        let vendor_id = manager.get_hw_ops().read_config(&address, 0, 16) as u16;
        
        // 有効なベンダーIDがあればセグメントは存在する
        vendor_id != 0xFFFF
    }
    
    /// デバイス情報を作成
    fn create_device_info(&self, address: PciAddress) -> PciDeviceInfo {
        let manager = get_manager();
        let hw_ops = manager.get_hw_ops();
        
        // 基本情報を読み取る
        let vendor_id = hw_ops.read_config(&address, 0x00, 16) as u16;
        let device_id = hw_ops.read_config(&address, 0x02, 16) as u16;
        let command = hw_ops.read_config(&address, 0x04, 16) as u16;
        let status = hw_ops.read_config(&address, 0x06, 16) as u16;
        let revision_id = hw_ops.read_config(&address, 0x08, 8) as u8;
        let prog_if = hw_ops.read_config(&address, 0x09, 8) as u8;
        let subclass_code = hw_ops.read_config(&address, 0x0A, 8) as u8;
        let class_code = hw_ops.read_config(&address, 0x0B, 8) as u8;
        let cache_line_size = hw_ops.read_config(&address, 0x0C, 8) as u8;
        let latency_timer = hw_ops.read_config(&address, 0x0D, 8) as u8;
        let header_type = hw_ops.read_config(&address, 0x0E, 8) as u8;
        let bist = hw_ops.read_config(&address, 0x0F, 8) as u8;
        
        // ヘッダタイプに基づいて追加情報を読み取る
        let (subsystem_vendor_id, subsystem_id, interrupt_line, interrupt_pin) = match header_type & 0x7F {
            // タイプ0ヘッダ (通常のPCIデバイス)
            0 => {
                let subsystem_vendor_id = hw_ops.read_config(&address, 0x2C, 16) as u16;
                let subsystem_id = hw_ops.read_config(&address, 0x2E, 16) as u16;
                let interrupt_line = hw_ops.read_config(&address, 0x3C, 8) as u8;
                let interrupt_pin = hw_ops.read_config(&address, 0x3D, 8) as u8;
                (subsystem_vendor_id, subsystem_id, interrupt_line, interrupt_pin)
            },
            
            // タイプ1ヘッダ (PCI-PCIブリッジ)
            1 => {
                // ブリッジには通常サブシステム情報がない
                let interrupt_line = hw_ops.read_config(&address, 0x3C, 8) as u8;
                let interrupt_pin = hw_ops.read_config(&address, 0x3D, 8) as u8;
                (0, 0, interrupt_line, interrupt_pin)
            },
            
            // タイプ2ヘッダ (CardBusブリッジ)
            2 => {
                let subsystem_vendor_id = hw_ops.read_config(&address, 0x40, 16) as u16;
                let subsystem_id = hw_ops.read_config(&address, 0x42, 16) as u16;
                let interrupt_line = hw_ops.read_config(&address, 0x3C, 8) as u8;
                let interrupt_pin = hw_ops.read_config(&address, 0x3D, 8) as u8;
                (subsystem_vendor_id, subsystem_id, interrupt_line, interrupt_pin)
            },
            
            // その他の未知のヘッダタイプ
            _ => (0, 0, 0, 0),
        };
        
        PciDeviceInfo {
            address,
            vendor_id,
            device_id,
            class_code,
            subclass_code,
            prog_if,
            revision_id,
            header_type,
            subsystem_vendor_id,
            subsystem_id,
            interrupt_line,
            interrupt_pin,
        }
    }
    
    /// デバイスの説明を取得
    fn get_device_description(&self, info: &PciDeviceInfo) -> String {
        let class = PciClass::from(info.class_code);
        let subclass = PciSubclass::from_codes(info.class_code, info.subclass_code);
        
        let class_name = match class {
            PciClass::Unclassified => "未分類",
            PciClass::MassStorageController => "マスストレージコントローラ",
            PciClass::NetworkController => "ネットワークコントローラ",
            PciClass::DisplayController => "ディスプレイコントローラ",
            PciClass::MultimediaController => "マルチメディアコントローラ",
            PciClass::MemoryController => "メモリコントローラ",
            PciClass::BridgeDevice => "ブリッジデバイス",
            PciClass::SimpleCommunicationController => "通信コントローラ",
            PciClass::BaseSystemPeripheral => "システム周辺機器",
            PciClass::InputDevice => "入力デバイス",
            PciClass::DockingStation => "ドッキングステーション",
            PciClass::Processor => "プロセッサ",
            PciClass::SerialBusController => "シリアルバスコントローラ",
            PciClass::WirelessController => "ワイヤレスコントローラ",
            PciClass::IntelligentController => "インテリジェントコントローラ",
            PciClass::SatelliteCommunicationController => "衛星通信コントローラ",
            PciClass::EncryptionController => "暗号化コントローラ",
            PciClass::SignalProcessingController => "信号処理コントローラ",
            PciClass::Reserved(_) => "予約済みデバイス",
            PciClass::VendorSpecific => "ベンダー固有デバイス",
        };
        
        let subclass_description = match subclass {
            PciSubclass::ScsiController => "SCSIコントローラ",
            PciSubclass::IdeController => "IDEコントローラ",
            PciSubclass::FloppyController => "フロッピーコントローラ",
            PciSubclass::IpiController => "IPIコントローラ",
            PciSubclass::RaidController => "RAIDコントローラ",
            PciSubclass::AtaController => "ATAコントローラ",
            PciSubclass::SerialAta => "Serial ATA",
            PciSubclass::SerialScsi => "Serial SCSI",
            PciSubclass::NonVolatileMemory => "不揮発性メモリコントローラ",
            PciSubclass::EthernetController => "イーサネットコントローラ",
            PciSubclass::TokenRingController => "トークンリングコントローラ",
            PciSubclass::FddiController => "FDDIコントローラ",
            PciSubclass::AtmController => "ATMコントローラ",
            PciSubclass::IsdnController => "ISDNコントローラ",
            PciSubclass::VgaController => "VGAコントローラ",
            PciSubclass::XgaController => "XGAコントローラ",
            PciSubclass::ThreeDController => "3Dコントローラ",
            PciSubclass::HostBridge => "ホストブリッジ",
            PciSubclass::IsaBridge => "ISAブリッジ",
            PciSubclass::EisaBridge => "EISAブリッジ",
            PciSubclass::McaBridge => "MCAブリッジ",
            PciSubclass::PciToPciBridge => "PCI-PCIブリッジ",
            PciSubclass::PcmciaBridge => "PCMCIAブリッジ",
            PciSubclass::NuBusBridge => "NuBusブリッジ",
            PciSubclass::CardBusBridge => "CardBusブリッジ",
            PciSubclass::Other(_, _) => "",
        };
        
        format!("{} {}", class_name, subclass_description).trim().to_string()
    }
    
    /// PCIデバイスツリーを表示
    fn print_pci_tree(&self) {
        log::info!("PCIデバイスツリー:");
        
        // ルートバスのデバイスを列挙
        for segment in 0..8 {
            if !self.probe_segment_exists(segment as u16) {
                continue;
            }
            
            self.print_bus_devices(segment as u16, 0, 0);
        }
    }
    
    /// バスのデバイスを表示（再帰的に）
    fn print_bus_devices(&self, segment: u16, bus: u8, indent: usize) {
        let indent_str = " ".repeat(indent);
        
        // このバス上のデバイスを取得
        let devices = self.devices.lock();
        
        for device in devices.iter().filter(|d| 
            d.address().segment == segment && 
            d.address().bus == bus
        ) {
            let addr = device.address();
            
            // デバイス情報を表示
            log::info!("{}[{:04x}:{:02x}:{:02x}.{:01x}] {:04x}:{:04x} {}",
                     indent_str,
                     addr.segment, addr.bus, addr.device, addr.function,
                     device.vendor_id(), device.device_id(),
                     self.get_device_description(&PciDeviceInfo {
                         address: addr,
                         vendor_id: device.vendor_id(),
                         device_id: device.device_id(),
                         class_code: device.class_code(),
                         subclass_code: device.subclass_code(),
                         prog_if: device.prog_if(),
                         revision_id: device.revision_id(),
                         header_type: device.header_type(),
                         subsystem_vendor_id: device.subsystem_vendor_id(),
                         subsystem_id: device.subsystem_id(),
                         interrupt_line: device.interrupt_line(),
                         interrupt_pin: device.interrupt_pin(),
                     }));
            
            // PCI-PCIブリッジの場合、セカンダリバスも表示
            if device.class_code() == 0x06 && device.subclass_code() == 0x04 {
                // コンフィギュレーション空間からセカンダリバス番号を読み取る
                let secondary_bus = get_manager().get_hw_ops().read_config(&addr, 0x19, 8) as u8;
                
                if secondary_bus != 0 {
                    // 再帰的にセカンダリバスのデバイスを表示
                    self.print_bus_devices(segment, secondary_bus, indent + 2);
                }
            }
        }
    }
    
    /// 列挙されたデバイスを取得
    pub fn get_devices(&self) -> Vec<Box<PciDevice>> {
        self.devices.lock().clone()
    }
    
    /// 列挙統計を取得
    pub fn get_stats(&self) -> PciBusEnumerationStats {
        self.stats.lock().clone()
    }
}

/// PCIデバイス列挙を実行して結果を取得
pub fn enumerate_pci_devices() -> PciBusEnumerationStats {
    // デフォルトオプションでPCIデバイスを列挙
    let options = PciBusEnumerationOptions::default();
    let enumerator = PciBusEnumerator::new(options);
    
    enumerator.enumerate_all()
}

/// PCIデバイス列挙を実行して詳細なデバッグログを出力
pub fn debug_enumerate_pci_devices() -> PciBusEnumerationStats {
    // 詳細なデバッグログを有効にしたオプションを作成
    let mut options = PciBusEnumerationOptions::default();
    options.verbosity = 3;
    
    let enumerator = PciBusEnumerator::new(options);
    enumerator.enumerate_all()
}

/// PCIデバイスの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciDeviceType {
    /// 通常のPCIデバイス
    Normal,
    /// PCIブリッジ
    Bridge,
    /// PCIカードバスブリッジ
    CardBusBridge,
    /// 不明なデバイスタイプ
    Unknown,
}

impl From<u8> for PciDeviceType {
    fn from(header_type: u8) -> Self {
        // ヘッダータイプの下位7ビットのみを使用
        match header_type & 0x7F {
            0x00 => PciDeviceType::Normal,
            0x01 => PciDeviceType::Bridge,
            0x02 => PciDeviceType::CardBusBridge,
            _ => PciDeviceType::Unknown,
        }
    }
}

/// PCIデバイス情報
#[derive(Debug, Clone)]
pub struct PciDeviceInfo {
    /// デバイスのPCIアドレス
    pub address: PciAddress,
    /// ベンダーID
    pub vendor_id: u16,
    /// デバイスID
    pub device_id: u16,
    /// クラスコード（上位8ビット: ベースクラス、中間8ビット: サブクラス、下位8ビット: プログラミングインターフェース）
    pub class_code: u32,
    /// デバイスタイプ
    pub device_type: PciDeviceType,
    /// このデバイスがマルチファンクションデバイスの一部かどうか
    pub is_multifunction: bool,
    /// デバイスが有効かどうか
    pub is_enabled: bool,
    /// ブリッジ特有の情報（ブリッジの場合のみ有効）
    pub bridge_info: Option<PciBridgeInfo>,
}

/// PCIブリッジ特有の情報
#[derive(Debug, Clone)]
pub struct PciBridgeInfo {
    /// セカンダリバス番号
    pub secondary_bus: u8,
    /// サブオーディネートバス番号
    pub subordinate_bus: u8,
}

/// PCIシステム管理
pub struct PciSystem {
    /// 検出されたすべてのPCIデバイス（キー: PciAddress、値: PciDeviceInfo）
    devices: RwLock<BTreeMap<PciAddress, PciDeviceInfo>>,
    /// PCI設定空間へのアクセスインスタンス
    config_access: &'static PciConfigAccess,
}

impl PciSystem {
    /// 新しいPCIシステムインスタンスを作成
    pub fn new(config_access: &'static PciConfigAccess) -> Self {
        Self {
            devices: RwLock::new(BTreeMap::new()),
            config_access,
        }
    }

    /// すべてのPCIデバイスを列挙
    pub fn enumerate_all_devices(&self) -> Result<usize, PciConfigError> {
        log::info!("PCI: デバイス列挙を開始します");
        let mut devices = self.devices.write();
        devices.clear();

        // まず従来のPCIバスをスキャン（セグメント0）
        let mut total = 0;
        total += self.scan_bus(0, 0, 0, &mut devices)?;

        // 列挙の結果を表示
        log::info!("PCI: {}個のデバイスを発見しました", total);
        for (addr, device) in devices.iter() {
            let class = (device.class_code >> 16) & 0xFF;
            let subclass = (device.class_code >> 8) & 0xFF;
            let prog_if = device.class_code & 0xFF;
            
            let device_type_str = match device.device_type {
                PciDeviceType::Normal => "通常",
                PciDeviceType::Bridge => "ブリッジ",
                PciDeviceType::CardBusBridge => "カードバスブリッジ",
                PciDeviceType::Unknown => "不明",
            };
            
            log::info!("PCI: [{:04x}:{:02x}:{:02x}.{:x}] ベンダー={:04x} デバイス={:04x} クラス={:02x}:{:02x}:{:02x} タイプ={}",
                addr.segment(), addr.bus(), addr.device(), addr.function(),
                device.vendor_id, device.device_id,
                class, subclass, prog_if,
                device_type_str);
        }

        Ok(total)
    }

    /// 指定されたバスをスキャンし、すべてのデバイスを列挙
    fn scan_bus(
        &self, 
        segment: u16, 
        bus: u8, 
        bus_level: usize,
        devices: &mut BTreeMap<PciAddress, PciDeviceInfo>
    ) -> Result<usize, PciConfigError> {
        log::debug!("PCI: バス{:02x}をスキャン中（レベル{}）", bus, bus_level);

        let mut device_count = 0;

        // 各デバイスをスキャン
        for device in 0..32 {
            device_count += self.scan_device(segment, bus, device, bus_level, devices)?;
        }

        log::debug!("PCI: バス{:02x}のスキャン完了、{}個のデバイスを発見", bus, device_count);
        Ok(device_count)
    }

    /// 指定されたデバイスをスキャン
    fn scan_device(
        &self, 
        segment: u16, 
        bus: u8, 
        device: u8,
        bus_level: usize,
        devices: &mut BTreeMap<PciAddress, PciDeviceInfo>
    ) -> Result<usize, PciConfigError> {
        let addr = PciAddress::new(segment, bus, device, 0);
        let vendor_id = match self.config_access.read_vendor_id(&addr) {
            Ok(id) => id,
            Err(PciConfigError::DeviceNotFound) => return Ok(0),
            Err(e) => return Err(e),
        };

        // ベンダーIDが無効（0xFFFF）の場合、デバイスは存在しない
        if vendor_id == 0xFFFF {
            return Ok(0);
        }

        // 最初のファンクションを確認
        let mut device_count = self.scan_function(segment, bus, device, 0, bus_level, devices)?;
        
        // ヘッダータイプを読み取り、マルチファンクションかどうかを確認
        let header_type = self.config_access.read_register_u8(&addr, CONFIG_HEADER_TYPE)?;
        let is_multifunction = (header_type & 0x80) != 0;

        // マルチファンクションデバイスの場合は、残りのファンクションもスキャン
        if is_multifunction {
            for function in 1..8 {
                device_count += self.scan_function(segment, bus, device, function, bus_level, devices)?;
            }
        }

        Ok(device_count)
    }

    /// 指定されたファンクションをスキャン
    fn scan_function(
        &self, 
        segment: u16, 
        bus: u8, 
        device: u8, 
        function: u8,
        bus_level: usize,
        devices: &mut BTreeMap<PciAddress, PciDeviceInfo>
    ) -> Result<usize, PciConfigError> {
        let addr = PciAddress::new(segment, bus, device, function);
        
        // ベンダーIDを確認
        let vendor_id = match self.config_access.read_vendor_id(&addr) {
            Ok(id) => id,
            Err(PciConfigError::DeviceNotFound) => return Ok(0),
            Err(e) => return Err(e),
        };

        // ベンダーIDが無効な場合はスキップ
        if vendor_id == 0xFFFF {
            return Ok(0);
        }

        // デバイス情報を取得
        let device_id = self.config_access.read_device_id(&addr)?;
        let class_code = self.config_access.read_class_code(&addr)?;
        let header_type = self.config_access.read_register_u8(&addr, CONFIG_HEADER_TYPE)?;
        let device_type = PciDeviceType::from(header_type);
        let is_multifunction = (header_type & 0x80) != 0;

        // デバイス情報を構築
        let mut bridge_info = None;
        
        // ブリッジデバイスの場合は、セカンダリバスとサブオーディネートバスの情報を取得
        if device_type == PciDeviceType::Bridge {
            let secondary_bus = self.config_access.read_register_u8(&addr, CONFIG_SECONDARY_BUS)?;
            let subordinate_bus = self.config_access.read_register_u8(&addr, CONFIG_SUBORDINATE_BUS)?;
            
            bridge_info = Some(PciBridgeInfo {
                secondary_bus,
                subordinate_bus,
            });
        }

        // デバイス情報を保存
        let device_info = PciDeviceInfo {
            address: addr,
            vendor_id,
            device_id,
            class_code,
            device_type,
            is_multifunction,
            is_enabled: true, // デフォルトで有効とする
            bridge_info,
        };

        log::debug!("PCI: デバイス発見 [{:04x}:{:02x}:{:02x}.{:x}] V={:04x} D={:04x} C={:08x}",
            addr.segment(), addr.bus(), addr.device(), addr.function(),
            vendor_id, device_id, class_code);

        // デバイスをマップに追加
        devices.insert(addr, device_info.clone());

        // PCIブリッジの場合は、セカンダリバスも再帰的にスキャン
        let mut child_devices = 0;
        if let Some(bridge_info) = &bridge_info {
            // 無限再帰を防ぐために最大深さをチェック
            if bus_level < 16 {
                child_devices = self.scan_bus(
                    segment, 
                    bridge_info.secondary_bus, 
                    bus_level + 1,
                    devices
                )?;
                
                log::debug!("PCI: ブリッジ [{:04x}:{:02x}:{:02x}.{:x}] のセカンダリバス {:02x} で{}個のデバイスを発見",
                    addr.segment(), addr.bus(), addr.device(), addr.function(),
                    bridge_info.secondary_bus, child_devices);
            } else {
                log::warn!("PCI: バス階層が深すぎます。スキャンを中止します。");
            }
        }

        Ok(1 + child_devices)
    }

    /// アドレスによるPCIデバイスの検索
    pub fn get_device(&self, address: &PciAddress) -> Option<PciDeviceInfo> {
        self.devices.read().get(address).cloned()
    }

    /// すべてのPCIデバイスのリストを取得
    pub fn get_all_devices(&self) -> Vec<PciDeviceInfo> {
        self.devices.read().values().cloned().collect()
    }

    /// 指定されたベンダーIDとデバイスIDを持つすべてのデバイスを検索
    pub fn find_devices_by_id(&self, vendor_id: u16, device_id: u16) -> Vec<PciDeviceInfo> {
        self.devices.read()
            .values()
            .filter(|d| d.vendor_id == vendor_id && d.device_id == device_id)
            .cloned()
            .collect()
    }

    /// 指定されたクラスコードを持つすべてのデバイスを検索
    pub fn find_devices_by_class(&self, class_code: u32, mask: u32) -> Vec<PciDeviceInfo> {
        self.devices.read()
            .values()
            .filter(|d| (d.class_code & mask) == (class_code & mask))
            .cloned()
            .collect()
    }
}

/// PCI列挙システムのシングルトンインスタンス
static PCI_SYSTEM: RwLock<Option<PciSystem>> = RwLock::new(None);

/// PCI列挙システムを初期化
pub fn init(config_access: &'static PciConfigAccess) -> Result<usize, PciConfigError> {
    log::info!("PCI: システム初期化");
    let system = PciSystem::new(config_access);
    let device_count = system.enumerate_all_devices()?;
    *PCI_SYSTEM.write() = Some(system);
    Ok(device_count)
}

/// PCIシステムのインスタンスを取得
pub fn get_pci_system() -> Option<&'static PciSystem> {
    match *PCI_SYSTEM.read() {
        Some(ref system) => Some(unsafe { &*(system as *const PciSystem) }),
        None => None,
    }
} 