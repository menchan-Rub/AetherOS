// AetherOS PCIデバイス実装
//
// このファイルはPCIデバイスの構造体と関連機能を定義します。
// PCIデバイスのプロパティ、操作、状態管理が含まれます。

use alloc::vec::Vec;
use alloc::string::String;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::core::sync::SpinLock;
use crate::core::log;

use super::{
    PciAddress, PciVendorId, PciDeviceId, PciClassCode,
    PciSubclassCode, PciProgIf, PciRevisionId, PciResource,
    PciResourceType, PciCapability, PciCapabilityId, PciHwOps,
    get_vendor_name, get_device_name, get_class_name, get_subclass_name
};
use super::resource::PciBarInfo;
use super::config::PciConfigSpace;

/// PCIデバイスクラスの列挙型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciClass {
    /// 未定義クラス
    Unclassified,
    /// マスコントローラ
    MassStorageController,
    /// ネットワークコントローラ
    NetworkController,
    /// ディスプレイコントローラ
    DisplayController,
    /// マルチメディアコントローラ
    MultimediaController,
    /// メモリコントローラ
    MemoryController,
    /// ブリッジデバイス
    BridgeDevice,
    /// 単純通信コントローラ
    SimpleCommunicationController,
    /// ベースシステム周辺機器
    BaseSystemPeripheral,
    /// 入力デバイス
    InputDevice,
    /// ドックステーション
    DockingStation,
    /// プロセッサ
    Processor,
    /// シリアルバスコントローラ
    SerialBusController,
    /// ワイヤレスコントローラ
    WirelessController,
    /// インテリジェントI/Oコントローラ
    IntelligentController,
    /// 衛星通信コントローラ
    SatelliteCommunicationController,
    /// 暗号化コントローラ
    EncryptionController,
    /// データ収集および信号処理コントローラ
    SignalProcessingController,
    /// 予約済み
    Reserved(u8),
    /// ベンダー固有
    VendorSpecific,
}

impl From<PciClassCode> for PciClass {
    fn from(code: PciClassCode) -> Self {
        match code {
            0x00 => PciClass::Unclassified,
            0x01 => PciClass::MassStorageController,
            0x02 => PciClass::NetworkController,
            0x03 => PciClass::DisplayController,
            0x04 => PciClass::MultimediaController,
            0x05 => PciClass::MemoryController,
            0x06 => PciClass::BridgeDevice,
            0x07 => PciClass::SimpleCommunicationController,
            0x08 => PciClass::BaseSystemPeripheral,
            0x09 => PciClass::InputDevice,
            0x0A => PciClass::DockingStation,
            0x0B => PciClass::Processor,
            0x0C => PciClass::SerialBusController,
            0x0D => PciClass::WirelessController,
            0x0E => PciClass::IntelligentController,
            0x0F => PciClass::SatelliteCommunicationController,
            0x10 => PciClass::EncryptionController,
            0x11 => PciClass::SignalProcessingController,
            0x12..=0xFE => PciClass::Reserved(code),
            0xFF => PciClass::VendorSpecific,
        }
    }
}

/// PCIデバイスサブクラスの列挙型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciSubclass {
    // 主要なサブクラスのみを列挙（実際には各クラスに対応するサブクラスがある）
    
    // Mass Storage Controller (0x01)
    /// SCSI バスコントローラ
    ScsiController,
    /// IDE コントローラ
    IdeController,
    /// フロッピーディスクコントローラ
    FloppyController,
    /// IPI バスコントローラ
    IpiController,
    /// RAID コントローラ
    RaidController,
    /// ATA コントローラ
    AtaController,
    /// シリアルATA
    SerialAta,
    /// シリアルアタッチドSCSI
    SerialScsi,
    /// 不揮発性メモリコントローラ
    NonVolatileMemory,
    
    // Network Controller (0x02)
    /// イーサネットコントローラ
    EthernetController,
    /// トークンリングコントローラ
    TokenRingController,
    /// FDDIコントローラ
    FddiController,
    /// ATMコントローラ
    AtmController,
    /// ISDNコントローラ
    IsdnController,
    
    // Display Controller (0x03)
    /// VGAコントローラ
    VgaController,
    /// XGAコントローラ
    XgaController,
    /// 3Dコントローラ
    ThreeDController,
    
    // Bridge Device (0x06)
    /// ホストブリッジ
    HostBridge,
    /// ISAブリッジ
    IsaBridge,
    /// EISAブリッジ
    EisaBridge,
    /// MCAブリッジ
    McaBridge,
    /// PCI-PCIブリッジ
    PciToPciBridge,
    /// PCMCIAブリッジ
    PcmciaBridge,
    /// NuBusブリッジ
    NuBusBridge,
    /// CardBusブリッジ
    CardBusBridge,
    
    /// その他のサブクラス
    Other(PciClassCode, PciSubclassCode),
}

impl PciSubclass {
    /// クラスコードとサブクラスコードからサブクラスを取得
    pub fn from_codes(class: PciClassCode, subclass: PciSubclassCode) -> Self {
        match (class, subclass) {
            // Mass Storage Controller (0x01)
            (0x01, 0x00) => PciSubclass::ScsiController,
            (0x01, 0x01) => PciSubclass::IdeController,
            (0x01, 0x02) => PciSubclass::FloppyController,
            (0x01, 0x03) => PciSubclass::IpiController,
            (0x01, 0x04) => PciSubclass::RaidController,
            (0x01, 0x05) => PciSubclass::AtaController,
            (0x01, 0x06) => PciSubclass::SerialAta,
            (0x01, 0x07) => PciSubclass::SerialScsi,
            (0x01, 0x08) => PciSubclass::NonVolatileMemory,
            
            // Network Controller (0x02)
            (0x02, 0x00) => PciSubclass::EthernetController,
            (0x02, 0x01) => PciSubclass::TokenRingController,
            (0x02, 0x02) => PciSubclass::FddiController,
            (0x02, 0x03) => PciSubclass::AtmController,
            (0x02, 0x04) => PciSubclass::IsdnController,
            
            // Display Controller (0x03)
            (0x03, 0x00) => PciSubclass::VgaController,
            (0x03, 0x01) => PciSubclass::XgaController,
            (0x03, 0x02) => PciSubclass::ThreeDController,
            
            // Bridge Device (0x06)
            (0x06, 0x00) => PciSubclass::HostBridge,
            (0x06, 0x01) => PciSubclass::IsaBridge,
            (0x06, 0x02) => PciSubclass::EisaBridge,
            (0x06, 0x03) => PciSubclass::McaBridge,
            (0x06, 0x04) => PciSubclass::PciToPciBridge,
            (0x06, 0x05) => PciSubclass::PcmciaBridge,
            (0x06, 0x06) => PciSubclass::NuBusBridge,
            (0x06, 0x07) => PciSubclass::CardBusBridge,
            
            // その他
            (class, subclass) => PciSubclass::Other(class, subclass),
        }
    }
}

/// PCIデバイス情報構造体
#[derive(Debug, Clone)]
pub struct PciDeviceInfo {
    /// PCIアドレス
    pub address: PciAddress,
    /// ベンダーID
    pub vendor_id: PciVendorId,
    /// デバイスID
    pub device_id: PciDeviceId,
    /// クラスコード
    pub class_code: PciClassCode,
    /// サブクラスコード
    pub subclass_code: PciSubclassCode,
    /// プログラミングインタフェース
    pub prog_if: PciProgIf,
    /// リビジョンID
    pub revision_id: PciRevisionId,
    /// ヘッダタイプ (0=通常, 1=PCI-PCIブリッジ, 2=CardBus)
    pub header_type: u8,
    /// サブシステムベンダーID
    pub subsystem_vendor_id: PciVendorId,
    /// サブシステムID
    pub subsystem_id: PciDeviceId,
    /// 割り込みライン
    pub interrupt_line: u8,
    /// 割り込みピン (0=なし, 1=INTA#, 2=INTB#, 3=INTC#, 4=INTD#)
    pub interrupt_pin: u8,
}

/// PCIデバイス構造体
pub struct PciDevice {
    /// デバイス情報
    info: PciDeviceInfo,
    /// デバイスがイネーブルされているか
    enabled: AtomicBool,
    /// デバイスがバスマスタリングを許可されているか
    bus_master: AtomicBool,
    /// 割り込みが無効化されているか
    int_disabled: AtomicBool,
    /// デバイスリソース
    resources: SpinLock<Vec<PciResource>>,
    /// デバイスケイパビリティ
    capabilities: SpinLock<Vec<PciCapability>>,
    /// ハードウェア操作オブジェクト
    hw_ops: &'static dyn PciHwOps,
    /// ドライバがアタッチされているか
    driver_attached: AtomicBool,
    /// BARの情報
    bar_info: [Option<PciBarInfo>; 6],
}

impl PciDevice {
    /// 新しいPCIデバイスを作成
    pub fn new(info: PciDeviceInfo, hw_ops: &'static dyn PciHwOps) -> Self {
        let mut device = Self {
            info,
            enabled: AtomicBool::new(false),
            bus_master: AtomicBool::new(false),
            int_disabled: AtomicBool::new(true),
            resources: SpinLock::new(Vec::new()),
            capabilities: SpinLock::new(Vec::new()),
            hw_ops,
            driver_attached: AtomicBool::new(false),
            bar_info: [None, None, None, None, None, None],
        };
        
        // ケイパビリティをスキャン
        device.scan_capabilities();
        
        // デバイスリソースを初期化
        device.init_resources();
        
        // コマンドレジスタの初期状態を読み取り
        let cmd = device.read_config_u16(0x04);
        device.enabled.store((cmd & 0x3) != 0, Ordering::Relaxed);
        device.bus_master.store((cmd & 0x4) != 0, Ordering::Relaxed);
        device.int_disabled.store((cmd & 0x400) != 0, Ordering::Relaxed);
        
        device
    }
    
    /// PCIコンフィギュレーション空間から8ビット値を読み取る
    pub fn read_config_u8(&self, offset: u16) -> u8 {
        let value = self.hw_ops.read_config(&self.info.address, offset, 8);
        value as u8
    }
    
    /// PCIコンフィギュレーション空間から16ビット値を読み取る
    pub fn read_config_u16(&self, offset: u16) -> u16 {
        let value = self.hw_ops.read_config(&self.info.address, offset, 16);
        value as u16
    }
    
    /// PCIコンフィギュレーション空間から32ビット値を読み取る
    pub fn read_config_u32(&self, offset: u16) -> u32 {
        self.hw_ops.read_config(&self.info.address, offset, 32)
    }
    
    /// PCIコンフィギュレーション空間に8ビット値を書き込む
    pub fn write_config_u8(&self, offset: u16, value: u8) {
        self.hw_ops.write_config(&self.info.address, offset, 8, value as u32);
    }
    
    /// PCIコンフィギュレーション空間に16ビット値を書き込む
    pub fn write_config_u16(&self, offset: u16, value: u16) {
        self.hw_ops.write_config(&self.info.address, offset, 16, value as u32);
    }
    
    /// PCIコンフィギュレーション空間に32ビット値を書き込む
    pub fn write_config_u32(&self, offset: u16, value: u32) {
        self.hw_ops.write_config(&self.info.address, offset, 32, value);
    }
    
    /// PCIケイパビリティをスキャンする
    fn scan_capabilities(&self) {
        // ステータスレジスタを読み取り、ケイパビリティリストが存在するか確認
        let status = self.read_config_u16(0x06);
        if (status & 0x10) == 0 {
            // ケイパビリティリストがない
            return;
        }
        
        // ケイパビリティポインタを取得（ヘッダタイプに応じて位置が異なる）
        let cap_ptr = match self.info.header_type & 0x7F {
            0 => self.read_config_u8(0x34), // 通常デバイス
            1 => self.read_config_u8(0x34), // PCI-PCIブリッジ
            2 => self.read_config_u8(0x14), // CardBusブリッジ
            _ => 0, // 不明なヘッダタイプ
        };
        
        if cap_ptr == 0 {
            return;
        }
        
        // ケイパビリティをスキャン（ループ検出のための安全対策を含む）
        let mut offset = cap_ptr;
        let mut visited = [false; 256];
        let mut capabilities = Vec::new();
        
        while offset != 0 {
            if visited[offset as usize] {
                // ループ検出
                log::warn!("PCI ケイパビリティリストでループを検出: {}", self.info.address);
                break;
            }
            
            visited[offset as usize] = true;
            
            // ケイパビリティIDと次のポインタを読み取る
            let cap_id = self.read_config_u8(offset as u16);
            let next_ptr = self.read_config_u8((offset + 1) as u16);
            
            // ケイパビリティを作成して追加
            let capability = PciCapability::new(
                PciCapabilityId::from(cap_id),
                offset,
                self
            );
            
            capabilities.push(capability);
            
            // 次のケイパビリティへ
            offset = next_ptr;
        }
        
        // 見つかったケイパビリティを格納
        *self.capabilities.lock() = capabilities;
    }
    
    /// デバイスリソースを初期化する
    fn init_resources(&mut self) {
        // BARをスキャン
        let mut resources = Vec::new();
        let bar_count = if (self.info.header_type & 0x7F) == 0 { 6 } else { 2 };
        
        for i in 0..bar_count {
            let bar_offset = 0x10 + (i * 4) as u16;
            let bar_value = self.read_config_u32(bar_offset);
            
            if bar_value == 0 {
                continue; // BARが未使用
            }
            
            // BARの種類を判定
            let is_io = (bar_value & 0x1) == 0x1;
            let is_64bit = !is_io && ((bar_value & 0x6) == 0x4);
            
            // BARのアドレスを取得
            let resource_type = if is_io {
                PciResourceType::Io
            } else {
                match (bar_value >> 1) & 0x3 {
                    0 => PciResourceType::Memory32,
                    1 => PciResourceType::Memory16,
                    2 => PciResourceType::Memory32Prefetchable,
                    3 => if is_64bit {
                            PciResourceType::Memory64Prefetchable
                        } else {
                            PciResourceType::Memory32Prefetchable
                        },
                    _ => unreachable!(),
                }
            };
            
            // リソースサイズを取得
            let bar_size = self.get_bar_size(i);
            if bar_size == 0 {
                continue; // 無効なBAR
            }
            
            // リソースアドレスを計算
            let resource_addr = if is_io {
                (bar_value & !0x3) as usize
            } else {
                (bar_value & !0xF) as usize
            };
            
            // 64ビットBARの場合、上位32ビットを取得
            let resource_addr = if is_64bit && i < bar_count - 1 {
                let upper = self.read_config_u32(bar_offset + 4) as usize;
                (upper << 32) | resource_addr
            } else {
                resource_addr
            };
            
            // リソースを追加
            let resource = PciResource::new(
                resource_addr, 
                bar_size, 
                resource_type,
                format!("BAR{}", i)
            );
            
            resources.push(resource);
            
            // BARの情報を保存
            self.bar_info[i as usize] = Some(PciBarInfo {
                address: resource_addr,
                size: bar_size,
                resource_type,
                is_64bit,
                index: i as u8,
            });
            
            // 64ビットBARの場合、次のインデックスをスキップ
            if is_64bit && i < bar_count - 1 {
                self.bar_info[(i + 1) as usize] = None;
                i += 1;
            }
        }
        
        // ROM BARを確認（ヘッダタイプ0のみ）
        if (self.info.header_type & 0x7F) == 0 {
            let rom_bar = self.read_config_u32(0x30);
            if rom_bar != 0 && (rom_bar & 0x1) == 0x1 {
                // ROM BARのサイズを計算
                let orig_value = rom_bar;
                self.write_config_u32(0x30, 0xFFFFFFFE); // ROM BARに書き込み（最下位ビットを0に）
                let size_mask = self.read_config_u32(0x30) & !0x1;
                self.write_config_u32(0x30, orig_value); // 元の値を復元
                
                if size_mask != 0 {
                    let rom_size = (!size_mask + 1) as usize;
                    let rom_addr = (rom_bar & !0x3FF) as usize;
                    
                    let resource = PciResource::new(
                        rom_addr,
                        rom_size,
                        PciResourceType::Memory32,
                        "ROM".to_string()
                    );
                    
                    resources.push(resource);
                }
            }
        }
        
        // リソースを格納
        *self.resources.lock() = resources;
    }
    
    /// BARのサイズを取得
    fn get_bar_size(&self, bar_idx: usize) -> usize {
        let bar_offset = 0x10 + (bar_idx * 4) as u16;
        let orig_value = self.read_config_u32(bar_offset);
        
        if orig_value == 0 {
            return 0; // BARが未使用
        }
        
        // BARの種類を判定
        let is_io = (orig_value & 0x1) == 0x1;
        
        // アドレスマスクを保存
        let addr_mask = if is_io {
            !0x3 // I/O BAR
        } else {
            !0xF // メモリBAR
        };
        
        // BARにすべて1を書き込み
        self.write_config_u32(bar_offset, 0xFFFFFFFF);
        
        // サイズを読み取り
        let size_mask = self.read_config_u32(bar_offset) & addr_mask;
        
        // 元の値を復元
        self.write_config_u32(bar_offset, orig_value);
        
        // サイズを計算
        if size_mask == 0 {
            0
        } else {
            (!size_mask + 1) as usize
        }
    }
    
    /// デバイスをイネーブルする
    pub fn enable(&self) -> Result<(), &'static str> {
        // 現在のコマンドレジスタを読み取り
        let mut cmd = self.read_config_u16(0x04);
        
        // I/O空間アクセスとメモリ空間アクセスを有効化
        cmd |= 0x3;
        
        // 新しいコマンドを書き込み
        self.write_config_u16(0x04, cmd);
        
        // 成功を記録
        self.enabled.store(true, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// デバイスを無効化する
    pub fn disable(&self) -> Result<(), &'static str> {
        // 現在のコマンドレジスタを読み取り
        let mut cmd = self.read_config_u16(0x04);
        
        // I/O空間アクセスとメモリ空間アクセスを無効化
        cmd &= !0x3;
        
        // 新しいコマンドを書き込み
        self.write_config_u16(0x04, cmd);
        
        // 成功を記録
        self.enabled.store(false, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// バスマスタリングを有効化する
    pub fn enable_bus_master(&self) -> Result<(), &'static str> {
        // 現在のコマンドレジスタを読み取り
        let mut cmd = self.read_config_u16(0x04);
        
        // バスマスタリングを有効化
        cmd |= 0x4;
        
        // 新しいコマンドを書き込み
        self.write_config_u16(0x04, cmd);
        
        // 成功を記録
        self.bus_master.store(true, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// バスマスタリングを無効化する
    pub fn disable_bus_master(&self) -> Result<(), &'static str> {
        // 現在のコマンドレジスタを読み取り
        let mut cmd = self.read_config_u16(0x04);
        
        // バスマスタリングを無効化
        cmd &= !0x4;
        
        // 新しいコマンドを書き込み
        self.write_config_u16(0x04, cmd);
        
        // 成功を記録
        self.bus_master.store(false, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// 割り込みを有効化する
    pub fn enable_interrupt(&self) -> Result<(), &'static str> {
        // 現在のコマンドレジスタを読み取り
        let mut cmd = self.read_config_u16(0x04);
        
        // 割り込み無効フラグをクリア
        cmd &= !0x400;
        
        // 新しいコマンドを書き込み
        self.write_config_u16(0x04, cmd);
        
        // 成功を記録
        self.int_disabled.store(false, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// 割り込みを無効化する
    pub fn disable_interrupt(&self) -> Result<(), &'static str> {
        // 現在のコマンドレジスタを読み取り
        let mut cmd = self.read_config_u16(0x04);
        
        // 割り込み無効フラグを設定
        cmd |= 0x400;
        
        // 新しいコマンドを書き込み
        self.write_config_u16(0x04, cmd);
        
        // 成功を記録
        self.int_disabled.store(true, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// PCIアドレスを取得
    pub fn address(&self) -> PciAddress {
        self.info.address
    }
    
    /// ベンダーIDを取得
    pub fn vendor_id(&self) -> PciVendorId {
        self.info.vendor_id
    }
    
    /// デバイスIDを取得
    pub fn device_id(&self) -> PciDeviceId {
        self.info.device_id
    }
    
    /// クラスコードを取得
    pub fn class_code(&self) -> PciClassCode {
        self.info.class_code
    }
    
    /// サブクラスコードを取得
    pub fn subclass_code(&self) -> PciSubclassCode {
        self.info.subclass_code
    }
    
    /// プログラミングインタフェースを取得
    pub fn prog_if(&self) -> PciProgIf {
        self.info.prog_if
    }
    
    /// リビジョンIDを取得
    pub fn revision_id(&self) -> PciRevisionId {
        self.info.revision_id
    }
    
    /// ヘッダタイプを取得
    pub fn header_type(&self) -> u8 {
        self.info.header_type
    }
    
    /// サブシステムベンダーIDを取得
    pub fn subsystem_vendor_id(&self) -> PciVendorId {
        self.info.subsystem_vendor_id
    }
    
    /// サブシステムIDを取得
    pub fn subsystem_id(&self) -> PciDeviceId {
        self.info.subsystem_id
    }
    
    /// 割り込みラインを取得
    pub fn interrupt_line(&self) -> u8 {
        self.info.interrupt_line
    }
    
    /// 割り込みピンを取得
    pub fn interrupt_pin(&self) -> u8 {
        self.info.interrupt_pin
    }
    
    /// デバイスクラスを取得
    pub fn class(&self) -> PciClass {
        PciClass::from(self.info.class_code)
    }
    
    /// デバイスサブクラスを取得
    pub fn subclass(&self) -> PciSubclass {
        PciSubclass::from_codes(self.info.class_code, self.info.subclass_code)
    }
    
    /// デバイスがマルチファンクションであるかを確認
    pub fn is_multifunction(&self) -> bool {
        (self.info.header_type & 0x80) != 0
    }
    
    /// デバイスリソースを取得
    pub fn get_resources(&self) -> Vec<PciResource> {
        self.resources.lock().clone()
    }
    
    /// デバイスケイパビリティを取得
    pub fn get_capabilities(&self) -> Vec<PciCapability> {
        self.capabilities.lock().clone()
    }
    
    /// 指定されたタイプのケイパビリティを検索
    pub fn find_capability(&self, id: PciCapabilityId) -> Option<PciCapability> {
        self.capabilities.lock().iter()
            .find(|cap| cap.id() == id)
            .cloned()
    }
    
    /// デバイスがイネーブルされているかを確認
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
    
    /// デバイスがバスマスタリングを許可されているかを確認
    pub fn is_bus_master_enabled(&self) -> bool {
        self.bus_master.load(Ordering::Relaxed)
    }
    
    /// 割り込みが無効化されているかを確認
    pub fn is_interrupt_disabled(&self) -> bool {
        self.int_disabled.load(Ordering::Relaxed)
    }
    
    /// ドライバがアタッチされているかを確認
    pub fn is_driver_attached(&self) -> bool {
        self.driver_attached.load(Ordering::Relaxed)
    }
    
    /// ドライバのアタッチ状態を設定
    pub fn set_driver_attached(&self, attached: bool) {
        self.driver_attached.store(attached, Ordering::Relaxed);
    }
    
    /// BARに関する情報を取得
    pub fn get_bar_info(&self, bar_idx: usize) -> Option<PciBarInfo> {
        if bar_idx >= 6 {
            return None;
        }
        self.bar_info[bar_idx].clone()
    }
    
    /// デバイス名を取得
    pub fn get_name(&self) -> String {
        // ベンダー名とデバイス名を取得
        let vendor_name = get_vendor_name(self.info.vendor_id)
            .unwrap_or_else(|| format!("Unknown vendor {:04x}", self.info.vendor_id));
            
        let device_name = get_device_name(self.info.vendor_id, self.info.device_id)
            .unwrap_or_else(|| format!("Unknown device {:04x}", self.info.device_id));
            
        format!("{} {}", vendor_name, device_name)
    }
    
    /// クラス名を取得
    pub fn get_class_name(&self) -> String {
        // クラス名とサブクラス名を取得
        let class_name = get_class_name(self.info.class_code)
            .unwrap_or_else(|| format!("Unknown class {:02x}", self.info.class_code));
            
        let subclass_name = get_subclass_name(self.info.class_code, self.info.subclass_code)
            .unwrap_or_else(|| format!("Unknown subclass {:02x}", self.info.subclass_code));
            
        format!("{} [{}]", class_name, subclass_name)
    }
}

impl Clone for PciDevice {
    fn clone(&self) -> Self {
        // クローンはキャッシュやリソース管理に影響を与えるため、注意が必要
        // ここでは簡略化のために同じハードウェア操作を使用
        let mut clone = Self {
            info: self.info.clone(),
            enabled: AtomicBool::new(self.enabled.load(Ordering::Relaxed)),
            bus_master: AtomicBool::new(self.bus_master.load(Ordering::Relaxed)),
            int_disabled: AtomicBool::new(self.int_disabled.load(Ordering::Relaxed)),
            resources: SpinLock::new(self.resources.lock().clone()),
            capabilities: SpinLock::new(self.capabilities.lock().clone()),
            hw_ops: self.hw_ops,
            driver_attached: AtomicBool::new(self.driver_attached.load(Ordering::Relaxed)),
            bar_info: [None, None, None, None, None, None],
        };
        
        // BARの情報をコピー
        for i in 0..6 {
            clone.bar_info[i] = self.bar_info[i].clone();
        }
        
        clone
    }
}

impl fmt::Display for PciDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}:{}.{}] {} {}", 
            self.address(),
            format!("{:04x}", self.vendor_id()),
            format!("{:04x}", self.device_id()),
            format!("{:02x}", self.revision_id()),
            self.get_name(),
            self.get_class_name())
    }
}

impl fmt::Debug for PciDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PciDevice")
            .field("address", &self.info.address)
            .field("vendor_id", &format_args!("{:04x}", self.info.vendor_id))
            .field("device_id", &format_args!("{:04x}", self.info.device_id))
            .field("class_code", &format_args!("{:02x}", self.info.class_code))
            .field("subclass_code", &format_args!("{:02x}", self.info.subclass_code))
            .field("prog_if", &format_args!("{:02x}", self.info.prog_if))
            .field("revision_id", &format_args!("{:02x}", self.info.revision_id))
            .field("header_type", &format_args!("{:02x}", self.info.header_type))
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .field("bus_master", &self.bus_master.load(Ordering::Relaxed))
            .field("int_disabled", &self.int_disabled.load(Ordering::Relaxed))
            .field("driver_attached", &self.driver_attached.load(Ordering::Relaxed))
            .finish()
    }
} 