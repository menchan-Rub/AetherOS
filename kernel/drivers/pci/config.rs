// AetherOS PCIコンフィグレーション空間アクセス
//
// このモジュールはPCIデバイスのコンフィグレーション空間への読み書きアクセスを提供します。
// PIOとMMIOの両方のアクセス方法をサポートし、適切な方法を自動的に選択します。

use core::sync::atomic::{AtomicBool, Ordering};
use crate::arch::io::{inl, outl};
use crate::core::memory::page::PhysAddr;
use crate::core::memory::mmio::{MmioReader, MmioWriter};
use crate::core::log;

use super::address::PciAddress;
use super::firmware::PciFirmwareInfo;

/// PCIコンフィグレーションアクセスモード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciConfigAccessMode {
    /// レガシーPIOアクセス（0xCF8/0xCFC）
    LegacyPio,
    /// MMIOベースアクセス（MMCFG）
    Mmio,
}

/// PCIコンフィグレーションアクセスエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciConfigError {
    /// デバイスが存在しない
    DeviceNotExist,
    /// アクセスモードがサポートされていない
    UnsupportedAccessMode,
    /// アラインメントエラー
    AlignmentError,
    /// 無効なレジスタ
    InvalidRegister,
    /// 未知のエラー
    Unknown,
}

/// PCIコンフィグレーションアクセスの結果
pub type PciConfigResult<T> = Result<T, PciConfigError>;

/// PCIコンフィグレーションスペースオフセット
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciConfigOffset(pub u16);

impl PciConfigOffset {
    /// オフセットがレジスタ境界上にあるか検証
    pub fn is_aligned(&self, size: usize) -> bool {
        (self.0 as usize) & (size - 1) == 0
    }
    
    /// 有効なオフセットかどうかを検証（4KBを超えない）
    pub fn is_valid(&self) -> bool {
        self.0 < 4096
    }
}

/// 標準PCIコンフィグレーションレジスタのオフセット定数
pub mod offset {
    use super::PciConfigOffset;
    
    // PCI共通ヘッダフィールド (0-3Fh)
    pub const VENDOR_ID: PciConfigOffset = PciConfigOffset(0x00);
    pub const DEVICE_ID: PciConfigOffset = PciConfigOffset(0x02);
    pub const COMMAND: PciConfigOffset = PciConfigOffset(0x04);
    pub const STATUS: PciConfigOffset = PciConfigOffset(0x06);
    pub const REVISION_ID: PciConfigOffset = PciConfigOffset(0x08);
    pub const PROG_IF: PciConfigOffset = PciConfigOffset(0x09);
    pub const SUBCLASS: PciConfigOffset = PciConfigOffset(0x0A);
    pub const CLASS_CODE: PciConfigOffset = PciConfigOffset(0x0B);
    pub const CACHE_LINE_SIZE: PciConfigOffset = PciConfigOffset(0x0C);
    pub const LATENCY_TIMER: PciConfigOffset = PciConfigOffset(0x0D);
    pub const HEADER_TYPE: PciConfigOffset = PciConfigOffset(0x0E);
    pub const BIST: PciConfigOffset = PciConfigOffset(0x0F);

    // ヘッダータイプ0（一般デバイス）
    pub const BAR0: PciConfigOffset = PciConfigOffset(0x10);
    pub const BAR1: PciConfigOffset = PciConfigOffset(0x14);
    pub const BAR2: PciConfigOffset = PciConfigOffset(0x18);
    pub const BAR3: PciConfigOffset = PciConfigOffset(0x1C);
    pub const BAR4: PciConfigOffset = PciConfigOffset(0x20);
    pub const BAR5: PciConfigOffset = PciConfigOffset(0x24);
    pub const CARDBUS_CIS_PTR: PciConfigOffset = PciConfigOffset(0x28);
    pub const SUBSYSTEM_VENDOR_ID: PciConfigOffset = PciConfigOffset(0x2C);
    pub const SUBSYSTEM_ID: PciConfigOffset = PciConfigOffset(0x2E);
    pub const EXPANSION_ROM_BASE: PciConfigOffset = PciConfigOffset(0x30);
    pub const CAPABILITIES_PTR: PciConfigOffset = PciConfigOffset(0x34);
    pub const INTERRUPT_LINE: PciConfigOffset = PciConfigOffset(0x3C);
    pub const INTERRUPT_PIN: PciConfigOffset = PciConfigOffset(0x3D);
    pub const MIN_GNT: PciConfigOffset = PciConfigOffset(0x3E);
    pub const MAX_LAT: PciConfigOffset = PciConfigOffset(0x3F);

    // ヘッダータイプ1（PCIブリッジ）
    pub const PRIMARY_BUS: PciConfigOffset = PciConfigOffset(0x18);
    pub const SECONDARY_BUS: PciConfigOffset = PciConfigOffset(0x19);
    pub const SUBORDINATE_BUS: PciConfigOffset = PciConfigOffset(0x1A);
    pub const SECONDARY_LATENCY: PciConfigOffset = PciConfigOffset(0x1B);
    pub const IO_BASE: PciConfigOffset = PciConfigOffset(0x1C);
    pub const IO_LIMIT: PciConfigOffset = PciConfigOffset(0x1D);
    pub const SECONDARY_STATUS: PciConfigOffset = PciConfigOffset(0x1E);
    pub const MEMORY_BASE: PciConfigOffset = PciConfigOffset(0x20);
    pub const MEMORY_LIMIT: PciConfigOffset = PciConfigOffset(0x22);
    pub const PREFETCHABLE_MEMORY_BASE: PciConfigOffset = PciConfigOffset(0x24);
    pub const PREFETCHABLE_MEMORY_LIMIT: PciConfigOffset = PciConfigOffset(0x26);
    pub const PREFETCHABLE_BASE_UPPER: PciConfigOffset = PciConfigOffset(0x28);
    pub const PREFETCHABLE_LIMIT_UPPER: PciConfigOffset = PciConfigOffset(0x2C);
    pub const IO_BASE_UPPER: PciConfigOffset = PciConfigOffset(0x30);
    pub const IO_LIMIT_UPPER: PciConfigOffset = PciConfigOffset(0x32);
    pub const BRIDGE_EXPANSION_ROM_BASE: PciConfigOffset = PciConfigOffset(0x38);
    pub const BRIDGE_CONTROL: PciConfigOffset = PciConfigOffset(0x3E);
}

/// PCIコマンドレジスタのビットフラグ
pub mod command {
    pub const IO_SPACE: u16 = 0x0001;             // I/Oアクセス有効
    pub const MEMORY_SPACE: u16 = 0x0002;         // メモリアクセス有効
    pub const BUS_MASTER: u16 = 0x0004;           // バスマスター有効
    pub const SPECIAL_CYCLES: u16 = 0x0008;       // 特殊サイクル有効
    pub const MEMORY_WRITE_INVALIDATE: u16 = 0x0010; // メモリ書き込み無効化有効
    pub const VGA_PALETTE_SNOOP: u16 = 0x0020;    // VGAパレットスヌープ有効
    pub const PARITY_ERROR_RESPONSE: u16 = 0x0040; // パリティエラー応答有効
    pub const SERR_ENABLE: u16 = 0x0100;          // SERRエラー有効
    pub const FAST_BACK_TO_BACK: u16 = 0x0200;    // 高速バックトゥバック有効
    pub const INTERRUPT_DISABLE: u16 = 0x0400;    // 割り込み無効
}

/// PCIステータスレジスタのビットフラグ
pub mod status {
    pub const INTERRUPT_STATUS: u16 = 0x0008;     // 割り込みステータス
    pub const CAPABILITIES_LIST: u16 = 0x0010;    // ケイパビリティリスト
    pub const MHZ_66_CAPABLE: u16 = 0x0020;       // 66MHz対応
    pub const FAST_BACK_TO_BACK: u16 = 0x0080;    // 高速バックトゥバック
    pub const MASTER_DATA_PARITY_ERROR: u16 = 0x0100; // マスターデータパリティエラー
    pub const DEVSEL_TIMING_MASK: u16 = 0x0600;   // DEVSELタイミングマスク
    pub const SIGNALED_TARGET_ABORT: u16 = 0x0800; // シグナルターゲットアボート
    pub const RECEIVED_TARGET_ABORT: u16 = 0x1000; // 受信ターゲットアボート
    pub const RECEIVED_MASTER_ABORT: u16 = 0x2000; // 受信マスターアボート
    pub const SIGNALED_SYSTEM_ERROR: u16 = 0x4000; // シグナルシステムエラー
    pub const DETECTED_PARITY_ERROR: u16 = 0x8000; // パリティエラー検出
}

/// PCIコンフィグレーションアクセサ
pub struct PciConfigAccess {
    /// 現在選択されているアクセスモード
    mode: PciConfigAccessMode,
    /// MMIOアクセスが利用可能かどうか
    mmio_available: AtomicBool,
    /// ファームウェア情報への参照
    firmware_info: Option<&'static PciFirmwareInfo>,
}

impl PciConfigAccess {
    /// PCIコンフィグレーションアクセサを作成
    pub fn new() -> Self {
        Self {
            mode: PciConfigAccessMode::LegacyPio,
            mmio_available: AtomicBool::new(false),
            firmware_info: None,
        }
    }
    
    /// 利用可能なアクセスモードを設定
    pub fn set_available_modes(&mut self, firmware_info: &'static PciFirmwareInfo) {
        self.firmware_info = Some(firmware_info);
        
        if firmware_info.has_mmcfg() {
            self.mmio_available.store(true, Ordering::SeqCst);
            self.mode = PciConfigAccessMode::Mmio;
            log::info!("PCIコンフィグレーションアクセス: MMIOモードを使用");
        } else {
            log::info!("PCIコンフィグレーションアクセス: レガシーPIOモードを使用");
        }
    }
    
    /// アクセスモードを設定
    pub fn set_access_mode(&mut self, mode: PciConfigAccessMode) -> PciConfigResult<()> {
        match mode {
            PciConfigAccessMode::Mmio => {
                if !self.mmio_available.load(Ordering::SeqCst) {
                    return Err(PciConfigError::UnsupportedAccessMode);
                }
            }
            PciConfigAccessMode::LegacyPio => {
                // PIOモードは常にサポート
            }
        }
        
        self.mode = mode;
        Ok(())
    }
    
    /// 現在のアクセスモードを取得
    pub fn access_mode(&self) -> PciConfigAccessMode {
        self.mode
    }
    
    /// アドレスをPCIコンフィグレーションアドレスに変換（PIOモード用）
    fn address_to_pio_config(&self, address: &PciAddress, offset: PciConfigOffset) -> u32 {
        let mut config_address: u32 = 0x80000000; // Enable bit
        
        // PCIアドレスのコンポーネントを配置
        config_address |= (address.bus as u32) << 16;
        config_address |= (address.device as u32) << 11;
        config_address |= (address.function as u32) << 8;
        config_address |= (offset.0 as u32) & 0xFC; // 下位2ビットは常に0
        
        config_address
    }
    
    /// PCIコンフィグレーション空間からu8を読み込み
    pub fn read_u8(&self, address: &PciAddress, offset: PciConfigOffset) -> PciConfigResult<u8> {
        if !offset.is_valid() {
            return Err(PciConfigError::InvalidRegister);
        }
        
        let byte_offset = offset.0 & 0x3;
        let aligned_offset = PciConfigOffset(offset.0 & !0x3);
        
        // 32ビット値を読み込んで、必要なバイトを抽出
        let value = self.read_u32(address, aligned_offset)?;
        let shift = (byte_offset as u32) * 8;
        let byte_value = ((value >> shift) & 0xFF) as u8;
        
        Ok(byte_value)
    }
    
    /// PCIコンフィグレーション空間からu16を読み込み
    pub fn read_u16(&self, address: &PciAddress, offset: PciConfigOffset) -> PciConfigResult<u16> {
        if !offset.is_valid() {
            return Err(PciConfigError::InvalidRegister);
        }
        
        if !offset.is_aligned(2) {
            return Err(PciConfigError::AlignmentError);
        }
        
        let word_offset = (offset.0 & 0x2) >> 1;
        let aligned_offset = PciConfigOffset(offset.0 & !0x3);
        
        // 32ビット値を読み込んで、必要なワードを抽出
        let value = self.read_u32(address, aligned_offset)?;
        let shift = (word_offset as u32) * 16;
        let word_value = ((value >> shift) & 0xFFFF) as u16;
        
        Ok(word_value)
    }
    
    /// PCIコンフィグレーション空間からu32を読み込み
    pub fn read_u32(&self, address: &PciAddress, offset: PciConfigOffset) -> PciConfigResult<u32> {
        if !offset.is_valid() {
            return Err(PciConfigError::InvalidRegister);
        }
        
        if !offset.is_aligned(4) {
            return Err(PciConfigError::AlignmentError);
        }
        
        match self.mode {
            PciConfigAccessMode::LegacyPio => {
                // PIOモードでは、セグメントが0の場合のみサポート
                if address.segment != 0 {
                    return Err(PciConfigError::UnsupportedAccessMode);
                }
                
                // PIOアドレスを生成
                let config_address = self.address_to_pio_config(address, offset);
                
                // PIOポートを通じて読み込み
                unsafe {
                    outl(0xCF8, config_address);
                    let value = inl(0xCFC);
                    
                    // 無効なデバイスの場合、すべてのビットが1に設定される
                    if value == 0xFFFFFFFF && offset.0 == 0 {
                        return Err(PciConfigError::DeviceNotExist);
                    }
                    
                    Ok(value)
                }
            }
            PciConfigAccessMode::Mmio => {
                // ファームウェア情報が必要
                let firmware_info = match self.firmware_info {
                    Some(info) => info,
                    None => return Err(PciConfigError::UnsupportedAccessMode),
                };
                
                // MMCFG物理アドレスを計算
                let phys_addr = match firmware_info.calculate_mmcfg_address(address) {
                    Some(addr) => addr,
                    None => return Err(PciConfigError::UnsupportedAccessMode),
                };
                
                // オフセットを加算
                let final_addr = phys_addr.as_u64() + offset.0 as u64;
                
                // MMIOリーダーを使用して読み込み
                let reader = MmioReader::new(final_addr);
                let value = reader.read_u32();
                
                // 無効なデバイスの場合、すべてのビットが1に設定される
                if value == 0xFFFFFFFF && offset.0 == 0 {
                    return Err(PciConfigError::DeviceNotExist);
                }
                
                Ok(value)
            }
        }
    }
    
    /// PCIコンフィグレーション空間にu8を書き込み
    pub fn write_u8(&self, address: &PciAddress, offset: PciConfigOffset, value: u8) -> PciConfigResult<()> {
        if !offset.is_valid() {
            return Err(PciConfigError::InvalidRegister);
        }
        
        let byte_offset = offset.0 & 0x3;
        let aligned_offset = PciConfigOffset(offset.0 & !0x3);
        
        // 32ビット値を読み込み、特定のバイトを修正して書き戻す
        let mut dword = self.read_u32(address, aligned_offset)?;
        
        let shift = (byte_offset as u32) * 8;
        let mask = !(0xFF << shift);
        
        dword = (dword & mask) | ((value as u32) << shift);
        
        self.write_u32(address, aligned_offset, dword)
    }
    
    /// PCIコンフィグレーション空間にu16を書き込み
    pub fn write_u16(&self, address: &PciAddress, offset: PciConfigOffset, value: u16) -> PciConfigResult<()> {
        if !offset.is_valid() {
            return Err(PciConfigError::InvalidRegister);
        }
        
        if !offset.is_aligned(2) {
            return Err(PciConfigError::AlignmentError);
        }
        
        let word_offset = (offset.0 & 0x2) >> 1;
        let aligned_offset = PciConfigOffset(offset.0 & !0x3);
        
        // 32ビット値を読み込み、特定のワードを修正して書き戻す
        let mut dword = self.read_u32(address, aligned_offset)?;
        
        let shift = (word_offset as u32) * 16;
        let mask = !(0xFFFF << shift);
        
        dword = (dword & mask) | ((value as u32) << shift);
        
        self.write_u32(address, aligned_offset, dword)
    }
    
    /// PCIコンフィグレーション空間にu32を書き込み
    pub fn write_u32(&self, address: &PciAddress, offset: PciConfigOffset, value: u32) -> PciConfigResult<()> {
        if !offset.is_valid() {
            return Err(PciConfigError::InvalidRegister);
        }
        
        if !offset.is_aligned(4) {
            return Err(PciConfigError::AlignmentError);
        }
        
        match self.mode {
            PciConfigAccessMode::LegacyPio => {
                // PIOモードでは、セグメントが0の場合のみサポート
                if address.segment != 0 {
                    return Err(PciConfigError::UnsupportedAccessMode);
                }
                
                // PIOアドレスを生成
                let config_address = self.address_to_pio_config(address, offset);
                
                // PIOポートを通じて書き込み
                unsafe {
                    outl(0xCF8, config_address);
                    outl(0xCFC, value);
                    Ok(())
                }
            }
            PciConfigAccessMode::Mmio => {
                // ファームウェア情報が必要
                let firmware_info = match self.firmware_info {
                    Some(info) => info,
                    None => return Err(PciConfigError::UnsupportedAccessMode),
                };
                
                // MMCFG物理アドレスを計算
                let phys_addr = match firmware_info.calculate_mmcfg_address(address) {
                    Some(addr) => addr,
                    None => return Err(PciConfigError::UnsupportedAccessMode),
                };
                
                // オフセットを加算
                let final_addr = phys_addr.as_u64() + offset.0 as u64;
                
                // MMIOライターを使用して書き込み
                let writer = MmioWriter::new(final_addr);
                writer.write_u32(value);
                
                Ok(())
            }
        }
    }
    
    /// デバイスID情報を読み込み
    pub fn read_device_id(&self, address: &PciAddress) -> PciConfigResult<(u16, u16)> {
        // ベンダーIDとデバイスIDを読み込み
        let vendor_id = self.read_u16(address, offset::VENDOR_ID)?;
        let device_id = self.read_u16(address, offset::DEVICE_ID)?;
        
        Ok((vendor_id, device_id))
    }
    
    /// クラスコードを読み込み
    pub fn read_class_code(&self, address: &PciAddress) -> PciConfigResult<(u8, u8, u8)> {
        // クラス、サブクラス、プログラミングインターフェイスを読み込み
        let class_code = self.read_u8(address, offset::CLASS_CODE)?;
        let subclass = self.read_u8(address, offset::SUBCLASS)?;
        let prog_if = self.read_u8(address, offset::PROG_IF)?;
        
        Ok((class_code, subclass, prog_if))
    }
    
    /// ヘッダータイプを読み込み
    pub fn read_header_type(&self, address: &PciAddress) -> PciConfigResult<u8> {
        self.read_u8(address, offset::HEADER_TYPE)
    }
    
    /// デバイスのコマンドレジスタを読み込み
    pub fn read_command(&self, address: &PciAddress) -> PciConfigResult<u16> {
        self.read_u16(address, offset::COMMAND)
    }
    
    /// デバイスのコマンドレジスタに書き込み
    pub fn write_command(&self, address: &PciAddress, value: u16) -> PciConfigResult<()> {
        self.write_u16(address, offset::COMMAND, value)
    }
    
    /// デバイスのステータスレジスタを読み込み
    pub fn read_status(&self, address: &PciAddress) -> PciConfigResult<u16> {
        self.read_u16(address, offset::STATUS)
    }
    
    /// デバイスのベースアドレスレジスタ（BAR）を読み込み
    pub fn read_bar(&self, address: &PciAddress, bar_index: usize) -> PciConfigResult<u32> {
        if bar_index > 5 {
            return Err(PciConfigError::InvalidRegister);
        }
        
        let bar_offset = match bar_index {
            0 => offset::BAR0,
            1 => offset::BAR1,
            2 => offset::BAR2,
            3 => offset::BAR3,
            4 => offset::BAR4,
            5 => offset::BAR5,
            _ => unreachable!(),
        };
        
        self.read_u32(address, bar_offset)
    }
    
    /// デバイスのベースアドレスレジスタ（BAR）に書き込み
    pub fn write_bar(&self, address: &PciAddress, bar_index: usize, value: u32) -> PciConfigResult<()> {
        if bar_index > 5 {
            return Err(PciConfigError::InvalidRegister);
        }
        
        let bar_offset = match bar_index {
            0 => offset::BAR0,
            1 => offset::BAR1,
            2 => offset::BAR2,
            3 => offset::BAR3,
            4 => offset::BAR4,
            5 => offset::BAR5,
            _ => unreachable!(),
        };
        
        self.write_u32(address, bar_offset, value)
    }
    
    /// PCIブリッジのバス番号を読み込み
    pub fn read_bridge_buses(&self, address: &PciAddress) -> PciConfigResult<(u8, u8, u8)> {
        let primary = self.read_u8(address, offset::PRIMARY_BUS)?;
        let secondary = self.read_u8(address, offset::SECONDARY_BUS)?;
        let subordinate = self.read_u8(address, offset::SUBORDINATE_BUS)?;
        
        Ok((primary, secondary, subordinate))
    }
    
    /// PCIブリッジのバス番号を設定
    pub fn write_bridge_buses(&self, address: &PciAddress, primary: u8, secondary: u8, subordinate: u8) -> PciConfigResult<()> {
        self.write_u8(address, offset::PRIMARY_BUS, primary)?;
        self.write_u8(address, offset::SECONDARY_BUS, secondary)?;
        self.write_u8(address, offset::SUBORDINATE_BUS, subordinate)
    }
    
    /// 割り込み情報を読み込み
    pub fn read_interrupt_info(&self, address: &PciAddress) -> PciConfigResult<(u8, u8)> {
        let line = self.read_u8(address, offset::INTERRUPT_LINE)?;
        let pin = self.read_u8(address, offset::INTERRUPT_PIN)?;
        
        Ok((line, pin))
    }
    
    /// 割り込みラインを設定
    pub fn write_interrupt_line(&self, address: &PciAddress, line: u8) -> PciConfigResult<()> {
        self.write_u8(address, offset::INTERRUPT_LINE, line)
    }
    
    /// ケイパビリティポインタを読み込み
    pub fn read_capabilities_ptr(&self, address: &PciAddress) -> PciConfigResult<u8> {
        let status = self.read_status(address)?;
        
        // ケイパビリティリストが存在するかチェック
        if status & status::CAPABILITIES_LIST == 0 {
            return Ok(0); // ケイパビリティリストなし
        }
        
        self.read_u8(address, offset::CAPABILITIES_PTR)
    }
}

/// デバイスがマルチファンクションかどうかをチェック
pub fn is_multifunction_device(header_type: u8) -> bool {
    (header_type & 0x80) != 0
}

/// ヘッダータイプを取得（マルチファンクションビットを除去）
pub fn get_header_type(header_type: u8) -> u8 {
    header_type & 0x7F
}

/// PCIコンフィグレーションアクセス用のシングルトンインスタンスを取得
static mut PCI_CONFIG_ACCESS: Option<PciConfigAccess> = None;

/// PCIコンフィグレーションアクセスモジュールを初期化
pub fn init_pci_config(firmware_info: &'static PciFirmwareInfo) {
    unsafe {
        let mut access = PciConfigAccess::new();
        access.set_available_modes(firmware_info);
        PCI_CONFIG_ACCESS = Some(access);
    }
}

/// グローバルPCIコンフィグレーションアクセスインスタンスを取得
pub fn global_pci_config() -> &'static mut PciConfigAccess {
    unsafe {
        match &mut PCI_CONFIG_ACCESS {
            Some(access) => access,
            None => panic!("PCIコンフィグレーションアクセスが初期化されていません"),
        }
    }
} 