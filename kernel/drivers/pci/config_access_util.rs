// PCIコンフィギュレーション空間アクセスユーティリティ
//
// PCIコンフィギュレーション空間からの情報読み取りや設定を簡単にするユーティリティ機能を提供します。

use super::address::PciAddress;
use super::config_access::PciConfigAccess;
use super::device_trait::{PciCapability, PciCapabilityId, PciDeviceInfo};
use alloc::vec::Vec;
use log::{debug, warn};
use crate::core::memory::mmio::{MemoryMappedIo, MmioAccess};
use crate::drivers::pci::config::PciConfigSpace;
use crate::drivers::pci::ecam::EcamAccess;
use crate::drivers::pci::port_io::PortIoAccess;
use crate::sync::mutex::Mutex;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

/// PCIコンフィギュレーション空間のレジスタオフセット定義
pub mod offsets {
    // 共通ヘッダ（すべてのPCIデバイス）
    pub const VENDOR_ID: u8 = 0x00;       // 2バイト: ベンダーID
    pub const DEVICE_ID: u8 = 0x02;       // 2バイト: デバイスID
    pub const COMMAND: u8 = 0x04;         // 2バイト: コマンドレジスタ
    pub const STATUS: u8 = 0x06;          // 2バイト: ステータスレジスタ
    pub const REVISION_ID: u8 = 0x08;     // 1バイト: リビジョンID
    pub const PROG_IF: u8 = 0x09;         // 1バイト: プログラミングインターフェース
    pub const SUBCLASS: u8 = 0x0A;        // 1バイト: サブクラスコード
    pub const CLASS_CODE: u8 = 0x0B;      // 1バイト: クラスコード
    pub const CACHE_LINE_SIZE: u8 = 0x0C; // 1バイト: キャッシュラインサイズ
    pub const LATENCY_TIMER: u8 = 0x0D;   // 1バイト: レイテンシタイマー
    pub const HEADER_TYPE: u8 = 0x0E;     // 1バイト: ヘッダタイプ
    pub const BIST: u8 = 0x0F;            // 1バイト: BIST（Built-In Self Test）
    
    // タイプ0ヘッダ（一般デバイス）
    pub const BAR0: u8 = 0x10;            // 4バイト: ベースアドレスレジスタ0
    pub const BAR1: u8 = 0x14;            // 4バイト: ベースアドレスレジスタ1
    pub const BAR2: u8 = 0x18;            // 4バイト: ベースアドレスレジスタ2
    pub const BAR3: u8 = 0x1C;            // 4バイト: ベースアドレスレジスタ3
    pub const BAR4: u8 = 0x20;            // 4バイト: ベースアドレスレジスタ4
    pub const BAR5: u8 = 0x24;            // 4バイト: ベースアドレスレジスタ5
    pub const CARDBUS_CIS_PTR: u8 = 0x28; // 4バイト: CardBus CISポインタ
    pub const SUBSYS_VENDOR_ID: u8 = 0x2C;// 2バイト: サブシステムベンダーID
    pub const SUBSYS_ID: u8 = 0x2E;       // 2バイト: サブシステムID
    pub const EXP_ROM_BASE: u8 = 0x30;    // 4バイト: 拡張ROMベースアドレス
    pub const CAP_PTR: u8 = 0x34;         // 1バイト: ケイパビリティポインタ
    pub const INT_LINE: u8 = 0x3C;        // 1バイト: 割り込みライン
    pub const INT_PIN: u8 = 0x3D;         // 1バイト: 割り込みピン
    pub const MIN_GNT: u8 = 0x3E;         // 1バイト: 最小許可
    pub const MAX_LAT: u8 = 0x3F;         // 1バイト: 最大レイテンシ
}

/// PCIコマンドレジスタビットフラグ
pub mod cmd_bits {
    pub const IO_SPACE: u16 = 0x0001;         // I/O空間イネーブル
    pub const MEMORY_SPACE: u16 = 0x0002;     // メモリ空間イネーブル
    pub const BUS_MASTER: u16 = 0x0004;       // バスマスターイネーブル
    pub const SPECIAL_CYCLES: u16 = 0x0008;   // 特殊サイクルイネーブル
    pub const MEM_WRITE_INVALIDATE: u16 = 0x0010; // メモリ書き込み・無効化イネーブル
    pub const VGA_PALETTE_SNOOP: u16 = 0x0020; // VGAパレットスヌープイネーブル
    pub const PARITY_ERROR_RESP: u16 = 0x0040; // パリティエラー応答
    pub const SERR_ENABLE: u16 = 0x0100;      // SERRイネーブル
    pub const FAST_BACK_TO_BACK: u16 = 0x0200; // 高速バック・ツー・バックイネーブル
    pub const INTERRUPT_DISABLE: u16 = 0x0400; // 割り込み無効
}

/// PCIステータスレジスタビットフラグ
pub mod status_bits {
    pub const INTERRUPT_STATUS: u16 = 0x0008;  // 割り込みステータス
    pub const CAPABILITIES: u16 = 0x0010;      // ケイパビリティリストサポート
    pub const MHZ_66_CAPABLE: u16 = 0x0020;    // 66MHz対応
    pub const FAST_BACK_TO_BACK: u16 = 0x0080; // 高速バック・ツー・バック対応
    pub const MASTER_DATA_PARITY: u16 = 0x0100;// マスターデータパリティエラー
    pub const DEVSEL_TIMING: u16 = 0x0600;     // DEVSELタイミング
    pub const SIG_TARGET_ABORT: u16 = 0x0800;  // シグナルドターゲットアボート
    pub const RCV_TARGET_ABORT: u16 = 0x1000;  // 受信ターゲットアボート
    pub const RCV_MASTER_ABORT: u16 = 0x2000;  // 受信マスターアボート
    pub const SIG_SYSTEM_ERROR: u16 = 0x4000;  // シグナルドシステムエラー
    pub const DETECTED_PARITY: u16 = 0x8000;   // パリティエラー検出
}

/// PCIデバイス情報を読み取るユーティリティ
pub struct PciConfigReader<'a> {
    /// コンフィギュレーション空間アクセサ
    config_access: &'a dyn PciConfigAccess,
}

impl<'a> PciConfigReader<'a> {
    /// 新しいリーダーを作成
    pub fn new(config_access: &'a dyn PciConfigAccess) -> Self {
        Self { config_access }
    }
    
    /// PCI設定空間からデバイス情報を読み取る
    pub fn read_device_info(&self, address: &PciAddress) -> Option<PciDeviceInfo> {
        // 最初にベンダーIDを確認して、デバイスが存在するかチェック
        let vendor_id = self.config_access.read_config_word(address, offsets::VENDOR_ID);
        if vendor_id == 0xFFFF {
            return None; // デバイスが存在しない
        }
        
        // 基本情報の読み取り
        let device_id = self.config_access.read_config_word(address, offsets::DEVICE_ID);
        let revision_id = self.config_access.read_config_byte(address, offsets::REVISION_ID);
        let prog_if = self.config_access.read_config_byte(address, offsets::PROG_IF);
        let subclass = self.config_access.read_config_byte(address, offsets::SUBCLASS);
        let class_code = self.config_access.read_config_byte(address, offsets::CLASS_CODE);
        let header_type = self.config_access.read_config_byte(address, offsets::HEADER_TYPE);
        
        // 割り込み情報の読み取り
        let int_line = self.config_access.read_config_byte(address, offsets::INT_LINE);
        let int_pin = self.config_access.read_config_byte(address, offsets::INT_PIN);
        
        // サブシステム情報の読み取り（ヘッダタイプ0のみ）
        let (subsystem_vendor_id, subsystem_id) = if (header_type & 0x7F) == 0 {
            (
                self.config_access.read_config_word(address, offsets::SUBSYS_VENDOR_ID),
                self.config_access.read_config_word(address, offsets::SUBSYS_ID),
            )
        } else {
            (0, 0)
        };
        
        // デバイス情報の構築
        let info = PciDeviceInfo {
            address: address.clone(),
            vendor_id,
            device_id,
            class_code,
            subclass_code: subclass,
            prog_if,
            revision_id,
            header_type,
            subsystem_vendor_id,
            subsystem_id,
            interrupt_line: int_line,
            interrupt_pin: int_pin,
        };
        
        Some(info)
    }
    
    /// すべてのケイパビリティをスキャン
    pub fn scan_capabilities(&self, address: &PciAddress, header_type: u8) -> Vec<PciCapability> {
        let mut capabilities = Vec::new();
        
        // ステータスレジスタからケイパビリティリストの有無をチェック
        let status = self.config_access.read_config_word(address, offsets::STATUS);
        if (status & status_bits::CAPABILITIES) == 0 {
            return capabilities; // ケイパビリティリストなし
        }
        
        // ケイパビリティポインタの取得
        let cap_ptr = match header_type & 0x7F {
            0 => self.config_access.read_config_byte(address, offsets::CAP_PTR), // 標準デバイス
            1 => self.config_access.read_config_byte(address, offsets::CAP_PTR), // PCI-PCIブリッジ
            _ => 0, // 不明/サポート外のヘッダタイプ
        };
        
        if cap_ptr == 0 {
            return capabilities; // ケイパビリティポインタが無効
        }
        
        // ケイパビリティリストを走査
        let mut current_ptr = cap_ptr;
        let mut visited = [false; 256]; // ループ検出用
        
        while current_ptr != 0 && current_ptr != 0xFF {
            // ループ検出
            if visited[current_ptr as usize] {
                warn!("PCIケイパビリティリストでループを検出: {:?}, offset: {:#x}", address, current_ptr);
                break;
            }
            
            visited[current_ptr as usize] = true;
            
            // ケイパビリティの読み取り
            let cap_id = self.config_access.read_config_byte(address, current_ptr);
            let next_ptr = self.config_access.read_config_byte(address, current_ptr + 1);
            
            // ケイパビリティデータの読み取り（拡張可能）
            let mut data = Vec::new();
            
            // 一部のケイパビリティではバージョン情報を含む
            let version = match cap_id {
                0x05 => Some((self.config_access.read_config_byte(address, current_ptr + 2) & 0x70) >> 4), // MSI
                0x10 => Some(self.config_access.read_config_byte(address, current_ptr + 2) & 0x0F), // PCIe
                _ => None,
            };
            
            // 各ケイパビリティに応じて固有データを追加処理できる
            
            // ケイパビリティを追加
            let capability = PciCapability::new(cap_id, current_ptr, version, data);
            capabilities.push(capability);
            
            // 次のケイパビリティへ
            current_ptr = next_ptr;
        }
        
        capabilities
    }
    
    /// BARの情報を収集（サイズなど）
    pub fn get_bar_info(&self, address: &PciAddress, bar_idx: usize) -> Option<(u32, usize, bool, bool)> {
        if bar_idx > 5 {
            return None; // 無効なBARインデックス
        }
        
        let bar_offset = offsets::BAR0 + (bar_idx as u8 * 4);
        
        // 現在のBAR値を保存
        let orig_value = self.config_access.read_config_dword(address, bar_offset);
        if orig_value == 0 {
            return None; // BARが使用されていない
        }
        
        // I/Oスペースかメモリスペースかをチェック
        let is_io = (orig_value & 0x1) == 0x1;
        
        // 64ビットアドレスかどうかをチェック
        let is_64bit = !is_io && ((orig_value & 0x6) == 0x4);
        
        // BARの使用可能サイズを調査するために全ビットを1に設定
        self.config_access.write_config_dword(address, bar_offset, 0xFFFFFFFF);
        
        // 結果を読み取り
        let size_data = self.config_access.read_config_dword(address, bar_offset);
        
        // 元の値を復元
        self.config_access.write_config_dword(address, bar_offset, orig_value);
        
        // アドレスマスクを計算
        let addr_mask = if is_io { !0x3 } else { !0xF };
        
        // サイズを計算
        let size = if (size_data & addr_mask) == 0 {
            0
        } else {
            // サイズは"not(size_mask) + 1"
            let size_mask = size_data & addr_mask;
            (!(size_mask) + 1) as usize
        };
        
        // 64ビットBARの場合、上位32ビットも処理
        if is_64bit && bar_idx < 5 {
            // 上位32ビットの元の値を保存
            let upper_offset = bar_offset + 4;
            let upper_orig = self.config_access.read_config_dword(address, upper_offset);
            
            // 上位32ビットも1に設定
            self.config_access.write_config_dword(address, upper_offset, 0xFFFFFFFF);
            
            // 元の値を復元
            self.config_access.write_config_dword(address, upper_offset, upper_orig);
        }
        
        Some((orig_value, size, is_io, is_64bit))
    }
    
    /// デバイスのステータスを読み取り
    pub fn get_device_status(&self, address: &PciAddress) -> u16 {
        self.config_access.read_config_word(address, offsets::STATUS)
    }
    
    /// コマンドレジスタを読み取り
    pub fn get_command(&self, address: &PciAddress) -> u16 {
        self.config_access.read_config_word(address, offsets::COMMAND)
    }
    
    /// コマンドレジスタを設定
    pub fn set_command(&self, address: &PciAddress, command: u16) {
        self.config_access.write_config_word(address, offsets::COMMAND, command);
    }
    
    /// 特定のケイパビリティを探す
    pub fn find_capability(&self, address: &PciAddress, cap_id: PciCapabilityId) -> Option<PciCapability> {
        // ステータスレジスタからケイパビリティリストの有無をチェック
        let status = self.config_access.read_config_word(address, offsets::STATUS);
        if (status & status_bits::CAPABILITIES) == 0 {
            return None; // ケイパビリティリストなし
        }
        
        // ヘッダタイプの取得
        let header_type = self.config_access.read_config_byte(address, offsets::HEADER_TYPE);
        
        // ケイパビリティポインタの取得
        let cap_ptr = match header_type & 0x7F {
            0 => self.config_access.read_config_byte(address, offsets::CAP_PTR), // 標準デバイス
            1 => self.config_access.read_config_byte(address, offsets::CAP_PTR), // PCI-PCIブリッジ
            _ => 0, // 不明/サポート外のヘッダタイプ
        };
        
        if cap_ptr == 0 {
            return None; // ケイパビリティポインタが無効
        }
        
        // ケイパビリティリストを走査
        let mut current_ptr = cap_ptr;
        let mut visited = [false; 256]; // ループ検出用
        
        while current_ptr != 0 && current_ptr != 0xFF {
            // ループ検出
            if visited[current_ptr as usize] {
                warn!("PCIケイパビリティリストでループを検出: {:?}, offset: {:#x}", address, current_ptr);
                break;
            }
            
            visited[current_ptr as usize] = true;
            
            // ケイパビリティの読み取り
            let current_cap_id = self.config_access.read_config_byte(address, current_ptr);
            let next_ptr = self.config_access.read_config_byte(address, current_ptr + 1);
            
            // 目的のケイパビリティを見つけたら
            if current_cap_id == cap_id {
                // バージョン情報があれば取得
                let version = match cap_id {
                    0x05 => Some((self.config_access.read_config_byte(address, current_ptr + 2) & 0x70) >> 4), // MSI
                    0x10 => Some(self.config_access.read_config_byte(address, current_ptr + 2) & 0x0F), // PCIe
                    _ => None,
                };
                
                // ケイパビリティデータ（必要に応じて拡張）
                let data = Vec::new();
                
                return Some(PciCapability::new(cap_id, current_ptr, version, data));
            }
            
            // 次のケイパビリティへ
            current_ptr = next_ptr;
        }
        
        None
    }
}

/// PCIコンフィギュレーション空間へのアクセスを簡素化するユーティリティ
pub struct PciConfigUtil<'a> {
    config_access: &'a dyn PciConfigAccess,
}

impl<'a> PciConfigUtil<'a> {
    /// 新しいインスタンスを作成
    pub fn new(config_access: &'a dyn PciConfigAccess) -> Self {
        Self { config_access }
    }
    
    /// PCIデバイスを有効化（メモリアクセスとI/Oアクセスを有効化）
    pub fn enable_device(&self, address: &PciAddress) {
        let mut cmd = self.config_access.read_config_word(address, offsets::COMMAND);
        cmd |= cmd_bits::MEMORY_SPACE | cmd_bits::IO_SPACE;
        self.config_access.write_config_word(address, offsets::COMMAND, cmd);
        
        debug!("PCIデバイスを有効化しました: {:?}", address);
    }
    
    /// PCIデバイスを無効化
    pub fn disable_device(&self, address: &PciAddress) {
        let mut cmd = self.config_access.read_config_word(address, offsets::COMMAND);
        cmd &= !(cmd_bits::MEMORY_SPACE | cmd_bits::IO_SPACE);
        self.config_access.write_config_word(address, offsets::COMMAND, cmd);
        
        debug!("PCIデバイスを無効化しました: {:?}", address);
    }
    
    /// バスマスタリングを有効化
    pub fn enable_bus_master(&self, address: &PciAddress) {
        let mut cmd = self.config_access.read_config_word(address, offsets::COMMAND);
        cmd |= cmd_bits::BUS_MASTER;
        self.config_access.write_config_word(address, offsets::COMMAND, cmd);
        
        debug!("PCIデバイスのバスマスタリングを有効化しました: {:?}", address);
    }
    
    /// バスマスタリングを無効化
    pub fn disable_bus_master(&self, address: &PciAddress) {
        let mut cmd = self.config_access.read_config_word(address, offsets::COMMAND);
        cmd &= !cmd_bits::BUS_MASTER;
        self.config_access.write_config_word(address, offsets::COMMAND, cmd);
        
        debug!("PCIデバイスのバスマスタリングを無効化しました: {:?}", address);
    }
    
    /// 割り込みを有効化
    pub fn enable_interrupt(&self, address: &PciAddress) {
        let mut cmd = self.config_access.read_config_word(address, offsets::COMMAND);
        cmd &= !cmd_bits::INTERRUPT_DISABLE;
        self.config_access.write_config_word(address, offsets::COMMAND, cmd);
        
        debug!("PCIデバイスの割り込みを有効化しました: {:?}", address);
    }
    
    /// 割り込みを無効化
    pub fn disable_interrupt(&self, address: &PciAddress) {
        let mut cmd = self.config_access.read_config_word(address, offsets::COMMAND);
        cmd |= cmd_bits::INTERRUPT_DISABLE;
        self.config_access.write_config_word(address, offsets::COMMAND, cmd);
        
        debug!("PCIデバイスの割り込みを無効化しました: {:?}", address);
    }
    
    /// セカンダリバスの情報を取得（PCI-PCIブリッジのみ）
    pub fn get_bridge_secondary_bus(&self, address: &PciAddress) -> Option<u8> {
        // まずデバイスがPCI-PCIブリッジかどうかをチェック
        let class_code = self.config_access.read_config_byte(address, offsets::CLASS_CODE);
        let subclass = self.config_access.read_config_byte(address, offsets::SUBCLASS);
        
        if class_code != 0x06 || subclass != 0x04 {
            return None; // PCI-PCIブリッジではない
        }
        
        // セカンダリバス番号を取得
        let secondary_bus = self.config_access.read_config_byte(address, 0x19);
        Some(secondary_bus)
    }
    
    /// デバイスの電源状態を設定（Power Management Capability必須）
    pub fn set_power_state(&self, address: &PciAddress, state: u8) -> Result<(), &'static str> {
        // Power Management Capabilityを探す
        let reader = PciConfigReader::new(self.config_access);
        let pm_cap = reader.find_capability(address, 0x01);
        
        if let Some(cap) = pm_cap {
            // PM Control/Statusレジスタ（PM Capabilityオフセット+4）
            let pm_ctrl_offset = cap.offset + 4;
            
            // 現在の値を読み取り
            let mut pm_ctrl = self.config_access.read_config_word(address, pm_ctrl_offset);
            
            // 電源状態ビット（0-1）を設定
            pm_ctrl = (pm_ctrl & !0x3) | (state as u16 & 0x3);
            
            // 更新した値を書き込み
            self.config_access.write_config_word(address, pm_ctrl_offset, pm_ctrl);
            
            Ok(())
        } else {
            Err("Power Management Capabilityが見つかりません")
        }
    }
    
    /// MSI（Message Signaled Interrupt）を設定
    pub fn configure_msi(&self, address: &PciAddress, vector: u8, cpu: u8) -> Result<(), &'static str> {
        // MSI Capabilityを探す
        let reader = PciConfigReader::new(self.config_access);
        let msi_cap = reader.find_capability(address, 0x05);
        
        if let Some(cap) = msi_cap {
            // MSI制御レジスタ（MSI Capabilityオフセット+2）
            let msi_ctrl_offset = cap.offset + 2;
            let msi_ctrl = self.config_access.read_config_word(address, msi_ctrl_offset);
            
            // MSI対応かチェック
            if (msi_ctrl & 0x0001) == 0 {
                return Err("MSIがサポートされていません");
            }
            
            // MSI有効化
            let updated_ctrl = msi_ctrl | 0x0001;
            self.config_access.write_config_word(address, msi_ctrl_offset, updated_ctrl);
            
            // メッセージアドレスとデータを設定
            // アドレスはx86のローカルAPICに対応：0xFEE00000 | (cpu << 12)
            let msi_address = 0xFEE00000 | ((cpu as u32) << 12);
            
            // メッセージデータはベクター番号と配送モード（固定）
            let msi_data = 0x4000 | vector as u16; // 配送モード=0（固定）
            
            // アドレスレジスタ（MSI Capabilityオフセット+4）
            let addr_offset = cap.offset + 4;
            self.config_access.write_config_dword(address, addr_offset, msi_address);
            
            // データレジスタ（MSI Capabilityオフセット+8 または +12、64ビット対応かどうかによる）
            let data_offset = if (msi_ctrl & 0x0080) != 0 {
                cap.offset + 12 // 64ビット対応
            } else {
                cap.offset + 8 // 32ビット
            };
            self.config_access.write_config_word(address, data_offset, msi_data);
            
            Ok(())
        } else {
            Err("MSI Capabilityが見つかりません")
        }
    }
}

/// PCIアクセス方式の種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciAccessMethod {
    /// ポートI/Oベースのアクセス (レガシーモード)
    PortIo,
    /// ECaMベースのアクセス (PCIe標準)
    Ecam,
    /// カスタムアクセスモード (プラットフォーム固有)
    Custom,
}

/// PCI設定空間にアクセスするためのトレイト
/// このトレイトはさまざまなアクセス方法（ECAM、ポートI/Oなど）で実装されます
pub trait PciConfigAccess: Send + Sync {
    /// 指定されたPCIアドレスとオフセットから8ビット値を読み取る
    fn read_u8(&self, addr: PciAddress, offset: u16) -> u8;
    
    /// 指定されたPCIアドレスとオフセットから16ビット値を読み取る
    fn read_u16(&self, addr: PciAddress, offset: u16) -> u16;
    
    /// 指定されたPCIアドレスとオフセットから32ビット値を読み取る
    fn read_u32(&self, addr: PciAddress, offset: u16) -> u32;
    
    /// 指定されたPCIアドレスとオフセットに8ビット値を書き込む
    fn write_u8(&self, addr: PciAddress, offset: u16, value: u8);
    
    /// 指定されたPCIアドレスとオフセットに16ビット値を書き込む
    fn write_u16(&self, addr: PciAddress, offset: u16, value: u16);
    
    /// 指定されたPCIアドレスとオフセットに32ビット値を書き込む
    fn write_u32(&self, addr: PciAddress, offset: u16, value: u32);
    
    /// デフォルト実装：PCI標準ヘッダのベンダーIDを読み取る
    fn read_vendor_id(&self, addr: PciAddress) -> u16 {
        self.read_u16(addr, 0x00)
    }
    
    /// デフォルト実装：PCI標準ヘッダのデバイスIDを読み取る
    fn read_device_id(&self, addr: PciAddress) -> u16 {
        self.read_u16(addr, 0x02)
    }
    
    /// デフォルト実装：PCI標準ヘッダのコマンドレジスタを読み取る
    fn read_command(&self, addr: PciAddress) -> u16 {
        self.read_u16(addr, 0x04)
    }
    
    /// デフォルト実装：PCI標準ヘッダのステータスレジスタを読み取る
    fn read_status(&self, addr: PciAddress) -> u16 {
        self.read_u16(addr, 0x06)
    }
    
    /// デフォルト実装：PCI標準ヘッダのリビジョンIDを読み取る
    fn read_revision_id(&self, addr: PciAddress) -> u8 {
        self.read_u8(addr, 0x08)
    }
    
    /// デフォルト実装：PCI標準ヘッダのクラスコードを読み取る
    fn read_class_code(&self, addr: PciAddress) -> u32 {
        // 0x08からの3バイト（クラスコード、サブクラス、プログラミングインターフェース）を読み取る
        // リビジョンIDは下位バイトに含まれる
        let value = self.read_u32(addr, 0x08);
        value >> 8 // リビジョンIDを除去
    }
    
    /// デフォルト実装：PCI標準ヘッダのキャッシュラインサイズを読み取る
    fn read_cache_line_size(&self, addr: PciAddress) -> u8 {
        self.read_u8(addr, 0x0C)
    }
    
    /// デフォルト実装：PCI標準ヘッダのレイテンシタイマーを読み取る
    fn read_latency_timer(&self, addr: PciAddress) -> u8 {
        self.read_u8(addr, 0x0D)
    }
    
    /// デフォルト実装：PCI標準ヘッダのヘッダタイプを読み取る
    fn read_header_type(&self, addr: PciAddress) -> u8 {
        self.read_u8(addr, 0x0E)
    }
    
    /// デフォルト実装：PCI標準ヘッダのBISTを読み取る
    fn read_bist(&self, addr: PciAddress) -> u8 {
        self.read_u8(addr, 0x0F)
    }
    
    /// デフォルト実装：PCI標準ヘッダのヘッダタイプからマルチファンクションフラグを取得
    fn is_multi_function(&self, addr: PciAddress) -> bool {
        (self.read_header_type(addr) & 0x80) != 0
    }
    
    /// デフォルト実装：PCI標準ヘッダのヘッダタイプからヘッダタイプを取得
    fn get_header_type(&self, addr: PciAddress) -> u8 {
        self.read_header_type(addr) & 0x7F
    }
    
    /// デフォルト実装：PCIデバイスにBARを書き込む
    fn write_bar(&self, addr: PciAddress, bar_index: u8, value: u32) {
        if bar_index >= 6 {
            return; // 無効なBARインデックス
        }
        
        let offset = 0x10 + (bar_index as u16) * 4;
        self.write_u32(addr, offset, value);
    }
    
    /// デフォルト実装：PCIデバイスからBARを読み取る
    fn read_bar(&self, addr: PciAddress, bar_index: u8) -> u32 {
        if bar_index >= 6 {
            return 0; // 無効なBARインデックス
        }
        
        let offset = 0x10 + (bar_index as u16) * 4;
        self.read_u32(addr, offset)
    }
    
    /// デフォルト実装：PCIデバイスのBARサイズを取得する
    fn get_bar_size(&self, addr: PciAddress, bar_index: u8) -> u64 {
        if bar_index >= 6 {
            return 0; // 無効なBARインデックス
        }
        
        let offset = 0x10 + (bar_index as u16) * 4;
        
        // 現在のBAR値を保存
        let original_value = self.read_u32(addr, offset);
        
        // 全ビット1を書き込む
        self.write_u32(addr, offset, 0xFFFFFFFF);
        
        // 読み戻して調整されたビットを確認
        let size_mask = self.read_u32(addr, offset);
        
        // 元の値を復元
        self.write_u32(addr, offset, original_value);
        
        // BARタイプを確認（メモリかI/Oか）
        if (original_value & 0x1) == 0 {
            // メモリ空間BAR
            
            // 64ビットかチェック
            let is_64bit = ((original_value & 0x6) >> 1) == 0x2;
            
            if is_64bit && bar_index < 5 {
                // 上位32ビットを取得
                let upper_offset = offset + 4;
                let original_upper = self.read_u32(addr, upper_offset);
                
                // 全ビット1を書き込む
                self.write_u32(addr, upper_offset, 0xFFFFFFFF);
                
                // 読み戻し
                let upper_size_mask = self.read_u32(addr, upper_offset);
                
                // 元の値を復元
                self.write_u32(addr, upper_offset, original_upper);
                
                // 64ビットサイズを計算 (サイズは常に2の累乗)
                let size_bits = !((size_mask & 0xFFFFFFF0) | ((upper_size_mask as u64) << 32)) + 1;
                return size_bits;
            } else {
                // 32ビットサイズを計算 (サイズは常に2の累乗)
                let size_bits = !((size_mask & 0xFFFFFFF0) as u64) + 1;
                return size_bits;
            }
        } else {
            // I/O空間BAR
            let size_bits = !((size_mask & 0xFFFFFFFC) as u64) + 1;
            return size_bits;
        }
    }
    
    /// デフォルト実装：PCIコマンドレジスタのビットを設定
    fn set_command_bit(&self, addr: PciAddress, bit_mask: u16, enable: bool) {
        let cmd = self.read_command(addr);
        let new_cmd = if enable {
            cmd | bit_mask
        } else {
            cmd & !bit_mask
        };
        
        // 変更がある場合のみ書き込む
        if cmd != new_cmd {
            self.write_u16(addr, 0x04, new_cmd);
        }
    }
    
    /// デフォルト実装：PCIデバイスのバスマスタリングを有効/無効にする
    fn enable_bus_mastering(&self, addr: PciAddress, enable: bool) {
        self.set_command_bit(addr, 0x04, enable);
    }
    
    /// デフォルト実装：PCIデバイスのメモリ空間アクセスを有効/無効にする
    fn enable_memory_space(&self, addr: PciAddress, enable: bool) {
        self.set_command_bit(addr, 0x02, enable);
    }
    
    /// デフォルト実装：PCIデバイスのI/O空間アクセスを有効/無効にする
    fn enable_io_space(&self, addr: PciAddress, enable: bool) {
        self.set_command_bit(addr, 0x01, enable);
    }
    
    /// デフォルト実装：PCIデバイスが有効か（ベンダーIDが無効値でない）確認
    fn is_device_valid(&self, addr: PciAddress) -> bool {
        let vendor_id = self.read_vendor_id(addr);
        vendor_id != 0xFFFF
    }
    
    /// デフォルト実装：特定のキャパビリティを持つかチェック
    fn has_capability(&self, addr: PciAddress, cap_id: u8) -> bool {
        // ステータスレジスタをチェックしてキャパビリティリストのサポートを確認
        let status = self.read_status(addr);
        if (status & 0x10) == 0 {
            return false; // キャパビリティリストはサポートされていない
        }
        
        // ヘッダタイプをチェック（タイプ0またはタイプ1のみがキャパビリティを持つ）
        let header_type = self.get_header_type(addr);
        if header_type > 1 {
            return false;
        }
        
        // キャパビリティリストのポインタを取得
        let cap_ptr = self.read_u8(addr, 0x34);
        if cap_ptr == 0 {
            return false; // キャパビリティリストなし
        }
        
        // リストを巡回して指定されたキャパビリティIDを探す
        let mut current = cap_ptr as u16;
        let mut visited = [false; 256]; // 循環リンクを検出するための配列
        
        while current != 0 {
            if visited[current as usize] {
                break; // 循環リンクを検出
            }
            
            visited[current as usize] = true;
            
            // キャパビリティIDをチェック
            let this_cap_id = self.read_u8(addr, current);
            if this_cap_id == cap_id {
                return true; // 指定されたキャパビリティを見つけた
            }
            
            // 次のキャパビリティへ
            current = self.read_u8(addr, current + 1) as u16;
        }
        
        false // 指定されたキャパビリティは見つからなかった
    }
    
    /// デフォルト実装：特定のキャパビリティのオフセットを取得
    fn find_capability(&self, addr: PciAddress, cap_id: u8) -> Option<u16> {
        // ステータスレジスタをチェックしてキャパビリティリストのサポートを確認
        let status = self.read_status(addr);
        if (status & 0x10) == 0 {
            return None; // キャパビリティリストはサポートされていない
        }
        
        // ヘッダタイプをチェック（タイプ0またはタイプ1のみがキャパビリティを持つ）
        let header_type = self.get_header_type(addr);
        if header_type > 1 {
            return None;
        }
        
        // キャパビリティリストのポインタを取得
        let cap_ptr = self.read_u8(addr, 0x34);
        if cap_ptr == 0 {
            return None; // キャパビリティリストなし
        }
        
        // リストを巡回して指定されたキャパビリティIDを探す
        let mut current = cap_ptr as u16;
        let mut visited = [false; 256]; // 循環リンクを検出するための配列
        
        while current != 0 {
            if visited[current as usize] {
                break; // 循環リンクを検出
            }
            
            visited[current as usize] = true;
            
            // キャパビリティIDをチェック
            let this_cap_id = self.read_u8(addr, current);
            if this_cap_id == cap_id {
                return Some(current); // 指定されたキャパビリティのオフセットを返す
            }
            
            // 次のキャパビリティへ
            current = self.read_u8(addr, current + 1) as u16;
        }
        
        None // 指定されたキャパビリティは見つからなかった
    }
}

/// PCI設定空間へのアクセスを管理するユーティリティ
pub struct PciConfigAccessManager {
    /// ECAMアクセスが利用可能かどうか
    ecam_available: AtomicBool,
    /// レガシーポートI/Oアクセスが利用可能かどうか
    port_io_available: AtomicBool,
}

impl PciConfigAccessManager {
    /// 新しい設定アクセスマネージャを作成
    pub fn new() -> Self {
        Self {
            ecam_available: AtomicBool::new(false),
            port_io_available: AtomicBool::new(false),
        }
    }
    
    /// 利用可能なアクセス方法をプローブ
    pub fn probe_available_access_methods(&self) {
        // ECAMアクセスが利用可能かチェック
        let ecam_available = false; // EcamAccess::is_available() の代わり
        self.ecam_available.store(ecam_available, Ordering::SeqCst);
        
        // レガシーポートI/Oアクセスが利用可能かチェック
        let port_io_available = false; // PortIoAccess::is_available() の代わり
        self.port_io_available.store(port_io_available, Ordering::SeqCst);
    }
    
    /// ECAMアクセスが利用可能かどうかを取得
    pub fn is_ecam_available(&self) -> bool {
        self.ecam_available.load(Ordering::SeqCst)
    }
    
    /// レガシーポートI/Oアクセスが利用可能かどうかを取得
    pub fn is_port_io_available(&self) -> bool {
        self.port_io_available.load(Ordering::SeqCst)
    }
    
    /// 任意のアクセス方法が利用可能かどうかを取得
    pub fn is_any_access_available(&self) -> bool {
        self.is_ecam_available() || self.is_port_io_available()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::pci::address::PciAddress;
    
    // テスト用のモックアクセス実装
    struct MockAccess {
        memory: [u8; 256],
    }
    
    impl MockAccess {
        fn new() -> Self {
            let mut memory = [0u8; 256];
            
            // ベンダーID（0x8086 = Intel）
            memory[0] = 0x86;
            memory[1] = 0x80;
            
            // デバイスID（0x1234）
            memory[2] = 0x34;
            memory[3] = 0x12;
            
            // コマンドレジスタ
            memory[4] = 0x00;
            memory[5] = 0x00;
            
            // ステータスレジスタ（キャパビリティリスト有り）
            memory[6] = 0x10;
            memory[7] = 0x00;
            
            // ヘッダタイプ（シングルファンクション、タイプ0）
            memory[0x0E] = 0x00;
            
            // キャパビリティポインタ
            memory[0x34] = 0x40;
            
            // キャパビリティリスト
            // 最初のキャパビリティ（ID=0x01、次=0x50）
            memory[0x40] = 0x01;
            memory[0x41] = 0x50;
            
            // 2番目のキャパビリティ（ID=0x05、次=0x60）
            memory[0x50] = 0x05;
            memory[0x51] = 0x60;
            
            // 3番目のキャパビリティ（ID=0x10、次=0x00＝終了）
            memory[0x60] = 0x10;
            memory[0x61] = 0x00;
            
            Self { memory }
        }
    }
    
    impl PciConfigAccess for MockAccess {
        fn read_u8(&self, _addr: PciAddress, offset: u16) -> u8 {
            self.memory[offset as usize]
        }
        
        fn read_u16(&self, _addr: PciAddress, offset: u16) -> u16 {
            let low = self.memory[offset as usize] as u16;
            let high = self.memory[(offset + 1) as usize] as u16;
            low | (high << 8)
        }
        
        fn read_u32(&self, _addr: PciAddress, offset: u16) -> u32 {
            let b0 = self.memory[offset as usize] as u32;
            let b1 = self.memory[(offset + 1) as usize] as u32;
            let b2 = self.memory[(offset + 2) as usize] as u32;
            let b3 = self.memory[(offset + 3) as usize] as u32;
            b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        }
        
        fn write_u8(&self, _addr: PciAddress, _offset: u16, _value: u8) {
            // テストではライトは不要
        }
        
        fn write_u16(&self, _addr: PciAddress, _offset: u16, _value: u16) {
            // テストではライトは不要
        }
        
        fn write_u32(&self, _addr: PciAddress, _offset: u16, _value: u32) {
            // テストではライトは不要
        }
    }
    
    #[test]
    fn test_read_vendor_device_id() {
        let mock = MockAccess::new();
        let addr = PciAddress::legacy(0, 0, 0);
        
        assert_eq!(mock.read_vendor_id(addr), 0x8086);
        assert_eq!(mock.read_device_id(addr), 0x1234);
    }
    
    #[test]
    fn test_has_capability() {
        let mock = MockAccess::new();
        let addr = PciAddress::legacy(0, 0, 0);
        
        assert!(mock.has_capability(addr, 0x01));
        assert!(mock.has_capability(addr, 0x05));
        assert!(mock.has_capability(addr, 0x10));
        assert!(!mock.has_capability(addr, 0x20));
    }
    
    #[test]
    fn test_find_capability() {
        let mock = MockAccess::new();
        let addr = PciAddress::legacy(0, 0, 0);
        
        assert_eq!(mock.find_capability(addr, 0x01), Some(0x40));
        assert_eq!(mock.find_capability(addr, 0x05), Some(0x50));
        assert_eq!(mock.find_capability(addr, 0x10), Some(0x60));
        assert_eq!(mock.find_capability(addr, 0x20), None);
    }
} 