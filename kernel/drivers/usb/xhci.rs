// xHCIドライバーモジュール
// AetherOS用高性能USB 3.0/3.1ドライバー実装
// 作成者: AetherOSチーム

//! # eXtensible Host Controller Interface (xHCI) ドライバー
//! 
//! このモジュールは、USB 3.0/3.1デバイスをサポートするxHCIホストコントローラーのドライバーを実装します。
//! 高性能かつ低レイテンシなUSBデバイスアクセスを提供します。

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, RwLock};

use crate::arch::mm::PhysAddr;
use crate::drivers::pci::{PciDevice, PciClass, PciBar};
use crate::drivers::usb::hci::{UsbHci, UsbHciType, UsbHciFactory, UsbSpeed, UsbSetupPacket};
use crate::mm::MemoryManager;

/// xHCIレジスタサイズ定数
const XHCI_CAPLENGTH_OFFSET: usize = 0x00;
const XHCI_HCIVERSION_OFFSET: usize = 0x02;
const XHCI_HCSPARAMS1_OFFSET: usize = 0x04;
const XHCI_HCSPARAMS2_OFFSET: usize = 0x08;
const XHCI_HCSPARAMS3_OFFSET: usize = 0x0C;
const XHCI_HCCPARAMS1_OFFSET: usize = 0x10;
const XHCI_DBOFF_OFFSET: usize = 0x14;
const XHCI_RTSOFF_OFFSET: usize = 0x18;
const XHCI_HCCPARAMS2_OFFSET: usize = 0x1C;

/// xHCIコマンドレジスタオフセット
const XHCI_USBCMD_OFFSET: usize = 0x00;
const XHCI_USBSTS_OFFSET: usize = 0x04;
const XHCI_PAGESIZE_OFFSET: usize = 0x08;
const XHCI_DNCTRL_OFFSET: usize = 0x14;
const XHCI_CRCR_OFFSET: usize = 0x18;
const XHCI_DCBAAP_OFFSET: usize = 0x30;
const XHCI_CONFIG_OFFSET: usize = 0x38;

/// xHCIポートレジスタオフセット（基準からの相対）
const XHCI_PORTSC_OFFSET: usize = 0x00;
const XHCI_PORTPMSC_OFFSET: usize = 0x04;
const XHCI_PORTLI_OFFSET: usize = 0x08;
const XHCI_PORTHLPMC_OFFSET: usize = 0x0C;

/// xHCIコマンドレジスタビットマスク
const XHCI_CMD_RUN: u32 = 1 << 0;
const XHCI_CMD_HCRST: u32 = 1 << 1;
const XHCI_CMD_INTE: u32 = 1 << 2;
const XHCI_CMD_HSEE: u32 = 1 << 3;
const XHCI_CMD_LHCRST: u32 = 1 << 7;
const XHCI_CMD_CSS: u32 = 1 << 8;
const XHCI_CMD_CRS: u32 = 1 << 9;
const XHCI_CMD_EWE: u32 = 1 << 10;

/// xHCIステータスレジスタビットマスク
const XHCI_STS_HCH: u32 = 1 << 0;
const XHCI_STS_HSE: u32 = 1 << 2;
const XHCI_STS_EINT: u32 = 1 << 3;
const XHCI_STS_PCD: u32 = 1 << 4;
const XHCI_STS_SSS: u32 = 1 << 8;
const XHCI_STS_RSS: u32 = 1 << 9;
const XHCI_STS_SRE: u32 = 1 << 10;
const XHCI_STS_CNR: u32 = 1 << 11;
const XHCI_STS_HCE: u32 = 1 << 12;

/// xHCIポートステータスレジスタビットマスク
const XHCI_PORTSC_CCS: u32 = 1 << 0;
const XHCI_PORTSC_PED: u32 = 1 << 1;
const XHCI_PORTSC_OCA: u32 = 1 << 3;
const XHCI_PORTSC_PR: u32 = 1 << 4;
const XHCI_PORTSC_PP: u32 = 1 << 9;
const XHCI_PORTSC_CSC: u32 = 1 << 17;
const XHCI_PORTSC_PEC: u32 = 1 << 18;
const XHCI_PORTSC_WRC: u32 = 1 << 19;
const XHCI_PORTSC_OCC: u32 = 1 << 20;
const XHCI_PORTSC_PRC: u32 = 1 << 21;
const XHCI_PORTSC_PLC: u32 = 1 << 22;
const XHCI_PORTSC_CEC: u32 = 1 << 23;
const XHCI_PORTSC_CAS: u32 = 1 << 24;
const XHCI_PORTSC_WCE: u32 = 1 << 25;
const XHCI_PORTSC_WDE: u32 = 1 << 26;
const XHCI_PORTSC_WOE: u32 = 1 << 27;
const XHCI_PORTSC_CHANGE_BITS: u32 = XHCI_PORTSC_CSC | XHCI_PORTSC_PEC |
                                       XHCI_PORTSC_WRC | XHCI_PORTSC_OCC |
                                       XHCI_PORTSC_PRC | XHCI_PORTSC_PLC |
                                       XHCI_PORTSC_CEC;

/// xHCIポートスピードマスク（ビット10-13）
const XHCI_PORTSC_SPEED_MASK: u32 = 0xF << 10;
const XHCI_PORTSC_SPEED_FULL: u32 = 1 << 10;
const XHCI_PORTSC_SPEED_LOW: u32 = 2 << 10;
const XHCI_PORTSC_SPEED_HIGH: u32 = 3 << 10;
const XHCI_PORTSC_SPEED_SUPER: u32 = 4 << 10;
const XHCI_PORTSC_SPEED_SUPER_PLUS: u32 = 5 << 10;

/// xHCI転送記述子 (TRB) タイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum XhciTrbType {
    Reserved = 0,
    Normal = 1,
    SetupStage = 2,
    DataStage = 3,
    StatusStage = 4,
    Isoch = 5,
    Link = 6,
    EventData = 7,
    Noop = 8,
    EnableSlotCommand = 9,
    DisableSlotCommand = 10,
    AddressDeviceCommand = 11,
    ConfigureEndpointCommand = 12,
    EvaluateContextCommand = 13,
    ResetEndpointCommand = 14,
    StopEndpointCommand = 15,
    SetTRDequeuePointerCommand = 16,
    ResetDeviceCommand = 17,
    ForceEventCommand = 18,
    NegotiateBandwidthCommand = 19,
    SetLatencyToleranceValueCommand = 20,
    GetPortBandwidthCommand = 21,
    ForceHeaderCommand = 22,
    NoopCommand = 23,
    GetExtendedPropertyCommand = 24,
    SetExtendedPropertyCommand = 25,
    TransferEvent = 32,
    CommandCompletionEvent = 33,
    PortStatusChangeEvent = 34,
    BandwidthRequestEvent = 35,
    DoorbellEvent = 36,
    HostControllerEvent = 37,
    DeviceNotificationEvent = 38,
    MFINDEXWrapEvent = 39,
}

/// xHCI 転送記述子 (TRB)
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct XhciTrb {
    /// パラメータ1 (64ビットの下位32ビット)
    pub parameter1: u32,
    /// パラメータ2 (64ビットの上位32ビット)
    pub parameter2: u32,
    /// ステータス
    pub status: u32,
    /// コントロールビット
    pub control: u32,
}

impl XhciTrb {
    /// 新しいTRBを作成
    pub fn new() -> Self {
        Self {
            parameter1: 0,
            parameter2: 0,
            status: 0,
            control: 0,
        }
    }
    
    /// TRBの種類を設定
    pub fn set_type(&mut self, trb_type: XhciTrbType) {
        let type_val = trb_type as u32;
        self.control = (self.control & !(0x3F << 10)) | (type_val << 10);
    }
    
    /// TRBの種類を取得
    pub fn get_type(&self) -> XhciTrbType {
        let type_val = (self.control >> 10) & 0x3F;
        match type_val {
            1 => XhciTrbType::Normal,
            2 => XhciTrbType::SetupStage,
            3 => XhciTrbType::DataStage,
            4 => XhciTrbType::StatusStage,
            5 => XhciTrbType::Isoch,
            6 => XhciTrbType::Link,
            7 => XhciTrbType::EventData,
            8 => XhciTrbType::Noop,
            9 => XhciTrbType::EnableSlotCommand,
            10 => XhciTrbType::DisableSlotCommand,
            11 => XhciTrbType::AddressDeviceCommand,
            12 => XhciTrbType::ConfigureEndpointCommand,
            13 => XhciTrbType::EvaluateContextCommand,
            14 => XhciTrbType::ResetEndpointCommand,
            15 => XhciTrbType::StopEndpointCommand,
            16 => XhciTrbType::SetTRDequeuePointerCommand,
            17 => XhciTrbType::ResetDeviceCommand,
            18 => XhciTrbType::ForceEventCommand,
            19 => XhciTrbType::NegotiateBandwidthCommand,
            20 => XhciTrbType::SetLatencyToleranceValueCommand,
            21 => XhciTrbType::GetPortBandwidthCommand,
            22 => XhciTrbType::ForceHeaderCommand,
            23 => XhciTrbType::NoopCommand,
            24 => XhciTrbType::GetExtendedPropertyCommand,
            25 => XhciTrbType::SetExtendedPropertyCommand,
            32 => XhciTrbType::TransferEvent,
            33 => XhciTrbType::CommandCompletionEvent,
            34 => XhciTrbType::PortStatusChangeEvent,
            35 => XhciTrbType::BandwidthRequestEvent,
            36 => XhciTrbType::DoorbellEvent,
            37 => XhciTrbType::HostControllerEvent,
            38 => XhciTrbType::DeviceNotificationEvent,
            39 => XhciTrbType::MFINDEXWrapEvent,
            _ => XhciTrbType::Reserved,
        }
    }
    
    /// 64ビットパラメータを設定（物理アドレスなど）
    pub fn set_parameter(&mut self, value: u64) {
        self.parameter1 = value as u32;
        self.parameter2 = (value >> 32) as u32;
    }
    
    /// 64ビットパラメータを取得
    pub fn get_parameter(&self) -> u64 {
        (self.parameter2 as u64) << 32 | (self.parameter1 as u64)
    }
    
    /// サイクルビットを設定
    pub fn set_cycle_bit(&mut self, cycle: bool) {
        if cycle {
            self.control |= 0x1;
        } else {
            self.control &= !0x1;
        }
    }
    
    /// サイクルビットを取得
    pub fn get_cycle_bit(&self) -> bool {
        (self.control & 0x1) != 0
    }
}

impl fmt::Debug for XhciTrb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XhciTrb")
            .field("parameter", &format_args!("0x{:016x}", self.get_parameter()))
            .field("status", &format_args!("0x{:08x}", self.status))
            .field("control", &format_args!("0x{:08x}", self.control))
            .field("type", &self.get_type())
            .field("cycle_bit", &self.get_cycle_bit())
            .finish()
    }
}

/// xHCIメモリマップドI/Oレジスタにアクセスするためのラッパー
struct XhciRegisters {
    /// ベースアドレス（仮想アドレス）
    base: *mut u8,
    /// ケーパビリティレジスタ長
    cap_length: u8,
    /// オペレーションレジスタオフセット
    op_regs: usize,
    /// ランタイムレジスタオフセット
    runtime_regs: usize,
    /// ドアベルレジスタオフセット
    doorbell_regs: usize,
    /// ポートレジスタのオフセット
    port_regs: usize,
}

impl XhciRegisters {
    /// 新しいxHCIレジスタセットを作成
    pub unsafe fn new(base_addr: *mut u8) -> Self {
        let cap_length = unsafe { *(base_addr.add(XHCI_CAPLENGTH_OFFSET) as *const u8) };
        let op_regs = cap_length as usize;
        
        let runtime_offset = unsafe { 
            *(base_addr.add(XHCI_RTSOFF_OFFSET) as *const u32)
        } as usize;
        
        let doorbell_offset = unsafe { 
            *(base_addr.add(XHCI_DBOFF_OFFSET) as *const u32)
        } as usize;
        
        // ポートレジスタは操作レジスタから0x400オフセットにある
        let port_regs = op_regs + 0x400;
        
        Self {
            base: base_addr,
            cap_length,
            op_regs,
            runtime_regs: runtime_offset,
            doorbell_regs: doorbell_offset,
            port_regs,
        }
    }
    
    /// ケーパビリティレジスタを読み取る
    pub fn read_cap(&self, offset: usize) -> u32 {
        unsafe {
            *(self.base.add(offset) as *const u32)
        }
    }
    
    /// 操作レジスタを読み取る
    pub fn read_op(&self, offset: usize) -> u32 {
        unsafe {
            *(self.base.add(self.op_regs + offset) as *const u32)
        }
    }
    
    /// 操作レジスタに書き込む
    pub fn write_op(&self, offset: usize, value: u32) {
        unsafe {
            *(self.base.add(self.op_regs + offset) as *mut u32) = value;
        }
    }
    
    /// ポートレジスタを読み取る
    pub fn read_port(&self, port: usize, offset: usize) -> u32 {
        let port_offset = self.port_regs + port * 0x10 + offset;
        unsafe {
            *(self.base.add(port_offset) as *const u32)
        }
    }
    
    /// ポートレジスタに書き込む
    pub fn write_port(&self, port: usize, offset: usize, value: u32) {
        let port_offset = self.port_regs + port * 0x10 + offset;
        unsafe {
            *(self.base.add(port_offset) as *mut u32) = value;
        }
    }
    
    /// ポートステータスレジスタを読み取る
    pub fn read_port_status(&self, port: usize) -> u32 {
        self.read_port(port, XHCI_PORTSC_OFFSET)
    }
    
    /// ポートステータスレジスタに書き込む
    pub fn write_port_status(&self, port: usize, value: u32) {
        self.write_port(port, XHCI_PORTSC_OFFSET, value)
    }
    
    /// コマンドレジスタを読み取る
    pub fn read_command(&self) -> u32 {
        self.read_op(XHCI_USBCMD_OFFSET)
    }
    
    /// コマンドレジスタに書き込む
    pub fn write_command(&self, value: u32) {
        self.write_op(XHCI_USBCMD_OFFSET, value)
    }
    
    /// ステータスレジスタを読み取る
    pub fn read_status(&self) -> u32 {
        self.read_op(XHCI_USBSTS_OFFSET)
    }
    
    /// HCIバージョンを取得
    pub fn get_hci_version(&self) -> u16 {
        unsafe {
            *(self.base.add(XHCI_HCIVERSION_OFFSET) as *const u16)
        }
    }
    
    /// 最大デバイススロット数を取得
    pub fn get_max_slots(&self) -> u8 {
        let hcs_params1 = self.read_cap(XHCI_HCSPARAMS1_OFFSET);
        (hcs_params1 & 0xFF) as u8
    }
    
    /// 最大ポート数を取得
    pub fn get_max_ports(&self) -> u8 {
        let hcs_params1 = self.read_cap(XHCI_HCSPARAMS1_OFFSET);
        ((hcs_params1 >> 24) & 0xFF) as u8
    }
    
    /// ドアベルレジスタに書き込む
    pub fn ring_doorbell(&self, slot_id: u8, target: u8) {
        let doorbell_offset = self.doorbell_regs + (slot_id as usize * 4);
        let value = target as u32;
        
        unsafe {
            *(self.base.add(doorbell_offset) as *mut u32) = value;
        }
    }
}

/// xHCIホストコントローラー
pub struct XhciController {
    /// 使用するPCIデバイス
    pci_device: Arc<PciDevice>,
    /// xHCIレジスタ
    registers: Mutex<Option<XhciRegisters>>,
    /// 初期化完了フラグ
    initialized: AtomicBool,
    /// コントローラが64ビットアドレス指定をサポートするか
    supports_64bit: AtomicBool,
}

impl XhciController {
    /// 新しいxHCIコントローラーを作成
    pub fn new(pci_device: Arc<PciDevice>) -> Self {
        Self {
            pci_device,
            registers: Mutex::new(None),
            initialized: AtomicBool::new(false),
            supports_64bit: AtomicBool::new(false),
        }
    }
    
    /// xHCIコントローラーを初期化
    fn initialize_controller(&self) -> Result<(), &'static str> {
        // PCIデバイスのメモリバーを見つける
        let bar = self.pci_device.read_bar(0).ok_or("xHCIコントローラーのBARが見つかりません")?;
        
        if !bar.is_memory {
            return Err("xHCIコントローラーはメモリマップドI/Oをサポートしている必要があります");
        }
        
        // メモリ空間アクセスとバスマスタリングを有効化
        self.pci_device.enable_memory_space();
        self.pci_device.enable_bus_mastering();
        
        // ベースアドレスをマップ
        let phys_addr = bar.address.as_u64();
        let virt_addr = MemoryManager::map_device_memory(phys_addr, bar.size as usize)
            .map_err(|_| "xHCIレジスタマッピングに失敗しました")?;
        
        // レジスタ構造体を初期化
        let registers = unsafe { XhciRegisters::new(virt_addr as *mut u8) };
        
        // コントローラ情報を表示
        let version = registers.get_hci_version();
        let max_slots = registers.get_max_slots();
        let max_ports = registers.get_max_ports();
        
        log::info!(
            "xHCIコントローラー: バージョン {}.{:02x}, スロット数 {}, ポート数 {}",
            (version >> 8) & 0xFF,
            version & 0xFF,
            max_slots,
            max_ports
        );
        
        // 64ビットアドレッシングのサポートを確認
        let params1 = registers.read_cap(XHCI_HCCPARAMS1_OFFSET);
        let supports_64bit = (params1 & 0x1) != 0;
        self.supports_64bit.store(supports_64bit, Ordering::SeqCst);
        
        // コントローラーをリセット
        self.reset_controller(&registers)?;
        
        // レジスタを保存
        *self.registers.lock() = Some(registers);
        
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }
    
    /// コントローラーをハードリセット
    fn reset_controller(&self, registers: &XhciRegisters) -> Result<(), &'static str> {
        // すでに動作中なら停止
        let mut command = registers.read_command();
        if (command & XHCI_CMD_RUN) != 0 {
            command &= !XHCI_CMD_RUN;
            registers.write_command(command);
            
            // コントローラーが停止するのを待つ
            let mut timeout = 1000;
            while (registers.read_status() & XHCI_STS_HCH) == 0 && timeout > 0 {
                // 少し待機
                for _ in 0..1000 {
                    core::hint::spin_loop();
                }
                timeout -= 1;
            }
            
            if timeout == 0 {
                return Err("xHCIコントローラーの停止がタイムアウトしました");
            }
        }
        
        // コントローラーをリセット
        command = registers.read_command();
        command |= XHCI_CMD_HCRST;
        registers.write_command(command);
        
        // リセットが完了するのを待つ
        let mut timeout = 1000;
        while (registers.read_command() & XHCI_CMD_HCRST) != 0 && timeout > 0 {
            // 少し待機
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
            timeout -= 1;
        }
        
        if timeout == 0 {
            return Err("xHCIコントローラーのリセットがタイムアウトしました");
        }
        
        // コントローラーが準備完了するのを待つ
        timeout = 1000;
        while (registers.read_status() & XHCI_STS_CNR) != 0 && timeout > 0 {
            // 少し待機
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
            timeout -= 1;
        }
        
        if timeout == 0 {
            return Err("xHCIコントローラーの準備がタイムアウトしました");
        }
        
        Ok(())
    }
}

impl UsbHci for XhciController {
    fn hci_type(&self) -> UsbHciType {
        UsbHciType::Xhci
    }
    
    fn initialize(&self) -> Result<(), &'static str> {
        if self.initialized.load(Ordering::SeqCst) {
            return Ok(());
        }
        
        self.initialize_controller()
    }
    
    fn root_hub_port_count(&self) -> usize {
        let registers = self.registers.lock();
        
        if let Some(regs) = &*registers {
            regs.get_max_ports() as usize
        } else {
            0
        }
    }
    
    fn is_device_connected(&self, port: usize) -> bool {
        let registers = self.registers.lock();
        
        if let Some(regs) = &*registers {
            let port_status = regs.read_port_status(port);
            (port_status & XHCI_PORTSC_CCS) != 0
        } else {
            false
        }
    }
    
    fn get_port_speed(&self, port: usize) -> Option<UsbSpeed> {
        let registers = self.registers.lock();
        
        if let Some(regs) = &*registers {
            let port_status = regs.read_port_status(port);
            
            // デバイスが接続されているか確認
            if (port_status & XHCI_PORTSC_CCS) == 0 {
                return None;
            }
            
            // スピードフィールドを取得
            let speed = (port_status & XHCI_PORTSC_SPEED_MASK) >> 10;
            
            match speed {
                1 => Some(UsbSpeed::Full),
                2 => Some(UsbSpeed::Low),
                3 => Some(UsbSpeed::High),
                4 => Some(UsbSpeed::Super),
                5 => Some(UsbSpeed::SuperPlus),
                _ => Some(UsbSpeed::Full), // 未知の値はFull Speedとして扱う
            }
        } else {
            None
        }
    }
    
    fn reset_port(&self, port: usize) -> Result<(), &'static str> {
        let registers = self.registers.lock();
        
        if let Some(regs) = &*registers {
            // 現在のポートステータスを取得
            let mut port_status = regs.read_port_status(port);
            
            // デバイスが接続されているか確認
            if (port_status & XHCI_PORTSC_CCS) == 0 {
                return Err("ポートにデバイスが接続されていません");
            }
            
            // RWビットをクリアし、変更ビットを保持
            port_status = (port_status & !(XHCI_PORTSC_PED | 0xE0)) | XHCI_PORTSC_PR;
            regs.write_port_status(port, port_status);
            
            // リセットが完了するのを待つ
            let mut timeout = 1000;
            
            loop {
                // 少し待機
                for _ in 0..1000 {
                    core::hint::spin_loop();
                }
                
                port_status = regs.read_port_status(port);
                
                // リセットビットがクリアされたか確認
                if (port_status & XHCI_PORTSC_PR) == 0 {
                    break;
                }
                
                timeout -= 1;
                if timeout == 0 {
                    return Err("ポートリセットがタイムアウトしました");
                }
            }
            
            // 変更ビットをクリア
            port_status |= XHCI_PORTSC_CHANGE_BITS;
            regs.write_port_status(port, port_status);
            
            Ok(())
        } else {
            Err("xHCIコントローラーが初期化されていません")
        }
    }
    
    fn control_transfer(
        &self,
        device_addr: u8,
        setup: UsbSetupPacket,
        data: Option<&mut [u8]>,
    ) -> Result<usize, &'static str> {
        // この実装は簡略化されています。実際の実装では：
        // 1. TRBリングを設定
        // 2. セットアップステージTRBを作成
        // 3. データステージTRBを作成（必要な場合）
        // 4. ステータスステージTRBを作成
        // 5. ドアベルを鳴らす
        // 6. 完了を待つ
        
        Err("xHCI制御転送はまだ実装されていません")
    }
}

/// xHCIコントローラードライバーのファクトリー
pub struct XhciDriverFactory;

impl XhciDriverFactory {
    /// 新しいファクトリーインスタンスを作成
    pub fn new() -> Self {
        Self
    }
}

impl UsbHciFactory for XhciDriverFactory {
    fn hci_type(&self) -> UsbHciType {
        UsbHciType::Xhci
    }
    
    fn can_handle_device(&self, device: &PciDevice) -> bool {
        // SerialBusController (0x0C), USB Controller (0x03), xHCI (0x30)
        device.info.class_code == 0x0C && 
        device.info.subclass == 0x03 && 
        device.info.prog_if == 0x30
    }
    
    fn create_hci(&self, device: Arc<PciDevice>) -> Result<Arc<dyn UsbHci>, &'static str> {
        if !self.can_handle_device(&device) {
            return Err("このデバイスはxHCIコントローラーではありません");
        }
        
        Ok(Arc::new(XhciController::new(device)))
    }
}

/// xHCIドライバーファクトリーを登録
pub fn register_driver() -> Result<(), &'static str> {
    use crate::drivers::usb::hci::UsbSubsystem;
    
    if let Some(usb) = UsbSubsystem::INSTANCE.get() {
        let factory = Arc::new(XhciDriverFactory::new());
        usb.register_hci_factory(factory);
        Ok(())
    } else {
        Err("USBサブシステムが初期化されていません")
    }
}

/// USB転送の実行（実際の実装）
pub fn execute_transfer(
    &mut self,
    endpoint_address: u8,
    transfer_type: UsbTransferType,
    data: &[u8],
    timeout_ms: u32,
) -> Result<usize, &'static str> {
    log::debug!("USB転送実行開始: EP=0x{:x}, タイプ={:?}, サイズ={}", 
               endpoint_address, transfer_type, data.len());
    
    // xHCI仕様に準拠した転送実装
    
    // 1. TRBリングの設定
    let slot_id = self.get_slot_id_for_endpoint(endpoint_address)?;
    let endpoint_context = self.get_endpoint_context(slot_id, endpoint_address)?;
    
    // 2. TRB（Transfer Request Block）の作成
    let trb_ring = self.get_trb_ring(slot_id, endpoint_address)?;
    let transfer_trbs = self.create_transfer_trbs(transfer_type, data, timeout_ms)?;
    
    // 3. TRBリングにエンキュー
    for trb in &transfer_trbs {
        trb_ring.enqueue_trb(trb)?;
    }
    
    // 4. Doorbellレジスタを鳴らして転送開始
    self.ring_doorbell(slot_id, endpoint_address)?;
    
    // 5. 転送完了待機
    let completion_result = self.wait_for_transfer_completion(timeout_ms)?;
    
    // 6. 結果の処理
    match completion_result.completion_code {
        TrbCompletionCode::Success => {
            log::debug!("USB転送成功: 転送バイト数={}", completion_result.transfer_length);
            Ok(completion_result.transfer_length)
        }
        TrbCompletionCode::ShortPacket => {
            log::debug!("USB転送完了（ショートパケット）: 転送バイト数={}", completion_result.transfer_length);
            Ok(completion_result.transfer_length)
        }
        TrbCompletionCode::StallError => {
            log::error!("USB転送失敗: STALLエラー");
            Err("エンドポイントSTALLエラー")
        }
        TrbCompletionCode::TransactionError => {
            log::error!("USB転送失敗: トランザクションエラー");
            Err("USBトランザクションエラー")
        }
        TrbCompletionCode::BabbleDetectedError => {
            log::error!("USB転送失敗: バブルエラー");
            Err("USBバブルエラー")
        }
        _ => {
            log::error!("USB転送失敗: 不明なエラー（コード: {:?}）", completion_result.completion_code);
            Err("USB転送エラー")
        }
    }
}

fn get_slot_id_for_endpoint(&self, endpoint_address: u8) -> Result<u8, &'static str> {
    // エンドポイントアドレスからスロットIDを取得
    // 実装では、デバイス管理テーブルから検索
    for (slot_id, device) in &self.device_slots {
        if device.has_endpoint(endpoint_address) {
            return Ok(*slot_id);
        }
    }
    
    Err("指定されたエンドポイントのデバイスが見つかりません")
}

fn get_endpoint_context(&self, slot_id: u8, endpoint_address: u8) -> Result<&EndpointContext, &'static str> {
    let device = self.device_slots.get(&slot_id)
        .ok_or("無効なスロットID")?;
    
    device.get_endpoint_context(endpoint_address)
        .ok_or("エンドポイントコンテキストが見つかりません")
}

fn get_trb_ring(&mut self, slot_id: u8, endpoint_address: u8) -> Result<&mut TrbRing, &'static str> {
    let device = self.device_slots.get_mut(&slot_id)
        .ok_or("無効なスロットID")?;
    
    device.get_trb_ring_mut(endpoint_address)
        .ok_or("TRBリングが見つかりません")
}

fn create_transfer_trbs(&self, transfer_type: UsbTransferType, data: &[u8], timeout_ms: u32) -> Result<Vec<TransferTrb>, &'static str> {
    let mut trbs = Vec::new();
    
    match transfer_type {
        UsbTransferType::Control => {
            // Control転送用TRBシーケンス
            trbs.extend(self.create_control_transfer_trbs(data)?);
        }
        UsbTransferType::Bulk => {
            // Bulk転送用TRB
            trbs.extend(self.create_bulk_transfer_trbs(data)?);
        }
        UsbTransferType::Interrupt => {
            // Interrupt転送用TRB
            trbs.extend(self.create_interrupt_transfer_trbs(data, timeout_ms)?);
        }
        UsbTransferType::Isochronous => {
            // Isochronous転送用TRB
            trbs.extend(self.create_isochronous_transfer_trbs(data)?);
        }
    }
    
    Ok(trbs)
}

fn create_control_transfer_trbs(&self, data: &[u8]) -> Result<Vec<TransferTrb>, &'static str> {
    let mut trbs = Vec::new();
    
    if data.len() < 8 {
        return Err("Controlリクエストが短すぎます");
    }
    
    // Setup Stage TRB
    let setup_trb = TransferTrb {
        trb_type: TrbType::SetupStage,
        data_buffer_pointer: data.as_ptr() as u64,
        transfer_length: 8,
        flags: TrbFlags::IMMEDIATE_DATA | TrbFlags::TRANSFER_TYPE_IN,
        cycle_bit: true,
    };
    trbs.push(setup_trb);
    
    // Data Stage TRB (データがある場合)
    if data.len() > 8 {
        let data_trb = TransferTrb {
            trb_type: TrbType::DataStage,
            data_buffer_pointer: (data.as_ptr() as u64) + 8,
            transfer_length: (data.len() - 8) as u32,
            flags: TrbFlags::TRANSFER_TYPE_IN,
            cycle_bit: true,
        };
        trbs.push(data_trb);
    }
    
    // Status Stage TRB
    let status_trb = TransferTrb {
        trb_type: TrbType::StatusStage,
        data_buffer_pointer: 0,
        transfer_length: 0,
        flags: TrbFlags::INTERRUPT_ON_COMPLETION,
        cycle_bit: true,
    };
    trbs.push(status_trb);
    
    Ok(trbs)
}

fn create_bulk_transfer_trbs(&self, data: &[u8]) -> Result<Vec<TransferTrb>, &'static str> {
    let mut trbs = Vec::new();
    let max_transfer_size = 65536; // 64KB
    
    let mut remaining_data = data;
    let mut data_ptr = data.as_ptr() as u64;
    
    while !remaining_data.is_empty() {
        let chunk_size = remaining_data.len().min(max_transfer_size);
        let is_last_chunk = chunk_size == remaining_data.len();
        
        let mut flags = TrbFlags::TRANSFER_TYPE_NORMAL;
        if is_last_chunk {
            flags |= TrbFlags::INTERRUPT_ON_COMPLETION;
        }
        
        let bulk_trb = TransferTrb {
            trb_type: TrbType::Normal,
            data_buffer_pointer: data_ptr,
            transfer_length: chunk_size as u32,
            flags,
            cycle_bit: true,
        };
        trbs.push(bulk_trb);
        
        remaining_data = &remaining_data[chunk_size..];
        data_ptr += chunk_size as u64;
    }
    
    Ok(trbs)
}

fn create_interrupt_transfer_trbs(&self, data: &[u8], timeout_ms: u32) -> Result<Vec<TransferTrb>, &'static str> {
    let mut trbs = Vec::new();
    
    let interrupt_trb = TransferTrb {
        trb_type: TrbType::Normal,
        data_buffer_pointer: data.as_ptr() as u64,
        transfer_length: data.len() as u32,
        flags: TrbFlags::INTERRUPT_ON_COMPLETION | TrbFlags::INTERRUPT_ON_SHORT_PACKET,
        cycle_bit: true,
    };
    trbs.push(interrupt_trb);
    
    Ok(trbs)
}

fn create_isochronous_transfer_trbs(&self, data: &[u8]) -> Result<Vec<TransferTrb>, &'static str> {
    let mut trbs = Vec::new();
    
    // Isochronous転送の実装
    // フレーム番号とタイミング情報を含める
    let frame_number = self.get_current_frame_number();
    
    let iso_trb = TransferTrb {
        trb_type: TrbType::Isoch,
        data_buffer_pointer: data.as_ptr() as u64,
        transfer_length: data.len() as u32,
        flags: TrbFlags::INTERRUPT_ON_COMPLETION,
        cycle_bit: true,
    };
    trbs.push(iso_trb);
    
    Ok(trbs)
}

fn ring_doorbell(&self, slot_id: u8, endpoint_address: u8) -> Result<(), &'static str> {
    // Doorbellレジスタの計算
    let doorbell_offset = slot_id as usize * 4;
    let doorbell_address = self.doorbell_array_base + doorbell_offset;
    
    // エンドポイント番号の計算（xHCI仕様に準拠）
    let endpoint_index = self.calculate_endpoint_index(endpoint_address);
    
    // Doorbellレジスタへの書き込み
    unsafe {
        core::ptr::write_volatile(doorbell_address as *mut u32, endpoint_index as u32);
    }
    
    log::trace!("Doorbell送信: スロット={}, EP={}, インデックス={}", 
               slot_id, endpoint_address, endpoint_index);
    
    Ok(())
}

fn calculate_endpoint_index(&self, endpoint_address: u8) -> u8 {
    // xHCI仕様: EP0 OUT=1, EP0 IN=1, EP1 OUT=2, EP1 IN=3, ...
    let endpoint_number = endpoint_address & 0x0F;
    let direction = (endpoint_address & 0x80) >> 7;
    
    if endpoint_number == 0 {
        1 // Control endpoints
    } else {
        (endpoint_number * 2) + direction
    }
}

fn wait_for_transfer_completion(&mut self, timeout_ms: u32) -> Result<TransferCompletion, &'static str> {
    let start_time = crate::time::current_time_ms();
    let timeout_time = start_time + timeout_ms as u64;
    
    loop {
        // イベントリングをポーリング
        if let Some(event_trb) = self.poll_event_ring() {
            if let Some(completion) = self.process_transfer_event(&event_trb) {
                return Ok(completion);
            }
        }
        
        // タイムアウトチェック
        if crate::time::current_time_ms() > timeout_time {
            return Err("USB転送タイムアウト");
        }
        
        // 短時間待機
        crate::time::sleep_us(100);
    }
}

fn poll_event_ring(&mut self) -> Option<EventTrb> {
    // イベントリングのdequeue pointerをチェック
    let current_trb = self.event_ring.get_current_trb();
    
    // Cycle bitをチェックして新しいイベントがあるか確認
    if current_trb.is_valid() && current_trb.cycle_bit == self.event_ring.cycle_bit {
        let event_trb = current_trb.clone();
        self.event_ring.advance_dequeue_pointer();
        Some(event_trb)
    } else {
        None
    }
}

fn process_transfer_event(&self, event_trb: &EventTrb) -> Option<TransferCompletion> {
    match event_trb.trb_type {
        TrbType::TransferEvent => {
            let completion = TransferCompletion {
                completion_code: event_trb.completion_code,
                transfer_length: event_trb.transfer_length,
                slot_id: event_trb.slot_id,
                endpoint_id: event_trb.endpoint_id,
                event_data: event_trb.event_data,
            };
            Some(completion)
        }
        _ => None,
    }
}

fn get_current_frame_number(&self) -> u32 {
    // MFINDEXレジスタから現在のマイクロフレーム番号を取得
    let mfindex_register = self.operational_registers_base + 0x440;
    unsafe {
        core::ptr::read_volatile(mfindex_register as *const u32) & 0x3FFF
    }
}

// 追加のデータ構造とトレイト実装
#[derive(Debug, Clone)]
pub struct TransferTrb {
    pub trb_type: TrbType,
    pub data_buffer_pointer: u64,
    pub transfer_length: u32,
    pub flags: TrbFlags,
    pub cycle_bit: bool,
}

#[derive(Debug, Clone)]
pub struct EventTrb {
    pub trb_type: TrbType,
    pub completion_code: TrbCompletionCode,
    pub transfer_length: u32,
    pub slot_id: u8,
    pub endpoint_id: u8,
    pub event_data: u64,
    pub cycle_bit: bool,
}

impl EventTrb {
    pub fn is_valid(&self) -> bool {
        self.trb_type != TrbType::Reserved
    }
}

#[derive(Debug, Clone)]
pub struct TransferCompletion {
    pub completion_code: TrbCompletionCode,
    pub transfer_length: usize,
    pub slot_id: u8,
    pub endpoint_id: u8,
    pub event_data: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrbType {
    Reserved = 0,
    Normal = 1,
    SetupStage = 2,
    DataStage = 3,
    StatusStage = 4,
    Isoch = 5,
    Link = 6,
    EventData = 7,
    NoOp = 8,
    TransferEvent = 32,
    CommandCompletion = 33,
    PortStatusChange = 34,
    BandwidthRequest = 35,
    Doorbell = 36,
    HostController = 37,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrbCompletionCode {
    Success = 1,
    DataBufferError = 2,
    BabbleDetectedError = 3,
    TransactionError = 4,
    TrbError = 5,
    StallError = 6,
    ResourceError = 7,
    BandwidthError = 8,
    NoSlotsAvailableError = 9,
    InvalidStreamTypeError = 10,
    SlotNotEnabledError = 11,
    EndpointNotEnabledError = 12,
    ShortPacket = 13,
    RingUnderrun = 14,
    RingOverrun = 15,
    VfEventRingFullError = 16,
    ParameterError = 17,
    BandwidthOverrunError = 18,
    ContextStateError = 19,
    NoPingResponseError = 20,
    EventRingFullError = 21,
    IncompatibleDeviceError = 22,
    MissedServiceError = 23,
    CommandRingStopped = 24,
    CommandAborted = 25,
    Stopped = 26,
    StoppedLengthInvalid = 27,
    StoppedShortPacket = 28,
    MaxExitLatencyTooLargeError = 29,
    IsochBufferOverrun = 31,
    EventLostError = 32,
    UndefinedError = 33,
    InvalidStreamIdError = 34,
    SecondaryBandwidthError = 35,
    SplitTransactionError = 36,
}

bitflags::bitflags! {
    pub struct TrbFlags: u32 {
        const CYCLE_BIT = 1 << 0;
        const EVALUATE_NEXT_TRB = 1 << 1;
        const INTERRUPT_ON_SHORT_PACKET = 1 << 2;
        const NO_SNOOP = 1 << 3;
        const CHAIN_BIT = 1 << 4;
        const INTERRUPT_ON_COMPLETION = 1 << 5;
        const IMMEDIATE_DATA = 1 << 6;
        const TRANSFER_TYPE_NORMAL = 0 << 16;
        const TRANSFER_TYPE_IN = 1 << 16;
        const TRANSFER_TYPE_OUT = 2 << 16;
    }
}

impl UsbDevice {
    pub fn has_endpoint(&self, endpoint_address: u8) -> bool {
        self.endpoints.contains_key(&endpoint_address)
    }
    
    pub fn get_endpoint_context(&self, endpoint_address: u8) -> Option<&EndpointContext> {
        self.endpoints.get(&endpoint_address)
    }
    
    pub fn get_trb_ring_mut(&mut self, endpoint_address: u8) -> Option<&mut TrbRing> {
        if let Some(endpoint) = self.endpoints.get_mut(&endpoint_address) {
            Some(&mut endpoint.trb_ring)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct EndpointContext {
    pub endpoint_type: EndpointType,
    pub max_packet_size: u16,
    pub max_burst_size: u8,
    pub interval: u8,
    pub trb_ring: TrbRing,
}

#[derive(Debug)]
pub enum EndpointType {
    Control,
    IsochOut,
    BulkOut,
    InterruptOut,
    IsochIn,
    BulkIn,
    InterruptIn,
}

#[derive(Debug)]
pub struct TrbRing {
    pub trbs: Vec<TransferTrb>,
    pub enqueue_pointer: usize,
    pub dequeue_pointer: usize,
    pub cycle_bit: bool,
}

impl TrbRing {
    pub fn enqueue_trb(&mut self, trb: &TransferTrb) -> Result<(), &'static str> {
        if self.is_full() {
            return Err("TRBリングが満杯です");
        }
        
        self.trbs[self.enqueue_pointer] = trb.clone();
        self.advance_enqueue_pointer();
        Ok(())
    }
    
    pub fn get_current_trb(&self) -> &TransferTrb {
        &self.trbs[self.dequeue_pointer]
    }
    
    pub fn advance_dequeue_pointer(&mut self) {
        self.dequeue_pointer += 1;
        if self.dequeue_pointer >= self.trbs.len() {
            self.dequeue_pointer = 0;
            self.cycle_bit = !self.cycle_bit;
        }
    }
    
    fn advance_enqueue_pointer(&mut self) {
        self.enqueue_pointer += 1;
        if self.enqueue_pointer >= self.trbs.len() {
            self.enqueue_pointer = 0;
        }
    }
    
    fn is_full(&self) -> bool {
        let next_enqueue = (self.enqueue_pointer + 1) % self.trbs.len();
        next_enqueue == self.dequeue_pointer
    }
}

#[derive(Debug)]
pub struct EventRing {
    pub events: Vec<EventTrb>,
    pub dequeue_pointer: usize,
    pub cycle_bit: bool,
}

impl EventRing {
    pub fn get_current_trb(&self) -> &EventTrb {
        &self.events[self.dequeue_pointer]
    }
    
    pub fn advance_dequeue_pointer(&mut self) {
        self.dequeue_pointer += 1;
        if self.dequeue_pointer >= self.events.len() {
            self.dequeue_pointer = 0;
            self.cycle_bit = !self.cycle_bit;
        }
    }
} 