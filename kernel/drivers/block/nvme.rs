// NVMeドライバーモジュール
// AetherOS用高性能NVMeストレージドライバー実装
// 作成者: AetherOSチーム

//! # NVMeドライバー
//! 
//! このモジュールは、NVM Express (NVMe) ストレージデバイス向けの高性能ドライバーを提供します。
//! PCIeインターフェースを介して接続されたSSDやNVMeデバイスにアクセスするための機能を実装しています。

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::{Mutex, RwLock};

use crate::drivers::pci::{PciDevice, PciClass};
use crate::mm::{MemoryManager, PhysAddr, VirtAddr};
use crate::sync::OnceCell;

/// NVMeレジスタオフセット
const NVME_REG_CAP: usize = 0x0000;       // Controller Capabilities
const NVME_REG_VS: usize = 0x0008;        // Version
const NVME_REG_INTMS: usize = 0x000C;     // Interrupt Mask Set
const NVME_REG_INTMC: usize = 0x0010;     // Interrupt Mask Clear
const NVME_REG_CC: usize = 0x0014;        // Controller Configuration
const NVME_REG_CSTS: usize = 0x001C;      // Controller Status
const NVME_REG_NSSR: usize = 0x0020;      // NVM Subsystem Reset
const NVME_REG_AQA: usize = 0x0024;       // Admin Queue Attributes
const NVME_REG_ASQ: usize = 0x0028;       // Admin Submission Queue Base Address
const NVME_REG_ACQ: usize = 0x0030;       // Admin Completion Queue Base Address
const NVME_REG_CMBLOC: usize = 0x0038;    // Controller Memory Buffer Location
const NVME_REG_CMBSZ: usize = 0x003C;     // Controller Memory Buffer Size
const NVME_REG_SQ0TDBL: usize = 0x1000;   // Submission Queue 0 Tail Doorbell
const NVME_REG_CQ0HDBL: usize = 0x1004;   // Completion Queue 0 Head Doorbell

/// NVMeコントローラー設定レジスタ (CC) のビットマスク
const NVME_CC_EN: u32 = 1 << 0;           // Enable
const NVME_CC_CSS_NVM: u32 = 0 << 4;      // I/O Command Set: NVM
const NVME_CC_MPS_SHIFT: u32 = 7;         // Memory Page Size shift
const NVME_CC_AMS_RR: u32 = 0 << 11;      // Arbitration Mechanism: Round Robin
const NVME_CC_SHN_NONE: u32 = 0 << 14;    // Shutdown Notification: None
const NVME_CC_IOSQES_SHIFT: u32 = 16;     // I/O Submission Queue Entry Size shift
const NVME_CC_IOCQES_SHIFT: u32 = 20;     // I/O Completion Queue Entry Size shift

/// NVMeコントローラーステータスレジスタ (CSTS) のビットマスク
const NVME_CSTS_RDY: u32 = 1 << 0;        // Ready
const NVME_CSTS_CFS: u32 = 1 << 1;        // Controller Fatal Status
const NVME_CSTS_SHST_MASK: u32 = 3 << 2;  // Shutdown Status mask
const NVME_CSTS_SHST_NORMAL: u32 = 0 << 2; // Shutdown Status: Normal
const NVME_CSTS_SHST_OCCURRING: u32 = 1 << 2; // Shutdown Status: Occurring
const NVME_CSTS_SHST_COMPLETE: u32 = 2 << 2; // Shutdown Status: Complete

/// NVMe管理コマンドオペコード
const NVME_ADMIN_CMD_DELETE_SQ: u8 = 0x00;  // Delete I/O Submission Queue
const NVME_ADMIN_CMD_CREATE_SQ: u8 = 0x01;  // Create I/O Submission Queue
const NVME_ADMIN_CMD_DELETE_CQ: u8 = 0x04;  // Delete I/O Completion Queue
const NVME_ADMIN_CMD_CREATE_CQ: u8 = 0x05;  // Create I/O Completion Queue
const NVME_ADMIN_CMD_IDENTIFY: u8 = 0x06;   // Identify
const NVME_ADMIN_CMD_ABORT: u8 = 0x08;      // Abort
const NVME_ADMIN_CMD_SET_FEATURES: u8 = 0x09; // Set Features
const NVME_ADMIN_CMD_GET_FEATURES: u8 = 0x0A; // Get Features
const NVME_ADMIN_CMD_ASYNC_EVENT: u8 = 0x0C; // Asynchronous Event Request
const NVME_ADMIN_CMD_NS_MGMT: u8 = 0x0D;    // Namespace Management
const NVME_ADMIN_CMD_FW_COMMIT: u8 = 0x10;  // Firmware Commit
const NVME_ADMIN_CMD_FW_DOWNLOAD: u8 = 0x11; // Firmware Image Download
const NVME_ADMIN_CMD_NS_ATTACH: u8 = 0x15;  // Namespace Attachment
const NVME_ADMIN_CMD_FORMAT_NVM: u8 = 0x80; // Format NVM
const NVME_ADMIN_CMD_SECURITY_SEND: u8 = 0x81; // Security Send
const NVME_ADMIN_CMD_SECURITY_RECV: u8 = 0x82; // Security Receive

/// NVMe I/Oコマンドオペコード
const NVME_CMD_FLUSH: u8 = 0x00;           // Flush
const NVME_CMD_WRITE: u8 = 0x01;           // Write
const NVME_CMD_READ: u8 = 0x02;            // Read
const NVME_CMD_WRITE_UNCORRECTABLE: u8 = 0x04; // Write Uncorrectable
const NVME_CMD_COMPARE: u8 = 0x05;         // Compare
const NVME_CMD_WRITE_ZEROES: u8 = 0x08;    // Write Zeroes
const NVME_CMD_DATASET_MANAGEMENT: u8 = 0x09; // Dataset Management

/// NVMeアイデンティファイコントローラーデータ構造 (簡略化)
#[derive(Debug, Clone)]
#[repr(C, packed)]
pub struct NvmeIdCtrl {
    /// PCI Vendor ID
    pub vid: u16,
    /// PCI Subsystem Vendor ID
    pub ssvid: u16,
    /// シリアル番号
    pub sn: [u8; 20],
    /// モデル番号
    pub mn: [u8; 40],
    /// ファームウェアリビジョン
    pub fr: [u8; 8],
    /// 推奨Arbitration Burst
    pub rab: u8,
    /// IEEE OUI Identifier
    pub ieee: [u8; 3],
    /// マルチパスI/O機能
    pub mic: u8,
    /// 最大データ転送サイズ
    pub mdts: u8,
    /// コントローラーID
    pub cntlid: u16,
    /// バージョン
    pub ver: u32,
    /// RTD3レジューム遅延
    pub rtd3r: u32,
    /// RTD3エントリー遅延
    pub rtd3e: u32,
    /// オプション非同期イベント
    pub oaes: u32,
    /// コントローラー属性
    pub ctratt: u32,
    /// 予約済み
    pub reserved: [u8; 100],
    /// ネームスペース数
    pub nn: u32,
    /// オプションNVMコマンドサポート
    pub oncs: u16,
    /// Firmware Update機能
    pub fuses: u16,
    /// Format NVM属性
    pub fna: u8,
    /// 揮発性書き込みキャッシュ
    pub vwc: u8,
    /// Atomic Write Unit Normal
    pub awun: u16,
    /// Atomic Write Unit Power Fail
    pub awupf: u16,
    /// NVMベンダー固有コマンド設定
    pub nvscc: u8,
    /// ネームスペースの見直しをサポート
    pub nwpc: u8,
    /// 共通ネームスペース属性
    pub acwu: u16,
    /// 予約済み
    pub reserved2: [u8; 384],
    /// サブシステムのリセットによって削除されないキュー
    pub sqes: u8,
    /// サブシステムのリセットによって削除されないキュー
    pub cqes: u8,
    /// 予約済み
    pub reserved3: [u8; 2046],
}

/// NVMeコマンド
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct NvmeCommand {
    /// コマンドDWORD 0
    pub cdw0: u32,
    /// ネームスペースID
    pub nsid: u32,
    /// 予約済み
    pub cdw2: u32,
    /// 予約済み
    pub cdw3: u32,
    /// メタデータポインター
    pub mptr: u64,
    /// データポインター
    pub dptr: [u64; 2],
    /// コマンドDWORD 10
    pub cdw10: u32,
    /// コマンドDWORD 11
    pub cdw11: u32,
    /// コマンドDWORD 12
    pub cdw12: u32,
    /// コマンドDWORD 13
    pub cdw13: u32,
    /// コマンドDWORD 14
    pub cdw14: u32,
    /// コマンドDWORD 15
    pub cdw15: u32,
}

impl NvmeCommand {
    /// 新しいNVMeコマンドを作成
    pub fn new() -> Self {
        Self {
            cdw0: 0,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            dptr: [0, 0],
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }
    
    /// オペコードとコマンドIDを設定
    pub fn set_opcode_and_cid(&mut self, opcode: u8, cid: u16) {
        self.cdw0 = ((cid as u32) << 16) | (opcode as u32);
    }
    
    /// ネームスペースIDを設定
    pub fn set_nsid(&mut self, nsid: u32) {
        self.nsid = nsid;
    }
    
    /// PRPエントリを設定（物理領域ページ）
    pub fn set_prp_entries(&mut self, prp1: u64, prp2: u64) {
        self.dptr[0] = prp1;
        self.dptr[1] = prp2;
    }
}

/// NVMe完了エントリ
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct NvmeCompletion {
    /// コマンド固有
    pub cdw0: u32,
    /// 予約済み
    pub cdw1: u32,
    /// サブミッションキューヘッドポインター
    pub sqhd: u16,
    /// サブミッションキューID
    pub sqid: u16,
    /// コマンドID
    pub cid: u16,
    /// フェーズタグ
    pub status: u16,
}

/// NVMeキュー
pub struct NvmeQueue {
    /// キューID
    pub id: u16,
    /// エントリ数
    pub size: u32,
    /// 物理ベースアドレス
    pub phys_addr: PhysAddr,
    /// 仮想ベースアドレス
    pub virt_addr: VirtAddr,
    /// ドアベルレジスタのオフセット
    pub doorbell: usize,
    /// ヘッドインデックス
    pub head: AtomicU32,
    /// テールインデックス
    pub tail: AtomicU32,
    /// フェーズタグ
    pub phase: AtomicBool,
}

impl NvmeQueue {
    /// 新しいNVMeキューを作成
    pub fn new(id: u16, size: u32, doorbell: usize) -> Result<Self, &'static str> {
        // サイズは2の累乗である必要がある
        if !size.is_power_of_two() || size > 4096 {
            return Err("NVMeキューのサイズは2の累乗で4096以下である必要があります");
        }
        
        // キュー用のメモリを割り当て
        let alloc_size = size as usize * 64; // 各エントリは64バイト
        let (virt_addr, phys_addr) = MemoryManager::allocate_dma_buffer(alloc_size)
            .map_err(|_| "NVMeキュー用のDMAバッファの割り当てに失敗しました")?;
        
        // メモリをゼロクリア
        unsafe {
            core::ptr::write_bytes(virt_addr as *mut u8, 0, alloc_size);
        }
        
        Ok(Self {
            id,
            size,
            phys_addr,
            virt_addr,
            doorbell,
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            phase: AtomicBool::new(true),
        })
    }
    
    /// キューのサイズを取得
    pub fn get_size(&self) -> u32 {
        self.size
    }
    
    /// キューが空かどうかを確認
    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Relaxed) == self.tail.load(Ordering::Relaxed)
    }
    
    /// キューが満杯かどうかを確認
    pub fn is_full(&self) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        
        (tail + 1) % self.size == head
    }
}

/// NVMeレジスタにアクセスするためのラッパー
struct NvmeRegisters {
    /// ベースアドレス（仮想アドレス）
    base: *mut u8,
    /// Admin Submission Queue
    admin_sq: Mutex<Option<NvmeQueue>>,
    /// Admin Completion Queue
    admin_cq: Mutex<Option<NvmeQueue>>,
}

impl NvmeRegisters {
    /// 新しいNVMeレジスタセットを作成
    pub unsafe fn new(base_addr: *mut u8) -> Self {
        Self {
            base: base_addr,
            admin_sq: Mutex::new(None),
            admin_cq: Mutex::new(None),
        }
    }
    
    /// レジスタを読み取る
    pub fn read_reg(&self, offset: usize) -> u32 {
        unsafe {
            *(self.base.add(offset) as *const u32)
        }
    }
    
    /// レジスタに書き込む
    pub fn write_reg(&self, offset: usize, value: u32) {
        unsafe {
            *(self.base.add(offset) as *mut u32) = value;
        }
    }
    
    /// 64ビットレジスタを読み取る
    pub fn read_reg64(&self, offset: usize) -> u64 {
        unsafe {
            *(self.base.add(offset) as *const u64)
        }
    }
    
    /// 64ビットレジスタに書き込む
    pub fn write_reg64(&self, offset: usize, value: u64) {
        unsafe {
            *(self.base.add(offset) as *mut u64) = value;
        }
    }
    
    /// コントローラーのCAPレジスタを取得
    pub fn get_cap(&self) -> u64 {
        self.read_reg64(NVME_REG_CAP)
    }
    
    /// コントローラーのバージョンを取得
    pub fn get_version(&self) -> u32 {
        self.read_reg(NVME_REG_VS)
    }
    
    /// CC（Controller Configuration）レジスタを取得
    pub fn get_cc(&self) -> u32 {
        self.read_reg(NVME_REG_CC)
    }
    
    /// CC（Controller Configuration）レジスタを設定
    pub fn set_cc(&self, value: u32) {
        self.write_reg(NVME_REG_CC, value)
    }
    
    /// CSTS（Controller Status）レジスタを取得
    pub fn get_csts(&self) -> u32 {
        self.read_reg(NVME_REG_CSTS)
    }
    
    /// AQA（Admin Queue Attributes）レジスタを設定
    pub fn set_aqa(&self, sq_size: u16, cq_size: u16) {
        let value = ((cq_size as u32) << 16) | (sq_size as u32);
        self.write_reg(NVME_REG_AQA, value);
    }
    
    /// ASQ（Admin Submission Queue Base Address）レジスタを設定
    pub fn set_asq(&self, addr: u64) {
        self.write_reg64(NVME_REG_ASQ, addr);
    }
    
    /// ACQ（Admin Completion Queue Base Address）レジスタを設定
    pub fn set_acq(&self, addr: u64) {
        self.write_reg64(NVME_REG_ACQ, addr);
    }
    
    /// ドアベルレジスタを鳴らす
    pub fn ring_doorbell(&self, doorbell: usize, value: u32) {
        self.write_reg(doorbell, value);
    }
    
    /// SQのテールドアベルをリング
    pub fn ring_sq_doorbell(&self, queue_id: u16, tail: u32) {
        let doorbell = NVME_REG_SQ0TDBL + (queue_id as usize * 8);
        self.ring_doorbell(doorbell, tail);
    }
    
    /// CQのヘッドドアベルをリング
    pub fn ring_cq_doorbell(&self, queue_id: u16, head: u32) {
        let doorbell = NVME_REG_CQ0HDBL + (queue_id as usize * 8);
        self.ring_doorbell(doorbell, head);
    }
}

/// NVMeコントローラー
pub struct NvmeController {
    /// 使用するPCIデバイス
    pci_device: Arc<PciDevice>,
    /// NVMeレジスタ
    registers: Mutex<Option<NvmeRegisters>>,
    /// 初期化完了フラグ
    initialized: AtomicBool,
    /// コントローラーID
    controller_id: AtomicU32,
    /// 次のコマンドID
    next_cmd_id: AtomicU32,
}

impl NvmeController {
    /// 新しいNVMeコントローラーを作成
    pub fn new(pci_device: Arc<PciDevice>) -> Self {
        Self {
            pci_device,
            registers: Mutex::new(None),
            initialized: AtomicBool::new(false),
            controller_id: AtomicU32::new(0),
            next_cmd_id: AtomicU32::new(0),
        }
    }
    
    /// NVMeコントローラーを初期化
    pub fn initialize(&self) -> Result<(), &'static str> {
        if self.initialized.load(Ordering::SeqCst) {
            return Ok(());
        }
        
        // PCIデバイスのメモリバーを見つける
        let bar = self.pci_device.read_bar(0).ok_or("NVMeコントローラーのBARが見つかりません")?;
        
        if !bar.is_memory {
            return Err("NVMeコントローラーはメモリマップドI/Oをサポートしている必要があります");
        }
        
        // メモリ空間アクセスとバスマスタリングを有効化
        self.pci_device.enable_memory_space();
        self.pci_device.enable_bus_mastering();
        
        // ベースアドレスをマップ
        let phys_addr = bar.address.as_u64();
        let virt_addr = MemoryManager::map_device_memory(phys_addr, bar.size as usize)
            .map_err(|_| "NVMeレジスタマッピングに失敗しました")?;
        
        // レジスタ構造体を初期化
        let registers = unsafe { NvmeRegisters::new(virt_addr as *mut u8) };
        
        // コントローラー情報を表示
        let version = registers.get_version();
        log::info!(
            "NVMeコントローラー: バージョン {}.{}.{}",
            (version >> 16) & 0xFF,
            (version >> 8) & 0xFF,
            version & 0xFF
        );
        
        // コントローラーをリセット
        self.reset_controller(&registers)?;
        
        // 管理キューを設定
        self.setup_admin_queues(&registers)?;
        
        // コントローラーを有効化
        self.enable_controller(&registers)?;
        
        // コントローラー情報を取得（Identify Controller）
        // TODO: Identify Controllerコマンドを実装
        
        // レジスタを保存
        *self.registers.lock() = Some(registers);
        
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }
    
    /// コントローラーをリセット
    fn reset_controller(&self, registers: &NvmeRegisters) -> Result<(), &'static str> {
        // コントローラー設定を取得
        let mut cc = registers.get_cc();
        
        // コントローラーが有効なら無効化
        if (cc & NVME_CC_EN) != 0 {
            // ENビットをクリア
            cc &= !NVME_CC_EN;
            registers.set_cc(cc);
            
            // コントローラーが無効になるのを待つ
            let mut timeout = 500; // 最大5秒待機
            while (registers.get_csts() & NVME_CSTS_RDY) != 0 && timeout > 0 {
                // 10ミリ秒待機
                // TODO: スリープ関数を実装
                for _ in 0..1000000 {
                    core::hint::spin_loop();
                }
                timeout -= 1;
            }
            
            if timeout == 0 {
                return Err("NVMeコントローラーの無効化がタイムアウトしました");
            }
        }
        
        Ok(())
    }
    
    /// 管理キューを設定
    fn setup_admin_queues(&self, registers: &NvmeRegisters) -> Result<(), &'static str> {
        // Admin Submission Queueを作成
        let admin_sq = NvmeQueue::new(0, 64, NVME_REG_SQ0TDBL)?;
        
        // Admin Completion Queueを作成
        let admin_cq = NvmeQueue::new(0, 64, NVME_REG_CQ0HDBL)?;
        
        // キューサイズを登録
        registers.set_aqa(admin_sq.get_size() as u16 - 1, admin_cq.get_size() as u16 - 1);
        
        // キューベースアドレスを登録
        registers.set_asq(admin_sq.phys_addr.as_u64());
        registers.set_acq(admin_cq.phys_addr.as_u64());
        
        // キューを保存
        *registers.admin_sq.lock() = Some(admin_sq);
        *registers.admin_cq.lock() = Some(admin_cq);
        
        Ok(())
    }
    
    /// コントローラーを有効化
    fn enable_controller(&self, registers: &NvmeRegisters) -> Result<(), &'static str> {
        // CAPレジスタを取得
        let cap = registers.get_cap();
        
        // CCレジスタを設定
        let cc = NVME_CC_EN |  // コントローラー有効化
                NVME_CC_CSS_NVM |  // NVMコマンドセット
                (0 << NVME_CC_MPS_SHIFT) |  // メモリページサイズ：4KiB
                NVME_CC_AMS_RR |  // ラウンドロビン
                NVME_CC_SHN_NONE |  // シャットダウンなし
                (6 << NVME_CC_IOSQES_SHIFT) |  // SQエントリサイズ：64バイト (2^6)
                (4 << NVME_CC_IOCQES_SHIFT);   // CQエントリサイズ：16バイト (2^4)
        
        registers.set_cc(cc);
        
        // コントローラーが有効になるのを待つ
        let mut timeout = 500; // 最大5秒待機
        while (registers.get_csts() & NVME_CSTS_RDY) == 0 && timeout > 0 {
            // 10ミリ秒待機
            // TODO: スリープ関数を実装
            for _ in 0..1000000 {
                core::hint::spin_loop();
            }
            timeout -= 1;
        }
        
        if timeout == 0 {
            return Err("NVMeコントローラーの有効化がタイムアウトしました");
        }
        
        Ok(())
    }
    
    /// 次のコマンドIDを取得
    fn get_next_cmd_id(&self) -> u16 {
        (self.next_cmd_id.fetch_add(1, Ordering::Relaxed) % 0xFFFF) as u16
    }
}

/// NVMeドライバー
pub struct NvmeDriver {
    /// 検出されたコントローラー
    controllers: RwLock<Vec<Arc<NvmeController>>>,
    /// 初期化完了フラグ
    initialized: AtomicBool,
}

impl NvmeDriver {
    /// NVMeドライバーのグローバルインスタンス
    pub static INSTANCE: OnceCell<NvmeDriver> = OnceCell::new();
    
    /// 新しいNVMeドライバーを作成
    pub fn new() -> Self {
        Self {
            controllers: RwLock::new(Vec::new()),
            initialized: AtomicBool::new(false),
        }
    }
    
    /// NVMeドライバーを初期化
    pub fn initialize(&self) -> Result<(), &'static str> {
        if self.initialized.load(Ordering::SeqCst) {
            return Ok(());
        }
        
        log::info!("NVMeドライバーを初期化中...");
        
        // PCIバスからNVMeコントローラーを検出
        self.detect_controllers_from_pci()?;
        
        // 各コントローラーを初期化
        let controllers = self.controllers.read();
        for controller in controllers.iter() {
            if let Err(e) = controller.initialize() {
                log::error!("NVMeコントローラーの初期化に失敗: {}", e);
            }
        }
        
        log::info!("NVMeドライバーの初期化が完了しました");
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }
    
    /// PCIバスからNVMeコントローラーを検出
    fn detect_controllers_from_pci(&self) -> Result<(), &'static str> {
        use crate::drivers::pci::PciSubsystem;
        
        if let Some(pci) = PciSubsystem::INSTANCE.get() {
            // MassStorage (0x01), NVM Express (0x08)
            let nvme_devices = pci.find_devices_by_class(0x01, 0x08);
            
            let mut controllers = self.controllers.write();
            
            for device in nvme_devices {
                log::info!(
                    "NVMeコントローラーを検出: {:?}",
                    device.info.address
                );
                
                let controller = Arc::new(NvmeController::new(device.clone()));
                controllers.push(controller);
            }
            
            if controllers.is_empty() {
                log::warn!("NVMeコントローラーが見つかりませんでした");
            } else {
                log::info!("{} 台のNVMeコントローラーを検出しました", controllers.len());
            }
            
            Ok(())
        } else {
            Err("PCIサブシステムが初期化されていません")
        }
    }
    
    /// すべてのNVMeコントローラーを取得
    pub fn get_controllers(&self) -> Vec<Arc<NvmeController>> {
        let controllers = self.controllers.read();
        controllers.clone()
    }
}

/// NVMeドライバーの初期化
pub fn init() -> Result<(), &'static str> {
    let driver = NvmeDriver::new();
    driver.initialize()?;
    
    // グローバルインスタンスを設定
    NvmeDriver::INSTANCE.set(driver)
        .map_err(|_| "NVMeドライバーの初期化に失敗しました")?;
    
    Ok(())
}

/// NVMe関連の診断情報を出力
pub fn print_diagnostic_info() {
    if let Some(nvme) = NvmeDriver::INSTANCE.get() {
        let controllers = nvme.get_controllers();
        
        log::info!("NVMeコントローラー一覧 ({} 台見つかりました):", controllers.len());
        
        for (i, controller) in controllers.iter().enumerate() {
            log::info!(
                "  コントローラー #{}: PCI {:?}",
                i,
                controller.pci_device.info.address
            );
        }
    } else {
        log::warn!("NVMeドライバーが初期化されていません");
    }
} 