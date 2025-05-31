// AetherOS AArch64 Generic Interrupt Controller (GIC) ドライバ
//
// ARMアーキテクチャの割り込みコントローラ（GIC）の実装

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};
use crate::core::sync::SpinLock;
use alloc::vec::Vec;

// GICレジスタオフセット
const GICD_CTLR: usize = 0x0000; // Distributor Control Register
const GICD_TYPER: usize = 0x0004; // Interrupt Controller Type Register
const GICD_IIDR: usize = 0x0008; // Distributor Implementer Identification Register
const GICD_IGROUPR: usize = 0x0080; // Interrupt Group Registers
const GICD_ISENABLER: usize = 0x0100; // Interrupt Set-Enable Registers
const GICD_ICENABLER: usize = 0x0180; // Interrupt Clear-Enable Registers
const GICD_ISPENDR: usize = 0x0200; // Interrupt Set-Pending Registers
const GICD_ICPENDR: usize = 0x0280; // Interrupt Clear-Pending Registers
const GICD_ISACTIVER: usize = 0x0300; // Interrupt Set-Active Registers
const GICD_ICACTIVER: usize = 0x0380; // Interrupt Clear-Active Registers
const GICD_IPRIORITYR: usize = 0x0400; // Interrupt Priority Registers
const GICD_ITARGETSR: usize = 0x0800; // Interrupt Processor Targets Registers
const GICD_ICFGR: usize = 0x0C00; // Interrupt Configuration Registers
const GICD_SGIR: usize = 0x0F00; // Software Generated Interrupt Register

const GICC_CTLR: usize = 0x0000; // CPU Interface Control Register
const GICC_PMR: usize = 0x0004; // Interrupt Priority Mask Register
const GICC_BPR: usize = 0x0008; // Binary Point Register
const GICC_IAR: usize = 0x000C; // Interrupt Acknowledge Register
const GICC_EOIR: usize = 0x0010; // End of Interrupt Register
const GICC_RPR: usize = 0x0014; // Running Priority Register
const GICC_HPPIR: usize = 0x0018; // Highest Priority Pending Interrupt Register
const GICC_ABPR: usize = 0x001C; // Aliased Binary Point Register
const GICC_AIAR: usize = 0x0020; // Aliased Interrupt Acknowledge Register
const GICC_AEOIR: usize = 0x0024; // Aliased End of Interrupt Register
const GICC_AHPPIR: usize = 0x0028; // Aliased Highest Priority Pending Interrupt Register

// GIC v3のレジスタオフセット
const ICC_IAR1_EL1: u32 = 0xc643; // Interrupt Acknowledge Register
const ICC_EOIR1_EL1: u32 = 0xc65b; // End of Interrupt Register
const ICC_SGI1R_EL1: u32 = 0xc65d; // SGI Generate Register
const ICC_PMR_EL1: u32 = 0xc230; // Priority Mask Register
const ICC_CTLR_EL1: u32 = 0xc664; // Control Register
const ICC_SRE_EL1: u32 = 0xc665; // System Register Enable
const ICC_IGRPEN1_EL1: u32 = 0xc666; // Interrupt Group 1 Enable

/// GICのバージョン
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum GicVersion {
    /// GIC v2
    V2,
    /// GIC v3
    V3,
    /// GIC v4
    V4,
}

/// 割り込みハンドラのタイプ
pub type InterruptHandler = fn(irq: u32) -> ();

/// GICドライバ
pub struct Gic {
    /// GICのバージョン
    version: GicVersion,
    /// GIC Distributor (GICD) のベースアドレス
    gicd_base: usize,
    /// GIC CPU Interface (GICC) のベースアドレス (GICv2用)
    gicc_base: Option<usize>,
    /// 割り込みの数
    irq_count: u32,
    /// 割り込みハンドラテーブル
    handlers: SpinLock<Vec<Option<InterruptHandler>>>,
}

impl Gic {
    /// 新しいGICインスタンスを作成
    pub fn new(gicd_base: usize, gicc_base: Option<usize>, version: GicVersion) -> Self {
        let mut gic = Self {
            version,
            gicd_base,
            gicc_base,
            irq_count: 0,
            handlers: SpinLock::new(Vec::new()),
        };
        
        // GICDのTYPERレジスタから割り込み数を取得
        let typer = gic.gicd_read(GICD_TYPER);
        let lines = ((typer & 0x1F) + 1) * 32;
        gic.irq_count = lines;
        
        // ハンドラテーブルを初期化
        let mut handlers = gic.handlers.lock();
        handlers.resize_with(lines as usize, || None);
        
        gic
    }
    
    /// GICを初期化
    pub fn init(&self) {
        match self.version {
            GicVersion::V2 => self.init_v2(),
            GicVersion::V3 | GicVersion::V4 => self.init_v3(),
        }
    }
    
    /// GICv2を初期化
    fn init_v2(&self) {
        if let Some(gicc_base) = self.gicc_base {
            // Distributor初期化
            // グループ1の割り込みを有効化
            self.gicd_write(GICD_CTLR, 1);
            
            // すべての割り込みを無効化
            for i in 0..((self.irq_count / 32) as usize) {
                self.gicd_write(GICD_ICENABLER + i * 4, 0xFFFF_FFFF);
            }
            
            // すべての割り込みの保留状態をクリア
            for i in 0..((self.irq_count / 32) as usize) {
                self.gicd_write(GICD_ICPENDR + i * 4, 0xFFFF_FFFF);
            }
            
            // すべての割り込みの優先度を最低に設定
            for i in 0..(self.irq_count as usize) {
                self.gicd_write8(GICD_IPRIORITYR + i, 0xFF);
            }
            
            // CPU Interface初期化
            // 優先度マスクを設定（すべての優先度を許可）
            self.gicc_write(GICC_PMR, 0xFF);
            
            // バイナリポイントレジスタを設定
            self.gicc_write(GICC_BPR, 0);
            
            // CPU Interfaceを有効化
            self.gicc_write(GICC_CTLR, 1);
        }
    }
    
    /// GICv3を初期化
    fn init_v3(&self) {
        // Distributor初期化
        // グループ1の割り込みを有効化
        self.gicd_write(GICD_CTLR, 2); // Enable affinity routing
        
        // すべての割り込みを無効化
        for i in 0..((self.irq_count / 32) as usize) {
            self.gicd_write(GICD_ICENABLER + i * 4, 0xFFFF_FFFF);
        }
        
        // すべての割り込みの保留状態をクリア
        for i in 0..((self.irq_count / 32) as usize) {
            self.gicd_write(GICD_ICPENDR + i * 4, 0xFFFF_FFFF);
        }
        
        // システムレジスタによるCPU Interface初期化
        unsafe {
            // システムレジスタアクセスを有効化
            core::arch::asm!("msr S3_0_C12_C12_5, {}", in(reg) 0x7);
            
            // 優先度マスクを設定（すべての優先度を許可）
            core::arch::asm!("msr S3_0_C4_C6_0, {}", in(reg) 0xFF);
            
            // 割り込みグループ1を有効化
            core::arch::asm!("msr S3_0_C12_C12_7, {}", in(reg) 0x1);
        }
    }
    
    /// 割り込みハンドラを登録
    pub fn register_handler(&self, irq: u32, handler: InterruptHandler) -> Result<(), &'static str> {
        if irq >= self.irq_count {
            return Err("無効な割り込み番号");
        }
        
        let mut handlers = self.handlers.lock();
        handlers[irq as usize] = Some(handler);
        
        Ok(())
    }
    
    /// 割り込みを有効化
    pub fn enable_irq(&self, irq: u32) -> Result<(), &'static str> {
        if irq >= self.irq_count {
            return Err("無効な割り込み番号");
        }
        
        let reg_offset = GICD_ISENABLER + ((irq / 32) as usize) * 4;
        let bit = 1 << (irq % 32);
        self.gicd_write(reg_offset, bit);
        
        Ok(())
    }
    
    /// 割り込みを無効化
    pub fn disable_irq(&self, irq: u32) -> Result<(), &'static str> {
        if irq >= self.irq_count {
            return Err("無効な割り込み番号");
        }
        
        let reg_offset = GICD_ICENABLER + ((irq / 32) as usize) * 4;
        let bit = 1 << (irq % 32);
        self.gicd_write(reg_offset, bit);
        
        Ok(())
    }
    
    /// 割り込みの優先度を設定
    pub fn set_priority(&self, irq: u32, priority: u8) -> Result<(), &'static str> {
        if irq >= self.irq_count {
            return Err("無効な割り込み番号");
        }
        
        let reg_offset = GICD_IPRIORITYR + (irq as usize);
        self.gicd_write8(reg_offset, priority);
        
        Ok(())
    }
    
    /// 割り込みを処理
    pub fn handle_irq(&self) {
        match self.version {
            GicVersion::V2 => self.handle_irq_v2(),
            GicVersion::V3 | GicVersion::V4 => self.handle_irq_v3(),
        }
    }
    
    /// GICv2割り込み処理
    fn handle_irq_v2(&self) {
        if let Some(gicc_base) = self.gicc_base {
            // 割り込みを確認
            let iar = self.gicc_read(GICC_IAR);
            let irq = iar & 0x3FF; // 下位10ビットが割り込み番号
            
            if irq < 1022 {  // 特殊な値（1022, 1023）でなければ
                // 対応するハンドラを呼び出し
                let handlers = self.handlers.lock();
                if let Some(handler) = handlers[irq as usize] {
                    handler(irq);
                }
                
                // 割り込み終了を通知
                self.gicc_write(GICC_EOIR, iar);
            }
        }
    }
    
    /// GICv3割り込み処理
    fn handle_irq_v3(&self) {
        // システムレジスタから割り込みを確認
        let iar: u32;
        unsafe { core::arch::asm!("mrs {}, S3_0_C12_C12_0", out(reg) iar); }
        
        let irq = iar & 0xFFFFFF; // 下位24ビットが割り込み番号
        
        if irq < 1020 {  // 特殊な値でなければ
            // 対応するハンドラを呼び出し
            let handlers = self.handlers.lock();
            if let Some(handler) = handlers[irq as usize] {
                handler(irq);
            }
            
            // 割り込み終了を通知
            unsafe { core::arch::asm!("msr S3_0_C12_C12_1, {}", in(reg) iar); }
        }
    }
    
    /// ソフトウェア生成割り込み（SGI）を送信
    pub fn send_sgi(&self, cpu_target: u8, sgi_id: u8) -> Result<(), &'static str> {
        if sgi_id > 15 {
            return Err("無効なSGI ID");
        }
        
        match self.version {
            GicVersion::V2 => {
                if let Some(_) = self.gicc_base {
                    // GICv2: GICD_SGIRレジスタを使用
                    let value = ((cpu_target as u32) << 16) | (sgi_id as u32);
                    self.gicd_write(GICD_SGIR, value);
                    Ok(())
                } else {
                    Err("GICC未設定")
                }
            },
            GicVersion::V3 | GicVersion::V4 => {
                // GICv3: システムレジスタICC_SGI1R_EL1を使用
                let value = ((cpu_target as u64) << 16) | (sgi_id as u64);
                unsafe { core::arch::asm!("msr S3_0_C12_C11_5, {}", in(reg) value); }
                Ok(())
            }
        }
    }
    
    // GICD（Distributor）レジスタ読み込み
    fn gicd_read(&self, offset: usize) -> u32 {
        unsafe { read_volatile((self.gicd_base + offset) as *const u32) }
    }
    
    // GICD（Distributor）レジスタ書き込み
    fn gicd_write(&self, offset: usize, value: u32) {
        unsafe { 
            write_volatile((self.gicd_base + offset) as *mut u32, value);
            fence(Ordering::SeqCst);
        }
    }
    
    // GICD（Distributor）バイト単位レジスタ書き込み
    fn gicd_write8(&self, offset: usize, value: u8) {
        unsafe { 
            write_volatile((self.gicd_base + offset) as *mut u8, value);
            fence(Ordering::SeqCst);
        }
    }
    
    // GICC（CPU Interface）レジスタ読み込み
    fn gicc_read(&self, offset: usize) -> u32 {
        if let Some(gicc_base) = self.gicc_base {
            unsafe { read_volatile((gicc_base + offset) as *const u32) }
        } else {
            0
        }
    }
    
    // GICC（CPU Interface）レジスタ書き込み
    fn gicc_write(&self, offset: usize, value: u32) {
        if let Some(gicc_base) = self.gicc_base {
            unsafe { 
                write_volatile((gicc_base + offset) as *mut u32, value);
                fence(Ordering::SeqCst);
            }
        }
    }
}

// グローバルGICインスタンス
static mut GIC_INSTANCE: Option<Gic> = None;

/// グローバルGICインスタンスを初期化
pub fn init(gicd_base: usize, gicc_base: Option<usize>, version: GicVersion) {
    unsafe {
        GIC_INSTANCE = Some(Gic::new(gicd_base, gicc_base, version));
        GIC_INSTANCE.as_ref().unwrap().init();
    }
}

/// グローバルGICインスタンスの参照を取得
pub fn instance() -> &'static Gic {
    unsafe {
        GIC_INSTANCE.as_ref().expect("GICが初期化されていません")
    }
}

/// 割り込みハンドラを登録
pub fn register_handler(irq: u32, handler: InterruptHandler) -> Result<(), &'static str> {
    instance().register_handler(irq, handler)
}

/// 割り込みを有効化
pub fn enable_irq(irq: u32) -> Result<(), &'static str> {
    instance().enable_irq(irq)
}

/// 割り込みを無効化
pub fn disable_irq(irq: u32) -> Result<(), &'static str> {
    instance().disable_irq(irq)
}

/// 割り込みの優先度を設定
pub fn set_priority(irq: u32, priority: u8) -> Result<(), &'static str> {
    instance().set_priority(irq, priority)
}

/// 割り込みを処理
pub fn handle_irq() {
    instance().handle_irq();
}

/// ソフトウェア生成割り込み（SGI）を送信
pub fn send_sgi(cpu_target: u8, sgi_id: u8) -> Result<(), &'static str> {
    instance().send_sgi(cpu_target, sgi_id)
} 