// AetherOS AArch64 割り込みサブシステム
//
// ARM GIC（Generic Interrupt Controller）を使用した
// 割り込み処理システムを実装します。

pub mod gic;
pub mod vectors;

use core::sync::atomic::{AtomicU32, Ordering};
use crate::sync::{RwLock, SpinLock};
use alloc::vec::Vec;

/// 割り込み種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptType {
    /// 例外
    Exception,
    /// SGI（Software Generated Interrupt）
    SGI,
    /// PPI（Private Peripheral Interrupt）
    PPI,
    /// SPI（Shared Peripheral Interrupt）
    SPI,
    /// LPI（Locality-specific Peripheral Interrupt）GICv3以降
    LPI,
}

/// 割り込みハンドラ情報
#[derive(Clone)]
pub struct InterruptHandler {
    /// ハンドラ関数
    pub handler: fn(),
    /// 割り込み種別
    pub int_type: InterruptType,
    /// 割り込み名
    pub name: &'static str,
    /// 優先度（0-255, 0が最高）
    pub priority: u8,
    /// コア限定（Noneの場合は任意のコアで処理可能）
    pub core_affinity: Option<usize>,
    /// 処理回数
    pub invocation_count: AtomicU32,
    /// 最後の処理時間（ナノ秒）
    pub last_execution_time: AtomicU32,
    /// 平均処理時間（ナノ秒）
    pub average_execution_time: AtomicU32,
}

/// 割り込みコントローラ抽象化
pub trait InterruptController {
    /// 初期化
    fn init(&self);
    
    /// 割り込みを有効化
    fn enable(&self, irq: u32) -> bool;
    
    /// 割り込みを無効化
    fn disable(&self, irq: u32) -> bool;
    
    /// 割り込み優先度を設定
    fn set_priority(&self, irq: u32, priority: u8) -> bool;
    
    /// コア間割り込みを送信（SGI）
    fn send_sgi(&self, target_cpu: usize, sgi_id: u8) -> bool;
    
    /// 割り込み処理完了通知
    fn eoi(&self, irq: u32);
}

/// GICバージョン
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GicVersion {
    /// GICv2
    V2,
    /// GICv3
    V3,
    /// GICv4
    V4,
}

/// 割り込みハンドラテーブル
pub struct InterruptTable {
    /// ハンドラテーブル
    handlers: RwLock<Vec<Option<InterruptHandler>>>,
    /// 割り込み統計情報
    stats: SpinLock<InterruptStats>,
    /// 割り込みコントローラ
    controller: &'static dyn InterruptController,
}

/// 割り込み統計情報
struct InterruptStats {
    /// 各割り込み番号の発生回数
    count_by_vector: Vec<u64>,
    /// 各種類別の割り込み発生回数
    count_by_type: [(InterruptType, u64); 5],
    /// コア別の割り込み処理回数
    count_by_core: Vec<u64>,
    /// 最も頻繁に発生する割り込み番号
    most_frequent: (u32, u64),
    /// 最も処理時間が長い割り込み番号
    longest_processing: (u32, u64),
    /// 最後に発生した割り込み番号
    last_interrupt: u32,
    /// 割り込み処理の総時間
    total_processing_time: u64,
}

impl InterruptTable {
    /// 新しい割り込みテーブルを作成
    pub fn new(controller: &'static dyn InterruptController) -> Self {
        let cpu_count = crate::arch::aarch64::get_cpu_count();
        
        let stats = InterruptStats {
            count_by_vector: vec![0; 1024], // 十分な数の割り込みベクターをサポート
            count_by_type: [
                (InterruptType::Exception, 0),
                (InterruptType::SGI, 0),
                (InterruptType::PPI, 0),
                (InterruptType::SPI, 0),
                (InterruptType::LPI, 0),
            ],
            count_by_core: vec![0; cpu_count],
            most_frequent: (0, 0),
            longest_processing: (0, 0),
            last_interrupt: 0,
            total_processing_time: 0,
        };
        
        Self {
            handlers: RwLock::new(vec![None; 1024]),
            stats: SpinLock::new(stats),
            controller,
        }
    }
    
    /// 割り込みハンドラを登録
    pub fn register_handler(&self, irq: u32, handler: fn(), int_type: InterruptType, name: &'static str) -> bool {
        if irq as usize >= self.handlers.read().len() {
            return false;
        }
        
        let mut handlers = self.handlers.write();
        
        // 既存のハンドラがある場合は上書き
        handlers[irq as usize] = Some(InterruptHandler {
            handler,
            int_type,
            name,
            priority: match int_type {
                InterruptType::Exception => 0, // 最高優先度
                InterruptType::SGI => 32,
                InterruptType::PPI => 64,
                InterruptType::SPI => 128,
                InterruptType::LPI => 192,
            },
            core_affinity: None,
            invocation_count: AtomicU32::new(0),
            last_execution_time: AtomicU32::new(0),
            average_execution_time: AtomicU32::new(0),
        });
        
        // 割り込みコントローラを通じて割り込みを有効化
        self.controller.enable(irq)
    }
    
    /// 割り込み処理を記録
    pub fn record_interrupt(&self, irq: u32, processing_time: u64) {
        let mut stats = self.stats.lock();
        let cpu_id = crate::arch::aarch64::get_current_cpu_id();
        
        // 統計情報を更新
        if irq as usize < stats.count_by_vector.len() {
            stats.count_by_vector[irq as usize] += 1;
        }
        
        if cpu_id < stats.count_by_core.len() {
            stats.count_by_core[cpu_id] += 1;
        }
        
        stats.last_interrupt = irq;
        stats.total_processing_time += processing_time;
        
        // 最も頻繁な割り込みを更新
        if irq as usize < stats.count_by_vector.len() && stats.count_by_vector[irq as usize] > stats.most_frequent.1 {
            stats.most_frequent = (irq, stats.count_by_vector[irq as usize]);
        }
        
        // 最も処理時間が長い割り込みを更新
        if processing_time > stats.longest_processing.1 {
            stats.longest_processing = (irq, processing_time);
        }
        
        // ハンドラの統計情報も更新
        if irq as usize < self.handlers.read().len() {
            if let Some(handler) = &self.handlers.read()[irq as usize] {
                let count = handler.invocation_count.fetch_add(1, Ordering::Relaxed) + 1;
                handler.last_execution_time.store(processing_time as u32, Ordering::Relaxed);
                
                // 指数移動平均で平均処理時間を更新
                let old_avg = handler.average_execution_time.load(Ordering::Relaxed);
                let new_avg = if old_avg == 0 {
                    processing_time as u32
                } else {
                    ((old_avg as u64 * 7 + processing_time as u64) / 8) as u32
                };
                handler.average_execution_time.store(new_avg, Ordering::Relaxed);
                
                // タイプ別カウントも更新
                match handler.int_type {
                    InterruptType::Exception => stats.count_by_type[0].1 += 1,
                    InterruptType::SGI => stats.count_by_type[1].1 += 1,
                    InterruptType::PPI => stats.count_by_type[2].1 += 1,
                    InterruptType::SPI => stats.count_by_type[3].1 += 1,
                    InterruptType::LPI => stats.count_by_type[4].1 += 1,
                }
            }
        }
    }
}

/// グローバル割り込みテーブル
static mut INTERRUPT_TABLE: Option<InterruptTable> = None;

/// 割り込みサブシステムを初期化
pub fn init() {
    // GICを初期化（検出されたバージョンに応じて）
    gic::init();
    
    // 例外ベクタテーブルを設定
    vectors::init();
    
    log::info!("AArch64割り込みサブシステム初期化完了");
}

/// 割り込みを有効化
pub fn enable_irq(irq: u32) -> bool {
    unsafe {
        if let Some(table) = &INTERRUPT_TABLE {
            table.controller.enable(irq)
        } else {
            false
        }
    }
}

/// 割り込みを無効化
pub fn disable_irq(irq: u32) -> bool {
    unsafe {
        if let Some(table) = &INTERRUPT_TABLE {
            table.controller.disable(irq)
        } else {
            false
        }
    }
} 