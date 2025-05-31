// AetherOS RISC-V 割り込みサブシステム
//
// RISC-V PLIC（Platform-Level Interrupt Controller）と
// CLINT（Core Local Interruptor）を使用した割り込み処理システムを実装します。

pub mod plic;
pub mod clint;
pub mod vectors;

use core::sync::atomic::{AtomicU32, Ordering};
use crate::sync::{RwLock, SpinLock};
use alloc::vec::Vec;

/// 割り込み種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptType {
    /// 例外
    Exception,
    /// タイマー割り込み（マシンモード）
    MTimer,
    /// ソフトウェア割り込み（マシンモード）
    MSoftware,
    /// 外部割り込み（マシンモード）
    MExternal,
    /// タイマー割り込み（スーパーバイザーモード）
    STimer,
    /// ソフトウェア割り込み（スーパーバイザーモード）
    SSoftware,
    /// 外部割り込み（スーパーバイザーモード）
    SExternal,
}

/// 例外コード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionCode {
    /// 命令アドレス整列違反
    InstructionAddressMisaligned = 0,
    /// 命令アクセス障害
    InstructionAccessFault = 1,
    /// 不正な命令
    IllegalInstruction = 2,
    /// ブレークポイント
    Breakpoint = 3,
    /// ロードアドレス整列違反
    LoadAddressMisaligned = 4,
    /// ロードアクセス障害
    LoadAccessFault = 5,
    /// ストアアドレス整列違反
    StoreAddressMisaligned = 6,
    /// ストアアクセス障害
    StoreAccessFault = 7,
    /// ユーザーモードからの環境呼び出し
    EnvironmentCallFromUMode = 8,
    /// スーパーバイザーモードからの環境呼び出し
    EnvironmentCallFromSMode = 9,
    /// ハイパーバイザーモードからの環境呼び出し
    EnvironmentCallFromHMode = 10,
    /// マシンモードからの環境呼び出し
    EnvironmentCallFromMMode = 11,
    /// 命令ページ障害
    InstructionPageFault = 12,
    /// ロードページ障害
    LoadPageFault = 13,
    /// ストアページ障害
    StorePageFault = 15,
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
    /// 優先度（PLIC割り込みのみ適用）
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
    
    /// 割り込み要求をクリア
    fn clear_irq(&self, irq: u32);
}

/// 割り込みハンドラテーブル
pub struct InterruptTable {
    /// ハンドラテーブル（PLICのIRQ番号ベース）
    handlers: RwLock<Vec<Option<InterruptHandler>>>,
    /// 例外ハンドラテーブル
    exception_handlers: [Option<fn(ExceptionCode)>; 16],
    /// 割り込み統計情報
    stats: SpinLock<InterruptStats>,
    /// PLICコントローラ
    plic: &'static dyn InterruptController,
    /// CLINTコントローラ
    clint: &'static dyn InterruptController,
}

/// 割り込み統計情報
struct InterruptStats {
    /// 各割り込み番号の発生回数
    count_by_vector: Vec<u64>,
    /// 各種類別の割り込み発生回数
    count_by_type: [(InterruptType, u64); 7],
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
    pub fn new(plic: &'static dyn InterruptController, clint: &'static dyn InterruptController) -> Self {
        let cpu_count = crate::arch::riscv64::get_cpu_count();
        
        let stats = InterruptStats {
            count_by_vector: vec![0; 1024], // 十分な数の割り込みベクターをサポート
            count_by_type: [
                (InterruptType::Exception, 0),
                (InterruptType::MTimer, 0),
                (InterruptType::MSoftware, 0),
                (InterruptType::MExternal, 0),
                (InterruptType::STimer, 0),
                (InterruptType::SSoftware, 0),
                (InterruptType::SExternal, 0),
            ],
            count_by_core: vec![0; cpu_count],
            most_frequent: (0, 0),
            longest_processing: (0, 0),
            last_interrupt: 0,
            total_processing_time: 0,
        };
        
        Self {
            handlers: RwLock::new(vec![None; 1024]),
            exception_handlers: [None; 16],
            stats: SpinLock::new(stats),
            plic,
            clint,
        }
    }
    
    /// PLICの外部割り込みハンドラを登録
    pub fn register_external_handler(&self, irq: u32, handler: fn(), name: &'static str, priority: u8) -> bool {
        if irq as usize >= self.handlers.read().len() {
            return false;
        }
        
        let mut handlers = self.handlers.write();
        
        // 既存のハンドラがある場合は上書き
        handlers[irq as usize] = Some(InterruptHandler {
            handler,
            int_type: InterruptType::MExternal, // 通常はマシンモード
            name,
            priority,
            core_affinity: None,
            invocation_count: AtomicU32::new(0),
            last_execution_time: AtomicU32::new(0),
            average_execution_time: AtomicU32::new(0),
        });
        
        // PLICに優先度を設定
        self.plic.set_priority(irq, priority);
        
        // 割り込みを有効化
        self.plic.enable(irq)
    }
    
    /// 例外ハンドラを登録
    pub fn register_exception_handler(&mut self, code: ExceptionCode, handler: fn(ExceptionCode)) -> bool {
        let code_idx = code as usize;
        if code_idx >= self.exception_handlers.len() {
            return false;
        }
        
        self.exception_handlers[code_idx] = Some(handler);
        true
    }
    
    /// 割り込み処理を記録
    pub fn record_interrupt(&self, irq: u32, int_type: InterruptType, processing_time: u64) {
        let mut stats = self.stats.lock();
        let hart_id = crate::arch::riscv64::get_current_cpu_id();
        
        // 統計情報を更新
        if irq as usize < stats.count_by_vector.len() {
            stats.count_by_vector[irq as usize] += 1;
        }
        
        if hart_id < stats.count_by_core.len() {
            stats.count_by_core[hart_id] += 1;
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
        
        // 種別別カウントを更新
        match int_type {
            InterruptType::Exception => stats.count_by_type[0].1 += 1,
            InterruptType::MTimer => stats.count_by_type[1].1 += 1,
            InterruptType::MSoftware => stats.count_by_type[2].1 += 1,
            InterruptType::MExternal => stats.count_by_type[3].1 += 1,
            InterruptType::STimer => stats.count_by_type[4].1 += 1,
            InterruptType::SSoftware => stats.count_by_type[5].1 += 1,
            InterruptType::SExternal => stats.count_by_type[6].1 += 1,
        }
        
        // 外部割り込みの場合、ハンドラの統計情報も更新
        if int_type == InterruptType::MExternal || int_type == InterruptType::SExternal {
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
                }
            }
        }
    }
}

/// グローバル割り込みテーブル
static mut INTERRUPT_TABLE: Option<InterruptTable> = None;

/// 割り込みサブシステムを初期化
pub fn init() {
    // PLICを初期化
    plic::init();
    
    // CLINTを初期化
    clint::init();
    
    // 例外ベクタテーブルを設定
    vectors::init();
    
    log::info!("RISC-V割り込みサブシステム初期化完了");
}

/// 割り込みハンドラを取得
pub fn get_handler(irq: u32) -> Option<fn()> {
    unsafe {
        if let Some(table) = &INTERRUPT_TABLE {
            if irq as usize < table.handlers.read().len() {
                if let Some(handler) = &table.handlers.read()[irq as usize] {
                    return Some(handler.handler);
                }
            }
        }
        None
    }
}

/// 例外ハンドラを取得
pub fn get_exception_handler(code: ExceptionCode) -> Option<fn(ExceptionCode)> {
    unsafe {
        if let Some(table) = &INTERRUPT_TABLE {
            let code_idx = code as usize;
            if code_idx < table.exception_handlers.len() {
                return table.exception_handlers[code_idx];
            }
        }
        None
    }
} 