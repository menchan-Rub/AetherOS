// AetherOS x86_64割り込みハンドラテーブル
//
// 割り込みディスクリプタテーブル（IDT）エントリの管理と
// 割り込みハンドラの登録を行います。

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use crate::arch::x86_64::idt::{IdtEntry, IdtDescriptor};
use crate::sync::{RwLock, SpinLock};
use alloc::vec::Vec;

/// 割り込み種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptType {
    /// 例外（CPU内部エラー）
    Exception,
    /// ハードウェア割り込み（IRQ）
    Hardware,
    /// ソフトウェア割り込み
    Software,
    /// システムコール
    Syscall,
}

/// 割り込みハンドラ情報
#[derive(Clone)]
pub struct InterruptHandler {
    /// ハンドラ関数ポインタ
    pub handler: AtomicPtr<fn()>,
    /// 割り込み種別
    pub int_type: InterruptType,
    /// 割り込み名
    pub name: &'static str,
    /// 優先度（0-15, 0が最高）
    pub priority: u8,
    /// コア限定（Noneの場合は任意のコアで処理可能）
    pub core_affinity: Option<usize>,
    /// 処理回数
    pub invocation_count: AtomicU32,
    /// 最後の処理時間（CPU TSCクロック）
    pub last_execution_time: AtomicU32,
    /// 平均処理時間（ナノ秒）
    pub average_execution_time: AtomicU32,
}

/// 割り込みハンドラテーブル
pub struct InterruptTable {
    /// IDTエントリ（256個）
    idt_entries: [IdtEntry; 256],
    /// IDTディスクリプタ
    idt_descriptor: IdtDescriptor,
    /// ハンドラ情報
    handlers: RwLock<[Option<InterruptHandler>; 256]>,
    /// 割り込み統計情報
    stats: SpinLock<InterruptStats>,
}

/// 割り込み統計情報
struct InterruptStats {
    /// 各割り込み番号の発生回数
    count_by_vector: [u64; 256],
    /// 各種類別の割り込み発生回数
    count_by_type: [(InterruptType, u64); 4],
    /// コア別の割り込み処理回数
    count_by_core: Vec<u64>,
    /// 最も頻繁に発生する割り込み番号
    most_frequent: (u8, u64),
    /// 最も処理時間が長い割り込み番号
    longest_processing: (u8, u64),
    /// 最後に発生した割り込み番号
    last_interrupt: u8,
    /// 割り込み処理の総時間
    total_processing_time: u64,
}

/// グローバル割り込みテーブル
static mut INTERRUPT_TABLE: Option<InterruptTable> = None;

impl InterruptTable {
    /// 新しい割り込みテーブルを作成
    pub fn new() -> Self {
        // デフォルトのIDTエントリを作成
        let mut idt_entries = [IdtEntry::new_empty(); 256];
        
        // CPU例外用のエントリを設定
        idt_entries[0] = IdtEntry::new_gate(divide_error_handler as usize, 0x08, 0x8E);
        idt_entries[1] = IdtEntry::new_gate(debug_exception_handler as usize, 0x08, 0x8E);
        idt_entries[2] = IdtEntry::new_gate(nmi_handler as usize, 0x08, 0x8E);
        idt_entries[3] = IdtEntry::new_gate(breakpoint_handler as usize, 0x08, 0x8E);
        idt_entries[4] = IdtEntry::new_gate(overflow_handler as usize, 0x08, 0x8E);
        idt_entries[5] = IdtEntry::new_gate(bound_range_handler as usize, 0x08, 0x8E);
        idt_entries[6] = IdtEntry::new_gate(invalid_opcode_handler as usize, 0x08, 0x8E);
        idt_entries[7] = IdtEntry::new_gate(device_not_available_handler as usize, 0x08, 0x8E);
        idt_entries[8] = IdtEntry::new_gate(double_fault_handler as usize, 0x08, 0x8E);
        idt_entries[10] = IdtEntry::new_gate(invalid_tss_handler as usize, 0x08, 0x8E);
        idt_entries[11] = IdtEntry::new_gate(segment_not_present_handler as usize, 0x08, 0x8E);
        idt_entries[12] = IdtEntry::new_gate(stack_segment_fault_handler as usize, 0x08, 0x8E);
        idt_entries[13] = IdtEntry::new_gate(general_protection_fault_handler as usize, 0x08, 0x8E);
        idt_entries[14] = IdtEntry::new_gate(page_fault_handler as usize, 0x08, 0x8E);
        idt_entries[16] = IdtEntry::new_gate(fpu_error_handler as usize, 0x08, 0x8E);
        idt_entries[17] = IdtEntry::new_gate(alignment_check_handler as usize, 0x08, 0x8E);
        idt_entries[18] = IdtEntry::new_gate(machine_check_handler as usize, 0x08, 0x8E);
        idt_entries[19] = IdtEntry::new_gate(simd_exception_handler as usize, 0x08, 0x8E);
        idt_entries[20] = IdtEntry::new_gate(virtualization_exception_handler as usize, 0x08, 0x8E);
        
        // システムコール用のエントリ設定（特権レベル3からのアクセスを許可）
        idt_entries[0x80] = IdtEntry::new_gate(syscall_handler as usize, 0x08, 0xEE);
        
        // IRQ用のエントリ設定（0x20-0x2F）
        for i in 0x20..0x30 {
            idt_entries[i] = IdtEntry::new_gate(irq_handler as usize, 0x08, 0x8E);
        }
        
        // IDTディスクリプタを作成
        let idt_descriptor = IdtDescriptor::new(&idt_entries);
        
        // ハンドラ情報を初期化
        let mut handlers = [None; 256];
        
        // CPU例外ハンドラの情報を設定
        handlers[0] = Some(InterruptHandler {
            handler: AtomicPtr::new(divide_error_handler as *mut fn()),
            int_type: InterruptType::Exception,
            name: "Divide Error",
            priority: 0,
            core_affinity: None,
            invocation_count: AtomicU32::new(0),
            last_execution_time: AtomicU32::new(0),
            average_execution_time: AtomicU32::new(0),
        });
        
        // (他の例外ハンドラも同様に設定...)
        
        // 割り込み統計情報を初期化
        let cpu_count = crate::arch::x86_64::get_cpu_count();
        let stats = InterruptStats {
            count_by_vector: [0; 256],
            count_by_type: [
                (InterruptType::Exception, 0),
                (InterruptType::Hardware, 0),
                (InterruptType::Software, 0),
                (InterruptType::Syscall, 0),
            ],
            count_by_core: vec![0; cpu_count],
            most_frequent: (0, 0),
            longest_processing: (0, 0),
            last_interrupt: 0,
            total_processing_time: 0,
        };
        
        Self {
            idt_entries,
            idt_descriptor,
            handlers: RwLock::new(handlers),
            stats: SpinLock::new(stats),
        }
    }
    
    /// IDTをロードしてハンドラを有効化
    pub fn load(&self) {
        unsafe {
            // IDTをロード
            self.idt_descriptor.load();
        }
    }
    
    /// 割り込みハンドラを登録
    pub fn register_handler(&self, vector: u8, handler: fn(), int_type: InterruptType, name: &'static str) -> bool {
        let mut handlers = self.handlers.write();
        
        // 既存のハンドラがある場合は上書き
        handlers[vector as usize] = Some(InterruptHandler {
            handler: AtomicPtr::new(handler as *mut fn()),
            int_type,
            name,
            priority: match int_type {
                InterruptType::Exception => 0, // 最高優先度
                InterruptType::Hardware => 4,
                InterruptType::Software => 8,
                InterruptType::Syscall => 12,
            },
            core_affinity: None,
            invocation_count: AtomicU32::new(0),
            last_execution_time: AtomicU32::new(0),
            average_execution_time: AtomicU32::new(0),
        });
        
        true
    }
    
    /// 割り込みハンドラを削除
    pub fn unregister_handler(&self, vector: u8) -> bool {
        let mut handlers = self.handlers.write();
        
        if handlers[vector as usize].is_some() {
            handlers[vector as usize] = None;
            true
        } else {
            false
        }
    }
    
    /// 割り込み処理を記録
    pub fn record_interrupt(&self, vector: u8, processing_time: u64) {
        let mut stats = self.stats.lock();
        let cpu_id = crate::arch::x86_64::get_current_cpu_id();
        
        // 統計情報を更新
        stats.count_by_vector[vector as usize] += 1;
        stats.count_by_core[cpu_id] += 1;
        stats.last_interrupt = vector;
        stats.total_processing_time += processing_time;
        
        // 最も頻繁な割り込みを更新
        if stats.count_by_vector[vector as usize] > stats.most_frequent.1 {
            stats.most_frequent = (vector, stats.count_by_vector[vector as usize]);
        }
        
        // 最も処理時間が長い割り込みを更新
        if processing_time > stats.longest_processing.1 {
            stats.longest_processing = (vector, processing_time);
        }
        
        // ハンドラの統計情報も更新
        if let Some(handler) = &self.handlers.read()[vector as usize] {
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
                InterruptType::Hardware => stats.count_by_type[1].1 += 1,
                InterruptType::Software => stats.count_by_type[2].1 += 1,
                InterruptType::Syscall => stats.count_by_type[3].1 += 1,
            }
        }
    }
    
    /// 割り込み統計情報を取得
    pub fn get_stats(&self) -> InterruptStatistics {
        let stats = self.stats.lock();
        
        InterruptStatistics {
            total_interrupts: stats.count_by_vector.iter().sum(),
            exception_count: stats.count_by_type[0].1,
            hardware_count: stats.count_by_type[1].1,
            software_count: stats.count_by_type[2].1,
            syscall_count: stats.count_by_type[3].1,
            most_frequent_vector: stats.most_frequent.0,
            most_frequent_count: stats.most_frequent.1,
            longest_processing_vector: stats.longest_processing.0,
            longest_processing_time: stats.longest_processing.1,
            last_interrupt: stats.last_interrupt,
            total_processing_time: stats.total_processing_time,
        }
    }
}

/// グローバルテーブルを初期化
pub fn init() {
    unsafe {
        INTERRUPT_TABLE = Some(InterruptTable::new());
        INTERRUPT_TABLE.as_ref().unwrap().load();
    }
}

/// グローバルテーブルを取得
pub fn get_interrupt_table() -> &'static InterruptTable {
    unsafe {
        INTERRUPT_TABLE.as_ref().unwrap()
    }
}

/// ハンドラ関数を登録（グローバルインターフェース）
pub fn register_handler(vector: u8, handler: fn(), int_type: InterruptType, name: &'static str) -> bool {
    get_interrupt_table().register_handler(vector, handler, int_type, name)
}

/// ハンドラ関数を削除（グローバルインターフェース）
pub fn unregister_handler(vector: u8) -> bool {
    get_interrupt_table().unregister_handler(vector)
}

/// 割り込み統計情報（公開用）
#[derive(Debug, Clone, Copy)]
pub struct InterruptStatistics {
    /// 総割り込み数
    pub total_interrupts: u64,
    /// 例外数
    pub exception_count: u64,
    /// ハードウェア割り込み数
    pub hardware_count: u64,
    /// ソフトウェア割り込み数
    pub software_count: u64,
    /// システムコール数
    pub syscall_count: u64,
    /// 最も頻繁な割り込みベクター
    pub most_frequent_vector: u8,
    /// 最も頻繁な割り込みの回数
    pub most_frequent_count: u64,
    /// 最も処理時間が長い割り込みベクター
    pub longest_processing_vector: u8,
    /// 最も長い処理時間（ナノ秒）
    pub longest_processing_time: u64,
    /// 最後に発生した割り込み
    pub last_interrupt: u8,
    /// 総処理時間（ナノ秒）
    pub total_processing_time: u64,
}

// 各種割り込みハンドラの実装
// これらは低レベルのハンドラで、実際の処理は別の関数で行う

extern "x86-interrupt" fn divide_error_handler() {
    // ゼロ除算エラー処理
    // 実装は別途定義
}

extern "x86-interrupt" fn debug_exception_handler() {
    // デバッグ例外処理
}

extern "x86-interrupt" fn nmi_handler() {
    // 非マスク可能割り込み処理
}

extern "x86-interrupt" fn breakpoint_handler() {
    // ブレークポイント処理
}

extern "x86-interrupt" fn overflow_handler() {
    // オーバーフロー例外処理
}

extern "x86-interrupt" fn bound_range_handler() {
    // 境界範囲超過例外処理
}

extern "x86-interrupt" fn invalid_opcode_handler() {
    // 無効オペコード例外処理
}

extern "x86-interrupt" fn device_not_available_handler() {
    // デバイス利用不可例外処理
}

extern "x86-interrupt" fn double_fault_handler() {
    // ダブルフォルト例外処理
}

extern "x86-interrupt" fn invalid_tss_handler() {
    // 無効TSS例外処理
}

extern "x86-interrupt" fn segment_not_present_handler() {
    // セグメント不在例外処理
}

extern "x86-interrupt" fn stack_segment_fault_handler() {
    // スタックセグメントフォルト処理
}

extern "x86-interrupt" fn general_protection_fault_handler() {
    // 一般保護違反例外処理
}

extern "x86-interrupt" fn page_fault_handler() {
    // ページフォルト例外処理
}

extern "x86-interrupt" fn fpu_error_handler() {
    // FPUエラー処理
}

extern "x86-interrupt" fn alignment_check_handler() {
    // アライメントチェック例外処理
}

extern "x86-interrupt" fn machine_check_handler() {
    // マシンチェック例外処理
}

extern "x86-interrupt" fn simd_exception_handler() {
    // SIMD浮動小数点例外処理
}

extern "x86-interrupt" fn virtualization_exception_handler() {
    // 仮想化例外処理
}

extern "x86-interrupt" fn syscall_handler() {
    // システムコール処理
}

extern "x86-interrupt" fn irq_handler() {
    // IRQ共通ハンドラ
} 