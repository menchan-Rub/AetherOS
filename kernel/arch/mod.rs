// AetherOS アーキテクチャ抽象化レイヤー
//
// 各ハードウェアアーキテクチャへの抽象化インターフェースを提供します。
// x86_64、AArch64、RISC-Vなどの異なるハードウェアアーキテクチャをサポートします。

use alloc::string::String;

// 各アーキテクチャのサポートモジュール
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

#[cfg(target_arch = "x86_64")]
use self::x86_64 as current_arch;
#[cfg(target_arch = "aarch64")]
use self::aarch64 as current_arch;
#[cfg(target_arch = "riscv64")]
use self::riscv64 as current_arch;

/// CPU機能フラグの列挙型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuFeatures {
    /// SSE命令セット
    Sse,
    /// SSE2命令セット
    Sse2,
    /// SSE3命令セット
    Sse3,
    /// SSSE3命令セット
    Ssse3,
    /// SSE4.1命令セット
    Sse4_1,
    /// SSE4.2命令セット
    Sse4_2,
    /// AVX命令セット
    Avx,
    /// AVX2命令セット
    Avx2,
    /// AVX512命令セット
    Avx512,
    /// NEON命令セット (ARM)
    Neon,
    /// SVE命令セット (ARM)
    Sve,
    /// SVE2命令セット (ARM)
    Sve2,
    /// RVV (RISC-V Vector)
    Rvv,
    /// x2APICサポート
    X2apic,
    /// パーミッション機能 (ARM)
    Pauth,
    /// メモリタグ機能 (ARM)
    Mte,
}

/// CPUコアタイプの列挙型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreType {
    /// 汎用コア (通常の高性能コア)
    General,
    /// 高性能コア (ビッグコア、Pコアなど)
    Performance,
    /// 省電力コア (LITTLEコア、Eコアなど)
    Efficiency,
    /// 特殊機能コア (NPU、DSPなど)
    Specialized,
}

// アーキテクチャ初期化トレイト
pub trait ArchInit {
    fn init();
    fn idle() -> !;
}

// アーキテクチャに依存しないインターフェース
pub fn init() {
    current_arch::init();
}

pub fn idle() -> ! {
    current_arch::idle()
}

// メモリ管理抽象化
pub mod mm {
    use crate::core::memory::PageSize;
    
    pub fn init_memory() {
        super::current_arch::mm::init_memory();
    }
    
    pub fn allocate_physical_page(size: PageSize) -> Option<usize> {
        super::current_arch::mm::allocate_physical_page(size)
    }
    
    pub fn free_physical_page(addr: usize, size: PageSize) {
        super::current_arch::mm::free_physical_page(addr, size);
    }
}

// 割り込み管理抽象化
pub mod interrupts {
    pub fn init() {
        super::current_arch::interrupts::init();
    }
    
    pub fn enable() {
        super::current_arch::interrupts::enable();
    }
    
    pub fn disable() {
        super::current_arch::interrupts::disable();
    }
}

// CPU抽象化
pub mod cpu {
    pub fn get_current_id() -> usize {
        super::current_arch::cpu::get_current_id()
    }
    
    pub fn get_core_count() -> usize {
        super::current_arch::cpu::get_core_count()
    }
}

/// 現在のCPUコア数を取得
pub fn get_cpu_count() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::cpu::get_cpu_count()
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::cpu::get_cpu_count()
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::cpu::get_cpu_count()
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
    {
        1 // デフォルト値
    }
}

/// 現在のCPU ID/コアIDを取得
pub fn get_current_cpu_id() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::cpu::get_current_cpu_id()
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::cpu::get_current_cpu_id()
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::cpu::get_current_hart_id()
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
    {
        0 // デフォルト値
    }
}

/// CPU情報を文字列形式で取得
pub fn cpu_info_string() -> String {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::cpu::cpu_info_string()
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::cpu::cpu_info_string()
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::cpu::cpu_info_string()
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
    {
        String::from("未サポートアーキテクチャ")
    }
}

/// ページサイズを取得
pub fn get_page_size() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::mm::PAGE_SIZE
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::mm::PAGE_SIZE
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::mm::PAGE_SIZE
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
    {
        4096 // デフォルト値
    }
}

/// 割込みが有効かどうかを確認
pub fn interrupts_enabled() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::interrupts::are_enabled()
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::interrupts::are_enabled()
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        riscv64::interrupts::are_enabled()
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
    {
        false // デフォルト値
    }
}