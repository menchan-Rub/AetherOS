// AetherOS アーキテクチャ抽象化レイヤー
//
// 異なるハードウェアアーキテクチャ間で一貫したインターフェースを提供します。

#[cfg(target_arch = "x86_64")]
pub use self::x86_64::*;

#[cfg(target_arch = "aarch64")]
pub use self::aarch64::*;

#[cfg(target_arch = "riscv64")]
pub use self::riscv64::*;

// アーキテクチャ固有の実装
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

/// メモリ情報構造体
pub struct MemoryInfo {
    /// 物理メモリの合計サイズ（バイト）
    pub total_memory: usize,
    /// カーネル用に予約されたメモリサイズ（バイト）
    pub reserved_memory: usize,
    /// カーネルが現在使用しているメモリサイズ（バイト）
    pub kernel_memory_usage: usize,
    
    /// 通常ゾーンの開始アドレス
    pub normal_zone_start: usize,
    /// 通常ゾーンのサイズ（バイト）
    pub normal_zone_size: usize,
    
    /// カーネルゾーンの開始アドレス
    pub kernel_zone_start: usize,
    /// カーネルゾーンのサイズ（バイト）
    pub kernel_zone_size: usize,
    
    /// DMAゾーンの開始アドレス
    pub dma_zone_start: usize,
    /// DMAゾーンのサイズ（バイト）
    pub dma_zone_size: usize,
    
    /// 高性能メモリゾーンの開始アドレス
    pub high_performance_zone_start: usize,
    /// 高性能メモリゾーンのサイズ（バイト）
    pub high_performance_zone_size: usize,
    
    /// NUMAサポートの有無
    pub numa_supported: bool,
    /// NUMAノード数
    pub numa_node_count: usize,
    /// NUMAノードあたりのメモリサイズ（バイト）
    pub numa_memory_per_node: usize,
    /// NUMAノード間のレイテンシマトリックス（ナノ秒）
    pub numa_latency_matrix: [[usize; 32]; 32],
    /// NUMAノードとCPUのマッピング
    pub numa_cpu_map: [Vec<usize>; 32],
    
    /// 永続メモリ（PMEM）サポートの有無
    pub pmem_supported: bool,
    /// 永続メモリの合計サイズ（バイト）
    pub pmem_size: usize,
    /// 永続メモリゾーンの開始アドレス
    pub pmem_zone_start: usize,
    /// 永続メモリゾーンのサイズ（バイト）
    pub pmem_zone_size: usize,
    
    /// CXLメモリサポートの有無
    pub cxl_supported: bool,
    /// CXLメモリの合計サイズ（バイト）
    pub cxl_memory_size: usize,
    /// CXLメモリゾーンの開始アドレス
    pub cxl_zone_start: usize,
    /// CXLメモリゾーンのサイズ（バイト）
    pub cxl_zone_size: usize,
}

/// スレッドコンテキスト（アーキテクチャ非依存）
#[repr(C)]
pub struct ThreadContext {
    /// アーキテクチャ固有の実装
    pub arch_data: [u8; 256],
}

/// アーキテクチャサブシステムの初期化
pub fn init() {
    #[cfg(target_arch = "x86_64")]
    x86_64::init();
    
    #[cfg(target_arch = "aarch64")]
    aarch64::init();
    
    #[cfg(target_arch = "riscv64")]
    riscv64::init();
    
    log::info!("アーキテクチャサブシステム初期化完了");
} 