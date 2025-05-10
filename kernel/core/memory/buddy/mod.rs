// AetherOS バディアロケータモジュール
//
// このモジュールはカーネルのバディメモリアロケータを実装します。
// バディアロケータは物理メモリを効率的に管理し、フラグメンテーションを
// 最小限に抑えながら様々なサイズのメモリブロックを割り当てます。

mod allocator;
mod block;
pub mod api;

pub use allocator::BuddyAllocator;
pub use block::{BlockHeader, BlockInfo, BlockState};

/// アロケータの統計情報
#[derive(Debug, Clone, Copy)]
pub struct AllocatorStats {
    /// 総メモリ量（バイト）
    pub total_memory: usize,
    /// 使用中のメモリ量（バイト）
    pub used_memory: usize,
    /// 空きメモリ量（バイト）
    pub free_memory: usize,
    /// 総ページ数
    pub total_pages: usize,
    /// 使用中のページ数
    pub used_pages: usize,
    /// フラグメンテーション率（%）
    pub fragmentation_percent: usize,
}

/// バディアロケータの設定
#[derive(Debug, Clone)]
pub struct BuddyConfig {
    /// 最小メモリアドレス
    pub min_addr: usize,
    /// 最大メモリアドレス
    pub max_addr: usize,
    /// ページサイズ（バイト単位）
    pub page_size: usize,
    /// 最大オーダー
    pub max_order: usize,
    /// NUMAノードID（NUMAサポート時）
    pub numa_node: Option<usize>,
    /// メモリゾーンタイプ
    pub zone_type: ZoneType,
}

/// メモリゾーンタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneType {
    /// 通常のメモリ
    Normal,
    /// DMA用メモリ（32ビットデバイス用）
    Dma,
    /// DMA用メモリ（64ビットデバイス用）
    Dma64,
    /// 高メモリ領域
    HighMem,
    /// 不揮発性メモリ
    Pmem,
    /// CXLメモリ
    Cxl,
}

/// 割り当て優先度
#[derive(Debug, Clone, Copy)]
pub enum AllocationPriority {
    /// 標準優先度
    Normal,
    /// 高速割り当て優先
    Speed,
    /// メモリ効率優先
    Efficiency,
    /// NUMAローカリティ優先
    NumaLocal(u8),
}

/// 割り当てフラグ
#[derive(Debug, Clone, Copy)]
pub struct AllocationFlags {
    /// 割り当て優先度
    pub priority: AllocationPriority,
    /// 隣接物理メモリを要求するか
    pub contiguous: bool,
    /// メモリを事前に0クリアするか
    pub zero: bool,
    /// メモリ使用目的タグ（デバッグ用）
    pub purpose_tag: [u8; 8],
}

impl Default for AllocationFlags {
    fn default() -> Self {
        Self {
            priority: AllocationPriority::Normal,
            contiguous: false,
            zero: false,
            purpose_tag: [0; 8],
        }
    }
} 