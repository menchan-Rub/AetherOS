// AetherOS ページ管理モジュール
//
// このモジュールは物理メモリページの管理を担当します。
// バディアロケータやメモリマッピングの機能を提供します。

pub mod buddy;
pub mod api;

/// メモリアロケータの状態情報
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