// AetherOS SLUB 統計情報実装

use core::sync::atomic::{AtomicUsize, Ordering};

/// SLUBアロケータ全体の統計情報
#[derive(Debug, Clone)]
pub struct SlubStats {
    /// 総割り当て回数
    pub total_allocs: usize,
    
    /// 総解放回数
    pub total_frees: usize,
    
    /// 現在割り当て中のオブジェクト数
    pub active_objects: usize,
    
    /// 総スラブ数
    pub total_slabs: usize,
    
    /// アクティブなスラブ数
    pub active_slabs: usize,
    
    /// 総ページ数
    pub total_pages: usize,
    
    /// キャッシュヒット数
    pub cache_hits: usize,
    
    /// キャッシュミス数
    pub cache_misses: usize,
}

impl SlubStats {
    /// 新しい統計情報を作成
    pub fn new() -> Self {
        SlubStats {
            total_allocs: 0,
            total_frees: 0,
            active_objects: 0,
            total_slabs: 0,
            active_slabs: 0,
            total_pages: 0,
            cache_hits: 0,
            cache_misses: 0,
        }
    }
    
    /// キャッシュヒット率を計算
    pub fn cache_hit_ratio(&self) -> f32 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f32 / total as f32
        }
    }
    
    /// 利用率を計算
    pub fn utilization(&self) -> f32 {
        if self.total_slabs == 0 {
            0.0
        } else {
            self.active_objects as f32 / (self.total_slabs * 100) as f32
        }
    }
}

impl Default for SlubStats {
    fn default() -> Self {
        Self::new()
    }
}

/// キャッシュごとの統計情報
#[derive(Debug)]
pub struct CacheStats {
    /// 総割り当て回数
    pub total_allocs: AtomicUsize,
    
    /// 総解放回数
    pub total_frees: AtomicUsize,
    
    /// キャッシュヒット数
    pub cache_hits: AtomicUsize,
    
    /// キャッシュミス数
    pub cache_misses: AtomicUsize,
}

impl CacheStats {
    /// 新しい統計情報を作成
    pub fn new() -> Self {
        CacheStats {
            total_allocs: AtomicUsize::new(0),
            total_frees: AtomicUsize::new(0),
            cache_hits: AtomicUsize::new(0),
            cache_misses: AtomicUsize::new(0),
        }
    }
    
    /// キャッシュヒット率を計算
    pub fn cache_hit_ratio(&self) -> f32 {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let total = hits + misses;
        
        if total == 0 {
            0.0
        } else {
            hits as f32 / total as f32
        }
    }
}

impl Default for CacheStats {
    fn default() -> Self {
        Self::new()
    }
}

/// CPU別の統計情報
#[derive(Debug, Default)]
pub struct PerCpuStats {
    /// 割り当て回数
    pub allocs: usize,
    
    /// 解放回数
    pub frees: usize,
} 