// AetherOS SLUB CPUキャッシュ実装

use crate::sync::SpinLock;
use alloc::vec::Vec;

/// CPU別キャッシュ
/// 各CPUコア専用のオブジェクト管理
#[derive(Debug)]
pub struct PerCpuCache {
    /// ローカルフリーリスト
    local_free: SpinLock<Vec<usize>>,
    
    /// キャッシュサイズ上限
    capacity: usize,
}

impl PerCpuCache {
    /// 新しいCPUキャッシュを作成
    pub fn new(capacity: usize) -> Self {
        PerCpuCache {
            local_free: SpinLock::new(Vec::with_capacity(capacity)),
            capacity,
        }
    }
    
    /// キャッシュからオブジェクトを取得
    pub fn pop(&self) -> Option<usize> {
        let mut local_free = self.local_free.lock();
        local_free.pop()
    }
    
    /// キャッシュにオブジェクトを返却
    /// 返り値は成功したかどうか
    pub fn push(&self, address: usize) -> bool {
        let mut local_free = self.local_free.lock();
        
        // キャッシュが満杯でなければ追加
        if local_free.len() < self.capacity {
            local_free.push(address);
            true
        } else {
            false
        }
    }
    
    /// 複数のオブジェクトをバッチ追加
    pub fn push_batch(&self, addresses: &[usize]) -> usize {
        let mut local_free = self.local_free.lock();
        let free_space = self.capacity - local_free.len();
        
        // 追加可能な数を計算
        let add_count = addresses.len().min(free_space);
        
        // オブジェクトを追加
        for i in 0..add_count {
            local_free.push(addresses[i]);
        }
        
        add_count
    }
    
    /// 一部のオブジェクトを取り出し
    pub fn drain(&self, count: usize) -> Vec<usize> {
        let mut local_free = self.local_free.lock();
        let available = local_free.len();
        
        // 取り出し可能な数を計算
        let drain_count = count.min(available);
        
        // 必要な数のオブジェクトを取り出す
        let new_len = available - drain_count;
        let result = local_free.split_off(new_len);
        
        result
    }
    
    /// キャッシュをクリア
    pub fn clear(&self) -> Result<(), &'static str> {
        let mut local_free = self.local_free.lock();
        local_free.clear();
        Ok(())
    }
    
    /// キャッシュ内のオブジェクト数
    pub fn size(&self) -> usize {
        self.local_free.lock().len()
    }
    
    /// キャッシュ容量
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    
    /// キャッシュを収縮
    pub fn shrink(&self) -> Result<usize, &'static str> {
        // 半分のオブジェクトを解放
        let drain_count = self.size() / 2;
        let drained = self.drain(drain_count);
        
        // 実際に解放された数（ページ単位）を返す
        // 注: 実際にはオブジェクトがどのページから来たかを追跡する必要があるが
        // 簡略化のために0を返す
        Ok(0)
    }
} 