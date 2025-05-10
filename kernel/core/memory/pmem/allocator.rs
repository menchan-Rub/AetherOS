// AetherOS PMEMアロケータ
//
// このモジュールはPMEM（不揮発性メモリ）の割り当てと解放を管理します。
// 効率的なメモリ管理とフラグメンテーション軽減のための戦略を実装します。

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cmp::Ordering;
use log::{debug, error, info, warn};
use spin::Mutex;

use super::region::{PmemRegion, PmemRegionInfo, PmemRegionType, PmemRegionDetector};

/// PMEMメモリ割り当てフラグ
#[derive(Debug, Clone, Copy)]
pub struct PmemAllocFlags {
    /// ゼロフィル
    pub zero: bool,
    /// 永続化を保証
    pub persistent: bool,
    /// キャッシュ可能
    pub cacheable: bool,
    /// 大きいページを使用
    pub huge_pages: bool,
    /// NUMAノードID（Some(node_id)で特定ノード、Noneで任意）
    pub numa_node: Option<u32>,
}

impl Default for PmemAllocFlags {
    fn default() -> Self {
        Self {
            zero: false,
            persistent: true,
            cacheable: true,
            huge_pages: false,
            numa_node: None,
        }
    }
}

/// メモリブロック情報
#[derive(Debug, Clone)]
struct MemoryBlock {
    /// 物理アドレス
    address: usize,
    /// サイズ（バイト）
    size: usize,
    /// 割り当てID
    alloc_id: usize,
    /// 使用中フラグ
    used: bool,
}

impl MemoryBlock {
    /// 新しいメモリブロックを作成
    fn new(address: usize, size: usize) -> Self {
        Self {
            address,
            size,
            alloc_id: 0,
            used: false,
        }
    }
    
    /// 使用済みとしてマーク
    fn mark_used(&mut self, alloc_id: usize) {
        self.used = true;
        self.alloc_id = alloc_id;
    }
    
    /// 未使用としてマーク
    fn mark_free(&mut self) {
        self.used = false;
        self.alloc_id = 0;
    }
    
    /// ブロック分割
    fn split(&self, size: usize) -> (MemoryBlock, MemoryBlock) {
        assert!(size < self.size, "分割サイズはブロックサイズより小さくなければなりません");
        
        let first = MemoryBlock {
            address: self.address,
            size,
            alloc_id: 0,
            used: false,
        };
        
        let second = MemoryBlock {
            address: self.address + size,
            size: self.size - size,
            alloc_id: 0,
            used: false,
        };
        
        (first, second)
    }
}

/// 領域マネージャー
struct RegionManager {
    /// 管理対象の領域情報
    region_info: PmemRegionInfo,
    /// メモリブロックのリスト
    blocks: Vec<MemoryBlock>,
    /// 次の割り当てID
    next_alloc_id: usize,
}

impl RegionManager {
    /// 新しい領域マネージャーを作成
    fn new(region: PmemRegion) -> Self {
        let region_info = PmemRegionInfo::new(region);
        let mut blocks = Vec::new();
        
        // 最初は領域全体を1つの空きブロックとして扱う
        blocks.push(MemoryBlock::new(region.physical_address, region.size));
        
        Self {
            region_info,
            blocks,
            next_alloc_id: 1,
        }
    }
    
    /// メモリを割り当て
    fn allocate(&mut self, size: usize, flags: PmemAllocFlags) -> Option<(usize, usize, usize)> {
        // アライメント調整（64バイトアライメント）
        let aligned_size = (size + 63) & !63;
        
        // 最適なブロックを探す（最初適合アルゴリズム）
        let block_index = self.find_best_block(aligned_size);
        if block_index.is_none() {
            return None;
        }
        
        let block_index = block_index.unwrap();
        let block = &self.blocks[block_index];
        
        // ブロックが要求サイズよりかなり大きい場合、分割する
        if block.size > aligned_size + 128 {
            let (first, second) = block.split(aligned_size);
            self.blocks[block_index] = first;
            self.blocks.insert(block_index + 1, second);
        }
        
        // ブロックを使用中としてマーク
        let alloc_id = self.next_alloc_id;
        self.next_alloc_id += 1;
        self.blocks[block_index].mark_used(alloc_id);
        
        // 領域の使用サイズを更新
        self.region_info.update_used_size(aligned_size as u64);
        
        // 割り当て情報を返す（アドレス、サイズ、割り当てID）
        Some((self.blocks[block_index].address, aligned_size, alloc_id))
    }
    
    /// メモリを解放
    fn free(&mut self, address: usize, size: usize, alloc_id: usize) -> Result<(), ()> {
        // ブロックを探す
        let block_index = self.find_block_by_address_and_id(address, alloc_id);
        if block_index.is_none() {
            return Err(());
        }
        
        let block_index = block_index.unwrap();
        
        // ブロックが使用中でない場合はエラー
        if !self.blocks[block_index].used {
            return Err(());
        }
        
        // ブロックを未使用としてマーク
        self.blocks[block_index].mark_free();
        
        // 領域の使用サイズを更新
        self.region_info.update_used_size(-(size as i64));
        
        // 隣接する空きブロックをマージ
        self.merge_free_blocks();
        
        Ok(())
    }
    
    /// 最適なブロックを探す
    fn find_best_block(&self, size: usize) -> Option<usize> {
        let mut best_index = None;
        let mut best_size = usize::MAX;
        
        for (i, block) in self.blocks.iter().enumerate() {
            if !block.used && block.size >= size {
                // 最初適合の場合はすぐに返す
                // return Some(i);
                
                // 最適適合の場合は最小の適合ブロックを選択
                if block.size < best_size {
                    best_size = block.size;
                    best_index = Some(i);
                }
            }
        }
        
        best_index
    }
    
    /// アドレスと割り当てIDでブロックを探す
    fn find_block_by_address_and_id(&self, address: usize, alloc_id: usize) -> Option<usize> {
        for (i, block) in self.blocks.iter().enumerate() {
            if block.address == address && block.alloc_id == alloc_id {
                return Some(i);
            }
        }
        
        None
    }
    
    /// 隣接する空きブロックをマージ
    fn merge_free_blocks(&mut self) {
        let mut i = 0;
        while i < self.blocks.len() - 1 {
            let current_free = !self.blocks[i].used;
            let next_free = !self.blocks[i + 1].used;
            
            if current_free && next_free {
                // 隣接するブロックが両方空きの場合はマージ
                let current_addr = self.blocks[i].address;
                let current_size = self.blocks[i].size;
                let next_size = self.blocks[i + 1].size;
                
                // 現在のブロックにサイズを追加
                self.blocks[i].size = current_size + next_size;
                
                // 次のブロックを削除
                self.blocks.remove(i + 1);
                
                // インデックスを変更しない（次のイテレーションで次のブロックをチェック）
            } else {
                // マージできない場合は次へ
                i += 1;
            }
        }
    }
    
    /// 使用状況を取得
    fn get_usage(&self) -> (usize, usize, usize, f32) {
        let total = self.region_info.region.size;
        let used = self.region_info.used_size as usize;
        let free = total - used;
        let usage_percent = (used as f32 / total as f32) * 100.0;
        
        (total, used, free, usage_percent)
    }
}

/// PMEMアロケータ
/// 異なるPMEM領域を管理し、メモリ割り当て要求を処理します
pub struct PmemAllocator {
    /// 領域マネージャーのマップ（領域名 -> 領域マネージャー）
    region_managers: Mutex<BTreeMap<String, RegionManager>>,
    /// 領域検出器
    region_detector: PmemRegionDetector,
}

impl PmemAllocator {
    /// 新しいPMEMアロケータを作成
    pub fn new() -> Self {
        Self {
            region_managers: Mutex::new(BTreeMap::new()),
            region_detector: PmemRegionDetector::new(),
        }
    }
    
    /// アロケータを初期化
    pub fn init(&self) -> Result<(), ()> {
        // PMEM領域を検出
        let regions = self.region_detector.detect_regions();
        
        if regions.is_empty() {
            warn!("PMEM領域が検出されませんでした");
            return Ok(());
        }
        
        // 各領域に対応する領域マネージャーを作成
        let mut managers = self.region_managers.lock();
        for region in regions {
            info!("PMEM領域を登録: {} (アドレス={:#x}, サイズ={}バイト, ノード={})",
                  region.name, region.physical_address, region.size, region.numa_node);
            managers.insert(region.name.clone(), RegionManager::new(region));
        }
        
        Ok(())
    }
    
    /// メモリを割り当て
    pub fn allocate(&self, size: usize, flags: PmemAllocFlags) -> Result<(usize, usize, usize), ()> {
        let mut managers = self.region_managers.lock();
        
        // 特定のNUMAノードが指定されている場合
        if let Some(node_id) = flags.numa_node {
            for (name, manager) in managers.iter_mut() {
                if manager.region_info.region.numa_node == node_id {
                    if let Some(alloc) = manager.allocate(size, flags) {
                        debug!("PMEM割り当て: 領域={}, アドレス={:#x}, サイズ={}バイト, ID={}",
                               name, alloc.0, alloc.1, alloc.2);
                        return Ok(alloc);
                    }
                }
            }
            
            // 指定されたノードで割り当て不可能な場合
            warn!("指定されたNUMAノード{}でPMEM割り当てに失敗。他のノードを試行中", node_id);
        }
        
        // いずれかの領域から割り当て
        for (name, manager) in managers.iter_mut() {
            if let Some(alloc) = manager.allocate(size, flags) {
                debug!("PMEM割り当て: 領域={}, アドレス={:#x}, サイズ={}バイト, ID={}",
                       name, alloc.0, alloc.1, alloc.2);
                return Ok(alloc);
            }
        }
        
        // 割り当て失敗
        error!("PMEM割り当て失敗: サイズ={}バイト", size);
        Err(())
    }
    
    /// メモリを解放
    pub fn free(&self, address: usize, size: usize, alloc_id: usize) -> Result<(), ()> {
        let mut managers = self.region_managers.lock();
        
        // 全ての領域を確認
        for (name, manager) in managers.iter_mut() {
            if manager.find_block_by_address_and_id(address, alloc_id).is_some() {
                let result = manager.free(address, size, alloc_id);
                if result.is_ok() {
                    debug!("PMEM解放: 領域={}, アドレス={:#x}, サイズ={}バイト, ID={}",
                           name, address, size, alloc_id);
                } else {
                    error!("PMEM解放失敗: 領域={}, アドレス={:#x}, サイズ={}バイト, ID={}",
                           name, address, size, alloc_id);
                }
                return result;
            }
        }
        
        // 該当するブロックが見つからない
        error!("PMEM解放失敗: 未知のブロック - アドレス={:#x}, サイズ={}バイト, ID={}",
               address, size, alloc_id);
        Err(())
    }
    
    /// 使用統計を取得
    pub fn get_stats(&self) -> (usize, usize, usize, f32) {
        let managers = self.region_managers.lock();
        
        let mut total_size = 0;
        let mut total_used = 0;
        let mut total_free = 0;
        
        for manager in managers.values() {
            let (region_total, region_used, region_free, _) = manager.get_usage();
            total_size += region_total;
            total_used += region_used;
            total_free += region_free;
        }
        
        let usage_percent = if total_size > 0 {
            (total_used as f32 / total_size as f32) * 100.0
        } else {
            0.0
        };
        
        (total_size, total_used, total_free, usage_percent)
    }
} 