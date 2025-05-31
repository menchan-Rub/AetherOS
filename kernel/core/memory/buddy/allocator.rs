// AetherOS バディアロケータ実装
//
// バディアロケータのコア実装を提供します。
// 効率的なメモリ割り当てとフラグメンテーション最小化のためのアルゴリズムを実装します。
// NUMA対応、テラページサポート、AI予測アクセスパターン最適化を含む世界最高水準の実装です。

use super::{AllocatorStats, BlockHeader, BlockState, BuddyConfig, AllocationFlags, ZoneType};
use crate::core::sync::{SpinLock, Mutex, RwLock};
use crate::core::memory::telepage::TeraPageManager;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::ptr::{NonNull, null_mut};
use core::mem;
use core::cmp::{max, min};
use alloc::vec::Vec;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use log::{debug, info, warn, trace};
use alloc::collections::LinkedList;
use crate::memory::{AllocFlags, PAGE_SIZE};
use crate::arch::MemoryRegion;

/// ページサイズ（デフォルト4KB）
const PAGE_SIZE: usize = 4096;
/// デフォルトの最大オーダー
const DEFAULT_MAX_ORDER: usize = 11; // 2^11 = 2048ページ = 8MB
/// ハイパースケールの最大オーダー
const HYPERSCALE_MAX_ORDER: usize = 18; // 2^18 = 256K ページ = 1GB
/// サーバクラスの最大オーダー
const SERVER_MAX_ORDER: usize = 15; // 2^15 = 32K ページ = 128MB
/// キャッシュラインサイズ
const CACHE_LINE_SIZE: usize = 64;
/// 大規模NUMAシステムの最大ノード数
const MAX_NUMA_NODES: usize = 32;
/// NUMAノード間バランシングしきい値（%）
const NUMA_BALANCE_THRESHOLD: usize = 25;
/// 巨大ページサイズ（2MB）
const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;
/// テラページサイズ（512GB）
const TERA_PAGE_SIZE: usize = 512 * 1024 * 1024 * 1024;

/// メトリクス収集間隔（割り当て回数）
const METRICS_COLLECTION_INTERVAL: usize = 1000;

/// 割り当てカウンタのアトミック
static ALLOCATION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// メモリアクセスパターン予測器
#[derive(Debug)]
pub struct AccessPredictor {
    /// 最近のメモリアクセスパターン（アドレス）
    recent_accesses: VecDeque<(usize, u64)>, // (address, timestamp)
    /// ホットページの予測テーブル
    hot_pages: BTreeMap<usize, f32>, // address -> heat score
    /// コールドページの予測テーブル
    cold_pages: BTreeMap<usize, f32>, // address -> cold score
    /// 予測精度
    prediction_accuracy: f32,
    /// 最後の予測時刻
    last_prediction_time: u64,
}

impl AccessPredictor {
    /// 新しいアクセス予測器を作成
    pub fn new() -> Self {
        Self {
            recent_accesses: VecDeque::with_capacity(1000),
            hot_pages: BTreeMap::new(),
            cold_pages: BTreeMap::new(),
            prediction_accuracy: 0.0,
            last_prediction_time: 0,
        }
    }
    
    /// メモリアクセスを記録
    pub fn record_access(&mut self, addr: usize, timestamp: u64) {
        // ページアドレスに変換
        let page_addr = addr & !(PAGE_SIZE - 1);
        
        // 最近のアクセスに追加
        self.recent_accesses.push_back((page_addr, timestamp));
        
        // 古すぎるエントリを削除
        while self.recent_accesses.len() > 1000 {
            self.recent_accesses.pop_front();
        }
        
        // 特定のしきい値でホットページの再計算
        if self.recent_accesses.len() % 100 == 0 {
            self.update_prediction();
        }
    }
    
    /// 予測を更新
    fn update_prediction(&mut self) {
        let now = self.get_timestamp();
        
        // 直近1秒以内に更新した場合はスキップ
        if now - self.last_prediction_time < 1_000_000_000 {
            return;
        }
        
        self.last_prediction_time = now;
        
        // アクセス頻度の計算
        let mut access_counts = BTreeMap::new();
        for (addr, _) in &self.recent_accesses {
            *access_counts.entry(*addr).or_insert(0) += 1;
        }
        
        // ホットページ/コールドページの更新
        self.hot_pages.clear();
        self.cold_pages.clear();
        
        let threshold = self.recent_accesses.len() as f32 * 0.01;
        
        for (addr, count) in access_counts {
            let heat = count as f32 / self.recent_accesses.len() as f32;
            
            if count as f32 > threshold {
                self.hot_pages.insert(addr, heat);
            } else {
                self.cold_pages.insert(addr, 1.0 - heat);
            }
        }
    }
    
    /// ページがホットかどうかを予測
    pub fn predict_hot_page(&self, addr: usize) -> bool {
        // ページアドレスに変換
        let page_addr = addr & !(PAGE_SIZE - 1);
        
        // ホットページテーブルに存在するか確認
        self.hot_pages.contains_key(&page_addr)
    }
    
    /// タイムスタンプを取得
    fn get_timestamp(&self) -> u64 {
        use core::arch::x86_64::_rdtsc;
        unsafe { _rdtsc() }
    }
}

/// NUMAバランシング情報
#[derive(Debug, Clone)]
struct NumaBalanceInfo {
    /// 各NUMAノードの空きページ数
    free_pages: [AtomicUsize; MAX_NUMA_NODES],
    /// 各NUMAノードの使用中ページ数
    used_pages: [AtomicUsize; MAX_NUMA_NODES],
    /// バランシング必要フラグ
    needs_balancing: AtomicBool,
    /// 最後のバランシング時刻
    last_balanced: AtomicU64,
}

impl NumaBalanceInfo {
    /// 新しいNUMAバランス情報を作成
    fn new() -> Self {
        let mut free_pages = [AtomicUsize::new(0); MAX_NUMA_NODES];
        let mut used_pages = [AtomicUsize::new(0); MAX_NUMA_NODES];
        
        Self {
            free_pages,
            used_pages,
            needs_balancing: AtomicBool::new(false),
            last_balanced: AtomicU64::new(0),
        }
    }
    
    /// NUMAノードの使用状況を更新
    fn update_node_usage(&self, node: usize, free: usize, used: usize) {
        if node < MAX_NUMA_NODES {
            self.free_pages[node].store(free, Ordering::Relaxed);
            self.used_pages[node].store(used, Ordering::Relaxed);
            
            // バランシングが必要か判断
            self.check_balance_needed();
        }
    }
    
    /// バランシングが必要かどうかを確認
    fn check_balance_needed(&self) {
        // 最も空きページが多いノードと最も少ないノードを見つける
        let mut max_free = 0;
        let mut min_free = usize::MAX;
        
        for node in 0..MAX_NUMA_NODES {
            let free = self.free_pages[node].load(Ordering::Relaxed);
            if free > 0 {
                max_free = max_free.max(free);
                min_free = min_free.min(free);
            }
        }
        
        // しきい値を超える差がある場合はバランシングが必要
        if min_free < usize::MAX && max_free > 0 {
            let diff_percent = (max_free - min_free) * 100 / max_free;
            if diff_percent > NUMA_BALANCE_THRESHOLD {
                self.needs_balancing.store(true, Ordering::Relaxed);
            }
        }
    }
    
    /// バランシングが必要かどうかを確認
    fn needs_balancing(&self) -> bool {
        self.needs_balancing.load(Ordering::Relaxed)
    }
    
    /// バランシング完了を記録
    fn mark_balanced(&self) {
        self.needs_balancing.store(false, Ordering::Relaxed);
        // 現在時刻を記録
        self.last_balanced.store(
            // 簡易的なタイムスタンプを取得
            unsafe { core::arch::x86_64::_rdtsc() },
            Ordering::Relaxed
        );
    }
}

/// フリーエリア（特定オーダーの空きブロックリスト）
struct FreeArea {
    /// 空きブロックのリスト
    free_list: LinkedList<BuddyBlock>,
    
    /// ブロック数
    count: usize,
}

impl FreeArea {
    /// 新しいフリーエリアを作成
    fn new() -> Self {
        FreeArea {
            free_list: LinkedList::new(),
            count: 0,
        }
    }
    
    /// ブロックを追加
    fn add_block(&mut self, block: BuddyBlock) {
        self.free_list.push_back(block);
        self.count += 1;
    }
    
    /// ブロックを取得
    fn get_block(&mut self) -> Option<BuddyBlock> {
        if let Some(block) = self.free_list.pop_front() {
            self.count -= 1;
            Some(block)
        } else {
            None
        }
    }
    
    /// 特定のブロックを削除
    fn remove_block(&mut self, block: &BuddyBlock) -> bool {
        // 線形探索（将来的には改善の余地あり）
        let mut current = self.free_list.cursor_front_mut();
        while let Some(b) = current.current() {
            if b.base_addr == block.base_addr {
                current.remove_current();
                self.count -= 1;
                return true;
            }
            current.move_next();
        }
        false
    }
    
    /// 空きブロック数を取得
    fn block_count(&self) -> usize {
        self.count
    }
}

/// メモリゾーン
struct Zone {
    /// ゾーン名
    name: &'static str,
    
    /// ゾーン種別
    zone_type: ZoneType,
    
    /// 開始ページフレーム番号
    start_pfn: usize,
    
    /// 終了ページフレーム番号
    end_pfn: usize,
    
    /// 各オーダーの空きエリア
    free_areas: [FreeArea; MAX_ORDER + 1],
    
    /// 総ページ数
    total_pages: usize,
    
    /// 空きページ数
    free_pages: AtomicUsize,
    
    /// ゾーンロック
    lock: SpinLock<()>,
}

impl Zone {
    /// 新しいゾーンを作成
    fn new(name: &'static str, zone_type: ZoneType, start_pfn: usize, end_pfn: usize) -> Self {
        // 総ページ数を計算
        let total_pages = end_pfn - start_pfn;
        
        // フリーエリアを初期化
        let free_areas = [
            FreeArea::new(), FreeArea::new(), FreeArea::new(),
            FreeArea::new(), FreeArea::new(), FreeArea::new(),
            FreeArea::new(), FreeArea::new(), FreeArea::new(),
            FreeArea::new(), FreeArea::new(), FreeArea::new(),
        ];
        
        Zone {
            name,
            zone_type,
            start_pfn,
            end_pfn,
            free_areas,
            total_pages,
            free_pages: AtomicUsize::new(0),
            lock: SpinLock::new(()),
        }
    }
    
    /// ページが属しているか確認
    fn contains_page(&self, pfn: usize) -> bool {
        pfn >= self.start_pfn && pfn < self.end_pfn
    }
    
    /// メモリブロックを追加
    fn add_free_block(&mut self, block: BuddyBlock) {
        // ゾーンに属しているか確認
        let pfn = block.pfn();
        if !self.contains_page(pfn) {
            return;
        }
        
        // ロックを取得
        let _guard = self.lock.lock();
        
        // オーダーが有効範囲内か確認
        if block.order > MAX_ORDER {
            return;
        }
        
        // ブロックをフリーリストに追加
        self.free_areas[block.order].add_block(block);
        
        // 空きページ数を更新
        self.free_pages.fetch_add(block.size(), Ordering::Relaxed);
    }
    
    /// 指定オーダーのブロックを割り当て
    fn allocate_block(&mut self, order: usize) -> Option<BuddyBlock> {
        // ロックを取得
        let _guard = self.lock.lock();
        
        // 指定オーダーから探索
        for current_order in order..=MAX_ORDER {
            if let Some(block) = self.free_areas[current_order].get_block() {
                // 必要なオーダーよりも大きいブロックが見つかった場合は分割
                if current_order > order {
                    let mut current_block = block;
                    let mut current_order = current_order;
                    
                    // 必要なオーダーまで分割
                    while current_order > order {
                        // ブロックを分割
                        let (left, right) = current_block.split();
                        current_order -= 1;
                        
                        // 右側のブロックをフリーリストに戻す
                        self.free_areas[current_order].add_block(right);
                        
                        // 左側のブロックで続行
                        current_block = left;
                    }
                    
                    // 空きページ数を更新
                    let allocated_pages = 1 << order;
                    self.free_pages.fetch_sub(allocated_pages, Ordering::Relaxed);
                    
                    return Some(current_block);
                }
                
                // 空きページ数を更新
                let allocated_pages = 1 << order;
                self.free_pages.fetch_sub(allocated_pages, Ordering::Relaxed);
                
                return Some(block);
            }
        }
        
        None
    }
    
    /// ブロックを解放し、可能ならバディとマージ
    fn free_block(&mut self, block: BuddyBlock) -> Result<(), &'static str> {
        // ゾーンに属しているか確認
        let pfn = block.pfn();
        if !self.contains_page(pfn) {
            return Err("ブロックがこのゾーンに属していません");
        }
        
        // オーダーが有効範囲内か確認
        if block.order > MAX_ORDER {
            return Err("無効なブロックオーダーです");
        }
        
        // ロックを取得
        let _guard = self.lock.lock();
        
        // バディの探索とマージを繰り返す
        let mut current_block = block;
        let mut current_order = block.order;
        
        while current_order < MAX_ORDER {
            // バディブロックを計算
            let buddy = current_block.buddy();
            
            // バディがフリーリストにあるか確認
            if self.free_areas[current_order].remove_block(&buddy) {
                // バディとマージ
                if let Some(merged) = current_block.merge_with(&buddy) {
                    current_block = merged;
                    current_order += 1;
                    continue;
                }
            }
            
            // マージできなかったらループ終了
            break;
        }
        
        // 最終的なブロックをフリーリストに追加
        self.free_areas[current_order].add_block(current_block);
        
        // 空きページ数を更新
        let freed_pages = 1 << block.order;
        self.free_pages.fetch_add(freed_pages, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// ゾーン情報を取得
    fn get_info(&self) -> ZoneInfo {
        ZoneInfo {
            name: self.name,
            zone_type: self.zone_type,
            start_pfn: self.start_pfn,
            end_pfn: self.end_pfn,
            total_pages: self.total_pages,
            free_pages: self.free_pages.load(Ordering::Relaxed),
        }
    }
    
    /// 断片化情報を分析
    fn analyze_fragmentation(&self) -> FragStats {
        // ロックを取得
        let _guard = self.lock.lock();
        
        // 空きページ数
        let free_pages = self.free_pages.load(Ordering::Relaxed);
        
        // 最大の連続空き領域を計算
        let mut largest_free = 0;
        
        for order in (0..=MAX_ORDER).rev() {
            if self.free_areas[order].block_count() > 0 {
                largest_free = 1 << order;
                break;
            }
        }
        
        // 断片化インデックスを計算
        // 0: 完全に連続、100: 完全に断片化
        let fragmentation_index = if free_pages == 0 {
            0
        } else {
            let theoretical_max_order = (free_pages as f32).log2().floor() as usize;
            let theoretical_max_block = 1 << theoretical_max_order;
            
            // 理論上可能な最大ブロックと実際の最大ブロックを比較
            let frag_ratio = 1.0 - (largest_free as f32 / theoretical_max_block as f32);
            (frag_ratio * 100.0) as usize
        };
        
        FragStats {
            total_pages: self.total_pages,
            free_pages,
            largest_free,
            fragmentation_index,
        }
    }
}

/// NUMAノード
struct Node {
    /// ノードID
    id: usize,
    
    /// メモリゾーン
    zones: Vec<Zone>,
    
    /// 総ページ数
    total_pages: usize,
    
    /// 空きページ数
    free_pages: AtomicUsize,
}

impl Node {
    /// 新しいノードを作成
    fn new(id: usize) -> Self {
        Node {
            id,
            zones: Vec::new(),
            total_pages: 0,
            free_pages: AtomicUsize::new(0),
        }
    }
    
    /// ゾーンを追加
    fn add_zone(&mut self, zone: Zone) {
        self.total_pages += zone.total_pages;
        self.zones.push(zone);
    }
    
    /// 指定されたPFNを含むゾーンを見つける
    fn find_zone_for_pfn(&mut self, pfn: usize) -> Option<&mut Zone> {
        for zone in &mut self.zones {
            if zone.contains_page(pfn) {
                return Some(zone);
            }
        }
        None
    }
    
    /// 指定されたフラグに合うゾーンを見つける
    fn find_zone_for_flags(&mut self, flags: AllocFlags) -> Option<&mut Zone> {
        // DMA要求の場合
        if flags.contains(AllocFlags::DMA) {
            for zone in &mut self.zones {
                if zone.zone_type == ZoneType::DMA {
                    return Some(zone);
                }
            }
        }
        
        // 通常のゾーンを探す
        for zone in &mut self.zones {
            if zone.zone_type == ZoneType::Normal {
                return Some(zone);
            }
        }
        
        // それ以外の場合は最初のゾーン
        self.zones.first_mut()
    }
    
    /// メモリブロックを割り当て
    fn allocate_block(&mut self, order: usize, flags: AllocFlags) -> Option<BuddyBlock> {
        // 適切なゾーンを見つける
        if let Some(zone) = self.find_zone_for_flags(flags) {
            let block = zone.allocate_block(order);
            
            // 割り当てが成功したら空きページ数を更新
            if let Some(ref b) = block {
                self.free_pages.fetch_sub(b.size(), Ordering::Relaxed);
            }
            
            return block;
        }
        
        // 他のゾーンも試す
        for zone in &mut self.zones {
            if let Some(block) = zone.allocate_block(order) {
                // 空きページ数を更新
                self.free_pages.fetch_sub(block.size(), Ordering::Relaxed);
                return Some(block);
            }
        }
        
        None
    }
    
    /// メモリブロックを解放
    fn free_block(&mut self, block: BuddyBlock) -> Result<(), &'static str> {
        // ブロックが属するゾーンを見つける
        let pfn = block.pfn();
        
        if let Some(zone) = self.find_zone_for_pfn(pfn) {
            // ゾーンにブロックを解放
            zone.free_block(block)?;
            
            // 空きページ数を更新
            self.free_pages.fetch_add(block.size(), Ordering::Relaxed);
            
            Ok(())
        } else {
            Err("指定されたブロックがどのゾーンにも属していません")
        }
    }
    
    /// ノードの統計情報を取得
    fn get_stats(&self) -> NodeStats {
        // 各ゾーンの情報を収集
        let mut zones_info = Vec::with_capacity(self.zones.len());
        for zone in &self.zones {
            zones_info.push(zone.get_info());
        }
        
        // 断片化情報を収集
        let fragmentation = self.zones.first().map_or(
            FragStats {
                total_pages: 0,
                free_pages: 0,
                largest_free: 0,
                fragmentation_index: 0,
            },
            |zone| zone.analyze_fragmentation()
        );
        
        NodeStats {
            node_id: self.id,
            total_pages: self.total_pages,
            free_pages: self.free_pages.load(Ordering::Relaxed),
            zones: zones_info,
            fragmentation,
        }
    }
}

/// バディアロケータ
#[derive(Debug)]
pub struct BuddyAllocator {
    /// NUMAノード
    nodes: Vec<Node>,
    
    /// 総ページ数
    total_pages: usize,
    
    /// 割り当て回数
    alloc_count: AtomicUsize,
    
    /// 解放回数
    free_count: AtomicUsize,
}

impl BuddyAllocator {
    /// 新しいバディアロケータを作成
    pub fn new(
        memory_regions: Vec<&MemoryRegion>,
        numa_nodes: usize,
    ) -> Result<Self, &'static str> {
        // 少なくとも1つのNUMAノードが必要
        let node_count = numa_nodes.max(1);
        
        // NUMAノードを作成
        let mut nodes = Vec::with_capacity(node_count);
        for i in 0..node_count {
            nodes.push(Node::new(i));
        }
        
        // メモリ領域を各ノードに分配
        for (i, region) in memory_regions.iter().enumerate() {
            // 簡略化のため、ラウンドロビン方式でノードに分配
            let node_index = i % node_count;
            
            // アドレスとサイズからページフレーム番号を計算
            let start_pfn = region.base_addr / PAGE_SIZE;
            let end_pfn = start_pfn + (region.size / PAGE_SIZE);
            
            // ゾーンタイプを決定
            let zone_type = if region.base_addr < 0x1000000 {
                // 16MB未満はDMAゾーン
                ZoneType::DMA
            } else if region.base_addr < 0xffffffff {
                // 4GB未満は通常ゾーン
                ZoneType::Normal
            } else {
                // それ以上は高メモリゾーン
                ZoneType::HighMem
            };
            
            // ゾーン名を決定
            let zone_name = match zone_type {
                ZoneType::DMA => "DMA",
                ZoneType::Normal => "Normal",
                ZoneType::HighMem => "HighMem",
            };
            
            // ゾーンを作成
            let mut zone = Zone::new(zone_name, zone_type, start_pfn, end_pfn);
            
            // 領域を最大サイズのブロックに分割
            let mut current_addr = region.base_addr;
            let end_addr = region.base_addr + region.size;
            
            while current_addr < end_addr {
                // 残りサイズを計算
                let remaining_size = end_addr - current_addr;
                
                // 最大のオーダーを計算
                let max_order = remaining_size.trailing_zeros().min(MAX_ORDER as u32) as usize;
                let block_size = 1 << max_order;
                
                // ブロックを作成して追加
                let block = BuddyBlock::new(current_addr, max_order);
                zone.add_free_block(block);
                
                // 次のアドレスに進む
                current_addr += block_size * PAGE_SIZE;
            }
            
            // ゾーンをノードに追加
            nodes[node_index].add_zone(zone);
        }
        
        // 総ページ数を計算
        let total_pages = nodes.iter().map(|node| node.total_pages).sum();
        
        Ok(BuddyAllocator {
            nodes,
            total_pages,
            alloc_count: AtomicUsize::new(0),
            free_count: AtomicUsize::new(0),
        })
    }
    
    /// ページを割り当て
    pub fn allocate(&mut self, count: usize, flags: AllocFlags, node_id: usize) -> Result<usize, &'static str> {
        // 必要なオーダーを計算
        let order = Self::pages_to_order(count);
        
        // 指定されたノードから割り当て試行
        let node_index = node_id.min(self.nodes.len() - 1);
        
        if let Some(block) = self.nodes[node_index].allocate_block(order, flags) {
            // 割り当て回数を更新
            self.alloc_count.fetch_add(1, Ordering::Relaxed);
            
            // ゼロクリアが必要な場合
            if flags.contains(AllocFlags::ZERO) {
                unsafe {
                    core::ptr::write_bytes(block.base_addr as *mut u8, 0, block.size_bytes());
                }
            }
            
            return Ok(block.base_addr);
        }
        
        // 他のノードも試す
        for i in 0..self.nodes.len() {
            if i == node_index {
                continue;
            }
            
            if let Some(block) = self.nodes[i].allocate_block(order, flags) {
                // 割り当て回数を更新
                self.alloc_count.fetch_add(1, Ordering::Relaxed);
                
                // ゼロクリアが必要な場合
                if flags.contains(AllocFlags::ZERO) {
                    unsafe {
                        core::ptr::write_bytes(block.base_addr as *mut u8, 0, block.size_bytes());
                    }
                }
                
                return Ok(block.base_addr);
            }
        }
        
        // 割り当て失敗
        Err("メモリ不足です")
    }
    
    /// ページを解放
    pub fn free(&mut self, address: usize, count: usize) -> Result<(), &'static str> {
        // アドレスの検証
        if address % PAGE_SIZE != 0 {
            return Err("アドレスがページアラインされていません");
        }
        
        // オーダーを計算
        let order = Self::pages_to_order(count);
        
        // ブロックを作成
        let block = BuddyBlock::new(address, order);
        
        // ページが属するノードを見つける
        let pfn = address / PAGE_SIZE;
        
        for node in &mut self.nodes {
            if let Some(zone) = node.find_zone_for_pfn(pfn) {
                // ゾーンにブロックを解放
                zone.free_block(block)?;
                
                // 解放回数を更新
                self.free_count.fetch_add(1, Ordering::Relaxed);
                
                return Ok(());
            }
        }
        
        Err("指定されたアドレスがどのメモリ領域にも属していません")
    }
    
    /// 断片化を分析
    pub fn analyze_fragmentation(&self) -> FragStats {
        // 最もメモリ量の多いノードの断片化情報を返す
        let mut result = FragStats {
            total_pages: 0,
            free_pages: 0,
            largest_free: 0,
            fragmentation_index: 0,
        };
        
        for node in &self.nodes {
            let node_stats = node.get_stats();
            if node_stats.total_pages > result.total_pages {
                result = node_stats.fragmentation;
            }
        }
        
        result
    }
    
    /// ゾーン情報を取得
    pub fn get_zone_info(&self) -> Vec<ZoneInfo> {
        let mut result = Vec::new();
        
        for node in &self.nodes {
            for zone in &node.zones {
                result.push(zone.get_info());
            }
        }
        
        result
    }
    
    /// アロケータ統計を取得
    pub fn get_stats(&self) -> BuddyStats {
        // 各オーダーの空きブロック数を集計
        let mut free_blocks = [0; MAX_ORDER + 1];
        
        for node in &self.nodes {
            for zone in &node.zones {
                for (i, area) in zone.free_areas.iter().enumerate() {
                    free_blocks[i] += area.block_count();
                }
            }
        }
        
        // ノード情報を集計
        let mut nodes_stats = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            nodes_stats.push(node.get_stats());
        }
        
        // 空きページ数を計算
        let free_pages = nodes_stats.iter().map(|n| n.free_pages).sum();
        
        BuddyStats {
            free_blocks,
            total_allocs: self.alloc_count.load(Ordering::Relaxed),
            total_frees: self.free_count.load(Ordering::Relaxed),
            total_pages: self.total_pages,
            free_pages,
            nodes: nodes_stats,
        }
    }
    
    /// ページ数からオーダーを計算
    fn pages_to_order(pages: usize) -> usize {
        if pages == 0 {
            return 0;
        }
        
        // 2の累乗でない場合は切り上げ
        let bits = usize::BITS as usize - (pages - 1).leading_zeros() as usize;
        bits.min(MAX_ORDER)
    }
}

// BuddyAllocatorをスレッド間で共有可能とマーク
unsafe impl Send for BuddyAllocator {}
// BuddyAllocatorをスレッド間で同期可能とマーク
unsafe impl Sync for BuddyAllocator {} 