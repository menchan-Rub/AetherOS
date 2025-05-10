// AetherOS バディアロケータ実装
//
// バディアロケータのコア実装を提供します。
// 効率的なメモリ割り当てとフラグメンテーション最小化のためのアルゴリズムを実装します。

use super::{AllocatorStats, BlockHeader, BlockState, BuddyConfig, AllocationFlags, ZoneType};
use crate::core::sync::{SpinLock, Mutex, RwLock};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::ptr::{NonNull, null_mut};
use core::mem;
use core::cmp::{max, min};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use log::{debug, info, warn, trace};

/// ページサイズ（デフォルト4KB）
const PAGE_SIZE: usize = 4096;
/// デフォルトの最大オーダー
const DEFAULT_MAX_ORDER: usize = 11; // 2^11 = 2048ページ = 8MB
/// キャッシュラインサイズ
const CACHE_LINE_SIZE: usize = 64;

/// メトリクス収集間隔（割り当て回数）
const METRICS_COLLECTION_INTERVAL: usize = 1000;

/// 割り当てカウンタのアトミック
static ALLOCATION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// バディアロケータの実装
#[repr(C, align(64))] // キャッシュラインアライメント
pub struct BuddyAllocator {
    /// フリーリスト（各オーダーごと）
    free_lists: SpinLock<Vec<*mut BlockHeader>>,
    /// アロケータ設定
    config: BuddyConfig,
    /// 管理されているブロックマップ（アドレス -> ブロックヘッダ）
    blocks: RwLock<BTreeMap<usize, NonNull<BlockHeader>>>,
    /// 総ページ数
    total_pages: AtomicUsize,
    /// 空きページ数
    free_pages: AtomicUsize,
    /// 使用中ページ数
    used_pages: AtomicUsize,
    /// 分割されたブロック数
    split_blocks: AtomicUsize,
    /// 割り当て失敗カウント
    allocation_failures: AtomicUsize,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// 割り当てカウンタ
    allocation_count: AtomicU64,
    /// 解放カウンタ
    free_count: AtomicU64,
    /// 最大割り当てサイズ（バイト）
    max_allocation_size: AtomicUsize,
    /// 平均割り当て時間（ナノ秒）
    avg_allocation_time_ns: AtomicU64,
    /// コンパクション試行回数
    compaction_attempts: AtomicUsize,
    /// コンパクション成功回数
    compaction_successes: AtomicUsize,
    /// メモリアクセスパターン予測器（オプション）
    #[cfg(feature = "memory_profiling")]
    access_predictor: Option<Mutex<AccessPredictor>>,
    /// パディング（キャッシュライン境界調整用）
    _padding: [u8; 16],
}

impl BuddyAllocator {
    /// 新しいバディアロケータを作成
    pub fn new(config: BuddyConfig) -> Self {
        // ページサイズが2のべき乗であることを確認
        assert!(config.page_size.is_power_of_two(), "ページサイズは2のべき乗である必要があります");
        
        // 最大オーダーが合理的な範囲内であることを確認
        let max_order = if config.max_order == 0 || config.max_order > 32 {
            DEFAULT_MAX_ORDER
        } else {
            config.max_order
        };
        
        // オーダーごとの空のフリーリストを作成
        let mut free_lists = Vec::with_capacity(max_order + 1);
        for _ in 0..=max_order {
            free_lists.push(null_mut());
        }
        
        let mut config = config.clone();
        config.max_order = max_order;
        
        // 管理するアドレス範囲が適切であることを確認
        assert!(config.max_addr > config.min_addr, "最大アドレスは最小アドレスより大きい必要があります");
        
        Self {
            free_lists: SpinLock::new(free_lists),
            config,
            blocks: RwLock::new(BTreeMap::new()),
            total_pages: AtomicUsize::new(0),
            free_pages: AtomicUsize::new(0),
            used_pages: AtomicUsize::new(0),
            split_blocks: AtomicUsize::new(0),
            allocation_failures: AtomicUsize::new(0),
            initialized: AtomicBool::new(false),
            allocation_count: AtomicU64::new(0),
            free_count: AtomicU64::new(0),
            max_allocation_size: AtomicUsize::new(0),
            avg_allocation_time_ns: AtomicU64::new(0),
            compaction_attempts: AtomicUsize::new(0),
            compaction_successes: AtomicUsize::new(0),
            #[cfg(feature = "memory_profiling")]
            access_predictor: Some(Mutex::new(AccessPredictor::new())),
            _padding: [0; 16],
        }
    }
    
    /// アロケータを初期化
    pub fn init(&self) -> Result<(), &'static str> {
        if self.initialized.load(Ordering::Acquire) {
            return Ok(());
        }
        
        // 管理するメモリ領域の合計サイズを計算
        let mem_size = self.config.max_addr - self.config.min_addr;
        let page_size = self.config.page_size;
        
        // 総ページ数を計算
        let total_pages = mem_size / page_size;
        self.total_pages.store(total_pages, Ordering::Release);
        self.free_pages.store(total_pages, Ordering::Release);
        
        info!("バディアロケータを初期化: アドレス範囲={:#x}-{:#x}, ページ数={}, 最大オーダー={}",
            self.config.min_addr, self.config.max_addr, total_pages, self.config.max_order);
        
        // メモリブロックの初期化
        self.initialize_blocks()?;
        
        self.initialized.store(true, Ordering::Release);
        
        Ok(())
    }
    
    /// メモリブロックを初期化
    fn initialize_blocks(&self) -> Result<(), &'static str> {
        let min_addr = self.config.min_addr;
        let max_addr = self.config.max_addr;
        let page_size = self.config.page_size;
        let max_order = self.config.max_order;
        
        // 最大のブロックサイズを計算（2^max_order * page_size）
        let max_block_size = page_size << max_order;
        
        // 利用可能なメモリをできるだけ大きなブロックに分割
        let mut addr = min_addr;
        let mut blocks = self.blocks.write().map_err(|_| "ブロックマップのロック取得に失敗")?;
        
        while addr + page_size <= max_addr {
            // 現在のアドレスで作成できる最大オーダーを見つける
            let mut order = max_order;
            let mut block_size = max_block_size;
            
            // アドレスアライメントとメモリ残量に基づいて適切なオーダーを見つける
            while order > 0 {
                if addr % block_size == 0 && addr + block_size <= max_addr {
                    break;
                }
                order -= 1;
                block_size >>= 1;
            }
            
            // ブロックヘッダを作成
            let header_size = mem::size_of::<BlockHeader>();
            let header_ptr = self.allocate_header_memory()?;
            
            // ヘッダを初期化
            let header = BlockHeader::new(order as u8, self.config.numa_node.unwrap_or(0) as u8);
            unsafe {
                *header_ptr = header;
            }
            
            // フリーリストに追加
            self.add_to_free_list(header_ptr, order);
            
            // ブロックマップに追加
            if let Some(non_null) = NonNull::new(header_ptr) {
                blocks.insert(addr, non_null);
            } else {
                return Err("無効なヘッダポインタ");
            }
            
            // 次のアドレスに進む
            addr += block_size;
            
            trace!("ブロック初期化: アドレス={:#x}, オーダー={}, サイズ={}", addr - block_size, order, block_size);
        }
        
        info!("メモリブロック初期化完了: {}ブロック", blocks.len());
        
        Ok(())
    }
    
    /// ヘッダ用のメモリを割り当て
    fn allocate_header_memory(&self) -> Result<*mut BlockHeader, &'static str> {
        // 実際の実装ではカーネルのグローバルアロケータや専用のプールを使用
        // ここでは簡略化のため、組み込み環境を想定してスタティックな領域を確保
        static mut HEADER_POOL: [u8; 1024 * 1024] = [0; 1024 * 1024]; // 1MBのヘッダプール
        static HEADER_POOL_OFFSET: AtomicUsize = AtomicUsize::new(0);
        
        let header_size = mem::size_of::<BlockHeader>();
        let aligned_size = (header_size + CACHE_LINE_SIZE - 1) & !(CACHE_LINE_SIZE - 1);
        
        let offset = HEADER_POOL_OFFSET.fetch_add(aligned_size, Ordering::SeqCst);
        if offset + aligned_size > unsafe { HEADER_POOL.len() } {
            return Err("ヘッダプールが不足しています");
        }
        
        let ptr = unsafe { HEADER_POOL.as_mut_ptr().add(offset) as *mut BlockHeader };
        Ok(ptr)
    }
    
    /// フリーリストにブロックを追加
    fn add_to_free_list(&self, block: *mut BlockHeader, order: usize) {
        let mut free_lists = self.free_lists.lock();
        
        unsafe {
            // 現在のフリーリストの先頭を取得
            let current_head = free_lists[order];
            
            // 新しいブロックをリストの先頭に設定
            (*block).set_next(current_head);
            if !current_head.is_null() {
                (*current_head).set_prev(block);
            }
            (*block).set_prev(null_mut());
            
            // フリーリストの先頭を更新
            free_lists[order] = block;
            
            // ブロックを空き状態にマーク
            (*block).set_state(BlockState::Free);
        }
    }
    
    /// フリーリストからブロックを削除
    fn remove_from_free_list(&self, block: *mut BlockHeader, order: usize) {
        let mut free_lists = self.free_lists.lock();
        
        unsafe {
            let prev = (*block).get_prev();
            let next = (*block).get_next();
            
            // 前のブロックがある場合、そのnextを更新
            if !prev.is_null() {
                (*prev).set_next(next);
            } else {
                // 先頭ブロックの場合はフリーリストの先頭を更新
                free_lists[order] = next;
            }
            
            // 次のブロックがある場合、そのprevを更新
            if !next.is_null() {
                (*next).set_prev(prev);
            }
            
            // ブロックのリンクをクリア
            (*block).set_prev(null_mut());
            (*block).set_next(null_mut());
        }
    }
    
    /// ブロックを分割
    fn split_block(&self, block: *mut BlockHeader, target_order: usize) -> Option<*mut BlockHeader> {
        unsafe {
            let block_order = (*block).get_order() as usize;
            
            if block_order <= target_order {
                // すでに十分小さいか必要なサイズと同じ場合は分割不要
                return Some(block);
            }
            
            // ブロックをフリーリストから削除
            self.remove_from_free_list(block, block_order);
            
            // 新しいオーダー
            let new_order = block_order - 1;
            
            // 分割されたブロックのサイズ
            let half_size = self.config.page_size << new_order;
            
            // ブロックの物理アドレスを取得（blocks mapから）
            let blocks = self.blocks.read().expect("ブロックマップのロック取得に失敗");
            let block_addr = match blocks.iter().find(|(_, &b)| b.as_ptr() == block) {
                Some((addr, _)) => *addr,
                None => return None,
            };
            
            // 右側の子ブロックのアドレス
            let right_addr = block_addr + half_size;
            
            // 右子ブロックのヘッダを作成
            let right_block = self.allocate_header_memory().ok()?;
            let right_header = BlockHeader::new(new_order as u8, (*block).get_numa_node());
            *right_block = right_header;
            
            // 分割されたブロックの状態を更新
            (*block).set_state(BlockState::Split);
            (*block).set_order(new_order as u8);
            
            // 親子関係を設定
            (*block).set_left_child(block);
            (*block).set_right_child(right_block);
            (*right_block).set_parent(block);
            
            // ブロックマップを更新
            drop(blocks);
            let mut blocks = self.blocks.write().expect("ブロックマップのロック取得に失敗");
            if let Some(non_null) = NonNull::new(right_block) {
                blocks.insert(right_addr, non_null);
            } else {
                return None;
            }
            
            // 分割されたブロック数をインクリメント
            self.split_blocks.fetch_add(1, Ordering::Relaxed);
            
            // 両方のブロックをフリーリストに追加
            self.add_to_free_list(block, new_order);
            self.add_to_free_list(right_block, new_order);
            
            // さらに分割が必要な場合は再帰的に処理
            self.split_block(block, target_order)
        }
    }
    
    /// ページを割り当て
    pub fn allocate_pages(&self, num_pages: usize, flags: AllocationFlags) -> Option<usize> {
        if !self.initialized.load(Ordering::Acquire) {
            return None;
        }
        
        // 割り当てカウンタをインクリメント
        let allocation_id = ALLOCATION_COUNTER.fetch_add(1, Ordering::Relaxed);
        self.allocation_count.fetch_add(1, Ordering::Relaxed);
        
        // 開始時間を記録（パフォーマンス測定用）
        let start_time = self.get_current_time_ns();
        
        // 必要なオーダーを計算
        let required_order = self.size_to_order(num_pages * self.config.page_size);
        
        // 空きブロックを探索
        let block = self.find_free_block(required_order);
        
        // ブロックが見つからない場合
        if block.is_none() {
            self.allocation_failures.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        
        let block = block.unwrap();
        
        // ブロックを割り当て状態にマーク
        unsafe {
            (*block).set_state(BlockState::Allocated);
            (*block).set_allocation_id(allocation_id as u32);
            (*block).set_allocation_time(start_time);
            
            // 目的タグを設定（デバッグ用）
            if flags.purpose_tag != [0; 8] {
                let mut block_mut = &mut *block;
                block_mut.set_purpose_tag(&flags.purpose_tag);
            }
        }
        
        // ブロックの物理アドレスを取得
        let blocks = self.blocks.read().expect("ブロックマップのロック取得に失敗");
        let block_addr = match blocks.iter().find(|(_, &b)| b.as_ptr() == block) {
            Some((addr, _)) => *addr,
            None => return None,
        };
        
        // メモリをゼロ化する必要がある場合
        if flags.zero {
            unsafe {
                let size = self.config.page_size << (*block).get_order();
                core::ptr::write_bytes(block_addr as *mut u8, 0, size);
            }
        }
        
        // 使用中ページ数を更新
        let pages_in_block = 1 << ((*block as *const BlockHeader).as_ref().unwrap().get_order() as usize);
        self.used_pages.fetch_add(pages_in_block, Ordering::Relaxed);
        self.free_pages.fetch_sub(pages_in_block, Ordering::Relaxed);
        
        // 最大割り当てサイズを更新
        let size = pages_in_block * self.config.page_size;
        let current_max = self.max_allocation_size.load(Ordering::Relaxed);
        if size > current_max {
            self.max_allocation_size.store(size, Ordering::Relaxed);
        }
        
        // 割り当て時間を計算・更新
        let end_time = self.get_current_time_ns();
        let elapsed = end_time - start_time;
        self.update_allocation_time(elapsed);
        
        // 割り当てられたブロックのアドレスを返す
        Some(block_addr)
    }
    
    /// ページを解放
    pub fn free_pages(&self, addr: usize, num_pages: usize) -> Result<(), &'static str> {
        if !self.initialized.load(Ordering::Acquire) {
            return Err("アロケータが初期化されていません");
        }
        
        // アドレスが管理範囲内であることを確認
        if addr < self.config.min_addr || addr >= self.config.max_addr {
            return Err("アドレスが管理範囲外です");
        }
        
        // ブロックヘッダを取得
        let blocks = self.blocks.read().map_err(|_| "ブロックマップのロック取得に失敗")?;
        let block_ptr = match blocks.get(&addr) {
            Some(block) => block.as_ptr(),
            None => return Err("指定されたアドレスのブロックが見つかりません"),
        };
        
        unsafe {
            // ブロックが割り当て状態であることを確認
            if (*block_ptr).get_state() != BlockState::Allocated {
                return Err("このブロックは割り当てられていません");
            }
            
            // ブロックのオーダーを取得
            let order = (*block_ptr).get_order() as usize;
            let block_pages = 1 << order;
            
            // 要求されたページ数と実際のブロックサイズの整合性をチェック
            if block_pages < num_pages {
                return Err("解放要求ページ数がブロックサイズより大きいです");
            }
            
            // ブロックを空き状態にマーク
            (*block_ptr).set_state(BlockState::Free);
            
            // 使用中/空きページ数を更新
            self.used_pages.fetch_sub(block_pages, Ordering::Relaxed);
            self.free_pages.fetch_add(block_pages, Ordering::Relaxed);
            
            // 解放カウンタをインクリメント
            self.free_count.fetch_add(1, Ordering::Relaxed);
            
            // ブロックをフリーリストに追加
            drop(blocks);
            self.add_to_free_list(block_ptr, order);
            
            // 隣接するバディブロックをマージ
            self.merge_buddy_blocks(block_ptr, addr, order);
        }
        
        Ok(())
    }
    
    /// バディブロックをマージ
    fn merge_buddy_blocks(&self, block: *mut BlockHeader, addr: usize, order: usize) {
        if order >= self.config.max_order {
            return; // これ以上マージできない
        }
        
        // バディブロックのアドレスを計算
        let buddy_addr = self.get_buddy_address(addr, order);
        
        // バディブロックが存在するか確認
        let blocks = self.blocks.read().expect("ブロックマップのロック取得に失敗");
        let buddy_ptr = match blocks.get(&buddy_addr) {
            Some(buddy) => buddy.as_ptr(),
            None => return, // バディブロックが存在しない
        };
        
        unsafe {
            // バディブロックが空き状態であることを確認
            if (*buddy_ptr).get_state() != BlockState::Free {
                return;
            }
            
            // バディブロックのオーダーが同じであることを確認
            if (*buddy_ptr).get_order() as usize != order {
                return;
            }
            
            // 両方のブロックをフリーリストから削除
            drop(blocks);
            self.remove_from_free_list(block, order);
            self.remove_from_free_list(buddy_ptr, order);
            
            // 親ブロックを取得（左側のブロックの親）
            let parent_order = order + 1;
            let parent_addr = min(addr, buddy_addr);
            
            // 親ブロックのヘッダを取得
            let blocks = self.blocks.read().expect("ブロックマップのロック取得に失敗");
            let parent_ptr = match blocks.get(&parent_addr) {
                Some(parent) => parent.as_ptr(),
                None => return, // 親ブロックが存在しない
            };
            
            // 親ブロックの状態を更新
            drop(blocks);
            (*parent_ptr).set_state(BlockState::Free);
            (*parent_ptr).set_order(parent_order as u8);
            
            // バディブロックの状態をクリア
            (*buddy_ptr).set_state(BlockState::Free);
            
            // 親ブロックをフリーリストに追加
            self.add_to_free_list(parent_ptr, parent_order);
            
            // 分割されたブロック数を減らす
            self.split_blocks.fetch_sub(1, Ordering::Relaxed);
            
            // さらに上位のバディブロックをマージする可能性をチェック
            self.merge_buddy_blocks(parent_ptr, parent_addr, parent_order);
        }
    }
    
    /// バディブロックのアドレスを計算
    fn get_buddy_address(&self, addr: usize, order: usize) -> usize {
        let block_size = self.config.page_size << order;
        addr ^ block_size
    }
    
    /// サイズからオーダーに変換
    fn size_to_order(&self, size: usize) -> usize {
        let page_size = self.config.page_size;
        let mut pages = (size + page_size - 1) / page_size;
        
        // ページ数を2のべき乗に切り上げ
        let mut order = 0;
        while (1 << order) < pages {
            order += 1;
        }
        
        order.min(self.config.max_order)
    }
    
    /// 空きブロックを探索
    fn find_free_block(&self, order: usize) -> Option<*mut BlockHeader> {
        let free_lists = self.free_lists.lock();
        
        // 要求されたオーダー以上のオーダーをチェック
        for current_order in order..=self.config.max_order {
            if !free_lists[current_order].is_null() {
                // 空きブロックが見つかった
                let block = free_lists[current_order];
                
                // ブロックをフリーリストから削除
                // 注: ここでロックを保持したまま操作するため、
                // remove_from_free_listを直接呼ばず簡略化
                let mut current_block = block;
                let mut next_block = unsafe { (*current_block).get_next() };
                
                // フリーリストを更新
                unsafe {
                    if !next_block.is_null() {
                        (*next_block).set_prev(null_mut());
                    }
                }
                
                drop(free_lists);
                
                // 要求されたオーダーより大きい場合は分割
                if current_order > order {
                    return self.split_block(block, order);
                }
                
                return Some(block);
            }
        }
        
        None
    }
    
    /// 統計情報を取得
    pub fn get_stats(&self) -> AllocatorStats {
        let total_pages = self.total_pages.load(Ordering::Relaxed);
        let used_pages = self.used_pages.load(Ordering::Relaxed);
        let free_pages = self.free_pages.load(Ordering::Relaxed);
        let page_size = self.config.page_size;
        
        // フラグメンテーション率を計算
        let fragmentation = self.calculate_fragmentation();
        
        AllocatorStats {
            total_memory: total_pages * page_size,
            used_memory: used_pages * page_size,
            free_memory: free_pages * page_size,
            total_pages,
            used_pages,
            fragmentation_percent: fragmentation,
        }
    }
    
    /// フラグメンテーション率を計算
    fn calculate_fragmentation(&self) -> usize {
        let free_pages = self.free_pages.load(Ordering::Relaxed);
        let split_blocks = self.split_blocks.load(Ordering::Relaxed);
        
        if free_pages == 0 {
            return 0;
        }
        
        // フラグメンテーション率 = 分割ブロック数 / 空きページ数 * 100
        let fragmentation = (split_blocks * 100) / free_pages;
        fragmentation.min(100)
    }
    
    /// 現在時刻を取得（ナノ秒）
    fn get_current_time_ns(&self) -> u64 {
        // 実装依存の時刻取得
        // システム時間が利用できる場合はそれを使用
        // 簡易実装としてカウンタ値を返す
        ALLOCATION_COUNTER.load(Ordering::Relaxed)
    }
    
    /// 割り当て時間の統計を更新
    fn update_allocation_time(&self, elapsed_ns: u64) {
        let current_avg = self.avg_allocation_time_ns.load(Ordering::Relaxed);
        let alloc_count = self.allocation_count.load(Ordering::Relaxed);
        
        if alloc_count <= 1 {
            self.avg_allocation_time_ns.store(elapsed_ns, Ordering::Relaxed);
        } else {
            // 指数移動平均で更新
            let new_avg = (current_avg * 9 + elapsed_ns) / 10;
            self.avg_allocation_time_ns.store(new_avg, Ordering::Relaxed);
        }
    }
    
    /// メモリコンパクションを実行
    pub fn compact_memory(&self) -> usize {
        if !self.initialized.load(Ordering::Acquire) {
            return 0;
        }
        
        self.compaction_attempts.fetch_add(1, Ordering::Relaxed);
        
        // 実装はより複雑になり、実際のメモリ移動が必要
        // ここでは単純化のため、隣接する空きブロックをマージするだけ
        
        let mut compacted = 0;
        
        // マージ可能なバディを探索
        for order in 0..self.config.max_order {
            let free_blocks = {
                let free_lists = self.free_lists.lock();
                let mut blocks = Vec::new();
                let mut current = free_lists[order];
                
                while !current.is_null() {
                    blocks.push(current);
                    current = unsafe { (*current).get_next() };
                }
                
                blocks
            };
            
            for block in free_blocks {
                let blocks = self.blocks.read().expect("ブロックマップのロック取得に失敗");
                let block_addr = match blocks.iter().find(|(_, &b)| b.as_ptr() == block) {
                    Some((addr, _)) => *addr,
                    None => continue,
                };
                
                // バディブロックをマージ
                drop(blocks);
                let buddy_addr = self.get_buddy_address(block_addr, order);
                let buddy_free = {
                    let blocks = self.blocks.read().expect("ブロックマップのロック取得に失敗");
                    match blocks.get(&buddy_addr) {
                        Some(buddy) => unsafe { (*buddy.as_ptr()).get_state() == BlockState::Free },
                        None => false,
                    }
                };
                
                if buddy_free {
                    // バディをマージ
                    unsafe {
                        let block_state = (*block).get_state();
                        if block_state == BlockState::Free {
                            self.merge_buddy_blocks(block, block_addr, order);
                            compacted += 1;
                        }
                    }
                }
            }
        }
        
        if compacted > 0 {
            self.compaction_successes.fetch_add(1, Ordering::Relaxed);
        }
        
        compacted
    }
}

// BuddyAllocatorをスレッド間で共有可能とマーク
unsafe impl Send for BuddyAllocator {}
// BuddyAllocatorをスレッド間で同期可能とマーク
unsafe impl Sync for BuddyAllocator {} 