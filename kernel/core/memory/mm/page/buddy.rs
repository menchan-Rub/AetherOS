// AetherOS バディアロケータ
//
// このモジュールはバディアロケータを実装します。バディアロケータは、
// メモリを2のべき乗サイズのブロックに分割して管理する効率的なアロケータです。

use super::AllocatorStats;
use crate::arch::{get_memory_map, MemoryRegion, MemoryRegionType, PhysicalAddress, PAGE_SIZE};
use alloc::vec::Vec;
use core::cmp::{max, min};
use log::{debug, info, warn};

/// 最大オーダー（2^MAX_ORDER ページのブロックサイズ）
const MAX_ORDER: usize = 10; // 最大 2^10 = 1024 ページ

/// バディアロケータ構造体
///
/// 物理メモリページを効率的に管理するためのバディアロケータを実装します。
pub struct BuddyAllocator {
    /// 各オーダーのフリーリスト
    free_lists: [Vec<usize>; MAX_ORDER + 1],
    /// 各ページのオーダー情報 (アドレス -> (オーダー, 使用中フラグ))
    page_info: Vec<(usize, bool)>,
    /// 管理対象の最小物理アドレス
    min_addr: usize,
    /// 管理対象の最大物理アドレス
    max_addr: usize,
    /// 総ページ数
    total_pages: usize,
    /// 空きページ数
    free_pages: usize,
    /// 予約済みページ数
    reserved_pages: usize,
}

impl BuddyAllocator {
    /// 新しいバディアロケータを作成
    pub fn new() -> Self {
        // フリーリストの初期化
        let free_lists = array_init::array_init(|_| Vec::new());

        BuddyAllocator {
            free_lists,
            page_info: Vec::new(),
            min_addr: 0,
            max_addr: 0,
            total_pages: 0,
            free_pages: 0,
            reserved_pages: 0,
        }
    }

    /// バディアロケータを初期化
    pub fn init(&mut self) {
        // メモリマップを取得
        let memory_map = get_memory_map();
        let mut total_memory = 0;
        let mut usable_memory = 0;

        // 合計メモリと使用可能メモリを計算
        for region in &memory_map {
            total_memory += region.size;
            if region.region_type == MemoryRegionType::Usable {
                usable_memory += region.size;
            }
        }

        info!("メモリマップ: 合計メモリ={} MB, 使用可能メモリ={} MB",
              total_memory / (1024 * 1024),
              usable_memory / (1024 * 1024));

        // 使用可能な最小・最大アドレスを特定
        let mut min_addr = usize::MAX;
        let mut max_addr = 0;

        for region in &memory_map {
            if region.region_type == MemoryRegionType::Usable {
                min_addr = min(min_addr, region.start);
                max_addr = max(max_addr, region.start + region.size);
            }
        }

        // ページサイズにアラインメント
        min_addr = (min_addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        max_addr = max_addr & !(PAGE_SIZE - 1);

        // 管理対象の総ページ数
        let total_pages = (max_addr - min_addr) / PAGE_SIZE;

        self.min_addr = min_addr;
        self.max_addr = max_addr;
        self.total_pages = total_pages;
        self.free_pages = 0;

        // ページ情報配列を初期化
        self.page_info = vec![(0, true); total_pages];

        info!("バディアロケータ初期化: 開始アドレス={:#x}, 終了アドレス={:#x}, 総ページ数={}",
              min_addr, max_addr, total_pages);

        // 使用可能なメモリ領域をフリーリストに追加
        for region in &memory_map {
            if region.region_type == MemoryRegionType::Usable {
                // 領域の開始・終了アドレスをページサイズにアラインメント
                let start = (region.start + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                let end = (region.start + region.size) & !(PAGE_SIZE - 1);

                if start < end {
                    self.add_free_region(start, end - start);
                }
            }
        }

        info!("バディアロケータ初期化完了: 空きページ数={}, 総ページ数={}",
              self.free_pages, self.total_pages);
    }

    /// メモリ領域をフリーリストに追加
    fn add_free_region(&mut self, start: usize, size: usize) {
        if start < self.min_addr || start >= self.max_addr {
            return;
        }

        let end = min(start + size, self.max_addr);
        let actual_size = end - start;
        let pages = actual_size / PAGE_SIZE;

        if pages == 0 {
            return;
        }

        debug!("フリー領域追加: 開始={:#x}, サイズ={} KB, ページ数={}",
              start, actual_size / 1024, pages);

        // 領域内の各アドレスを適切なサイズのブロックに分割して追加
        let mut addr = start;
        while addr < end {
            // 現在のアドレスから最大のブロックサイズを見つける
            let max_order = self.find_max_block_order(addr, end - addr);

            // ブロックを追加
            self.add_free_block(addr, max_order);

            // 次のアドレスに進む
            addr += (1 << max_order) * PAGE_SIZE;
        }
    }

    /// 与えられたサイズ内で作成可能な最大のブロックオーダーを見つける
    fn find_max_block_order(&self, addr: usize, size: usize) -> usize {
        // アドレスがアラインされているかチェック
        let page_idx = (addr - self.min_addr) / PAGE_SIZE;
        let pages = size / PAGE_SIZE;

        // ブロックサイズは2のべき乗である必要がある
        let mut order = 0;
        let mut block_size = 1;

        while order < MAX_ORDER && block_size * 2 <= pages && (page_idx & block_size) == 0 {
            block_size *= 2;
            order += 1;
        }

        order
    }

    /// フリーブロックをフリーリストに追加
    fn add_free_block(&mut self, addr: usize, order: usize) {
        // ページインデックスを計算
        let page_idx = (addr - self.min_addr) / PAGE_SIZE;

        // ページ情報を更新
        for i in 0..(1 << order) {
            if page_idx + i < self.page_info.len() {
                self.page_info[page_idx + i] = (order, false);
            }
        }

        // フリーリストに追加
        self.free_lists[order].push(addr);
        self.free_pages += 1 << order;

        debug!("フリーブロック追加: アドレス={:#x}, オーダー={}, ページ数={}",
              addr, order, 1 << order);
    }

    /// ページを割り当てる
    ///
    /// # 引数
    /// * `num_pages` - 割り当てるページ数
    ///
    /// # 戻り値
    /// * 割り当てが成功した場合は物理アドレス、失敗した場合は `None`
    pub fn alloc_pages(&mut self, num_pages: usize) -> Option<usize> {
        if num_pages == 0 {
            return None;
        }

        // 必要なオーダーを計算
        let mut order = 0;
        let mut pages = 1;
        while pages < num_pages && order < MAX_ORDER {
            pages *= 2;
            order += 1;
        }

        // 要求されたオーダー以上のブロックを探す
        let mut current_order = order;
        while current_order <= MAX_ORDER {
            if !self.free_lists[current_order].is_empty() {
                // ブロックを取得
                let addr = self.free_lists[current_order].pop().unwrap();

                // ブロックを分割
                if current_order > order {
                    self.split_block(addr, current_order, order);
                }

                // 割り当てたブロックをマークする
                let page_idx = (addr - self.min_addr) / PAGE_SIZE;
                for i in 0..(1 << order) {
                    if page_idx + i < self.page_info.len() {
                        self.page_info[page_idx + i] = (order, true);
                    }
                }

                // 空きページ数を更新
                self.free_pages -= 1 << order;

                debug!("ページ割り当て: アドレス={:#x}, オーダー={}, ページ数={}",
                      addr, order, 1 << order);

                return Some(addr);
            }

            current_order += 1;
        }

        warn!("ページ割り当て失敗: 要求ページ数={}, 要求オーダー={}", num_pages, order);
        None
    }

    /// ブロックを分割して、要求されたオーダーのブロックを作成
    fn split_block(&mut self, addr: usize, current_order: usize, target_order: usize) {
        if current_order <= target_order {
            return;
        }

        // ブロックを2つに分割
        let new_order = current_order - 1;
        let buddy_addr = addr + (1 << new_order) * PAGE_SIZE;

        // バディブロックをフリーリストに追加
        self.free_lists[new_order].push(buddy_addr);

        // ページ情報を更新
        let page_idx = (buddy_addr - self.min_addr) / PAGE_SIZE;
        for i in 0..(1 << new_order) {
            if page_idx + i < self.page_info.len() {
                self.page_info[page_idx + i] = (new_order, false);
            }
        }

        debug!("ブロック分割: 元ブロック={:#x}(オーダー={}), 新ブロック={:#x}(オーダー={})",
              addr, current_order, buddy_addr, new_order);

        // 必要に応じて、さらに分割
        if new_order > target_order {
            self.split_block(addr, new_order, target_order);
        }
    }

    /// 物理ページを解放する
    ///
    /// # 引数
    /// * `addr` - 解放する物理アドレス
    /// * `num_pages` - 解放するページ数
    pub fn free_pages(&mut self, addr: usize, num_pages: usize) {
        if num_pages == 0 || addr < self.min_addr || addr >= self.max_addr {
            return;
        }

        // アドレスがページサイズにアラインされているか確認
        if addr % PAGE_SIZE != 0 {
            warn!("ページ解放エラー: アドレス={:#x} はページアラインされていません", addr);
            return;
        }

        // ページインデックスを計算
        let page_idx = (addr - self.min_addr) / PAGE_SIZE;
        if page_idx >= self.page_info.len() {
            return;
        }

        // ページが割り当てられているか確認
        let (order, is_used) = self.page_info[page_idx];
        if !is_used {
            warn!("ページ解放エラー: アドレス={:#x} は既に解放されています", addr);
            return;
        }

        // ブロックサイズが解放するページ数と一致するか確認
        let block_pages = 1 << order;
        if block_pages != num_pages {
            warn!("ページ解放エラー: 不一致 - ブロックサイズ={}, 解放ページ数={}",
                 block_pages, num_pages);
            // ただし解放は続行（正しいオーダーで解放）
        }

        debug!("ページ解放: アドレス={:#x}, オーダー={}, ページ数={}",
              addr, order, block_pages);

        // ブロックを解放し、可能ならマージ
        self.free_block(addr, order);
    }

    /// ブロックを解放し、可能であればバディとマージ
    fn free_block(&mut self, addr: usize, order: usize) {
        // ページ情報を更新
        let page_idx = (addr - self.min_addr) / PAGE_SIZE;
        for i in 0..(1 << order) {
            if page_idx + i < self.page_info.len() {
                self.page_info[page_idx + i] = (order, false);
            }
        }

        // 空きページ数を更新
        self.free_pages += 1 << order;

        // バディアドレスを計算
        let buddy_addr = self.get_buddy_address(addr, order);

        // バディが存在し、同じオーダーで空き状態なら、マージして上位オーダーへ
        if order < MAX_ORDER && self.is_buddy_free(buddy_addr, order) {
            // バディをフリーリストから削除
            if let Some(index) = self.free_lists[order].iter().position(|&r| r == buddy_addr) {
                self.free_lists[order].remove(index);

                // マージしたブロックの先頭アドレスを決定
                let merged_addr = min(addr, buddy_addr);

                debug!("ブロックマージ: アドレス={:#x}, バディ={:#x}, 新オーダー={}",
                      addr, buddy_addr, order + 1);

                // マージしたブロックを再帰的に処理（上位オーダーでバディとのマージを試行）
                self.free_block(merged_addr, order + 1);
            } else {
                // バディが見つからない場合は現在のブロックをフリーリストに追加
                self.free_lists[order].push(addr);
            }
        } else {
            // バディが存在しないか使用中の場合は、現在のブロックをフリーリストに追加
            self.free_lists[order].push(addr);
        }
    }

    /// バディアドレスを計算する
    fn get_buddy_address(&self, addr: usize, order: usize) -> usize {
        // バディは同じオーダーのブロックで、特定のビットが反転したアドレス
        let mask = (1 << order) * PAGE_SIZE;
        addr ^ mask
    }

    /// バディブロックが空きかどうかをチェックする
    fn is_buddy_free(&self, buddy_addr: usize, order: usize) -> bool {
        // バディアドレスが有効範囲内かチェック
        if buddy_addr < self.min_addr || buddy_addr >= self.max_addr {
            return false;
        }

        // ページインデックスを計算
        let page_idx = (buddy_addr - self.min_addr) / PAGE_SIZE;
        if page_idx >= self.page_info.len() {
            return false;
        }

        // バディが同じオーダーで空き状態かチェック
        let (buddy_order, is_used) = self.page_info[page_idx];
        buddy_order == order && !is_used
    }

    /// アロケータの統計情報を取得
    pub fn get_stats(&self) -> AllocatorStats {
        let total_memory = self.total_pages * PAGE_SIZE;
        let free_memory = self.free_pages * PAGE_SIZE;
        let used_memory = total_memory - free_memory;
        let used_pages = self.total_pages - self.free_pages;

        // フラグメンテーション率を計算
        let fragmentation_percent = self.calculate_fragmentation();

        AllocatorStats {
            total_memory,
            used_memory,
            free_memory,
            total_pages: self.total_pages,
            used_pages,
            fragmentation_percent,
        }
    }

    /// フラグメンテーション率を計算（0-100%）
    fn calculate_fragmentation(&self) -> usize {
        if self.free_pages == 0 {
            return 0;
        }

        // 理想的には、すべての空きページが単一の大きなブロックになっているはず
        // フラグメンテーション率は、実際のブロック数と理想的なブロック数の比率で計算
        let mut total_blocks = 0;
        for order in 0..=MAX_ORDER {
            total_blocks += self.free_lists[order].len();
        }

        // 理想的なブロック数を計算
        let mut ideal_blocks = 0;
        let mut remaining_pages = self.free_pages;
        for order in (0..=MAX_ORDER).rev() {
            let block_pages = 1 << order;
            let blocks = remaining_pages / block_pages;
            ideal_blocks += blocks;
            remaining_pages -= blocks * block_pages;
        }

        // 残りのページがある場合は、最小ブロックとして加算
        if remaining_pages > 0 {
            ideal_blocks += 1;
        }

        // フラグメンテーション率を計算（0-100%）
        if ideal_blocks == 0 {
            0
        } else {
            ((total_blocks - ideal_blocks) * 100) / total_blocks
        }
    }

    /// 空きページ数を取得
    pub fn get_free_pages_count(&self) -> usize {
        self.free_pages
    }

    /// 使用中ページ数を取得
    pub fn get_used_pages_count(&self) -> usize {
        self.total_pages - self.free_pages
    }

    /// 総ページ数を取得
    pub fn get_total_pages_count(&self) -> usize {
        self.total_pages
    }

    /// 連続した空きページを探す（割り当てなし）
    pub fn find_free_pages(&self, num_pages: usize) -> Option<PhysicalAddress> {
        if num_pages == 0 {
            return None;
        }

        // 必要なオーダーを計算
        let mut required_order = 0;
        let mut pages = 1;
        while pages < num_pages && required_order < MAX_ORDER {
            pages *= 2;
            required_order += 1;
        }

        // 十分な大きさのブロックを探す
        for order in required_order..=MAX_ORDER {
            if !self.free_lists[order].is_empty() {
                return Some(self.free_lists[order][0]);
            }
        }

        None
    }

    /// メモリ領域を予約する（他のアロケータが使用できないようにする）
    pub fn reserve_region(&mut self, start_addr: PhysicalAddress, num_pages: usize) -> bool {
        if num_pages == 0 || start_addr < self.min_addr || start_addr >= self.max_addr {
            return false;
        }

        // アドレスがページサイズにアラインされているか確認
        if start_addr % PAGE_SIZE != 0 {
            return false;
        }

        // ページインデックスを計算
        let page_idx = (start_addr - self.min_addr) / PAGE_SIZE;
        if page_idx + num_pages > self.page_info.len() {
            return false;
        }

        // 領域が既に使用中でないか確認
        for i in 0..num_pages {
            let (_, is_used) = self.page_info[page_idx + i];
            if is_used {
                return false;
            }
        }

        // 領域を予約
        for i in 0..num_pages {
            self.page_info[page_idx + i] = (0, true);
        }

        // 予約ページ数を更新
        self.reserved_pages += num_pages;
        self.free_pages -= num_pages;

        true
    }

    /// メモリ領域の予約を解除する
    pub fn unreserve_region(&mut self, start_addr: PhysicalAddress, num_pages: usize) -> bool {
        if num_pages == 0 || start_addr < self.min_addr || start_addr >= self.max_addr {
            return false;
        }

        // アドレスがページサイズにアラインされているか確認
        if start_addr % PAGE_SIZE != 0 {
            return false;
        }

        // ページインデックスを計算
        let page_idx = (start_addr - self.min_addr) / PAGE_SIZE;
        if page_idx + num_pages > self.page_info.len() {
            return false;
        }

        // 領域が予約されているか確認
        for i in 0..num_pages {
            let (order, is_used) = self.page_info[page_idx + i];
            if !is_used || order != 0 {
                return false;
            }
        }

        // 領域を解放
        self.add_free_region(start_addr, num_pages * PAGE_SIZE);

        // 予約ページ数を更新
        self.reserved_pages -= num_pages;

        true
    }
} 