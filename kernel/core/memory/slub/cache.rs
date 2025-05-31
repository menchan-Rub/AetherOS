// AetherOS SLUB Cache実装

use alloc::collections::LinkedList;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::memory::{AllocFlags, PAGE_SIZE};
use crate::memory::buddy;
use crate::sync::{Mutex, SpinLock};
use crate::arch::cpu;

use super::page::{SlubPage, PageState};
use super::object::SlubObject;
use super::cpu_cache::PerCpuCache;
use super::stats::CacheStats;

/// キャッシュID型
pub type CacheId = usize;

/// キャッシュフラグ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheFlags(usize);

impl CacheFlags {
    /// すべてゼロ初期化
    pub const ZERO: CacheFlags = CacheFlags(1);
    
    /// ハードウェアキャッシュアライン
    pub const HWCACHE_ALIGN: CacheFlags = CacheFlags(2);
    
    /// 一括操作に最適化
    pub const BULK_OPS: CacheFlags = CacheFlags(4);
    
    /// デバッグ情報を維持
    pub const DEBUG: CacheFlags = CacheFlags(8);
    
    /// RCUフレンドリー
    pub const RCU_AWARE: CacheFlags = CacheFlags(16);
    
    /// 新しいフラグを作成
    pub const fn new(bits: usize) -> Self {
        CacheFlags(bits)
    }
    
    /// フラグをマージ
    pub const fn merge(&self, other: CacheFlags) -> Self {
        CacheFlags(self.0 | other.0)
    }
    
    /// フラグが含まれているか
    pub const fn contains(&self, flag: CacheFlags) -> bool {
        (self.0 & flag.0) == flag.0
    }
}

/// スラブキャッシュ構造体
#[derive(Debug)]
pub struct SlubCache {
    /// キャッシュID
    id: CacheId,
    
    /// キャッシュ名
    name: String,
    
    /// オブジェクトサイズ
    object_size: usize,
    
    /// アライメント
    align: usize,
    
    /// フラグ
    flags: CacheFlags,
    
    /// グローバルフリーリスト
    free_list: Mutex<LinkedList<SlubObject>>,
    
    /// パーCPUキャッシュ
    cpu_caches: Vec<PerCpuCache>,
    
    /// 部分的に埋まったスラブのリスト
    partial_slabs: Mutex<LinkedList<SlubPage>>,
    
    /// 完全に空のスラブのリスト
    free_slabs: Mutex<LinkedList<SlubPage>>,
    
    /// 完全に埋まったスラブのリスト
    full_slabs: Mutex<LinkedList<SlubPage>>,
    
    /// 統計情報
    stats: CacheStats,
    
    /// オブジェクト/スラブあたりの数
    objects_per_slab: usize,
    
    /// カラーリングオフセット
    color_offset: usize,
    
    /// 現在のカラー
    current_color: AtomicUsize,
}

impl SlubCache {
    /// 新しいキャッシュを作成
    pub fn new(
        id: CacheId, 
        name: &str, 
        size: usize, 
        align: usize, 
        flags: CacheFlags
    ) -> Result<Self, &'static str> {
        // サイズとアライメントを調整
        let adjusted_size = if size < align { align } else { size };
        
        // オブジェクトサイズを計算（ポインタサイズを追加）
        let real_size = adjusted_size + core::mem::size_of::<usize>();
        
        // スラブあたりのオブジェクト数を計算
        let objects_per_slab = calculate_objects_per_slab(real_size, PAGE_SIZE);
        if objects_per_slab == 0 {
            return Err("オブジェクトが大きすぎます");
        }
        
        // カラーリングオフセットを計算
        let color_offset = calculate_color_offset(real_size);
        
        // CPUキャッシュを作成
        let core_count = cpu::get_info().core_count;
        let mut cpu_caches = Vec::with_capacity(core_count);
        
        for _ in 0..core_count {
            cpu_caches.push(PerCpuCache::new(
                super::get_config().per_cpu_cache_size
            ));
        }
        
        Ok(SlubCache {
            id,
            name: String::from(name),
            object_size: real_size,
            align,
            flags,
            free_list: Mutex::new(LinkedList::new()),
            cpu_caches,
            partial_slabs: Mutex::new(LinkedList::new()),
            free_slabs: Mutex::new(LinkedList::new()),
            full_slabs: Mutex::new(LinkedList::new()),
            stats: CacheStats::default(),
            objects_per_slab,
            color_offset,
            current_color: AtomicUsize::new(0),
        })
    }
    
    /// キャッシュからオブジェクトを割り当て
    pub fn allocate(&self) -> Result<usize, &'static str> {
        // 現在のCPU ID取得
        let cpu_id = cpu::current_id();
        
        // CPUキャッシュからの高速割り当てを試みる
        if let Some(address) = self.cpu_caches[cpu_id as usize].pop() {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(address);
        }
        
        // CPUキャッシュミス
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        
        // グローバルリストから割り当て試行
        let mut free_list = self.free_list.lock();
        if let Some(obj) = free_list.pop_front() {
            return Ok(obj.address());
        }
        
        // 部分的に使用されているスラブから割り当て試行
        let mut partial_slabs = self.partial_slabs.lock();
        if let Some(slab) = partial_slabs.front_mut() {
            if let Some(address) = slab.allocate_object() {
                // スラブが満杯になった場合は移動
                if slab.is_full() {
                    let full_slab = partial_slabs.pop_front().unwrap();
                    self.full_slabs.lock().push_back(full_slab);
                }
                
                return Ok(address);
            }
        }
        
        // 空きスラブから割り当て試行
        let mut free_slabs = self.free_slabs.lock();
        if let Some(slab) = free_slabs.pop_front() {
            let address = slab.allocate_object().unwrap(); // 空きスラブからは必ず成功するはず
            partial_slabs.push_back(slab);
            return Ok(address);
        }
        
        // 新しいスラブを割り当て
        match self.allocate_slab() {
            Ok(new_slab) => {
                let address = new_slab.allocate_object().unwrap(); // 新規スラブからも必ず成功するはず
                partial_slabs.push_back(new_slab);
                Ok(address)
            },
            Err(e) => {
                log::error!("SlubCache '{}' (ID: {}): 新規スラブの割り当てに失敗しました (サイズ: {}). エラー: {}. キャッシュの縮小を試みます。", 
                           self.name, self.id, self.object_size, e);
                // フォールバックとしてキャッシュシュリンクを試みる
                match self.shrink() {
                    Ok(freed_pages) => {
                        log::info!("SlubCache '{}': シュリンク操作により {} ページ解放されました。再試行します。", self.name, freed_pages);
                        // シュリンク後にもう一度割り当てを試みる (再帰呼び出しに注意、ここでは1回のみ)
                        // より高度な実装では、リトライ回数制限や、それでも失敗した場合の処理が必要
                        // ここでは再度グローバルリストから探し、なければエラーとする単純な再試行
                        if let Some(obj) = self.free_list.lock().pop_front() {
                            return Ok(obj.address());
                        }
                        // 部分スラブからも再確認 (shrinkで状況が変わった可能性)
                        if let Some(slab) = self.partial_slabs.lock().front_mut() {
                            if let Some(address) = slab.allocate_object() {
                                if slab.is_full() {
                                    let full_slab = self.partial_slabs.lock().pop_front().unwrap();
                                    self.full_slabs.lock().push_back(full_slab);
                                }
                                return Ok(address);
                            }
                        }
                        log::error!("SlubCache '{}': シュリンク後の再試行でもオブジェクト割り当てに失敗しました。", self.name);
                        Err("新規スラブ割り当て失敗後、シュリンクしてもリカバリできませんでした")
                    },
                    Err(shrink_err) => {
                        log::error!("SlubCache '{}': シュリンク操作自体に失敗しました: {}。オブジェクト割り当て失敗。", self.name, shrink_err);
                        Err(e) // 元の allocate_slab のエラーを返す
                    }
                }
            }
        }
    }
    
    /// キャッシュにオブジェクトを返却
    pub fn free(&self, address: usize) -> Result<(), &'static str> {
        // アドレスの検証
        if address == 0 {
            return Err("無効なアドレスです (NULLポインタ)");
        }

        log::trace!("SlubCache '{}' (ID: {}): オブジェクト 0x{:x} の解放を開始します。", self.name, self.id, address);
        // デバッグフラグ有効時の追加検証実装
        if self.flags.contains(CacheFlags::DEBUG) {
            // 1. オブジェクトの二重解放チェック
            let object_metadata = self.find_object_metadata(address)
                .ok_or_else(|| "オブジェクトメタデータが見つかりません")?;
            
            if object_metadata.is_free {
                return Err("二重解放の検出: このオブジェクトは既に解放されています");
            }
            
            // 2. オブジェクト境界外書き込みチェック
            if let Err(e) = self.check_object_boundaries(address) {
                log::error!("境界侵害: {}", e);
                // 侵害情報をログに詳細出力
                self.log_boundary_violation(address);
                return Err("オブジェクト境界侵害が検出されました");
            }
            
            // 3. 解放前にオブジェクト内容をポイズニング (0xDEADBEEFパターン)
            unsafe {
                let obj_ptr = address as *mut u32;
                let obj_size = self.object_size;
                let words = obj_size / 4;
                
                for i in 0..words {
                    *obj_ptr.add(i) = 0xDEADBEEF;
                }
                
                // オブジェクトサイズが4の倍数でない場合の残りバイト
                let remainder = obj_size % 4;
                if remainder > 0 {
                    let last_bytes = (address + obj_size - remainder) as *mut u8;
                    for i in 0..remainder {
                        *last_bytes.add(i) = 0xDE;
                    }
                }
                
                // メモリバリア
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            }
            
            // 4. バックトレース記録（解放箇所特定用）
            if self.track_allocation_sites {
                let backtrace = crate::debug::capture_backtrace(3); // 3フレームスキップ
                self.free_sites.lock().insert(address, backtrace);
            }
        }
        
        // スラブを特定
        let slab_address = match self.find_slab_for_address(address) {
            Ok(sa) => sa,
            Err(e) => {
                log::error!("SlubCache '{}': アドレス 0x{:x} の解放試行中にスラブ特定に失敗: {}. このアドレスはこのキャッシュに属していない可能性があります。", self.name, address, e);
                // DEBUGフラグが有効なら、より詳細なダンプやパニックも検討
                return Err(e);
            }
        };

        if self.flags.contains(CacheFlags::DEBUG) {
            // スラブが特定できたことをログに残す
            log::trace!("SlubCache '{}': アドレス 0x{:x} はスラブ 0x{:x} に属すると判断し、CPUキャッシュまたはスラブへの返却を試みます。", self.name, address, slab_address);
        }
        
        // ローカルCPUキャッシュに返却
        let cpu_id = cpu::current_id();
        if self.cpu_caches[cpu_id as usize].push(address) {
            return Ok(());
        }
        
        // スラブに直接返却
        let slab_result = self.return_to_slab(address, slab_address);
        
        // 統計情報を更新
        self.stats.total_frees.fetch_add(1, Ordering::Relaxed);
        
        slab_result
    }
    
    /// 新しいスラブを割り当て
    fn allocate_slab(&self) -> Result<SlubPage, &'static str> {
        // バディアロケータからページを割り当て
        let flags = AllocFlags::default(); // 必要に応じてフラグを設定
        let page_address = buddy::allocate_pages(1, flags, 0)?;
        
        // カラーを計算
        let color = self.current_color.fetch_add(1, Ordering::Relaxed) % self.color_offset;
        self.current_color.compare_exchange(
            self.color_offset,
            0,
            Ordering::Relaxed,
            Ordering::Relaxed
        ).ok();
        
        // 新しいスラブを作成
        let new_slab = SlubPage::new(
            page_address,
            self.object_size,
            self.objects_per_slab,
            color,
            self.id,
            self.flags.contains(CacheFlags::ZERO)
        );
        
        // 統計情報を更新
        self.stats.total_slabs.fetch_add(1, Ordering::Relaxed);
        self.stats.active_slabs.fetch_add(1, Ordering::Relaxed);
        
        Ok(new_slab)
    }
    
    /// アドレスを含むスラブを見つける
    fn find_slab_for_address(&self, address: usize) -> Result<usize, &'static str> {
        // アドレスからスラブアドレスを計算 (ページ境界にアライン)
        let slab_address = address & !(PAGE_SIZE - 1);

        // スラブの検証を実装
        if self.flags.contains(CacheFlags::DEBUG) {
            unsafe {
                // 1. マジックナンバーの検証
                let slab_metadata = slab_address as *const SlubPageMetadata;
                if (*slab_metadata).magic != SLUB_PAGE_MAGIC {
                    return Err("無効なスラブメタデータ: マジックナンバー不一致");
                }
                
                // 2. 所有キャッシュIDの検証
                if (*slab_metadata).owner_cache_id != self.id {
                    return Err("無効なスラブメタデータ: キャッシュID不一致");
                }
                
                // 3. アドレス範囲の検証
                let slab_start = slab_address + core::mem::size_of::<SlubPageMetadata>();
                let slab_end = slab_address + PAGE_SIZE;
                
                if address < slab_start || address >= slab_end {
                    return Err("オブジェクトアドレスがスラブ範囲外");
                }
                
                // 4. アラインメント検証
                let offset_in_slab = address - slab_start;
                if offset_in_slab % self.object_size != 0 {
                    return Err("オブジェクトアドレスがアラインメント違反");
                }
                
                // 5. オブジェクトインデックスの検証
                let obj_index = offset_in_slab / self.object_size;
                let max_objects = (*slab_metadata).objects_per_slab;
                
                if obj_index >= max_objects {
                    return Err("オブジェクトインデックスがスラブの最大オブジェクト数を超過");
                }
                
                // 6. メタデータ整合性チェック
                let total_objects = (*slab_metadata).free_objects + (*slab_metadata).used_objects;
                if total_objects != max_objects {
                    log::warn!(
                        "スラブメタデータ整合性警告: free_objects({}) + used_objects({}) != max_objects({})",
                        (*slab_metadata).free_objects,
                        (*slab_metadata).used_objects,
                        max_objects
                    );
                }
                
                // 7. オブジェクトビットマップの検証（オプション）
                if self.flags.contains(CacheFlags::DEBUG) {
                    let is_object_free = (*slab_metadata).is_object_free(obj_index);
                    if is_object_free {
                        return Err("解放済みオブジェクトへのアクセス検出");
                    }
                }
            }
        }

        trace!("SlubCache '{}' (ID: {}): アドレス 0x{:x} はスラブ 0x{:x} に属すると判断しました。", self.name, self.id, address, slab_address);
        Ok(slab_address)
    }
    
    /// スラブにオブジェクトを返却
    fn return_to_slab(&self, address: usize, slab_address: usize) -> Result<(), &'static str> {
        // スラブの状態を調べる
        let mut full_slabs = self.full_slabs.lock();
        
        // 満杯スラブリストから検索
        for (index, slab) in full_slabs.iter_mut().enumerate() {
            if slab.address() == slab_address {
                // オブジェクトを返却
                slab.free_object(address)?;
                
                // 満杯からパーシャルに移動
                if !slab.is_full() {
                    let removed_slab = full_slabs.remove(index);
                    self.partial_slabs.lock().push_back(removed_slab);
                }
                
                return Ok(());
            }
        }
        
        // 部分的に使用されているスラブリストから検索
        let mut partial_slabs = self.partial_slabs.lock();
        for (index, slab) in partial_slabs.iter_mut().enumerate() {
            if slab.address() == slab_address {
                // オブジェクトを返却
                slab.free_object(address)?;
                
                // 空になったら空スラブリストに移動
                if slab.is_empty() {
                    let removed_slab = partial_slabs.remove(index);
                    
                    // 空スラブ数が閾値を超えたら解放するかどうか判断
                    let free_slabs_len = self.free_slabs.lock().len();
                    let release_threshold = super::get_config().slab_release_threshold;
                    
                    if free_slabs_len > release_threshold {
                        // スラブを解放
                        removed_slab.destroy();
                        self.stats.active_slabs.fetch_sub(1, Ordering::Relaxed);
                    } else {
                        // 空スラブリストに追加
                        self.free_slabs.lock().push_back(removed_slab);
                    }
                }
                
                return Ok(());
            }
        }
        
        // 空スラブリストから検索
        let mut free_slabs = self.free_slabs.lock();
        for slab in free_slabs.iter_mut() {
            if slab.address() == slab_address {
                return slab.free_object(address);
            }
        }
        
        Err("指定されたアドレスは無効です")
    }
    
    /// キャッシュを収縮して未使用のスラブを解放
    pub fn shrink(&self) -> Result<usize, &'static str> {
        let mut freed_pages = 0;
        
        // 空スラブを解放
        let mut free_slabs = self.free_slabs.lock();
        while let Some(slab) = free_slabs.pop_front() {
            slab.destroy();
            freed_pages += 1;
            self.stats.active_slabs.fetch_sub(1, Ordering::Relaxed);
        }
        
        // CPU別キャッシュを解放
        for cpu_cache in self.cpu_caches.iter() {
            freed_pages += cpu_cache.shrink()?;
        }
        
        Ok(freed_pages)
    }
    
    /// キャッシュを破棄
    pub fn destroy(&self) -> Result<(), &'static str> {
        // すべてのスラブを解放
        
        // 満杯スラブを解放
        let mut full_slabs = self.full_slabs.lock();
        while let Some(slab) = full_slabs.pop_front() {
            slab.destroy();
        }
        
        // 部分的に使用されているスラブを解放
        let mut partial_slabs = self.partial_slabs.lock();
        while let Some(slab) = partial_slabs.pop_front() {
            slab.destroy();
        }
        
        // 空スラブを解放
        let mut free_slabs = self.free_slabs.lock();
        while let Some(slab) = free_slabs.pop_front() {
            slab.destroy();
        }
        
        // CPUキャッシュをクリア
        for cpu_cache in self.cpu_caches.iter() {
            cpu_cache.clear()?;
        }
        
        Ok(())
    }
}

/// スラブあたりのオブジェクト数を計算
fn calculate_objects_per_slab(object_size: usize, slab_size: usize) -> usize {
    // オブジェクトサイズがページサイズより大きい場合
    if object_size > slab_size {
        return 0;
    }
    
    // スラブサイズからオブジェクト数を計算
    slab_size / object_size
}

/// カラーリングオフセットを計算
fn calculate_color_offset(object_size: usize) -> usize {
    // カラーオフセットの最大値を取得
    let max_offset = super::get_config().max_color_offset;
    
    // アラインメントに基づいてオフセットを計算
    let cache_line_size = 64; // 一般的なキャッシュラインサイズ
    
    // オブジェクトサイズがキャッシュラインサイズより小さい場合
    if object_size < cache_line_size {
        (cache_line_size / object_size).min(max_offset)
    } else {
        // オブジェクトが既にキャッシュラインサイズより大きい場合
        max_offset.min(4)
    }
} 