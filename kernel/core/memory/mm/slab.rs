// AetherOS Slabアロケータ実装
//
// Slabアロケータは同じサイズのオブジェクトを効率的に割り当てるために使用されます。
// カーネルのデータ構造（タスク、ファイルディスクリプタなど）の管理に最適です。

use crate::arch::PhysicalAddress;
use crate::core::memory::mm::page::{PageManager, PageMemoryType, flags};
use core::alloc::Layout;
use core::ptr::NonNull;
use spin::{Mutex, MutexGuard};
use alloc::vec::Vec;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::{String, ToString};
use log::{debug, trace, warn};

/// Slabのカラーリングオフセットの最大値
const MAX_SLAB_COLOR: usize = 16;

/// Slabサイズ（通常は1ページサイズ）
const SLAB_SIZE: usize = 4096;

/// アラインメント要件
const MIN_ALIGNMENT: usize = 8;

/// slabオブジェクトのメタデータ
struct SlabObjectMeta {
    /// 次の空きオブジェクトへのオフセット、または None
    next_free: Option<u16>, 
}

/// Slabページを表す構造体
struct SlabPage {
    /// このSlabのベースとなる物理アドレス
    phys_addr: PhysicalAddress,
    /// 仮想アドレス（マップされた場合）
    /// このアドレスは、Slabページ全体を指し、カラーリングオフセット前の先頭アドレスとなります。
    virt_addr: usize,
    /// 1つのオブジェクトのサイズ（メタデータとアライメント考慮済み）
    obj_size: usize,
    /// このSlabページ内の合計オブジェクト数
    total_objects: usize,
    /// 使用中のオブジェクト数
    used_objects: usize,
    /// 最初の空きオブジェクトのインデックスまたはNone
    /// `SlabObjectMeta` を介して単方向リストを形成します。
    free_list: Option<u16>,
    /// このSlabページのカラーリングオフセット
    /// キャッシュライン衝突を避けるために、Slab内のオブジェクト配置を開始するオフセットです。
    color_offset: usize,
    /// このSlabの所有者キャッシュへの参照（デバッグ用）
    owner_cache: String,
}

impl SlabPage {
    /// 新しいSlabページを作成する
    ///
    /// # Arguments
    /// * `phys_addr`: Slabページの物理ベースアドレス。ページアラインされている必要があります。
    /// * `virt_addr`: マップされた仮想ベースアドレス。ページアラインされている必要があります。
    /// * `obj_size`: 要求されたオブジェクトの純粋なサイズ（メタデータやアライメント含まず）。
    /// * `color_offset`: このスラブページで使用するカラーリングオフセット。
    /// * `owner`: このスラブページを所有するキャッシュの名前（デバッグ用）。
    ///
    /// # Panics
    /// * `obj_size` が0の場合。
    /// * `phys_addr` または `virt_addr` が0の場合 (デバッグ時)。
    /// * `color_offset` が `SLAB_SIZE` 以上の場合 (デバッグ時)。
    fn new(
        phys_addr: PhysicalAddress, 
        virt_addr: usize, 
        obj_size: usize, 
        color_offset: usize,
        owner: &str
    ) -> Self {
        debug_assert!(phys_addr != 0, "SlabPage::new phys_addr cannot be null");
        debug_assert!(virt_addr != 0, "SlabPage::new virt_addr cannot be null");
        assert!(obj_size > 0, "SlabPage::new obj_size must be greater than 0");
        debug_assert!(color_offset < SLAB_SIZE, "SlabPage::new color_offset must be less than SLAB_SIZE");

        // オブジェクトサイズにメタデータのサイズを加える
        let real_obj_size = obj_size.max(core::mem::size_of::<SlabObjectMeta>());
        // 最小アラインメントに合わせる
        let aligned_size = (real_obj_size + MIN_ALIGNMENT - 1) & !(MIN_ALIGNMENT - 1);
        
        // 使用可能な領域を計算（カラーリングオフセット後）
        let usable_space = SLAB_SIZE.saturating_sub(color_offset); // color_offset が SLAB_SIZE 以上なら0
        let total_objects = if aligned_size > 0 { usable_space / aligned_size } else { 0 };
        
        trace!("SlabPage new: owner='{}', phys=0x{:x}, virt=0x{:x}, obj_size={}, color_offset={}, real_obj_size={}, aligned_size={}, usable_space={}, total_objects={}",
               owner, phys_addr, virt_addr, obj_size, color_offset, real_obj_size, aligned_size, usable_space, total_objects);

        // 空きリストの初期化
        let mut result = Self {
            phys_addr,
            virt_addr,
            obj_size: aligned_size,
            total_objects,
            used_objects: 0,
            free_list: if total_objects > 0 { Some(0) } else { None },
            color_offset,
            owner_cache: owner.to_string(),
        };
        
        // 空きリストを初期化 (total_objects > 0 の場合のみ意味がある)
        if total_objects > 0 {
            result.init_free_list();
        }
        
        result
    }
    
    /// 空きリストを初期化する
    /// `virt_addr` が有効で、オブジェクトを配置するメモリ領域が書き込み可能である必要があります。
    fn init_free_list(&mut self) {
        debug_assert!(self.total_objects > 0, "init_free_list called on a slab with no objects");
        // 各オブジェクトを連結リストに繋げる
        // ループは total_objects - 1 まで。最後の要素は next_free = None となる。
        for i in 0..(self.total_objects as u16).saturating_sub(1) {
            let obj_ptr = self.obj_addr(i);
            debug_assert!(obj_ptr != 0, "Object pointer should not be null in init_free_list");
            // Ensure the object pointer is within the slab page bounds
            debug_assert!(obj_ptr >= self.virt_addr + self.color_offset && 
                          obj_ptr + self.obj_size <= self.virt_addr + SLAB_SIZE,
                          "Object pointer out of bounds in init_free_list");
            unsafe {
                let meta = obj_ptr as *mut SlabObjectMeta;
                (*meta).next_free = Some(i + 1);
            }
        }
        
        // 最後のオブジェクトはリストの終端
        if self.total_objects > 0 { // 再度確認（上記のdebug_assertとは別に）
            let last_obj_idx = (self.total_objects - 1) as u16;
            let last_obj_ptr = self.obj_addr(last_obj_idx);
            debug_assert!(last_obj_ptr != 0, "Last object pointer should not be null");
            debug_assert!(last_obj_ptr >= self.virt_addr + self.color_offset &&
                          last_obj_ptr + self.obj_size <= self.virt_addr + SLAB_SIZE,
                          "Last object pointer out of bounds in init_free_list");
            unsafe {
                let meta = last_obj_ptr as *mut SlabObjectMeta;
                (*meta).next_free = None;
            }
        }
        
        // 空きリストの先頭を設定
        self.free_list = Some(0); // total_objects > 0 は既に保証されているはず
        self.used_objects = 0;
    }
    
    /// 指定されたインデックスのオブジェクトの仮想アドレスを計算する
    ///
    /// # Panics
    /// * `idx` が `total_objects` 以上の場合 (デバッグ時)。
    #[inline]
    fn obj_addr(&self, idx: u16) -> usize {
        debug_assert!((idx as usize) < self.total_objects, 
                      "obj_addr index out of bounds: idx={}, total_objects={}", idx, self.total_objects);
        self.virt_addr + self.color_offset + (idx as usize * self.obj_size)
    }
    
    /// オブジェクトを割り当てる
    /// 空きオブジェクトが存在する場合、その仮想アドレスを返します。
    /// 内部で `used_objects` をインクリメントし、`free_list` を更新します。
    ///
    /// # Returns
    /// * `Some(usize)`: 割り当てられたオブジェクトの仮想アドレス。
    /// * `None`: 空きオブジェクトがない場合。
    fn alloc_object(&mut self) -> Option<usize> {
        if self.is_full() { // is_full は free_list.is_none() と同等のはず
            debug_assert!(self.free_list.is_none(), "alloc_object: Slab is full but free_list is Some");
            return None;
        }
        debug_assert!(self.free_list.is_some(), "alloc_object: Slab is not full but free_list is None");
        debug_assert!(self.used_objects < self.total_objects, "alloc_object: used_objects overflow before alloc");

        // 空きリストから取り出す
        let free_idx = self.free_list.unwrap(); // 上のassertでSomeが保証される
        let obj_addr = self.obj_addr(free_idx);
        
        // 次の空きオブジェクトを取得
        unsafe {
            // obj_addrが有効なメモリアドレスであることを期待
            debug_assert!(obj_addr != 0, "Object pointer should not be null in alloc_object");
            debug_assert!(obj_addr >= self.virt_addr + self.color_offset &&
                          obj_addr + self.obj_size <= self.virt_addr + SLAB_SIZE,
                          "Object pointer out of bounds in alloc_object");
            let meta = obj_addr as *mut SlabObjectMeta;
            self.free_list = (*meta).next_free;
        }
        
        self.used_objects += 1;
        // オブジェクトが割り当てられた後、used_objectsはtotal_objects以下であるべき
        debug_assert!(self.used_objects <= self.total_objects, "alloc_object: used_objects overflow after alloc");

        trace!("SlabPage '{}': オブジェクト割り当て: virt_addr=0x{:x}, phys_addr=0x{:x}, obj_idx={}, used/total={}/{}", 
               self.owner_cache, obj_addr, self.phys_addr_of(obj_addr), free_idx, self.used_objects, self.total_objects);
        
        Some(obj_addr)
    }
    
    /// オブジェクトを解放する
    /// 指定された仮想アドレスのオブジェクトを空きリストに戻します。
    /// 内部で `used_objects` をデクリメントし、`free_list` を更新します。
    ///
    /// # Arguments
    /// * `addr`: 解放するオブジェクトの仮想アドレス。
    ///
    /// # Returns
    /// * `true`: 解放に成功した場合。
    /// * `false`: 指定されたアドレスがこのスラブページに属していない、またはアライメントが不正な場合。
    ///
    /// # Safety
    /// 呼び出し元は、`addr` がこのスラブページから以前に割り当てられ、まだ解放されていない有効なオブジェクトを指すことを保証する責任があります（二重解放のチェックは限定的）。
    fn free_object(&mut self, addr: usize) -> bool {
        // アドレスがこのSlabページに属しているか確認
        if addr < self.virt_addr + self.color_offset || 
           addr >= self.virt_addr + SLAB_SIZE { // color_offset を考慮した実質的なSlabの開始アドレスと比較
            warn!("SlabPage '{}': 解放試行アドレス 0x{:x} はスラブ範囲 [0x{:x} - 0x{:x}) 外です。", 
                  self.owner_cache, addr, self.virt_addr + self.color_offset, self.virt_addr + SLAB_SIZE);
            return false;
        }
        
        // オブジェクト境界にアラインされているか確認
        let offset_in_colored_slab = addr - (self.virt_addr + self.color_offset);
        if self.obj_size == 0 || offset_in_colored_slab % self.obj_size != 0 {
            warn!("SlabPage '{}': 解放試行アドレス 0x{:x} (オフセット 0x{:x}) はオブジェクトサイズ {} のアライメントに違反しています。", 
                  self.owner_cache, addr, offset_in_colored_slab, self.obj_size);
            return false;
        }
        
        // オブジェクトインデックスを計算
        let obj_idx = (offset_in_colored_slab / self.obj_size) as u16;
        debug_assert!((obj_idx as usize) < self.total_objects, "free_object: Calculated obj_idx out of bounds");

        // デバッグビルド時: 二重解放の基本的なチェック (より高度なチェックはアロケータ層で)
        // 既にfree_listに含まれているか線形探索するのは高コストなので、ここでは行わない。
        // 代わりに、解放するオブジェクトのメタ領域が壊れていないかなどをチェックできる。
        // 例えば、デアロケーション時に特定のポイズン値を書き込み、アロケーション時にそれをチェックするなど。
        // 現状は、SlabObjectMeta の next_free が有効なインデックスかNoneを指しているかで判断 (限定的)

        // 空きリストに追加
        unsafe {
            // addrが有効なメモリアドレスであることを期待
            debug_assert!(addr != 0, "Object pointer should not be null in free_object");
            let meta = addr as *mut SlabObjectMeta;
            (*meta).next_free = self.free_list;
        }
        
        self.free_list = Some(obj_idx);
        debug_assert!(self.used_objects > 0, "free_object: used_objects underflow before free");
        self.used_objects -= 1;
        
        trace!("SlabPage '{}': オブジェクト解放: virt_addr=0x{:x}, phys_addr=0x{:x}, obj_idx={}, used/total={}/{}", 
               self.owner_cache, addr, self.phys_addr_of(addr), obj_idx, self.used_objects, self.total_objects);
        
        true
    }

    /// 指定された仮想アドレスに対応する物理アドレスを計算する (デバッグ/トレース用)
    /// virt_addr がこのスラブページに属していることを前提とする。
    #[inline]
    fn phys_addr_of(&self, virt_addr_in_slab: usize) -> PhysicalAddress {
        debug_assert!(virt_addr_in_slab >= self.virt_addr && virt_addr_in_slab < self.virt_addr + SLAB_SIZE,
                      "phys_addr_of: virt_addr_in_slab is out of slab page bounds");
        let offset = virt_addr_in_slab - self.virt_addr;
        self.phys_addr + offset
    }
    
    /// このSlabページが空かどうか
    #[inline]
    fn is_empty(&self) -> bool {
        self.used_objects == 0
    }
    
    /// このSlabページが満杯かどうか
    #[inline]
    fn is_full(&self) -> bool {
        // total_objects が0の場合も考慮 (この場合、常に満杯かつ空)
        if self.total_objects == 0 {
            return true; 
        }
        self.used_objects == self.total_objects
    }
    
    /// このSlabページの使用率
    fn usage_percentage(&self) -> f32 {
        if self.total_objects == 0 {
            return 0.0;
        }
        (self.used_objects as f32 / self.total_objects as f32) * 100.0
    }
}

/// SlabオブジェクトのROキャッシュ
struct SlabCache {
    /// キャッシュ名
    name: String,
    /// オブジェクトサイズ
    obj_size: usize,
    /// アラインメント要件
    alignment: usize,
    /// Slabページのリスト（パーティャル、フル、空き）
    partial_slabs: Vec<SlabPage>,
    full_slabs: Vec<SlabPage>,
    free_slabs: Vec<SlabPage>,
    /// カラーリングオフセットカウンタ
    next_color: usize,
    /// 作成済みのSlabページ数
    slab_count: usize,
    /// 割り当て済みのオブジェクト数
    allocated_objects: usize,
    /// NUMA対応のための優先ノードID
    numa_node_id: Option<usize>,
}

impl SlabCache {
    /// 新しいSlabキャッシュを作成する
    ///
    /// # Arguments
    /// * `name`: キャッシュの名前。
    /// * `obj_size`: キャッシュするオブジェクトのサイズ（バイト単位）。
    /// * `alignment`: オブジェクトのアライメント要件。
    /// * `node_id`: このキャッシュが優先的にメモリを確保すべきNUMAノードのID。`None`の場合は指定なし。
    ///
    /// # Returns
    /// 新しく作成された `SlabCache` インスタンス。
    ///
    /// # Panics
    /// * `obj_size` が0の場合。
    /// * `alignment` が0または2のべき乗でない場合 (デバッグ時)。
    fn new(name: &str, obj_size: usize, alignment: usize, node_id: Option<usize>) -> Self {
        assert!(obj_size > 0, "Object size must be greater than 0 for SlabCache '{}'", name);
        debug_assert!(alignment > 0 && alignment.is_power_of_two(),
                      "Alignment must be > 0 and a power of two for SlabCache '{}', got {}", name, alignment);
                // obj_size は alignment 以上であるべき、または alignment に切り上げられるべきだが、        // SlabPage::new で実効オブジェクトサイズが計算される際にアライメントが考慮されるため、ここではチェック不要。        trace!("Creating new SlabCache: name='{}', obj_size={}, alignment={}, node_id={:?}",                name, obj_size, alignment, node_id);        // キャッシュラインの最適化のため、アライメントを調整        // 一般的なCPUのキャッシュラインサイズは64バイト        let align_for_cache = if obj_size >= 64 || alignment >= 64 {            // 大きなオブジェクトはキャッシュライン単位でアライン            64        } else if obj_size <= 8 {            // 非常に小さいオブジェクトは複数をキャッシュラインに詰める            8        } else {            // 中間サイズのオブジェクトは自身のサイズに合わせる            alignment.max((obj_size + 7) & !7) // 8バイト単位に切り上げ        };                // 小さいオブジェクトの場合のプール容量最適化        let initial_capacity = if obj_size < 256 {            16 // 小さいオブジェクトはより多くのSlabを保持        } else if obj_size < 1024 {            8  // 中間サイズは適度な数        } else {            4  // 大きなオブジェクトはSlabを節約        };        Self {            name: name.to_string(),            obj_size,            alignment: alignment.max(align_for_cache), // キャッシュライン考慮済みのアライメント            partial_slabs: Vec::with_capacity(initial_capacity),            full_slabs: Vec::with_capacity(initial_capacity),            free_slabs: Vec::with_capacity(initial_capacity / 2),            next_color: 0,            slab_count: 0,            allocated_objects: 0,            numa_node_id: node_id,        }
    }
    
        /// 新しいSlabページを割り当て、初期化し、キャッシュに追加する。    /// このメソッドはキャッシュの内部ロックを取得している間に呼び出されることを想定している。    /// NUMAノードを考慮してメモリ割り当てを行う。    ///    /// # Returns    /// * `Some(SlabPage)`: 正常に割り当ておよび初期化された場合。    /// * `None`: 物理メモリの割り当てに失敗した場合、またはページのマッピングに失敗した場合。    fn allocate_slab(&mut self) -> Option<SlabPage> {        let page_manager = PageManager::get();                // オブジェクトのアクセスパターンに基づいたページフラグの決定        let mut page_flags = flags::KERNEL;                // NUMAノードを考慮してページを割り当てる        let phys_addr = match self.numa_node_id {            Some(node_id) => {                // 特定のNUMAノードからページを割り当て                trace!("SlabCache '{}': Attempting to allocate slab from NUMA node {}", self.name, node_id);                                // オブジェクトサイズに応じて最適な割り当て戦略を選択                if self.obj_size >= 1024 {                    // 大きなオブジェクトには連続したページを要求                    page_flags |= flags::ALLOC_CONTIGUOUS;                }                                match page_manager.alloc_page_on_node(PageMemoryType::Slab, page_flags, node_id) {                    Ok(addr) => {                        trace!("SlabCache '{}': Successfully allocated page on NUMA node {}", self.name, node_id);                        addr                    },                    Err(e) => {                        // 指定ノードでの割り当てに失敗した場合、任意のノードでフォールバック                        warn!("SlabCache '{}': Failed to allocate page on NUMA node {}: {:?}. Falling back to any node.",                                self.name, node_id, e);                        match page_manager.alloc_page(PageMemoryType::Slab, page_flags) {                            Ok(addr) => addr,                            Err(e) => {                                warn!("SlabCache '{}': Failed to allocate physical page for new slab: {:?}", self.name, e);                                return None;                            }                        }                    }                }            },            None => {                // NUMAノード指定がない場合は通常の割り当て                match page_manager.alloc_page(PageMemoryType::Slab, page_flags) {                    Ok(addr) => addr,                    Err(e) => {                        warn!("SlabCache '{}': Failed to allocate physical page for new slab: {:?}", self.name, e);                        return None;                    }                }            }        };                debug_assert!(phys_addr != 0, "allocate_slab: Physical address from page manager is null");        // キャッシュ特性を最適化        let cache_flags = if self.obj_size <= 64 {            // 小さいオブジェクトは頻繁にアクセスされる可能性が高いのでWriteBackが適切            PageMemoryType::WriteBack        } else if self.obj_size >= 4096 {            // 大きなオブジェクトはWriteThroughで直接更新            PageMemoryType::WriteThrough        } else {            // 中間サイズは標準キャッシュポリシー            PageMemoryType::WriteBack        };        // 物理メモリを仮想アドレス空間にマップする        let virt_addr = map_physical_memory(phys_addr, SLAB_SIZE, cache_flags)?;        if virt_addr == 0 { // マッピング失敗            warn!("SlabCache '{}': Failed to map physical memory 0x{:x} for new slab", self.name, phys_addr);            // 割り当てた物理ページを解放する必要がある            if page_manager.free_page(phys_addr).is_err() {                warn!("SlabCache '{}': Failed to free physical page 0x{:x} after mapping failure. Memory leak!", self.name, phys_addr);            }            return None;        }        debug_assert!(virt_addr != 0, "allocate_slab: Virtual address after mapping is null");        // メモリにプリフェッチヒントを送る（最初のアクセスを高速化）        if self.obj_size >= 64 {            for offset in (0..SLAB_SIZE).step_by(64) {                unsafe {                    crate::arch::prefetch((virt_addr + offset) as *const u8, 64, true);                }            }        }        trace!("SlabCache '{}': Allocated new slab. Phys: 0x{:x}, Virt: 0x{:x}, NUMA node: {:?}",                self.name, phys_addr, virt_addr, self.numa_node_id);

        let color = self.next_color;
        // MAX_SLAB_COLOR * MIN_ALIGNMENT が SLAB_SIZE を超えないように注意
        self.next_color = (self.next_color + 1) % MAX_SLAB_COLOR;

        let mut slab_page = SlabPage::new(phys_addr, virt_addr, self.obj_size, color * MIN_ALIGNMENT, &self.name);
        
        // オブジェクトが一つも配置できないSlabPageは無効
        if slab_page.total_objects == 0 {
            warn!("SlabCache '{}': New slab page (phys: 0x{:x}, virt: 0x{:x}, color_offset: {}) cannot hold any objects for obj_size {}. Discarding.", 
                  self.name, phys_addr, virt_addr, slab_page.color_offset, self.obj_size);
                        // マップ解除と物理ページ解放            if let Err(e) = unmap_physical_memory(virt_addr, SLAB_SIZE) {                warn!("SlabCache '{}': Failed to unmap virtual memory at 0x{:x}: {}",                      self.name, virt_addr, e);            }
            if page_manager.free_page(phys_addr).is_err() {
                warn!("SlabCache '{}': Failed to free physical page 0x{:x} after invalid slab page creation. Memory leak!", self.name, phys_addr);
            }
            return None;
        }

        self.slab_count += 1;
        Some(slab_page)
    }
    
    /// Slabページを解放し、関連する物理メモリも解放する。
    /// このメソッドはキャッシュの内部ロックを取得している間に呼び出されることを想定している。
    ///
    /// # Arguments
    /// * `slab`: 解放する `SlabPage`。
    ///
    /// # Panics
    /// * `slab.virt_addr` が0の場合 (デバッグ時)。
    /// * 物理ページの解放に失敗した場合 (リカバリ不能なためパニック、またはエラーログを出力して継続)。
    fn free_slab(&mut self, slab: SlabPage) {
        debug_assert!(slab.virt_addr != 0, "free_slab: SlabPage virtual address is null");
        debug_assert!(slab.phys_addr != 0, "free_slab: SlabPage physical address is null");
        trace!("SlabCache '{}': Freeing slab. Phys: 0x{:x}, Virt: 0x{:x}", self.name, slab.phys_addr, slab.virt_addr);

        let page_manager = PageManager::get();

                // 仮想メモリマッピングを解除        match unmap_physical_memory(slab.virt_addr, SLAB_SIZE) {            Ok(_) => {                trace!("SlabCache '{}': Successfully unmapped virtual memory at 0x{:x} (phys: 0x{:x})",                      self.name, slab.virt_addr, slab.phys_addr);            },            Err(e) => {                warn!("SlabCache '{}': Failed to unmap virtual memory at 0x{:x} (phys: 0x{:x}): {}",                     self.name, slab.virt_addr, slab.phys_addr, e);                // 解放処理は続行（物理メモリの解放は行う）            }        }

        // 物理ページを解放
        if let Err(e) = page_manager.free_page(slab.phys_addr) {
            // 物理ページの解放失敗は深刻な問題（メモリリーク）
            // システムの安定性に応じて、パニックさせるかエラーを記録して続行するかを決定
            warn!("SlabCache '{}': CRITICAL: Failed to free physical page 0x{:x} for slab (virt: 0x{:x}). Error: {:?}. Potential memory leak!", 
                  self.name, slab.phys_addr, slab.virt_addr, e);
            // ここでパニックすることも検討: panic!(...);
        }

        self.slab_count = self.slab_count.saturating_sub(1);
    }
    
    /// キャッシュからオブジェクトを割り当てる。
    /// 必要であれば新しいSlabページを割り当てる。
    /// このメソッドはキャッシュの内部ロックを取得している間に呼び出されることを想定している。
    ///
    /// # Returns
    /// * `Some(usize)`: 割り当てられたオブジェクトの仮想アドレス。
    /// * `None`: メモリ割り当てに失敗した場合（例: 物理メモリ不足で新しいスラブを確保できない）。
    fn alloc_object(&mut self) -> Option<usize> {
        trace!("SlabCache '{}': Attempting to allocate object. partial_slabs: {}, free_slabs: {}, full_slabs: {}", 
               self.name, self.partial_slabs.len(), self.free_slabs.len(), self.full_slabs.len());

        // 1. パーシャルSlabから割り当てを試みる
        if let Some(slab_idx) = self.partial_slabs.iter().position(|s| !s.is_full()) {
            let mut slab = self.partial_slabs.remove(slab_idx);
            match slab.alloc_object() {
                Some(addr) => {
                    trace!("SlabCache '{}': Allocated object 0x{:x} from partial slab (phys: 0x{:x})", self.name, addr, slab.phys_addr);
                    self.allocated_objects += 1;
                    if slab.is_full() {
                        trace!("SlabCache '{}': Partial slab (phys: 0x{:x}) became full. Moving to full_slabs.", self.name, slab.phys_addr);
                        self.full_slabs.push(slab);
                    } else {
                        self.partial_slabs.push(slab); // 再びpartialリストへ (効率のため先頭や末尾を検討)
                    }
                    return Some(addr);
                }
                None => {
                    // 本来ここには到達しないはず (is_full() でチェックしているため)
                    warn!("SlabCache '{}': Failed to allocate from supposedly non-full partial slab (phys: 0x{:x}). This indicates a bug.", self.name, slab.phys_addr);
                    // とりあえずfullリストに移動させておく (安全策)
                    self.full_slabs.push(slab);
                }
            }
        }

        // 2. 空きSlabから割り当てを試みる
        if let Some(mut slab) = self.free_slabs.pop() {
            trace!("SlabCache '{}': Trying to use a free slab (phys: 0x{:x}).", self.name, slab.phys_addr);
            debug_assert!(slab.is_empty(), "Slab in free_slabs was not empty!");
            match slab.alloc_object() {
                Some(addr) => {
                    trace!("SlabCache '{}': Allocated object 0x{:x} from a previously free slab (phys: 0x{:x})", self.name, addr, slab.phys_addr);
                    self.allocated_objects += 1;
                    if slab.is_full() {
                        trace!("SlabCache '{}': Previously free slab (phys: 0x{:x}) became full. Moving to full_slabs.", self.name, slab.phys_addr);
                        self.full_slabs.push(slab);
                    } else {
                        trace!("SlabCache '{}': Previously free slab (phys: 0x{:x}) is now partial. Moving to partial_slabs.", self.name, slab.phys_addr);
                        self.partial_slabs.push(slab);
                    }
                    return Some(addr);
                }
                None => {
                    // total_objects = 0 のSlabPageだった場合など
                    warn!("SlabCache '{}': Failed to allocate from a supposedly free slab (phys: 0x{:x}). This might indicate a slab with no usable objects.", self.name, slab.phys_addr);
                    // このSlabは問題がある可能性があるので、どこにも戻さず破棄する (free_slabで処理されるべきだったかもしれない)
                    // あるいは、allocate_slabでtotal_objects == 0 のチェックがされているので、ここには到達しないはず
                    // free_slab(slab) を呼ぶべきか？ しかし、このslabは既にfree_slabsからpopされている。
                    // ここで単純に破棄するとslab_countと合わなくなる。allocate_slabの時点で弾かれるべき。
                    // もしここに来たら、それはバグの可能性が高い。
                    // 安全のため、一旦full_slabs に移動させておくか、あるいは何もせずに（実質破棄）ログで警告。
                    // 今回は、allocate_slabでtotal_objects == 0がチェックされている前提で、ここには到達しないと仮定。
                    // 到達した場合はバグなので警告を出す。
                    self.full_slabs.push(slab); // 安全策としてfullに入れておく
                }
            }
        }

        // 3. 新しいSlabページを割り当てる
        trace!("SlabCache '{}': No suitable partial or free slabs found. Attempting to allocate a new slab.", self.name);
        if let Some(mut new_slab) = self.allocate_slab() {
            trace!("SlabCache '{}': Successfully allocated a new slab (phys: 0x{:x}).", self.name, new_slab.phys_addr);
            match new_slab.alloc_object() {
                Some(addr) => {
                    trace!("SlabCache '{}': Allocated object 0x{:x} from new slab (phys: 0x{:x})", self.name, addr, new_slab.phys_addr);
                    self.allocated_objects += 1;
                    if new_slab.is_full() {
                        trace!("SlabCache '{}': New slab (phys: 0x{:x}) became full immediately. Moving to full_slabs.", self.name, new_slab.phys_addr);
                        self.full_slabs.push(new_slab);
                    } else {
                        trace!("SlabCache '{}': New slab (phys: 0x{:x}) is now partial. Moving to partial_slabs.", self.name, new_slab.phys_addr);
                        self.partial_slabs.push(new_slab);
                    }
                    return Some(addr);
                }
                None => {
                    // allocate_slabで total_objects > 0 が保証されているはずなので、alloc_objectはSomeを返すはず
                    warn!("SlabCache '{}': Failed to allocate from a newly allocated slab (phys: 0x{:x}) which should have space. This indicates a severe bug.", self.name, new_slab.phys_addr);
                    // このSlabは問題がある。どこにも追加せず、allocate_slabで確保したリソースを解放すべきだが、
                    // ここではSlabPageのdropで物理ページが解放されるわけではないため、手動でfree_slabを呼ぶ必要がある。
                    // ただし、この状況は深刻なバグを示唆するため、ログ出力に留めるか、パニックも検討。
                    self.free_slab(new_slab); // 確保したスラブをすぐに解放
                    return None; // オブジェクト割り当て失敗
                }
            }
        } else {
            warn!("SlabCache '{}': Failed to allocate a new slab (e.g. out of physical memory). Cannot allocate object.", self.name);
            return None; // 新しいSlabの割り当てに失敗
        }
    }
    
    /// キャッシュにオブジェクトを解放する。
    /// オブジェクトが属するSlabページを見つけ、解放処理を行う。
    /// このメソッドはキャッシュの内部ロックを取得している間に呼び出されることを想定している。
    ///
    /// # Arguments
    /// * `addr`: 解放するオブジェクトの仮想アドレス。
    ///
    /// # Returns
    /// * `true`: 解放に成功した場合。
    /// * `false`: 指定されたアドレスがこのキャッシュのどのスラブにも属していない場合、または `SlabPage::free_object` が失敗した場合。
    fn free_object(&mut self, addr: usize) -> bool {
        debug_assert!(addr != 0, "free_object: Attempting to free a null pointer");
        trace!("SlabCache '{}': Attempting to free object at addr 0x{:x}", self.name, addr);

        // どのスラブに属しているかを探す
        // まずパーシャルスラブを検索
        if let Some(idx) = self.partial_slabs.iter().position(|s| 
            addr >= s.virt_addr && addr < s.virt_addr + SLAB_SIZE
        ) {
            let mut slab = self.partial_slabs.remove(idx);
            let slab_phys_addr = slab.phys_addr; // ログ用
            if slab.free_object(addr) {
                trace!("SlabCache '{}': Freed object 0x{:x} from partial slab (phys: 0x{:x})", self.name, addr, slab_phys_addr);
                self.allocated_objects = self.allocated_objects.saturating_sub(1);
                // もしスラブが空になったらfree_slabsへ移動
                if slab.is_empty() {
                    trace!("SlabCache '{}': Partial slab (phys: 0x{:x}) became empty. Moving to free_slabs.", self.name, slab_phys_addr);
                    self.free_slabs.push(slab);
                } else {
                    // 空でなければ、まだパーシャルなので戻す
                    self.partial_slabs.push(slab);
                }
                return true;
            } else {
                // SlabPage::free_objectがfalseを返した場合 (アドレス不正など)
                warn!("SlabCache '{}': SlabPage (phys: 0x{:x}) rejected free for addr 0x{:x}", self.name, slab_phys_addr, addr);
                self.partial_slabs.push(slab); // 元のリストに戻す
                return false;
            }
        }

        // 次にフルスラブを検索
        if let Some(idx) = self.full_slabs.iter().position(|s| 
            addr >= s.virt_addr && addr < s.virt_addr + SLAB_SIZE
        ) {
            let mut slab = self.full_slabs.remove(idx);
            let slab_phys_addr = slab.phys_addr; // ログ用
            if slab.free_object(addr) {
                trace!("SlabCache '{}': Freed object 0x{:x} from full slab (phys: 0x{:x})", self.name, addr, slab_phys_addr);
                self.allocated_objects = self.allocated_objects.saturating_sub(1);
                // フルだったスラブから解放されたので、必ずパーシャルになる (空になる場合も含む)
                // もしスラブが空になったらfree_slabsへ移動
                if slab.is_empty() {
                    trace!("SlabCache '{}': Full slab (phys: 0x{:x}) became empty. Moving to free_slabs.", self.name, slab_phys_addr);
                    self.free_slabs.push(slab);
                } else {
                    trace!("SlabCache '{}': Full slab (phys: 0x{:x}) is now partial. Moving to partial_slabs.", self.name, slab_phys_addr);
                    self.partial_slabs.push(slab);
                }
                return true;
            } else {
                // SlabPage::free_objectがfalseを返した場合
                warn!("SlabCache '{}': SlabPage (phys: 0x{:x}) from full_slabs rejected free for addr 0x{:x}", self.name, slab_phys_addr, addr);
                self.full_slabs.push(slab); // 元のリストに戻す
                return false;
            }
        }
        
        // free_slabs内のスラブは全て空のはずなので、解放対象のオブジェクトを含むことはない
        // ただし、念のためチェックするコードをデバッグビルドで入れることも検討できる
        debug_assert!(self.free_slabs.iter().all(|s| addr < s.virt_addr || addr >= s.virt_addr + SLAB_SIZE),
                      "free_object: Address 0x{:x} found in a supposedly empty slab! Cache: '{}'", addr, self.name);

        warn!("SlabCache '{}': Address 0x{:x} not found in any slabs for this cache.", self.name, addr);
        false
    }
    
    /// キャッシュを破棄し、関連するすべてのSlabページを解放する。
    /// このメソッドはキャッシュの内部ロックを取得している間に呼び出されることを想定している。
    /// 注意: このメソッドを呼び出す前に、このキャッシュから割り当てられたすべてのオブジェクトが
    /// 解放されていることを確認するのは呼び出し元の責任である。
    /// 解放されていないオブジェクトがある場合、それらへのポインタはダングリングポインタになる可能性がある。
    ///
    /// # Panics
    /// * `allocated_objects` が0でない場合（デバッグ時）。これは、解放漏れのオブジェクトがあることを示すため。
    fn destroy(&mut self) {
        trace!("SlabCache '{}': Destroying cache. allocated_objects: {}, slab_count: {}", 
               self.name, self.allocated_objects, self.slab_count);
        debug_assert!(self.allocated_objects == 0, 
                      "SlabCache '{}': Destroying cache with {} active allocations! Potential memory leak or use-after-free.", 
                      self.name, self.allocated_objects);

        // すべてのSlabページを解放
        // into_iter() を使って所有権を奪い、元のVecを空にする
        for slab in self.partial_slabs.drain(..) {
            trace!("SlabCache '{}': Freeing partial slab (phys: 0x{:x}) during destroy.", self.name, slab.phys_addr);
            self.free_slab(slab);
        }
        for slab in self.full_slabs.drain(..) {
            trace!("SlabCache '{}': Freeing full slab (phys: 0x{:x}) during destroy.", self.name, slab.phys_addr);
            self.free_slab(slab);
        }
        for slab in self.free_slabs.drain(..) {
            trace!("SlabCache '{}': Freeing free slab (phys: 0x{:x}) during destroy.", self.name, slab.phys_addr);
            self.free_slab(slab);
        }

        // カウンタをリセット (実際にはこのキャッシュインスタンスは通常破棄される)
        self.slab_count = 0;
        self.allocated_objects = 0; // debug_assert の後だが、念のため
        self.next_color = 0;

        trace!("SlabCache '{}': Cache destroyed.", self.name);
    }
    
    /// キャッシュの使用状況を報告する。
    /// (割り当て済みオブジェクト数, 合計オブジェクト数, 使用中スラブ数, 合計スラブ数)
    fn report_usage(&self) -> (usize, usize, usize, usize) {
        (
            self.obj_size,
            self.allocated_objects,
            self.slab_count,
            self.slab_count * SLAB_SIZE,
        )
    }
}

/// Slabアロケータ管理構造体
pub struct SlabAllocator {
    /// サイズ別の汎用キャッシュ（8, 16, 32, 64, 128, 256, 512, 1024, 2048バイト）
    size_caches: BTreeMap<usize, SlabCache>,
    /// 名前付きの特殊キャッシュ
    named_caches: BTreeMap<String, SlabCache>,
}

impl SlabAllocator {
    /// 新しいSlabアロケータを作成
    pub fn new() -> Self {
        let mut allocator = Self {
            size_caches: BTreeMap::new(),
            named_caches: BTreeMap::new(),
        };
        
        // 標準サイズキャッシュを初期化
        let standard_sizes = [8, 16, 32, 64, 128, 256, 512, 1024, 2048];
        for &size in &standard_sizes {
            let cache_name = format!("size-{}", size);
            let cache = SlabCache::new(&cache_name, size, MIN_ALIGNMENT, None);
            allocator.size_caches.insert(size, cache);
        }
        
        allocator
    }
    
    /// 適切なサイズのキャッシュを選択
    fn select_size_cache(&self, size: usize) -> Option<usize> {
        self.size_caches.keys()
            .filter(|&&cache_size| cache_size >= size)
            .min()
            .copied()
    }
    
    /// 特定サイズのメモリを汎用キャッシュから割り当て
    pub fn allocate(&mut self, size: usize) -> Option<usize> {
        // サイズが大きすぎる場合は処理できない
        if size > 2048 {
            return None;
        }
        
        // 適切なサイズキャッシュを選択
        let cache_size = self.select_size_cache(size)?;
        let cache = self.size_caches.get_mut(&cache_size)?;
        
        cache.alloc_object()
    }
    
    /// メモリを解放
    pub fn deallocate(&mut self, ptr: usize) -> bool {
        // まず汎用キャッシュで試す
        for (_, cache) in &mut self.size_caches {
            if cache.free_object(ptr) {
                return true;
            }
        }
        
        // 次に名前付きキャッシュで試す
        for (_, cache) in &mut self.named_caches {
            if cache.free_object(ptr) {
                return true;
            }
        }
        
        warn!("SlabAllocator: Pointer 0x{:x} not found in any cache for deallocation.", ptr);
        false
    }
    
    /// 新しい名前付きキャッシュを作成する。
    /// 作成されたキャッシュは `named_caches` に格納される。
    ///
    /// # Arguments
    /// * `name`: 作成するキャッシュの名前。既存のキャッシュ名と衝突してはならない。空であってはならない。
    /// * `obj_size`: このキャッシュで割り当てるオブジェクトのサイズ。0より大きくなければならない。
    /// * `alignment`: オブジェクトのアライメント要件。`MIN_ALIGNMENT` 以上で、2のべき乗でなければならない。
    ///
    /// # Returns
    /// * `true`: キャッシュの作成に成功した場合。
    /// * `false`: キャッシュ名が空、または既に存在する場合。`obj_size` が0の場合。`alignment` が不正な場合。
    ///
    /// # Panics
    /// * (デバッグ時) `SlabCache::new` の内部パニック条件に抵触した場合。
    pub fn create_cache(&mut self, name: &str, obj_size: usize, alignment: usize) -> bool {
        debug_assert!(!name.is_empty(), "Cache name cannot be empty in create_cache");
        debug_assert!(obj_size > 0, "Object size must be > 0 in create_cache for '{}'", name);
        debug_assert!(alignment > 0 && alignment.is_power_of_two(),
                      "Alignment must be > 0 and a power of two in create_cache for '{}', got {}", name, alignment);
        trace!(
            "SlabAllocator::create_cache: name='{}', obj_size={}, alignment={}",
            name,
            obj_size,
            alignment
        );

        if self.named_caches.contains_key(name) {
            warn!(
                "SlabAllocator::create_cache: Cache with name '{}' already exists.",
                name
            );
            return false;
        }

        // name が標準サイズキャッシュの命名規則 ("size_XXX") と衝突しないか確認
        if name.starts_with("size_") {
            warn!(
                "SlabAllocator::create_cache: Cache name '{}' might conflict with standard size cache naming convention.", 
                name
            );
            // ここでは警告に留め、作成は許可する。厳格にするなら false を返す。
        }

        let cache = SlabCache::new(name, obj_size, alignment, None); // NUMAノードIDとしてNoneを渡す
        self.named_caches.insert(name.to_string(), cache);
        true
    }
    
    /// 名前付きキャッシュからオブジェクトを割り当てる。
    ///
    /// # Arguments
    /// * `name`: オブジェクトを割り当てるキャッシュの名前。空であってはならない。
    ///
    /// # Returns
    /// * `Some(usize)`: 割り当てられたオブジェクトの仮想アドレス。
    /// * `None`: 指定された名前のキャッシュが存在しない、またはそのキャッシュからの割り当てに失敗した場合。
    ///
    /// # Panics
    /// * `name` が空の場合 (デバッグ時)。
    pub fn allocate_from_cache(&mut self, name: &str) -> Option<usize> {
        debug_assert!(!name.is_empty(), "SlabAllocator::allocate_from_cache called with empty name");
        trace!("SlabAllocator: Attempting to allocate from named cache '{}'", name);

        if let Some(cache) = self.named_caches.get_mut(name) {
            match cache.alloc_object() {
                Some(addr) => {
                    trace!("SlabAllocator: Allocated object at 0x{:x} from named cache '{}'", addr, name);
                    return Some(addr);
                }
                None => {
                    warn!("SlabAllocator: Failed to allocate object from named cache '{}'. Cache might be full or ran out of memory.", name);
                    return None;
                }
            }
        } else {
            warn!("SlabAllocator: Named cache '{}' not found for allocation.", name);
            None
        }
    }
    
    /// 指定された名前の名前付きキャッシュを削除し、関連するすべてのリソースを解放する。
    ///
    /// # Arguments
    /// * `name`: 削除するキャッシュの名前。空であってはならない。
    ///
    /// # Returns
    /// * `true`: キャッシュの削除に成功した場合。
    /// * `false`: 指定された名前のキャッシュが存在しない場合。
    ///
    /// # Panics
    /// * `name` が空の場合 (デバッグ時)。
    /// * 解放漏れのオブジェクトがキャッシュ内に残っている場合 (デバッグ時、`SlabCache::destroy` 内で発生)。
    pub fn destroy_cache(&mut self, name: &str) -> bool {
        debug_assert!(!name.is_empty(), "SlabAllocator::destroy_cache called with empty name");
        trace!("SlabAllocator: Attempting to destroy named cache '{}'", name);

        if let Some(mut cache) = self.named_caches.remove(name) {
            trace!("SlabAllocator: Destroying named cache '{}' (was found).", name);
            cache.destroy(); // SlabCache::destroy内で詳細なログとアサーションが行われる
            trace!("SlabAllocator: Named cache '{}' successfully destroyed.", name);
            true
        } else {
            warn!("SlabAllocator: Named cache '{}' not found for destruction.", name);
            false
        }
    }
    
    /// すべての汎用サイズキャッシュおよび名前付きキャッシュの現在の使用状況をデバッグログに出力する。
    /// 各キャッシュについて、オブジェクトサイズ、割り当て済みオブジェクト数、スラブ数、総メモリ使用量などが報告される。
    /// また、全体での合計オブジェクト数と合計メモリ使用量も報告される。
    pub fn report_usage(&self) {
        debug!("=== SlabAllocator Usage Report ===");
        trace!("SlabAllocator: Beginning usage report generation.");

        let mut grand_total_allocated_objects = 0;
        let mut grand_total_capacity = 0;
        let mut grand_total_active_slabs = 0;
        let mut grand_total_slabs = 0;

        debug!("--- Size Caches ---");
        if self.size_caches.is_empty() {
            debug!("  No size caches active.");
        } else {
            for (size_key, cache) in &self.size_caches {
                let (allocated, capacity, active_slabs, total_slabs) = cache.report_usage();
                debug!("  Cache '{}' (for obj_size: {}B): Objects: {}/{}, Slabs: {}/{} (Active/Total)", 
                       cache.name, size_key, allocated, capacity, active_slabs, total_slabs);
                grand_total_allocated_objects += allocated;
                grand_total_capacity += capacity;
                grand_total_active_slabs += active_slabs;
                grand_total_slabs += total_slabs;
            }
        }

        debug!("--- Named Caches ---");
        if self.named_caches.is_empty() {
            debug!("  No named caches active.");
        } else {
            for (name, cache) in &self.named_caches {
                let (allocated, capacity, active_slabs, total_slabs) = cache.report_usage();
                // 名前付きキャッシュの場合、cache.obj_size を直接参照してオブジェクトサイズを表示
                debug!("  Cache '{}' (obj_size: {}B): Objects: {}/{}, Slabs: {}/{} (Active/Total)", 
                       name, cache.obj_size, allocated, capacity, active_slabs, total_slabs);
                grand_total_allocated_objects += allocated;
                grand_total_capacity += capacity;
                grand_total_active_slabs += active_slabs;
                grand_total_slabs += total_slabs;
            }
        }
        
        debug!("--- Overall Totals ---");
        debug!("  Total Allocated Objects: {}", grand_total_allocated_objects);
        debug!("  Total Object Capacity:   {}", grand_total_capacity);
        debug!("  Total Active Slabs:      {}", grand_total_active_slabs);
        debug!("  Total Slabs Managed:     {}", grand_total_slabs);
        let overall_occupancy = if grand_total_capacity > 0 {
            (grand_total_allocated_objects as f64 / grand_total_capacity as f64) * 100.0
        } else {
            0.0
        };
        debug!("  Overall Occupancy:       {:.2}%", overall_occupancy);

        trace!("SlabAllocator: Usage report generation complete.");
        debug!("==================================");
    }
}

// グローバルSlabアロケータのインスタンス
static SLAB_ALLOCATOR: Mutex<Option<SlabAllocator>> = Mutex::new(None);

/// SlabアロケータのAPIモジュール
pub mod api {
    use super::*;
    
    /// Slabアロケータを初期化
    pub fn init() {
        debug!("Slabアロケータを初期化中...");
        
        let allocator = SlabAllocator::new();
        let mut global = SLAB_ALLOCATOR.lock();
        *global = Some(allocator);
        
        debug!("Slabアロケータの初期化が完了しました");
    }
    
    /// Slabアロケータを取得
    fn get_allocator<'a>() -> MutexGuard<'a, Option<SlabAllocator>> {
        let guard = SLAB_ALLOCATOR.lock();
        if guard.is_none() {
            panic!("Slabアロケータが初期化されていません");
        }
        guard
    }
    
    /// 特定サイズのメモリを割り当て
    pub fn allocate(size: usize) -> Option<NonNull<u8>> {
        let mut allocator = get_allocator();
        
        if let Some(addr) = allocator.as_mut().unwrap().allocate(size) {
            unsafe { NonNull::new(addr as *mut u8) }
        } else {
            None
        }
    }
    
    /// メモリを解放
    pub fn deallocate(ptr: NonNull<u8>) -> bool {
        let mut allocator = get_allocator();
        
        allocator.as_mut().unwrap().deallocate(ptr.as_ptr() as usize)
    }
    
    /// レイアウトに基づいてメモリを割り当て
    pub fn allocate_layout(layout: Layout) -> Option<NonNull<u8>> {
        if layout.size() <= 2048 && layout.align() <= MIN_ALIGNMENT {
            allocate(layout.size())
        } else {
            None
        }
    }
    
    /// 名前付きキャッシュを作成
    pub fn create_cache(name: &str, obj_size: usize, alignment: usize) -> bool {
        let mut allocator = get_allocator();
        
        allocator.as_mut().unwrap().create_cache(name, obj_size, alignment)
    }
    
    /// 名前付きキャッシュからオブジェクトを割り当て
    pub fn allocate_from_cache(name: &str) -> Option<NonNull<u8>> {
        let mut allocator = get_allocator();
        
        if let Some(addr) = allocator.as_mut().unwrap().allocate_from_cache(name) {
            unsafe { NonNull::new(addr as *mut u8) }
        } else {
            None
        }
    }
    
    /// 名前付きキャッシュを削除
    pub fn destroy_cache(name: &str) -> bool {
        let mut allocator = get_allocator();
        
        allocator.as_mut().unwrap().destroy_cache(name)
    }
    
    /// すべてのキャッシュの使用状況を報告
    pub fn report_usage() {
        let allocator = get_allocator();
        
        allocator.as_ref().unwrap().report_usage();
    }
}

/// グローバルアロケータ機能のためのラッパー関数
pub mod global_alloc {
    use super::*;
    use core::alloc::{GlobalAlloc, Layout};
    use core::ptr;
    
    /// グローバルアロケータの実装
    pub struct SlabGlobalAlloc;
    
    unsafe impl GlobalAlloc for SlabGlobalAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if let Some(ptr) = api::allocate_layout(layout) {
                ptr.as_ptr()
            } else {
                // サイズが大きい場合や初期化前の場合はページアロケータを直接使用
                let page_manager = PageManager::get();
                let size = layout.size();
                let pages = (size + SLAB_SIZE - 1) / SLAB_SIZE;
                
                if let Some(phys_addr) = page_manager.alloc_pages(                    pages,                    flags::KERNEL_USED,                    PageMemoryType::Normal,                    0, // カーネル所有                ) {                    // 物理アドレスを仮想アドレスにマッピング                    let virt_addr = map_physical_memory(                        phys_addr as usize,                        pages * SLAB_SIZE,                        flags::KERNEL_USED // キャッシュフラグを引き継ぐ                    );                                        if virt_addr == 0 {                        // マッピングに失敗した場合は物理メモリを解放して失敗を返す                        page_manager.free_pages(phys_addr, pages);                        ptr::null_mut()                    } else {                        virt_addr as *mut u8                    }                } else {                    ptr::null_mut()                }
            }
        }
        
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            if layout.size() <= 2048 && layout.align() <= MIN_ALIGNMENT {
                if let Some(non_null) = NonNull::new(ptr) {
                    if !api::deallocate(non_null) {
                        // Slabアロケータでの解放に失敗した場合
                        warn!("Slabアロケータで解放できないポインタ: {:p}", ptr);
                    }
                }
            } else {
                // ページアロケータで割り当てたメモリを解放
                let page_manager = PageManager::get();
                page_manager.free_pages(ptr as PhysicalAddress, (layout.size() + SLAB_SIZE - 1) / SLAB_SIZE);
            }
        }
    }
}

// 物理アドレスを仮想アドレスに変換
fn phys_to_virt(phys_addr: usize) -> usize {
    if crate::arch::is_higher_half() {
        // 高位半分カーネルの場合、物理アドレスに定数オフセットを加える
        phys_addr + crate::arch::KERNEL_VIRTUAL_BASE
    } else {
        // 直接マッピングの場合、そのまま返す
        phys_addr
    }
}

/// 物理メモリを指定されたキャッシュフラグでマップする
///
/// # Arguments
/// * `phys_addr`: マップする物理アドレス
/// * `size`: マップするサイズ（バイト単位）
/// * `mem_type`: 要求されるメモリタイプ（キャッシュ属性など）
///
/// # Returns
/// * `Ok(usize)`: マップされた仮想アドレス
/// * `Err(&'static str)`: エラーが発生した場合
///
/// - 実際のページテーブル操作を実装する。
/// - `mem_type` に基づいて適切なキャッシュ属性を設定する。
/// - エラーハンドリングを強化する。
fn map_physical_memory(phys_addr: PhysicalAddress, size: usize, mem_type: PageMemoryType) -> Result<usize, &'static str> {
    // ページマネージャから仮想アドレス範囲を確保
    let virt_addr = crate::core::memory::mm::vmm::allocate_virtual_range(size)
        .ok_or("仮想アドレス空間の確保に失敗しました")?;

    trace!(
        "map_physical_memory: phys=0x{:x}, size={}B, mem_type={:?}, mapped_to_virt=0x{:x}",
        phys_addr,
        size,
        mem_type,
        virt_addr
    );
    
    // ページマッピングを行う
    let flags = PageFlags::from_memory_type(mem_type) | PageFlags::PRESENT | PageFlags::WRITABLE;
    let num_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    crate::core::memory::mm::map_pages(virt_addr, phys_addr, num_pages, flags)?;

    Ok(virt_addr)
}

/// ページテーブル操作の実装
/// 仮想アドレスから物理アドレスへのマッピングを行う
fn map_virtual_to_physical(virt_addr: usize, phys_addr: usize, size: usize, flags: PageFlags) -> Result<(), &'static str> {
    if virt_addr % PAGE_SIZE != 0 || phys_addr % PAGE_SIZE != 0 {
        return Err("アドレスがページ境界にアライメントされていません");
    }
    let page_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    let mut mapped = 0;
    match crate::arch::current() {
        crate::arch::Architecture::X86_64 => unsafe {
            let cr3 = crate::arch::x86_64::read_cr3() & 0xFFFFFFFFFF000;
            for i in 0..page_count {
                let v_addr = virt_addr + i * PAGE_SIZE;
                let p_addr = phys_addr + i * PAGE_SIZE;
                // ページテーブルエントリを設定（省略: 実際はPML4/PDPT/PD/PTを辿る）
                if let Err(e) = crate::arch::x86_64::map_page(v_addr, p_addr, flags) {
                    // ロールバック
                    for j in 0..mapped { let va = virt_addr + j * PAGE_SIZE; let _ = crate::arch::x86_64::unmap_page(va); }
                    return Err(e);
                }
                mapped += 1;
                crate::arch::x86_64::invlpg(v_addr as *const u8);
            }
        },
        crate::arch::Architecture::AARCH64 => unsafe {
            for i in 0..page_count {
                let v_addr = virt_addr + i * PAGE_SIZE;
                let p_addr = phys_addr + i * PAGE_SIZE;
                if let Err(e) = crate::arch::aarch64::map_page(v_addr, p_addr, flags) {
                    for j in 0..mapped { let va = virt_addr + j * PAGE_SIZE; let _ = crate::arch::aarch64::unmap_page(va); }
                    return Err(e);
                }
                mapped += 1;
                crate::arch::aarch64::flush_tlb_page(v_addr);
            }
        },
        _ => return Err("未サポートのアーキテクチャです"),
    }
    Ok(())
}