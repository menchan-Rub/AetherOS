// AetherOS 物理→仮想アドレス逆引きマップ
//
// このモジュールは、物理アドレスから仮想アドレスへの逆引きマッピングを提供し、
// メモリ管理の効率化、デバッグ、およびシステム診断をサポートします。

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};
use crate::arch::PageSize;
use crate::core::memory::mm::{self, PageTable, PageTableLevel};

/// 物理メモリマッピング情報
#[derive(Debug, Clone)]
pub struct PhysicalMapping {
    /// 仮想アドレス
    pub virtual_address: usize,
    /// マッピングサイズ（バイト単位）
    pub size: usize,
    /// 物理アドレス
    pub physical_address: usize,
    /// マッピング所有者（プロセスIDなど、0はカーネル）
    pub owner_id: usize,
    /// マッピング種別
    pub mapping_type: MappingType,
    /// ページ属性
    pub attributes: PageAttributes,
}

/// マッピング種別
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MappingType {
    /// カーネルコード
    KernelCode,
    /// カーネルデータ
    KernelData,
    /// カーネルヒープ（動的割り当て）
    KernelHeap,
    /// カーネルスタック
    KernelStack,
    /// ユーザープロセスコード
    UserCode,
    /// ユーザープロセスデータ
    UserData,
    /// ユーザープロセススタック
    UserStack,
    /// 共有メモリ
    SharedMemory,
    /// メモリマップドI/O
    MMIO,
    /// DMAバッファ
    DMABuffer,
    /// テレページ（リモートメモリ）
    TelePageMemory,
    /// 一時マッピング
    Temporary,
    /// その他/未分類
    Other,
}

/// ページ属性
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PageAttributes {
    /// 読み取り可能
    pub readable: bool,
    /// 書き込み可能
    pub writable: bool,
    /// 実行可能
    pub executable: bool,
    /// キャッシュ可能
    pub cacheable: bool,
    /// ユーザーモードからアクセス可能
    pub user_accessible: bool,
    /// グローバル（全プロセスで共有）
    pub global: bool,
}

impl Default for PageAttributes {
    fn default() -> Self {
        Self {
            readable: true,
            writable: false,
            executable: false,
            cacheable: true,
            user_accessible: false,
            global: false,
        }
    }
}

/// 逆引きマップのメインデータ構造
struct ReverseMapManager {
    /// 物理アドレス → 仮想マッピングのセット
    phys_to_virt_map: RwLock<BTreeMap<usize, BTreeSet<usize>>>,
    /// 仮想アドレス → マッピング情報
    virt_to_info_map: RwLock<BTreeMap<usize, PhysicalMapping>>,
    /// 最近参照された物理アドレスのキャッシュ
    recent_lookups: Mutex<BTreeMap<usize, Vec<usize>>>,
    /// キャッシュ最大サイズ
    cache_max_size: usize,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// 自動追跡が有効かどうか
    auto_tracking_enabled: AtomicBool,
    /// 追跡エントリ数
    entry_count: AtomicUsize,
}

/// グローバル逆引きマップマネージャ
static REVERSE_MAP_MANAGER: ReverseMapManager = ReverseMapManager {
    phys_to_virt_map: RwLock::new(BTreeMap::new()),
    virt_to_info_map: RwLock::new(BTreeMap::new()),
    recent_lookups: Mutex::new(BTreeMap::new()),
    cache_max_size: 128,
    initialized: AtomicBool::new(false),
    auto_tracking_enabled: AtomicBool::new(true),
    entry_count: AtomicUsize::new(0),
};

/// 逆引きマップサブシステムの初期化
pub fn init() {
    // 初期化フェンス
    if REVERSE_MAP_MANAGER.initialized.load(Ordering::Acquire) {
        return;
    }
    
    // カーネルページテーブルの初期スキャン
    scan_kernel_page_tables();
    
    // ページテーブル変更監視の設定
    mm::register_page_table_observer(page_table_change_handler);
    
    REVERSE_MAP_MANAGER.initialized.store(true, Ordering::Release);
    log::info!("物理→仮想アドレス逆引きマップの初期化完了");
}

/// カーネルページテーブルをスキャンして初期マッピングを構築
fn scan_kernel_page_tables() {
    // カーネルページテーブルの取得
    let kernel_table = mm::get_kernel_page_table();
    
    // L4ページテーブルから開始
    scan_page_table_level(kernel_table, PageTableLevel::L4, 0, 0);
    
    let entry_count = REVERSE_MAP_MANAGER.entry_count.load(Ordering::Relaxed);
    log::debug!("カーネルページテーブルスキャン完了: {} エントリを検出", entry_count);
}

/// 再帰的にページテーブルをスキャン
fn scan_page_table_level(table: &PageTable, level: PageTableLevel, 
                        base_virt_addr: usize, owner_id: usize) {
    // テーブル内の各エントリをチェック
    for (i, entry) in table.entries.iter().enumerate() {
        if !entry.is_present() {
            continue;
        }
        
        // エントリの物理アドレスを取得
        let phys_addr = entry.get_physical_address();
        
        // 現在のレベルでの仮想アドレスオフセットを計算
        let virt_addr_offset = match level {
            PageTableLevel::L4 => i << 39,
            PageTableLevel::L3 => i << 30,
            PageTableLevel::L2 => i << 21,
            PageTableLevel::L1 => i << 12,
        };
        
        let virt_addr = base_virt_addr | virt_addr_offset;
        
        if entry.is_leaf() {
            // 通常ページの場合、マッピングを追加
            let page_size = match level {
                PageTableLevel::L1 => PageSize::Default as usize, // 4KB
                PageTableLevel::L2 => PageSize::Huge as usize,    // 2MB
                PageTableLevel::L3 => PageSize::Gigantic as usize, // 1GB
                _ => continue, // L4レベルのリーフはない
            };
            
            // マッピング種別を判断
            let mapping_type = determine_mapping_type(virt_addr, owner_id);
            
            // ページ属性を取得
            let attributes = PageAttributes {
                readable: true,
                writable: entry.is_writable(),
                executable: !entry.is_no_execute(),
                cacheable: entry.is_cacheable(),
                user_accessible: entry.is_user_accessible(),
                global: entry.is_global(),
            };
            
            // マッピング情報を作成
            let mapping = PhysicalMapping {
                virtual_address: virt_addr,
                size: page_size,
                physical_address: phys_addr,
                owner_id,
                mapping_type,
                attributes,
            };
            
            // 逆引きマップに追加
            add_mapping_to_reverse_map(mapping);
        } else {
            // 次のレベルのページテーブルを取得
            let next_level = match level {
                PageTableLevel::L4 => PageTableLevel::L3,
                PageTableLevel::L3 => PageTableLevel::L2,
                PageTableLevel::L2 => PageTableLevel::L1,
                PageTableLevel::L1 => continue, // L1の次のレベルはない
            };
            
            let next_table = mm::get_page_table_at(phys_addr, next_level);
            
            // 再帰的にスキャン
            scan_page_table_level(next_table, next_level, virt_addr, owner_id);
        }
    }
}

/// マッピング種別を判断
fn determine_mapping_type(virt_addr: usize, owner_id: usize) -> MappingType {
    // カーネルアドレス空間内のマッピング種別の判断
    if owner_id == 0 {
        let kernel_text_start = 0xffffffff80000000;
        let kernel_text_end = 0xffffffff80100000;
        
        if virt_addr >= kernel_text_start && virt_addr < kernel_text_end {
            return MappingType::KernelCode;
        }
        
        let kernel_data_start = kernel_text_end;
        let kernel_data_end = 0xffffffff81000000;
        
        if virt_addr >= kernel_data_start && virt_addr < kernel_data_end {
            return MappingType::KernelData;
        }
        
        let kernel_heap_start = 0xffff800000000000;
        let kernel_heap_end = 0xffff800040000000;
        
        if virt_addr >= kernel_heap_start && virt_addr < kernel_heap_end {
            return MappingType::KernelHeap;
        }
        
        let mmio_start = 0xffff830000000000;
        let mmio_end = 0xffff840000000000;
        
        if virt_addr >= mmio_start && virt_addr < mmio_end {
            return MappingType::MMIO;
        }
        
        // その他のカーネル領域
        return MappingType::Other;
    } else {
        // ユーザープロセスのアドレス空間
        let user_stack_end = 0x7ffffffff000;
        let user_stack_start = 0x7ffff0000000;
        
        if virt_addr >= user_stack_start && virt_addr < user_stack_end {
            return MappingType::UserStack;
        }
        
        let user_code_start = 0x400000;
        let user_code_end = 0x1000000;
        
        if virt_addr >= user_code_start && virt_addr < user_code_end {
            return MappingType::UserCode;
        }
        
        let user_heap_start = 0x1000000;
        let user_heap_end = 0x7ffff0000000;
        
        if virt_addr >= user_heap_start && virt_addr < user_heap_end {
            return MappingType::UserData;
        }
        
        // その他のユーザー領域
        return MappingType::Other;
    }
}

/// マッピングを逆引きマップに追加
fn add_mapping_to_reverse_map(mapping: PhysicalMapping) {
    if !REVERSE_MAP_MANAGER.initialized.load(Ordering::Relaxed) {
        return;
    }
    
    let physical_address = mapping.physical_address;
    let virtual_address = mapping.virtual_address;
    
    // 物理→仮想マップに追加
    let mut phys_to_virt = REVERSE_MAP_MANAGER.phys_to_virt_map.write();
    
    let virt_set = phys_to_virt.entry(physical_address).or_insert_with(BTreeSet::new);
    if virt_set.insert(virtual_address) {
        // 新しいエントリが追加された場合
        REVERSE_MAP_MANAGER.entry_count.fetch_add(1, Ordering::Relaxed);
    }
    
    // 仮想→情報マップに追加
    let mut virt_to_info = REVERSE_MAP_MANAGER.virt_to_info_map.write();
    virt_to_info.insert(virtual_address, mapping);
    
    // キャッシュをクリア
    let mut recent_lookups = REVERSE_MAP_MANAGER.recent_lookups.lock();
    recent_lookups.remove(&physical_address);
}

/// マッピングを逆引きマップから削除
fn remove_mapping_from_reverse_map(virtual_address: usize) {
    if !REVERSE_MAP_MANAGER.initialized.load(Ordering::Relaxed) {
        return;
    }
    
    // 仮想→情報マップから削除
    let mut virt_to_info = REVERSE_MAP_MANAGER.virt_to_info_map.write();
    let mapping = match virt_to_info.remove(&virtual_address) {
        Some(mapping) => mapping,
        None => return, // マッピングがない場合は何もしない
    };
    
    let physical_address = mapping.physical_address;
    
    // 物理→仮想マップから削除
    let mut phys_to_virt = REVERSE_MAP_MANAGER.phys_to_virt_map.write();
    
    if let Some(virt_set) = phys_to_virt.get_mut(&physical_address) {
        if virt_set.remove(&virtual_address) {
            // エントリが削除された場合
            REVERSE_MAP_MANAGER.entry_count.fetch_sub(1, Ordering::Relaxed);
        }
        
        // セットが空になったら、エントリ自体を削除
        if virt_set.is_empty() {
            phys_to_virt.remove(&physical_address);
        }
    }
    
    // キャッシュをクリア
    let mut recent_lookups = REVERSE_MAP_MANAGER.recent_lookups.lock();
    recent_lookups.remove(&physical_address);
}

/// ページテーブル変更通知ハンドラ
fn page_table_change_handler(virt_addr: usize, _old_phys: Option<usize>, 
                           new_phys: Option<usize>, owner_id: usize) {
    if !REVERSE_MAP_MANAGER.auto_tracking_enabled.load(Ordering::Relaxed) {
        return;
    }
    
    // ページサイズで切り捨て
    let page_size = PageSize::Default as usize;
    let aligned_virt = virt_addr & !(page_size - 1);
    
    if let Some(phys_addr) = new_phys {
        // 新しいマッピングを追加
        let mapping_type = determine_mapping_type(aligned_virt, owner_id);
        
        // ページ属性を取得
        let attributes = match mm::get_page_attributes(aligned_virt) {
            Ok(attrs) => attrs,
            Err(_) => PageAttributes::default(),
        };
        
        let mapping = PhysicalMapping {
            virtual_address: aligned_virt,
            size: page_size,
            physical_address: phys_addr,
            owner_id,
            mapping_type,
            attributes,
        };
        
        add_mapping_to_reverse_map(mapping);
    } else {
        // マッピングを削除
        remove_mapping_from_reverse_map(aligned_virt);
    }
}

/// 物理アドレスから仮想アドレスを検索
pub fn lookup_virtual_address(phys_addr: usize) -> Option<usize> {
    if !REVERSE_MAP_MANAGER.initialized.load(Ordering::Relaxed) {
        return None;
    }
    
    // ページサイズでアラインする
    let page_size = PageSize::Default as usize;
    let aligned_phys = phys_addr & !(page_size - 1);
    
    // まずキャッシュをチェック
    {
        let recent_lookups = REVERSE_MAP_MANAGER.recent_lookups.lock();
        if let Some(virt_addrs) = recent_lookups.get(&aligned_phys) {
            if !virt_addrs.is_empty() {
                let virt_base = virt_addrs[0];
                return Some(virt_base + (phys_addr - aligned_phys));
            }
        }
    }
    
    // 次に逆引きマップをチェック
    let phys_to_virt = REVERSE_MAP_MANAGER.phys_to_virt_map.read();
    
    if let Some(virt_set) = phys_to_virt.get(&aligned_phys) {
        if !virt_set.is_empty() {
            let virt_base = *virt_set.iter().next().unwrap();
            
            // キャッシュに結果を保存
            let mut recent_lookups = REVERSE_MAP_MANAGER.recent_lookups.lock();
            let virt_addrs = virt_set.iter().copied().collect::<Vec<_>>();
            
            // キャッシュサイズを制限
            if recent_lookups.len() >= REVERSE_MAP_MANAGER.cache_max_size {
                // LRU的に最も古いキーを削除
                if let Some(&oldest_key) = recent_lookups.keys().next() {
                    recent_lookups.remove(&oldest_key);
                }
            }
            
            recent_lookups.insert(aligned_phys, virt_addrs);
            
            return Some(virt_base + (phys_addr - aligned_phys));
        }
    }
    
    // 最後の手段として、ページテーブルを直接スキャン
    scan_page_tables_for_physical(aligned_phys).map(|virt_base| {
        virt_base + (phys_addr - aligned_phys)
    })
}

/// 物理アドレスに対するすべての仮想マッピングを検索
pub fn lookup_all_virtual_mappings(phys_addr: usize) -> Vec<usize> {
    if !REVERSE_MAP_MANAGER.initialized.load(Ordering::Relaxed) {
        return Vec::new();
    }
    
    // ページサイズでアラインする
    let page_size = PageSize::Default as usize;
    let aligned_phys = phys_addr & !(page_size - 1);
    
    // まずキャッシュをチェック
    {
        let recent_lookups = REVERSE_MAP_MANAGER.recent_lookups.lock();
        if let Some(virt_addrs) = recent_lookups.get(&aligned_phys) {
            if !virt_addrs.is_empty() {
                return virt_addrs.clone();
            }
        }
    }
    
    // 次に逆引きマップをチェック
    let phys_to_virt = REVERSE_MAP_MANAGER.phys_to_virt_map.read();
    
    if let Some(virt_set) = phys_to_virt.get(&aligned_phys) {
        let virt_addrs = virt_set.iter().copied().collect::<Vec<_>>();
        
        if !virt_addrs.is_empty() {
            // キャッシュに結果を保存
            let mut recent_lookups = REVERSE_MAP_MANAGER.recent_lookups.lock();
            
            // キャッシュサイズを制限
            if recent_lookups.len() >= REVERSE_MAP_MANAGER.cache_max_size {
                // LRU的に最も古いキーを削除
                if let Some(&oldest_key) = recent_lookups.keys().next() {
                    recent_lookups.remove(&oldest_key);
                }
            }
            
            recent_lookups.insert(aligned_phys, virt_addrs.clone());
            
            return virt_addrs;
        }
    }
    
    // 最後の手段として、ページテーブルを直接スキャン
    // これは非常にコストが高いので、初回時のみ実行
    let virt_addr = scan_page_tables_for_physical(aligned_phys);
    
    match virt_addr {
        Some(addr) => vec![addr],
        None => Vec::new(),
    }
}

/// 物理アドレスを探すためにページテーブルを直接スキャン
fn scan_page_tables_for_physical(phys_addr: usize) -> Option<usize> {
    // まずカーネルページテーブルをチェック
    let kernel_table = mm::get_kernel_page_table();
    
    if let Some(virt_addr) = scan_table_for_physical(kernel_table, PageTableLevel::L4, 0, phys_addr) {
        return Some(virt_addr);
    }
    
    // カーネルで見つからなければ、アクティブなユーザープロセスのページテーブルをチェック
    let current_proc = crate::core::process::get_current_process();
    if let Some(proc) = current_proc {
        let proc_table = proc.get_page_table();
        
        if let Some(virt_addr) = scan_table_for_physical(proc_table, PageTableLevel::L4, 0, phys_addr) {
            return Some(virt_addr);
        }
    }
    
    None
}

/// 再帰的にページテーブルをスキャンして物理アドレスを検索
fn scan_table_for_physical(table: &PageTable, level: PageTableLevel, 
                         base_virt_addr: usize, target_phys: usize) -> Option<usize> {
    // テーブル内の各エントリをチェック
    for (i, entry) in table.entries.iter().enumerate() {
        if !entry.is_present() {
            continue;
        }
        
        // エントリの物理アドレスを取得
        let phys_addr = entry.get_physical_address();
        
        // 現在のレベルでの仮想アドレスオフセットを計算
        let virt_addr_offset = match level {
            PageTableLevel::L4 => i << 39,
            PageTableLevel::L3 => i << 30,
            PageTableLevel::L2 => i << 21,
            PageTableLevel::L1 => i << 12,
        };
        
        let virt_addr = base_virt_addr | virt_addr_offset;
        
        if entry.is_leaf() {
            // ページサイズを取得
            let page_size = match level {
                PageTableLevel::L1 => PageSize::Default as usize,
                PageTableLevel::L2 => PageSize::Huge as usize,
                PageTableLevel::L3 => PageSize::Gigantic as usize,
                _ => continue,
            };
            
            // ページ内の物理アドレス範囲をチェック
            let phys_start = phys_addr;
            let phys_end = phys_start + page_size;
            
            if target_phys >= phys_start && target_phys < phys_end {
                // 見つかった！
                let offset = target_phys - phys_start;
                return Some(virt_addr + offset);
            }
        } else {
            // 次のレベルのページテーブルを取得
            let next_level = match level {
                PageTableLevel::L4 => PageTableLevel::L3,
                PageTableLevel::L3 => PageTableLevel::L2,
                PageTableLevel::L2 => PageTableLevel::L1,
                PageTableLevel::L1 => continue,
            };
            
            let next_table = mm::get_page_table_at(phys_addr, next_level);
            
            // 再帰的にスキャン
            if let Some(found_virt) = scan_table_for_physical(next_table, next_level, virt_addr, target_phys) {
                return Some(found_virt);
            }
        }
    }
    
    None
}

/// マッピング情報を取得
pub fn get_mapping_info(virt_addr: usize) -> Option<PhysicalMapping> {
    if !REVERSE_MAP_MANAGER.initialized.load(Ordering::Relaxed) {
        return None;
    }
    
    // ページサイズでアラインする
    let page_size = PageSize::Default as usize;
    let aligned_virt = virt_addr & !(page_size - 1);
    
    // 仮想→情報マップから取得
    let virt_to_info = REVERSE_MAP_MANAGER.virt_to_info_map.read();
    virt_to_info.get(&aligned_virt).cloned()
}

/// 指定された物理アドレス範囲に対するすべてのマッピングを取得
pub fn get_mappings_for_physical_range(phys_start: usize, phys_end: usize) -> Vec<PhysicalMapping> {
    if !REVERSE_MAP_MANAGER.initialized.load(Ordering::Relaxed) {
        return Vec::new();
    }
    
    let mut result = Vec::new();
    let phys_to_virt = REVERSE_MAP_MANAGER.phys_to_virt_map.read();
    let virt_to_info = REVERSE_MAP_MANAGER.virt_to_info_map.read();
    
    // ページサイズ
    let page_size = PageSize::Default as usize;
    
    // ページ境界にアラインする
    let aligned_start = phys_start & !(page_size - 1);
    let aligned_end = (phys_end + page_size - 1) & !(page_size - 1);
    
    // 範囲内の各ページについて
    for phys_addr in (aligned_start..aligned_end).step_by(page_size) {
        if let Some(virt_set) = phys_to_virt.get(&phys_addr) {
            for &virt_addr in virt_set {
                if let Some(mapping) = virt_to_info.get(&virt_addr) {
                    result.push(mapping.clone());
                }
            }
        }
    }
    
    result
}

/// 指定されたマッピング種別のエントリを探す
pub fn find_mappings_by_type(mapping_type: MappingType) -> Vec<PhysicalMapping> {
    if !REVERSE_MAP_MANAGER.initialized.load(Ordering::Relaxed) {
        return Vec::new();
    }
    
    let virt_to_info = REVERSE_MAP_MANAGER.virt_to_info_map.read();
    let mut result = Vec::new();
    
    for mapping in virt_to_info.values() {
        if mapping.mapping_type == mapping_type {
            result.push(mapping.clone());
        }
    }
    
    result
}

/// マッピング情報をダンプ（デバッグ用）
pub fn dump_mappings() {
    if !REVERSE_MAP_MANAGER.initialized.load(Ordering::Relaxed) {
        log::warn!("逆引きマップが初期化されていません");
        return;
    }
    
    let virt_to_info = REVERSE_MAP_MANAGER.virt_to_info_map.read();
    
    log::debug!("=== メモリマッピング情報 ===");
    log::debug!("登録エントリ数: {}", virt_to_info.len());
    
    // 種別ごとのカウント
    let mut type_counts = BTreeMap::new();
    
    for mapping in virt_to_info.values() {
        *type_counts.entry(mapping.mapping_type).or_insert(0) += 1;
        
        log::trace!("仮想: {:#x} -> 物理: {:#x}, サイズ: {:#x}, 種別: {:?}, 所有者: {}",
                 mapping.virtual_address, mapping.physical_address, mapping.size,
                 mapping.mapping_type, mapping.owner_id);
    }
    
    log::debug!("種別ごとのマッピング数:");
    for (typ, count) in type_counts.iter() {
        log::debug!("  {:?}: {}", typ, count);
    }
    
    log::debug!("==========================");
}

/// 自動追跡を有効/無効に設定
pub fn set_auto_tracking(enabled: bool) {
    REVERSE_MAP_MANAGER.auto_tracking_enabled.store(enabled, Ordering::Relaxed);
    log::info!("逆引きマップの自動追跡: {}", if enabled { "有効" } else { "無効" });
}

/// メモリマップ情報を取得（指定された範囲）
pub fn get_memory_map(start_addr: usize, size: usize) -> Vec<PhysicalMapping> {
    if !REVERSE_MAP_MANAGER.initialized.load(Ordering::Relaxed) {
        return Vec::new();
    }
    
    let end_addr = start_addr + size;
    let virt_to_info = REVERSE_MAP_MANAGER.virt_to_info_map.read();
    let mut result = Vec::new();
    
    for (virt_addr, mapping) in virt_to_info.iter() {
        let mapping_end = *virt_addr + mapping.size;
        
        // 範囲が重なるかチェック
        if *virt_addr < end_addr && mapping_end > start_addr {
            result.push(mapping.clone());
        }
    }
    
    result
}

/// マッピングを手動で追加
pub fn add_mapping(virt_addr: usize, phys_addr: usize, size: usize, 
                 owner_id: usize, mapping_type: MappingType) {
    if !REVERSE_MAP_MANAGER.initialized.load(Ordering::Relaxed) {
        return;
    }
    
    // ページ属性を取得
    let attributes = match mm::get_page_attributes(virt_addr) {
        Ok(attrs) => attrs,
        Err(_) => PageAttributes::default(),
    };
    
    let mapping = PhysicalMapping {
        virtual_address: virt_addr,
        size,
        physical_address: phys_addr,
        owner_id,
        mapping_type,
        attributes,
    };
    
    add_mapping_to_reverse_map(mapping);
}

/// マッピングを手動で削除
pub fn remove_mapping(virt_addr: usize) {
    if !REVERSE_MAP_MANAGER.initialized.load(Ordering::Relaxed) {
        return;
    }
    
    remove_mapping_from_reverse_map(virt_addr);
}

/// 現在の統計情報を取得
pub fn get_stats() -> ReverseMapStats {
    let entry_count = REVERSE_MAP_MANAGER.entry_count.load(Ordering::Relaxed);
    let cache_size = REVERSE_MAP_MANAGER.recent_lookups.lock().len();
    
    ReverseMapStats {
        entry_count,
        cache_size,
        auto_tracking_enabled: REVERSE_MAP_MANAGER.auto_tracking_enabled.load(Ordering::Relaxed),
    }
}

/// 逆引きマップの統計情報
#[derive(Debug, Clone, Copy)]
pub struct ReverseMapStats {
    /// 登録エントリ数
    pub entry_count: usize,
    /// キャッシュサイズ
    pub cache_size: usize,
    /// 自動追跡が有効か
    pub auto_tracking_enabled: bool,
}

/// キャッシュをクリア
pub fn clear_cache() {
    if !REVERSE_MAP_MANAGER.initialized.load(Ordering::Relaxed) {
        return;
    }
    
    REVERSE_MAP_MANAGER.recent_lookups.lock().clear();
    log::debug!("逆引きマップキャッシュをクリアしました");
}

/// すべてのマッピングを再スキャン
pub fn rescan_all_mappings() {
    if !REVERSE_MAP_MANAGER.initialized.load(Ordering::Relaxed) {
        return;
    }
    
    // 現在のマッピングをクリア
    {
        let mut phys_to_virt = REVERSE_MAP_MANAGER.phys_to_virt_map.write();
        let mut virt_to_info = REVERSE_MAP_MANAGER.virt_to_info_map.write();
        
        phys_to_virt.clear();
        virt_to_info.clear();
        
        REVERSE_MAP_MANAGER.entry_count.store(0, Ordering::Relaxed);
    }
    
    // キャッシュもクリア
    REVERSE_MAP_MANAGER.recent_lookups.lock().clear();
    
    // カーネルページテーブルを再スキャン
    scan_kernel_page_tables();
    
    // アクティブなプロセスのページテーブルもスキャン
    if let Some(current_proc) = crate::core::process::get_current_process() {
        let proc_table = current_proc.get_page_table();
        scan_page_table_level(proc_table, PageTableLevel::L4, 0, current_proc.get_id());
    }
    
    log::info!("全マッピングの再スキャン完了: {} エントリを検出",
              REVERSE_MAP_MANAGER.entry_count.load(Ordering::Relaxed));
}

/// キャッシュサイズを設定
pub fn set_cache_size(size: usize) {
    if !REVERSE_MAP_MANAGER.initialized.load(Ordering::Relaxed) {
        return;
    }
    
    // 最大キャッシュサイズを更新
    let mut recent_lookups = REVERSE_MAP_MANAGER.recent_lookups.lock();
    
    // 新しいサイズが現在のキャッシュサイズより小さい場合、エントリを削除
    while recent_lookups.len() > size {
        if let Some(&oldest_key) = recent_lookups.keys().next() {
            recent_lookups.remove(&oldest_key);
        } else {
            break;
        }
    }
    
    // 最大キャッシュサイズを更新
    // 安全のため書き込み不可な静的変数へのポインタ操作としてマークする
    unsafe {
        let reverse_map_manager = &REVERSE_MAP_MANAGER as *const _ as *mut ReverseMapManager;
        (*reverse_map_manager).cache_max_size = size;
    }
    
    log::debug!("逆引きマップキャッシュサイズを変更: {}", size);
} 