// AetherOS メモリキャッシュ管理モジュール
//
// このモジュールは、メモリアクセスパターンに応じたキャッシュ最適化、
// キャッシュ階層管理、およびハードウェアキャッシュとの連携を行います。

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};
use crate::arch::{CacheLevel, CacheLine, CacheInfo};

/// キャッシュ制御オプション
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CacheControl {
    /// 通常のキャッシュ可能メモリ
    Normal,
    /// キャッシュ不可（デバイスメモリなど）
    Uncacheable,
    /// ライトスルー（書き込み即反映）
    WriteThrough,
    /// ライトバック（遅延書き込み）
    WriteBack,
    /// ライトコンバイン（連続書き込み最適化）
    WriteCombining,
    /// ライトプロテクト（読み取り専用キャッシュ）
    WriteProtect,
}

/// キャッシュプリフェッチポリシー
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PrefetchPolicy {
    /// プリフェッチ無効
    Disabled,
    /// 順次アクセスパターン検出時のみプリフェッチ
    Sequential,
    /// アドレス予測に基づくプリフェッチ
    Predictive,
    /// アグレッシブプリフェッチ（帯域幅/消費電力増加）
    Aggressive,
    /// アダプティブプリフェッチ（状況に応じた最適化）
    Adaptive,
}

/// キャッシュヒント情報
#[derive(Debug, Clone)]
pub struct CacheHint {
    /// メモリ領域の開始アドレス
    pub start_addr: usize,
    /// メモリ領域のサイズ
    pub size: usize,
    /// キャッシュ制御オプション
    pub control: CacheControl,
    /// プリフェッチポリシー
    pub prefetch: PrefetchPolicy,
    /// 優先度（高いほど重要）
    pub priority: u8,
    /// アクセス予測頻度
    pub access_frequency: f32,
}

/// キャッシュ操作結果
pub type CacheResult = Result<(), &'static str>;

/// キャッシュライン状態
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum CacheLineState {
    /// 無効
    Invalid,
    /// 共有（読み取り専用）
    Shared,
    /// 排他的（読み書き可能）
    Exclusive,
    /// 変更済み（書き込み済み）
    Modified,
}

/// ソフトウェアキャッシュエントリ
struct CacheEntry {
    /// 物理アドレス
    phys_addr: usize,
    /// 仮想アドレス
    virt_addr: usize,
    /// キャッシュライン状態
    state: CacheLineState,
    /// 最終アクセス時間
    last_accessed: u64,
    /// アクセス回数
    access_count: usize,
    /// キャッシュオプション
    control: CacheControl,
}

/// キャッシュヒント領域のマップ
struct CacheHintMap {
    /// アドレス範囲 -> キャッシュヒント
    hints: BTreeMap<(usize, usize), CacheHint>,
}

impl CacheHintMap {
    /// 新しいキャッシュヒントマップを作成
    fn new() -> Self {
        Self {
            hints: BTreeMap::new(),
        }
    }
    
    /// キャッシュヒントを追加
    fn add_hint(&mut self, hint: CacheHint) {
        let end_addr = hint.start_addr + hint.size;
        self.hints.insert((hint.start_addr, end_addr), hint);
    }
    
    /// キャッシュヒントを削除
    fn remove_hint(&mut self, start_addr: usize, size: usize) {
        let end_addr = start_addr + size;
        self.hints.remove(&(start_addr, end_addr));
    }
    
    /// 指定されたアドレスに対するキャッシュヒントを検索
    fn find_hint(&self, addr: usize) -> Option<&CacheHint> {
        for ((start, end), hint) in &self.hints {
            if addr >= *start && addr < *end {
                return Some(hint);
            }
        }
        None
    }
}

/// ソフトウェアキャッシュ（診断および最適化用）
struct SoftwareCache {
    /// キャッシュエントリ
    entries: VecDeque<CacheEntry>,
    /// キャッシュサイズ
    capacity: usize,
    /// ヒット数
    hits: AtomicUsize,
    /// ミス数
    misses: AtomicUsize,
    /// 有効フラグ
    enabled: AtomicBool,
}

impl SoftwareCache {
    /// 新しいソフトウェアキャッシュを作成
    fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity,
            hits: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
            enabled: AtomicBool::new(true),
        }
    }
    
    /// エントリを追加または更新
    fn update(&mut self, phys_addr: usize, virt_addr: usize, 
              timestamp: u64, control: CacheControl) {
        // アドレスをキャッシュライン境界に合わせる
        let line_size = CacheLine::Size as usize;
        let aligned_addr = phys_addr & !(line_size - 1);
        
        // 既存エントリの検索
        let mut found = false;
        for entry in &mut self.entries {
            if entry.phys_addr == aligned_addr {
                entry.last_accessed = timestamp;
                entry.access_count += 1;
                entry.control = control;
                entry.state = CacheLineState::Modified;
                found = true;
                break;
            }
        }
        
        if !found {
            // キャッシュがいっぱいなら最も古いエントリを削除
            if self.entries.len() >= self.capacity {
                self.entries.pop_front();
            }
            
            // 新しいエントリを追加
            self.entries.push_back(CacheEntry {
                phys_addr: aligned_addr,
                virt_addr,
                state: CacheLineState::Exclusive,
                last_accessed: timestamp,
                access_count: 1,
                control,
            });
            
            self.misses.fetch_add(1, Ordering::Relaxed);
        } else {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    /// キャッシュヒット率を計算
    fn hit_rate(&self) -> f32 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        
        if total == 0 {
            return 0.0;
        }
        
        hits as f32 / total as f32
    }
    
    /// キャッシュをフラッシュ
    fn flush(&mut self) {
        self.entries.clear();
    }
}

/// キャッシュマネージャ
struct CacheManager {
    /// キャッシュヒントマップ
    hint_map: RwLock<CacheHintMap>,
    /// ソフトウェアキャッシュ（シミュレーション用）
    software_cache: Mutex<SoftwareCache>,
    /// 現在のプリフェッチポリシー
    prefetch_policy: RwLock<PrefetchPolicy>,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// システム時間カウンタ
    time_counter: AtomicUsize,
}

/// グローバルキャッシュマネージャ
static CACHE_MANAGER: CacheManager = CacheManager {
    hint_map: RwLock::new(CacheHintMap::new()),
    software_cache: Mutex::new(SoftwareCache::new(1024)),
    prefetch_policy: RwLock::new(PrefetchPolicy::Adaptive),
    initialized: AtomicBool::new(false),
    time_counter: AtomicUsize::new(0),
};

/// キャッシュサブシステムの初期化
pub fn init() {
    // 初期化フェンス
    if CACHE_MANAGER.initialized.load(Ordering::Acquire) {
        return;
    }
    
    // ハードウェアキャッシュ情報の取得
    let cache_info = crate::arch::get_cache_info();
    log::info!("キャッシュ階層: L1 {}KB, L2 {}KB, L3 {}KB",
               cache_info.l1_size / 1024,
               cache_info.l2_size / 1024,
               cache_info.l3_size / 1024);
    
    // プラットフォーム固有のキャッシュ最適化
    optimize_for_platform(&cache_info);
    
    CACHE_MANAGER.initialized.store(true, Ordering::Release);
    log::info!("キャッシュ管理サブシステムの初期化完了");
}

/// プラットフォーム固有のキャッシュ最適化
fn optimize_for_platform(cache_info: &CacheInfo) {
    // キャッシュライン境界に合わせたメモリアクセスの最適化
    let line_size = cache_info.line_size;
    log::debug!("キャッシュラインサイズに合わせた最適化: {} バイト", line_size);
    
    // L1/L2/L3キャッシュサイズに基づくデータ構造サイズ調整
    let optimal_sw_cache_size = (cache_info.l2_size / line_size) / 4;
    *CACHE_MANAGER.software_cache.lock() = SoftwareCache::new(optimal_sw_cache_size);
    
    // プリフェッチポリシーの初期化
    if cache_info.supports_adaptive_prefetch {
        *CACHE_MANAGER.prefetch_policy.write() = PrefetchPolicy::Adaptive;
    } else {
        *CACHE_MANAGER.prefetch_policy.write() = PrefetchPolicy::Sequential;
    }
}

/// メモリ領域のキャッシュ制御設定を追加
pub fn add_cache_hint(start_addr: usize, size: usize, 
                     control: CacheControl, prefetch: PrefetchPolicy) -> CacheResult {
    if !CACHE_MANAGER.initialized.load(Ordering::Relaxed) {
        return Err("キャッシュマネージャが初期化されていません");
    }
    
    // キャッシュヒントの作成
    let hint = CacheHint {
        start_addr,
        size,
        control,
        prefetch,
        priority: 10, // デフォルト優先度
        access_frequency: 0.0,
    };
    
    // ヒントマップに追加
    CACHE_MANAGER.hint_map.write().add_hint(hint);
    
    // アーキテクチャ固有のキャッシュ設定を適用
    apply_cache_control(start_addr, size, control)?;
    
    Ok(())
}

/// メモリ領域のキャッシュヒントを削除
pub fn remove_cache_hint(start_addr: usize, size: usize) -> CacheResult {
    if !CACHE_MANAGER.initialized.load(Ordering::Relaxed) {
        return Err("キャッシュマネージャが初期化されていません");
    }
    
    // ヒントマップから削除
    CACHE_MANAGER.hint_map.write().remove_hint(start_addr, size);
    
    // キャッシュ設定をデフォルトに戻す
    apply_cache_control(start_addr, size, CacheControl::Normal)?;
    
    Ok(())
}

/// アーキテクチャ固有のキャッシュ制御を適用
fn apply_cache_control(start_addr: usize, size: usize, 
                      control: CacheControl) -> CacheResult {
    // アーキテクチャ固有のMMUキャッシュ属性設定
    let result = match control {
        CacheControl::Normal => {
            crate::arch::set_memory_attributes(start_addr, size, true, true)
        },
        CacheControl::Uncacheable => {
            crate::arch::set_memory_attributes(start_addr, size, false, false)
        },
        CacheControl::WriteThrough => {
            crate::arch::set_memory_attributes(start_addr, size, true, false)
        },
        CacheControl::WriteBack => {
            crate::arch::set_memory_attributes(start_addr, size, true, true)
        },
        CacheControl::WriteCombining => {
            crate::arch::set_memory_attributes(start_addr, size, false, true)
        },
        CacheControl::WriteProtect => {
            // 読み取り専用ページの設定
            crate::core::memory::mm::set_page_protection(start_addr, size, true, false)
        },
    };
    
    match result {
        Ok(_) => Ok(()),
        Err(_) => Err("キャッシュ属性の設定に失敗しました"),
    }
}

/// メモリ領域のキャッシュをフラッシュ
pub fn flush_cache_range(start_addr: usize, size: usize) -> CacheResult {
    if !CACHE_MANAGER.initialized.load(Ordering::Relaxed) {
        return Err("キャッシュマネージャが初期化されていません");
    }
    
    // アーキテクチャ固有のキャッシュフラッシュ
    if let Err(_) = crate::arch::flush_cache_range(start_addr, size) {
        return Err("キャッシュフラッシュに失敗しました");
    }
    
    Ok(())
}

/// 全キャッシュをフラッシュ
pub fn flush_all_caches() -> CacheResult {
    if !CACHE_MANAGER.initialized.load(Ordering::Relaxed) {
        return Err("キャッシュマネージャが初期化されていません");
    }
    
    // アーキテクチャ固有の全キャッシュフラッシュ
    if let Err(_) = crate::arch::flush_all_caches() {
        return Err("全キャッシュのフラッシュに失敗しました");
    }
    
    // ソフトウェアキャッシュもフラッシュ
    CACHE_MANAGER.software_cache.lock().flush();
    
    Ok(())
}

/// キャッシュ階層の指定レベルをフラッシュ
pub fn flush_cache_level(level: CacheLevel) -> CacheResult {
    if !CACHE_MANAGER.initialized.load(Ordering::Relaxed) {
        return Err("キャッシュマネージャが初期化されていません");
    }
    
    // アーキテクチャ固有の指定レベルキャッシュフラッシュ
    if let Err(_) = crate::arch::flush_cache_level(level) {
        return Err("指定レベルのキャッシュフラッシュに失敗しました");
    }
    
    Ok(())
}

/// メモリアクセスをシミュレート（ソフトウェアキャッシュ更新）
pub fn simulate_memory_access(phys_addr: usize, virt_addr: usize) {
    if !CACHE_MANAGER.initialized.load(Ordering::Relaxed) {
        return;
    }
    
    // ソフトウェアキャッシュが有効な場合のみ
    if !CACHE_MANAGER.software_cache.lock().enabled.load(Ordering::Relaxed) {
        return;
    }
    
    // 現在の時間カウンタを取得
    let time = CACHE_MANAGER.time_counter.fetch_add(1, Ordering::Relaxed) as u64;
    
    // キャッシュ制御を決定
    let control = {
        let hint_map = CACHE_MANAGER.hint_map.read();
        hint_map.find_hint(virt_addr)
            .map(|hint| hint.control)
            .unwrap_or(CacheControl::Normal)
    };
    
    // ソフトウェアキャッシュを更新
    CACHE_MANAGER.software_cache.lock().update(phys_addr, virt_addr, time, control);
    
    // 必要に応じてプリフェッチを実行
    let prefetch_policy = *CACHE_MANAGER.prefetch_policy.read();
    match prefetch_policy {
        PrefetchPolicy::Disabled => {},
        PrefetchPolicy::Sequential => {
            // シーケンシャルプリフェッチ：次のキャッシュラインを事前ロード
            let line_size = CacheLine::Size as usize;
            let next_line = (phys_addr & !(line_size - 1)) + line_size;
            prefetch_address(next_line);
        },
        PrefetchPolicy::Predictive | PrefetchPolicy::Aggressive => {
            // 予測的プリフェッチ：過去のアクセスパターンに基づいて予測
            let predicted = predict_next_access(phys_addr);
            for addr in predicted {
                prefetch_address(addr);
            }
        },
        PrefetchPolicy::Adaptive => {
            // アダプティブプリフェッチ：現在のワークロードに基づいて最適化
            let sw_cache = CACHE_MANAGER.software_cache.lock();
            let hit_rate = sw_cache.hit_rate();
            drop(sw_cache);
            
            if hit_rate < 0.7 {
                // ヒット率が低い場合はアグレッシブにプリフェッチ
                let predicted = predict_next_access(phys_addr);
                for addr in predicted {
                    prefetch_address(addr);
                }
            } else {
                // ヒット率が高い場合はシーケンシャルプリフェッチのみ
                let line_size = CacheLine::Size as usize;
                let next_line = (phys_addr & !(line_size - 1)) + line_size;
                prefetch_address(next_line);
            }
        },
    }
}

/// 次のメモリアクセスを予測
fn predict_next_access(phys_addr: usize) -> Vec<usize> {
    let line_size = CacheLine::Size as usize;
    let base_addr = phys_addr & !(line_size - 1);
    
    let mut predicted = Vec::with_capacity(4);
    
    // 単純な順次アクセス予測
    predicted.push(base_addr + line_size);
    predicted.push(base_addr + line_size * 2);
    
    // ストライドパターン予測（例：配列要素をスキップするアクセス）
    predicted.push(base_addr + 4096);
    
    predicted
}

/// アドレスをプリフェッチ
fn prefetch_address(phys_addr: usize) {
    // アーキテクチャ固有のプリフェッチ命令を発行
    crate::arch::prefetch_address(phys_addr);
}

/// 現在のキャッシュ統計情報を取得
pub fn get_cache_stats() -> CacheStats {
    let sw_cache = CACHE_MANAGER.software_cache.lock();
    
    CacheStats {
        hits: sw_cache.hits.load(Ordering::Relaxed),
        misses: sw_cache.misses.load(Ordering::Relaxed),
        hit_rate: sw_cache.hit_rate(),
        capacity: sw_cache.capacity,
        current_size: sw_cache.entries.len(),
    }
}

/// キャッシュ統計情報
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    /// ヒット数
    pub hits: usize,
    /// ミス数
    pub misses: usize,
    /// ヒット率（0.0-1.0）
    pub hit_rate: f32,
    /// キャパシティ
    pub capacity: usize,
    /// 現在のエントリ数
    pub current_size: usize,
}

/// キャッシュ統計情報を表示
pub fn print_cache_stats() {
    let stats = get_cache_stats();
    
    log::info!("=== キャッシュ統計 ===");
    log::info!("ヒット数: {}", stats.hits);
    log::info!("ミス数: {}", stats.misses);
    log::info!("ヒット率: {:.2}%", stats.hit_rate * 100.0);
    log::info!("キャパシティ: {}", stats.capacity);
    log::info!("使用中: {}", stats.current_size);
    log::info!("===================");
}

/// グローバルプリフェッチポリシーを設定
pub fn set_prefetch_policy(policy: PrefetchPolicy) {
    if CACHE_MANAGER.initialized.load(Ordering::Relaxed) {
        *CACHE_MANAGER.prefetch_policy.write() = policy;
        log::info!("プリフェッチポリシーを変更: {:?}", policy);
    }
}

/// メモリアクセスパターン分析を有効/無効化
pub fn enable_access_pattern_analysis(enable: bool) {
    if CACHE_MANAGER.initialized.load(Ordering::Relaxed) {
        CACHE_MANAGER.software_cache.lock().enabled.store(enable, Ordering::Relaxed);
        log::info!("メモリアクセスパターン分析: {}", if enable { "有効" } else { "無効" });
    }
}

/// キャッシュ制御とメモリ保護の統合最適化
pub fn optimize_memory_region(start_addr: usize, size: usize, 
                             access_pattern: &str) -> CacheResult {
    // アクセスパターンに基づく最適なキャッシュ制御を決定
    let (control, prefetch) = match access_pattern {
        "read_mostly" => (CacheControl::WriteProtect, PrefetchPolicy::Aggressive),
        "write_heavy" => (CacheControl::WriteBack, PrefetchPolicy::Sequential),
        "stream" => (CacheControl::WriteCombining, PrefetchPolicy::Sequential),
        "random" => (CacheControl::Normal, PrefetchPolicy::Disabled),
        "device" => (CacheControl::Uncacheable, PrefetchPolicy::Disabled),
        _ => (CacheControl::Normal, PrefetchPolicy::Adaptive),
    };
    
    // キャッシュヒントを設定
    add_cache_hint(start_addr, size, control, prefetch)
} 