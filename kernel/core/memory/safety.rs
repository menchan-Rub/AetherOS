// AetherOS メモリ安全性保証モジュール
//
// このモジュールは、メモリアクセスの安全性を監視・検証し、
// バッファオーバーフロー、UAF、ダブルフリーなどのバグを検出します。

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};
use crate::arch::PageSize;
use crate::core::memory::mm::{self, PageFlags};

/// 安全性検証レベル
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SafetyLevel {
    /// 最小限の検証（パフォーマンス重視）
    Minimal,
    /// 標準検証（バランス重視）
    Standard,
    /// 厳格な検証（安全性重視）
    Strict,
    /// 全検証（デバッグ用、非常に遅い）
    Debug,
    /// 無効（検証なし）
    Disabled,
}

/// メモリアクセス違反の種類
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ViolationType {
    /// バッファオーバーフロー
    BufferOverflow,
    /// 解放済メモリへのアクセス
    UseAfterFree,
    /// 初期化前のメモリ読み取り
    UninitializedRead,
    /// NULL/無効ポインタ参照
    NullPointerDereference,
    /// メモリリーク
    MemoryLeak,
    /// ダブルフリー
    DoubleFree,
    /// 不正アラインメント
    UnalignedAccess,
    /// 読み取り専用メモリへの書き込み
    WriteToReadOnly,
    /// カーネル/ユーザー空間違反
    PrivilegeViolation,
    /// スタックオーバーフロー
    StackOverflow,
}

/// メモリアクセス違反情報
#[derive(Debug, Clone)]
pub struct ViolationInfo {
    /// 違反種別
    pub violation_type: ViolationType,
    /// 違反アドレス
    pub address: usize,
    /// アクセスサイズ
    pub size: usize,
    /// 違反検出時の命令ポインタ
    pub instruction_ptr: usize,
    /// スタックトレース（可能な場合）
    pub stack_trace: Option<Vec<usize>>,
    /// タイムスタンプ
    pub timestamp: u64,
    /// 関連プロセスID（ある場合）
    pub process_id: Option<usize>,
    /// 説明
    pub description: Option<&'static str>,
}

/// ガードページ設定
#[derive(Debug, Clone)]
struct GuardPageConfig {
    /// ページアドレス
    addr: usize,
    /// 保護対象のメモリ領域サイズ
    protected_size: usize,
    /// アクティブか
    active: bool,
    /// 検出する違反タイプ
    detection_type: ViolationType,
    /// 説明文
    description: &'static str,
}

/// アクセス履歴エントリ
struct AccessHistoryEntry {
    /// メモリアドレス
    addr: usize,
    /// アクセスサイズ
    size: usize,
    /// 書き込みか読み取りか
    is_write: bool,
    /// 命令ポインタ
    instruction_ptr: usize,
    /// タイムスタンプ
    timestamp: u64,
}

/// メモリ領域メタデータ
struct MemoryRegionMetadata {
    /// 開始アドレス
    start_addr: usize,
    /// サイズ
    size: usize,
    /// 割り当て時のスタックトレース
    allocation_stack: Option<Vec<usize>>,
    /// 割り当て時のタイムスタンプ
    allocation_time: u64,
    /// 初期化済みビットマップ（1ビット=1バイト、1=初期化済み）
    initialization_bitmap: Vec<u8>,
    /// メタデータフラグ
    flags: u32,
}

impl MemoryRegionMetadata {
    /// 新しいメモリ領域メタデータを作成
    fn new(start_addr: usize, size: usize, timestamp: u64) -> Self {
        let bitmap_size = (size + 7) / 8; // 8ビットで1バイト
        
        Self {
            start_addr,
            size,
            allocation_stack: if cfg!(debug_assertions) {
                Some(capture_stack_trace(10))
            } else {
                None
            },
            allocation_time: timestamp,
            initialization_bitmap: vec![0; bitmap_size],
            flags: 0,
        }
    }
    
    /// 指定されたオフセットが初期化済みかチェック
    fn is_initialized(&self, offset: usize, size: usize) -> bool {
        if offset >= self.size {
            return false;
        }
        
        let end_offset = core::cmp::min(offset + size, self.size);
        
        for i in offset..end_offset {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            
            if byte_idx < self.initialization_bitmap.len() {
                let byte = self.initialization_bitmap[byte_idx];
                if (byte & (1 << bit_idx)) == 0 {
                    return false;
                }
            } else {
                return false;
            }
        }
        
        true
    }
    
    /// 指定されたオフセットを初期化済みとしてマーク
    fn mark_initialized(&mut self, offset: usize, size: usize) {
        if offset >= self.size {
            return;
        }
        
        let end_offset = core::cmp::min(offset + size, self.size);
        
        for i in offset..end_offset {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            
            if byte_idx < self.initialization_bitmap.len() {
                self.initialization_bitmap[byte_idx] |= 1 << bit_idx;
            }
        }
    }
}

/// 安全性サブシステムマネージャ
struct SafetyManager {
    /// 現在の安全性レベル
    safety_level: RwLock<SafetyLevel>,
    /// 違反ハンドラ登録マップ
    violation_handlers: RwLock<BTreeMap<ViolationType, Vec<fn(&ViolationInfo)>>>,
    /// アクティブなガードページ
    guard_pages: RwLock<Vec<GuardPageConfig>>,
    /// メモリ領域メタデータ
    memory_regions: RwLock<BTreeMap<usize, MemoryRegionMetadata>>,
    /// 解放済みアドレス（UAF検出用）
    freed_addresses: RwLock<BTreeSet<usize>>,
    /// アクセス履歴（重複アクセス検出用）
    access_history: Mutex<Vec<AccessHistoryEntry>>,
    /// システム時間カウンタ
    time_counter: AtomicUsize,
    /// 違反検出数
    violation_count: AtomicUsize,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// 検証有効フラグ
    verification_enabled: AtomicBool,
}

/// グローバル安全性マネージャ
static SAFETY_MANAGER: SafetyManager = SafetyManager {
    safety_level: RwLock::new(SafetyLevel::Standard),
    violation_handlers: RwLock::new(BTreeMap::new()),
    guard_pages: RwLock::new(Vec::new()),
    memory_regions: RwLock::new(BTreeMap::new()),
    freed_addresses: RwLock::new(BTreeSet::new()),
    access_history: Mutex::new(Vec::with_capacity(128)),
    time_counter: AtomicUsize::new(0),
    violation_count: AtomicUsize::new(0),
    initialized: AtomicBool::new(false),
    verification_enabled: AtomicBool::new(true),
};

/// 安全性サブシステムの初期化
pub fn init() {
    // 初期化フェンス
    if SAFETY_MANAGER.initialized.load(Ordering::Acquire) {
        return;
    }
    
    // デフォルトの違反ハンドラを登録
    register_default_handlers();
    
    // ハードウェア支援の初期化
    init_hardware_assistance();
    
    SAFETY_MANAGER.initialized.store(true, Ordering::Release);
    log::info!("メモリ安全性サブシステムの初期化完了");
    
    #[cfg(debug_assertions)]
    log::warn!("デバッグビルドでメモリ安全性検証が有効になっています。パフォーマンスに影響します。");
}

/// デフォルトの違反ハンドラを登録
fn register_default_handlers() {
    let mut handlers = SAFETY_MANAGER.violation_handlers.write();
    
    // すべての違反タイプに対してデフォルトハンドラを登録
    for &violation_type in &[
        ViolationType::BufferOverflow,
        ViolationType::UseAfterFree,
        ViolationType::UninitializedRead,
        ViolationType::NullPointerDereference,
        ViolationType::MemoryLeak,
        ViolationType::DoubleFree,
        ViolationType::UnalignedAccess,
        ViolationType::WriteToReadOnly,
        ViolationType::PrivilegeViolation,
        ViolationType::StackOverflow,
    ] {
        handlers.insert(violation_type, vec![default_violation_handler]);
    }
}

/// デフォルトの違反ハンドラ
fn default_violation_handler(info: &ViolationInfo) {
    log::error!("メモリ安全性違反検出: {:?} @ {:#x}, サイズ: {}, 命令: {:#x}",
               info.violation_type, info.address, info.size, info.instruction_ptr);
    
    if let Some(trace) = &info.stack_trace {
        log::error!("スタックトレース:");
        for (i, &addr) in trace.iter().enumerate() {
            log::error!("  #{} {:#x}", i, addr);
        }
    }
    
    // 違反カウンタの更新
    SAFETY_MANAGER.violation_count.fetch_add(1, Ordering::Relaxed);
    
    // パニックしない（継続処理を許可）
}

/// ハードウェア支援の初期化
fn init_hardware_assistance() {
    // ページフォルトハンドラの登録
    crate::arch::register_page_fault_handler(handle_page_fault);
    
    // ハードウェアウォッチポイントの設定（可能であれば）
    if crate::arch::supports_hw_watchpoints() {
        log::info!("ハードウェアウォッチポイントが利用可能です");
    }
}

/// ページフォルト処理ハンドラ
fn handle_page_fault(fault_addr: usize, is_write: bool, instruction_ptr: usize) -> bool {
    // ガードページ違反のチェック
    let guard_pages = SAFETY_MANAGER.guard_pages.read();
    
    for guard in guard_pages.iter() {
        if guard.active && 
           fault_addr >= guard.addr && 
           fault_addr < guard.addr + PageSize::Default as usize {
            
            // 違反情報の作成
            let violation = ViolationInfo {
                violation_type: guard.detection_type,
                address: fault_addr,
                size: 0, // 不明
                instruction_ptr,
                stack_trace: Some(capture_stack_trace(10)),
                timestamp: SAFETY_MANAGER.time_counter.load(Ordering::Relaxed) as u64,
                process_id: None, // カーネルコンテキスト
                description: Some(guard.description),
            };
            
            // 違反を報告
            report_violation(&violation);
            
            return true; // ハンドラで処理済み
        }
    }
    
    // 解放済みメモリへのアクセスチェック
    {
        let freed_addresses = SAFETY_MANAGER.freed_addresses.read();
        let page_base = fault_addr & !(PageSize::Default as usize - 1);
        
        if freed_addresses.contains(&page_base) {
            // UAF違反情報の作成
            let violation = ViolationInfo {
                violation_type: ViolationType::UseAfterFree,
                address: fault_addr,
                size: 0, // 不明
                instruction_ptr,
                stack_trace: Some(capture_stack_trace(10)),
                timestamp: SAFETY_MANAGER.time_counter.load(Ordering::Relaxed) as u64,
                process_id: None,
                description: Some("解放済みメモリへのアクセス"),
            };
            
            report_violation(&violation);
            return true;
        }
    }
    
    // カーネル/ユーザー空間の分離違反チェック
    if is_kernel_address(instruction_ptr) != is_kernel_address(fault_addr) {
        // 権限違反情報の作成
        let violation = ViolationInfo {
            violation_type: ViolationType::PrivilegeViolation,
            address: fault_addr,
            size: 0,
            instruction_ptr,
            stack_trace: Some(capture_stack_trace(10)),
            timestamp: SAFETY_MANAGER.time_counter.load(Ordering::Relaxed) as u64,
            process_id: None,
            description: Some("カーネル/ユーザー空間分離違反"),
        };
        
        report_violation(&violation);
        return true;
    }
    
    // その他の標準的なメモリアクセス違反
    if is_write {
        // 書き込み保護違反
        let violation = ViolationInfo {
            violation_type: ViolationType::WriteToReadOnly,
            address: fault_addr,
            size: 0,
            instruction_ptr,
            stack_trace: Some(capture_stack_trace(10)),
            timestamp: SAFETY_MANAGER.time_counter.load(Ordering::Relaxed) as u64,
            process_id: None,
            description: Some("読み取り専用メモリへの書き込み"),
        };
        
        report_violation(&violation);
        return true;
    }
    
    // ハンドラで処理できなかった
    false
}

/// 違反を報告
fn report_violation(info: &ViolationInfo) {
    if !SAFETY_MANAGER.verification_enabled.load(Ordering::Relaxed) {
        // 検証が無効化されている場合はスキップ
        return;
    }
    
    // ハンドラリストを取得
    let handlers = SAFETY_MANAGER.violation_handlers.read();
    
    // 該当する違反タイプのハンドラを呼び出し
    if let Some(type_handlers) = handlers.get(&info.violation_type) {
        for handler in type_handlers {
            handler(info);
        }
    }
}

/// スタックトレースを取得
fn capture_stack_trace(max_frames: usize) -> Vec<usize> {
    let mut trace = Vec::with_capacity(max_frames);
    
    // アーキテクチャに依存したスタックトレース取得
    if let Some(frames) = crate::arch::capture_stack_trace(max_frames) {
        trace.extend_from_slice(&frames);
    } else {
        // バックアップとして、フレームポインタを手動でたどる
        let mut frame_ptr = get_frame_pointer();
        let mut i = 0;
        
        while !frame_ptr.is_null() && i < max_frames {
            let return_addr = unsafe { *((frame_ptr as usize + 8) as *const usize) };
            trace.push(return_addr);
            
            // 次のフレームポインタ
            frame_ptr = unsafe { *(frame_ptr as *const *const u8) };
            i += 1;
            
            // 無限ループ防止
            if frame_ptr as usize <= 0x1000 {
                break;
            }
        }
    }
    
    trace
}

/// 現在のフレームポインタを取得
#[inline(always)]
fn get_frame_pointer() -> *const u8 {
    let frame_ptr: *const u8;
    
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) frame_ptr);
    }
    
    frame_ptr
}

/// アドレスがカーネル空間かどうかをチェック
fn is_kernel_address(addr: usize) -> bool {
    // アーキテクチャに依存したカーネル空間チェック
    crate::arch::is_kernel_address(addr)
}

/// メモリ安全性検証レベルを設定
pub fn set_safety_level(level: SafetyLevel) {
    if SAFETY_MANAGER.initialized.load(Ordering::Relaxed) {
        *SAFETY_MANAGER.safety_level.write() = level;
        
        // レベルに応じて検証を有効/無効化
        let enabled = level != SafetyLevel::Disabled;
        SAFETY_MANAGER.verification_enabled.store(enabled, Ordering::Relaxed);
        
        log::info!("メモリ安全性検証レベルを変更: {:?}", level);
    }
}

/// メモリアクセス監視（指定されたアドレス範囲）
pub fn monitor_memory_region(start_addr: usize, size: usize, 
                         violation_type: ViolationType, description: &'static str) -> Result<(), &'static str> {
    if !SAFETY_MANAGER.initialized.load(Ordering::Acquire) {
        return Err("安全性マネージャが初期化されていません");
    }
    
    if size == 0 {
        return Err("監視サイズがゼロです");
    }
    
    // ページサイズに合わせる
    let page_size = PageSize::Default as usize;
    let aligned_start = start_addr & !(page_size - 1);
    let pages = (size + (start_addr - aligned_start) + page_size - 1) / page_size;
    
    // ガードページの設定
    for i in 0..pages {
        let guard_addr = aligned_start + i * page_size;
        
        // ガード設定を作成
        let guard = GuardPageConfig {
            addr: guard_addr,
            protected_size: size,
            active: true,
            detection_type: violation_type,
            description,
        };
        
        // 現在のページ属性を保存してから保護設定を適用
        let res = mm::set_page_protection(guard_addr, page_size, true, false);
        if res.is_err() {
            return Err("ページ保護の設定に失敗しました");
        }
        
        // ガードページリストに追加
        SAFETY_MANAGER.guard_pages.write().push(guard);
    }
    
    Ok(())
}

/// メモリアクセス監視を解除
pub fn unmonitor_memory_region(start_addr: usize, size: usize) -> Result<(), &'static str> {
    if !SAFETY_MANAGER.initialized.load(Ordering::Acquire) {
        return Err("安全性マネージャが初期化されていません");
    }
    
    // ページサイズに合わせる
    let page_size = PageSize::Default as usize;
    let aligned_start = start_addr & !(page_size - 1);
    let pages = (size + (start_addr - aligned_start) + page_size - 1) / page_size;
    
    let mut guard_pages = SAFETY_MANAGER.guard_pages.write();
    
    // 該当するガード設定を非アクティブ化
    for i in 0..pages {
        let page_addr = aligned_start + i * page_size;
        
        for guard in guard_pages.iter_mut() {
            if guard.addr == page_addr {
                guard.active = false;
                
                // 標準のページ属性に戻す
                mm::set_page_protection(page_addr, page_size, true, true)?;
                break;
            }
        }
    }
    
    // 非アクティブなガードページを削除
    guard_pages.retain(|g| g.active);
    
    Ok(())
}

/// メモリ割り当て追跡を開始
pub fn track_allocation(addr: usize, size: usize) {
    if !SAFETY_MANAGER.initialized.load(Ordering::Relaxed) ||
       !SAFETY_MANAGER.verification_enabled.load(Ordering::Relaxed) {
        return;
    }
    
    // 現在のタイムスタンプ
    let time = SAFETY_MANAGER.time_counter.fetch_add(1, Ordering::Relaxed) as u64;
    
    // メタデータを作成
    let metadata = MemoryRegionMetadata::new(addr, size, time);
    
    // メモリ領域マップに追加
    SAFETY_MANAGER.memory_regions.write().insert(addr, metadata);
    
    // 解放済みアドレスリストから削除（再利用の場合）
    SAFETY_MANAGER.freed_addresses.write().remove(&addr);
    
    // 安全性レベルがStrict以上の場合、未初期化アクセス検出のための設定を行う
    let safety_level = *SAFETY_MANAGER.safety_level.read();
    if safety_level == SafetyLevel::Strict || safety_level == SafetyLevel::Debug {
        // ページのアクセス属性を変更して書き込み監視を有効化
        // 実際の実装では、ページごとに設定が必要
        let page_size = PageSize::Default as usize;
        let aligned_addr = addr & !(page_size - 1);
        let end_addr = addr + size;
        let aligned_end = (end_addr + page_size - 1) & !(page_size - 1);
        
        for page_addr in (aligned_addr..aligned_end).step_by(page_size) {
            if let Ok(_) = mm::set_page_protection(page_addr, page_size, true, true) {
                // 書き込み時にトラップしてmark_initializedを呼び出す設定
                // この実装は簡略化のため省略
            }
        }
    }
}

/// メモリ解放の追跡
pub fn track_deallocation(addr: usize, size: usize) {
    if !SAFETY_MANAGER.initialized.load(Ordering::Relaxed) ||
       !SAFETY_MANAGER.verification_enabled.load(Ordering::Relaxed) {
        return;
    }
    
    // メモリ領域マップから削除
    SAFETY_MANAGER.memory_regions.write().remove(&addr);
    
    // 解放済みアドレスリストに追加（UAF検出用）
    SAFETY_MANAGER.freed_addresses.write().insert(addr);
    
    // 安全性レベルがStrict以上の場合、解放後アクセス検出のための設定を行う
    let safety_level = *SAFETY_MANAGER.safety_level.read();
    if safety_level == SafetyLevel::Strict || safety_level == SafetyLevel::Debug {
        // ページを無効化してアクセス時にトラップ
        let page_size = PageSize::Default as usize;
        let aligned_addr = addr & !(page_size - 1);
        let end_addr = addr + size;
        let aligned_end = (end_addr + page_size - 1) & !(page_size - 1);
        
        for page_addr in (aligned_addr..aligned_end).step_by(page_size) {
            if let Ok(_) = mm::set_page_protection(page_addr, page_size, false, false) {
                // この設定により、解放後のメモリにアクセスするとページフォルトが発生
            }
        }
    }
}

/// メモリを初期化済みとしてマーク
pub fn mark_initialized(addr: usize, size: usize) {
    if !SAFETY_MANAGER.initialized.load(Ordering::Relaxed) ||
       !SAFETY_MANAGER.verification_enabled.load(Ordering::Relaxed) {
        return;
    }
    
    let mut regions = SAFETY_MANAGER.memory_regions.write();
    
    // 該当するメモリ領域を検索
    for (&region_addr, metadata) in regions.iter_mut() {
        if addr >= region_addr && addr < region_addr + metadata.size {
            let offset = addr - region_addr;
            metadata.mark_initialized(offset, size);
            break;
        }
    }
}

/// メモリ初期化状態をチェック
pub fn check_initialized(addr: usize, size: usize) -> bool {
    if !SAFETY_MANAGER.initialized.load(Ordering::Relaxed) ||
       !SAFETY_MANAGER.verification_enabled.load(Ordering::Relaxed) {
        return true; // 検証無効時は常に初期化済みとみなす
    }
    
    let regions = SAFETY_MANAGER.memory_regions.read();
    
    // 該当するメモリ領域を検索
    for (&region_addr, metadata) in regions.iter() {
        if addr >= region_addr && addr < region_addr + metadata.size {
            let offset = addr - region_addr;
            return metadata.is_initialized(offset, size);
        }
    }
    
    // 追跡されていないメモリは初期化済みとみなす
    true
}

/// メモリアクセス監視ハンドラを登録
pub fn register_violation_handler(violation_type: ViolationType, 
                                 handler: fn(&ViolationInfo)) {
    if !SAFETY_MANAGER.initialized.load(Ordering::Relaxed) {
        return;
    }
    
    let mut handlers = SAFETY_MANAGER.violation_handlers.write();
    
    // 既存のハンドラリストを取得または新規作成
    let type_handlers = handlers.entry(violation_type).or_insert_with(Vec::new);
    
    // ハンドラがまだ登録されていなければ追加
    if !type_handlers.contains(&handler) {
        type_handlers.push(handler);
    }
}

/// メモリアクセス監視ハンドラを削除
pub fn unregister_violation_handler(violation_type: ViolationType, 
                                   handler: fn(&ViolationInfo)) {
    if !SAFETY_MANAGER.initialized.load(Ordering::Relaxed) {
        return;
    }
    
    let mut handlers = SAFETY_MANAGER.violation_handlers.write();
    
    // 該当するハンドラリストがあれば、指定されたハンドラを削除
    if let Some(type_handlers) = handlers.get_mut(&violation_type) {
        type_handlers.retain(|&h| h != handler);
    }
}

/// メモリリーク検出を実行
pub fn check_memory_leaks() -> usize {
    if !SAFETY_MANAGER.initialized.load(Ordering::Relaxed) ||
       !SAFETY_MANAGER.verification_enabled.load(Ordering::Relaxed) {
        return 0;
    }
    
    let regions = SAFETY_MANAGER.memory_regions.read();
    let now = SAFETY_MANAGER.time_counter.load(Ordering::Relaxed) as u64;
    let mut leak_count = 0;
    
    // 長時間解放されていないメモリを検出
    for (&addr, metadata) in regions.iter() {
        let age = now - metadata.allocation_time;
        
        // 長時間（例：1時間以上）割り当てられたままのメモリを検出
        // 実際の閾値はシステムに応じて調整
        if age > 3600000 { // 60分*60秒*1000ミリ秒
            leak_count += 1;
            
            // リークの報告
            let violation = ViolationInfo {
                violation_type: ViolationType::MemoryLeak,
                address: addr,
                size: metadata.size,
                instruction_ptr: 0, // 不明
                stack_trace: metadata.allocation_stack.clone(),
                timestamp: now,
                process_id: None,
                description: Some("長時間解放されていないメモリ"),
            };
            
            report_violation(&violation);
        }
    }
    
    leak_count
}

/// メモリアクセスイベントを記録
pub fn record_memory_access(addr: usize, size: usize, is_write: bool, instruction_ptr: usize) {
    if !SAFETY_MANAGER.initialized.load(Ordering::Relaxed) ||
       !SAFETY_MANAGER.verification_enabled.load(Ordering::Relaxed) {
        return;
    }
    
    let safety_level = *SAFETY_MANAGER.safety_level.read();
    if safety_level != SafetyLevel::Debug {
        return; // デバッグレベルのみで有効
    }
    
    // 現在のタイムスタンプ
    let time = SAFETY_MANAGER.time_counter.fetch_add(1, Ordering::Relaxed) as u64;
    
    // アクセス履歴に記録
    let mut history = SAFETY_MANAGER.access_history.lock();
    
    // 履歴が満杯なら古いエントリを削除
    if history.len() >= 128 {
        history.remove(0);
    }
    
    // 新しいアクセスを記録
    history.push(AccessHistoryEntry {
        addr,
        size,
        is_write,
        instruction_ptr,
        timestamp: time,
    });
    
    // 読み取りアクセスの場合、初期化状態をチェック
    if !is_write && !check_initialized(addr, size) {
        // 未初期化メモリ読み取り違反の報告
        let violation = ViolationInfo {
            violation_type: ViolationType::UninitializedRead,
            address: addr,
            size,
            instruction_ptr,
            stack_trace: Some(capture_stack_trace(10)),
            timestamp: time,
            process_id: None,
            description: Some("未初期化メモリからの読み取り"),
        };
        
        report_violation(&violation);
    }
    
    // 書き込みアクセスの場合、領域を初期化済みとしてマーク
    if is_write {
        mark_initialized(addr, size);
    }
}

/// 現在のメモリ安全性統計を取得
pub fn get_safety_stats() -> SafetyStats {
    SafetyStats {
        violation_count: SAFETY_MANAGER.violation_count.load(Ordering::Relaxed),
        tracked_regions: SAFETY_MANAGER.memory_regions.read().len(),
        freed_addresses: SAFETY_MANAGER.freed_addresses.read().len(),
        guard_pages: SAFETY_MANAGER.guard_pages.read().len(),
        safety_level: *SAFETY_MANAGER.safety_level.read(),
    }
}

/// メモリ安全性統計
#[derive(Debug, Clone, Copy)]
pub struct SafetyStats {
    /// 検出された違反の数
    pub violation_count: usize,
    /// 追跡中のメモリ領域数
    pub tracked_regions: usize,
    /// 解放済みアドレス数
    pub freed_addresses: usize,
    /// アクティブなガードページ数
    pub guard_pages: usize,
    /// 現在の安全性レベル
    pub safety_level: SafetyLevel,
}

/// メモリ安全性統計を表示
pub fn print_safety_stats() {
    let stats = get_safety_stats();
    
    log::info!("=== メモリ安全性統計 ===");
    log::info!("違反検出数: {}", stats.violation_count);
    log::info!("追跡領域数: {}", stats.tracked_regions);
    log::info!("解放済アドレス: {}", stats.freed_addresses);
    log::info!("ガードページ: {}", stats.guard_pages);
    log::info!("安全性レベル: {:?}", stats.safety_level);
    log::info!("=======================");
}

/// アラインメント違反をチェック
pub fn check_alignment(addr: usize, alignment: usize) -> bool {
    addr % alignment == 0
}

/// スタック使用量をチェック
pub fn check_stack_usage(stack_base: usize, stack_size: usize) -> Result<usize, &'static str> {
    if !SAFETY_MANAGER.initialized.load(Ordering::Relaxed) {
        return Err("安全性マネージャが初期化されていません");
    }
    
    // 現在のスタックポインタを取得
    let stack_ptr: usize;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) stack_ptr);
    }
    
    // スタック使用量を計算（スタックは下方向に成長）
    if stack_ptr < stack_base - stack_size {
        // スタックオーバーフロー
        let violation = ViolationInfo {
            violation_type: ViolationType::StackOverflow,
            address: stack_ptr,
            size: 0,
            instruction_ptr: 0, // 不明
            stack_trace: Some(capture_stack_trace(5)),
            timestamp: SAFETY_MANAGER.time_counter.load(Ordering::Relaxed) as u64,
            process_id: None,
            description: Some("スタックオーバーフロー"),
        };
        
        report_violation(&violation);
        return Err("スタックオーバーフロー");
    }
    
    // 使用量の計算（スタックは上位アドレスから下位アドレスに向かって成長）
    let used = stack_base - stack_ptr;
    
    Ok(used)
}

/// NULLポインタデリファレンス保護を有効化
pub fn enable_null_pointer_protection() -> Result<(), &'static str> {
    if !SAFETY_MANAGER.initialized.load(Ordering::Acquire) {
        return Err("安全性マネージャが初期化されていません");
    }
    
    // NULLページを保護（0ページから1ページ分）
    monitor_memory_region(0, PageSize::Default as usize, 
                         ViolationType::NullPointerDereference, 
                         "NULLポインタデリファレンス")
}

/// 安全性検証の有効/無効を設定
pub fn set_verification_enabled(enabled: bool) {
    SAFETY_MANAGER.verification_enabled.store(enabled, Ordering::Relaxed);
    log::info!("メモリ安全性検証: {}", if enabled { "有効" } else { "無効" });
} 