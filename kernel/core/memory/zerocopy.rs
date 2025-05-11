// AetherOS ゼロコピーメモリ転送
//
// このモジュールは異なるメモリ階層間での効率的なデータ転送を実現します。
// DMA、マップ/リマップ、ハードウェアオフロード技術を活用して
// コピー操作のオーバーヘッドを最小化します。

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};
use crate::arch::{PageSize, DmaCapabilities, DmaChannelType};
use crate::core::memory::{mm, cxl, pmem, numa, MemoryTier};
use crate::drivers::dma::{self, DmaRequest, DmaTransferType, DmaCallback, DmaFlags};

/// 転送方式
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransferMethod {
    /// CPU制御コピー
    CpuCopy,
    /// DMAコントローラ利用
    DmaEngine,
    /// ページテーブル操作
    PageRemapping,
    /// ハードウェアアクセラレータ使用
    HardwareAccelerated,
    /// 自動選択（最適な方法）
    Auto,
}

/// 転送プライオリティ
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransferPriority {
    /// 低優先度
    Low = 0,
    /// 通常優先度
    Normal = 1,
    /// 高優先度
    High = 2,
    /// 最高優先度（リアルタイム）
    Realtime = 3,
}

/// 転送状態
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransferStatus {
    /// 初期状態
    Initial,
    /// 待機中
    Queued,
    /// 進行中
    InProgress,
    /// 完了
    Completed,
    /// 失敗
    Failed,
    /// キャンセル済み
    Cancelled,
}

/// ゼロコピー転送ディスクリプタ
pub struct ZeroCopyTransfer {
    /// 転送ID
    pub id: usize,
    /// ソースアドレス
    pub source: usize,
    /// 宛先アドレス
    pub destination: usize,
    /// サイズ
    pub size: usize,
    /// 転送方式
    pub method: TransferMethod,
    /// 優先度
    pub priority: TransferPriority,
    /// 現在の状態
    pub status: AtomicUsize,
    /// 転送完了時コールバック
    pub callback: Option<fn(usize, bool)>,
    /// ソースメモリ階層
    pub source_tier: MemoryTier,
    /// 宛先メモリ階層
    pub destination_tier: MemoryTier,
    /// 開始時間
    pub start_time: Option<u64>,
    /// 完了時間
    pub completion_time: Option<u64>,
    /// メタデータのみフラグ
    pub metadata_only: bool,
    /// ゼロコピーフラグ
    pub zero_copy: bool,
}

impl ZeroCopyTransfer {
    /// 新しい転送ディスクリプタを作成
    pub fn new(source: usize, destination: usize, size: usize) -> Self {
        static NEXT_TRANSFER_ID: AtomicUsize = AtomicUsize::new(1);
        
        // ソースと宛先のメモリ階層を判定
        let source_tier = crate::core::memory::determine_memory_tier(
            mm::virtual_to_physical(source).unwrap_or(0)
        );
        
        let destination_tier = crate::core::memory::determine_memory_tier(
            mm::virtual_to_physical(destination).unwrap_or(0)
        );
        
        Self {
            id: NEXT_TRANSFER_ID.fetch_add(1, Ordering::Relaxed),
            source,
            destination,
            size,
            method: TransferMethod::Auto,
            priority: TransferPriority::Normal,
            status: AtomicUsize::new(TransferStatus::Initial as usize),
            callback: None,
            source_tier,
            destination_tier,
            start_time: None,
            completion_time: None,
            metadata_only: false,
            zero_copy: true,
        }
    }
    
    /// 転送方式を設定
    pub fn with_method(mut self, method: TransferMethod) -> Self {
        self.method = method;
        self
    }
    
    /// 優先度を設定
    pub fn with_priority(mut self, priority: TransferPriority) -> Self {
        self.priority = priority;
        self
    }
    
    /// コールバックを設定
    pub fn with_callback(mut self, callback: fn(usize, bool)) -> Self {
        self.callback = Some(callback);
        self
    }
    
    /// メタデータのみフラグを設定
    pub fn with_metadata_only(mut self, metadata_only: bool) -> Self {
        self.metadata_only = metadata_only;
        self
    }
    
    /// 転送状態を取得
    pub fn get_status(&self) -> TransferStatus {
        let status_raw = self.status.load(Ordering::Relaxed);
        match status_raw {
            0 => TransferStatus::Initial,
            1 => TransferStatus::Queued,
            2 => TransferStatus::InProgress,
            3 => TransferStatus::Completed,
            4 => TransferStatus::Failed,
            5 => TransferStatus::Cancelled,
            _ => TransferStatus::Failed,
        }
    }
    
    /// 転送状態を設定
    fn set_status(&self, status: TransferStatus) {
        self.status.store(status as usize, Ordering::Release);
    }
    
    /// 転送が完了したかチェック
    pub fn is_completed(&self) -> bool {
        self.get_status() == TransferStatus::Completed
    }
    
    /// 転送が失敗したかチェック
    pub fn is_failed(&self) -> bool {
        self.get_status() == TransferStatus::Failed
    }
}

/// 転送スケジューラ
struct TransferScheduler {
    /// 転送キュー
    queue: Mutex<Vec<ZeroCopyTransfer>>,
    /// アクティブな転送数
    active_transfers: AtomicUsize,
    /// 最大並列転送数
    max_concurrent: usize,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// DMA利用可能フラグ
    dma_available: bool,
    /// ハードウェアアクセラレータ利用可能フラグ
    hw_accelerator_available: bool,
}

/// グローバル転送スケジューラ
static TRANSFER_SCHEDULER: TransferScheduler = TransferScheduler {
    queue: Mutex::new(Vec::new()),
    active_transfers: AtomicUsize::new(0),
    max_concurrent: 8,
    initialized: AtomicBool::new(false),
    dma_available: false,
    hw_accelerator_available: false,
};

/// ゼロコピー転送サブシステムの初期化
pub fn init() {
    // 初期化フェンス
    if TRANSFER_SCHEDULER.initialized.load(Ordering::Acquire) {
        return;
    }
    
    // ハードウェア機能の検出
    let dma_available = dma::is_available();
    let hw_accelerator_available = crate::drivers::accelerator::is_memory_copy_available();
    
    // スケジューラの初期化（static変更のためunsafe）
    unsafe {
        let scheduler_ptr = &TRANSFER_SCHEDULER as *const _ as *mut TransferScheduler;
        (*scheduler_ptr).dma_available = dma_available;
        (*scheduler_ptr).hw_accelerator_available = hw_accelerator_available;
        
        // 環境に応じた最大並列転送数の設定
        let cpu_count = crate::arch::get_cpu_count();
        (*scheduler_ptr).max_concurrent = core::cmp::max(4, cpu_count / 2);
    }
    
    // ワーカースレッド起動
    let _ = crate::core::thread::spawn("zerocopy_worker", transfer_worker_thread);
    
    TRANSFER_SCHEDULER.initialized.store(true, Ordering::Release);
    log::info!("ゼロコピー転送サブシステム初期化完了 (DMA: {}, HW: {})",
              dma_available, hw_accelerator_available);
}

/// 転送ワーカースレッド
fn transfer_worker_thread() -> Result<(), &'static str> {
    if !TRANSFER_SCHEDULER.initialized.load(Ordering::Relaxed) {
        return Err("ゼロコピー転送サブシステムが初期化されていません");
    }
    
    log::debug!("ゼロコピー転送ワーカースレッド開始");
    
    loop {
        // スケジューラからの転送タスク取得・実行
        process_pending_transfers();
        
        // 短時間スリープ
        crate::core::thread::sleep(10);
    }
}

/// 保留中の転送を処理
fn process_pending_transfers() {
    // アクティブな転送数が上限に達していたら何もしない
    let active = TRANSFER_SCHEDULER.active_transfers.load(Ordering::Relaxed);
    if active >= TRANSFER_SCHEDULER.max_concurrent {
        return;
    }
    
    let available_slots = TRANSFER_SCHEDULER.max_concurrent - active;
    if available_slots == 0 {
        return;
    }
    
    // 保留中の転送を処理
    let mut queue = TRANSFER_SCHEDULER.queue.lock();
    
    // 優先度に基づいてキューをソート
    queue.sort_by(|a, b| b.priority.cmp(&a.priority));
    
    let mut started = 0;
    let mut i = 0;
    
    while i < queue.len() && started < available_slots {
        let transfer = &queue[i];
        
        // まだ開始されていない転送のみ処理
        if transfer.get_status() == TransferStatus::Queued {
            // 転送開始
            let result = start_transfer(transfer);
            
            if result.is_ok() {
                started += 1;
                TRANSFER_SCHEDULER.active_transfers.fetch_add(1, Ordering::Relaxed);
            } else {
                // 転送開始に失敗した場合は状態を更新
                transfer.set_status(TransferStatus::Failed);
                
                // コールバックを呼び出し
                if let Some(callback) = transfer.callback {
                    callback(transfer.id, false);
                }
            }
        }
        
        i += 1;
    }
    
    // 完了または失敗した転送をキューから削除
    queue.retain(|t| {
        let status = t.get_status();
        status != TransferStatus::Completed && status != TransferStatus::Failed
    });
}

/// 転送を開始
fn start_transfer(transfer: &ZeroCopyTransfer) -> Result<(), &'static str> {
    // 現在のシステム時間を記録
    let now = crate::core::time::get_system_time();
    
    // 開始時間を設定（static変更のためunsafe）
    unsafe {
        let transfer_ptr = transfer as *const _ as *mut ZeroCopyTransfer;
        (*transfer_ptr).start_time = Some(now);
    }
    
    // 状態を進行中に更新
    transfer.set_status(TransferStatus::InProgress);
    
    // 転送方式を選択
    let method = if transfer.method == TransferMethod::Auto {
        select_optimal_transfer_method(transfer)
    } else {
        transfer.method
    };
    
    // 転送を実行
    match method {
        TransferMethod::CpuCopy => {
            execute_cpu_copy(transfer)?;
        },
        TransferMethod::DmaEngine => {
            if TRANSFER_SCHEDULER.dma_available {
                execute_dma_transfer(transfer)?;
            } else {
                // DMAが利用できない場合はCPUコピーにフォールバック
                execute_cpu_copy(transfer)?;
            }
        },
        TransferMethod::PageRemapping => {
            if transfer.metadata_only {
                execute_page_remapping(transfer)?;
            } else {
                // メタデータのみでない場合はCPUコピーにフォールバック
                execute_cpu_copy(transfer)?;
            }
        },
        TransferMethod::HardwareAccelerated => {
            if TRANSFER_SCHEDULER.hw_accelerator_available {
                execute_hardware_accelerated(transfer)?;
            } else {
                // ハードウェアアクセラレータが利用できない場合はDMAまたはCPUコピーにフォールバック
                if TRANSFER_SCHEDULER.dma_available {
                    execute_dma_transfer(transfer)?;
                } else {
                    execute_cpu_copy(transfer)?;
                }
            }
        },
        _ => {
            return Err("未サポートの転送方式");
        }
    }
    
    Ok(())
}

/// 最適な転送方式を選択
fn select_optimal_transfer_method(transfer: &ZeroCopyTransfer) -> TransferMethod {
    // ソースと宛先のティア（階層）に基づいて最適な方法を選択
    match (transfer.source_tier, transfer.destination_tier) {
        // 同一階層内の転送
        (tier1, tier2) if tier1 == tier2 => {
            // メタデータのみのケースはページリマッピングが効率的
            if transfer.metadata_only {
                return TransferMethod::PageRemapping;
            }
            
            // サイズに応じた選択
            if transfer.size >= 64 * 1024 {
                // 大きなサイズはDMAが効率的
                if TRANSFER_SCHEDULER.dma_available {
                    return TransferMethod::DmaEngine;
                }
            }
            
            // ハードウェアアクセラレータが利用可能なら使用
            if TRANSFER_SCHEDULER.hw_accelerator_available {
                return TransferMethod::HardwareAccelerated;
            }
            
            // デフォルトはCPUコピー
            TransferMethod::CpuCopy
        },
        
        // PMEM→DRAM転送
        (MemoryTier::PMEM, MemoryTier::StandardDRAM) | 
        (MemoryTier::PMEM, MemoryTier::FastDRAM) => {
            // PMEMからの読み出しはDMAが効率的
            if TRANSFER_SCHEDULER.dma_available {
                return TransferMethod::DmaEngine;
            }
            TransferMethod::CpuCopy
        },
        
        // CXL→DRAM転送
        (MemoryTier::ExtendedMemory, MemoryTier::StandardDRAM) | 
        (MemoryTier::ExtendedMemory, MemoryTier::FastDRAM) => {
            // CXLメモリからの転送はハードウェアアクセラレータが効率的
            if TRANSFER_SCHEDULER.hw_accelerator_available {
                return TransferMethod::HardwareAccelerated;
            }
            if TRANSFER_SCHEDULER.dma_available {
                return TransferMethod::DmaEngine;
            }
            TransferMethod::CpuCopy
        },
        
        // リモートNUMA→ローカルDRAM転送
        (MemoryTier::RemoteMemory, MemoryTier::StandardDRAM) | 
        (MemoryTier::RemoteMemory, MemoryTier::FastDRAM) => {
            // NUMAリモートアクセスはDMAが効率的
            if TRANSFER_SCHEDULER.dma_available {
                return TransferMethod::DmaEngine;
            }
            TransferMethod::CpuCopy
        },
        
        // その他の組み合わせ
        _ => {
            // 大きなサイズはDMA
            if transfer.size >= 64 * 1024 && TRANSFER_SCHEDULER.dma_available {
                return TransferMethod::DmaEngine;
            }
            
            // デフォルトはCPUコピー
            TransferMethod::CpuCopy
        }
    }
}

/// CPU制御のコピー処理を実行
fn execute_cpu_copy(transfer: &ZeroCopyTransfer) -> Result<(), &'static str> {
    // 非同期コピー用のスレッド起動
    let transfer_id = transfer.id;
    let src = transfer.source;
    let dst = transfer.destination;
    let size = transfer.size;
    let callback = transfer.callback;
    
    let _ = crate::core::thread::spawn_once("cpu_copy", move || {
        // サイズに応じてSIMD拡張を使用
        if size >= 128 && crate::arch::has_avx2() {
            // AVX2命令を使用した高速コピー
            unsafe { simd_memcpy(dst as *mut u8, src as *const u8, size); }
        } else {
            // 標準的なメモリコピー
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src as *const u8,
                    dst as *mut u8,
                    size
                );
            }
        }
        
        // 転送完了通知
        notify_transfer_completion(transfer_id, true);
        
        // コールバック呼び出し
        if let Some(cb) = callback {
            cb(transfer_id, true);
        }
    });
    
    Ok(())
}

/// DMA転送を実行
fn execute_dma_transfer(transfer: &ZeroCopyTransfer) -> Result<(), &'static str> {
    // 転送IDを取得
    let transfer_id = transfer.id;
    
    // 物理アドレスを取得
    let src_phys = mm::virtual_to_physical(transfer.source)
        .ok_or("ソースの物理アドレス変換に失敗")?;
    
    let dst_phys = mm::virtual_to_physical(transfer.destination)
        .ok_or("宛先の物理アドレス変換に失敗")?;
    
    // DMリクエスト作成
    let request = DmaRequest {
        src_addr: src_phys,
        dst_addr: dst_phys,
        size: transfer.size,
        transfer_type: DmaTransferType::MemoryToMemory,
        callback: Some(DmaCallback::new(move |success| {
            // 転送完了通知
            notify_transfer_completion(transfer_id, success);
            
            // コールバック呼び出し
            if let Some(cb) = transfer.callback {
                cb(transfer_id, success);
            }
        })),
        flags: if transfer.priority >= TransferPriority::High {
            DmaFlags::HIGH_PRIORITY
        } else {
            DmaFlags::NONE
        },
    };
    
    // DMA転送開始
    dma::start_transfer(request)?;
    
    Ok(())
}

/// ページリマッピングによる転送を実行
fn execute_page_remapping(transfer: &ZeroCopyTransfer) -> Result<(), &'static str> {
    // メタデータのみの転送の場合にのみ有効
    if !transfer.metadata_only {
        return Err("メタデータのみ転送でないためページリマッピングを使用できません");
    }
    
    // 転送IDを取得
    let transfer_id = transfer.id;
    
    // 物理アドレスを取得
    let src_phys = mm::virtual_to_physical(transfer.source)
        .ok_or("ソースの物理アドレス変換に失敗")?;
    
    // ページサイズとページ数を計算
    let page_size = crate::arch::PageSize::Default as usize;
    let page_count = (transfer.size + page_size - 1) / page_size;
    
    // 宛先をリマップ
    mm::remap_pages(transfer.destination, src_phys, page_count, true, true)?;
    
    // 非同期完了通知
    let callback = transfer.callback;
    let _ = crate::core::thread::spawn_once("remap_notify", move || {
        // 転送完了通知
        notify_transfer_completion(transfer_id, true);
        
        // コールバック呼び出し
        if let Some(cb) = callback {
            cb(transfer_id, true);
        }
    });
    
    Ok(())
}

/// ハードウェアアクセラレータを使用した転送を実行
fn execute_hardware_accelerated(transfer: &ZeroCopyTransfer) -> Result<(), &'static str> {
    // 転送IDを取得
    let transfer_id = transfer.id;
    
    // ハードウェアアクセラレータに転送を依頼
    let result = crate::drivers::accelerator::copy_memory(
        transfer.source,
        transfer.destination,
        transfer.size,
        Box::new(move |success| {
            // 転送完了通知
            notify_transfer_completion(transfer_id, success);
            
            // コールバック呼び出し
            if let Some(cb) = transfer.callback {
                cb(transfer_id, success);
            }
        })
    );
    
    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            // ハードウェアアクセラレータが失敗した場合はCPUコピーにフォールバック
            log::warn!("ハードウェアアクセラレータ転送失敗: {}, CPUコピーにフォールバック", e);
            execute_cpu_copy(transfer)
        }
    }
}

/// 転送完了を通知
fn notify_transfer_completion(transfer_id: usize, success: bool) {
    // キューから転送を探す
    let mut queue = TRANSFER_SCHEDULER.queue.lock();
    
    for transfer in queue.iter() {
        if transfer.id == transfer_id {
            // 状態を更新
            transfer.set_status(if success {
                TransferStatus::Completed
            } else {
                TransferStatus::Failed
            });
            
            // 完了時間を設定
            unsafe {
                let transfer_ptr = transfer as *const _ as *mut ZeroCopyTransfer;
                (*transfer_ptr).completion_time = Some(crate::core::time::get_system_time());
            }
            
            break;
        }
    }
    
    // アクティブ転送カウンタを減少
    TRANSFER_SCHEDULER.active_transfers.fetch_sub(1, Ordering::Relaxed);
}

/// 新しい転送を開始
pub fn start(source: usize, destination: usize, size: usize) -> Result<usize, &'static str> {
    if !TRANSFER_SCHEDULER.initialized.load(Ordering::Relaxed) {
        return Err("ゼロコピー転送サブシステムが初期化されていません");
    }
    
    // 新しい転送ディスクリプタを作成
    let transfer = ZeroCopyTransfer::new(source, destination, size);
    let transfer_id = transfer.id;
    
    // 状態を待機中に設定
    transfer.set_status(TransferStatus::Queued);
    
    // 転送キューに追加
    TRANSFER_SCHEDULER.queue.lock().push(transfer);
    
    Ok(transfer_id)
}

/// 指定したIDの転送をキャンセル
pub fn cancel(transfer_id: usize) -> bool {
    if !TRANSFER_SCHEDULER.initialized.load(Ordering::Relaxed) {
        return false;
    }
    
    let mut queue = TRANSFER_SCHEDULER.queue.lock();
    
    for transfer in queue.iter() {
        if transfer.id == transfer_id {
            let current_status = transfer.get_status();
            
            // キューに入っているか進行中の転送のみキャンセル可能
            if current_status == TransferStatus::Queued || 
               current_status == TransferStatus::InProgress {
                transfer.set_status(TransferStatus::Cancelled);
                return true;
            }
            
            break;
        }
    }
    
    false
}

/// 転送状態を取得
pub fn get_status(transfer_id: usize) -> Option<TransferStatus> {
    if !TRANSFER_SCHEDULER.initialized.load(Ordering::Relaxed) {
        return None;
    }
    
    let queue = TRANSFER_SCHEDULER.queue.lock();
    
    for transfer in queue.iter() {
        if transfer.id == transfer_id {
            return Some(transfer.get_status());
        }
    }
    
    None
}

/// 転送完了を待機
pub fn wait_for_completion(transfer_id: usize, timeout_ms: Option<u64>) -> Result<bool, &'static str> {
    if !TRANSFER_SCHEDULER.initialized.load(Ordering::Relaxed) {
        return Err("ゼロコピー転送サブシステムが初期化されていません");
    }
    
    let start_time = crate::core::time::get_system_time();
    
    loop {
        // 転送状態を確認
        match get_status(transfer_id) {
            Some(TransferStatus::Completed) => return Ok(true),
            Some(TransferStatus::Failed) => return Ok(false),
            Some(TransferStatus::Cancelled) => return Ok(false),
            Some(_) => {
                // 継続して待機
            },
            None => return Err("指定された転送が見つかりません"),
        }
        
        // タイムアウトチェック
        if let Some(timeout) = timeout_ms {
            let elapsed = crate::core::time::get_system_time() - start_time;
            if elapsed >= timeout {
                return Err("タイムアウト");
            }
        }
        
        // 短時間スリープ
        crate::core::thread::yield_now();
    }
}

/// SIMD命令を使用した高速メモリコピー
///
/// # Safety
///
/// ソースとデスティネーションのポインタが有効で、サイズが適切であること
unsafe fn simd_memcpy(dst: *mut u8, src: *const u8, size: usize) {
    // 16バイトアラインメントに合わせる
    let mut dst_ptr = dst;
    let mut src_ptr = src;
    let mut remaining = size;
    
    // 16バイトアラインメントに合わせるための処理
    let dst_offset = (dst as usize) & 15;
    if dst_offset != 0 {
        let prefix = 16 - dst_offset;
        if prefix <= remaining {
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, prefix);
            dst_ptr = dst_ptr.add(prefix);
            src_ptr = src_ptr.add(prefix);
            remaining -= prefix;
        } else {
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, remaining);
            return;
        }
    }
    
    // AVX2を使用した高速コピー（32バイト単位）
    if crate::arch::has_avx2() && remaining >= 32 {
        while remaining >= 32 {
            // AVX2でロード・ストア
            #[cfg(target_arch = "x86_64")]
            {
                use core::arch::x86_64::{__m256i, _mm256_load_si256, _mm256_store_si256};
                
                let ymm0 = _mm256_load_si256(src_ptr as *const __m256i);
                _mm256_store_si256(dst_ptr as *mut __m256i, ymm0);
            }
            
            dst_ptr = dst_ptr.add(32);
            src_ptr = src_ptr.add(32);
            remaining -= 32;
        }
    }
    
    // SSEを使用した高速コピー（16バイト単位）
    if crate::arch::has_sse2() && remaining >= 16 {
        while remaining >= 16 {
            // SSE2でロード・ストア
            #[cfg(target_arch = "x86_64")]
            {
                use core::arch::x86_64::{__m128i, _mm_load_si128, _mm_store_si128};
                
                let xmm0 = _mm_load_si128(src_ptr as *const __m128i);
                _mm_store_si128(dst_ptr as *mut __m128i, xmm0);
            }
            
            dst_ptr = dst_ptr.add(16);
            src_ptr = src_ptr.add(16);
            remaining -= 16;
        }
    }
    
    // 残りのバイトを通常のコピーで処理
    if remaining > 0 {
        core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, remaining);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_zero_copy_transfer() {
        // 初期化
        init();
        
        // テスト用のメモリ割り当て
        let src_size = 1024 * 1024; // 1MB
        let src = crate::core::memory::allocator::allocate(src_size).unwrap();
        let dst = crate::core::memory::allocator::allocate(src_size).unwrap();
        
        // テストデータの作成
        for i in 0..src_size {
            unsafe {
                *((src as usize + i) as *mut u8) = (i % 256) as u8;
            }
        }
        
        // 転送開始
        let transfer_id = start(src as usize, dst as usize, src_size).unwrap();
        
        // 完了待機
        let result = wait_for_completion(transfer_id, Some(1000)).unwrap();
        assert!(result);
        
        // データ検証
        for i in 0..src_size {
            let src_byte = unsafe { *((src as usize + i) as *const u8) };
            let dst_byte = unsafe { *((dst as usize + i) as *const u8) };
            assert_eq!(src_byte, dst_byte);
        }
        
        // メモリ解放
        let _ = crate::core::memory::allocator::free(src, src_size);
        let _ = crate::core::memory::allocator::free(dst, src_size);
    }
} 