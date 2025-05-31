// AetherOS ゼロコピー転送モジュール
//
// このモジュールは効率的なデータ転送のためのゼロコピー機能を提供します。
// ゼロコピーはデータ移動を最小限に抑え、メモリバス帯域とCPU使用率を削減します。

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::fmt::Debug;
use crate::core::memory::mm::MappingFlags;
use crate::core::network::protocol::TransportError;
use crate::core::network::device::{RdmaMemoryRegion, DeviceId};
use crate::core::sync::{Mutex, RwLock};

/// ゼロコピーバッファ
///
/// このバッファはデータのコピーを回避するための特別なメモリ領域です。
/// 物理的に連続したメモリ領域を確保し、カーネルとユーザー空間、
/// そしてネットワークデバイスと直接共有できるようにします。
pub struct ZeroCopyBuffer {
    /// 開始アドレス
    addr: NonNull<u8>,
    /// バッファサイズ
    size: usize,
    /// 物理アドレス（DMA用）
    phys_addr: usize,
    /// RDMA登録（該当する場合）
    rdma_region: Option<Arc<dyn RdmaMemoryRegion>>,
    /// デバイスID
    device_id: Option<DeviceId>,
    /// バッファのフラグ
    flags: ZeroCopyFlags,
    /// リファレンスカウント
    refs: Mutex<usize>,
    /// 使用中バイト数
    used_bytes: Mutex<usize>,
}

/// ゼロコピーバッファビュー
///
/// バッファの特定の範囲への参照を表します。
/// バッファの一部を他のコンポーネントと共有するために使用します。
pub struct ZeroCopyBufferView {
    /// 基盤バッファ
    buffer: Arc<ZeroCopyBuffer>,
    /// オフセット
    offset: usize,
    /// 長さ
    length: usize,
    /// 書き込み可能フラグ
    writable: bool,
}

/// ゼロコピーフラグ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroCopyFlags(u32);

impl ZeroCopyFlags {
    /// カーネル専用（ユーザー空間からアクセス不可）
    pub const KERNEL_ONLY: Self = Self(0x0001);
    /// デバイスマップ済み（DMAが可能）
    pub const DEVICE_MAPPED: Self = Self(0x0002);
    /// 読み取り専用
    pub const READ_ONLY: Self = Self(0x0004);
    /// CPU非キャッシュ
    pub const NON_CACHED: Self = Self(0x0008);
    /// CPU書き込み結合（write-combining）
    pub const WRITE_COMBINING: Self = Self(0x0010);
    /// 共有可能
    pub const SHAREABLE: Self = Self(0x0020);
    /// ページロック済み
    pub const PAGE_LOCKED: Self = Self(0x0040);
    /// RDMA登録済み
    pub const RDMA_REGISTERED: Self = Self(0x0080);
    
    /// 新しいフラグセットを作成
    pub fn new() -> Self {
        Self(0)
    }
    
    /// フラグを追加
    pub fn with(self, flag: Self) -> Self {
        Self(self.0 | flag.0)
    }
    
    /// フラグを持っているか確認
    pub fn has(&self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }
}

/// ゼロコピー転送記述子
#[derive(Debug)]
pub struct ZeroCopyTransferDescriptor {
    /// 転送元バッファビュー
    pub src: ZeroCopyBufferView,
    /// 転送先バッファビュー（None=送信）
    pub dst: Option<ZeroCopyBufferView>,
    /// 完了コールバック
    pub completion: Option<ZeroCopyCompletionCallback>,
    /// ユーザーデータ
    pub user_data: u64,
}

/// ゼロコピー完了コールバック
pub type ZeroCopyCompletionCallback = fn(result: Result<usize, TransportError>, user_data: u64);

/// ゼロコピー転送マネージャ
pub struct ZeroCopyManager {
    /// アロケーションプール（サイズ別）
    pools: RwLock<Vec<ZeroCopyPool>>,
    /// 進行中の転送
    active_transfers: Mutex<Vec<ZeroCopyTransfer>>,
    /// デバイスマッピング
    device_mappings: Mutex<Vec<DeviceMapping>>,
}

/// ゼロコピープール
struct ZeroCopyPool {
    /// ブロックサイズ
    block_size: usize,
    /// プールフラグ
    flags: ZeroCopyFlags,
    /// 使用可能なバッファ
    available: Mutex<Vec<Arc<ZeroCopyBuffer>>>,
    /// 使用中バッファ数
    used_count: Mutex<usize>,
    /// 最大バッファ数
    max_buffers: usize,
}

/// 進行中のゼロコピー転送
struct ZeroCopyTransfer {
    /// 転送ID
    id: u64,
    /// 転送元バッファ
    src_buffer: Arc<ZeroCopyBuffer>,
    /// 転送先バッファ
    dst_buffer: Option<Arc<ZeroCopyBuffer>>,
    /// 転送サイズ
    size: usize,
    /// 完了コールバック
    completion: Option<ZeroCopyCompletionCallback>,
    /// ユーザーデータ
    user_data: u64,
    /// デバイスID
    device_id: DeviceId,
    /// 転送開始時刻
    start_time: u64,
}

/// デバイスマッピング
struct DeviceMapping {
    /// デバイスID
    device_id: DeviceId,
    /// バッファ
    buffer: Arc<ZeroCopyBuffer>,
    /// デバイス固有のハンドル
    device_handle: u64,
}

// SAFETY: ZeroCopyBufferは複数スレッドで共有可能
unsafe impl Send for ZeroCopyBuffer {}
unsafe impl Sync for ZeroCopyBuffer {}

// SAFETY: ZeroCopyBufferViewは複数スレッドで共有可能
unsafe impl Send for ZeroCopyBufferView {}
unsafe impl Sync for ZeroCopyBufferView {}

impl ZeroCopyBuffer {
    /// 新しいゼロコピーバッファを作成
    pub fn new(size: usize, flags: ZeroCopyFlags) -> Result<Self, TransportError> {
        // メモリ管理サブシステムから物理的に連続したメモリを割り当て
        let mapping_flags = if flags.has(ZeroCopyFlags::NON_CACHED) {
            MappingFlags::NON_CACHED
        } else if flags.has(ZeroCopyFlags::WRITE_COMBINING) {
            MappingFlags::WRITE_COMBINING
        } else {
            MappingFlags::NORMAL
        };
        
        // 物理メモリ割り当て（実際のコードでは適切なAPIを呼び出す）
        let (virt_addr, phys_addr) = allocate_contiguous_memory(size, mapping_flags)
            .map_err(|e| TransportError::AllocationFailed(format!("ゼロコピーバッファ割り当て失敗: {}", e)))?;
        
        // バッファを作成
        Ok(Self {
            addr: virt_addr,
            size,
            phys_addr,
            rdma_region: None,
            device_id: None,
            flags,
            refs: Mutex::new(1),
            used_bytes: Mutex::new(0),
        })
    }
    
    /// ポインタを取得
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr.as_ptr()
    }
    
    /// サイズを取得
    pub fn size(&self) -> usize {
        self.size
    }
    
    /// 物理アドレスを取得
    pub fn physical_address(&self) -> usize {
        self.phys_addr
    }
    
    /// バッファにデータを書き込み
    pub fn write(&self, offset: usize, data: &[u8]) -> Result<usize, TransportError> {
        // 境界チェック
        if offset + data.len() > self.size {
            return Err(TransportError::InvalidData(format!(
                "バッファ境界外書き込み: オフセット={}, 長さ={}, バッファサイズ={}",
                offset, data.len(), self.size
            )));
        }
        
        // 読み取り専用チェック
        if self.flags.has(ZeroCopyFlags::READ_ONLY) {
            return Err(TransportError::InvalidData("読み取り専用バッファに書き込み".to_string()));
        }
        
        // データをコピー
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.addr.as_ptr().add(offset),
                data.len()
            );
        }
        
        // 使用中バイト数を更新
        let mut used = self.used_bytes.lock().unwrap();
        *used = (*used).max(offset + data.len());
        
        Ok(data.len())
    }
    
    /// バッファからデータを読み取り
    pub fn read(&self, offset: usize, buffer: &mut [u8]) -> Result<usize, TransportError> {
        // 境界チェック
        if offset >= self.size {
            return Err(TransportError::InvalidData(format!(
                "バッファ境界外読み取り: オフセット={}, バッファサイズ={}",
                offset, self.size
            )));
        }
        
        // 読み取り可能な最大バイト数を計算
        let bytes_to_read = core::cmp::min(buffer.len(), self.size - offset);
        
        // データをコピー
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.addr.as_ptr().add(offset),
                buffer.as_mut_ptr(),
                bytes_to_read
            );
        }
        
        Ok(bytes_to_read)
    }
    
    /// RDMAメモリ領域として登録
    pub fn register_for_rdma(&mut self, device_id: DeviceId) -> Result<(), TransportError> {
        // 既に登録済みかチェック
        if self.flags.has(ZeroCopyFlags::RDMA_REGISTERED) {
            return Ok(());
        }
        
        // RDMAデバイスを取得
        let device = get_rdma_device(device_id)?;
        
        // メモリ領域を登録
        let region = device.register_memory_at(self.addr.as_ptr(), self.size)?;
        
        // 登録情報を保存
        self.rdma_region = Some(Arc::new(region));
        self.device_id = Some(device_id);
        self.flags = self.flags.with(ZeroCopyFlags::RDMA_REGISTERED);
        
        Ok(())
    }
    
    /// ビューを作成
    pub fn create_view(&self, offset: usize, length: usize, writable: bool) -> Result<ZeroCopyBufferView, TransportError> {
        // 境界チェック
        if offset + length > self.size {
            return Err(TransportError::InvalidData(format!(
                "無効なビュー範囲: オフセット={}, 長さ={}, バッファサイズ={}",
                offset, length, self.size
            )));
        }
        
        // 書き込み権限チェック
        if writable && self.flags.has(ZeroCopyFlags::READ_ONLY) {
            return Err(TransportError::InvalidData("読み取り専用バッファに書き込みビュー".to_string()));
        }
        
        // 参照カウントを増加
        let mut refs = self.refs.lock().unwrap();
        *refs += 1;
        
        // ビューを作成
        Ok(ZeroCopyBufferView {
            buffer: Arc::new(self.clone()),
            offset,
            length,
            writable,
        })
    }
}

// 実際の実装はシステムのメモリ管理APIに依存
fn allocate_contiguous_memory(size: usize, flags: MappingFlags) -> Result<(NonNull<u8>, usize), &'static str> {
    // 物理的に連続なメモリ領域を確保
    let aligned_size = (size + 4095) & !4095; // 4KBアライメント
    
    // DMA可能な物理メモリの確保
    let physical_addr = crate::memory::allocate_dma_memory(aligned_size)?;
    
    // 仮想アドレス空間にマッピング
    let virtual_addr = crate::memory::map_physical_to_virtual(
        physical_addr,
        aligned_size,
        flags.to_page_flags()
    )?;
    
    // キャッシュ一貫性の設定
    if flags.contains(MappingFlags::CACHE_COHERENT) {
        crate::arch::set_cache_policy(virtual_addr, aligned_size, CachePolicy::Uncached);
    } else if flags.contains(MappingFlags::WRITE_COMBINING) {
        crate::arch::set_cache_policy(virtual_addr, aligned_size, CachePolicy::WriteCombining);
    }
    
    let ptr = NonNull::new(virtual_addr as *mut u8)
        .ok_or("仮想アドレス変換失敗")?;
    
    log::debug!("連続メモリ確保成功: 仮想=0x{:x}, 物理=0x{:x}, サイズ=0x{:x}", 
               virtual_addr, physical_addr, aligned_size);
    
    Ok((ptr, aligned_size))
}

// 実際の実装はRDMAデバイス管理に依存
fn get_rdma_device(device_id: DeviceId) -> Result<Arc<dyn RdmaDevice>, TransportError> {
    // デバイスマネージャからRDMAデバイスを取得
    let device_manager = crate::drivers::get_device_manager();
    
    match device_manager.get_rdma_device(device_id) {
        Some(device) => {
            // デバイスが利用可能かチェック
            if device.is_available() {
                log::debug!("RDMAデバイス取得成功: ID={}", device_id);
                Ok(device)
            } else {
                log::warn!("RDMAデバイスが利用不可: ID={}", device_id);
                Err(TransportError::DeviceNotAvailable)
            }
        }
        None => {
            log::error!("RDMAデバイスが見つかりません: ID={}", device_id);
            Err(TransportError::DeviceNotFound)
        }
    }
}

impl Clone for ZeroCopyBuffer {
    fn clone(&self) -> Self {
        let mut refs = self.refs.lock().unwrap();
        *refs += 1;
        
        Self {
            addr: self.addr,
            size: self.size,
            phys_addr: self.phys_addr,
            rdma_region: self.rdma_region.clone(),
            device_id: self.device_id,
            flags: self.flags,
            refs: Mutex::new(*refs),
            used_bytes: Mutex::new(*self.used_bytes.lock().unwrap()),
        }
    }
}

impl Drop for ZeroCopyBuffer {
    fn drop(&mut self) {
        let mut refs = self.refs.lock().unwrap();
        *refs -= 1;
        
        if *refs == 0 {
            // リソースを解放
            if self.flags.has(ZeroCopyFlags::RDMA_REGISTERED) {
                // RDMA登録解除
                if let Some(device_id) = self.device_id {
                    if let Some(rdma_region) = &self.rdma_region {
                        // デバイスを取得してメモリ登録解除
                        if let Ok(device) = get_rdma_device(device_id) {
                            let _ = device.deregister_memory(&**rdma_region);
                        }
                    }
                }
            }
            
            // メモリを解放
            unsafe {
                alloc::alloc::dealloc(
                    self.addr.as_ptr(),
                    alloc::alloc::Layout::from_size_align(self.size, 4096).unwrap()
                );
            }
        }
    }
}

impl Debug for ZeroCopyBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ZeroCopyBuffer")
            .field("addr", &self.addr)
            .field("size", &self.size)
            .field("phys_addr", &format_args!("0x{:x}", self.phys_addr))
            .field("flags", &self.flags)
            .finish()
    }
}

impl ZeroCopyBufferView {
    /// ポインタを取得
    pub fn as_ptr(&self) -> *mut u8 {
        unsafe { self.buffer.addr.as_ptr().add(self.offset) }
    }
    
    /// 長さを取得
    pub fn len(&self) -> usize {
        self.length
    }
    
    /// 空かどうかを確認
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    
    /// ビューのデータをコピー
    pub fn copy_to(&self, dst: &mut [u8]) -> Result<usize, TransportError> {
        let bytes_to_copy = core::cmp::min(dst.len(), self.length);
        
        self.buffer.read(self.offset, &mut dst[..bytes_to_copy])
    }
    
    /// ビューにデータをコピー
    pub fn copy_from(&self, src: &[u8]) -> Result<usize, TransportError> {
        if !self.writable {
            return Err(TransportError::InvalidData("読み取り専用ビューに書き込み".to_string()));
        }
        
        let bytes_to_copy = core::cmp::min(src.len(), self.length);
        
        self.buffer.write(self.offset, &src[..bytes_to_copy])
    }
    
    /// ビューのサブビューを作成
    pub fn subview(&self, offset: usize, length: usize) -> Result<Self, TransportError> {
        if offset + length > self.length {
            return Err(TransportError::InvalidData(format!(
                "無効なサブビュー範囲: オフセット={}, 長さ={}, ビューサイズ={}",
                offset, length, self.length
            )));
        }
        
        Ok(Self {
            buffer: self.buffer.clone(),
            offset: self.offset + offset,
            length,
            writable: self.writable,
        })
    }
    
    /// RDMA転送用の情報を取得
    pub fn get_rdma_info(&self) -> Option<(usize, u32)> {
        self.buffer.rdma_region.as_ref().map(|region| {
            let local_addr = self.buffer.phys_addr + self.offset;
            let rkey = region.local_key();
            (local_addr, rkey)
        })
    }
}

impl Debug for ZeroCopyBufferView {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ZeroCopyBufferView")
            .field("offset", &self.offset)
            .field("length", &self.length)
            .field("writable", &self.writable)
            .finish()
    }
}

impl ZeroCopyManager {
    /// 新しいマネージャを作成
    pub fn new() -> Self {
        Self {
            pools: RwLock::new(Vec::new()),
            active_transfers: Mutex::new(Vec::new()),
            device_mappings: Mutex::new(Vec::new()),
        }
    }
    
    /// プールを作成
    pub fn create_pool(&self, block_size: usize, max_buffers: usize, flags: ZeroCopyFlags) -> Result<(), TransportError> {
        let mut pools = self.pools.write().unwrap();
        
        // 同じサイズのプールが既にあるか確認
        for pool in &*pools {
            if pool.block_size == block_size && pool.flags == flags {
                return Ok(());
            }
        }
        
        // 新しいプールを作成
        let pool = ZeroCopyPool {
            block_size,
            flags,
            available: Mutex::new(Vec::with_capacity(max_buffers)),
            used_count: Mutex::new(0),
            max_buffers,
        };
        
        pools.push(pool);
        Ok(())
    }
    
    /// バッファを割り当て
    pub fn allocate(&self, size: usize, flags: ZeroCopyFlags) -> Result<Arc<ZeroCopyBuffer>, TransportError> {
        let pools = self.pools.read().unwrap();
        
        // 適切なプールを探す
        for pool in &*pools {
            if size <= pool.block_size && flags == pool.flags {
                // プールからバッファを取得
                let mut available = pool.available.lock().unwrap();
                if let Some(buffer) = available.pop() {
                    // 使用中カウントを更新
                    let mut used_count = pool.used_count.lock().unwrap();
                    *used_count += 1;
                    
                    return Ok(buffer);
                }
                
                // 使用中バッファ数が最大数未満なら新しく作成
                let used_count = pool.used_count.lock().unwrap();
                if *used_count < pool.max_buffers {
                    drop(used_count); // ロックを解放
                    
                    // 新しいバッファを作成
                    let buffer = Arc::new(ZeroCopyBuffer::new(pool.block_size, flags)?);
                    
                    // 使用中カウントを更新
                    let mut used_count = pool.used_count.lock().unwrap();
                    *used_count += 1;
                    
                    return Ok(buffer);
                }
                
                // このプールは満杯
                break;
            }
        }
        
        // 適切なプールが見つからないか満杯の場合は直接割り当て
        Ok(Arc::new(ZeroCopyBuffer::new(size, flags)?))
    }
    
    /// バッファを解放
    pub fn release(&self, buffer: Arc<ZeroCopyBuffer>) -> Result<(), TransportError> {
        let pools = self.pools.read().unwrap();
        
        // 適切なプールを探す
        for pool in &*pools {
            if buffer.size() == pool.block_size && buffer.flags == pool.flags {
                // バッファをリセット（使用中バイト数をクリア）
                let mut used_bytes = buffer.used_bytes.lock().unwrap();
                *used_bytes = 0;
                
                // プールに戻す
                let mut available = pool.available.lock().unwrap();
                available.push(buffer);
                
                // 使用中カウントを更新
                let mut used_count = pool.used_count.lock().unwrap();
                *used_count = used_count.saturating_sub(1);
                
                return Ok(());
            }
        }
        
        // 適切なプールが見つからない場合は何もしない（Dropで処理）
        Ok(())
    }
    
    /// 転送を開始
    pub fn start_transfer(&self, desc: ZeroCopyTransferDescriptor) -> Result<u64, TransportError> {
        // 転送IDを生成
        let transfer_id = generate_transfer_id();
        
        // デバイスを決定
        let device_id = determine_device_for_transfer(&desc)?;
        
        // 転送を記録
        let transfer = ZeroCopyTransfer {
            id: transfer_id,
            src_buffer: desc.src.buffer.clone(),
            dst_buffer: desc.dst.as_ref().map(|view| view.buffer.clone()),
            size: desc.src.length,
            completion: desc.completion,
            user_data: desc.user_data,
            device_id,
            start_time: crate::core::time::current_timestamp(),
        };
        
        let mut active_transfers = self.active_transfers.lock().unwrap();
        active_transfers.push(transfer);
        
        // 実際のデバイス転送を開始
        self.initiate_device_transfer(device_id, &desc)?;
        
        Ok(transfer_id)
    }
    
    /// デバイス転送を開始
    fn initiate_device_transfer(&self, device_id: DeviceId, desc: &ZeroCopyTransferDescriptor) -> Result<(), TransportError> {
        // デバイスタイプに応じた転送を実行
        match device_id.device_type {
            DeviceType::Rdma => {
                self.initiate_rdma_transfer(device_id, desc)
            },
            DeviceType::Dma => {
                self.initiate_dma_transfer(device_id, desc)
            },
            DeviceType::Network => {
                self.initiate_network_transfer(device_id, desc)
            },
            DeviceType::Storage => {
                self.initiate_storage_transfer(device_id, desc)
            },
        }
    }
    
    /// RDMA転送を開始
    fn initiate_rdma_transfer(&self, device_id: DeviceId, desc: &ZeroCopyTransferDescriptor) -> Result<(), TransportError> {
        log::debug!("RDMA転送開始: デバイス={}, サイズ={}", device_id.id, desc.src.length);
        
        // RDMAデバイスハンドルを取得
        let rdma_device = self.get_rdma_device(device_id.id)?;
        
        // RDMA Work Request (WR) を作成
        let work_request = RdmaWorkRequest {
            operation: if desc.dst.is_some() { RdmaOperation::Write } else { RdmaOperation::Read },
            local_addr: desc.src.buffer.as_ptr() as u64,
            local_length: desc.src.length as u32,
            local_key: desc.src.buffer.memory_key(),
            remote_addr: desc.dst.as_ref().map(|dst| dst.buffer.as_ptr() as u64).unwrap_or(0),
            remote_key: desc.dst.as_ref().map(|dst| dst.buffer.memory_key()).unwrap_or(0),
            immediate_data: 0,
            flags: RdmaFlags::SIGNALED | RdmaFlags::FENCE,
        };
        
        // Work Requestをキューに投入
        rdma_device.post_send(&work_request)?;
        
        // Completion Queueをポーリング（非同期の場合）
        if desc.completion == CompletionMode::Async {
            self.schedule_completion_polling(device_id, desc.user_data)?;
        }
        
        Ok(())
    }
    
    /// DMA転送を開始
    fn initiate_dma_transfer(&self, device_id: DeviceId, desc: &ZeroCopyTransferDescriptor) -> Result<(), TransportError> {
        log::debug!("DMA転送開始: デバイス={}, サイズ={}", device_id.id, desc.src.length);
        
        // DMAコントローラを取得
        let dma_controller = self.get_dma_controller(device_id.id)?;
        
        // DMA記述子を作成
        let dma_descriptor = DmaDescriptor {
            src_addr: desc.src.buffer.physical_addr(),
            dst_addr: desc.dst.as_ref().map(|dst| dst.buffer.physical_addr()).unwrap_or(0),
            length: desc.src.length,
            flags: DmaFlags::INTERRUPT_ON_COMPLETION,
            next_descriptor: core::ptr::null(),
        };
        
        // DMA転送を開始
        dma_controller.start_transfer(&dma_descriptor)?;
        
        Ok(())
    }
    
    /// ネットワーク転送を開始
    fn initiate_network_transfer(&self, device_id: DeviceId, desc: &ZeroCopyTransferDescriptor) -> Result<(), TransportError> {
        log::debug!("ネットワーク転送開始: デバイス={}, サイズ={}", device_id.id, desc.src.length);
        
        // ネットワークデバイスを取得
        let network_device = self.get_network_device(device_id.id)?;
        
        // パケット記述子を作成
        let packet_descriptor = NetworkPacketDescriptor {
            buffer_addr: desc.src.buffer.physical_addr(),
            length: desc.src.length,
            flags: NetworkFlags::CHECKSUM_OFFLOAD | NetworkFlags::TSO_ENABLED,
            vlan_tag: 0,
            protocol: NetworkProtocol::Tcp,
        };
        
        // 送信キューに追加
        network_device.enqueue_packet(&packet_descriptor)?;
        
        // 送信開始
        network_device.kick_tx_queue()?;
        
        Ok(())
    }
    
    /// ストレージ転送を開始
    fn initiate_storage_transfer(&self, device_id: DeviceId, desc: &ZeroCopyTransferDescriptor) -> Result<(), TransportError> {
        log::debug!("ストレージ転送開始: デバイス={}, サイズ={}", device_id.id, desc.src.length);
        
        // ストレージデバイスを取得
        let storage_device = self.get_storage_device(device_id.id)?;
        
        // I/O記述子を作成
        let io_descriptor = StorageIoDescriptor {
            operation: if desc.dst.is_some() { StorageOperation::Write } else { StorageOperation::Read },
            buffer_addr: desc.src.buffer.physical_addr(),
            length: desc.src.length,
            lba: desc.user_data as u64, // LBAとしてuser_dataを使用
            flags: StorageFlags::DIRECT_IO | StorageFlags::ASYNC,
        };
        
        // I/O要求を送信
        storage_device.submit_io(&io_descriptor)?;
        
        Ok(())
    }
    
    /// 完了をポーリング
    pub fn poll_completions(&self) -> Result<Vec<(u64, Result<usize, TransportError>)>, TransportError> {
        let mut completed = Vec::new();
        let mut active_transfers = self.active_transfers.lock().unwrap();
        
        // 各デバイスをポーリング
        // 実際の実装ではデバイス固有のポーリングコードを呼び出す
        
        // デバッグ用のダミー実装：ランダムに完了を生成
        let now = crate::core::time::current_timestamp();
        let mut i = 0;
        while i < active_transfers.len() {
            let transfer = &active_transfers[i];
            
            // 5ms以上経過したら完了とみなす
            if now - transfer.start_time > 5 {
                let result = Ok(transfer.size);
                
                // 完了コールバックを呼び出し
                if let Some(callback) = transfer.completion {
                    callback(result.clone(), transfer.user_data);
                }
                
                // 完了リストに追加
                completed.push((transfer.id, result));
                
                // アクティブリストから削除
                active_transfers.swap_remove(i);
            } else {
                i += 1;
            }
        }
        
        Ok(completed)
    }
}

// 転送ID生成（アトミックカウンタを使用したユニークID生成）
fn generate_transfer_id() -> u64 {
    static TRANSFER_ID_COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
    
    TRANSFER_ID_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

fn determine_device_for_transfer(desc: &ZeroCopyTransferDescriptor) -> Result<DeviceId, TransportError> {
    // 転送タイプに基づいてデバイスを選択
    match desc.transfer_type {
        ZeroCopyTransferType::RDMA => {
            // 利用可能なRDMAデバイスを検索
            let device_manager = crate::drivers::get_device_manager();
            
            for device_id in device_manager.enumerate_rdma_devices() {
                if let Ok(device) = get_rdma_device(device_id) {
                    if device.is_available() && device.can_handle_transfer(desc) {
                        return Ok(device_id);
                    }
                }
            }
            
            Err(TransportError::NoSuitableDevice)
        }
        
        ZeroCopyTransferType::DMA => {
            // 利用可能なDMAエンジンを検索
            let device_manager = crate::drivers::get_device_manager();
            
            for device_id in device_manager.enumerate_dma_devices() {
                if let Ok(engine) = crate::drivers::get_dma_engine(device_id) {
                    if engine.is_available() && engine.can_handle_transfer_size(desc.total_size()) {
                        return Ok(device_id);
                    }
                }
            }
            
            Err(TransportError::NoSuitableDevice)
        }
        
        ZeroCopyTransferType::NVMeOver => {
            // NVMeデバイスを検索
            let device_manager = crate::drivers::get_device_manager();
            
            for device_id in device_manager.enumerate_nvme_devices() {
                if let Ok(device) = crate::drivers::get_nvme_device(device_id) {
                    if device.is_available() {
                        return Ok(device_id);
                    }
                }
            }
            
            Err(TransportError::NoSuitableDevice)
        }
        
        ZeroCopyTransferType::UserDefined => {
            // CPUコピーフォールバック
            log::warn!("ユーザー定義転送タイプ、CPUコピーフォールバック使用");
            Ok(DeviceId::CPU_FALLBACK)
        }
    }
}

// 追加のデータ構造と列挙型
#[derive(Debug, Clone, Copy)]
pub enum CachePolicy {
    Cached,
    Uncached,
    WriteCombining,
    WriteThrough,
}

#[derive(Debug)]
pub struct RdmaWorkRequest {
    pub wr_id: u64,
    pub opcode: RdmaOpcode,
    pub sg_list: Vec<ScatterGatherEntry>,
    pub remote_addr: u64,
    pub rkey: u32,
    pub flags: RdmaFlags,
}

#[derive(Debug)]
pub enum RdmaOpcode {
    Send,
    Recv,
    RdmaWrite,
    RdmaRead,
    AtomicCompareAndSwap,
    AtomicFetchAndAdd,
}

#[derive(Debug)]
pub struct DmaDescriptor {
    pub transfer_id: u64,
    pub source_address: u64,
    pub destination_address: u64,
    pub transfer_size: usize,
    pub flags: DmaFlags,
}

#[derive(Debug)]
pub struct NvmeCommand {
    pub opcode: NvmeOpcode,
    pub command_id: u16,
    pub prp_list: Vec<u64>,
    pub lba_start: u64,
    pub lba_count: u32,
    pub flags: NvmeFlags,
}

#[derive(Debug)]
pub enum NvmeOpcode {
    Read,
    Write,
    Flush,
    WriteUncorrectable,
    Compare,
    WriteZeroes,
}

bitflags::bitflags! {
    pub struct RdmaFlags: u32 {
        const SIGNALED = 1 << 0;
        const FENCE = 1 << 1;
        const SOLICITED = 1 << 2;
        const INLINE = 1 << 3;
    }
}

bitflags::bitflags! {
    pub struct DmaFlags: u32 {
        const INTERRUPT_ON_COMPLETION = 1 << 0;
        const MEMORY_TO_MEMORY = 1 << 1;
        const DEVICE_TO_MEMORY = 1 << 2;
        const MEMORY_TO_DEVICE = 1 << 3;
    }
}

bitflags::bitflags! {
    pub struct NvmeFlags: u16 {
        const FORCE_UNIT_ACCESS = 1 << 0;
        const LIMITED_RETRY = 1 << 1;
        const PROTECTION_INFO = 1 << 2;
    }
}

impl MappingFlags {
    fn to_page_flags(&self) -> crate::memory::PageFlags {
        let mut flags = crate::memory::PageFlags::empty();
        
        if self.contains(MappingFlags::READ()) {
            flags |= crate::memory::PageFlags::READABLE;
        }
        if self.contains(MappingFlags::write()) {
            flags |= crate::memory::PageFlags::WRITABLE;
        }
        if self.contains(MappingFlags::execute()) {
            flags |= crate::memory::PageFlags::EXECUTABLE;
        }
        if self.contains(MappingFlags::user()) {
            flags |= crate::memory::PageFlags::USER_ACCESSIBLE;
        }
        
        flags
    }
} 