// AetherOS CXL (Compute Express Link) メモリ管理モジュール
//
// このモジュールは、CXL規格に基づくメモリデバイスの検出、初期化、管理を担当します。
// CXLは、CPU-メモリ間の高速な相互接続を提供し、ホストからのメモリ拡張や永続メモリの
// 効率的な活用を可能にします。

use crate::arch::MemoryInfo;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::RwLock;
use crate::drivers::pci;

/// CXLデバイスタイプ
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CxlDeviceType {
    /// CXL.mem - メモリ拡張
    Memory,
    /// CXL.cache - キャッシュ拡張
    Cache,
    /// CXL.io - I/Oアクセラレーション
    IO,
    /// 組み合わせデバイス
    Hybrid,
}

/// CXLデバイス情報
pub struct CxlDevice {
    /// デバイスID
    pub id: usize,
    /// デバイスタイプ
    pub device_type: CxlDeviceType,
    /// ベースアドレス
    pub base_address: usize,
    /// メモリサイズ（バイト）
    pub size: usize,
    /// 帯域幅（GB/s）
    pub bandwidth_gbps: f32,
    /// レイテンシ（ナノ秒）
    pub latency_ns: usize,
    /// デバイスが使用可能か
    pub available: AtomicBool,
    /// 使用中のメモリ量
    pub used_memory: AtomicUsize,
    /// NUMAノードID（関連付けられている場合）
    pub numa_node: Option<usize>,
}

/// CXL管理システム
struct CxlManager {
    /// 検出されたCXLデバイス
    devices: Vec<CxlDevice>,
    /// 総CXLメモリ容量
    total_memory: usize,
    /// 利用可能なCXLメモリ容量
    available_memory: AtomicUsize,
    /// CXL.memをシステムアドレス空間にマップするベースアドレス
    memory_base: usize,
    /// CXL対応か
    supported: bool,
    /// CXLプロトコルバージョン (例: 0x20 = 2.0)
    version: u8,
}

/// メモリプール割り当てポリシー
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CxlAllocationPolicy {
    /// 通常のDRAMを優先し、必要な場合のみCXLを使用
    DramFirst,
    /// CXLメモリを優先的に使用
    CxlFirst,
    /// DRAM/CXL間で均等に分散
    Balanced,
    /// データアクセスパターンに基づいて最適な場所に配置
    AdaptiveBalanced,
}

/// グローバルCXLマネージャ
static mut CXL_MANAGER: Option<CxlManager> = None;

/// 現在の割り当てポリシー
static CXL_POLICY: RwLock<CxlAllocationPolicy> = RwLock::new(CxlAllocationPolicy::DramFirst);

/// CXLサブシステムの初期化
pub fn init(mem_info: &MemoryInfo) {
    if !mem_info.cxl_supported {
        log::info!("CXLサポートが検出されませんでした、CXLモジュールはパッシブモードで初期化");
        let manager = CxlManager {
            devices: Vec::new(),
            total_memory: 0,
            available_memory: AtomicUsize::new(0),
            memory_base: 0,
            supported: false,
            version: 0,
        };
        
        unsafe {
            CXL_MANAGER = Some(manager);
        }
        return;
    }
    
    log::info!("CXLサポートを初期化中: プロトコルバージョン {}.{}", 
               mem_info.cxl_version >> 4, mem_info.cxl_version & 0xF);
    
    // デバイス検出
    let mut devices = Vec::new();
    let mut total_memory = 0;
    
    // PCIサブシステム経由でCXLデバイスを検出
    if let Some(cxl_devices) = detect_cxl_devices() {
        for (i, dev_info) in cxl_devices.iter().enumerate() {
            let device = CxlDevice {
                id: i,
                device_type: dev_info.device_type,
                base_address: dev_info.base_address,
                size: dev_info.size,
                bandwidth_gbps: dev_info.bandwidth_gbps,
                latency_ns: dev_info.latency_ns,
                available: AtomicBool::new(true),
                used_memory: AtomicUsize::new(0),
                numa_node: dev_info.numa_node,
            };
            
            total_memory += device.size;
            devices.push(device);
            
            log::info!("CXLデバイス#{} 検出: タイプ={:?}, サイズ={}GB, 帯域={}GB/s, レイテンシ={}ns",
                      i, device.device_type, device.size / 1024 / 1024 / 1024,
                      device.bandwidth_gbps, device.latency_ns);
        }
    }
    
    if devices.is_empty() {
        log::warn!("CXLデバイスは検出されましたが、使用可能なデバイスが見つかりません");
    }
    
    // マネージャの初期化
    let manager = CxlManager {
        devices,
        total_memory,
        available_memory: AtomicUsize::new(total_memory),
        memory_base: mem_info.cxl_memory_base,
        supported: true,
        version: mem_info.cxl_version,
    };
    
    unsafe {
        CXL_MANAGER = Some(manager);
    }
    
    log::info!("CXL初期化完了: {}台のデバイス, 総容量{}GB",
               manager.devices.len(), total_memory / 1024 / 1024 / 1024);
}

/// CXLデバイス検出（PCIサブシステム経由）
fn detect_cxl_devices() -> Option<Vec<CxlDeviceInfo>> {
    // ここでは仮の実装としてダミーデータを返す
    // 実際の実装ではPCIサブシステムからデバイスを列挙する
    
    #[allow(dead_code)]
    struct CxlDeviceInfo {
        device_type: CxlDeviceType,
        base_address: usize,
        size: usize,
        bandwidth_gbps: f32,
        latency_ns: usize,
        numa_node: Option<usize>,
    }
    
    // 実際の環境ではこの部分をPCIスキャンに置き換える
    Some(Vec::new())
}

/// CXLデバイスが利用可能かを確認
pub fn is_supported() -> bool {
    unsafe {
        CXL_MANAGER.as_ref().map_or(false, |m| m.supported)
    }
}

/// 利用可能なCXLメモリ容量を取得
pub fn get_available_memory() -> usize {
    unsafe {
        CXL_MANAGER.as_ref().map_or(0, |m| m.available_memory.load(Ordering::Relaxed))
    }
}

/// 総CXLメモリ容量を取得
pub fn get_total_memory() -> usize {
    unsafe {
        CXL_MANAGER.as_ref().map_or(0, |m| m.total_memory)
    }
}

/// CXLデバイス数を取得
pub fn get_device_count() -> usize {
    unsafe {
        CXL_MANAGER.as_ref().map_or(0, |m| m.devices.len())
    }
}

/// 割り当てポリシーを設定
pub fn set_allocation_policy(policy: CxlAllocationPolicy) {
    *CXL_POLICY.write() = policy;
    log::debug!("CXL割り当てポリシーを設定: {:?}", policy);
}

/// 現在の割り当てポリシーを取得
pub fn get_allocation_policy() -> CxlAllocationPolicy {
    *CXL_POLICY.read()
}

/// 次の割り当てにCXLメモリを使うべきか判断
pub fn should_use_cxl_for_allocation(size: usize) -> bool {
    let manager = unsafe {
        if let Some(manager) = CXL_MANAGER.as_ref() {
            if !manager.supported || manager.devices.is_empty() {
                return false;
            }
            manager
        } else {
            return false;
        }
    };
    
    let available_cxl = manager.available_memory.load(Ordering::Relaxed);
    if available_cxl < size {
        return false; // CXLに十分な空きがない
    }
    
    match *CXL_POLICY.read() {
        CxlAllocationPolicy::CxlFirst => true,
        
        CxlAllocationPolicy::DramFirst => {
            // DRAMの空き容量が少ない場合のみCXLを使用
            let available_dram = crate::core::memory::get_available_physical();
            let dram_threshold = crate::core::memory::get_total_physical() / 10; // 10%の閾値
            
            available_dram < dram_threshold || available_dram < size
        },
        
        CxlAllocationPolicy::Balanced => {
            // DRAMとCXLの使用率を均等にする
            let available_dram = crate::core::memory::get_available_physical();
            let total_dram = crate::core::memory::get_total_physical();
            let dram_usage_percent = 100 - (available_dram * 100 / total_dram);
            
            let cxl_usage_percent = 100 - (available_cxl * 100 / manager.total_memory);
            
            // CXLの使用率がDRAMより低い場合はCXLを使う
            cxl_usage_percent < dram_usage_percent
        },
        
        CxlAllocationPolicy::AdaptiveBalanced => {
            // アクセスパターンに基づいた高度な判断
            // ここでは簡略化のため、Balancedと同じロジックを使用
            let available_dram = crate::core::memory::get_available_physical();
            let total_dram = crate::core::memory::get_total_physical();
            let dram_usage_percent = 100 - (available_dram * 100 / total_dram);
            
            let cxl_usage_percent = 100 - (available_cxl * 100 / manager.total_memory);
            
            cxl_usage_percent < dram_usage_percent
        },
    }
}

/// CXLメモリから指定サイズを割り当て
pub fn allocate(size: usize) -> Option<*mut u8> {
    let manager = unsafe { CXL_MANAGER.as_ref()? };
    if !manager.supported || manager.devices.is_empty() {
        return None;
    }
    
    let available = manager.available_memory.load(Ordering::Relaxed);
    if available < size {
        return None; // 十分な空きがない
    }
    
    // 最適なデバイスを選択（この例では単純に最も空きのあるデバイス）
    let best_device_idx = find_best_device_for_allocation(size)?;
    let device = &manager.devices[best_device_idx];
    
    // デバイスのアドレス空間からメモリ割り当て
    // 実際の実装ではページ割り当てとマッピングが必要
    let device_offset = allocate_from_device(device, size)?;
    
    // 物理アドレスへの変換
    let physical_addr = device.base_address + device_offset;
    
    // カーネル仮想アドレス空間へマッピング
    let virtual_addr = map_cxl_memory(physical_addr, size)?;
    
    // 統計情報更新
    manager.available_memory.fetch_sub(size, Ordering::Relaxed);
    device.used_memory.fetch_add(size, Ordering::Relaxed);
    
    Some(virtual_addr as *mut u8)
}

/// 指定サイズの割り当てに最適なデバイスを見つける
fn find_best_device_for_allocation(size: usize) -> Option<usize> {
    let manager = unsafe { CXL_MANAGER.as_ref()? };
    
    let mut best_device = None;
    let mut most_available = 0;
    
    for (idx, device) in manager.devices.iter().enumerate() {
        if !device.available.load(Ordering::Relaxed) {
            continue; // 使用不可のデバイスはスキップ
        }
        
        let used = device.used_memory.load(Ordering::Relaxed);
        let available = device.size.saturating_sub(used);
        
        if available >= size && available > most_available {
            most_available = available;
            best_device = Some(idx);
        }
    }
    
    best_device
}

/// 特定のCXLデバイスからメモリを割り当て
fn allocate_from_device(device: &CxlDevice, size: usize) -> Option<usize> {
    // 実際の実装ではデバイス固有のメモリマップとフリーリスト管理が必要
    // ここでは簡略化のため、常に成功するダミー実装を提供
    
    // 使用中メモリが既にデバイスの容量を超えていないかチェック
    let used = device.used_memory.load(Ordering::Relaxed);
    if used + size > device.size {
        return None;
    }
    
    // このダミー実装では単純にオフセットを返す
    // 実際の実装では空き領域の検索と確保が必要
    Some(used)
}

/// CXLメモリ領域をカーネル仮想アドレス空間にマッピング
fn map_cxl_memory(physical_addr: usize, size: usize) -> Option<usize> {
    // 実際の実装ではページテーブル操作が必要
    // VMM経由でのマッピング要求
    crate::core::memory::mm::map_device_memory(physical_addr, size, true)
}

/// メモリ領域を解放
pub fn free(ptr: *mut u8, size: usize) -> Result<(), &'static str> {
    let manager = unsafe { CXL_MANAGER.as_ref().ok_or("CXLマネージャが初期化されていません")? };
    
    // 仮想アドレスから物理アドレスを取得
    let physical_addr = crate::core::memory::mm::virtual_to_physical(ptr as usize)
        .ok_or("無効な仮想アドレス")?;
    
    // 物理アドレスがどのCXLデバイスに属するか特定
    let mut device_idx = None;
    for (idx, device) in manager.devices.iter().enumerate() {
        if physical_addr >= device.base_address && 
           physical_addr < device.base_address + device.size {
            device_idx = Some(idx);
            break;
        }
    }
    
    let device_idx = device_idx.ok_or("アドレスがCXLデバイスに属していません")?;
    let device = &manager.devices[device_idx];
    
    // メモリ領域の開放処理（実際の実装ではデバイス固有の処理が必要）
    free_from_device(device, physical_addr - device.base_address, size)?;
    
    // マッピング解除
    crate::core::memory::mm::unmap_memory(ptr as usize, size)?;
    
    // 統計情報更新
    manager.available_memory.fetch_add(size, Ordering::Relaxed);
    device.used_memory.fetch_sub(size, Ordering::Relaxed);
    
    Ok(())
}

/// 特定のCXLデバイスからメモリを解放
fn free_from_device(device: &CxlDevice, offset: usize, size: usize) -> Result<(), &'static str> {
    // 実際の実装ではデバイス固有のメモリマップとフリーリスト管理が必要
    // ここでは簡略化のため、常に成功するダミー実装を提供
    Ok(())
}

/// CXLデバイス情報を表示
pub fn print_info() {
    let manager = unsafe {
        if let Some(manager) = CXL_MANAGER.as_ref() {
            manager
        } else {
            log::info!("CXLマネージャが初期化されていません");
            return;
        }
    };
    
    if !manager.supported {
        log::info!("このシステムはCXLをサポートしていません");
        return;
    }
    
    log::info!("--- CXL情報 ---");
    log::info!("プロトコルバージョン: {}.{}", manager.version >> 4, manager.version & 0xF);
    log::info!("デバイス数: {}", manager.devices.len());
    
    let total_gb = manager.total_memory / 1024 / 1024 / 1024;
    let available_gb = manager.available_memory.load(Ordering::Relaxed) / 1024 / 1024 / 1024;
    log::info!("総メモリ: {}GB, 利用可能: {}GB", total_gb, available_gb);
    
    for (i, device) in manager.devices.iter().enumerate() {
        let size_gb = device.size / 1024 / 1024 / 1024;
        let used_gb = device.used_memory.load(Ordering::Relaxed) / 1024 / 1024 / 1024;
        let status = if device.available.load(Ordering::Relaxed) { "有効" } else { "無効" };
        
        log::info!("デバイス#{}: タイプ={:?}, 状態={}, メモリ: {}GB/{}GB, 帯域={}GB/s, レイテンシ={}ns, NUMA={}",
                  i, device.device_type, status, used_gb, size_gb, device.bandwidth_gbps, 
                  device.latency_ns, device.numa_node.map_or("なし".to_string(), |n| n.to_string()));
    }
    
    log::info!("現在の割り当てポリシー: {:?}", *CXL_POLICY.read());
    log::info!("-----------------");
}

/// メモリタイプと容量に基づいて最適な割り当て先を推奨
pub fn recommend_allocation_target(size: usize, is_persistent: bool) -> MemoryClass {
    let manager = unsafe { CXL_MANAGER.as_ref() };
    
    // CXLサポートがない場合は常にDRAM
    if manager.is_none() || !manager.unwrap().supported {
        return MemoryClass::StandardDram;
    }
    
    // 永続的なデータの場合はPMEMかCXL.mem
    if is_persistent {
        if crate::core::memory::pmem::is_supported() {
            return MemoryClass::PersistentMemory;
        } else {
            return MemoryClass::CxlMemory;
        }
    }
    
    // 非永続データの場合は割り当てポリシーに従う
    if should_use_cxl_for_allocation(size) {
        MemoryClass::CxlMemory
    } else {
        MemoryClass::StandardDram
    }
}

/// メモリクラス（どの種類のメモリに割り当てるべきか）
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemoryClass {
    /// 高速DRAM（DDR5, HBM）
    HighPerformanceDram,
    /// 標準DRAM
    StandardDram,
    /// 不揮発性メモリ
    PersistentMemory,
    /// CXLメモリ
    CxlMemory,
}

/// メモリアクセスパターンに基づいて最適なデバイスを提案
pub fn suggest_memory_tier(size: usize, access_pattern: MemoryAccessPattern) -> MemoryClass {
    match access_pattern {
        // 頻繁にアクセスされるホットデータ
        MemoryAccessPattern::Random | MemoryAccessPattern::HighFrequency => {
            MemoryClass::HighPerformanceDram
        },
        
        // シーケンシャルアクセスや中程度の頻度のデータ
        MemoryAccessPattern::Sequential | MemoryAccessPattern::MediumFrequency => {
            // サイズによって判断
            if size > 1024 * 1024 * 128 { // 128MB以上
                MemoryClass::CxlMemory
            } else {
                MemoryClass::StandardDram
            }
        },
        
        // 長期保存が必要なコールドデータ
        MemoryAccessPattern::LowFrequency | MemoryAccessPattern::ReadMostly => {
            if crate::core::memory::pmem::is_supported() {
                MemoryClass::PersistentMemory
            } else {
                MemoryClass::CxlMemory
            }
        },
        
        // 特殊なパターン
        MemoryAccessPattern::Custom => {
            recommend_allocation_target(size, false)
        },
    }
}

/// メモリアクセスパターン
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemoryAccessPattern {
    /// ランダムアクセス
    Random,
    /// シーケンシャルアクセス
    Sequential,
    /// 高頻度アクセス
    HighFrequency,
    /// 中頻度アクセス
    MediumFrequency,
    /// 低頻度アクセス
    LowFrequency,
    /// 主に読み取り操作
    ReadMostly,
    /// カスタムパターン（ヒントなし）
    Custom,
} 