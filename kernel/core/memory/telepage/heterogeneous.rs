// AetherOS テレページ異種メモリ（ヘテロジニアスメモリ）管理
// 異なる特性を持つ複数種類のメモリを統合管理

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use crate::sync::{Mutex, SpinLock, RwLock};
use crate::arch::cpu;
use crate::memory::{PAGE_SIZE, HUGE_PAGE_SIZE, GIGANTIC_PAGE_SIZE, TERA_PAGE_SIZE, AllocFlags};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::string::String;
use super::{stats, mloptimizer};

/// 異種メモリタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    /// 標準DRAM
    DRAM,
    /// 高帯域メモリ (HBM)
    HBM,
    /// 不揮発性メモリ (NVRAM)
    NVRAM,
    /// GPUメモリ
    GPU,
    /// FPGAメモリ
    FPGA,
    /// 量子メモリ (将来用)
    Quantum,
}

/// メモリ特性
#[derive(Debug, Clone)]
pub struct MemoryCharacteristics {
    /// 読み取り帯域幅 (GB/秒)
    pub read_bandwidth_gbps: f32,
    
    /// 書き込み帯域幅 (GB/秒)
    pub write_bandwidth_gbps: f32,
    
    /// 読み取りレイテンシ (ナノ秒)
    pub read_latency_ns: u64,
    
    /// 書き込みレイテンシ (ナノ秒)
    pub write_latency_ns: u64,
    
    /// 電力効率 (操作あたりの相対的なエネルギー消費)
    pub power_efficiency: f32,
    
    /// 揮発性か (false = 不揮発)
    pub is_volatile: bool,
    
    /// 最大容量 (バイト)
    pub capacity: usize,
    
    /// 現在の使用量 (バイト)
    pub used: AtomicUsize,
}

/// メモリ領域
#[derive(Debug)]
pub struct MemoryRegion {
    /// メモリタイプ
    pub memory_type: MemoryType,
    
    /// 開始アドレス
    pub start_addr: usize,
    
    /// サイズ (バイト)
    pub size: usize,
    
    /// メモリ特性
    pub characteristics: MemoryCharacteristics,
    
    /// デバイスID (GPUやFPGA用)
    pub device_id: Option<usize>,
    
    /// 使用中かどうか
    pub is_used: AtomicBool,
    
    /// 使用量 (バイト)
    pub used_bytes: AtomicUsize,
    
    /// マッピングカウント
    pub mapping_count: AtomicUsize,
}

/// 異種メモリのマッピング
#[derive(Debug)]
pub struct HeterogeneousMapping {
    /// 仮想アドレス
    pub virtual_addr: usize,
    
    /// 物理アドレス配列 (開始アドレスのリスト)
    pub physical_addrs: Vec<usize>,
    
    /// 各物理アドレスのサイズ
    pub sizes: Vec<usize>,
    
    /// 各物理アドレスのメモリタイプ
    pub memory_types: Vec<MemoryType>,
    
    /// マッピング作成時刻
    pub creation_time: u64,
    
    /// 最終アクセス時刻
    pub last_access: AtomicU64,
    
    /// 参照カウント
    pub ref_count: AtomicUsize,
}

/// 初期化済みフラグ
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// 利用可能なメモリ領域
static mut MEMORY_REGIONS: Option<RwLock<Vec<MemoryRegion>>> = None;

/// 異種メモリマッピング
static mut HETEROGENEOUS_MAPPINGS: Option<RwLock<BTreeMap<usize, HeterogeneousMapping>>> = None;

/// マイグレーション閾値（秒）
const MIGRATION_THRESHOLD_SECS: u64 = 60;

/// モジュール初期化
pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }
    
    // 領域とマッピングの初期化
    unsafe {
        MEMORY_REGIONS = Some(RwLock::new(Vec::new()));
        HETEROGENEOUS_MAPPINGS = Some(RwLock::new(BTreeMap::new()));
    }
    
    // 利用可能な異種メモリを検出
    detect_memory_types()?;
    
    INITIALIZED.store(true, Ordering::SeqCst);
    
    Ok(())
}

/// シャットダウン処理
pub fn shutdown() -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }
    
    // リソースを解放
    unsafe {
        if let Some(mappings_lock) = HETEROGENEOUS_MAPPINGS.as_ref() {
            if let Ok(mut mappings) = mappings_lock.write() {
                mappings.clear();
            }
        }
        
        if let Some(regions_lock) = MEMORY_REGIONS.as_ref() {
            if let Ok(mut regions) = regions_lock.write() {
                regions.clear();
            }
        }
    }
    
    INITIALIZED.store(false, Ordering::SeqCst);
    
    Ok(())
}

/// 利用可能なメモリタイプを検出
fn detect_memory_types() -> Result<(), &'static str> {
    unsafe {
        if let Some(regions_lock) = MEMORY_REGIONS.as_mut() {
            let mut regions = regions_lock.write().map_err(|_| "メモリ領域のロックに失敗しました")?;
            
            // 標準DRAMを追加
            regions.push(MemoryRegion {
                memory_type: MemoryType::DRAM,
                start_addr: 0, // アドレスは後で計算される
                size: get_available_dram_size(),
                characteristics: MemoryCharacteristics {
                    read_bandwidth_gbps: 25.6, // DDR4-3200
                    write_bandwidth_gbps: 25.6,
                    read_latency_ns: 70,
                    write_latency_ns: 70,
                    power_efficiency: 1.0, // 基準値
                    is_volatile: true,
                    capacity: get_available_dram_size(),
                    used: AtomicUsize::new(0),
                },
                device_id: None,
                is_used: AtomicBool::new(false),
                used_bytes: AtomicUsize::new(0),
                mapping_count: AtomicUsize::new(0),
            });
            
            // HBMが利用可能か確認
            if has_hbm() {
                regions.push(MemoryRegion {
                    memory_type: MemoryType::HBM,
                    start_addr: 0,
                    size: get_available_hbm_size(),
                    characteristics: MemoryCharacteristics {
                        read_bandwidth_gbps: 256.0, // HBM2
                        write_bandwidth_gbps: 256.0,
                        read_latency_ns: 100,
                        write_latency_ns: 100,
                        power_efficiency: 0.8, // DRAMより効率的
                        is_volatile: true,
                        capacity: get_available_hbm_size(),
                        used: AtomicUsize::new(0),
                    },
                    device_id: None,
                    is_used: AtomicBool::new(false),
                    used_bytes: AtomicUsize::new(0),
                    mapping_count: AtomicUsize::new(0),
                });
            }
            
            // NVRAMが利用可能か確認
            if has_nvram() {
                regions.push(MemoryRegion {
                    memory_type: MemoryType::NVRAM,
                    start_addr: 0,
                    size: get_available_nvram_size(),
                    characteristics: MemoryCharacteristics {
                        read_bandwidth_gbps: 6.6, // Optane DC
                        write_bandwidth_gbps: 2.3,
                        read_latency_ns: 300,
                        write_latency_ns: 600,
                        power_efficiency: 0.5, // 低消費電力
                        is_volatile: false,
                        capacity: get_available_nvram_size(),
                        used: AtomicUsize::new(0),
                    },
                    device_id: None,
                    is_used: AtomicBool::new(false),
                    used_bytes: AtomicUsize::new(0),
                    mapping_count: AtomicUsize::new(0),
                });
            }
            
            // GPUメモリの検出
            let gpu_devices = detect_gpu_devices()?;
            for (idx, device) in gpu_devices.iter().enumerate() {
                regions.push(MemoryRegion {
                    memory_type: MemoryType::GPU,
                    start_addr: 0,
                    size: device.memory_size,
                    characteristics: MemoryCharacteristics {
                        read_bandwidth_gbps: device.bandwidth_gbps,
                        write_bandwidth_gbps: device.bandwidth_gbps,
                        read_latency_ns: device.latency_ns,
                        write_latency_ns: device.latency_ns,
                        power_efficiency: 1.2, // GPUは通常消費電力が高い
                        is_volatile: true,
                        capacity: device.memory_size,
                        used: AtomicUsize::new(0),
                    },
                    device_id: Some(idx),
                    is_used: AtomicBool::new(false),
                    used_bytes: AtomicUsize::new(0),
                    mapping_count: AtomicUsize::new(0),
                });
            }
            
            // アドレスを割り当て
            assign_memory_addresses(&mut regions);
        }
    }
    
    Ok(())
}

/// メモリ領域にアドレスを割り当て
fn assign_memory_addresses(regions: &mut Vec<MemoryRegion>) {
    let mut current_addr = super::TERAPAGE_BASE + TERA_PAGE_SIZE * 1024; // テラページ領域の後
    
    for region in regions.iter_mut() {
        region.start_addr = current_addr;
        current_addr += region.size + HUGE_PAGE_SIZE; // 安全のためにギャップを追加
    }
}

/// 異種メモリを割り当て
pub fn allocate(size: usize, preferred_type: Option<MemoryType>, flags: AllocFlags) -> Result<usize, &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("異種メモリシステムが初期化されていません");
    }
    
    // アライメントされたサイズを計算
    let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    
    // 最適なメモリタイプを選択
    let memory_type = if let Some(preferred) = preferred_type {
        preferred
    } else {
        select_optimal_memory_type(aligned_size, flags)?
    };
    
    // メモリ特性に基づいて割り当て
    let (virtual_addr, physical_addrs, sizes, types) = match memory_type {
        MemoryType::DRAM => {
            allocate_from_dram(aligned_size)?
        },
        MemoryType::HBM => {
            allocate_from_hbm(aligned_size)?
        },
        MemoryType::NVRAM => {
            allocate_from_nvram(aligned_size)?
        },
        MemoryType::GPU => {
            // 最適なGPUデバイスを選択
            let device_id = select_optimal_gpu_device()?;
            allocate_from_gpu(aligned_size, device_id)?
        },
        _ => {
            return Err("未サポートのメモリタイプです");
        }
    };
    
    // マッピングを作成
    let mapping = HeterogeneousMapping {
        virtual_addr,
        physical_addrs,
        sizes,
        memory_types: types,
        creation_time: get_timestamp(),
        last_access: AtomicU64::new(get_timestamp()),
        ref_count: AtomicUsize::new(1),
    };
    
    // マッピングを登録
    unsafe {
        if let Some(mappings_lock) = HETEROGENEOUS_MAPPINGS.as_ref() {
            if let Ok(mut mappings) = mappings_lock.write() {
                mappings.insert(virtual_addr, mapping);
            } else {
                return Err("マッピングテーブルのロックに失敗しました");
            }
        } else {
            return Err("マッピングテーブルが初期化されていません");
        }
    }
    
    Ok(virtual_addr)
}

/// 異種メモリを解放
pub fn free(addr: usize) -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("異種メモリシステムが初期化されていません");
    }
    
    // マッピングを探索
    let mapping = unsafe {
        if let Some(mappings_lock) = HETEROGENEOUS_MAPPINGS.as_ref() {
            if let Ok(mut mappings) = mappings_lock.write() {
                if let Some(m) = mappings.remove(&addr) {
                    m
                } else {
                    return Err("指定されたアドレスのマッピングが見つかりません");
                }
            } else {
                return Err("マッピングテーブルのロックに失敗しました");
            }
        } else {
            return Err("マッピングテーブルが初期化されていません");
        }
    };
    
    // 各物理メモリを解放
    for (i, phys_addr) in mapping.physical_addrs.iter().enumerate() {
        let mem_type = mapping.memory_types[i];
        let size = mapping.sizes[i];
        
        match mem_type {
            MemoryType::DRAM => {
                free_dram(*phys_addr, size)?;
            },
            MemoryType::HBM => {
                free_hbm(*phys_addr, size)?;
            },
            MemoryType::NVRAM => {
                free_nvram(*phys_addr, size)?;
            },
            MemoryType::GPU => {
                // デバイスIDを取得
                let device_id = get_device_id_from_address(*phys_addr)?;
                free_gpu_memory(*phys_addr, size, device_id)?;
            },
            _ => {
                return Err("未サポートのメモリタイプです");
            }
        }
    }
    
    Ok(())
}

/// 異種メモリ間でデータを移動
pub fn migrate(src_addr: usize, dest_type: MemoryType) -> Result<usize, &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("異種メモリシステムが初期化されていません");
    }
    
    // ソースマッピングを取得
    let src_mapping = get_mapping(src_addr)?;
    
    // 合計サイズを計算
    let total_size: usize = src_mapping.sizes.iter().sum();
    
    // 新しい領域を割り当て
    let dest_addr = allocate(total_size, Some(dest_type), AllocFlags::empty())?;
    
    // データをコピー
    copy_memory(src_addr, dest_addr, total_size)?;
    
    // ソースを解放（ユースケースによって異なる場合がある）
    // free(src_addr)?;
    
    Ok(dest_addr)
}

/// 移行が必要なメモリを自動的に検出して移行
pub fn auto_migrate() -> Result<usize, &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("異種メモリシステムが初期化されていません");
    }
    
    let mut migration_count = 0;
    let now = get_timestamp();
    
    // すべてのマッピングを反復処理
    unsafe {
        if let Some(mappings_lock) = HETEROGENEOUS_MAPPINGS.as_ref() {
            if let Ok(mappings) = mappings_lock.read() {
                for (addr, mapping) in mappings.iter() {
                    // アクセスパターンを分析
                    let last_access = mapping.last_access.load(Ordering::Relaxed);
                    let elapsed_secs = (now - last_access) / 1_000_000_000;
                    
                    // メモリタイプを確認
                    let primary_type = mapping.memory_types[0];
                    
                    // ホットメモリはHBMに移動
                    if elapsed_secs < MIGRATION_THRESHOLD_SECS && primary_type != MemoryType::HBM && has_hbm() {
                        let _ = migrate(*addr, MemoryType::HBM);
                        migration_count += 1;
                    }
                    // コールドメモリはNVRAMに移動
                    else if elapsed_secs > MIGRATION_THRESHOLD_SECS * 10 && primary_type != MemoryType::NVRAM && has_nvram() {
                        let _ = migrate(*addr, MemoryType::NVRAM);
                        migration_count += 1;
                    }
                }
            }
        }
    }
    
    Ok(migration_count)
}

/// 異種メモリアクセスを記録
pub fn record_access(addr: usize) -> Result<(), &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("異種メモリシステムが初期化されていません");
    }
    
    // マッピングを取得
    let mapping = get_mapping(addr)?;
    
    // 最終アクセス時刻を更新
    mapping.last_access.store(get_timestamp(), Ordering::Relaxed);
    
    Ok(())
}

/// 利用可能なメモリタイプを取得
pub fn get_available_memory_types() -> Result<Vec<MemoryType>, &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("異種メモリシステムが初期化されていません");
    }
    
    let mut types = Vec::new();
    
    unsafe {
        if let Some(regions_lock) = MEMORY_REGIONS.as_ref() {
            if let Ok(regions) = regions_lock.read() {
                for region in regions.iter() {
                    if !types.contains(&region.memory_type) {
                        types.push(region.memory_type);
                    }
                }
            }
        }
    }
    
    Ok(types)
}

/// メモリタイプの特性を取得
pub fn get_memory_characteristics(mem_type: MemoryType) -> Result<MemoryCharacteristics, &'static str> {
    if !INITIALIZED.load(Ordering::SeqCst) {
        return Err("異種メモリシステムが初期化されていません");
    }
    
    unsafe {
        if let Some(regions_lock) = MEMORY_REGIONS.as_ref() {
            if let Ok(regions) = regions_lock.read() {
                for region in regions.iter() {
                    if region.memory_type == mem_type {
                        return Ok(region.characteristics.clone());
                    }
                }
            }
        }
    }
    
    Err("指定されたメモリタイプが見つかりません")
}

// 内部関数 //

/// 最適なメモリタイプを選択
fn select_optimal_memory_type(size: usize, flags: AllocFlags) -> Result<MemoryType, &'static str> {
    // 低レイテンシが要求される場合はHBM
    if flags.contains(AllocFlags::LOW_LATENCY) && has_hbm() {
        return Ok(MemoryType::HBM);
    }
    
    // 永続化が必要な場合はNVRAM
    if flags.contains(AllocFlags::PERSISTENT) && has_nvram() {
        return Ok(MemoryType::NVRAM);
    }
    
    // GPUアクセスが主な場合はGPUメモリ
    if flags.contains(AllocFlags::GPU_ACCESSIBLE) && has_gpu_memory() {
        return Ok(MemoryType::GPU);
    }
    
    // デフォルトはDRAM
    Ok(MemoryType::DRAM)
}

/// DRAMから割り当て
fn allocate_from_dram(size: usize) -> Result<(usize, Vec<usize>, Vec<usize>, Vec<MemoryType>), &'static str> {
    // 実際の割り当て処理
    let physical_addr = crate::memory::allocate_pages(size / PAGE_SIZE, AllocFlags::empty())?;
    let virtual_addr = generate_virtual_address(MemoryType::DRAM);
    
    Ok((
        virtual_addr,
        vec![physical_addr],
        vec![size],
        vec![MemoryType::DRAM]
    ))
}

/// HBMから割り当て
fn allocate_from_hbm(size: usize) -> Result<(usize, Vec<usize>, Vec<usize>, Vec<MemoryType>), &'static str> {
    // 実際にはHBMデバイスとの連携が必要
    let physical_addr = allocate_hbm_memory(size)?;
    let virtual_addr = generate_virtual_address(MemoryType::HBM);
    
    Ok((
        virtual_addr,
        vec![physical_addr],
        vec![size],
        vec![MemoryType::HBM]
    ))
}

/// NVRAMから割り当て
fn allocate_from_nvram(size: usize) -> Result<(usize, Vec<usize>, Vec<usize>, Vec<MemoryType>), &'static str> {
    // 実際にはNVRAMデバイスとの連携が必要
    let physical_addr = allocate_nvram_memory(size)?;
    let virtual_addr = generate_virtual_address(MemoryType::NVRAM);
    
    Ok((
        virtual_addr,
        vec![physical_addr],
        vec![size],
        vec![MemoryType::NVRAM]
    ))
}

/// GPUメモリから割り当て
fn allocate_from_gpu(size: usize, device_id: usize) -> Result<(usize, Vec<usize>, Vec<usize>, Vec<MemoryType>), &'static str> {
    // 実際にはGPUドライバとの連携が必要
    let physical_addr = allocate_gpu_memory(size, device_id)?;
    let virtual_addr = generate_virtual_address(MemoryType::GPU);
    
    Ok((
        virtual_addr,
        vec![physical_addr],
        vec![size],
        vec![MemoryType::GPU]
    ))
}

/// 仮想アドレスを生成
fn generate_virtual_address(mem_type: MemoryType) -> usize {
    // 単純な実装 - より洗練された方法が必要
    static NEXT_ADDR: AtomicUsize = AtomicUsize::new(0x8000_0000_0000); // 仮想アドレス空間の任意の場所
    NEXT_ADDR.fetch_add(GIGANTIC_PAGE_SIZE, Ordering::SeqCst)
}

/// DRAMメモリを解放
fn free_dram(addr: usize, size: usize) -> Result<(), &'static str> {
    let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    crate::memory::free_pages(addr, pages)
}

/// HBMメモリを解放
fn free_hbm(addr: usize, size: usize) -> Result<(), &'static str> {
    // 実際のHBM解放処理
    Ok(())
}

/// NVRAMメモリを解放
fn free_nvram(addr: usize, size: usize) -> Result<(), &'static str> {
    // 実際のNVRAM解放処理
    Ok(())
}

/// GPUメモリを解放
fn free_gpu_memory(addr: usize, size: usize, device_id: usize) -> Result<(), &'static str> {
    // 実際のGPUメモリ解放処理
    Ok(())
}

/// アドレスからデバイスIDを取得
fn get_device_id_from_address(addr: usize) -> Result<usize, &'static str> {
    for region in &DEVICE_ADDRESS_RANGES {
        if addr >= region.base && addr < region.base + region.size {
            return Ok(region.device_id);
        }
    }
    Err("該当デバイスなし")
}

/// メモリコピー
fn copy_memory(src: usize, dest: usize, size: usize) -> Result<(), &'static str> {
    // 安全ではない生のメモリコピー
    unsafe {
        core::ptr::copy_nonoverlapping(
            src as *const u8,
            dest as *mut u8,
            size
        );
    }
    
    Ok(())
}

/// マッピングを取得
fn get_mapping(addr: usize) -> Result<&'static HeterogeneousMapping, &'static str> {
    // アドレスに最も近いマッピングのベースを見つける
    let base_addr = {
        let mut closest = 0;
        
        unsafe {
            if let Some(mappings_lock) = HETEROGENEOUS_MAPPINGS.as_ref() {
                if let Ok(mappings) = mappings_lock.read() {
                    for (&map_addr, mapping) in mappings.iter() {
                        if map_addr <= addr {
                            let end_addr = map_addr + mapping.sizes.iter().sum::<usize>();
                            if addr < end_addr && map_addr > closest {
                                closest = map_addr;
                            }
                        }
                    }
                }
            }
        }
        
        if closest == 0 {
            return Err("指定されたアドレスのマッピングが見つかりません");
        }
        
        closest
    };
    
    // マッピングを返す
    unsafe {
        if let Some(mappings_lock) = HETEROGENEOUS_MAPPINGS.as_ref() {
            if let Ok(mappings) = mappings_lock.read() {
                if let Some(mapping) = mappings.get(&base_addr) {
                    return Ok(mapping);
                }
            }
        }
    }
    
    Err("マッピングの取得に失敗しました")
}

/// HBMが利用可能か確認
fn has_hbm() -> bool {
    crate::arch::detect_hbm_devices() > 0
}

/// NVRAMが利用可能か確認
fn has_nvram() -> bool {
    crate::arch::detect_nvram_devices() > 0
}

/// GPUメモリが利用可能か確認
fn has_gpu_memory() -> bool {
    crate::arch::gpu::detect_devices().len() > 0
}

/// 利用可能なDRAMサイズを取得
fn get_available_dram_size() -> usize {
    crate::arch::memory::get_total_dram_size()
}

/// 利用可能なHBMサイズを取得
fn get_available_hbm_size() -> usize {
    crate::arch::hbm::get_total_hbm_size()
}

/// 利用可能なNVRAMサイズを取得
fn get_available_nvram_size() -> usize {
    crate::arch::nvram::get_total_nvram_size()
}

/// HBMメモリを割り当て
fn allocate_hbm_memory(size: usize) -> Result<usize, &'static str> {
    crate::arch::hbm::allocate(size)
}

/// NVRAMメモリを割り当て
fn allocate_nvram_memory(size: usize) -> Result<usize, &'static str> {
    crate::arch::nvram::allocate(size)
}

/// GPUメモリを割り当て
fn allocate_gpu_memory(size: usize, device_id: usize) -> Result<usize, &'static str> {
    crate::arch::gpu::allocate(device_id, size)
}

/// GPUデバイスを検出
fn detect_gpu_devices() -> Result<Vec<GpuDevice>, &'static str> {
    crate::arch::gpu::detect_devices()
}

/// 最適なGPUデバイスを選択
fn select_optimal_gpu_device() -> Result<usize, &'static str> {
    // 実装省略 - 実際にはGPUの性能や利用状況に基づいて選択
    Ok(0)
}

/// GPUデバイス情報
struct GpuDevice {
    /// メモリサイズ
    memory_size: usize,
    
    /// 帯域幅 (GB/秒)
    bandwidth_gbps: f32,
    
    /// レイテンシ (ナノ秒)
    latency_ns: u64,
}

/// 現在のタイムスタンプを取得
fn get_timestamp() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    {
        0 // 他のアーキテクチャでの実装
    }
} 