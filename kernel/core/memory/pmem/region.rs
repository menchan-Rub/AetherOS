// AetherOS 不揮発性メモリ（PMEM）リージョン管理
//
// このモジュールは不揮発性メモリリージョンの検出と管理を担当します。
// リージョンの追跡、メモリマッピング、使用状況の監視などの機能を提供します。

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicBool, AtomicUsize, Ordering};
use core::fmt;
use crate::arch::{flush_pmem, memory_barrier};
use crate::sync::{RwLock, Mutex, SpinLock};
use log::{debug, info, warn, error, trace};

/// PMEMリージョンの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmemRegionType {
    /// App-Directモード（バイトアドレッサブルなPMEM）
    AppDirect,
    /// メモリモード（揮発性キャッシュとしてのDRAM + PMEMの組み合わせ）
    Memory,
    /// 混合モード（App-DirectとMemoryモードの混合）
    Mixed,
    /// デバイスDAXモード（rawデバイスアクセス）
    DeviceDax,
    /// ファイルシステムDAXモード（DAX対応ファイルシステム）
    FilesystemDax,
    /// 発見されたが分類不能なリージョン
    Unknown,
}

impl fmt::Display for PmemRegionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AppDirect => write!(f, "App-Direct"),
            Self::Memory => write!(f, "Memory"),
            Self::Mixed => write!(f, "Mixed"),
            Self::DeviceDax => write!(f, "Device-DAX"),
            Self::FilesystemDax => write!(f, "Filesystem-DAX"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// PMEMリージョンの健全性状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmemRegionHealth {
    /// 正常
    Healthy,
    /// 警告（一部エラーが検出されているが使用可能）
    Warning,
    /// 致命的なエラー（使用不可）
    Critical,
    /// 不明
    Unknown,
}

/// PMEMリージョン情報
#[derive(Debug, Clone)]
pub struct PmemRegion {
    /// 物理アドレス
    pub physical_address: usize,
    /// サイズ（バイト単位）
    pub size: usize,
    /// リージョン名
    pub name: String,
    /// リージョンタイプ
    pub region_type: PmemRegionType,
    /// NUMAノードID
    pub numa_node_id: u32,
    /// インターリーブされているか
    pub is_interleaved: bool,
    /// リージョンの健全性
    pub health: PmemRegionHealth,
    /// メディア寿命（残り書き込み可能な推定割合）
    pub media_life_remaining: Option<u8>,
}

impl PmemRegion {
    /// 新しいPMEMリージョンを作成
    pub fn new(physical_address: usize, size: usize, name: String, region_type: PmemRegionType, numa_node_id: u32) -> Self {
        Self {
            physical_address,
            size,
            name,
            region_type,
            numa_node_id,
            is_interleaved: false,
            health: PmemRegionHealth::Healthy,
            media_life_remaining: None,
        }
    }

    /// リージョンの終了アドレスを取得
    pub fn end_address(&self) -> usize {
        self.physical_address + self.size
    }

    /// 指定されたアドレスがこのリージョンに含まれているか確認
    pub fn contains(&self, address: usize) -> bool {
        address >= self.physical_address && address < self.end_address()
    }

    /// リージョンの健全性を更新
    pub fn update_health(&mut self, health: PmemRegionHealth) {
        self.health = health;
        if health != PmemRegionHealth::Healthy {
            warn!("PMEM region '{}' health changed to {:?}", self.name, health);
        }
    }

    /// メディア寿命を更新
    pub fn update_media_life(&mut self, life_percent: u8) {
        self.media_life_remaining = Some(life_percent);
        if life_percent < 20 {
            warn!("PMEM region '{}' media life low: {}%", self.name, life_percent);
        }
    }
}

/// PMEMリージョン詳細情報
pub struct PmemRegionInfo {
    /// 基本リージョン情報
    pub region: PmemRegion,
    /// 使用済みサイズ
    used_size: AtomicU64,
    /// マップ済みフラグ
    is_mapped: AtomicBool,
    /// マップされた仮想アドレス
    mapped_address: AtomicUsize,
    /// 最終アクセス時間
    last_access: AtomicU64,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// マッピングカウント (複数回マッピングの追跡用)
    mapping_count: AtomicUsize,
    /// アクセス回数
    access_count: AtomicU64,
}

impl PmemRegionInfo {
    /// 新しいPMEMリージョン情報を作成
    pub fn new(region: PmemRegion) -> Self {
        Self {
            region,
            used_size: AtomicU64::new(0),
            is_mapped: AtomicBool::new(false),
            mapped_address: AtomicUsize::new(0),
            last_access: AtomicU64::new(0),
            initialized: AtomicBool::new(false),
            mapping_count: AtomicUsize::new(0),
            access_count: AtomicU64::new(0),
        }
    }

    /// 使用済みサイズを更新
    pub fn update_used_size(&self, delta: i64) {
        if delta >= 0 {
            // 正の場合は増加
            self.used_size.fetch_add(delta as u64, Ordering::Release);
        } else {
            // 負の場合は減少
            self.used_size.fetch_sub((-delta) as u64, Ordering::Release);
        }
    }

    /// 使用済みサイズを取得
    pub fn get_used_size(&self) -> u64 {
        self.used_size.load(Ordering::Acquire)
    }

    /// 空きサイズを取得
    pub fn get_free_size(&self) -> u64 {
        let total = self.region.size as u64;
        let used = self.get_used_size();
        if used > total {
            // ありえないはずだが、安全のため
            return 0;
        }
        total - used
    }

    /// 使用率（パーセント）を取得
    pub fn get_usage_percent(&self) -> f32 {
        let total = self.region.size as f32;
        let used = self.get_used_size() as f32;
        (used / total) * 100.0
    }

    /// マッピングアドレスを設定
    pub fn set_mapped_address(&self, virt_addr: usize) {
        self.mapped_address.store(virt_addr, Ordering::Release);
        self.is_mapped.store(true, Ordering::Release);
        self.mapping_count.fetch_add(1, Ordering::Release);
    }

    /// マッピングアドレスを取得
    pub fn get_mapped_address(&self) -> Option<usize> {
        let addr = self.mapped_address.load(Ordering::Acquire);
        if self.is_mapped.load(Ordering::Acquire) {
            Some(addr)
        } else {
            None
        }
    }

    /// マッピングを解除
    pub fn unmap(&self) {
        let count = self.mapping_count.fetch_sub(1, Ordering::Release);
        if count <= 1 {
            self.is_mapped.store(false, Ordering::Release);
            self.mapped_address.store(0, Ordering::Release);
        }
    }

    /// アクセス時間を更新
    pub fn update_access_time(&self, time: u64) {
        self.last_access.store(time, Ordering::Release);
        self.access_count.fetch_add(1, Ordering::Release);
    }

    /// 最終アクセス時間を取得
    pub fn get_last_access_time(&self) -> u64 {
        self.last_access.load(Ordering::Acquire)
    }

    /// アクセス回数を取得
    pub fn get_access_count(&self) -> u64 {
        self.access_count.load(Ordering::Acquire)
    }

    /// 初期化済みフラグを設定
    pub fn set_initialized(&self, initialized: bool) {
        self.initialized.store(initialized, Ordering::Release);
    }

    /// 初期化済みかどうかを確認
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }
}

impl fmt::Debug for PmemRegionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PmemRegionInfo")
            .field("region", &self.region)
            .field("used_size", &self.get_used_size())
            .field("free_size", &self.get_free_size())
            .field("usage_percent", &self.get_usage_percent())
            .field("is_mapped", &self.is_mapped.load(Ordering::Relaxed))
            .field("mapped_address", &format_args!("0x{:x}", self.mapped_address.load(Ordering::Relaxed)))
            .field("access_count", &self.get_access_count())
            .field("initialized", &self.is_initialized())
            .finish()
    }
}

/// PMEMリージョン検出器
pub struct PmemRegionDetector {
    /// 検出されたリージョンのキャッシュ
    regions: RwLock<Vec<PmemRegion>>,
    /// リージョン情報キャッシュ
    region_info: RwLock<BTreeMap<String, PmemRegionInfo>>,
    /// 検出ハンドラリスト
    detection_handlers: Mutex<Vec<fn(&PmemRegion)>>,
    /// 検出済みフラグ
    detected: AtomicBool,
    /// リージョン更新通知コールバック
    change_notifiers: Mutex<Vec<fn(&PmemRegion, bool)>>,
}

impl PmemRegionDetector {
    /// 新しいPMEMリージョン検出器を作成
    pub fn new() -> Self {
        Self {
            regions: RwLock::new(Vec::new()),
            region_info: RwLock::new(BTreeMap::new()),
            detection_handlers: Mutex::new(Vec::new()),
            detected: AtomicBool::new(false),
            change_notifiers: Mutex::new(Vec::new()),
        }
    }

    /// PMEMリージョンを検出
    pub fn detect_regions(&self) -> Result<usize, &'static str> {
        if self.detected.load(Ordering::Acquire) {
            // すでに検出済み
            return Ok(self.regions.read().unwrap_or_default().len());
        }

        // システムのPMEMリージョンを検出
        // 実際には、ACPIテーブル、UEFI、カーネルコマンドラインなどから情報を取得
        
        let mut regions = Vec::new();
        
        // テスト用ダミーリージョン
        // 実際の実装では、ハードウェア検出コードと置き換える
        let dummy_region = PmemRegion::new(
            0x100000000,  // 4GB以降
            16 * 1024 * 1024 * 1024,  // 16GB
            "pmem0".to_string(),
            PmemRegionType::AppDirect,
            0,
        );
        regions.push(dummy_region);
        
        let dummy_region2 = PmemRegion::new(
            0x500000000,  // 20GB以降
            32 * 1024 * 1024 * 1024,  // 32GB
            "pmem1".to_string(),
            PmemRegionType::DeviceDax,
            0,
        );
        regions.push(dummy_region2);
        
        // リージョン情報キャッシュを更新
        let mut region_info_map = BTreeMap::new();
        for region in &regions {
            // リージョン検出ハンドラを呼び出し
            for handler in self.detection_handlers.lock().unwrap_or_default().iter() {
                handler(region);
            }
            
            // リージョン情報を作成
            let info = PmemRegionInfo::new(region.clone());
            region_info_map.insert(region.name.clone(), info);
        }
        
        // キャッシュを更新
        {
            let mut region_cache = self.regions.write().map_err(|_| "regions lock failed")?;
            *region_cache = regions.clone();
        }
        
        {
            let mut info_cache = self.region_info.write().map_err(|_| "region_info lock failed")?;
            *info_cache = region_info_map;
        }
        
        self.detected.store(true, Ordering::Release);
        
        info!("検出されたPMEMリージョン: {} 個", regions.len());
        for region in &regions {
            info!("  - {}: {} GB ({:?}, NUMA node {})",
                  region.name,
                  region.size / 1024 / 1024 / 1024,
                  region.region_type,
                  region.numa_node_id);
        }
        
        Ok(regions.len())
    }

    /// リージョンを名前で取得
    pub fn get_region_by_name(&self, name: &str) -> Option<PmemRegion> {
        if !self.detected.load(Ordering::Acquire) {
            // まだ検出されていない場合は検出を試みる
            let _ = self.detect_regions();
        }
        
        let regions = self.regions.read().unwrap_or_default();
        regions.iter()
            .find(|r| r.name == name)
            .cloned()
    }

    /// リージョン情報を名前で取得
    pub fn get_region_info(&self, name: &str) -> Option<PmemRegionInfo> {
        if !self.detected.load(Ordering::Acquire) {
            // まだ検出されていない場合は検出を試みる
            let _ = self.detect_regions();
        }
        
        let info_map = self.region_info.read().unwrap_or_default();
        info_map.get(name).cloned()
    }

    /// 特定のNUMAノードに関連するリージョンを取得
    pub fn get_regions_by_numa_node(&self, node_id: u32) -> Vec<PmemRegion> {
        if !self.detected.load(Ordering::Acquire) {
            // まだ検出されていない場合は検出を試みる
            let _ = self.detect_regions();
        }
        
        let regions = self.regions.read().unwrap_or_default();
        regions.iter()
            .filter(|r| r.numa_node_id == node_id)
            .cloned()
            .collect()
    }

    /// 特定のタイプのリージョンを取得
    pub fn get_regions_by_type(&self, region_type: PmemRegionType) -> Vec<PmemRegion> {
        if !self.detected.load(Ordering::Acquire) {
            // まだ検出されていない場合は検出を試みる
            let _ = self.detect_regions();
        }
        
        let regions = self.regions.read().unwrap_or_default();
        regions.iter()
            .filter(|r| r.region_type == region_type)
            .cloned()
            .collect()
    }

    /// すべてのリージョンを取得
    pub fn get_all_regions(&self) -> Vec<PmemRegion> {
        if !self.detected.load(Ordering::Acquire) {
            // まだ検出されていない場合は検出を試みる
            let _ = self.detect_regions();
        }
        
        self.regions.read().unwrap_or_default().clone()
    }

    /// リージョン検出ハンドラを登録
    pub fn register_detection_handler(&self, handler: fn(&PmemRegion)) {
        let mut handlers = self.detection_handlers.lock().unwrap_or_default();
        handlers.push(handler);
    }

    /// リージョン変更通知ハンドラを登録
    pub fn register_change_notifier(&self, notifier: fn(&PmemRegion, bool)) {
        let mut notifiers = self.change_notifiers.lock().unwrap_or_default();
        notifiers.push(notifier);
    }

    /// リージョンの追加（主にホットプラグ用）
    pub fn add_region(&self, region: PmemRegion) -> Result<(), &'static str> {
        // リージョンが存在するか確認
        {
            let regions = self.regions.read().map_err(|_| "regions lock failed")?;
            if regions.iter().any(|r| r.name == region.name) {
                return Err("region already exists");
            }
        }
        
        // リージョンを追加
        {
            let mut regions = self.regions.write().map_err(|_| "regions write lock failed")?;
            regions.push(region.clone());
        }
        
        // リージョン情報を追加
        {
            let mut info_map = self.region_info.write().map_err(|_| "region_info write lock failed")?;
            let info = PmemRegionInfo::new(region.clone());
            info_map.insert(region.name.clone(), info);
        }
        
        // 変更通知
        for notifier in self.change_notifiers.lock().unwrap_or_default().iter() {
            notifier(&region, true); // true = 追加
        }
        
        info!("PMEMリージョン追加: {}", region.name);
        Ok(())
    }

    /// リージョンの削除（主にホットプラグ用）
    pub fn remove_region(&self, name: &str) -> Result<(), &'static str> {
        // リージョンが存在するか確認
        let region = {
            let regions = self.regions.read().map_err(|_| "regions lock failed")?;
            match regions.iter().find(|r| r.name == name) {
                Some(r) => r.clone(),
                None => return Err("region not found"),
            }
        };
        
        // リージョンを削除
        {
            let mut regions = self.regions.write().map_err(|_| "regions write lock failed")?;
            regions.retain(|r| r.name != name);
        }
        
        // リージョン情報を削除
        {
            let mut info_map = self.region_info.write().map_err(|_| "region_info write lock failed")?;
            info_map.remove(name);
        }
        
        // 変更通知
        for notifier in self.change_notifiers.lock().unwrap_or_default().iter() {
            notifier(&region, false); // false = 削除
        }
        
        info!("PMEMリージョン削除: {}", name);
        Ok(())
    }
}

/// PMEMリージョンユーティリティ
pub struct PmemRegionUtils;

impl PmemRegionUtils {
    /// PMEMリージョンをメモリにマップ
    pub fn map_region(region: &PmemRegion, virt_addr: Option<usize>) -> Result<usize, &'static str> {
        // 物理アドレスを仮想アドレスにマップ
        // 実際にはメモリマッピング処理をアーキテクチャ依存で実装
        
        let target_virt_addr = match virt_addr {
            Some(addr) => addr,
            None => {
                // マッピング用の仮想アドレスを自動的に選択
                // 実際の実装ではVMマネージャーから適切なアドレスを取得
                0xFFFF800000000000 + region.physical_address
            }
        };
        
        // TODO: 実際のマッピング処理
        // ページテーブルを設定してマッピング
        
        debug!("PMEMリージョン '{}' をマップ: 物理アドレス 0x{:x} -> 仮想アドレス 0x{:x}, サイズ: {} bytes",
               region.name, region.physical_address, target_virt_addr, region.size);
        
        Ok(target_virt_addr)
    }

    /// PMEMリージョンのマッピングを解除
    pub fn unmap_region(region: &PmemRegion, virt_addr: usize) -> Result<(), &'static str> {
        // 仮想アドレスのマッピングを解除
        
        debug!("PMEMリージョン '{}' のマッピングを解除: 仮想アドレス 0x{:x}", 
               region.name, virt_addr);
        
        // TODO: 実際のアンマッピング処理
        // ページテーブルからマッピングを削除
        
        Ok(())
    }

    /// PMEMリージョンのゼロ初期化
    pub fn zero_region(region: &PmemRegion) -> Result<(), &'static str> {
        // PMEMリージョンをゼロで初期化
        
        info!("PMEMリージョン '{}' をゼロ初期化中 ({} MB)...", 
              region.name, region.size / 1024 / 1024);
        
        // TODO: 実際のゼロ初期化実装
        // 高速なゼロ化命令（AVX-512など）を使用
        
        Ok(())
    }

    /// PMEMリージョンを安全に消去（セキュアワイプ）
    pub fn secure_erase_region(region: &PmemRegion) -> Result<(), &'static str> {
        // PMEMリージョンを安全に消去（機密データ消去用）
        
        info!("PMEMリージョン '{}' を安全に消去中 ({} MB)...", 
              region.name, region.size / 1024 / 1024);
        
        // TODO: 実際の安全消去実装
        // 複数パターンの上書きを行う
        
        Ok(())
    }

    /// PMEMリージョンをメモリにコピー
    pub fn copy_to_memory(region: &PmemRegion, dest: *mut u8, offset: usize, size: usize) -> Result<usize, &'static str> {
        if offset >= region.size {
            return Err("offset out of bounds");
        }
        
        // コピーサイズを調整
        let actual_size = core::cmp::min(size, region.size - offset);
        
        // コピー元アドレス
        let src_addr = region.physical_address + offset;
        
        // TODO: 実際のコピー実装（ハードウェアアクセラレーション活用）
        
        trace!("PMEMから通常メモリへコピー: 物理アドレス 0x{:x} + 0x{:x} -> 0x{:x}, サイズ: {} bytes",
               region.physical_address, offset, dest as usize, actual_size);
        
        Ok(actual_size)
    }

    /// メモリからPMEMリージョンにコピー
    pub fn copy_from_memory(region: &PmemRegion, src: *const u8, offset: usize, size: usize) -> Result<usize, &'static str> {
        if offset >= region.size {
            return Err("offset out of bounds");
        }
        
        // コピーサイズを調整
        let actual_size = core::cmp::min(size, region.size - offset);
        
        // コピー先アドレス
        let dest_addr = region.physical_address + offset;
        
        // TODO: 実際のコピー実装（ハードウェアアクセラレーション活用）
        
        trace!("通常メモリからPMEMへコピー: 0x{:x} -> 物理アドレス 0x{:x} + 0x{:x}, サイズ: {} bytes",
               src as usize, region.physical_address, offset, actual_size);
        
        // PMEM範囲をフラッシュ
        // これは必須でCPUキャッシュからPMEMへの確実な書き込みを保証する
        unsafe {
            flush_pmem(dest_addr, actual_size);
            memory_barrier();
        }
        
        Ok(actual_size)
    }

    /// PMEMリージョンが有効かどうか確認
    pub fn validate_region(region: &PmemRegion) -> Result<bool, &'static str> {
        // 様々な妥当性チェックを行う
        
        // 1. アドレス範囲のチェック
        if region.physical_address == 0 || region.size == 0 {
            return Err("invalid address or size");
        }
        
        // 2. アラインメントチェック
        if region.physical_address % 4096 != 0 {
            return Err("unaligned physical address");
        }
        
        // 3. サイズのチェック（最小サイズを超えているか）
        if region.size < 4 * 1024 * 1024 {
            // 最小4MB
            return Err("region size too small");
        }
        
        // TODO: その他の妥当性検証
        
        Ok(true)
    }

    /// PMEMリージョンの健全性をチェック
    pub fn check_health(region: &PmemRegion) -> Result<PmemRegionHealth, &'static str> {
        // PMEMデバイスのヘルスチェック
        // 実際にはNVDIMMのヘルスクエリやSMARTチェックを実行
        
        // TODO: 実際のヘルスチェック実装
        // - メディア寿命チェック
        // - エラーカウンタ
        // - 温度
        // など
        
        Ok(PmemRegionHealth::Healthy)
    }

    /// PMEMリージョンを永続化する（キャッシュをフラッシュ）
    pub fn persist_region(region: &PmemRegion, offset: usize, size: usize) -> Result<(), &'static str> {
        if offset >= region.size {
            return Err("offset out of bounds");
        }
        
        // 永続化サイズを調整
        let actual_size = core::cmp::min(size, region.size - offset);
        
        // アドレス
        let addr = region.physical_address + offset;
        
        // PMEMキャッシュラインをフラッシュ
        unsafe {
            flush_pmem(addr, actual_size);
            memory_barrier();
        }
        
        trace!("PMEMリージョン永続化: 物理アドレス 0x{:x} + 0x{:x}, サイズ: {} bytes",
               region.physical_address, offset, actual_size);
        
        Ok(())
    }
} 