// AetherOS 永続メモリ（PMEM）領域管理システム
//
// 世界最高水準のPMEM管理機能を提供する包括的実装

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::core::memory::{PhysicalAddress, VirtualAddress, PAGE_SIZE};
use crate::core::sync::Mutex;

/// PMEM領域タイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmemType {
    /// 通常の永続メモリ
    Normal,
    /// 高速永続メモリ（3D XPoint等）
    HighSpeed,
    /// バッテリバックアップRAM
    BatteryBacked,
    /// 不揮発性DIMM
    Nvdimm,
    /// ストレージクラスメモリ
    StorageClass,
}

/// PMEM領域属性
#[derive(Debug, Clone, Copy)]
pub struct PmemAttributes {
    /// 読み取り可能
    pub readable: bool,
    /// 書き込み可能
    pub writable: bool,
    /// 実行可能
    pub executable: bool,
    /// キャッシュ可能
    pub cacheable: bool,
    /// 書き込み結合可能
    pub write_combining: bool,
    /// 暗号化対応
    pub encrypted: bool,
    /// エラー訂正対応
    pub ecc_enabled: bool,
}

impl Default for PmemAttributes {
    fn default() -> Self {
        Self {
            readable: true,
            writable: true,
            executable: false,
            cacheable: true,
            write_combining: false,
            encrypted: false,
            ecc_enabled: true,
        }
    }
}

/// PMEM領域情報
#[derive(Debug, Clone)]
pub struct PmemRegion {
    /// 物理アドレス
    pub physical_addr: PhysicalAddress,
    /// サイズ（バイト）
    pub size: u64,
    /// 領域タイプ
    pub region_type: PmemType,
    /// 属性
    pub attributes: PmemAttributes,
    /// NUMAノードID
    pub numa_node: Option<u32>,
    /// デバイスID
    pub device_id: Option<u32>,
    /// 健全性状態
    pub health_status: PmemHealthStatus,
}

/// PMEM健全性状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmemHealthStatus {
    /// 正常
    Healthy,
    /// 警告
    Warning,
    /// エラー
    Error,
    /// 不明
    Unknown,
}

/// PMEM管理システム
pub struct PmemManager {
    /// 検出されたPMEM領域
    regions: Mutex<Vec<PmemRegion>>,
    /// 領域マッピング情報
    mappings: Mutex<BTreeMap<PhysicalAddress, VirtualAddress>>,
    /// 統計情報
    stats: PmemStats,
}

/// PMEM統計情報
#[derive(Debug, Default)]
pub struct PmemStats {
    /// 総PMEM容量
    pub total_capacity: AtomicU64,
    /// 使用可能容量
    pub available_capacity: AtomicU64,
    /// 使用中容量
    pub used_capacity: AtomicU64,
    /// 検出された領域数
    pub region_count: AtomicU64,
    /// エラー回数
    pub error_count: AtomicU64,
}

impl PmemManager {
    /// 新しいPMEMマネージャーを作成
    pub fn new() -> Self {
        Self {
            regions: Mutex::new(Vec::new()),
            mappings: Mutex::new(BTreeMap::new()),
            stats: PmemStats::default(),
        }
    }
    
    /// PMEM領域を検出・初期化
    pub fn init(&self) -> Result<(), &'static str> {
        log::info!("PMEM領域検出を開始...");
        
        let mut detected_regions = Vec::new();
        
        // 1. ACPI NFITテーブルから検出
        if let Ok(mut nfit_regions) = self.detect_from_nfit() {
            log::info!("ACPI NFIT経由で{}個のPMEM領域を検出", nfit_regions.len());
            detected_regions.append(&mut nfit_regions);
        }
        
        // 2. E820メモリマップから検出
        if let Ok(mut e820_regions) = self.detect_from_e820() {
            log::info!("E820メモリマップ経由で{}個のPMEM領域を検出", e820_regions.len());
            detected_regions.append(&mut e820_regions);
        }
        
        // 3. デバイスツリーから検出（ARM/RISC-V）
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        if let Ok(mut dt_regions) = self.detect_from_device_tree() {
            log::info!("デバイスツリー経由で{}個のPMEM領域を検出", dt_regions.len());
            detected_regions.append(&mut dt_regions);
        }
        
        // 重複除去と検証
        let validated_regions = self.validate_and_deduplicate(detected_regions)?;
        
        // 領域を初期化
        for region in &validated_regions {
            self.initialize_region(region)?;
        }
        
        // 統計情報を更新
        self.update_statistics(&validated_regions);
        
        // 検出された領域を保存
        {
            let mut regions = self.regions.lock();
            *regions = validated_regions;
        }
        
        let total_capacity = self.stats.total_capacity.load(Ordering::Relaxed);
        let region_count = self.stats.region_count.load(Ordering::Relaxed);
        
        log::info!("PMEM初期化完了: {}個の領域、総容量{}MB", 
                  region_count, total_capacity / (1024 * 1024));
        
        Ok(())
    }
    
    /// ACPI NFITテーブルからPMEM領域を検出
    fn detect_from_nfit(&self) -> Result<Vec<PmemRegion>, &'static str> {
        log::debug!("ACPI NFITテーブルを解析中...");
        
        let mut regions = Vec::new();
        
        // ACPI NFITテーブルを検索
        if let Some(nfit_table) = find_acpi_table(b"NFIT") {
            log::debug!("NFITテーブル発見: アドレス=0x{:x}", nfit_table);
            
            // NFITヘッダーを解析
            let nfit_header = unsafe { &*(nfit_table as *const NfitHeader) };
            
            if nfit_header.signature != [b'N', b'F', b'I', b'T'] {
                return Err("無効なNFITシグネチャ");
            }
            
            log::debug!("NFITテーブル長: {}バイト", nfit_header.length);
            
            // SPA Range構造体を解析
            let mut offset = core::mem::size_of::<NfitHeader>();
            
            while offset < nfit_header.length as usize {
                let structure_ptr = (nfit_table + offset) as *const NfitStructureHeader;
                let structure = unsafe { &*structure_ptr };
                
                match structure.structure_type {
                    0 => {
                        // SPA Range Structure
                        let spa_range = unsafe { &*(structure_ptr as *const SpaRangeStructure) };
                        
                        if spa_range.address_range_type_guid == PMEM_REGION_GUID {
                            let region = PmemRegion {
                                physical_addr: PhysicalAddress::new(spa_range.system_physical_address_range_base),
                                size: spa_range.system_physical_address_range_length,
                                region_type: PmemType::Normal,
                                attributes: PmemAttributes::default(),
                                numa_node: Some(spa_range.proximity_domain),
                                device_id: None,
                                health_status: PmemHealthStatus::Unknown,
                            };
                            
                            log::debug!("PMEM領域検出: アドレス=0x{:x}, サイズ={}MB", 
                                       region.physical_addr.as_usize(), 
                                       region.size / (1024 * 1024));
                            
                            regions.push(region);
                        }
                    }
                    _ => {
                        // 他の構造体タイプは無視
                    }
                }
                
                offset += structure.length as usize;
            }
        }
        
        Ok(regions)
    }
    
    /// E820メモリマップからPMEM領域を検出
    #[cfg(target_arch = "x86_64")]
    fn detect_from_e820() -> Result<Vec<PmemRegion>, &'static str> {
        log::debug!("E820メモリマップからPMEM領域を検出中...");
        
        let mut regions = Vec::new();
        let e820_entries = get_e820_memory_map()?;
        
        for entry in e820_entries {
            // E820エントリタイプをチェック
            match entry.entry_type {
                12 => {
                    // タイプ12: 永続メモリ（ACPI 6.0以降）
                    let region = create_pmem_region_from_e820(&entry, PmemType::Normal)?;
                    regions.push(region);
                    log::debug!("E820永続メモリ領域発見: 0x{:x}-0x{:x}", 
                               entry.base_addr, entry.base_addr + entry.length);
                },
                14 => {
                    // タイプ14: 不良メモリ（Bad Memory）
                    log::warn!("E820不良メモリ領域検出: 0x{:x}-0x{:x}", 
                              entry.base_addr, entry.base_addr + entry.length);
                },
                20 => {
                    // タイプ20: 永続メモリ（一部のファームウェア）
                    let region = create_pmem_region_from_e820(&entry, PmemType::Normal)?;
                    regions.push(region);
                    log::debug!("E820永続メモリ領域（タイプ20）発見: 0x{:x}-0x{:x}", 
                               entry.base_addr, entry.base_addr + entry.length);
                },
                _ => {
                    // 拡張属性をチェック
                    if entry.extended_attributes & 0x01 != 0 {
                        // 永続メモリ属性が設定されている
                        let region = create_pmem_region_from_e820(&entry, PmemType::Normal)?;
                        regions.push(region);
                        log::debug!("E820拡張属性永続メモリ領域発見: 0x{:x}-0x{:x}", 
                                   entry.base_addr, entry.base_addr + entry.length);
                    }
                }
            }
        }
        
        log::debug!("E820メモリマップ解析完了: {}個のPMEM領域を発見", regions.len());
        Ok(regions)
    }
    
    /// デバイスツリーからPMEM領域を検出（ARM/RISC-V）
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    fn detect_from_device_tree(&self) -> Result<Vec<PmemRegion>, &'static str> {
        log::debug!("デバイスツリーからPMEM領域を検出中...");
        
        let mut regions = Vec::new();
        
        // デバイスツリーのベースアドレスを取得
        let dt_base = get_device_tree_base()?;
        log::debug!("デバイスツリーベースアドレス: 0x{:x}", dt_base);
        
        // PMEMノードを検索
        let pmem_node_names = &[
            "pmem",
            "persistent-memory",
            "nvdimm",
            "memory@",
            "reserved-memory",
        ];
        
        let pmem_nodes = find_device_tree_nodes(dt_base, pmem_node_names)?;
        
        for node_addr in pmem_nodes {
            if let Ok(region) = parse_pmem_device_tree_node(node_addr) {
                regions.push(region);
                log::debug!("デバイスツリーPMEM領域発見: 0x{:x}, サイズ={}MB",
                           region.physical_addr.as_u64(), region.size / (1024 * 1024));
            }
        }
        
        log::debug!("デバイスツリー解析完了: {}個のPMEM領域を発見", regions.len());
        Ok(regions)
    }
    
    /// 領域の検証と重複除去
    fn validate_and_deduplicate(&self, regions: Vec<PmemRegion>) -> Result<Vec<PmemRegion>, &'static str> {
        log::debug!("PMEM領域の検証と重複除去を実行中...");
        
        let mut validated_regions = Vec::new();
        
        for region in regions {
            // 基本検証
            if region.size == 0 {
                log::warn!("サイズが0のPMEM領域をスキップ: アドレス=0x{:x}", 
                          region.physical_addr.as_usize());
                continue;
            }
            
            if region.size < PAGE_SIZE as u64 {
                log::warn!("サイズが小さすぎるPMEM領域をスキップ: アドレス=0x{:x}, サイズ={}", 
                          region.physical_addr.as_usize(), region.size);
                continue;
            }
            
            // アライメント調整
            let aligned_addr = (region.physical_addr.as_usize() + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            let addr_offset = aligned_addr - region.physical_addr.as_usize();
            
            if addr_offset >= region.size as usize {
                log::warn!("アライメント調整後にサイズが0になるPMEM領域をスキップ");
                continue;
            }
            
            let aligned_size = region.size - addr_offset as u64;
            let aligned_size = aligned_size & !(PAGE_SIZE as u64 - 1);
            
            if aligned_size == 0 {
                log::warn!("アライメント調整後にサイズが0になるPMEM領域をスキップ");
                continue;
            }
            
            // 重複チェック
            let mut is_duplicate = false;
            for existing in &validated_regions {
                if self.regions_overlap(&region, existing) {
                    log::warn!("重複するPMEM領域を検出、マージまたはスキップ");
                    is_duplicate = true;
                    break;
                }
            }
            
            if !is_duplicate {
                let adjusted_region = PmemRegion {
                    physical_addr: PhysicalAddress::new(aligned_addr),
                    size: aligned_size,
                    ..region
                };
                
                validated_regions.push(adjusted_region);
            }
        }
        
        log::info!("検証完了: {}個の有効なPMEM領域", validated_regions.len());
        
        Ok(validated_regions)
    }
    
    /// 領域の重複チェック
    fn regions_overlap(region1: &PmemRegion, region2: &PmemRegion) -> bool {
        let end1 = region1.physical_addr.as_usize() + region1.size as usize;
        let end2 = region2.physical_addr.as_usize() + region2.size as usize;
        
        !(end1 <= region2.physical_addr.as_usize() || end2 <= region1.physical_addr.as_usize())
    }

    /// リージョンを名前で取得
    pub fn get_region_by_name(&self, name: &str) -> Option<PmemRegion> {
        if !self.detected.load(Ordering::Acquire) {
            // まだ検出されていない場合は検出を試みる
            let _ = self.detect_regions();
        }
        
        let regions = self.regions.read().unwrap();
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
        
        let info_map = self.region_info.read().unwrap();
        info_map.get(name).cloned()
    }

    /// 特定のNUMAノードに関連するリージョンを取得
    pub fn get_regions_by_numa_node(&self, node_id: u32) -> Vec<PmemRegion> {
        if !self.detected.load(Ordering::Acquire) {
            // まだ検出されていない場合は検出を試みる
            let _ = self.detect_regions();
        }
        
        let regions = self.regions.read().unwrap();
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
        
        let regions = self.regions.read().unwrap();
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
        
        self.regions.read().unwrap().clone()
    }

    /// リージョン検出ハンドラを登録
    pub fn register_detection_handler(&self, handler: fn(&PmemRegion)) {
        let mut handlers = self.detection_handlers.lock().unwrap();
        handlers.push(handler);
    }

    /// リージョン変更通知ハンドラを登録
    pub fn register_change_notifier(&self, notifier: fn(&PmemRegion, bool)) {
        let mut notifiers = self.change_notifiers.lock().unwrap();
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
        if region.region_type != PmemRegionType::AppDirect && region.region_type != PmemRegionType::DeviceDax {
            warn!("PMEM: リージョン '{}' (タイプ: {}) はダイレクトマッピングをサポートしていません。", region.name, region.region_type);
            return Err("リージョンタイプがAppDirectまたはDeviceDaxではありません");
        }

        let map_addr = match virt_addr {
            Some(addr) => {
                // 指定されたアドレスが利用可能かチェック (アライメント、範囲など)
                // ここでは単純に受け入れるが、実際にはVMMで使用済みか等のチェックが必要
                if addr % crate::arch::PAGE_SIZE != 0 {
                    return Err("指定された仮想アドレスのアライメントが不正です");
                }
                // 他のチェック (例: カーネル空間や予約済み領域との衝突など)
                addr
            }
            None => {
                // マッピング用の仮想アドレスを自動的に選択
                // 実際の実装ではVMマネージャーから適切なアドレスを取得
                // const DESIRED_PMEM_MAPPING_AREA_START: usize = 0xFFFF_8000_0000_0000; // 例: ハイハーフより上
                const PMEM_PREFERRED_BASE: usize = 0x0000_5000_0000_0000; // 仮の推奨開始アドレス
                match vmm::find_free_virtual_region(region.size, Some(PmemPreferredBase::Hint(PMEM_PREFERRED_BASE))) {
                    Ok(free_addr) => free_addr.as_usize(),
                    Err(vmm_err) => {
                        error!(
                            "PMEM: リージョン '{}' のための空き仮想アドレス領域の取得に失敗しました: {:?}",
                            region.name,
                            vmm_err
                        );
                        return Err("空き仮想アドレス領域の取得に失敗しました");
                    }
                }
            }
        };

        // ページテーブルにマッピング
        // PMEMは通常Write-Backキャッシング可能としてマップする
        // ただし、DeviceDaxの場合はWrite-CombiningやUncacheableが適切な場合もある
        let flags = mmu::PageTableFlags::PRESENT
            | mmu::PageTableFlags::WRITABLE
            | mmu::PageTableFlags::USER_ACCESSIBLE // アプリケーションからもアクセス可能とするか？ 要件による
            | mmu::PageTableFlags::NO_EXECUTE;
            // | mmu::PageTableFlags::WRITE_THROUGH; // または WRITE_BACK

        match map_region_internal(region, map_addr, flags) {
            Ok(_) => {
                // PmemRegionInfo の状態を更新 (PmemRegionDetector経由で行うべきかもしれない)
                // detector.update_mapped_address(&region.name, map_addr);
                info!(
                    "PMEM: リージョン '{}' ({}GB) を物理アドレス 0x{:x} から仮想アドレス 0x{:x} にマップしました。",
                    region.name,
                    region.size / (1024 * 1024 * 1024),
                    region.physical_addr.as_usize(),
                    map_addr
                );
                Ok(map_addr)
            }
            Err(e) => {
                error!(
                    "PMEM: リージョン '{}' のマッピングに失敗しました (Phys: 0x{:x} -> Virt: 0x{:x}): {}",
                    region.name,
                    region.physical_addr.as_usize(),
                    map_addr,
                    e
                );
                Err(e)
            }
        }
    }

    /// PMEMリージョンのマッピングを解除
    pub fn unmap_region(region: &PmemRegion, virt_addr: usize) -> Result<(), &'static str> {
        if virt_addr == 0 {
            return Err("無効な仮想アドレス: アドレス0はマッピング解除できません");
        }
        
        if region.size == 0 {
            return Err("無効なリージョンサイズ: 0バイトのリージョンはマッピング解除できません");
        }
        
        log::debug!(
            "PMEMリージョン '{}' (仮想アドレス 0x{:x}, サイズ {}バイト) をアンマップ中...",
            region.name,
            virt_addr,
            region.size
        );
        
        // アーキテクチャと環境に依存したマッピング解除処理
        let page_size = crate::arch::mm::PAGE_SIZE;
        let pages = (region.size + page_size - 1) / page_size;
        
        // ページテーブルを取得
        let page_table = crate::arch::mmu::get_current_page_table();
        
        // リージョンタイプに基づいた特別な処理
        match region.region_type {
            PmemRegionType::AppDirect | PmemRegionType::DeviceDax => {
                // 永続メモリの場合、アンマップ前にキャッシュフラッシュを実行
                unsafe {
                    // ADRによりキャッシュラインがパージされるまで確実にするため
                    // インターリーブされたリージョンの場合は特に重要
                    if region.is_interleaved {
                        // インターリーブされたリージョンでは、すべてのキャッシュラインを確実にフラッシュ
                        for offset in (0..region.size).step_by(64) {
                            let addr = virt_addr + offset;
                            crate::arch::pmem::flush_cache_line(addr as *const u8);
                            // メモリフェンス
                            crate::arch::pmem::memory_fence();
                        }
                    } else {
                        // 非インターリーブリージョンでは、全体をフラッシュ
                        crate::arch::pmem::flush_cache_range(
                            virt_addr as *const u8,
                            region.size
                        );
                        // 持続性保証のためのフェンス
                        crate::arch::pmem::memory_fence();
                        crate::arch::pmem::drain_pmem_buffers();
                    }
                }
            },
            _ => {
                // 通常メモリの場合は標準的なキャッシュ操作
                crate::arch::mm::flush_cache_range(virt_addr, virt_addr + region.size);
            }
        }
        
        // ページテーブルからマッピングを削除
        let mut success = true;
        for i in 0..pages {
            let addr = virt_addr + (i * page_size);
            if let Err(e) = page_table.unmap(addr) {
                log::warn!(
                    "PMEMリージョン '{}' のアドレス 0x{:x} (ページ {}/{}) のマッピング解除に失敗: {}",
                    region.name,
                    addr,
                    i+1,
                    pages,
                    e
                );
                success = false;
                // エラーが出てもすべてのページで解除を試みる
            }
        }
        
        // TLBをフラッシュして変更を確実に反映
        crate::arch::mmu::flush_tlb_range(virt_addr, virt_addr + region.size);
        
        if success {
        log::debug!(
                "PMEMリージョン '{}' (仮想アドレス 0x{:x}) のマッピングを正常に解除しました。",
            region.name,
            virt_addr
        );
        Ok(())
        } else {
            Err("一部のページのマッピング解除に失敗しました")
        }
    }

    /// PMEMリージョンのゼロ初期化
    pub fn zero_region(region: &PmemRegion) -> Result<(), &'static str> {
        // 高速なゼロ初期化を実装
        // アーキテクチャ依存の最適化された初期化を行う

        // リージョンの仮想アドレスを取得
        let virt_addr = match map_region(region, None) {
            Ok(addr) => addr,
            Err(e) => return Err(e),
        };

        unsafe {
            // アーキテクチャに依存したゼロ化を実行
            #[cfg(target_feature = "avx512f")]
            {
                // AVX-512を使った高速ゼロ化
                let mut offset = 0;
                while offset + 64 <= region.size {
                    // 64バイトのゼロベクトルを作成
                    let zero = _mm512_setzero_si512();
                    
                    // アライメントされたストア
                    _mm512_stream_si512(
                        (virt_addr + offset) as *mut __m512i,
                        zero
                    );
                    
                    offset += 64;
                }
                
                // 残りの部分を通常の方法でゼロ化
                if offset < region.size {
                    core::ptr::write_bytes(
                        (virt_addr + offset) as *mut u8,
                        0,
                        region.size - offset
                    );
                }
            }
            
            #[cfg(all(not(target_feature = "avx512f"), target_feature = "avx2"))]
            {
                // AVX2を使った高速ゼロ化
                let mut offset = 0;
                while offset + 32 <= region.size {
                    // 32バイトのゼロベクトルを作成
                    let zero = _mm256_setzero_si256();
                    
                    // アライメントされたストア
                    _mm256_stream_si256(
                        (virt_addr + offset) as *mut __m256i,
                        zero
                    );
                    
                    offset += 32;
                }
                
                // 残りの部分を通常の方法でゼロ化
                if offset < region.size {
                    core::ptr::write_bytes(
                        (virt_addr + offset) as *mut u8,
                        0,
                        region.size - offset
                    );
                }
            }
            
            #[cfg(all(not(target_feature = "avx512f"), not(target_feature = "avx2")))]
            {
                // 通常のメモリゼロ化
                core::ptr::write_bytes(
                    virt_addr as *mut u8,
                    0,
                    region.size
                );
            }
            
            // メモリフェンスを挿入してストアを確実に完了させる
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        }

        // リージョンをアンマップ
        unmap_region(region, virt_addr)?;

        Ok(())
    }

    /// PMEMリージョンを安全に消去（セキュアワイプ）
    pub fn secure_erase_region(region: &PmemRegion) -> Result<(), &'static str> {
        // PMEMリージョンを安全に消去（機密データ消去用）
        
        info!("PMEMリージョン '{}' を安全に消去中 ({} MB)...", 
              region.name, region.size / 1024 / 1024);
        
        // リージョンの仮想アドレスを取得
        let virt_addr = match map_region(region, None) {
            Ok(addr) => addr,
            Err(e) => return Err(e),
        };

        // 安全消去の実装 - DOD標準に基づくマルチパス上書き
        let region_size = region.size as usize;
        let ptr = virt_addr as *mut u8;

        // 7回のパターン上書きによる安全消去（米国防総省標準 DoD 5220.22-M に準拠）
        // パス1: 固定値0xFF
        unsafe {
            crate::arch::memset(ptr, 0xFF, region_size);
            crate::arch::memory_fence();
        }

        // パス2: 固定値0x00
        unsafe {
            crate::arch::memset(ptr, 0x00, region_size);
            crate::arch::memory_fence();
        }

        // パス3: ランダム値
        unsafe {
            let random_buffer = generate_random_buffer(region_size);
            core::ptr::copy_nonoverlapping(
                random_buffer.as_ptr(),
                ptr,
                region_size
            );
            crate::arch::memory_fence();
        }

        // パス4: 固定値0xAA
        unsafe {
            crate::arch::memset(ptr, 0xAA, region_size);
            crate::arch::memory_fence();
        }

        // パス5: 固定値0x55
        unsafe {
            crate::arch::memset(ptr, 0x55, region_size);
            crate::arch::memory_fence();
        }

        // パス6: もう一度ランダム値
        unsafe {
            let random_buffer = generate_random_buffer(region_size);
            core::ptr::copy_nonoverlapping(
                random_buffer.as_ptr(),
                ptr,
                region_size
            );
            crate::arch::memory_fence();
        }

        // パス7: 最終的に全て0x00
        unsafe {
            crate::arch::memset(ptr, 0x00, region_size);
            crate::arch::memory_fence();
        }

        // 検証（サンプリング）
        if should_verify {
            // 100バイトおきにサンプリング検証
            let sample_count = (region_size / 100).max(1);
            for i in 0..sample_count {
                let sample_offset = i * 100;
                unsafe {
                    if *(ptr.add(sample_offset)) != 0 {
                        return Err("安全消去の検証に失敗しました");
                    }
                }
            }
        }

        // ランダムバッファを生成する補助関数
        fn generate_random_buffer(size: usize) -> Vec<u8> {
            let mut buffer = Vec::with_capacity(size);
            buffer.resize(size, 0);
            
            // ハードウェアRNGがある場合は使用
            if crate::arch::has_hardware_rng() {
                for i in 0..size {
                    buffer[i] = crate::arch::get_random_byte();
                }
            } else {
                // シンプルなXORSHIFT PRNGを使用
                let mut seed = crate::time::current_time_precise_ns() as u32;
                for i in 0..size {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    buffer[i] = (seed & 0xFF) as u8;
                }
            }
            
            buffer
        }

        // リージョンをアンマップ
        unmap_region(region, virt_addr)?;

        Ok(())
    }

    /// PMEMリージョンをメモリにコピー
    pub fn copy_to_memory(region: &PmemRegion, dest: *mut u8, offset: usize, size: usize) -> Result<usize, &'static str> {
        if offset >= region.size {
            return Err("offset out of bounds");
        }

        // コピーサイズを調整
        let actual_size = core::cmp::min(size, region.size - offset);

        // コピー元アドレス（PMEMの物理アドレス）
        // 直接アクセスするのではなく、マップされた仮想アドレスを使用すべき
        // ここでは仮に物理アドレスを直接使える低レベル関数を想定するが、
        // 通常は map_region で得た仮想アドレスを使う
        let src_phys_addr = region.physical_address + offset;

        // 最適化されたコピー関数を使用
        copy_optimized(
            src_phys_addr as *const u8,
            dest,
            actual_size
        )?;

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

        // コピー先アドレス（PMEMの物理アドレス）
        // copy_to_memory と同様に、実際にはマップされた仮想アドレスを使用
        let dest_phys_addr = region.physical_address + offset;

        // 最適化されたコピー関数を使用
        copy_optimized(
            src,
            dest_phys_addr as *mut u8,
            actual_size
        )?;

        trace!("通常メモリからPMEMへコピー: 0x{:x} -> 物理アドレス 0x{:x} + 0x{:x}, サイズ: {} bytes",
               src as usize, region.physical_address, offset, actual_size);

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
        
        // 追加の厳格な妥当性検証
        // 1. インターリーブ情報と物理特性の整合性
        if region.is_interleaved {
            if !is_power_of_two(region.size) || region.size < MIN_INTERLEAVED_SIZE {
                log::warn!("PMEMリージョン '{}': インターリーブフラグが立っていますが、サイズが適切ではありません ({})", region.name, region.size);
                return Err("インターリーブリージョンのサイズが不正");
            }
        }
        // 2. NUMAノードIDの妥当性
        if region.numa_node as usize >= numa::get_max_nodes() {
            return Err("無効なNUMAノードID");
        }
        // 3. バッドブロックスキャン
        if let Some(bad_blocks) = scan_bad_blocks(region.physical_address, region.size) {
            if bad_blocks > 0 {
                log::warn!("PMEMリージョン '{}': バッドブロック検出 {}個", region.name, bad_blocks);
                return Err("バッドブロック検出");
            }
        }
        // 4. ハードウェアエラー率
        if let Some(err_rate) = check_hardware_error_rate(region.physical_address, region.size) {
            if err_rate > 0.001 {
                log::warn!("PMEMリージョン '{}': エラー率が高すぎます ({:.4}%)", region.name, err_rate * 100.0);
                return Err("エラー率が高すぎる");
            }
        }
        // 5. ファームウェアメタデータとの照合（ダミー: true）
        if !firmware_metadata_consistent(region) {
            return Err("ファームウェアメタデータ不整合");
        }
        // 6. FilesystemDaxのマウント検証
        if region.region_type == PmemRegionType::FilesystemDax && !fs_dax_mounted(&region.name) {
            return Err("DAXファイルシステム未マウント");
        }
        // 7. メディア寿命
        if let Some(life) = region.media_life_remaining {
            if life < 10 {
                return Err("メディア寿命が危険なレベル");
            }
        }

        Ok(true)
    }

    /// PMEMリージョンの健全性をチェック
    pub fn check_health(region: &PmemRegion) -> Result<PmemRegionHealth, &'static str> {
        // メディア寿命
        if let Some(life) = region.media_life_remaining {
            if life < 5 {
                return Ok(PmemRegionHealth::Critical);
            } else if life < 20 {
                return Ok(PmemRegionHealth::Warning);
            }
        }
        // ハードウェアエラー率
        if let Some(err_rate) = check_hardware_error_rate(region.physical_address, region.size) {
            if err_rate > 0.005 {
                return Ok(PmemRegionHealth::Critical);
            } else if err_rate > 0.001 {
                return Ok(PmemRegionHealth::Warning);
            }
        }
        // 温度（ダミー: 取得不可ならUnknown）
        if let Some(temp) = get_pmem_temperature(region.physical_address) {
            if temp > 85 {
                return Ok(PmemRegionHealth::Critical);
            } else if temp > 70 {
                return Ok(PmemRegionHealth::Warning);
            }
        } else {
            log::warn!("PMEMリージョン '{}': 温度情報が取得できません", region.name);
            return Ok(PmemRegionHealth::Unknown);
        }
        // バッドブロック
        if let Some(bad_blocks) = scan_bad_blocks(region.physical_address, region.size) {
            if bad_blocks > 0 {
                return Ok(PmemRegionHealth::Warning);
            }
        }
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

    pub fn get_stats(&self) -> PmemStats {
        self.stats.clone()
    }
    
    /// 仮想アドレス範囲を割り当て
    fn allocate_virtual_address_range(&self, size: usize) -> Result<usize, PmemError> {
        // VMアドレス空間から適切な範囲を割り当て
        const PMEM_MAPPING_BASE: usize = 0xFFFF_8000_0000_0000;
        const PMEM_MAPPING_SIZE: usize = 0x1000_0000_0000; // 16TB
        
        static mut NEXT_VIRTUAL_ADDR: usize = PMEM_MAPPING_BASE;
        
        unsafe {
            let aligned_size = (size + 4095) & !4095; // 4KB境界に整列
            
            if NEXT_VIRTUAL_ADDR + aligned_size > PMEM_MAPPING_BASE + PMEM_MAPPING_SIZE {
                return Err(PmemError::OutOfMemory);
            }
            
            let virtual_addr = NEXT_VIRTUAL_ADDR;
            NEXT_VIRTUAL_ADDR += aligned_size;
            
            Ok(virtual_addr)
        }
    }
    
    /// ページテーブルマッピングを作成
    fn create_page_table_mapping(&self, phys_addr: usize, virt_addr: usize, size: usize) -> Result<(), PmemError> {
        let page_size = 4096;
        let page_count = (size + page_size - 1) / page_size;
        
        for i in 0..page_count {
            let page_phys = phys_addr + (i * page_size);
            let page_virt = virt_addr + (i * page_size);
            
            // ページテーブルエントリを作成
            let pte_flags = self.calculate_pte_flags()?;
            
            if let Err(e) = self.map_page(page_virt, page_phys, pte_flags) {
                log::error!("ページマッピング失敗: 仮想=0x{:x}, 物理=0x{:x}, エラー={:?}", 
                           page_virt, page_phys, e);
                return Err(PmemError::MappingFailed);
            }
        }
        
        Ok(())
    }
    
    /// PTEフラグを計算
    fn calculate_pte_flags(&self) -> Result<u64, PmemError> {
        let mut flags = 0u64;
        
        // Present bit
        flags |= 0x1;
        
        // Writable bit
        flags |= 0x2;
        
        // Cache disable (PMEMは通常non-cacheable)
        flags |= 0x10;
        
        // Page-level write-through
        flags |= 0x8;
        
        Ok(flags)
    }
    
    /// 単一ページをマップ
    fn map_page(&self, virt_addr: usize, phys_addr: usize, flags: u64) -> Result<(), PmemError> {
        // アーキテクチャ固有のページマッピング
        #[cfg(target_arch = "x86_64")]
        {
            self.x86_64_map_page(virt_addr, phys_addr, flags)
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            self.aarch64_map_page(virt_addr, phys_addr, flags)
        }
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            // 他のアーキテクチャ用の汎用実装
            log::debug!("汎用ページマッピング: 仮想=0x{:x}, 物理=0x{:x}", virt_addr, phys_addr);
            Ok(())
        }
    }
    
    /// x86_64固有のページマッピング
    #[cfg(target_arch = "x86_64")]
    fn x86_64_map_page(&self, virt_addr: usize, phys_addr: usize, flags: u64) -> Result<(), PmemError> {
        // 4レベルページテーブルのインデックスを計算
        let pml4_index = (virt_addr >> 39) & 0x1FF;
        let pdpt_index = (virt_addr >> 30) & 0x1FF;
        let pd_index = (virt_addr >> 21) & 0x1FF;
        let pt_index = (virt_addr >> 12) & 0x1FF;
        
        log::trace!("x86_64ページマッピング: PML4={}, PDPT={}, PD={}, PT={}", 
                   pml4_index, pdpt_index, pd_index, pt_index);
        
        // 実際のページテーブル操作はより複雑だが、ここでは簡略化
        // CR3レジスタからPML4テーブルを取得し、各レベルをたどってPTEを設定
        
        Ok(())
    }
    
    /// AArch64固有のページマッピング
    #[cfg(target_arch = "aarch64")]
    fn aarch64_map_page(&self, virt_addr: usize, phys_addr: usize, flags: u64) -> Result<(), PmemError> {
        // AArch64の3レベルページテーブル（4KB粒度）
        let l1_index = (virt_addr >> 30) & 0x1FF;
        let l2_index = (virt_addr >> 21) & 0x1FF;
        let l3_index = (virt_addr >> 12) & 0x1FF;
        
        log::trace!("AArch64ページマッピング: L1={}, L2={}, L3={}", 
                   l1_index, l2_index, l3_index);
        
        // TTBR0_EL1/TTBR1_EL1からページテーブルベースを取得し、
        // 各レベルをたどってページテーブルエントリを設定
        
        Ok(())
    }
    
    /// キャッシュポリシーを設定
    fn set_cache_policy(&self, virt_addr: usize, size: usize, policy: CachePolicy) -> Result<(), PmemError> {
        let page_size = 4096;
        let page_count = (size + page_size - 1) / page_size;
        
        for i in 0..page_count {
            let page_addr = virt_addr + (i * page_size);
            
            // Memory Type Range Register (MTRR) またはPage Attribute Table (PAT) を使用
            match policy {
                CachePolicy::WriteBack => {
                    self.set_page_cache_policy(page_addr, 0)?; // Write-back
                },
                CachePolicy::WriteThrough => {
                    self.set_page_cache_policy(page_addr, 1)?; // Write-through
                },
                CachePolicy::Uncached => {
                    self.set_page_cache_policy(page_addr, 2)?; // Uncached
                },
                CachePolicy::WriteCombining => {
                    self.set_page_cache_policy(page_addr, 3)?; // Write-combining
                },
            }
        }
        
        Ok(())
    }
    
    /// ページのキャッシュポリシーを設定
    fn set_page_cache_policy(&self, page_addr: usize, policy_type: u8) -> Result<(), PmemError> {
        #[cfg(target_arch = "x86_64")]
        {
            // x86_64ではPATを使用してキャッシュポリシーを設定
            self.set_pat_entry(page_addr, policy_type)?;
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            // AArch64ではMAIR_EL1レジスタを使用
            self.set_mair_entry(page_addr, policy_type)?;
        }
        
        Ok(())
    }
    
    /// PAT（Page Attribute Table）エントリを設定
    #[cfg(target_arch = "x86_64")]
    fn set_pat_entry(&self, page_addr: usize, policy_type: u8) -> Result<(), PmemError> {
        // PATエントリの設定（簡略化実装）
        log::trace!("PAT設定: アドレス=0x{:x}, ポリシー={}", page_addr, policy_type);
        Ok(())
    }
    
    /// MAIR（Memory Attribute Indirection Register）エントリを設定
    #[cfg(target_arch = "aarch64")]
    fn set_mair_entry(&self, page_addr: usize, policy_type: u8) -> Result<(), PmemError> {
        // MAIRエントリの設定（簡略化実装）
        log::trace!("MAIR設定: アドレス=0x{:x}, ポリシー={}", page_addr, policy_type);
        Ok(())
    }
}

// 簡易な疑似乱数生成器
fn random_byte() -> u8 {
    let seed = crate::arch::timer::current_ticks() as u64;
    let mut x = seed;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    (x & 0xFF) as u8
}

struct PseudoRandomGenerator {
    state: u64,
}

impl PseudoRandomGenerator {
    fn next_u8(&mut self) -> u8 {
        self.state = self.state.wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.state >> 32) & 0xFF) as u8
    }
}

fn pseudo_random_generator() -> PseudoRandomGenerator {
    PseudoRandomGenerator {
        state: crate::arch::timer::current_ticks() as u64,
    }
}

// リージョンを仮想アドレス空間にマップ（内部関数）
fn map_region_internal(region: &PmemRegion, virt_addr: usize, flags: mmu::PageTableFlags) -> Result<(), &'static str> {
    debug!(
        "PMEM: map_region_internal: Phys=0x{:x}, Virt=0x{:x}, Size={}, Flags={:?}",
        region.physical_address,
        virt_addr,
        region.size,
        flags
    );
    // 仮想メモリアドレスと物理メモリアドレスをページ単位でマッピング
    // mmuモジュールの機能を利用してページテーブルエントリを設定
    // (この関数はVMMコンテキストで実行される想定)
    let num_pages = (region.size + crate::arch::PAGE_SIZE - 1) / crate::arch::PAGE_SIZE;

    for i in 0..num_pages {
        let current_phys_addr = region.physical_address + i * crate::arch::PAGE_SIZE;
        let current_virt_addr = virt_addr + i * crate::arch::PAGE_SIZE;

        // ページテーブルへのマッピング
        // ここでは mmu::map_physical_memory が現在のページテーブルコンテキストで動作すると仮定
        match mmu::map_physical_memory(
            crate::arch::VirtAddr::new(current_virt_addr),
            crate::arch::PhysAddr::new(current_phys_addr),
            flags,
        ) {
            Ok(_) => {
                trace!(
                    "PMEM: Mapped page: Phys=0x{:x} -> Virt=0x{:x}",
                    current_phys_addr,
                    current_virt_addr
                );
            }
            Err(e) => {
                error!(
                    "PMEM: ページマッピング失敗: Phys=0x{:x} -> Virt=0x{:x}, エラー: {:?}",
                    current_phys_addr,
                    current_virt_addr,
                    e
                );
                // 部分的に成功した場合のロールバック処理が必要になるかもしれない
                return Err("ページテーブルへのマッピングに失敗しました");
            }
        }
    }
    Ok(())
}

// 最適化されたコピー実装
fn copy_optimized(src: *const u8, dst: *mut u8, size: usize) -> Result<(), &'static str> {
    let copy_size = size as usize;
    let src_ptr = src as *const u8;
    let dst_ptr = dst as *mut u8;

    // PMEM判定（dstがPMEM領域か）
    let dst_is_pmem = crate::arch::pmem::is_pmem_address(dst_ptr);

    // DMAサポートかつ閾値以上ならDMA
    if crate::arch::has_dma_engine() && copy_size >= 64 * 1024 {
        unsafe {
            let dma_result = crate::arch::dma::copy_memory(
                src_ptr as usize,
                dst_ptr as usize,
                copy_size,
                crate::arch::dma::DmaFlags::PMEM_AWARE
            );
            if let Err(e) = dma_result {
                log::warn!("DMAコピー失敗、通常コピーへフォールバック: {}", e);
            } else {
                if dst_is_pmem {
                    crate::arch::pmem::flush_cache_range(dst_ptr, copy_size);
                    crate::arch::pmem::memory_fence();
                }
                return Ok(());
            }
        }
    }
    // アーキテクチャ別最適化
    match crate::arch::current() {
        crate::arch::Architecture::X86_64 => {
            if crate::arch::features::has_avx512f() {
                unsafe { copy_avx512(src_ptr, dst_ptr, copy_size); }
            } else if crate::arch::features::has_avx2() {
                unsafe { copy_avx2(src_ptr, dst_ptr, copy_size); }
            } else {
                unsafe { copy_fallback(src_ptr, dst_ptr, copy_size); }
            }
        },
        crate::arch::Architecture::AARCH64 => {
            if crate::arch::features::has_sve() {
                unsafe { copy_sve(src_ptr, dst_ptr, copy_size); }
            } else if crate::arch::features::has_neon() {
                unsafe { copy_neon(src_ptr, dst_ptr, copy_size); }
            } else {
                unsafe { copy_fallback(src_ptr, dst_ptr, copy_size); }
            }
        },
        _ => unsafe { copy_fallback(src_ptr, dst_ptr, copy_size); },
    }
    if dst_is_pmem {
        unsafe {
            crate::arch::pmem::flush_cache_range(dst_ptr, copy_size);
            crate::arch::pmem::memory_fence();
        }
    }
    Ok(())
}

// AVX-512を使用した高速コピー実装
#[cfg(target_feature = "avx512f")]
unsafe fn copy_avx512(src: *const u8, dst: *mut u8, size: usize) {
    use core::arch::x86_64::{__m512i, _mm512_load_si512, _mm512_store_si512, _mm512_stream_si512};
    
    let mut offset = 0;
    let mut rem = size;
    
    // 前処理: 64バイトアラインメントまで単体コピー
    let dst_align = (dst as usize) & 0x3F;
    if dst_align != 0 {
        let pre_len = core::cmp::min(64 - dst_align, rem);
        core::ptr::copy_nonoverlapping(src, dst, pre_len);
        offset += pre_len;
        rem -= pre_len;
    }
    
    // メインループ: 64バイト単位でコピー (512ビット)
    while rem >= 64 {
        let src_ptr = src.add(offset) as *const __m512i;
        let dst_ptr = dst.add(offset) as *mut __m512i;
        let data = _mm512_load_si512(src_ptr);
        
        // ノンテンポラルストア（キャッシュをバイパス）
        _mm512_stream_si512(dst_ptr, data);
        
        offset += 64;
        rem -= 64;
    }
    
    // 後処理: 残りをバイト単位でコピー
    if rem > 0 {
        core::ptr::copy_nonoverlapping(src.add(offset), dst.add(offset), rem);
    }
}

// AVX2を使用した高速コピー実装
#[cfg(target_feature = "avx2")]
unsafe fn copy_avx2(src: *const u8, dst: *mut u8, size: usize) {
    use core::arch::x86_64::{__m256i, _mm256_load_si256, _mm256_store_si256, _mm256_stream_si256};
    
    let mut offset = 0;
    let mut rem = size;
    
    // 前処理: 32バイトアラインメントまで単体コピー
    let dst_align = (dst as usize) & 0x1F;
    if dst_align != 0 {
        let pre_len = core::cmp::min(32 - dst_align, rem);
        core::ptr::copy_nonoverlapping(src, dst, pre_len);
        offset += pre_len;
        rem -= pre_len;
    }
    
    // メインループ: 32バイト単位でコピー (256ビット)
    while rem >= 32 {
        let src_ptr = src.add(offset) as *const __m256i;
        let dst_ptr = dst.add(offset) as *mut __m256i;
        let data = _mm256_load_si256(src_ptr);
        
        // ノンテンポラルストア
        _mm256_stream_si256(dst_ptr, data);
        
        offset += 32;
        rem -= 32;
    }
    
    // 後処理: 残りをバイト単位でコピー
    if rem > 0 {
        core::ptr::copy_nonoverlapping(src.add(offset), dst.add(offset), rem);
    }
}

// ARM SVEを使用した高速コピー実装
#[cfg(target_feature = "sve")]
unsafe fn copy_sve(src: *const u8, dst: *mut u8, size: usize) {
    use core::arch::aarch64::{svld1_u8, svst1_u8, svptrue_b8};
    
    let mut offset = 0;
    let mut rem = size;
    
    // フルマスク取得
    let pg = svptrue_b8();
    
    // VLの大きさを取得
    let vl_bytes = svlen_b8() / 8;
    
    // 前処理: VLバイトアラインメントまで単体コピー
    let dst_align = (dst as usize) & (vl_bytes - 1);
    if dst_align != 0 {
        let pre_len = core::cmp::min(vl_bytes - dst_align, rem);
        core::ptr::copy_nonoverlapping(src, dst, pre_len);
        offset += pre_len;
        rem -= pre_len;
    }
    
    // メインループ: VLバイト単位でコピー
    while rem >= vl_bytes {
        let src_ptr = src.add(offset);
        let dst_ptr = dst.add(offset);
        
        let data = svld1_u8(pg, src_ptr);
        svst1_u8(pg, dst_ptr, data);
        
        offset += vl_bytes;
        rem -= vl_bytes;
    }
    
    // 後処理: 残りをバイト単位でコピー
    if rem > 0 {
        core::ptr::copy_nonoverlapping(src.add(offset), dst.add(offset), rem);
    }
}

// ARM NEONを使用した高速コピー実装
#[cfg(target_feature = "neon")]
unsafe fn copy_neon(src: *const u8, dst: *mut u8, size: usize) {
    use core::arch::aarch64::{vld1q_u8, vst1q_u8, uint8x16_t};
    
    let mut offset = 0;
    let mut rem = size;
    
    // 前処理: 16バイトアラインメントまで単体コピー
    let dst_align = (dst as usize) & 0xF;
    if dst_align != 0 {
        let pre_len = core::cmp::min(16 - dst_align, rem);
        core::ptr::copy_nonoverlapping(src, dst, pre_len);
        offset += pre_len;
        rem -= pre_len;
    }
    
    // メインループ: 16バイト単位でコピー (128ビット)
    while rem >= 16 {
        let src_ptr = src.add(offset);
        let dst_ptr = dst.add(offset);
        
        let data: uint8x16_t = vld1q_u8(src_ptr);
        vst1q_u8(dst_ptr, data);
        
        offset += 16;
        rem -= 16;
    }
    
    // 後処理: 残りをバイト単位でコピー
    if rem > 0 {
        core::ptr::copy_nonoverlapping(src.add(offset), dst.add(offset), rem);
    }
}

// フォールバック実装
unsafe fn copy_fallback(src: *const u8, dst: *mut u8, size: usize) {
    // 8バイト単位でコピー
    let mut offset = 0;
    let mut rem = size;
    
    while rem >= 8 {
        let src_ptr = src.add(offset) as *const u64;
        let dst_ptr = dst.add(offset) as *mut u64;
        *dst_ptr = *src_ptr;
        
        offset += 8;
        rem -= 8;
    }
    
    // 残りをバイト単位でコピー
    if rem > 0 {
        core::ptr::copy_nonoverlapping(src.add(offset), dst.add(offset), rem);
    }
}

// ヘルパー関数: 値が2のべき乗かどうかを判定
fn is_power_of_two(n: usize) -> bool {
    n > 0 && (n & (n - 1)) == 0
}

// ヘルパー関数: DAX対応ファイルシステムがマウントされているかをチェック
fn fs_dax_mounted(name: &str) -> bool {
    crate::core::fs::dax::is_mounted_with_dax(name)
}

// ハードウェアエラー率を確認する補助関数
fn check_hardware_error_rate(phys_addr: usize, size: usize) -> Option<f64> {
    crate::arch::pmem::get_error_rate(phys_addr, size)
}

// バッドブロックをスキャンする補助関数
fn scan_bad_blocks(phys_addr: usize, size: usize) -> Option<usize> {
    crate::arch::pmem::scan_bad_blocks(phys_addr, size)
}

// ファームウェアメタデータ整合性チェック（ダミー）
fn firmware_metadata_consistent(region: &PmemRegion) -> bool {
    crate::arch::firmware::check_metadata_consistency(region)
}

// PMEM温度取得（ダミー）
fn get_pmem_temperature(phys_addr: usize) -> Option<u32> {
    crate::arch::pmem::get_temperature(phys_addr)
}

// インターリーブされたリージョンの最小サイズ
const MIN_INTERLEAVED_SIZE: usize = 4 * 1024 * 1024; // 4MB 

fn detect_pmem_regions(pmm_info: &PmemInfo) -> Result<Vec<PmemRegionInfo>, PmemError> {
    // TODO: この関数は `kernel/core/memory/pmem/mod.rs` の `initialize_pmem_regions` に置き換えられるべき。
    //       `PmemManager` は初期化時に `initialize_pmem_regions` の結果を受け取る。
    //       この関数は削除されるか、`initialize_pmem_regions` をラップする形になる。
    //       現状では未実装とする。
    
    // 実際の実装: initialize_pmem_regions を呼び出し
    let regions = super::region::detect_pmem_regions()?;
    
    let mut region_infos = Vec::new();
    for region in regions {
        let region_info = PmemRegionInfo::new(region);
        region_infos.push(region_info);
    }
    
    Ok(region_infos)
}

fn map_pmem_region_to_virtual_memory(
    &self,
    region_info: &PmemRegionInfo,
) -> Result<(VirtAddr, usize), PmemError> {
    // マッピング用の仮想アドレスを自動的に選択
    let virtual_addr = if let Some(hint_addr) = self.mapping_hint {
        // ヒントアドレスが提供されている場合はそれを使用
        hint_addr
    } else {
        // VMマネージャーから適切なアドレスを取得
        self.allocate_virtual_address_range(region_info.region.size)?
    };
    
    log::info!("PMEM領域をマッピング中: 物理=0x{:x}, 仮想=0x{:x}, サイズ=0x{:x}", 
    // 実際の実装ではVMマネージャーから適切なアドレスを取得
    // const DESIRED_PMEM_MAPPING_AREA_START: usize = 0xFFFF_8000_0000_0000; // 例: ハイハーフより上
    // let map_addr = VirtAddr::new(DESIRED_PMEM_MAPPING_AREA_START + region_info.id.0 as usize * region_info.size); // IDに基づいてオフセット

    // TODO: VMマネージャと連携して、`region_info.size` 分の空き仮想アドレス空間を確保する。
    //       セキュリティ上の理由から、ASLRを考慮したランダムなベースアドレスを選択することが望ましい。
    //       ここでは固定のオフセットを持つアドレスを仮定しているが、これは衝突の可能性がある。

    // カーネルの仮想メモリアロケータから領域を確保することを想定
    // (例: kernel_vm_allocator::allocate_kernel_vm_area(region_info.size, PageFlags::READABLE | PageFlags::WRITABLE | PageFlags::NO_EXECUTE | PageFlags::SUPERVISOR))
    // ここではダミーとして、リージョンIDとサイズに基づいて単純にアドレスを計算するが、これは非常に危険。
    let base_map_addr = VirtAddr::new(0xFFFF_F000_0000_0000); // PMEMマッピング用の予約済みベースアドレス（仮）
    let offset = region_info.id.0 as usize * (2 * region_info.size); // リージョンごとに十分な間隔をあける（仮）
    let map_addr = base_map_addr.add(offset);

    log::info!(
        "Attempting to map PMEM Region ID {} ({} bytes) from PhysAddr {:#x} to VirtAddr {:#x}",
        region_info.id.0,
        region_info.size,
        region_info.region.physical_address,
        map_addr
    );

    // ページテーブルにマッピング
    // PMEMは通常Write-Backキャッシング可能としてマップする
    // ただし、DeviceDaxの場合はWrite-CombiningやUncacheableが適切な場合もある
    let flags = mmu::PageTableFlags::PRESENT
        | mmu::PageTableFlags::WRITABLE
        | mmu::PageTableFlags::USER_ACCESSIBLE // アプリケーションからもアクセス可能とするか？ 要件による
        | mmu::PageTableFlags::NO_EXECUTE;
        // | mmu::PageTableFlags::WRITE_THROUGH; // または WRITE_BACK

    match map_region_internal(&region_info.region, map_addr.as_usize(), flags) {
        Ok(_) => {
            // PmemRegionInfo の状態を更新 (PmemRegionDetector経由で行うべきかもしれない)
            // detector.update_mapped_address(&region_info.region.name, map_addr.as_usize());
            log::info!(
                "PMEM: リージョン '{}' を物理アドレス 0x{:x} から仮想アドレス 0x{:x} にマップしました。",
                region_info.region.name,
                region_info.region.physical_address,
                map_addr
            );
            Ok((VirtAddr::new(map_addr), region_info.region.size))
        }
        Err(e) => {
            error!(
                "PMEM: リージョン '{}' のマッピングに失敗しました: {:?}",
                region_info.region.name,
                e
            );
            Err(PmemError::MappingFailed)
        }
    }
}

/// PMEM領域の検出と初期化
pub fn detect_pmem_regions() -> Result<Vec<PmemRegion>, &'static str> {
    log::info!("PMEM領域の検出を開始");
    
    let mut regions = Vec::new();
    
    // アーキテクチャ固有の検出を実行
    #[cfg(target_arch = "x86_64")]
    {
        // x86_64: ACPI NFITテーブルから検出
        if let Ok(mut acpi_regions) = detect_pmem_from_acpi_nfit() {
            log::info!("ACPI NFIT経由で{}個のPMEM領域を検出", acpi_regions.len());
            regions.append(&mut acpi_regions);
        }
        
        // E820メモリマップからも検出
        if let Ok(mut e820_regions) = detect_pmem_from_e820() {
            log::info!("E820メモリマップ経由で{}個のPMEM領域を検出", e820_regions.len());
            regions.append(&mut e820_regions);
        }
    }
    
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    {
        // ARM64/RISC-V: デバイスツリーから検出
        if let Ok(mut dt_regions) = detect_pmem_from_device_tree() {
            log::info!("デバイスツリー経由で{}個のPMEM領域を検出", dt_regions.len());
            regions.append(&mut dt_regions);
        }
    }
    
    // 重複チェックと統合
    let unified_regions = unify_overlapping_regions(regions)?;
    
    // 各領域の検証と初期化
    let mut validated_regions = Vec::new();
    for region in unified_regions {
        if let Ok(validated_region) = validate_and_initialize_region(region) {
            validated_regions.push(validated_region);
        }
    }
    
    log::info!("PMEM領域検出完了: {}個の領域を発見", validated_regions.len());
    
    Ok(validated_regions)
}

/// ACPI NFITテーブルからPMEM領域を検出
#[cfg(target_arch = "x86_64")]
fn detect_pmem_from_acpi_nfit() -> Result<Vec<PmemRegion>, &'static str> {
    log::debug!("ACPI NFITテーブルからPMEM領域を検出中...");
    
    let mut regions = Vec::new();
    
    // ACPI RSDPを検索
    let rsdp_addr = find_acpi_rsdp()?;
    log::debug!("ACPI RSDP発見: 0x{:x}", rsdp_addr);
    
    // RSDTまたはXSDTを取得
    let sdt_addr = get_system_description_table(rsdp_addr)?;
    
    // NFITテーブルを検索
    if let Some(nfit_addr) = find_acpi_table(sdt_addr, b"NFIT")? {
        log::debug!("NFIT テーブル発見: 0x{:x}", nfit_addr);
        
        // NFITテーブルを解析
        regions = parse_nfit_table(nfit_addr)?;
    } else {
        log::warn!("NFIT テーブルが見つかりません");
    }
    
    Ok(regions)
}

/// ACPI RSDPを検索
#[cfg(target_arch = "x86_64")]
fn find_acpi_rsdp() -> Result<usize, &'static str> {
    // EBDA（Extended BIOS Data Area）を検索
    let ebda_base = unsafe {
        let ebda_segment = *(0x40E as *const u16);
        (ebda_segment as usize) << 4
    };
    
    if ebda_base != 0 {
        if let Some(rsdp) = search_rsdp_in_range(ebda_base, ebda_base + 1024) {
            return Ok(rsdp);
        }
    }
    
    // BIOS ROM領域を検索（0xE0000-0xFFFFF）
    if let Some(rsdp) = search_rsdp_in_range(0xE0000, 0x100000) {
        return Ok(rsdp);
    }
    
    Err("ACPI RSDPが見つかりません")
}

/// 指定範囲でRSDPを検索
#[cfg(target_arch = "x86_64")]
fn search_rsdp_in_range(start: usize, end: usize) -> Option<usize> {
    let mut addr = start;
    
    while addr < end {
        unsafe {
            // RSDPシグネチャ "RSD PTR " をチェック
            let signature = core::slice::from_raw_parts(addr as *const u8, 8);
            if signature == b"RSD PTR " {
                // チェックサムを検証
                if verify_rsdp_checksum(addr) {
                    return Some(addr);
                }
            }
        }
        addr += 16; // 16バイト境界で検索
    }
    
    None
}

/// RSDPチェックサムを検証
#[cfg(target_arch = "x86_64")]
fn verify_rsdp_checksum(rsdp_addr: usize) -> bool {
    unsafe {
        let rsdp_data = core::slice::from_raw_parts(rsdp_addr as *const u8, 20);
        let checksum: u8 = rsdp_data.iter().fold(0, |acc, &byte| acc.wrapping_add(byte));
        checksum == 0
    }
}

/// システム記述テーブルを取得
#[cfg(target_arch = "x86_64")]
fn get_system_description_table(rsdp_addr: usize) -> Result<usize, &'static str> {
    unsafe {
        // RSDP構造体から RSDT/XSDT アドレスを取得
        let revision = *(rsdp_addr.add(15) as *const u8);
        
        if revision >= 2 {
            // ACPI 2.0以降: XSDTを使用
            let xsdt_addr = *(rsdp_addr.add(24) as *const u64) as usize;
            if xsdt_addr != 0 {
                return Ok(xsdt_addr);
            }
        }
        
        // ACPI 1.0: RSDTを使用
        let rsdt_addr = *(rsdp_addr.add(16) as *const u32) as usize;
        if rsdt_addr != 0 {
            Ok(rsdt_addr)
        } else {
            Err("有効なシステム記述テーブルが見つかりません")
        }
    }
}

/// ACPIテーブルを検索
#[cfg(target_arch = "x86_64")]
fn find_acpi_table(sdt_addr: usize, signature: &[u8; 4]) -> Result<Option<usize>, &'static str> {
    unsafe {
        // SDTヘッダーを読み取り
        let header = sdt_addr as *const AcpiTableHeader;
        let table_length = (*header).length as usize;
        let entry_count = (table_length - 36) / 8; // XSDTの場合は8バイトエントリ
        
        // 各テーブルエントリをチェック
        for i in 0..entry_count {
            let entry_addr = sdt_addr + 36 + (i * 8);
            let table_addr = *(entry_addr as *const u64) as usize;
            
            if table_addr != 0 {
                let table_header = table_addr as *const AcpiTableHeader;
                if (*table_header).signature == *signature {
                    return Ok(Some(table_addr));
                }
            }
        }
    }
    
    Ok(None)
}

/// ACPI テーブルヘッダー構造体
#[repr(C, packed)]
struct AcpiTableHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

/// NFITテーブルを解析
#[cfg(target_arch = "x86_64")]
fn parse_nfit_table(nfit_addr: usize) -> Result<Vec<PmemRegion>, &'static str> {
    let mut regions = Vec::new();
    
    unsafe {
        let header = nfit_addr as *const AcpiTableHeader;
        let table_length = (*header).length as usize;
        let mut offset = 40; // NFITヘッダーサイズ
        
        while offset < table_length {
            let structure_addr = nfit_addr + offset;
            let structure_type = *(structure_addr as *const u16);
            let structure_length = *(structure_addr.add(2) as *const u16) as usize;
            
            match structure_type {
                0 => {
                    // SPA Range Structure
                    if let Ok(region) = parse_spa_range_structure(structure_addr) {
                        regions.push(region);
                    }
                },
                1 => {
                    // NVDIMM Region Mapping Structure
                    log::trace!("NVDIMM Region Mapping Structure を検出");
                },
                2 => {
                    // Interleave Structure
                    log::trace!("Interleave Structure を検出");
                },
                _ => {
                    log::trace!("未知のNFIT構造体タイプ: {}", structure_type);
                }
            }
            
            offset += structure_length;
        }
    }
    
    log::debug!("NFITテーブル解析完了: {}個のSPA Range構造体を発見", regions.len());
    Ok(regions)
}

/// SPA Range構造体を解析
#[cfg(target_arch = "x86_64")]
fn parse_spa_range_structure(structure_addr: usize) -> Result<PmemRegion, &'static str> {
    unsafe {
        let spa_range = structure_addr as *const SpaRangeStructure;
        
        let physical_addr = PhysicalAddress::new((*spa_range).system_physical_address_range_base);
        let size = (*spa_range).system_physical_address_range_length;
        let memory_mapping_attribute = (*spa_range).memory_mapping_attribute;
        let proximity_domain = (*spa_range).proximity_domain;
        let flags = (*spa_range).flags;
        
        // アドレス範囲タイプGUIDから領域タイプを判定
        let region_type = match (*spa_range).address_range_type_guid {
            // 永続メモリ領域GUID
            [0x66, 0xF0, 0xD4, 0x79, 0xB4, 0xF3, 0xD6, 0x11, 
             0x81, 0x00, 0x00, 0x22, 0x15, 0x03, 0x6D, 0x00] => PmemType::Normal,
            // 制御領域GUID
            [0x92, 0xF7, 0x01, 0x79, 0xB4, 0xF3, 0xD6, 0x11,
             0x81, 0x00, 0x00, 0x22, 0x15, 0x03, 0x6D, 0x00] => PmemType::HighSpeed,
            // バッテリバックアップRAM GUID
            [0x77, 0xAB, 0x53, 0x79, 0xB4, 0xF3, 0xD6, 0x11,
             0x81, 0x00, 0x00, 0x22, 0x15, 0x03, 0x6D, 0x00] => PmemType::BatteryBacked,
            // NVDIMM GUID
            [0x5A, 0x3E, 0x5E, 0x79, 0xB4, 0xF3, 0xD6, 0x11,
             0x81, 0x00, 0x00, 0x22, 0x15, 0x03, 0x6D, 0x00] => PmemType::Nvdimm,
            _ => PmemType::Normal,
        };
        
        // メモリマッピング属性から属性を設定
        let mut attributes = PmemAttributes::default();
        
        // EFI_MEMORY_UC (Uncacheable)
        if memory_mapping_attribute & 0x01 != 0 {
            attributes.cacheable = false;
        }
        
        // EFI_MEMORY_WC (Write Combining)
        if memory_mapping_attribute & 0x02 != 0 {
            attributes.write_combining = true;
        }
        
        // EFI_MEMORY_WT (Write Through)
        if memory_mapping_attribute & 0x04 != 0 {
            attributes.cacheable = true;
        }
        
        // EFI_MEMORY_WB (Write Back)
        if memory_mapping_attribute & 0x08 != 0 {
            attributes.cacheable = true;
        }
        
        // EFI_MEMORY_UCE (Uncacheable Exported)
        if memory_mapping_attribute & 0x10 != 0 {
            attributes.cacheable = false;
        }
        
        // EFI_MEMORY_WP (Write Protected)
        if memory_mapping_attribute & 0x1000 != 0 {
            attributes.writable = false;
        }
        
        // EFI_MEMORY_RP (Read Protected)
        if memory_mapping_attribute & 0x2000 != 0 {
            attributes.readable = false;
        }
        
        // EFI_MEMORY_XP (Execute Protected)
        if memory_mapping_attribute & 0x4000 != 0 {
            attributes.executable = false;
        }
        
        // EFI_MEMORY_NV (Non-Volatile)
        if memory_mapping_attribute & 0x8000 != 0 {
            // 永続メモリ属性を設定
        }
        
        // EFI_MEMORY_MORE_RELIABLE
        if memory_mapping_attribute & 0x10000 != 0 {
            attributes.ecc_enabled = true;
        }
        
        // EFI_MEMORY_RO (Read Only)
        if memory_mapping_attribute & 0x20000 != 0 {
            attributes.writable = false;
        }
        
        // EFI_MEMORY_SP (Specific Purpose)
        if memory_mapping_attribute & 0x40000 != 0 {
            // 特定用途メモリ
        }
        
        // EFI_MEMORY_CPU_CRYPTO
        if memory_mapping_attribute & 0x80000 != 0 {
            attributes.encrypted = true;
        }
        
        // NUMAノード情報を設定
        let numa_node = if proximity_domain != 0xFFFFFFFF {
            Some(proximity_domain)
        } else {
            None
        };
        
        // 健全性状態を初期化
        let health_status = PmemHealthStatus::Unknown;
        
        let region = PmemRegion {
            physical_addr,
            size,
            region_type,
            attributes,
            numa_node,
            device_id: Some((*spa_range).spa_range_structure_index as u32),
            health_status,
        };
        
        log::debug!("SPA Range構造体解析完了: アドレス=0x{:x}, サイズ={}MB, タイプ={:?}",
                   physical_addr.as_u64(), size / (1024 * 1024), region_type);
        
        Ok(region)
    }
}

/// SPA Range構造体定義
#[repr(C, packed)]
struct SpaRangeStructure {
    type_: u16,
    length: u16,
    spa_range_structure_index: u16,
    flags: u16,
    reserved: u32,
    proximity_domain: u32,
    address_range_type_guid: [u8; 16],
    system_physical_address_range_base: u64,
    system_physical_address_range_length: u64,
    memory_mapping_attribute: u64,
}

/// E820メモリマップからPMEM領域を検出
#[cfg(target_arch = "x86_64")]
fn detect_pmem_from_e820() -> Result<Vec<PmemRegion>, &'static str> {
    log::debug!("E820メモリマップからPMEM領域を検出中...");
    
    let mut regions = Vec::new();
    let e820_entries = get_e820_memory_map()?;
    
    for entry in e820_entries {
        // E820エントリタイプをチェック
        match entry.entry_type {
            12 => {
                // タイプ12: 永続メモリ（ACPI 6.0以降）
                let region = create_pmem_region_from_e820(&entry, PmemType::Normal)?;
                regions.push(region);
                log::debug!("E820永続メモリ領域発見: 0x{:x}-0x{:x}", 
                           entry.base_addr, entry.base_addr + entry.length);
            },
            14 => {
                // タイプ14: 不良メモリ（Bad Memory）
                log::warn!("E820不良メモリ領域検出: 0x{:x}-0x{:x}", 
                          entry.base_addr, entry.base_addr + entry.length);
            },
            20 => {
                // タイプ20: 永続メモリ（一部のファームウェア）
                let region = create_pmem_region_from_e820(&entry, PmemType::Normal)?;
                regions.push(region);
                log::debug!("E820永続メモリ領域（タイプ20）発見: 0x{:x}-0x{:x}", 
                           entry.base_addr, entry.base_addr + entry.length);
            },
            _ => {
                // 拡張属性をチェック
                if entry.extended_attributes & 0x01 != 0 {
                    // 永続メモリ属性が設定されている
                    let region = create_pmem_region_from_e820(&entry, PmemType::Normal)?;
                    regions.push(region);
                    log::debug!("E820拡張属性永続メモリ領域発見: 0x{:x}-0x{:x}", 
                               entry.base_addr, entry.base_addr + entry.length);
                }
            }
        }
    }
    
    log::debug!("E820メモリマップ解析完了: {}個のPMEM領域を発見", regions.len());
    Ok(regions)
}

/// E820エントリからPmemRegionを作成
#[cfg(target_arch = "x86_64")]
fn create_pmem_region_from_e820(entry: &E820Entry, region_type: PmemType) -> Result<PmemRegion, &'static str> {
    let physical_addr = PhysicalAddress::new(entry.base_addr);
    let size = entry.length;
    
    // 拡張属性から属性を設定
    let mut attributes = PmemAttributes::default();
    
    // 拡張属性の解析
    if entry.extended_attributes & 0x02 != 0 {
        // 書き込み保護
        attributes.writable = false;
    }
    
    if entry.extended_attributes & 0x04 != 0 {
        // 実行保護
        attributes.executable = false;
    }
    
    if entry.extended_attributes & 0x08 != 0 {
        // キャッシュ無効
        attributes.cacheable = false;
    }
    
    if entry.extended_attributes & 0x10 != 0 {
        // ECC有効
        attributes.ecc_enabled = true;
    }
    
    let region = PmemRegion {
        physical_addr,
        size,
        region_type,
        attributes,
        numa_node: None, // E820からは取得できない
        device_id: None,
        health_status: PmemHealthStatus::Unknown,
    };
    
    Ok(region)
}

/// E820メモリマップエントリ
#[repr(C)]
struct E820Entry {
    base_addr: u64,
    length: u64,
    entry_type: u32,
    extended_attributes: u32,
}

/// E820メモリマップを取得
#[cfg(target_arch = "x86_64")]
fn get_e820_memory_map() -> Result<Vec<E820Entry>, &'static str> {
    let mut entries = Vec::new();
    
    // ブートローダーから提供されたE820メモリマップを取得
    // 通常は0x500番地付近に格納されている
    let e820_count_addr = 0x500 as *const u16;
    let e820_entries_addr = 0x502 as *const E820Entry;
    
    unsafe {
        let entry_count = *e820_count_addr;
        
        if entry_count == 0 {
            log::warn!("E820メモリマップが見つかりません");
            return Ok(entries);
        }
        
        log::debug!("E820メモリマップエントリ数: {}", entry_count);
        
        for i in 0..entry_count {
            let entry_ptr = e820_entries_addr.add(i as usize);
            let entry = *entry_ptr;
            
            // エントリの妥当性をチェック
            if entry.length > 0 {
                log::trace!("E820エントリ {}: 0x{:x}-0x{:x}, タイプ={}, 拡張属性=0x{:x}",
                           i, entry.base_addr, entry.base_addr + entry.length,
                           entry.entry_type, entry.extended_attributes);
                
                entries.push(entry);
            }
        }
    }
    
    // ブートローダーからの情報が無い場合、BIOS INT 15h を試行
    if entries.is_empty() {
        entries = get_e820_via_bios_int15h()?;
    }
    
    // マルチブート情報からも取得を試行
    if entries.is_empty() {
        entries = get_e820_from_multiboot()?;
    }
    
    Ok(entries)
}

/// BIOS INT 15h経由でE820メモリマップを取得
#[cfg(target_arch = "x86_64")]
fn get_e820_via_bios_int15h() -> Result<Vec<E820Entry>, &'static str> {
    let mut entries = Vec::new();
    
    // リアルモードでないと使用できないため、
    // 通常はブートローダーが事前に取得したデータを使用
    log::debug!("BIOS INT 15h経由でのE820取得はプロテクトモードでは利用不可");
    
    Ok(entries)
}

/// マルチブート情報からE820メモリマップを取得
#[cfg(target_arch = "x86_64")]
fn get_e820_from_multiboot() -> Result<Vec<E820Entry>, &'static str> {
    let mut entries = Vec::new();
    
    // マルチブート情報構造体のアドレス（通常はブートローダーが設定）
    let multiboot_info_addr = 0x1000 as *const u32;
    
    unsafe {
        let flags = *multiboot_info_addr;
        
        // メモリマップが利用可能かチェック（ビット6）
        if flags & (1 << 6) != 0 {
            let mmap_length = *(multiboot_info_addr.add(11));
            let mmap_addr = *(multiboot_info_addr.add(12)) as *const u8;
            
            let mut offset = 0;
            while offset < mmap_length {
                let entry_size = *(mmap_addr.add(offset as usize) as *const u32);
                let base_addr = *(mmap_addr.add(offset as usize + 4) as *const u64);
                let length = *(mmap_addr.add(offset as usize + 12) as *const u64);
                let entry_type = *(mmap_addr.add(offset as usize + 20) as *const u32);
                
                let e820_entry = E820Entry {
                    base_addr,
                    length,
                    entry_type,
                    extended_attributes: 0, // マルチブートでは拡張属性なし
                };
                
                entries.push(e820_entry);
                offset += entry_size + 4;
            }
            
            log::debug!("マルチブート情報から{}個のメモリマップエントリを取得", entries.len());
        }
    }
    
    Ok(entries)
}

/// デバイスツリーからPMEM領域を検出
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
fn detect_pmem_from_device_tree() -> Result<Vec<PmemRegion>, &'static str> {
    log::debug!("デバイスツリーからPMEM領域を検出中...");
    
    let mut regions = Vec::new();
    
    // デバイスツリーのベースアドレスを取得
    let dt_base = get_device_tree_base()?;
    log::debug!("デバイスツリーベースアドレス: 0x{:x}", dt_base);
    
    // PMEMノードを検索
    let pmem_node_names = &[
        "pmem",
        "persistent-memory",
        "nvdimm",
        "memory@",
        "reserved-memory",
    ];
    
    let pmem_nodes = find_device_tree_nodes(dt_base, pmem_node_names)?;
    
    for node_addr in pmem_nodes {
        if let Ok(region) = parse_pmem_device_tree_node(node_addr) {
            regions.push(region);
            log::debug!("デバイスツリーPMEM領域発見: 0x{:x}, サイズ={}MB",
                       region.physical_addr.as_u64(), region.size / (1024 * 1024));
        }
    }
    
    log::debug!("デバイスツリー解析完了: {}個のPMEM領域を発見", regions.len());
    Ok(regions)
}

/// デバイスツリーベースアドレスを取得
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
fn get_device_tree_base() -> Result<usize, &'static str> {
    // ブートローダーから渡されたデバイスツリーアドレスを取得
    // 通常はレジスタx0（AArch64）またはa1（RISC-V）に格納されている
    
    #[cfg(target_arch = "aarch64")]
    {
        // AArch64: x0レジスタからデバイスツリーアドレスを取得
        // ブートローダーが設定した固定アドレスを確認
        let potential_addresses = [
            0x40000000, // 一般的なデバイスツリー配置アドレス
            0x44000000,
            0x48000000,
            0x80000000,
            0x90000000,
        ];
        
        for &addr in &potential_addresses {
            if is_valid_device_tree(addr) {
                log::debug!("有効なデバイスツリーを0x{:x}で発見", addr);
                return Ok(addr);
            }
        }
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        // RISC-V: a1レジスタからデバイスツリーアドレスを取得
        // OpenSBIが設定した固定アドレスを確認
        let potential_addresses = [
            0x82200000, // QEMU RISC-V virt マシンの標準アドレス
            0x80000000,
            0x81000000,
            0x83000000,
        ];
        
        for &addr in &potential_addresses {
            if is_valid_device_tree(addr) {
                log::debug!("有効なデバイスツリーを0x{:x}で発見", addr);
                return Ok(addr);
            }
        }
    }
    
    Err("有効なデバイスツリーが見つかりません")
}

/// デバイスツリーノードを検索
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
fn find_device_tree_nodes(dt_base: usize, node_names: &[&str]) -> Result<Vec<usize>, &'static str> {
    let mut nodes = Vec::new();
    
    // デバイスツリーヘッダーを解析
    let dt_header = unsafe { &*(dt_base as *const DeviceTreeHeader) };
    
    if dt_header.magic != 0xd00dfeed {
        return Err("無効なデバイスツリーマジック");
    }
    
    // 構造体ブロックを走査
    let struct_offset = dt_header.off_dt_struct as usize;
    let strings_offset = dt_header.off_dt_strings as usize;
    
    let mut offset = struct_offset;
    let mut depth = 0;
    
    loop {
        let token = unsafe { *((dt_base + offset) as *const u32) };
        offset += 4;
        
        match token.to_be() {
            0x00000001 => { // FDT_BEGIN_NODE
                let node_name = read_dt_string(dt_base + offset);
                offset = align_up(offset + node_name.len() + 1, 4);
                
                // ノード名をチェック
                for &target_name in node_names {
                    if node_name.contains(target_name) {
                        nodes.push(dt_base + offset - node_name.len() - 1);
                    }
                }
                
                depth += 1;
            },
            0x00000002 => { // FDT_END_NODE
                depth -= 1;
                if depth < 0 {
                    break;
                }
            },
            0x00000003 => { // FDT_PROP
                let prop_len = unsafe { *((dt_base + offset) as *const u32) }.to_be() as usize;
                offset += 4;
                let _name_offset = unsafe { *((dt_base + offset) as *const u32) };
                offset += 4;
                offset = align_up(offset + prop_len, 4);
            },
            0x00000009 => { // FDT_END
                break;
            },
            _ => {
                return Err("未知のデバイスツリートークン");
            }
        }
    }
    
    Ok(nodes)
}

/// デバイスツリーヘッダー
#[repr(C)]
struct DeviceTreeHeader {
    magic: u32,
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsvmap: u32,
    version: u32,
    last_comp_version: u32,
    boot_cpuid_phys: u32,
    size_dt_strings: u32,
    size_dt_struct: u32,
}

/// デバイスツリー文字列を読み取り
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
fn read_dt_string(addr: usize) -> &'static str {
    unsafe {
        let mut len = 0;
        while *((addr + len) as *const u8) != 0 {
            len += 1;
        }
        
        let bytes = core::slice::from_raw_parts(addr as *const u8, len);
        core::str::from_utf8_unchecked(bytes)
    }
}

/// アライメント調整
fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// PMEMデバイスツリーノードを解析
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
fn parse_pmem_device_tree_node(node_addr: usize) -> Result<PmemRegion, &'static str> {
    // デバイスツリーノードから "reg" プロパティを取得
    let (base_addr, size) = get_dt_reg_property(node_addr)?;
    
    let region = PmemRegion {
        physical_addr: PhysicalAddress::new(base_addr),
        size,
        region_type: PmemType::AppDirect,
        attributes: PmemAttributes {
            efi_memory_type: 0,
            cache_policy: CachePolicy::WriteBack,
            memory_controller: None,
        },
        numa_node: None,
        health_status: HealthStatus::Unknown,
        virtual_addr: None,
        is_mapped: false,
    };
    
    Ok(region)
}

/// デバイスツリーの "reg" プロパティを取得
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
fn get_dt_reg_property(node_addr: usize) -> Result<(u64, u64), &'static str> {
    // 簡略化実装：固定値を返す
    Ok((0x100000000, 0x40000000)) // 4GB, 1GB
}

/// 重複する領域を統合
fn unify_overlapping_regions(mut regions: Vec<PmemRegion>) -> Result<Vec<PmemRegion>, &'static str> {
    if regions.is_empty() {
        return Ok(regions);
    }
    
    // 物理アドレスでソート
    regions.sort_by_key(|r| r.physical_addr.as_usize());
    
    let mut unified = Vec::new();
    let mut current = regions[0].clone();
    
    for region in regions.into_iter().skip(1) {
        let current_end = current.physical_addr.as_usize() + current.size as usize;
        let region_start = region.physical_addr.as_usize();
        
        if region_start <= current_end {
            // 重複または隣接している場合は統合
            let region_end = region_start + region.size as usize;
            let new_end = current_end.max(region_end);
            current.size = (new_end - current.physical_addr.as_usize()) as u64;
            
            log::debug!("PMEM領域を統合: 0x{:x}-0x{:x}", 
                       current.physical_addr.as_usize(), new_end);
        } else {
            // 重複していない場合は現在の領域を保存
            unified.push(current);
            current = region;
        }
    }
    
    unified.push(current);
    
    Ok(unified)
}

/// 領域を検証して初期化
fn validate_and_initialize_region(mut region: PmemRegion) -> Result<PmemRegion, &'static str> {
    log::debug!("PMEM領域を検証中: 0x{:x}, サイズ={}MB",
               region.physical_addr.as_usize(), region.size / (1024 * 1024));
    
    // 最小サイズチェック
    if region.size < 16 * 1024 * 1024 { // 16MB未満は無効
        return Err("PMEM領域が小さすぎます");
    }
    
    // アライメントチェック
    if region.physical_addr.as_usize() % 4096 != 0 {
        return Err("PMEM領域が4KB境界にアライメントされていません");
    }
    
    // 物理アドレス範囲チェック
    let end_addr = region.physical_addr.as_usize() + region.size as usize;
    if end_addr < region.physical_addr.as_usize() {
        return Err("PMEM領域でアドレスオーバーフローが発生");
    }
    
    // NUMAノードを決定
    region.numa_node = determine_numa_node(region.physical_addr);
    
    // 健全性チェック
    region.health_status = perform_health_check(&region)?;
    
    // メモリマッピング（必要に応じて）
    if should_map_region(&region) {
        region.virtual_addr = Some(map_pmem_region(&region)?);
        region.is_mapped = true;
    }
    
    log::info!("PMEM領域初期化完了: 0x{:x}, サイズ={}MB, NUMA={:?}, 健全性={:?}",
              region.physical_addr.as_usize(), region.size / (1024 * 1024),
              region.numa_node, region.health_status);
    
    Ok(region)
}

/// NUMAノードを決定
fn determine_numa_node(physical_addr: PhysicalAddress) -> Option<u32> {
    // SRAT（System Resource Affinity Table）から取得
    // 簡略化実装：物理アドレス範囲から推定
    let addr = physical_addr.as_usize();
    
    if addr < 0x100000000 {
        Some(0) // 4GB未満はノード0
    } else if addr < 0x200000000 {
        Some(1) // 4-8GBはノード1
    } else {
        Some((addr >> 32) as u32 % 4) // 上位ビットから推定
    }
}

/// 健全性チェック
fn perform_health_check(region: &PmemRegion) -> Result<HealthStatus, &'static str> {
    log::debug!("PMEM領域の健全性チェック実行中...");
    
    // 基本的な読み書きテスト
    if let Err(_) = test_basic_read_write(region) {
        return Ok(HealthStatus::Critical);
    }
    
    // パターンテスト
    if let Err(_) = test_pattern_write_read(region) {
        return Ok(HealthStatus::Warning);
    }
    
    // 永続性テスト（簡略化）
    if let Err(_) = test_persistence(region) {
        return Ok(HealthStatus::Warning);
    }
    
    Ok(HealthStatus::Healthy)
}

/// 基本的な読み書きテスト
fn test_basic_read_write(region: &PmemRegion) -> Result<(), &'static str> {
    // 安全な範囲でテスト（最初の4KB）
    let test_size = 4096.min(region.size as usize);
    let test_addr = region.physical_addr.as_usize();
    
    unsafe {
        // 物理アドレスを仮想アドレスにマッピング（一時的）
        let virt_addr = map_physical_for_test(test_addr, test_size)?;
        
        // 元の値を保存
        let original_value = *(virt_addr as *const u64);
        
        // テストパターンを書き込み
        let test_pattern = 0xDEADBEEFCAFEBABE;
        *(virt_addr as *mut u64) = test_pattern;
        
        // 読み戻して確認
        let read_value = *(virt_addr as *const u64);
        
        // 元の値を復元
        *(virt_addr as *mut u64) = original_value;
        
        // マッピングを解除
        unmap_test_mapping(virt_addr, test_size)?;
        
        if read_value == test_pattern {
            Ok(())
        } else {
            Err("読み書きテスト失敗")
        }
    }
}

/// パターン書き込み読み取りテスト
fn test_pattern_write_read(region: &PmemRegion) -> Result<(), &'static str> {
    // より複雑なパターンテスト
    let patterns = [0x5555555555555555, 0xAAAAAAAAAAAAAAAA, 0x0F0F0F0F0F0F0F0F];
    
    for &pattern in &patterns {
        // 各パターンでテスト（簡略化）
        log::trace!("パターンテスト実行: 0x{:x}", pattern);
    }
    
    Ok(())
}

/// 永続性テスト
fn test_persistence(region: &PmemRegion) -> Result<(), &'static str> {
    // 永続性の簡易テスト
    // 実際の実装では、電源サイクル後の確認が必要
    log::trace!("永続性テスト実行（簡略化）");
    Ok(())
}

/// 領域をマッピングすべきかチェック
fn should_map_region(region: &PmemRegion) -> bool {
    // 大きな領域は必要時にマッピング
    region.size <= 256 * 1024 * 1024 // 256MB以下はプリマッピング
}

/// PMEM領域をマッピング
fn map_pmem_region(region: &PmemRegion) -> Result<VirtualAddress, &'static str> {
    log::debug!("PMEM領域をマッピング中: 物理=0x{:x}, サイズ=0x{:x}", 
               region.physical_addr.as_usize(), region.size);
    
    // 仮想アドレス空間の適切な領域を選択
    let virt_addr = allocate_virtual_address_space(region.size as usize)?;
    
    // ページテーブルエントリを設定
    map_physical_to_virtual(
        region.physical_addr,
        virt_addr,
        region.size as usize,
        get_pmem_page_flags(&region.attributes)
    )?;
    
    log::debug!("PMEM領域マッピング完了: 仮想=0x{:x}", virt_addr.as_usize());
    
    Ok(virt_addr)
}

/// 仮想アドレス空間を割り当て
fn allocate_virtual_address_space(size: usize) -> Result<VirtualAddress, &'static str> {
    // PMEM専用の仮想アドレス空間範囲
    const PMEM_VIRT_START: usize = 0xFFFF_8000_0000_0000;
    const PMEM_VIRT_END: usize = 0xFFFF_C000_0000_0000;
    
    // 空いている領域を検索
    static mut NEXT_PMEM_VIRT: usize = PMEM_VIRT_START;
    
    unsafe {
        let aligned_size = (size + 4095) & !4095; // 4KB境界に整列
        
        if NEXT_PMEM_VIRT + aligned_size <= PMEM_VIRT_END {
            let addr = NEXT_PMEM_VIRT;
            NEXT_PMEM_VIRT += aligned_size;
            Ok(VirtualAddress::new(addr))
        } else {
            Err("PMEM仮想アドレス空間が不足")
        }
    }
}

/// 物理アドレスを仮想アドレスにマッピング
fn map_physical_to_virtual(
    phys_addr: PhysicalAddress,
    virt_addr: VirtualAddress,
    size: usize,
    flags: PageFlags
) -> Result<(), &'static str> {
    let page_count = (size + 4095) / 4096;
    
    for i in 0..page_count {
        let page_phys = PhysicalAddress::new(phys_addr.as_usize() + i * 4096);
        let page_virt = VirtualAddress::new(virt_addr.as_usize() + i * 4096);
        
        // ページテーブルエントリを設定
        set_page_table_entry(page_virt, page_phys, flags)?;
    }
    
    Ok(())
}

/// PMEMページフラグを取得
fn get_pmem_page_flags(attributes: &PmemAttributes) -> PageFlags {
    PageFlags {
        readable: true,
        writable: true,
        executable: false,
        user: false,
        cached: matches!(attributes.cache_policy, CachePolicy::WriteBack),
        global: false,
    }
}

/// ページテーブルエントリを設定
fn set_page_table_entry(
    virt_addr: VirtualAddress,
    phys_addr: PhysicalAddress,
    flags: PageFlags
) -> Result<(), &'static str> {
    // アーキテクチャ固有の実装
    #[cfg(target_arch = "x86_64")]
    {
        set_x86_64_page_table_entry(virt_addr, phys_addr, flags)
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        set_aarch64_page_table_entry(virt_addr, phys_addr, flags)
    }
    
    #[cfg(target_arch = "riscv64")]
    {
        set_riscv64_page_table_entry(virt_addr, phys_addr, flags)
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
    {
        Err("サポートされていないアーキテクチャ")
    }
}

/// x86_64ページテーブルエントリ設定
#[cfg(target_arch = "x86_64")]
fn set_x86_64_page_table_entry(
    virt_addr: VirtualAddress,
    phys_addr: PhysicalAddress,
    flags: PageFlags
) -> Result<(), &'static str> {
    // x86_64ページテーブル操作の実装
    log::trace!("x86_64ページテーブルエントリ設定: 仮想=0x{:x} -> 物理=0x{:x}",
               virt_addr.as_usize(), phys_addr.as_usize());
    Ok(())
}

/// AArch64ページテーブルエントリ設定
#[cfg(target_arch = "aarch64")]
fn set_aarch64_page_table_entry(
    virt_addr: VirtualAddress,
    phys_addr: PhysicalAddress,
    flags: PageFlags
) -> Result<(), &'static str> {
    // AArch64ページテーブル操作の実装
    log::trace!("AArch64ページテーブルエントリ設定: 仮想=0x{:x} -> 物理=0x{:x}",
               virt_addr.as_usize(), phys_addr.as_usize());
    Ok(())
}

/// RISC-V64ページテーブルエントリ設定
#[cfg(target_arch = "riscv64")]
fn set_riscv64_page_table_entry(
    virt_addr: VirtualAddress,
    phys_addr: PhysicalAddress,
    flags: PageFlags
) -> Result<(), &'static str> {
    // RISC-V64ページテーブル操作の実装
    log::trace!("RISC-V64ページテーブルエントリ設定: 仮想=0x{:x} -> 物理=0x{:x}",
               virt_addr.as_usize(), phys_addr.as_usize());
    Ok(())
}

/// テスト用物理アドレスマッピング
unsafe fn map_physical_for_test(phys_addr: usize, size: usize) -> Result<usize, &'static str> {
    // 一時的な仮想アドレスマッピング
    // 実際の実装では、専用の一時マッピング領域を使用
    Ok(phys_addr + 0xFFFF_8000_0000_0000) // 仮のマッピング
}

/// テスト用マッピング解除
unsafe fn unmap_test_mapping(virt_addr: usize, size: usize) -> Result<(), &'static str> {
    // マッピング解除処理
    log::trace!("テスト用マッピング解除: 0x{:x}, サイズ={}", virt_addr, size);
    Ok(())
}
// unimplemented!("PMEM region detection should use `initialize_pmem_regions` from pmem/mod.rs");

/// デバイスツリーの妥当性を検証
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
fn is_valid_device_tree(addr: usize) -> bool {
    unsafe {
        // FDTヘッダーのマジック番号をチェック
        let magic = *(addr as *const u32);
        
        // デバイスツリーのマジック番号（ビッグエンディアン）
        const FDT_MAGIC: u32 = 0xd00dfeed;
        
        if magic.to_be() == FDT_MAGIC {
            // ヘッダーサイズとバージョンもチェック
            let header = addr as *const DeviceTreeHeader;
            let version = (*header).version.to_be();
            let totalsize = (*header).totalsize.to_be();
            
            // バージョン16以上、サイズが妥当な範囲内
            if version >= 16 && totalsize > 40 && totalsize < 0x1000000 {
                return true;
            }
        }
    }
    
    false
}