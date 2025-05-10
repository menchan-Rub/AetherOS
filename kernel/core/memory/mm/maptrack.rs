// AetherOS マップトラッキングモジュール
//
// このモジュールはメモリマッピングの追跡を行い、メモリ領域の管理を担当します。
// - 仮想アドレス空間のマッピングを追跡
// - メモリ保護属性の管理
// - マッピングのライフサイクル管理

use crate::core::memory::addr::{VirtAddr, PhysAddr};
use crate::core::memory::page::{Page, PageSize, PageMapper, NORMAL_PAGE_SIZE};
use crate::core::sync::{RwLock, Mutex};
use crate::core::collections::BTreeMap;
use alloc::vec::Vec;
use core::ops::Range;

/// メモリ保護属性
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protection {
    /// 読み取り許可
    pub read: bool,
    /// 書き込み許可
    pub write: bool,
    /// 実行許可
    pub execute: bool,
    /// ユーザーモードからのアクセス許可
    pub user: bool,
    /// キャッシュ属性
    pub cache_policy: CachePolicy,
}

impl Protection {
    /// 読み込み専用保護属性を作成
    pub fn read_only() -> Self {
        Protection {
            read: true,
            write: false,
            execute: false,
            user: false,
            cache_policy: CachePolicy::Cached,
        }
    }

    /// 読み書き可能な保護属性を作成
    pub fn read_write() -> Self {
        Protection {
            read: true,
            write: true,
            execute: false,
            user: false,
            cache_policy: CachePolicy::Cached,
        }
    }

    /// カーネルコード用の保護属性を作成
    pub fn kernel_code() -> Self {
        Protection {
            read: true,
            write: false,
            execute: true,
            user: false,
            cache_policy: CachePolicy::Cached,
        }
    }

    /// カーネルデータ用の保護属性を作成
    pub fn kernel_data() -> Self {
        Protection {
            read: true,
            write: true,
            execute: false,
            user: false,
            cache_policy: CachePolicy::Cached,
        }
    }

    /// ユーザーコード用の保護属性を作成
    pub fn user_code() -> Self {
        Protection {
            read: true,
            write: false,
            execute: true,
            user: true,
            cache_policy: CachePolicy::Cached,
        }
    }

    /// ユーザーデータ用の保護属性を作成
    pub fn user_data() -> Self {
        Protection {
            read: true,
            write: true,
            execute: false,
            user: true,
            cache_policy: CachePolicy::Cached,
        }
    }

    /// デバイスメモリ用の保護属性を作成
    pub fn device_memory() -> Self {
        Protection {
            read: true,
            write: true,
            execute: false,
            user: false,
            cache_policy: CachePolicy::Uncached,
        }
    }
}

/// キャッシュポリシー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    /// 通常のキャッシュ可能メモリ
    Cached,
    /// キャッシュ不可能（デバイスメモリなど）
    Uncached,
    /// ライトスルーキャッシュ
    WriteThrough,
    /// ライトバックキャッシュ
    WriteBack,
    /// ライトコンバインキャッシュ
    WriteCombining,
}

/// マッピングのソース
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingSource {
    /// 物理メモリからのマッピング
    Physical(PhysAddr),
    /// 匿名マッピング（ゼロ初期化）
    Anonymous,
    /// ファイルからのマッピング
    File(FileMapping),
    /// デバイスメモリからのマッピング
    Device(PhysAddr),
    /// 共有メモリ領域
    Shared(SharedMapping),
    /// テレページマッピング
    Telepage(TelepageMapping),
}

/// ファイルマッピング情報
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMapping {
    /// ファイルID
    pub file_id: u64,
    /// ファイル内オフセット
    pub offset: u64,
    /// マッピングサイズ
    pub size: usize,
    /// 共有マッピングかどうか
    pub shared: bool,
}

/// 共有メモリマッピング情報
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedMapping {
    /// 共有ID
    pub shared_id: u64,
    /// オフセット
    pub offset: usize,
    /// サイズ
    pub size: usize,
}

/// テレページマッピング情報
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelepageMapping {
    /// テレページID
    pub telepage_id: u64,
    /// リモートノードID
    pub node_id: u64,
    /// オフセット
    pub offset: usize,
}

/// メモリマッピングレコード
#[derive(Debug)]
pub struct MappingRecord {
    /// 仮想アドレス範囲
    pub range: Range<VirtAddr>,
    /// ソース
    pub source: MappingSource,
    /// 保護属性
    pub protection: Protection,
    /// 固定マッピングかどうか
    pub pinned: bool,
    /// メタデータ
    pub metadata: Option<MappingMetadata>,
}

/// マッピングメタデータ
#[derive(Debug, Clone, Default)]
pub struct MappingMetadata {
    /// 作成時間
    pub created_at: u64,
    /// 最終アクセス時間
    pub last_access: u64,
    /// アクセスカウント
    pub access_count: u64,
    /// 説明
    pub description: Option<alloc::string::String>,
    /// カスタムタグ
    pub tags: Vec<alloc::string::String>,
}

/// マップトラッカー
pub struct MapTracker {
    /// マッピングレコードのリスト
    mappings: RwLock<BTreeMap<VirtAddr, MappingRecord>>,
    /// 利用可能な仮想アドレス領域のリスト
    free_regions: Mutex<Vec<Range<VirtAddr>>>,
}

impl MapTracker {
    /// 新しいマップトラッカーを作成
    pub fn new() -> Self {
        // 初期の空き領域
        let mut free_regions = Vec::new();
        
        // カーネル空間とユーザー空間を分離した初期設定
        // 実際のアドレス範囲はアーキテクチャに依存します
        
        // 例：x86_64の場合
        // ユーザー空間: 0x0000000000000000 - 0x00007fffffffffff
        // カーネル空間: 0xffff800000000000 - 0xffffffffffffffff
        
        // ユーザー空間の利用可能領域
        free_regions.push(Range {
            start: VirtAddr::new(0x1000), // 先頭の4KiBはNULLポインタ保護のため除外
            end: VirtAddr::new(0x00007fffffffffff),
        });
        
        // カーネル空間の利用可能領域
        free_regions.push(Range {
            start: VirtAddr::new(0xffff800000000000),
            end: VirtAddr::new(0xffffffffffffffff),
        });
        
        MapTracker {
            mappings: RwLock::new(BTreeMap::new()),
            free_regions: Mutex::new(free_regions),
        }
    }
    
    /// マッピングを追加
    pub fn add_mapping(
        &self, 
        range: Range<VirtAddr>, 
        source: MappingSource, 
        protection: Protection,
        mapper: &mut impl PageMapper
    ) -> Result<(), MapError> {
        // 範囲が有効かチェック
        self.validate_range(&range)?;
        
        // 範囲が他のマッピングと重複していないかチェック
        self.check_overlap(&range)?;
        
        // ページマッピングを実行
        self.map_pages(&range, &source, protection, mapper)?;
        
        // マッピングレコードを作成
        let record = MappingRecord {
            range: range.clone(),
            source,
            protection,
            pinned: false,
            metadata: Some(MappingMetadata {
                created_at: crate::core::time::current_timestamp(),
                last_access: crate::core::time::current_timestamp(),
                access_count: 0,
                description: None,
                tags: Vec::new(),
            }),
        };
        
        // マッピングリストに追加
        let mut mappings = self.mappings.write().map_err(|_| MapError::LockError)?;
        mappings.insert(range.start, record);
        
        // 空き領域を更新
        self.update_free_regions(&range)?;
        
        Ok(())
    }
    
    /// マッピングを削除
    pub fn remove_mapping(
        &self, 
        addr: VirtAddr, 
        mapper: &mut impl PageMapper
    ) -> Result<(), MapError> {
        let record = {
            let mut mappings = self.mappings.write().map_err(|_| MapError::LockError)?;
            
            // 指定されたアドレスを含むマッピングを検索
            let key = mappings.range(..=addr)
                .next_back()
                .filter(|(start, record)| {
                    addr >= **start && addr < record.range.end
                })
                .map(|(k, _)| *k);
            
            if let Some(key) = key {
                // マッピングが見つかった場合、削除
                mappings.remove(&key)
            } else {
                // マッピングが見つからない
                return Err(MapError::InvalidMapping);
            }
        };
        
        if let Some(record) = record {
            // マッピングを解除
            self.unmap_pages(&record.range, mapper)?;
            
            // 空き領域を更新
            let mut free_regions = self.free_regions.lock().map_err(|_| MapError::LockError)?;
            
            // 新しい空き領域を追加
            self.merge_free_region(&mut free_regions, record.range);
            
            Ok(())
        } else {
            Err(MapError::InvalidMapping)
        }
    }
    
    /// 指定されたアドレスのマッピングを検索
    pub fn lookup_mapping(&self, addr: VirtAddr) -> Result<MappingRecord, MapError> {
        let mappings = self.mappings.read().map_err(|_| MapError::LockError)?;
        
        // アドレスを含むマッピングを検索
        let record = mappings.range(..=addr)
            .next_back()
            .filter(|(start, record)| {
                addr >= **start && addr < record.range.end
            })
            .map(|(_, record)| record.clone());
        
        if let Some(record) = record {
            // アクセス統計を更新
            if let Some(metadata) = &record.metadata {
                let mut metadata = metadata.clone();
                metadata.last_access = crate::core::time::current_timestamp();
                metadata.access_count += 1;
                
                // マッピングレコードを更新
                let mut mappings = self.mappings.write().map_err(|_| MapError::LockError)?;
                if let Some(record) = mappings.get_mut(&record.range.start) {
                    record.metadata = Some(metadata);
                }
            }
            
            Ok(record)
        } else {
            Err(MapError::InvalidMapping)
        }
    }
    
    /// 指定されたサイズの利用可能な仮想アドレス領域を見つける
    pub fn find_free_region(
        &self, 
        size: usize, 
        alignment: usize, 
        kernel_space: bool
    ) -> Result<Range<VirtAddr>, MapError> {
        let mut free_regions = self.free_regions.lock().map_err(|_| MapError::LockError)?;
        
        // アラインメントは少なくともページサイズであることを確認
        let alignment = alignment.max(NORMAL_PAGE_SIZE);
        
        // サイズをページサイズの倍数に切り上げ
        let size = (size + NORMAL_PAGE_SIZE - 1) & !(NORMAL_PAGE_SIZE - 1);
        
        for region in free_regions.iter() {
            // カーネル/ユーザー空間の要件をチェック
            let is_kernel_region = region.start.as_u64() >= 0x8000_0000_0000_0000;
            if kernel_space != is_kernel_region {
                continue;
            }
            
            // 領域のサイズをチェック
            let region_size = region.end.as_usize() - region.start.as_usize();
            if region_size < size {
                continue;
            }
            
            // アラインメントされた開始アドレスを計算
            let aligned_start = (region.start.as_usize() + alignment - 1) & !(alignment - 1);
            let aligned_start = VirtAddr::new(aligned_start as u64);
            
            // アラインメント後も領域内かチェック
            if aligned_start >= region.end {
                continue;
            }
            
            // アラインメント後の終了アドレスを計算
            let aligned_end = aligned_start.as_usize() + size;
            if aligned_end > region.end.as_usize() {
                continue;
            }
            
            // 有効な領域が見つかった
            return Ok(Range {
                start: aligned_start,
                end: VirtAddr::new(aligned_end as u64),
            });
        }
        
        // 十分なサイズの空き領域が見つからなかった
        Err(MapError::NoFreeRegion)
    }
    
    /// 保護属性を変更
    pub fn change_protection(
        &self, 
        addr: VirtAddr, 
        protection: Protection,
        mapper: &mut impl PageMapper
    ) -> Result<(), MapError> {
        let record = self.lookup_mapping(addr)?;
        
        // ページの保護属性を変更
        for page_addr in (record.range.start.as_usize()..record.range.end.as_usize())
            .step_by(NORMAL_PAGE_SIZE)
            .map(|a| VirtAddr::new(a as u64))
        {
            let page = Page::containing_address(page_addr);
            mapper.update_flags(page, protection)?;
        }
        
        // マッピングレコードを更新
        let mut mappings = self.mappings.write().map_err(|_| MapError::LockError)?;
        if let Some(record) = mappings.get_mut(&record.range.start) {
            record.protection = protection;
        }
        
        Ok(())
    }
    
    /// 固定マッピングとしてマーク
    pub fn pin_mapping(&self, addr: VirtAddr) -> Result<(), MapError> {
        let mut mappings = self.mappings.write().map_err(|_| MapError::LockError)?;
        
        // アドレスを含むマッピングを検索
        let key = mappings.range(..=addr)
            .next_back()
            .filter(|(start, record)| {
                addr >= **start && addr < record.range.end
            })
            .map(|(k, _)| *k);
        
        if let Some(key) = key {
            // マッピングが見つかった場合、固定とマーク
            if let Some(record) = mappings.get_mut(&key) {
                record.pinned = true;
                Ok(())
            } else {
                Err(MapError::InvalidMapping)
            }
        } else {
            // マッピングが見つからない
            Err(MapError::InvalidMapping)
        }
    }
    
    /// 固定マッピングを解除
    pub fn unpin_mapping(&self, addr: VirtAddr) -> Result<(), MapError> {
        let mut mappings = self.mappings.write().map_err(|_| MapError::LockError)?;
        
        // アドレスを含むマッピングを検索
        let key = mappings.range(..=addr)
            .next_back()
            .filter(|(start, record)| {
                addr >= **start && addr < record.range.end
            })
            .map(|(k, _)| *k);
        
        if let Some(key) = key {
            // マッピングが見つかった場合、固定解除
            if let Some(record) = mappings.get_mut(&key) {
                record.pinned = false;
                Ok(())
            } else {
                Err(MapError::InvalidMapping)
            }
        } else {
            // マッピングが見つからない
            Err(MapError::InvalidMapping)
        }
    }
    
    /// すべてのマッピングを取得
    pub fn get_all_mappings(&self) -> Result<Vec<MappingRecord>, MapError> {
        let mappings = self.mappings.read().map_err(|_| MapError::LockError)?;
        
        // すべてのマッピングをクローンして返す
        let result = mappings.values().cloned().collect();
        
        Ok(result)
    }
    
    /// 特定の範囲にあるマッピングを取得
    pub fn get_mappings_in_range(&self, range: &Range<VirtAddr>) -> Result<Vec<MappingRecord>, MapError> {
        let mappings = self.mappings.read().map_err(|_| MapError::LockError)?;
        
        // 範囲内または範囲と重複するマッピングを検索
        let result = mappings.values()
            .filter(|record| {
                // 範囲の重複チェック
                record.range.start < range.end && record.range.end > range.start
            })
            .cloned()
            .collect();
        
        Ok(result)
    }
    
    // ---------- 内部ヘルパーメソッド ----------
    
    /// 範囲の有効性をチェック
    fn validate_range(&self, range: &Range<VirtAddr>) -> Result<(), MapError> {
        // 範囲が空でないことを確認
        if range.start >= range.end {
            return Err(MapError::InvalidRange);
        }
        
        // 開始アドレスがページアラインされていることを確認
        if !range.start.is_aligned(NORMAL_PAGE_SIZE) {
            return Err(MapError::UnalignedAddress);
        }
        
        // 終了アドレスがページアラインされていることを確認
        if !range.end.is_aligned(NORMAL_PAGE_SIZE) {
            return Err(MapError::UnalignedAddress);
        }
        
        Ok(())
    }
    
    /// 他のマッピングとの重複をチェック
    fn check_overlap(&self, range: &Range<VirtAddr>) -> Result<(), MapError> {
        let mappings = self.mappings.read().map_err(|_| MapError::LockError)?;
        
        // 重複をチェック
        for record in mappings.values() {
            if record.range.start < range.end && record.range.end > range.start {
                return Err(MapError::OverlappingMapping);
            }
        }
        
        Ok(())
    }
    
    /// ページをマッピング
    fn map_pages(
        &self, 
        range: &Range<VirtAddr>, 
        source: &MappingSource, 
        protection: Protection,
        mapper: &mut impl PageMapper
    ) -> Result<(), MapError> {
        // 各ページについてマッピングを実行
        let mut current_phys: Option<PhysAddr> = None;
        
        match source {
            MappingSource::Physical(phys_addr) => {
                current_phys = Some(*phys_addr);
            },
            MappingSource::Anonymous => {
                // 匿名マッピングは必要に応じてページを割り当て
                // ただし、ページフォルト時に実際に割り当てるようにする場合もある
            },
            MappingSource::File(_) => {
                // ファイルマッピングはページフォルト時に実際にロード
            },
            MappingSource::Device(phys_addr) => {
                current_phys = Some(*phys_addr);
            },
            MappingSource::Shared(_) => {
                // 共有マッピングは別途処理
            },
            MappingSource::Telepage(_) => {
                // テレページは別途処理
            },
        }
        
        // ページ単位でマッピング
        for page_addr in (range.start.as_usize()..range.end.as_usize())
            .step_by(NORMAL_PAGE_SIZE)
            .map(|a| VirtAddr::new(a as u64))
        {
            let page = Page::containing_address(page_addr);
            
            match source {
                MappingSource::Physical(_) | MappingSource::Device(_) => {
                    if let Some(phys) = current_phys {
                        mapper.map(page, phys, protection)?;
                        
                        // 次のページの物理アドレスを更新
                        current_phys = Some(PhysAddr::new(phys.as_u64() + NORMAL_PAGE_SIZE as u64));
                    } else {
                        return Err(MapError::InvalidSource);
                    }
                },
                MappingSource::Anonymous => {
                    // 匿名マッピングの場合、新しいページを割り当て
                    let frame = crate::core::memory::mm::page_allocator::allocate_frame()
                        .ok_or(MapError::AllocationFailed)?;
                    
                    // ページをゼロクリア
                    unsafe {
                        let ptr = frame.start_address().as_u64() as *mut u8;
                        core::ptr::write_bytes(ptr, 0, NORMAL_PAGE_SIZE);
                    }
                    
                    mapper.map(page, frame.start_address(), protection)?;
                },
                MappingSource::File(file_mapping) => {
                    // ファイルマッピングは実際にはページフォルトハンドラで処理
                    // ここではプレースホルダとしてのマッピングのみ作成
                    mapper.map_lazy(page, protection)?;
                },
                MappingSource::Shared(shared_mapping) => {
                    // 共有メモリマッピングの処理
                    // 共有メモリ管理者から適切なフレームを取得
                    let frame = crate::core::memory::mm::shared_memory::get_shared_frame(
                        shared_mapping.shared_id, 
                        page_addr.as_usize() - range.start.as_usize() + shared_mapping.offset
                    ).ok_or(MapError::InvalidSource)?;
                    
                    mapper.map(page, frame, protection)?;
                },
                MappingSource::Telepage(telepage_mapping) => {
                    // テレページマッピングは実際にはページフォルトハンドラで処理
                    // ここではプレースホルダとしてのマッピングのみ作成
                    mapper.map_lazy(page, protection)?;
                },
            }
        }
        
        Ok(())
    }
    
    /// ページのマッピングを解除
    fn unmap_pages(
        &self, 
        range: &Range<VirtAddr>, 
        mapper: &mut impl PageMapper
    ) -> Result<(), MapError> {
        // 各ページについてマッピングを解除
        for page_addr in (range.start.as_usize()..range.end.as_usize())
            .step_by(NORMAL_PAGE_SIZE)
            .map(|a| VirtAddr::new(a as u64))
        {
            let page = Page::containing_address(page_addr);
            mapper.unmap(page)?;
        }
        
        Ok(())
    }
    
    /// 空き領域リストを更新
    fn update_free_regions(&self, used_range: &Range<VirtAddr>) -> Result<(), MapError> {
        let mut free_regions = self.free_regions.lock().map_err(|_| MapError::LockError)?;
        
        // 新しく使用された領域を反映して空き領域リストを更新
        let mut i = 0;
        while i < free_regions.len() {
            let region = &free_regions[i];
            
            // 領域が使用された範囲と重複するかチェック
            if region.end <= used_range.start || region.start >= used_range.end {
                // 重複なし
                i += 1;
                continue;
            }
            
            // 重複あり - 現在の領域を削除
            let current_region = free_regions.remove(i);
            
            // 使用された範囲の前にある部分を追加
            if current_region.start < used_range.start {
                free_regions.insert(i, Range {
                    start: current_region.start,
                    end: used_range.start,
                });
                i += 1;
            }
            
            // 使用された範囲の後にある部分を追加
            if current_region.end > used_range.end {
                free_regions.insert(i, Range {
                    start: used_range.end,
                    end: current_region.end,
                });
                i += 1;
            }
        }
        
        Ok(())
    }
    
    /// 空き領域を統合
    fn merge_free_region(&self, free_regions: &mut Vec<Range<VirtAddr>>, new_free: Range<VirtAddr>) {
        // 新しい空き領域を追加
        let mut inserted = false;
        
        // 適切な位置に挿入
        for i in 0..free_regions.len() {
            if free_regions[i].start > new_free.start {
                free_regions.insert(i, new_free.clone());
                inserted = true;
                break;
            }
        }
        
        if !inserted {
            free_regions.push(new_free.clone());
        }
        
        // 隣接する領域を統合
        let mut i = 0;
        while i < free_regions.len() - 1 {
            let current = &free_regions[i];
            let next = &free_regions[i + 1];
            
            if current.end >= next.start {
                // 領域が重複または隣接している場合、統合
                let merged = Range {
                    start: current.start,
                    end: core::cmp::max(current.end, next.end),
                };
                
                free_regions[i] = merged;
                free_regions.remove(i + 1);
            } else {
                i += 1;
            }
        }
    }
}

/// マッピングエラー
#[derive(Debug)]
pub enum MapError {
    /// 無効なアドレス範囲
    InvalidRange,
    /// アライメントされていないアドレス
    UnalignedAddress,
    /// 既存のマッピングと重複
    OverlappingMapping,
    /// 無効なマッピング
    InvalidMapping,
    /// メモリ割り当て失敗
    AllocationFailed,
    /// マッピングソースが無効
    InvalidSource,
    /// ロックエラー
    LockError,
    /// アドレス変換エラー
    TranslationError,
    /// 空き領域が不足
    NoFreeRegion,
    /// ページマッピングエラー
    PageMapError(crate::core::memory::page::MapperError),
}

impl From<crate::core::memory::page::MapperError> for MapError {
    fn from(err: crate::core::memory::page::MapperError) -> Self {
        MapError::PageMapError(err)
    }
}

// グローバルマップトラッカーインスタンス
static GLOBAL_MAP_TRACKER: RwLock<Option<MapTracker>> = RwLock::new(None);

/// グローバルマップトラッカーの初期化
pub fn init_map_tracker() {
    let mut tracker = GLOBAL_MAP_TRACKER.write().unwrap();
    *tracker = Some(MapTracker::new());
}

/// グローバルマップトラッカーの取得
pub fn get_map_tracker() -> Option<&'static MapTracker> {
    let tracker = GLOBAL_MAP_TRACKER.read().ok()?;
    tracker.as_ref()
} 