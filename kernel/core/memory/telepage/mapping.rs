// AetherOS TeraPage マッピング機能
// 大規模仮想メモリと物理メモリのマッピングを管理

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use crate::sync::{Mutex, SpinLock, RwLock};
use crate::arch::cpu;
use crate::memory::{PAGE_SIZE, HUGE_PAGE_SIZE, GIGANTIC_PAGE_SIZE, TERA_PAGE_SIZE, AllocFlags};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use super::stats;
use super::terapage;
use super::remote;

/// メモリマップの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapState {
    /// 未マップ
    Unmapped,
    /// テラページマップ済み
    TeraPageMapped,
    /// リモートメモリマップ済み
    RemoteMapped,
    /// 分割マップ（複数ページ種類の混在）
    SplitMapped,
}

/// マップの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapType {
    /// 読み取り専用
    ReadOnly,
    /// 読み書き可能
    ReadWrite,
    /// 実行可能
    Executable,
    /// 読み取りと実行可能
    ReadExecute,
}

/// メモリマップエントリ
#[derive(Debug)]
pub struct MemoryMapEntry {
    /// 開始アドレス
    pub start: usize,
    
    /// サイズ
    pub size: usize,
    
    /// マップ状態
    pub state: MapState,
    
    /// マップの種類
    pub map_type: MapType,
    
    /// リモートノードID (リモートマップの場合)
    pub remote_node_id: Option<remote::RemoteNodeId>,
    
    /// 作成時刻
    pub creation_time: u64,
    
    /// 最終アクセス時刻
    pub last_access: AtomicU64,
    
    /// 参照カウント
    pub ref_count: AtomicUsize,
}

/// メモリマップ構造体
#[derive(Debug)]
pub struct MemoryMap {
    /// マップエントリ (開始アドレス -> エントリ)
    entries: RwLock<BTreeMap<usize, MemoryMapEntry>>,
}

impl MemoryMap {
    /// 新しいメモリマップを作成
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
        }
    }
    
    /// マップエントリを追加
    pub fn add_entry(&self, entry: MemoryMapEntry) -> Result<(), &'static str> {
        let mut entries = self.entries.write().map_err(|_| "マップのロックに失敗しました")?;
        
        // 重複がないか確認
        let end = entry.start + entry.size;
        
        for (addr, existing) in entries.iter() {
            let existing_end = *addr + existing.size;
            
            // 重複チェック
            if (entry.start >= *addr && entry.start < existing_end) ||
               (end > *addr && end <= existing_end) ||
               (entry.start <= *addr && end >= existing_end) {
                return Err("メモリ領域が既存のマップと重複しています");
            }
        }
        
        // エントリを追加
        entries.insert(entry.start, entry);
        
        Ok(())
    }
    
    /// テラページのマッピングを作成
    pub fn map_terapage(&self, address: usize, pages: usize, map_type: MapType) -> Result<(), &'static str> {
        // アドレスのアライメント確認
        if address % TERA_PAGE_SIZE != 0 {
            return Err("テラページマッピングはTERA_PAGE_SIZEでアライメントする必要があります");
        }
        
        // サイズ計算
        let size = pages * TERA_PAGE_SIZE;
        
        // アロケーション用のフラグ設定
        let mut alloc_flags = AllocFlags::empty();
        
        match map_type {
            MapType::ReadOnly => {
                alloc_flags |= AllocFlags::READ_ONLY;
            },
            MapType::ReadWrite => {
                // デフォルト
            },
            MapType::Executable => {
                alloc_flags |= AllocFlags::EXEC;
            },
            MapType::ReadExecute => {
                alloc_flags |= AllocFlags::READ_ONLY | AllocFlags::EXEC;
            },
        }
        
        // テラページを割り当て
        let allocated_addr = terapage::allocate(pages, alloc_flags)?;
        
        // 割り当てたアドレスと要求されたアドレスが一致するか確認
        if allocated_addr != address {
            // アドレスが一致しない場合は解放して再試行が必要
            let _ = terapage::free(allocated_addr, pages);
            return Err("指定されたアドレスにテラページを割り当てできませんでした");
        }
        
        // マップエントリを作成
        let entry = MemoryMapEntry {
            start: address,
            size,
            state: MapState::TeraPageMapped,
            map_type,
            remote_node_id: None,
            creation_time: get_timestamp(),
            last_access: AtomicU64::new(get_timestamp()),
            ref_count: AtomicUsize::new(1),
        };
        
        // エントリを追加
        self.add_entry(entry)?;
        
        Ok(())
    }
    
    /// リモートメモリのマッピングを作成
    pub fn map_remote(&self, address: usize, pages: usize, node_id: remote::RemoteNodeId, map_type: MapType) -> Result<(), &'static str> {
        // アドレスのアライメント確認
        if address % PAGE_SIZE != 0 {
            return Err("リモートメモリマッピングはPAGE_SIZEでアライメントする必要があります");
        }
        
        // サイズ計算
        let size = pages * PAGE_SIZE;
        
        // アロケーション用のフラグ設定
        let mut alloc_flags = AllocFlags::empty();
        
        match map_type {
            MapType::ReadOnly => {
                alloc_flags |= AllocFlags::READ_ONLY;
            },
            MapType::ReadWrite => {
                // デフォルト
            },
            MapType::Executable => {
                alloc_flags |= AllocFlags::EXEC;
            },
            MapType::ReadExecute => {
                alloc_flags |= AllocFlags::READ_ONLY | AllocFlags::EXEC;
            },
        }
        
        // リモートメモリを割り当て
        let allocated_addr = remote::allocate(node_id, pages, alloc_flags)?;
        
        // 割り当てたアドレスと要求されたアドレスが一致するか確認
        if allocated_addr != address {
            // アドレスが一致しない場合は解放して再試行が必要
            let _ = remote::free(node_id, allocated_addr, pages);
            return Err("指定されたアドレスにリモートメモリを割り当てできませんでした");
        }
        
        // マップエントリを作成
        let entry = MemoryMapEntry {
            start: address,
            size,
            state: MapState::RemoteMapped,
            map_type,
            remote_node_id: Some(node_id),
            creation_time: get_timestamp(),
            last_access: AtomicU64::new(get_timestamp()),
            ref_count: AtomicUsize::new(1),
        };
        
        // エントリを追加
        self.add_entry(entry)?;
        
        Ok(())
    }
    
    /// マッピングを解除
    pub fn unmap(&self, address: usize, size: usize) -> Result<(), &'static str> {
        let mut entries = self.entries.write().map_err(|_| "マップのロックに失敗しました")?;
        
        // 対応するエントリを探す
        if let Some(entry) = entries.get(&address) {
            // サイズ確認
            if entry.size != size {
                return Err("指定されたサイズがマップと一致しません");
            }
            
            // 参照カウントをデクリメント
            let ref_count = entry.ref_count.fetch_sub(1, Ordering::Relaxed);
            
            // 参照カウントが0になったら解放
            if ref_count <= 1 {
                // マップの種類に応じた解放処理
                match entry.state {
                    MapState::TeraPageMapped => {
                        let pages = size / TERA_PAGE_SIZE;
                        terapage::free(address, pages)?;
                    },
                    MapState::RemoteMapped => {
                        if let Some(node_id) = entry.remote_node_id {
                            let pages = size / PAGE_SIZE;
                            remote::free(node_id, address, pages)?;
                        } else {
                            return Err("リモートノードIDが見つかりません");
                        }
                    },
                    MapState::SplitMapped => {
                        // 分割マップは複雑な解放処理が必要
                        // 各部分をマッピング種別に応じて適切に解放
                        // リモートマップ部分はネットワーク層API、テラページ部分はローカル解放
                        
                        // エントリから具体的なマッピング情報を取得
                        if let Some(mapping_info) = get_split_mapping_details(&entry) {
                            release_split_mapping_resources(&mapping_info)?;
                        }
                    },
                    MapState::Unmapped => {
                        // 何もしない、またはエラー
                        return Err("既にアンマップされている領域です");
                    }
                }
                
                // エントリを削除
                entries.remove(&address);
                
                Ok(())
            } else {
                Ok(()) // 参照カウントがまだ残っている
            }
        } else {
            Err("指定されたアドレスにマップが見つかりません")
        }
    }
    
    /// 分割マッピングリソースの解放（仮）
    /// この関数は TeraPageMapping の実体が必要なため、MemoryMapからは直接呼び出しにくい
    fn release_split_mapping_resources(mapping: &TeraPageMapping) -> Result<(), &'static str> {
        if let TeraPageMapping::Split { parts, .. } = mapping {
            log::debug!("分割マッピングのリソース解放を開始します...");
            for part_mapping_arc in parts {
                let part_mapping = part_mapping_arc.read(); // Arc<RwLock<TeraPageMapping>>を想定
                // 各部分マッピングに対して再帰的に解放処理を試みる
                // ここでは unmap_terapage_mapping が各マッピングタイプに応じた解放を行うと仮定
                match unmap_terapage_mapping(&part_mapping) {
                    Ok(_) => log::trace!("部分マッピングを解放しました。"),
                    Err(e) => {
                        log::error!("部分マッピングの解放に失敗しました: {}", e);
                        // 一部失敗しても他の部分の解放を試みるか、即時エラーとするか
                        // return Err("分割マップの一部の解放に失敗しました");
                    }
                }
            }
            log::info!("分割マッピングのリソースを解放しました。");
            Ok(())
        } else {
            Err("指定されたマッピングはSplitではありません")
        }
    }

    /// アドレスからマップエントリを取得
    pub fn get_entry(&self, address: usize) -> Result<Option<MemoryMapEntry>, &'static str> {
        let entries = self.entries.read().map_err(|_| "マップのロックに失敗しました")?;
        
        // 完全一致するエントリを探す
        if let Some(entry) = entries.get(&address) {
            // アクセス時刻を更新
            entry.last_access.store(get_timestamp(), Ordering::Relaxed);
            return Ok(Some(entry.clone()));
        }
        
        // 範囲内に含まれるエントリを探す
        for (start, entry) in entries.iter() {
            let end = *start + entry.size;
            
            if address >= *start && address < end {
                // アクセス時刻を更新
                entry.last_access.store(get_timestamp(), Ordering::Relaxed);
                return Ok(Some(entry.clone()));
            }
        }
        
        Ok(None)
    }
    
    /// マップエントリのリストを取得
    pub fn list_entries(&self) -> Result<Vec<MemoryMapEntry>, &'static str> {
        let entries = self.entries.read().map_err(|_| "マップのロックに失敗しました")?;
        
        let mut result = Vec::with_capacity(entries.len());
        
        for entry in entries.values() {
            result.push(entry.clone());
        }
        
        Ok(result)
    }
    
    /// テラページからリモートメモリへの移行
    pub fn migrate_terapage_to_remote(&self, address: usize, node_id: remote::RemoteNodeId) -> Result<(), &'static str> {
        let mut entries = self.entries.write().map_err(|_| "マップのロックに失敗しました")?;
        
        // 対応するエントリを探す
        let entry = entries.get_mut(&address)
            .ok_or("指定されたアドレスにマップが見つかりません")?;
        
        // マップ状態を確認
        if entry.state != MapState::TeraPageMapped {
            return Err("テラページマップではないため移行できません");
        }
        
        let size = entry.size;
        let pages = size / TERA_PAGE_SIZE; // テラページの場合
        let remote_pages = size / PAGE_SIZE; // リモートは通常ページ単位

        // 1. リモートに同サイズのメモリを確保
        //    (map_type は既存のものを引き継ぐ。alloc_flagsも同様に設定)
        let mut alloc_flags = AllocFlags::empty();
        match entry.map_type {
            MapType::ReadOnly => alloc_flags |= AllocFlags::READ_ONLY,
            MapType::ReadWrite => { /* Default */ }
            MapType::Executable => alloc_flags |= AllocFlags::EXEC,
            MapType::ReadExecute => alloc_flags |= AllocFlags::READ_ONLY | AllocFlags::EXEC,
        }
        let remote_allocated_addr = remote::allocate(node_id, remote_pages, alloc_flags)?;
        
        // 2. データをコピー
        // TODO: ネットワークスタック/転送マネージャを使用して、`address` から始まる
        //       `size` のデータを `remote_allocated_addr` へ送信する。
        //       これには信頼性のある転送プロトコル (例: RDMA Write, TCP) の使用を想定。
        //       例: `network_manager.send_large_data_reliable(local_source_vaddr, size, destination_node_id, remote_dest_paddr)`
        log::info!(
            "テラページ (0x{:x}, {}B) からリモートノード {} のアドレス 0x{:x} へデータコピーを開始します。",
            address, size, node_id, remote_allocated_addr
        );
        match remote::copy_to_remote(node_id, address, remote_allocated_addr, size) {
            Ok(_) => log::info!("データコピーが完了しました。"),
            Err(e) => {
                log::error!("データコピー中にエラーが発生しました: {:?}", e);
                // エラー発生時はリモートに確保したメモリを解放
                let _ = remote::free(node_id, remote_allocated_addr, remote_pages);
                return Err("データコピーに失敗しました");
            }
        }

        // 3. ローカルのテラページを解放
        terapage::free(address, pages)?;
        
        // 4. マップエントリを更新
        entry.state = MapState::RemoteMapped;
        entry.remote_node_id = Some(node_id);
        entry.last_access.store(get_timestamp(), Ordering::Relaxed);
        
        log::info!("テラページ 0x{:x} をリモートノード {} (0x{:x}) に移行しました", address, node_id, remote_allocated_addr);
        Ok(())
    }
    
    /// リモートメモリからテラページへの移行
    pub fn migrate_remote_to_terapage(&self, address: usize) -> Result<(), &'static str> {
        let mut entries = self.entries.write().map_err(|_| "マップのロックに失敗しました")?;
        
        // 対応するエントリを探す
        let entry = entries.get_mut(&address)
            .ok_or("指定されたアドレスにマップが見つかりません")?;
        
        // マップ状態を確認
        if entry.state != MapState::RemoteMapped {
            return Err("リモートマップではないため移行できません");
        }
        
        let remote_node_id = entry.remote_node_id.ok_or("リモートノードIDがありません")?;
        let size = entry.size;
        let remote_pages = size / PAGE_SIZE; // リモートは通常ページ単位
        let terapage_pages = size / TERA_PAGE_SIZE; // テラページの場合

        // 1. ローカルにテラページを確保
        //    (map_type は既存のものを引き継ぐ。alloc_flagsも同様に設定)
        let mut alloc_flags = AllocFlags::empty();
        match entry.map_type {
            MapType::ReadOnly => alloc_flags |= AllocFlags::READ_ONLY,
            MapType::ReadWrite => { /* Default */ }
            MapType::Executable => alloc_flags |= AllocFlags::EXEC,
            MapType::ReadExecute => alloc_flags |= AllocFlags::READ_ONLY | AllocFlags::EXEC,
        }
        // migrate_remote_to_terapage は address をローカルのターゲットアドレスとして使用する
        let local_terapage_addr = terapage::allocate_at(address, terapage_pages, alloc_flags)
            .map_err(|e| {
                log::error!("ローカルテラページの確保に失敗 (アドレス: 0x{:x}): {:?}", address, e);
                e
            })?;
        if local_terapage_addr != address {
             // 通常は allocate_at でアドレス指定しているので一致するはずだが念のため
            let _ = terapage::free(local_terapage_addr, terapage_pages);
            return Err("指定されたアドレスにテラページを確保できませんでした。");
        }

        // 2. データをコピー
        // TODO: ネットワークスタック/転送マネージャを使用して、`source_node_id` の
        //       `remote_memory_info.remote_start_address` から `TERAPAGE_SIZE` のデータを
        //       ローカルの `local_terapage_addr` へ受信する。
        //       信頼性のある転送プロトコル (例: RDMA Read, TCP) の使用を想定。
        //       例: `network_manager.receive_large_data_reliable(local_dest_vaddr, TERAPAGE_SIZE, source_node_id, remote_source_paddr)`
        log::info!(
            "リモートノード {} のアドレス 0x{:x} ({}B) からローカルテラページ 0x{:x} へデータコピーを開始します。",
            remote_node_id, address, size, local_terapage_addr
        );
        match remote::copy_from_remote(remote_node_id, address, local_terapage_addr, size) {
            Ok(_) => log::info!("データコピーが完了しました。"),
            Err(e) => {
                log::error!("データコピー中にエラーが発生しました: {:?}", e);
                // エラー発生時はローカルに確保したテラページを解放
                let _ = terapage::free(local_terapage_addr, terapage_pages);
                return Err("データコピーに失敗しました");
            }
        }
        
        // 3. リモートのメモリを解放
        remote::free(remote_node_id, address, remote_pages)?;
        
        // 4. マップエントリを更新
        entry.state = MapState::TeraPageMapped;
        entry.remote_node_id = None;
        entry.last_access.store(get_timestamp(), Ordering::Relaxed);
        
        log::info!("リモートメモリ 0x{:x} (ノード {}) をローカルテラページ 0x{:x} に移行しました", address, remote_node_id, local_terapage_addr);
        Ok(())
    }
    
    /// 最適なノードに自動的に移行
    pub fn auto_migrate(&self, address: usize) -> Result<(), &'static str> {
        // マップエントリを取得
        let entry = match self.get_entry(address)? {
            Some(e) => e,
            None => return Err("指定されたアドレスのマップが見つかりません"),
        };
        
        // アクセスパターンに基づいて最適な移行先を決定
        match entry.state {
            MapState::TeraPageMapped => {
                // アクセス頻度が低い場合はリモートに移行
                let current_time = get_timestamp();
                let last_access = entry.last_access.load(Ordering::Relaxed);
                
                // 例: 1秒以上アクセスがなければリモートへ移行（実際の閾値は調整が必要）
                if current_time - last_access > 1_000_000_000 {
                    // 最適なノードを選択
                    let node_id = remote::select_optimal_node(entry.size / PAGE_SIZE)?;
                    
                    // リモートへ移行
                    self.migrate_terapage_to_remote(address, node_id)?;
                }
            },
            MapState::RemoteMapped => {
                // アクセス頻度が高い場合はテラページに移行
                let current_time = get_timestamp();
                let last_access = entry.last_access.load(Ordering::Relaxed);
                
                // 例: 0.1秒以内にアクセスがあればテラページへ移行
                if current_time - last_access < 100_000_000 {
                    // テラページへ移行
                    self.migrate_remote_to_terapage(address)?;
                }
            },
            _ => {
                // 他の状態には対応しない
            }
        }
        
        Ok(())
    }
}

impl Clone for MemoryMapEntry {
    fn clone(&self) -> Self {
        Self {
            start: self.start,
            size: self.size,
            state: self.state,
            map_type: self.map_type,
            remote_node_id: self.remote_node_id,
            creation_time: self.creation_time,
            last_access: AtomicU64::new(self.last_access.load(Ordering::Relaxed)),
            ref_count: AtomicUsize::new(self.ref_count.load(Ordering::Relaxed)),
        }
    }
}

/// デフォルトメモリマップ
static mut DEFAULT_MEMORY_MAP: Option<MemoryMap> = None;

/// 初期化フラグ
static MAPPING_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// マッピングシステムを初期化
pub fn init() -> Result<(), &'static str> {
    // 既に初期化されている場合は早期リターン
    if MAPPING_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }
    
    // デフォルトマップを作成
    unsafe {
        DEFAULT_MEMORY_MAP = Some(MemoryMap::new());
    }
    
    // 初期化完了
    MAPPING_INITIALIZED.store(true, Ordering::SeqCst);
    
    Ok(())
}

/// デフォルトマップを取得
pub fn get_default_map() -> Result<&'static MemoryMap, &'static str> {
    if !MAPPING_INITIALIZED.load(Ordering::SeqCst) {
        return Err("マッピングシステムが初期化されていません");
    }
    
    unsafe {
        DEFAULT_MEMORY_MAP.as_ref()
            .ok_or("デフォルトマップが初期化されていません")
    }
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

impl Drop for MemoryMapEntry {
    fn drop(&mut self) {
        if self.ref_count.load(Ordering::Relaxed) == 1 {
            // このエントリーが最後の参照である場合、実際の解放処理を行う
            match self.state {
                MapState::TeraPageMapped => {
                    let pages = self.size / TERA_PAGE_SIZE;
                    terapage::free(self.start, pages)?;
                },
                MapState::RemoteMapped => {
                    if let Some(node_id) = self.remote_node_id {
                        let pages = self.size / PAGE_SIZE;
                        remote::free(node_id, self.start, pages)?;
                    }
                },
                MapState::SplitMapped => {
                    log::warn!("SplitMapped の解放処理は現在の実装では不完全です。アドレス: 0x{:x}", self.start);
                    // release_split_mapping_resources(self.start, self.size)?; // 仮の関数呼び出し
                },
                MapState::Unmapped => {
                    // 何もしない
                }
            }
        }
    }
} 