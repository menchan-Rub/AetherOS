// AetherOS テレページングページフォルトハンドラ
//
// リモートページフォルトの処理と、分散メモリ管理の中核機能を提供

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::arch::cpu::{disable_interrupts, enable_interrupts};
use crate::core::memory::mm::page::{Page, PageFlags, PhysicalAddress, VirtualAddress, PAGE_SIZE};
use crate::core::memory::telepage::{global_telepage, RemotePageId, RequestType, PageState};
use crate::core::process::{current_process, current_thread, Process, Thread};
use crate::core::distributed::global_cluster;
use crate::time::{get_current_time, Timespec};

/// ページフォルト処理の結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageFaultResult {
    /// 成功（ページが取得または作成された）
    Success,
    /// リモートページでないため処理されなかった
    NotRemote,
    /// アクセス拒否
    AccessDenied,
    /// メモリ不足
    OutOfMemory,
    /// ノード接続エラー
    ConnectionError,
    /// タイムアウト
    Timeout,
    /// 一般的なエラー
    Error,
}

/// リモートページフォルトハンドラ
/// 
/// 仮想メモリページフォルトをキャッチし、そのページがリモートページであれば
/// テレページマネージャを使用してリモートからフェッチします
pub fn handle_page_fault(fault_addr: VirtualAddress, is_write: bool) -> PageFaultResult {
    // まず現在のプロセスを取得
    let proc = current_process();
    if proc.is_none() {
        return PageFaultResult::Error;
    }
    
    let process = proc.unwrap();
    
    // テレページマネージャの参照を取得
    let telepage = global_telepage();
    
    // 対象アドレスをページアライン
    let page_addr = fault_addr & !(PAGE_SIZE - 1);
    
    // プロセスのメモリマップを確認し、このアドレスがリモートページとして登録されているか確認
    if !is_remote_page(process.as_ref(), page_addr) {
        return PageFaultResult::NotRemote;
    }
    
    // リモートページIDを構築
    let page_id = build_remote_page_id(process.as_ref(), page_addr);
    
    // 統計情報を更新
    telepage.stats.remote_page_faults.fetch_add(1, Ordering::Relaxed);
    
    // 読み取りか書き込みかに応じてリクエストを作成
    let req_type = if is_write {
        RequestType::Write
    } else {
        RequestType::Read
    };
    
    // ページの取得を試みる
    match fetch_remote_page(page_id, req_type) {
        Ok(phys_addr) => {
            // ページテーブルに物理アドレスをマッピング
            let mut flags = PageFlags::PRESENT | PageFlags::USER;
            if is_write {
                flags |= PageFlags::WRITABLE;
            }
            
            map_page(process.as_ref(), page_addr, phys_addr, flags);
            
            // TLBをフラッシュ
            flush_tlb(page_addr);
            
            // 予測的プリフェッチを考慮
            consider_prefetch(page_id);
            
            PageFaultResult::Success
        },
        Err(_) => {
            PageFaultResult::ConnectionError
        }
    }
}

/// 指定されたアドレスがリモートページかどうかを確認
fn is_remote_page(process: &Process, addr: VirtualAddress) -> bool {
    // プロセスのリモートメモリマップをチェック
    process.memory.is_remote_mapped(addr)
}

/// リモートページIDを構築
fn build_remote_page_id(process: &Process, addr: VirtualAddress) -> RemotePageId {
    // プロセスから必要な情報を取得
    let node_id = process.memory.get_remote_page_node(addr).unwrap_or(0);
    
    RemotePageId {
        node_id,
        process_id: process.id,
        virtual_address: addr,
    }
}

/// リモートページを取得
fn fetch_remote_page(page_id: RemotePageId, req_type: RequestType) -> Result<PhysicalAddress, &'static str> {
    let telepage = global_telepage();
    
    // 既にローカルにキャッシュされているか確認
    if let Some(phys_addr) = telepage.get_cached_page(page_id) {
        // ヒット統計をインクリメント
        telepage.stats.local_page_hits.fetch_add(1, Ordering::Relaxed);
        return Ok(phys_addr);
    }
    
    // ページ転送リクエストを作成
    let request = telepage.create_transfer_request(page_id, req_type, 100);
    
    // リクエストをキューに追加
    telepage.queue_transfer_request(request);
    
    // ページが利用可能になるまで待機
    let current = current_thread().ok_or("現在のスレッドを取得できません")?;
    telepage.wait_for_page(page_id, current)?;
    
    // ページが利用可能になったので物理アドレスを取得
    telepage.get_page_physical_address(page_id).ok_or("ページの物理アドレスを取得できません")
}

/// 物理アドレスを仮想アドレスにマッピング
fn map_page(process: &Process, virt_addr: VirtualAddress, phys_addr: PhysicalAddress, flags: PageFlags) {
    // プロセスのページテーブルに物理ページをマッピング
    process.memory.map_page(virt_addr, phys_addr, flags);
}

/// TLBをフラッシュ
fn flush_tlb(addr: VirtualAddress) {
    // アーキテクチャ固有のTLBフラッシュ
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("invlpg [{}]", in(reg) addr);
        
        #[cfg(target_arch = "aarch64")]
        {
            // AArch64ではVMID/ASIDによるTLBフラッシュ
            core::arch::asm!("tlbi vaae1is, {}", in(reg) addr >> 12);
            core::arch::asm!("dsb ish");
            core::arch::asm!("isb");
        }
        
        #[cfg(target_arch = "riscv64")]
        {
            // RISC-Vではsfence.vma命令を使用
            core::arch::asm!("sfence.vma {}, x0", in(reg) addr >> 12);
        }
    }
}

/// 予測的プリフェッチを考慮
fn consider_prefetch(page_id: RemotePageId) {
    let telepage = global_telepage();
    
    // 予測エンジンが有効な場合のみ
    if !telepage.is_prediction_enabled() {
        return;
    }
    
    // 関連ページのプリフェッチを検討
    let candidates = telepage.predict_related_pages(page_id);
    
    // 候補がある場合はプリフェッチをキュー
    for candidate in candidates {
        telepage.queue_prefetch(candidate);
    }
}

/// ページ逆参照テーブル（マッピング解除時に使用）
pub struct PageReverseMap {
    // 物理アドレスから使用中のプロセスとアドレスへのマッピング
    mappings: crate::core::sync::RwLock<alloc::collections::BTreeMap<PhysicalAddress, Vec<(Arc<Process>, VirtualAddress)>>>,
}

impl PageReverseMap {
    /// 新しいページ逆参照テーブルを作成
    pub fn new() -> Self {
        Self {
            mappings: crate::core::sync::RwLock::new(alloc::collections::BTreeMap::new()),
        }
    }
    
    /// マッピングを追加
    pub fn add_mapping(&self, phys_addr: PhysicalAddress, process: Arc<Process>, virt_addr: VirtualAddress) {
        let mut mappings = self.mappings.write();
        let entries = mappings.entry(phys_addr).or_insert_with(Vec::new);
        entries.push((process, virt_addr));
    }
    
    /// マッピングを削除
    pub fn remove_mapping(&self, phys_addr: PhysicalAddress, process: &Process, virt_addr: VirtualAddress) {
        let mut mappings = self.mappings.write();
        if let Some(entries) = mappings.get_mut(&phys_addr) {
            entries.retain(|(p, v)| p.id != process.id || *v != virt_addr);
            if entries.is_empty() {
                mappings.remove(&phys_addr);
            }
        }
    }
    
    /// 物理アドレスの全マッピングを取得
    pub fn get_mappings(&self, phys_addr: PhysicalAddress) -> Vec<(Arc<Process>, VirtualAddress)> {
        let mappings = self.mappings.read();
        if let Some(entries) = mappings.get(&phys_addr) {
            entries.clone()
        } else {
            Vec::new()
        }
    }
}

/// グローバル逆参照テーブル
static mut PAGE_REVERSE_MAP: Option<PageReverseMap> = None;

/// 逆参照テーブルを初期化
pub fn init_reverse_map() {
    unsafe {
        if PAGE_REVERSE_MAP.is_none() {
            PAGE_REVERSE_MAP = Some(PageReverseMap::new());
        }
    }
}

/// グローバル逆参照テーブルを取得
pub fn global_reverse_map() -> &'static PageReverseMap {
    unsafe {
        PAGE_REVERSE_MAP.as_ref().expect("逆参照テーブルが初期化されていません")
    }
} 