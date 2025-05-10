// AetherOS バディアロケータブロック管理
//
// このモジュールはバディアロケータのメモリブロックを管理します。
// ブロックヘッダ、ブロック情報、状態管理などを実装します。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use core::ptr::NonNull;
use core::mem;

/// ブロックマジックナンバー（メモリ破損検出用）
const BLOCK_MAGIC: u32 = 0xA173_05A1;
/// キャッシュラインサイズ（通常64バイト）
const CACHE_LINE_SIZE: usize = 64;

/// ブロックの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockState {
    /// 空きブロック
    Free,
    /// 割り当て済みブロック
    Allocated,
    /// 分割済みブロック（子ブロックが存在）
    Split,
    /// 予約済みブロック（システム使用）
    Reserved,
    /// 不良ブロック（ハードウェア障害など）
    BadBlock,
}

/// ブロック情報
#[derive(Debug, Clone)]
pub struct BlockInfo {
    /// ブロックの物理アドレス
    pub phys_addr: usize,
    /// ブロックのサイズ（バイト）
    pub size: usize,
    /// ブロックのオーダー
    pub order: usize,
    /// ブロックの現在の状態
    pub state: BlockState,
    /// NUMAノードID
    pub numa_node: u8,
    /// アクセスカウント（ホット/コールド分析用）
    pub access_count: usize,
}

/// メモリブロックヘッダ
/// 
/// メモリブロック管理のためのヘッダ構造体。
/// キャッシュラインにアライメントされています。
#[repr(C, align(64))]
pub struct BlockHeader {
    /// マジックナンバー（メモリ破損検出用）
    magic: AtomicU32,
    /// ブロックオーダー
    order: u8,
    /// ブロックの状態
    state: AtomicU8,
    /// NUMAノードID
    numa_node: u8,
    /// 予約（アライメント用）
    _reserved: u8,
    /// 割り当てID（トレース用）
    allocation_id: AtomicU32,
    /// 前のブロックへのポインタ（フリーリスト用）
    prev: AtomicPtr<BlockHeader>,
    /// 次のブロックへのポインタ（フリーリスト用）
    next: AtomicPtr<BlockHeader>,
    /// 親ブロックへのポインタ
    parent: AtomicPtr<BlockHeader>,
    /// 左の子ブロックへのポインタ
    left_child: AtomicPtr<BlockHeader>,
    /// 右の子ブロックへのポインタ
    right_child: AtomicPtr<BlockHeader>,
    /// アクセスカウント（ホット/コールド分析用）
    access_count: AtomicUsize,
    /// 割り当て時間（統計用）
    allocation_time: AtomicU64,
    /// 使用目的タグ（デバッグ用）
    purpose_tag: [u8; 8],
    /// パディング（キャッシュライン境界調整用）
    _padding: [u8; 8],
}

/// アトミックポインタの型エイリアス
type AtomicPtr<T> = core::sync::atomic::AtomicPtr<T>;
/// アトミックU8の型エイリアス
type AtomicU8 = core::sync::atomic::AtomicU8;
/// アトミックU64の型エイリアス
type AtomicU64 = core::sync::atomic::AtomicU64;

impl BlockHeader {
    /// 新しいブロックヘッダを作成
    pub fn new(order: u8, numa_node: u8) -> Self {
        Self {
            magic: AtomicU32::new(BLOCK_MAGIC),
            order,
            state: AtomicU8::new(BlockState::Free as u8),
            numa_node,
            _reserved: 0,
            allocation_id: AtomicU32::new(0),
            prev: AtomicPtr::new(core::ptr::null_mut()),
            next: AtomicPtr::new(core::ptr::null_mut()),
            parent: AtomicPtr::new(core::ptr::null_mut()),
            left_child: AtomicPtr::new(core::ptr::null_mut()),
            right_child: AtomicPtr::new(core::ptr::null_mut()),
            access_count: AtomicUsize::new(0),
            allocation_time: AtomicU64::new(0),
            purpose_tag: [0; 8],
            _padding: [0; 8],
        }
    }

    /// マジックナンバーを検証
    pub fn validate_magic(&self) -> bool {
        self.magic.load(Ordering::Relaxed) == BLOCK_MAGIC
    }

    /// ブロックの状態を取得
    pub fn get_state(&self) -> BlockState {
        let state_u8 = self.state.load(Ordering::Acquire);
        match state_u8 {
            0 => BlockState::Free,
            1 => BlockState::Allocated,
            2 => BlockState::Split,
            3 => BlockState::Reserved,
            _ => BlockState::BadBlock,
        }
    }

    /// ブロックの状態を設定
    pub fn set_state(&self, state: BlockState) {
        self.state.store(state as u8, Ordering::Release);
    }

    /// 前のブロックを設定
    pub fn set_prev(&self, prev: *mut BlockHeader) {
        self.prev.store(prev, Ordering::Release);
    }

    /// 次のブロックを設定
    pub fn set_next(&self, next: *mut BlockHeader) {
        self.next.store(next, Ordering::Release);
    }

    /// 親ブロックを設定
    pub fn set_parent(&self, parent: *mut BlockHeader) {
        self.parent.store(parent, Ordering::Release);
    }

    /// 左の子ブロックを設定
    pub fn set_left_child(&self, child: *mut BlockHeader) {
        self.left_child.store(child, Ordering::Release);
    }

    /// 右の子ブロックを設定
    pub fn set_right_child(&self, child: *mut BlockHeader) {
        self.right_child.store(child, Ordering::Release);
    }

    /// 前のブロックを取得
    pub fn get_prev(&self) -> *mut BlockHeader {
        self.prev.load(Ordering::Acquire)
    }

    /// 次のブロックを取得
    pub fn get_next(&self) -> *mut BlockHeader {
        self.next.load(Ordering::Acquire)
    }

    /// 親ブロックを取得
    pub fn get_parent(&self) -> *mut BlockHeader {
        self.parent.load(Ordering::Acquire)
    }

    /// 左の子ブロックを取得
    pub fn get_left_child(&self) -> *mut BlockHeader {
        self.left_child.load(Ordering::Acquire)
    }

    /// 右の子ブロックを取得
    pub fn get_right_child(&self) -> *mut BlockHeader {
        self.right_child.load(Ordering::Acquire)
    }

    /// ブロックのオーダーを取得
    pub fn get_order(&self) -> u8 {
        self.order
    }

    /// ブロックのNUMAノードを取得
    pub fn get_numa_node(&self) -> u8 {
        self.numa_node
    }

    /// アクセスカウントをインクリメント
    pub fn increment_access_count(&self) {
        self.access_count.fetch_add(1, Ordering::Relaxed);
    }

    /// アクセスカウントを取得
    pub fn get_access_count(&self) -> usize {
        self.access_count.load(Ordering::Relaxed)
    }

    /// 割り当て時間を設定
    pub fn set_allocation_time(&self, time: u64) {
        self.allocation_time.store(time, Ordering::Relaxed);
    }

    /// 割り当て時間を取得
    pub fn get_allocation_time(&self) -> u64 {
        self.allocation_time.load(Ordering::Relaxed)
    }

    /// 使用目的タグを設定
    pub fn set_purpose_tag(&mut self, tag: &[u8; 8]) {
        self.purpose_tag.copy_from_slice(tag);
    }

    /// 割り当てIDを設定
    pub fn set_allocation_id(&self, id: u32) {
        self.allocation_id.store(id, Ordering::Relaxed);
    }

    /// 割り当てIDを取得
    pub fn get_allocation_id(&self) -> u32 {
        self.allocation_id.load(Ordering::Relaxed)
    }
}

/// BlockHeaderをスレッド間で共有可能とマーク
unsafe impl Send for BlockHeader {}
/// BlockHeaderをスレッド間で同期可能とマーク
unsafe impl Sync for BlockHeader {} 