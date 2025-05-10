// AetherOS プロセス管理サブシステム
//
// インテリジェント・プロセス管理システムを実装します:
// - 優先度自動調整
// - リアルタイム応答保証
// - 細粒度リソース制御
// - 耐障害性スケジューリング
// - 意図認識型タスク割り当て
// - プロセス間データフロー最適化

pub mod scheduler;       // プロセススケジューラ
pub mod task;            // タスク構造体とAPI
pub mod thread;          // スレッド管理
pub mod group;           // プロセスグループ管理
pub mod namespace;       // 名前空間管理
pub mod resource;        // リソース制限と割り当て
pub mod signal;          // シグナル処理
pub mod context;         // コンテキスト切り替え
pub mod adaptive;        // 適応型プロセス管理
pub mod realtime;        // リアルタイムスケジューリング
pub mod priority;        // 優先度管理
pub mod fault;           // 障害検出と回復
pub mod flowopt;         // データフロー最適化
pub mod intent;          // 意図認識とタスク割り当て

use crate::arch::{CpuState, ThreadContext};
use crate::sync::{Mutex, RwLock, SpinLock};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};

/// プロセスID型
pub type Pid = i32;
/// スレッドID型
pub type Tid = i32;
/// プロセスグループID型
pub type PgId = i32;
/// セッションID型
pub type SessId = i32;
/// ユーザーID型
pub type Uid = u32;
/// グループID型
pub type Gid = u32;

/// プロセス状態
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProcessState {
    /// 新規作成
    New,
    /// 実行可能
    Ready,
    /// 実行中
    Running,
    /// 停止中（シグナル等による）
    Stopped,
    /// スリープ中（I/O待ち等）
    Sleeping,
    /// ゾンビ（終了済みだが親プロセスが状態を回収していない）
    Zombie,
    /// 完全に終了
    Dead,
}

/// スレッド状態
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ThreadState {
    /// 新規作成
    New,
    /// 実行可能
    Ready,
    /// 実行中
    Running,
    /// I/O待ち
    Blocked,
    /// 一時停止
    Stopped,
    /// スリープ中
    Sleeping,
    /// 終了中
    Exiting,
    /// 終了済み
    Terminated,
}

/// スケジューリングポリシー
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SchedPolicy {
    /// 通常（デフォルト）
    Normal,
    /// バッチ処理
    Batch,
    /// アイドル優先度
    Idle,
    /// FIFO（リアルタイム）
    Fifo,
    /// ラウンドロビン（リアルタイム）
    RoundRobin,
    /// デッドライン駆動（リアルタイム）
    Deadline,
    /// 適応型（AetherOS独自）
    Adaptive,
}

/// プロセス優先度クラス
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PriorityClass {
    /// システム重要プロセス
    System,
    /// リアルタイム
    RealTime,
    /// 高優先度
    High,
    /// 通常優先度
    Normal,
    /// 低優先度
    Low,
    /// バックグラウンド
    Background,
    /// アイドル
    Idle,
}

/// リソース使用統計
#[derive(Debug, Clone)]
pub struct ResourceUsage {
    /// ユーザーモードでのCPU時間（ナノ秒）
    pub user_time_ns: u64,
    /// カーネルモードでのCPU時間（ナノ秒）
    pub system_time_ns: u64,
    /// メジャーページフォルト数
    pub major_page_faults: usize,
    /// マイナーページフォルト数
    pub minor_page_faults: usize,
    /// 最大常駐セットサイズ（バイト）
    pub max_rss: usize,
    /// 現在の常駐セットサイズ（バイト）
    pub current_rss: usize,
    /// 読み取り操作数
    pub read_ops: usize,
    /// 書き込み操作数
    pub write_ops: usize,
    /// 送信されたメッセージ数
    pub messages_sent: usize,
    /// 受信したメッセージ数
    pub messages_received: usize,
    /// 発生したシグナル数
    pub signals_received: usize,
    /// コンテキストスイッチ回数（自発的）
    pub voluntary_context_switches: usize,
    /// コンテキストスイッチ回数（非自発的）
    pub involuntary_context_switches: usize,
}

/// リソース制限
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// CPUタイム制限（ナノ秒）
    pub cpu_time: (u64, u64),     // (ソフトリミット, ハードリミット)
    /// ファイルサイズ制限（バイト）
    pub file_size: (u64, u64),
    /// データセグメントサイズ（バイト）
    pub data_size: (u64, u64),
    /// スタックサイズ（バイト）
    pub stack_size: (u64, u64),
    /// コアファイルサイズ（バイト）
    pub core_size: (u64, u64),
    /// 常駐メモリサイズ（バイト）
    pub resident_set: (u64, u64),
    /// プロセス数
    pub processes: (u32, u32),
    /// オープンファイル数
    pub open_files: (u32, u32),
    /// メモリロックサイズ（バイト）
    pub locked_memory: (u64, u64),
    /// アドレス空間サイズ（バイト）
    pub address_space: (u64, u64),
}

/// プロセス特性（挙動予測用）
#[derive(Debug, Clone)]
pub struct ProcessCharacteristics {
    /// I/O集中型かどうか
    pub io_intensive: bool,
    /// CPU集中型かどうか
    pub cpu_intensive: bool,
    /// メモリ集中型かどうか
    pub memory_intensive: bool,
    /// インタラクティブかどうか
    pub interactive: bool,
    /// バックグラウンドサービスかどうか
    pub background_service: bool,
    /// リアルタイム制約の厳しさ（0.0-1.0）
    pub realtime_strictness: f32,
    /// 予測されるCPU使用率（0.0-1.0）
    pub expected_cpu_usage: f32,
    /// 予測されるメモリ使用量（バイト）
    pub expected_memory_usage: usize,
    /// 予測されるI/O帯域（バイト/秒）
    pub expected_io_bandwidth: usize,
    /// 学習された実行パターン
    pub execution_pattern: Vec<(String, f32)>,
}

/// プロセス構造体
pub struct Process {
    /// プロセスID
    pub pid: Pid,
    /// 親プロセスID
    pub ppid: Pid,
    /// プロセスグループID
    pub pgid: PgId,
    /// セッションID
    pub session_id: SessId,
    /// 実効ユーザーID
    pub euid: Uid,
    /// 実ユーザーID
    pub uid: Uid,
    /// 保存されたユーザーID
    pub suid: Uid,
    /// 実効グループID
    pub egid: Gid,
    /// 実グループID
    pub gid: Gid,
    /// 保存されたグループID
    pub sgid: Gid,
    /// 補助グループIDリスト
    pub groups: Vec<Gid>,
    /// プロセス名
    pub name: String,
    /// 実行ファイルパス
    pub executable: String,
    /// 現在の作業ディレクトリ
    pub cwd: String,
    /// コマンドライン引数
    pub args: Vec<String>,
    /// 環境変数
    pub environ: BTreeMap<String, String>,
    /// プロセス状態
    pub state: SpinLock<ProcessState>,
    /// 終了コード
    pub exit_code: AtomicI32,
    /// リソース使用統計
    pub rusage: Mutex<ResourceUsage>,
    /// リソース制限
    pub rlimits: RwLock<ResourceLimits>,
    /// スレッドID → スレッド構造体マップ
    pub threads: RwLock<BTreeMap<Tid, Arc<Thread>>>,
    /// メインスレッド
    pub main_thread: Arc<Thread>,
    /// 子プロセスリスト
    pub children: RwLock<Vec<Weak<Process>>>,
    /// 親プロセス参照
    pub parent: Mutex<Option<Weak<Process>>>,
    /// 処理されていないシグナルキュー
    pub pending_signals: Mutex<VecDeque<Signal>>,
    /// シグナルマスク
    pub sigmask: AtomicU64,
    /// シグナルハンドラテーブル
    pub sighandlers: RwLock<[SignalHandler; 64]>,
    /// スケジューリングポリシー
    pub sched_policy: AtomicI32,
    /// スケジューリング優先度
    pub sched_priority: AtomicI32,
    /// 優先度クラス
    pub priority_class: AtomicI32,
    /// 最後にCPUで実行された時刻（ナノ秒）
    pub last_run_time: AtomicU64,
    /// 累積CPU時間（ナノ秒）
    pub cpu_time_ns: AtomicU64,
    /// AI予測による特性
    pub characteristics: RwLock<ProcessCharacteristics>,
    /// ファイルディスクリプタテーブル
    pub files: RwLock<Vec<Option<Arc<FileHandle>>>>,
    /// メモリマップ領域
    pub mmap_regions: RwLock<Vec<MmapRegion>>,
    /// 共有メモリセグメント
    pub shm_segments: RwLock<Vec<Arc<ShmSegment>>>,
    /// 名前空間
    pub namespaces: RwLock<ProcessNamespaces>,
    /// セキュリティコンテキスト
    pub security_context: RwLock<SecurityContext>,
    /// プロセス作成時刻（ナノ秒）
    pub start_time: u64,
    /// プロセス終了時刻（ナノ秒）
    pub end_time: AtomicU64,
    /// CPUアフィニティマスク
    pub cpu_affinity: AtomicU64,
    /// NUMAノードアフィニティ
    pub numa_policy: RwLock<NumaPolicy>,
    /// プロセス固有データ（拡張情報用）
    pub data: RwLock<BTreeMap<String, Vec<u8>>>,
}

/// スレッド構造体
pub struct Thread {
    /// スレッドID
    pub tid: Tid,
    /// 所属プロセスID
    pub pid: Pid,
    /// スレッド名
    pub name: String,
    /// スレッド状態
    pub state: SpinLock<ThreadState>,
    /// カーネルスタック
    pub kernel_stack: usize,
    /// カーネルスタックサイズ
    pub kernel_stack_size: usize,
    /// ユーザースタック
    pub user_stack: usize,
    /// ユーザースタックサイズ
    pub user_stack_size: usize,
    /// スレッドコンテキスト
    pub context: SpinLock<ThreadContext>,
    /// CPUコンテキスト（レジスタ状態）
    pub cpu_state: SpinLock<CpuState>,
    /// スレッド固有ストレージ（TLS）
    pub tls: usize,
    /// リソース使用統計
    pub rusage: Mutex<ResourceUsage>,
    /// 終了コード
    pub exit_code: AtomicI32,
    /// スケジューリング優先度
    pub sched_priority: AtomicI32,
    /// 最後に実行されたCPUコアID
    pub last_cpu: AtomicUsize,
    /// 最後にCPUで実行された時刻（ナノ秒）
    pub last_run_time: AtomicU64,
    /// 累積CPU時間（ナノ秒）
    pub cpu_time_ns: AtomicU64,
    /// 実行中フラグ
    pub running: AtomicBool,
    /// 実行キャンセル可能ポイント
    pub cancelation_point: AtomicBool,
    /// スレッド固有データ
    pub data: RwLock<BTreeMap<String, Vec<u8>>>,
    /// CPUアフィニティマスク
    pub cpu_affinity: AtomicU64,
    /// 処理中のシステムコール
    pub current_syscall: AtomicI32,
    /// システムコール引数
    pub syscall_args: [AtomicUsize; 6],
    /// 所属プロセス
    pub process: Weak<Process>,
}

/// シグナル
#[derive(Debug, Clone, Copy)]
pub struct Signal {
    /// シグナル番号
    pub signum: i32,
    /// 送信元プロセスID
    pub sender_pid: Pid,
    /// シグナルコード
    pub code: i32,
    /// シグナル付加情報
    pub info: SignalInfo,
}

/// シグナル付加情報
#[derive(Debug, Clone, Copy)]
pub enum SignalInfo {
    /// 一般的なシグナル
    Generic,
    /// キル
    Kill { uid: Uid },
    /// メモリ関連
    Memory { addr: usize, reason: MemorySignalReason },
    /// 子プロセス関連
    Child { pid: Pid, uid: Uid, status: i32 },
    /// タイマー関連
    Timer { timer_id: i32, overrun: i32 },
    /// I/O関連
    IO { fd: i32, band: i32 },
}

/// メモリシグナル理由
#[derive(Debug, Clone, Copy)]
pub enum MemorySignalReason {
    /// アドレス不正
    InvalidAddress,
    /// アクセス権限不足
    AccessViolation,
    /// アラインメント不正
    AlignmentFault,
    /// スタックオーバーフロー
    StackOverflow,
}

/// シグナルハンドラ
#[derive(Debug, Clone, Copy)]
pub enum SignalHandler {
    /// デフォルト処理
    Default,
    /// 無視
    Ignore,
    /// ユーザー定義ハンドラ
    Handler(usize),
    /// シグブロック
    SigAction(usize, u64),
}

/// プロセス名前空間
#[derive(Debug, Clone)]
pub struct ProcessNamespaces {
    /// ユーザー名前空間
    pub user: Arc<Namespace>,
    /// プロセス名前空間
    pub pid: Arc<Namespace>,
    /// ネットワーク名前空間
    pub net: Arc<Namespace>,
    /// マウント名前空間
    pub mnt: Arc<Namespace>,
    /// UTS（ホスト名など）名前空間
    pub uts: Arc<Namespace>,
    /// IPC名前空間
    pub ipc: Arc<Namespace>,
    /// cgroup名前空間
    pub cgroup: Arc<Namespace>,
    /// 時間名前空間
    pub time: Arc<Namespace>,
}

/// 名前空間
pub struct Namespace {
    /// 名前空間ID
    pub id: u64,
    /// 名前空間タイプ
    pub type_: NamespaceType,
    /// 参照カウント
    pub refcount: AtomicUsize,
    /// 名前空間特有データ
    pub data: RwLock<Vec<u8>>,
}

/// 名前空間タイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceType {
    User,
    Pid,
    Net,
    Mount,
    Uts,
    Ipc,
    Cgroup,
    Time,
}

/// ファイルハンドル
pub struct FileHandle {
    /// ファイルディスクリプタフラグ
    pub flags: AtomicI32,
    /// ファイルオフセット
    pub offset: AtomicU64,
    /// ファイルモード（アクセス権限）
    pub mode: AtomicU64,
    /// ファイルタイプ
    pub file_type: FileType,
    /// ファイル操作インターフェース
    pub ops: Arc<dyn FileOperations>,
    /// ファイルシステムノード
    pub inode: Arc<dyn FilesystemNode>,
    /// パス
    pub path: String,
}

/// ファイルタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    SymbolicLink,
    BlockDevice,
    CharDevice,
    Fifo,
    Socket,
    Unknown,
}

/// ファイルシステムノード
pub trait FilesystemNode: Send + Sync {
    /// ノードID取得
    fn get_id(&self) -> u64;
    /// ノード情報取得
    fn get_stat(&self) -> Result<FileStat, i32>;
    /// 所有者変更
    fn chown(&self, uid: Uid, gid: Gid) -> Result<(), i32>;
    /// アクセス権限変更
    fn chmod(&self, mode: u32) -> Result<(), i32>;
    /// サイズ取得
    fn size(&self) -> u64;
}

/// ファイル操作
pub trait FileOperations: Send + Sync {
    /// 読み取り
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize, i32>;
    /// 書き込み
    fn write(&self, offset: u64, buf: &[u8]) -> Result<usize, i32>;
    /// I/O制御
    fn ioctl(&self, cmd: u64, arg: usize) -> Result<i32, i32>;
    /// メモリマッピング
    fn mmap(&self, addr: usize, length: usize, prot: i32, flags: i32, offset: u64) -> Result<usize, i32>;
    /// 同期
    fn fsync(&self) -> Result<(), i32>;
    /// 切り詰め
    fn truncate(&self, size: u64) -> Result<(), i32>;
    /// 閉じる
    fn close(&self) -> Result<(), i32>;
}

/// ファイル情報
#[derive(Debug, Clone)]
pub struct FileStat {
    /// デバイスID
    pub dev: u64,
    /// ファイルシステム内のファイル一意識別子
    pub ino: u64,
    /// ファイルモード
    pub mode: u32,
    /// ハードリンク数
    pub nlink: u32,
    /// 所有者のユーザーID
    pub uid: Uid,
    /// 所有者のグループID
    pub gid: Gid,
    /// デバイスID（特殊ファイルの場合）
    pub rdev: u64,
    /// 合計サイズ（バイト単位）
    pub size: u64,
    /// ブロックサイズ
    pub blksize: u32,
    /// 割り当てられたブロック数
    pub blocks: u64,
    /// 最終アクセス時刻
    pub atime: TimeSpec,
    /// 最終修正時刻
    pub mtime: TimeSpec,
    /// 最終状態変更時刻
    pub ctime: TimeSpec,
    /// ファイル作成時刻
    pub birthtime: TimeSpec,
}

/// 時間仕様
#[derive(Debug, Clone, Copy)]
pub struct TimeSpec {
    /// 秒
    pub sec: i64,
    /// ナノ秒
    pub nsec: i32,
}

/// メモリマップ領域
#[derive(Debug, Clone)]
pub struct MmapRegion {
    /// 開始アドレス
    pub start: usize,
    /// 長さ
    pub length: usize,
    /// 保護フラグ
    pub prot: i32,
    /// マップフラグ
    pub flags: i32,
    /// ファイルオフセット
    pub offset: u64,
    /// ファイルハンドル（ファイルバックドの場合）
    pub file: Option<Weak<FileHandle>>,
}

/// 共有メモリセグメント
pub struct ShmSegment {
    /// セグメントID
    pub id: i32,
    /// 開始アドレス
    pub addr: usize,
    /// サイズ
    pub size: usize,
    /// アクセス権限
    pub perm: u32,
    /// 作成者UID
    pub cuid: Uid,
    /// 作成者GID
    pub cgid: Gid,
    /// 所有者UID
    pub uid: Uid,
    /// 所有者GID
    pub gid: Gid,
    /// 最終アタッチ時刻
    pub atime: TimeSpec,
    /// 最終デタッチ時刻
    pub dtime: TimeSpec,
    /// 最終変更時刻
    pub ctime: TimeSpec,
    /// アタッチプロセス数
    pub nattch: AtomicUsize,
    /// セグメントデータ
    pub data: *mut u8,
}

/// セキュリティコンテキスト
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// ケイパビリティセット（許可された特権）
    pub capabilities: Capabilities,
    /// セキュリティラベル
    pub security_label: String,
    /// アクセス制御リスト
    pub acl: Vec<AclEntry>,
    /// セキュリティ属性
    pub attributes: BTreeMap<String, String>,
}

/// ケイパビリティ
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    /// 許可されたケイパビリティセット
    pub permitted: u64,
    /// 有効なケイパビリティセット
    pub effective: u64,
    /// 継承可能なケイパビリティセット
    pub inheritable: u64,
    /// 周囲のケイパビリティセット
    pub ambient: u64,
    /// bounding（境界）ケイパビリティセット
    pub bounding: u64,
}

/// アクセス制御リストエントリ
#[derive(Debug, Clone)]
pub struct AclEntry {
    /// エントリタイプ
    pub entry_type: AclEntryType,
    /// ユーザー/グループID
    pub id: u32,
    /// アクセス権限
    pub perms: u32,
}

/// アクセス制御リストエントリタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclEntryType {
    User,
    Group,
    Other,
    Mask,
}

/// NUMAポリシー
#[derive(Debug, Clone)]
pub struct NumaPolicy {
    /// ポリシータイプ
    pub policy_type: NumaPolicyType,
    /// NUMAノードマスク
    pub node_mask: u64,
}

/// NUMAポリシータイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumaPolicyType {
    /// デフォルト
    Default,
    /// 指定ノードに拘束
    Bind,
    /// 指定ノードを優先
    Preferred,
    /// インターリーブ（分散配置）
    Interleave,
    /// ローカル（実行CPUに近いノード）
    Local,
}

// グローバル変数

/// 次に割り当てられるプロセスID
static NEXT_PID: AtomicI32 = AtomicI32::new(1);
/// 次に割り当てられるスレッドID
static NEXT_TID: AtomicI32 = AtomicI32::new(1);
/// プロセステーブル
static mut PROCESS_TABLE: Option<RwLock<BTreeMap<Pid, Arc<Process>>>> = None;
/// スレッドテーブル
static mut THREAD_TABLE: Option<RwLock<BTreeMap<Tid, Weak<Thread>>>> = None;
/// 現在のプロセス（CPUコアごと）
static mut CURRENT_PROCESS: Option<Vec<AtomicI32>> = None;
/// 現在のスレッド（CPUコアごと）
static mut CURRENT_THREAD: Option<Vec<AtomicI32>> = None;
/// init（PID 1）プロセス
static mut INIT_PROCESS: Option<Arc<Process>> = None;

// 公開API関数

/// プロセス管理サブシステムの初期化
pub fn init() {
    let cpu_count = crate::arch::get_cpu_count();
    
    // テーブルの初期化
    unsafe {
        PROCESS_TABLE = Some(RwLock::new(BTreeMap::new()));
        THREAD_TABLE = Some(RwLock::new(BTreeMap::new()));
        
        // CPUコアごとの現在のプロセス/スレッド追跡用配列
        let mut curr_proc = Vec::with_capacity(cpu_count);
        let mut curr_thread = Vec::with_capacity(cpu_count);
        
        for _ in 0..cpu_count {
            curr_proc.push(AtomicI32::new(-1));
            curr_thread.push(AtomicI32::new(-1));
        }
        
        CURRENT_PROCESS = Some(curr_proc);
        CURRENT_THREAD = Some(curr_thread);
    }
    
    // サブモジュールの初期化
    scheduler::init();
    task::init();
    thread::init();
    group::init();
    namespace::init();
    resource::init();
    signal::init();
    context::init();
    adaptive::init();
    realtime::init();
    priority::init();
    fault::init();
    flowopt::init();
    intent::init();
    
    log::info!("プロセス管理サブシステム初期化完了");
}

/// 初期化プロセス（PID 1）を作成し起動
pub fn spawn_init_process() {
    // initプロセスを作成
    match create_kernel_process("init", init_process_main) {
        Ok(process) => {
            // グローバル参照を保存
            unsafe {
                INIT_PROCESS = Some(process.clone());
            }
            
            log::info!("initプロセス（PID {}）起動完了", process.pid);
        }
        Err(e) => {
            panic!("initプロセスの作成に失敗: エラーコード {}", e);
        }
    }
}

/// カーネルプロセスを作成
pub fn create_kernel_process(name: &str, entry_point: fn()) -> Result<Arc<Process>, i32> {
    task::create_kernel_process(name, entry_point)
}

/// 現在のプロセスを取得
pub fn current_process() -> Option<Arc<Process>> {
    let cpu_id = crate::arch::get_current_cpu_id();
    
    unsafe {
        if let Some(current) = &CURRENT_PROCESS {
            let pid = current[cpu_id].load(Ordering::Acquire);
            if pid > 0 {
                if let Some(table) = &PROCESS_TABLE {
                    let table = table.read();
                    return table.get(&pid).cloned();
                }
            }
        }
        None
    }
}

/// 現在のスレッドを取得
pub fn current_thread() -> Option<Arc<Thread>> {
    let cpu_id = crate::arch::get_current_cpu_id();
    
    unsafe {
        if let Some(current) = &CURRENT_THREAD {
            let tid = current[cpu_id].load(Ordering::Acquire);
            if tid > 0 {
                if let Some(table) = &THREAD_TABLE {
                    let table = table.read();
                    if let Some(weak_thread) = table.get(&tid) {
                        return weak_thread.upgrade();
                    }
                }
            }
        }
        None
    }
}

/// プロセスをPIDで検索
pub fn get_process_by_pid(pid: Pid) -> Option<Arc<Process>> {
    unsafe {
        if let Some(table) = &PROCESS_TABLE {
            let table = table.read();
            return table.get(&pid).cloned();
        }
        None
    }
}

/// スレッドをTIDで検索
pub fn get_thread_by_tid(tid: Tid) -> Option<Arc<Thread>> {
    unsafe {
        if let Some(table) = &THREAD_TABLE {
            let table = table.read();
            if let Some(weak_thread) = table.get(&tid) {
                return weak_thread.upgrade();
            }
        }
        None
    }
}

/// プロセスリストを取得
pub fn get_process_list() -> Vec<Arc<Process>> {
    unsafe {
        if let Some(table) = &PROCESS_TABLE {
            let table = table.read();
            return table.values().cloned().collect();
        }
        Vec::new()
    }
}

/// 新しいプロセスIDを生成
pub fn allocate_pid() -> Pid {
    NEXT_PID.fetch_add(1, Ordering::SeqCst)
}

/// 新しいスレッドIDを生成
pub fn allocate_tid() -> Tid {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// カレントプロセスの更新
pub fn set_current_process(process: &Arc<Process>) {
    let cpu_id = crate::arch::get_current_cpu_id();
    
    unsafe {
        if let Some(current) = &CURRENT_PROCESS {
            current[cpu_id].store(process.pid, Ordering::Release);
        }
    }
}

/// カレントスレッドの更新
pub fn set_current_thread(thread: &Arc<Thread>) {
    let cpu_id = crate::arch::get_current_cpu_id();
    
    unsafe {
        if let Some(current) = &CURRENT_THREAD {
            current[cpu_id].store(thread.tid, Ordering::Release);
        }
    }
}

/// initプロセスのメイン関数
fn init_process_main() {
    log::info!("initプロセス: 実行開始");
    
    // システム初期化サービスを起動
    // 実際の実装ではここでシステムサービスを順次起動します
    
    // スレッドを永久スリープ状態にする（実際の実装ではプロセス管理を行う）
    loop {
        crate::time::sleep_ms(1000);
    }
} 