// AetherOS マルチカーネルシステム
// 
// 単一のOS上で複数のカーネルインスタンスを同時に実行し、
// 究極の信頼性、パフォーマンス、および隔離を実現します。
// このアプローチはLinuxやWindowsの単一カーネルモデルを超える
// 新しい次元のOSアーキテクチャを提供します。

use crate::arch::cpu::{CpuSet, CpuInfo};
use crate::memory::{PhysicalMemoryRegion, VirtualAddress, PhysicalAddress};
use crate::process::{Process, Thread, Priority};
use crate::sync::{Mutex, SpinLock, RwLock};
use crate::scheduler::{KernelSchedulerPolicy};
use crate::time::{Duration, Instant};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};

/// マルチカーネル構成の最大カーネル数
pub const MAX_KERNELS: usize = 16;

/// カーネルインスタンスの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelType {
    /// プライマリカーネル（システム全体を管理）
    Primary,
    
    /// セキュリティカーネル（特権操作とセキュリティ機能に特化）
    Security,
    
    /// ストレージカーネル（I/Oとファイルシステム操作に特化）
    Storage,
    
    /// ネットワークカーネル（ネットワーク処理に特化）
    Network,
    
    /// リアルタイムカーネル（時間制約のあるタスクに特化）
    RealTime,
    
    /// ユーザーアプリケーション用カーネル
    Application,
    
    /// バックアップ/フェイルオーバーカーネル
    Backup,
    
    /// カスタムカーネル
    Custom(u32),
}

/// カーネルインスタンスの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelState {
    /// 初期化中
    Initializing,
    
    /// 実行中
    Running,
    
    /// 一時停止中
    Paused,
    
    /// 停止中
    Stopped,
    
    /// クラッシュ/エラー状態
    Crashed,
    
    /// シャットダウン中
    ShuttingDown,
}

/// カーネル間通信チャネルの種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkcChannelType {
    /// 共有メモリベース
    SharedMemory,
    
    /// メッセージパッシングベース
    MessagePassing,
    
    /// ハイパーバイザ支援型
    HypervisorAssisted,
    
    /// ダイレクトレジスタ転送
    DirectRegister,
}

/// カーネルインスタンス構造体
#[derive(Debug)]
pub struct KernelInstance {
    /// カーネルID
    pub id: u32,
    
    /// カーネルタイプ
    pub kernel_type: KernelType,
    
    /// カーネル名
    pub name: String,
    
    /// カーネル状態
    pub state: AtomicU32, // KernelState as u32
    
    /// 割り当てられたCPUコア
    pub assigned_cpus: CpuSet,
    
    /// 使用可能物理メモリ領域
    pub memory_regions: Vec<PhysicalMemoryRegion>,
    
    /// カーネルベースアドレス
    pub base_address: VirtualAddress,
    
    /// エントリーポイント
    pub entry_point: VirtualAddress,
    
    /// スタックポインタ
    pub stack_pointer: VirtualAddress,
    
    /// 起動時刻
    pub start_time: Option<Instant>,
    
    /// 最終ハートビート時刻
    pub last_heartbeat: AtomicU32,
    
    /// 健全性スコア (0-100)
    pub health_score: AtomicU32,
}

/// マルチカーネルマネージャ
pub struct MultiKernelManager {
    /// 実行中のカーネルインスタンス
    kernels: RwLock<BTreeMap<u32, KernelInstance>>,
    
    /// カーネル間通信チャネル
    ikc_channels: RwLock<Vec<IkcChannel>>,
    
    /// アクティブなプライマリカーネルID
    primary_kernel_id: AtomicU32,
    
    /// マルチカーネルモードが有効か
    enabled: AtomicBool,
    
    /// 最後に割り当てられたカーネルID
    last_kernel_id: AtomicU32,
    
    /// リソース管理ポリシー
    resource_policy: SpinLock<ResourcePolicy>,
    
    /// フェイルオーバー設定
    failover_config: Mutex<FailoverConfig>,
}

/// カーネル間通信チャネル
#[derive(Debug)]
pub struct IkcChannel {
    /// チャネルID
    pub id: u32,
    
    /// 送信元カーネルID
    pub source_kernel_id: u32,
    
    /// 宛先カーネルID
    pub target_kernel_id: u32,
    
    /// チャネルタイプ
    pub channel_type: IkcChannelType,
    
    /// 共有メモリ領域（該当する場合）
    pub shared_memory: Option<PhysicalAddress>,
    
    /// 共有メモリサイズ
    pub shared_memory_size: usize,
    
    /// 最終アクティビティタイムスタンプ
    pub last_activity: AtomicU32,
}

/// リソース管理ポリシー
#[derive(Debug, Clone)]
pub struct ResourcePolicy {
    /// CPU割り当て戦略
    pub cpu_allocation_strategy: CpuAllocationStrategy,
    
    /// メモリ割り当て戦略
    pub memory_allocation_strategy: MemoryAllocationStrategy,
    
    /// 自動スケーリング設定
    pub auto_scaling: bool,
    
    /// 動的リソース再配分
    pub dynamic_reallocation: bool,
    
    /// 優先度マッピング
    pub priority_mapping: BTreeMap<KernelType, Priority>,
}

/// CPU割り当て戦略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuAllocationStrategy {
    /// 静的分割（固定コア割り当て）
    StaticPartitioning,
    
    /// 動的分割（実行時調整）
    DynamicPartitioning,
    
    /// オーバーラップ許可（コア共有）
    OverlappingAllowed,
    
    /// 負荷ベース割り当て
    LoadBased,
}

/// メモリ割り当て戦略
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAllocationStrategy {
    /// 静的分割
    StaticPartitioning,
    
    /// 動的割り当て
    DynamicAllocation,
    
    /// オンデマンド割り当て
    OnDemand,
}

/// フェイルオーバー設定
#[derive(Debug, Clone)]
pub struct FailoverConfig {
    /// フェイルオーバーを有効にするか
    pub enabled: bool,
    
    /// 自動フェイルオーバー
    pub automatic: bool,
    
    /// プライマリからバックアップへの切り替えタイムアウト (ms)
    pub failover_timeout_ms: u32,
    
    /// 状態同期間隔 (ms)
    pub state_sync_interval_ms: u32,
    
    /// ヘルスチェック間隔 (ms)
    pub health_check_interval_ms: u32,
}

// MultiKernelManager のシングルトンインスタンス
static mut MULTI_KERNEL_MANAGER: Option<MultiKernelManager> = None;

impl MultiKernelManager {
    /// マルチカーネルマネージャを初期化
    pub fn init() -> &'static Self {
        let manager = Self {
            kernels: RwLock::new(BTreeMap::new()),
            ikc_channels: RwLock::new(Vec::new()),
            primary_kernel_id: AtomicU32::new(0),
            enabled: AtomicBool::new(true),
            last_kernel_id: AtomicU32::new(0),
            resource_policy: SpinLock::new(ResourcePolicy {
                cpu_allocation_strategy: CpuAllocationStrategy::DynamicPartitioning,
                memory_allocation_strategy: MemoryAllocationStrategy::DynamicAllocation,
                auto_scaling: true,
                dynamic_reallocation: true,
                priority_mapping: BTreeMap::new(),
            }),
            failover_config: Mutex::new(FailoverConfig {
                enabled: true,
                automatic: true,
                failover_timeout_ms: 1000,
                state_sync_interval_ms: 500,
                health_check_interval_ms: 100,
            }),
        };
        
        unsafe {
            MULTI_KERNEL_MANAGER = Some(manager);
            MULTI_KERNEL_MANAGER.as_ref().unwrap()
        }
    }
    
    /// マルチカーネルマネージャのインスタンスを取得
    pub fn instance() -> &'static Self {
        unsafe {
            MULTI_KERNEL_MANAGER.as_ref().expect("マルチカーネルマネージャが初期化されていません")
        }
    }
    
    /// 新しいカーネルインスタンスを作成
    pub fn create_kernel(&self, kernel_type: KernelType, name: &str, cpus: CpuSet) -> Result<u32, KernelError> {
        if self.kernels.read().unwrap().len() >= MAX_KERNELS {
            return Err(KernelError::TooManyKernels);
        }
        
        // 新しいカーネルIDを生成
        let kernel_id = self.last_kernel_id.fetch_add(1, Ordering::SeqCst) + 1;
        
        // メモリ領域を割り当て
        let memory_regions = self.allocate_memory_for_kernel(kernel_type)?;
        
        // ベースアドレスを計算
        let base_address = VirtualAddress::new(0xFFFF_0000_0000_0000 + (kernel_id as u64 * 0x1000_0000_0000));
        
        // 新しいカーネルインスタンスを作成
        let kernel = KernelInstance {
            id: kernel_id,
            kernel_type,
            name: name.to_string(),
            state: AtomicU32::new(KernelState::Initializing as u32),
            assigned_cpus: cpus,
            memory_regions,
            base_address,
            entry_point: base_address + 0x1000, // エントリーポイントはベースから4KB後
            stack_pointer: base_address + 0x100000, // スタックはベースから1MB後
            start_time: None,
            last_heartbeat: AtomicU32::new(0),
            health_score: AtomicU32::new(100),
        };
        
        // カーネルをマップに追加
        self.kernels.write().unwrap().insert(kernel_id, kernel);
        
        // プライマリカーネルの場合はIDを設定
        if kernel_type == KernelType::Primary {
            self.primary_kernel_id.store(kernel_id, Ordering::SeqCst);
        }
        
        log::info!("カーネル #{} '{}' ({:?}) を作成しました", kernel_id, name, kernel_type);
        
        Ok(kernel_id)
    }
    
    /// カーネルにメモリを割り当て
    fn allocate_memory_for_kernel(&self, kernel_type: KernelType) -> Result<Vec<PhysicalMemoryRegion>, KernelError> {
        // カーネルタイプに応じたメモリサイズを決定
        let base_size = match kernel_type {
            KernelType::Primary => 2 * 1024 * 1024 * 1024, // 2GB
            KernelType::Security => 512 * 1024 * 1024,    // 512MB
            KernelType::Storage => 1024 * 1024 * 1024,     // 1GB
            KernelType::Network => 1024 * 1024 * 1024,     // 1GB
            KernelType::RealTime => 256 * 1024 * 1024,    // 256MB
            KernelType::Application => 512 * 1024 * 1024,  // 512MB
            KernelType::Backup => 1024 * 1024 * 1024,      // 1GB
            KernelType::Custom(_) => 128 * 1024 * 1024,   // 128MB (カスタムカーネルのデフォルト)
        };

        // 物理メモリアロケータから連続した領域を確保
        // TODO: より高度なメモリ割り当て戦略（NUMA対応、特定バンク指定など）を実装
        let num_pages = (base_size + crate::core::memory::PAGE_SIZE - 1) / crate::core::memory::PAGE_SIZE;
        let allocated_start_addr = crate::core::memory::allocate_physical_pages(num_pages)
            .ok_or(KernelError::MemoryAllocationFailed)?;

        let region = PhysicalMemoryRegion {
            start: allocated_start_addr, // 物理メモリアロケータから取得したアドレス
            size: base_size,
            // TODO: メモリ領域の属性（キャッシュポリシーなど）を設定
            // memory_type: MemoryType::KernelCode, // 仮
        };

        log::info!("カーネルタイプ {:?} のために {} MB のメモリ領域を {:#x} から確保しました。", 
                   kernel_type, base_size / (1024 * 1024), allocated_start_addr.as_u64());

        Ok(vec![region])
    }
    
    /// カーネルインスタンスを起動
    pub fn start_kernel(&self, kernel_id: u32) -> Result<(), KernelError> {
        let mut kernels = self.kernels.write().unwrap();
        
        let kernel = kernels.get_mut(&kernel_id).ok_or(KernelError::KernelNotFound)?;
        
        // 現在の状態を確認
        let current_state = KernelState::from_u32(kernel.state.load(Ordering::SeqCst));
        if current_state != KernelState::Initializing && current_state != KernelState::Stopped {
            return Err(KernelError::InvalidState);
        }
        
        // カーネルを起動するためのセットアップ
        self.setup_kernel_environment(kernel)?;
        
        // 起動時刻を記録
        kernel.start_time = Some(Instant::now());
        
        // 状態を「実行中」に更新
        kernel.state.store(KernelState::Running as u32, Ordering::SeqCst);
        
        log::info!("カーネル #{} '{}' を起動しました", kernel_id, kernel.name);
        
        // 実際のカーネル起動処理（アーキテクチャ固有）
        self.arch_start_kernel(kernel)?;
        
        Ok(())
    }
    
    /// カーネル環境をセットアップ
    fn setup_kernel_environment(&self, kernel: &mut KernelInstance) -> Result<(), KernelError> {
        // CPUコアを割り当て
        crate::arch::cpu::assign_cores_to_kernel(kernel.id, &kernel.assigned_cpus)?;
        
        // カーネルメモリをマッピング
        for region in &kernel.memory_regions {
            crate::memory::map_kernel_memory(kernel.id, *region, kernel.base_address)?;
        }
        
        // IKCチャネルをセットアップ
        self.setup_ikc_channels(kernel.id)?;
        
        Ok(())
    }
    
    /// アーキテクチャ固有のカーネル起動処理
    fn arch_start_kernel(&self, kernel: &KernelInstance) -> Result<(), KernelError> {
        // TODO: アーキテクチャ固有のカーネル起動処理を実装する
        // カーネルのエントリーポイントにジャンプするコードなど
        log::info!("カーネル #{} ({}) をアーキテクチャ固有の方法で起動します (エントリー: {:#x}, スタック: {:#x})", 
                   kernel.id, kernel.name, kernel.entry_point.as_u64(), kernel.stack_pointer.as_u64());

        // TODO: アーキテクチャ固有のカーネル起動関数を呼び出す。
        //       この関数は新しいページテーブルの設定、CPUコンテキストの切り替え、
        //       指定されたエントリーポイントへのジャンプなどを行う必要がある。
        // 例: crate::arch::start_secondary_kernel(kernel.entry_point, kernel.stack_pointer, kernel.base_address, &kernel.memory_regions, kernel.assigned_cpus.get_first_cpu());
        //       引数は仮であり、アーキテクチャの要求に応じて調整が必要。

        // ダミー実装: 起動成功をログに出力するのみ
        log::warn!("arch_start_kernel: 現在はダミー実装です。実際のカーネル起動処理は実装されていません。");
        Ok(())
    }
    
    /// カーネル間通信チャネルをセットアップ
    fn setup_ikc_channels(&self, kernel_id: u32) -> Result<(), KernelError> {
        let mut ikc_channels = self.ikc_channels.write().unwrap();
        let kernels = self.kernels.read().unwrap();

        for (other_kernel_id, _other_kernel) in kernels.iter() {
            if *other_kernel_id == kernel_id { continue; }

            // 双方向チャネルを作成
            let channel_id_fwd = self.last_kernel_id.fetch_add(1, Ordering::Relaxed);
            let channel_id_bwd = self.last_kernel_id.fetch_add(1, Ordering::Relaxed);

            let shared_mem_size = 4096 * 16; // 64KB (仮のサイズ)
            // TODO: IKCチャネルタイプに応じて、より適切な共有メモリサイズを決定する

            let shared_mem_pages_fwd = (shared_mem_size + crate::core::memory::PAGE_SIZE - 1) / crate::core::memory::PAGE_SIZE;
            let shared_mem_addr_fwd = crate::core::memory::allocate_physical_pages(shared_mem_pages_fwd)
                .ok_or(KernelError::MemoryAllocationFailed)?;
            
            log::info!("IKCチャネル ({} -> {}): 共有メモリ {:#x} ({}KB) を確保", 
                       kernel_id, other_kernel_id, shared_mem_addr_fwd.as_u64(), shared_mem_size / 1024);

            ikc_channels.push(IkcChannel {
                id: channel_id_fwd,
                source_kernel_id: kernel_id,
                target_kernel_id: *other_kernel_id,
                channel_type: IkcChannelType::SharedMemory, // デフォルトは共有メモリ
                shared_memory: Some(shared_mem_addr_fwd),
                shared_memory_size: shared_mem_size,
                last_activity: AtomicU32::new(0),
            });

            let shared_mem_pages_bwd = (shared_mem_size + crate::core::memory::PAGE_SIZE - 1) / crate::core::memory::PAGE_SIZE;
            let shared_mem_addr_bwd = crate::core::memory::allocate_physical_pages(shared_mem_pages_bwd)
                .ok_or(KernelError::MemoryAllocationFailed)?;

            log::info!("IKCチャネル ({} -> {}): 共有メモリ {:#x} ({}KB) を確保", 
                       other_kernel_id, kernel_id, shared_mem_addr_bwd.as_u64(), shared_mem_size / 1024);

            ikc_channels.push(IkcChannel {
                id: channel_id_bwd,
                source_kernel_id: *other_kernel_id,
                target_kernel_id: kernel_id,
                channel_type: IkcChannelType::SharedMemory,
                shared_memory: Some(shared_mem_addr_bwd),
                shared_memory_size: shared_mem_size,
                last_activity: AtomicU32::new(0),
            });
        }
        Ok(())
    }
    
    /// カーネルを停止
    pub fn stop_kernel(&self, kernel_id: u32) -> Result<(), KernelError> {
        let mut kernels = self.kernels.write().unwrap();
        
        let kernel = kernels.get_mut(&kernel_id).ok_or(KernelError::KernelNotFound)?;
        
        // プライマリカーネルは停止できない
        if kernel.kernel_type == KernelType::Primary {
            return Err(KernelError::CannotStopPrimary);
        }
        
        // 現在の状態を確認
        let current_state = KernelState::from_u32(kernel.state.load(Ordering::SeqCst));
        if current_state != KernelState::Running && current_state != KernelState::Paused {
            return Err(KernelError::InvalidState);
        }
        
        // 状態を「シャットダウン中」に更新
        kernel.state.store(KernelState::ShuttingDown as u32, Ordering::SeqCst);
        
        // カーネルに停止シグナルを送信
        self.send_stop_signal(kernel_id)?;
        
        // 一定時間待機
        let timeout = Duration::from_millis(1000);
        let start = Instant::now();
        
        loop {
            // カーネルの状態を確認
            let state = KernelState::from_u32(kernel.state.load(Ordering::SeqCst));
            if state == KernelState::Stopped {
                break;
            }
            
            // タイムアウトチェック
            if Instant::now() - start > timeout {
                // 強制終了
                self.force_stop_kernel(kernel)?;
                break;
            }
            
            // 少し待機
            crate::time::sleep(Duration::from_millis(10));
        }
        
        // 状態を「停止」に更新
        kernel.state.store(KernelState::Stopped as u32, Ordering::SeqCst);
        
        log::info!("カーネル #{} '{}' を停止しました", kernel_id, kernel.name);
        
        Ok(())
    }
    
    /// カーネルに停止シグナルを送信
    fn send_stop_signal(&self, kernel_id: u32) -> Result<(), KernelError> {
        // TODO: 具体的なIPC機構を使用してカーネルに停止シグナルを送信する処理を実装する
        log::debug!("カーネル #{} に停止シグナルを送信中...", kernel_id);

        // TODO: IKC (Inter-Kernel Communication) を使用して停止メッセージを送信する。
        //       対象カーネルがメッセージを受信し、シャットダウン処理を開始するようにする。
        // 例:
        // let stop_message = IkcMessage::KernelControl { target_id: kernel_id, command: KernelControlCommand::Shutdown };
        // self.send_ikc_message_to_kernel(kernel_id, stop_message)?;

        // ダミー実装: 成功をログに出力するのみ
        log::warn!("send_stop_signal: 現在はダミー実装です。実際のIPC機構は実装されていません。");
        Ok(())
    }
    
    /// カーネルを強制停止
    fn force_stop_kernel(&self, kernel: &mut KernelInstance) -> Result<(), KernelError> {
        // TODO: アーキテクチャ固有のコードを使用して対象カーネルを強制停止する処理を実装する
        // 対象カーネルが動作しているCPUコアを特定し、強制的に停止させる
        log::warn!("カーネル #{} ({}) を強制停止します。割り当てCPU: {:?}", 
                   kernel.id, kernel.name, kernel.assigned_cpus);

        // TODO: アーキテクチャ固有のカーネル強制停止処理を実装する。
        //       これには、対象カーネルが使用しているCPUコアへの割り込み送信、
        //       実行中のプロセスの強制終了、リソースの強制解放などが含まれる可能性がある。
        //       非常に危険な操作であり、システムの不安定化を招く可能性があるため、慎重な設計が必要。
        // 例:
        // for cpu_id in kernel.assigned_cpus.iter() {
        //     crate::arch::force_stop_cpu(cpu_id)?;
        // }

        kernel.state.store(KernelState::Crashed as u32, Ordering::SeqCst);
        log::info!("カーネル #{} を強制停止し、状態を Crashed に設定しました。", kernel.id);
        Ok(())
    }
    
    /// バックアップカーネルにフェイルオーバー
    pub fn failover_to_backup_kernel() -> Result<(), KernelError> {
        let manager = Self::instance();
        
        // バックアップカーネルを検索
        let backup_id = {
            let kernels = manager.kernels.read().unwrap();
            let mut backup_id = None;
            
            for (id, kernel) in kernels.iter() {
                if kernel.kernel_type == KernelType::Backup {
                    let state = KernelState::from_u32(kernel.state.load(Ordering::SeqCst));
                    if state == KernelState::Running {
                        backup_id = Some(*id);
                        break;
                    }
                }
            }
            
            backup_id.ok_or(KernelError::NoBackupKernel)?
        };
        
        log::warn!("プライマリカーネルから バックアップカーネル #{} にフェイルオーバーします", backup_id);
        
        // バックアップをプライマリに昇格
        manager.promote_to_primary(backup_id)?;
        
        Ok(())
    }
    
    /// カーネルをプライマリに昇格
    fn promote_to_primary(&self, kernel_id: u32) -> Result<(), KernelError> {
        let mut kernels = self.kernels.write().unwrap();
        
        let kernel = kernels.get_mut(&kernel_id).ok_or(KernelError::KernelNotFound)?;
        
        // 現在の状態を確認
        let current_state = KernelState::from_u32(kernel.state.load(Ordering::SeqCst));
        if current_state != KernelState::Running {
            return Err(KernelError::InvalidState);
        }
        
        // カーネルタイプを変更
        kernel.kernel_type = KernelType::Primary;
        
        // プライマリカーネルIDを更新
        self.primary_kernel_id.store(kernel_id, Ordering::SeqCst);
        
        log::info!("カーネル #{} '{}' をプライマリに昇格しました", kernel_id, kernel.name);
        
        Ok(())
    }
    
    /// カーネルの状態を取得
    pub fn get_kernel_state(&self, kernel_id: u32) -> Result<KernelState, KernelError> {
        let kernels = self.kernels.read().unwrap();
        
        let kernel = kernels.get(&kernel_id).ok_or(KernelError::KernelNotFound)?;
        
        Ok(KernelState::from_u32(kernel.state.load(Ordering::SeqCst)))
    }
    
    /// カーネルの健全性をチェック
    pub fn check_kernel_health(&self, kernel_id: u32) -> Result<u32, KernelError> {
        let kernels = self.kernels.read().unwrap();
        
        let kernel = kernels.get(&kernel_id).ok_or(KernelError::KernelNotFound)?;
        
        Ok(kernel.health_score.load(Ordering::SeqCst))
    }
    
    /// すべてのカーネルの健全性をチェック
    pub fn check_all_kernels_health(&self) -> BTreeMap<u32, u32> {
        let kernels = self.kernels.read().unwrap();
        let mut health_map = BTreeMap::new();
        
        for (id, kernel) in kernels.iter() {
            let health = kernel.health_score.load(Ordering::SeqCst);
            health_map.insert(*id, health);
            
            // 健全性が低い場合は警告
            if health < 50 {
                log::warn!("カーネル #{} '{}' の健全性が低下しています: {}/100", 
                        *id, kernel.name, health);
            }
        }
        
        health_map
    }
    
    /// マルチカーネル情報を取得
    pub fn get_info(&self) -> MultiKernelInfo {
        let kernels = self.kernels.read().unwrap();
        let channels = self.ikc_channels.read().unwrap();
        
        MultiKernelInfo {
            kernel_count: kernels.len(),
            active_kernel_count: kernels.iter()
                .filter(|(_, k)| {
                    let state = KernelState::from_u32(k.state.load(Ordering::SeqCst));
                    state == KernelState::Running
                })
                .count(),
            primary_kernel_id: self.primary_kernel_id.load(Ordering::SeqCst),
            channel_count: channels.len(),
            enabled: self.enabled.load(Ordering::SeqCst),
        }
    }
}

impl KernelState {
    /// u32からKernelStateへの変換
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => KernelState::Initializing,
            1 => KernelState::Running,
            2 => KernelState::Paused,
            3 => KernelState::Stopped,
            4 => KernelState::Crashed,
            5 => KernelState::ShuttingDown,
            _ => KernelState::Crashed, // 不明な値の場合はCrashedとみなす
        }
    }
}

/// マルチカーネルエラー
#[derive(Debug, Clone, Copy)]
pub enum KernelError {
    /// カーネルが見つからない
    KernelNotFound,
    
    /// 無効な状態
    InvalidState,
    
    /// メモリ割り当て失敗
    MemoryAllocationFailed,
    
    /// プライマリカーネルを停止できない
    CannotStopPrimary,
    
    /// バックアップカーネルがない
    NoBackupKernel,
    
    /// カーネルの最大数に達した
    TooManyKernels,
    
    /// その他のエラー
    Other,
}

/// マルチカーネル情報
#[derive(Debug, Clone)]
pub struct MultiKernelInfo {
    /// カーネル数
    pub kernel_count: usize,
    
    /// アクティブなカーネル数
    pub active_kernel_count: usize,
    
    /// プライマリカーネルID
    pub primary_kernel_id: u32,
    
    /// IKCチャネル数
    pub channel_count: usize,
    
    /// マルチカーネルモードが有効か
    pub enabled: bool,
} 