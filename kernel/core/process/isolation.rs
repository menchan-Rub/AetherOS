// AetherOS プロセス空間分離・隔離システム
//
// このモジュールはプロセス間の強力な空間分離と隔離機能を提供します。
// ハードウェア支援型の隔離技術とソフトウェアベースの保護を組み合わせています。

use crate::arch;
use crate::core::process::{Process, Thread, ProcessId, ThreadId};
use crate::core::memory::{MemoryPermission, VirtualMemory, MemoryRegion};
use crate::core::sync::{Mutex, RwLock, SpinLock};
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// 分離レベル
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IsolationLevel {
    /// 分離なし（完全共有）
    None,
    /// 基本分離（標準的なプロセス分離）
    Basic,
    /// 拡張分離（特権分離による強力な保護）
    Enhanced,
    /// 最高分離（ハードウェア支援型の完全分離）
    Maximum,
}

/// 分離ドメイン
/// 同じ分離ドメインに属するプロセスは特定のリソースを共有できる
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationDomain {
    /// ドメインID
    id: usize,
    /// ドメイン名
    name: String,
    /// 分離レベル
    level: IsolationLevel,
    /// メンバープロセスID
    members: Vec<ProcessId>,
    /// ドメイン間通信が許可されたドメインID
    allowed_communication: Vec<usize>,
    /// 特権操作が許可されているか
    privileged: bool,
    /// リソース制限
    resource_limits: ResourceLimits,
}

/// リソース制限
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    /// メモリ上限（バイト）
    memory_limit: usize,
    /// CPU時間割合上限（0-100）
    cpu_percentage: usize,
    /// ストレージ容量上限（バイト）
    storage_limit: usize,
    /// ネットワーク帯域幅（バイト/秒）
    network_bandwidth: usize,
    /// I/O操作数上限（毎秒）
    io_operations: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_limit: usize::MAX,
            cpu_percentage: 100,
            storage_limit: usize::MAX,
            network_bandwidth: usize::MAX,
            io_operations: usize::MAX,
        }
    }
}

/// トラストレベル（セキュリティ信頼性）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    /// システム（最高レベル、カーネル自身）
    System,
    /// 特権（システムサービス）
    Privileged,
    /// 標準（一般アプリケーション）
    Standard,
    /// 制限（サンドボックス）
    Restricted,
    /// 未信頼（外部からのコード）
    Untrusted,
}

/// メモリ分離技術
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryIsolationTech {
    /// 仮想メモリ（標準的なページテーブル）
    VirtualMemory,
    /// EPT（Extended Page Tables、仮想化支援）
    EPT,
    /// MPK（Memory Protection Keys）
    MPK,
    /// SME/SEV（Secure Memory Encryption）
    SME,
    /// IOMMU（DMA保護）
    IOMMU,
}

/// 隔離ドメインマネージャー
pub struct IsolationManager {
    /// 分離ドメイン
    domains: RwLock<BTreeMap<usize, IsolationDomain>>,
    /// プロセスIDとドメインIDのマッピング
    process_domain_map: RwLock<BTreeMap<ProcessId, usize>>,
    /// 次の利用可能なドメインID
    next_domain_id: AtomicUsize,
    /// サポートされているメモリ分離技術
    supported_isolation_tech: Vec<MemoryIsolationTech>,
    /// MPKキー割り当て（MPK技術を使用する場合）
    mpk_key_allocation: SpinLock<Vec<bool>>,
    /// MPK有効フラグ
    mpk_enabled: AtomicBool,
    /// IOMMU有効フラグ
    iommu_enabled: AtomicBool,
}

impl IsolationManager {
    /// 新しい隔離マネージャーを作成
    pub fn new() -> Self {
        // サポートされている分離技術を検出
        let mut supported_tech = Vec::new();
        
        supported_tech.push(MemoryIsolationTech::VirtualMemory);
        
        if arch::has_extended_page_tables() {
            supported_tech.push(MemoryIsolationTech::EPT);
        }
        
        if arch::has_memory_protection_keys() {
            supported_tech.push(MemoryIsolationTech::MPK);
        }
        
        if arch::has_secure_memory_encryption() {
            supported_tech.push(MemoryIsolationTech::SME);
        }
        
        if arch::has_iommu() {
            supported_tech.push(MemoryIsolationTech::IOMMU);
        }
        
        // デフォルトドメイン（システム用）を作成
        let mut domains = BTreeMap::new();
        domains.insert(0, IsolationDomain {
            id: 0,
            name: "System".to_string(),
            level: IsolationLevel::Maximum,
            members: Vec::new(),
            allowed_communication: Vec::new(),
            privileged: true,
            resource_limits: ResourceLimits::default(),
        });
        
        Self {
            domains: RwLock::new(domains),
            process_domain_map: RwLock::new(BTreeMap::new()),
            next_domain_id: AtomicUsize::new(1), // 0はシステム用
            supported_isolation_tech: supported_tech,
            mpk_key_allocation: SpinLock::new(vec![false; 16]), // x86では通常16キー
            mpk_enabled: AtomicBool::new(false),
            iommu_enabled: AtomicBool::new(false),
        }
    }
    
    /// 新しい分離ドメインを作成
    pub fn create_domain(&self, name: &str, level: IsolationLevel, privileged: bool) -> usize {
        let domain_id = self.next_domain_id.fetch_add(1, Ordering::Relaxed);
        
        let domain = IsolationDomain {
            id: domain_id,
            name: name.to_string(),
            level,
            members: Vec::new(),
            allowed_communication: Vec::new(),
            privileged,
            resource_limits: ResourceLimits::default(),
        };
        
        let mut domains = self.domains.write();
        domains.insert(domain_id, domain);
        
        domain_id
    }
    
    /// プロセスをドメインに追加
    pub fn add_process_to_domain(&self, process_id: ProcessId, domain_id: usize) -> bool {
        // ドメインを取得
        let mut domains = self.domains.write();
        if let Some(domain) = domains.get_mut(&domain_id) {
            // プロセスをドメインに追加
            if !domain.members.contains(&process_id) {
                domain.members.push(process_id);
                
                // マッピングを更新
                let mut map = self.process_domain_map.write();
                map.insert(process_id, domain_id);
                
                // ハードウェア分離を適用（必要に応じて）
                self.apply_hw_isolation(process_id, domain_id);
                
                return true;
            }
        }
        
        false
    }
    
    /// プロセスのドメインを取得
    pub fn get_process_domain(&self, process_id: ProcessId) -> Option<usize> {
        let map = self.process_domain_map.read();
        map.get(&process_id).copied()
    }
    
    /// ドメイン間通信の許可設定
    pub fn allow_communication(&self, from_domain: usize, to_domain: usize) -> bool {
        let mut domains = self.domains.write();
        
        if let Some(domain) = domains.get_mut(&from_domain) {
            if !domain.allowed_communication.contains(&to_domain) {
                domain.allowed_communication.push(to_domain);
                return true;
            }
        }
        
        false
    }
    
    /// ドメイン間通信が許可されているか確認
    pub fn is_communication_allowed(&self, from_domain: usize, to_domain: usize) -> bool {
        let domains = self.domains.read();
        
        if let Some(domain) = domains.get(&from_domain) {
            return domain.allowed_communication.contains(&to_domain);
        }
        
        false
    }
    
    /// 2つのプロセス間の通信が許可されているか確認
    pub fn can_processes_communicate(&self, pid1: ProcessId, pid2: ProcessId) -> bool {
        let map = self.process_domain_map.read();
        
        if let (Some(&domain1), Some(&domain2)) = (map.get(&pid1), map.get(&pid2)) {
            // 同じドメインなら常に許可
            if domain1 == domain2 {
                return true;
            }
            
            // ドメイン間通信の許可をチェック
            return self.is_communication_allowed(domain1, domain2);
        }
        
        // マッピングがない場合はデフォルトで許可
        true
    }
    
    /// ドメインリソース制限の設定
    pub fn set_resource_limits(&self, domain_id: usize, limits: ResourceLimits) -> bool {
        let mut domains = self.domains.write();
        
        if let Some(domain) = domains.get_mut(&domain_id) {
            domain.resource_limits = limits;
            return true;
        }
        
        false
    }
    
    /// 特定のプロセスにMPKキーを割り当て
    fn allocate_mpk_key(&self) -> Option<usize> {
        if !self.mpk_enabled.load(Ordering::Relaxed) {
            return None;
        }
        
        let mut keys = self.mpk_key_allocation.lock();
        
        // 空きキーを探す
        for (i, &used) in keys.iter().enumerate() {
            if !used {
                keys[i] = true;
                return Some(i);
            }
        }
        
        None
    }
    
    /// MPKキーを解放
    fn free_mpk_key(&self, key: usize) {
        if !self.mpk_enabled.load(Ordering::Relaxed) {
            return;
        }
        
        let mut keys = self.mpk_key_allocation.lock();
        if key < keys.len() {
            keys[key] = false;
        }
    }
    
    /// ハードウェア分離を適用
    fn apply_hw_isolation(&self, process_id: ProcessId, domain_id: usize) {
        let domains = self.domains.read();
        
        if let Some(domain) = domains.get(&domain_id) {
            match domain.level {
                IsolationLevel::None => {
                    // 分離なし、追加のハードウェア分離は不要
                },
                IsolationLevel::Basic => {
                    // 基本分離は標準の仮想メモリで十分
                },
                IsolationLevel::Enhanced => {
                    // 拡張分離：MPKが利用可能なら適用
                    if self.supported_isolation_tech.contains(&MemoryIsolationTech::MPK) {
                        if let Some(key) = self.allocate_mpk_key() {
                            // MPKキーをプロセスに実際に適用
                            self.apply_mpk_key_to_process(process_id, key)?;
                            
                            // ページ保護を適用
                            crate::arch::apply_mpk_protection(process_id, key)?;
                            
                            log::info!("プロセス {} にMPKキー {} を適用しました", process_id, key);
                        }
                    }
                },
                IsolationLevel::Maximum => {
                    // 最大分離：利用可能な全ての技術を適用
                    
                    // EPT（仮想化支援）が利用可能なら適用
                    if self.supported_isolation_tech.contains(&MemoryIsolationTech::EPT) {
                        // arch::apply_ept_isolation(process_id);
                    }
                    
                    // SME/SEV（メモリ暗号化）が利用可能なら適用
                    if self.supported_isolation_tech.contains(&MemoryIsolationTech::SME) {
                        // arch::apply_memory_encryption(process_id);
                    }
                    
                    // IOMMUが利用可能ならDMA保護を適用
                    if self.supported_isolation_tech.contains(&MemoryIsolationTech::IOMMU) && 
                       self.iommu_enabled.load(Ordering::Relaxed) {
                        // arch::apply_iommu_protection(process_id);
                    }
                },
            }
        }
    }
    
    /// 利用可能な分離技術を取得
    pub fn get_supported_technologies(&self) -> &[MemoryIsolationTech] {
        &self.supported_isolation_tech
    }
    
    /// MPKサポートを有効化
    pub fn enable_mpk(&self) -> bool {
        if self.supported_isolation_tech.contains(&MemoryIsolationTech::MPK) {
            // MPKを有効化
            if arch::enable_memory_protection_keys() {
                self.mpk_enabled.store(true, Ordering::Relaxed);
                return true;
            }
        }
        
        false
    }
    
    /// IOMMUサポートを有効化
    pub fn enable_iommu(&self) -> bool {
        if self.supported_isolation_tech.contains(&MemoryIsolationTech::IOMMU) {
            // IOMMUを有効化
            if arch::enable_iommu() {
                self.iommu_enabled.store(true, Ordering::Relaxed);
                return true;
            }
        }
        
        false
    }
    
    /// サポートされているメモリ分離技術を検出する補助関数
    fn detect_supported_technologies() -> Vec<MemoryIsolationTech> {
        let mut techs = vec![MemoryIsolationTech::VirtualMemory]; // 常にサポート
        
        // x86_64固有の技術を検出
        #[cfg(target_arch = "x86_64")]
        {
            if crate::arch::x86_64::features::has_mpk() {
                techs.push(MemoryIsolationTech::MPK);
            }
            if crate::arch::x86_64::features::has_ept() {
                techs.push(MemoryIsolationTech::EPT);
            }
            if crate::arch::x86_64::features::has_sme() {
                techs.push(MemoryIsolationTech::SME);
            }
        }
        
        // IOMMU検出
        if crate::drivers::iommu::is_available() {
            techs.push(MemoryIsolationTech::IOMMU);
        }
        
        techs
    }
    
    /// MPKキーをプロセスに適用
    fn apply_mpk_key_to_process(&self, process_id: ProcessId, mpk_key: usize) -> Result<(), &'static str> {
        // プロセス管理システムからプロセス情報を取得
        if let Ok(process_manager) = crate::core::process::ProcessManager::instance() {
            // プロセス構造体にMPKキーを設定
            process_manager.set_mpk_key(process_id, mpk_key)?;
            
            // プロセスのメモリ領域にMPK保護を適用
            let memory_regions = process_manager.get_memory_regions(process_id)?;
            
            for region in memory_regions {
                // 各メモリ領域にMPKキーを関連付け
                self.apply_mpk_to_memory_region(&region, mpk_key)?;
            }
            
            log::debug!("プロセス {} のメモリ領域 {} 個にMPKキー {} を適用", 
                       process_id, memory_regions.len(), mpk_key);
        } else {
            return Err("プロセス管理システムにアクセスできません");
        }
        
        Ok(())
    }
    
    /// メモリ領域にMPK保護を適用
    fn apply_mpk_to_memory_region(
        &self, 
        region: &MemoryRegion, 
        mpk_key: usize
    ) -> Result<(), &'static str> {
        let start_addr = region.start_address;
        let end_addr = region.end_address;
        let page_size = crate::arch::PAGE_SIZE;
        
        // ページ単位でMPKキーを設定
        let mut current_addr = start_addr;
        while current_addr < end_addr {
            // ページテーブルエントリにMPKキーを設定
            crate::arch::mm::set_page_mpk_key(current_addr, mpk_key)?;
            current_addr += page_size;
        }
        
        // PKRUレジスタを更新してアクセス権限を設定
        let access_rights = self.calculate_mpk_access_rights(region.permissions);
        crate::arch::x86_64::mpk::set_pkru_for_key(mpk_key, access_rights)?;
        
        log::trace!("メモリ領域 0x{:x}-0x{:x} にMPKキー {} を適用（権限: {:?}）", 
                   start_addr, end_addr, mpk_key, access_rights);
        
        Ok(())
    }
    
    /// MPKアクセス権限を計算
    fn calculate_mpk_access_rights(&self, permissions: MemoryPermissions) -> MPKAccessRights {
        let mut rights = MPKAccessRights::empty();
        
        if permissions.contains(MemoryPermissions::READ) {
            rights |= MPKAccessRights::READ();
        }
        
        if permissions.contains(MemoryPermissions::WRITE) {
            rights |= MPKAccessRights::write();
        }
        
        if permissions.contains(MemoryPermissions::EXECUTE) {
            // MPKは実行権限を直接制御しないが、NXビットとの組み合わせで制御
            rights |= MPKAccessRights::execute();
        }
        
        rights
    }
    
    /// ドメイン情報を取得
    pub fn get_domain_info(&self, domain_id: usize) -> Option<IsolationDomain> {
        let domains = self.domains.read().ok()?;
        domains.get(&domain_id).cloned()
    }
}

/// 分離違反ポリシー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationViolationPolicy {
    /// 無視（警告のみ）
    Ignore,
    /// ブロック（操作を拒否）
    Block,
    /// 強制終了（プロセスを終了）
    Terminate,
    /// パニック（カーネルパニック）
    Panic,
}

/// 分離違反ハンドラー
pub struct IsolationViolationHandler {
    /// デフォルトポリシー
    default_policy: IsolationViolationPolicy,
    /// ドメインごとのカスタムポリシー
    domain_policies: RwLock<BTreeMap<usize, IsolationViolationPolicy>>,
    /// 違反ログ記録が有効か
    logging_enabled: AtomicBool,
    /// 違反通知が有効か
    notifications_enabled: AtomicBool,
}

impl IsolationViolationHandler {
    /// 新しい違反ハンドラーを作成
    pub fn new(default_policy: IsolationViolationPolicy) -> Self {
        Self {
            default_policy,
            domain_policies: RwLock::new(BTreeMap::new()),
            logging_enabled: AtomicBool::new(true),
            notifications_enabled: AtomicBool::new(true),
        }
    }
    
    /// ドメイン固有のポリシーを設定
    pub fn set_domain_policy(&self, domain_id: usize, policy: IsolationViolationPolicy) {
        let mut policies = self.domain_policies.write();
        policies.insert(domain_id, policy);
    }
    
    /// 特定のドメインのポリシーを取得
    pub fn get_policy(&self, domain_id: usize) -> IsolationViolationPolicy {
        let policies = self.domain_policies.read();
        
        if let Some(&policy) = policies.get(&domain_id) {
            policy
        } else {
            self.default_policy
        }
    }
    
    /// 分離違反を処理
    pub fn handle_violation(
        &self, 
        process_id: ProcessId, 
        domain_id: usize, 
        violation_type: IsolationViolationType
    ) -> IsolationViolationAction {
        // ポリシーを取得
        let policy = self.get_policy(domain_id);
        
        // 違反をログに記録
        if self.logging_enabled.load(Ordering::Relaxed) {
            log::warn!(
                "分離違反検出: プロセス={}, ドメイン={}, 違反タイプ={:?}", 
                process_id, 
                domain_id, 
                violation_type
            );
        }
        
        // 通知を送信（必要に応じて）
        if self.notifications_enabled.load(Ordering::Relaxed) {
            // 実際の監視プロセス通知実装
            self.send_violation_notification(process_id, domain_id, violation_type)?;
        }
        
        // ポリシーに基づいてアクションを実行
        match policy {
            IsolationViolationPolicy::Ignore => {
                // 違反を無視して続行
                IsolationViolationAction::Continue
            },
            IsolationViolationPolicy::Block => {
                // 操作をブロック
                IsolationViolationAction::Block
            },
            IsolationViolationPolicy::Terminate => {
                // プロセスを終了
                // terminate_process(process_id);
                IsolationViolationAction::Terminate
            },
            IsolationViolationPolicy::Panic => {
                // カーネルパニック（最も厳格）
                panic!("重大な分離違反を検出: {:?}", violation_type);
            },
        }
    }
    
    /// ログ記録を有効/無効化
    pub fn set_logging(&self, enabled: bool) {
        self.logging_enabled.store(enabled, Ordering::Relaxed);
    }
    
    /// 通知を有効/無効化
    pub fn set_notifications(&self, enabled: bool) {
        self.notifications_enabled.store(enabled, Ordering::Relaxed);
    }
    
    /// 分離違反の通知を送信
    fn send_violation_notification(
        &self,
        process_id: ProcessId,
        domain_id: usize,
        violation_type: IsolationViolationType
    ) -> Result<(), &'static str> {
        // 1. システム監視プロセスへの通知
        if let Ok(monitor) = crate::core::process::monitoring::ProcessMonitor::instance() {
            let notification = ViolationNotification {
                timestamp: crate::core::sync::current_time_ns(),
                process_id,
                domain_id,
                violation_type,
                severity: self.calculate_violation_severity(violation_type),
                additional_info: self.gather_violation_context(process_id, domain_id)?,
            };
            
            monitor.report_security_violation(notification)?;
        }
        
        // 2. 親プロセスへの通知（存在する場合）
        if let Ok(process_manager) = crate::core::process::ProcessManager::instance() {
            if let Some(parent_id) = process_manager.get_parent_process(process_id) {
                self.notify_parent_process(parent_id, process_id, violation_type)?;
            }
        }
        
        // 3. セキュリティログへの記録
        self.log_security_event(process_id, domain_id, violation_type)?;
        
        // 4. 緊急時のアラート送信
        if self.is_critical_violation(violation_type) {
            self.send_critical_alert(process_id, domain_id, violation_type)?;
        }
        
        Ok(())
    }
    
    /// 違反の重大度を計算
    fn calculate_violation_severity(&self, violation_type: IsolationViolationType) -> ViolationSeverity {
        match violation_type {
            IsolationViolationType::MemoryAccess => ViolationSeverity::High,
            IsolationViolationType::UnauthorizedCommunication => ViolationSeverity::Medium,
            IsolationViolationType::PrivilegedOperation => ViolationSeverity::Critical,
            IsolationViolationType::ResourceLimit => ViolationSeverity::Low,
            IsolationViolationType::UnauthorizedSyscall => ViolationSeverity::High,
            IsolationViolationType::TimingChannelAttack => ViolationSeverity::Medium,
            IsolationViolationType::Other => ViolationSeverity::Low,
        }
    }
    
    /// 違反コンテキスト情報を収集
    fn gather_violation_context(
        &self,
        process_id: ProcessId,
        domain_id: usize
    ) -> Result<ViolationContext, &'static str> {
        let mut context = ViolationContext::new();
        
        // プロセス情報の収集
        if let Ok(process_manager) = crate::core::process::ProcessManager::instance() {
            if let Some(process_info) = process_manager.get_process_info(process_id) {
                context.process_name = process_info.name.clone();
                context.process_priority = process_info.priority;
                context.process_state = process_info.state;
                context.cpu_usage = process_info.cpu_usage_percent;
                context.memory_usage = process_info.memory_usage_bytes;
            }
        }
        
        // ドメイン情報の収集
        if let Ok(isolation_manager) = crate::core::process::isolation::get_isolation_manager() {
            if let Some(domain_info) = isolation_manager.get_domain_info(domain_id) {
                context.domain_name = domain_info.name.clone();
                context.isolation_level = domain_info.level;
                context.resource_limits = domain_info.resource_limits.clone();
            }
        }
        
        // システム状態の収集
        context.system_load = crate::core::system::get_system_load_average();
        context.available_memory = crate::core::memory::get_available_memory();
        context.cpu_temperature = crate::arch::cpu::get_temperature().unwrap_or(0);
        
        // 最近のネットワーク活動
        if let Ok(network_monitor) = crate::core::network::monitoring::NetworkMonitor::instance() {
            context.recent_network_activity = network_monitor.get_recent_activity(process_id);
        }
        
        Ok(context)
    }
    
    /// 親プロセスに通知
    fn notify_parent_process(
        &self,
        parent_id: ProcessId,
        child_id: ProcessId,
        violation_type: IsolationViolationType
    ) -> Result<(), &'static str> {
        // シグナルベースの通知
        let signal = match violation_type {
            IsolationViolationType::MemoryAccess => crate::core::signals::SIGUSR1,
            IsolationViolationType::PrivilegedOperation => crate::core::signals::SIGUSR2,
            _ => crate::core::signals::SIGCHLD,
        };
        
        // 追加情報をプロセス間メッセージとして送信
        let message = IsolationViolationMessage {
            violation_type,
            child_process_id: child_id,
            timestamp: crate::core::sync::current_time_ns(),
        };
        
        if let Ok(ipc) = crate::core::ipc::IPCManager::instance() {
            ipc.send_message(parent_id, &message)?;
        }
        
        // シグナル送信
        crate::core::signals::send_signal(parent_id, signal)?;
        
        Ok(())
    }
    
    /// セキュリティログに記録
    fn log_security_event(
        &self,
        process_id: ProcessId,
        domain_id: usize,
        violation_type: IsolationViolationType
    ) -> Result<(), &'static str> {
        let event = SecurityLogEvent {
            timestamp: crate::core::sync::current_time_ns(),
            event_type: SecurityEventType::IsolationViolation,
            process_id,
            domain_id,
            violation_type,
            source_ip: self.get_process_source_ip(process_id),
            user_id: self.get_process_user_id(process_id),
            additional_data: format!("分離違反検出: プロセス={}, ドメイン={}, タイプ={:?}", 
                                   process_id, domain_id, violation_type),
        };
        
        if let Ok(security_logger) = crate::core::security::SecurityLogger::instance() {
            security_logger.log_event(event)?;
        }
        
        Ok(())
    }
    
    /// 緊急アラートを送信
    fn send_critical_alert(
        &self,
        process_id: ProcessId,
        domain_id: usize,
        violation_type: IsolationViolationType
    ) -> Result<(), &'static str> {
        let alert = CriticalSecurityAlert {
            timestamp: crate::core::sync::current_time_ns(),
            alert_type: CriticalAlertType::IsolationBreach,
            process_id,
            domain_id,
            violation_type,
            risk_level: self.assess_risk_level(violation_type),
            recommended_action: self.get_recommended_action(violation_type),
        };
        
        // システム管理者への通知
        if let Ok(alert_system) = crate::core::security::AlertSystem::instance() {
            alert_system.send_critical_alert(alert)?;
        }
        
        // 監査ログへの即座の記録
        if let Ok(audit_log) = crate::core::audit::AuditLogger::instance() {
            audit_log.log_critical_event(&alert)?;
        }
        
        Ok(())
    }
    
    /// 重大な違反かどうかを判定
    fn is_critical_violation(&self, violation_type: IsolationViolationType) -> bool {
        matches!(violation_type, 
            IsolationViolationType::PrivilegedOperation |
            IsolationViolationType::MemoryAccess |
            IsolationViolationType::UnauthorizedSyscall
        )
    }
    
    /// リスクレベルを評価
    fn assess_risk_level(&self, violation_type: IsolationViolationType) -> RiskLevel {
        match violation_type {
            IsolationViolationType::PrivilegedOperation => RiskLevel::Critical,
            IsolationViolationType::MemoryAccess => RiskLevel::High,
            IsolationViolationType::UnauthorizedSyscall => RiskLevel::High,
            IsolationViolationType::UnauthorizedCommunication => RiskLevel::Medium,
            IsolationViolationType::TimingChannelAttack => RiskLevel::Medium,
            IsolationViolationType::ResourceLimit => RiskLevel::Low,
            IsolationViolationType::Other => RiskLevel::Low,
        }
    }
    
    /// 推奨アクションを取得
    fn get_recommended_action(&self, violation_type: IsolationViolationType) -> RecommendedAction {
        match violation_type {
            IsolationViolationType::PrivilegedOperation => RecommendedAction::TerminateProcess,
            IsolationViolationType::MemoryAccess => RecommendedAction::IsolateProcess,
            IsolationViolationType::UnauthorizedSyscall => RecommendedAction::RestrictPermissions,
            IsolationViolationType::UnauthorizedCommunication => RecommendedAction::BlockCommunication,
            IsolationViolationType::TimingChannelAttack => RecommendedAction::EnhanceMonitoring,
            IsolationViolationType::ResourceLimit => RecommendedAction::ApplyLimits,
            IsolationViolationType::Other => RecommendedAction::LogAndMonitor,
        }
    }
    
    /// プロセスの送信元IPアドレスを取得
    fn get_process_source_ip(&self, process_id: ProcessId) -> Option<String> {
        if let Ok(network_monitor) = crate::core::network::monitoring::NetworkMonitor::instance() {
            network_monitor.get_process_source_ip(process_id)
        } else {
            None
        }
    }
    
    /// プロセスのユーザーIDを取得
    fn get_process_user_id(&self, process_id: ProcessId) -> Option<u32> {
        if let Ok(process_manager) = crate::core::process::ProcessManager::instance() {
            process_manager.get_process_user_id(process_id)
        } else {
            None
        }
    }
}

/// 分離違反タイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationViolationType {
    /// メモリアクセス違反
    MemoryAccess,
    /// 不正な通信試行
    UnauthorizedCommunication,
    /// 不正な特権操作
    PrivilegedOperation,
    /// リソース制限違反
    ResourceLimit,
    /// 不正なシステムコール
    UnauthorizedSyscall,
    /// タイミングチャネル攻撃
    TimingChannelAttack,
    /// その他
    Other,
}

/// 分離違反アクション
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationViolationAction {
    /// 操作を継続
    Continue,
    /// 操作をブロック
    Block,
    /// プロセスを終了
    Terminate,
}

/// 違反重大度
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationSeverity {
    /// 低
    Low,
    /// 中
    Medium,
    /// 高
    High,
    /// 致命的
    Critical,
}

/// 違反通知
#[derive(Debug, Clone)]
pub struct ViolationNotification {
    /// タイムスタンプ
    pub timestamp: u64,
    /// プロセスID
    pub process_id: ProcessId,
    /// ドメインID
    pub domain_id: usize,
    /// 違反タイプ
    pub violation_type: IsolationViolationType,
    /// 重大度
    pub severity: ViolationSeverity,
    /// 追加情報
    pub additional_info: ViolationContext,
}

/// 違反コンテキスト
#[derive(Debug, Clone)]
pub struct ViolationContext {
    /// プロセス名
    pub process_name: String,
    /// プロセス優先度
    pub process_priority: i32,
    /// プロセス状態
    pub process_state: ProcessState,
    /// CPU使用率
    pub cpu_usage: f32,
    /// メモリ使用量
    pub memory_usage: usize,
    /// ドメイン名
    pub domain_name: String,
    /// 分離レベル
    pub isolation_level: IsolationLevel,
    /// リソース制限
    pub resource_limits: ResourceLimits,
    /// システム負荷
    pub system_load: f64,
    /// 利用可能メモリ
    pub available_memory: usize,
    /// CPU温度
    pub cpu_temperature: u32,
    /// 最近のネットワーク活動
    pub recent_network_activity: Option<NetworkActivity>,
}

impl ViolationContext {
    /// 新しいコンテキストを作成
    pub fn new() -> Self {
        Self {
            process_name: String::new(),
            process_priority: 0,
            process_state: ProcessState::Unknown,
            cpu_usage: 0.0,
            memory_usage: 0,
            domain_name: String::new(),
            isolation_level: IsolationLevel::None,
            resource_limits: ResourceLimits::default(),
            system_load: 0.0,
            available_memory: 0,
            cpu_temperature: 0,
            recent_network_activity: None,
        }
    }
}

/// プロセス状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// 実行中
    Running,
    /// 休眠中
    Sleeping,
    /// 待機中
    Waiting,
    /// ゾンビ
    Zombie,
    /// 停止
    Stopped,
    /// 不明
    Unknown,
}

/// ネットワーク活動
#[derive(Debug, Clone)]
pub struct NetworkActivity {
    /// 送信バイト数
    pub bytes_sent: u64,
    /// 受信バイト数
    pub bytes_received: u64,
    /// 接続数
    pub connection_count: u32,
    /// 最終活動時刻
    pub last_activity: u64,
}

/// 分離違反メッセージ
#[derive(Debug, Clone)]
pub struct IsolationViolationMessage {
    /// 違反タイプ
    pub violation_type: IsolationViolationType,
    /// 子プロセスID
    pub child_process_id: ProcessId,
    /// タイムスタンプ
    pub timestamp: u64,
}

/// セキュリティログイベント
#[derive(Debug, Clone)]
pub struct SecurityLogEvent {
    /// タイムスタンプ
    pub timestamp: u64,
    /// イベントタイプ
    pub event_type: SecurityEventType,
    /// プロセスID
    pub process_id: ProcessId,
    /// ドメインID
    pub domain_id: usize,
    /// 違反タイプ
    pub violation_type: IsolationViolationType,
    /// 送信元IP
    pub source_ip: Option<String>,
    /// ユーザーID
    pub user_id: Option<u32>,
    /// 追加データ
    pub additional_data: String,
}

/// セキュリティイベントタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEventType {
    /// 分離違反
    IsolationViolation,
    /// 権限昇格試行
    PrivilegeEscalation,
    /// 不正アクセス試行
    UnauthorizedAccess,
    /// リソース枯渇攻撃
    ResourceExhaustion,
    /// その他
    Other,
}

/// 緊急セキュリティアラート
#[derive(Debug, Clone)]
pub struct CriticalSecurityAlert {
    /// タイムスタンプ
    pub timestamp: u64,
    /// アラートタイプ
    pub alert_type: CriticalAlertType,
    /// プロセスID
    pub process_id: ProcessId,
    /// ドメインID
    pub domain_id: usize,
    /// 違反タイプ
    pub violation_type: IsolationViolationType,
    /// リスクレベル
    pub risk_level: RiskLevel,
    /// 推奨アクション
    pub recommended_action: RecommendedAction,
}

/// 緊急アラートタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CriticalAlertType {
    /// 分離破綻
    IsolationBreach,
    /// システム侵害
    SystemCompromise,
    /// 権限昇格
    PrivilegeEscalation,
    /// データ漏洩
    DataLeak,
    /// サービス拒否攻撃
    DenialOfService,
}

/// リスクレベル
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    /// 低
    Low,
    /// 中
    Medium,
    /// 高
    High,
    /// 致命的
    Critical,
}

/// 推奨アクション
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendedAction {
    /// ログ記録と監視
    LogAndMonitor,
    /// 通信をブロック
    BlockCommunication,
    /// 権限を制限
    RestrictPermissions,
    /// 制限を適用
    ApplyLimits,
    /// 監視を強化
    EnhanceMonitoring,
    /// プロセスを分離
    IsolateProcess,
    /// プロセスを終了
    TerminateProcess,
}

/// メモリ領域情報
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// 開始アドレス
    pub start_address: usize,
    /// 終了アドレス
    pub end_address: usize,
    /// アクセス権限
    pub permissions: MemoryPermissions,
    /// リージョンタイプ
    pub region_type: MemoryRegionType,
}

/// メモリ権限
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryPermissions {
    bits: u8,
}

impl MemoryPermissions {
    /// 読み取り権限
    pub const READ: Self = Self { bits: 0b001 };
    /// 書き込み権限
    pub const WRITE: Self = Self { bits: 0b010 };
    /// 実行権限
    pub const EXECUTE: Self = Self { bits: 0b100 };
    
    /// 空の権限
    pub fn empty() -> Self {
        Self { bits: 0 }
    }
    
    /// 全ての権限
    pub fn all() -> Self {
        Self { bits: 0b111 }
    }
    
    /// 権限を含むかチェック
    pub fn contains(&self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }
}

impl core::ops::BitOr for MemoryPermissions {
    type Output = Self;
    
    fn bitor(self, rhs: Self) -> Self::Output {
        Self { bits: self.bits | rhs.bits }
    }
}

impl core::ops::BitOrAssign for MemoryPermissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.bits |= rhs.bits;
    }
}

/// メモリリージョンタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegionType {
    /// コードセグメント
    Code,
    /// データセグメント
    Data,
    /// スタック
    Stack,
    /// ヒープ
    Heap,
    /// 共有メモリ
    Shared,
    /// デバイスメモリ
    Device,
    /// その他
    Other,
}

/// MPKアクセス権限
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MPKAccessRights {
    bits: u8,
}

impl MPKAccessRights {
    /// 読み取り権限
    pub fn read() -> Self {
        Self { bits: 0b01 }
    }
    
    /// 書き込み権限
    pub fn write() -> Self {
        Self { bits: 0b10 }
    }
    
    /// 実行権限（論理的、実際はNXビットと組み合わせ）
    pub fn execute() -> Self {
        Self { bits: 0b100 }
    }
    
    /// 空の権限
    pub fn empty() -> Self {
        Self { bits: 0 }
    }
    
    /// 権限を含むかチェック
    pub fn contains(&self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }
}

impl core::ops::BitOr for MPKAccessRights {
    type Output = Self;
    
    fn bitor(self, rhs: Self) -> Self::Output {
        Self { bits: self.bits | rhs.bits }
    }
}

impl core::ops::BitOrAssign for MPKAccessRights {
    fn bitor_assign(&mut self, rhs: Self) {
        self.bits |= rhs.bits;
    }
}

/// グローバル分離マネージャー
static mut ISOLATION_MANAGER: Option<IsolationManager> = None;

/// グローバル違反ハンドラー
static mut VIOLATION_HANDLER: Option<IsolationViolationHandler> = None;

/// 分離システムの初期化
pub fn init() {
    unsafe {
        ISOLATION_MANAGER = Some(IsolationManager::new());
        VIOLATION_HANDLER = Some(IsolationViolationHandler::new(
            IsolationViolationPolicy::Block
        ));
    }
    
    // ハードウェア分離機能を有効化
    let manager = get_isolation_manager();
    
    // MPKを有効化（利用可能な場合）
    if manager.supported_isolation_tech.contains(&MemoryIsolationTech::MPK) {
        manager.enable_mpk();
    }
    
    // IOMMUを有効化（利用可能な場合）
    if manager.supported_isolation_tech.contains(&MemoryIsolationTech::IOMMU) {
        manager.enable_iommu();
    }
    
    log::info!("プロセス分離・隔離システム初期化完了");
}

/// 分離マネージャーの取得
pub fn get_isolation_manager() -> &'static IsolationManager {
    unsafe {
        ISOLATION_MANAGER.as_ref().expect("分離マネージャーが初期化されていません")
    }
}

/// 違反ハンドラーの取得
pub fn get_violation_handler() -> &'static IsolationViolationHandler {
    unsafe {
        VIOLATION_HANDLER.as_ref().expect("違反ハンドラーが初期化されていません")
    }
}

/// 新しい分離ドメインを作成
pub fn create_domain(name: &str, level: IsolationLevel, privileged: bool) -> usize {
    get_isolation_manager().create_domain(name, level, privileged)
}

/// プロセスをドメインに追加
pub fn add_process_to_domain(process_id: ProcessId, domain_id: usize) -> bool {
    get_isolation_manager().add_process_to_domain(process_id, domain_id)
}

/// プロセス間通信が許可されているか確認
pub fn can_processes_communicate(pid1: ProcessId, pid2: ProcessId) -> bool {
    get_isolation_manager().can_processes_communicate(pid1, pid2)
}

/// 分離違反を報告
pub fn report_violation(
    process_id: ProcessId, 
    violation_type: IsolationViolationType
) -> IsolationViolationAction {
    let manager = get_isolation_manager();
    let handler = get_violation_handler();
    
    // プロセスのドメインを取得
    if let Some(domain_id) = manager.get_process_domain(process_id) {
        // 違反を処理
        handler.handle_violation(process_id, domain_id, violation_type)
    } else {
        // ドメインが見つからない場合はデフォルトポリシーを適用
        handler.handle_violation(process_id, 0, violation_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_domain_creation() {
        let manager = IsolationManager::new();
        
        // ドメインを作成
        let domain_id = manager.create_domain("TestDomain", IsolationLevel::Enhanced, false);
        
        // IDが1以上であることを確認（0はシステム用）
        assert!(domain_id > 0);
        
        // ドメインが作成されたことを確認
        let domains = manager.domains.read();
        assert!(domains.contains_key(&domain_id));
    }
    
    #[test]
    fn test_process_domain_assignment() {
        let manager = IsolationManager::new();
        
        // ドメインを作成
        let domain_id = manager.create_domain("TestDomain", IsolationLevel::Basic, false);
        
        // プロセスをドメインに追加
        let process_id = ProcessId(1);
        let result = manager.add_process_to_domain(process_id, domain_id);
        
        // 追加が成功したことを確認
        assert!(result);
        
        // プロセスがドメインに属していることを確認
        let domain = manager.get_process_domain(process_id);
        assert_eq!(domain, Some(domain_id));
    }
    
    #[test]
    fn test_domain_communication() {
        let manager = IsolationManager::new();
        
        // 2つのドメインを作成
        let domain1 = manager.create_domain("Domain1", IsolationLevel::Basic, false);
        let domain2 = manager.create_domain("Domain2", IsolationLevel::Basic, false);
        
        // 初期状態では通信が許可されていないことを確認
        assert!(!manager.is_communication_allowed(domain1, domain2));
        
        // 通信を許可
        let result = manager.allow_communication(domain1, domain2);
        assert!(result);
        
        // 通信が許可されていることを確認
        assert!(manager.is_communication_allowed(domain1, domain2));
        
        // 逆方向は許可されていないことを確認
        assert!(!manager.is_communication_allowed(domain2, domain1));
    }
} 