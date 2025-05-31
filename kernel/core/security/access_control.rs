// AetherOS アクセス制御モジュール
//
// 細粒度のアクセス権限管理と厳格な権限分離を提供する
// マンデトリアクセス制御（MAC）と役割ベースアクセス制御（RBAC）の機能を統合

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::core::sync::{Mutex, RwLock, SpinLock};
use super::{SecurityLevel, SecurityResult, Privilege};
use crate::core::security::SecurityError;
use spin::RwLock as SpinRwLock;
use core::sync::atomic::AtomicU64;
use crate::core::security::access_control::{ConditionExpressionParser, SemanticAnalyzer, ExpressionOptimizer, ExpressionEvaluator};

/// アクセス制御モデル
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AccessControlModel {
    /// 任意アクセス制御（DAC）
    Discretionary,
    /// 強制アクセス制御（MAC）
    Mandatory,
    /// 役割ベースアクセス制御（RBAC）
    RoleBased,
    /// 属性ベースアクセス制御（ABAC）
    AttributeBased,
    /// ケイパビリティベースアクセス制御
    CapabilityBased,
    /// ハイブリッドアクセス制御
    Hybrid,
}

/// セキュリティラベル
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecurityLabel {
    /// 機密性レベル（0-100）
    pub confidentiality: u8,
    /// 完全性レベル（0-100）
    pub integrity: u8,
    /// コンパートメント（分離区画）
    pub compartments: BTreeSet<String>,
    /// カテゴリ
    pub categories: BTreeSet<String>,
}

/// アクセス権限
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    /// 読み取り
    Read,
    /// 書き込み
    Write,
    /// 実行
    Execute,
    /// 作成
    Create,
    /// 削除
    Delete,
    /// 所有権変更
    ChangeOwner,
    /// 権限変更
    ChangePermission,
    /// リンク
    Link,
    /// トラバース（ディレクトリ閲覧）
    Traverse,
    /// アペンド（追加のみ）
    Append,
    /// 名前変更
    Rename,
}

/// 役割（ロール）
#[derive(Debug, Clone)]
pub struct Role {
    /// 役割ID
    pub id: usize,
    /// 役割名
    pub name: String,
    /// 権限セット
    pub privileges: BTreeSet<Privilege>,
    /// 許可されたアクセス権限
    pub permissions: BTreeSet<Permission>,
    /// 親役割ID
    pub parent_id: Option<usize>,
}

/// ケイパビリティ
#[derive(Debug, Clone)]
pub struct Capability {
    /// ケイパビリティID
    pub id: usize,
    /// ケイパビリティ名
    pub name: String,
    /// 対象リソース
    pub target_resource: Option<usize>,
    /// 許可された操作
    pub allowed_operations: BTreeSet<Permission>,
    /// 有効期限（ミリ秒タイムスタンプ）
    pub expiration: Option<u64>,
    /// 追加条件
    pub conditions: Option<String>,
}

/// アクセス制御エントリ（ACE）
#[derive(Debug, Clone)]
pub struct AccessControlEntry {
    /// プリンシパルID（ユーザー、プロセス、ドメインなど）
    pub principal_id: usize,
    /// プリンシパルタイプ
    pub principal_type: PrincipalType,
    /// 許可されたアクセス権限
    pub allowed_permissions: BTreeSet<Permission>,
    /// 拒否されたアクセス権限
    pub denied_permissions: BTreeSet<Permission>,
    /// 条件（ある場合）
    pub condition: Option<String>,
}

/// プリンシパルタイプ
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrincipalType {
    /// ユーザー
    User,
    /// プロセス
    Process,
    /// ドメイン
    Domain,
    /// グループ
    Group,
    /// 役割
    Role,
}

/// アクセス制御リスト（ACL）
#[derive(Debug, Clone)]
pub struct AccessControlList {
    /// リソースID
    pub resource_id: usize,
    /// エントリリスト
    pub entries: Vec<AccessControlEntry>,
    /// 継承フラグ
    pub inheritable: bool,
}

/// アクセス制御エンジン
pub struct AccessControlEngine {
    /// アクセス制御モデル
    access_model: RwLock<AccessControlModel>,
    /// プロセスセキュリティラベル
    process_labels: RwLock<BTreeMap<usize, SecurityLabel>>,
    /// リソースセキュリティラベル
    resource_labels: RwLock<BTreeMap<usize, SecurityLabel>>,
    /// アクセス制御リスト
    access_control_lists: RwLock<BTreeMap<usize, AccessControlList>>,
    /// 役割定義
    roles: RwLock<BTreeMap<usize, Role>>,
    /// プロセス役割マッピング
    process_roles: RwLock<BTreeMap<usize, BTreeSet<usize>>>,
    /// プロセスケイパビリティ
    process_capabilities: RwLock<BTreeMap<usize, BTreeSet<Capability>>>,
    /// 現在のセキュリティレベル
    security_level: RwLock<SecurityLevel>,
    /// 次の役割ID
    next_role_id: AtomicUsize,
    /// 次のケイパビリティID
    next_capability_id: AtomicUsize,
    /// 初期化済みフラグ
    initialized: AtomicBool,
}

impl AccessControlEngine {
    /// 新しいアクセス制御エンジンを作成
    pub fn new() -> Self {
        Self {
            access_model: RwLock::new(AccessControlModel::Hybrid),
            process_labels: RwLock::new(BTreeMap::new()),
            resource_labels: RwLock::new(BTreeMap::new()),
            access_control_lists: RwLock::new(BTreeMap::new()),
            roles: RwLock::new(BTreeMap::new()),
            process_roles: RwLock::new(BTreeMap::new()),
            process_capabilities: RwLock::new(BTreeMap::new()),
            security_level: RwLock::new(SecurityLevel::Standard),
            next_role_id: AtomicUsize::new(1),
            next_capability_id: AtomicUsize::new(1),
            initialized: AtomicBool::new(false),
        }
    }
    
    /// アクセス制御エンジンを初期化
    pub fn initialize(&self) -> Result<(), &'static str> {
        if self.initialized.load(Ordering::SeqCst) {
            return Err("アクセス制御エンジンは既に初期化されています");
        }
        
        // デフォルトの役割を設定
        self.create_default_roles();
        
        self.initialized.store(true, Ordering::SeqCst);
        
        log::info!("アクセス制御エンジンを初期化しました");
        
        Ok(())
    }
    
    /// デフォルトの役割を作成
    fn create_default_roles(&self) {
        let mut roles = self.roles.write().unwrap();
        
        // システム管理者役割
        let admin_role = Role {
            id: 1,
            name: "system_admin".to_string(),
            privileges: [
                Privilege::SystemAdmin,
                Privilege::ProcessManagement,
                Privilege::MemoryManagement,
                Privilege::FileSystemAccess,
                Privilege::NetworkAccess,
                Privilege::DeviceAccess,
                Privilege::SecurityManagement,
                Privilege::KernelAccess,
            ].iter().cloned().collect(),
            permissions: [
                Permission::Read,
                Permission::Write,
                Permission::Execute,
                Permission::Create,
                Permission::Delete,
                Permission::ChangeOwner,
                Permission::ChangePermission,
                Permission::Link,
                Permission::Traverse,
                Permission::Append,
                Permission::Rename,
            ].iter().cloned().collect(),
            parent_id: None,
        };
        
        // ユーザー役割
        let user_role = Role {
            id: 2,
            name: "user".to_string(),
            privileges: [
                Privilege::ProcessManagement,
                Privilege::FileSystemAccess,
                Privilege::NetworkAccess,
            ].iter().cloned().collect(),
            permissions: [
                Permission::Read,
                Permission::Write,
                Permission::Execute,
                Permission::Create,
                Permission::Traverse,
                Permission::Append,
            ].iter().cloned().collect(),
            parent_id: None,
        };
        
        // ゲスト役割
        let guest_role = Role {
            id: 3,
            name: "guest".to_string(),
            privileges: [
                Privilege::FileSystemAccess,
            ].iter().cloned().collect(),
            permissions: [
                Permission::Read,
                Permission::Traverse,
            ].iter().cloned().collect(),
            parent_id: None,
        };
        
        // サービス役割
        let service_role = Role {
            id: 4,
            name: "service".to_string(),
            privileges: [
                Privilege::ProcessManagement,
                Privilege::NetworkAccess,
                Privilege::DeviceAccess,
            ].iter().cloned().collect(),
            permissions: [
                Permission::Read,
                Permission::Write,
                Permission::Execute,
                Permission::Create,
                Permission::Traverse,
            ].iter().cloned().collect(),
            parent_id: None,
        };
        
        // カーネル役割
        let kernel_role = Role {
            id: 5,
            name: "kernel".to_string(),
            privileges: [
                Privilege::KernelAccess,
                Privilege::SystemAdmin,
                Privilege::ProcessManagement,
                Privilege::MemoryManagement,
                Privilege::FileSystemAccess,
                Privilege::NetworkAccess,
                Privilege::DeviceAccess,
                Privilege::SecurityManagement,
                Privilege::HardwareAccess,
            ].iter().cloned().collect(),
            permissions: [
                Permission::Read,
                Permission::Write,
                Permission::Execute,
                Permission::Create,
                Permission::Delete,
                Permission::ChangeOwner,
                Permission::ChangePermission,
                Permission::Link,
                Permission::Traverse,
                Permission::Append,
                Permission::Rename,
            ].iter().cloned().collect(),
            parent_id: None,
        };
        
        roles.insert(1, admin_role);
        roles.insert(2, user_role);
        roles.insert(3, guest_role);
        roles.insert(4, service_role);
        roles.insert(5, kernel_role);
        
        // 次のIDを更新
        self.next_role_id.store(6, Ordering::SeqCst);
        
        log::info!("デフォルト役割を作成しました: admin, user, guest, service, kernel");
    }
    
    /// 役割を登録
    pub fn register_role(
        &self,
        name: &str,
        parent_id: Option<usize>,
        privileges: BTreeSet<Privilege>,
        permissions: BTreeSet<Permission>
    ) -> Result<usize, &'static str> {
        // 親役割の存在確認
        if let Some(parent) = parent_id {
            let roles = self.roles.read().unwrap();
            if !roles.contains_key(&parent) {
                return Err("親役割が存在しません");
            }
        }
        
        let role_id = self.next_role_id.fetch_add(1, Ordering::SeqCst);
        
        let role = Role {
            id: role_id,
            name: name.to_string(),
            privileges,
            permissions,
            parent_id,
        };
        
        let mut roles = self.roles.write().unwrap();
        roles.insert(role_id, role);
        
        log::info!("役割を登録: {} (ID: {})", name, role_id);
        
        Ok(role_id)
    }
    
    /// プロセスに役割を割り当て
    pub fn assign_role_to_process(&self, process_id: usize, role_id: usize) -> Result<(), &'static str> {
        // 役割の存在確認
        {
            let roles = self.roles.read().unwrap();
            if !roles.contains_key(&role_id) {
                return Err("指定された役割が存在しません");
            }
        }
        
        // 役割を割り当て
        let mut process_roles = self.process_roles.write().unwrap();
        
        if !process_roles.contains_key(&process_id) {
            process_roles.insert(process_id, BTreeSet::new());
        }
        
        let roles = process_roles.get_mut(&process_id).unwrap();
        roles.insert(role_id);
        
        log::info!("プロセス {} に役割 {} を割り当てました", process_id, role_id);
        
        Ok(())
    }
    
    /// ケイパビリティを作成
    pub fn create_capability(
        &self,
        name: &str,
        target_resource: Option<usize>,
        operations: BTreeSet<Permission>,
        expiration: Option<u64>,
        conditions: Option<&str>
    ) -> usize {
        let capability_id = self.next_capability_id.fetch_add(1, Ordering::SeqCst);
        
        let capability = Capability {
            id: capability_id,
            name: name.to_string(),
            target_resource,
            allowed_operations: operations,
            expiration,
            conditions: conditions.map(String::from),
        };
        
        log::info!("ケイパビリティを作成: {} (ID: {})", name, capability_id);
        
        capability_id
    }
    
    /// プロセスにケイパビリティを付与
    pub fn grant_capability_to_process(
        &self,
        process_id: usize,
        capability: Capability
    ) -> Result<(), &'static str> {
        let mut process_capabilities = self.process_capabilities.write().unwrap();
        
        if !process_capabilities.contains_key(&process_id) {
            process_capabilities.insert(process_id, BTreeSet::new());
        }
        
        let capabilities = process_capabilities.get_mut(&process_id).unwrap();
        capabilities.insert(capability.clone());
        
        log::info!(
            "プロセス {} にケイパビリティ {} を付与しました",
            process_id, capability.name
        );
        
        Ok(())
    }
    
    /// セキュリティラベルを設定
    pub fn set_security_label(
        &self,
        resource_id: usize,
        is_process: bool,
        confidentiality: u8,
        integrity: u8,
        compartments: BTreeSet<String>,
        categories: BTreeSet<String>
    ) -> Result<(), &'static str> {
        let label = SecurityLabel {
            confidentiality,
            integrity,
            compartments,
            categories,
        };
        
        if is_process {
            let mut process_labels = self.process_labels.write().unwrap();
            process_labels.insert(resource_id, label);
        } else {
            let mut resource_labels = self.resource_labels.write().unwrap();
            resource_labels.insert(resource_id, label);
        }
        
        log::info!(
            "{} {} にセキュリティラベルを設定しました: 機密性={}, 完全性={}",
            if is_process { "プロセス" } else { "リソース" },
            resource_id, confidentiality, integrity
        );
        
        Ok(())
    }
    
    /// アクセス制御リスト（ACL）を設定
    pub fn set_acl(
        &self,
        resource_id: usize,
        entries: Vec<AccessControlEntry>,
        inheritable: bool
    ) -> Result<(), &'static str> {
        let acl = AccessControlList {
            resource_id,
            entries,
            inheritable,
        };
        
        let mut acls = self.access_control_lists.write().unwrap();
        acls.insert(resource_id, acl);
        
        log::info!(
            "リソース {} にACLを設定しました: {} エントリ, 継承={}",
            resource_id, entries.len(), inheritable
        );
        
        Ok(())
    }
    
    /// アクセス制御モデルを設定
    pub fn set_access_control_model(&self, model: AccessControlModel) -> Result<(), &'static str> {
        let mut current_model = self.access_model.write().unwrap();
        *current_model = model;
        
        log::info!("アクセス制御モデルを {:?} に設定しました", model);
        
        Ok(())
    }
    
    /// アクセス検証
    pub fn verify_access(
        &self,
        process_id: usize,
        domain_id: usize,
        privilege: Privilege,
        resource_id: usize,
        context: &str
    ) -> SecurityResult {
        if !self.initialized.load(Ordering::SeqCst) {
            return SecurityResult::Denied("アクセス制御エンジンが初期化されていません".to_string());
        }
        
        log::debug!("アクセス検証開始: プロセス={}, ドメイン={}, 権限={:?}, リソース={}", 
                   process_id, domain_id, privilege, resource_id);
        
        // セキュリティレベルチェック
        let security_level = *self.security_level.read().unwrap();
        if security_level == SecurityLevel::Maximum {
            // 最大セキュリティレベルでは追加検証が必要
            if !self.verify_maximum_security_access(process_id, privilege, resource_id) {
                return SecurityResult::Denied("最大セキュリティレベルでアクセス拒否".to_string());
            }
        }
        
        // アクセス制御モデルに応じて検証
        let access_model = *self.access_model.read().unwrap();
        match access_model {
            AccessControlModel::Mandatory => {
                self.verify_mac_access(process_id, resource_id)
            },
            AccessControlModel::RoleBased => {
                self.verify_rbac_access(process_id, privilege, resource_id)
            },
            AccessControlModel::AttributeBased => {
                self.verify_abac_access(process_id, domain_id, privilege, resource_id, context)
            },
            AccessControlModel::CapabilityBased => {
                self.verify_capability_access(process_id, resource_id, context)
            },
            AccessControlModel::Discretionary => {
                self.verify_acl_access(process_id, resource_id)
            },
            AccessControlModel::Hybrid => {
                // ハイブリッドモデル：複数の制御方式を組み合わせ
                let mac_result = self.verify_mac_access(process_id, resource_id);
                let rbac_result = self.verify_rbac_access(process_id, privilege, resource_id);
                let acl_result = self.verify_acl_access(process_id, resource_id);
                
                // すべての制御方式で許可された場合のみアクセス許可
                match (mac_result, rbac_result, acl_result) {
                    (SecurityResult::Allowed, SecurityResult::Allowed, SecurityResult::Allowed) => {
                        SecurityResult::Allowed
                    },
                    _ => {
                        SecurityResult::Denied("ハイブリッドアクセス制御で拒否".to_string())
                    }
                }
            }
        }
    }
    
    /// 最大セキュリティレベルでのアクセス検証
    fn verify_maximum_security_access(&self, process_id: usize, privilege: Privilege, resource_id: usize) -> bool {
        // プロセスの信頼性スコアを確認
        let trust_score = self.calculate_process_trust_score(process_id);
        if trust_score < 80 {
            log::warn!("プロセス{}の信頼性スコアが低すぎます: {}", process_id, trust_score);
            return false;
        }
        
        // 高権限操作の場合は追加チェック
        match privilege {
            Privilege::SystemAdmin | Privilege::KernelAccess | Privilege::SecurityManagement => {
                // システム管理者権限が必要
                let process_roles = self.process_roles.read().unwrap();
                if let Some(roles) = process_roles.get(&process_id) {
                    return roles.contains(&1); // システム管理者役割
                }
                false
            },
            _ => true
        }
    }
    
    /// 強制アクセス制御（MAC）検証
    fn verify_mac_access(&self, process_id: usize, resource_id: usize) -> SecurityResult {
        let process_labels = self.process_labels.read().unwrap();
        let resource_labels = self.resource_labels.read().unwrap();
        
        let process_label = match process_labels.get(&process_id) {
            Some(label) => label,
                None => {
                log::warn!("プロセス{}のセキュリティラベルが見つかりません", process_id);
                return SecurityResult::Denied("プロセスラベル未設定".to_string());
            }
        };
        
        let resource_label = match resource_labels.get(&resource_id) {
            Some(label) => label,
                None => {
                log::warn!("リソース{}のセキュリティラベルが見つかりません", resource_id);
                return SecurityResult::Denied("リソースラベル未設定".to_string());
            }
        };
        
        // Bell-LaPadula モデル：読み取りは下位レベルから、書き込みは上位レベルへ
        // Simple Security Property: プロセスの機密性レベル >= リソースの機密性レベル（読み取り）
        if process_label.confidentiality < resource_label.confidentiality {
            return SecurityResult::Denied("機密性レベル不足（読み取り拒否）".to_string());
        }
        
        // *-Property: プロセスの完全性レベル <= リソースの完全性レベル（書き込み）
        if process_label.integrity > resource_label.integrity {
            return SecurityResult::Denied("完全性レベル超過（書き込み拒否）".to_string());
        }
        
        // コンパートメント検証
        if !process_label.compartments.is_superset(&resource_label.compartments) {
            return SecurityResult::Denied("コンパートメント不一致".to_string());
        }
        
        // カテゴリ検証
        if !process_label.categories.is_superset(&resource_label.categories) {
            return SecurityResult::Denied("カテゴリ不一致".to_string());
        }
        
        log::debug!("MAC検証成功: プロセス{}からリソース{}へのアクセス", process_id, resource_id);
        SecurityResult::Allowed
    }
    
    /// 役割ベースアクセス制御（RBAC）検証
    fn verify_rbac_access(&self, process_id: usize, privilege: Privilege, resource_id: usize) -> SecurityResult {
            let process_roles = self.process_roles.read().unwrap();
        let roles = self.roles.read().unwrap();
        
        let assigned_roles = match process_roles.get(&process_id) {
            Some(roles) => roles,
                None => {
                log::warn!("プロセス{}に役割が割り当てられていません", process_id);
                return SecurityResult::Denied("役割未割り当て".to_string());
            }
        };
        
        // 割り当てられた役割で必要な権限を持っているかチェック
        for &role_id in assigned_roles {
            if let Some(role) = roles.get(&role_id) {
                if role.privileges.contains(&privilege) {
                    log::debug!("RBAC検証成功: プロセス{}が役割{}で権限{:?}を持っています", 
                               process_id, role.name, privilege);
                    return SecurityResult::Allowed;
                }
                
                // 親役割もチェック
                if let Some(parent_id) = role.parent_id {
                    if let Some(parent_role) = roles.get(&parent_id) {
                        if parent_role.privileges.contains(&privilege) {
                            log::debug!("RBAC検証成功: プロセス{}が親役割{}で権限{:?}を持っています", 
                                       process_id, parent_role.name, privilege);
                            return SecurityResult::Allowed;
                        }
                    }
                }
            }
        }
        
        SecurityResult::Denied("必要な権限を持つ役割がありません".to_string())
    }
    
    /// ケイパビリティベースアクセス制御検証
    fn verify_capability_access(&self, process_id: usize, resource_id: usize, context: &str) -> SecurityResult {
            let process_capabilities = self.process_capabilities.read().unwrap();
        
        let capabilities = match process_capabilities.get(&process_id) {
            Some(caps) => caps,
                None => {
                log::warn!("プロセス{}にケイパビリティが割り当てられていません", process_id);
                return SecurityResult::Denied("ケイパビリティ未割り当て".to_string());
            }
        };
        
        let current_time = crate::core::time::current_timestamp();
        let requested_operations = self.parse_requested_operations(context);
        
        for capability in capabilities {
            // 有効期限チェック
            if let Some(expiration) = capability.expiration {
                if current_time > expiration {
                    continue; // 期限切れのケイパビリティはスキップ
                }
            }
            
            // 対象リソースチェック
            if let Some(target) = capability.target_resource {
                if target != resource_id {
                    continue; // 対象リソースが異なる場合はスキップ
                }
            }
            
            // 操作権限チェック
            let mut all_operations_allowed = true;
            for operation in &requested_operations {
                let permission = self.map_operation_to_permission(*operation);
                if !capability.allowed_operations.contains(&permission) {
                    all_operations_allowed = false;
                break;
            }
        }
        
            if all_operations_allowed {
                // 追加条件チェック
                if let Some(conditions) = &capability.conditions {
                    if !self.evaluate_capability_conditions(conditions, context) {
                        continue;
                    }
                }
                
                log::debug!("ケイパビリティ検証成功: プロセス{}がケイパビリティ{}でアクセス", 
                           process_id, capability.name);
                return SecurityResult::Allowed;
            }
        }
        
        SecurityResult::Denied("適切なケイパビリティがありません".to_string())
    }
    
    /// ケイパビリティ条件を評価
    fn evaluate_capability_conditions(&self, conditions: &str, context: &str) -> bool {
        // 簡略化された条件評価
        // 実際の実装では、より複雑な条件式パーサーが必要
        
        let context_attrs = parse_context_attributes(context);
        
        // 条件文字列を解析（例: "time=day,location=office"）
        for condition in conditions.split(',') {
            let parts: Vec<&str> = condition.split('=').collect();
            if parts.len() != 2 {
                continue;
            }
            
            let key = parts[0].trim();
            let expected_value = parts[1].trim();
            
            match context_attrs.get(key) {
                Some(actual_value) => {
                    if actual_value != expected_value {
                        return false;
                    }
                },
                None => return false,
            }
        }
        
        true
    }
    
    /// アクセス制御リスト（ACL）ベースアクセス制御検証
    fn verify_acl_access(&self, process_id: usize, resource_id: usize) -> SecurityResult {
        let access_control_lists = self.access_control_lists.read().unwrap();
        
        // リソースのACLを取得
        let acl = match access_control_lists.get(&resource_id) {
            Some(acl) => acl,
            None => {
                // 親リソースのACLを確認
                if let Some(parent_acl) = self.get_parent_acl(resource_id) {
                    parent_acl
                } else {
                    log::warn!("リソース{}のACLが見つかりません", resource_id);
                    return SecurityResult::Denied("ACL未設定".to_string());
                }
            }
        };
        
        // プロセスに対する明示的な拒否エントリをチェック
        for entry in &acl.entries {
            if entry.principal_type == PrincipalType::Process && entry.principal_id == process_id {
                if !entry.denied_permissions.is_empty() {
                    log::debug!("ACL明示的拒否: プロセス{}のリソース{}アクセス", process_id, resource_id);
                    return SecurityResult::Denied("ACL明示的拒否".to_string());
                }
            }
        }
        
        // プロセスに対する許可エントリをチェック
        for entry in &acl.entries {
            if entry.principal_type == PrincipalType::Process && entry.principal_id == process_id {
                if !entry.allowed_permissions.is_empty() {
                    // 条件チェック
                    if let Some(condition) = &entry.condition {
                        if !self.evaluate_acl_condition(condition, process_id) {
                            continue;
                        }
                    }
                    
                    log::debug!("ACL検証成功: プロセス{}のリソース{}アクセス", process_id, resource_id);
                    return SecurityResult::Allowed;
                }
            }
        }
        
        // プロセスの役割に対するエントリをチェック
        let process_roles = self.process_roles.read().unwrap();
        if let Some(roles) = process_roles.get(&process_id) {
            for &role_id in roles {
                for entry in &acl.entries {
                    if entry.principal_type == PrincipalType::Role && entry.principal_id == role_id {
                        if !entry.allowed_permissions.is_empty() {
                            // 条件チェック
                            if let Some(condition) = &entry.condition {
                                if !self.evaluate_acl_condition(condition, process_id) {
                                    continue;
                                }
                            }
                            
                            log::debug!("ACL役割検証成功: プロセス{}が役割{}でリソース{}アクセス", 
                                       process_id, role_id, resource_id);
                            return SecurityResult::Allowed;
                        }
                    }
                }
            }
        }
        
        SecurityResult::Denied("ACLでアクセス許可されていません".to_string())
    }
    
    /// ACL条件を評価
    fn evaluate_acl_condition(&self, condition: &str, process_id: usize) -> bool {
        // 簡略化された条件評価
        // 実際の実装では、より複雑な条件式パーサーが必要
        
        match condition {
            "trusted_process" => {
                self.calculate_process_trust_score(process_id) >= 70
            },
            "daytime_only" => {
                let current_hour = self.get_current_hour();
                current_hour >= 8 && current_hour <= 18
            },
            "high_integrity" => {
        let process_labels = self.process_labels.read().unwrap();
        if let Some(label) = process_labels.get(&process_id) {
                    label.integrity >= 80
        } else {
                    false
                }
            },
            _ => true // 未知の条件は許可
        }
    }
    
    /// 現在の時刻を取得
    fn get_current_hour(&self) -> u8 {
        // 簡略化された実装
        let timestamp = crate::core::time::current_timestamp();
        ((timestamp / 3600) % 24) as u8
    }
    
    /// セキュリティレベルを更新
    pub fn update_security_level(&self, level: SecurityLevel) {
        let mut current_level = self.security_level.write().unwrap();
        *current_level = level;
        
        // セキュリティレベルに応じてアクセス制御モデルを調整
        let model = match level {
            SecurityLevel::Minimal => AccessControlModel::Discretionary,
            SecurityLevel::Low => AccessControlModel::RoleBased,
            SecurityLevel::Standard => AccessControlModel::Hybrid,
            SecurityLevel::High => AccessControlModel::Mandatory,
            SecurityLevel::Maximum => AccessControlModel::Mandatory,
            SecurityLevel::Custom => AccessControlModel::Hybrid,
        };
        
        let mut current_model = self.access_model.write().unwrap();
        *current_model = model;
        
        log::info!(
            "セキュリティレベルに基づきアクセス制御モデルを {:?} に更新しました",
            model
        );
    }
}

/// アクセス操作の種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessOperation {
    Read,
    Write,
    Execute,
    Delete,
    Create,
    Modify,
    List,
}

/// コンテキスト文字列から属性マップを作成
fn parse_context_attributes(context: &str) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::new();
    
    for pair in context.split(';') {
        let parts: Vec<&str> = pair.split('=').collect();
        if parts.len() == 2 {
            attributes.insert(parts[0].trim().to_string(), parts[1].trim().to_string());
        }
    }
    
    attributes
}

// 権限を公開
pub use self::Permission;

/// 主要なアクセス制御管理コンポーネント
pub struct AccessControlManager {
    // 現在のデフォルトポリシー
    default_policy: DefaultPolicy,
    
    // エンティティID割り当てカウンター
    next_entity_id: AtomicU64,
    
    // エンティティデータベース
    entities: BTreeMap<EntityId, Entity>,
    
    // リソースデータベース
    resources: BTreeMap<ResourceId, Resource>,
    
    // ポリシーデータベース
    policies: BTreeMap<PolicyId, Policy>,
    
    // ロールデータベース
    roles: BTreeMap<RoleId, Role>,
    
    // 許可マトリックス
    permission_matrices: BTreeMap<DomainId, PermissionMatrix>,
    
    // 管理者設定
    admin_settings: AdminSettings,
}

// 基本的な型定義
pub type EntityId = u64;
pub type ResourceId = u64;
pub type PolicyId = u64;
pub type RoleId = u64;
pub type DomainId = u64;
pub type PermissionId = u64;

/// デフォルトのポリシー設定
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultPolicy {
    /// 明示的に許可されない限りアクセスは拒否
    DenyByDefault,
    /// 明示的に許可されない限りアクセスは拒否（より厳格）
    StrictDenyByDefault,
    /// 検証後に許可（ほとんどのアクセスは許可だが検証が必要）
    AllowWithVerification,
}

/// エンティティ情報
#[derive(Debug, Clone)]
pub struct Entity {
    pub id: EntityId,
    pub entity_type: EntityType,
    pub name: String,
    pub attributes: BTreeMap<String, String>,
    pub roles: BTreeSet<RoleId>,
    pub permissions: BTreeSet<PermissionId>,
    pub domains: BTreeSet<DomainId>,
    pub created_at: u64,
    pub last_modified: u64,
    pub state: EntityState,
}

/// エンティティの種類
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityType {
    User,
    Process,
    Service,
    Device,
    Group,
    Application,
    Container,
    VirtualMachine,
    Other(String),
}

/// エンティティの状態
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityState {
    Active,
    Suspended,
    Locked,
    PendingApproval,
    Quarantined,
    Terminated,
}

/// リソース情報
#[derive(Debug, Clone)]
pub struct Resource {
    pub id: ResourceId,
    pub resource_type: ResourceType,
    pub name: String,
    pub owner: EntityId,
    pub path: String,
    pub attributes: BTreeMap<String, String>,
    pub sensitivity: ResourceSensitivity,
    pub created_at: u64,
    pub last_modified: u64,
}

/// リソースの種類
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceType {
    File,
    Directory,
    Memory,
    Device,
    Network,
    Socket,
    Port,
    Process,
    SystemService,
    Database,
    ApiEndpoint,
    Other(String),
}

/// リソースの感度レベル
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceSensitivity {
    Public,
    Internal,
    Confidential,
    Restricted,
    Secret,
    Critical,
}

/// アクセス制御ポリシー
#[derive(Debug, Clone)]
pub struct Policy {
    pub id: PolicyId,
    pub name: String,
    pub description: String,
    pub rules: Vec<AccessRule>,
    pub priority: u8,
    pub domain_id: DomainId,
    pub enabled: bool,
    pub created_at: u64,
    pub last_modified: u64,
}

/// アクセスルール
#[derive(Debug, Clone)]
pub struct AccessRule {
    pub rule_type: RuleType,
    pub entity_selector: EntitySelector,
    pub resource_selector: ResourceSelector,
    pub operations: BTreeSet<Operation>,
    pub conditions: Vec<Condition>,
    pub effect: Effect,
}

/// ルールの種類
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleType {
    Permission,
    Prohibition,
    Obligation,
}

/// エンティティセレクタ
#[derive(Debug, Clone)]
pub enum EntitySelector {
    All,
    ById(EntityId),
    ByIds(Vec<EntityId>),
    ByType(EntityType),
    ByRole(RoleId),
    ByRoles(Vec<RoleId>),
    ByAttribute { key: String, value: String },
    ByDomain(DomainId),
    Complex(Vec<EntitySelector>),
}

/// リソースセレクタ
#[derive(Debug, Clone)]
pub enum ResourceSelector {
    All,
    ById(ResourceId),
    ByIds(Vec<ResourceId>),
    ByType(ResourceType),
    ByPath(String),
    ByPathPattern(String),
    BySensitivity(ResourceSensitivity),
    ByAttribute { key: String, value: String },
    Complex(Vec<ResourceSelector>),
}

/// 操作の種類
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Operation {
    Read,
    Write,
    Execute,
    Delete,
    Create,
    Modify,
    List,
    Query,
    Control,
    Manage,
    Connect,
    Disconnect,
    Monitor,
}

/// 条件
#[derive(Debug, Clone)]
pub enum Condition {
    TimeRange {
        start_hour: u8,
        end_hour: u8,
        days: DaysOfWeek,
    },
    LocationIs(String),
    NetworkIs(String),
    DeviceIs(String),
    AttributeEquals { key: String, value: String },
    AttributeMatches { key: String, pattern: String },
    ResourceAttributeEquals { key: String, value: String },
    TrustScoreAbove(u8),
    Custom(String, Vec<String>),
}

/// 曜日のビットマスク
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaysOfWeek(u8);

impl DaysOfWeek {
    pub const MONDAY: u8 = 0b0000001;
    pub const TUESDAY: u8 = 0b0000010;
    pub const WEDNESDAY: u8 = 0b0000100;
    pub const THURSDAY: u8 = 0b0001000;
    pub const FRIDAY: u8 = 0b0010000;
    pub const SATURDAY: u8 = 0b0100000;
    pub const SUNDAY: u8 = 0b1000000;
    pub const WEEKDAYS: u8 = Self::MONDAY | Self::TUESDAY | Self::WEDNESDAY | Self::THURSDAY | Self::FRIDAY;
    pub const WEEKEND: u8 = Self::SATURDAY | Self::SUNDAY;
    pub const ALL_DAYS: u8 = Self::WEEKDAYS | Self::WEEKEND;
}

/// ルールの効果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
    AllowWithAudit,
    DenyWithAudit,
    Escalate,
}

/// ロール定義
#[derive(Debug, Clone)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    pub description: String,
    pub permissions: BTreeSet<PermissionId>,
    pub parent_roles: BTreeSet<RoleId>,
    pub domain_id: DomainId,
    pub attributes: BTreeMap<String, String>,
}

/// 許可マトリックス
#[derive(Debug)]
pub struct PermissionMatrix {
    domain_id: DomainId,
    entity_resource_permissions: BTreeMap<(EntityId, ResourceId), BTreeSet<Operation>>,
    role_resource_permissions: BTreeMap<(RoleId, ResourceId), BTreeSet<Operation>>,
    entity_type_resource_type_permissions: BTreeMap<(EntityType, ResourceType), BTreeSet<Operation>>,
}

/// 管理設定
#[derive(Debug)]
pub struct AdminSettings {
    enable_emergency_override: bool,
    emergency_override_entities: BTreeSet<EntityId>,
    audit_all_admin_actions: bool,
    require_mfa_for_sensitive_operations: bool,
    password_policy: PasswordPolicy,
    session_policy: SessionPolicy,
}

/// パスワードポリシー
#[derive(Debug)]
pub struct PasswordPolicy {
    min_length: u8,
    require_uppercase: bool,
    require_lowercase: bool,
    require_numbers: bool,
    require_special_chars: bool,
    max_age_days: u16,
    prevent_reuse_count: u8,
}

/// セッションポリシー
#[derive(Debug)]
pub struct SessionPolicy {
    max_session_duration_minutes: u32,
    require_reauthentication_minutes: u32,
    idle_timeout_minutes: u16,
    max_concurrent_sessions: u8,
}

/// アクセス制御ステータス
#[derive(Debug)]
pub struct AccessControlStatus {
    pub entity_count: usize,
    pub resource_count: usize,
    pub policy_count: usize,
    pub role_count: usize,
    pub default_policy: DefaultPolicy,
    pub last_policy_update: u64,
}

/// 許可付与結果
#[derive(Debug)]
pub enum PermissionResult {
    Granted,
    Denied(DenialReason),
    RequiresEscalation,
    RequiresAdditionalAuthentication,
}

/// 拒否理由
#[derive(Debug)]
pub enum DenialReason {
    ExplicitDeny,
    NoPolicyMatch,
    InsufficientPrivileges,
    ResourceNotFound,
    EntityNotActive,
    ConditionNotMet(String),
    OutsideTimeWindow,
    ExceededLimit,
    Other(String),
}

// アクセス制御マネージャの実装
impl AccessControlManager {
    /// 新しいアクセス制御マネージャを作成
    pub fn new() -> Self {
        Self {
            default_policy: DefaultPolicy::DenyByDefault,
            next_entity_id: AtomicU64::new(1),
            entities: BTreeMap::new(),
            resources: BTreeMap::new(),
            policies: BTreeMap::new(),
            roles: BTreeMap::new(),
            permission_matrices: BTreeMap::new(),
            admin_settings: AdminSettings {
                enable_emergency_override: false,
                emergency_override_entities: BTreeSet::new(),
                audit_all_admin_actions: true,
                require_mfa_for_sensitive_operations: true,
                password_policy: PasswordPolicy {
                    min_length: 12,
                    require_uppercase: true,
                    require_lowercase: true,
                    require_numbers: true,
                    require_special_chars: true,
                    max_age_days: 90,
                    prevent_reuse_count: 10,
                },
                session_policy: SessionPolicy {
                    max_session_duration_minutes: 480,
                    require_reauthentication_minutes: 120,
                    idle_timeout_minutes: 30,
                    max_concurrent_sessions: 3,
                },
            },
        }
    }

    /// アクセス制御システムを初期化
    pub fn initialize(&mut self) -> Result<(), SecurityError> {
        // デフォルトドメインを作成
        self.setup_default_domain()?;
        
        // デフォルトロールを作成
        self.setup_default_roles()?;
        
        // デフォルトポリシーを作成
        self.setup_default_policies()?;
        
        // 管理者エンティティを設定
        self.setup_admin_entity()?;
        
        Ok(())
    }

    /// デフォルトポリシーを設定
    pub fn set_default_policy(&mut self, policy: DefaultPolicy) -> Result<(), SecurityError> {
        self.default_policy = policy;
        Ok(())
    }

    /// エンティティを作成
    pub fn create_entity(&mut self, entity_type: EntityType, name: String) -> Result<EntityId, SecurityError> {
        let id = self.next_entity_id.fetch_add(1, Ordering::SeqCst);
        let now = crate::core::sync::current_time_ns() / 1_000_000; // ミリ秒に変換
        
        let entity = Entity {
            id,
            entity_type,
            name,
            attributes: BTreeMap::new(),
            roles: BTreeSet::new(),
            permissions: BTreeSet::new(),
            domains: BTreeSet::new(),
            created_at: now,
            last_modified: now,
            state: EntityState::Active,
        };
        
        self.entities.insert(id, entity);
        Ok(id)
    }

    /// リソースを作成
    pub fn create_resource(
        &mut self,
        resource_type: ResourceType,
        name: String,
        path: String,
        owner: EntityId,
        sensitivity: ResourceSensitivity,
    ) -> Result<ResourceId, SecurityError> {
        // エンティティの存在を確認
        if !self.entities.contains_key(&owner) {
            return Err(SecurityError::ComponentFailure("所有者エンティティが存在しません".to_string()));
        }
        
        let id = self.next_entity_id.fetch_add(1, Ordering::SeqCst);
        let now = crate::core::sync::current_time_ns() / 1_000_000; // ミリ秒に変換
        
        let resource = Resource {
            id,
            resource_type,
            name,
            owner,
            path,
            attributes: BTreeMap::new(),
            sensitivity,
            created_at: now,
            last_modified: now,
        };
        
        self.resources.insert(id, resource);
        Ok(id)
    }

    /// リソースへのアクセス許可をチェック
    pub fn check_permission(
        &self, 
        entity_id: EntityId, 
        resource_id: ResourceId, 
        operation: Operation,
        context: Option<&AccessContext>,
    ) -> Result<PermissionResult, SecurityError> {
        // エンティティの存在をチェック
        let entity = match self.entities.get(&entity_id) {
            Some(e) => e,
            None => return Ok(PermissionResult::Denied(DenialReason::EntityNotActive)),
        };
        
        // エンティティの状態をチェック
        if entity.state != EntityState::Active {
            return Ok(PermissionResult::Denied(DenialReason::EntityNotActive));
        }
        
        // リソースの存在をチェック
        let resource = match self.resources.get(&resource_id) {
            Some(r) => r,
            None => return Ok(PermissionResult::Denied(DenialReason::ResourceNotFound)),
        };
        
        // 緊急オーバーライドをチェック
        if self.admin_settings.enable_emergency_override 
           && self.admin_settings.emergency_override_entities.contains(&entity_id) {
            return Ok(PermissionResult::Granted);
        }
        
        // 明示的なポリシーをチェック
        for (_, policy) in &self.policies {
            if !policy.enabled {
                continue;
            }
            
            for rule in &policy.rules {
                // エンティティが対象かチェック
                if !self.entity_matches_selector(entity, &rule.entity_selector) {
                    continue;
                }
                
                // リソースが対象かチェック
                if !self.resource_matches_selector(resource, &rule.resource_selector) {
                    continue;
                }
                
                // 操作が対象かチェック
                if !rule.operations.contains(&operation) {
                    continue;
                }
                
                // 条件をチェック
                let mut conditions_met = true;
                if let Some(ctx) = context {
                    for condition in &rule.conditions {
                        if !self.check_condition(condition, entity, resource, ctx) {
                            conditions_met = false;
                            break;
                        }
                    }
                } else if !rule.conditions.is_empty() {
                    // コンテキストがないが条件がある場合は一致しない
                    conditions_met = false;
                }
                
                if !conditions_met {
                    continue;
                }
                
                // ルールが一致したので、効果を適用
                match rule.effect {
                    Effect::Allow => return Ok(PermissionResult::Granted),
                    Effect::Deny => return Ok(PermissionResult::Denied(DenialReason::ExplicitDeny)),
                    Effect::AllowWithAudit => return Ok(PermissionResult::Granted), // 監査はここでは処理しない
                    Effect::DenyWithAudit => return Ok(PermissionResult::Denied(DenialReason::ExplicitDeny)), // 監査はここでは処理しない
                    Effect::Escalate => return Ok(PermissionResult::RequiresEscalation),
                }
            }
        }
        
        // ポリシーが一致しなかった場合、デフォルトポリシーを適用
        match self.default_policy {
            DefaultPolicy::DenyByDefault | DefaultPolicy::StrictDenyByDefault => {
                Ok(PermissionResult::Denied(DenialReason::NoPolicyMatch))
            },
            DefaultPolicy::AllowWithVerification => {
                // 検証を必要とするが、ここでは簡単に許可
                Ok(PermissionResult::Granted)
            },
        }
    }

    /// エンティティにロールを割り当て
    pub fn assign_role_to_entity(&mut self, entity_id: EntityId, role_id: RoleId) -> Result<(), SecurityError> {
        log::info!("役割割り当て: ユーザー={}, 役割={}", entity_id, role_id);
        
        if let Some(entity) = self.entities.get_mut(&entity_id) {
            if !self.roles.contains_key(&role_id) {
                return Err(SecurityError::ComponentFailure("ロールが存在しません".to_string()));
            }
            entity.roles.insert(role_id);
            entity.last_modified = crate::core::sync::current_time_ns() / 1_000_000; // ミリ秒に変換
            Ok(())
        } else {
            Err(SecurityError::ComponentFailure("エンティティが存在しません".to_string()))
        }
    }

    /// ロールを作成
    pub fn create_role(
        &mut self,
        name: String,
        description: String,
        domain_id: DomainId,
    ) -> Result<RoleId, SecurityError> {
        log::info!("役割作成: {}", name);
        
        let id = self.next_entity_id.fetch_add(1, Ordering::SeqCst);
        
        let role = Role {
            id,
            name: name.clone(),
            description,
            permissions: BTreeSet::new(),
            parent_roles: BTreeSet::new(),
            domain_id,
            attributes: BTreeMap::new(),
        };
        
        {
            let mut roles = self.roles.write();
            roles.insert(id, role);
        }
        
        log::info!("役割作成完了: {} (ID: {})", name, id);
        Ok(id)
    }

    /// ロールに親ロールを追加（ロール階層）
    pub fn add_parent_role(&mut self, role_id: RoleId, parent_role_id: RoleId) -> Result<(), SecurityError> {
        if !self.roles.contains_key(&role_id) || !self.roles.contains_key(&parent_role_id) {
            return Err(SecurityError::ComponentFailure("ロールが存在しません".to_string()));
        }
        
        // 循環参照を防ぐためのチェックが必要
        
        if let Some(role) = self.roles.get_mut(&role_id) {
            role.parent_roles.insert(parent_role_id);
            Ok(())
        } else {
            Err(SecurityError::ComponentFailure("ロールが存在しません".to_string()))
        }
    }

    /// ポリシーを作成
    pub fn create_policy(
        &mut self,
        name: String,
        description: String,
        rules: Vec<AccessRule>,
        priority: u8,
        domain_id: DomainId,
    ) -> Result<PolicyId, SecurityError> {
        let id = self.next_entity_id.fetch_add(1, Ordering::SeqCst);
        let now = 0; // 現在時刻
        
        let policy = Policy {
            id,
            name,
            description,
            rules,
            priority,
            domain_id,
            enabled: true,
            created_at: now,
            last_modified: now,
        };
        
        self.policies.insert(id, policy);
        Ok(id)
    }

    /// 許可マトリックスに基づいて高速アクセスチェック
    pub fn fast_permission_check(
        &self,
        entity_id: EntityId,
        resource_id: ResourceId,
        operation: Operation,
        domain_id: DomainId,
    ) -> Option<bool> {
        if let Some(matrix) = self.permission_matrices.get(&domain_id) {
            // エンティティ-リソースの直接許可をチェック
            if let Some(ops) = matrix.entity_resource_permissions.get(&(entity_id, resource_id)) {
                return Some(ops.contains(&operation));
            }
            
            // エンティティのロールを取得
            if let Some(entity) = self.entities.get(&entity_id) {
                // ロールベースのチェック
                for role_id in &entity.roles {
                    if let Some(ops) = matrix.role_resource_permissions.get(&(*role_id, resource_id)) {
                        if ops.contains(&operation) {
                            return Some(true);
                        }
                    }
                }
                
                // リソースを取得
                if let Some(resource) = self.resources.get(&resource_id) {
                    // エンティティタイプとリソースタイプのチェック
                    if let Some(ops) = matrix.entity_type_resource_type_permissions.get(&(entity.entity_type.clone(), resource.resource_type.clone())) {
                        return Some(ops.contains(&operation));
                    }
                }
            }
        }
        
        None // 高速パスでは決定できなかった
    }

    /// アクセス制御マネージャのステータスを取得
    pub fn status(&self) -> Result<AccessControlStatus, SecurityError> {
        let status = AccessControlStatus {
            entity_count: self.entities.len(),
            resource_count: self.resources.len(),
            policy_count: self.policies.len(),
            role_count: self.roles.len(),
            default_policy: self.default_policy,
            last_policy_update: 0, // 最後のポリシー更新時刻
        };
        
        Ok(status)
    }

    /// 緊急時の制限的アクセス制御を適用
    pub fn restrict_access(&mut self) -> Result<(), SecurityError> {
        // デフォルトポリシーを最も制限的なものに変更
        self.default_policy = DefaultPolicy::StrictDenyByDefault;
        
        // 一時的な制限ポリシーを適用するために既存のポリシーを無効化
        for (_, policy) in self.policies.iter_mut() {
            if policy.priority < 100 {  // 高優先度ポリシーは維持
                policy.enabled = false;
            }
        }
        
        Ok(())
    }

    /// 緊急ロックダウンの適用
    pub fn emergency_lockdown(&mut self) -> Result<(), SecurityError> {
        // 最も厳格なデフォルトポリシーに設定
        self.default_policy = DefaultPolicy::StrictDenyByDefault;
        
        // 管理者以外のエンティティを一時停止
        for (id, entity) in self.entities.iter_mut() {
            if !self.admin_settings.emergency_override_entities.contains(id) {
                entity.state = EntityState::Suspended;
            }
        }
        
        // 特別なロックダウンポリシーを適用
        self.apply_lockdown_policies()?;
        
        Ok(())
    }

    // 内部ヘルパーメソッド
    
    fn setup_default_domain(&mut self) -> Result<(), SecurityError> {
        // デフォルトドメインを作成
        let default_matrix = PermissionMatrix {
            domain_id: 1, // デフォルトドメイン
            entity_resource_permissions: BTreeMap::new(),
            role_resource_permissions: BTreeMap::new(),
            entity_type_resource_type_permissions: BTreeMap::new(),
        };
        
        self.permission_matrices.insert(1, default_matrix);
        Ok(())
    }
    
    fn setup_default_roles(&mut self) -> Result<(), SecurityError> {
        // システム管理者ロール
        let admin_role_id = self.create_role(
            "SystemAdministrator".to_string(),
            "システム全体の管理者権限を持つロール".to_string(),
            1, // デフォルトドメイン
        )?;
        
        // 一般ユーザーロール
        let user_role_id = self.create_role(
            "StandardUser".to_string(),
            "一般的なユーザー権限を持つロール".to_string(),
            1, // デフォルトドメイン
        )?;
        
        // ゲストユーザーロール
        let guest_role_id = self.create_role(
            "GuestUser".to_string(),
            "制限された権限を持つゲストロール".to_string(),
            1, // デフォルトドメイン
        )?;
        
        Ok(())
    }
    
    fn setup_default_policies(&mut self) -> Result<(), SecurityError> {
        // 管理者許可ポリシー
        let admin_rule = AccessRule {
            rule_type: RuleType::Permission,
            entity_selector: EntitySelector::ByRole(1), // 管理者ロール
            resource_selector: ResourceSelector::All,
            operations: [
                Operation::Read,
                Operation::Write,
                Operation::Execute,
                Operation::Delete,
                Operation::Create,
                Operation::Modify,
                Operation::List,
                Operation::Query,
                Operation::Control,
                Operation::Manage,
            ].iter().cloned().collect(),
            conditions: Vec::new(),
            effect: Effect::Allow,
        };
        
        let admin_policy_id = self.create_policy(
            "AdminFullAccess".to_string(),
            "管理者に完全なアクセス権を付与".to_string(),
            vec![admin_rule],
            255, // 最高優先度
            1,   // デフォルトドメイン
        )?;
        
        // 一般ユーザーポリシー
        let user_rule = AccessRule {
            rule_type: RuleType::Permission,
            entity_selector: EntitySelector::ByRole(2), // 一般ユーザーロール
            resource_selector: ResourceSelector::BySensitivity(ResourceSensitivity::Internal),
            operations: [
                Operation::Read,
                Operation::Write,
                Operation::Execute,
                Operation::List,
                Operation::Query,
            ].iter().cloned().collect(),
            conditions: Vec::new(),
            effect: Effect::Allow,
        };
        
        let user_policy_id = self.create_policy(
            "StandardUserAccess".to_string(),
            "一般ユーザーへの基本的なアクセス権".to_string(),
            vec![user_rule],
            100, // 中程度の優先度
            1,   // デフォルトドメイン
        )?;
        
        // ゲストユーザーポリシー
        let guest_rule = AccessRule {
            rule_type: RuleType::Permission,
            entity_selector: EntitySelector::ByRole(3), // ゲストロール
            resource_selector: ResourceSelector::BySensitivity(ResourceSensitivity::Public),
            operations: [
                Operation::Read,
                Operation::List,
                Operation::Query,
            ].iter().cloned().collect(),
            conditions: vec![
                Condition::TimeRange {
                    start_hour: 9,
                    end_hour: 17,
                    days: DaysOfWeek(DaysOfWeek::WEEKDAYS),
                }
            ],
            effect: Effect::Allow,
        };
        
        let guest_policy_id = self.create_policy(
            "GuestLimitedAccess".to_string(),
            "ゲストユーザーへの制限付きアクセス権".to_string(),
            vec![guest_rule],
            50, // 低優先度
            1,  // デフォルトドメイン
        )?;
        
        Ok(())
    }
    
    fn setup_admin_entity(&mut self) -> Result<(), SecurityError> {
        // 管理者エンティティを作成
        let admin_id = self.create_entity(
            EntityType::User,
            "SystemAdministrator".to_string(),
        )?;
        
        // 管理者ロールを割り当て
        self.assign_role_to_entity(admin_id, 1)?; // 管理者ロールID
        
        // 緊急時オーバーライドエンティティに追加
        self.admin_settings.emergency_override_entities.insert(admin_id);
        
        Ok(())
    }
    
    fn apply_lockdown_policies(&mut self) -> Result<(), SecurityError> {
        // ロックダウン専用ポリシーを作成
        let lockdown_rule = AccessRule {
            rule_type: RuleType::Prohibition,
            entity_selector: EntitySelector::All,
            resource_selector: ResourceSelector::BySensitivity(ResourceSensitivity::Critical),
            operations: [
                Operation::Delete,
                Operation::Modify,
                Operation::Control,
                Operation::Manage,
            ].iter().cloned().collect(),
            conditions: Vec::new(),
            effect: Effect::DenyWithAudit,
        };
        
        // 緊急アクセス許可ルール（管理者のみ）
        let emergency_rule = AccessRule {
            rule_type: RuleType::Permission,
            entity_selector: EntitySelector::Complex(vec![
                EntitySelector::ByRole(1), // 管理者ロール
                EntitySelector::ByType(EntityType::User),
            ]),
            resource_selector: ResourceSelector::All,
            operations: [
                Operation::Read,
                Operation::Write,
                Operation::Control,
                Operation::Monitor,
            ].iter().cloned().collect(),
            conditions: vec![
                Condition::TrustScoreAbove(90),
                Condition::Custom("emergency_mode".to_string(), vec!["true".to_string()]),
            ],
            effect: Effect::AllowWithAudit,
        };
        
        // ロックダウンポリシーを作成
        let lockdown_policy_id = self.create_policy(
            "EmergencyLockdown".to_string(),
            "緊急時ロックダウンポリシー".to_string(),
            vec![lockdown_rule, emergency_rule],
            200, // 非常に高い優先度
            1,   // デフォルトドメイン
        )?;
        
        log::info!("緊急ロックダウンポリシー適用完了: ポリシーID={}", lockdown_policy_id);
        Ok(())
    }
    
    fn entity_matches_selector(&self, entity: &Entity, selector: &EntitySelector) -> bool {
        match selector {
            EntitySelector::All => true,
            EntitySelector::ById(id) => entity.id == *id,
            EntitySelector::ByIds(ids) => ids.contains(&entity.id),
            EntitySelector::ByType(entity_type) => entity.entity_type == *entity_type,
            EntitySelector::ByRole(role_id) => entity.roles.contains(role_id),
            EntitySelector::ByRoles(role_ids) => {
                role_ids.iter().any(|role_id| entity.roles.contains(role_id))
            },
            EntitySelector::ByAttribute { key, value } => {
                entity.attributes.get(key) == Some(value)
            },
            EntitySelector::ByDomain(domain_id) => entity.domains.contains(domain_id),
            EntitySelector::Complex(selectors) => {
                selectors.iter().all(|s| self.entity_matches_selector(entity, s))
            },
        }
    }
    
    fn resource_matches_selector(&self, resource: &Resource, selector: &ResourceSelector) -> bool {
        match selector {
            ResourceSelector::All => true,
            ResourceSelector::ById(id) => resource.id == *id,
            ResourceSelector::ByIds(ids) => ids.contains(&resource.id),
            ResourceSelector::ByType(resource_type) => resource.resource_type == *resource_type,
            ResourceSelector::ByPath(path) => resource.path == *path,
            ResourceSelector::ByPathPattern(pattern) => {
                // 完全な正規表現とglobパターンマッチング実装
                let pattern_matcher = PatternMatcher::new();
                pattern_matcher.matches(&resource.path, pattern)
            },
            ResourceSelector::BySensitivity(sensitivity) => resource.sensitivity == *sensitivity,
            ResourceSelector::ByAttribute { key, value } => {
                resource.attributes.get(key) == Some(value)
            },
            ResourceSelector::Complex(selectors) => {
                selectors.iter().all(|s| self.resource_matches_selector(resource, s))
            },
        }
    }
    
    fn check_condition(&self, condition: &Condition, entity: &Entity, resource: &Resource, context: &AccessContext) -> bool {
        match condition {
            Condition::TimeRange { start_hour, end_hour, days } => {
                // 現在時刻を取得（実装簡略化のため固定値）
                let current_hour = 14; // 14時と仮定
                let current_day = 2;   // 火曜日と仮定（ビット位置）
                
                let hour_check = current_hour >= *start_hour && current_hour <= *end_hour;
                let day_check = (days.0 & (1 << current_day)) != 0;
                
                hour_check && day_check
            },
            Condition::LocationIs(location) => {
                context.location.as_ref() == Some(location)
            },
            Condition::NetworkIs(network) => {
                context.network.as_ref() == Some(network)
            },
            Condition::DeviceIs(device) => {
                context.device.as_ref() == Some(device)
            },
            Condition::AttributeEquals { key, value } => {
                entity.attributes.get(key) == Some(value)
            },
            Condition::AttributeMatches { key, pattern } => {
                if let Some(attr_value) = entity.attributes.get(key) {
                    // 簡易パターンマッチング
                    attr_value.contains(pattern)
                } else {
                    false
                }
            },
            Condition::ResourceAttributeEquals { key, value } => {
                resource.attributes.get(key) == Some(value)
            },
            Condition::TrustScoreAbove(threshold) => {
                context.trust_score.unwrap_or(0) > *threshold
            },
            Condition::Custom(condition_name, parameters) => {
                match condition_name.as_str() {
                    "emergency_mode" => {
                        parameters.get(0) == Some(&"true".to_string())
                    },
                    "mfa_verified" => {
                        context.authentication_method.as_ref()
                            .map(|method| method.contains("mfa"))
                            .unwrap_or(false)
                    },
                    "secure_channel" => {
                        context.additional_attributes.get("channel_security")
                            .map(|security| security == "encrypted")
                            .unwrap_or(false)
                    },
                    _ => {
                        log::warn!("未知のカスタム条件: {}", condition_name);
                        false
                    }
                }
            },
        }
    }
}

/// アクセスコンテキスト（アクセス決定の際に使用される追加情報）
#[derive(Debug, Clone)]
pub struct AccessContext {
    pub timestamp: Option<u64>,
    pub location: Option<String>,
    pub network: Option<String>,
    pub device: Option<String>,
    pub session_id: Option<String>,
    pub authentication_method: Option<String>,
    pub trust_score: Option<u8>,
    pub additional_attributes: BTreeMap<String, String>,
} 