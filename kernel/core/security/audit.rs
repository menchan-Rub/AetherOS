// AetherOS セキュリティ監査ログシステム
//
// 高度な監査機能とセキュリティイベント記録を提供し、
// システム全体のセキュリティ状態を監視・追跡する

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::core::sync::{Mutex, RwLock, SpinLock};
use super::{SecurityLevel, SecurityEvent, SecurityEventType, SecurityResult};
use crate::core::security::SecurityError;
use alloc::string::ToString;
use alloc::collections::BTreeSet;
use core::sync::atomic::AtomicU64;
use spin::Mutex as SpinMutex;

/// 監査ポリシータイプ
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AuditPolicyType {
    /// イベントタイプベース
    EventType,
    /// リソースベース
    Resource,
    /// プロセスベース
    Process,
    /// ユーザーベース
    User,
    /// ドメインベース
    Domain,
    /// 時間ベース
    Time,
    /// 重要度レベルベース
    SeverityLevel,
}

/// 監査ポリシー
#[derive(Debug, Clone)]
pub struct AuditPolicy {
    /// ポリシーID
    pub id: usize,
    /// ポリシー名
    pub name: String,
    /// ポリシータイプ
    pub policy_type: AuditPolicyType,
    /// イベントタイプ（EventTypeポリシー用）
    pub event_types: Option<Vec<SecurityEventType>>,
    /// リソースID（Resourceポリシー用）
    pub resource_ids: Option<Vec<usize>>,
    /// プロセスID（Processポリシー用）
    pub process_ids: Option<Vec<usize>>,
    /// ユーザーID（Userポリシー用）
    pub user_ids: Option<Vec<usize>>,
    /// ドメインID（Domainポリシー用）
    pub domain_ids: Option<Vec<usize>>,
    /// 時間範囲（Timeポリシー用）
    pub time_ranges: Option<Vec<(u8, u8)>>, // (開始時間, 終了時間)
    /// 重要度レベル閾値（SeverityLevelポリシー用）
    pub min_severity: Option<u8>, // 0-100
    /// アラート通知が必要か
    pub alert_required: bool,
    /// 保存先
    pub log_destination: LogDestination,
}

/// ログ保存先
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LogDestination {
    /// メモリのみ（揮発性）
    Memory,
    /// ローカルファイル
    LocalFile,
    /// セキュアストレージ（暗号化）
    SecureStorage,
    /// リモートサーバー
    RemoteServer,
    /// 複数の場所（冗長）
    Multiple,
}

/// 監査ログエントリ
#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    /// イベントID
    pub event_id: usize,
    /// タイムスタンプ
    pub timestamp: u64,
    /// イベント種別
    pub event_type: SecurityEventType,
    /// 関連プロセスID（該当する場合）
    pub process_id: Option<usize>,
    /// 関連ユーザーID（該当する場合）
    pub user_id: Option<usize>,
    /// 関連ドメインID（該当する場合）
    pub domain_id: Option<usize>,
    /// 重要度（0-100, 高いほど重要）
    pub severity: u8,
    /// イベント詳細
    pub details: String,
    /// 処理結果
    pub result: SecurityResult,
    /// ソースIP（該当する場合）
    pub source_ip: Option<[u8; 4]>,
    /// 対象リソースID（該当する場合）
    pub resource_id: Option<usize>,
    /// 追加属性
    pub attributes: BTreeMap<String, String>,
}

/// 監査エンジン
pub struct AuditEngine {
    /// 監査ポリシー
    audit_policies: RwLock<Vec<AuditPolicy>>,
    /// 監査ログ
    audit_logs: Mutex<VecDeque<AuditLogEntry>>,
    /// メモリ内ログの最大サイズ
    max_log_size: AtomicUsize,
    /// 監査アラート用閾値
    alert_threshold: AtomicUsize,
    /// 現在のセキュリティレベル
    security_level: RwLock<SecurityLevel>,
    /// 次のポリシーID
    next_policy_id: AtomicUsize,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// 監査有効フラグ
    auditing_enabled: AtomicBool,
}

impl AuditEngine {
    /// 新しい監査エンジンを作成
    pub fn new() -> Self {
        Self {
            audit_policies: RwLock::new(Vec::new()),
            audit_logs: Mutex::new(VecDeque::with_capacity(1000)),
            max_log_size: AtomicUsize::new(1000),
            alert_threshold: AtomicUsize::new(80),
            security_level: RwLock::new(SecurityLevel::Standard),
            next_policy_id: AtomicUsize::new(1),
            initialized: AtomicBool::new(false),
            auditing_enabled: AtomicBool::new(false),
        }
    }
    
    /// 監査エンジンを初期化
    pub fn initialize(&self) -> Result<(), &'static str> {
        if self.initialized.load(Ordering::SeqCst) {
            return Err("監査エンジンは既に初期化されています");
        }
        
        // デフォルトのポリシーを設定
        self.create_default_policies();
        
        // 監査を有効化
        self.auditing_enabled.store(true, Ordering::SeqCst);
        
        self.initialized.store(true, Ordering::SeqCst);
        
        log::info!("監査エンジンを初期化しました");
        
        Ok(())
    }
    
    /// デフォルトの監査ポリシーを作成
    fn create_default_policies(&self) {
        let policies = vec![
            // 認証イベントポリシー
            AuditPolicy {
                id: self.next_policy_id.fetch_add(1, Ordering::SeqCst),
                name: "認証監査".to_string(),
                policy_type: AuditPolicyType::EventType,
                event_types: Some(vec![SecurityEventType::Authentication]),
                resource_ids: None,
                process_ids: None,
                user_ids: None,
                domain_ids: None,
                time_ranges: None,
                min_severity: None,
                alert_required: true,
                log_destination: LogDestination::SecureStorage,
            },
            
            // 高重要度イベントポリシー
            AuditPolicy {
                id: self.next_policy_id.fetch_add(1, Ordering::SeqCst),
                name: "高重要度イベント監査".to_string(),
                policy_type: AuditPolicyType::SeverityLevel,
                event_types: None,
                resource_ids: None,
                process_ids: None,
                user_ids: None,
                domain_ids: None,
                time_ranges: None,
                min_severity: Some(80),
                alert_required: true,
                log_destination: LogDestination::Multiple,
            },
            
            // システムリソースポリシー
            AuditPolicy {
                id: self.next_policy_id.fetch_add(1, Ordering::SeqCst),
                name: "システムリソース監査".to_string(),
                policy_type: AuditPolicyType::Resource,
                event_types: None,
                resource_ids: Some(vec![1, 2, 3]), // 重要システムリソースID
                process_ids: None,
                user_ids: None,
                domain_ids: None,
                time_ranges: None,
                min_severity: None,
                alert_required: false,
                log_destination: LogDestination::LocalFile,
            },
        ];
        
        let mut audit_policies = self.audit_policies.write().unwrap();
        audit_policies.extend(policies);
    }
    
    /// 監査ポリシーを追加
    pub fn add_audit_policy(&self, policy: AuditPolicy) -> usize {
        let policy_id = policy.id;
        
        let mut policies = self.audit_policies.write().unwrap();
        policies.push(policy);
        
        log::info!("監査ポリシーを追加しました: ID {}", policy_id);
        
        policy_id
    }
    
    /// セキュリティイベントをログに記録
    pub fn log_event(&self, event: &SecurityEvent) {
        if !self.auditing_enabled.load(Ordering::Relaxed) {
            return;
        }
        
        // イベントを監査ログエントリに変換
        let log_entry = AuditLogEntry {
            event_id: event.id,
            timestamp: event.timestamp,
            event_type: event.event_type,
            process_id: event.process_id,
            user_id: event.user_id,
            domain_id: event.domain_id,
            severity: event.severity,
            details: event.details.clone(),
            result: event.result,
            source_ip: None, // イベントに含まれていない場合
            resource_id: None, // イベントに含まれていない場合
            attributes: BTreeMap::new(),
        };
        
        // ポリシーに基づいて処理
        if self.should_log_event(&log_entry) {
            // メモリに保存
            self.store_log_entry(log_entry.clone());
            
            // 永続ストレージに保存（実際の実装では各宛先に適切に保存）
            self.persist_log_entry(&log_entry);
            
            // アラートが必要かチェック
            if self.should_alert(&log_entry) {
                self.send_alert(&log_entry);
            }
        }
    }
    
    /// イベントをログに記録すべきかチェック
    fn should_log_event(&self, entry: &AuditLogEntry) -> bool {
        // ポリシーに基づいて判断
        let policies = self.audit_policies.read().unwrap();
        
        for policy in policies.iter() {
            // イベントタイプポリシー
            if policy.policy_type == AuditPolicyType::EventType {
                if let Some(event_types) = &policy.event_types {
                    if event_types.contains(&entry.event_type) {
                        return true;
                    }
                }
            }
            
            // 重要度レベルポリシー
            if policy.policy_type == AuditPolicyType::SeverityLevel {
                if let Some(min_severity) = policy.min_severity {
                    if entry.severity >= min_severity {
                        return true;
                    }
                }
            }
            
            // プロセスポリシー
            if policy.policy_type == AuditPolicyType::Process {
                if let (Some(process_ids), Some(process_id)) = (&policy.process_ids, entry.process_id) {
                    if process_ids.contains(&process_id) {
                        return true;
                    }
                }
            }
            
            // ユーザーポリシー
            if policy.policy_type == AuditPolicyType::User {
                if let (Some(user_ids), Some(user_id)) = (&policy.user_ids, entry.user_id) {
                    if user_ids.contains(&user_id) {
                        return true;
                    }
                }
            }
            
            // ドメインポリシー
            if policy.policy_type == AuditPolicyType::Domain {
                if let (Some(domain_ids), Some(domain_id)) = (&policy.domain_ids, entry.domain_id) {
                    if domain_ids.contains(&domain_id) {
                        return true;
                    }
                }
            }
            
            // リソースポリシー
            if policy.policy_type == AuditPolicyType::Resource {
                if let (Some(resource_ids), Some(resource_id)) = (&policy.resource_ids, entry.resource_id) {
                    if resource_ids.contains(&resource_id) {
                        return true;
                    }
                }
            }
            
            // 時間ポリシー
            if policy.policy_type == AuditPolicyType::Time {
                if let Some(time_ranges) = &policy.time_ranges {
                    let current_hour = self.get_current_hour(entry.timestamp);
                    for &(start, end) in time_ranges {
                        if current_hour >= start && current_hour <= end {
                            return true;
                        }
                    }
                }
            }
        }
        
        // セキュリティレベルに応じてデフォルト動作を切り替え
        match self.security_level.read().unwrap() {
            SecurityLevel::High => true,
            _ => false,
        }
    }
    
    /// アラートが必要かチェック
    fn should_alert(&self, entry: &AuditLogEntry) -> bool {
        // 重要度がアラート閾値以上の場合
        if entry.severity >= self.alert_threshold.load(Ordering::Relaxed) as u8 {
            return true;
        }
        
        // 特定のイベントタイプの場合
        match entry.event_type {
            SecurityEventType::Authentication | 
            SecurityEventType::PolicyViolation |
            SecurityEventType::ThreatDetection => {
                if entry.result == SecurityResult::Deny {
                    return true;
                }
            },
            _ => {}
        }
        
        // ポリシーに基づいてチェック
        let policies = self.audit_policies.read().unwrap();
        
        for policy in policies.iter() {
            if !policy.alert_required {
                continue;
            }
            
            // 以下はshould_log_eventと同様のロジック
            // イベントタイプポリシー
            if policy.policy_type == AuditPolicyType::EventType {
                if let Some(event_types) = &policy.event_types {
                    if event_types.contains(&entry.event_type) {
                        return true;
                    }
                }
            }
            
            // 他のポリシータイプも同様...
        }
        
        false
    }
    
    /// アラートを送信
    fn send_alert(&self, entry: &AuditLogEntry) {
        // 通知システムと連携
        notification::send_alert(entry)?;
    }
    
    /// ログエントリをメモリに保存
    fn store_log_entry(&self, entry: AuditLogEntry) {
        let mut logs = self.audit_logs.lock().unwrap();
        logs.push_back(entry);
        
        // 最大サイズを超えた場合、古いエントリを削除
        let max_size = self.max_log_size.load(Ordering::Relaxed);
        while logs.len() > max_size {
            logs.pop_front();
        }
    }
    
    /// ログエントリを永続ストレージに保存
    fn persist_log_entry(&self, log_entry: &AuditLogEntry) {
        // 永続ストレージへの保存処理
        match self.storage_config.storage_type {
            StorageType::File => self.persist_to_file(log_entry),
            StorageType::Database => self.persist_to_database(log_entry),
            StorageType::Network => self.persist_to_network(log_entry),
            StorageType::Memory => self.persist_to_memory(log_entry),
        }
        
        // バックアップストレージへの書き込み（冗長性のため）
        if let Some(backup_config) = &self.storage_config.backup_storage {
            match backup_config.storage_type {
                StorageType::File => self.persist_to_backup_file(log_entry, backup_config),
                StorageType::Network => self.persist_to_backup_network(log_entry, backup_config),
                _ => {} // その他のバックアップ方式
            }
        }
        
        // リモート監査サーバーへの送信（セキュリティ要件が高い場合）
        if self.storage_config.enable_remote_audit {
            self.send_to_remote_audit_server(log_entry);
        }
        
        // ログローテーション処理
        self.check_and_rotate_logs();
        
        log::trace!("監査ログ永続化完了: ID={}", log_entry.event_id);
    }

    fn persist_to_file(&self, log_entry: &AuditLogEntry) {
        let file_path = self.get_current_log_file_path();
        
        // JSON形式でシリアライズ
        let serialized = self.serialize_log_entry(log_entry);
        
        // ファイルに追記書き込み
        match crate::fs::append_file(&file_path, &serialized) {
            Ok(_) => {
                log::trace!("ファイルへの監査ログ書き込み成功: {}", file_path);
                self.stats.file_writes.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => {
                log::error!("ファイルへの監査ログ書き込み失敗: {}, エラー: {:?}", file_path, e);
                self.stats.write_errors.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                
                // フォールバック: メモリ内緊急バッファに保存
                self.emergency_buffer_append(log_entry);
            }
        }
    }

    fn persist_to_database(&self, log_entry: &AuditLogEntry) {
        // SQLライトデータベースへの挿入（組み込みDB使用）
        let db_connection = match self.get_database_connection() {
            Ok(conn) => conn,
            Err(e) => {
                log::error!("データベース接続失敗: {:?}", e);
                self.emergency_buffer_append(log_entry);
                return;
            }
        };
        
        let insert_query = format!(
            "INSERT INTO audit_logs (id, timestamp, event_type, user_id, process_id, resource, action, result, details) VALUES ({}, {}, '{}', {}, {}, '{}', '{}', '{}', '{}')",
            log_entry.event_id,
            log_entry.timestamp,
            log_entry.event_type,
            log_entry.user_id.unwrap_or(0),
            log_entry.process_id.unwrap_or(0),
            log_entry.resource_id.map(|id| id.to_string()).unwrap_or_else(|| "null".to_string()),
            log_entry.details.as_deref().unwrap_or(""),
            log_entry.result,
            log_entry.severity
        );
        
        match db_connection.execute(&insert_query) {
            Ok(_) => {
                log::trace!("データベースへの監査ログ書き込み成功");
                self.stats.database_writes.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => {
                log::error!("データベースへの監査ログ書き込み失敗: {:?}", e);
                self.stats.write_errors.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                self.emergency_buffer_append(log_entry);
            }
        }
    }

    fn persist_to_network(&self, log_entry: &AuditLogEntry) {
        // ネットワーク経由でのログ送信（syslogプロトコル使用）
        let network_config = &self.storage_config.network_config;
        
        // syslogメッセージの構築
        let syslog_message = self.build_syslog_message(log_entry);
        
        // UDP/TCPソケットでの送信
        match network_config.protocol {
            NetworkProtocol::UDP => self.send_udp_syslog(&syslog_message, &network_config.server_address, network_config.port),
            NetworkProtocol::TCP => self.send_tcp_syslog(&syslog_message, &network_config.server_address, network_config.port),
            NetworkProtocol::TLS => self.send_tls_syslog(&syslog_message, &network_config.server_address, network_config.port),
        }
    }

    fn persist_to_memory(&self, log_entry: &AuditLogEntry) {
        // メモリ内リングバッファへの保存
        let mut memory_buffer = self.memory_buffer.write();
        
        if memory_buffer.len() >= self.storage_config.max_memory_entries {
            // バッファが満杯の場合、最古のエントリを削除
            memory_buffer.remove(0);
            self.stats.buffer_overflows.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        
        memory_buffer.push(log_entry.clone());
        self.stats.memory_writes.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        
        log::trace!("メモリバッファへの監査ログ書き込み完了");
    }

    fn serialize_log_entry(&self, log_entry: &AuditLogEntry) -> Vec<u8> {
        // JSON形式でのシリアライゼーション
        let json_string = format!(
            "{{\"id\":{},\"timestamp\":{},\"event_type\":\"{}\",\"user_id\":{},\"process_id\":{},\"resource\":\"{}\",\"action\":\"{}\",\"result\":\"{}\",\"details\":\"{}\",\"severity\":\"{:?}\"}}\n",
            log_entry.event_id,
            log_entry.timestamp,
            log_entry.event_type,
            log_entry.user_id.map(|id| id.to_string()).unwrap_or_else(|| "null".to_string()),
            log_entry.process_id.map(|id| id.to_string()).unwrap_or_else(|| "null".to_string()),
            log_entry.resource_id.map(|id| id.to_string()).unwrap_or_else(|| "null".to_string()),
            log_entry.details.as_deref().unwrap_or(""),
            log_entry.result,
            log_entry.severity
        );
        
        json_string.into_bytes()
    }

    fn build_syslog_message(&self, log_entry: &AuditLogEntry) -> String {
        // RFC3164形式のsyslogメッセージ構築
        let priority = match log_entry.severity {
            AuditSeverity::Critical => 2,  // Critical
            AuditSeverity::High => 3,      // Error
            AuditSeverity::Medium => 4,    // Warning
            AuditSeverity::Low => 6,       // Info
        };
        
        // <priority>timestamp hostname tag: message
        format!(
            "<{}>{} {} audit[{}]: {} {} {} {} {}",
            priority,
            crate::time::format_timestamp(log_entry.timestamp),
            crate::system::get_hostname(),
            log_entry.event_id,
            log_entry.event_type,
            log_entry.resource_id.map(|id| id.to_string()).unwrap_or_else(|| "null".to_string()),
            log_entry.details.as_deref().unwrap_or(""),
            log_entry.result
        )
    }

    fn send_udp_syslog(&self, message: &str, server_address: &str, port: u16) {
        match crate::network::udp::send_message(server_address, port, message.as_bytes()) {
            Ok(_) => {
                log::trace!("UDP syslog送信成功: {}", server_address);
                self.stats.network_writes.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => {
                log::error!("UDP syslog送信失敗: {}, エラー: {:?}", server_address, e);
                self.stats.network_errors.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    fn send_tcp_syslog(&self, message: &str, server_address: &str, port: u16) {
        // TCPコネクション確立とメッセージ送信
        match crate::network::tcp::connect_and_send(server_address, port, message.as_bytes()) {
            Ok(_) => {
                log::trace!("TCP syslog送信成功: {}", server_address);
                self.stats.network_writes.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => {
                log::error!("TCP syslog送信失敗: {}, エラー: {:?}", server_address, e);
                self.stats.network_errors.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    fn send_tls_syslog(&self, message: &str, server_address: &str, port: u16) {
        // TLS暗号化によるsyslog送信
        match crate::network::tls::connect_and_send(server_address, port, message.as_bytes()) {
            Ok(_) => {
                log::trace!("TLS syslog送信成功: {}", server_address);
                self.stats.network_writes.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => {
                log::error!("TLS syslog送信失敗: {}, エラー: {:?}", server_address, e);
                self.stats.network_errors.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    fn get_current_log_file_path(&self) -> String {
        let base_path = &self.storage_config.file_config.base_path;
        let current_date = crate::time::format_date(crate::time::current_time_ms());
        let log_index = self.get_current_log_index();
        
        format!("{}/audit-{}-{:03}.log", base_path, current_date, log_index)
    }

    fn get_current_log_index(&self) -> u32 {
        // 現在のログファイルインデックスを取得
        let current_file_size = self.get_current_log_file_size();
        let max_file_size = self.storage_config.file_config.max_file_size;
        
        if current_file_size >= max_file_size {
            self.increment_log_index()
        } else {
            self.current_log_index.load(core::sync::atomic::Ordering::Relaxed)
        }
    }

    fn get_current_log_file_size(&self) -> u64 {
        let file_path = self.get_current_log_file_path();
        crate::fs::get_file_size(&file_path).unwrap_or(0)
    }

    fn increment_log_index(&self) -> u32 {
        self.current_log_index.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1
    }

    fn check_and_rotate_logs(&self) {
        let current_file_size = self.get_current_log_file_size();
        let max_file_size = self.storage_config.file_config.max_file_size;
        
        if current_file_size >= max_file_size {
            self.rotate_log_files();
        }
        
        // 古いログファイルの削除
        self.cleanup_old_logs();
    }

    fn rotate_log_files(&self) {
        log::info!("監査ログファイルローテーション開始");
        
        // 現在のログファイルを閉じて新しいファイルを開始
        self.increment_log_index();
        
        // 古いファイルの圧縮（オプション）
        if self.storage_config.file_config.compress_old_files {
            self.compress_old_log_files();
        }
        
        log::info!("監査ログファイルローテーション完了");
    }

    fn cleanup_old_logs(&self) {
        let retention_days = self.storage_config.file_config.retention_days;
        let cutoff_time = crate::time::current_time_ms() - (retention_days as u64 * 24 * 60 * 60 * 1000);
        
        // 保存期間を過ぎたログファイルを削除
        if let Ok(log_files) = crate::fs::list_directory(&self.storage_config.file_config.base_path) {
            for file in log_files {
                if file.starts_with("audit-") && file.ends_with(".log") {
                    if let Ok(file_time) = crate::fs::get_file_creation_time(&file) {
                        if file_time < cutoff_time {
                            match crate::fs::delete_file(&file) {
                                Ok(_) => log::info!("古い監査ログファイル削除: {}", file),
                                Err(e) => log::error!("監査ログファイル削除失敗: {}, エラー: {:?}", file, e),
                            }
                        }
                    }
                }
            }
        }
    }

    fn compress_old_log_files(&self) {
        // 古いログファイルの圧縮処理
        if let Ok(log_files) = crate::fs::list_directory(&self.storage_config.file_config.base_path) {
            for file in log_files {
                if file.ends_with(".log") && !self.is_current_log_file(&file) {
                    match self.compress_file(&file) {
                        Ok(compressed_file) => {
                            log::info!("ログファイル圧縮完了: {} -> {}", file, compressed_file);
                            // 元ファイルを削除
                            let _ = crate::fs::delete_file(&file);
                        }
                        Err(e) => {
                            log::error!("ログファイル圧縮失敗: {}, エラー: {:?}", file, e);
                        }
                    }
                }
            }
        }
    }

    fn compress_file(&self, file_path: &str) -> Result<String, &'static str> {
        // gzip圧縮の実装
        let compressed_path = format!("{}.gz", file_path);
        
        let file_content = crate::fs::read_file(file_path)
            .map_err(|_| "ファイル読み込み失敗")?;
        
        let compressed_content = crate::compression::gzip::compress(&file_content)
            .map_err(|_| "圧縮失敗")?;
        
        crate::fs::write_file(&compressed_path, &compressed_content)
            .map_err(|_| "圧縮ファイル書き込み失敗")?;
        
        Ok(compressed_path)
    }

    fn is_current_log_file(&self, file_path: &str) -> bool {
        let current_path = self.get_current_log_file_path();
        file_path == current_path
    }

    fn emergency_buffer_append(&self, log_entry: &AuditLogEntry) {
        // 緊急時メモリバッファへの保存
        let mut emergency_buffer = self.emergency_buffer.write();
        
        if emergency_buffer.len() >= EMERGENCY_BUFFER_SIZE {
            emergency_buffer.remove(0); // 最古のエントリを削除
        }
        
        emergency_buffer.push(log_entry.clone());
        log::warn!("緊急バッファに監査ログ保存: ID={}", log_entry.event_id);
    }

    fn get_database_connection(&self) -> Result<DatabaseConnection, &'static str> {
        // SQLiteデータベース接続の取得
        DatabaseConnection::connect(&self.storage_config.database_config.connection_string)
    }

    fn send_to_remote_audit_server(&self, log_entry: &AuditLogEntry) {
        // リモート監査サーバーへの送信
        let remote_config = &self.storage_config.remote_audit_config;
        
        let encrypted_entry = self.encrypt_log_entry(log_entry, &remote_config.encryption_key);
        
        match crate::network::https::post_request(&remote_config.server_url, &encrypted_entry) {
            Ok(_) => {
                log::trace!("リモート監査サーバーへの送信成功");
                self.stats.remote_writes.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => {
                log::error!("リモート監査サーバーへの送信失敗: {:?}", e);
                self.stats.remote_errors.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    fn encrypt_log_entry(&self, log_entry: &AuditLogEntry, encryption_key: &[u8]) -> Vec<u8> {
        let serialized = self.serialize_log_entry(log_entry);
        
        // AES-256-GCMによる暗号化
        match crate::crypto::aes::encrypt_aes256_gcm(&serialized, encryption_key) {
            Ok(encrypted) => encrypted,
            Err(_) => {
                log::error!("監査ログ暗号化失敗");
                serialized // フォールバック: 平文で送信（セキュリティリスクあり）
            }
        }
    }
}

/// 監査サブシステムを管理する主要コンポーネント
pub struct AuditManager {
    // 監査ログレベル
    logging_level: LoggingLevel,
    
    // イベントバッファ
    event_buffer: Mutex<Vec<AuditEvent>>,
    
    // イベントID割り当てカウンター
    next_event_id: AtomicU64,
    
    // イベントタイプ設定
    event_type_configs: BTreeMap<AuditEventType, EventTypeConfig>,
    
    // 保持ポリシー
    retention_policy: RetentionPolicy,
    
    // アクティブなアラート条件
    alert_conditions: Vec<AlertCondition>,
    
    // 監査メトリクス
    metrics: AuditMetrics,
}

/// 監査ログレベル
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LoggingLevel {
    /// 重要なイベントのみを記録
    Important,
    
    /// 詳細なイベントを記録
    Detailed,
    
    /// あらゆる種類のイベントを記録
    Comprehensive,
}

/// 監査イベント
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub id: u64,
    pub event_type: AuditEventType,
    pub timestamp: u64,
    pub source: String,
    pub user_id: Option<u64>,
    pub process_id: Option<u64>,
    pub resource: Option<String>,
    pub action: String,
    pub result: ActionResult,
    pub severity: EventSeverity,
    pub details: String,
    pub metadata: BTreeMap<String, String>,
    pub related_events: Vec<u64>,
}

/// 監査イベントタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditEventType {
    // システムイベント
    SystemStartup,
    SystemShutdown,
    SystemCrash,
    SystemUpdate,
    ServiceStateChange,
    
    // セキュリティイベント
    Authentication,
    Authorization,
    AccessControl,
    PolicyChange,
    CertificateManagement,
    PrivilegeChange,
    
    // ユーザーアクション
    UserLogin,
    UserLogout,
    UserCreation,
    UserModification,
    UserDeletion,
    PasswordChange,
    
    // リソースアクション
    FileAccess,
    NetworkAccess,
    DatabaseAccess,
    ResourceCreation,
    ResourceModification,
    ResourceDeletion,
    
    // セキュリティアラート
    IntrusionDetection,
    MalwareDetection,
    AnomalyDetection,
    IntegrityViolation,
    PolicyViolation,
    
    // 管理イベント
    ConfigurationChange,
    MaintenanceActivity,
    BackupActivity,
    AuditConfigChange,
    
    // カスタムイベント
    Custom(u16),
    
    // 監査サブシステム自体のイベント
    SecuritySystemInitialized,
    SecurityLevelChanged,
}

/// イベントタイプ設定
#[derive(Debug, Clone)]
pub struct EventTypeConfig {
    pub enabled: bool,
    pub minimum_level: LoggingLevel,
    pub retention_days: u32,
    pub requires_immediate_sync: bool,
}

/// アクション結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionResult {
    Success,
    Failure,
    Denied,
    Error,
    Timeout,
    Pending,
    Unknown,
}

/// イベント重大度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// 保持ポリシー
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    pub default_retention_days: u32,
    pub high_severity_retention_days: u32,
    pub max_events_in_memory: usize,
    pub sync_interval_seconds: u32,
    pub compression_enabled: bool,
}

/// アラート条件
#[derive(Debug, Clone)]
pub struct AlertCondition {
    pub id: u64,
    pub name: String,
    pub event_types: Vec<AuditEventType>,
    pub minimum_severity: EventSeverity,
    pub pattern: Option<String>,
    pub threshold: Option<ThresholdCondition>,
    pub actions: Vec<AlertAction>,
    pub enabled: bool,
}

/// しきい値条件
#[derive(Debug, Clone)]
pub struct ThresholdCondition {
    pub count: u32,
    pub time_window_seconds: u32,
    pub aggregation_key: Option<String>,
}

/// アラートアクション
#[derive(Debug, Clone)]
pub enum AlertAction {
    Log,
    Notify,
    ExecuteCommand(String),
    TriggerResponse(String),
}

/// 監査メトリクス
#[derive(Debug, Clone)]
pub struct AuditMetrics {
    pub total_events: u64,
    pub events_by_type: BTreeMap<AuditEventType, u64>,
    pub events_by_severity: BTreeMap<EventSeverity, u64>,
    pub failed_actions: u64,
    pub alerts_triggered: u64,
}

/// 監査クエリ
#[derive(Debug, Clone)]
pub struct AuditQuery {
    pub event_types: Option<Vec<AuditEventType>>,
    pub start_time: Option<u64>,
    pub end_time: Option<u64>,
    pub min_severity: Option<EventSeverity>,
    pub user_ids: Option<Vec<u64>>,
    pub resources: Option<Vec<String>>,
    pub results: Option<Vec<ActionResult>>,
    pub text_search: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// 監査ステータス
#[derive(Debug, Clone)]
pub struct AuditStatus {
    pub logging_level: LoggingLevel,
    pub events_in_buffer: usize,
    pub last_event_time: Option<u64>,
    pub alerts_active: usize,
    pub total_events_processed: u64,
    pub health_status: HealthStatus,
}

/// ヘルスステータス
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Critical,
}

/// セキュリティインシデント
#[derive(Debug, Clone)]
pub struct SecurityIncident {
    pub id: u64,
    pub incident_type: IncidentType,
    pub timestamp: u64,
    pub source: String,
    pub severity: IncidentSeverity,
    pub status: IncidentStatus,
    pub details: String,
    pub related_events: Vec<u64>,
    pub affected_resources: Vec<String>,
    pub resolution: Option<String>,
}

/// インシデントタイプ
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncidentType {
    UnauthorizedAccess,
    AuthenticationFailure,
    MalwareDetection,
    DataExfiltration,
    DenialOfService,
    EscalationOfPrivilege,
    IntegrityViolation,
    Other(String),
}

/// インシデント重大度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// インシデント状態
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncidentStatus {
    New,
    InProgress,
    Contained,
    Resolved,
    Closed,
}

// AuditManagerの実装
impl AuditManager {
    /// 新しい監査マネージャを作成
    pub fn new() -> Self {
        Self {
            logging_level: LoggingLevel::Important,
            event_buffer: Mutex::new(Vec::with_capacity(1000)),
            next_event_id: AtomicU64::new(1),
            event_type_configs: BTreeMap::new(),
            retention_policy: RetentionPolicy {
                default_retention_days: 90,
                high_severity_retention_days: 365,
                max_events_in_memory: 10000,
                sync_interval_seconds: 60,
                compression_enabled: true,
            },
            alert_conditions: Vec::new(),
            metrics: AuditMetrics {
                total_events: 0,
                events_by_type: BTreeMap::new(),
                events_by_severity: BTreeMap::new(),
                failed_actions: 0,
                alerts_triggered: 0,
            },
        }
    }

    /// 監査システムを初期化
    pub fn initialize(&mut self) -> Result<(), SecurityError> {
        // デフォルトのイベントタイプ設定を構成
        self.setup_default_event_type_configs();
        
        // デフォルトのアラート条件を設定
        self.setup_default_alert_conditions();
        
        // 初期化イベントを記録
        self.log_event(
            AuditEventType::SecuritySystemInitialized,
            "監査システムが初期化されました"
        )?;
        
        Ok(())
    }

    /// 監査ログレベルを設定
    pub fn set_logging_level(&mut self, level: LoggingLevel) -> Result<(), SecurityError> {
        self.logging_level = level;
        Ok(())
    }

    /// 監査イベントを記録
    pub fn log_event(
        &self,
        event_type: AuditEventType,
        details: &str,
    ) -> Result<u64, SecurityError> {
        // イベントタイプの設定を取得
        let config = self.get_event_type_config(&event_type);
        
        // 現在のログレベルに基づいてフィルタリング
        if config.minimum_level > self.logging_level {
            return Ok(0); // 記録しない
        }
        
        let event_id = self.next_event_id.fetch_add(1, Ordering::SeqCst);
        let now = 0; // 現在のタイムスタンプ
        
        // イベントを作成
        let event = AuditEvent {
            id: event_id,
            event_type,
            timestamp: now,
            source: "security_system".to_string(),
            user_id: None,
            process_id: None,
            resource: None,
            action: "システムイベント".to_string(),
            result: ActionResult::Success,
            severity: EventSeverity::Medium,
            details: details.to_string(),
            metadata: BTreeMap::new(),
            related_events: Vec::new(),
        };
        
        // イベントをバッファに追加
        let mut buffer = self.event_buffer.lock();
        buffer.push(event.clone());
        
        // バッファが最大サイズを超えた場合、古いイベントを削除
        if buffer.len() > self.retention_policy.max_events_in_memory {
            buffer.remove(0);
        }
        
        // メトリクスを更新
        self.update_metrics(&event);
        
        // アラート条件をチェック
        self.check_alert_conditions(&event);
        
        // 即時同期が必要な場合は処理
        if config.requires_immediate_sync {
            self.sync_events()?;
        }
        
        Ok(event_id)
    }

    /// 詳細な監査イベントを記録
    pub fn log_detailed_event(
        &self,
        event_type: AuditEventType,
        source: &str,
        user_id: Option<u64>,
        process_id: Option<u64>,
        resource: Option<&str>,
        action: &str,
        result: ActionResult,
        severity: EventSeverity,
        details: &str,
        metadata: Option<&BTreeMap<String, String>>,
    ) -> Result<u64, SecurityError> {
        // イベントタイプの設定を取得
        let config = self.get_event_type_config(&event_type);
        
        // 現在のログレベルに基づいてフィルタリング
        if config.minimum_level > self.logging_level {
            return Ok(0); // 記録しない
        }
        
        let event_id = self.next_event_id.fetch_add(1, Ordering::SeqCst);
        let now = 0; // 現在のタイムスタンプ
        
        // イベントを作成
        let event = AuditEvent {
            id: event_id,
            event_type,
            timestamp: now,
            source: source.to_string(),
            user_id,
            process_id,
            resource: resource.map(ToString::to_string),
            action: action.to_string(),
            result,
            severity,
            details: details.to_string(),
            metadata: metadata.cloned().unwrap_or_default(),
            related_events: Vec::new(),
        };
        
        // イベントをバッファに追加
        let mut buffer = self.event_buffer.lock();
        buffer.push(event.clone());
        
        // バッファが最大サイズを超えた場合、古いイベントを削除
        if buffer.len() > self.retention_policy.max_events_in_memory {
            buffer.remove(0);
        }
        
        // メトリクスを更新
        self.update_metrics(&event);
        
        // アラート条件をチェック
        self.check_alert_conditions(&event);
        
        // 即時同期が必要な場合は処理
        if config.requires_immediate_sync {
            self.sync_events()?;
        }
        
        Ok(event_id)
    }

    /// セキュリティインシデントを記録
    pub fn log_security_incident(&self, incident: &SecurityIncident) -> Result<(), SecurityError> {
        // インシデント関連のイベントを記録
        let event_type = match incident.incident_type {
            IncidentType::UnauthorizedAccess => AuditEventType::IntrusionDetection,
            IncidentType::AuthenticationFailure => AuditEventType::Authentication,
            IncidentType::MalwareDetection => AuditEventType::MalwareDetection,
            IncidentType::DataExfiltration => AuditEventType::AnomalyDetection,
            IncidentType::DenialOfService => AuditEventType::AnomalyDetection,
            IncidentType::EscalationOfPrivilege => AuditEventType::PrivilegeChange,
            IncidentType::IntegrityViolation => AuditEventType::IntegrityViolation,
            IncidentType::Other(_) => AuditEventType::AnomalyDetection,
        };
        
        // 重大度をマッピング
        let severity = match incident.severity {
            IncidentSeverity::Low => EventSeverity::Low,
            IncidentSeverity::Medium => EventSeverity::Medium,
            IncidentSeverity::High => EventSeverity::High,
            IncidentSeverity::Critical => EventSeverity::Critical,
        };
        
        // メタデータを構築
        let mut metadata = BTreeMap::new();
        metadata.insert("incident_id".to_string(), incident.id.to_string());
        metadata.insert("status".to_string(), format!("{:?}", incident.status));
        
        // インシデントを監査イベントとして記録
        self.log_detailed_event(
            event_type,
            "security_system",
            None,
            None,
            None,
            "セキュリティインシデント検出",
            ActionResult::Failure,
            severity,
            &incident.details,
            Some(&metadata),
        )?;
        
        // 高重大度のインシデントは即時同期を強制
        if incident.severity >= IncidentSeverity::High {
            self.sync_events()?;
        }
        
        Ok(())
    }

    /// イベントをクエリ
    pub fn query_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, SecurityError> {
        let buffer = self.event_buffer.lock();
        
        // クエリ条件に基づいてイベントをフィルタリング
        let mut results: Vec<AuditEvent> = buffer.iter()
            .filter(|event| {
                // イベントタイプフィルタ
                if let Some(types) = &query.event_types {
                    if !types.contains(&event.event_type) {
                        return false;
                    }
                }
                
                // 時間範囲フィルタ
                if let Some(start) = query.start_time {
                    if event.timestamp < start {
                        return false;
                    }
                }
                
                if let Some(end) = query.end_time {
                    if event.timestamp > end {
                        return false;
                    }
                }
                
                // 重大度フィルタ
                if let Some(min_severity) = &query.min_severity {
                    if &event.severity < min_severity {
                        return false;
                    }
                }
                
                // ユーザーIDフィルタ
                if let Some(user_ids) = &query.user_ids {
                    if let Some(user_id) = event.user_id {
                        if !user_ids.contains(&user_id) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                
                // リソースフィルタ
                if let Some(resources) = &query.resources {
                    if let Some(resource) = &event.resource {
                        if !resources.iter().any(|r| resource.contains(r)) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                
                // 結果フィルタ
                if let Some(results) = &query.results {
                    if !results.contains(&event.result) {
                        return false;
                    }
                }
                
                // テキスト検索
                if let Some(text) = &query.text_search {
                    if !event.details.contains(text) && 
                       !event.action.contains(text) && 
                       !event.source.contains(text) {
                        return false;
                    }
                }
                
                true
            })
            .cloned()
            .collect();
        
        // 最新のイベントが先に来るように並べ替え
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        // ページング処理
        if let Some(offset) = query.offset {
            if offset < results.len() {
                results = results.split_off(offset);
            } else {
                results.clear();
            }
        }
        
        if let Some(limit) = query.limit {
            if limit < results.len() {
                results.truncate(limit);
            }
        }
        
        Ok(results)
    }

    /// アラート条件を追加
    pub fn add_alert_condition(&mut self, condition: AlertCondition) -> Result<u64, SecurityError> {
        let id = condition.id;
        self.alert_conditions.push(condition);
        Ok(id)
    }

    /// イベントバッファを同期
    pub fn sync_events(&self) -> Result<(), SecurityError> {
        // イベントをディスクやネットワークに永続化
        event_store::sync_events()?;
    }

    /// 監査マネージャのステータスを取得
    pub fn status(&self) -> Result<AuditStatus, SecurityError> {
        let buffer = self.event_buffer.lock();
        
        // 最後のイベント時間を取得
        let last_event_time = buffer.last().map(|e| e.timestamp);
        
        let status = AuditStatus {
            logging_level: self.logging_level,
            events_in_buffer: buffer.len(),
            last_event_time,
            alerts_active: self.alert_conditions.iter().filter(|c| c.enabled).count(),
            total_events_processed: self.metrics.total_events,
            health_status: if buffer.len() < self.retention_policy.max_events_in_memory * 9 / 10 {
                HealthStatus::Healthy
            } else if buffer.len() < self.retention_policy.max_events_in_memory {
                HealthStatus::Degraded
            } else {
                HealthStatus::Critical
            },
        };
        
        Ok(status)
    }

    // 内部ヘルパーメソッド
    
    /// デフォルトのイベントタイプ設定を構成
    fn setup_default_event_type_configs(&mut self) {
        // セキュリティ関連イベント
        self.event_type_configs.insert(AuditEventType::Authentication, EventTypeConfig {
            enabled: true,
            minimum_level: LoggingLevel::Important,
            retention_days: 365,
            requires_immediate_sync: false,
        });
        
        self.event_type_configs.insert(AuditEventType::Authorization, EventTypeConfig {
            enabled: true,
            minimum_level: LoggingLevel::Important,
            retention_days: 365,
            requires_immediate_sync: false,
        });
        
        // アラートイベント
        self.event_type_configs.insert(AuditEventType::IntrusionDetection, EventTypeConfig {
            enabled: true,
            minimum_level: LoggingLevel::Important,
            retention_days: 365,
            requires_immediate_sync: true,
        });
        
        self.event_type_configs.insert(AuditEventType::MalwareDetection, EventTypeConfig {
            enabled: true,
            minimum_level: LoggingLevel::Important,
            retention_days: 365,
            requires_immediate_sync: true,
        });
        
        // システムイベント
        self.event_type_configs.insert(AuditEventType::SystemStartup, EventTypeConfig {
            enabled: true,
            minimum_level: LoggingLevel::Important,
            retention_days: 90,
            requires_immediate_sync: true,
        });
        
        self.event_type_configs.insert(AuditEventType::SystemShutdown, EventTypeConfig {
            enabled: true,
            minimum_level: LoggingLevel::Important,
            retention_days: 90,
            requires_immediate_sync: true,
        });
        
        // さらに多くのイベントタイプに設定を行う
        event_config::apply_default_settings()?;
    }
    
    /// デフォルトのアラート条件を設定
    fn setup_default_alert_conditions(&mut self) {
        // 複数の認証失敗のアラート
        self.alert_conditions.push(AlertCondition {
            id: 1,
            name: "Multiple Authentication Failures".to_string(),
            event_types: vec![AuditEventType::Authentication],
            minimum_severity: EventSeverity::Medium,
            pattern: None,
            threshold: Some(ThresholdCondition {
                count: 5,
                time_window_seconds: 300, // 5分
                aggregation_key: Some("user_id".to_string()),
            }),
            actions: vec![AlertAction::Log, AlertAction::Notify],
            enabled: true,
        });
        
        // 権限昇格のアラート
        self.alert_conditions.push(AlertCondition {
            id: 2,
            name: "Privilege Escalation".to_string(),
            event_types: vec![AuditEventType::PrivilegeChange],
            minimum_severity: EventSeverity::High,
            pattern: None,
            threshold: None,
            actions: vec![AlertAction::Log, AlertAction::Notify, AlertAction::TriggerResponse("investigate_escalation".to_string())],
            enabled: true,
        });
        
        // システム整合性違反のアラート
        self.alert_conditions.push(AlertCondition {
            id: 3,
            name: "System Integrity Violation".to_string(),
            event_types: vec![AuditEventType::IntegrityViolation],
            minimum_severity: EventSeverity::High,
            pattern: None,
            threshold: None,
            actions: vec![AlertAction::Log, AlertAction::Notify, AlertAction::TriggerResponse("lockdown_system".to_string())],
            enabled: true,
        });
    }
    
    /// イベントタイプ設定を取得
    fn get_event_type_config(&self, event_type: &AuditEventType) -> &EventTypeConfig {
        if let Some(config) = self.event_type_configs.get(event_type) {
            config
        } else {
            // デフォルト設定
            static DEFAULT_CONFIG: EventTypeConfig = EventTypeConfig {
                enabled: true,
                minimum_level: LoggingLevel::Detailed,
                retention_days: 90,
                requires_immediate_sync: false,
            };
            &DEFAULT_CONFIG
        }
    }
    
    /// メトリクス更新
    fn update_metrics(&self, event: &AuditEvent) {
        self.metrics.total_events += 1;
        
        // イベントタイプ別カウント
        let type_count = self.metrics.events_by_type.entry(event.event_type).or_insert(0);
        *type_count += 1;
        
        // 重大度別カウント
        let severity_count = self.metrics.events_by_severity.entry(event.severity).or_insert(0);
        *severity_count += 1;
        
        // 失敗したアクションをカウント
        if event.result == ActionResult::Failure || event.result == ActionResult::Denied {
            self.metrics.failed_actions += 1;
        }
    }
    
    /// アラート条件をチェック
    fn check_alert_conditions(&self, event: &AuditEvent) {
        for condition in self.alert_conditions.iter().filter(|c| c.enabled) {
            // イベントタイプが一致するかチェック
            if !condition.event_types.contains(&event.event_type) {
                continue;
            }
            
            // 最小重大度をチェック
            if event.severity < condition.minimum_severity {
                continue;
            }
            
            // パターンマッチングをチェック
            if let Some(pattern) = &condition.pattern {
                if !event.details.contains(pattern) {
                    continue;
                }
            }
            
            // しきい値をチェック
            if let Some(threshold) = &condition.threshold {
                // しきい値条件に基づいてイベントを集計
                event_aggregator::aggregate_by_threshold(condition)?;
            }
            
            // アラート条件が一致したのでアクションを実行
            for action in &condition.actions {
                match action {
                    AlertAction::Log => {
                        // アラートをログに記録
                    },
                    AlertAction::Notify => {
                        // 通知を送信
                    },
                    AlertAction::ExecuteCommand(cmd) => {
                        // コマンドを実行
                    },
                    AlertAction::TriggerResponse(response) => {
                        // レスポンスをトリガー
                    },
                }
            }
            
            // アラートがトリガーされたことをカウント
            self.metrics.alerts_triggered += 1;
        }
    }
}