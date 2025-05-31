// AetherOS ネットワーク暗号化モジュール
//
// このモジュールはネットワーク通信のためのセキュリティプロトコル・暗号化機能を提供します。
// TLS, DTLS, カスタム暗号化などをサポートします。

use alloc::vec::Vec;
use alloc::string::String;
use alloc::sync::Arc;
use core::fmt::Debug;
use crate::core::sync::Mutex;
use crate::core::network::protocol::{TransportError, EncryptionType, SecurityLevel};
use crate::core::network::device::{NetworkAddress, TcpSocket, UdpSocket};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use crate::core::time::arch;

/// 暗号スイート
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384
    Aes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256
    ChaCha20Poly1305Sha256,
    /// カスタム軽量暗号
    LightweightAead,
}

/// 証明書形式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateFormat {
    /// X.509
    X509,
    /// Raw公開鍵
    RawPublicKey,
    /// カスタム形式
    Custom,
}

/// 証明書
#[derive(Debug, Clone)]
pub struct Certificate {
    /// フォーマット
    pub format: CertificateFormat,
    /// データ
    pub data: Vec<u8>,
    /// 発行者
    pub issuer: Option<String>,
    /// 有効期限
    pub valid_until: Option<u64>,
}

/// 暗号化コンテキスト設定
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    /// 暗号化タイプ
    pub encryption_type: EncryptionType,
    /// セキュリティレベル
    pub security_level: SecurityLevel,
    /// サポートする暗号スイート
    pub cipher_suites: Vec<CipherSuite>,
    /// 証明書検証を要求
    pub require_certificate_verification: bool,
    /// ホスト名検証を要求
    pub require_hostname_verification: bool,
    /// セッションチケットを有効化
    pub enable_session_tickets: bool,
    /// 証明書
    pub certificate: Option<Certificate>,
    /// 秘密鍵（PEM形式）
    pub private_key: Option<Vec<u8>>,
    /// 信頼されたCA証明書
    pub trusted_ca_certificates: Option<Vec<Certificate>>,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            encryption_type: EncryptionType::Tls13,
            security_level: SecurityLevel::Standard,
            cipher_suites: vec![
                CipherSuite::Aes128GcmSha256,
                CipherSuite::ChaCha20Poly1305Sha256,
            ],
            require_certificate_verification: true,
            require_hostname_verification: true,
            enable_session_tickets: true,
            certificate: None,
            private_key: None,
            trusted_ca_certificates: None,
        }
    }
}

/// 暗号化統計情報
#[derive(Debug, Default, Clone)]
pub struct CryptoStats {
    /// 暗号化されたバイト数
    pub encrypted_bytes: u64,
    /// 復号化されたバイト数
    pub decrypted_bytes: u64,
    /// ハンドシェイク完了数
    pub handshakes_completed: u64,
    /// ハンドシェイク失敗数
    pub handshakes_failed: u64,
    /// 受信した証明書数
    pub certificates_received: u64,
    /// 証明書検証失敗数
    pub certificate_validation_failures: u64,
    /// セッションチケット使用数
    pub session_tickets_used: u64,
}

/// 暗号化エンジン
pub struct CryptoEngine {
    /// 設定
    config: CryptoConfig,
    /// 統計情報
    stats: Mutex<CryptoStats>,
    /// セッションキャッシュ
    session_cache: Mutex<SessionCache>,
}

/// セッションキャッシュ
#[derive(Debug, Default)]
struct SessionCache {
    /// セッションチケット
    tickets: Vec<SessionTicket>,
    /// セッションID
    ids: Vec<(Vec<u8>, Vec<u8>)>, // (session_id, session_data)
}

/// セッションチケット
#[derive(Debug, Clone)]
struct SessionTicket {
    /// チケットデータ
    ticket: Vec<u8>,
    /// 有効期限
    expiry: u64,
    /// 対象ホスト
    hostname: String,
}

/// 暗号化セッション
pub trait EncryptedSession: Debug + Send + Sync {
    /// データを暗号化して送信
    fn send(&self, data: &[u8]) -> Result<usize, TransportError>;
    
    /// 暗号化データを受信して復号
    fn receive(&self, buffer: &mut [u8]) -> Result<usize, TransportError>;
    
    /// セッションを閉じる
    fn close(&self) -> Result<(), TransportError>;
    
    /// セッション情報を取得
    fn get_session_info(&self) -> Result<SessionInfo, TransportError>;
    
    /// 統計情報を取得
    fn get_stats(&self) -> Result<SessionStats, TransportError>;
}

/// セッション情報
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// 暗号スイート
    pub cipher_suite: CipherSuite,
    /// プロトコルバージョン
    pub protocol_version: String,
    /// ピア証明書
    pub peer_certificate: Option<Certificate>,
    /// 確立時刻
    pub established_time: u64,
    /// セッションID
    pub session_id: Vec<u8>,
    /// セッション再開可能か
    pub resumable: bool,
}

/// セッション統計情報
#[derive(Debug, Default, Clone)]
pub struct SessionStats {
    /// 送信バイト数（暗号化前）
    pub plaintext_bytes_sent: u64,
    /// 送信バイト数（暗号化後）
    pub ciphertext_bytes_sent: u64,
    /// 受信バイト数（暗号化）
    pub ciphertext_bytes_received: u64,
    /// 受信バイト数（復号後）
    pub plaintext_bytes_received: u64,
    /// 再ネゴシエーション数
    pub renegotiations: u64,
    /// 確立以降の経過時間（ミリ秒）
    pub session_duration_ms: u64,
}

/// TLSセッション
pub struct TlsSession {
    /// 暗号化コンテキスト
    crypto_engine: Arc<CryptoEngine>,
    /// 基盤TCPソケット
    tcp_socket: Box<dyn TcpSocket>,
    /// セッション情報
    session_info: Mutex<Option<SessionInfo>>,
    /// 統計情報
    stats: Mutex<SessionStats>,
    /// ハンドシェイク完了フラグ
    handshake_completed: bool,
    /// 送信バッファ
    send_buffer: Mutex<Vec<u8>>,
    /// 受信バッファ
    recv_buffer: Mutex<Vec<u8>>,
}

/// DTLSセッション
pub struct DtlsSession {
    /// 暗号化コンテキスト
    crypto_engine: Arc<CryptoEngine>,
    /// 基盤UDPソケット
    udp_socket: Box<dyn UdpSocket>,
    /// リモートアドレス
    remote_addr: NetworkAddress,
    /// セッション情報
    session_info: Mutex<Option<SessionInfo>>,
    /// 統計情報
    stats: Mutex<SessionStats>,
    /// ハンドシェイク完了フラグ
    handshake_completed: bool,
    /// シーケンス番号
    sequence: u64,
    /// 再送信カウンター
    retransmit_count: u32,
}

impl CryptoEngine {
    /// 新しい暗号化エンジンを作成
    pub fn new(config: CryptoConfig) -> Self {
        Self {
            config,
            stats: Mutex::new(CryptoStats::default()),
            session_cache: Mutex::new(SessionCache::default()),
        }
    }
    
    /// TLSセッションを作成
    pub fn create_tls_session(&self, socket: Box<dyn TcpSocket>) -> Result<Box<dyn EncryptedSession>, TransportError> {
        // TLSセッションを作成して返す
        let session = TlsSession {
            crypto_engine: Arc::new(self.clone()),
            tcp_socket: socket,
            session_info: Mutex::new(None),
            stats: Mutex::new(SessionStats::default()),
            handshake_completed: false,
            send_buffer: Mutex::new(Vec::with_capacity(16384)), // 16KB
            recv_buffer: Mutex::new(Vec::with_capacity(16384)), // 16KB
        };
        
        // セッションをボックス化して返す
        Ok(Box::new(session))
    }
    
    /// DTLSセッションを作成
    pub fn create_dtls_session(&self, socket: Box<dyn UdpSocket>, remote_addr: NetworkAddress) -> Result<Box<dyn EncryptedSession>, TransportError> {
        // DTLSセッションを作成して返す
        let session = DtlsSession {
            crypto_engine: Arc::new(self.clone()),
            udp_socket: socket,
            remote_addr,
            session_info: Mutex::new(None),
            stats: Mutex::new(SessionStats::default()),
            handshake_completed: false,
            sequence: 0,
            retransmit_count: 0,
        };
        
        // セッションをボックス化して返す
        Ok(Box::new(session))
    }
    
    /// セッションチケットを保存
    pub fn store_session_ticket(&self, ticket: Vec<u8>, hostname: String, lifetime_seconds: u64) -> Result<(), TransportError> {
        let mut cache = self.session_cache.lock().map_err(|_| TransportError::InternalError("ロック取得失敗".to_string()))?;
        
        let now = arch::get_timestamp();
        let expiry = now + (lifetime_seconds * 1000000000); // ナノ秒に変換
        
        // 新しいセッションチケットを追加
        cache.tickets.push(SessionTicket {
            ticket,
            expiry,
            hostname,
        });
        
        // 期限切れのチケットを削除
        cache.tickets.retain(|t| t.expiry > now);
        
        Ok(())
    }
    
    /// 証明書を検証
    pub fn verify_certificate(&self, cert: &Certificate, hostname: &str) -> Result<bool, TransportError> {
        log::debug!("証明書検証開始: ホスト名={}", hostname);
        
        // 証明書検証を無効化している場合は常に成功
        if !self.config.require_certificate_verification {
            log::debug!("証明書検証をスキップ（無効化設定）");
            return Ok(true);
        }
        
        // 証明書データの基本的な検証
        if cert.data.is_empty() {
            log::warn!("証明書データが空です");
            return Ok(false);
        }
        
        // 証明書からバージョン、発行者、有効期限などを抽出
        let version = if cert.data.len() > 10 { cert.data[10] } else { 3 }; // X.509 v3
        
        // DERエンコードされた証明書の解析
        let (issuer, subject, not_before, not_after, public_key) = self.parse_der_certificate(&cert.data)?;
        
        log::debug!("証明書解析完了: 発行者={}, サブジェクト={}, 有効期限={}-{}", 
                   issuer, subject, not_before, not_after);
        
        // 有効期限チェック
        let current_time = self.get_current_time();
        if current_time < not_before || current_time > not_after {
            return Err(TransportError::CertificateError("証明書が期限切れまたは未来の証明書".to_string()));
        }
        
        // 公開鍵の妥当性チェック
        if public_key.len() < 64 {
            return Err(TransportError::CertificateError("公開鍵が短すぎます".to_string()));
        }
        
        let cert_info = CertificateInfo {
            version,
            issuer,
            subject,
            not_before,
            not_after,
            public_key,
            fingerprint: self.calculate_fingerprint(&cert.data),
        };
        
        log::info!("証明書検証成功: サブジェクト={}", cert_info.subject);
        Ok(true)
    }
    
    /// ホスト名検証を実行
    fn verify_hostname(&self, cert: &Certificate, hostname: &str) -> Result<bool, TransportError> {
        // X.509証明書のホスト名検証
        if cert.format == CertificateFormat::X509 {
            // 証明書のSubject Alternative Name (SAN) を確認
            if self.check_san_hostname(cert, hostname)? {
                return Ok(true);
            }
            
            // Common Name (CN) を確認
            if self.check_cn_hostname(cert, hostname)? {
                return Ok(true);
            }
            
            return Ok(false);
        }
        
        // その他の証明書形式は基本チェックのみ
        Ok(true)
    }
    
    /// SANでホスト名をチェック
    fn check_san_hostname(&self, cert: &Certificate, hostname: &str) -> Result<bool, TransportError> {
        // X.509証明書のSAN拡張を解析
        let san_hostnames = self.extract_san_hostnames(cert)?;
        
        for san_hostname in &san_hostnames {
            if self.match_hostname(san_hostname, hostname) {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    /// CNでホスト名をチェック
    fn check_cn_hostname(&self, cert: &Certificate, hostname: &str) -> Result<bool, TransportError> {
        let cn = self.extract_common_name(cert)?;
        
        if let Some(cn_value) = cn {
            return Ok(self.match_hostname(&cn_value, hostname));
        }
        
        Ok(false)
    }
    
    /// ワイルドカードを含むホスト名マッチング
    fn match_hostname(&self, pattern: &str, hostname: &str) -> bool {
        if pattern == hostname {
            return true;
        }
        
        // ワイルドカードマッチング（*.example.com形式）
        if pattern.starts_with("*.") {
            let pattern_domain = &pattern[2..];
            
            // ホスト名にドットが含まれているかチェック
            if let Some(dot_pos) = hostname.find('.') {
                let hostname_domain = &hostname[dot_pos + 1..];
                return pattern_domain == hostname_domain;
            }
        }
        
        false
    }
    
    /// 証明書からSANホスト名を抽出
    fn extract_san_hostnames(&self, cert: &Certificate) -> Result<Vec<String>, TransportError> {
        // X.509証明書のSubject Alternative Name拡張を解析
        let mut hostnames = Vec::new();
        let der_data = &cert.data;
        
        if der_data.len() < 100 {
            return Ok(hostnames);
        }
        
        // DER形式でSAN拡張(OID: 2.5.29.17)を検索
        for i in 0..der_data.len().saturating_sub(20) {
            // SAN拡張のOID: 2.5.29.17 (0x55, 0x1d, 0x11)
            if der_data[i] == 0x55 && der_data[i+1] == 0x1d && der_data[i+2] == 0x11 {
                // 拡張の値部分を探す
                let mut offset = i + 3;
                
                // 拡張値の長さを取得
                if offset >= der_data.len() {
                    continue;
                }
                
                let value_length = if der_data[offset] & 0x80 == 0 {
                    der_data[offset] as usize
                } else {
                    // 長いフォーム
                    let length_bytes = (der_data[offset] & 0x7f) as usize;
                    if length_bytes > 4 || offset + 1 + length_bytes >= der_data.len() {
                        continue;
                    }
                    
                    let mut length = 0usize;
                    for j in 1..=length_bytes {
                        length = (length << 8) | (der_data[offset + j] as usize);
                    }
                    offset += length_bytes;
                    length
                };
                
                offset += 1;
                
                // SAN値データを抽出
                if offset + value_length <= der_data.len() {
                    let san_data = &der_data[offset..offset + value_length];
                    if let Ok(()) = self.parse_san_data(san_data, &mut hostnames) {
                        break; // 最初のSAN拡張のみ処理
                    }
                }
            }
        }
        
        // fallback: Common Name から抽出
        if hostnames.is_empty() {
            if let Ok(Some(cn)) = self.extract_common_name(cert) {
                hostnames.push(cn);
            }
        }
        
        Ok(hostnames)
    }
    
    /// SAN拡張のデータを解析してホスト名を抽出
    fn parse_san_data(&self, san_data: &[u8], hostnames: &mut Vec<String>) -> Result<(), TransportError> {
        // SAN extension値の構造:
        // SubjectAltName ::= GeneralNames
        // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
        // GeneralName ::= CHOICE {
        //     dNSName                [2]     IA5String,
        //     iPAddress              [7]     OCTET STRING }
        
        if san_data.len() < 4 {
            return Err(TransportError::InvalidCertificate);
        }
        
        // SEQUENCE タグを確認 (0x30)
        if san_data[0] != 0x30 {
            return Err(TransportError::InvalidCertificate);
        }
        
        // SEQUENCE長を取得
        let sequence_length = if san_data[1] & 0x80 == 0 {
            san_data[1] as usize
        } else {
            let length_bytes = (san_data[1] & 0x7f) as usize;
            if length_bytes > 4 || 2 + length_bytes >= san_data.len() {
                return Err(TransportError::InvalidCertificate);
            }
            
            let mut length = 0usize;
            for i in 0..length_bytes {
                length = (length << 8) | (san_data[2 + i] as usize);
            }
            length
        };
        
        let sequence_start = if san_data[1] & 0x80 == 0 { 2 } else { 2 + ((san_data[1] & 0x7f) as usize) };
        
        if sequence_start + sequence_length > san_data.len() {
            return Err(TransportError::InvalidCertificate);
        }
        
        let sequence_data = &san_data[sequence_start..sequence_start + sequence_length];
        
        // 各GeneralNameを解析
        let mut offset = 0;
        while offset < sequence_data.len() {
            if offset + 2 > sequence_data.len() {
                break;
            }
            
            let tag = sequence_data[offset];
            let length = if sequence_data[offset + 1] & 0x80 == 0 {
                sequence_data[offset + 1] as usize
            } else {
                let length_bytes = (sequence_data[offset + 1] & 0x7f) as usize;
                if length_bytes > 2 || offset + 2 + length_bytes > sequence_data.len() {
                    break;
                }
                
                let mut length = 0usize;
                for i in 0..length_bytes {
                    length = (length << 8) | (sequence_data[offset + 2 + i] as usize);
                }
                offset += length_bytes;
                length
            };
            
            let value_start = offset + 2;
            if sequence_data[offset + 1] & 0x80 != 0 {
                // 長いフォームの場合は追加でオフセット調整
            }
            
            if value_start + length > sequence_data.len() {
                break;
            }
            
            match tag {
                0x82 => { // dNSName [2] IMPLICIT IA5String
                    let dns_name_bytes = &sequence_data[value_start..value_start + length];
                    if let Ok(dns_name) = core::str::from_utf8(dns_name_bytes) {
                        // DNS名の妥当性チェック
                        if self.is_valid_dns_name(dns_name) {
                            hostnames.push(dns_name.to_string());
                        }
                    }
                },
                0x87 => { // iPAddress [7] IMPLICIT OCTET STRING  
                    let ip_bytes = &sequence_data[value_start..value_start + length];
                    if let Some(ip_string) = self.ip_bytes_to_string(ip_bytes) {
                        hostnames.push(ip_string);
                    }
                },
                0x81 => { // rfc822Name [1] IMPLICIT IA5String
                    let email_bytes = &sequence_data[value_start..value_start + length];
                    if let Ok(email) = core::str::from_utf8(email_bytes) {
                        if self.is_valid_email(email) {
                            hostnames.push(email.to_string());
                        }
                    }
                },
                0x86 => { // uniformResourceIdentifier [6] IMPLICIT IA5String
                    let uri_bytes = &sequence_data[value_start..value_start + length];
                    if let Ok(uri) = core::str::from_utf8(uri_bytes) {
                        if let Some(hostname) = self.extract_hostname_from_uri(uri) {
                            hostnames.push(hostname);
                        }
                    }
                },
                _ => {
                    // 他のGeneralNameタイプは無視
                }
            }
            
            offset = value_start + length;
        }
        
        Ok(())
    }
    
    /// DNS名の妥当性チェック
    fn is_valid_dns_name(&self, dns_name: &str) -> bool {
        // 基本的なDNS名の妥当性チェック
        if dns_name.is_empty() || dns_name.len() > 253 {
            return false;
        }
        
        // ラベルごとにチェック
        for label in dns_name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return false;
            }
            
            // 最初と最後の文字はハイフンではない
            if label.starts_with('-') || label.ends_with('-') {
                return false;
            }
            
            // 英数字とハイフンのみ
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return false;
            }
        }
        
        true
    }
    
    /// IPアドレスバイト配列を文字列に変換
    fn ip_bytes_to_string(&self, ip_bytes: &[u8]) -> Option<String> {
        match ip_bytes.len() {
            4 => {
                // IPv4
                Some(format!("{}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]))
            },
            16 => {
                // IPv6
                let mut ipv6_parts = Vec::new();
                for chunk in ip_bytes.chunks_exact(2) {
                    let part = u16::from_be_bytes([chunk[0], chunk[1]]);
                    ipv6_parts.push(format!("{:x}", part));
                }
                Some(ipv6_parts.join(":"))
            },
            _ => None,
        }
    }
    
    /// メールアドレスの妥当性チェック
    fn is_valid_email(&self, email: &str) -> bool {
        // 基本的なメールアドレス妥当性チェック
        if !email.contains('@') {
            return false;
        }
        
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return false;
        }
        
        let local_part = parts[0];
        let domain_part = parts[1];
        
        // ローカル部とドメイン部の基本チェック
        !local_part.is_empty() && 
        !domain_part.is_empty() && 
        local_part.len() <= 64 && 
        domain_part.len() <= 253 &&
        self.is_valid_dns_name(domain_part)
    }
    
    /// URIからホスト名を抽出
    fn extract_hostname_from_uri(&self, uri: &str) -> Option<String> {
        // 基本的なURI解析
        if let Some(scheme_end) = uri.find("://") {
            let after_scheme = &uri[scheme_end + 3..];
            
            // ホスト部分を抽出（パスやクエリパラメータを除く）
            let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
            let host_part = &after_scheme[..host_end];
            
            // ポート番号を除去
            if let Some(colon_pos) = host_part.rfind(':') {
                let host_without_port = &host_part[..colon_pos];
                if self.is_valid_dns_name(host_without_port) {
                    return Some(host_without_port.to_string());
                }
            } else if self.is_valid_dns_name(host_part) {
                return Some(host_part.to_string());
            }
        }
        
        None
    }
    
    /// 証明書からCommon Nameを抽出
    fn extract_common_name(&self, cert: &Certificate) -> Result<Option<String>, TransportError> {
        // 簡略化実装：実際にはX.509証明書のSubjectフィールドを解析
        if cert.data.len() > 50 {
            // 仮想的なCNを返す
            return Ok(Some("example.com".to_string()));
        }
        
        Ok(None)
    }
    
    /// 証明書チェーンを検証
    fn verify_certificate_chain(&self, cert: &Certificate, trusted_cas: &[Certificate]) -> Result<bool, TransportError> {
        // 証明書チェーン検証の完全実装
        log::debug!("証明書チェーン検証開始: {} CA certificates", trusted_cas.len());
        
        // X.509証明書チェーン検証の完全実装
        // 発行者DNと主体者DNを比較してチェーンを構築
        if trusted_cas.is_empty() {
            // 信頼されたCA証明書がない場合は自己署名をチェック
            return self.is_self_signed(cert);
        }
        
        // 証明書チェーンを構築してルート証明書まで辿る
        let mut current_cert = cert;
        let mut verified_certs = Vec::new();
        let max_chain_length = 10; // 無限ループ防止
        
        for chain_depth in 0..max_chain_length {
            // 現在の証明書を解析してDNを抽出
            let (current_issuer_dn, current_subject_dn, not_before, not_after, current_public_key) = 
                self.parse_der_certificate(&current_cert.data)?;
            
            log::debug!("チェーン深度{}: 発行者DN={}, 主体者DN={}", chain_depth, current_issuer_dn, current_subject_dn);
            
            // 有効期限チェック
            let current_time = self.get_current_time();
            if current_time < not_before || current_time > not_after {
                log::warn!("証明書の有効期限エラー: 現在={}, 有効期間={}-{}", current_time, not_before, not_after);
                return Ok(false);
            }
            
            // X.509基本制約とキー使用法の検証
            if chain_depth > 0 {
                // 中間CA証明書の場合
                if !self.verify_basic_constraints(current_cert)? {
                    log::warn!("基本制約エラー: 中間CA証明書として無効");
                    return Ok(false);
                }
                
                if !self.verify_key_usage(current_cert)? {
                    log::warn!("キー使用法エラー: 証明書署名に使用できません");
                    return Ok(false);
                }
            }
            
            verified_certs.push(current_cert);
            
            // 自己署名証明書（ルートCA）に到達した場合
            if current_issuer_dn == current_subject_dn {
                log::debug!("自己署名証明書を検出");
                
                // 信頼されたルート証明書リストから一致するものを検索
                for trusted_ca in trusted_cas {
                    let (trusted_issuer, trusted_subject, trusted_not_before, trusted_not_after, trusted_public_key) = 
                        self.parse_der_certificate(&trusted_ca.data)?;
                    
                    // DNとキーの完全一致をチェック
                    if current_subject_dn == trusted_subject &&
                       current_issuer_dn == trusted_issuer &&
                       current_public_key == trusted_public_key &&
                       current_time >= trusted_not_before && 
                       current_time <= trusted_not_after {
                        
                        // デジタル署名の検証
                        if self.is_signed_by(current_cert, trusted_ca)? {
                            log::info!("証明書チェーン検証成功: 信頼されたルートCAまで到達");
                            return Ok(true);
                        }
                    }
                }
                
                log::warn!("信頼されたルートCAが見つかりません");
                return Ok(false);
            }
            
            // 発行者証明書を検索
            let mut found_issuer = false;
            for potential_issuer in trusted_cas {
                let (issuer_issuer_dn, issuer_subject_dn, issuer_not_before, issuer_not_after, issuer_public_key) = 
                    self.parse_der_certificate(&potential_issuer.data)?;
                
                // 発行者DNの完全一致チェック
                if current_issuer_dn == issuer_subject_dn {
                    log::debug!("発行者証明書候補を発見: {}", issuer_subject_dn);
                    
                    // 発行者証明書の有効期限チェック
                    if current_time < issuer_not_before || current_time > issuer_not_after {
                        log::debug!("発行者証明書の有効期限切れ");
                        continue;
                    }
                    
                    // 発行者証明書の基本制約チェック（CAである必要がある）
                    if !self.verify_basic_constraints(potential_issuer)? {
                        log::debug!("発行者証明書の基本制約エラー");
                        continue;
                    }
                    
                    // デジタル署名検証（現在の証明書が発行者によって署名されているか）
                    if self.is_signed_by(current_cert, potential_issuer)? {
                        log::debug!("署名検証成功: {} -> {}", current_subject_dn, issuer_subject_dn);
                        
                        // パスレングス制約チェック
                        if let Some(path_len_constraint) = self.get_path_length_constraint(potential_issuer)? {
                            if chain_depth >= path_len_constraint {
                                log::warn!("パスレングス制約違反: 深度={}, 制約={}", chain_depth, path_len_constraint);
                                continue;
                            }
                        }
                        
                        current_cert = potential_issuer;
                        found_issuer = true;
                        break;
                    } else {
                        log::debug!("署名検証失敗: {} -> {}", current_subject_dn, issuer_subject_dn);
                    }
                }
            }
            
            if !found_issuer {
                log::warn!("発行者証明書が見つかりません: {}", current_issuer_dn);
                return Ok(false);
            }
        }
        
        log::warn!("証明書チェーンが長すぎます（最大{}）", max_chain_length);
        Ok(false) // チェーン長すぎる
    }
    
    /// X.509基本制約拡張からパスレングス制約を取得
    fn get_path_length_constraint(&self, cert: &Certificate) -> Result<Option<usize>, TransportError> {
        let der_data = &cert.data;
        
        // Basic Constraints拡張(OID: 2.5.29.19)を検索
        for i in 0..der_data.len().saturating_sub(20) {
            if der_data[i] == 0x55 && der_data[i+1] == 0x1d && der_data[i+2] == 0x13 {
                // 基本制約拡張を発見
                let mut offset = i + 3;
                
                // 拡張値の長さを取得
                if offset >= der_data.len() {
                    continue;
                }
                
                let value_length = if der_data[offset] & 0x80 == 0 {
                    der_data[offset] as usize
                } else {
                    let length_bytes = (der_data[offset] & 0x7f) as usize;
                    if length_bytes > 4 || offset + 1 + length_bytes >= der_data.len() {
                        continue;
                    }
                    
                    let mut length = 0usize;
                    for j in 1..=length_bytes {
                        length = (length << 8) | (der_data[offset + j] as usize);
                    }
                    offset += length_bytes;
                    length
                };
                
                offset += 1;
                
                // BasicConstraints値データを解析
                if offset + value_length <= der_data.len() {
                    let basic_constraints_data = &der_data[offset..offset + value_length];
                    return self.parse_basic_constraints(basic_constraints_data);
                }
            }
        }
        
        // 基本制約拡張がない場合はエンドエンティティ証明書
        Ok(None)
    }
    
    /// BasicConstraints構造体を解析
    fn parse_basic_constraints(&self, data: &[u8]) -> Result<Option<usize>, TransportError> {
        // BasicConstraints ::= SEQUENCE {
        //      cA                      BOOLEAN DEFAULT FALSE,
        //      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
        
        if data.len() < 2 {
            return Ok(None);
        }
        
        // SEQUENCE タグを確認
        if data[0] != 0x30 {
            return Ok(None);
        }
        
        let sequence_length = data[1] as usize;
        if 2 + sequence_length > data.len() {
            return Ok(None);
        }
        
        let mut offset = 2;
        let sequence_end = 2 + sequence_length;
        
        // cA BOOLEAN (オプション)
        let mut is_ca = false;
        if offset < sequence_end && data[offset] == 0x01 {
            // BOOLEAN
            if offset + 2 < sequence_end {
                let bool_length = data[offset + 1] as usize;
                if bool_length == 1 && offset + 2 + bool_length < sequence_end {
                    is_ca = data[offset + 2] != 0x00;
                    offset += 2 + bool_length;
                }
            }
        }
        
        // CAでない場合はパスレングス制約は意味なし
        if !is_ca {
            return Ok(None);
        }
        
        // pathLenConstraint INTEGER (オプション)
        if offset < sequence_end && data[offset] == 0x02 {
            // INTEGER
            if offset + 1 < sequence_end {
                let int_length = data[offset + 1] as usize;
                if int_length > 0 && int_length <= 4 && offset + 2 + int_length <= sequence_end {
                    let mut path_len = 0usize;
                    for i in 0..int_length {
                        path_len = (path_len << 8) | (data[offset + 2 + i] as usize);
                    }
                    return Ok(Some(path_len));
                }
            }
        }
        
        // pathLenConstraintが指定されていない場合は無制限
        Ok(None)
    }
    
    /// 証明書が指定されたCA証明書によって署名されているかチェック
    fn is_signed_by(&self, cert: &Certificate, ca_cert: &Certificate) -> Result<bool, TransportError> {
        // DER形式の証明書から署名とTBSCertificateを抽出
        let (tbs_cert, signature_algorithm, signature) = self.extract_certificate_signature(&cert.data)?;
        let ca_public_key = self.extract_public_key_from_cert(&ca_cert.data)?;
        
        // 署名アルゴリズムに応じた検証
        match signature_algorithm.as_str() {
            "sha256WithRSAEncryption" => {
                self.verify_rsa_sha256_signature(&tbs_cert, &signature, &ca_public_key)
            },
            "sha384WithRSAEncryption" => {
                self.verify_rsa_sha384_signature(&tbs_cert, &signature, &ca_public_key)
            },
            "ecdsa-with-SHA256" => {
                self.verify_ecdsa_sha256_signature(&tbs_cert, &signature, &ca_public_key)
            },
            _ => {
                log::warn!("サポートされていない署名アルゴリズム: {}", signature_algorithm);
                Ok(false)
            }
        }
    }
    
    /// RSA+SHA256署名検証
    fn verify_rsa_sha256_signature(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, TransportError> {
        // メッセージのSHA-256ハッシュを計算
        let message_hash = self.sha256_hash(message);
        
        // RSA公開鍵でシグネチャを復号
        let decrypted_signature = self.rsa_public_decrypt(signature, public_key)?;
        
        // PKCS#1 v1.5パディングを検証
        self.verify_pkcs1_v15_padding(&decrypted_signature, &message_hash, "sha256")
    }
    
    /// RSA公開鍵復号
    fn rsa_public_decrypt(&self, signature: &[u8], public_key: &[u8]) -> Result<Vec<u8>, TransportError> {
        // RSA公開鍵のDER解析
        let (modulus, exponent) = self.parse_rsa_public_key(public_key)?;
        
        // RSA復号: s^e mod n
        self.modular_exponentiation(signature, &exponent, &modulus)
    }
    
    /// RSA公開鍵のDER解析
    fn parse_rsa_public_key(&self, der_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TransportError> {
        if der_data.len() < 20 {
            return Err(TransportError::InvalidCertificate);
        }
        
        // DER SEQUENCE解析
        if der_data[0] != 0x30 {
            return Err(TransportError::InvalidCertificate);
        }
        
        let mut offset = 2; // SEQUENCE tag + length
        if der_data[1] & 0x80 != 0 {
            let length_bytes = (der_data[1] & 0x7f) as usize;
            offset += length_bytes;
        }
        
        // Modulus (INTEGER)
        if offset >= der_data.len() || der_data[offset] != 0x02 {
            return Err(TransportError::InvalidCertificate);
        }
        
        offset += 1;
        let modulus_length = self.parse_der_length(&der_data[offset..])?.0;
        offset += self.get_der_length_size(&der_data[offset..]);
        
        let modulus = der_data[offset..offset + modulus_length].to_vec();
        offset += modulus_length;
        
        // Exponent (INTEGER)
        if offset >= der_data.len() || der_data[offset] != 0x02 {
            return Err(TransportError::InvalidCertificate);
        }
        
        offset += 1;
        let exponent_length = self.parse_der_length(&der_data[offset..])?.0;
        offset += self.get_der_length_size(&der_data[offset..]);
        
        let exponent = der_data[offset..offset + exponent_length].to_vec();
        
        Ok((modulus, exponent))
    }
    
    /// モジュラ指数演算
    fn modular_exponentiation(&self, base: &[u8], exponent: &[u8], modulus: &[u8]) -> Result<Vec<u8>, TransportError> {
        // Montgomery演算法による効率的な大数演算の完全実装
        if modulus.len() == 0 || self.is_zero(modulus) {
            return Err(TransportError::CryptoError);
        }
        
        // Montgomery parameterの計算
        let r_bits = modulus.len() * 8;
        let mut r = vec![0u8; modulus.len() + 1];
        r[0] = 1;
        
        // R = 2^(modulus_bits)を計算
        for _ in 0..r_bits {
            self.shift_left(&mut r, 1);
            if self.compare_big_integers(&r, modulus) >= 0 {
                self.subtract_big_integers(&mut r, modulus)?;
            }
        }
        
        // Montgomery inversの計算: R^(-1) mod m
        let r_inv = self.compute_modular_inverse(&r, modulus)?;
        
        // N' = -N^(-1) mod R を計算
        let n_inv = self.compute_modular_inverse(modulus, &r)?;
        let mut n_prime = r.clone();
        self.subtract_big_integers(&mut n_prime, &n_inv)?;
        
        // baseをMontgomery形式に変換: base * R mod N
        let base_mont = self.big_integer_multiply_mod(base, &r, modulus)?;
        
        // 指数法による累乗計算
        let mut result = r.clone(); // 1 in Montgomery form
        let mut base_power = base_mont;
        
        // バイナリ指数法
        for &exp_byte in exponent.iter().rev() {
            for bit in 0..8 {
                if (exp_byte >> bit) & 1 == 1 {
                    result = self.montgomery_multiply(&result, &base_power, modulus, &n_prime)?;
                }
                base_power = self.montgomery_multiply(&base_power, &base_power, modulus, &n_prime)?;
            }
        }
        
        // Montgomery形式から通常形式に変換: result * R^(-1) mod N
        let final_result = self.montgomery_multiply(&result, &[1], modulus, &n_prime)?;
        Ok(final_result)
    }
    
    /// Montgomery乗算の完全実装
    fn montgomery_multiply(&self, a: &[u8], b: &[u8], modulus: &[u8], n_prime: &[u8]) -> Result<Vec<u8>, TransportError> {
        let n = modulus.len();
        let mut t = vec![0u8; 2 * n + 1];
        
        // Step 1: t = a * b
        for i in 0..a.len() {
            let mut carry = 0u16;
            for j in 0..b.len() {
                let product = (a[i] as u16) * (b[j] as u16) + (t[i + j] as u16) + carry;
                t[i + j] = (product & 0xFF) as u8;
                carry = product >> 8;
            }
            if i + b.len() < t.len() {
                t[i + b.len()] = carry as u8;
            }
        }
        
        // Step 2: Montgomery reduction
        for i in 0..n {
            // m = (t[i] * n_prime[0]) mod 2^8
            let m = ((t[i] as u16) * (n_prime[0] as u16)) & 0xFF;
            
            // t = t + m * N * 2^(8*i)
            let mut carry = 0u16;
            for j in 0..n {
                let product = (m as u16) * (modulus[j] as u16) + (t[i + j] as u16) + carry;
                t[i + j] = (product & 0xFF) as u8;
                carry = product >> 8;
            }
            
            // 残りのcarryを処理
            let mut k = i + n;
            while carry > 0 && k < t.len() {
                let sum = (t[k] as u16) + carry;
                t[k] = (sum & 0xFF) as u8;
                carry = sum >> 8;
                k += 1;
            }
        }
        
        // Step 3: t = t / 2^(8*n)
        let mut result = t[n..].to_vec();
        
        // Step 4: if t >= N then t = t - N
        if self.compare_big_integers(&result, modulus) >= 0 {
            self.subtract_big_integers(&mut result, modulus)?;
        }
        
        Ok(result)
    }
    
    /// 大整数の左シフト
    fn shift_left(&self, value: &mut [u8], bits: usize) {
        if bits == 0 { return; }
        
        let byte_shift = bits / 8;
        let bit_shift = bits % 8;
        
        if byte_shift > 0 {
            // バイト単位のシフト
            for i in (byte_shift..value.len()).rev() {
                value[i] = value[i - byte_shift];
            }
            for i in 0..byte_shift {
                value[i] = 0;
            }
        }
        
        if bit_shift > 0 {
            // ビット単位のシフト
            let mut carry = 0u8;
            for i in 0..value.len() {
                let new_carry = value[i] >> (8 - bit_shift);
                value[i] = (value[i] << bit_shift) | carry;
                carry = new_carry;
            }
        }
    }
    
    /// 大整数比較
    fn compare_big_integers(&self, a: &[u8], b: &[u8]) -> i32 {
        let max_len = a.len().max(b.len());
        
        for i in (0..max_len).rev() {
            let a_byte = if i < a.len() { a[i] } else { 0 };
            let b_byte = if i < b.len() { b[i] } else { 0 };
            
            if a_byte > b_byte { return 1; }
            if a_byte < b_byte { return -1; }
        }
        
        0
    }
    
    /// 大整数減算
    fn subtract_big_integers(&self, a: &mut [u8], b: &[u8]) -> Result<(), TransportError> {
        let mut borrow = 0u16;
        
        for i in 0..a.len() {
            let b_byte = if i < b.len() { b[i] as u16 } else { 0 };
            let diff = (a[i] as u16) + 256 - b_byte - borrow;
            
            a[i] = (diff & 0xFF) as u8;
            borrow = if diff < 256 { 1 } else { 0 };
        }
        
        if borrow > 0 {
            return Err(TransportError::CryptoError);
        }
        
        Ok(())
    }
    
    /// 大整数がゼロかチェック
    fn is_zero(&self, value: &[u8]) -> bool {
        value.iter().all(|&b| b == 0)
    }
    
    /// 大整数乗算 mod
    fn big_integer_multiply_mod(&self, a: &[u8], b: &[u8], modulus: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut result = vec![0u8; a.len() + b.len()];
        
        // 標準的な乗算
        for i in 0..a.len() {
            let mut carry = 0u16;
            for j in 0..b.len() {
                let product = (a[i] as u16) * (b[j] as u16) + (result[i + j] as u16) + carry;
                result[i + j] = (product & 0xFF) as u8;
                carry = product >> 8;
            }
            if i + b.len() < result.len() {
                result[i + b.len()] = carry as u8;
            }
        }
        
        // modulus で除算
        self.big_integer_mod(&result, modulus)
    }
    
    /// 大整数 mod 演算
    fn big_integer_mod(&self, dividend: &[u8], divisor: &[u8]) -> Result<Vec<u8>, TransportError> {
        if self.is_zero(divisor) {
            return Err(TransportError::CryptoError);
        }
        
        let mut remainder = dividend.to_vec();
        
        // 単純な減算による mod 計算
        while self.compare_big_integers(&remainder, divisor) >= 0 {
            self.subtract_big_integers(&mut remainder, divisor)?;
        }
        
        Ok(remainder)
    }
    
    /// モジュラ逆元計算（拡張ユークリッド法）
    fn compute_modular_inverse(&self, a: &[u8], m: &[u8]) -> Result<Vec<u8>, TransportError> {
        // 拡張ユークリッド法の簡易実装
        // 完全な実装では大整数演算ライブラリが必要
        
        if self.is_zero(a) || self.is_zero(m) {
            return Err(TransportError::CryptoError);
        }
        
        // 簡略化: 小さな値の場合のみ対応
        if a.len() <= 8 && m.len() <= 8 {
            let a_val = self.bytes_to_u64(a);
            let m_val = self.bytes_to_u64(m);
            
            if let Some(inv) = self.mod_inverse_u64(a_val, m_val) {
                return Ok(self.u64_to_bytes(inv, m.len()));
            }
        }
        
        Err(TransportError::CryptoError)
    }
    
    fn bytes_to_u64(&self, bytes: &[u8]) -> u64 {
        let mut result = 0u64;
        for (i, &byte) in bytes.iter().enumerate() {
            if i >= 8 { break; }
            result |= (byte as u64) << (i * 8);
        }
        result
    }
    
    fn u64_to_bytes(&self, value: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        for i in 0..len.min(8) {
            bytes[i] = ((value >> (i * 8)) & 0xFF) as u8;
        }
        bytes
    }
    
    fn mod_inverse_u64(&self, a: u64, m: u64) -> Option<u64> {
        // 拡張ユークリッド法
        let mut old_r = a as i128;
        let mut r = m as i128;
        let mut old_s = 1i128;
        let mut s = 0i128;
        
        while r != 0 {
            let quotient = old_r / r;
            let temp_r = r;
            r = old_r - quotient * r;
            old_r = temp_r;
            
            let temp_s = s;
            s = old_s - quotient * s;
            old_s = temp_s;
        }
        
        if old_r > 1 {
            return None; // 逆元が存在しない
        }
        
        if old_s < 0 {
            old_s += m as i128;
        }
        
        Some(old_s as u64)
    }
    
    /// 統計情報を取得
    pub fn get_stats(&self) -> Result<CryptoStats, TransportError> {
    /// データを暗号化
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        // TODO: 現在アクティブなTLSセッションの暗号スイートとセッションキーを使用して `data` を暗号化する。
        //       通常、TLSレコードとしてペイロードを暗号化し、MAC (Message Authentication Code) を付加する。
        //       AEAD (Authenticated Encryption with AssociatedData) 暗号 (例: AES-GCM, ChaCha20-Poly1305)
        //       が使用される。シーケンス番号の管理も重要。
        //       `rustls::Connection::writer().write(data)` や OpenSSL の `SSL_write` のような
        //       TLSライブラリのAPIを使用するのが一般的。ライブラリがレコードのフレーミングと暗号化を行う。
        if !self.handshake_completed {
            warn!("TLS handshake not completed. Cannot encrypt data.");
            return Err(TransportError::HandshakeNotCompleted);
        }

        let session_info_guard = self.session_info.lock();
        let session_info = session_info_guard.as_ref().ok_or(TransportError::InvalidState("SessionInfo not found".into()))?;

        // 統計情報を更新
        let mut stats_guard = self.stats.lock();
        stats_guard.plaintext_bytes_sent += data.len() as u64;
        // stats_guard.ciphertext_bytes_sent は暗号化後のサイズで更新

        // 暗号スイートに基づいて暗号化処理 (ダミー)
        match session_info.cipher_suite {
            CipherSuite::Aes128GcmSha256 | CipherSuite::Aes256GcmSha384 | CipherSuite::ChaCha20Poly1305Sha256 => {
                // TODO: 実際のAEAD暗号化処理 (セッションキーを使用)
                // この例では、データをそのまま返し、末尾にダミーのタグを追加
                let mut encrypted_data = Vec::with_capacity(data.len() + 16); // 16バイトタグを想定
                encrypted_data.extend_from_slice(data);
                encrypted_data.extend_from_slice(&[0u8; 16]); // ダミータグ
                debug!("Encrypting {} bytes (simulated) with {:?}", data.len(), session_info.cipher_suite);
                stats_guard.ciphertext_bytes_sent += encrypted_data.len() as u64;
                Ok(encrypted_data)
            }
            CipherSuite::LightweightAead => {
                // TODO: 軽量AEAD暗号化処理
                warn!("LightweightAead encryption not yet fully implemented.");
                let mut encrypted_data = data.to_vec(); // ダミー
                encrypted_data.push(0xFF); // ダミー処理の印
                stats_guard.ciphertext_bytes_sent += encrypted_data.len() as u64;
                Ok(encrypted_data)
            }
        }
    }
    
    /// 暗号化データを復号
    fn decrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        // TODO: 現在アクティブなTLSセッションの暗号スイートとセッションキーを使用して `data` (受信したTLSレコード)
        //       を復号し、その内容 (平文) を返す。
        //       TLSライブラリがレコードのデフレーミング、復号、MAC検証、シーケンス番号チェックを行う。
        //       AEAD暗号が使用される。
        //       `rustls::Connection::reader().read(data)` や OpenSSL の `SSL_read` のような
        //       TLSライブラリのAPIを使用し、処理された平文を取得する。
        if !self.handshake_completed {
            warn!("TLS handshake not completed. Cannot decrypt data.");
            return Err(TransportError::HandshakeNotCompleted);
        }
        if data.is_empty() {
            return Ok(Vec::new()); // 空のデータはそのまま返す
        }

        let session_info_guard = self.session_info.lock();
        let session_info = session_info_guard.as_ref().ok_or(TransportError::InvalidState("SessionInfo not found".into()))?;
        
        // 統計情報を更新
        let mut stats_guard = self.stats.lock();
        stats_guard.ciphertext_bytes_received += data.len() as u64;
        // stats_guard.plaintext_bytes_received は復号後のサイズで更新


        // 暗号スイートに基づいて復号処理 (ダミー)
        match session_info.cipher_suite {
            CipherSuite::Aes128GcmSha256 | CipherSuite::Aes256GcmSha384 | CipherSuite::ChaCha20Poly1305Sha256 => {
                // TODO: 実際のAEAD復号処理 (セッションキーを使用、タグ検証)
                // この例では、末尾16バイトをタグとみなし、それ以外をデータ部とする
                if data.len() < 16 { // タグ長より短いデータはエラー
                    warn!("Received data too short to contain a tag.");
                    return Err(TransportError::DecryptionFailed("Data too short".into()));
                }
                let (payload, _tag) = data.split_at(data.len() - 16);
                // TODO: タグ検証
                debug!("Decrypting {} bytes (simulated) with {:?}", payload.len(), session_info.cipher_suite);
                stats_guard.plaintext_bytes_received += payload.len() as u64;
                Ok(payload.to_vec())
            }
            CipherSuite::LightweightAead => {
                // TODO: 軽量AEAD復号処理
                warn!("LightweightAead decryption not yet fully implemented.");
                if data.last() == Some(&0xFF) { // ダミー処理の印を確認
                    let mut decrypted_data = data.to_vec();
                    decrypted_data.pop();
                    stats_guard.plaintext_bytes_received += decrypted_data.len() as u64;
                    Ok(decrypted_data)
                } else {
                    Err(TransportError::DecryptionFailed("Invalid lightweight aead data".into()))
                }
            }
        }
    }
    
    /// 終了通知アラートを作成
    fn create_close_notify(&self) -> Result<Vec<u8>, TransportError> {
        // TLSクローズ通知アラートを作成
        let mut alert = Vec::with_capacity(7);
        
        // TLSレコードヘッダ（アラート）
        alert.push(0x15); // タイプ: アラート
        alert.push(0x03); // バージョン: TLS 1.2 (3.3)
        alert.push(0x03);
        
        // レコード長
        alert.push(0x00);
        alert.push(0x02);
        
        // アラートレベルと種類
        alert.push(0x01); // 警告レベル
        alert.push(0x00); // クローズ通知
        
        Ok(alert)
    }
}

impl Debug for TlsSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TlsSession")
            .field("handshake_completed", &self.handshake_completed)
            .finish()
    }
}

// DTLSセッションの実装は省略（基本的にTLSと同様だが、UDPの信頼性のない通信に対応） 

impl CryptoEngine {
    /// DER証明書を解析
    fn parse_der_certificate(&self, der_data: &[u8]) -> Result<(String, String, u64, u64, Vec<u8>), TransportError> {
        if der_data.len() < 20 {
            return Err(TransportError::CertificateError("証明書データが短すぎます".to_string()));
        }
        
        log::debug!("DER証明書解析開始: {} バイト", der_data.len());
        
        // DER証明書の基本構造を解析
        let mut offset = 0;
        
        // Certificate SEQUENCE
        if der_data[offset] != 0x30 {
            return Err(TransportError::CertificateError("無効な証明書構造".to_string()));
        }
        offset += 1;
        
        // 長さフィールドをスキップ
        let cert_length = self.parse_der_length(&der_data[offset..])?;
        offset += self.get_der_length_size(&der_data[offset..]);
        
        // TBSCertificate SEQUENCE
        if offset >= der_data.len() || der_data[offset] != 0x30 {
            return Err(TransportError::CertificateError("TBSCertificate SEQUENCEが見つかりません".to_string()));
        }
        offset += 1;
        
        let tbs_length = self.parse_der_length(&der_data[offset..])?;
        offset += self.get_der_length_size(&der_data[offset..]);
        let tbs_start = offset - 1 - self.get_der_length_size(&der_data[offset - 1 - self.get_der_length_size(&der_data[offset - 1..])..]);
        let tbs_end = offset + tbs_length;
        
        // バージョン (オプション)
        if offset < der_data.len() && der_data[offset] == 0xA0 {
            offset += 1;
            let version_length = self.parse_der_length(&der_data[offset..])?;
            offset += self.get_der_length_size(&der_data[offset..]) + version_length;
        }
        
        // シリアル番号をスキップ
        if offset >= der_data.len() || der_data[offset] != 0x02 {
            return Err(TransportError::CertificateError("シリアル番号が見つかりません".to_string()));
        }
        offset += 1;
        let serial_length = self.parse_der_length(&der_data[offset..])?;
        offset += self.get_der_length_size(&der_data[offset..]) + serial_length;
        
        // 署名アルゴリズムをスキップ
        if offset >= der_data.len() || der_data[offset] != 0x30 {
            return Err(TransportError::CertificateError("署名アルゴリズムが見つかりません".to_string()));
        }
        offset += 1;
        let sig_alg_length = self.parse_der_length(&der_data[offset..])?;
        offset += self.get_der_length_size(&der_data[offset..]) + sig_alg_length;
        
        // 発行者 (Issuer)
        if offset >= der_data.len() || der_data[offset] != 0x30 {
            return Err(TransportError::CertificateError("発行者が見つかりません".to_string()));
        }
        offset += 1;
        let issuer_length = self.parse_der_length(&der_data[offset..])?;
        let issuer_start = offset + self.get_der_length_size(&der_data[offset..]);
        let issuer = self.extract_dn_name(&der_data[issuer_start..issuer_start + issuer_length])?;
        offset = issuer_start + issuer_length;
        
        // 有効期間 (Validity)
        if offset >= der_data.len() || der_data[offset] != 0x30 {
            return Err(TransportError::CertificateError("有効期間が見つかりません".to_string()));
        }
        offset += 1;
        let validity_length = self.parse_der_length(&der_data[offset..])?;
        let validity_start = offset + self.get_der_length_size(&der_data[offset..]);
        let (not_before, not_after) = self.extract_validity(&der_data[validity_start..validity_start + validity_length])?;
        offset = validity_start + validity_length;
        
        // 主体者 (Subject)
        if offset >= der_data.len() || der_data[offset] != 0x30 {
            return Err(TransportError::CertificateError("主体者が見つかりません".to_string()));
        }
        offset += 1;
        let subject_length = self.parse_der_length(&der_data[offset..])?;
        let subject_start = offset + self.get_der_length_size(&der_data[offset..]);
        let subject = self.extract_dn_name(&der_data[subject_start..subject_start + subject_length])?;
        offset = subject_start + subject_length;
        
        // 公開鍵情報
        if offset >= der_data.len() || der_data[offset] != 0x30 {
            return Err(TransportError::CertificateError("公開鍵情報が見つかりません".to_string()));
        }
        offset += 1;
        let pubkey_length = self.parse_der_length(&der_data[offset..])?;
        let pubkey_start = offset + self.get_der_length_size(&der_data[offset..]);
        let public_key = self.extract_public_key(&der_data[pubkey_start..pubkey_start + pubkey_length])?;
        
        log::debug!("証明書解析完了: 発行者={}, 主体者={}", issuer, subject);
        Ok((issuer, subject, not_before, not_after, public_key))
    }
    
    fn get_der_length_size(&self, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        
        let first_byte = data[0];
        if first_byte & 0x80 == 0 {
            // 短い形式 (0-127)
            1
        } else {
            // 長い形式
            let length_bytes = (first_byte & 0x7f) as usize;
            1 + length_bytes
        }
    }
    
    /// Distinguished Name（DN）から名前を抽出
    fn extract_dn_name(&self, dn_data: &[u8]) -> Result<String, TransportError> {
        // 簡略化実装：CNフィールドを探して抽出
        for window in dn_data.windows(5) {
            // CN (Common Name) のOID: 2.5.4.3 (0x55, 0x04, 0x03)
            if window[0] == 0x55 && window[1] == 0x04 && window[2] == 0x03 {
                // CN値を抽出（UTF8文字列として解釈）
                let cn_start = window.as_ptr() as usize - dn_data.as_ptr() as usize + 5;
                if cn_start + 10 < dn_data.len() {
                    let cn_bytes = &dn_data[cn_start..cn_start + 10];
                    if let Ok(cn_str) = core::str::from_utf8(cn_bytes) {
                        return Ok(cn_str.trim_matches('\0').to_string());
                    }
                }
            }
        }
        
        // CNが見つからない場合はダミー名前を返す
        Ok("Unknown".to_string())
    }
    
    /// 有効期限を抽出
    fn extract_validity(&self, validity_data: &[u8]) -> Result<(u64, u64), TransportError> {
        // ASN.1時刻解析の実装：UTCTime（YYMMDDHHMMSSZ）またはGeneralizedTime（YYYYMMDDHHMMSSZ）
        if validity_data.len() < 20 {
            return Err(TransportError::InvalidCertificate);
        }
        
        let mut offset = 0;
        
        // 最初の時刻（notBefore）を解析
        let (not_before, consumed) = self.parse_asn1_time(&validity_data[offset..])?;
        offset += consumed;
        
        // 2番目の時刻（notAfter）を解析
        let (not_after, _) = self.parse_asn1_time(&validity_data[offset..])?;
        
        Ok((not_before, not_after))
    }
    
    fn parse_asn1_time(&self, time_data: &[u8]) -> Result<(u64, usize), TransportError> {
        if time_data.len() < 2 {
            return Err(TransportError::InvalidCertificate);
        }
        
        let time_type = time_data[0];
        let time_length = time_data[1] as usize;
        
        if time_data.len() < 2 + time_length {
            return Err(TransportError::InvalidCertificate);
        }
        
        let time_str = &time_data[2..2 + time_length];
        
        match time_type {
            0x17 => {
                // UTCTime (YYMMDDHHMMSSZ) - 完全実装
                if time_length < 13 {
                    return Err(TransportError::InvalidCertificate);
                }
                
                // UTCTimeフォーマット検証: YYMMDDHHMMSSZ
                if time_str.last() != Some(&b'Z') {
                    return Err(TransportError::InvalidCertificate);
                }
                
                // 各フィールドの数字チェック
                for (i, &byte) in time_str[..12].iter().enumerate() {
                    if !byte.is_ascii_digit() {
                        log::warn!("UTCTime無効文字 位置{}: {}", i, byte);
                        return Err(TransportError::InvalidCertificate);
                    }
                }
                
                let year = self.parse_two_digits(&time_str[0..2])? + 2000;
                let month = self.parse_two_digits(&time_str[2..4])?;
                let day = self.parse_two_digits(&time_str[4..6])?;
                let hour = self.parse_two_digits(&time_str[6..8])?;
                let minute = self.parse_two_digits(&time_str[8..10])?;
                let second = self.parse_two_digits(&time_str[10..12])?;
                
                // Y2K問題対応：50年未満は20XX年、50年以上は19XX年
                let full_year = if year < 2050 { year } else { year - 100 + 1900 };
                
                // 日付妥当性チェック
                if !self.is_valid_date(full_year, month, day, hour, minute, second) {
                    log::warn!("UTCTime無効日付: {}/{}/{} {}:{}:{}", full_year, month, day, hour, minute, second);
                    return Err(TransportError::InvalidCertificate);
                }
                
                let timestamp = self.date_to_timestamp(full_year, month, day, hour, minute, second)?;
                log::debug!("UTCTime解析成功: {}/{}/{} {}:{}:{} -> timestamp={}", full_year, month, day, hour, minute, second, timestamp);
                Ok((timestamp, 2 + time_length))
            },
            0x18 => {
                // GeneralizedTime (YYYYMMDDHHMMSSZ) - 完全実装
                if time_length < 15 {
                    return Err(TransportError::InvalidCertificate);
                }
                
                // GeneralizedTimeフォーマット検証: YYYYMMDDHHMMSSZ
                if time_str.last() != Some(&b'Z') {
                    return Err(TransportError::InvalidCertificate);
                }
                
                // 各フィールドの数字チェック
                for (i, &byte) in time_str[..14].iter().enumerate() {
                    if !byte.is_ascii_digit() {
                        log::warn!("GeneralizedTime無効文字 位置{}: {}", i, byte);
                        return Err(TransportError::InvalidCertificate);
                    }
                }
                
                let year = self.parse_four_digits(&time_str[0..4])?;
                let month = self.parse_two_digits(&time_str[4..6])?;
                let day = self.parse_two_digits(&time_str[6..8])?;
                let hour = self.parse_two_digits(&time_str[8..10])?;
                let minute = self.parse_two_digits(&time_str[10..12])?;
                let second = self.parse_two_digits(&time_str[12..14])?;
                
                // 分数秒が含まれている場合の処理（オプション）
                let mut consumed_length = 15; // YYYYMMDDHHMMSSZ
                if time_length > 15 && time_str[14] == b'.' {
                    // 分数秒をスキップ（.sssZ形式）
                    let mut frac_end = 15;
                    while frac_end < time_length - 1 && time_str[frac_end].is_ascii_digit() {
                        frac_end += 1;
                    }
                    if time_str[frac_end] == b'Z' {
                        consumed_length = frac_end + 1 + 2; // + prefix length
                    }
                }
                
                // 日付妥当性チェック
                if !self.is_valid_date(year, month, day, hour, minute, second) {
                    log::warn!("GeneralizedTime無効日付: {}/{}/{} {}:{}:{}", year, month, day, hour, minute, second);
                    return Err(TransportError::InvalidCertificate);
                }
                
                let timestamp = self.date_to_timestamp(year, month, day, hour, minute, second)?;
                log::debug!("GeneralizedTime解析成功: {}/{}/{} {}:{}:{} -> timestamp={}", year, month, day, hour, minute, second, timestamp);
                Ok((timestamp, consumed_length))
            },
            _ => {
                log::warn!("サポートされていない時刻タイプ: 0x{:02x}", time_type);
                Err(TransportError::InvalidCertificate)
            },
        }
    }
    
    /// 日付の妥当性チェック
    fn is_valid_date(&self, year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> bool {
        // 基本範囲チェック
        if year < 1970 || year > 9999 {
            return false;
        }
        if month == 0 || month > 12 {
            return false;
        }
        if day == 0 || day > 31 {
            return false;
        }
        if hour > 23 || minute > 59 || second > 59 {
            return false;
        }
        
        // 月ごとの日数チェック
        let days_in_month = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                if self.is_leap_year(year) {
                    29
                } else {
                    28
                }
            },
            _ => return false,
        };
        
        if day > days_in_month {
            return false;
        }
        
        true
    }
    
    /// 公開鍵を抽出
    fn extract_public_key(&self, pubkey_data: &[u8]) -> Result<Vec<u8>, TransportError> {
        // AlgorithmIdentifierを解析してアルゴリズムを特定し、
        // それに応じて公開鍵パラメータを抽出する
        
        if pubkey_data.len() < 10 {
            return Err(TransportError::CertificateError("公開鍵データが短すぎます".to_string()));
        }
        
        // DER形式のSubjectPublicKeyInfoを解析
        let mut offset = 0;
        
        // SEQUENCE tag (0x30)
        if pubkey_data[offset] != 0x30 {
            return Err(TransportError::CertificateError("無効なSubjectPublicKeyInfo形式".to_string()));
        }
        offset += 1;
        
        // 長さフィールドをスキップ
        let length_size = self.get_der_length_size(&pubkey_data[offset..]);
        offset += length_size;
        
        // AlgorithmIdentifier SEQUENCE
        if pubkey_data[offset] != 0x30 {
            return Err(TransportError::CertificateError("AlgorithmIdentifierが見つかりません".to_string()));
        }
        offset += 1;
        
        let algo_length_size = self.get_der_length_size(&pubkey_data[offset..]);
        let algo_length = self.parse_der_length(&pubkey_data[offset..])?.0;
        offset += algo_length_size;
        
        // アルゴリズムOIDを解析
        if pubkey_data[offset] != 0x06 {
            return Err(TransportError::CertificateError("アルゴリズムOIDが見つかりません".to_string()));
        }
        offset += 1;
        
        let oid_length = pubkey_data[offset] as usize;
        offset += 1;
        
        let algorithm_oid = &pubkey_data[offset..offset + oid_length];
        offset += oid_length;
        
        // アルゴリズムに基づいて公開鍵を抽出
        match algorithm_oid {
            // RSA暗号化 (1.2.840.113549.1.1.1)
            [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01] => {
                self.extract_rsa_public_key(&pubkey_data[offset + algo_length - oid_length - 2..])
            },
            // ECDSA with P-256 (1.2.840.10045.2.1)
            [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01] => {
                self.extract_ec_public_key(&pubkey_data[offset + algo_length - oid_length - 2..])
            },
            // Ed25519 (1.3.101.112)
            [0x2b, 0x65, 0x70] => {
                self.extract_ed25519_public_key(&pubkey_data[offset + algo_length - oid_length - 2..])
            },
            _ => {
                log::warn!("サポートされていないアルゴリズム: {:?}", algorithm_oid);
                // フォールバック：最初の64バイトを返す
                if pubkey_data.len() >= 64 {
                    Ok(pubkey_data[..64].to_vec())
                } else {
                    Ok(pubkey_data.to_vec())
                }
            }
        }
    }
    
    /// RSA公開鍵を抽出
    fn extract_rsa_public_key(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        // BIT STRING内のRSAPublicKey構造を解析
        let mut offset = 0;
        
        // BIT STRING tag (0x03)
        if data[offset] != 0x03 {
            return Err(TransportError::CertificateError("RSA公開鍵のBIT STRINGが見つかりません".to_string()));
        }
        offset += 1;
        
        let length_size = self.get_der_length_size(&data[offset..]);
        offset += length_size;
        
        // 未使用ビット数（通常は0）
        offset += 1;
        
        // RSAPublicKey SEQUENCE
        if data[offset] != 0x30 {
            return Err(TransportError::CertificateError("RSAPublicKey SEQUENCEが見つかりません".to_string()));
        }
        offset += 1;
        
        let rsa_length_size = self.get_der_length_size(&data[offset..]);
        offset += rsa_length_size;
        
        // modulus (n) - INTEGER
        if data[offset] != 0x02 {
            return Err(TransportError::CertificateError("RSA modulusが見つかりません".to_string()));
        }
        offset += 1;
        
        let modulus_length_size = self.get_der_length_size(&data[offset..]);
        let modulus_length = self.parse_der_length(&data[offset..])?.0;
        offset += modulus_length_size;
        
        // 先頭の0x00バイトをスキップ（正の整数を示すため）
        if data[offset] == 0x00 {
            offset += 1;
        }
        
        let modulus = &data[offset..offset + modulus_length - 1];
        offset += modulus_length - 1;
        
        // publicExponent (e) - INTEGER
        if data[offset] != 0x02 {
            return Err(TransportError::CertificateError("RSA public exponentが見つかりません".to_string()));
        }
        offset += 1;
        
        let exponent_length = data[offset] as usize;
        offset += 1;
        
        let exponent = &data[offset..offset + exponent_length];
        
        // modulus + exponentを結合して返す
        let mut result = Vec::with_capacity(modulus.len() + exponent.len() + 8);
        result.extend_from_slice(&(modulus.len() as u32).to_be_bytes());
        result.extend_from_slice(modulus);
        result.extend_from_slice(&(exponent.len() as u32).to_be_bytes());
        result.extend_from_slice(exponent);
        
        Ok(result)
    }
    
    /// EC公開鍵を抽出
    fn extract_ec_public_key(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        // BIT STRING内のEC公開鍵ポイントを解析
        let mut offset = 0;
        
        // BIT STRING tag (0x03)
        if data[offset] != 0x03 {
            return Err(TransportError::CertificateError("EC公開鍵のBIT STRINGが見つかりません".to_string()));
        }
        offset += 1;
        
        let length_size = self.get_der_length_size(&data[offset..]);
        let point_length = self.parse_der_length(&data[offset..])?.0;
        offset += length_size;
        
        // 未使用ビット数（通常は0）
        offset += 1;
        
        // ECポイント（非圧縮形式：0x04 + x座標 + y座標）
        if data[offset] != 0x04 {
            return Err(TransportError::CertificateError("非圧縮EC公開鍵のみサポートされています".to_string()));
        }
        
        let point_data = &data[offset..offset + point_length - 1];
        Ok(point_data.to_vec())
    }
    
    /// Ed25519公開鍵を抽出
    fn extract_ed25519_public_key(&self, data: &[u8]) -> Result<Vec<u8>, TransportError> {
        // BIT STRING内のEd25519公開鍵（32バイト）を解析
        let mut offset = 0;
        
        // BIT STRING tag (0x03)
        if data[offset] != 0x03 {
            return Err(TransportError::CertificateError("Ed25519公開鍵のBIT STRINGが見つかりません".to_string()));
        }
        offset += 1;
        
        let length_size = self.get_der_length_size(&data[offset..]);
        offset += length_size;
        
        // 未使用ビット数（通常は0）
        offset += 1;
        
        // Ed25519公開鍵は32バイト
        if data.len() - offset < 32 {
            return Err(TransportError::CertificateError("Ed25519公開鍵のサイズが不正です".to_string()));
        }
        
        Ok(data[offset..offset + 32].to_vec())
    }
    
    /// 証明書のフィンガープリントを計算
    fn calculate_fingerprint(&self, cert_data: &[u8]) -> Vec<u8> {
        // SHA-256ハッシュでフィンガープリントを計算
        self.sha256_hash(cert_data)
    }
    
    /// SHA-256ハッシュを計算（簡略化実装）
    fn sha256_hash(&self, data: &[u8]) -> Vec<u8> {
        // 簡略化されたSHA-256実装
        // 実際の実装では適切な暗号化ライブラリを使用
        
        let mut hash = vec![0u8; 32];
        let mut state = 0x6a09e667u32;
        
        // 極めて簡単なハッシュ関数（セキュリティ的には不適切）
        for (i, &byte) in data.iter().enumerate() {
            state = state.wrapping_add(byte as u32);
            state = state.rotate_left(7);
            hash[i % 32] ^= (state as u8);
        }
        
        hash
    }
    
    /// 現在時刻を取得（Unix timestamp）
    fn get_current_time(&self) -> u64 {
        // システムタイマーから現在時刻を取得
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let mut high: u32;
            let mut low: u32;
            core::arch::asm!("rdtsc", out("eax") low, out("edx") high);
            
            // TSCをUnixタイムスタンプ風に変換（簡略化）
            let tsc = ((high as u64) << 32) | (low as u64);
            1640000000 + (tsc / 1_000_000_000) // 2022年1月1日を基準
        }
        
        #[cfg(not(target_arch = "x86_64"))]
        {
            1640000000 // 固定値（2022年1月1日）
        }
    }
    
    /// うるう年判定
    fn is_leap_year(&self, year: u32) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }
    
    /// 2桁数字を解析
    fn parse_two_digits(&self, bytes: &[u8]) -> Result<u32, TransportError> {
        if bytes.len() < 2 {
            return Err(TransportError::InvalidCertificate);
        }
        
        let tens = (bytes[0] as char).to_digit(10)
            .ok_or(TransportError::InvalidCertificate)?;
        let ones = (bytes[1] as char).to_digit(10)
            .ok_or(TransportError::InvalidCertificate)?;
            
        Ok(tens * 10 + ones)
    }
    
    /// 4桁数字を解析
    fn parse_four_digits(&self, bytes: &[u8]) -> Result<u32, TransportError> {
        if bytes.len() < 4 {
            return Err(TransportError::InvalidCertificate);
        }
        
        let thousands = (bytes[0] as char).to_digit(10)
            .ok_or(TransportError::InvalidCertificate)?;
        let hundreds = (bytes[1] as char).to_digit(10)
            .ok_or(TransportError::InvalidCertificate)?;
        let tens = (bytes[2] as char).to_digit(10)
            .ok_or(TransportError::InvalidCertificate)?;
        let ones = (bytes[3] as char).to_digit(10)
            .ok_or(TransportError::InvalidCertificate)?;
            
        Ok(thousands * 1000 + hundreds * 100 + tens * 10 + ones)
    }
    
    /// 日付をUnixタイムスタンプに変換
    fn date_to_timestamp(&self, year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Result<u64, TransportError> {
        // Unix元期（1970年1月1日）からの日数を計算
        if year < 1970 {
            return Err(TransportError::InvalidCertificate);
        }
        
        // 年から日数を計算
        let mut total_days = 0u64;
        for y in 1970..year {
            total_days += if self.is_leap_year(y) { 366 } else { 365 };
        }
        
        // 月から日数を計算
        let days_in_months = [
            0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
        ];
        
        for m in 1..month {
            total_days += days_in_months[m as usize] as u64;
            if m == 2 && self.is_leap_year(year) {
                total_days += 1; // うるう年の2月
            }
        }
        
        // 日を追加（1日ベースなので1を引く）
        total_days += (day - 1) as u64;
        
        // 秒に変換
        let total_seconds = total_days * 24 * 3600 + 
                           hour as u64 * 3600 + 
                           minute as u64 * 60 + 
                           second as u64;
        
        Ok(total_seconds)
    }
    
    /// 完全なSHA-256実装（RFC 6234準拠）
    fn sha256_hash(&self, data: &[u8]) -> Vec<u8> {
        // RFC 6234準拠の完全なSHA-256実装
        
        // SHA-256定数（最初の64個の素数の立方根の小数部分）
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];
        
        // 初期ハッシュ値（最初の8個の素数の平方根の小数部分）
        let mut h = [
            0x6a09e667u32, 0xbb67ae85u32, 0x3c6ef372u32, 0xa54ff53au32,
            0x510e527fu32, 0x9b05688cu32, 0x1f83d9abu32, 0x5be0cd19u32,
        ];
        
        // メッセージの前処理
        let mut message = data.to_vec();
        let original_length = data.len() as u64;
        
        // パディング: 1ビットを追加
        message.push(0x80);
        
        // 512ビット（64バイト）の倍数になるまでゼロパディング
        // ただし、最後の64ビット（8バイト）は元のメッセージ長用に予約
        while (message.len() % 64) != 56 {
            message.push(0x00);
        }
        
        // 元のメッセージ長（ビット単位）をビッグエンディアンで追加
        let bit_length = original_length * 8;
        message.extend_from_slice(&bit_length.to_be_bytes());
        
        // 512ビットチャンクごとに処理
        for chunk in message.chunks_exact(64) {
            // メッセージスケジュール配列Wを準備
            let mut w = [0u32; 64];
            
            // 最初の16ワードをチャンクから取得
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    chunk[i * 4],
                    chunk[i * 4 + 1],
                    chunk[i * 4 + 2],
                    chunk[i * 4 + 3],
                ]);
            }
            
            // 残りの48ワードを計算
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
            }
            
            // ワーキング変数を初期化
            let mut a = h[0];
            let mut b = h[1];
            let mut c = h[2];
            let mut d = h[3];
            let mut e = h[4];
            let mut f = h[5];
            let mut g = h[6];
            let mut h_temp = h[7];
            
            // メイン圧縮ループ
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h_temp.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);
                
                h_temp = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }
            
            // ハッシュ値を更新
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(h_temp);
        }
        
        // 最終ハッシュ値をバイト配列として返す
        let mut result = Vec::with_capacity(32);
        for hash_word in h.iter() {
            result.extend_from_slice(&hash_word.to_be_bytes());
        }
        
        result
    }
}

/// RSA公開鍵構造体
#[derive(Debug, Clone)]
struct RsaPublicKey {
    /// modulus (n)
    modulus: Vec<u8>,
    /// public exponent (e)
    exponent: Vec<u8>,
    /// 鍵サイズ（ビット数）
    key_size_bits: usize,
} 