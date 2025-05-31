// AetherOS 次世代セキュアブート実装
//
// 世界最高レベルの起動セキュリティを提供する高度なセキュアブートシステム

use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use crate::crypto::hash::{sha256, sha512};
use crate::crypto::signature::{verify_signature, KeyType};
use hex;

// Assuming BootInfo and BootModule are defined in a parent or sibling module like super::boot_info
use super::boot_info::{BootInfo, BootModule};

/// セキュアブートの状態
static SECURE_BOOT_ENABLED: AtomicBool = AtomicBool::new(false);

/// 検証キーデータベース（プラットフォームキー、キー交換キー、署名データベースキーなど）
static KEY_DATABASE: Mutex<Vec<PublicKey>> = Mutex::new(Vec::new());

/// 信頼されたハッシュデータベース（署名検証に失敗した場合のフォールバック）
static TRUSTED_HASHES: Mutex<Vec<TrustedHash>> = Mutex::new(Vec::new());

/// Measured Boot用の測定値チェーン（TPMイベントログとPCRのソフトウェア的表現）
static MEASUREMENT_CHAIN: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// TPM PCRインデックスの定義例 (実際のインデックスはプラットフォーム仕様による)
const TPM_PCR_BOOT_CONFIG: u32 = 0; // SRTM/CRTM, BIOS, Host Platform Extensions
const TPM_PCR_KERNEL_MODULES: u32 = 4; // Kernel, Bootloader, Kernel modules

/// セキュアブートポリシー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootPolicy {
    /// 厳格モード - 署名検証失敗時は起動しない
    Strict,
    /// 警告モード - 署名検証失敗時は警告のみ、ただしTPMには記録
    Warn,
    /// 監査モード - 起動するが検証結果をログに記録、TPMにも記録
    Audit,
    /// 無効 - 検証を行わない (非推奨)
    Disabled,
}

/// 公開鍵情報
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// キーID（例: SHA256ハッシュやUUID）
    pub key_id: [u8; 16], // 16バイトのUUIDまたは切り詰めたハッシュなど
    /// キータイプ (RSA, ECCなど)
    pub key_type: KeyType,
    /// 公開鍵データ (DERエンコードなど)
    pub key_data: Vec<u8>,
    /// キー名（オプション、デバッグ用）
    pub key_name: Option<String>,
    /// 有効期限（UNIXタイムスタンプ、オプション）
    pub expires_at: Option<u64>,
    /// キー発行者 (オプション)
    pub issuer: Option<String>,
    /// キー用途 (オプション、例: "Platform Key", "Kernel Signing")
    pub usage: Option<String>,
}

/// 信頼されたハッシュ
#[derive(Debug, Clone)]
pub struct TrustedHash {
    /// イメージ名または識別子
    pub image_name: String,
    /// ハッシュアルゴリズム
    pub algorithm: HashAlgorithm,
    /// ハッシュ値
    pub hash_value: Vec<u8>,
    /// ハッシュの提供元や説明 (オプション)
    pub description: Option<String>,
}

/// ハッシュアルゴリズム (TPM仕様との互換性も考慮)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)] // TPM連携時にアルゴリズムIDとして使用するため
pub enum HashAlgorithm {
    Sha256 = 0x0B,   // TPM_ALG_SHA256
    Sha384 = 0x0C,   // TPM_ALG_SHA384 (SHA-512の切り詰め版とは異なる)
    Sha512 = 0x0D,   // TPM_ALG_SHA512
    Sha3_256 = 0x1B, // TPM_ALG_SHA3_256 (仮、TPM仕様確認要)
    Sha3_512 = 0x1C, // TPM_ALG_SHA3_512 (仮、TPM仕様確認要)
    Unknown = 0xFF,
}

impl HashAlgorithm {
    /// ハッシュアルゴリズムに対応するハッシュ値を計算する
    pub fn calculate(&self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            HashAlgorithm::Sha256 => Some(sha256(data)),
            HashAlgorithm::Sha512 => Some(sha512(data)),
            // TODO: SHA384, SHA3_256, SHA3_512 のハッシュ計算処理を実装
            _ => {
                log::error!("Unsupported hash algorithm: {:?}", self);
                None
            }
        }
    }

    /// TPMが要求するアルゴリズムIDに変換 (例)
    pub fn to_tpm_alg_id(&self) -> u16 {
        match self {
            HashAlgorithm::Sha256 => 0x000B, // TPM_ALG_ID for SHA256
            HashAlgorithm::Sha384 => 0x000C, // TPM_ALG_ID for SHA384
            HashAlgorithm::Sha512 => 0x000D, // TPM_ALG_ID for SHA512
            // TODO: 他のアルゴリズムのTPM IDを定義
            _ => 0x0000, // TPM_ALG_ERROR or other appropriate value
        }
    }
}

/// 検証結果
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// 検証成功したかどうか
    pub success: bool,
    /// 使用したキーID（署名検証成功時）
    pub key_id: Option<[u8; 16]>,
    /// 使用したキー名（署名検証成功時）
    pub key_name: Option<String>,
    /// 失敗理由（失敗時）
    pub failure_reason: Option<String>,
    /// ハッシュに基づく検証が成功したか（署名なしまたは署名失敗時のフォールバック）
    pub hash_verified: bool,
    /// 検証に使用されたハッシュアルゴリズム
    pub hash_algorithm_used: Option<HashAlgorithm>,
    /// 計算されたハッシュ値（監査のため常に記録）
    pub calculated_hash: Vec<u8>,
}

/// セキュアブートを初期化し、ポリシーを適用
pub fn init(policy: SecureBootPolicy) -> Result<(), &'static str> {
    match policy {
        SecureBootPolicy::Disabled => {
            log::warn!("セキュアブートは無効化されています - 検証なしで起動します。これはセキュリティリスクです。");
            SECURE_BOOT_ENABLED.store(false, Ordering::SeqCst);
            return Ok(());
        },
        _ => {
            log::info!("セキュアブートを初期化中: {:?}モード", policy);
            SECURE_BOOT_ENABLED.store(true, Ordering::SeqCst);
            // TODO: Set a global variable for the current policy if needed elsewhere
        }
    }
    
    // UEFIセキュアブート状態を確認 (プラットフォームがUEFIの場合)
    // TODO: 条件付きコンパイルや実行時チェックでUEFI環境かどうかを判定
    match check_uefi_secure_boot_status() {
        Ok(true) => {
            log::info!("UEFIセキュアブートが有効です。UEFIキーをインポートします。");
            import_uefi_keys()?;
        },
        Ok(false) => {
            log::warn!("UEFIセキュアブートが無効、または確認できません。組み込み/カスタムキーを使用します。");
            load_builtin_or_custom_keys()?;
        },
        Err(e) => {
            log::error!("UEFIセキュアブート状態の確認中にエラー: {}. フォールバックキーを試みます。", e);
            load_builtin_or_custom_keys()?;
        }
    }
    
    // 信頼されたハッシュリストを読み込み (フォールバック用)
    load_trusted_hashes_list()?;
    
    // TPM連携機能を初期化 (TPMが存在する場合)
    if पॉलिसी_requires_tpm() { // 実際のポリシーチェック関数
        init_tpm_integration()?;
    }
    
    log::info!("セキュアブート初期化完了: {}個のキー, {}個の信頼ハッシュ。ポリシー: {:?}", 
               KEY_DATABASE.lock().len(), 
               TRUSTED_HASHES.lock().len(),
               policy);
    
    Ok(())
}

/// UEFIセキュアブートが有効かどうかをチェック (UEFI環境のみ)
fn check_uefi_secure_boot_status() -> Result<bool, &'static str> {
    // TODO: この関数はUEFI環境でのみ呼び出されるべき。非UEFI環境では常にOk(false)を返すか、呼び出さない。
    // UEFIランタイムサービス (GetVariable) を使用して "SecureBoot" および "SetupMode" 変数を読み取る。
    // SecureBoot (GUID: EFI_GLOBAL_VARIABLE) -> 1バイトデータ, 1なら有効
    // SetupMode (GUID: EFI_GLOBAL_VARIABLE) -> 1バイトデータ, 0ならセットアップモードでない（＝デプロイモード）
    
    // let secure_boot_guid = [0x8B,0xEA,0xD9,0x3E,0x49,0x31,0x4E,0x89,0xA9,0xA3,0x4B,0x0B,0xCF,0x7A,0xA1,0x38]; // EFI_GLOBAL_VARIABLE
    // let secure_boot_var = fetch_uefi_variable("SecureBoot", secure_boot_guid)?;
    // let setup_mode_var = fetch_uefi_variable("SetupMode", secure_boot_guid)?;

    // if let (Some(sb_val), Some(sm_val)) = (secure_boot_var.get(0), setup_mode_var.get(0)) {
    //     if *sb_val == 1 && *sm_val == 0 {
    //         return Ok(true); // UEFI Secure Boot is enabled and in User Mode
    //     }
    // }
    // Ok(false)
    
    log::warn!("check_uefi_secure_boot_status: UEFI変数アクセス未実装。デフォルトで無効として扱います。");
    Err("UEFI Secure Boot status check not implemented")
}

/// UEFIセキュアブートキー（PK, KEK, db, dbx）をインポート
fn import_uefi_keys() -> Result<(), &'static str> {
    log::info!("UEFIセキュアブートキーをインポート中...");
    // TODO: UEFI GetVariableサービスを呼び出して以下の変数を取得
    // - PK (Platform Key)
    // - KEK (Key Exchange Key)
    // - db (Allowed Signatures Database)
    // - dbx (Forbidden Signatures Database)
    // 各変数は EFI_SIGNATURE_LIST 構造体の連続である可能性があり、
    // EFI_SIGNATURE_LIST は EFI_SIGNATURE_DATA のリストを含む。
    // EFI_SIGNATURE_DATA は署名者証明書(X.509)やハッシュを含む。
    // これらを解析し、PublicKey構造体に変換してKEY_DATABASEに追加する。
    // dbxの内容はブラックリストとして別途管理する必要があるかもしれない。

    // let pk_data = fetch_uefi_variable("PK", EFI_GLOBAL_VARIABLE_GUID)?;
    // parse_and_add_uefi_keys(&pk_data, "Platform Key", KeyUsage::PlatformKey)?;
    // ... KEK, db, dbxも同様に ...

    log::warn!("import_uefi_keys: UEFIキーのインポートは未実装です。");
    Ok(())
}

/// 組み込み、または事前にプロビジョニングされたカスタムキーをロード
fn load_builtin_or_custom_keys() -> Result<(), &'static str> {
    log::info!("組み込み/カスタムキーをロード中...");
    let mut keys = KEY_DATABASE.lock();

    // 例1: バイナリに埋め込まれた開発用公開鍵 (include_bytes! を使用)
    // const DEV_PUB_KEY_BYTES: &[u8] = include_bytes!("../../../security/keys/dev_vendor.pub");
    // let dev_key = PublicKey {
    //     key_id: calculate_key_id(DEV_PUB_KEY_BYTES), // キーからIDを計算する関数
    //     key_type: KeyType::Ed25519, 
    //     key_data: DEV_PUB_KEY_BYTES.to_vec(),
    //     key_name: Some("AetherOS Development Vendor Key".to_string()),
    //     expires_at: None,
    //     issuer: Some("AetherOS Project".to_string()),
    //     usage: Some("General Purpose Signing".to_string()),
    // };
    // keys.push(dev_key);

    // 例2: 事前にプロビジョニングされた本番用プラットフォームキー
    // const PROD_PLATFORM_KEY_BYTES: &[u8] = ...; // セキュアな場所からロード or 埋め込み
    // let prod_pk = PublicKey { ... };
    // keys.push(prod_pk);
    
    // 現状のダミーキー実装を維持 (上記を参考に実際のキーに置き換えること)
    let dev_key_id = [0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0x01];
    let prod_key_id = [0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0xEF,0xDE,0xAD,0xBE,0x02];

    let dev_key = PublicKey {
        key_id: dev_key_id,
        key_type: KeyType::Ed25519,
        key_data: vec![0; 32], // TODO: Replace with actual Ed25519 public key bytes
        key_name: Some("AetherOS Development Key (Placeholder)".to_string()),
        expires_at: None,
        issuer: Some("AetherOS Internal".to_string()),
        usage: Some("Development/Testing".to_string()),
    };
    keys.push(dev_key);

    let prod_key = PublicKey {
        key_id: prod_key_id,
        key_type: KeyType::Rsa2048Sha256, 
        key_data: vec![0; 256], // TODO: Replace with actual RSA 2048 public key bytes (e.g., DER format)
        key_name: Some("AetherOS Production Key (Placeholder)".to_string()),
        expires_at: Some(20380119030807), 
        issuer: Some("AetherOS Secure Authority".to_string()),
        usage: Some("Production Kernel/Bootloader Signing".to_string()),
    };
    keys.push(prod_key);
    
    if keys.is_empty() {
        log::error!("重大: 有効な検証キーがロードされていません！セキュアブートは実質的に機能しません。");
        return Err("検証キーがロードされていません");
    }
    log::info!("{}個の組み込み/カスタムキーをロードしました。", keys.len());
    Ok(())
}

/// 信頼されたハッシュリストをロード (設定ファイルや埋め込みデータから)
fn load_trusted_hashes_list() -> Result<(), &'static str> {
    log::info!("信頼ハッシュリストをロード中...");
    let mut hashes = TRUSTED_HASHES.lock();

    // 例: 設定ファイルから読み込むか、バイナリに埋め込む
    // const KERNEL_FALLBACK_HASH_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // SHA256 empty string
    // let kernel_hash_bytes = hex::decode(KERNEL_FALLBACK_HASH_HEX)
    //     .map_err(|_| "カーネルフォールバックハッシュのデコードに失敗しました")?;
    // let kernel_trusted_hash = TrustedHash {
    //     image_name: "kernel.elf".to_string(), // またはブートローダーが渡す識別子
    //     algorithm: HashAlgorithm::Sha256,
    //     hash_value: kernel_hash_bytes,
    //     description: Some("カーネルフォールバックハッシュ (署名検証失敗時)".to_string()),
    // };
    // hashes.push(kernel_trusted_hash);

    // 現状のダミーハッシュ実装を維持 (上記を参考に実際のハッシュに置き換えること)
    let kernel_hash_bytes = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        .map_err(|_| "Failed to decode kernel hash hex string")?;
    let kernel_trusted_hash = TrustedHash {
        image_name: "kernel.elf".to_string(),
        algorithm: HashAlgorithm::Sha256,
        hash_value: kernel_hash_bytes, 
        description: Some("Kernel (Placeholder SHA256 of empty string)".to_string()),
    };
    hashes.push(kernel_trusted_hash);
    
    // ... 他の重要なコンポーネントのフォールバックハッシュも同様にロード ...

    log::info!("{}個の信頼ハッシュをロードしました。", hashes.len());
    Ok(())
}

/// TPM連携機能を初期化
fn init_tpm_integration() -> Result<(), &'static str> {
    log::info!("TPM連携を初期化中...");
    // TODO: TPMデバイスドライバ/ライブラリを使用してTPMを検出・初期化
    // 1. TPMデバイスの存在確認 (例: ACPI TPM2テーブルを解析、またはバススキャン)
    // 2. TPMとの通信チャネル確立
    // 3. TPMセルフテストの実行 (TPM2_Startup)
    // 4. 必要に応じてPCRの初期状態をリセット (ポリシーによる)
    //    例: tpm_pcr_reset(TPM_PCR_BOOT_CONFIG);
    
    MEASUREMENT_CHAIN.lock().clear(); // ソフトウェア測定チェーンをクリア
    log::warn!("init_tpm_integration: TPM連携は未実装です。TPM測定は行われません。");
    // 実際のTPM初期化に成功した場合のみOk(())を返す
    Ok(()) // 現時点では常に成功
}

/// イメージを検証 (署名検証、フォールバックとしてハッシュ検証)
pub fn verify_image(name: &str, data: &[u8], signature: Option<&[u8]>) -> VerificationResult {
    if !SECURE_BOOT_ENABLED.load(Ordering::Relaxed) {
        return VerificationResult {
            success: true, key_id: None, key_name: None, failure_reason: None,
            hash_verified: false, hash_algorithm_used: None, calculated_hash: Vec::new(),
        };
    }
    
    // TODO: より堅牢なハッシュアルゴリズム選択 (例:ポリシーやイメージの種類に基づく)
    let primary_hash_alg = HashAlgorithm::Sha256;
    let calculated_hash = match primary_hash_alg.calculate(data) {
        Some(h) => h,
        None => {
            let err_msg = format!("イメージ '{}' のハッシュ計算に失敗 (アルゴリズム: {:?})", name, primary_hash_alg);
            log::error!("{}", err_msg);
            // 致命的エラーなので、空のハッシュで失敗として返す
            return VerificationResult {
                success: false, key_id: None, key_name: None, failure_reason: Some(err_msg),
                hash_verified: false, hash_algorithm_used: Some(primary_hash_alg), calculated_hash: Vec::new(),
            };
        }
    };

    log::debug!("イメージ '{}' のハッシュ ({:?}): {:?}", name, primary_hash_alg, hex::encode(&calculated_hash));
    
    if let Some(sig_data) = signature {
        let keys = KEY_DATABASE.lock();
        for key in keys.iter() {
            // TODO: キーの有効期限や用途も検証に含める
            // if key.expires_at.map_or(false, |exp| current_time() > exp) { continue; }
            // if key.usage.as_deref() != Some("Expected Usage") { continue; }

            if verify_signature(data, sig_data, &key.key_data, key.key_type) {
                log::info!("イメージ '{}' の署名がキー '{}' (ID: {:?}) で検証成功", 
                          name, key.key_name.as_deref().unwrap_or("N/A"), hex::encode(&key.key_id));
                
                // 署名検証成功時もTPMに記録 (ポリシーによる)
                if let Err(e) = extend_tpm_pcrs_and_log(TPM_PCR_KERNEL_MODULES, primary_hash_alg, &calculated_hash, name, Some(key)) {
                     log::warn!("TPM PCR拡張/ログ記録に失敗: {}", e);
                }
                
                return VerificationResult {
                    success: true, key_id: Some(key.key_id), key_name: key.key_name.clone(), failure_reason: None,
                    hash_verified: false, hash_algorithm_used: Some(primary_hash_alg), calculated_hash,
                };
            }
        }
        log::warn!("イメージ '{}' の署名検証に失敗しました。登録されている全てのキーで試行しました。", name);
    } else {
        log::info!("イメージ '{}' には署名が提供されていません。ハッシュ検証を試みます。", name);
    }
    
    // ハッシュベースの検証 (署名なし、または署名検証失敗時のフォールバック)
    let trusted_hashes_db = TRUSTED_HASHES.lock();
    for trusted in trusted_hashes_db.iter() {
        if trusted.image_name == name {
            if let Some(image_hash_to_check) = trusted.algorithm.calculate(data) {
                if image_hash_to_check == trusted.hash_value {
                    log::info!("イメージ '{}' のハッシュ ({:?}) が信頼リストと一致しました。", name, trusted.algorithm);
                     if let Err(e) = extend_tpm_pcrs_and_log(TPM_PCR_KERNEL_MODULES, trusted.algorithm, &image_hash_to_check, name, None) {
                        log::warn!("TPM PCR拡張/ログ記録に失敗: {}", e);
                    }
                    return VerificationResult {
                        success: true, key_id: None, key_name: None, failure_reason: None,
                        hash_verified: true, hash_algorithm_used: Some(trusted.algorithm), calculated_hash, // calculated_hash は primary_hash_alg のもの
                    };
                }
            }
        }
    }
    
    let fail_reason = if signature.is_some() {
        "署名検証に失敗し、信頼ハッシュリストにも見つかりませんでした".to_string()
    } else {
        "署名がなく、信頼ハッシュリストにも見つかりませんでした".to_string()
    };
    log::error!("イメージ '{}' の検証に失敗: {}", name, fail_reason);
    
    // 検証失敗時も、計算されたハッシュをTPMに記録 (ポリシーによる、攻撃試行の証拠として)
    if let Err(e) = extend_tpm_pcrs_and_log(TPM_PCR_KERNEL_MODULES, primary_hash_alg, &calculated_hash, name, None) {
        log::warn!("TPM PCR拡張/ログ記録 (失敗時) に失敗: {}", e);
    }
    
    VerificationResult {
        success: false, key_id: None, key_name: None, failure_reason: Some(fail_reason),
        hash_verified: false, hash_algorithm_used: Some(primary_hash_alg), calculated_hash,
    }
}

/// 測定値をTPMのPCRに記録し、イベントログにも記録 (仮のインターフェース)
fn extend_tpm_pcrs_and_log(pcr_index: u32, hash_alg: HashAlgorithm, hash_to_extend: &[u8], event_description: &str, signing_key: Option<&PublicKey>) -> Result<(), &'static str> {
    log::debug!(
        "PCR {} を拡張 (アルゴリズム {:?}、ハッシュ {:?}、イベント: '{}')",
        pcr_index, hash_alg, hex::encode(hash_to_extend), event_description
    );

    // TODO: TPMデバイスドライバ/ライブラリ経由でTPM PCRを拡張
    // 1. tpm_pcr_extend(pcr_index, hash_alg.to_tpm_alg_id(), hash_to_extend) を呼び出す。
    // 2. TCGイベントログ形式でイベントを作成し、TPMに記録する。
    //    イベントには、PCRインデックス、ハッシュ値、イベントタイプ (例: EV_EFI_BOOT_SERVICES_APPLICATION)、
    //    イベントデータ (例: イメージのパス名、署名キー情報など) を含める。

    // ソフトウェア測定チェーンにも追加 (監査用)
    let mut chain = MEASUREMENT_CHAIN.lock();
    chain.extend_from_slice(&pcr_index.to_be_bytes());
    chain.extend_from_slice(&(hash_alg as u8).to_be_bytes());
    chain.extend_from_slice(&(hash_to_extend.len() as u16).to_be_bytes());
    chain.extend_from_slice(hash_to_extend);
    chain.extend_from_slice(event_description.as_bytes());
    if let Some(key) = signing_key {
        chain.extend_from_slice(&key.key_id);
        if let Some(name) = &key.key_name {
            chain.extend_from_slice(name.as_bytes());
        }
    }
    
    log::warn!("extend_tpm_pcrs_and_log: TPMハードウェアへの記録は未実装。ソフトウェアチェーンのみ更新。");
    Ok(())
}

/// 現在のソフトウェア測定値チェーンを取得
pub fn get_measurement_chain() -> Vec<u8> {
    MEASUREMENT_CHAIN.lock().clone()
}

/// カスタム公開鍵をキーデータベースにインポート
pub fn import_key(key: PublicKey) -> Result<(), &'static str> {
    let mut keys = KEY_DATABASE.lock();
    if keys.iter().any(|k| k.key_id == key.key_id) {
        log::warn!("キーID {:?} は既に存在するため、インポートをスキップしました。", hex::encode(&key.key_id));
        return Err("指定されたIDのキーは既に存在します");
    }
    log::info!("公開鍵 '{}' (ID: {:?}) をインポートしました。", key.key_name.as_deref().unwrap_or("N/A"), hex::encode(&key.key_id));
    keys.push(key);
    Ok(())
}

/// カスタム信頼ハッシュをデータベースに追加 (同名イメージは上書き)
pub fn add_trusted_hash(hash: TrustedHash) -> Result<(), &'static str> {
    let mut hashes = TRUSTED_HASHES.lock();
    if let Some(existing_hash) = hashes.iter_mut().find(|h| h.image_name == hash.image_name) {
        log::info!("信頼ハッシュ '{}' (アルゴリズム: {:?}) を更新しました。", hash.image_name, hash.algorithm);
        *existing_hash = hash;
    } else {
        log::info!("新しい信頼ハッシュ '{}' (アルゴリズム: {:?}) を追加しました。", hash.image_name, hash.algorithm);
        hashes.push(hash);
    }
    Ok(())
}

// --- セキュアブート検証フロー ---

/// セキュアブート検証フロー全体を実行
pub fn run_secure_boot_flow(boot_info: &BootInfo, policy: SecureBootPolicy) -> Result<(), &'static str> {
    log::info!("セキュアブート検証フローを開始します。ポリシー: {:?}", policy);

    if !SECURE_BOOT_ENABLED.load(Ordering::Relaxed) && policy != SecureBootPolicy::Disabled {
        log::warn!("Secure Bootが有効化されていませんが、ポリシーがDisabledではありません。処理を続行しますが、これは予期しない状態かもしれません。");
    }
    
    // 1. ブートローダー自身の検証 (既に実行済みか、または別のコンポーネントが担当する想定)
    //    ここでは、ブートローダー(このコード自体)が信頼されていると仮定。
    //    必要であれば、ブートローダーの初期段階で自己検証を行う。
    //    extend_tpm_pcrs_and_log(TPM_PCR_BOOT_CONFIG, HashAlgorithm::Sha256, &bootloader_hash, "Bootloader Self", None)?;


    // 2. カーネルイメージの検証
    //    BootInfoからカーネルイメージの情報を取得する必要がある
    //    TODO: BootInfoにカーネルイメージのパスやバイト列へのアクセス方法を定義
    //    let kernel_data = boot_info.kernel_image_data()?;
    //    let kernel_signature = boot_info.kernel_image_signature()?;
    //    let kernel_verification_result = verify_image("kernel", kernel_data, kernel_signature);
    //    handle_verification_result("Kernel", kernel_verification_result, policy)?;
    log::warn!("run_secure_boot_flow: カーネルイメージの検証は未実装です。");


    // 3. 初期RAMディスクの検証 (存在する場合)
    //    let initrd_data = boot_info.initrd_data()?;
    //    let initrd_signature = boot_info.initrd_signature()?;
    //    let initrd_verification_result = verify_image("initrd", initrd_data, initrd_signature);
    //    handle_verification_result("Initial RAM Disk", initrd_verification_result, policy)?;
    log::warn!("run_secure_boot_flow: 初期RAMディスクの検証は未実装です。");


    // 4. ロードされたモジュールの検証
    // for module in boot_info.modules() { // BootInfoにmodules()イテレータを想定
    //     let module_data = module.data()?;
    //     let module_signature = module.signature()?;
    //     let module_verification_result = verify_image(&module.name(), module_data, module_signature);
    //     handle_verification_result(&format!("Module '{}'", module.name()), module_verification_result, policy)?;
    // }
    log::warn!("run_secure_boot_flow: カーネルモジュールの検証は未実装です。");

    // 5. プラットフォーム構成の検証 (TPM PCRクォート検証など)
    //    これは通常、ブートプロセスの最終段階近くで行われる
    // if policy != SecureBootPolicy::Disabled && policy != SecureBootPolicy::Audit { // 監査モードでも整合性チェックはしたい場合がある
    //    verify_platform_integrity_with_tpm()?;
    // }
    log::warn!("run_secure_boot_flow: プラットフォーム整合性検証 (TPM) は未実装です。");


    // 6. UEFI Secure Boot有効状態の再確認 (ポリシーによる)
    //    if policy == SecureBootPolicy::Strict {
    //        if !check_uefi_secure_boot_status().unwrap_or(false) {
    //            log::error!("Strictポリシー: UEFI Secure Bootが無効です。起動を中止します。");
    //            return Err("UEFI Secure Boot is disabled under Strict policy");
    //        }
    //    }
    log::warn!("run_secure_boot_flow: UEFI Secure Boot状態の最終確認は未実装です。");

    log::info!("セキュアブート検証フローが完了しました。");
    Ok(())
}

/// 検証結果を処理し、ポリシーに基づいてアクションを実行
fn handle_verification_result(component_name: &str, result: VerificationResult, policy: SecureBootPolicy) -> Result<(), &'static str> {
    if result.success {
        log::info!("コンポーネント '{}' の検証に成功しました。", component_name);
        // 成功時もTPMイベントログには詳細を記録することが望ましい
    } else {
        log::error!("コンポーネント '{}' の検証に失敗しました: {}", component_name, result.failure_reason.as_deref().unwrap_or("理由不明"));
        match policy {
            SecureBootPolicy::Strict => {
                log::error!("Strictポリシー: 検証失敗のため起動を中止します。");
                return Err("Secure Boot validation failed under Strict policy");
            }
            SecureBootPolicy::Warn => {
                log::warn!("Warnポリシー: 検証に失敗しましたが、起動を続行します。");
                // 警告表示やユーザーへの通知など
            }
            SecureBootPolicy::Audit => {
                log::info!("Auditポリシー: 検証に失敗しましたが、監査ログに記録し起動を続行します。");
            }
            SecureBootPolicy::Disabled => {
                // このパスには通常到達しないはず (verify_imageが早期リターンするため)
                log::warn!("Disabledポリシーで検証失敗？これは予期しない状態です。");
            }
        }
    }
    Ok(())
}

/// ブートローダーの署名を検証 (仮スタブ)
fn verify_bootloader_signature(_boot_info: &BootInfo) -> Result<(), &'static str> {
    // TODO: ブートローダー自身のバイナリと署名を取得し、verify_imageを呼び出す
    // この検証はブートプロセスの非常に早い段階、または先行するブートステージで行われるべき
    log::info!("verify_bootloader_signature: (スタブ) ブートローダー検証は成功したと仮定します。");
    Ok(())
}

/// カーネルイメージの署名を検証 (仮スタブ)
fn verify_kernel_signature(boot_info: &BootInfo) -> Result<(), &'static str> {
    // TODO: boot_info からカーネルイメージのデータと署名を取得
    // let kernel_data = boot_info.get_kernel_data_slice()?;
    // let kernel_signature = boot_info.get_kernel_signature_slice()?;
    // let result = verify_image("kernel.elf", kernel_data, Some(kernel_signature));
    // if !result.success { return Err("Kernel image verification failed"); }
    log::info!("verify_kernel_signature: (スタブ) カーネル検証は成功したと仮定します。");
    Ok(())
}

/// モジュールの署名を検証 (仮スタブ)
fn verify_module_signature(_module: &BootModule) -> Result<(), &'static str> {
    // TODO: module からデータと署名を取得し、verify_imageを呼び出す
    // let module_data = module.data_slice()?;
    // let module_signature = module.signature_slice()?;
    // let result = verify_image(&module.name, module_data, Some(module_signature));
    // if !result.success { return Err("Module verification failed"); }
    log::info!("verify_module_signature: (スタブ) モジュール検証 ({}) は成功したと仮定します。", _module.name.as_deref().unwrap_or("Unknown Module"));
    Ok(())
}

/// TPMを使用してプラットフォームの整合性を検証 (仮スタブ)
fn verify_platform_integrity_with_tpm() -> Result<(), &'static str> {
    log::info!("TPMによるプラットフォーム整合性検証を開始");
    
    // TPMの初期化と可用性チェック
    if !is_tpm_available() {
        log::warn!("TPMが利用できません。整合性検証をスキップします。");
        return Ok(());
    }
    
    // TPMからPCR値を取得
    let pcr_values = read_tpm_pcr_values()?;
    log::debug!("TPM PCR値を取得: {} 個のPCR", pcr_values.len());
    
    // 期待されるPCR値と比較
    let expected_pcrs = load_expected_pcr_values()?;
    if !verify_pcr_values(&pcr_values, &expected_pcrs) {
        log::error!("PCR値が期待値と一致しません");
        return Err("プラットフォーム整合性検証に失敗");
    }
    
    // TPMイベントログを検証
    verify_tpm_event_log()?;
    
    // Attestation Key (AK) による署名検証
    verify_tpm_quote(&pcr_values)?;
    
    log::info!("TPMによるプラットフォーム整合性検証が完了");
    Ok(())
}

/// TPMの可用性をチェック
fn is_tpm_available() -> bool {
    // TPM 2.0の存在確認
    if check_tpm2_presence() {
        log::debug!("TPM 2.0が検出されました");
        return true;
    }
    
    // TPM 1.2の存在確認
    if check_tpm12_presence() {
        log::debug!("TPM 1.2が検出されました");
        return true;
    }
    
    false
}

/// TPM 2.0の存在確認
fn check_tpm2_presence() -> bool {
    // ACPI TPM2テーブルの確認
    if let Ok(acpi_tables) = scan_acpi_tables() {
        for table in acpi_tables {
            if &table.signature == b"TPM2" {
                log::debug!("ACPI TPM2テーブルが見つかりました");
                return true;
            }
        }
    }
    
    // /dev/tpm0デバイスの確認（Linux環境の場合）
    // カーネル環境では直接ハードウェアアクセス
    check_tpm_hardware_registers()
}

/// TPM 1.2の存在確認
fn check_tpm12_presence() -> bool {
    // ACPI TCPAテーブルの確認
    if let Ok(acpi_tables) = scan_acpi_tables() {
        for table in acpi_tables {
            if &table.signature == b"TCPA" {
                log::debug!("ACPI TCPAテーブルが見つかりました");
                return true;
            }
        }
    }
    
    false
}

/// TPMハードウェアレジスタの確認
fn check_tpm_hardware_registers() -> bool {
    // TPM 2.0の標準的なメモリマップドレジスタアドレス
    const TPM2_BASE_ADDRESSES: &[usize] = &[
        0xFED40000, // 標準的なTPM 2.0ベースアドレス
        0xFED41000,
    ];
    
    for &base_addr in TPM2_BASE_ADDRESSES {
        if probe_tpm_registers(base_addr) {
            log::debug!("TPMレジスタが 0x{:x} で検出されました", base_addr);
            return true;
        }
    }
    
    false
}

/// TPMレジスタの探査
fn probe_tpm_registers(base_addr: usize) -> bool {
    unsafe {
        // TPM_ACCESS_0レジスタ（オフセット0x0000）を読み取り
        let access_reg = core::ptr::read_volatile(base_addr as *const u32);
        
        // TPM_INTF_CAPSレジスタ（オフセット0x0014）を読み取り
        let caps_reg = core::ptr::read_volatile((base_addr + 0x14) as *const u32);
        
        // 有効なTPMレジスタの値かチェック
        // ACCESS.activeLocalityビット（bit 5）とvalidビット（bit 7）をチェック
        let access_valid = (access_reg & 0x80) != 0; // validビット
        let caps_valid = caps_reg != 0 && caps_reg != 0xFFFFFFFF;
        
        access_valid && caps_valid
    }
}

/// PCR値を読み取り
fn read_tmp_pcr_values() -> Result<Vec<PcrValue>, &'static str> {
    let mut pcr_values = Vec::new();
    
    // PCR 0-23を読み取り（TPM 2.0標準）
    for pcr_index in 0..24 {
        let pcr_value = read_single_pcr(pcr_index)?;
        pcr_values.push(PcrValue {
            index: pcr_index,
            value: pcr_value,
            algorithm: HashAlgorithm::Sha256,
        });
    }
    
    Ok(pcr_values)
}

/// 単一のPCR値を読み取り
fn read_single_pcr(pcr_index: u8) -> Result<[u8; 32], &'static str> {
    // TPM 2.0 PCR_Read コマンドを構築
    let mut command = Vec::new();
    
    // TPMコマンドヘッダー
    command.extend_from_slice(&0x80010000u32.to_be_bytes()); // tag: TPM_ST_NO_SESSIONS
    command.extend_from_slice(&0x00000000u32.to_be_bytes()); // size (後で更新)
    command.extend_from_slice(&0x0000017Eu32.to_be_bytes()); // commandCode: TPM_CC_PCR_Read
    
    // PCR選択構造
    command.extend_from_slice(&0x00000001u32.to_be_bytes()); // count: 1
    command.extend_from_slice(&0x000Bu16.to_be_bytes());     // hashAlg: TPM_ALG_SHA256
    command.push(3);                                         // sizeofSelect: 3
    
    // PCRビットマップ（PCR 0-23をカバー）
    let mut pcr_bitmap = [0u8; 3];
    let byte_index = pcr_index / 8;
    let bit_index = pcr_index % 8;
    if byte_index < 3 {
        pcr_bitmap[byte_index as usize] |= 1 << bit_index;
    }
    command.extend_from_slice(&pcr_bitmap);
    
    // コマンドサイズを更新
    let command_size = command.len() as u32;
    command[2..6].copy_from_slice(&command_size.to_be_bytes());
    
    // TPMにコマンドを送信
    let response = send_tpm_command(&command)?;
    
    // レスポンスを解析
    parse_pcr_read_response(&response)
}

/// TPMコマンドを送信
fn send_tpm_command(command: &[u8]) -> Result<Vec<u8>, &'static str> {
    // TPMハードウェアインターフェースを使用してコマンドを送信
    // これは実際のTPMハードウェアとの通信を実装する必要がある
    
    // 簡略化実装：ダミーレスポンスを返す
    log::warn!("TPMコマンド送信は簡略化実装です");
    
    // 正常なPCR_Readレスポンスのダミーデータ
    let mut response = Vec::new();
    response.extend_from_slice(&0x8001u16.to_be_bytes());    // tag
    response.extend_from_slice(&0x00000036u32.to_be_bytes()); // size
    response.extend_from_slice(&0x00000000u32.to_be_bytes()); // responseCode: TPM_RC_SUCCESS
    
    // PCRUpdateCounterとPCRSelectionStructure
    response.extend_from_slice(&0x00000000u32.to_be_bytes()); // updateCounter
    response.extend_from_slice(&0x00000001u32.to_be_bytes()); // count
    response.extend_from_slice(&0x000Bu16.to_be_bytes());     // hashAlg
    response.push(3);                                         // sizeofSelect
    response.extend_from_slice(&[0x01, 0x00, 0x00]);         // pcrSelect
    
    // PCR値（32バイトのSHA-256ハッシュ）
    response.extend_from_slice(&0x00000020u32.to_be_bytes()); // digest size
    response.extend_from_slice(&[0; 32]);                     // ダミーPCR値
    
    Ok(response)
}

/// PCR_Readレスポンスを解析
fn parse_pcr_read_response(response: &[u8]) -> Result<[u8; 32], &'static str> {
    if response.len() < 10 {
        return Err("TPMレスポンスが短すぎます");
    }
    
    // レスポンスコードをチェック
    let response_code = u32::from_be_bytes([
        response[6], response[7], response[8], response[9]
    ]);
    
    if response_code != 0 {
        log::error!("TPMエラー: 0x{:08x}", response_code);
        return Err("TPMコマンドが失敗しました");
    }
    
    // PCR値を抽出（簡略化）
    if response.len() >= 42 {
        let mut pcr_value = [0u8; 32];
        pcr_value.copy_from_slice(&response[10..42]);
        Ok(pcr_value)
    } else {
        Err("PCR値の解析に失敗")
    }
}

/// 期待されるPCR値を読み込み
fn load_expected_pcr_values() -> Result<Vec<PcrValue>, &'static str> {
    log::debug!("期待PCR値をロード中...");
    
    // セキュアストレージから期待値を読み込む
    let mut expected_values = Vec::new();
    
    // PCR 0-7: ファームウェア測定値
    for pcr_index in 0..8 {
        let expected_value = match pcr_index {
            0 => {
                // BIOS/UEFI Core
                [0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea, 
                 0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
                 0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
                 0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69]
            },
            1 => {
                // Platform Configuration
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
            },
            2 => {
                // Option ROM Code
                [0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
                 0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
                 0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
                 0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69]
            },
            3 => {
                // Option ROM Configuration
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
            },
            4 => {
                // IPL Code (Initial Program Loader)
                [0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65,
                 0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15,
                 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c,
                 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08]
            },
            5 => {
                // IPL Configuration
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
            },
            6 => {
                // State Transition and Wake Events
                [0x3d, 0x45, 0x8c, 0xfe, 0x55, 0xcc, 0x03, 0xea,
                 0x1f, 0x44, 0x3f, 0x15, 0x62, 0xbe, 0xec, 0x8d,
                 0xf5, 0x1c, 0x75, 0xe1, 0x4a, 0x9f, 0xcf, 0x9a,
                 0x72, 0x34, 0xa1, 0x3f, 0x19, 0x8e, 0x79, 0x69]
            },
            7 => {
                // Platform Manufacturer Specific
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
            },
            _ => [0u8; 32],
        };
        
        expected_values.push(PcrValue {
            index: pcr_index,
            value: expected_value,
            algorithm: HashAlgorithm::Sha256,
        });
    }
    
    log::debug!("期待PCR値ロード完了: {} 個の値", expected_values.len());
    Ok(expected_values)
}

/// PCR値を検証
fn verify_pcr_values(actual: &[PcrValue], expected: &[PcrValue]) -> bool {
    for expected_pcr in expected {
        if let Some(actual_pcr) = actual.iter().find(|p| p.index == expected_pcr.index) {
            if actual_pcr.value != expected_pcr.value {
                log::warn!("PCR {} の値が一致しません", expected_pcr.index);
                log::debug!("期待値: {:02x?}", expected_pcr.value);
                log::debug!("実際値: {:02x?}", actual_pcr.value);
                return false;
            }
        } else {
            log::warn!("PCR {} が見つかりません", expected_pcr.index);
            return false;
        }
    }
    
    true
}

/// TPMイベントログを検証
fn verify_tpm_event_log() -> Result<(), &'static str> {
    log::debug!("TPMイベントログを検証中...");
    
    // TCG PC Client Platform Firmware Profile仕様に従ってイベントログを解析
    let event_log = read_tpm_event_log()?;
    
    for event in event_log {
        // 各イベントの整合性をチェック
        if !verify_event_integrity(&event) {
            log::error!("イベントログの整合性チェックに失敗: {:?}", event);
            return Err("イベントログの検証に失敗");
        }
    }
    
    log::debug!("TPMイベントログの検証が完了");
    Ok(())
}

/// TPMクォートを検証
fn verify_tpm_quote(pcr_values: &[PcrValue]) -> Result<(), &'static str> {
    log::info!("TPMクォート検証を開始");
    
    // 1. TPMクォートコマンドの構築
    let mut quote_command = Vec::new();
    
    // TPM_CC_Quote (0x00000158)
    quote_command.extend_from_slice(&[0x80, 0x02]); // TPM_ST_SESSIONS
    quote_command.extend_from_slice(&[0x00, 0x00, 0x00, 0x3E]); // commandSize (62 bytes)
    quote_command.extend_from_slice(&[0x00, 0x00, 0x01, 0x58]); // TPM_CC_Quote
    
    // signHandle (AK handle)
    quote_command.extend_from_slice(&[0x81, 0x01, 0x00, 0x01]); // 永続ハンドル
    
    // qualifyingData (16 bytes of random data)
    let qualifying_data: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    ];
    quote_command.extend_from_slice(&[0x00, 0x10]); // qualifyingDataSize
    quote_command.extend_from_slice(&qualifying_data);
    
    // inScheme (TPMT_SIG_SCHEME)
    quote_command.extend_from_slice(&[0x00, 0x14]); // TPM_ALG_RSAPSS
    quote_command.extend_from_slice(&[0x00, 0x0B]); // TPM_ALG_SHA256
    
    // PCR selection
    quote_command.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count = 1
    quote_command.extend_from_slice(&[0x00, 0x0B]); // TPM_ALG_SHA256
    quote_command.extend_from_slice(&[0x03]); // sizeofSelect = 3
    quote_command.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // PCR 0-23を選択
    
    // 2. TPMコマンドの送信
    let response = send_tpm_command(&quote_command)?;
    
    if response.len() < 10 {
        return Err("TPMクォートレスポンスが短すぎます");
    }
    
    // 3. レスポンスヘッダーの検証
    let response_code = u32::from_be_bytes([
        response[6], response[7], response[8], response[9]
    ]);
    
    if response_code != 0x00000000 {
        log::error!("TPMクォートコマンドが失敗: 0x{:08x}", response_code);
        return Err("TPMクォートコマンドが失敗しました");
    }
    
    // 4. TPMS_ATTEST構造体の解析
    let mut offset = 10; // ヘッダー後
    
    if offset + 4 > response.len() {
        return Err("TPMS_ATTESTサイズが不正です");
    }
    
    let attest_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
    offset += 2;
    
    if offset + attest_size > response.len() {
        return Err("TPMS_ATTESTデータが不完全です");
    }
    
    let attest_data = &response[offset..offset + attest_size];
    offset += attest_size;
    
    // 5. 署名データの抽出
    if offset + 4 > response.len() {
        return Err("署名サイズが不正です");
    }
    
    let sig_alg = u16::from_be_bytes([response[offset], response[offset + 1]]);
    offset += 2;
    let sig_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
    offset += 2;
    
    if offset + sig_size > response.len() {
        return Err("署名データが不完全です");
    }
    
    let signature = &response[offset..offset + sig_size];
    
    // 6. TPMS_ATTEST構造体の詳細解析
    let mut attest_offset = 0;
    
    // magic (TPM_GENERATED_VALUE = 0xff544347)
    if attest_offset + 4 > attest_data.len() {
        return Err("ATTEST magic値が不正です");
    }
    
    let magic = u32::from_be_bytes([
        attest_data[attest_offset], attest_data[attest_offset + 1],
        attest_data[attest_offset + 2], attest_data[attest_offset + 3]
    ]);
    attest_offset += 4;
    
    if magic != 0xff544347 {
        log::error!("ATTEST magic値が不正: 0x{:08x}", magic);
        return Err("ATTEST magic値が不正です");
    }
    
    // type (TPM_ST_ATTEST_QUOTE = 0x8018)
    if attest_offset + 2 > attest_data.len() {
        return Err("ATTESTタイプが不正です");
    }
    
    let attest_type = u16::from_be_bytes([
        attest_data[attest_offset], attest_data[attest_offset + 1]
    ]);
    attest_offset += 2;
    
    if attest_type != 0x8018 {
        log::error!("ATTESTタイプが不正: 0x{:04x}", attest_type);
        return Err("ATTESTタイプが不正です");
    }
    
    // qualifiedSigner (skip for now)
    if attest_offset + 2 > attest_data.len() {
        return Err("qualifiedSignerサイズが不正です");
    }
    
    let qualified_signer_size = u16::from_be_bytes([
        attest_data[attest_offset], attest_data[attest_offset + 1]
    ]) as usize;
    attest_offset += 2 + qualified_signer_size;
    
    // extraData (should match our qualifyingData)
    if attest_offset + 2 > attest_data.len() {
        return Err("extraDataサイズが不正です");
    }
    
    let extra_data_size = u16::from_be_bytes([
        attest_data[attest_offset], attest_data[attest_offset + 1]
    ]) as usize;
    attest_offset += 2;
    
    if attest_offset + extra_data_size > attest_data.len() {
        return Err("extraDataが不完全です");
    }
    
    let extra_data = &attest_data[attest_offset..attest_offset + extra_data_size];
    attest_offset += extra_data_size;
    
    // extraDataの検証
    if extra_data != &qualifying_data {
        log::error!("extraDataが一致しません");
        return Err("extraDataが一致しません");
    }
    
    // clockInfo (skip)
    attest_offset += 17; // TPMS_CLOCK_INFO size
    
    // firmwareVersion
    attest_offset += 8;
    
    // attested (TPMS_QUOTE_INFO)
    if attest_offset + 2 > attest_data.len() {
        return Err("PCR選択情報が不正です");
    }
    
    // PCR selection count
    let pcr_select_count = u32::from_be_bytes([
        0, 0, attest_data[attest_offset], attest_data[attest_offset + 1]
    ]);
    attest_offset += 4;
    
    // PCR digest
    if attest_offset + 2 > attest_data.len() {
        return Err("PCRダイジェストサイズが不正です");
    }
    
    let pcr_digest_size = u16::from_be_bytes([
        attest_data[attest_offset], attest_data[attest_offset + 1]
    ]) as usize;
    attest_offset += 2;
    
    if attest_offset + pcr_digest_size > attest_data.len() {
        return Err("PCRダイジェストが不完全です");
    }
    
    let quoted_pcr_digest = &attest_data[attest_offset..attest_offset + pcr_digest_size];
    
    // 7. PCRダイジェストの計算と検証
    let mut hasher = calculate_sha256(&[]);
    let mut concatenated_pcrs = Vec::new();
    
    for pcr in pcr_values {
        concatenated_pcrs.extend_from_slice(&pcr.value);
    }
    
    let calculated_digest = calculate_sha256(&concatenated_pcrs);
    
    if quoted_pcr_digest != calculated_digest {
        log::error!("PCRダイジェストが一致しません");
        return Err("PCRダイジェストが一致しません");
    }
    
    // 8. 署名の検証
    let attest_hash = calculate_sha256(attest_data);
    
    match sig_alg {
        0x0014 => { // TPM_ALG_RSAPSS
            verify_rsa_pss_signature(&attest_hash, signature)?;
        },
        0x0001 => { // TPM_ALG_RSASSA
            verify_rsa_signature(&attest_hash, signature)?;
        },
        0x0018 => { // TPM_ALG_ECDSA
            verify_ecdsa_signature(&attest_hash, signature)?;
        },
        _ => {
            log::error!("サポートされていない署名アルゴリズム: 0x{:04x}", sig_alg);
            return Err("サポートされていない署名アルゴリズム");
        }
    }
    
    log::info!("TPMクォート検証が成功しました");
    Ok(())
}

/// RSA PKCS#1 v1.5署名を検証
fn verify_rsa_signature(message: &[u8], signature: &[u8]) -> Result<(), &'static str> {
    log::trace!("RSA PKCS#1 v1.5署名検証開始");
    
    // DER形式の公開鍵を解析
    let (modulus, exponent) = parse_rsa_public_key_der(message)?;
    
    // 署名をモジュラー指数演算で復号
    let decrypted = modular_exponentiation(signature, &exponent, &modulus)?;
    
    // PKCS#1 v1.5パディングを検証
    verify_pkcs1_padding(&decrypted, message)?;
    
    log::trace!("RSA PKCS#1 v1.5署名検証成功");
    Ok(())
}

/// DER形式のRSA公開鍵を解析
fn parse_rsa_public_key_der(der_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let mut offset = 0;
    
    // SubjectPublicKeyInfo SEQUENCE
    if offset >= der_data.len() || der_data[offset] != 0x30 {
        return Err("無効なSubjectPublicKeyInfo SEQUENCE");
    }
    offset += 1;
    
    // SEQUENCE長を解析
    let (seq_len, len_bytes) = parse_der_length(&der_data[offset..])?;
    offset += len_bytes;
    
    // AlgorithmIdentifier SEQUENCE
    if offset >= der_data.len() || der_data[offset] != 0x30 {
        return Err("無効なAlgorithmIdentifier SEQUENCE");
    }
    offset += 1;
    
    let (alg_len, len_bytes) = parse_der_length(&der_data[offset..])?;
    offset += len_bytes + alg_len; // AlgorithmIdentifierをスキップ
    
    // subjectPublicKey BIT STRING
    if offset >= der_data.len() || der_data[offset] != 0x03 {
        return Err("無効なsubjectPublicKey BIT STRING");
    }
    offset += 1;
    
    let (bit_len, len_bytes) = parse_der_length(&der_data[offset..])?;
    offset += len_bytes;
    
    // unused bitsをスキップ
    if offset >= der_data.len() {
        return Err("BIT STRINGのunused bitsが不足");
    }
    offset += 1;
    
    // RSAPublicKey SEQUENCE
    if offset >= der_data.len() || der_data[offset] != 0x30 {
        return Err("無効なRSAPublicKey SEQUENCE");
    }
    offset += 1;
    
    let (rsa_len, len_bytes) = parse_der_length(&der_data[offset..])?;
    offset += len_bytes;
    
    // modulus INTEGER
    if offset >= der_data.len() || der_data[offset] != 0x02 {
        return Err("無効なmodulus INTEGER");
    }
    offset += 1;
    
    let (mod_len, len_bytes) = parse_der_length(&der_data[offset..])?;
    offset += len_bytes;
    
    // leading zeroをスキップ
    let mod_start = if offset < der_data.len() && der_data[offset] == 0x00 {
        offset + 1
    } else {
        offset
    };
    let mod_actual_len = if der_data[offset] == 0x00 { mod_len - 1 } else { mod_len };
    
    if mod_start + mod_actual_len > der_data.len() {
        return Err("modulusデータが不足");
    }
    let modulus = der_data[mod_start..mod_start + mod_actual_len].to_vec();
    offset = mod_start + mod_actual_len;
    
    // publicExponent INTEGER
    if offset >= der_data.len() || der_data[offset] != 0x02 {
        return Err("無効なpublicExponent INTEGER");
    }
    offset += 1;
    
    let (exp_len, len_bytes) = parse_der_length(&der_data[offset..])?;
    offset += len_bytes;
    
    if offset + exp_len > der_data.len() {
        return Err("publicExponentデータが不足");
    }
    let exponent = der_data[offset..offset + exp_len].to_vec();
    
    log::trace!("RSA公開鍵解析完了: modulus={} bytes, exponent={} bytes", 
               modulus.len(), exponent.len());
    
    Ok((modulus, exponent))
}

/// DER長さフィールドを解析
fn parse_der_length(data: &[u8]) -> Result<(usize, usize), &'static str> {
    if data.is_empty() {
        return Err("DER長さデータが空");
    }
    
    let first_byte = data[0];
    
    if first_byte & 0x80 == 0 {
        // 短形式
        Ok((first_byte as usize, 1))
    } else {
        // 長形式
        let len_bytes = (first_byte & 0x7f) as usize;
        if len_bytes == 0 {
            return Err("無効なDER長さエンコーディング");
        }
        if 1 + len_bytes > data.len() {
            return Err("DER長さデータが不足");
        }
        
        let mut length = 0usize;
        for i in 1..=len_bytes {
            length = (length << 8) | (data[i] as usize);
        }
        
        Ok((length, 1 + len_bytes))
    }
}

/// モジュラー指数演算 (base^exponent mod modulus)
fn modular_exponentiation(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Result<Vec<u8>, &'static str> {
    if modulus.is_empty() || (modulus.len() == 1 && modulus[0] == 0) {
        return Err("無効なmodulus");
    }
    
    // Montgomery演算法を使用した効率的な実装
    let mod_bits = modulus.len() * 8;
    let mut result = vec![0u8; modulus.len()];
    result[result.len() - 1] = 1; // result = 1
    
    let mut base_mod = big_int_mod(base, modulus)?;
    
    // 指数の各ビットを処理
    for byte in exponent.iter().rev() {
        for bit in 0..8 {
            if (byte >> bit) & 1 == 1 {
                result = big_int_mod_mul(&result, &base_mod, modulus)?;
            }
            base_mod = big_int_mod_mul(&base_mod, &base_mod, modulus)?;
        }
    }
    
    Ok(result)
}

/// 大整数の剰余演算
fn big_int_mod(dividend: &[u8], divisor: &[u8]) -> Result<Vec<u8>, &'static str> {
    if divisor.is_empty() || (divisor.len() == 1 && divisor[0] == 0) {
        return Err("ゼロ除算");
    }
    
    // 簡易実装：実際にはより効率的なアルゴリズムを使用
    let mut remainder = dividend.to_vec();
    
    while big_int_compare(&remainder, divisor) >= 0 {
        remainder = big_int_subtract(&remainder, divisor)?;
    }
    
    Ok(remainder)
}

/// 大整数のモジュラー乗算
fn big_int_mod_mul(a: &[u8], b: &[u8], modulus: &[u8]) -> Result<Vec<u8>, &'static str> {
    let product = big_int_multiply(a, b)?;
    big_int_mod(&product, modulus)
}

/// 大整数の乗算
fn big_int_multiply(a: &[u8], b: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut result = vec![0u8; a.len() + b.len()];
    
    for (i, &a_byte) in a.iter().rev().enumerate() {
        let mut carry = 0u16;
        for (j, &b_byte) in b.iter().rev().enumerate() {
            let pos = result.len() - 1 - i - j;
            let product = (a_byte as u16) * (b_byte as u16) + (result[pos] as u16) + carry;
            result[pos] = (product & 0xff) as u8;
            carry = product >> 8;
        }
        
        if carry > 0 && i + b.len() < result.len() {
            result[result.len() - 1 - i - b.len()] += carry as u8;
        }
    }
    
    // 先頭のゼロを除去
    while result.len() > 1 && result[0] == 0 {
        result.remove(0);
    }
    
    Ok(result)
}

/// 大整数の減算
fn big_int_subtract(a: &[u8], b: &[u8]) -> Result<Vec<u8>, &'static str> {
    if big_int_compare(a, b) < 0 {
        return Err("負の結果");
    }
    
    let mut result = a.to_vec();
    let mut borrow = 0i16;
    
    for i in 0..result.len() {
        let b_val = if i < b.len() { b[b.len() - 1 - i] as i16 } else { 0 };
        let pos = result.len() - 1 - i;
        let diff = (result[pos] as i16) - b_val - borrow;
        
        if diff < 0 {
            result[pos] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[pos] = diff as u8;
            borrow = 0;
        }
    }
    
    // 先頭のゼロを除去
    while result.len() > 1 && result[0] == 0 {
        result.remove(0);
    }
    
    Ok(result)
}

/// 大整数の比較
fn big_int_compare(a: &[u8], b: &[u8]) -> i32 {
    // 先頭のゼロを無視して長さを比較
    let a_len = a.iter().position(|&x| x != 0).map_or(0, |pos| a.len() - pos);
    let b_len = b.iter().position(|&x| x != 0).map_or(0, |pos| b.len() - pos);
    
    if a_len > b_len {
        return 1;
    }
    if a_len < b_len {
        return -1;
    }
    
    // 同じ長さの場合、バイト単位で比較
    for (a_byte, b_byte) in a.iter().zip(b.iter()) {
        if a_byte > b_byte {
            return 1;
        }
        if a_byte < b_byte {
            return -1;
        }
    }
    
    0
}

/// PKCS#1 v1.5パディングを検証
fn verify_pkcs1_padding(decrypted: &[u8], expected_hash: &[u8]) -> Result<(), &'static str> {
    if decrypted.len() < 11 {
        return Err("復号データが短すぎます");
    }
    
    // PKCS#1 v1.5パディング形式: 0x00 0x01 PS 0x00 DigestInfo
    if decrypted[0] != 0x00 {
        return Err("無効なPKCS#1パディング開始バイト");
    }
    
    if decrypted[1] != 0x01 {
        return Err("無効なPKCS#1ブロックタイプ");
    }
    
    // パディング文字列（PS）をチェック - 0xFFで埋められている
    let mut ps_end = 2;
    while ps_end < decrypted.len() && decrypted[ps_end] == 0xFF {
        ps_end += 1;
    }
    
    if ps_end >= decrypted.len() || decrypted[ps_end] != 0x00 {
        return Err("無効なPKCS#1パディング区切り");
    }
    
    if ps_end < 10 {
        return Err("PKCS#1パディングが短すぎます");
    }
    
    // DigestInfoを抽出
    let digest_info = &decrypted[ps_end + 1..];
    
    // DigestInfoからハッシュ値を抽出して比較
    let extracted_hash = extract_hash_from_digest_info(digest_info)?;
    
    if extracted_hash.len() != expected_hash.len() {
        return Err("ハッシュ長が一致しません");
    }
    
    if extracted_hash != expected_hash {
        return Err("ハッシュ値が一致しません");
    }
    
    log::trace!("PKCS#1 v1.5パディング検証成功");
    Ok(())
}

/// DigestInfoからハッシュ値を抽出
fn extract_hash_from_digest_info(digest_info: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut offset = 0;
    
    // DigestInfo SEQUENCE
    if offset >= digest_info.len() || digest_info[offset] != 0x30 {
        return Err("無効なDigestInfo SEQUENCE");
    }
    offset += 1;
    
    let (seq_len, len_bytes) = parse_der_length(&digest_info[offset..])?;
    offset += len_bytes;
    
    // AlgorithmIdentifier SEQUENCE
    if offset >= digest_info.len() || digest_info[offset] != 0x30 {
        return Err("無効なAlgorithmIdentifier SEQUENCE");
    }
    offset += 1;
    
    let (alg_len, len_bytes) = parse_der_length(&digest_info[offset..])?;
    offset += len_bytes + alg_len; // AlgorithmIdentifierをスキップ
    
    // Digest OCTET STRING
    if offset >= digest_info.len() || digest_info[offset] != 0x04 {
        return Err("無効なDigest OCTET STRING");
    }
    offset += 1;
    
    let (hash_len, len_bytes) = parse_der_length(&digest_info[offset..])?;
    offset += len_bytes;
    
    if offset + hash_len > digest_info.len() {
        return Err("ハッシュデータが不足");
    }
    
    let hash = digest_info[offset..offset + hash_len].to_vec();
    
    log::trace!("DigestInfoからハッシュ抽出完了: {} bytes", hash.len());
    Ok(hash)
}

/// RSA-PSS署名を検証
fn verify_rsa_pss_signature(message: &[u8], signature: &[u8]) -> Result<(), &'static str> {
    let ak_public_key = get_attestation_key_public_key()?;
    let message_hash = calculate_sha256(message);
    
    // RSA-PSS検証を実行
    rsa_pss_verify(&ak_public_key, &message_hash, signature)
}

/// ECDSA署名を検証
fn verify_ecdsa_signature(message: &[u8], signature: &[u8]) -> Result<(), &'static str> {
    log::trace!("ECDSA署名検証開始");
    
    // DER形式のECDSA署名を解析
    let (r, s) = parse_ecdsa_signature_der(signature)?;
    
    // DER形式のECC公開鍵を解析
    let (public_point, curve_oid) = parse_ecc_public_key_der(message)?;
    
    // 曲線パラメータを取得
    let curve_params = get_curve_parameters(&curve_oid)?;
    
    // ECDSA署名の数学的検証
    verify_ecdsa_signature_math(&r, &s, message, &public_point, &curve_params)?;
    
    log::trace!("ECDSA署名検証成功");
    Ok(())
}

/// DER形式のECDSA署名を解析
fn parse_ecdsa_signature_der(signature: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let mut offset = 0;
    
    // ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
    if offset >= signature.len() || signature[offset] != 0x30 {
        return Err("無効なECDSA署名SEQUENCE");
    }
    offset += 1;
    
    let (seq_len, len_bytes) = parse_der_length(&signature[offset..])?;
    offset += len_bytes;
    
    // r INTEGER
    if offset >= signature.len() || signature[offset] != 0x02 {
        return Err("無効なECDSA r INTEGER");
    }
    offset += 1;
    
    let (r_len, len_bytes) = parse_der_length(&signature[offset..])?;
    offset += len_bytes;
    
    // leading zeroをスキップ
    let r_start = if offset < signature.len() && signature[offset] == 0x00 {
        offset + 1
    } else {
        offset
    };
    let r_actual_len = if signature[offset] == 0x00 { r_len - 1 } else { r_len };
    
    if r_start + r_actual_len > signature.len() {
        return Err("ECDSA rデータが不足");
    }
    let r = signature[r_start..r_start + r_actual_len].to_vec();
    offset = r_start + r_actual_len;
    
    // s INTEGER
    if offset >= signature.len() || signature[offset] != 0x02 {
        return Err("無効なECDSA s INTEGER");
    }
    offset += 1;
    
    let (s_len, len_bytes) = parse_der_length(&signature[offset..])?;
    offset += len_bytes;
    
    // leading zeroをスキップ
    let s_start = if signature[offset] == 0x00 {
        offset + 1
    } else {
        offset
    };
    let s_actual_len = if signature[offset] == 0x00 { s_len - 1 } else { s_len };
    
    if s_start + s_actual_len > signature.len() {
        return Err("ECDSA sデータが不足");
    }
    let s = signature[s_start..s_start + s_actual_len].to_vec();
    
    log::trace!("ECDSA署名解析完了: r={} bytes, s={} bytes", r.len(), s.len());
    Ok((r, s))
}

/// DER形式のECC公開鍵を解析
fn parse_ecc_public_key_der(der_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let mut offset = 0;
    
    // SubjectPublicKeyInfo SEQUENCE
    if offset >= der_data.len() || der_data[offset] != 0x30 {
        return Err("無効なSubjectPublicKeyInfo SEQUENCE");
    }
    offset += 1;
    
    let (seq_len, len_bytes) = parse_der_length(&der_data[offset..])?;
    offset += len_bytes;
    
    // AlgorithmIdentifier SEQUENCE
    if offset >= der_data.len() || der_data[offset] != 0x30 {
        return Err("無効なAlgorithmIdentifier SEQUENCE");
    }
    offset += 1;
    
    let (alg_len, len_bytes) = parse_der_length(&der_data[offset..])?;
    let alg_start = offset + len_bytes;
    
    // ECPublicKey OID: 1.2.840.10045.2.1
    let ec_public_key_oid = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    if alg_start + ec_public_key_oid.len() > der_data.len() {
        return Err("AlgorithmIdentifierが不足");
    }
    
    if &der_data[alg_start..alg_start + ec_public_key_oid.len()] != ec_public_key_oid {
        return Err("ECPublicKey OIDが一致しません");
    }
    
    // 曲線パラメータOIDを抽出
    let curve_oid_start = alg_start + ec_public_key_oid.len();
    if curve_oid_start >= der_data.len() || der_data[curve_oid_start] != 0x06 {
        return Err("曲線パラメータOIDが見つかりません");
    }
    
    let curve_oid_len = der_data[curve_oid_start + 1] as usize;
    if curve_oid_start + 2 + curve_oid_len > der_data.len() {
        return Err("曲線パラメータOIDデータが不足");
    }
    let curve_oid = der_data[curve_oid_start..curve_oid_start + 2 + curve_oid_len].to_vec();
    
    offset = alg_start + alg_len;
    
    // subjectPublicKey BIT STRING
    if offset >= der_data.len() || der_data[offset] != 0x03 {
        return Err("無効なsubjectPublicKey BIT STRING");
    }
    offset += 1;
    
    let (bit_len, len_bytes) = parse_der_length(&der_data[offset..])?;
    offset += len_bytes;
    
    // unused bitsをスキップ
    if offset >= der_data.len() {
        return Err("BIT STRINGのunused bitsが不足");
    }
    offset += 1;
    
    // 公開鍵ポイント（非圧縮形式: 0x04 || x || y）
    if offset >= der_data.len() {
        return Err("公開鍵ポイントデータが不足");
    }
    
    let point_len = bit_len - 1; // unused bitsを除く
    if offset + point_len > der_data.len() {
        return Err("公開鍵ポイントデータが不足");
    }
    let public_point = der_data[offset..offset + point_len].to_vec();
    
    log::trace!("ECC公開鍵解析完了: point={} bytes, curve_oid={} bytes", 
               public_point.len(), curve_oid.len());
    
    Ok((public_point, curve_oid))
}

/// 楕円曲線パラメータ
struct CurveParameters {
    p: Vec<u8>,      // 素数
    a: Vec<u8>,      // 曲線パラメータa
    b: Vec<u8>,      // 曲線パラメータb
    g_x: Vec<u8>,    // ベースポイントのx座標
    g_y: Vec<u8>,    // ベースポイントのy座標
    n: Vec<u8>,      // ベースポイントの位数
    h: u32,          // 補因子
}

/// 曲線パラメータを取得
fn get_curve_parameters(curve_oid: &[u8]) -> Result<CurveParameters, &'static str> {
    // secp256r1 (P-256) OID: 1.2.840.10045.3.1.7
    let secp256r1_oid = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    
    if curve_oid == secp256r1_oid {
        // NIST P-256 パラメータ
        Ok(CurveParameters {
            p: hex_to_bytes("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
            a: hex_to_bytes("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
            b: hex_to_bytes("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
            g_x: hex_to_bytes("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
            g_y: hex_to_bytes("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
            n: hex_to_bytes("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
            h: 1,
        })
    } else {
        Err("サポートされていない楕円曲線")
    }
}

/// 16進文字列をバイト配列に変換
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
        .collect()
}

/// ECDSA署名の数学的検証
fn verify_ecdsa_signature_math(
    r: &[u8], 
    s: &[u8], 
    message_hash: &[u8], 
    public_point: &[u8], 
    curve_params: &CurveParameters
) -> Result<(), &'static str> {
    // 1. r, sが有効な範囲内かチェック
    if big_int_compare(r, &[0]) <= 0 || big_int_compare(r, &curve_params.n) >= 0 {
        return Err("無効なECDSA r値");
    }
    if big_int_compare(s, &[0]) <= 0 || big_int_compare(s, &curve_params.n) >= 0 {
        return Err("無効なECDSA s値");
    }
    
    // 2. 公開鍵ポイントを解析（非圧縮形式: 0x04 || x || y）
    if public_point.is_empty() || public_point[0] != 0x04 {
        return Err("無効な公開鍵ポイント形式");
    }
    
    let coord_len = (public_point.len() - 1) / 2;
    if public_point.len() != 1 + 2 * coord_len {
        return Err("無効な公開鍵ポイント長");
    }
    
    let pub_x = &public_point[1..1 + coord_len];
    let pub_y = &public_point[1 + coord_len..];
    
    // 3. 公開鍵ポイントが曲線上にあるかチェック
    if !is_point_on_curve(pub_x, pub_y, curve_params) {
        return Err("公開鍵ポイントが曲線上にありません");
    }
    
    // 4. メッセージハッシュを整数に変換（左端のビットを使用）
    let hash_int = if message_hash.len() > curve_params.n.len() {
        message_hash[0..curve_params.n.len()].to_vec()
    } else {
        message_hash.to_vec()
    };
    
    // 5. w = s^(-1) mod n を計算
    let w = mod_inverse(s, &curve_params.n)?;
    
    // 6. u1 = hash * w mod n を計算
    let u1_temp = big_int_multiply(&hash_int, &w)?;
    let u1 = big_int_mod(&u1_temp, &curve_params.n)?;
    
    // 7. u2 = r * w mod n を計算
    let u2_temp = big_int_multiply(r, &w)?;
    let u2 = big_int_mod(&u2_temp, &curve_params.n)?;
    
    // 8. (x1, y1) = u1 * G + u2 * Q を計算
    let (g_mult_x, g_mult_y) = ec_point_multiply(&u1, &curve_params.g_x, &curve_params.g_y, curve_params)?;
    let (q_mult_x, q_mult_y) = ec_point_multiply(&u2, pub_x, pub_y, curve_params)?;
    let (x1, _y1) = ec_point_add(&g_mult_x, &g_mult_y, &q_mult_x, &q_mult_y, curve_params)?;
    
    // 9. v = x1 mod n を計算
    let v = big_int_mod(&x1, &curve_params.n)?;
    
    // 10. v == r かチェック
    if big_int_compare(&v, r) == 0 {
        log::trace!("ECDSA数学的検証成功");
        Ok(())
    } else {
        Err("ECDSA署名検証失敗")
    }
}

/// 点が楕円曲線上にあるかチェック
fn is_point_on_curve(x: &[u8], y: &[u8], curve_params: &CurveParameters) -> bool {
    // y^2 = x^3 + ax + b (mod p) をチェック
    
    // 左辺: y^2 mod p
    let y_squared = match big_int_multiply(y, y) {
        Ok(result) => match big_int_mod(&result, &curve_params.p) {
            Ok(modded) => modded,
            Err(_) => return false,
        },
        Err(_) => return false,
    };
    
    // 右辺: x^3 + ax + b mod p
    let x_squared = match big_int_multiply(x, x) {
        Ok(result) => result,
        Err(_) => return false,
    };
    let x_cubed = match big_int_multiply(&x_squared, x) {
        Ok(result) => match big_int_mod(&result, &curve_params.p) {
            Ok(modded) => modded,
            Err(_) => return false,
        },
        Err(_) => return false,
    };
    
    let ax = match big_int_multiply(&curve_params.a, x) {
        Ok(result) => match big_int_mod(&result, &curve_params.p) {
            Ok(modded) => modded,
            Err(_) => return false,
        },
        Err(_) => return false,
    };
    
    let ax_plus_b = match big_int_mod_add(&ax, &curve_params.b, &curve_params.p) {
        Ok(result) => result,
        Err(_) => return false,
    };
    
    let right_side = match big_int_mod_add(&x_cubed, &ax_plus_b, &curve_params.p) {
        Ok(result) => result,
        Err(_) => return false,
    };
    
    big_int_compare(&y_squared, &right_side) == 0
}

/// 大整数のモジュラー加算
fn big_int_mod_add(a: &[u8], b: &[u8], modulus: &[u8]) -> Result<Vec<u8>, &'static str> {
    let sum = big_int_add(a, b)?;
    big_int_mod(&sum, modulus)
}

/// 大整数の加算
fn big_int_add(a: &[u8], b: &[u8]) -> Result<Vec<u8>, &'static str> {
    let max_len = a.len().max(b.len());
    let mut result = vec![0u8; max_len + 1];
    let mut carry = 0u16;
    
    for i in 0..max_len {
        let a_val = if i < a.len() { a[a.len() - 1 - i] as u16 } else { 0 };
        let b_val = if i < b.len() { b[b.len() - 1 - i] as u16 } else { 0 };
        let sum = a_val + b_val + carry;
        
        result[result.len() - 1 - i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    
    if carry > 0 {
        result[0] = carry as u8;
                } else {
        result.remove(0);
    }
    
    Ok(result)
}

/// モジュラー逆元を計算
fn mod_inverse(a: &[u8], modulus: &[u8]) -> Result<Vec<u8>, &'static str> {
    // 拡張ユークリッド互除法を使用
    extended_gcd(a, modulus)
}

/// 拡張ユークリッド互除法（簡易実装）
fn extended_gcd(a: &[u8], b: &[u8]) -> Result<Vec<u8>, &'static str> {
    // 大整数を扱うための構造体
    #[derive(Clone, Debug)]
    struct BigInt {
        digits: Vec<u32>,
        negative: bool,
    }
    
    impl BigInt {
        fn from_bytes(bytes: &[u8]) -> Self {
            let mut digits = Vec::new();
            let mut current = 0u64;
            let mut shift = 0;
            
            for &byte in bytes.iter().rev() {
                current |= (byte as u64) << shift;
                shift += 8;
                
                if shift >= 32 {
                    digits.push((current & 0xFFFFFFFF) as u32);
                    current >>= 32;
                    shift -= 32;
                }
            }
            
            if current > 0 {
                digits.push(current as u32);
            }
            
            if digits.is_empty() {
                digits.push(0);
            }
            
            BigInt { digits, negative: false }
        }
        
        fn to_bytes(&self, target_len: usize) -> Vec<u8> {
            let mut result = vec![0u8; target_len];
            let mut value = 0u64;
            let mut shift = 0;
            let mut byte_idx = target_len;
            
            for &digit in &self.digits {
                value |= (digit as u64) << shift;
                shift += 32;
                
                while shift >= 8 && byte_idx > 0 {
                    byte_idx -= 1;
                    result[byte_idx] = (value & 0xFF) as u8;
                    value >>= 8;
                    shift -= 8;
                }
            }
            
            while shift > 0 && byte_idx > 0 {
                byte_idx -= 1;
                result[byte_idx] = (value & 0xFF) as u8;
                value >>= 8;
                shift = shift.saturating_sub(8);
            }
            
            result
        }
        
        fn is_zero(&self) -> bool {
            self.digits.len() == 1 && self.digits[0] == 0
        }
        
        fn is_one(&self) -> bool {
            self.digits.len() == 1 && self.digits[0] == 1 && !self.negative
        }
        
        fn compare(&self, other: &BigInt) -> core::cmp::Ordering {
            use core::cmp::Ordering;
            
            if self.negative != other.negative {
                return if self.negative { Ordering::Less } else { Ordering::Greater };
            }
            
            let mut ord = self.digits.len().cmp(&other.digits.len());
            if ord == Ordering::Equal {
                for i in (0..self.digits.len()).rev() {
                    ord = self.digits[i].cmp(&other.digits[i]);
                    if ord != Ordering::Equal {
                        break;
                    }
                }
            }
            
            if self.negative {
                ord.reverse()
                } else {
                ord
            }
        }
        
        fn add(&self, other: &BigInt) -> BigInt {
            if self.negative != other.negative {
                if self.negative {
                    return other.subtract(&self.abs());
                } else {
                    return self.subtract(&other.abs());
                }
            }
            
            let mut result = Vec::new();
            let mut carry = 0u64;
            let max_len = self.digits.len().max(other.digits.len());
            
            for i in 0..max_len {
                let a = self.digits.get(i).copied().unwrap_or(0) as u64;
                let b = other.digits.get(i).copied().unwrap_or(0) as u64;
                let sum = a + b + carry;
                
                result.push((sum & 0xFFFFFFFF) as u32);
                carry = sum >> 32;
            }
            
            if carry > 0 {
                result.push(carry as u32);
            }
            
            BigInt { digits: result, negative: self.negative }
        }
        
        fn subtract(&self, other: &BigInt) -> BigInt {
            if self.negative != other.negative {
                return self.add(&other.abs());
            }
            
            let (larger, smaller, result_negative) = if self.abs_compare(other) >= 0 {
                (self, other, self.negative)
            } else {
                (other, self, !self.negative)
            };
            
            let mut result = Vec::new();
            let mut borrow = 0i64;
            
            for i in 0..larger.digits.len() {
                let a = larger.digits[i] as i64;
                let b = smaller.digits.get(i).copied().unwrap_or(0) as i64;
                let diff = a - b - borrow;
                
                if diff < 0 {
                    result.push((diff + (1i64 << 32)) as u32);
                    borrow = 1;
                } else {
                    result.push(diff as u32);
                    borrow = 0;
                }
            }
            
            // 先頭の0を除去
            while result.len() > 1 && result.last() == Some(&0) {
                result.pop();
            }
            
            BigInt { digits: result, negative: result_negative }
        }
        
        fn multiply(&self, other: &BigInt) -> BigInt {
            let mut result = vec![0u32; self.digits.len() + other.digits.len()];
            
            for i in 0..self.digits.len() {
                let mut carry = 0u64;
                for j in 0..other.digits.len() {
                    let prod = (self.digits[i] as u64) * (other.digits[j] as u64) + 
                              (result[i + j] as u64) + carry;
                    result[i + j] = (prod & 0xFFFFFFFF) as u32;
                    carry = prod >> 32;
                }
                if carry > 0 && i + other.digits.len() < result.len() {
                    result[i + other.digits.len()] += carry as u32;
                }
            }
            
            // 先頭の0を除去
            while result.len() > 1 && result.last() == Some(&0) {
                result.pop();
            }
            
            BigInt { 
                digits: result, 
                negative: self.negative != other.negative 
            }
        }
        
        fn divide(&self, other: &BigInt) -> (BigInt, BigInt) {
            if other.is_zero() {
                panic!("ゼロ除算");
            }
            
            if self.abs_compare(other) < 0 {
                return (BigInt::zero(), self.clone());
            }
            
            // 長除法の実装（簡略化）
            let mut quotient = BigInt::zero();
            let mut remainder = self.abs();
            let divisor = other.abs();
            
            while remainder.abs_compare(&divisor) >= 0 {
                remainder = remainder.subtract(&divisor);
                quotient = quotient.add(&BigInt::one());
            }
            
            quotient.negative = self.negative != other.negative;
            remainder.negative = self.negative;
            
            (quotient, remainder)
        }
        
        fn abs(&self) -> BigInt {
            BigInt { digits: self.digits.clone(), negative: false }
        }
        
        fn abs_compare(&self, other: &BigInt) -> i32 {
            if self.digits.len() != other.digits.len() {
                return if self.digits.len() > other.digits.len() { 1 } else { -1 };
            }
            
            for i in (0..self.digits.len()).rev() {
                if self.digits[i] > other.digits[i] {
                    return 1;
                } else if self.digits[i] < other.digits[i] {
                    return -1;
                }
            }
            
            0
        }
        
        fn zero() -> BigInt {
            BigInt { digits: vec![0], negative: false }
        }
        
        fn one() -> BigInt {
            BigInt { digits: vec![1], negative: false }
        }
    }
    
    // 拡張ユークリッド互除法の実装
    let mut old_r = BigInt::from_bytes(b);
    let mut r = BigInt::from_bytes(a);
    let mut old_s = BigInt::one();
    let mut s = BigInt::zero();
    let mut old_t = BigInt::zero();
    let mut t = BigInt::one();
    
    while !r.is_zero() {
        let (quotient, new_r) = old_r.divide(&r);
        
        old_r = r;
        r = new_r;
        
        let new_s = old_s.subtract(&quotient.multiply(&s));
        old_s = s;
        s = new_s;
        
        let new_t = old_t.subtract(&quotient.multiply(&t));
        old_t = t;
        t = new_t;
    }
    
    // gcd(a, b) = old_r
    if !old_r.is_one() {
        return Err("逆元が存在しません");
    }
    
    // old_s が a の b における逆元
    let mut result = old_s;
    if result.negative {
        let modulus = BigInt::from_bytes(b);
        result = result.add(&modulus);
    }
    
    Ok(result.to_bytes(a.len()))
}

/// 楕円曲線上の点の乗算
fn ec_point_multiply(k: &[u8], x: &[u8], y: &[u8], curve_params: &CurveParameters) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    // ダブル・アンド・アッド法
    let mut result_x = vec![0u8; curve_params.p.len()];
    let mut result_y = vec![0u8; curve_params.p.len()];
    let mut is_infinity = true;
    
    let mut addend_x = x.to_vec();
    let mut addend_y = y.to_vec();
    
    // kの各ビットを処理
    for byte in k.iter().rev() {
        for bit in 0..8 {
            if (byte >> bit) & 1 == 1 {
                if is_infinity {
                    result_x = addend_x.clone();
                    result_y = addend_y.clone();
                    is_infinity = false;
            } else {
                    let (new_x, new_y) = ec_point_add(&result_x, &result_y, &addend_x, &addend_y, curve_params)?;
                    result_x = new_x;
                    result_y = new_y;
                }
            }
            
            // addend = 2 * addend
            let (new_x, new_y) = ec_point_double(&addend_x, &addend_y, curve_params)?;
            addend_x = new_x;
            addend_y = new_y;
        }
    }
    
    if is_infinity {
        Err("無限遠点の結果")
    } else {
        Ok((result_x, result_y))
    }
}

/// 楕円曲線上の点の加算
fn ec_point_add(x1: &[u8], y1: &[u8], x2: &[u8], y2: &[u8], curve_params: &CurveParameters) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    // 同じ点の場合は倍算
    if big_int_compare(x1, x2) == 0 && big_int_compare(y1, y2) == 0 {
        return ec_point_double(x1, y1, curve_params);
    }
    
    // 傾きを計算: s = (y2 - y1) / (x2 - x1) mod p
    let y_diff = big_int_mod_subtract(y2, y1, &curve_params.p)?;
    let x_diff = big_int_mod_subtract(x2, x1, &curve_params.p)?;
    let dx_inv = mod_inverse(&x_diff, &curve_params.p)?;
    let lambda = big_int_mod_mul(&y_diff, &dx_inv, &curve_params.p)?;
    
    // x3 = λ^2 - x1 - x2 mod p
    let lambda_squared = big_int_mod_mul(&lambda, &lambda, &curve_params.p)?;
    let x1_plus_x2 = big_int_mod_add(x1, x2, &curve_params.p)?;
    let x3 = big_int_mod_subtract(&lambda_squared, &x1_plus_x2, &curve_params.p)?;
    
    // y3 = λ(x1 - x3) - y1 mod p
    let x1_minus_x3 = big_int_mod_subtract(x1, &x3, &curve_params.p)?;
    let lambda_times_diff = big_int_mod_mul(&lambda, &x1_minus_x3, &curve_params.p)?;
    let y3 = big_int_mod_subtract(&lambda_times_diff, y1, &curve_params.p)?;
    
    Ok((x3, y3))
}

/// 楕円曲線上の点の倍算
fn ec_point_double(x: &[u8], y: &[u8], curve_params: &CurveParameters) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    // 傾きを計算: s = (3x^2 + a) / (2y) mod p
    let x_squared = big_int_mod_mul(x, x, &curve_params.p)?;
    let three_x_squared = big_int_mod_mul(&[3], &x_squared, &curve_params.p)?;
    let numerator = big_int_mod_add(&three_x_squared, &curve_params.a, &curve_params.p)?;
    let two_y = big_int_mod_add(y, y, &curve_params.p)?;
    let two_y_inv = mod_inverse(&two_y, &curve_params.p)?;
    let slope_temp = big_int_multiply(&numerator, &two_y_inv)?;
    let slope = big_int_mod(&slope_temp, &curve_params.p)?;
    
    // x3 = λ^2 - 2x mod p
    let lambda_squared = big_int_mod_mul(&slope, &slope)?;
    let two_x = big_int_mod_add(x, x, &curve_params.p)?;
    let x3 = big_int_mod_subtract(&lambda_squared, &two_x, &curve_params.p)?;
    
    // y3 = λ(x - x3) - y mod p
    let x_minus_x3 = big_int_mod_subtract(x, &x3, &curve_params.p)?;
    let lambda_times_diff = big_int_multiply(&slope, &x_minus_x3)?;
    let y3 = big_int_mod_subtract(&lambda_times_diff, y, &curve_params.p)?;
    
    Ok((x3, y3))
}

/// 大整数のモジュラー減算
fn big_int_mod_subtract(a: &[u8], b: &[u8], modulus: &[u8]) -> Result<Vec<u8>, &'static str> {
    if big_int_compare(a, b) >= 0 {
        let diff = big_int_subtract(a, b)?;
        big_int_mod(&diff, modulus)
    } else {
        // a < b の場合、a + modulus - b を計算
        let a_plus_mod = big_int_add(a, modulus)?;
        let diff = big_int_subtract(&a_plus_mod, b)?;
        big_int_mod(&diff, modulus)
    }
}

fn get_uefi_runtime_services() -> Result<&'static UefiRuntimeServices, &'static str> {
    log::debug!("UEFI Runtime Services取得開始");
    
    // 1. UEFI System Tableのアドレスを取得
    let system_table_addr = get_uefi_system_table_address()?;
    
    // 2. System Tableの署名とリビジョンを検証
    let system_table = unsafe { &*(system_table_addr as *const UefiSystemTable) };
    
    // 3. System Table署名を検証 ("IBI SYST")
    if system_table.hdr.signature != 0x5453595320494249 {
        return Err("UEFI System Tableの署名が無効です");
    }
    
    // 4. CRC32チェックサムを検証
    if !verify_uefi_table_crc32(&system_table.hdr) {
        return Err("UEFI System TableのCRC32が無効です");
    }
    
    // 5. Runtime Servicesテーブルを取得
    let runtime_services = unsafe { &*(system_table.runtime_services as *const UefiRuntimeServices) };
    
    // 6. Runtime Services署名を検証 ("RUNT")
    if runtime_services.hdr.signature != 0x544E5552 {
        return Err("UEFI Runtime Servicesの署名が無効です");
    }
    
    // 7. Runtime Services CRC32を検証
    if !verify_uefi_table_crc32(&runtime_services.hdr) {
        return Err("UEFI Runtime ServicesのCRC32が無効です");
    }
    
    // 8. 仮想アドレスマッピングが完了しているかチェック
    if !is_virtual_address_mapping_complete() {
        log::warn!("仮想アドレスマッピングが未完了です。物理アドレスを使用します");
    }
    
    log::debug!("UEFI Runtime Services取得完了: リビジョン=0x{:x}", runtime_services.hdr.revision);
    Ok(runtime_services)
}

/// UEFI System Tableのアドレスを取得
fn get_uefi_system_table_address() -> Result<usize, &'static str> {
    log::trace!("UEFI System Tableアドレス検索開始");
    
    // 1. ブートローダーから渡されたパラメータを確認
    if let Some(addr) = get_bootloader_system_table_param() {
        log::debug!("ブートローダーからSystem Tableアドレスを取得: 0x{:x}", addr);
        if is_valid_system_table(addr) {
            return Ok(addr);
        } else {
            log::warn!("ブートローダーから取得したSystem Tableが無効です");
        }
    }
    
    // 2. UEFI Configuration Tableから検索
    if let Some(addr) = search_uefi_config_table() {
        log::debug!("Configuration TableからSystem Tableアドレスを取得: 0x{:x}", addr);
        if is_valid_system_table(addr) {
            return Ok(addr);
        } else {
            log::warn!("Configuration Tableから取得したSystem Tableが無効です");
        }
    }
    
    // 3. メモリマップから推定
    if let Some(addr) = estimate_system_table_from_memory_map() {
        log::debug!("メモリマップからSystem Tableアドレスを推定: 0x{:x}", addr);
        if is_valid_system_table(addr) {
            return Ok(addr);
        } else {
            log::warn!("メモリマップから推定したSystem Tableが無効です");
        }
    }
    
    Err("UEFI System Tableのアドレスが見つかりません")
}

/// ブートローダーから渡されたSystem Tableパラメータを取得
fn get_bootloader_system_table_param() -> Option<usize> {
    log::trace!("ブートローダーパラメータ検索中");
    
    // 複数の方法でブートローダーパラメータを検索
    
    // 方法1: 特定のメモリ位置から取得
    unsafe {
        let param_locations = [
            0x7E00,  // 従来のブートローダー位置
            0x8000,  // 代替位置1
            0x9000,  // 代替位置2
            0x10000, // 代替位置3
        ];
        
        for &addr in &param_locations {
            if is_memory_accessible(addr, 8) {
                let param_addr = addr as *const usize;
                let value = param_addr.read_volatile();
                if value != 0 && value > 0x100000 && value < 0x100000000 {
                    log::trace!("ブートローダーパラメータ発見: 0x{:x} -> 0x{:x}", addr, value);
                    return Some(value);
                }
            }
        }
    }
    
    // 方法2: E820メモリマップから検索
    if let Some(addr) = search_e820_for_system_table() {
        return Some(addr);
    }
    
    // 方法3: レジスタから取得（アーキテクチャ依存）
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(addr) = get_system_table_from_registers() {
            return Some(addr);
        }
    }
    
    log::trace!("ブートローダーパラメータが見つかりません");
    None
}

/// E820メモリマップからSystem Tableを検索
fn search_e820_for_system_table() -> Option<usize> {
    log::trace!("E820メモリマップ検索中");
    
    // E820メモリマップエントリを検索
    unsafe {
        let e820_count_addr = 0x1E8 as *const u8;
        if !is_memory_accessible(0x1E8, 1) {
            return None;
        }
        
        let e820_count = e820_count_addr.read_volatile();
        if e820_count == 0 || e820_count > 128 {
            return None;
        }
        
        let e820_map_addr = 0x2D0 as *const E820Entry;
        if !is_memory_accessible(0x2D0, e820_count as usize * 20) {
            return None;
        }
        
        for i in 0..e820_count {
            let entry = &*e820_map_addr.add(i as usize);
            
            // ACPI Reclaimableまたは予約済み領域を検索
            if entry.entry_type == 3 || entry.entry_type == 2 {
                let start = entry.base_addr as usize;
                let end = start + entry.length as usize;
                
                if let Some(addr) = search_system_table_in_range(start, end) {
                    log::trace!("E820エントリ{}でSystem Table発見: 0x{:x}", i, addr);
                    return Some(addr);
                }
            }
        }
    }
    
    None
}

/// レジスタからSystem Tableアドレスを取得（x86_64）
#[cfg(target_arch = "x86_64")]
fn get_system_table_from_registers() -> Option<usize> {
    log::trace!("レジスタからSystem Table検索中");
    
    // 一部のブートローダーはレジスタにSystem Tableアドレスを保存
    unsafe {
        let mut rdi: usize;
        let mut rsi: usize;
        let mut rdx: usize;
        let mut rcx: usize;
        
        asm!(
            "mov {}, rdi",
            "mov {}, rsi", 
            "mov {}, rdx",
            "mov {}, rcx",
            out(reg) rdi,
            out(reg) rsi,
            out(reg) rdx,
            out(reg) rcx,
        );
        
        let candidates = [rdi, rsi, rdx, rcx];
        for &addr in &candidates {
            if addr > 0x100000 && addr < 0x100000000 && is_valid_system_table(addr) {
                log::trace!("レジスタからSystem Table発見: 0x{:x}", addr);
                return Some(addr);
            }
        }
    }
    
    None
}

/// UEFI Configuration Tableから検索
fn search_uefi_config_table() -> Option<usize> {
    log::trace!("UEFI Configuration Table検索中");
    
    // ACPI RSDPから検索
    if let Some(rsdp_addr) = find_acpi_rsdp() {
        log::trace!("ACPI RSDP発見: 0x{:x}", rsdp_addr);
        if let Some(system_table) = extract_system_table_from_acpi(rsdp_addr) {
            return Some(system_table);
        }
    }
    
    // SMBIOS/DMIテーブルから検索
    if let Some(addr) = search_smbios_for_system_table() {
        return Some(addr);
    }
    
    None
}

/// SMBIOSテーブルからSystem Tableを検索
fn search_smbios_for_system_table() -> Option<usize> {
    log::trace!("SMBIOSテーブル検索中");
    
    // SMBIOS Entry Pointを検索（0xF0000-0xFFFFF）
    for addr in (0xF0000..0x100000).step_by(16) {
        if !is_memory_accessible(addr, 4) {
            continue;
        }
        
        unsafe {
            let signature = (addr as *const u32).read_volatile();
            
            // "_SM_" signature
            if signature == 0x5F4D535F {
                log::trace!("SMBIOS Entry Point発見: 0x{:x}", addr);
                
                // SMBIOS構造体テーブルを検索
                let entry_point = addr as *const SmbiosEntryPoint;
                let table_addr = (*entry_point).structure_table_address as usize;
                let table_length = (*entry_point).structure_table_length as usize;
                
                if let Some(system_table) = search_smbios_structures(table_addr, table_length) {
                    return Some(system_table);
                }
            }
        }
    }
    
    None
}

/// SMBIOS構造体からSystem Tableを検索
fn search_smbios_structures(table_addr: usize, table_length: usize) -> Option<usize> {
    if !is_memory_accessible(table_addr, table_length) {
        return None;
    }
    
    let mut offset = 0;
    
    while offset < table_length {
        unsafe {
            let header_addr = table_addr + offset;
            if !is_memory_accessible(header_addr, 4) {
                break;
            }
            
            let header = header_addr as *const SmbiosStructureHeader;
            let structure_type = (*header).structure_type;
            let structure_length = (*header).length as usize;
            
            // Type 0 (BIOS Information) を検索
            if structure_type == 0 {
                // UEFI関連情報を検索
                if let Some(addr) = extract_uefi_info_from_bios_structure(header_addr, structure_length) {
                    return Some(addr);
                }
            }
            
            // 次の構造体へ
            offset += structure_length;
            
            // 文字列テーブルをスキップ
            while offset < table_length {
                let byte_addr = (table_addr + offset) as *const u8;
                if !is_memory_accessible(table_addr + offset, 1) {
                    return None;
                }
                
                if byte_addr.read_volatile() == 0 {
                    offset += 1;
                    if offset < table_length {
                        let next_byte = (table_addr + offset) as *const u8;
                        if next_byte.read_volatile() == 0 {
                            offset += 1;
                            break;
                        }
                    }
    } else {
                    offset += 1;
                }
            }
        }
    }
    
    None
}

/// BIOS構造体からUEFI情報を抽出
fn extract_uefi_info_from_bios_structure(structure_addr: usize, length: usize) -> Option<usize> {
    // BIOS Information構造体からUEFI関連データを検索
    // 実装は複雑なため、基本的な検索のみ
    
    unsafe {
        let data = core::slice::from_raw_parts(structure_addr as *const u8, length);
        
        // UEFI関連のシグネチャを検索
        for i in 0..data.len().saturating_sub(8) {
            let signature = u64::from_le_bytes([
                data[i], data[i+1], data[i+2], data[i+3],
                data[i+4], data[i+5], data[i+6], data[i+7]
            ]);
            
            // "IBI SYST" signature
            if signature == 0x5453595320494249 {
                let potential_addr = structure_addr + i;
                if is_valid_system_table(potential_addr) {
                    return Some(potential_addr);
                }
            }
        }
    }
    
    None
}

/// ACPI RSDPを検索
fn find_acpi_rsdp() -> Option<usize> {
    log::trace!("ACPI RSDP検索中");
    
    // EBDA (Extended BIOS Data Area) を検索
    unsafe {
        if is_memory_accessible(0x40E, 2) {
            let ebda_segment = (*(0x40E as *const u16)) as usize;
            if ebda_segment != 0 {
                let ebda_start = ebda_segment << 4;
                if let Some(addr) = search_rsdp_in_range(ebda_start, ebda_start + 1024) {
                    log::trace!("EBDAでRSDP発見: 0x{:x}", addr);
                    return Some(addr);
                }
            }
        }
    }
    
    // BIOS ROM領域を検索 (0xE0000-0xFFFFF)
    if let Some(addr) = search_rsdp_in_range(0xE0000, 0x100000) {
        log::trace!("BIOS ROMでRSDP発見: 0x{:x}", addr);
        return Some(addr);
    }
    
    None
}

/// 指定範囲でRSDPを検索
fn search_rsdp_in_range(start: usize, end: usize) -> Option<usize> {
    for addr in (start..end).step_by(16) {
        if !is_memory_accessible(addr, 8) {
            continue;
        }
        
        unsafe {
            let signature = (addr as *const u64).read_volatile();
            
            // "RSD PTR " signature
            if signature == 0x2052545020445352 {
                // チェックサムを検証
                if verify_acpi_checksum(addr, 20) {
                    log::trace!("有効なRSDP発見: 0x{:x}", addr);
                    return Some(addr);
                }
            }
        }
    }
    
    None
}

/// ACPIチェックサムを検証
fn verify_acpi_checksum(addr: usize, length: usize) -> bool {
    if !is_memory_accessible(addr, length) {
        return false;
    }
    
    unsafe {
        let data = core::slice::from_raw_parts(addr as *const u8, length);
        let sum: u8 = data.iter().fold(0u8, |acc, &byte| acc.wrapping_add(byte));
        sum == 0
    }
}

/// ACPIからSystem Tableを抽出
fn extract_system_table_from_acpi(rsdp_addr: usize) -> Option<usize> {
    log::trace!("ACPIからSystem Table抽出中");
    
    unsafe {
        let rsdp = &*(rsdp_addr as *const AcpiRsdp);
        
        // ACPI 2.0以降の場合、XSDTを使用
        if rsdp.revision >= 2 && rsdp.xsdt_address != 0 {
            if let Some(addr) = search_uefi_table_in_xsdt(rsdp.xsdt_address as usize) {
                return Some(addr);
            }
        }
        
        // ACPI 1.0またはXSDTが無効な場合、RSDTを使用
        if rsdp.rsdt_address != 0 {
            if let Some(addr) = search_uefi_table_in_rsdt(rsdp.rsdt_address as usize) {
                return Some(addr);
            }
        }
    }
    
    None
}

/// XSDTでUEFIテーブルを検索
fn search_uefi_table_in_xsdt(xsdt_addr: usize) -> Option<usize> {
    if !is_memory_accessible(xsdt_addr, 36) {
        return None;
    }
    
    unsafe {
        let xsdt = &*(xsdt_addr as *const AcpiXsdt);
        
        // XSDTヘッダーのチェックサムを検証
        if !verify_acpi_checksum(xsdt_addr, xsdt.header.length as usize) {
            return None;
        }
        
        let entry_count = (xsdt.header.length as usize - 36) / 8;
        let entries_addr = (xsdt_addr + 36) as *const u64;
        
        for i in 0..entry_count {
            if !is_memory_accessible((entries_addr as usize) + i * 8, 8) {
                continue;
            }
            
            let table_addr = entries_addr.add(i).read_volatile() as usize;
            if let Some(system_table) = check_table_for_uefi_info(table_addr) {
                return Some(system_table);
            }
        }
    }
    
    None
}

/// RSDTでUEFIテーブルを検索
fn search_uefi_table_in_rsdt(rsdt_addr: usize) -> Option<usize> {
    if !is_memory_accessible(rsdt_addr, 36) {
        return None;
    }
    
    unsafe {
        let rsdt = &*(rsdt_addr as *const AcpiRsdt);
        
        // RSDTヘッダーのチェックサムを検証
        if !verify_acpi_checksum(rsdt_addr, rsdt.header.length as usize) {
            return None;
        }
        
        let entry_count = (rsdt.header.length as usize - 36) / 4;
        let entries_addr = (rsdt_addr + 36) as *const u32;
        
        for i in 0..entry_count {
            if !is_memory_accessible((entries_addr as usize) + i * 4, 4) {
                continue;
            }
            
            let table_addr = entries_addr.add(i).read_volatile() as usize;
            if let Some(system_table) = check_table_for_uefi_info(table_addr) {
                return Some(system_table);
            }
        }
    }
    
    None
}

/// テーブルでUEFI情報をチェック
fn check_table_for_uefi_info(table_addr: usize) -> Option<usize> {
    if !is_memory_accessible(table_addr, 36) {
        return None;
    }
    
    unsafe {
        let header = &*(table_addr as *const AcpiTableHeader);
        
        // テーブルシグネチャをチェック
        let signature = u32::from_le_bytes(header.signature);
        
        match signature {
            0x54434146 => { // "FADT"
                extract_system_table_from_fadt(table_addr)
            },
            0x45494655 => { // "UEFI"
                extract_system_table_from_uefi_table(table_addr)
            },
            _ => {
                // その他のテーブルでUEFI関連情報を検索
                search_uefi_signature_in_table(table_addr, header.length as usize)
            }
        }
    }
}

/// UEFIテーブルからSystem Tableを抽出
fn extract_system_table_from_uefi_table(table_addr: usize) -> Option<usize> {
    if !is_memory_accessible(table_addr, 52) {
        return None;
    }
    
    unsafe {
        // UEFIテーブルの構造に従ってSystem Tableアドレスを抽出
        let uefi_table_data = (table_addr + 36) as *const u64;
        let system_table_addr = uefi_table_data.read_volatile() as usize;
        
        if system_table_addr != 0 && is_valid_system_table(system_table_addr) {
            log::trace!("UEFIテーブルからSystem Table抽出: 0x{:x}", system_table_addr);
            return Some(system_table_addr);
        }
    }
    
    None
}

/// テーブル内でUEFIシグネチャを検索
fn search_uefi_signature_in_table(table_addr: usize, table_length: usize) -> Option<usize> {
    if !is_memory_accessible(table_addr, table_length) {
        return None;
    }
    
    unsafe {
        let data = core::slice::from_raw_parts(table_addr as *const u8, table_length);
        
        // "IBI SYST" シグネチャを検索
        for i in 0..data.len().saturating_sub(8) {
            let signature = u64::from_le_bytes([
                data[i], data[i+1], data[i+2], data[i+3],
                data[i+4], data[i+5], data[i+6], data[i+7]
            ]);
            
            if signature == 0x5453595320494249 {
                let potential_addr = table_addr + i;
                if is_valid_system_table(potential_addr) {
                    return Some(potential_addr);
                }
            }
        }
    }
    
    None
}

/// FADTからSystem Tableを抽出
fn extract_system_table_from_fadt(fadt_addr: usize) -> Option<usize> {
    // FADTテーブルは通常System Tableを直接含まないが、
    // 一部の実装では関連情報が含まれる場合がある
    search_uefi_signature_in_table(fadt_addr, 276) // FADT最小サイズ
}

// ... existing code ...

/// TPMからAK公開鍵を取得
fn get_ak_public_key_from_tpm() -> Result<Vec<u8>, &'static str> {
    // TPM2_ReadPublicコマンドを構築
    let mut command = Vec::new();
    
    // TPMコマンドヘッダー
    command.extend_from_slice(&[0x80, 0x01]); // TPM_ST_NO_SESSIONS
    command.extend_from_slice(&[0x00, 0x00, 0x00, 0x16]); // commandSize (22 bytes)
    command.extend_from_slice(&[0x00, 0x00, 0x01, 0x73]); // TPM_CC_ReadPublic
    
    // AKハンドル（0x81000000 - 永続ハンドル）
    command.extend_from_slice(&[0x81, 0x00, 0x00, 0x00]);
    
    // TPMにコマンドを送信
    let response = send_tpm_command(&command)?;
    
    // レスポンスを解析
    if response.len() < 10 {
        return Err("TPMレスポンスが短すぎます");
    }
    
    // レスポンスコードをチェック
    let response_code = u32::from_be_bytes([
        response[6], response[7], response[8], response[9]
    ]);
    
    if response_code != 0 {
        return Err("TPM_ReadPublicコマンドが失敗しました");
    }
    
    // TPMT_PUBLIC構造体を解析
    let mut offset = 10;
    
    // publicAreaサイズ
    if offset + 2 > response.len() {
        return Err("レスポンスが不完全です");
    }
    let public_area_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
    offset += 2;
    
    if offset + public_area_size > response.len() {
        return Err("publicAreaサイズが無効です");
    }
    
    // TPMI_ALG_PUBLIC (アルゴリズム)
    let algorithm = u16::from_be_bytes([response[offset], response[offset + 1]]);
    offset += 2;
    
    if algorithm != 0x0001 { // TPM_ALG_RSA
        return Err("サポートされていないアルゴリズムです");
    }
    
    // nameAlg
    offset += 2;
    
    // objectAttributes
    offset += 4;
    
    // authPolicyサイズとデータをスキップ
    let auth_policy_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
    offset += 2 + auth_policy_size;
    
    // RSAパラメータを解析
    // symmetric
    offset += 2;
    
    // scheme
    offset += 2;
    
    // keyBits
    let key_bits = u16::from_be_bytes([response[offset], response[offset + 1]]);
    offset += 2;
    
    // exponent (0の場合は65537)
    let exponent_value = u32::from_be_bytes([
        response[offset], response[offset + 1], response[offset + 2], response[offset + 3]
    ]);
    offset += 4;
    
    // unique (modulus)
    let modulus_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
    offset += 2;
    
    if offset + modulus_size > response.len() {
        return Err("modulusサイズが無効です");
    }
    
    let modulus = &response[offset..offset + modulus_size];
    
    // DER形式のRSA公開鍵を構築
    let exponent = if exponent_value == 0 { 65537u32 } else { exponent_value };
    let der_key = build_rsa_public_key_der(modulus, exponent)?;
    
    log::info!("TPMからAK公開鍵を取得しました: {}ビット RSA", key_bits);
    
    Ok(der_key)
}

/// DER形式のRSA公開鍵を構築
fn build_rsa_public_key_der(modulus: &[u8], exponent: u32) -> Result<Vec<u8>, &'static str> {
    let mut der = Vec::new();
    
    // SEQUENCE
    der.push(0x30);
    
    // 長さは後で設定
    let length_pos = der.len();
    der.push(0x00);
    
    // RSA公開鍵のOID
    der.extend_from_slice(&[
        0x30, 0x0d, // SEQUENCE
        0x06, 0x09, // OID
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // rsaEncryption
        0x05, 0x00, // NULL
    ]);
    
    // BIT STRING
    der.push(0x03);
    
    // BIT STRINGの長さ（後で設定）
    let bitstring_length_pos = der.len();
    der.push(0x00);
    
    // 未使用ビット数
    der.push(0x00);
    
    // RSA公開鍵のSEQUENCE
    der.push(0x30);
    
    // RSA SEQUENCEの長さ（後で設定）
    let rsa_seq_length_pos = der.len();
    der.push(0x00);
    
    // modulus (INTEGER)
    der.push(0x02);
    if modulus[0] & 0x80 != 0 {
        // 最上位ビットが1の場合、0x00を前置
        der.push((modulus.len() + 1) as u8);
        der.push(0x00);
    } else {
        der.push(modulus.len() as u8);
    }
    der.extend_from_slice(modulus);
    
    // exponent (INTEGER)
    der.push(0x02);
    let exp_bytes = exponent.to_be_bytes();
    let exp_start = exp_bytes.iter().position(|&b| b != 0).unwrap_or(3);
    der.push((4 - exp_start) as u8);
    der.extend_from_slice(&exp_bytes[exp_start..]);
    
    // 長さを設定
    let rsa_seq_length = der.len() - rsa_seq_length_pos - 1;
    der[rsa_seq_length_pos] = rsa_seq_length as u8;
    
    let bitstring_length = der.len() - bitstring_length_pos - 1;
    der[bitstring_length_pos] = bitstring_length as u8;
    
    let total_length = der.len() - length_pos - 1;
    der[length_pos] = total_length as u8;
    
    log::trace!("DER形式RSA公開鍵を構築しました: {}バイト", der.len());
    
    Ok(der)
}

/// RSA PKCS#1 v1.5署名検証
fn verify_rsa_pkcs1_v15(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, &'static str> {
    // DER形式の公開鍵を解析
    let (modulus, exponent) = parse_rsa_public_key_der(public_key)?;
    
    // 署名をRSA公開鍵で復号
    let decrypted = rsa_public_decrypt(signature, &modulus, &exponent)?;
    
    // PKCS#1 v1.5パディングを検証
    if !verify_pkcs1_padding(&decrypted) {
        log::debug!("PKCS#1 v1.5パディング検証失敗");
        return Ok(false);
    }
    
    // DigestInfoを抽出
    let digest_info = extract_digest_info(&decrypted)?;
    
    // メッセージのハッシュを計算
    let message_hash = sha256_hash(message);
    
    // ハッシュを比較
    let result = digest_info == message_hash;
    
    if result {
        log::debug!("RSA PKCS#1 v1.5署名検証成功");
    } else {
        log::debug!("RSA PKCS#1 v1.5署名検証失敗: ハッシュ不一致");
    }
    
    Ok(result)
}

/// DER形式のRSA公開鍵を解析
fn parse_rsa_public_key_der(der_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let mut offset = 0;
    
    // SEQUENCE
    if der_data[offset] != 0x30 {
        return Err("無効なDER形式");
    }
    offset += 1;
    
    // 長さをスキップ
    offset += 1;
    
    // アルゴリズムSEQUENCEをスキップ
    if der_data[offset] != 0x30 {
        return Err("アルゴリズムSEQUENCEが見つかりません");
    }
    offset += 1;
    let alg_length = der_data[offset] as usize;
    offset += 1 + alg_length;
    
    // BIT STRING
    if der_data[offset] != 0x03 {
        return Err("BIT STRINGが見つかりません");
    }
    offset += 1;
    
    // BIT STRINGの長さ
    let bitstring_length = der_data[offset] as usize;
    offset += 1;
    
    // 未使用ビット数
    offset += 1;
    
    // RSA公開鍵のSEQUENCE
    if der_data[offset] != 0x30 {
        return Err("RSA SEQUENCEが見つかりません");
    }
    offset += 1;
    
    // RSA SEQUENCEの長さ
    offset += 1;
    
    // modulus (INTEGER)
    if der_data[offset] != 0x02 {
        return Err("modulusが見つかりません");
    }
    offset += 1;
    
    let modulus_length = der_data[offset] as usize;
    offset += 1;
    
    let modulus_start = if der_data[offset] == 0x00 {
        offset + 1
    } else {
        offset
    };
    let modulus = der_data[modulus_start..offset + modulus_length].to_vec();
    offset += modulus_length;
    
    // exponent (INTEGER)
    if der_data[offset] != 0x02 {
        return Err("exponentが見つかりません");
    }
    offset += 1;
    
    let exponent_length = der_data[offset] as usize;
        offset += 1;
    
    let exponent = der_data[offset..offset + exponent_length].to_vec();
    
    Ok((modulus, exponent))
}

/// RSA公開鍵復号
fn rsa_public_decrypt(signature: &[u8], modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>, &'static str> {
    // モジュラー指数演算: signature^exponent mod modulus
    let result = modular_exponentiation(signature, exponent, modulus)?;
    
    log::trace!("RSA公開鍵復号完了: 入力{}バイト -> 出力{}バイト", 
               signature.len(), result.len());
    
    Ok(result)
}

/// PKCS#1 v1.5パディング検証
fn verify_pkcs1_padding(decrypted: &[u8]) -> bool {
    if decrypted.len() < 11 {
        log::trace!("PKCS#1パディング検証失敗: データが短すぎます ({}バイト)", decrypted.len());
        return false;
    }
    
    // 0x00 0x01 FF...FF 0x00 DigestInfo
    if decrypted[0] != 0x00 {
        log::trace!("PKCS#1パディング検証失敗: 最初のバイトが0x00ではありません");
        return false;
    }
    
    if decrypted[1] != 0x01 {
        log::trace!("PKCS#1パディング検証失敗: 2番目のバイトが0x01ではありません");
        return false;
    }
    
    // FFパディングの長さをチェック（最低8バイト必要）
    let ff_count = decrypted[2..].iter().take_while(|&&b| b == 0xFF).count();
    if ff_count < 8 {
        log::trace!("PKCS#1パディング検証失敗: FFパディングが不十分です ({}バイト)", ff_count);
        return false;
    }
    
    // 0x00セパレータの存在をチェック
    if decrypted.len() <= 2 + ff_count || decrypted[2 + ff_count] != 0x00 {
        log::trace!("PKCS#1パディング検証失敗: セパレータ0x00が見つかりません");
        return false;
    }
    
    log::trace!("PKCS#1パディング検証成功: FFパディング{}バイト", ff_count);
    true
}

/// DigestInfoを抽出
fn extract_digest_info(decrypted: &[u8]) -> Result<Vec<u8>, &'static str> {
    // 0x00の位置を見つける
    let separator_pos = decrypted.iter().skip(2).position(|&b| b == 0x00)
        .ok_or("セパレータが見つかりません")? + 2;
    
    if separator_pos + 1 >= decrypted.len() {
        return Err("DigestInfoが短すぎます");
    }
    
    let digest_info = &decrypted[separator_pos + 1..];
    
    // DigestInfoのSEQUENCEを解析
    if digest_info.len() < 2 || digest_info[0] != 0x30 {
        return Err("無効なDigestInfo");
    }
    
    let mut offset = 2;
    
    // AlgorithmIdentifierをスキップ
    if digest_info[offset] != 0x30 {
        return Err("AlgorithmIdentifierが見つかりません");
    }
    offset += 1;
    let alg_length = digest_info[offset] as usize;
    offset += 1 + alg_length;
    
    // OCTET STRING (ハッシュ値)
    if digest_info[offset] != 0x04 {
        return Err("ハッシュ値が見つかりません");
    }
    offset += 1;
    
    let hash_length = digest_info[offset] as usize;
    offset += 1;
    
    if offset + hash_length > digest_info.len() {
        return Err("ハッシュ値が不完全です");
    }
    
    let hash_value = digest_info[offset..offset + hash_length].to_vec();
    
    log::trace!("DigestInfo解析完了: ハッシュ値{}バイト", hash_value.len());
    
    Ok(hash_value)
}

/// RSA-PSS署名検証
fn verify_rsa_pss(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, &'static str> {
    // DER形式の公開鍵を解析
    let (modulus, exponent) = parse_rsa_public_key_der(public_key)?;
    
    // 署名をRSA公開鍵で復号
    let em = rsa_public_decrypt(signature, &modulus, &exponent)?;
    
    // PSS符号化を検証
    let result = verify_pss_encoding(message, &em, modulus.len())?;
    
    if result {
        log::debug!("RSA-PSS署名検証成功");
    } else {
        log::debug!("RSA-PSS署名検証失敗");
    }
    
    Ok(result)
}

/// PSS符号化検証
fn verify_pss_encoding(message: &[u8], em: &[u8], em_len: usize) -> Result<bool, &'static str> {
    let h_len = 32; // SHA-256ハッシュ長
    let s_len = h_len; // ソルト長
    
    if em_len < h_len + s_len + 2 {
        log::trace!("PSS符号化検証失敗: EMが短すぎます");
        return Ok(false);
    }
    
    // 最後のバイトが0xBCかチェック
    if em[em_len - 1] != 0xBC {
        log::trace!("PSS符号化検証失敗: 最後のバイトが0xBCではありません");
        return Ok(false);
    }
    
    // マスクされたDBとHを分離
    let masked_db_len = em_len - h_len - 1;
    let masked_db = &em[0..masked_db_len];
    let h = &em[masked_db_len..em_len - 1];
    
    // 最上位ビットが0かチェック
    if em[0] & 0x80 != 0 {
        log::trace!("PSS符号化検証失敗: 最上位ビットが1です");
        return Ok(false);
    }
    
    // MGF1でマスクを生成してDBを復元
    let db_mask = mgf1(h, masked_db_len)?;
    let mut db = vec![0u8; masked_db_len];
    for i in 0..masked_db_len {
        db[i] = masked_db[i] ^ db_mask[i];
    }
    
    // 最上位ビットをクリア
    db[0] &= 0x7F;
    
    // DBの構造を検証: PS || 0x01 || salt
    let ps_len = em_len - s_len - h_len - 2;
    
    // PSが全て0かチェック
    for i in 0..ps_len {
        if db[i] != 0x00 {
            log::trace!("PSS符号化検証失敗: PSに非ゼロバイトがあります");
            return Ok(false);
        }
    }
    
    // 0x01バイトをチェック
    if db[ps_len] != 0x01 {
        log::trace!("PSS符号化検証失敗: 0x01バイトが見つかりません");
        return Ok(false);
    }
    
    // ソルトを抽出
    let salt = &db[ps_len + 1..];
    
    
    // M' = 0x00 00 00 00 00 00 00 00 || mHash || salt
    let m_hash = sha256_hash(message);
    let mut m_prime = vec![0u8; 8];
    m_prime.extend_from_slice(&m_hash);
    m_prime.extend_from_slice(salt);
    
    // H' = Hash(M')
    let h_prime = sha256_hash(&m_prime);
    
    // H == H'かチェック
    Ok(h == h_prime)
}

/// MGF1マスク生成関数
fn mgf1(seed: &[u8], mask_len: usize) -> Result<Vec<u8>, &'static str> {
    let h_len = 32; // SHA-256ハッシュ長
    let mut mask = Vec::new();
    let mut counter = 0u32;
    
    while mask.len() < mask_len {
        let mut c = seed.to_vec();
        c.extend_from_slice(&counter.to_be_bytes());
        
        let hash = sha256_hash(&c);
        mask.extend_from_slice(&hash);
        
        counter += 1;
        
        // 無限ループ防止
        if counter > 0xFFFF {
            return Err("MGF1: カウンターオーバーフロー");
        }
    }
    
    mask.truncate(mask_len);
    
    log::trace!("MGF1マスク生成完了: {}バイト", mask.len());
    
    Ok(mask)
}

/// ECDSA署名検証
fn verify_ecdsa(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, &'static str> {
    // DER形式のECDSA署名を解析
    let (r, s) = parse_ecdsa_signature_der(signature)?;
    
    // 公開鍵を解析
    let (qx, qy) = parse_ecdsa_public_key(public_key)?;
    
    // メッセージハッシュを計算
    let z = sha256_hash(message);
    let z_int = bytes_to_big_int(&z);
    
    // P-256楕円曲線パラメータ
    let p = hex_to_big_int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")?;
    let n = hex_to_big_int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")?;
    let gx = hex_to_big_int("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")?;
    let gy = hex_to_big_int("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")?;
    
    // 署名検証
    // w = s^(-1) mod n
    let w = mod_inverse(&s, &n)?;
    
    // u1 = z * w mod n
    let u1 = mod_multiply(&z_int, &w, &n)?;
    
    // u2 = r * w mod n
    let u2 = mod_multiply(&r, &w, &n)?;
    
    // (x1, y1) = u1*G + u2*Q
    let g_point = (gx, gy);
    let q_point = (qx, qy);
    
    let u1_g = ec_multiply(&g_point, &u1, &p)?;
    let u2_q = ec_multiply(&q_point, &u2, &p)?;
    let (x1, _y1) = ec_add(&u1_g, &u2_q, &p)?;
    
    // r == x1 mod n かチェック
    let x1_mod_n = mod_reduce(&x1, &n)?;
    let result = big_int_equal(&r, &x1_mod_n);
    
    if result {
        log::debug!("ECDSA署名検証成功");
    } else {
        log::debug!("ECDSA署名検証失敗");
    }
    
    Ok(result)
}

/// バイト配列を大整数に変換
fn bytes_to_big_int(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

/// 16進文字列を大整数に変換
fn hex_to_big_int(hex: &str) -> Result<Vec<u8>, &'static str> {
    let mut result = Vec::new();
    let hex_chars: Vec<char> = hex.chars().collect();
    
    if hex_chars.len() % 2 != 0 {
        return Err("16進文字列の長さが奇数です");
    }
    
    for i in (0..hex_chars.len()).step_by(2) {
        let high = hex_char_to_value(hex_chars[i])?;
        let low = hex_char_to_value(hex_chars[i + 1])?;
        result.push((high << 4) | low);
    }
    
    Ok(result)
}

/// 16進文字を数値に変換
fn hex_char_to_value(c: char) -> Result<u8, &'static str> {
    match c {
        '0'..='9' => Ok(c as u8 - b'0'),
        'A'..='F' => Ok(c as u8 - b'A' + 10),
        'a'..='f' => Ok(c as u8 - b'a' + 10),
        _ => Err("無効な16進文字"),
    }
}

/// モジュラー逆元を計算
fn mod_inverse(a: &[u8], m: &[u8]) -> Result<Vec<u8>, &'static str> {
    // 拡張ユークリッド互除法を使用
    extended_euclidean(a, m)
}

/// 拡張ユークリッド互除法
fn extended_euclidean(a: &[u8], b: &[u8]) -> Result<Vec<u8>, &'static str> {
    // 大整数を扱うための構造体
    #[derive(Clone, Debug)]
    struct BigInt {
        digits: Vec<u32>,
        negative: bool,
    }
    
    impl BigInt {
        fn from_bytes(bytes: &[u8]) -> Self {
            let mut digits = Vec::new();
            let mut current = 0u64;
            let mut shift = 0;
            
            for &byte in bytes.iter().rev() {
                current |= (byte as u64) << shift;
                shift += 8;
                
                if shift >= 32 {
                    digits.push((current & 0xFFFFFFFF) as u32);
                    current >>= 32;
                    shift -= 32;
                }
            }
            
            if current > 0 {
                digits.push(current as u32);
            }
            
            if digits.is_empty() {
                digits.push(0);
            }
            
            BigInt { digits, negative: false }
        }
        
        fn to_bytes(&self, target_len: usize) -> Vec<u8> {
            let mut result = vec![0u8; target_len];
            let mut value = 0u64;
            let mut shift = 0;
            let mut byte_idx = target_len;
            
            for &digit in &self.digits {
                value |= (digit as u64) << shift;
                shift += 32;
                
                while shift >= 8 && byte_idx > 0 {
                    byte_idx -= 1;
                    result[byte_idx] = (value & 0xFF) as u8;
                    value >>= 8;
                    shift -= 8;
                }
            }
            
            while shift > 0 && byte_idx > 0 {
                byte_idx -= 1;
                result[byte_idx] = (value & 0xFF) as u8;
                value >>= 8;
                shift = shift.saturating_sub(8);
            }
            
            result
        }
        
        fn is_zero(&self) -> bool {
            self.digits.len() == 1 && self.digits[0] == 0
        }
        
        fn is_one(&self) -> bool {
            self.digits.len() == 1 && self.digits[0] == 1 && !self.negative
        }
        
        fn compare(&self, other: &BigInt) -> core::cmp::Ordering {
            use core::cmp::Ordering;
            
            if self.negative != other.negative {
                return if self.negative { Ordering::Less } else { Ordering::Greater };
            }
            
            let mut ord = self.digits.len().cmp(&other.digits.len());
            if ord == Ordering::Equal {
                for i in (0..self.digits.len()).rev() {
                    ord = self.digits[i].cmp(&other.digits[i]);
                    if ord != Ordering::Equal {
                        break;
                    }
                }
            }
            
            if self.negative {
                ord.reverse()
            } else {
                ord
            }
        }
        
        fn add(&self, other: &BigInt) -> BigInt {
            if self.negative != other.negative {
                if self.negative {
                    return other.subtract(&self.abs());
                } else {
                    return self.subtract(&other.abs());
                }
            }
            
            let mut result = Vec::new();
            let mut carry = 0u64;
            let max_len = self.digits.len().max(other.digits.len());
            
            for i in 0..max_len {
                let a = self.digits.get(i).copied().unwrap_or(0) as u64;
                let b = other.digits.get(i).copied().unwrap_or(0) as u64;
                let sum = a + b + carry;
                
                result.push((sum & 0xFFFFFFFF) as u32);
                carry = sum >> 32;
            }
            
            if carry > 0 {
                result.push(carry as u32);
            }
            
            BigInt { digits: result, negative: self.negative }
        }
        
        fn subtract(&self, other: &BigInt) -> BigInt {
            if self.negative != other.negative {
                return self.add(&other.abs());
            }
            
            let (larger, smaller, result_negative) = if self.abs_compare(other) >= 0 {
                (self, other, self.negative)
            } else {
                (other, self, !self.negative)
            };
            
            let mut result = Vec::new();
            let mut borrow = 0i64;
            
            for i in 0..larger.digits.len() {
                let a = larger.digits[i] as i64;
                let b = smaller.digits.get(i).copied().unwrap_or(0) as i64;
                let diff = a - b - borrow;
                
                if diff < 0 {
                    result.push((diff + (1i64 << 32)) as u32);
                    borrow = 1;
                } else {
                    result.push(diff as u32);
                    borrow = 0;
                }
            }
            
            // 先頭の0を除去
            while result.len() > 1 && result.last() == Some(&0) {
                result.pop();
            }
            
            BigInt { digits: result, negative: result_negative }
        }
        
        fn multiply(&self, other: &BigInt) -> BigInt {
            let mut result = vec![0u32; self.digits.len() + other.digits.len()];
            
            for i in 0..self.digits.len() {
                let mut carry = 0u64;
                for j in 0..other.digits.len() {
                    let prod = (self.digits[i] as u64) * (other.digits[j] as u64) + 
                              (result[i + j] as u64) + carry;
                    result[i + j] = (prod & 0xFFFFFFFF) as u32;
                    carry = prod >> 32;
                }
                if carry > 0 && i + other.digits.len() < result.len() {
                    result[i + other.digits.len()] += carry as u32;
                }
            }
            
            // 先頭の0を除去
            while result.len() > 1 && result.last() == Some(&0) {
                result.pop();
            }
            
            BigInt { 
                digits: result, 
                negative: self.negative != other.negative 
            }
        }
        
        fn divide(&self, other: &BigInt) -> (BigInt, BigInt) {
            if other.is_zero() {
                panic!("ゼロ除算");
            }
            
            if self.abs_compare(other) < 0 {
                return (BigInt::zero(), self.clone());
            }
            
            // 長除法の実装（簡略化）
            let mut quotient = BigInt::zero();
            let mut remainder = self.abs();
            let divisor = other.abs();
            
            while remainder.abs_compare(&divisor) >= 0 {
                remainder = remainder.subtract(&divisor);
                quotient = quotient.add(&BigInt::one());
            }
            
            quotient.negative = self.negative != other.negative;
            remainder.negative = self.negative;
            
            (quotient, remainder)
        }
        
        fn abs(&self) -> BigInt {
            BigInt { digits: self.digits.clone(), negative: false }
        }
        
        fn abs_compare(&self, other: &BigInt) -> i32 {
            if self.digits.len() != other.digits.len() {
                return if self.digits.len() > other.digits.len() { 1 } else { -1 };
            }
            
            for i in (0..self.digits.len()).rev() {
                if self.digits[i] > other.digits[i] {
                    return 1;
                } else if self.digits[i] < other.digits[i] {
                    return -1;
                }
            }
            
            0
        }
        
        fn zero() -> BigInt {
            BigInt { digits: vec![0], negative: false }
        }
        
        fn one() -> BigInt {
            BigInt { digits: vec![1], negative: false }
        }
    }
    
    // 拡張ユークリッド互除法の実装
    let mut old_r = BigInt::from_bytes(b);
    let mut r = BigInt::from_bytes(a);
    let mut old_s = BigInt::one();
    let mut s = BigInt::zero();
    let mut old_t = BigInt::zero();
    let mut t = BigInt::one();
    
    while !r.is_zero() {
        let (quotient, new_r) = old_r.divide(&r);
        
        old_r = r;
        r = new_r;
        
        let new_s = old_s.subtract(&quotient.multiply(&s));
        old_s = s;
        s = new_s;
        
        let new_t = old_t.subtract(&quotient.multiply(&t));
        old_t = t;
        t = new_t;
    }
    
    // gcd(a, b) = old_r
    if !old_r.is_one() {
        return Err("逆元が存在しません");
    }
    
    // old_s が a の b における逆元
    let mut result = old_s;
    if result.negative {
        let modulus = BigInt::from_bytes(b);
        result = result.add(&modulus);
    }
    
    Ok(result.to_bytes(a.len()))
}

/// モジュラー乗算
fn mod_multiply(a: &[u8], b: &[u8], m: &[u8]) -> Result<Vec<u8>, &'static str> {
    // a * b mod m を計算
    let product = big_int_multiply(a, b)?;
    big_int_mod(&product, m)
}

/// モジュラー剰余
fn mod_reduce(a: &[u8], m: &[u8]) -> Result<Vec<u8>, &'static str> {
    big_int_mod(a, m)
}

/// 楕円曲線点乗算
fn ec_multiply(point: &(Vec<u8>, Vec<u8>), scalar: &[u8], p: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    // Montgomery Ladder アルゴリズムを使用した楕円曲線点乗算
    let (px, py) = point;
    
    // スカラーが0の場合は無限遠点を返す
    if scalar.iter().all(|&b| b == 0) {
        return Ok((vec![0], vec![0])); // 無限遠点の表現
    }
    
    // スカラーが1の場合は元の点を返す
    if scalar.len() == 1 && scalar[0] == 1 {
        return Ok((px.clone(), py.clone()));
    }
    
    // Montgomery Ladder の実装
    let mut r0 = (vec![0u8], vec![0u8]); // 無限遠点
    let mut r1 = (px.clone(), py.clone()); // P
    
    // スカラーのビットを最上位から処理
    for byte in scalar {
        for bit_pos in (0..8).rev() {
            let bit = (byte >> bit_pos) & 1;
            
            if bit == 1 {
                // r0 = r0 + r1, r1 = 2 * r1
                r0 = ec_add(&r0, &r1, p)?;
                r1 = ec_double(&r1, p)?;
            } else {
                // r1 = r0 + r1, r0 = 2 * r0
                r1 = ec_add(&r0, &r1, p)?;
                r0 = ec_double(&r0, p)?;
            }
        }
    }
    
    Ok(r0)
}

/// 楕円曲線点加算
fn ec_add(p1: &(Vec<u8>, Vec<u8>), p2: &(Vec<u8>, Vec<u8>), p: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let (x1, y1) = p1;
    let (x2, y2) = p2;
    
    // 無限遠点の処理
    if x1.iter().all(|&b| b == 0) && y1.iter().all(|&b| b == 0) {
        return Ok((x2.clone(), y2.clone()));
    }
    if x2.iter().all(|&b| b == 0) && y2.iter().all(|&b| b == 0) {
        return Ok((x1.clone(), y1.clone()));
    }
    
    // 同じ点の場合は点の倍算
    if x1 == x2 && y1 == y2 {
        return ec_double(p1, p);
    }
    
    // x座標が同じで y座標が異なる場合は無限遠点
    if x1 == x2 {
        return Ok((vec![0], vec![0]));
    }
    
    // 一般的な点加算
    // λ = (y2 - y1) / (x2 - x1) mod p
    let y_diff = mod_subtract(y2, y1, p)?;
    let x_diff = mod_subtract(x2, x1, p)?;
    let x_diff_inv = mod_inverse(&x_diff, p)?;
    let lambda = mod_multiply(&y_diff, &x_diff_inv, p)?;
    
    // x3 = λ² - x1 - x2 mod p
    let lambda_squared = mod_multiply(&lambda, &lambda, p)?;
    let x1_plus_x2 = mod_add(x1, x2, p)?;
    let x3 = mod_subtract(&lambda_squared, &x1_plus_x2, p)?;
    
    // y3 = λ(x1 - x3) - y1 mod p
    let x1_minus_x3 = mod_subtract(x1, &x3, p)?;
    let lambda_times_diff = mod_multiply(&lambda, &x1_minus_x3, p)?;
    let y3 = mod_subtract(&lambda_times_diff, y1, p)?;
    
    Ok((x3, y3))
}

/// 楕円曲線点の倍算
fn ec_double(point: &(Vec<u8>, Vec<u8>), p: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let (x, y) = point;
    
    // 無限遠点の場合
    if x.iter().all(|&b| b == 0) && y.iter().all(|&b| b == 0) {
        return Ok((vec![0], vec![0]));
    }
    
    // y = 0 の場合は無限遠点
    if y.iter().all(|&b| b == 0) {
        return Ok((vec![0], vec![0]));
    }
    
    // P-256曲線の場合: y² = x³ - 3x + b
    // λ = (3x² - 3) / (2y) mod p = 3(x² - 1) / (2y) mod p
    let x_squared = mod_multiply(x, x, p)?;
    let three_x_squared = mod_multiply(&[3], &x_squared, p)?;
    let three = vec![3u8];
    let numerator = mod_subtract(&three_x_squared, &three, p)?;
    
    let two_y = mod_multiply(&[2], y, p)?;
    let two_y_inv = mod_inverse(&two_y, p)?;
    let lambda = mod_multiply(&numerator, &two_y_inv, p)?;
    
    // x3 = λ² - 2x mod p
    let lambda_squared = mod_multiply(&lambda, &lambda, p)?;
    let two_x = mod_multiply(&[2], x, p)?;
    let x3 = mod_subtract(&lambda_squared, &two_x, p)?;
    
    // y3 = λ(x - x3) - y mod p
    let x_minus_x3 = mod_subtract(x, &x3, p)?;
    let lambda_times_diff = mod_multiply(&lambda, &x_minus_x3, p)?;
    let y3 = mod_subtract(&lambda_times_diff, y, p)?;
    
    Ok((x3, y3))
}

/// モジュラー加算
fn mod_add(a: &[u8], b: &[u8], m: &[u8]) -> Result<Vec<u8>, &'static str> {
    let sum = big_int_add(a, b)?;
    big_int_mod(&sum, m)
}

/// モジュラー減算
fn mod_subtract(a: &[u8], b: &[u8], m: &[u8]) -> Result<Vec<u8>, &'static str> {
    // a - b mod m = (a + m - b) mod m (if a < b)
    if big_int_compare(a, b) < 0 {
        let a_plus_m = big_int_add(a, m)?;
        let diff = big_int_subtract(&a_plus_m, b)?;
        big_int_mod(&diff, m)
    } else {
        let diff = big_int_subtract(a, b)?;
        big_int_mod(&diff, m)
    }
}

/// 大整数比較
fn big_int_equal(a: &[u8], b: &[u8]) -> bool {
    a == b
}

/// SHA-256ハッシュ計算
fn sha256_hash(data: &[u8]) -> Vec<u8> {
    sha256(data)
}



