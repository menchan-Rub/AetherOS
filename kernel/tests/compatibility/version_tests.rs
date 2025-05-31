// AetherOS バージョン互換性機能のテスト

use crate::universal_compatibility::version_manager::{OSVersion, OSType};
use crate::universal_compatibility::{CompatibilityManager, BinaryFormat};
use alloc::string::String;
use alloc::vec::Vec;

/// OSVersionの基本機能テスト
#[test]
fn test_os_version_basics() {
    // バージョン生成
    let win10 = OSVersion::new(10, 0, 19041, Some(1151), Some("Windows 10 20H2".to_string()));
    let win11 = OSVersion::new(11, 0, 22000, Some(795), Some("Windows 11 21H2".to_string()));
    
    // 比較テスト
    assert!(win11.is_newer_than(&win10));
    assert!(!win10.is_newer_than(&win11));
    
    // 同一メジャーバージョンでのマイナーバージョン比較
    let macos_monterey = OSVersion::new(12, 3, 1, None, Some("macOS Monterey".to_string()));
    let macos_ventura = OSVersion::new(13, 0, 0, None, Some("macOS Ventura".to_string()));
    
    assert!(macos_ventura.is_newer_than(&macos_monterey));
    assert!(!macos_monterey.is_newer_than(&macos_ventura));
    
    // 範囲内チェック
    let linux_5_15 = OSVersion::new(5, 15, 0, None, Some("Linux Kernel 5.15 LTS".to_string()));
    let linux_min = OSVersion::new(5, 10, 0, None, None);
    let linux_max = OSVersion::new(5, 19, 0, None, None);
    
    assert!(linux_5_15.is_in_range(&linux_min, &linux_max));
}

/// 文字列パース/フォーマットテスト
#[test]
fn test_os_version_string_parsing() {
    // バージョン文字列のパース
    let ver1 = OSVersion::from_string("10.0.19041").unwrap();
    assert_eq!(ver1.major, 10);
    assert_eq!(ver1.minor, 0);
    assert_eq!(ver1.patch, 19041);
    assert_eq!(ver1.build, None);
    
    // ビルド番号付きバージョン
    let ver2 = OSVersion::from_string("11.0.22000-795").unwrap();
    assert_eq!(ver2.major, 11);
    assert_eq!(ver2.minor, 0);
    assert_eq!(ver2.patch, 22000);
    assert_eq!(ver2.build, Some(795));
    
    // 文字列表現
    let ver3 = OSVersion::new(5, 15, 0, None, None);
    assert_eq!(ver3.to_string(), "5.15.0");
    
    let ver4 = OSVersion::new(10, 0, 19041, Some(1151), None);
    assert_eq!(ver4.to_string(), "10.0.19041-1151");
}

/// バージョン互換性チェックテスト
#[test]
fn test_compatibility_check() {
    // 互換性マネージャを取得
    let cm = CompatibilityManager::instance();
    
    // テスト用のバイナリデータ
    let fake_pe_binary = [0x4D, 0x5A, 0x90, 0x00]; // MZ\x90\x00 - PE/COFFファイルの先頭
    
    // バイナリ形式を検出
    let format = cm.detect_binary_format(&fake_pe_binary);
    assert_eq!(format, BinaryFormat::Pe);
    
    // 現在のエミュレーションバージョンを保存
    let old_win_ver = cm.get_emulated_os_version(OSType::Windows);
    
    // Windows 7をエミュレート
    cm.set_os_version_emulation(OSType::Windows, "6.1.0");
    
    // 互換性チェック（Windows 10が必要なバイナリなので互換性なし）
    let (compat, issues) = cm.check_binary_compatibility(&fake_pe_binary);
    assert!(!compat);
    assert!(!issues.is_empty());
    
    // Windows 10をエミュレート
    cm.set_os_version_emulation(OSType::Windows, "10.0.19041");
    
    // 互換性チェック（今度は互換性あり）
    let (compat, _) = cm.check_binary_compatibility(&fake_pe_binary);
    assert!(compat);
    
    // 元のエミュレーションバージョンに戻す
    if let Some(ver) = old_win_ver {
        cm.set_os_version_emulation(OSType::Windows, &ver.to_string());
    }
}

/// API互換性チェックテスト
#[test]
fn test_api_compatibility() {
    // 互換性マネージャを取得
    let cm = CompatibilityManager::instance();
    
    // 現在のエミュレーションバージョンを保存
    let old_win_ver = cm.get_emulated_os_version(OSType::Windows);
    
    // Windows XPをエミュレート
    cm.set_os_version_emulation(OSType::Windows, "5.1.0");
    
    // CreateFileW API互換性チェック（XPでは利用可能）
    assert!(cm.check_api_compatibility(OSType::Windows, "CreateFileW"));
    
    // Windows 8+のAPIはXPでは利用不可
    assert!(!cm.check_api_compatibility(OSType::Windows, "RoGetActivationFactory"));
    
    // Windows 8をエミュレート
    cm.set_os_version_emulation(OSType::Windows, "6.2.0");
    
    // Windows 8ではWinRTのAPIが利用可能
    assert!(cm.check_api_compatibility(OSType::Windows, "RoGetActivationFactory"));
    
    // 元のエミュレーションバージョンに戻す
    if let Some(ver) = old_win_ver {
        cm.set_os_version_emulation(OSType::Windows, &ver.to_string());
    }
}

/// Linuxバージョン互換性テスト
#[test]
fn test_linux_compatibility() {
    // 互換性マネージャを取得
    let cm = CompatibilityManager::instance();
    
    // 現在のエミュレーションバージョンを保存
    let old_linux_ver = cm.get_emulated_os_version(OSType::Linux);
    
    // 古いLinuxカーネルをエミュレート
    cm.set_os_version_emulation(OSType::Linux, "4.19.0");
    
    // 基本的なsyscallは利用可能
    assert!(cm.check_api_compatibility(OSType::Linux, "open"));
    
    // Linux 5.6以降のAPIは利用不可
    assert!(!cm.check_api_compatibility(OSType::Linux, "openat2"));
    
    // 新しいLinuxカーネルをエミュレート
    cm.set_os_version_emulation(OSType::Linux, "5.15.0");
    
    // 新しいsyscallも利用可能
    assert!(cm.check_api_compatibility(OSType::Linux, "openat2"));
    
    // 元のエミュレーションバージョンに戻す
    if let Some(ver) = old_linux_ver {
        cm.set_os_version_emulation(OSType::Linux, &ver.to_string());
    }
}

/// macOSバージョン互換性テスト
#[test]
fn test_macos_compatibility() {
    // 互換性マネージャを取得
    let cm = CompatibilityManager::instance();
    
    // 現在のエミュレーションバージョンを保存
    let old_macos_ver = cm.get_emulated_os_version(OSType::MacOS);
    
    // 古いmacOSをエミュレート
    cm.set_os_version_emulation(OSType::MacOS, "10.7.0");
    
    // FSOpenIteratorはOS X Leopard(10.4)から利用可能
    assert!(cm.check_api_compatibility(OSType::MacOS, "FSOpenIterator"));
    
    // 新しいmacOSをエミュレート
    cm.set_os_version_emulation(OSType::MacOS, "10.15.0");
    
    // FSOpenIteratorはmacOS Mojave(10.14)以降では非推奨
    // 実際の実装では警告が表示されるが、まだ利用可能
    assert!(cm.check_api_compatibility(OSType::MacOS, "FSOpenIterator"));
    
    // 元のエミュレーションバージョンに戻す
    if let Some(ver) = old_macos_ver {
        cm.set_os_version_emulation(OSType::MacOS, &ver.to_string());
    }
}

/// 複合テスト - システム情報
#[test]
fn test_system_version_info() {
    // 各種OSのバージョン情報を表示
    let cm = CompatibilityManager::instance();
    
    // Windows情報
    if let Some(win_ver) = cm.get_emulated_os_version(OSType::Windows) {
        println!("エミュレート中のWindows: {}", win_ver.to_string());
        if let Some(name) = &win_ver.name {
            println!("名称: {}", name);
        }
    }
    
    // Linux情報
    if let Some(linux_ver) = cm.get_emulated_os_version(OSType::Linux) {
        println!("エミュレート中のLinux: {}", linux_ver.to_string());
        if let Some(name) = &linux_ver.name {
            println!("名称: {}", name);
        }
    }
    
    // macOS情報
    if let Some(macos_ver) = cm.get_emulated_os_version(OSType::MacOS) {
        println!("エミュレート中のmacOS: {}", macos_ver.to_string());
        if let Some(name) = &macos_ver.name {
            println!("名称: {}", name);
        }
    }
} 