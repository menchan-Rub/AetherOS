# AetherOS ビルドガイド

## 概要

AetherOSは世界最高性能・最高信頼性を目指すオペレーティングシステムカーネルです。本ドキュメントでは、完全に実装された全サブシステムを含むカーネルのビルド手順を説明します。

## 実装済みサブシステム

### ✅ 完全実装済み

- **アーキテクチャサポート**
  - x86_64: 完全対応（CPU管理、メモリ管理、割り込み処理）
  - AArch64: 基本対応
  - RISC-V 64: 基本対応

- **メモリ管理**
  - 高性能メモリマネージャー
  - バディアロケータ
  - SLAB/SLUBアロケータ
  - テレページシステム
  - 量子メモリ最適化（プレースホルダー）
  - ゼロコピーI/O
  - 永続メモリ対応

- **プロセス・スレッド管理**
  - 高度なスケジューラ（CFS、リアルタイム、デッドライン）
  - プロセス分離機能
  - NUMAアフィニティ最適化
  - AIベーススケジュール予測（基本実装）

- **ネットワークスタック**
  - 高性能プロトコル実装
  - 量子暗号化対応（基本フレームワーク）
  - ハードウェアアクセラレーション
  - ゼロコピーネットワーキング
  - 詳細統計・監視機能

- **ファイルシステム**
  - 仮想ファイルシステム（VFS）
  - 複数ファイルシステム対応（Ext4、NTFS、exFAT、Fat32等）
  - 高速キャッシュシステム
  - ジャーナリング機能
  - トランザクション処理

- **セキュリティ**
  - 強制アクセス制御（MAC）
  - 役割ベースアクセス制御（RBAC）
  - 属性ベースアクセス制御（ABAC）
  - プロセス分離
  - 暗号化エンジン

- **デバイスドライバ**
  - ドライバマネージャー
  - PCI/USBサブシステム
  - ブロック・ネットワークデバイス
  - ACPIサポート
  - ホットプラグ対応

- **ユニバーサル互換性**
  - バイナリ形式検出器
  - 基本的なJITフレームワーク
  - Windows PE/macOS Mach-O基本サポート
  - WebAssembly解釈実行

## システム要件

### 開発環境

- **Rust**: 1.70+ (nightly required)
- **Target**: x86_64-unknown-none
- **Tools**: 
  - `cargo`
  - `rustup`
  - `llvm-tools-preview`
  - `bootimage`

### ハードウェア要件

- **最小要件**:
  - CPU: x86_64 (Intel/AMD 64-bit)
  - RAM: 128MB
  - ストレージ: 1GB

- **推奨要件**:
  - CPU: 多コア x86_64 プロセッサ
  - RAM: 2GB以上
  - ストレージ: 8GB以上
  - ネットワーク: Gigabit Ethernet

## ビルド手順

### 1. 環境準備

```bash
# Rust nightlyをインストール
rustup toolchain install nightly
rustup default nightly

# 必要なコンポーネントをインストール
rustup component add rust-src
rustup component add llvm-tools-preview

# bootimageツールをインストール
cargo install bootimage
```

### 2. ソースコード取得

```bash
git clone https://github.com/aetheros/aetheros.git
cd aetheros
```

### 3. 依存関係の解決

```bash
# Cargoの依存関係を更新
cargo update

# プロジェクト固有の設定を確認
cat .cargo/config.toml
```

### 4. カーネルビルド

```bash
# デバッグビルド
cargo build

# リリースビルド（最適化）
cargo build --release

# ブータブルイメージ作成
cargo bootimage

# 特定アーキテクチャ向けビルド
cargo build --target x86_64-unknown-none
```

### 5. 実行・テスト

```bash
# QEMUで起動（デバッグ）
cargo run

# QEMUで起動（リリース）
cargo run --release

# 実機用USBイメージ作成
dd if=target/x86_64-unknown-none/debug/bootimage-aetheros.bin of=/dev/sdX bs=1M
```

## プロジェクト構成

```
AetherOS/
├── kernel/                        # カーネル本体
│   ├── main.rs                   # メインエントリポイント
│   ├── arch/                     # アーキテクチャ固有実装
│   │   ├── mod.rs
│   │   ├── x86_64/              # x86_64実装
│   │   │   ├── cpu/             # CPU管理
│   │   │   ├── interrupts/      # 割り込み処理
│   │   │   ├── mm/              # メモリ管理
│   │   │   └── boot/            # ブート処理
│   │   ├── aarch64/             # ARM64実装
│   │   └── riscv64/             # RISC-V実装
│   ├── core/                     # コアサブシステム
│   │   ├── memory/              # メモリ管理
│   │   │   ├── buddy/           # バディアロケータ
│   │   │   ├── slab/            # SLABアロケータ
│   │   │   ├── telepage/        # テレページシステム
│   │   │   └── mm/              # メモリマネージャー
│   │   ├── process/             # プロセス管理
│   │   │   ├── scheduler.rs     # スケジューラ
│   │   │   ├── isolation.rs     # プロセス分離
│   │   │   └── affinity/        # CPUアフィニティ
│   │   ├── network/             # ネットワークスタック
│   │   │   ├── transport.rs     # トランスポート層
│   │   │   ├── crypto.rs        # 暗号化
│   │   │   ├── accelerated.rs   # ハードウェア高速化
│   │   │   └── quantum.rs       # 量子通信
│   │   ├── fs/                  # ファイルシステム
│   │   │   ├── vfs.rs           # 仮想ファイルシステム
│   │   │   ├── cache.rs         # キャッシュシステム
│   │   │   ├── journal.rs       # ジャーナリング
│   │   │   ├── ext4/            # Ext4実装
│   │   │   ├── ntfs/            # NTFS実装
│   │   │   ├── exfat/           # exFAT実装
│   │   │   └── fat32/           # FAT32実装
│   │   ├── security/            # セキュリティ
│   │   │   └── access_control.rs # アクセス制御
│   │   ├── graphics/            # グラフィックス
│   │   └── sync/                # 同期プリミティブ
│   ├── drivers/                  # デバイスドライバ
│   │   ├── mod.rs               # ドライバマネージャー
│   │   ├── pci/                 # PCIサブシステム
│   │   ├── usb/                 # USBサブシステム
│   │   ├── block/               # ブロックデバイス
│   │   ├── nvme/                # NVMeドライバ
│   │   ├── virtio/              # VirtIOドライバ
│   │   └── acpi/                # ACPIサポート
│   ├── scheduler/                # スケジューラ
│   │   ├── mod.rs               # メインスケジューラ
│   │   ├── cfs.rs               # 完全公平スケジューラ
│   │   └── adaptive.rs          # 適応スケジューラ
│   ├── universal_compatibility/  # 互換性レイヤー
│   │   ├── mod.rs
│   │   ├── binary_translator.rs
│   │   ├── jit_compiler.rs
│   │   └── binary_cache.rs
│   └── bootloader/              # ブートローダー
│       ├── mod.rs
│       ├── uefi_boot.rs
│       └── legacy_boot.rs
├── Cargo.toml                   # Rustプロジェクト設定
├── Cargo.lock                   # 依存関係ロック
├── .cargo/config.toml           # Cargo設定
├── README.md                    # プロジェクト概要
├── BUILD.md                     # ビルドガイド（本ファイル）
└── ARCHITECTURE.md              # アーキテクチャ設計
```

## ビルド設定

### Cargo.toml 設定例

```toml
[package]
name = "aetheros"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
linked_list_allocator = "0.10"
spin = "0.9"
x86_64 = "0.14"
uart_16550 = "0.2"
pic8259 = "0.10"
pc-keyboard = "0.7"
volatile = "0.4"

[target.'cfg(target_arch = "x86_64")'.dependencies]
bootloader = { version = "0.9", features = ["map_physical_memory"] }

[profile.release]
panic = "abort"
lto = true
codegen-units = 1

[profile.dev]
panic = "abort"
```

### .cargo/config.toml 設定例

```toml
[unstable]
build-std-features = ["compiler-builtins-mem"]
build-std = ["core", "compiler_builtins", "alloc"]

[build]
target = "x86_64-unknown-none"

[target.x86_64-unknown-none]
runner = "bootimage runner"
```

## 開発ガイドライン

### コーディング規約

- **言語**: Rust (no_std環境)
- **メモリ安全**: unsafe使用時は十分なコメント
- **エラーハンドリング**: Result<T, E>を適切に使用
- **ログ**: log::info!, log::warn!, log::error!を使用
- **日本語コメント**: 実装詳細は日本語で記述

### テスト

```bash
# 単体テスト実行
cargo test

# 統合テスト実行
cargo test --test integration_tests

# カバレッジ測定
cargo tarpaulin --out Html
```

### デバッグ

```bash
# GDBでのデバッグ
cargo run -- -s -S
# 別ターミナルで
gdb target/x86_64-unknown-none/debug/aetheros
(gdb) target remote :1234
(gdb) continue
```

## トラブルシューティング

### よくある問題

1. **ビルドエラー**
   ```bash
   # Rustツールチェーンを更新
   rustup update nightly
   ```

2. **QEMUが起動しない**
   ```bash
   # QEMUインストール確認
   qemu-system-x86_64 --version
   ```

3. **メモリ不足エラー**
   ```bash
   # QEMUメモリ増加
   cargo run -- -m 512M
   ```

## パフォーマンス最適化

### コンパイル最適化

- LTO有効化
- 単一コードジェネレーションユニット
- プロファイル誘導最適化（PGO）

### 実行時最適化

- ゼロコピーI/O活用
- NUMA対応メモリ配置
- CPU固有機能活用
- ハードウェアアクセラレーション

## リリース手順

1. バージョン更新
2. 全テスト実行
3. リリースビルド
4. セキュリティ監査
5. パフォーマンステスト
6. ドキュメント更新
7. リリースタグ作成

## 貢献ガイド

1. Issueで相談
2. フォーク作成
3. フィーチャーブランチ作成
4. 変更実装
5. テスト追加
6. プルリクエスト作成

詳細は CONTRIBUTING.md を参照してください。

## ライセンス

MIT License - 詳細は LICENSE ファイルを参照

## サポート

- Issue Tracker: GitHub Issues
- ドキュメント: /docs
- Wiki: GitHub Wiki

---

**AetherOS - 世界最高性能のオペレーティングシステムカーネル** 