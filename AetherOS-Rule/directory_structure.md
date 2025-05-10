### AetherOS: ディレクトリ構造

```
/AetherOS/
├── kernel/                      # カーネルソースコード
│   ├── arch/                    # アーキテクチャ固有コード (x86_64, aarch64, riscv)
│   ├── core/                    # コアカーネル機能
│   │   ├── process/             # プロセス/スレッド管理、スケジューリング
│   │   ├── memory/              # メモリ管理 (ページング, アロケータ, NUMA, CXL)
│   │   │   ├── mm/              # 仮想メモリ管理
│   │   │   ├── slab/            # スラブアロケータ
│   │   │   ├── buddy/           # バディアロケータ
│   │   │   └── pmem/            # 不揮発性メモリ管理
│   │   ├── sync/                # 同期プリミティブ (Mutex, Sem, RWLock)
│   │   ├── ipc/                 # プロセス間通信 (パイプ, シグナル, メッセージキュー, 共有メモリ)
│   │   └── time/                # 時間管理、タイマー
│   ├── drivers/                 # デバイスドライバ
│   │   ├── block/               # ブロックデバイス (NVMe, SATA, VirtIO-Blk)
│   │   ├── char/                # キャラクタデバイス (シリアル, TTY)
│   │   ├── gpu/                 # GPUドライバ (DRM/KMSベース)
│   │   ├── net/                 # ネットワークドライバ (Ethernet, WiFi, RDMA)
│   │   ├── usb/                 # USBホスト/デバイスコントローラ
│   │   ├── pci/                 # PCI/PCIeバス
│   │   ├── input/               # 入力デバイス (キーボード, マウス, タッチ)
│   │   └── platform/            # プラットフォーム固有ドライバ (ACPI, DTB)
│   ├── fs/                      # ファイルシステム
│   │   ├── aefs/                # AetherOS ネイティブFS (トランザクショナル, 時空間)
│   │   ├── compat/              # 互換FS (ext4, ntfs, apfs, fat)
│   │   ├── vfs/                 # 仮想ファイルシステムレイヤー
│   │   ├── cache/               # ファイルシステムキャッシュ
│   │   └── distributed/         # 分散FSクライアント (NFS, CephFS)
│   ├── net/                     # ネットワークスタック
│   │   ├── core/                # コアネットワーク機能 (ソケット, プロトコル管理)
│   │   ├── ipv4/                # IPv4 実装
│   │   ├── ipv6/                # IPv6 実装
│   │   ├── tcp/                 # TCP 実装
│   │   ├── udp/                 # UDP 実装
│   │   ├── transport/           # トランスポート層 (TLS, QUIC)
│   │   ├── routing/             # ルーティング
│   │   └── wireless/            # 無線LAN (802.11), Bluetooth
│   ├── security/                # セキュリティサブシステム
│   │   ├── capability/          # ケイパビリティベースアクセス制御
│   │   ├── sandbox/             # サンドボックス機構 (プロセス分離強化)
│   │   ├── crypto/              # 暗号化API (HWアクセラレーション)
│   │   ├── integrity/           # システム整合性検証 (IMA/EVM)
│   │   └── audit/               # 監査ログ
│   ├── power/                   # 電力管理
│   │   ├── cpufreq/             # CPU 周波数スケーリング
│   │   ├── cpuidle/             # CPU アイドル管理
│   │   ├── suspend/             # サスペンド / ハイバネート
│   │   └── adaptive/            # AI 支援電力制御
│   └── include/                 # カーネル公開ヘッダー
├── system/                      # システムコンポーネント
│   ├── init/                    # システム初期化マネージャ (systemd/launchd 代替)
│   ├── hal/                     # ハードウェア抽象化レイヤー (HAL)
│   ├── services/                # システムサービスデーモン
│   │   ├── device_manager/      # デバイス管理
│   │   ├── network_manager/     # ネットワーク管理
│   │   ├── storage_manager/     # ストレージ管理
│   │   ├── security_daemon/     # セキュリティサービス
│   │   ├── identity_manager/    # ID/認証管理
│   │   ├── update_service/      # システム更新サービス
│   │   ├── log_service/         # ログ収集・管理
│   │   └── power_manager/       # 電力管理
│   ├── runtime/                 # ランタイム環境
│   │   ├── libc/                # C 標準ライブラリ (musl 拡張)
│   │   ├── libae/               # AetherOS コアライブラリ (Rust)
│   │   ├── compatibility/       # 互換ランタイム (Linux, Windows, macOS)
│   │   └── wasm/                # WebAssembly ランタイム (WASI)
│   └── recovery/                # システム回復環境
├── interface/                   # UI レイヤ (LumosDesktop, NexusShell)
│   ├── lumos/                   # LumosDesktop シェル
│   └── nexus_shell/             # NexusShell シェル
├── applications/                # 標準アプリケーション
│   ├── core/                    # コアユーティリティ
│   ├── utilities/               # 日常ユーティリティ
│   └── media/                   # メディアアプリ
├── sdk/                         # 開発キット
│   ├── compiler/                # コンパイラ (LLVM/Clang, Rustc, GCC)
│   ├── libraries/               # 開発ライブラリ (GUI, Media, Net, AI, Crypto, ...)
│   ├── tools/                   # デバッガ・プロファイラ等
│   ├── frameworks/              # アプリケーションフレームワーク
│   └── documentation/           # API ドキュメント
├── platform/                    # プラットフォーム最適化
│   ├── desktop/                 # デスクトップ向け
│   ├── server/                  # サーバー向け
│   ├── mobile/                  # モバイル向け
│   ├── embedded/                # 組み込み向け
│   └── virtual/                 # 仮想環境向け
├── formal/                      # 形式検証
│   ├── specs/                   # 仕様記述
│   ├── proofs/                  # 証明スクリプト
│   └── tools/                   # 検証ツール連携
├── third_party/                 # サードパーティライブラリ
│   ├── licensed/                # ライセンス付き
│   └── open_source/             # オープンソース
├── tests/                       # テストスイート
│   ├── unit/                    # ユニットテスト
│   ├── integration/             # 統合テスト
│   ├── system/                  # システムテスト (E2E)
│   ├── performance/             # パフォーマンステスト
│   ├── security/                # セキュリティテスト
│   ├── compatibility/           # 互換性テスト
│   └── formal/                  # 形式検証テスト
├── build/                       # ビルドシステム設定
│   ├── Makefile                 # ルート Makefile
│   ├── CMakeLists.txt           # CMake 定義
│   ├── WORKSPACE                # Bazel ワークスペース
│   └── .bazelrc                 # Bazel 設定
├── scripts/                     # 開発・デプロイ用スクリプト
│   ├── setup_env.sh             # 環境セットアップ
│   ├── build_all.sh             # 全ビルドスクリプト
│   └── deploy.sh                # デプロイスクリプト
├── .gitignore                   # Git 無視設定
├── README.md                    # プロジェクト概要
├── LICENSE_MIT                  # MIT ライセンス
├── LICENSE_APACHE               # Apache ライセンス
└── CONTRIBUTING.md              # 貢献ガイドライン
```

#### 主要ディレクトリの説明 (更新)

1. **kernel/**: (変更なし)
   - **kernel/core/memory/**: NUMA/CXL対応、階層メモリ管理などを追加。
   - **kernel/drivers/**: より具体的なドライバ分類 (PCI, Input, Platform)。
   - **kernel/fs/**: 互換FS、キャッシュ、分散FSクライアントを明確化。
   - **kernel/net/**: TCP/UDP、トランスポート層、ルーティングなどを詳細化。
   - **kernel/security/**: IMA/EVM相当の整合性検証、監査ログを追加。
   - **kernel/power/**: CPUFreq/Idle、サスペンド、AI支援制御を追加。

2. **system/**: (変更なし)
   - **system/services/**: より具体的なサービスデーモンを列挙。
   - **system/runtime/**: AetherOSコアライブラリ(`libae`)、WASMランタイムを追加。

3. **interface/**: LumosDesktopとNexusShellの詳細はそれぞれのディレクトリ構造を参照するように変更。

4. **applications/**: (変更なし)

5. **sdk/**: アプリケーションフレームワークを追加。

6. **platform/**: (変更なし)

7. **ai/**: 新規追加。OSに統合されるAIコンポーネントを格納。

8. **formal/**: 新規追加。形式検証関連の仕様、証明、ツール連携を格納。

9. **third_party/**: (変更なし)

10. **tests/**:
    - システムテスト (E2E) を追加。
    - 形式検証連携テストを追加。

11. **docs/**: ホワイトペーパーを追加。