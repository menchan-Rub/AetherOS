# AetherOS バディアロケータ

## 概要

バディアロケータはAetherOSにおける物理メモリページ割り当ての基盤となるシステムです。2のべき乗サイズのメモリブロックを効率的に管理し、メモリ断片化を最小化しつつ高速な割り当てと解放を実現します。

## 基本原理

バディシステムは以下の原則に基づいて動作します：

1. 物理メモリを2のべき乗サイズのブロックに分割
2. 各ブロックサイズごとにフリーリストを管理
3. 必要なサイズに最も近いブロックを割り当て
4. 大きなブロックは必要に応じて分割（バディの生成）
5. 解放時に隣接するバディが空いていれば結合

## 主要機能

### ページ割り当て

```rust
/// 通常ページ（4KB）の割り当て
pub fn allocate_pages(count: usize, flags: AllocFlags, numa_node: u8) -> Result<usize, &'static str>;

/// 連続した物理ページの割り当て
pub fn allocate_pages_contiguous(count: usize, flags: AllocFlags, numa_node: u8) -> Result<usize, &'static str>;

/// ヒュージページ（2MB）の割り当て
pub fn allocate_huge_pages(count: usize, flags: AllocFlags, numa_node: u8) -> Result<usize, &'static str>;

/// ギガンティックページ（1GB）の割り当て
pub fn allocate_gigantic_pages(count: usize, flags: AllocFlags, numa_node: u8) -> Result<usize, &'static str>;
```

### ページ解放

```rust
/// 通常ページの解放
pub fn free_pages(address: usize, count: usize) -> Result<(), &'static str>;

/// ヒュージページの解放
pub fn free_huge_pages(address: usize, count: usize) -> Result<(), &'static str>;

/// ギガンティックページの解放
pub fn free_gigantic_pages(address: usize, count: usize) -> Result<(), &'static str>;
```

### 管理・監視機能

```rust
/// 断片化の分析
pub fn analyze_fragmentation() -> Result<usize, &'static str>;

/// ゾーン情報の取得
pub fn get_zone_info() -> Vec<ZoneInfo>;

/// アロケータ統計の取得
pub fn get_stats() -> BuddyStats;
```

## 高度な機能

### マルチゾーン管理

物理メモリを複数のゾーン（ZONE_DMA, ZONE_NORMAL, ZONE_HIGHMEM等）に分割して管理します：

- 各ゾーンはそれぞれ独立したバディシステムを持つ
- ゾーン特性に基づいて割り当て戦略を最適化
- ゾーン間のバランスを監視して調整

### NUMA対応

NUMA（Non-Uniform Memory Access）アーキテクチャに最適化された割り当てを実現：

- ノード単位のバディシステム管理
- ローカルノード優先の割り当て
- ノード間負荷分散
- スレッドアフィニティと連携した割り当て

### ヒュージページサポート

TLB（Translation Lookaside Buffer）の効率を向上させるヒュージページ管理：

- 2MB/1GBページの特殊管理
- 専用フリーリストによる高速割り当て
- 透過的な通常ページとの変換
- 適応的ヒュージページ割り当てポリシー

### アンチフラグメンテーション

メモリ断片化を積極的に防止・解消する機能：

- バックグラウンドデフラグメンテーション
- マイグレーションによる連続領域の確保
- ブロック配置の最適化
- 断片化メトリクスの継続的監視

## 実装の詳細

### データ構造

バディアロケータは以下の主要データ構造を使用します：

```rust
/// バディシステムのオーダー（サイズ）定義
pub const MAX_ORDER: usize = 11;  // 4KBから4MBまで

/// フリーエリアのリスト
struct FreeArea {
    free_list: LinkedList<PhysPage>,
    count: usize,
}

/// ゾーン定義
struct Zone {
    name: &'static str,
    start_pfn: usize,
    end_pfn: usize,
    free_areas: [FreeArea; MAX_ORDER + 1],
    total_pages: usize,
    free_pages: AtomicUsize,
    lock: Spinlock<()>,
}

/// ノード定義（NUMA用）
struct Node {
    id: u8,
    zones: Vec<Zone>,
    total_pages: usize,
    free_pages: AtomicUsize,
}
```

### アルゴリズム

#### 割り当てアルゴリズム

1. 要求されたページ数から必要なオーダーを計算
2. 指定されたノードとゾーンのフリーリストを探索
3. 適切なサイズのブロックが見つからない場合、大きなブロックを分割
4. 分割時は残りのバディをフリーリストに戻す
5. 割り当てられたブロックを追跡情報に登録

#### 解放アルゴリズム

1. 解放されるアドレスから物理ページフレーム番号を計算
2. ページのバディ（兄弟ブロック）が空いているか確認
3. バディが空いている場合、両方を結合して一つ上のオーダーのブロックを形成
4. 結合プロセスは再帰的に続行（最大オーダーまで）
5. 追跡情報から該当エントリを削除

## パフォーマンス特性

- **割り当て時間複雑性**: O(log n) - nはオーダー数
- **解放時間複雑性**: O(log n)
- **メモリオーバーヘッド**: 約1%（ページ管理構造体用）
- **断片化率**: 通常使用で5～15%（ワークロードによる）

## 最適化技術

### 先行割り当て

予測に基づいてページを先行割り当てし、後続の割り当て要求を高速化します：

- 使用パターン分析による予測
- アイドル時の事前準備
- コールドパスとホットパスの分離

### ロックレス操作

スケーラビリティを向上させるロックレスアルゴリズムを一部操作に適用：

- RCU（Read-Copy-Update）ベースのリスト操作
- パーコア割り当てキャッシュ
- アトミック操作による同期

### キャッシュローカリティ

CPUキャッシュの効率を最大化する最適化：

- NUMA対応データ構造配置
- キャッシュライン配慮型データ構造
- データアクセスパターンの最適化

## 設定オプション

バディアロケータの動作は以下の設定で調整できます：

```rust
/// バディアロケータ設定
pub struct BuddyConfig {
    /// 先行割り当て率（0.0～1.0）
    pub prefetch_ratio: f32,
    
    /// デフラグ実行のしきい値（0～100%）
    pub defrag_threshold: usize,
    
    /// 連続割り当て最大サイズ（ページ数）
    pub max_contiguous_allocation: usize,
    
    /// バックグラウンドデフラグ有効化
    pub enable_background_defrag: bool,
    
    /// メモリゾーンバランス比率
    pub zone_balance_ratio: [f32; MAX_ZONES],
}
```

## デバッグ機能

開発者向けのデバッグ機能が用意されています：

- 詳細なメモリマップのダンプ
- フリーリスト整合性の検証
- 割り当て追跡と統計情報
- パフォーマンスプロファイリング

## 使用例

### 基本的な使用方法

```rust
// バディアロケータを初期化
buddy::init(memory_map)?;

// 4ページ（16KB）を割り当て
let flags = AllocFlags::new(AllocFlags::ZERO);
let address = buddy::allocate_pages(4, flags, 0)?;

// メモリを使用
use_memory(address, 4 * PAGE_SIZE);

// メモリを解放
buddy::free_pages(address, 4)?;
```

### 連続メモリの割り当て

```rust
// DMA用に連続した物理メモリを割り当て
let flags = AllocFlags::new(AllocFlags::CONTIGUOUS | AllocFlags::DMA);
let address = buddy::allocate_pages_contiguous(16, flags, 0)?;

// DMA操作を実行
perform_dma_operation(address, 16 * PAGE_SIZE);

// 解放
buddy::free_pages(address, 16)?;
```

### ヒュージページの使用

```rust
// 2MBヒュージページを割り当て（アドレス変換キャッシュのヒット率向上）
let flags = AllocFlags::new(AllocFlags::HUGE_PAGE);
let address = buddy::allocate_huge_pages(1, flags, 0)?;

// 大きなデータ構造を配置
place_large_data_structure(address, 2 * 1024 * 1024);

// 解放
buddy::free_huge_pages(address, 1)?;
```

## 将来の拡張計画

- **ML予測アロケーション**: 機械学習を用いた割り当てパターン予測
- **ハードウェアアクセラレーション**: メモリコントローラと連携した高速操作
- **エラスティックゾーニング**: 実行時のゾーン境界動的調整
- **セキュアアロケーション**: 物理メモリレイアウトのランダム化

---

© AetherOS Project 