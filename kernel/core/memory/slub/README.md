# AetherOS SLUBアロケータ

## 概要

SLUBアロケータ（Slab Unqueued Buddy-based Allocator）は、AetherOSカーネルにおける小サイズメモリ割り当て用の高性能オブジェクトアロケータです。従来のSlabアロケータを拡張し、キャッシュ効率、スケーラビリティ、メモリ使用効率を大幅に向上させています。

## 基本原理

SLUBアロケータは以下の原則に基づいて動作します：

1. 同一サイズのオブジェクトをスラブ（ページブロック）で管理
2. 各CPUコアに対してローカルキャッシュを維持
3. オブジェクト再利用によるメモリ効率の最大化
4. ページ割り当てとの統合による複雑性の最小化
5. スケーラビリティの確保と同期オーバーヘッドの削減

## 主要機能

### メモリ割り当て・解放

```rust
/// オブジェクト割り当て
pub fn allocate(size: usize, flags: AllocFlags) -> Result<usize, &'static str>;

/// オブジェクト解放
pub fn free(address: usize, size: usize) -> Result<(), &'static str>;

/// アラインメント付き割り当て
pub fn allocate_aligned(size: usize, align: usize, flags: AllocFlags) -> Result<usize, &'static str>;
```

### キャッシュ管理

```rust
/// 新しいキャッシュの作成
pub fn create_cache(name: &str, size: usize, align: usize, flags: CacheFlags) -> Result<CacheId, &'static str>;

/// キャッシュからのオブジェクト割り当て
pub fn cache_alloc(cache_id: CacheId) -> Result<usize, &'static str>;

/// キャッシュへのオブジェクト返却
pub fn cache_free(cache_id: CacheId, address: usize) -> Result<(), &'static str>;

/// キャッシュの破棄
pub fn destroy_cache(cache_id: CacheId) -> Result<(), &'static str>;
```

### システム管理

```rust
/// SLUBアロケータの初期化
pub fn init() -> Result<(), &'static str>;

/// メモリ不足時の緊急収縮
pub fn emergency_shrink() -> Result<usize, &'static str>;

/// 統計情報の取得
pub fn get_stats() -> SlubStats;
```

## アーキテクチャ

### キャッシュヒエラルキー

SLUBアロケータは3層のヒエラルキーでオブジェクトを管理します：

1. **グローバルキャッシュ**: 全体の構造とスラブを管理
2. **パーCPUキャッシュ**: 各CPUコア専用のオブジェクトリスト
3. **ホットオブジェクトリスト**: 最近使用されたオブジェクトの高速アクセスリスト

### サイズクラス

メモリ効率を最大化するために、オブジェクトサイズに基づいて最適化されたサイズクラスを用意しています：

- 小サイズクラス: 8, 16, 32, 64, 128, 256バイト
- 中サイズクラス: 512, 1024, 2048バイト
- 大サイズクラス: 4096, 8192バイト

各サイズクラスは専用のキャッシュを持ち、内部断片化を最小限に抑えます。

### メモリレイアウト

スラブの内部メモリレイアウト：

```
+------------------+
| スラブヘッダ      |
+------------------+
| オブジェクト 1    | ← フリーリストポインタ
+------------------+
| オブジェクト 2    | ← 次のフリーオブジェクトを指すポインタを内包
+------------------+
| ...              |
+------------------+
| オブジェクト N    |
+------------------+
```

## 高度な機能

### カラーリング

CPUキャッシュラインの競合を減らすためのカラーリング機能：

- オブジェクト配置のオフセットをランダム化
- キャッシュライン境界でのアライメント最適化
- 偽共有（false sharing）の回避

### メモリ転送最適化

大量のオブジェクト操作を最適化するメカニズム：

- バルク割り当て/解放の効率化
- バッチ処理による同期オーバーヘッドの削減
- プリフェッチヒントの適用

### NUMA対応

NUMA環境でのパフォーマンスを最大化：

- ノード局所性を考慮したスラブ割り当て
- ノードローカルキャッシュの優先使用
- 自動ノードバランシング

### スラブマージ

メモリ効率をさらに向上させる高度な機能：

- 部分的に使用されているスラブの統合
- 未使用スラブの積極的な回収
- メモリ断片化の防止

## 実装の詳細

### データ構造

```rust
/// スラブキャッシュ構造体
struct SlubCache {
    /// キャッシュ名
    name: String,
    /// オブジェクトサイズ
    object_size: usize,
    /// アライメント
    align: usize,
    /// フラグ
    flags: CacheFlags,
    /// グローバルフリーリスト
    free_list: Mutex<LinkedList<SlubObject>>,
    /// パーCPUキャッシュ
    cpu_caches: Vec<PerCpuCache>,
    /// 統計情報
    stats: CacheStats,
}

/// パーCPUキャッシュ
struct PerCpuCache {
    /// ローカルフリーリスト
    local_free: SpinLock<Vec<SlubObject>>,
    /// プリロード数
    preload_count: usize,
    /// 統計情報
    stats: PerCpuStats,
}

/// スラブページ
struct SlubPage {
    /// フリーオブジェクトの数
    free_count: usize,
    /// 最初のフリーオブジェクトへのポインタ
    free_list: *mut SlubObject,
    /// オーナーキャッシュへの参照
    owner: *mut SlubCache,
    /// 物理ページフレーム番号
    page_frame: usize,
}
```

### アルゴリズム

#### 割り当てパス

1. CPU固有のローカルキャッシュからオブジェクトを取得（ファストパス）
2. ローカルキャッシュが空の場合、グローバルリストから一括でオブジェクトを移動
3. グローバルリストが不十分な場合、新しいスラブをバディアロケータから割り当て
4. 新しいスラブからオブジェクトを取得して返却

#### 解放パス

1. オブジェクトがどのスラブに属するかを判定
2. CPU固有のローカルキャッシュにオブジェクトを返却（ファストパス）
3. ローカルキャッシュが一定量を超えたら、一部をグローバルリストに移動
4. スラブが完全に空になった場合、スラブをバディアロケータに返却（設定可能なしきい値）

## パフォーマンス特性

- **割り当て/解放時間**: 最適化パスで数十nsec、最悪ケースでも数百nsec
- **キャッシュヒット率**: 通常の使用で95%以上
- **メモリオーバーヘッド**: 割り当てサイズの3～5%
- **スケーラビリティ**: 数百コアまで線形スケール

## 最適化技術

### ホットパス最適化

最も頻繁に実行されるパスを極限まで最適化：

- インライン展開
- プリフェッチ指示子の戦略的配置
- 分岐予測ヒント
- ロックレスファストパス

### プロファイリングガイド最適化

実際の使用パターンに基づいた自動最適化：

- 実行時のオブジェクトサイズ分布分析
- ホットスポットの識別と最適化
- キャッシュパラメータの動的調整

### メモリレイアウト最適化

キャッシュ効率を最大化するレイアウト：

- キャッシュライン考慮型データ構造
- アクセスパターンに基づいた配置
- 関連データの局所性確保

## 設定オプション

```rust
/// SLUBアロケータ設定
pub struct SlubConfig {
    /// パーCPUキャッシュのサイズ
    pub per_cpu_cache_size: usize,
    
    /// スラブ解放しきい値（0～100%）
    pub slab_release_threshold: usize,
    
    /// バルク転送サイズ
    pub bulk_transfer_size: usize,
    
    /// カラーリングオフセット最大値
    pub max_color_offset: usize,
    
    /// 緊急時の収縮率
    pub emergency_shrink_ratio: f32,
}
```

## 使用例

### 基本的な使用方法

```rust
// 128バイトのメモリを割り当て
let ptr = slub::allocate(128, AllocFlags::default())?;

// メモリを使用
unsafe {
    *(ptr as *mut u32) = 0xdeadbeef;
}

// メモリを解放
slub::free(ptr, 128)?;
```

### 専用キャッシュの使用

```rust
// 構造体サイズのキャッシュを作成
let cache_id = slub::create_cache(
    "my_struct_cache",
    size_of::<MyStruct>(),
    align_of::<MyStruct>(),
    CacheFlags::ZERO
)?;

// キャッシュから割り当て
let obj_ptr = slub::cache_alloc(cache_id)?;
let obj = obj_ptr as *mut MyStruct;

// オブジェクトを使用
unsafe {
    (*obj).initialize();
    (*obj).process();
}

// オブジェクトを解放
slub::cache_free(cache_id, obj_ptr)?;

// 使い終わったらキャッシュを破棄
slub::destroy_cache(cache_id)?;
```

### 大量のオブジェクト操作

```rust
// バルクアロケーション用のカスタムキャッシュ
let bulk_cache_id = slub::create_cache(
    "bulk_cache",
    64,
    8,
    CacheFlags::BULK_OPS
)?;

// 複数オブジェクトの一括割り当て
let mut objects = Vec::with_capacity(1000);
for _ in 0..1000 {
    objects.push(slub::cache_alloc(bulk_cache_id)?);
}

// 一括解放
for obj in objects {
    slub::cache_free(bulk_cache_id, obj)?;
}

slub::destroy_cache(bulk_cache_id)?;
```

## デバッグ機能

カーネル開発者向けのデバッグ機能が実装されています：

- **スラブ検査**: メモリ破損の検出
- **使用状況トラッキング**: 割り当てパターンの分析
- **リークチェック**: 未解放メモリの検出
- **パフォーマンスプロファイリング**: ホットパスとコールドパスの分析

## 将来の拡張計画

- **AIベース最適化**: 機械学習を用いたキャッシュサイズとレイアウトの最適化
- **GPGPU統合**: 大量の小オブジェクト操作の並列処理
- **耐障害性強化**: メモリエラー自動検出と回復
- **部分隔離**: セキュリティ強化のためのスラブ隔離

---

© AetherOS Project 