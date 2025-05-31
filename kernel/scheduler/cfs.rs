// AetherOS 完全公平スケジューラ (CFS) 実装
//
// Linuxカーネルのインスパイアを受けた高効率なスケジューラ
// - 赤黒木を使用した高効率なタスク管理
// - 仮想実行時間に基づく公平なスケジューリング
// - マルチコア環境での負荷分散
// - スループットと対話性のバランスを調整

use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::cmp::Ordering as CmpOrdering;
use crate::core::sync::{RwLock, SpinLock};
use crate::core::process::{Thread, ThreadState, Priority};
use crate::time::{Timespec, get_current_time};

/// CFS用の仮想ランタイム計算の重み係数
const CFS_WEIGHTS: [u32; 40] = [
    /* -20 */ 88761, 71755, 56483, 46273, 36291,
    /* -15 */ 29154, 23254, 18705, 14949, 11916,
    /* -10 */  9548,  7620,  6100,  4904,  3906,
    /*  -5 */  3121,  2501,  1991,  1586,  1277,
    /*   0 */  1024,   820,   655,   526,   423,
    /*   5 */   335,   272,   215,   172,   137,
    /*  10 */   110,    87,    70,    56,    45,
    /*  15 */    36,    29,    23,    18,    15,
];

/// 最小グランド期間（ナノ秒）
const MIN_GRAND_PERIOD_NS: u64 = 6_000_000; // 6ミリ秒

/// 最大グランド期間（ナノ秒）
const MAX_GRAND_PERIOD_NS: u64 = 100_000_000; // 100ミリ秒

/// 対話性向上のためのスリープボーナス係数
const SLEEP_BONUS_FACTOR: f32 = 0.5;

/// 最大スリープボーナス値
const MAX_SLEEP_BONUS_NS: u64 = 50_000_000; // 50ミリ秒

/// 最大実行時間ペナルティ
const MAX_EXEC_PENALTY_NS: u64 = 10_000_000; // 10ミリ秒

/// CFS実行キュー
pub struct CFSRunQueue {
    /// スレッドマップ (ThreadID -> CFS情報)
    threads: SpinLock<BTreeMap<u64, CFSThreadInfo>>,
    /// 赤黒木に実装された実行キュー
    /// vruntime基準で並べる（仮想ランタイムが小さい順）
    rbtree: SpinLock<BTreeMap<u64, Arc<Thread>>>,
    /// 最小の仮想ランタイム値（新規タスク挿入用基準点）
    min_vruntime: AtomicU64,
    /// 現在の負荷
    load: AtomicU64,
    /// この実行キューの重み合計
    weight_sum: AtomicU32,
    /// 現在のレイテンシターゲット（ナノ秒）
    latency_target_ns: AtomicU64,
    /// 最小実行時間（ナノ秒）
    min_granularity_ns: AtomicU64,
}

/// CFSスレッド情報
#[derive(Clone)]
struct CFSThreadInfo {
    /// スレッドの仮想実行時間（ナノ秒）
    vruntime: u64,
    /// スレッドの重み（ナイス値から計算）
    weight: u32,
    /// スレッドの負荷貢献度
    load_contrib: u32,
    /// プリエンプション用のdelta_execフラグ
    delta_exec: u64,
    /// 最後に起床した時間
    last_wakeup: u64,
    /// 最後に実行された時間
    last_exec: u64,
    /// 累積実行時間
    sum_exec_runtime: u64,
    /// 前回実行時のタイムスライス
    prev_slice: u64,
    /// 連続実行カウンタ
    exec_count: u32,
}

impl CFSRunQueue {
    /// 新しいCFS実行キューを作成
    pub fn new() -> Self {
        Self {
            threads: SpinLock::new(BTreeMap::new()),
            rbtree: SpinLock::new(BTreeMap::new()),
            min_vruntime: AtomicU64::new(0),
            load: AtomicU64::new(0),
            weight_sum: AtomicU32::new(0),
            latency_target_ns: AtomicU64::new(20_000_000), // 20ms
            min_granularity_ns: AtomicU64::new(4_000_000), // 4ms
        }
    }
    
    /// スレッドをCFS実行キューに追加
    pub fn enqueue(&self, thread: Arc<Thread>) {
        // ロックを取得
        let mut threads = self.threads.lock();
        let mut rbtree = self.rbtree.lock();
        
        let thread_id = thread.get_id();
        
        if threads.contains_key(&thread_id) {
            // すでにキューに存在する場合は何もしない
            return;
        }
        
        // スレッドの重みを計算
        let nice = thread.get_priority().to_nice();
        let weight = self.nice_to_weight(nice);
        
        // 現在の最小vruntimeを取得
        let min_vruntime = self.min_vruntime.load(Ordering::Relaxed);
        let now = get_current_time().as_nanos();
        
        // 新しいスレッドのvruntimeを初期化（公平性のため現在の最小値を使用）
        let vruntime = min_vruntime;
        
        // スリープボーナスを適用（対話的タスクにボーナスを与え、優先的に実行）
        let sleep_time = if thread.get_state() == ThreadState::Blocked {
            let last_sleep = thread.get_last_sleep_time();
            if last_sleep > 0 {
                let sleep_duration = now - last_sleep;
                self.calculate_sleep_bonus(sleep_duration)
            } else {
                0
            }
        } else {
            0
        };
        
        // 最終的なvruntimeを計算
        let final_vruntime = if sleep_time > vruntime {
            0 // 下限を0に
        } else {
            vruntime - sleep_time
        };
        
        // スレッド情報を作成
        let thread_info = CFSThreadInfo {
            vruntime: final_vruntime,
            weight,
            load_contrib: weight,
            delta_exec: 0,
            last_wakeup: now,
            last_exec: 0,
            sum_exec_runtime: 0,
            prev_slice: 0,
            exec_count: 0,
        };
        
        // スレッド情報をマップに追加
        threads.insert(thread_id, thread_info);
        
        // スレッドを実行キューに追加
        rbtree.insert(final_vruntime, Arc::clone(&thread));
        
        // 負荷と重み合計を更新
        self.weight_sum.fetch_add(weight, Ordering::Relaxed);
        self.update_load();
    }
    
    /// スレッドをCFS実行キューから削除
    pub fn dequeue(&self, thread: &Arc<Thread>) {
        // ロックを取得
        let mut threads = self.threads.lock();
        
        let thread_id = thread.get_id();
        
        // スレッド情報がなければ何もしない
        if let Some(thread_info) = threads.remove(&thread_id) {
            // 実行キューからも削除
            let mut rbtree = self.rbtree.lock();
            
            // vruntimeでスレッドを検索して削除
            let vruntime = thread_info.vruntime;
            if let Some(entry) = rbtree.remove(&vruntime) {
                // 確認: 本当に同じスレッドか
                if entry.get_id() != thread_id {
                    // vruntimeが重複している場合、正しいエントリを再検索して削除
                    for (vr, t) in rbtree.iter() {
                        if t.get_id() == thread_id {
                            rbtree.remove(vr);
                            break;
                        }
                    }
                }
            }
            
            // 重み合計を更新
            self.weight_sum.fetch_sub(thread_info.weight, Ordering::Relaxed);
            
            // 負荷を更新
            self.update_load();
        }
    }
    
    /// 次に実行するスレッドを選択
    pub fn pick_next(&self) -> Option<Arc<Thread>> {
        let rbtree = self.rbtree.lock();
        
        // 木が空の場合
        if rbtree.is_empty() {
            return None;
        }
        
        // 最小のvruntimeを持つスレッドを選択（赤黒木の最左ノード）
        let (_, thread) = rbtree.iter().next()?;
        
        Some(Arc::clone(thread))
    }
    
    /// 再スケジューリングが必要かチェック
    pub fn need_resched(&self, current: &Option<Arc<Thread>>) -> bool {
        if let Some(thread) = current {
            // 現在のスレッドのスケジューリングポリシーをチェック
            if !thread.is_normal_policy() {
                // CFSで管理されていないスレッド
                return false;
            }
            
            // 現在のスレッドのvruntime情報を取得
            let thread_id = thread.get_id();
            let threads = self.threads.lock();
            
            if let Some(thread_info) = threads.get(&thread_id) {
                // 現在のvruntime
                let current_vruntime = thread_info.vruntime;
                
                // 他のスレッドの最小vruntimeと比較
                let rbtree = self.rbtree.lock();
                
                if !rbtree.is_empty() {
                    // 最小のvruntime
                    if let Some((min_vr, _)) = rbtree.iter().next() {
                        // 実行時間のスレッショルドを計算
                        let threshold = self.min_granularity_ns.load(Ordering::Relaxed);
                        
                        // 現在のスレッドのvruntimeと最小vruntimeの差が
                        // スレッショルドを超えるとプリエンプション
                        if current_vruntime > *min_vr + threshold {
                            return true;
                        }
                    }
                }
            }
            
            false
        } else {
            // 現在実行中のスレッドがなければスケジューリングが必要
            true
        }
    }
    
    /// タイマーティック処理
    pub fn tick(&self) {
        // 現在のスレッドを取得
        if let Some(current) = crate::scheduler::current_thread() {
            // 通常ポリシーのスレッドのみ処理
            if current.is_normal_policy() {
                let thread_id = current.get_id();
                let mut threads = self.threads.lock();
                
                if let Some(thread_info) = threads.get_mut(&thread_id) {
                    // 実行時間を増やす
                    let delta = self.calculate_delta_exec(thread_info);
                    thread_info.delta_exec += delta;
                    
                    // 統計情報を更新
                    thread_info.sum_exec_runtime += delta;
                    thread_info.exec_count += 1;
                    thread_info.last_exec = get_current_time().as_nanos();
                    
                    // vruntimeが大きく進んだ場合はセットプリエンプションフラグ
                    if thread_info.delta_exec > self.min_granularity_ns.load(Ordering::Relaxed) {
                        // vruntimeを更新
                        self.update_vruntime(&current, thread_info);
                        thread_info.delta_exec = 0;
                        
                        // プリエンプションフラグを設定
                        current.set_need_resched(true);
                    }
                }
            }
        }
        
        // 動的に最小粒度と遅延ターゲットを調整
        self.update_latency_parameters();
    }
    
    /// vruntimeを更新
    fn update_vruntime(&self, thread: &Arc<Thread>, thread_info: &mut CFSThreadInfo) {
        // 実際の実行時間をvruntime増分に変換
        let delta_exec = thread_info.delta_exec;
        let weight = thread_info.weight;
        
        // 標準重み（1024）に対する相対的なvruntime増分を計算
        let delta_vruntime = (delta_exec * 1024) / weight as u64;
        
        // vuntimeを更新
        thread_info.vruntime += delta_vruntime;
        
        // rbtreeの更新（スレッドを一度削除して再挿入）
        let mut rbtree = self.rbtree.lock();
        
        // 古いエントリを検索して削除
        let thread_id = thread.get_id();
        for (vr, t) in rbtree.iter() {
            if t.get_id() == thread_id {
                rbtree.remove(vr);
                break;
            }
        }
        
        // 新しいvruntimeで再挿入
        rbtree.insert(thread_info.vruntime, Arc::clone(thread));
        
        // 最小vruntimeを更新
        if let Some((min_vr, _)) = rbtree.iter().next() {
            self.min_vruntime.store(*min_vr, Ordering::Relaxed);
        }
    }
    
    /// デルタ実行時間を計算
    fn calculate_delta_exec(&self, thread_info: &CFSThreadInfo) -> u64 {
        // 標準的なティック時間（10ms）
        // 実際の環境では、前回のティックからの経過時間を使うべき
        10_000_000
    }
    
    /// スリープボーナスを計算
    fn calculate_sleep_bonus(&self, sleep_duration: u64) -> u64 {
        // スリープ時間に比例したボーナスを計算
        let bonus = (sleep_duration as f32 * SLEEP_BONUS_FACTOR) as u64;
        
        // 最大ボーナス値を制限
        if bonus > MAX_SLEEP_BONUS_NS {
            MAX_SLEEP_BONUS_NS
        } else {
            bonus
        }
    }
    
    /// 遅延パラメータを更新
    fn update_latency_parameters(&self) {
        // スレッド数に基づいてスケジューリングパラメータを調整
        let nr_threads = {
            let threads = self.threads.lock();
            threads.len()
        } as u64;
        
        if nr_threads > 0 {
            // スレッド数に基づいてレイテンシターゲットを調整
            let latency = MIN_GRAND_PERIOD_NS + nr_threads * 1_000_000;
            let latency = if latency > MAX_GRAND_PERIOD_NS {
                MAX_GRAND_PERIOD_NS
            } else {
                latency
            };
            
            self.latency_target_ns.store(latency, Ordering::Relaxed);
            
            // 最小粒度を調整（レイテンシターゲットの5分の1程度）
            let granularity = latency / 5;
            self.min_granularity_ns.store(granularity, Ordering::Relaxed);
        }
    }
    
    /// ナイス値を重みに変換
    fn nice_to_weight(&self, nice: i8) -> u32 {
        let nice_idx = (nice + 20) as usize;
        
        if nice_idx < CFS_WEIGHTS.len() {
            CFS_WEIGHTS[nice_idx]
        } else {
            // 範囲外のナイス値
            CFS_WEIGHTS[39] // 最小の重み
        }
    }
    
    /// 負荷を更新
    fn update_load(&self) {
        // 単純な計算：アクティブなスレッド数と重みの合計から負荷を計算
        let threads = self.threads.lock();
        let nr_threads = threads.len() as u64;
        let weight_sum = self.weight_sum.load(Ordering::Relaxed) as u64;
        
        // 標準化された負荷
        let normalized_load = if nr_threads > 0 {
            (weight_sum * 1024) / (nr_threads * 1024)
        } else {
            0
        };
        
        self.load.store(normalized_load, Ordering::Relaxed);
    }
} 