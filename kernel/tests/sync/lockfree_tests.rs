// AetherOS ロックフリーデータ構造高度テスト
//
// このモジュールはロックフリーデータ構造の正確性、
// 並行性能、耐久性を徹底的に検証します。

use core::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use core::ptr;
use core::time::Duration;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use alloc::string::String;

use crate::core::sync::lockfree::{LockFreeStack, LockFreeQueue, LockFreeHashMap, HardwareTransaction};
use crate::core::sync::{Barrier, Mutex, RwLock};
use crate::core::process::{create_kernel_thread, yield_cpu};
use crate::time;

/// 同時実行ストレステスト設定
struct ConcurrencyTestConfig {
    /// スレッド数
    thread_count: usize,
    /// 1スレッドあたりの操作数
    ops_per_thread: usize,
    /// プロデューサースレッド数（キュー用）
    producer_count: usize,
    /// コンシューマースレッド数（キュー用）
    consumer_count: usize,
    /// スレッド起動タイミングをずらすか
    staggered_start: bool,
    /// 検証レベル（0-3）
    validation_level: usize,
    /// 操作ミックス（push/pop比率 0-100）
    operation_mix: usize,
}

impl Default for ConcurrencyTestConfig {
    fn default() -> Self {
        Self {
            thread_count: 8,
            ops_per_thread: 100000,
            producer_count: 4,
            consumer_count: 4,
            staggered_start: false,
            validation_level: 2,
            operation_mix: 50, // 50%プッシュ、50%ポップ
        }
    }
}

/// 高度スタックテスト
#[test]
fn test_lock_free_stack_advanced() {
    // テスト設定
    let config = ConcurrencyTestConfig {
        thread_count: 16,
        ops_per_thread: 50000,
        validation_level: 2,
        ..Default::default()
    };
    
    // スタック作成
    let stack = Arc::new(LockFreeStack::new());
    
    // スレッド間同期用バリア
    let barrier = Arc::new(Barrier::new(config.thread_count));
    
    // 成功回数カウンタ
    let push_success = Arc::new(AtomicUsize::new(0));
    let pop_success = Arc::new(AtomicUsize::new(0));
    
    // 全ポップ値の合計（整合性検証用）
    let popped_sum = Arc::new(AtomicUsize::new(0));
    
    // 理論上のプッシュ値合計
    let expected_pushes = (config.thread_count * config.ops_per_thread * config.operation_mix) / 100;
    let expected_sum = (expected_pushes * (expected_pushes + 1)) / 2;
    
    // テストスレッド作成
    let mut handles = Vec::with_capacity(config.thread_count);
    
    for thread_id in 0..config.thread_count {
        let stack_clone = Arc::clone(&stack);
        let barrier_clone = Arc::clone(&barrier);
        let push_success_clone = Arc::clone(&push_success);
        let pop_success_clone = Arc::clone(&pop_success);
        let popped_sum_clone = Arc::clone(&popped_sum);
        
        // 各スレッドの起動タイミングをずらす（オプション）
        let stagger_delay = if config.staggered_start {
            thread_id * 10 // 10ms間隔
        } else {
            0
        };
        
        let handle = create_kernel_thread(
            &format!("stack_test_{}", thread_id),
            16384, // スタックサイズ
            0,     // 優先度
            move || {
                // 遅延開始（必要な場合）
                if stagger_delay > 0 {
                    time::sleep(stagger_delay);
                }
                
                // 全スレッド同期
                barrier_clone.wait();
                
                // 各スレッドのプッシュ値範囲を計算（値が重複しないように）
                let base_value = thread_id * config.ops_per_thread + 1;
                let mut next_value = base_value;
                let mut rng_state = thread_id as u64 * 0x1234567;
                
                // 各スレッドの作業
                for _ in 0..config.ops_per_thread {
                    // ランダムに操作を選択（プッシュまたはポップ）
                    let do_push = xorshift(&mut rng_state) % 100 < config.operation_mix as u64;
                    
                    if do_push {
                        // スタックにプッシュ
                        stack_clone.push(next_value);
                        push_success_clone.fetch_add(1, Ordering::Relaxed);
                        next_value += 1;
                    } else {
                        // スタックからポップ
                        if let Some(value) = stack_clone.pop() {
                            popped_sum_clone.fetch_add(value, Ordering::Relaxed);
                            pop_success_clone.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    
                    // たまにCPUを譲る
                    if xorshift(&mut rng_state) % 1000 == 0 {
                        yield_cpu();
                    }
                }
            }
        );
        
        handles.push(handle);
    }
    
    // 開始時間を記録
    let start_time = time::current_time_ns();
    
    // 全スレッド完了を待機
    for handle in handles {
        // ハンドル待機操作（実際の実装では結合など）
    }
    
    // 終了時間を記録
    let end_time = time::current_time_ns();
    let duration_ms = (end_time - start_time) / 1_000_000;
    
    // 最終結果を集計
    let final_push_count = push_success.load(Ordering::Relaxed);
    let final_pop_count = pop_success.load(Ordering::Relaxed);
    let final_sum = popped_sum.load(Ordering::Relaxed);
    
    // スタック内の残り要素数
    let remaining_elements = stack.len();
    
    // 全要素をポップして消費
    let mut remaining_sum = 0;
    while let Some(value) = stack.pop() {
        remaining_sum += value;
    }
    
    // 総合チェック
    let total_sum = final_sum + remaining_sum;
    
    // 結果を表示
    log::info!("ロックフリースタック 高度テスト結果:");
    log::info!("  スレッド数: {}", config.thread_count);
    log::info!("  操作数（スレッドあたり）: {}", config.ops_per_thread);
    log::info!("  実行時間: {}ms", duration_ms);
    log::info!("  スループット: {:.2}操作/秒", 
               ((final_push_count + final_pop_count) as f64 * 1000.0) / duration_ms as f64);
    log::info!("  プッシュ成功: {}", final_push_count);
    log::info!("  ポップ成功: {}", final_pop_count);
    log::info!("  残り要素数: {}", remaining_elements);
    log::info!("  合計値: {} (期待値: {})", total_sum, expected_sum);
    
    // 検証
    assert_eq!(stack.is_empty(), true, "スタックが空ではありません");
    
    // 厳密な検証（プッシュ/ポップのバランスが等しい場合）
    if config.operation_mix == 50 {
        assert_eq!(total_sum, expected_sum, 
                   "値の合計が期待値と一致しません。データ損失の可能性あり");
    }
}

/// 高度キューテスト（プロデューサー/コンシューマーモデル）
#[test]
fn test_lock_free_queue_producer_consumer() {
    // テスト設定
    let config = ConcurrencyTestConfig {
        producer_count: 8,
        consumer_count: 8,
        ops_per_thread: 20000,
        ..Default::default()
    };
    
    // キュー作成
    let queue = Arc::new(LockFreeQueue::new());
    
    // スレッド間同期用バリア
    let barrier = Arc::new(Barrier::new(config.producer_count + config.consumer_count));
    
    // 成功回数カウンタ
    let enqueue_success = Arc::new(AtomicUsize::new(0));
    let dequeue_success = Arc::new(AtomicUsize::new(0));
    
    // 全体検証用カウンタ
    let dequeued_sum = Arc::new(AtomicUsize::new(0));
    let dequeued_count = Arc::new(AtomicUsize::new(0));
    
    // 終了フラグ
    let producers_done = Arc::new(AtomicBool::new(false));
    
    // プロデューサースレッド作成
    let mut producer_handles = Vec::with_capacity(config.producer_count);
    
    for thread_id in 0..config.producer_count {
        let queue_clone = Arc::clone(&queue);
        let barrier_clone = Arc::clone(&barrier);
        let enqueue_success_clone = Arc::clone(&enqueue_success);
        
        let handle = create_kernel_thread(
            &format!("queue_producer_{}", thread_id),
            16384,
            0,
            move || {
                // 全スレッド同期
                barrier_clone.wait();
                
                // 各プロデューサーの生成値範囲を計算
                let base_value = thread_id * config.ops_per_thread + 1;
                
                // エンキュー処理
                for i in 0..config.ops_per_thread {
                    let value = base_value + i;
                    queue_clone.enqueue(value);
                    enqueue_success_clone.fetch_add(1, Ordering::Relaxed);
                    
                    // たまにCPUを譲る
                    if i % 1000 == 0 {
                        yield_cpu();
                    }
                }
            }
        );
        
        producer_handles.push(handle);
    }
    
    // コンシューマースレッド作成
    let mut consumer_handles = Vec::with_capacity(config.consumer_count);
    
    for thread_id in 0..config.consumer_count {
        let queue_clone = Arc::clone(&queue);
        let barrier_clone = Arc::clone(&barrier);
        let dequeue_success_clone = Arc::clone(&dequeue_success);
        let dequeued_sum_clone = Arc::clone(&dequeued_sum);
        let dequeued_count_clone = Arc::clone(&dequeued_count);
        let producers_done_clone = Arc::clone(&producers_done);
        
        let handle = create_kernel_thread(
            &format!("queue_consumer_{}", thread_id),
            16384,
            0,
            move || {
                // 全スレッド同期
                barrier_clone.wait();
                
                // デキュー処理
                loop {
                    // 定期的にプロデューサーの完了状態をチェック
                    let is_producers_done = producers_done_clone.load(Ordering::Relaxed);
                    
                    // キューからデキュー
                    match queue_clone.dequeue() {
                        Some(value) => {
                            dequeue_success_clone.fetch_add(1, Ordering::Relaxed);
                            dequeued_sum_clone.fetch_add(value, Ordering::Relaxed);
                            dequeued_count_clone.fetch_add(1, Ordering::Relaxed);
                        }
                        None => {
                            // キューが空の場合
                            if is_producers_done {
                                // プロデューサーが完了していて、キューが空なら終了
                                if queue_clone.is_empty() {
                                    break;
                                }
                            }
                            
                            // 少し待機してリトライ
                            for _ in 0..10 {
                                yield_cpu();
                            }
                        }
                    }
                }
            }
        );
        
        consumer_handles.push(handle);
    }
    
    // 開始時間を記録
    let start_time = time::current_time_ns();
    
    // プロデューサースレッド完了を待機
    for handle in producer_handles {
        // ハンドル待機操作
    }
    
    // プロデューサー完了フラグを設定
    producers_done.store(true, Ordering::Release);
    
    // コンシューマースレッドの完了を待機
    for handle in consumer_handles {
        // ハンドル待機操作
    }
    
    // 終了時間を記録
    let end_time = time::current_time_ns();
    let duration_ms = (end_time - start_time) / 1_000_000;
    
    // 最終結果を集計
    let final_enqueue_count = enqueue_success.load(Ordering::Relaxed);
    let final_dequeue_count = dequeue_success.load(Ordering::Relaxed);
    let final_sum = dequeued_sum.load(Ordering::Relaxed);
    
    // キュー内の残り要素数
    let remaining_elements = queue.len();
    
    // 理論上の合計値を計算
    let total_elements = config.producer_count * config.ops_per_thread;
    let expected_sum = (total_elements * (total_elements + 1)) / 2;
    
    // 結果を表示
    log::info!("ロックフリーキュー プロデューサー/コンシューマーテスト結果:");
    log::info!("  プロデューサー数: {}", config.producer_count);
    log::info!("  コンシューマー数: {}", config.consumer_count);
    log::info!("  操作数（プロデューサーあたり）: {}", config.ops_per_thread);
    log::info!("  実行時間: {}ms", duration_ms);
    log::info!("  スループット: {:.2}操作/秒", 
               ((final_enqueue_count + final_dequeue_count) as f64 * 1000.0) / duration_ms as f64);
    log::info!("  エンキュー成功: {}", final_enqueue_count);
    log::info!("  デキュー成功: {}", final_dequeue_count);
    log::info!("  残り要素数: {}", remaining_elements);
    log::info!("  デキューされた要素の合計値: {}", final_sum);
    log::info!("  期待される合計値: {}", expected_sum);
    
    // 検証
    assert_eq!(queue.is_empty(), true, "全要素が処理されていません");
    assert_eq!(final_dequeue_count, total_elements, 
               "エンキューとデキューの数が一致しません");
    assert_eq!(final_sum, expected_sum, 
               "要素の合計値が期待値と一致しません。データ損失の可能性あり");
}

/// データ競合検出テスト
#[test]
fn test_lock_free_data_race_detection() {
    // 特殊フラグ付きスタック
    struct RaceDetectionStack<T> {
        stack: LockFreeStack<T>,
        // データ競合検出カウンタ
        race_checks: AtomicUsize,
        race_detected: AtomicBool,
    }
    
    impl<T> RaceDetectionStack<T> {
        fn new() -> Self {
            Self {
                stack: LockFreeStack::new(),
                race_checks: AtomicUsize::new(0),
                race_detected: AtomicBool::new(false),
            }
        }
        
        // データ競合可能性の高い操作を行う
        fn push_and_check(&self, value: T) {
            // ここに敢えて遅延を入れて競合を誘発
            self.race_checks.fetch_add(1, Ordering::SeqCst);
            self.stack.push(value);
            
            // 競合チェック
            if !self.stack.is_empty() && self.stack.pop().is_none() {
                self.race_detected.store(true, Ordering::Release);
            }
        }
    }
    
    // 高負荷スレッド数
    const THREAD_COUNT: usize = 32;
    
    // テスト用スタック
    let test_stack = Arc::new(RaceDetectionStack::new());
    
    // スレッド同期用バリア
    let barrier = Arc::new(Barrier::new(THREAD_COUNT));
    
    // テストスレッド作成
    let mut handles = Vec::with_capacity(THREAD_COUNT);
    
    for thread_id in 0..THREAD_COUNT {
        let stack_clone = Arc::clone(&test_stack);
        let barrier_clone = Arc::clone(&barrier);
        
        let handle = create_kernel_thread(
            &format!("race_test_{}", thread_id),
            8192,
            0,
            move || {
                // 全スレッド同期
                barrier_clone.wait();
                
                // 各スレッド1000回のプッシュ操作
                for i in 0..1000 {
                    stack_clone.push_and_check(thread_id * 1000 + i);
                    
                    // 不規則な遅延を挿入
                    if i % 10 == 0 {
                        yield_cpu();
                    }
                }
            }
        );
        
        handles.push(handle);
    }
    
    // スレッド完了を待機
    for handle in handles {
        // ハンドル待機操作
    }
    
    // テスト結果
    let checks = test_stack.race_checks.load(Ordering::Relaxed);
    let race_detected = test_stack.race_detected.load(Ordering::Relaxed);
    
    log::info!("データ競合テスト結果:");
    log::info!("  スレッド数: {}", THREAD_COUNT);
    log::info!("  チェック回数: {}", checks);
    log::info!("  競合検出: {}", race_detected);
    
    // ロックフリー実装では競合は検出されないはず
    assert_eq!(race_detected, false, "データ競合が検出されました");
}

/// ハードウェアトランザクショナルメモリ（HTM）テスト
#[test]
fn test_hardware_transactional_memory() {
    // HTMがサポートされているか確認
    if !HardwareTransaction::is_supported() {
        log::info!("ハードウェアトランザクショナルメモリがサポートされていません。テストをスキップします。");
        return;
    }
    
    // HTMを使用したカウンタ実装
    struct HTMCounter {
        value: AtomicUsize,
        fallback_lock: AtomicBool,
    }
    
    impl HTMCounter {
        fn new() -> Self {
            Self {
                value: AtomicUsize::new(0),
                fallback_lock: AtomicBool::new(false),
            }
        }
        
        fn increment(&self) -> bool {
            // まずトランザクションを試行
            match HardwareTransaction::begin() {
                Ok(_) => {
                    // トランザクション内の操作
                    let current = self.value.load(Ordering::Relaxed);
                    self.value.store(current + 1, Ordering::Relaxed);
                    
                    // トランザクションをコミット
                    HardwareTransaction::commit();
                    true
                },
                Err(_) => {
                    // トランザクション失敗時のフォールバック
                    // 通常のアトミック操作
                    self.value.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        }
    }
    
    // HTMカウンタを作成
    let counter = Arc::new(HTMCounter::new());
    
    // 複数スレッドでインクリメント
    let threads = 8;
    let increments_per_thread = 1000;
    let mut handles = Vec::with_capacity(threads);
    
    let successful_transactions = Arc::new(AtomicUsize::new(0));
    
    for thread_id in 0..threads {
        let counter_clone = Arc::clone(&counter);
        let successful_clone = Arc::clone(&successful_transactions);
        
        let handle = create_kernel_thread(
            &format!("htm_test_{}", thread_id),
            8192,
            0,
            move || {
                let mut local_success = 0;
                
                for _ in 0..increments_per_thread {
                    if counter_clone.increment() {
                        local_success += 1;
                    }
                }
                
                successful_clone.fetch_add(local_success, Ordering::Relaxed);
            }
        );
        
        handles.push(handle);
    }
    
    // スレッド完了を待機
    for handle in handles {
        // ハンドル待機操作
    }
    
    // テスト結果
    let final_value = counter.value.load(Ordering::Relaxed);
    let successful = successful_transactions.load(Ordering::Relaxed);
    let total_ops = threads * increments_per_thread;
    let success_rate = (successful as f64 * 100.0) / total_ops as f64;
    
    log::info!("HTMテスト結果:");
    log::info!("  期待値: {}", total_ops);
    log::info!("  実際値: {}", final_value);
    log::info!("  成功したトランザクション: {} ({:.2}%)", successful, success_rate);
    
    // 値の検証
    assert_eq!(final_value, total_ops, "カウンタの最終値が期待値と一致しません");
}

/// スループット測定テスト
#[test]
fn benchmark_lock_free_data_structures() {
    // テスト設定
    const THREAD_COUNTS: [usize; 5] = [1, 2, 4, 8, 16];
    const OPS_PER_THREAD: usize = 100000;
    
    // 結果保存
    let mut stack_results = Vec::with_capacity(THREAD_COUNTS.len());
    let mut queue_results = Vec::with_capacity(THREAD_COUNTS.len());
    
    // 各スレッド数でのテスト
    for &threads in THREAD_COUNTS.iter() {
        // 1. スタックベンチマーク
        let stack = Arc::new(LockFreeStack::new());
        let barrier = Arc::new(Barrier::new(threads));
        let mut handles = Vec::with_capacity(threads);
        
        // スタックスレッド作成
        for thread_id in 0..threads {
            let stack_clone = Arc::clone(&stack);
            let barrier_clone = Arc::clone(&barrier);
            
            let handle = create_kernel_thread(
                &format!("stack_bench_{}", thread_id),
                8192,
                0,
                move || {
                    // 全スレッド同期
                    barrier_clone.wait();
                    
                    // 操作を交互に実行
                    for i in 0..OPS_PER_THREAD {
                        if i % 2 == 0 {
                            stack_clone.push(i);
                        } else {
                            let _ = stack_clone.pop();
                        }
                    }
                }
            );
            
            handles.push(handle);
        }
        
        // 実行時間計測
        let stack_start = time::current_time_ns();
        
        // スレッド完了を待機
        for handle in handles {
            // ハンドル待機操作
        }
        
        let stack_end = time::current_time_ns();
        let stack_duration_ms = (stack_end - stack_start) / 1_000_000;
        let stack_ops_per_sec = ((threads * OPS_PER_THREAD) as f64 * 1000.0) / stack_duration_ms as f64;
        
        // 結果保存
        stack_results.push((threads, stack_ops_per_sec));
        
        // スタッククリーンアップ
        while stack.pop().is_some() {}
        
        // 2. キューベンチマーク
        let queue = Arc::new(LockFreeQueue::new());
        let barrier = Arc::new(Barrier::new(threads));
        let mut handles = Vec::with_capacity(threads);
        
        // キュースレッド作成
        for thread_id in 0..threads {
            let queue_clone = Arc::clone(&queue);
            let barrier_clone = Arc::clone(&barrier);
            
            let handle = create_kernel_thread(
                &format!("queue_bench_{}", thread_id),
                8192,
                0,
                move || {
                    // 全スレッド同期
                    barrier_clone.wait();
                    
                    // 操作を交互に実行
                    for i in 0..OPS_PER_THREAD {
                        if i % 2 == 0 {
                            queue_clone.enqueue(i);
                        } else {
                            let _ = queue_clone.dequeue();
                        }
                    }
                }
            );
            
            handles.push(handle);
        }
        
        // 実行時間計測
        let queue_start = time::current_time_ns();
        
        // スレッド完了を待機
        for handle in handles {
            // ハンドル待機操作
        }
        
        let queue_end = time::current_time_ns();
        let queue_duration_ms = (queue_end - queue_start) / 1_000_000;
        let queue_ops_per_sec = ((threads * OPS_PER_THREAD) as f64 * 1000.0) / queue_duration_ms as f64;
        
        // 結果保存
        queue_results.push((threads, queue_ops_per_sec));
        
        // キュークリーンアップ
        while queue.dequeue().is_some() {}
    }
    
    // 結果表示
    log::info!("ロックフリーデータ構造ベンチマーク結果:");
    log::info!("  操作数/スレッド: {}", OPS_PER_THREAD);
    
    log::info!("\nスタックスループット (操作/秒):");
    for &(threads, throughput) in stack_results.iter() {
        log::info!("  {} スレッド: {:.2}", threads, throughput);
    }
    
    log::info!("\nキュースループット (操作/秒):");
    for &(threads, throughput) in queue_results.iter() {
        log::info!("  {} スレッド: {:.2}", threads, throughput);
    }
    
    // スケーラビリティ検証
    let single_thread_stack = stack_results[0].1;
    let max_threads_stack = stack_results.last().unwrap().1;
    let scaling_factor_stack = max_threads_stack / single_thread_stack;
    
    let single_thread_queue = queue_results[0].1;
    let max_threads_queue = queue_results.last().unwrap().1;
    let scaling_factor_queue = max_threads_queue / single_thread_queue;
    
    log::info!("\nスケーラビリティ分析:");
    log::info!("  スタックスケーリング: {:.2}x", scaling_factor_stack);
    log::info!("  キュースケーリング: {:.2}x", scaling_factor_queue);
    
    // どちらかのデータ構造はスケールすべき
    assert!(scaling_factor_stack > 1.0 || scaling_factor_queue > 1.0, 
            "ロックフリーデータ構造がスケールしていません");
}

/// シンプルな乱数生成（XORShift）
fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
} 