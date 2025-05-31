// AetherOS バリア同期プリミティブ高度テスト
//
// このモジュールはバリア同期の正確性、性能、
// スケーラビリティを厳密に検証します。

use core::sync::atomic::{AtomicUsize, AtomicBool, AtomicU64, Ordering};
use core::cell::Cell;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::string::String;
use alloc::format;

use crate::core::sync::barrier::{Barrier, BarrierToken, BarrierOptions, CentralBarrier, PhaseBarrier};
use crate::core::sync::{SpinLock, Mutex, RwLock};
use crate::core::process::create_kernel_thread;
use crate::time;

/// 異なるスレッド数でのバリア性能テスト
#[test]
fn test_barrier_performance() {
    // テスト設定
    const THREAD_COUNTS: [usize; 5] = [2, 4, 8, 16, 32];
    const ITERATIONS: usize = 1000;
    
    // 結果記録
    let mut results = Vec::with_capacity(THREAD_COUNTS.len());
    
    for &thread_count in THREAD_COUNTS.iter() {
        // スレッド待機時間の合計（各スレッドの計測値）
        let total_wait_time = Arc::new(AtomicU64::new(0));
        // バリア越えの最大時間差（全スレッドが通過するまでの時間差の最大値）
        let max_crossing_time_diff = Arc::new(AtomicU64::new(0));
        // バリア通過タイムスタンプ
        let timestamps = Arc::new(Mutex::new(Vec::<u64>::with_capacity(thread_count * ITERATIONS)));
        
        // バリア作成（詳細統計を有効化）
        let options = BarrierOptions {
            detailed_stats: true,
            ..Default::default()
        };
        let barrier = Arc::new(Barrier::with_options(thread_count, options));
        
        // 開始時間を記録
        let start_time = time::current_time_ns();
        
        // テストスレッド作成
        let mut handles = Vec::with_capacity(thread_count);
        
        for thread_id in 0..thread_count {
            let barrier_clone = Arc::clone(&barrier);
            let total_wait_time_clone = Arc::clone(&total_wait_time);
            let max_crossing_time_diff_clone = Arc::clone(&max_crossing_time_diff);
            let timestamps_clone = Arc::clone(&timestamps);
            
            let handle = create_kernel_thread(
                &format!("barrier_perf_{}", thread_id),
                8192,
                0,
                move || {
                    // 各スレッドの待機時間合計
                    let mut local_wait_time = 0;
                    
                    for i in 0..ITERATIONS {
                        // バリア前の時間を記録
                        let before = time::current_time_ns();
                        
                        // バリアで待機
                        let token = barrier_clone.wait();
                        
                        // バリア後の時間を記録
                        let after = time::current_time_ns();
                        
                        // 待機時間を計算
                        let wait_time = after - before;
                        local_wait_time += wait_time;
                        
                        // 全スレッドのタイムスタンプを記録
                        {
                            let mut ts = timestamps_clone.lock();
                            ts.push(after);
                            
                            // バリア世代が一致することを検証
                            if thread_id == 0 {
                                assert_eq!(token.generation, i + 1, 
                                          "バリア世代が期待値と一致しません");
                            }
                        }
                        
                        // 少し作業をしてからバリアに向かう
                        // （実際のワークロードをシミュレート）
                        if i % 10 == 0 {
                            let work_time = (thread_id as u64 % 5) * 100; // 0-400us
                            time::sleep_us(work_time);
                        }
                    }
                    
                    // 合計待機時間を追加
                    total_wait_time_clone.fetch_add(local_wait_time, Ordering::Relaxed);
                }
            );
            
            handles.push(handle);
        }
        
        // スレッド完了を待機
        for handle in handles {
            // ハンドル待機操作
        }
        
        // 終了時間を記録
        let end_time = time::current_time_ns();
        let duration_ms = (end_time - start_time) / 1_000_000;
        
        // 通過タイムスタンプを分析（各バリア通過の最初と最後のスレッド間の時間差）
        let ts_lock = timestamps.lock();
        for i in 0..ITERATIONS {
            let mut crossing_timestamps = Vec::with_capacity(thread_count);
            
            // 各バリア通過時のタイムスタンプを収集
            for j in 0..thread_count {
                crossing_timestamps.push(ts_lock[i * thread_count + j]);
            }
            
            // 最速と最遅のスレッド間の差を計算
            crossing_timestamps.sort();
            let min_ts = crossing_timestamps[0];
            let max_ts = crossing_timestamps[crossing_timestamps.len() - 1];
            let diff = max_ts - min_ts;
            
            // 最大通過時間差を更新
            let current_max = max_crossing_time_diff.load(Ordering::Relaxed);
            if diff > current_max {
                max_crossing_time_diff.store(diff, Ordering::Relaxed);
            }
        }
        
        // 結果を保存
        let avg_wait_time = barrier.avg_wait_time_ns();
        let max_wait_time = barrier.max_wait_time_ns();
        let max_cross_diff = max_crossing_time_diff.load(Ordering::Relaxed);
        
        results.push((
            thread_count,
            duration_ms,
            avg_wait_time,
            max_wait_time,
            max_cross_diff
        ));
        
        // 結果表示
        log::info!("バリア性能テスト（{}スレッド）:", thread_count);
        log::info!("  実行時間: {}ms", duration_ms);
        log::info!("  イテレーション数: {}", ITERATIONS);
        log::info!("  スループット: {:.2}バリア/秒", 
                   (ITERATIONS as f64 * 1000.0) / duration_ms as f64);
        log::info!("  平均待機時間: {:.2}us", avg_wait_time as f64 / 1000.0);
        log::info!("  最大待機時間: {:.2}us", max_wait_time as f64 / 1000.0);
        log::info!("  最大通過時間差: {:.2}us", max_cross_diff as f64 / 1000.0);
    }
    
    // スケーラビリティ分析
    let mut scale_report = String::from("\nバリアスケーラビリティ分析:\n");
    
    for i in 1..results.len() {
        let (threads_prev, duration_prev, _, _, _) = results[i-1];
        let (threads_curr, duration_curr, _, _, _) = results[i];
        
        let ideal_slowdown = threads_curr as f64 / threads_prev as f64;
        let actual_slowdown = duration_curr as f64 / duration_prev as f64;
        let efficiency = ideal_slowdown / actual_slowdown;
        
        scale_report.push_str(&format!(
            "  {}→{}スレッド: 効率 {:.2}x（理想比）\n",
            threads_prev, threads_curr, efficiency
        ));
    }
    
    log::info!("{}", scale_report);
}

/// 階層型バリアの性能比較テスト
#[test]
fn test_central_barrier_performance() {
    // テスト設定
    const THREAD_COUNT: usize = 64;
    const ITERATIONS: usize = 100;
    
    // 通常バリアと階層型バリアの両方を作成
    let standard_barrier = Arc::new(Barrier::new(THREAD_COUNT));
    let central_barrier = Arc::new(CentralBarrier::new(THREAD_COUNT, 8)); // 8スレッドごとにローカルバリア
    
    // 標準バリアでのベンチマーク
    let standard_time = benchmark_barrier(
        Arc::clone(&standard_barrier),
        THREAD_COUNT,
        ITERATIONS,
        |barrier, _| barrier.wait()
    );
    
    // 階層型バリアでのベンチマーク
    let central_time = benchmark_barrier(
        Arc::clone(&central_barrier),
        THREAD_COUNT,
        ITERATIONS,
        |barrier, thread_id| barrier.wait(thread_id)
    );
    
    // 結果表示
    log::info!("バリア性能比較（{}スレッド, {}イテレーション）:", THREAD_COUNT, ITERATIONS);
    log::info!("  標準バリア実行時間: {}ms", standard_time);
    log::info!("  階層型バリア実行時間: {}ms", central_time);
    log::info!("  速度向上率: {:.2}x", standard_time as f64 / central_time as f64);
    
    // 階層型バリアは標準バリアより高速であるべき
    assert!(central_time < standard_time, 
            "階層型バリアが標準バリアより遅いです（{}ms > {}ms）", 
            central_time, standard_time);
}

/// 汎用バリアベンチマーク関数
fn benchmark_barrier<B, F>(barrier: Arc<B>, thread_count: usize, iterations: usize, wait_fn: F) -> u64
where
    F: Fn(&B, usize) -> BarrierToken + Send + Sync + Copy + 'static,
    B: Send + Sync + 'static,
{
    // 全スレッド完了フラグ
    let threads_done = Arc::new(AtomicUsize::new(0));
    
    // テストスレッド作成
    let mut handles = Vec::with_capacity(thread_count);
    
    // 開始時間を記録
    let start_time = time::current_time_ns();
    
    for thread_id in 0..thread_count {
        let barrier_clone = Arc::clone(&barrier);
        let threads_done_clone = Arc::clone(&threads_done);
        let wait = wait_fn;
        
        let handle = create_kernel_thread(
            &format!("barrier_bench_{}", thread_id),
            8192,
            0,
            move || {
                for _ in 0..iterations {
                    // バリアで待機（渡された関数を使用）
                    wait(&barrier_clone, thread_id);
                    
                    // スレッドごとに少し異なる作業を実行
                    let work_amount = thread_id % 5;
                    for _ in 0..work_amount {
                        // CPUに負荷をかける単純な計算
                        core::hint::black_box(thread_id * iterations);
                    }
                }
                
                // このスレッドの完了を記録
                threads_done_clone.fetch_add(1, Ordering::Relaxed);
            }
        );
        
        handles.push(handle);
    }
    
    // 全スレッドの完了を待機
    while threads_done.load(Ordering::Relaxed) < thread_count {
        // 少し待つ
        time::sleep(10);
    }
    
    // 終了時間を記録
    let end_time = time::current_time_ns();
    
    // 経過時間をミリ秒で返す
    (end_time - start_time) / 1_000_000
}

/// フェーズバリアテスト
#[test]
fn test_phase_barrier() {
    // テスト設定
    const THREAD_COUNT: usize = 8;
    const PHASE_COUNT: usize = 3;
    
    // フェーズごとの進捗追跡
    let phase_progress = Arc::new([
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ]);
    
    // フェーズバリア作成
    let barrier = Arc::new(PhaseBarrier::new(THREAD_COUNT, PHASE_COUNT));
    
    // 各フェーズが完了したかの検証フラグ
    let phases_completed = Arc::new([
        AtomicBool::new(false),
        AtomicBool::new(false),
        AtomicBool::new(false),
    ]);
    
    // テストスレッド作成
    let mut handles = Vec::with_capacity(THREAD_COUNT);
    
    for thread_id in 0..THREAD_COUNT {
        let barrier_clone = Arc::clone(&barrier);
        let phase_progress_clone = Arc::clone(&phase_progress);
        let phases_completed_clone = Arc::clone(&phases_completed);
        
        let handle = create_kernel_thread(
            &format!("phase_barrier_{}", thread_id),
            8192,
            0,
            move || {
                // フェーズ0の作業
                {
                    // フェーズ0の進捗を記録
                    phase_progress_clone[0].fetch_add(1, Ordering::Relaxed);
                    
                    // フェーズ0が完了していないことを検証
                    assert!(!phases_completed_clone[0].load(Ordering::Relaxed),
                           "フェーズ0が早期に完了マークされています");
                    
                    // フェーズバリアで待機
                    barrier_clone.wait_phase(0);
                    
                    // スレッド0がフェーズ完了をマーク
                    if thread_id == 0 {
                        phases_completed_clone[0].store(true, Ordering::Release);
                    }
                    
                    // 全スレッドがフェーズ0作業を完了したことを検証
                    assert_eq!(phase_progress_clone[0].load(Ordering::Relaxed), THREAD_COUNT,
                              "全スレッドがフェーズ0を完了していません");
                }
                
                // フェーズ1の作業
                {
                    // フェーズ1の進捗を記録
                    phase_progress_clone[1].fetch_add(1, Ordering::Relaxed);
                    
                    // フェーズ0が完了していることを検証
                    assert!(phases_completed_clone[0].load(Ordering::Relaxed),
                           "フェーズ0が完了マークされていません");
                    
                    // フェーズ1が完了していないことを検証
                    assert!(!phases_completed_clone[1].load(Ordering::Relaxed),
                           "フェーズ1が早期に完了マークされています");
                           
                    // フェーズバリアで待機
                    barrier_clone.wait_phase(1);
                    
                    // スレッド0がフェーズ完了をマーク
                    if thread_id == 0 {
                        phases_completed_clone[1].store(true, Ordering::Release);
                    }
                    
                    // 全スレッドがフェーズ1作業を完了したことを検証
                    assert_eq!(phase_progress_clone[1].load(Ordering::Relaxed), THREAD_COUNT,
                              "全スレッドがフェーズ1を完了していません");
                }
                
                // フェーズ2の作業
                {
                    // フェーズ2の進捗を記録
                    phase_progress_clone[2].fetch_add(1, Ordering::Relaxed);
                    
                    // フェーズ1が完了していることを検証
                    assert!(phases_completed_clone[1].load(Ordering::Relaxed),
                           "フェーズ1が完了マークされていません");
                           
                    // フェーズバリアで待機
                    barrier_clone.wait_phase(2);
                    
                    // スレッド0がフェーズ完了をマーク
                    if thread_id == 0 {
                        phases_completed_clone[2].store(true, Ordering::Release);
                    }
                    
                    // 全スレッドがフェーズ2作業を完了したことを検証
                    assert_eq!(phase_progress_clone[2].load(Ordering::Relaxed), THREAD_COUNT,
                              "全スレッドがフェーズ2を完了していません");
                }
                
                // 全フェーズが完了したことを検証
                assert!(phases_completed_clone[0].load(Ordering::Relaxed) &&
                        phases_completed_clone[1].load(Ordering::Relaxed) &&
                        phases_completed_clone[2].load(Ordering::Relaxed),
                       "全フェーズが完了マークされていません");
            }
        );
        
        handles.push(handle);
    }
    
    // スレッド完了を待機
    for handle in handles {
        // ハンドル待機操作
    }
    
    // 最終検証
    for phase in 0..PHASE_COUNT {
        assert_eq!(phase_progress[phase].load(Ordering::Relaxed), THREAD_COUNT,
                  "フェーズ{}が全スレッドで完了していません", phase);
        assert!(phases_completed[phase].load(Ordering::Relaxed),
               "フェーズ{}が完了マークされていません", phase);
    }
    
    // フェーズバリアの状態を検証
    assert!(barrier.is_phase_completed(0), "フェーズ0が完了マークされていません");
    assert!(barrier.is_phase_completed(1), "フェーズ1が完了マークされていません");
    assert!(barrier.is_phase_completed(2), "フェーズ2が完了マークされていません");
}

/// タイムアウト付きバリアテスト
#[test]
fn test_barrier_timeout() {
    // テスト設定
    const THREAD_COUNT: usize = 4;
    
    // バリア作成
    let barrier = Arc::new(Barrier::new(THREAD_COUNT));
    
    // 通過スレッド数
    let passed_count = Arc::new(AtomicUsize::new(0));
    
    // タイムアウト発生数
    let timeout_count = Arc::new(AtomicUsize::new(0));
    
    // テストスレッド作成
    let mut handles = Vec::with_capacity(THREAD_COUNT - 1); // 意図的に1スレッド少なく作成
    
    for thread_id in 0..THREAD_COUNT - 1 {
        let barrier_clone = Arc::clone(&barrier);
        let passed_count_clone = Arc::clone(&passed_count);
        let timeout_count_clone = Arc::clone(&timeout_count);
        
        let handle = create_kernel_thread(
            &format!("timeout_test_{}", thread_id),
            8192,
            0,
            move || {
                // タイムアウト時間の設定（スレッドごとに異なる）
                let timeout_ns = match thread_id {
                    0 => 1_000_000,        // 1ms（短すぎて常にタイムアウト）
                    1 => 1_000_000_000,    // 1000ms（長めのタイムアウト）
                    _ => 100_000_000,      // 100ms（中程度のタイムアウト）
                };
                
                // タイムアウト付きバリア待機
                match barrier_clone.wait_timeout(timeout_ns) {
                    Some(_) => {
                        // 成功（タイムアウトなし）
                        passed_count_clone.fetch_add(1, Ordering::Relaxed);
                    }
                    None => {
                        // タイムアウト発生
                        timeout_count_clone.fetch_add(1, Ordering::Relaxed);
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
    
    // 結果検証
    let final_passed = passed_count.load(Ordering::Relaxed);
    let final_timeout = timeout_count.load(Ordering::Relaxed);
    
    log::info!("バリアタイムアウトテスト結果:");
    log::info!("  通過スレッド数: {}", final_passed);
    log::info!("  タイムアウト数: {}", final_timeout);
    
    // 少なくとも1つはタイムアウトするはず（スレッド数が足りないため）
    assert!(final_timeout > 0, "タイムアウトが発生しませんでした");
    assert_eq!(final_passed + final_timeout, THREAD_COUNT - 1, 
               "通過数とタイムアウト数の合計が不正です");
}

/// 最大負荷バリアテスト
#[test]
#[ignore] // リソース要求が高いテストなので通常は無視
fn test_barrier_max_load() {
    // テスト設定
    const THREAD_COUNT: usize = 128; // 多数のスレッド
    const ITERATIONS: usize = 1000;  // 多数の繰り返し
    
    // バリア作成
    let barrier = Arc::new(Barrier::new(THREAD_COUNT));
    
    // 通過カウンタ
    let crossing_count = Arc::new(AtomicUsize::new(0));
    
    // スレッド作成前の時間を記録
    let start_time = time::current_time_ns();
    
    // テストスレッド作成
    let mut handles = Vec::with_capacity(THREAD_COUNT);
    
    for thread_id in 0..THREAD_COUNT {
        let barrier_clone = Arc::clone(&barrier);
        let crossing_count_clone = Arc::clone(&crossing_count);
        
        let handle = create_kernel_thread(
            &format!("max_load_{}", thread_id),
            8192,
            0,
            move || {
                // 各スレッドのローカル通過カウンタ
                let mut local_crossings = 0;
                
                for _ in 0..ITERATIONS {
                    // バリアで待機
                    barrier_clone.wait();
                    local_crossings += 1;
                    
                    // スレッドごとにランダムな遅延を挿入
                    if thread_id % 10 == 0 {
                        let delay = thread_id % 5;
                        time::sleep_us(delay as u64 * 100);
                    }
                }
                
                // 通過数を追加
                crossing_count_clone.fetch_add(local_crossings, Ordering::Relaxed);
            }
        );
        
        handles.push(handle);
    }
    
    // スレッド完了を待機
    for handle in handles {
        // ハンドル待機操作
    }
    
    // 終了時間を記録
    let end_time = time::current_time_ns();
    let duration_ms = (end_time - start_time) / 1_000_000;
    
    // 結果検証
    let total_crossings = crossing_count.load(Ordering::Relaxed);
    let expected_crossings = THREAD_COUNT * ITERATIONS;
    
    log::info!("バリア最大負荷テスト結果:");
    log::info!("  スレッド数: {}", THREAD_COUNT);
    log::info!("  イテレーション数: {}", ITERATIONS);
    log::info!("  実行時間: {}ms", duration_ms);
    log::info!("  通過回数: {}/{}", total_crossings, expected_crossings);
    log::info!("  スループット: {:.2}バリア/秒", 
               (ITERATIONS as f64 * 1000.0) / duration_ms as f64);
    
    // 通過回数が期待値と一致することを検証
    assert_eq!(total_crossings, expected_crossings, 
              "バリア通過回数が期待値と一致しません");
} 