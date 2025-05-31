// AetherOS 拡張スケジューラ高度テスト
//
// このモジュールはヘテロジニアスコンピューティング対応や
// 省電力スケジューリング、QoS制御などの機能を検証します。

use core::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::string::String;
use alloc::collections::BTreeMap;

use crate::core::process::{
    Process, Thread, ProcessId, ThreadId, ThreadOptions,
    create_kernel_thread, current_thread, yield_cpu
};
use crate::core::process::scheduler_extension::{
    ProcessorType, PowerState, QoSLevel, TaskAffinity,
    HeterogeneousScheduler, get_scheduler, select_optimal_core,
    schedule_gpu_task, ThreadExt
};
use crate::core::sync::{Mutex, Barrier, SpinLock};
use crate::time;

/// 最適コア選択テスト
#[test]
fn test_optimal_core_selection() {
    // テスト実行前の準備
    let scheduler = get_scheduler();
    
    // テスト用スレッド作成
    let thread1 = create_test_thread(1, None); // デフォルトアフィニティ
    let thread2 = create_test_thread(2, Some(create_performance_affinity()));
    let thread3 = create_test_thread(3, Some(create_efficiency_affinity()));
    
    // 最適コア選択
    let core1 = select_optimal_core(&thread1);
    let core2 = select_optimal_core(&thread2);
    let core3 = select_optimal_core(&thread3);
    
    // 結果検証
    log::info!("最適コア選択テスト結果:");
    log::info!("  汎用スレッド      → コア {}", core1);
    log::info!("  高性能スレッド    → コア {}", core2);
    log::info!("  省電力スレッド    → コア {}", core3);
    
    // 要件の検証（実際のコア番号はシステムによって異なる）
    assert!(core1 < scheduler.cpu_cores.len(), "無効なコアが選択されました");
    assert!(core2 < scheduler.cpu_cores.len(), "無効なコアが選択されました");
    assert!(core3 < scheduler.cpu_cores.len(), "無効なコアが選択されました");
    
    // 性能優先スレッドと省電力スレッドは異なるコアに割り当てられるべき
    assert_ne!(core2, core3, "性能特性の異なるスレッドが同じコアに割り当てられました");
}

/// QoSレベル影響テスト
#[test]
fn test_qos_levels() {
    // テスト用スレッド作成（異なるQoSレベル）
    let realtime_thread = create_test_thread_with_qos(1, QoSLevel::RealTime);
    let high_thread = create_test_thread_with_qos(2, QoSLevel::High);
    let normal_thread = create_test_thread_with_qos(3, QoSLevel::Normal);
    let background_thread = create_test_thread_with_qos(4, QoSLevel::Background);
    
    // 各QoSレベルの優先度確認
    let rt_priority = realtime_thread.priority();
    let high_priority = high_thread.priority();
    let normal_priority = normal_thread.priority();
    let bg_priority = background_thread.priority();
    
    // 優先度の順序を検証
    assert!(rt_priority > high_priority, "リアルタイム優先度が高優先度より低くなっています");
    assert!(high_priority > normal_priority, "高優先度が通常優先度より低くなっています");
    assert!(normal_priority > bg_priority, "通常優先度がバックグラウンド優先度より低くなっています");
    
    log::info!("QoSレベルテスト結果:");
    log::info!("  リアルタイム    優先度: {}", rt_priority);
    log::info!("  高              優先度: {}", high_priority);
    log::info!("  通常            優先度: {}", normal_priority);
    log::info!("  バックグラウンド優先度: {}", bg_priority);
}

/// コア周波数制御テスト
#[test]
fn test_frequency_control() {
    // テスト実行前の準備
    let scheduler = get_scheduler();
    
    // 現在の周波数を記録
    let mut initial_freqs = Vec::with_capacity(scheduler.cpu_cores.len());
    for core in &scheduler.cpu_cores {
        initial_freqs.push(core.current_frequency.load(Ordering::Relaxed));
    }
    
    // 負荷変化をシミュレート
    for core in &scheduler.cpu_cores {
        // 高負荷をシミュレート（キューに10タスク）
        core.queue_length.store(10, Ordering::Relaxed);
    }
    
    // 周波数制御を実行
    scheduler.adjust_frequencies();
    
    // 高負荷後の周波数を記録
    let mut high_load_freqs = Vec::with_capacity(scheduler.cpu_cores.len());
    for core in &scheduler.cpu_cores {
        high_load_freqs.push(core.current_frequency.load(Ordering::Relaxed));
    }
    
    // 低負荷をシミュレート
    for core in &scheduler.cpu_cores {
        core.queue_length.store(1, Ordering::Relaxed);
    }
    
    // 周波数制御を再実行
    scheduler.adjust_frequencies();
    
    // 低負荷後の周波数を記録
    let mut low_load_freqs = Vec::with_capacity(scheduler.cpu_cores.len());
    for core in &scheduler.cpu_cores {
        low_load_freqs.push(core.current_frequency.load(Ordering::Relaxed));
    }
    
    // 結果検証
    let mut high_load_avg = 0;
    let mut low_load_avg = 0;
    
    for i in 0..scheduler.cpu_cores.len() {
        high_load_avg += high_load_freqs[i];
        low_load_avg += low_load_freqs[i];
    }
    
    high_load_avg /= scheduler.cpu_cores.len();
    low_load_avg /= scheduler.cpu_cores.len();
    
    log::info!("周波数制御テスト結果:");
    log::info!("  高負荷時平均周波数: {} kHz", high_load_avg);
    log::info!("  低負荷時平均周波数: {} kHz", low_load_avg);
    
    // 高負荷時は低負荷時より周波数が高いはず
    assert!(high_load_avg > low_load_avg, 
            "負荷に応じた周波数制御が機能していません: 高負荷({}) ≤ 低負荷({})",
            high_load_avg, low_load_avg);
}

/// 電力状態制御テスト
#[test]
fn test_power_state_control() {
    // テスト実行前の準備
    let scheduler = get_scheduler();
    
    // 最初の電力状態を記録
    let mut initial_states = Vec::with_capacity(scheduler.cpu_cores.len());
    for core in &scheduler.cpu_cores {
        initial_states.push(core.power_state);
    }
    
    // 高負荷をシミュレート
    for core in &scheduler.cpu_cores {
        core.queue_length.store(95, Ordering::Relaxed); // 95%負荷
    }
    
    // 電力状態を更新
    scheduler.update_power_states();
    
    // 高負荷後の電力状態を記録
    let mut high_load_states = Vec::with_capacity(scheduler.cpu_cores.len());
    for core in &scheduler.cpu_cores {
        high_load_states.push(core.power_state);
    }
    
    // 低負荷をシミュレート
    for core in &scheduler.cpu_cores {
        core.queue_length.store(5, Ordering::Relaxed); // 5%負荷
    }
    
    // 電力状態を更新
    scheduler.update_power_states();
    
    // 低負荷後の電力状態を記録
    let mut low_load_states = Vec::with_capacity(scheduler.cpu_cores.len());
    for core in &scheduler.cpu_cores {
        low_load_states.push(core.power_state);
    }
    
    // 結果を集計
    let mut performance_count_high = 0;
    let mut efficient_count_low = 0;
    
    for state in &high_load_states {
        if *state == PowerState::Performance {
            performance_count_high += 1;
        }
    }
    
    for state in &low_load_states {
        if *state == PowerState::Efficient {
            efficient_count_low += 1;
        }
    }
    
    log::info!("電力状態制御テスト結果:");
    log::info!("  高負荷時パフォーマンスモードコア数: {}/{}", 
               performance_count_high, scheduler.cpu_cores.len());
    log::info!("  低負荷時省電力モードコア数: {}/{}", 
               efficient_count_low, scheduler.cpu_cores.len());
    
    // 高負荷時は少なくとも一部のコアがパフォーマンスモードに
    assert!(performance_count_high > 0, 
            "高負荷時にパフォーマンスモードに切り替わっていません");
    
    // 低負荷時は少なくとも一部のコアが省電力モードに
    assert!(efficient_count_low > 0, 
            "低負荷時に省電力モードに切り替わっていません");
}

/// 負荷分散テスト
#[test]
fn test_load_balancing() {
    // テスト実行前の準備
    let scheduler = get_scheduler();
    
    // 不均衡な負荷をシミュレート
    for (i, core) in scheduler.cpu_cores.iter().enumerate() {
        if i % 4 == 0 {
            // 一部のコアに高負荷
            core.queue_length.store(20, Ordering::Relaxed);
        } else {
            // その他は低負荷
            core.queue_length.store(2, Ordering::Relaxed);
        }
    }
    
    // 負荷分散前の状態を記録
    let mut before_balancing = Vec::with_capacity(scheduler.cpu_cores.len());
    for core in &scheduler.cpu_cores {
        before_balancing.push(core.queue_length.load(Ordering::Relaxed));
    }
    
    // 最大と最小の負荷差を計算
    let max_before = *before_balancing.iter().max().unwrap_or(&0);
    let min_before = *before_balancing.iter().min().unwrap_or(&0);
    let diff_before = max_before - min_before;
    
    // 負荷分散を実行
    scheduler.balance_load();
    
    // 負荷分散後の状態を記録
    let mut after_balancing = Vec::with_capacity(scheduler.cpu_cores.len());
    for core in &scheduler.cpu_cores {
        after_balancing.push(core.queue_length.load(Ordering::Relaxed));
    }
    
    // 最大と最小の負荷差を再計算
    let max_after = *after_balancing.iter().max().unwrap_or(&0);
    let min_after = *after_balancing.iter().min().unwrap_or(&0);
    let diff_after = max_after - min_after;
    
    log::info!("負荷分散テスト結果:");
    log::info!("  分散前 最大負荷: {}, 最小負荷: {}, 差: {}", 
               max_before, min_before, diff_before);
    log::info!("  分散後 最大負荷: {}, 最小負荷: {}, 差: {}", 
               max_after, min_after, diff_after);
    
    // 負荷分散後は負荷差が減少しているはず
    assert!(diff_after <= diff_before, 
            "負荷分散により負荷差が減少していません: 前({}) → 後({})",
            diff_before, diff_after);
}

/// GPU処理スケジューリングテスト
#[test]
fn test_gpu_scheduling() {
    // GPUがあるかチェック
    let scheduler = get_scheduler();
    if scheduler.gpu_queues.is_empty() {
        log::info!("GPUが検出されませんでした。テストをスキップします。");
        return;
    }
    
    // テスト用GPUスレッド作成
    let gpu_threads: Vec<_> = (0..5).map(|i| create_gpu_test_thread(i)).collect();
    
    // 全てのスレッドをGPUにスケジュール
    let mut scheduled_count = 0;
    for thread in &gpu_threads {
        if schedule_gpu_task(Arc::clone(thread)) {
            scheduled_count += 1;
        }
    }
    
    // GPUキューの状態を検証
    let mut queued_tasks = 0;
    let mut active_tasks = 0;
    
    for gpu in &scheduler.gpu_queues {
        active_tasks += gpu.active_tasks.load(Ordering::Relaxed);
        // キューの長さは内部状態なのでこのままでは取得できない
        // 実際のコードでは適切な方法で取得する
    }
    
    log::info!("GPUスケジューリングテスト結果:");
    log::info!("  スケジュール成功: {}/{}", scheduled_count, gpu_threads.len());
    log::info!("  アクティブタスク: {}", active_tasks);
    
    // 少なくとも一部のタスクがスケジュールされたはず
    assert!(scheduled_count > 0, "GPUタスクのスケジューリングに失敗しました");
}

/// 複合ワークロードパフォーマンステスト
#[test]
fn test_heterogeneous_workload() {
    // テスト設定
    const CPU_THREAD_COUNT: usize = 8;
    const GPU_THREAD_COUNT: usize = 4;
    const ITERATIONS: usize = 100;
    
    // テスト用カウンタ
    let cpu_work_done = Arc::new(AtomicUsize::new(0));
    let gpu_work_done = Arc::new(AtomicUsize::new(0));
    
    // スレッド同期用バリア
    let barrier = Arc::new(Barrier::new(CPU_THREAD_COUNT + GPU_THREAD_COUNT));
    
    // CPU処理スレッド作成
    let mut cpu_handles = Vec::with_capacity(CPU_THREAD_COUNT);
    
    for i in 0..CPU_THREAD_COUNT {
        let cpu_counter = Arc::clone(&cpu_work_done);
        let barrier_clone = Arc::clone(&barrier);
        
        let handle = create_kernel_thread(
            &format!("cpu_worker_{}", i),
            8192,
            0,
            move || {
                // 開始同期
                barrier_clone.wait();
                
                // CPU集中作業をシミュレート
                for _ in 0..ITERATIONS {
                    // 単純な計算作業
                    let mut sum = 0;
                    for j in 0..10000 {
                        sum += j;
                        core::hint::black_box(sum);
                    }
                    
                    // 完了した作業をカウント
                    cpu_counter.fetch_add(1, Ordering::Relaxed);
                    
                    // 短い休止
                    if i % 3 == 0 {
                        yield_cpu();
                    }
                }
            }
        );
        
        cpu_handles.push(handle);
    }
    
    // GPU処理スレッド作成
    let mut gpu_handles = Vec::with_capacity(GPU_THREAD_COUNT);
    
    for i in 0..GPU_THREAD_COUNT {
        let gpu_counter = Arc::clone(&gpu_work_done);
        let barrier_clone = Arc::clone(&barrier);
        
        let handle = create_kernel_thread(
            &format!("gpu_worker_{}", i),
            8192,
            0,
            move || {
                // 開始同期
                barrier_clone.wait();
                
                // GPU処理をシミュレート
                for _ in 0..ITERATIONS {
                    // GPU処理を模擬（実際にはGPUコマンド送信など）
                    time::sleep(1); // 1ms 待機して処理を模擬
                    
                    // 完了した作業をカウント
                    gpu_counter.fetch_add(1, Ordering::Relaxed);
                    
                    // たまにCPUを譲る
                    yield_cpu();
                }
            }
        );
        
        gpu_handles.push(handle);
    }
    
    // 開始時間を記録
    let start_time = time::current_time_ns();
    
    // スレッド完了を待機
    for handle in cpu_handles {
        // ハンドル待機
    }
    
    for handle in gpu_handles {
        // ハンドル待機
    }
    
    // 終了時間を記録
    let end_time = time::current_time_ns();
    let duration_ms = (end_time - start_time) / 1_000_000;
    
    // 結果検証
    let total_cpu_work = cpu_work_done.load(Ordering::Relaxed);
    let total_gpu_work = gpu_work_done.load(Ordering::Relaxed);
    
    let expected_cpu_work = CPU_THREAD_COUNT * ITERATIONS;
    let expected_gpu_work = GPU_THREAD_COUNT * ITERATIONS;
    
    log::info!("ヘテロジニアスワークロードテスト結果:");
    log::info!("  実行時間: {}ms", duration_ms);
    log::info!("  CPU作業完了: {}/{}", total_cpu_work, expected_cpu_work);
    log::info!("  GPU作業完了: {}/{}", total_gpu_work, expected_gpu_work);
    log::info!("  スループット: {:.2}操作/秒", 
              ((total_cpu_work + total_gpu_work) as f64 * 1000.0) / duration_ms as f64);
    
    // 全ての作業が完了したことを確認
    assert_eq!(total_cpu_work, expected_cpu_work, 
              "CPU作業が完了していません");
    assert_eq!(total_gpu_work, expected_gpu_work, 
              "GPU作業が完了していません");
}

// ----- ヘルパー関数 -----

/// テスト用スレッドを作成
fn create_test_thread(id: usize, affinity: Option<TaskAffinity>) -> Arc<Thread> {
    // このメソッドは実際の実装では、より具体的なThread構造体の作成が必要
    // ここではモックスレッドを作成
    
    struct MockThread {
        id: ThreadId,
        priority: i32,
        affinity: TaskAffinity,
        qos: QoSLevel,
    }
    
    impl Thread for MockThread {
        fn id(&self) -> ThreadId {
            self.id
        }
        
        fn priority(&self) -> i32 {
            self.priority
        }
        
        // その他のThread traitメソッド実装...
    }
    
    impl ThreadExt for MockThread {
        fn gpu_memory_required(&self) -> usize {
            1024 // 1KB のGPUメモリを要求
        }
        
        fn affinity(&self) -> &TaskAffinity {
            &self.affinity
        }
        
        fn qos_level(&self) -> QoSLevel {
            self.qos
        }
    }
    
    Arc::new(MockThread {
        id: ThreadId(id as u64),
        priority: 50,
        affinity: affinity.unwrap_or_default(),
        qos: QoSLevel::Normal,
    })
}

/// 性能優先のアフィニティを作成
fn create_performance_affinity() -> TaskAffinity {
    // 性能特性を持つCPUを優先
    let cpu_count = get_scheduler().cpu_cores.len();
    let mut cpu_mask = Vec::with_capacity(cpu_count);
    
    // 偶数番号のコアのみを使用（通常は高性能コア）
    for i in 0..cpu_count {
        cpu_mask.push(i % 2 == 0);
    }
    
    TaskAffinity {
        cpu_mask,
        required_processor: Some(ProcessorType::CPU),
        preferred_core: Some(0), // 通常、コア0が高性能
        numa_preference: None,
        cache_locality_preference: 80, // 高いキャッシュ局所性
    }
}

/// 省電力アフィニティを作成
fn create_efficiency_affinity() -> TaskAffinity {
    // 省電力特性を持つCPUを優先
    let cpu_count = get_scheduler().cpu_cores.len();
    let mut cpu_mask = Vec::with_capacity(cpu_count);
    
    // 奇数番号のコアのみを使用（通常は省電力コア）
    for i in 0..cpu_count {
        cpu_mask.push(i % 2 == 1);
    }
    
    TaskAffinity {
        cpu_mask,
        required_processor: Some(ProcessorType::CPU),
        preferred_core: Some(1), // 通常、コア1以降が省電力
        numa_preference: None,
        cache_locality_preference: 20, // 低いキャッシュ局所性
    }
}

/// 特定のQoSレベルでスレッドを作成
fn create_test_thread_with_qos(id: usize, qos: QoSLevel) -> Arc<Thread> {
    struct MockThread {
        id: ThreadId,
        priority: i32,
        affinity: TaskAffinity,
        qos: QoSLevel,
    }
    
    impl Thread for MockThread {
        fn id(&self) -> ThreadId {
            self.id
        }
        
        fn priority(&self) -> i32 {
            match self.qos {
                QoSLevel::RealTime => 95,
                QoSLevel::High => 75,
                QoSLevel::Normal => 50,
                QoSLevel::Background => 25,
                QoSLevel::Idle => 10,
            }
        }
        
        // その他のThread traitメソッド実装...
    }
    
    impl ThreadExt for MockThread {
        fn gpu_memory_required(&self) -> usize {
            0
        }
        
        fn affinity(&self) -> &TaskAffinity {
            &self.affinity
        }
        
        fn qos_level(&self) -> QoSLevel {
            self.qos
        }
    }
    
    Arc::new(MockThread {
        id: ThreadId(id as u64),
        priority: 0, // priority()メソッドで上書きされる
        affinity: TaskAffinity::default(),
        qos,
    })
}

/// GPUテスト用スレッドを作成
fn create_gpu_test_thread(id: usize) -> Arc<Thread> {
    struct MockGPUThread {
        id: ThreadId,
        priority: i32,
        gpu_memory: usize,
    }
    
    impl Thread for MockGPUThread {
        fn id(&self) -> ThreadId {
            self.id
        }
        
        fn priority(&self) -> i32 {
            self.priority
        }
        
        // その他のThread traitメソッド実装...
    }
    
    impl ThreadExt for MockGPUThread {
        fn gpu_memory_required(&self) -> usize {
            self.gpu_memory
        }
        
        fn affinity(&self) -> &TaskAffinity {
            static GPU_AFFINITY: TaskAffinity = TaskAffinity {
                cpu_mask: Vec::new(), // 初期化時に正しく設定される
                required_processor: Some(ProcessorType::GPU),
                preferred_core: None,
                numa_preference: None,
                cache_locality_preference: 30,
            };
            
            &GPU_AFFINITY
        }
        
        fn qos_level(&self) -> QoSLevel {
            QoSLevel::High // GPUタスクは通常高優先度
        }
    }
    
    // GPU要求メモリをスレッドごとに変える
    let gpu_memory = match id % 3 {
        0 => 1024 * 1024,      // 1MB
        1 => 4 * 1024 * 1024,  // 4MB
        _ => 512 * 1024,       // 512KB
    };
    
    Arc::new(MockGPUThread {
        id: ThreadId(id as u64),
        priority: 70,
        gpu_memory,
    })
} 