// AetherOS バディアロケータ高度テスト
// 
// このモジュールはバディアロケータシステムの堅牢性と
// パフォーマンスを徹底的に検証します。

use core::sync::atomic::{AtomicUsize, Ordering};
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::collections::BTreeMap;

use crate::core::memory::buddy::{BuddyAllocator, AllocatorStats};
use crate::core::sync::{Barrier, SpinLock, Mutex};
use crate::core::process::create_kernel_thread;
use crate::time;

/// メモリ使用パターン
enum AllocationPattern {
    /// ランダムサイズ
    Random,
    /// 固定サイズ
    Fixed(usize),
    /// 段階的に増加
    Increasing,
    /// 段階的に減少
    Decreasing,
    /// 現実的なワークロード分布
    Realistic,
}

/// アロケータストレステスト
struct AllocatorStressTest {
    /// アロケータ
    allocator: Arc<SpinLock<BuddyAllocator>>,
    /// スレッド数
    thread_count: usize,
    /// 1スレッドあたりの操作数
    ops_per_thread: usize,
    /// 割り当てパターン
    pattern: AllocationPattern,
    /// 最大割り当てサイズ
    max_alloc_size: usize,
    /// 割り当て/解放の比率(0-100)
    alloc_free_ratio: usize,
    /// 同期バリア
    barrier: Arc<Barrier>,
    /// 成功した割り当て数
    successful_allocs: AtomicUsize,
    /// 失敗した割り当て数
    failed_allocs: AtomicUsize,
    /// 検証エラー数
    validation_errors: AtomicUsize,
    /// 各スレッドのポインタ追跡
    thread_allocations: Vec<Arc<Mutex<Vec<(*mut u8, usize)>>>>,
}

impl AllocatorStressTest {
    /// 新しいストレステストを作成
    fn new(
        memory_size: usize,
        thread_count: usize,
        ops_per_thread: usize,
        pattern: AllocationPattern,
        max_alloc_size: usize,
        alloc_free_ratio: usize,
    ) -> Self {
        // バディアロケータを初期化
        let allocator = BuddyAllocator::new(memory_size);
        
        // スレッド間同期用バリア
        let barrier = Arc::new(Barrier::new(thread_count));
        
        // 各スレッドの割り当て追跡
        let mut thread_allocations = Vec::with_capacity(thread_count);
        for _ in 0..thread_count {
            thread_allocations.push(Arc::new(Mutex::new(Vec::new())));
        }
        
        Self {
            allocator: Arc::new(SpinLock::new(allocator)),
            thread_count,
            ops_per_thread,
            pattern,
            max_alloc_size,
            alloc_free_ratio,
            barrier,
            successful_allocs: AtomicUsize::new(0),
            failed_allocs: AtomicUsize::new(0),
            validation_errors: AtomicUsize::new(0),
            thread_allocations,
        }
    }
    
    /// テストを実行
    fn run(&self) -> AllocatorStats {
        let mut handles = Vec::with_capacity(self.thread_count);
        
        // 各スレッドを作成
        for thread_id in 0..self.thread_count {
            let allocator = Arc::clone(&self.allocator);
            let barrier = Arc::clone(&self.barrier);
            let allocations = Arc::clone(&self.thread_allocations[thread_id]);
            let successful_allocs = &self.successful_allocs;
            let failed_allocs = &self.failed_allocs;
            let validation_errors = &self.validation_errors;
            let max_alloc_size = self.max_alloc_size;
            let ops_count = self.ops_per_thread;
            let alloc_free_ratio = self.alloc_free_ratio;
            let pattern = match &self.pattern {
                AllocationPattern::Random => 0,
                AllocationPattern::Fixed(_) => 1,
                AllocationPattern::Increasing => 2,
                AllocationPattern::Decreasing => 3,
                AllocationPattern::Realistic => 4,
            };
            
            // テストスレッドを作成
            let handle = create_kernel_thread(
                &format!("buddy_test_{}", thread_id),
                8192,
                0,
                move || {
                    let mut local_allocs = Vec::new();
                    let mut rng_state = thread_id as u64; // 単純なシード値
                    
                    // 全スレッドの開始を同期
                    barrier.wait();
                    let start_time = time::current_time_ns();
                    
                    for op in 0..ops_count {
                        // 操作タイプを決定（割り当てか解放か）
                        let is_alloc = if local_allocs.is_empty() {
                            true // 最初は必ず割り当て
                        } else {
                            let rand_val = xorshift(&mut rng_state) % 100;
                            rand_val < alloc_free_ratio as u64
                        };
                        
                        if is_alloc {
                            // メモリ割り当て
                            let size = match pattern {
                                0 => (xorshift(&mut rng_state) % max_alloc_size as u64) as usize + 1, // ランダム
                                1 => max_alloc_size / 2, // 固定
                                2 => ((op * max_alloc_size) / ops_count).max(1), // 増加
                                3 => (((ops_count - op) * max_alloc_size) / ops_count).max(1), // 減少
                                4 => realistic_size_distribution(xorshift(&mut rng_state)), // 現実的
                                _ => max_alloc_size / 2,
                            };
                            
                            // アロケータから割り当て
                            let mut alloc_guard = allocator.lock();
                            match alloc_guard.allocate(size) {
                                Some(ptr) => {
                                    successful_allocs.fetch_add(1, Ordering::Relaxed);
                                    local_allocs.push((ptr, size));
                                    
                                    // メモリに特徴的なパターンを書き込み
                                    unsafe {
                                        let pattern_val = (thread_id as u8) ^ (op as u8);
                                        core::ptr::write_bytes(ptr, pattern_val, size);
                                    }
                                }
                                None => {
                                    failed_allocs.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        } else {
                            // ランダムに選択したメモリを解放
                            let index = (xorshift(&mut rng_state) % local_allocs.len() as u64) as usize;
                            let (ptr, size) = local_allocs.swap_remove(index);
                            
                            // パターン検証
                            unsafe {
                                let pattern_val = (thread_id as u8) ^ ((op - 1) as u8);
                                let mut is_valid = true;
                                for i in 0..size {
                                    if *ptr.add(i) != pattern_val {
                                        is_valid = false;
                                        break;
                                    }
                                }
                                
                                if !is_valid {
                                    validation_errors.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            
                            // メモリ解放
                            let mut alloc_guard = allocator.lock();
                            alloc_guard.deallocate(ptr, size);
                        }
                        
                        // たまにスレッドを切り替え
                        if op % 100 == 0 {
                            crate::core::process::yield_cpu();
                        }
                    }
                    
                    // 残りの割り当てをすべて解放
                    {
                        let mut alloc_guard = allocator.lock();
                        for (ptr, size) in local_allocs.iter() {
                            alloc_guard.deallocate(*ptr, *size);
                        }
                    }
                    
                    // 割り当て状況を保存
                    let mut alloc_list = allocations.lock();
                    *alloc_list = local_allocs;
                    
                    // 処理時間を記録
                    let elapsed = time::current_time_ns() - start_time;
                    log::debug!(
                        "スレッド {} 完了: {}操作 / {}ns (スループット: {:.2}操作/秒)",
                        thread_id,
                        ops_count,
                        elapsed,
                        (ops_count as f64 * 1_000_000_000.0) / elapsed as f64
                    );
                }
            );
            
            handles.push(handle);
        }
        
        // 全スレッド完了を待機
        for handle in handles {
            // スレッド終了を待機
        }
        
        // 最終的な統計情報を取得
        let allocator_guard = self.allocator.lock();
        allocator_guard.get_stats()
    }
    
    /// テスト結果レポートを生成
    fn generate_report(&self, stats: &AllocatorStats, duration_ns: u64) -> String {
        let successful = self.successful_allocs.load(Ordering::Relaxed);
        let failed = self.failed_allocs.load(Ordering::Relaxed);
        let errors = self.validation_errors.load(Ordering::Relaxed);
        let total_ops = successful + failed;
        let success_rate = if total_ops > 0 {
            (successful as f64 * 100.0) / total_ops as f64
        } else {
            0.0
        };
        let throughput = (total_ops as f64 * 1_000_000_000.0) / duration_ns as f64;
        
        let mut report = String::new();
        report.push_str(&format!("======= バディアロケータテスト結果 =======\n"));
        report.push_str(&format!("スレッド数: {}\n", self.thread_count));
        report.push_str(&format!("合計操作数: {}\n", total_ops));
        report.push_str(&format!("成功した割り当て: {}\n", successful));
        report.push_str(&format!("失敗した割り当て: {}\n", failed));
        report.push_str(&format!("成功率: {:.2}%\n", success_rate));
        report.push_str(&format!("検証エラー: {}\n", errors));
        report.push_str(&format!("実行時間: {:.2}秒\n", duration_ns as f64 / 1_000_000_000.0));
        report.push_str(&format!("スループット: {:.2}操作/秒\n", throughput));
        report.push_str(&format!("\n--- アロケータ統計 ---\n"));
        report.push_str(&format!("合計メモリ: {} バイト\n", stats.total_memory));
        report.push_str(&format!("割り当て済み: {} バイト\n", stats.allocated_memory));
        report.push_str(&format!("空きメモリ: {} バイト\n", stats.free_memory));
        report.push_str(&format!("使用率: {:.2}%\n", 
            (stats.allocated_memory as f64 * 100.0) / stats.total_memory as f64));
        report.push_str(&format!("断片化率: {:.2}%\n", stats.fragmentation_percent));
        
        report
    }
}

/// 現実的なメモリサイズ分布を生成
fn realistic_size_distribution(rand: u64) -> usize {
    let normalized = rand % 100;
    if normalized < 50 {
        // 小サイズ (50%の確率): 16-128バイト
        16 + (rand % 112) as usize
    } else if normalized < 80 {
        // 中サイズ (30%の確率): 128-4096バイト
        128 + (rand % 3968) as usize
    } else if normalized < 95 {
        // 大サイズ (15%の確率): 4096-65536バイト
        4096 + (rand % 61440) as usize
    } else {
        // 巨大サイズ (5%の確率): 65536-1048576バイト
        65536 + (rand % 983040) as usize
    }
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

/// フラグメンテーション誘発テスト
fn fragmentation_test(memory_size: usize) -> f64 {
    let mut allocator = BuddyAllocator::new(memory_size);
    let mut pointers = Vec::new();
    
    // パターン1: 小→大→小の順で割り当て
    for i in 0..10 {
        let size = 128 << i; // 128バイトから段階的に大きく
        if let Some(ptr) = allocator.allocate(size) {
            pointers.push((ptr, size));
        }
    }
    
    // パターン2: 特定のパターンで解放（断片化誘発）
    for i in (0..pointers.len()).step_by(2) {
        if i < pointers.len() {
            let (ptr, size) = pointers[i];
            allocator.deallocate(ptr, size);
        }
    }
    
    // パターン3: 残りの最大ブロックサイズをチェック
    let max_available = allocator.largest_free_chunk();
    
    // クリーンアップ
    for (ptr, size) in pointers.iter().skip(1).step_by(2) {
        allocator.deallocate(*ptr, *size);
    }
    
    // 理論上の最大空きサイズと実際の最大空きサイズの比較
    let stats = allocator.get_stats();
    stats.fragmentation_percent
}

/// コンカレント割り当て/解放テスト
#[test]
fn test_concurrent_allocation() {
    // 1GBのメモリプール
    const MEMORY_SIZE: usize = 1024 * 1024 * 1024;
    
    // 8スレッドで10000操作ずつ
    let stress_test = AllocatorStressTest::new(
        MEMORY_SIZE,
        8,
        10000,
        AllocationPattern::Random,
        1024 * 1024, // 最大1MB割り当て
        70,          // 70%割り当て、30%解放
    );
    
    // テスト開始時間
    let start_time = time::current_time_ns();
    
    // テスト実行
    let stats = stress_test.run();
    
    // 実行時間
    let duration = time::current_time_ns() - start_time;
    
    // 結果レポート生成
    let report = stress_test.generate_report(&stats, duration);
    log::info!("{}", report);
    
    // 検証
    let errors = stress_test.validation_errors.load(Ordering::Relaxed);
    assert_eq!(errors, 0, "メモリ整合性エラー: {}", errors);
    
    // メモリリークがないことを確認
    assert_eq!(stats.allocated_memory, 0, "メモリリーク検出: {}バイト", stats.allocated_memory);
}

/// バディアロケータ境界テスト
#[test]
fn test_buddy_edge_cases() {
    // 小さなメモリプール
    let mut allocator = BuddyAllocator::new(4096);
    
    // ケース1: 全メモリ割り当て
    let ptr1 = allocator.allocate(4096);
    assert!(ptr1.is_some(), "全メモリ割り当て失敗");
    
    // ケース2: キャパシティ超過割り当て
    let ptr2 = allocator.allocate(1);
    assert!(ptr2.is_none(), "キャパシティ超過で割り当てが成功してしまった");
    
    // ケース3: ゼロサイズ割り当て
    let ptr3 = allocator.allocate(0);
    assert!(ptr3.is_none(), "ゼロサイズ割り当てが成功してしまった");
    
    // クリーンアップ
    if let Some(ptr) = ptr1 {
        allocator.deallocate(ptr, 4096);
    }
    
    // ケース4: 最小単位以下の割り当て
    let min_alloc = allocator.min_allocation_size();
    let ptr4 = allocator.allocate(min_alloc / 2);
    assert!(ptr4.is_some(), "最小単位以下の割り当てが失敗");
    
    // ケース5: 断片化チェック
    let fragmentation = fragmentation_test(1024 * 1024);
    log::info!("フラグメンテーションテスト結果: {:.2}%", fragmentation);
    assert!(fragmentation < 50.0, "過度の断片化: {:.2}%", fragmentation);
}

/// パフォーマンスベンチマーク
#[test]
fn benchmark_buddy_allocator() {
    // テストサイズを段階的に増加
    let sizes = [1024, 4096, 16384, 65536, 262144];
    let thread_counts = [1, 2, 4, 8, 16];
    
    let mut results = Vec::new();
    
    for &size in sizes.iter() {
        for &threads in thread_counts.iter() {
            // テスト条件に合わせて操作数を調整
            let ops_per_thread = 1000000 / threads;
            
            // ストレステスト実行
            let stress_test = AllocatorStressTest::new(
                1024 * 1024 * 1024, // 1GBプール
                threads,
                ops_per_thread,
                AllocationPattern::Fixed(size),
                size,
                50, // 50%割り当て、50%解放
            );
            
            let start_time = time::current_time_ns();
            let stats = stress_test.run();
            let duration = time::current_time_ns() - start_time;
            
            // 結果を記録
            let throughput = ((threads * ops_per_thread) as f64 * 1_000_000_000.0) / duration as f64;
            results.push((size, threads, throughput));
            
            log::info!(
                "サイズ{}バイト x {}スレッド: スループット {:.2}操作/秒",
                size, threads, throughput
            );
        }
    }
    
    // 最高スループットを検証
    let max_throughput = results.iter().map(|&(_, _, t)| t).fold(0.0, f64::max);
    log::info!("最高スループット: {:.2}操作/秒", max_throughput);
    assert!(max_throughput > 100000.0, "スループットが不十分: {:.2}", max_throughput);
}

/// 長期安定性テスト
#[test]
#[ignore] // 通常のテスト実行では長時間かかるため無視
fn test_long_term_stability() {
    // 長時間実行テスト（約10分）
    const MEMORY_SIZE: usize = 512 * 1024 * 1024; // 512MB
    const THREAD_COUNT: usize = 4;
    const OPS_PER_THREAD: usize = 1000000; // 100万操作/スレッド
    
    let stress_test = AllocatorStressTest::new(
        MEMORY_SIZE,
        THREAD_COUNT,
        OPS_PER_THREAD,
        AllocationPattern::Realistic,
        1024 * 1024, // 最大1MB
        60,          // 60%割り当て、40%解放
    );
    
    // テスト実行
    let start_time = time::current_time_ns();
    let stats = stress_test.run();
    let duration = time::current_time_ns() - start_time;
    
    // 結果レポート
    let report = stress_test.generate_report(&stats, duration);
    log::info!("{}", report);
    
    // 検証
    let errors = stress_test.validation_errors.load(Ordering::Relaxed);
    assert_eq!(errors, 0, "長期実行中にメモリ整合性エラー: {}", errors);
    assert_eq!(stats.allocated_memory, 0, "長期実行後にメモリリーク: {}バイト", stats.allocated_memory);
} 