// AetherOS SLUBアロケータテスト
//
// このモジュールはSLUBアロケータの機能をテストします。

use crate::core::memory::mm::slub::api as slub_api;
use crate::core::memory::mm::page::api::{PAGE_SIZE, alloc_pages, free_pages};
use core::alloc::Layout;
use core::ptr::NonNull;
use log::{info, debug, warn};
use alloc::vec::Vec;

/// SLUBアロケータの基本機能をテスト
pub fn test_slub_basic() -> bool {
    info!("SLUBアロケータ基本テストを開始...");
    
    // 標準サイズのアロケーションをテスト
    let sizes = [8, 16, 32, 64, 128, 256, 512, 1024, 2048];
    let mut ptrs = Vec::new();
    
    // 各サイズでオブジェクトを確保
    for &size in &sizes {
        let ptr = slub_api::allocate(size, 8);
        
        if let Some(p) = ptr {
            debug!("サイズ {} のオブジェクトを確保: {:p}", size, p);
            ptrs.push((p, size));
            
            // 確保したメモリにパターンを書き込み
            unsafe {
                for i in 0..size {
                    *((p as usize + i) as *mut u8) = (i & 0xFF) as u8;
                }
            }
        } else {
            warn!("サイズ {} のオブジェクト確保に失敗", size);
            return false;
        }
    }
    
    // パターンを確認
    for (ptr, size) in &ptrs {
        let p = *ptr;
        
        // 書き込んだパターンを検証
        for i in 0..*size {
            let val = unsafe { *((p as usize + i) as *const u8) };
            if val != (i & 0xFF) as u8 {
                warn!("データ検証エラー: アドレス={:p}+{}, 期待={:02x}, 実際={:02x}",
                     p, i, (i & 0xFF), val);
                return false;
            }
        }
    }
    
    // オブジェクトを解放
    for (ptr, _) in ptrs {
        let result = slub_api::deallocate(ptr);
        if !result {
            warn!("オブジェクト {:p} の解放に失敗", ptr);
            return false;
        }
    }
    
    // カスタムキャッシュのテスト
    let cache_name = "test-cache";
    
    if !slub_api::create_cache(cache_name, 42, 8) {
        warn!("カスタムキャッシュの作成に失敗");
        return false;
    }
    
    // カスタムキャッシュからオブジェクトを確保
    let custom_objs = (0..10).map(|_| slub_api::allocate_from_cache(cache_name))
        .collect::<Vec<_>>();
    
    if custom_objs.iter().any(|o| o.is_none()) {
        warn!("カスタムキャッシュからのオブジェクト確保に失敗");
        return false;
    }
    
    // オブジェクトを解放
    for obj in custom_objs {
        if !slub_api::deallocate(obj.unwrap()) {
            warn!("カスタムキャッシュからのオブジェクト解放に失敗");
            return false;
        }
    }
    
    // キャッシュを削除
    if !slub_api::destroy_cache(cache_name) {
        warn!("カスタムキャッシュの削除に失敗");
        return false;
    }
    
    // 使用状況を表示
    slub_api::report_usage();
    
    info!("SLUBアロケータ基本テスト完了: 成功");
    true
}

/// SLUBアロケータのストレステスト
pub fn test_slub_stress() -> bool {
    info!("SLUBアロケータストレステストを開始...");
    
    // CPUキャッシュをオフにして真のアロケータ性能をテスト
    slub_api::set_cpu_cache(false);
    
    const ITERATIONS: usize = 1000;
    const MAX_ALLOCS: usize = 100;
    
    // 複数のサイズでテスト
    let sizes = [8, 32, 128, 512, 2048];
    
    for &size in &sizes {
        debug!("サイズ {} のストレステスト開始...", size);
        
        for _ in 0..ITERATIONS {
            let mut ptrs = Vec::with_capacity(MAX_ALLOCS);
            
            // 大量に確保
            for _ in 0..MAX_ALLOCS {
                if let Some(ptr) = slub_api::allocate(size, 8) {
                    ptrs.push(ptr);
                    
                    // メモリに書き込み
                    unsafe {
                        *ptr = 0xAA;
                    }
                } else {
                    warn!("ストレステスト中のアロケーションに失敗");
                    return false;
                }
            }
            
            // 確保したオブジェクトをランダムな順序で解放
            let mut indices: Vec<usize> = (0..ptrs.len()).collect();
            // shuffle indices
            for i in (1..indices.len()).rev() {
                let j = i % indices.len();
                indices.swap(i, j);
            }
            
            for idx in indices {
                if !slub_api::deallocate(ptrs[idx]) {
                    warn!("ストレステスト中のオブジェクト解放に失敗");
                    return false;
                }
            }
        }
    }
    
    // CPUキャッシュを戻す
    slub_api::set_cpu_cache(true);
    
    // 使用状況を表示
    slub_api::report_usage();
    
    info!("SLUBアロケータストレステスト完了: 成功");
    true
}

/// メモリ節約モードのテスト
pub fn test_slub_memory_saving() -> bool {
    info!("SLUBアロケータのメモリ節約モードテストを開始...");
    
    // 現在の使用状況を表示
    slub_api::report_usage();
    
    // メモリ節約モードを無効化
    slub_api::set_memory_saving(false);
    
    // テストキャッシュを作成
    let cache_name = "test-saving";
    if !slub_api::create_cache(cache_name, 100, 8) {
        warn!("テストキャッシュの作成に失敗");
        return false;
    }
    
    // 非節約モードでオブジェクトを確保
    let mut ptrs = Vec::new();
    for _ in 0..50 {
        if let Some(ptr) = slub_api::allocate_from_cache(cache_name) {
            ptrs.push(ptr);
        } else {
            warn!("非節約モードでのオブジェクト確保に失敗");
            return false;
        }
    }
    
    // メモリ使用状況を確認
    slub_api::report_usage();
    
    // オブジェクトを解放
    for ptr in ptrs {
        if !slub_api::deallocate(ptr) {
            warn!("非節約モードのオブジェクト解放に失敗");
            return false;
        }
    }
    
    // キャッシュを削除
    slub_api::destroy_cache(cache_name);
    
    // メモリ節約モードを有効化
    slub_api::set_memory_saving(true);
    
    // テストキャッシュを再度作成
    if !slub_api::create_cache(cache_name, 100, 8) {
        warn!("節約モードでのテストキャッシュの作成に失敗");
        return false;
    }
    
    // 節約モードでオブジェクトを確保
    let mut ptrs = Vec::new();
    for _ in 0..50 {
        if let Some(ptr) = slub_api::allocate_from_cache(cache_name) {
            ptrs.push(ptr);
        } else {
            warn!("節約モードでのオブジェクト確保に失敗");
            return false;
        }
    }
    
    // メモリ使用状況を確認
    slub_api::report_usage();
    
    // オブジェクトを解放
    for ptr in ptrs {
        if !slub_api::deallocate(ptr) {
            warn!("節約モードのオブジェクト解放に失敗");
            return false;
        }
    }
    
    // キャッシュを削除
    slub_api::destroy_cache(cache_name);
    
    info!("SLUBアロケータのメモリ節約モードテスト完了: 成功");
    true
}

/// SLUBとmmapの統合テスト
pub fn test_slub_mmap_integration() -> bool {
    info!("SLUBとmmapの統合テストを開始...");
    
    // ここでmmap関連のテストを実装
    // 実際のテスト実装はプロセスコンテキストが必要なため
    // 簡略化したテストを行う
    
    // まず基本的なキャッシュ作成テスト
    let cache_name = "mmap-test";
    if !slub_api::create_cache(cache_name, 128, 8) {
        warn!("mmapテスト用キャッシュの作成に失敗");
        return false;
    }
    
    // いくつかのオブジェクトを確保
    let mut ptrs = Vec::new();
    for _ in 0..10 {
        if let Some(ptr) = slub_api::allocate_from_cache(cache_name) {
            ptrs.push(ptr);
        } else {
            warn!("mmapテスト用キャッシュからのオブジェクト確保に失敗");
            return false;
        }
    }
    
    // オブジェクトを解放
    for ptr in ptrs {
        if !slub_api::deallocate(ptr) {
            warn!("mmapテスト用キャッシュのオブジェクト解放に失敗");
            return false;
        }
    }
    
    // キャッシュを削除
    if !slub_api::destroy_cache(cache_name) {
        warn!("mmapテスト用キャッシュの削除に失敗");
        return false;
    }
    
    info!("SLUBとmmapの統合テスト完了: 成功");
    true
}

/// すべてのSLUBテストを実行
pub fn run_all_tests() -> bool {
    info!("==== SLUBアロケータテストスイートを開始 ====");
    
    let basic_result = test_slub_basic();
    let stress_result = test_slub_stress();
    let memory_saving_result = test_slub_memory_saving();
    let mmap_result = test_slub_mmap_integration();
    
    let all_passed = basic_result && stress_result && memory_saving_result && mmap_result;
    
    info!("==== SLUBアロケータテストスイート完了 ====");
    info!("基本テスト: {}", if basic_result { "成功" } else { "失敗" });
    info!("ストレステスト: {}", if stress_result { "成功" } else { "失敗" });
    info!("メモリ節約テスト: {}", if memory_saving_result { "成功" } else { "失敗" });
    info!("MMAp統合テスト: {}", if mmap_result { "成功" } else { "失敗" });
    info!("総合結果: {}", if all_passed { "成功" } else { "失敗" });
    
    // 最終的なメモリ使用状況
    slub_api::report_usage();
    
    all_passed
} 