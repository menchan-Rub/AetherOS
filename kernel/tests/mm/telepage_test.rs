// AetherOS テレページングテスト
//
// テレページング機能の動作検証テスト

use alloc::sync::Arc;
use crate::core::memory::telepage::{
    global_telepage, init_telepage_manager, RemotePageId, RequestType, PageState
};
use crate::core::memory::mm::page::{PhysicalAddress, VirtualAddress, PAGE_SIZE};
use crate::core::network::{NetworkManager, mock::MockNetworkManager};
use crate::core::distributed::{ClusterManager, mock::MockClusterManager};
use crate::core::process::{current_process, Process, ProcessId};
use crate::time::get_current_time;

/// テレページング基本機能テスト
pub fn test_telepage_basic() -> Result<(), &'static str> {
    println!("テレページング基本機能テスト開始");
    
    // モックネットワークマネージャとクラスタマネージャを作成
    let network = Arc::new(MockNetworkManager::new());
    let cluster = Arc::new(MockClusterManager::new());
    
    // テレページマネージャを初期化
    init_telepage_manager(Arc::clone(&network) as Arc<dyn NetworkManager>, 
                          Arc::clone(&cluster) as Arc<dyn ClusterManager>);
    
    // グローバルインスタンスを取得
    let telepage = global_telepage();
    
    // モックページIDを作成
    let remote_page_id = RemotePageId {
        node_id: 2, // リモートノード
        process_id: 1000, // テスト用プロセスID
        virtual_address: 0x7FFF_0000_0000, // テスト用仮想アドレス
    };
    
    // ページ転送リクエストを作成
    let request = telepage.create_transfer_request(
        remote_page_id,
        RequestType::Read,
        50 // 標準優先度
    );
    
    // リクエストをキューに追加
    telepage.queue_transfer_request(request);
    
    // 統計情報の初期値を確認
    let before_faults = telepage.stats.remote_page_faults.load(core::sync::atomic::Ordering::Relaxed);
    
    // ページフォルトをシミュレート
    let result = crate::core::memory::telepage::handle_page_fault(
        remote_page_id.virtual_address,
        false // 読み取りアクセス
    );
    
    println!("ページフォルト結果: {:?}", result);
    
    // 統計情報が更新されたことを確認
    let after_faults = telepage.stats.remote_page_faults.load(core::sync::atomic::Ordering::Relaxed);
    assert!(after_faults > before_faults, "ページフォルトカウンタが更新されていません");
    
    // キャッシュされたページが取得できることを確認
    let cached = telepage.get_cached_page(remote_page_id);
    println!("キャッシュされたページ: {:?}", cached);
    
    // 予測エンジンのテスト
    telepage.prediction_engine.record_access(remote_page_id);
    
    // アクセスシーケンスをシミュレート
    for i in 1..10 {
        let page_id = RemotePageId {
            node_id: remote_page_id.node_id,
            process_id: remote_page_id.process_id,
            virtual_address: remote_page_id.virtual_address + (i * PAGE_SIZE as u64),
        };
        telepage.prediction_engine.record_access(page_id);
    }
    
    // 予測結果を取得
    let predicted = telepage.predict_related_pages(remote_page_id);
    println!("予測されたページ数: {}", predicted.len());
    
    // 圧縮機能のテスト
    let test_data = [0u8; PAGE_SIZE];
    if telepage.is_compression_available() {
        let compressed = telepage.compress_page_data(&test_data)?;
        println!("圧縮率: {:.2}%", (compressed.len() as f32 / PAGE_SIZE as f32) * 100.0);
        
        let decompressed = telepage.decompress_page_data(&compressed, PAGE_SIZE)?;
        assert_eq!(decompressed.len(), PAGE_SIZE, "解凍後のサイズが不正");
    }
    
    println!("テレページング基本機能テスト完了");
    Ok(())
}

/// テレページングパフォーマンステスト
pub fn test_telepage_performance() -> Result<(), &'static str> {
    println!("テレページングパフォーマンステスト開始");
    
    // グローバルインスタンスを取得
    let telepage = global_telepage();
    
    // パフォーマンステストのパラメータ
    const TEST_ITERATIONS: usize = 100;
    
    // 連続ページアクセスのシミュレーション
    let start_time = get_current_time().as_nanos();
    
    for i in 0..TEST_ITERATIONS {
        let page_id = RemotePageId {
            node_id: 2,
            process_id: 1000,
            virtual_address: 0x8000_0000_0000 + (i as u64 * PAGE_SIZE as u64),
        };
        
        // ページアクセスを記録
        telepage.prediction_engine.record_access(page_id);
        
        // 予測を実行
        let predicted = telepage.predict_related_pages(page_id);
        
        // プリフェッチをシミュレート
        for pred_page in predicted.iter().take(3) {
            telepage.queue_prefetch(*pred_page);
        }
    }
    
    let end_time = get_current_time().as_nanos();
    let elapsed_ns = end_time - start_time;
    
    println!("{}回の操作にかかった時間: {}ns (平均: {}ns/操作)",
             TEST_ITERATIONS, elapsed_ns, elapsed_ns / TEST_ITERATIONS as u64);
    
    // 予測精度の統計を表示
    let accuracy = telepage.prediction_engine.get_accuracy();
    println!("予測精度: {}%", accuracy);
    
    println!("テレページングパフォーマンステスト完了");
    Ok(())
}

/// テレページング分散連携テスト
pub fn test_telepage_distributed() -> Result<(), &'static str> {
    println!("テレページング分散連携テスト開始");
    
    // グローバルインスタンスを取得
    let telepage = global_telepage();
    
    // 複数ノード間のページ共有をシミュレート
    let shared_page_id = RemotePageId {
        node_id: 3,
        process_id: 2000,
        virtual_address: 0x9000_0000_0000,
    };
    
    // 共有リクエストを作成
    let request = telepage.create_transfer_request(
        shared_page_id,
        RequestType::Share,
        70 // 高め優先度
    );
    
    // リクエストをキューに追加
    telepage.queue_transfer_request(request);
    
    // 複数ノードからのアクセスをシミュレート
    for node_id in 1..5 {
        if node_id == shared_page_id.node_id {
            continue; // オーナーノードはスキップ
        }
        
        let page_id = RemotePageId {
            node_id: shared_page_id.node_id,
            process_id: shared_page_id.process_id,
            virtual_address: shared_page_id.virtual_address,
        };
        
        // 各ノードからのアクセスを記録
        telepage.prediction_engine.record_access(page_id);
    }
    
    // 現在の統計情報を表示
    println!("ページフォルト数: {}",
             telepage.stats.remote_page_faults.load(core::sync::atomic::Ordering::Relaxed));
    println!("転送ページ数: {}",
             telepage.stats.pages_transferred.load(core::sync::atomic::Ordering::Relaxed));
    println!("プリフェッチされたページ数: {}",
             telepage.stats.pages_prefetched.load(core::sync::atomic::Ordering::Relaxed));
    
    println!("テレページング分散連携テスト完了");
    Ok(())
}

/// テレページング全テストを実行
pub fn run_all_tests() -> Result<(), &'static str> {
    test_telepage_basic()?;
    test_telepage_performance()?;
    test_telepage_distributed()?;
    
    Ok(())
} 