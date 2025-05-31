// AetherOS ネットワーク統計情報モジュール
//
// このモジュールはネットワーク通信の詳細な統計情報を収集・分析するための
// 機能を提供します。

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::collections::BTreeMap;
use crate::core::sync::Mutex;
use crate::core::memory::telepage::NodeId;
use crate::core::network::protocol::TransportProtocol;

/// トランスポート層全体の統計情報
#[derive(Debug, Default)]
pub struct TransportStats {
    /// 送信バイト数
    pub bytes_sent: AtomicU64,
    /// 受信バイト数
    pub bytes_received: AtomicU64,
    /// 送信メッセージ数
    pub messages_sent: AtomicU64,
    /// 受信メッセージ数
    pub messages_received: AtomicU64,
    /// 接続確立数
    pub connections_established: AtomicU64,
    /// 接続失敗数
    pub connection_failures: AtomicU64,
    /// 転送エラー数
    pub transfer_errors: AtomicU64,
    /// タイムアウト数
    pub timeouts: AtomicU64,
    /// 再送回数
    pub retransmissions: AtomicU64,
    /// 平均レイテンシ（ナノ秒）
    pub avg_latency_ns: AtomicU64,
    /// 最小レイテンシ（ナノ秒）
    pub min_latency_ns: AtomicU64,
    /// 最大レイテンシ（ナノ秒）
    pub max_latency_ns: AtomicU64,
    /// ノード別統計情報
    pub node_stats: Mutex<BTreeMap<NodeId, NodeStats>>,
    /// プロトコル別統計情報
    pub protocol_stats: Mutex<BTreeMap<TransportProtocol, ProtocolStats>>,
}

/// ノード別の統計情報
#[derive(Debug, Default, Clone)]
pub struct NodeStats {
    /// 送信バイト数
    pub bytes_sent: u64,
    /// 受信バイト数
    pub bytes_received: u64,
    /// 送信メッセージ数
    pub messages_sent: u64,
    /// 受信メッセージ数
    pub messages_received: u64,
    /// 再送回数
    pub retransmissions: u64,
    /// パケットロス率（0.0-1.0）
    pub packet_loss_rate: f64,
    /// 平均レイテンシ（ナノ秒）
    pub avg_latency_ns: u64,
    /// 最後の活動時刻
    pub last_activity: u64,
    /// 活動セッション数
    pub active_sessions: usize,
}

/// プロトコル別の統計情報
#[derive(Debug, Default, Clone)]
pub struct ProtocolStats {
    /// 送信バイト数
    pub bytes_sent: u64,
    /// 受信バイト数
    pub bytes_received: u64,
    /// 送信メッセージ数
    pub messages_sent: u64,
    /// 受信メッセージ数
    pub messages_received: u64,
    /// エラー数
    pub errors: u64,
    /// 平均レイテンシ（ナノ秒）
    pub avg_latency_ns: u64,
}

/// 接続単位の統計情報
#[derive(Debug, Default, Clone)]
pub struct ConnectionStats {
    /// 送信バイト数
    pub bytes_sent: u64,
    /// 受信バイト数
    pub bytes_received: u64,
    /// 送信メッセージ数
    pub messages_sent: u64,
    /// 受信メッセージ数
    pub messages_received: u64,
    /// 再送回数
    pub retransmissions: u64,
    /// 最小レイテンシ（ナノ秒）
    pub min_latency_ns: u64,
    /// 最大レイテンシ（ナノ秒）
    pub max_latency_ns: u64,
    /// 平均レイテンシ（ナノ秒）
    pub avg_latency_ns: u64,
    /// バッファ使用量
    pub buffer_usage: usize,
    /// 前回の更新時刻
    pub last_updated: u64,
}

impl TransportStats {
    /// 新しい統計情報インスタンスを作成
    pub fn new() -> Self {
        Self::default()
    }
    
    /// バイト送信を記録
    pub fn record_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
    }
    
    /// バイト受信を記録
    pub fn record_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.messages_received.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 接続成功を記録
    pub fn record_connection_established(&self) {
        self.connections_established.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 接続失敗を記録
    pub fn record_connection_failure(&self) {
        self.connection_failures.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 転送エラーを記録
    pub fn record_transfer_error(&self) {
        self.transfer_errors.fetch_add(1, Ordering::Relaxed);
    }
    
    /// タイムアウトを記録
    pub fn record_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }
    
    /// 再送を記録
    pub fn record_retransmission(&self) {
        self.retransmissions.fetch_add(1, Ordering::Relaxed);
    }
    
    /// レイテンシを記録
    pub fn record_latency(&self, latency_ns: u64) {
        // 最小レイテンシを更新
        let current_min = self.min_latency_ns.load(Ordering::Relaxed);
        if current_min == 0 || latency_ns < current_min {
            self.min_latency_ns.store(latency_ns, Ordering::Relaxed);
        }
        
        // 最大レイテンシを更新
        let current_max = self.max_latency_ns.load(Ordering::Relaxed);
        if latency_ns > current_max {
            self.max_latency_ns.store(latency_ns, Ordering::Relaxed);
        }
        
        // 平均レイテンシを更新（指数移動平均）
        let current_avg = self.avg_latency_ns.load(Ordering::Relaxed);
        if current_avg == 0 {
            self.avg_latency_ns.store(latency_ns, Ordering::Relaxed);
        } else {
            // 新しい値の重みを0.1とした指数移動平均
            let new_avg = (current_avg * 9 + latency_ns) / 10;
            self.avg_latency_ns.store(new_avg, Ordering::Relaxed);
        }
    }
    
    /// ノード別統計情報を更新
    pub fn update_node_stats(&self, node: NodeId, update_fn: impl FnOnce(&mut NodeStats)) {
        let mut node_stats_map = self.node_stats.lock().expect("ノード統計ロック失敗");
        
        let node_stats = node_stats_map.entry(node).or_default();
        update_fn(node_stats);
    }
    
    /// プロトコル別統計情報を更新
    pub fn update_protocol_stats(&self, protocol: TransportProtocol, update_fn: impl FnOnce(&mut ProtocolStats)) {
        let mut protocol_stats_map = self.protocol_stats.lock().expect("プロトコル統計ロック失敗");
        
        let protocol_stats = protocol_stats_map.entry(protocol).or_default();
        update_fn(protocol_stats);
    }
    
    /// 全統計情報をリセット
    pub fn reset(&self) {
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.messages_sent.store(0, Ordering::Relaxed);
        self.messages_received.store(0, Ordering::Relaxed);
        self.connections_established.store(0, Ordering::Relaxed);
        self.connection_failures.store(0, Ordering::Relaxed);
        self.transfer_errors.store(0, Ordering::Relaxed);
        self.timeouts.store(0, Ordering::Relaxed);
        self.retransmissions.store(0, Ordering::Relaxed);
        self.avg_latency_ns.store(0, Ordering::Relaxed);
        self.min_latency_ns.store(0, Ordering::Relaxed);
        self.max_latency_ns.store(0, Ordering::Relaxed);
        
        // マップをクリア
        let mut node_stats_map = self.node_stats.lock().expect("ノード統計ロック失敗");
        node_stats_map.clear();
        
        let mut protocol_stats_map = self.protocol_stats.lock().expect("プロトコル統計ロック失敗");
        protocol_stats_map.clear();
    }
    
    /// 統計情報の概要を文字列で取得
    pub fn summary(&self) -> alloc::string::String {
        use alloc::string::String;
        use alloc::format;
        
        let bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        let bytes_received = self.bytes_received.load(Ordering::Relaxed);
        let messages_sent = self.messages_sent.load(Ordering::Relaxed);
        let messages_received = self.messages_received.load(Ordering::Relaxed);
        let avg_latency = self.avg_latency_ns.load(Ordering::Relaxed);
        
        format!(
            "ネットワーク統計: 送信={} MiB ({} メッセージ), 受信={} MiB ({} メッセージ), レイテンシ={} μs",
            bytes_sent / (1024 * 1024),
            messages_sent,
            bytes_received / (1024 * 1024),
            messages_received,
            avg_latency / 1000
        )
    }
}

impl ConnectionStats {
    /// 新しい接続統計情報を作成
    pub fn new() -> Self {
        let now = crate::core::time::current_timestamp();
        Self {
            last_updated: now,
            ..Default::default()
        }
    }
    
    /// 送信を記録
    pub fn record_send(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.messages_sent += 1;
        self.last_updated = crate::core::time::current_timestamp();
    }
    
    /// 受信を記録
    pub fn record_receive(&mut self, bytes: u64) {
        self.bytes_received += bytes;
        self.messages_received += 1;
        self.last_updated = crate::core::time::current_timestamp();
    }
    
    /// 再送を記録
    pub fn record_retransmission(&mut self) {
        self.retransmissions += 1;
        self.last_updated = crate::core::time::current_timestamp();
    }
    
    /// レイテンシを記録
    pub fn record_latency(&mut self, latency_ns: u64) {
        // 最小レイテンシを更新
        if self.min_latency_ns == 0 || latency_ns < self.min_latency_ns {
            self.min_latency_ns = latency_ns;
        }
        
        // 最大レイテンシを更新
        if latency_ns > self.max_latency_ns {
            self.max_latency_ns = latency_ns;
        }
        
        // 平均レイテンシを更新（指数移動平均）
        if self.avg_latency_ns == 0 {
            self.avg_latency_ns = latency_ns;
        } else {
            // 新しい値の重みを0.1とした指数移動平均
            self.avg_latency_ns = (self.avg_latency_ns * 9 + latency_ns) / 10;
        }
        
        self.last_updated = crate::core::time::current_timestamp();
    }
    
    /// バッファ使用量を更新
    pub fn update_buffer_usage(&mut self, usage: usize) {
        self.buffer_usage = usage;
        self.last_updated = crate::core::time::current_timestamp();
    }
} 