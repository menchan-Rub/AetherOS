// CPU アフィニティサポート
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::arch;

const MAX_CPUS: usize = 256;

// CPUアフィニティビットマスク
pub struct CpuAffinity {
    // 各CPUへの割り当て。trueの場合、そのCPUで実行可能
    cpu_mask: [bool; MAX_CPUS],
    count: usize,
}

impl CpuAffinity {
    pub fn new() -> Self {
        let mut cpu_mask = [false; MAX_CPUS];
        let cpu_count = arch::cpu::get_core_count();
        
        // デフォルトでは全CPUで実行可能
        for i in 0..cpu_count {
            cpu_mask[i] = true;
        }
        
        Self {
            cpu_mask,
            count: cpu_count,
        }
    }
    
    // 特定のCPUに割り当て
    pub fn set(&mut self, cpu_id: usize) {
        if cpu_id < MAX_CPUS {
            self.cpu_mask[cpu_id] = true;
        }
    }
    
    // 特定のCPUからの割り当てを解除
    pub fn clear(&mut self, cpu_id: usize) {
        if cpu_id < MAX_CPUS {
            self.cpu_mask[cpu_id] = false;
        }
    }
    
    // すべてのCPUに割り当て
    pub fn set_all(&mut self) {
        let cpu_count = arch::cpu::get_core_count();
        for i in 0..cpu_count {
            self.cpu_mask[i] = true;
        }
    }
    
    // すべてのCPUからの割り当てを解除
    pub fn clear_all(&mut self) {
        for i in 0..MAX_CPUS {
            self.cpu_mask[i] = false;
        }
    }
    
    // 指定したCPUで実行可能かどうかを確認
    pub fn is_allowed(&self, cpu_id: usize) -> bool {
        if cpu_id >= MAX_CPUS {
            return false;
        }
        self.cpu_mask[cpu_id]
    }
    
    // 実行可能なCPUのリストを取得
    pub fn get_allowed_cpus(&self) -> Vec<usize> {
        let mut allowed = Vec::new();
        
        for i in 0..MAX_CPUS {
            if self.cpu_mask[i] {
                allowed.push(i);
            }
        }
        
        allowed
    }
    
    // 実行可能なCPU数を取得
    pub fn allowed_count(&self) -> usize {
        self.cpu_mask.iter().filter(|&&allowed| allowed).count()
    }
}

// NUMAノード情報
pub struct NUMANode {
    node_id: usize,
    cpu_start: usize,
    cpu_count: usize,
    memory_start: usize,
    memory_size: usize,
}

impl NUMANode {
    pub fn new(node_id: usize, cpu_start: usize, cpu_count: usize, 
               memory_start: usize, memory_size: usize) -> Self {
        Self {
            node_id,
            cpu_start,
            cpu_count,
            memory_start,
            memory_size,
        }
    }
    
    pub fn get_id(&self) -> usize {
        self.node_id
    }
    
    pub fn get_cpu_range(&self) -> (usize, usize) {
        (self.cpu_start, self.cpu_start + self.cpu_count)
    }
    
    pub fn get_memory_range(&self) -> (usize, usize) {
        (self.memory_start, self.memory_start + self.memory_size)
    }
    
    pub fn contains_cpu(&self, cpu_id: usize) -> bool {
        cpu_id >= self.cpu_start && cpu_id < (self.cpu_start + self.cpu_count)
    }
}

// NUMAノードを検出・管理
static mut NUMA_NODES: Option<Vec<NUMANode>> = None;
static NUMA_INITIALIZED: AtomicUsize = AtomicUsize::new(0);

pub fn init_numa() {
    if NUMA_INITIALIZED.load(Ordering::SeqCst) != 0 {
        return;
    }
    
    // NUMAノードの検出（実装はアーキテクチャに依存）
    // ここでは簡単のため、単一のNUMAノードを作成
    let cpu_count = arch::cpu::get_core_count();
    
    let node = NUMANode::new(
        0,                  // ノードID
        0,                  // CPU開始番号
        cpu_count,          // CPU数
        0,                  // メモリ開始アドレス
        0xFFFFFFFF,         // メモリサイズ（実際には正確な値を取得する）
    );
    
    unsafe {
        let mut nodes = Vec::new();
        nodes.push(node);
        NUMA_NODES = Some(nodes);
    }
    
    NUMA_INITIALIZED.store(1, Ordering::SeqCst);
}

pub fn get_numa_node(node_id: usize) -> Option<&'static NUMANode> {
    if NUMA_INITIALIZED.load(Ordering::SeqCst) == 0 {
        init_numa();
    }
    
    unsafe {
        NUMA_NODES.as_ref()?.iter().find(|node| node.get_id() == node_id)
    }
}

pub fn get_numa_node_for_cpu(cpu_id: usize) -> Option<&'static NUMANode> {
    if NUMA_INITIALIZED.load(Ordering::SeqCst) == 0 {
        init_numa();
    }
    
    unsafe {
        NUMA_NODES.as_ref()?.iter().find(|node| node.contains_cpu(cpu_id))
    }
}

// スレッドに最適なNUMAノードを特定
pub fn optimize_affinity(affinity: &mut CpuAffinity, memory_address: usize) {
    if NUMA_INITIALIZED.load(Ordering::SeqCst) == 0 {
        init_numa();
    }
    
    // メモリアドレスを含むNUMAノードを探す
    let target_node = unsafe {
        if let Some(nodes) = NUMA_NODES.as_ref() {
            nodes.iter().find(|node| {
                let (start, end) = node.get_memory_range();
                memory_address >= start && memory_address < end
            })
        } else {
            None
        }
    };
    
    // 対象のノードが見つかれば、そのCPUだけに限定
    if let Some(node) = target_node {
        affinity.clear_all();
        
        let (cpu_start, cpu_end) = node.get_cpu_range();
        for cpu_id in cpu_start..cpu_end {
            affinity.set(cpu_id);
        }
    }
} 