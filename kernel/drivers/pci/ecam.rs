// PCIの拡張設定アクセスメカニズム（ECAM）を実装したモジュール
// PCIeデバイスの設定空間へのメモリマップドアクセスを提供します

use crate::core::memory::mmio::{MemoryMappedIo, MmioAccess};
use crate::drivers::pci::address::PciAddress;
use crate::drivers::pci::config_access_util::PciConfigAccess;
use core::sync::atomic::{AtomicPtr, Ordering};
use crate::platform::acpi::mcfg::{McfgEntry, McfgTable};
use alloc::vec::Vec;

/// ECaMベースのCFGアクセス構造体
pub struct EcamAccess {
    /// ECaMマッピングのリスト
    ecam_regions: Vec<EcamRegion>,
}

/// 単一のECaMマッピング領域
struct EcamRegion {
    /// マッピングのベースアドレス
    base_address: *mut u8,
    /// 開始セグメント番号
    start_segment: u16,
    /// 終了セグメント番号
    end_segment: u16,
    /// 開始バス番号
    start_bus: u8,
    /// 終了バス番号
    end_bus: u8,
}

// ECAMアクセスの基本構造定義
impl EcamAccess {
    /// 新しいECaMアクセスインスタンスを作成（手動設定）
    pub fn new(ecam_regions: Vec<EcamRegion>) -> Self {
        Self { ecam_regions }
    }
    
    /// ACPIのMCFGテーブルからECaMを検出
    pub fn probe() -> Option<Self> {
        // MCFGテーブルを取得
        if let Some(mcfg) = McfgTable::get() {
            let mut regions = Vec::new();
            
            // 各MCFGエントリをEcamRegionに変換
            for entry in mcfg.entries() {
                if let Ok(region) = Self::map_mcfg_entry(entry) {
                    regions.push(region);
                }
            }
            
            if regions.is_empty() {
                None
            } else {
                Some(Self { ecam_regions: regions })
            }
        } else {
            None
        }
    }
    
    /// MCFGエントリをEcamRegionにマッピング
    fn map_mcfg_entry(entry: &McfgEntry) -> Result<EcamRegion, &'static str> {
        // メモリマップドI/Oを作成
        let mmio = MemoryMappedIo::new(
            entry.base_address,
            Self::calculate_region_size(entry.start_bus, entry.end_bus),
            false, // キャッシュなし
        );
        
        if let Some(base_ptr) = mmio.map() {
            Ok(EcamRegion {
                base_address: base_ptr as *mut u8,
                start_segment: entry.segment_group,
                end_segment: entry.segment_group,
                start_bus: entry.start_bus,
                end_bus: entry.end_bus,
            })
        } else {
            Err("ECaMリージョンのマッピングに失敗しました")
        }
    }
    
    /// リージョンサイズを計算 (バス数 × デバイス数 × ファンクション数 × 設定空間サイズ)
    fn calculate_region_size(start_bus: u8, end_bus: u8) -> usize {
        let bus_count = (end_bus - start_bus + 1) as usize;
        bus_count * 32 * 8 * 4096 // 32デバイス、8ファンクション、4KiBの設定空間
    }
    
    /// 指定されたPCIアドレスに対応するリージョンとオフセットを取得
    fn get_region_and_offset(&self, addr: PciAddress) -> Option<(*mut u8, usize)> {
        for region in &self.ecam_regions {
            if addr.segment() >= region.start_segment && addr.segment() <= region.end_segment &&
               addr.bus() >= region.start_bus && addr.bus() <= region.end_bus {
                // オフセットを計算: (bus - start_bus) * devices_per_bus * funcs_per_device * config_size +
                //                  device * funcs_per_device * config_size +
                //                  function * config_size
                let bus_offset = (addr.bus() - region.start_bus) as usize * 32 * 8 * 4096;
                let device_offset = addr.device() as usize * 8 * 4096;
                let function_offset = addr.function() as usize * 4096;
                let offset = bus_offset + device_offset + function_offset;
                
                return Some((region.base_address, offset));
            }
        }
        
        None
    }
}

// PciConfigAccessトレイトの実装
impl PciConfigAccess for EcamAccess {
    /// 1バイト読み取り
    fn read_u8(&self, addr: PciAddress, offset: u16) -> u8 {
        if let Some((base, base_offset)) = self.get_region_and_offset(addr) {
            let ptr = unsafe { base.add(base_offset + offset as usize) };
            unsafe { core::ptr::read_volatile(ptr) }
        } else {
            0xFF // 無効な値
        }
    }
    
    /// 2バイト読み取り
    fn read_u16(&self, addr: PciAddress, offset: u16) -> u16 {
        if offset & 1 != 0 {
            // アラインメントチェック
            let low = self.read_u8(addr, offset);
            let high = self.read_u8(addr, offset + 1);
            return (high as u16) << 8 | (low as u16);
        }
        
        if let Some((base, base_offset)) = self.get_region_and_offset(addr) {
            let ptr = unsafe { base.add(base_offset + offset as usize) as *const u16 };
            unsafe { core::ptr::read_volatile(ptr) }
        } else {
            0xFFFF // 無効な値
        }
    }
    
    /// 4バイト読み取り
    fn read_u32(&self, addr: PciAddress, offset: u16) -> u32 {
        if offset & 3 != 0 {
            // アラインメントチェック
            let word_low = self.read_u16(addr, offset);
            let word_high = self.read_u16(addr, offset + 2);
            return (word_high as u32) << 16 | (word_low as u32);
        }
        
        if let Some((base, base_offset)) = self.get_region_and_offset(addr) {
            let ptr = unsafe { base.add(base_offset + offset as usize) as *const u32 };
            unsafe { core::ptr::read_volatile(ptr) }
        } else {
            0xFFFFFFFF // 無効な値
        }
    }
    
    /// 1バイト書き込み
    fn write_u8(&self, addr: PciAddress, offset: u16, value: u8) {
        if let Some((base, base_offset)) = self.get_region_and_offset(addr) {
            let ptr = unsafe { base.add(base_offset + offset as usize) };
            unsafe { core::ptr::write_volatile(ptr, value) };
        }
    }
    
    /// 2バイト書き込み
    fn write_u16(&self, addr: PciAddress, offset: u16, value: u16) {
        if offset & 1 != 0 {
            // アラインメントチェック
            self.write_u8(addr, offset, value as u8);
            self.write_u8(addr, offset + 1, (value >> 8) as u8);
            return;
        }
        
        if let Some((base, base_offset)) = self.get_region_and_offset(addr) {
            let ptr = unsafe { base.add(base_offset + offset as usize) as *mut u16 };
            unsafe { core::ptr::write_volatile(ptr, value) };
        }
    }
    
    /// 4バイト書き込み
    fn write_u32(&self, addr: PciAddress, offset: u16, value: u32) {
        if offset & 3 != 0 {
            // アラインメントチェック
            self.write_u16(addr, offset, value as u16);
            self.write_u16(addr, offset + 2, (value >> 16) as u16);
            return;
        }
        
        if let Some((base, base_offset)) = self.get_region_and_offset(addr) {
            let ptr = unsafe { base.add(base_offset + offset as usize) as *mut u32 };
            unsafe { core::ptr::write_volatile(ptr, value) };
        }
    }
}

// 安全な実装のために必要なトレイト
unsafe impl Send for EcamAccess {}
unsafe impl Sync for EcamAccess {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_calculate_region_size() {
        // 1バス分のサイズを計算 (32デバイス × 8ファンクション × 4096バイト)
        assert_eq!(EcamAccess::calculate_region_size(0, 0), 1_048_576);
        
        // 2バス分のサイズを計算 (2 × 32デバイス × 8ファンクション × 4096バイト)
        assert_eq!(EcamAccess::calculate_region_size(0, 1), 2_097_152);
    }
    
    // その他のテストはハードウェアに依存するため省略
} 