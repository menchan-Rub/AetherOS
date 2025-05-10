// PCIデバイスの設定空間へのレガシーポートI/Oアクセスを実装するモジュール
// このアクセス方式は古いPCIデバイス（PCIe以前）で使用されます

use crate::core::io::PortIo;
use crate::drivers::pci::address::PciAddress;
use crate::drivers::pci::config_access_util::PciConfigAccess;
use core::sync::atomic::{AtomicU32, Ordering};

/// CONFIG_ADDRESS ポートのアドレス (0xCF8)
const PCI_CONFIG_ADDRESS: u16 = 0xCF8;

/// CONFIG_DATA ポートのアドレス (0xCFC)
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// PCIポートI/Oアクセスを提供する構造体
pub struct PortIoAccess {
    /// 構成アドレスポート
    config_address: PortIo<u32>,
    /// 構成データポート
    config_data: PortIo<u32>,
    /// 現在の構成アドレス (キャッシュ用)
    current_address: AtomicU32,
}

impl PortIoAccess {
    /// 新しいPCIポートI/Oアクセスインスタンスを作成
    pub fn new() -> Self {
        Self {
            config_address: PortIo::new(PCI_CONFIG_ADDRESS),
            config_data: PortIo::new(PCI_CONFIG_DATA),
            current_address: AtomicU32::new(0),
        }
    }
    
    /// PCIポートI/Oアクセスが利用可能かを確認
    pub fn is_available() -> bool {
        // シンプルなチェック: CONFIG_ADDRESSに書き込み、読み戻して一致するか確認
        let mut access = Self::new();
        
        // テスト用のアドレス (バス0, デバイス0, 機能0, レジスタ0)
        let test_address = 0x80000000u32;
        
        // 書き込み
        access.config_address.write(test_address);
        
        // 読み戻し (マスクを適用)
        let readback = access.config_address.read() & 0x80FFFFFC;
        
        // 一致確認（使用されていないビットを無視）
        readback == test_address
    }
    
    /// PCI構成アドレスレジスタの値を生成
    fn make_address(&self, addr: PciAddress, offset: u16) -> u32 {
        // CONFIG_ADDRESS の形式:
        // 31      30-24    23-16   15-11   10-8    7-0
        // Enable  Reserved Bus     Device  Function Register
        
        // レガシーポートI/Oでは1つのセグメント（セグメント0）のみをサポート
        if addr.segment() != 0 {
            return 0; // 無効なセグメント
        }
        
        // オフセットは4バイト境界である必要がある
        let aligned_offset = (offset as u32) & 0xFC;
        
        // アドレスを構築
        0x80000000 | // イネーブルビット
        ((addr.bus() as u32) << 16) |
        ((addr.device() as u32) << 11) |
        ((addr.function() as u32) << 8) |
        aligned_offset
    }
    
    /// 指定されたアドレスに対してCONFIG_ADDRESSレジスタを設定
    fn set_address(&self, addr: PciAddress, offset: u16) {
        let address_value = self.make_address(addr, offset);
        let current = self.current_address.load(Ordering::Relaxed);
        
        // 現在のアドレスと異なる場合のみ更新（最適化）
        if current != address_value {
            self.config_address.write(address_value);
            self.current_address.store(address_value, Ordering::Relaxed);
        }
    }
}

// PciConfigAccessトレイトの実装
impl PciConfigAccess for PortIoAccess {
    fn read_u8(&self, addr: PciAddress, offset: u16) -> u8 {
        // セグメント0以外はサポートしない
        if addr.segment() != 0 {
            return 0xFF;
        }
        
        // アドレスを4バイト境界に合わせる
        let aligned_offset = offset & !0x3;
        
        // CONFIG_ADDRESSレジスタを設定
        self.set_address(addr, aligned_offset);
        
        // 32ビット値を読み取り
        let value = self.config_data.read();
        
        // 必要なバイトを抽出
        let shift = (offset & 0x3) * 8;
        ((value >> shift) & 0xFF) as u8
    }
    
    fn read_u16(&self, addr: PciAddress, offset: u16) -> u16 {
        // セグメント0以外はサポートしない
        if addr.segment() != 0 {
            return 0xFFFF;
        }
        
        // 2バイト境界チェック
        if offset & 0x1 != 0 {
            // アライメントされていない場合、1バイトずつ読み取る
            let low = self.read_u8(addr, offset);
            let high = self.read_u8(addr, offset + 1);
            return ((high as u16) << 8) | (low as u16);
        }
        
        // アドレスを4バイト境界に合わせる
        let aligned_offset = offset & !0x3;
        
        // CONFIG_ADDRESSレジスタを設定
        self.set_address(addr, aligned_offset);
        
        // 32ビット値を読み取り
        let value = self.config_data.read();
        
        // 必要な16ビットを抽出
        let shift = (offset & 0x2) * 8;
        ((value >> shift) & 0xFFFF) as u16
    }
    
    fn read_u32(&self, addr: PciAddress, offset: u16) -> u32 {
        // セグメント0以外はサポートしない
        if addr.segment() != 0 {
            return 0xFFFFFFFF;
        }
        
        // 4バイト境界チェック
        if offset & 0x3 != 0 {
            // アライメントされていない場合、2バイトずつ読み取る
            let low = self.read_u16(addr, offset);
            let high = self.read_u16(addr, offset + 2);
            return ((high as u32) << 16) | (low as u32);
        }
        
        // CONFIG_ADDRESSレジスタを設定
        self.set_address(addr, offset);
        
        // 32ビット値を読み取り
        self.config_data.read()
    }
    
    fn write_u8(&self, addr: PciAddress, offset: u16, value: u8) {
        // セグメント0以外はサポートしない
        if addr.segment() != 0 {
            return;
        }
        
        // アドレスを4バイト境界に合わせる
        let aligned_offset = offset & !0x3;
        
        // CONFIG_ADDRESSレジスタを設定
        self.set_address(addr, aligned_offset);
        
        // 現在の32ビット値を読み取り
        let mut data = self.config_data.read();
        
        // 書き込むバイトのビット位置を計算
        let shift = (offset & 0x3) * 8;
        let mask = !(0xFF << shift);
        
        // 対象バイトをクリアして新しい値を設定
        data = (data & mask) | ((value as u32) << shift);
        
        // 更新された値を書き込み
        self.config_data.write(data);
    }
    
    fn write_u16(&self, addr: PciAddress, offset: u16, value: u16) {
        // セグメント0以外はサポートしない
        if addr.segment() != 0 {
            return;
        }
        
        // 2バイト境界チェック
        if offset & 0x1 != 0 {
            // アライメントされていない場合、1バイトずつ書き込む
            self.write_u8(addr, offset, value as u8);
            self.write_u8(addr, offset + 1, (value >> 8) as u8);
            return;
        }
        
        // アドレスを4バイト境界に合わせる
        let aligned_offset = offset & !0x3;
        
        // CONFIG_ADDRESSレジスタを設定
        self.set_address(addr, aligned_offset);
        
        // 現在の32ビット値を読み取り
        let mut data = self.config_data.read();
        
        // 書き込む16ビットのビット位置を計算
        let shift = (offset & 0x2) * 8;
        let mask = !(0xFFFF << shift);
        
        // 対象16ビットをクリアして新しい値を設定
        data = (data & mask) | ((value as u32) << shift);
        
        // 更新された値を書き込み
        self.config_data.write(data);
    }
    
    fn write_u32(&self, addr: PciAddress, offset: u16, value: u32) {
        // セグメント0以外はサポートしない
        if addr.segment() != 0 {
            return;
        }
        
        // 4バイト境界チェック
        if offset & 0x3 != 0 {
            // アライメントされていない場合、2バイトずつ書き込む
            self.write_u16(addr, offset, value as u16);
            self.write_u16(addr, offset + 2, (value >> 16) as u16);
            return;
        }
        
        // CONFIG_ADDRESSレジスタを設定
        self.set_address(addr, offset);
        
        // 32ビット値を書き込み
        self.config_data.write(value);
    }
}

// 安全な実装のために必要なトレイト
unsafe impl Send for PortIoAccess {}
unsafe impl Sync for PortIoAccess {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_make_address() {
        let access = PortIoAccess::new();
        
        // バス0、デバイス0、機能0、オフセット0のテスト
        let addr1 = PciAddress::legacy(0, 0, 0);
        assert_eq!(access.make_address(addr1, 0), 0x80000000);
        
        // バス1、デバイス2、機能3、オフセット0x10のテスト
        let addr2 = PciAddress::legacy(1, 2, 3);
        assert_eq!(access.make_address(addr2, 0x10), 0x80010510);
        
        // 非整列オフセットのテスト（下位2ビットはクリアされるべき）
        assert_eq!(access.make_address(addr2, 0x13), 0x80010510);
    }
    
    // 実際のハードウェアに依存するテストは省略
} 