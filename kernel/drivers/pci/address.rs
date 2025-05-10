// PCIアドレスモジュール
//
// PCIデバイスを一意に識別するためのアドレス構造体を定義します。

use core::fmt;
use core::hash::{Hash, Hasher};

/// PCIデバイスアドレス
///
/// PCIデバイスを一意に識別するためのアドレス構造体です。
/// PCIe仕様に基づき、セグメント、バス、デバイス、ファンクションの
/// 4つの要素で構成されます。
#[derive(Debug, Clone, Copy)]
pub struct PciAddress {
    /// PCIセグメントグループ番号（PCIeでの拡張）
    pub segment: u16,
    /// バス番号（0-255）
    pub bus: u8,
    /// デバイス番号（0-31）
    pub device: u8,
    /// ファンクション番号（0-7）
    pub function: u8,
}

impl PciAddress {
    /// 新しいPCIアドレスを作成
    pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        Self {
            segment,
            bus,
            device,
            function,
        }
    }

    /// レガシーPCIアドレスを作成（セグメント0）
    pub const fn legacy(bus: u8, device: u8, function: u8) -> Self {
        Self::new(0, bus, device, function)
    }

    /// 無効なPCIアドレス（存在しないデバイス）
    pub const INVALID: Self = Self {
        segment: 0xFFFF,
        bus: 0xFF,
        device: 0xFF,
        function: 0xFF,
    };

    /// このアドレスが有効かどうかを確認
    pub fn is_valid(&self) -> bool {
        self.device <= 31 && self.function <= 7
    }

    /// 一意のIDを生成
    pub fn to_u64(&self) -> u64 {
        let mut id: u64 = 0;
        id |= (self.segment as u64) << 48;
        id |= (self.bus as u64) << 32;
        id |= (self.device as u64) << 16;
        id |= self.function as u64;
        id
    }

    /// 同じバス内の次のデバイスアドレスを取得
    pub fn next_device(&self) -> Option<Self> {
        if self.device >= 31 {
            None
        } else {
            Some(Self {
                segment: self.segment,
                bus: self.bus,
                device: self.device + 1,
                function: 0,
            })
        }
    }

    /// 同じデバイス内の次のファンクションアドレスを取得
    pub fn next_function(&self) -> Option<Self> {
        if self.function >= 7 {
            None
        } else {
            Some(Self {
                segment: self.segment,
                bus: self.bus,
                device: self.device,
                function: self.function + 1,
            })
        }
    }

    /// 同じセグメント内の次のバスアドレスを取得
    pub fn next_bus(&self) -> Option<Self> {
        if self.bus == 0xFF {
            None
        } else {
            Some(Self {
                segment: self.segment,
                bus: self.bus + 1,
                device: 0,
                function: 0,
            })
        }
    }

    /// 次のセグメントの最初のアドレスを取得
    pub fn next_segment(&self) -> Option<Self> {
        if self.segment == 0xFFFF {
            None
        } else {
            Some(Self {
                segment: self.segment + 1,
                bus: 0,
                device: 0,
                function: 0,
            })
        }
    }
}

impl PartialEq for PciAddress {
    fn eq(&self, other: &Self) -> bool {
        self.segment == other.segment
            && self.bus == other.bus
            && self.device == other.device
            && self.function == other.function
    }
}

impl Eq for PciAddress {}

impl Hash for PciAddress {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_u64().hash(state);
    }
}

impl fmt::Display for PciAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04x}:{:02x}:{:02x}.{:x}",
            self.segment, self.bus, self.device, self.function
        )
    }
}

/// PCIアドレスのパーサー
///
/// 文字列からPCIアドレスをパースするための構造体です。
/// BDFまたはSBDFフォーマットをサポートします。
pub struct PciAddressParser;

impl PciAddressParser {
    /// 文字列からPCIアドレスをパース
    ///
    /// 次の形式をサポート:
    /// - "bus:device.function" (レガシーBDF形式、例: "00:1f.3")
    /// - "segment:bus:device.function" (SBDF形式、例: "0000:00:1f.3")
    pub fn parse(s: &str) -> Result<PciAddress, &'static str> {
        // セグメントが含まれているかチェック
        let parts: Vec<&str> = s.split(':').collect();
        
        match parts.len() {
            2 => Self::parse_bdf(parts[0], parts[1]), // BDF形式
            3 => Self::parse_sbdf(parts[0], parts[1], parts[2]), // SBDF形式
            _ => Err("無効なPCIアドレス形式です"),
        }
    }
    
    // BDF形式 (bus:device.function) をパース
    fn parse_bdf(bus_str: &str, dev_fn_str: &str) -> Result<PciAddress, &'static str> {
        let bus = u8::from_str_radix(bus_str, 16)
            .map_err(|_| "バス番号のパースに失敗しました")?;
        
        let dev_fn_parts: Vec<&str> = dev_fn_str.split('.').collect();
        if dev_fn_parts.len() != 2 {
            return Err("デバイス・ファンクション形式が無効です");
        }
        
        let device = u8::from_str_radix(dev_fn_parts[0], 16)
            .map_err(|_| "デバイス番号のパースに失敗しました")?;
        let function = u8::from_str_radix(dev_fn_parts[1], 16)
            .map_err(|_| "ファンクション番号のパースに失敗しました")?;
        
        // 値の範囲チェック
        if device > 31 {
            return Err("デバイス番号は0-31の範囲内である必要があります");
        }
        if function > 7 {
            return Err("ファンクション番号は0-7の範囲内である必要があります");
        }
        
        Ok(PciAddress::legacy(bus, device, function))
    }
    
    // SBDF形式 (segment:bus:device.function) をパース
    fn parse_sbdf(segment_str: &str, bus_str: &str, dev_fn_str: &str) -> Result<PciAddress, &'static str> {
        let segment = u16::from_str_radix(segment_str, 16)
            .map_err(|_| "セグメント番号のパースに失敗しました")?;
        
        let bus = u8::from_str_radix(bus_str, 16)
            .map_err(|_| "バス番号のパースに失敗しました")?;
        
        let dev_fn_parts: Vec<&str> = dev_fn_str.split('.').collect();
        if dev_fn_parts.len() != 2 {
            return Err("デバイス・ファンクション形式が無効です");
        }
        
        let device = u8::from_str_radix(dev_fn_parts[0], 16)
            .map_err(|_| "デバイス番号のパースに失敗しました")?;
        let function = u8::from_str_radix(dev_fn_parts[1], 16)
            .map_err(|_| "ファンクション番号のパースに失敗しました")?;
        
        // 値の範囲チェック
        if device > 31 {
            return Err("デバイス番号は0-31の範囲内である必要があります");
        }
        if function > 7 {
            return Err("ファンクション番号は0-7の範囲内である必要があります");
        }
        
        Ok(PciAddress::new(segment, bus, device, function))
    }
} 