// kernel/arch/x86_64/mm/gdt.rs

use core::mem::size_of;

/// GDTエントリのフラグ (抜粋)
/// Access Byte のフォーマット:
/// P | DPL0 DPL1 | S | Type3 Type2 Type1 Type0
/// P: Present (1)
/// DPL: Descriptor Privilege Level (00 for kernel)
/// S: Descriptor Type (0 = system, 1 = code/data)
/// Type (Code): X (Executable), C (Conforming), R (Readable), A (Accessed)
/// Type (Data): W (Writable), E (Expand-down), A (Accessed)
/// Granularity Byte のフォーマット:
/// G | DB | L | AVL | Limit_19_16
/// G: Granularity (0 = 1 byte, 1 = 4 KiB)
/// DB: Default operation size (0 = 16-bit, 1 = 32-bit segment)
/// L: Long-mode code flag (1 for 64-bit code segment)

/// 64ビットカーネルコードセグメントのアクセスバイト
const KERNEL_CODE_ACCESS: u8 = 0b10011010; // Present, DPL0, Code, Executable, Readable
/// 64ビットカーネルデータセグメントのアクセスバイト
const KERNEL_DATA_ACCESS: u8 = 0b10010010; // Present, DPL0, Data, Writable

/// 64ビットカーネルコードセグメントのグラニュラリティバイト
const KERNEL_CODE_GRANULARITY: u8 = 0b10101111; // Granularity=4KiB, Long-mode, Limit (ignored in 64-bit for code)
/// 64ビットカーネルデータセグメントのグラニュラリティバイト
const KERNEL_DATA_GRANULARITY: u8 = 0b11001111; // Granularity=4KiB, 32-bit default size (ignored in 64-bit), Limit

/// GDTへのポインタ構造体
#[repr(C, packed)]
pub struct GdtPointer {
    limit: u16,
    base: u64,
}

impl GdtPointer {
    pub fn new(gdt_entries: &[GdtEntry]) -> Self {
        GdtPointer {
            limit: (size_of::<GdtEntry>() * gdt_entries.len() - 1) as u16,
            base: gdt_entries.as_ptr() as u64,
        }
    }

    /// GDTをロードします。
    ///
    /// # Safety
    /// この関数は `lgdt` 命令を実行し、GDTを直接変更するため安全ではありません。
    /// 誤ったGDTを設定するとシステムクラッシュを引き起こす可能性があります。
    pub unsafe fn load(&self) {
        core::arch::asm!("lgdt [{}]", in(reg) self, options(readonly, nostack, preserves_flags));
    }
}

/// GDTエントリ構造体 (64ビット)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct GdtEntry {
    limit_low: u16,      // セグメントリミット (0-15)
    base_low: u16,       // ベースアドレス (0-15)
    base_middle: u8,     // ベースアドレス (16-23)
    access: u8,          // アクセス権バイト
    granularity: u8,     // グラニュラリティとリミット (16-19)
    base_high: u8,       // ベースアドレス (24-31)
    // 64ビットモードでは、以下の2つは通常0に設定されるか、特定の用途に使用されます。
    // base_upper: u32,       // ベースアドレス (32-63) - システムセグメントディスクリプタでのみ使用
    // reserved: u32,         // 予約済み
}

impl GdtEntry {
    /// 新しいGDTエントリを作成します。
    /// base と limit は64ビットモードのセグメントでは多くの場合無視されます (特にコードセグメント)。
    /// しかし、互換性のために設定します。
    const fn new(base: u32, limit: u32, access: u8, granularity: u8) -> Self {
        GdtEntry {
            limit_low: (limit & 0xFFFF) as u16,
            base_low: (base & 0xFFFF) as u16,
            base_middle: ((base >> 16) & 0xFF) as u8,
            access,
            granularity: ((limit >> 16) & 0x0F) as u8 | (granularity & 0xF0),
            base_high: ((base >> 24) & 0xFF) as u8,
        }
    }

    /// 空の（NULL）GDTエントリを作成します。
    pub const fn new_null() -> Self {
        GdtEntry {
            limit_low: 0,
            base_low: 0,
            base_middle: 0,
            access: 0,
            granularity: 0,
            base_high: 0,
        }
    }

    /// 64ビットカーネルコードセグメントディスクリプタを作成します。
    pub const fn new_kernel_code_segment_64() -> Self {
        // 64ビットモードでは、ベースとリミットはほぼ0に設定されます。
        // Lビット(Long mode)がグラニュラリティバイトで設定されることが重要です。
        GdtEntry::new(0, 0xFFFFF, KERNEL_CODE_ACCESS, KERNEL_CODE_GRANULARITY)
    }

    /// 64ビットカーネルデータセグメントディスクリプタを作成します。
    pub const fn new_kernel_data_segment_64() -> Self {
        // データセグメントも同様にベースとリミットは0で良いです。
        GdtEntry::new(0, 0xFFFFF, KERNEL_DATA_ACCESS, KERNEL_DATA_GRANULARITY)
    }
}

/// GDTセレクタ定数
pub const KERNEL_NULL_SELECTOR: u16 = 0;
pub const KERNEL_CODE_SELECTOR: u16 = 1 * 8; // GDTの1番目のエントリ (インデックス1)
pub const KERNEL_DATA_SELECTOR: u16 = 2 * 8; // GDTの2番目のエントリ (インデックス2)

/// グローバルGDTインスタンス
/// 注意: `static mut` は通常避けるべきですが、GDTのような低レベル構造では
/// 初期化時に一度だけ設定され、その後は読み取り専用として扱われるため許容されることがあります。
/// より安全な方法は `OnceCell` などを使用することです。
#[repr(align(16))] // GDTは16バイトアライメント推奨
pub struct GlobalDescriptorTable {
    entries: [GdtEntry; 3], // NULL, Kernel Code, Kernel Data
}

impl GlobalDescriptorTable {
    pub const fn new() -> Self {
        GlobalDescriptorTable {
            entries: [
                GdtEntry::new_null(),
                GdtEntry::new_kernel_code_segment_64(),
                GdtEntry::new_kernel_data_segment_64(),
            ],
        }
    }

    pub fn pointer(&self) -> GdtPointer {
        GdtPointer::new(&self.entries)
    }
}

// グローバルGDTの静的インスタンス
// #[used]
#[no_mangle]
#[link_section = ".gdt"]
static GLOBAL_GDT: GlobalDescriptorTable = GlobalDescriptorTable::new();

/// GDTを初期化しロードします。
/// この関数はブートプロセスの早い段階で一度だけ呼び出されるべきです。
///
/// # Safety
/// この関数は `lgdt` 命令を実行するため安全ではありません。
pub unsafe fn init_gdt() {
    let gdt_ptr = GLOBAL_GDT.pointer();
    gdt_ptr.load();
    crate::core::debug::serial::serial_println!("GDT loaded. Base: {:#x}, Limit: {:#x}", gdt_ptr.base, gdt_ptr.limit);
} 