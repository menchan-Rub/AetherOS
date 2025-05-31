// kernel/arch/x86_64/mm/page_table/flag.rs

use bitflags::bitflags;

bitflags! {
    /// ページテーブルエントリのフラグ (PML4, PDPT, PD, PT共通)
    /// Intel SDM Vol 3A, Section 4.5 PAGE-TRANSLATION-TABLE ENTRY FORMATS
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct PageTableFlags: u64 {
        /// Present: ページが物理メモリに存在するかどうか
        const PRESENT = 1 << 0;
        /// Writable: ページへの書き込みが可能かどうか
        const WRITABLE = 1 << 1;
        /// User Accessible: ユーザーモードからのアクセスが可能かどうか (U/S)
        /// このフラグが0の場合、ページはスーパーバイザモードでのみアクセス可能
        const USER_ACCESSIBLE = 1 << 2;
        /// Page-Level Write-Through: ページレベルのライトスルーキャッシュポリシー (PWT)
        const WRITE_THROUGH = 1 << 3;
        /// Page-Level Cache Disable: ページレベルのキャッシュ無効化 (PCD)
        const CACHE_DISABLE = 1 << 4;
        /// Accessed: ページがアクセスされたかどうか (CPUがセット)
        const ACCESSED = 1 << 5;
        /// Dirty: ページが書き込まれたかどうか (CPUがセット、PTエントリのみ)
        const DIRTY = 1 << 6;
        /// Page Size (PS) または Huge Page: PDまたはPDPTエントリでページサイズを示す
        /// PDエントリの場合: 1 = 2MiBページ
        /// PDPTエントリの場合: 1 = 1GiBページ
        const HUGE_PAGE = 1 << 7;
        /// Global: TLBグローバルフラグ (PGEビットがCR4で有効な場合)
        /// 1の場合、TLBエントリはCR3が変更されても維持される
        const GLOBAL = 1 << 8;
        // 9-11: 利用可能 (ソフトウェアが自由に使用可能)
        // 52-62: 利用可能 (ソフトウェアが自由に使用可能)
        /// No Execute (NX) または Execute Disable (XD):
        /// ページからの命令フェッチを禁止するかどうか (EFER.NXEビットが有効な場合)
        const NO_EXECUTE = 1 << 63;
    }
} 