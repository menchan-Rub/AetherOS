// AetherOS Slub Object Meta
//
// このモジュールはSlubオブジェクトのメタデータを実装します。
// 各オブジェクトの先頭に配置され、フリーリストの構築に使用されます。
// SLUBアロケータではメタデータのサイズを最小限に抑えています。

use core::fmt;

/// Slubオブジェクトメタデータ
///
/// 各Slubオブジェクトの先頭に配置され、オブジェクトが
/// 解放されたときにフリーリストを構築するために使用されます。
/// Slabアロケータと互換性があり、最適化されています。
///
/// 実際のオブジェクトデータはこの構造体の直後に配置されます。
#[repr(C)]
pub struct SlubObjectMeta {
    /// フリーリスト内の次のオブジェクトへのポインタ
    pub next: *mut SlubObjectMeta,
    /// ページへの逆参照（メモリ節約モードではNULL）
    pub page: *mut u8,
}

impl SlubObjectMeta {
    /// 新しいSlubオブジェクトメタデータを作成
    pub fn new(page_addr: *mut u8) -> Self {
        SlubObjectMeta {
            next: core::ptr::null_mut(),
            page: page_addr,
        }
    }

    /// メモリ節約モードの新しいSlubオブジェクトメタデータを作成
    pub fn new_compact() -> Self {
        SlubObjectMeta {
            next: core::ptr::null_mut(),
            page: core::ptr::null_mut(),
        }
    }

    /// 次のオブジェクトへのポインタを設定
    pub fn set_next(&mut self, next: *mut SlubObjectMeta) {
        self.next = next;
    }

    /// 次のオブジェクトへのポインタを取得
    pub fn get_next(&self) -> *mut SlubObjectMeta {
        self.next
    }

    /// オブジェクトがフリーリストにリンクされているかをチェック
    pub fn is_linked(&self) -> bool {
        !self.next.is_null()
    }
    
    /// ページアドレスを設定
    pub fn set_page(&mut self, page: *mut u8) {
        self.page = page;
    }
    
    /// ページアドレスを取得
    pub fn get_page(&self) -> *mut u8 {
        self.page
    }
}

impl fmt::Debug for SlubObjectMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlubObjectMeta")
            .field("next", &self.next)
            .field("page", &self.page)
            .field("is_linked", &self.is_linked())
            .finish()
    }
}

impl Default for SlubObjectMeta {
    fn default() -> Self {
        Self::new_compact()
    }
} 