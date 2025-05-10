// AetherOS Slab Object Meta
//
// このモジュールはSlabオブジェクトのメタデータを実装します。
// 各オブジェクトの先頭に配置され、フリーリストの構築に使用されます。

use core::fmt;

/// Slabオブジェクトメタデータ
///
/// 各Slabオブジェクトの先頭に配置され、オブジェクトが
/// 解放されたときにフリーリストを構築するために使用されます。
///
/// 実際のオブジェクトデータはこの構造体の直後に配置されます。
#[repr(C)]
pub struct SlabObjectMeta {
    /// フリーリスト内の次のオブジェクトへのポインタ
    pub next: *mut SlabObjectMeta,
}

impl SlabObjectMeta {
    /// 新しいSlabオブジェクトメタデータを作成
    pub fn new() -> Self {
        SlabObjectMeta {
            next: core::ptr::null_mut(),
        }
    }

    /// 次のオブジェクトへのポインタを設定
    pub fn set_next(&mut self, next: *mut SlabObjectMeta) {
        self.next = next;
    }

    /// 次のオブジェクトへのポインタを取得
    pub fn get_next(&self) -> *mut SlabObjectMeta {
        self.next
    }

    /// オブジェクトがフリーリストにリンクされているかをチェック
    pub fn is_linked(&self) -> bool {
        !self.next.is_null()
    }
}

impl fmt::Debug for SlabObjectMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlabObjectMeta")
            .field("next", &self.next)
            .field("is_linked", &self.is_linked())
            .finish()
    }
}

impl Default for SlabObjectMeta {
    fn default() -> Self {
        Self::new()
    }
} 