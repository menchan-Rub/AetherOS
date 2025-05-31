// AetherOS SLUB オブジェクト実装

/// スラブオブジェクト構造体
/// オブジェクトの追跡と管理を行う
#[derive(Debug)]
pub struct SlubObject {
    /// オブジェクトアドレス
    address: usize,
}

impl SlubObject {
    /// 新しいオブジェクトを作成
    pub fn new(address: usize) -> Self {
        SlubObject { address }
    }
    
    /// アドレスを取得
    pub fn address(&self) -> usize {
        self.address
    }
}

/// リンクリスト用の実装
impl core::cmp::PartialEq for SlubObject {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl core::cmp::Eq for SlubObject {}

/// クローン実装
impl Clone for SlubObject {
    fn clone(&self) -> Self {
        SlubObject { address: self.address }
    }
}

/// コピー実装
impl Copy for SlubObject {} 