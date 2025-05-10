// AetherOS スラブアロケータの同期プリミティブ
//
// このファイルはスラブアロケータ用の同期プリミティブを提供します。
// マルチスレッド環境でのアクセスを安全に行うための実装です。

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};

/// スピンロック実装
/// 
/// CPUが忙しく待機するシンプルなロック機構です。
/// カーネル空間での短期的なロックに適しています。
pub struct SpinLock<T> {
    /// ロック状態
    locked: AtomicBool,
    /// 保護されたデータ
    data: UnsafeCell<T>,
}

/// スピンロックガード
/// 
/// スコープベースのロック解放を保証します。
pub struct SpinLockGuard<'a, T> {
    /// 参照しているロック
    lock: &'a SpinLock<T>,
}

// 複数スレッドで共有可能なことを明示
unsafe impl<T: Send> Send for SpinLock<T> {}
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// 新しいスピンロックを作成する
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    /// ロックを取得する
    /// 
    /// 他のスレッドがロックを保持している間は待機します。
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        // 空のループでロックが解放されるのを待機
        while self.locked.compare_exchange_weak(
            false, true, 
            Ordering::Acquire, 
            Ordering::Relaxed
        ).is_err() {
            // CPUリソースを節約するためのヒント
            core::hint::spin_loop();
        }
        
        SpinLockGuard { lock: self }
    }
    
    /// 内部データへの参照を安全に取得する
    /// 
    /// # 安全性
    /// このメソッドは内部的な使用のみを想定しています
    unsafe fn get_data(&self) -> &mut T {
        &mut *self.data.get()
    }
}

impl<'a, T> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        // ロックを解放
        self.lock.locked.store(false, Ordering::Release);
    }
}

impl<'a, T> Deref for SpinLockGuard<'a, T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

/// 読み取り/書き込みロック
/// 
/// 複数の読み取りまたは単一の書き込みを許可するロック機構です。
pub struct RwLock<T> {
    /// リーダー数とライターフラグ
    /// 最上位ビットがライターフラグ、残りがリーダーカウント
    state: AtomicUsize,
    /// 保護されたデータ
    data: UnsafeCell<T>,
}

/// 読み取りガード
pub struct RwLockReadGuard<'a, T> {
    lock: &'a RwLock<T>,
}

/// 書き込みガード
pub struct RwLockWriteGuard<'a, T> {
    lock: &'a RwLock<T>,
}

// 複数スレッドで共有可能なことを明示
unsafe impl<T: Send + Sync> Send for RwLock<T> {}
unsafe impl<T: Send + Sync> Sync for RwLock<T> {}
unsafe impl<'a, T: Send + Sync> Send for RwLockReadGuard<'a, T> {}
unsafe impl<'a, T: Send + Sync> Sync for RwLockReadGuard<'a, T> {}
unsafe impl<'a, T: Send + Sync> Send for RwLockWriteGuard<'a, T> {}

// 定数定義
const WRITER_BIT: usize = usize::MAX / 2 + 1;
const READERS_MASK: usize = WRITER_BIT - 1;

impl<T> RwLock<T> {
    /// 新しい読み取り/書き込みロックを作成する
    pub const fn new(data: T) -> Self {
        Self {
            state: AtomicUsize::new(0),
            data: UnsafeCell::new(data),
        }
    }
    
    /// 読み取りロックを取得する
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            // 現在の状態を取得
            let state = self.state.load(Ordering::Relaxed);
            
            // ライターがいる場合は待機
            if state & WRITER_BIT != 0 {
                core::hint::spin_loop();
                continue;
            }
            
            // リーダーカウントをインクリメント
            if self.state.compare_exchange_weak(
                state, state + 1,
                Ordering::Acquire,
                Ordering::Relaxed
            ).is_ok() {
                break;
            }
        }
        
        RwLockReadGuard { lock: self }
    }
    
    /// 書き込みロックを取得する
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        loop {
            // 現在の状態を取得
            let state = self.state.load(Ordering::Relaxed);
            
            // 他のライターやリーダーがいる場合は待機
            if state != 0 {
                core::hint::spin_loop();
                continue;
            }
            
            // ライターフラグを設定
            if self.state.compare_exchange_weak(
                0, WRITER_BIT,
                Ordering::Acquire,
                Ordering::Relaxed
            ).is_ok() {
                break;
            }
        }
        
        RwLockWriteGuard { lock: self }
    }
}

impl<'a, T> Drop for RwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        // リーダーカウントをデクリメント
        self.lock.state.fetch_sub(1, Ordering::Release);
    }
}

impl<'a, T> Drop for RwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        // ライターフラグをクリア
        self.lock.state.store(0, Ordering::Release);
    }
}

impl<'a, T> Deref for RwLockReadGuard<'a, T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> Deref for RwLockWriteGuard<'a, T> {
    type Target = T;
    
    fn deref(&mut self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for RwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

// テスト用コード
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_spinlock() {
        let lock = SpinLock::new(42);
        
        {
            let mut guard = lock.lock();
            assert_eq!(*guard, 42);
            *guard = 84;
        }
        
        let guard = lock.lock();
        assert_eq!(*guard, 84);
    }
    
    #[test]
    fn test_rwlock() {
        let lock = RwLock::new(42);
        
        // 複数リーダーテスト
        {
            let r1 = lock.read();
            let r2 = lock.read();
            assert_eq!(*r1, 42);
            assert_eq!(*r2, 42);
        }
        
        // ライターテスト
        {
            let mut w = lock.write();
            *w = 84;
        }
        
        // 変更確認
        let r = lock.read();
        assert_eq!(*r, 84);
    }
} 