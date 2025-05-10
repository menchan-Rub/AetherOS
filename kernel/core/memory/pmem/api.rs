// AetherOS PMEM API
//
// このモジュールはPMEM（不揮発性メモリ）のプログラミングインターフェースを提供します。
// カーネル内の他のサブシステムがPMEMを利用するためのAPIを定義します。

use alloc::string::String;
use alloc::vec::Vec;
use core::ptr::NonNull;
use log::info;

use super::allocator::{PmemAllocFlags, PmemAllocator};
use super::region::{PmemRegion, PmemRegionInfo, PmemRegionType};

/// PMEM領域へのハンドル
pub struct PmemHandle {
    /// ベースアドレス
    pub address: usize,
    /// サイズ
    pub size: usize,
    /// 関連する領域名
    pub region_name: String,
    /// アロケーションID
    pub alloc_id: usize,
}

/// PMEM操作のエラータイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmemError {
    /// メモリ不足
    OutOfMemory,
    /// 無効なパラメータ
    InvalidParameters,
    /// 領域が存在しない
    RegionNotFound,
    /// デバイスが存在しない
    DeviceNotFound,
    /// 既にマウント済み
    AlreadyMounted,
    /// マウントされていない
    NotMounted,
    /// アクセス権限エラー
    AccessDenied,
    /// I/Oエラー
    IoError,
    /// 内部エラー
    InternalError,
}

impl core::fmt::Display for PmemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfMemory => write!(f, "不揮発性メモリ不足"),
            Self::InvalidParameters => write!(f, "無効なパラメータ"),
            Self::RegionNotFound => write!(f, "PMEM領域が見つかりません"),
            Self::DeviceNotFound => write!(f, "PMEMデバイスが見つかりません"),
            Self::AlreadyMounted => write!(f, "PMEM領域は既にマウント済みです"),
            Self::NotMounted => write!(f, "PMEM領域がマウントされていません"),
            Self::AccessDenied => write!(f, "PMEM領域へのアクセスが拒否されました"),
            Self::IoError => write!(f, "PMEM I/Oエラー"),
            Self::InternalError => write!(f, "PMEM内部エラー"),
        }
    }
}

/// PMEM APIエントリポイント
/// シングルトンパターンで実装し、PMEM操作を抽象化
pub struct PmemApi {
    allocator: PmemAllocator,
}

impl PmemApi {
    /// 新しいPMEM APIインスタンスを作成
    pub fn new() -> Self {
        Self {
            allocator: PmemAllocator::new(),
        }
    }
    
    /// API初期化
    pub fn init(&mut self) -> Result<(), PmemError> {
        info!("PMEM APIを初期化中...");
        self.allocator.init().map_err(|_| PmemError::InternalError)
    }
    
    /// PMEM領域から指定サイズのメモリを割り当て
    pub fn alloc(&mut self, size: usize, flags: PmemAllocFlags) -> Result<PmemHandle, PmemError> {
        let allocation = self.allocator.allocate(size, flags)
            .map_err(|_| PmemError::OutOfMemory)?;
        
        let handle = PmemHandle {
            address: allocation.0,
            size: allocation.1,
            region_name: "pmem0".to_string(), // 単純化のため固定
            alloc_id: allocation.2,
        };
        
        info!("PMEM割り当て: アドレス={:#x}, サイズ={}バイト, ID={}",
             handle.address, handle.size, handle.alloc_id);
        
        Ok(handle)
    }
    
    /// 割り当てられたPMEMメモリを解放
    pub fn free(&mut self, handle: PmemHandle) -> Result<(), PmemError> {
        self.allocator.free(handle.address, handle.size, handle.alloc_id)
            .map_err(|_| PmemError::InvalidParameters)?;
        
        info!("PMEM解放: アドレス={:#x}, サイズ={}バイト, ID={}",
             handle.address, handle.size, handle.alloc_id);
        
        Ok(())
    }
    
    /// PMEM割り当てに対応するポインタを取得
    pub fn get_ptr<T>(&self, handle: &PmemHandle) -> Result<NonNull<T>, PmemError> {
        let ptr = handle.address as *mut T;
        NonNull::new(ptr).ok_or(PmemError::InvalidParameters)
    }
    
    /// PMEMにデータを書き込み
    pub fn write<T: Copy>(&self, handle: &PmemHandle, data: &T) -> Result<(), PmemError> {
        // 書き込みサイズがハンドルのサイズを超えていないことを確認
        if core::mem::size_of::<T>() > handle.size {
            return Err(PmemError::InvalidParameters);
        }
        
        let ptr = handle.address as *mut T;
        unsafe {
            *ptr = *data;
            // バリアを実行して永続化を保証
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        }
        
        Ok(())
    }
    
    /// PMEMからデータを読み込み
    pub fn read<T: Copy>(&self, handle: &PmemHandle) -> Result<T, PmemError> {
        // 読み込みサイズがハンドルのサイズを超えていないことを確認
        if core::mem::size_of::<T>() > handle.size {
            return Err(PmemError::InvalidParameters);
        }
        
        let ptr = handle.address as *const T;
        unsafe {
            Ok(*ptr)
        }
    }
    
    /// PMEM領域にバッファを書き込み
    pub fn write_buffer(&self, handle: &PmemHandle, buffer: &[u8], offset: usize) -> Result<(), PmemError> {
        // オフセットとバッファサイズがハンドルのサイズを超えていないことを確認
        if offset + buffer.len() > handle.size {
            return Err(PmemError::InvalidParameters);
        }
        
        let dest_ptr = (handle.address + offset) as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(buffer.as_ptr(), dest_ptr, buffer.len());
            // バリアを実行して永続化を保証
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        }
        
        Ok(())
    }
    
    /// PMEM領域からバッファに読み込み
    pub fn read_buffer(&self, handle: &PmemHandle, buffer: &mut [u8], offset: usize) -> Result<(), PmemError> {
        // オフセットとバッファサイズがハンドルのサイズを超えていないことを確認
        if offset + buffer.len() > handle.size {
            return Err(PmemError::InvalidParameters);
        }
        
        let src_ptr = (handle.address + offset) as *const u8;
        unsafe {
            core::ptr::copy_nonoverlapping(src_ptr, buffer.as_mut_ptr(), buffer.len());
        }
        
        Ok(())
    }
    
    /// PMEM領域をゼロで初期化
    pub fn zero_memory(&self, handle: &PmemHandle) -> Result<(), PmemError> {
        let ptr = handle.address as *mut u8;
        unsafe {
            core::ptr::write_bytes(ptr, 0, handle.size);
            // バリアを実行して永続化を保証
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        }
        
        Ok(())
    }
    
    /// PMEM使用統計を取得
    pub fn get_stats(&self) -> (usize, usize, usize, f32) {
        self.allocator.get_stats()
    }
}

/// グローバルPMEM APIインスタンス
/// シングルトンパターンでアクセス
static mut PMEM_API_INSTANCE: Option<PmemApi> = None;

/// PMEMグローバルアクセス関数
pub fn pmem() -> &'static mut PmemApi {
    unsafe {
        if PMEM_API_INSTANCE.is_none() {
            PMEM_API_INSTANCE = Some(PmemApi::new());
        }
        PMEM_API_INSTANCE.as_mut().unwrap()
    }
}

/// PMEMサブシステム初期化関数
pub fn init_pmem() -> Result<(), PmemError> {
    let api = pmem();
    api.init()
}

/// PMEMシンプルなラッパー関数群（便利関数）

/// 簡易割り当て関数
pub fn pmem_alloc(size: usize) -> Result<PmemHandle, PmemError> {
    let flags = PmemAllocFlags {
        zero: true,
        persistent: true,
        ..Default::default()
    };
    pmem().alloc(size, flags)
}

/// 簡易解放関数
pub fn pmem_free(handle: PmemHandle) -> Result<(), PmemError> {
    pmem().free(handle)
}

/// 簡易書き込み関数
pub fn pmem_write<T: Copy>(handle: &PmemHandle, data: &T) -> Result<(), PmemError> {
    pmem().write(handle, data)
}

/// 簡易読み込み関数
pub fn pmem_read<T: Copy>(handle: &PmemHandle) -> Result<T, PmemError> {
    pmem().read(handle)
} 