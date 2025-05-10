// AetherOS PMEMユーティリティ
//
// このモジュールはPMEM（不揮発性メモリ）操作のためのユーティリティ関数を提供します。
// 永続化、アトミック操作、バックアップ/復元などのヘルパー関数を含みます。

use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use log::{debug, info, warn, error};

use super::api::{PmemHandle, PmemError, pmem_alloc, pmem_free, pmem_read, pmem_write};

/// PMEMデータ永続化ユーティリティ
pub struct PmemPersistence;

impl PmemPersistence {
    /// メモリバリアを実行して永続化を保証
    pub fn memory_fence() {
        // PMEM操作の前後にフェンスが必要
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    
    /// CACHEFLUSHを実行（x86専用）
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn clflush(addr: *const u8) {
        core::arch::x86_64::_mm_clflush(addr);
    }
    
    /// 範囲をフラッシュ（x86専用）
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn clflush_range(addr: usize, size: usize) {
        let line_size = 64; // キャッシュラインサイズ（通常は64バイト）
        let mut p = addr as *const u8;
        let end = (addr + size) as *const u8;
        
        while p < end {
            core::arch::x86_64::_mm_clflush(p);
            p = p.add(line_size);
        }
    }
    
    /// ストア命令を永続化（x86専用）
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn store_persist<T: Copy>(addr: *mut T, value: T) {
        *addr = value;
        core::arch::x86_64::_mm_clflush(addr as *const u8);
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    
    /// メモリ領域全体の永続化を実行
    pub fn persist_region(handle: &PmemHandle) -> Result<(), PmemError> {
        // ここではシステムキャッシュをフラッシュするのみ
        Self::memory_fence();
        
        #[cfg(target_arch = "x86_64")]
        unsafe {
            Self::clflush_range(handle.address, handle.size);
        }
        
        Self::memory_fence();
        Ok(())
    }
}

/// PMEMチェックサム計算ユーティリティ
pub struct PmemChecksum;

impl PmemChecksum {
    /// シンプルなFletcher-16チェックサム計算
    pub fn fletcher16(data: &[u8]) -> u16 {
        let mut sum1: u16 = 0;
        let mut sum2: u16 = 0;
        
        for byte in data {
            sum1 = (sum1 + *byte as u16) % 255;
            sum2 = (sum2 + sum1) % 255;
        }
        
        (sum2 << 8) | sum1
    }
    
    /// CRC-32チェックサム計算
    pub fn crc32(data: &[u8]) -> u32 {
        // シンプルなCRC-32実装
        let mut crc: u32 = 0xFFFFFFFF;
        let polynomial: u32 = 0xEDB88320;
        
        for byte in data {
            crc ^= *byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ polynomial
                } else {
                    crc >> 1
                };
            }
        }
        
        !crc
    }
    
    /// PMEMデータのチェックサムを計算して追加
    pub fn add_checksum(handle: &PmemHandle) -> Result<u32, PmemError> {
        // データを読み込み
        let mut buffer = Vec::with_capacity(handle.size);
        unsafe {
            buffer.set_len(handle.size);
        }
        
        let api = super::api::pmem();
        api.read_buffer(handle, &mut buffer, 0)?;
        
        // チェックサム計算
        let checksum = Self::crc32(&buffer);
        
        // チェックサムをPMEMに書き込み（末尾4バイト）
        if handle.size >= 4 {
            let checksum_offset = handle.size - 4;
            api.write_buffer(handle, &checksum.to_le_bytes(), checksum_offset)?;
        }
        
        debug!("PMEMデータにチェックサム追加: アドレス={:#x}, チェックサム={:#x}",
             handle.address, checksum);
        
        Ok(checksum)
    }
    
    /// PMEMデータのチェックサムを検証
    pub fn verify_checksum(handle: &PmemHandle) -> Result<bool, PmemError> {
        if handle.size < 4 {
            return Err(PmemError::InvalidParameters);
        }
        
        // データを読み込み（チェックサム部分を除く）
        let mut buffer = Vec::with_capacity(handle.size - 4);
        unsafe {
            buffer.set_len(handle.size - 4);
        }
        
        let api = super::api::pmem();
        api.read_buffer(handle, &mut buffer, 0)?;
        
        // 保存されているチェックサムを読み込み
        let mut checksum_bytes = [0u8; 4];
        let checksum_offset = handle.size - 4;
        api.read_buffer(handle, &mut checksum_bytes, checksum_offset)?;
        let stored_checksum = u32::from_le_bytes(checksum_bytes);
        
        // 新しいチェックサムを計算
        let calculated_checksum = Self::crc32(&buffer);
        
        // 比較
        let is_valid = calculated_checksum == stored_checksum;
        if !is_valid {
            warn!("PMEMチェックサム不一致: 保存値={:#x}, 計算値={:#x}",
                stored_checksum, calculated_checksum);
        }
        
        Ok(is_valid)
    }
}

/// PMEMアトミック操作ユーティリティ
pub struct PmemAtomic;

impl PmemAtomic {
    /// アトミックなSwap操作（交換）
    pub fn atomic_swap<T: Copy>(handle: &PmemHandle, value: T) -> Result<T, PmemError> 
    where T: core::cmp::Eq
    {
        if core::mem::size_of::<T>() > handle.size {
            return Err(PmemError::InvalidParameters);
        }
        
        let api = super::api::pmem();
        let ptr = api.get_ptr::<T>(handle)?;
        
        // アトミックなSwap操作を実行
        let old_value = unsafe { ptr.as_ptr().read() };
        unsafe {
            let atomic_ptr = ptr.as_ptr() as *mut core::sync::atomic::AtomicU64;
            if core::mem::size_of::<T>() == 8 {
                let value_bits = core::mem::transmute::<T, u64>(value);
                let atom = &*atomic_ptr;
                let old_bits = atom.swap(value_bits, Ordering::SeqCst);
                return Ok(core::mem::transmute::<u64, T>(old_bits));
            }
        }
        
        // フォールバック: 非アトミックな操作
        let result = api.write(handle, &value)?;
        Ok(old_value)
    }
    
    /// Compare-and-Swap操作（CAS）
    pub fn compare_and_swap<T: Copy + PartialEq>(
        handle: &PmemHandle, 
        expected: T, 
        new_value: T
    ) -> Result<bool, PmemError> {
        if core::mem::size_of::<T>() > handle.size {
            return Err(PmemError::InvalidParameters);
        }
        
        let api = super::api::pmem();
        
        // 現在の値を読み込み
        let current = api.read::<T>(handle)?;
        
        // 期待値と一致する場合のみ新しい値を書き込み
        if current == expected {
            api.write(handle, &new_value)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// PMEM耐障害性ユーティリティ
pub struct PmemResilience;

impl PmemResilience {
    /// PMEMデータのバックアップを作成
    pub fn backup_data(src_handle: &PmemHandle) -> Result<PmemHandle, PmemError> {
        // バックアップ用のPMEM領域を割り当て
        let backup_handle = pmem_alloc(src_handle.size)?;
        
        // データをコピー
        let api = super::api::pmem();
        let mut buffer = Vec::with_capacity(src_handle.size);
        unsafe { buffer.set_len(src_handle.size); }
        
        api.read_buffer(src_handle, &mut buffer, 0)?;
        api.write_buffer(&backup_handle, &buffer, 0)?;
        
        // チェックサムを追加
        PmemChecksum::add_checksum(&backup_handle)?;
        
        info!("PMEMデータをバックアップ: 元={:#x}, バックアップ={:#x}, サイズ={}バイト",
             src_handle.address, backup_handle.address, src_handle.size);
        
        Ok(backup_handle)
    }
    
    /// PMEMデータをバックアップから復元
    pub fn restore_from_backup(
        dest_handle: &PmemHandle, 
        backup_handle: &PmemHandle
    ) -> Result<(), PmemError> {
        // バックアップのチェックサムを検証
        if !PmemChecksum::verify_checksum(backup_handle)? {
            error!("バックアップのチェックサムが無効です");
            return Err(PmemError::IoError);
        }
        
        // バックアップから復元
        let api = super::api::pmem();
        let data_size = backup_handle.size - 4; // チェックサムを除いたサイズ
        
        let mut buffer = Vec::with_capacity(data_size);
        unsafe { buffer.set_len(data_size); }
        
        api.read_buffer(backup_handle, &mut buffer, 0)?;
        api.write_buffer(dest_handle, &buffer, 0)?;
        
        info!("PMEMデータをバックアップから復元: 元={:#x}, 宛先={:#x}, サイズ={}バイト",
             backup_handle.address, dest_handle.address, data_size);
        
        Ok(())
    }
    
    /// 障害復旧ポイントを作成（CoW - Copy on Write）
    pub fn create_recovery_point(handle: &PmemHandle, tag: &str) -> Result<PmemHandle, PmemError> {
        // バックアップを作成
        let recovery_handle = Self::backup_data(handle)?;
        
        // タグ情報を保存（実際にはタグをどこかに保存する必要がある）
        info!("復旧ポイントを作成: タグ='{}', アドレス={:#x}, サイズ={}バイト",
             tag, recovery_handle.address, recovery_handle.size);
        
        Ok(recovery_handle)
    }
}

/// PMEM暗号化ユーティリティ
pub struct PmemSecurity;

impl PmemSecurity {
    /// 単純なXOR暗号化
    pub fn xor_encrypt(handle: &PmemHandle, key: &[u8]) -> Result<(), PmemError> {
        if key.is_empty() {
            return Err(PmemError::InvalidParameters);
        }
        
        let api = super::api::pmem();
        
        // データを読み込み
        let mut buffer = Vec::with_capacity(handle.size);
        unsafe { buffer.set_len(handle.size); }
        api.read_buffer(handle, &mut buffer, 0)?;
        
        // XOR暗号化
        for (i, byte) in buffer.iter_mut().enumerate() {
            *byte ^= key[i % key.len()];
        }
        
        // 暗号化データを書き戻し
        api.write_buffer(handle, &buffer, 0)?;
        
        Ok(())
    }
    
    /// 単純なXOR復号化（暗号化と同じ操作）
    pub fn xor_decrypt(handle: &PmemHandle, key: &[u8]) -> Result<(), PmemError> {
        // XORでは暗号化と復号化が同じ操作
        Self::xor_encrypt(handle, key)
    }
    
    /// PMEMデータをセキュアに消去
    pub fn secure_erase(handle: &PmemHandle) -> Result<(), PmemError> {
        let api = super::api::pmem();
        
        // パターン1: 0x55（01010101）
        let pattern1 = [0x55u8; 4096];
        for offset in (0..handle.size).step_by(4096) {
            let len = core::cmp::min(4096, handle.size - offset);
            api.write_buffer(handle, &pattern1[..len], offset)?;
        }
        PmemPersistence::persist_region(handle)?;
        
        // パターン2: 0xAA（10101010）
        let pattern2 = [0xAAu8; 4096];
        for offset in (0..handle.size).step_by(4096) {
            let len = core::cmp::min(4096, handle.size - offset);
            api.write_buffer(handle, &pattern2[..len], offset)?;
        }
        PmemPersistence::persist_region(handle)?;
        
        // パターン3: 0x00（ゼロ）
        api.zero_memory(handle)?;
        PmemPersistence::persist_region(handle)?;
        
        info!("PMEMデータをセキュアに消去: アドレス={:#x}, サイズ={}バイト",
             handle.address, handle.size);
        
        Ok(())
    }
}

/// PMEM Atomicity & Consistency (A/C)ユーティリティ
pub struct PmemAtomicity;

impl PmemAtomicity {
    /// 変更ログヘッダ
    #[repr(C, packed)]
    struct ChangeLogHeader {
        magic: u32,           // マジック番号（識別用）
        version: u16,         // ログフォーマットバージョン
        entry_count: u16,     // エントリ数
        timestamp: u64,       // タイムスタンプ
        checksum: u32,        // ヘッダチェックサム
    }
    
    /// 変更ログエントリ
    #[repr(C, packed)]
    struct ChangeLogEntry {
        offset: u32,          // データオフセット
        size: u16,            // データサイズ
        reserved: u16,        // 予約（アライメント用）
        old_data_offset: u32, // 古いデータのオフセット
        new_data_offset: u32, // 新しいデータのオフセット
        checksum: u32,        // エントリチェックサム
    }
    
    /// 変更ログを初期化
    pub fn init_change_log(handle: &PmemHandle) -> Result<(), PmemError> {
        if handle.size < 64 {
            return Err(PmemError::InvalidParameters);
        }
        
        let api = super::api::pmem();
        
        // ログヘッダを初期化
        let header = Self::ChangeLogHeader {
            magic: 0x504D4C47,  // "PMLG"
            version: 1,
            entry_count: 0,
            timestamp: 0,
            checksum: 0,
        };
        
        // ヘッダを書き込み
        api.write(handle, &header)?;
        
        info!("PMEM変更ログを初期化: アドレス={:#x}, サイズ={}バイト",
             handle.address, handle.size);
        
        Ok(())
    }
    
    /// トランザクション開始
    pub fn begin_transaction(data_handle: &PmemHandle, log_handle: &PmemHandle) -> Result<(), PmemError> {
        let api = super::api::pmem();
        
        // ログヘッダを読み込み
        let mut header = api.read::<Self::ChangeLogHeader>(log_handle)?;
        
        // タイムスタンプを更新
        header.timestamp = Self::get_timestamp();
        header.entry_count = 0;
        
        // ヘッダを書き戻し
        api.write(log_handle, &header)?;
        
        debug!("PMEMトランザクション開始: データ={:#x}, ログ={:#x}",
             data_handle.address, log_handle.address);
        
        Ok(())
    }
    
    /// トランザクションをコミット
    pub fn commit_transaction(log_handle: &PmemHandle) -> Result<(), PmemError> {
        // 永続化を保証
        PmemPersistence::persist_region(log_handle)?;
        
        debug!("PMEMトランザクションをコミット: ログ={:#x}", log_handle.address);
        
        Ok(())
    }
    
    /// トランザクションをロールバック
    pub fn rollback_transaction(data_handle: &PmemHandle, log_handle: &PmemHandle) -> Result<(), PmemError> {
        let api = super::api::pmem();
        
        // ログヘッダを読み込み
        let header = api.read::<Self::ChangeLogHeader>(log_handle)?;
        
        // 各エントリを処理して古いデータを復元
        let mut entry_offset = core::mem::size_of::<Self::ChangeLogHeader>();
        for _ in 0..header.entry_count {
            if entry_offset + core::mem::size_of::<Self::ChangeLogEntry>() > log_handle.size {
                return Err(PmemError::IoError);
            }
            
            // エントリを読み込み
            let mut entry_data = [0u8; core::mem::size_of::<Self::ChangeLogEntry>()];
            api.read_buffer(log_handle, &mut entry_data, entry_offset)?;
            let entry: Self::ChangeLogEntry = unsafe { core::mem::transmute(entry_data) };
            
            // 古いデータを取得
            let mut old_data = Vec::with_capacity(entry.size as usize);
            unsafe { old_data.set_len(entry.size as usize); }
            api.read_buffer(log_handle, &mut old_data, entry.old_data_offset as usize)?;
            
            // 古いデータを復元
            api.write_buffer(data_handle, &old_data, entry.offset as usize)?;
            
            // 次のエントリへ
            entry_offset += core::mem::size_of::<Self::ChangeLogEntry>();
        }
        
        // 永続化を保証
        PmemPersistence::persist_region(data_handle)?;
        
        debug!("PMEMトランザクションをロールバック: データ={:#x}, ログ={:#x}",
             data_handle.address, log_handle.address);
        
        Ok(())
    }
    
    /// 現在のタイムスタンプを取得
    fn get_timestamp() -> u64 {
        // 実際のシステムでは、現在時刻または単調に増加するカウンタを使用
        // ここでは単純なカウンタとしてダミー実装
        static mut COUNTER: u64 = 0;
        unsafe {
            COUNTER += 1;
            COUNTER
        }
    }
}

/// ユーティリティ関数群（簡易アクセス用）

/// PMEMデータのバックアップを作成
pub fn pmem_backup(handle: &PmemHandle) -> Result<PmemHandle, PmemError> {
    PmemResilience::backup_data(handle)
}

/// PMEMデータを復元
pub fn pmem_restore(dest: &PmemHandle, backup: &PmemHandle) -> Result<(), PmemError> {
    PmemResilience::restore_from_backup(dest, backup)
}

/// PMEMデータのチェックサムを検証
pub fn pmem_verify(handle: &PmemHandle) -> Result<bool, PmemError> {
    PmemChecksum::verify_checksum(handle)
}

/// PMEMデータをセキュアに消去
pub fn pmem_secure_erase(handle: &PmemHandle) -> Result<(), PmemError> {
    PmemSecurity::secure_erase(handle)
} 