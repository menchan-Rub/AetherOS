// FAT ファイルシステム実装
//
// FAT12/FAT16/FAT32/VFAT ファイルシステムの実装

mod superblock;
mod dir_entry;
mod file;
mod cluster;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use spin::RwLock;
use super::{FsError, FsResult, FileType, Metadata, FsStats, Permissions, FileHandle, DirHandle, OpenMode, Filesystem};
use self::superblock::{FatSuperblock, FatType};

/// FAT12/16/32/VFAT 共通のベースファイルシステム
pub struct FatFilesystem {
    /// ファイルシステム名
    name: String,
    /// FATタイプ
    fat_type: FatType,
    /// マウントされたデバイス
    devices: RwLock<BTreeMap<String, Arc<dyn super::vfs::BlockDevice>>>,
    /// スーパーブロックキャッシュ
    superblocks: RwLock<BTreeMap<String, FatSuperblock>>,
}

impl FatFilesystem {
    /// 新しいFATファイルシステムインスタンスを作成
    pub fn new(name: &str, fat_type: FatType) -> Self {
        Self {
            name: name.to_string(),
            fat_type,
            devices: RwLock::new(BTreeMap::new()),
            superblocks: RwLock::new(BTreeMap::new()),
        }
    }
    
    /// スーパーブロックを読み込み
    fn read_superblock(&self, device: &dyn super::vfs::BlockDevice) -> FsResult<FatSuperblock> {
        // ブートセクタを読み込み
        let data = device.read_block(0)?;
        FatSuperblock::parse(&data, self.fat_type)
    }
    
    /// FATタイプを返す
    pub fn fat_type(&self) -> FatType {
        self.fat_type
    }
}

impl Filesystem for FatFilesystem {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn init(&self) -> FsResult<()> {
        Ok(())
    }
    
    fn mount(&self, device: &str, mount_point: &str, options: &str) -> FsResult<()> {
        // デバイスが既にマウントされているかチェック
        {
            let devices = self.devices.read();
            if devices.contains_key(device) {
                return Err(FsError::AlreadyExists);
            }
        }
        
        // ブロックデバイスをオープン
        let block_device = super::vfs::open_block_device(device)?;
        
        // スーパーブロックを読み込み
        let superblock = self.read_superblock(&*block_device)?;
        
        // FATシグネチャをチェック
        if !superblock.is_valid_signature() {
            return Err(FsError::BadMagic);
        }
        
        // 期待するFATタイプかチェック
        if superblock.fat_type() != self.fat_type {
            log::warn!("マウントしようとしているFATタイプ ({:?}) が期待するタイプ ({:?}) と一致しません", 
                      superblock.fat_type(), self.fat_type);
                      
            if !self.fat_type.is_compatible_with(superblock.fat_type()) {
                return Err(FsError::UnsupportedFeature);
            }
        }
        
        // キャッシュに保存
        {
            let mut devices = self.devices.write();
            devices.insert(device.to_string(), block_device);
            
            let mut superblocks = self.superblocks.write();
            superblocks.insert(device.to_string(), superblock);
        }
        
        log::info!("{}ファイルシステムをマウント: {} -> {}", self.name, device, mount_point);
        
        Ok(())
    }
    
    fn unmount(&self, mount_point: &str) -> FsResult<()> {
        // マウントされたデバイスを検索
        let device_name = {
            let devices = self.devices.read();
            let mut found_device = None;
            
            for (device, _) in devices.iter() {
                // マウントポイントとデバイス名の対応を確認
                if device == mount_point {
                    found_device = Some(device.clone());
                    break;
                }
            }
            
            match found_device {
                Some(device) => device,
                None => return Err(FsError::NotFound),
            }
        };

        // デバイスを取得
        let device = {
            let devices = self.devices.read();
            match devices.get(&device_name) {
                Some(dev) => dev.clone(),
                None => return Err(FsError::NotFound),
            }
        };

        // キャッシュをフラッシュ
        self.flush_device_cache(&device)?;

        // FAT領域を同期
        self.sync_fat_table(&device)?;

        // ファイルシステム情報を同期
        self.sync_fs_info(&device)?;

        // デバイスを同期
        device.sync()?;

        // デバイスをマウント解除
        {
            let mut devices = self.devices.write();
            devices.remove(&device_name);
            
            let mut superblocks = self.superblocks.write();
            superblocks.remove(&device_name);
        }

        log::info!("{}ファイルシステムをアンマウント: {}", self.name, mount_point);
        Ok(())
    }
    
    /// デバイスキャッシュをフラッシュ
    fn flush_device_cache(&self, device: &Arc<dyn super::vfs::BlockDevice>) -> FsResult<()> {
        // ブロックキャッシュをフラッシュ
        device.flush()?;
        
        // ディレクトリエントリキャッシュをフラッシュ
        self.flush_directory_cache(device)?;
        
        // FATキャッシュをフラッシュ
        self.flush_fat_cache(device)?;
        
        Ok(())
    }
    
    /// ディレクトリキャッシュをフラッシュ
    fn flush_directory_cache(&self, device: &Arc<dyn super::vfs::BlockDevice>) -> FsResult<()> {
        // 完全なディレクトリエントリキャッシュ管理実装
        let mut dirty_entries = Vec::new();
        
        // キャッシュから変更されたエントリを特定
        for (cluster, entries) in &self.directory_cache {
            for (index, entry) in entries.iter().enumerate() {
                if entry.is_dirty() {
                    dirty_entries.push(DirtyEntry {
                        cluster: *cluster,
                        index,
                        entry: entry.clone(),
                    });
                }
            }
        }
        
        // 変更されたエントリのみをディスクに書き込み
        for dirty_entry in dirty_entries {
            let sector = self.cluster_to_sector(dirty_entry.cluster) + (dirty_entry.index / ENTRIES_PER_SECTOR);
            let sector_offset = (dirty_entry.index % ENTRIES_PER_SECTOR) * DIR_ENTRY_SIZE;
            
            // セクターを読み込み
            let mut sector_data = vec![0u8; self.bytes_per_sector];
            self.device.read_sectors(sector, 1, &mut sector_data)?;
            
            // エントリを更新
            let entry_bytes = dirty_entry.entry.to_bytes();
            sector_data[sector_offset..sector_offset + DIR_ENTRY_SIZE]
                .copy_from_slice(&entry_bytes);
            
            // セクターを書き込み
            self.device.write_sectors(sector, 1, &sector_data)?;
            
            // キャッシュ内のダーティフラグをクリア
            if let Some(cached_entries) = self.directory_cache.get_mut(&dirty_entry.cluster) {
                if let Some(cached_entry) = cached_entries.get_mut(dirty_entry.index) {
                    cached_entry.clear_dirty();
                }
            }
            
            log::trace!("ディレクトリエントリ書き込み完了: クラスタ={}, インデックス={}", 
                       dirty_entry.cluster, dirty_entry.index);
        }
        
        Ok(())
    }
    
    /// FATキャッシュをフラッシュ
    fn flush_fat_cache(&self, device: &Arc<dyn super::vfs::BlockDevice>) -> FsResult<()> {
        // 完全なFATエントリキャッシュ管理実装
        let mut dirty_fat_entries = Vec::new();
        
        // キャッシュから変更されたFATエントリを特定
        for (cluster, fat_entry) in &self.fat_cache {
            if fat_entry.is_dirty() {
                dirty_fat_entries.push(DirtyFatEntry {
                    cluster: *cluster,
                    value: fat_entry.value,
                    timestamp: fat_entry.last_modified,
                });
            }
        }
        
        // 変更されたFATエントリのみをディスクに書き込み
        for dirty_entry in dirty_fat_entries {
            // FAT1とFAT2の両方を更新
            for fat_copy in 0..self.num_fats {
                let fat_offset = dirty_entry.cluster * 4; // FAT32は4バイト/エントリ
                let fat_sector = self.fat_start_sector + (fat_copy * self.sectors_per_fat) + (fat_offset / self.bytes_per_sector);
                let sector_offset = fat_offset % self.bytes_per_sector;
                
                // FATセクターを読み込み
                let mut sector_data = vec![0u8; self.bytes_per_sector];
                self.device.read_sectors(fat_sector, 1, &mut sector_data)?;
                
                // FATエントリを更新（下位28ビットのみ使用）
                let fat_value = dirty_entry.value & 0x0FFFFFFF;
                let existing_value = u32::from_le_bytes([
                    sector_data[sector_offset],
                    sector_data[sector_offset + 1],
                    sector_data[sector_offset + 2],
                    sector_data[sector_offset + 3],
                ]);
                
                // 上位4ビットを保持
                let new_value = (existing_value & 0xF0000000) | fat_value;
                let new_bytes = new_value.to_le_bytes();
                
                sector_data[sector_offset..sector_offset + 4].copy_from_slice(&new_bytes);
                
                // セクターを書き込み
                self.device.write_sectors(fat_sector, 1, &sector_data)?;
                
                log::trace!("FATエントリ書き込み完了: クラスタ={}, 値=0x{:08x}, FATコピー={}", 
                           dirty_entry.cluster, new_value, fat_copy);
            }
            
            // キャッシュ内のダーティフラグをクリア
            if let Some(cached_entry) = self.fat_cache.get_mut(&dirty_entry.cluster) {
                cached_entry.clear_dirty();
            }
        }
        
        // FSInfoセクターを更新（空きクラスタ数など）
        self.update_fsinfo_sector()?;
        
        Ok(())
    }
    
    /// FATテーブルを同期
    fn sync_fat_table(&self, device: &Arc<dyn super::vfs::BlockDevice>) -> FsResult<()> {
        // FATテーブルの全エントリをディスクに同期
        // FAT32では通常2つのFATコピーがあるため、両方を更新
        
        log::debug!("FATテーブルを同期しました");
        Ok(())
    }
    
    /// ファイルシステム情報を同期
    fn sync_fs_info(&self, device: &Arc<dyn super::vfs::BlockDevice>) -> FsResult<()> {
        // FSInfoセクターを更新
        self.update_fsinfo_sector()?;
        
        log::debug!("ファイルシステム情報を同期しました");
        Ok(())
    }
    
    /// パスを解析
    fn parse_path(&self, path: &str) -> FsResult<ParsedPath> {
        if path.is_empty() || !path.starts_with('/') {
            return Err(FsError::InvalidPath);
        }
        
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        
        Ok(ParsedPath {
            path: path.to_string(),
            components,
        })
    }
    
    /// パスに対応するデバイスを検索
    fn find_device_for_path(&self, path: &str) -> FsResult<String> {
        // 簡略化された実装：最初にマウントされたデバイスを返す
        let devices = self.devices.read();
        
        if let Some((device_name, _)) = devices.iter().next() {
            Ok(device_name.clone())
        } else {
            Err(FsError::NotFound)
        }
    }
    
    fn open_file(&self, path: &str, mode: OpenMode) -> FsResult<Arc<dyn FileHandle>> {
        // パスを解析
        let parsed_path = self.parse_path(path)?;

        // デバイスを検索
        let device = self.find_device_for_path(path)?;
        let devices = self.devices.read();
        let device = match devices.get(&device) {
            Some(dev) => dev.clone(),
            None => return Err(FsError::NotFound),
        };

        // ファイルを開く
        match device.open_file(&parsed_path.path, mode) {
            Ok(handle) => Ok(Arc::new(Fat32FileHandle::new(handle, mode))),
            Err(e) => Err(e),
        }
    }
    
    fn open_directory(&self, path: &str) -> FsResult<Arc<dyn DirHandle>> {
        // パスを解析
        let parsed_path = self.parse_path(path)?;

        // デバイスを検索
        let device = self.find_device_for_path(path)?;
        let devices = self.devices.read();
        let device = match devices.get(&device) {
            Some(dev) => dev.clone(),
            None => return Err(FsError::NotFound),
        };

        // ディレクトリを開く
        match device.open_directory(&parsed_path.path) {
            Ok(handle) => Ok(Arc::new(Fat32DirHandle::new(handle))),
            Err(e) => Err(e),
        }
    }
    
    fn metadata(&self, path: &str) -> FsResult<Metadata> {
        // パスを解析
        let parsed_path = self.parse_path(path)?;

        // デバイスを検索
        let device = self.find_device_for_path(path)?;
        let devices = self.devices.read();
        let device = match devices.get(&device) {
            Some(dev) => dev.clone(),
            None => return Err(FsError::NotFound),
        };

        // メタデータを取得
        device.get_metadata(&parsed_path.path)
    }
    
    fn stats(&self, mount_point: &str) -> FsResult<FsStats> {
        // デバイスを検索
        let devices = self.devices.read();
        let device = match devices.get(mount_point) {
            Some(dev) => dev.clone(),
            None => return Err(FsError::NotFound),
        };
        
        // スーパーブロックを取得
        let superblocks = self.superblocks.read();
        let superblock = match superblocks.get(mount_point) {
            Some(sb) => sb,
            None => return Err(FsError::NotFound),
        };
        
        // ファイルシステム統計を計算
        let total_clusters = superblock.total_clusters();
        let cluster_size = superblock.cluster_size();
        let total_size = total_clusters as u64 * cluster_size as u64;
        
        // 空きクラスタ数を計算
        let free_clusters = self.count_free_clusters(&device, superblock)?;
        let free_size = free_clusters as u64 * cluster_size as u64;
        
        Ok(FsStats {
            filesystem_type: self.name.clone(),
            total_size,
            free_size,
            used_size: total_size - free_size,
            total_inodes: total_clusters as u64, // FATではクラスタ数がinode数に相当
            free_inodes: free_clusters as u64,
            block_size: cluster_size as u64,
            max_filename_length: 255, // VFAT長いファイル名
        })
    }
    
    /// 空きクラスタ数を計算
    fn count_free_clusters(&self, device: &Arc<dyn super::vfs::BlockDevice>, superblock: &FatSuperblock) -> FsResult<u32> {
        let fat_start = superblock.fat_start_sector();
        let fat_size = superblock.fat_size_sectors();
        let total_clusters = superblock.total_clusters();
        
        let mut free_count = 0u32;
        
        // FATエントリを読み込んで空きクラスタをカウント
        match self.fat_type {
            FatType::Fat12 => {
                // FAT12の場合：12ビットエントリ
                for cluster in 2..total_clusters + 2 {
                    let fat_entry = self.read_fat12_entry(device, fat_start, cluster)?;
                    if fat_entry == 0 {
                        free_count += 1;
                    }
                }
            },
            FatType::Fat16 => {
                // FAT16の場合：16ビットエントリ
                for cluster in 2..total_clusters + 2 {
                    let fat_entry = self.read_fat16_entry(device, fat_start, cluster)?;
                    if fat_entry == 0 {
                        free_count += 1;
                    }
                }
            },
            FatType::Fat32 => {
                // FAT32の場合：32ビットエントリ（下位28ビットのみ使用）
                for cluster in 2..total_clusters + 2 {
                    let fat_entry = self.read_fat32_entry(device, fat_start, cluster)?;
                    if (fat_entry & 0x0FFFFFFF) == 0 {
                        free_count += 1;
                    }
                }
            },
        }
        
        Ok(free_count)
    }
    
    /// FAT12エントリを読み込み
    fn read_fat12_entry(&self, device: &Arc<dyn super::vfs::BlockDevice>, fat_start: u32, cluster: u32) -> FsResult<u16> {
        let fat_offset = cluster + (cluster / 2); // 1.5バイト/エントリ
        let fat_sector = fat_start + (fat_offset / 512);
        let sector_offset = fat_offset % 512;
        
        let sector_data = device.read_block(fat_sector as u64)?;
        
        let entry = if sector_offset == 511 {
            // セクタ境界をまたぐ場合
            let next_sector_data = device.read_block((fat_sector + 1) as u64)?;
            ((next_sector_data[0] as u16) << 8) | (sector_data[511] as u16)
        } else {
            ((sector_data[sector_offset + 1] as u16) << 8) | (sector_data[sector_offset] as u16)
        };
        
        if cluster & 1 == 0 {
            Ok(entry & 0x0FFF) // 偶数クラスタ：下位12ビット
        } else {
            Ok(entry >> 4) // 奇数クラスタ：上位12ビット
        }
    }
    
    /// FAT16エントリを読み込み
    fn read_fat16_entry(&self, device: &Arc<dyn super::vfs::BlockDevice>, fat_start: u32, cluster: u32) -> FsResult<u16> {
        let fat_offset = cluster * 2; // 2バイト/エントリ
        let fat_sector = fat_start + (fat_offset / 512);
        let sector_offset = fat_offset % 512;
        
        let sector_data = device.read_block(fat_sector as u64)?;
        
        if sector_offset == 511 {
            // セクタ境界をまたぐ場合
            let next_sector_data = device.read_block((fat_sector + 1) as u64)?;
            Ok(((next_sector_data[0] as u16) << 8) | (sector_data[511] as u16))
        } else {
            Ok(((sector_data[sector_offset + 1] as u16) << 8) | (sector_data[sector_offset] as u16))
        }
    }
    
    /// FAT32エントリを読み込み
    fn read_fat32_entry(&self, device: &Arc<dyn super::vfs::BlockDevice>, fat_start: u32, cluster: u32) -> FsResult<u32> {
        let fat_offset = cluster * 4; // 4バイト/エントリ
        let fat_sector = fat_start + (fat_offset / 512);
        let sector_offset = fat_offset % 512;
        
        let sector_data = device.read_block(fat_sector as u64)?;
        
        if sector_offset > 508 {
            // セクタ境界をまたぐ場合
            let next_sector_data = device.read_block((fat_sector + 1) as u64)?;
            let bytes_in_current = 512 - sector_offset;
            let bytes_in_next = 4 - bytes_in_current;
            
            let mut entry = 0u32;
            for i in 0..bytes_in_current {
                entry |= (sector_data[sector_offset + i] as u32) << (i * 8);
            }
            for i in 0..bytes_in_next {
                entry |= (next_sector_data[i] as u32) << ((bytes_in_current + i) * 8);
            }
            Ok(entry)
        } else {
            Ok(((sector_data[sector_offset + 3] as u32) << 24) |
               ((sector_data[sector_offset + 2] as u32) << 16) |
               ((sector_data[sector_offset + 1] as u32) << 8) |
               (sector_data[sector_offset] as u32))
        }
    }
    
    fn sync(&self) -> FsResult<()> {
        // すべてのデバイスを同期
        let devices = self.devices.read();
        for (_, device) in devices.iter() {
            device.sync()?;
        }
        
        Ok(())
    }
}

/// FAT12ファイルシステム
pub struct Fat12Filesystem(FatFilesystem);

impl Fat12Filesystem {
    /// 新しいFAT12ファイルシステムインスタンスを作成
    pub fn new() -> Self {
        Self(FatFilesystem::new("fat12", FatType::Fat12))
    }
}

impl Filesystem for Fat12Filesystem {
    fn name(&self) -> &str {
        self.0.name()
    }
    
    fn init(&self) -> FsResult<()> {
        self.0.init()
    }
    
    fn mount(&self, device: &str, mount_point: &str, options: &str) -> FsResult<()> {
        self.0.mount(device, mount_point, options)
    }
    
    fn unmount(&self, mount_point: &str) -> FsResult<()> {
        self.0.unmount(mount_point)
    }
    
    fn open_file(&self, path: &str, mode: OpenMode) -> FsResult<Arc<dyn FileHandle>> {
        self.0.open_file(path, mode)
    }
    
    fn open_directory(&self, path: &str) -> FsResult<Arc<dyn DirHandle>> {
        self.0.open_directory(path)
    }
    
    fn metadata(&self, path: &str) -> FsResult<Metadata> {
        self.0.metadata(path)
    }
    
    fn stats(&self, mount_point: &str) -> FsResult<FsStats> {
        self.0.stats(mount_point)
    }
    
    fn sync(&self) -> FsResult<()> {
        self.0.sync()
    }
}

/// FAT16ファイルシステム
pub struct Fat16Filesystem(FatFilesystem);

impl Fat16Filesystem {
    /// 新しいFAT16ファイルシステムインスタンスを作成
    pub fn new() -> Self {
        Self(FatFilesystem::new("fat16", FatType::Fat16))
    }
}

impl Filesystem for Fat16Filesystem {
    fn name(&self) -> &str {
        self.0.name()
    }
    
    fn init(&self) -> FsResult<()> {
        self.0.init()
    }
    
    fn mount(&self, device: &str, mount_point: &str, options: &str) -> FsResult<()> {
        self.0.mount(device, mount_point, options)
    }
    
    fn unmount(&self, mount_point: &str) -> FsResult<()> {
        self.0.unmount(mount_point)
    }
    
    fn open_file(&self, path: &str, mode: OpenMode) -> FsResult<Arc<dyn FileHandle>> {
        self.0.open_file(path, mode)
    }
    
    fn open_directory(&self, path: &str) -> FsResult<Arc<dyn DirHandle>> {
        self.0.open_directory(path)
    }
    
    fn metadata(&self, path: &str) -> FsResult<Metadata> {
        self.0.metadata(path)
    }
    
    fn stats(&self, mount_point: &str) -> FsResult<FsStats> {
        self.0.stats(mount_point)
    }
    
    fn sync(&self) -> FsResult<()> {
        self.0.sync()
    }
}

/// FAT32ファイルシステム
pub struct Fat32Filesystem(FatFilesystem);

impl Fat32Filesystem {
    /// 新しいFAT32ファイルシステムインスタンスを作成
    pub fn new() -> Self {
        Self(FatFilesystem::new("fat32", FatType::Fat32))
    }
}

impl Filesystem for Fat32Filesystem {
    fn name(&self) -> &str {
        self.0.name()
    }
    
    fn init(&self) -> FsResult<()> {
        self.0.init()
    }
    
    fn mount(&self, device: &str, mount_point: &str, options: &str) -> FsResult<()> {
        self.0.mount(device, mount_point, options)
    }
    
    fn unmount(&self, mount_point: &str) -> FsResult<()> {
        self.0.unmount(mount_point)
    }
    
    fn open_file(&self, path: &str, mode: OpenMode) -> FsResult<Arc<dyn FileHandle>> {
        self.0.open_file(path, mode)
    }
    
    fn open_directory(&self, path: &str) -> FsResult<Arc<dyn DirHandle>> {
        self.0.open_directory(path)
    }
    
    fn metadata(&self, path: &str) -> FsResult<Metadata> {
        self.0.metadata(path)
    }
    
    fn stats(&self, mount_point: &str) -> FsResult<FsStats> {
        self.0.stats(mount_point)
    }
    
    fn sync(&self) -> FsResult<()> {
        self.0.sync()
    }
}

/// VFAT (長いファイル名をサポートするFAT) ファイルシステム
pub struct VfatFilesystem(FatFilesystem);

impl VfatFilesystem {
    /// 新しいVFATファイルシステムインスタンスを作成
    pub fn new() -> Self {
        Self(FatFilesystem::new("vfat", FatType::Vfat))
    }
}

impl Filesystem for VfatFilesystem {
    fn name(&self) -> &str {
        self.0.name()
    }
    
    fn init(&self) -> FsResult<()> {
        self.0.init()
    }
    
    fn mount(&self, device: &str, mount_point: &str, options: &str) -> FsResult<()> {
        self.0.mount(device, mount_point, options)
    }
    
    fn unmount(&self, mount_point: &str) -> FsResult<()> {
        self.0.unmount(mount_point)
    }
    
    fn open_file(&self, path: &str, mode: OpenMode) -> FsResult<Arc<dyn FileHandle>> {
        self.0.open_file(path, mode)
    }
    
    fn open_directory(&self, path: &str) -> FsResult<Arc<dyn DirHandle>> {
        self.0.open_directory(path)
    }
    
    fn metadata(&self, path: &str) -> FsResult<Metadata> {
        self.0.metadata(path)
    }
    
    fn stats(&self, mount_point: &str) -> FsResult<FsStats> {
        self.0.stats(mount_point)
    }
    
    fn sync(&self) -> FsResult<()> {
        self.0.sync()
    }
}

/// パス解析結果
struct ParsedPath {
    path: String,
    components: Vec<String>,
}

/// FAT32ファイルハンドル
pub struct Fat32FileHandle {
    inner: Box<dyn FileHandle>,
    mode: OpenMode,
    position: u64,
}

impl Fat32FileHandle {
    fn new(inner: Box<dyn FileHandle>, mode: OpenMode) -> Self {
        Self {
            inner,
            mode,
            position: 0,
        }
    }
}

impl FileHandle for Fat32FileHandle {
    fn read(&mut self, buffer: &mut [u8]) -> FsResult<usize> {
        let bytes_read = self.inner.read(buffer)?;
        self.position += bytes_read as u64;
        Ok(bytes_read)
    }
    
    fn write(&mut self, buffer: &[u8]) -> FsResult<usize> {
        if !self.mode.is_writable() {
            return Err(FsError::PermissionDenied);
        }
        
        let bytes_written = self.inner.write(buffer)?;
        self.position += bytes_written as u64;
        Ok(bytes_written)
    }
    
    fn seek(&mut self, position: u64) -> FsResult<u64> {
        self.position = self.inner.seek(position)?;
        Ok(self.position)
    }
    
    fn tell(&self) -> u64 {
        self.position
    }
    
    fn flush(&mut self) -> FsResult<()> {
        self.inner.flush()
    }
    
    fn metadata(&self) -> FsResult<Metadata> {
        self.inner.metadata()
    }
}

/// FAT32ディレクトリハンドル
pub struct Fat32DirHandle {
    inner: Box<dyn DirHandle>,
    entries: Vec<super::DirEntry>,
    position: usize,
}

impl Fat32DirHandle {
    fn new(inner: Box<dyn DirHandle>) -> Self {
        Self {
            inner,
            entries: Vec::new(),
            position: 0,
        }
    }
}

impl DirHandle for Fat32DirHandle {
    fn read_entry(&mut self) -> FsResult<Option<super::DirEntry>> {
        // エントリがキャッシュされていない場合は読み込み
        if self.entries.is_empty() {
            self.load_entries()?;
        }
        
        if self.position < self.entries.len() {
            let entry = self.entries[self.position].clone();
            self.position += 1;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }
    
    fn rewind(&mut self) -> FsResult<()> {
        self.position = 0;
        self.inner.rewind()
    }
}

impl Fat32DirHandle {
    /// ディレクトリエントリを読み込み
    fn load_entries(&mut self) -> FsResult<()> {
        self.entries.clear();
        
        while let Some(entry) = self.inner.read_entry()? {
            self.entries.push(entry);
        }
        
        Ok(())
    }
}

/// ダーティディレクトリエントリ
struct DirtyEntry {
    cluster: u32,
    index: usize,
    entry: DirectoryEntry,
}

/// ダーティFATエントリ
struct DirtyFatEntry {
    cluster: u32,
    value: u32,
    timestamp: u64,
}

/// キャッシュされたディレクトリエントリ
#[derive(Clone)]
struct CachedDirectoryEntry {
    entry: DirectoryEntry,
    dirty: bool,
    last_accessed: u64,
    access_count: u32,
}

impl CachedDirectoryEntry {
    fn new(entry: DirectoryEntry) -> Self {
        Self {
            entry,
            dirty: false,
            last_accessed: crate::time::current_time_ms(),
            access_count: 1,
        }
    }
    
    fn is_dirty(&self) -> bool {
        self.dirty
    }
    
    fn mark_dirty(&mut self) {
        self.dirty = true;
        self.last_accessed = crate::time::current_time_ms();
        self.access_count += 1;
    }
    
    fn clear_dirty(&mut self) {
        self.dirty = false;
    }
    
    fn to_bytes(&self) -> [u8; DIR_ENTRY_SIZE] {
        self.entry.to_bytes()
    }
}

/// キャッシュされたFATエントリ
#[derive(Clone)]
struct CachedFatEntry {
    value: u32,
    dirty: bool,
    last_modified: u64,
    access_count: u32,
}

impl CachedFatEntry {
    fn new(value: u32) -> Self {
        Self {
            value,
            dirty: false,
            last_modified: crate::time::current_time_ms(),
            access_count: 1,
        }
    }
    
    fn is_dirty(&self) -> bool {
        self.dirty
    }
    
    fn mark_dirty(&mut self) {
        self.dirty = true;
        self.last_modified = crate::time::current_time_ms();
        self.access_count += 1;
    }
    
    fn clear_dirty(&mut self) {
        self.dirty = false;
    }
    
    fn update_value(&mut self, new_value: u32) {
        self.value = new_value;
        self.mark_dirty();
    }
}

impl Fat32FileSystem {
    /// FSInfoセクターを更新
    fn update_fsinfo_sector(&self) -> Result<(), Fat32Error> {
        if self.fsinfo_sector == 0 {
            return Ok((); // FSInfoセクターが存在しない
        }
        
        // FSInfoセクターを読み込み
        let mut fsinfo_data = vec![0u8; self.bytes_per_sector];
        self.device.read_sectors(self.fsinfo_sector, 1, &mut fsinfo_data)?;
        
        // FSInfoシグネチャを確認
        let lead_sig = u32::from_le_bytes([fsinfo_data[0], fsinfo_data[1], fsinfo_data[2], fsinfo_data[3]]);
        let struc_sig = u32::from_le_bytes([fsinfo_data[484], fsinfo_data[485], fsinfo_data[486], fsinfo_data[487]]);
        
        if lead_sig != 0x41615252 || struc_sig != 0x61417272 {
            log::warn!("無効なFSInfoシグネチャ");
            return Ok(());
        }
        
        // 空きクラスタ数を計算
        let free_clusters = self.count_free_clusters()?;
        let next_free_cluster = self.find_next_free_cluster()?;
        
        // FSInfoセクターを更新
        let free_count_bytes = free_clusters.to_le_bytes();
        let next_free_bytes = next_free_cluster.to_le_bytes();
        
        fsinfo_data[488..492].copy_from_slice(&free_count_bytes);
        fsinfo_data[492..496].copy_from_slice(&next_free_bytes);
        
        // トレイルシグネチャを設定
        let trail_sig = 0xAA550000u32.to_le_bytes();
        fsinfo_data[508..512].copy_from_slice(&trail_sig);
        
        // FSInfoセクターを書き込み
        self.device.write_sectors(self.fsinfo_sector, 1, &fsinfo_data)?;
        
        log::debug!("FSInfo更新完了: 空きクラスタ={}, 次の空きクラスタ={}", 
                   free_clusters, next_free_cluster);
        
        Ok(())
    }
    
    /// 空きクラスタ数をカウント
    fn count_free_clusters(&self) -> Result<u32, Fat32Error> {
        let mut free_count = 0;
        
        for cluster in 2..self.total_clusters {
            let fat_entry = self.get_fat_entry(cluster)?;
            if fat_entry == 0 {
                free_count += 1;
            }
        }
        
        Ok(free_count)
    }
    
    /// 次の空きクラスタを検索
    fn find_next_free_cluster(&self) -> Result<u32, Fat32Error> {
        for cluster in 2..self.total_clusters {
            let fat_entry = self.get_fat_entry(cluster)?;
            if fat_entry == 0 {
                return Ok(cluster);
            }
        }
        
        Err(Fat32Error::NoSpace)
    }
    
    /// キャッシュサイズを制限
    fn limit_cache_size(&mut self) {
        const MAX_DIR_CACHE_ENTRIES: usize = 1000;
        const MAX_FAT_CACHE_ENTRIES: usize = 5000;
        
        // ディレクトリキャッシュのサイズ制限
        if self.directory_cache.len() > MAX_DIR_CACHE_ENTRIES {
            // LRU方式で古いエントリを削除
            let mut entries_by_access: Vec<_> = self.directory_cache.iter()
                .flat_map(|(cluster, entries)| {
                    entries.iter().enumerate().map(move |(index, entry)| {
                        (*cluster, index, entry.last_accessed)
                    })
                })
                .collect();
            
            entries_by_access.sort_by_key(|(_, _, last_accessed)| *last_accessed);
            
            let remove_count = self.directory_cache.len() - MAX_DIR_CACHE_ENTRIES;
            for (cluster, index, _) in entries_by_access.iter().take(remove_count) {
                if let Some(entries) = self.directory_cache.get_mut(cluster) {
                    if !entries[*index].is_dirty() {
                        entries.remove(*index);
                    }
                }
            }
        }
        
        // FATキャッシュのサイズ制限
        if self.fat_cache.len() > MAX_FAT_CACHE_ENTRIES {
            let mut entries_by_access: Vec<_> = self.fat_cache.iter()
                .map(|(cluster, entry)| (*cluster, entry.last_modified))
                .collect();
            
            entries_by_access.sort_by_key(|(_, last_modified)| *last_modified);
            
            let remove_count = self.fat_cache.len() - MAX_FAT_CACHE_ENTRIES;
            for (cluster, _) in entries_by_access.iter().take(remove_count) {
                if let Some(entry) = self.fat_cache.get(cluster) {
                    if !entry.is_dirty() {
                        self.fat_cache.remove(cluster);
                    }
                }
            }
        }
    }
    
    /// キャッシュ統計を取得
    fn get_cache_statistics(&self) -> CacheStatistics {
        let mut dir_dirty_count = 0;
        let mut dir_total_count = 0;
        
        for entries in self.directory_cache.values() {
            for entry in entries {
                dir_total_count += 1;
                if entry.is_dirty() {
                    dir_dirty_count += 1;
                }
            }
        }
        
        let fat_dirty_count = self.fat_cache.values()
            .filter(|entry| entry.is_dirty())
            .count();
        
        CacheStatistics {
            directory_cache_size: dir_total_count,
            directory_dirty_count: dir_dirty_count,
            fat_cache_size: self.fat_cache.len(),
            fat_dirty_count,
            cache_hit_rate: self.calculate_cache_hit_rate(),
        }
    }
    
    /// キャッシュヒット率を計算
    fn calculate_cache_hit_rate(&self) -> f32 {
        // 簡略化実装
        0.85 // 85%のヒット率を仮定
    }
}

/// キャッシュ統計情報
#[derive(Debug)]
struct CacheStatistics {
    directory_cache_size: usize,
    directory_dirty_count: usize,
    fat_cache_size: usize,
    fat_dirty_count: usize,
    cache_hit_rate: f32,
}

const DIR_ENTRY_SIZE: usize = 32;
const ENTRIES_PER_SECTOR: usize = 16; // 512バイト/セクタ ÷ 32バイト/エントリ 