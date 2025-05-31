// グラフィックモジュール
//
// ブート時のグラフィックスモード設定とフレームバッファ情報

use alloc::vec::Vec;
use core::fmt;

/// ピクセルフォーマット
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// RGBフォーマット（各色8ビット）
    RGB,
    /// BGRフォーマット（各色8ビット）
    BGR,
    /// UEFIグラフィック出力プロトコル用
    PixelBltOnly,
    /// その他のフォーマット
    Other(u32),
}

impl PixelFormat {
    /// UEFIピクセルフォーマットから変換
    pub fn from_uefi(format: u32) -> Self {
        match format {
            0 => Self::RGB,
            1 => Self::BGR,
            2 => Self::PixelBltOnly,
            other => Self::Other(other),
        }
    }
    
    /// ピクセルあたりのバイト数を取得
    pub fn bytes_per_pixel(&self) -> usize {
        match self {
            Self::RGB | Self::BGR => 4, // 通常は32ビット（4バイト）RGBA
            Self::PixelBltOnly => 0,    // メモリマップされたフレームバッファなし
            Self::Other(_) => 4,        // デフォルト値
        }
    }
    
    /// このフォーマットが直接メモリマップされたフレームバッファを持つか
    pub fn has_framebuffer(&self) -> bool {
        *self != Self::PixelBltOnly
    }
    
    /// 色の描画方法を取得（ARGB8888形式の色値から各形式への変換）
    pub fn convert_color(&self, argb: u32) -> u32 {
        match self {
            Self::RGB => {
                // ARGB -> RGBA (リトルエンディアンでのメモリレイアウト)
                let a = (argb >> 24) & 0xFF;
                let r = (argb >> 16) & 0xFF;
                let g = (argb >> 8) & 0xFF;
                let b = argb & 0xFF;
                (a << 24) | (b << 16) | (g << 8) | r
            },
            Self::BGR => {
                // ARGB -> BGRA (リトルエンディアンでのメモリレイアウト)
                let a = (argb >> 24) & 0xFF;
                let r = (argb >> 16) & 0xFF;
                let g = (argb >> 8) & 0xFF;
                let b = argb & 0xFF;
                (a << 24) | (r << 16) | (g << 8) | b
            },
            _ => argb, // その他の形式はそのまま
        }
    }
}

/// フレームバッファ情報
#[derive(Clone)]
pub struct FramebufferInfo {
    /// フレームバッファの物理アドレス
    pub physical_address: usize,
    /// 仮想アドレス（カーネルにマップ後）
    pub virtual_address: Option<usize>,
    /// 水平解像度
    pub width: usize,
    /// 垂直解像度
    pub height: usize,
    /// ピクセルあたりのバイト数
    pub bytes_per_pixel: usize,
    /// 1行あたりのバイト数（ストライド）
    pub stride: usize,
    /// ピクセルフォーマット
    pub pixel_format: PixelFormat,
    /// 総サイズ（バイト）
    pub size: usize,
}

impl FramebufferInfo {
    /// 新しいフレームバッファ情報を作成
    pub fn new(
        physical_address: usize,
        width: usize,
        height: usize,
        pixel_format: PixelFormat,
        stride: Option<usize>,
    ) -> Self {
        let bytes_per_pixel = pixel_format.bytes_per_pixel();
        
        // ストライドが指定されていない場合は、幅 * バイト数を使用
        let stride = stride.unwrap_or(width * bytes_per_pixel);
        
        // 総サイズを計算
        let size = height * stride;
        
        Self {
            physical_address,
            virtual_address: None,
            width,
            height,
            bytes_per_pixel,
            stride,
            pixel_format,
            size,
        }
    }
    
    /// このフレームバッファに仮想アドレスを設定
    pub fn set_virtual_address(&mut self, virtual_address: usize) {
        self.virtual_address = Some(virtual_address);
    }
    
    /// 指定された位置のピクセルオフセットを計算
    pub fn pixel_offset(&self, x: usize, y: usize) -> Option<usize> {
        if x >= self.width || y >= self.height {
            return None;
        }
        
        Some(y * self.stride + x * self.bytes_per_pixel)
    }
    
    /// ピクセルを設定（ARGBカラー）
    pub fn set_pixel(&self, x: usize, y: usize, argb: u32) -> Result<(), &'static str> {
        // まず仮想アドレスを確認
        let vaddr = self.virtual_address.ok_or("フレームバッファが仮想メモリにマップされていません")?;
        
        // ピクセルオフセットを計算
        let offset = self.pixel_offset(x, y).ok_or("座標が範囲外です")?;
        
        // ピクセル値を変換
        let color = self.pixel_format.convert_color(argb);
        
        // メモリに書き込み
        unsafe {
            *(vaddr as *mut u32).add(offset / 4) = color;
        }
        
        Ok(())
    }
    
    /// 画面をクリア（単色で塗りつぶし）
    pub fn clear(&self, color: u32) -> Result<(), &'static str> {
        // 仮想アドレスを確認
        let vaddr = self.virtual_address.ok_or("フレームバッファが仮想メモリにマップされていません")?;
        
        // 変換された色値
        let color = self.pixel_format.convert_color(color);
        
        // 幅がストライドと等しい場合（パディングなし）は一括で塗りつぶし
        if self.width * self.bytes_per_pixel == self.stride {
            let pixel_count = self.width * self.height;
            let ptr = vaddr as *mut u32;
            
            unsafe {
                for i in 0..pixel_count {
                    *ptr.add(i) = color;
                }
            }
        } else {
            // パディングがある場合は行ごとに処理
            for y in 0..self.height {
                let row_start = vaddr + y * self.stride;
                let ptr = row_start as *mut u32;
                
                unsafe {
                    for x in 0..self.width {
                        *ptr.add(x) = color;
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// 矩形を描画
    pub fn draw_rect(&self, x: usize, y: usize, width: usize, height: usize, color: u32) -> Result<(), &'static str> {
        if x + width > self.width || y + height > self.height {
            return Err("矩形が画面範囲外です");
        }
        
        let vaddr = self.virtual_address.ok_or("フレームバッファが仮想メモリにマップされていません")?;
        let color = self.pixel_format.convert_color(color);
        
        for cy in y..y+height {
            let row_start = vaddr + cy * self.stride;
            let ptr = row_start as *mut u32;
            
            unsafe {
                for cx in x..x+width {
                    *ptr.add(cx) = color;
                }
            }
        }
        
        Ok(())
    }
    
    /// UEFIグラフィックス出力プロトコルからフレームバッファ情報を作成
    pub fn from_uefi_gop(
        address: u64,
        width: u32,
        height: u32,
        stride: u32,
        format: u32,
    ) -> Self {
        let pixel_format = PixelFormat::from_uefi(format);
        Self::new(
            address as usize,
            width as usize,
            height as usize,
            pixel_format,
            Some(stride as usize),
        )
    }
}

impl fmt::Debug for FramebufferInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FramebufferInfo {{ physical: {:#x}, virtual: {:?}, {}x{}, format: {:?}, stride: {}, size: {} KiB }}",
            self.physical_address,
            self.virtual_address.map(|addr| format!("{:#x}", addr)).unwrap_or_else(|| "None".to_string()),
            self.width,
            self.height,
            self.pixel_format,
            self.stride,
            self.size / 1024
        )
    }
}

/// グラフィックモード設定
pub struct GraphicsMode {
    /// 水平解像度
    pub width: usize,
    /// 垂直解像度
    pub height: usize,
    /// ピクセルフォーマット
    pub pixel_format: PixelFormat,
}

impl GraphicsMode {
    /// 新しいグラフィックモードを作成
    pub fn new(width: usize, height: usize, pixel_format: PixelFormat) -> Self {
        Self {
            width,
            height,
            pixel_format,
        }
    }
    
    /// デフォルトのグラフィックモードを取得（一般的なHD解像度）
    pub fn default() -> Self {
        Self::new(1280, 720, PixelFormat::RGB)
    }
}

/// グラフィックモードを設定（UEFI用）
pub fn set_graphics_mode_uefi(
    gop: &mut dyn uefi_graphics::GraphicsOutput,
    preferred_mode: Option<GraphicsMode>,
) -> Result<FramebufferInfo, &'static str> {
    // 利用可能なモードを列挙
    let modes: Vec<_> = gop.modes().collect();
    
    // 設定すべきモードを決定
    let target_mode = if let Some(preferred) = preferred_mode {
        // 希望のモードに近いものを探す
        modes.iter().min_by_key(|mode| {
            let info = mode.info();
            let diff_width = (info.width as isize - preferred.width as isize).abs();
            let diff_height = (info.height as isize - preferred.height as isize).abs();
            diff_width + diff_height
        })
    } else {
        // モードが指定されていない場合は、最大解像度または現在のモードを使用
        modes.iter().max_by_key(|mode| {
            let info = mode.info();
            info.width * info.height
        })
    };
    
    let mode = target_mode.ok_or("利用可能なグラフィックモードがありません")?;
    
    // モードを設定
    gop.set_mode(mode).map_err(|_| "グラフィックモードの設定に失敗しました")?;
    
    // 現在のモード情報を取得
    let info = gop.current_mode_info();
    let fb = gop.frame_buffer();
    
    // フレームバッファ情報を作成
    Ok(FramebufferInfo::from_uefi_gop(
        fb.address() as u64,
        info.width,
        info.height,
        info.stride,
        info.format as u32,
    ))
}

/// グラフィックスサブシステムの初期化（汎用）
pub fn init_graphics(framebuffer: &mut FramebufferInfo) -> Result<(), &'static str> {
    // フレームバッファを仮想メモリにマップ
    let memory_manager = crate::core::memory::MemoryManager::instance();
    
    // フレームバッファをマップ
    let vaddr = memory_manager.map_physical_memory(
        framebuffer.physical_address,
        framebuffer.size,
        crate::core::memory::MemoryPermission::READ | crate::core::memory::MemoryPermission::WRITE,
    )?;
    
    // 仮想アドレスを設定
    framebuffer.set_virtual_address(vaddr);
    
    // 画面を黒でクリア
    framebuffer.clear(0x000000)?;
    
    Ok(())
} 