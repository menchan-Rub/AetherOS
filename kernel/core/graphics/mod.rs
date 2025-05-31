//! AetherOS 次世代グラフィックスサブシステム
//!
//! ハードウェアアクセラレーション対応の超高速グラフィックスエンジン

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

pub mod compositor;
pub mod render;
pub mod acceleration;
pub mod display;
pub mod window;
pub mod font;
pub mod color;
pub mod buffer;
pub mod adapter;
pub mod vulkan;
pub mod opengl;
pub mod directx;
pub mod metal;

/// 色を表す構造体
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    pub const TRANSPARENT: Color = Color { r: 0, g: 0, b: 0, a: 0 };
    pub const BLACK: Color = Color { r: 0, g: 0, b: 0, a: 255 };
    pub const WHITE: Color = Color { r: 255, g: 255, b: 255, a: 255 };
    pub const RED: Color = Color { r: 255, g: 0, b: 0, a: 255 };
    pub const GREEN: Color = Color { r: 0, g: 255, b: 0, a: 255 };
    pub const BLUE: Color = Color { r: 0, g: 0, b: 255, a: 255 };
    
    pub fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Color { r, g, b, a }
    }
    
    pub fn rgb(r: u8, g: u8, b: u8) -> Self {
        Color { r, g, b, a: 255 }
    }
    
    pub fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Color { r, g, b, a }
    }
    
    pub fn from_rgba32(rgba: u32) -> Self {
        let r = ((rgba >> 24) & 0xFF) as u8;
        let g = ((rgba >> 16) & 0xFF) as u8;
        let b = ((rgba >> 8) & 0xFF) as u8;
        let a = (rgba & 0xFF) as u8;
        
        Color { r, g, b, a }
    }
    
    pub fn to_rgba32(&self) -> u32 {
        ((self.r as u32) << 24) | ((self.g as u32) << 16) | ((self.b as u32) << 8) | (self.a as u32)
    }
    
    pub fn blend(&self, other: &Color) -> Self {
        if other.a == 0 {
            return *self;
        }
        
        if other.a == 255 || self.a == 0 {
            return *other;
        }
        
        let a_out = other.a as f32 / 255.0 + self.a as f32 / 255.0 * (1.0 - other.a as f32 / 255.0);
        let r_out = (other.r as f32 * other.a as f32 / 255.0 + 
                     self.r as f32 * self.a as f32 / 255.0 * (1.0 - other.a as f32 / 255.0)) / a_out;
        let g_out = (other.g as f32 * other.a as f32 / 255.0 + 
                     self.g as f32 * self.a as f32 / 255.0 * (1.0 - other.a as f32 / 255.0)) / a_out;
        let b_out = (other.b as f32 * other.a as f32 / 255.0 + 
                     self.b as f32 * self.a as f32 / 255.0 * (1.0 - other.a as f32 / 255.0)) / a_out;
        
        Color {
            r: r_out as u8,
            g: g_out as u8,
            b: b_out as u8,
            a: (a_out * 255.0) as u8,
        }
    }
}

/// 点の座標を表す構造体
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl Point {
    pub fn new(x: i32, y: i32) -> Self {
        Point { x, y }
    }
    
    pub fn offset(&self, dx: i32, dy: i32) -> Self {
        Point { x: self.x + dx, y: self.y + dy }
    }
    
    pub fn distance_squared(&self, other: &Point) -> i32 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        dx * dx + dy * dy
    }
}

/// 矩形を表す構造体
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Rect { x, y, width, height }
    }
    
    pub fn from_points(p1: Point, p2: Point) -> Self {
        let x = core::cmp::min(p1.x, p2.x);
        let y = core::cmp::min(p1.y, p2.y);
        let width = (core::cmp::max(p1.x, p2.x) - x) as u32;
        let height = (core::cmp::max(p1.y, p2.y) - y) as u32;
        
        Rect { x, y, width, height }
    }
    
    pub fn contains(&self, point: Point) -> bool {
        point.x >= self.x && point.x < self.x + self.width as i32 &&
        point.y >= self.y && point.y < self.y + self.height as i32
    }
    
    pub fn intersect(&self, other: &Rect) -> Option<Rect> {
        let x1 = core::cmp::max(self.x, other.x);
        let y1 = core::cmp::max(self.y, other.y);
        let x2 = core::cmp::min(self.x + self.width as i32, other.x + other.width as i32);
        let y2 = core::cmp::min(self.y + self.height as i32, other.y + other.height as i32);
        
        if x1 < x2 && y1 < y2 {
            Some(Rect {
                x: x1,
                y: y1,
                width: (x2 - x1) as u32,
                height: (y2 - y1) as u32,
            })
        } else {
            None
        }
    }
    
    pub fn union(&self, other: &Rect) -> Rect {
        let x1 = core::cmp::min(self.x, other.x);
        let y1 = core::cmp::min(self.y, other.y);
        let x2 = core::cmp::max(self.x + self.width as i32, other.x + other.width as i32);
        let y2 = core::cmp::max(self.y + self.height as i32, other.y + other.height as i32);
        
        Rect {
            x: x1,
            y: y1,
            width: (x2 - x1) as u32,
            height: (y2 - y1) as u32,
        }
    }
    
    pub fn offset(&self, dx: i32, dy: i32) -> Rect {
        Rect {
            x: self.x + dx,
            y: self.y + dy,
            width: self.width,
            height: self.height,
        }
    }
    
    pub fn area(&self) -> u32 {
        self.width * self.height
    }
}

/// ピクセルフォーマット
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    RGB888,
    RGBA8888,
    BGRA8888,
    RGB565,
    GRAY8,
    ALPHA8,
    YUYV,
    NV12,
    NV21,
    Custom(u32),
}

/// グラフィックエラー
#[derive(Debug)]
pub enum GraphicsError {
    DeviceNotFound,
    DeviceNotReady,
    OutOfMemory,
    InvalidParameter,
    UnsupportedOperation,
    RenderingError,
    DisplayError,
    ShaderError,
    BufferError,
    Other(String),
}

impl fmt::Display for GraphicsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GraphicsError::DeviceNotFound => write!(f, "グラフィックデバイスが見つかりません"),
            GraphicsError::DeviceNotReady => write!(f, "グラフィックデバイスが準備できていません"),
            GraphicsError::OutOfMemory => write!(f, "メモリ不足です"),
            GraphicsError::InvalidParameter => write!(f, "無効なパラメータです"),
            GraphicsError::UnsupportedOperation => write!(f, "サポートされていない操作です"),
            GraphicsError::RenderingError => write!(f, "レンダリングエラーが発生しました"),
            GraphicsError::DisplayError => write!(f, "ディスプレイエラーが発生しました"),
            GraphicsError::ShaderError => write!(f, "シェーダーエラーが発生しました"),
            GraphicsError::BufferError => write!(f, "バッファエラーが発生しました"),
            GraphicsError::Other(msg) => write!(f, "その他のグラフィックエラー: {}", msg),
        }
    }
}

pub type GraphicsResult<T> = Result<T, GraphicsError>;

/// フレームバッファ
pub struct FrameBuffer {
    pub width: u32,
    pub height: u32,
    pub format: PixelFormat,
    pub stride: u32,
    pub data: Box<[u8]>,
    pub dma_addr: Option<u64>,
}

impl FrameBuffer {
    pub fn new(width: u32, height: u32, format: PixelFormat) -> GraphicsResult<Self> {
        let bytes_per_pixel = match format {
            PixelFormat::RGB888 => 3,
            PixelFormat::RGBA8888 | PixelFormat::BGRA8888 => 4,
            PixelFormat::RGB565 => 2,
            PixelFormat::GRAY8 | PixelFormat::ALPHA8 => 1,
            PixelFormat::YUYV => 2,
            PixelFormat::NV12 | PixelFormat::NV21 => 2, // 平均
            PixelFormat::Custom(_) => return Err(GraphicsError::UnsupportedOperation),
        };
        
        let stride = width * bytes_per_pixel;
        let size = stride * height;
        
        let data = vec![0u8; size as usize].into_boxed_slice();
        
        Ok(FrameBuffer {
            width,
            height,
            format,
            stride,
            data,
            dma_addr: None,
        })
    }
    
    pub fn clear(&mut self, color: Color) {
        match self.format {
            PixelFormat::RGBA8888 => {
                for y in 0..self.height {
                    for x in 0..self.width {
                        let offset = (y * self.stride + x * 4) as usize;
                        self.data[offset] = color.r;
                        self.data[offset + 1] = color.g;
                        self.data[offset + 2] = color.b;
                        self.data[offset + 3] = color.a;
                    }
                }
            }
            PixelFormat::BGRA8888 => {
                for y in 0..self.height {
                    for x in 0..self.width {
                        let offset = (y * self.stride + x * 4) as usize;
                        self.data[offset] = color.b;
                        self.data[offset + 1] = color.g;
                        self.data[offset + 2] = color.r;
                        self.data[offset + 3] = color.a;
                    }
                }
            }
            // 他のフォーマットも実装
            _ => {}
        }
    }
    
    pub fn draw_pixel(&mut self, point: Point, color: Color) {
        if point.x < 0 || point.y < 0 || point.x >= self.width as i32 || point.y >= self.height as i32 {
            return;
        }
        
        match self.format {
            PixelFormat::RGBA8888 => {
                let offset = (point.y as u32 * self.stride + point.x as u32 * 4) as usize;
                self.data[offset] = color.r;
                self.data[offset + 1] = color.g;
                self.data[offset + 2] = color.b;
                self.data[offset + 3] = color.a;
            }
            PixelFormat::BGRA8888 => {
                let offset = (point.y as u32 * self.stride + point.x as u32 * 4) as usize;
                self.data[offset] = color.b;
                self.data[offset + 1] = color.g;
                self.data[offset + 2] = color.r;
                self.data[offset + 3] = color.a;
            }
            // 他のフォーマットも実装
            _ => {}
        }
    }
    
    pub fn draw_line(&mut self, start: Point, end: Point, color: Color) {
        // ブレゼンハムのアルゴリズムによる描画
        let mut x = start.x;
        let mut y = start.y;
        
        let dx = (end.x - start.x).abs();
        let dy = (end.y - start.y).abs();
        
        let sx = if start.x < end.x { 1 } else { -1 };
        let sy = if start.y < end.y { 1 } else { -1 };
        
        let mut err = dx - dy;
        
        loop {
            self.draw_pixel(Point::new(x, y), color);
            
            if x == end.x && y == end.y {
                break;
            }
            
            let e2 = 2 * err;
            
            if e2 > -dy {
                err -= dy;
                x += sx;
            }
            
            if e2 < dx {
                err += dx;
                y += sy;
            }
        }
    }
    
    pub fn draw_rect(&mut self, rect: Rect, color: Color, fill: bool) {
        if fill {
            for y in rect.y.max(0)..(rect.y + rect.height as i32).min(self.height as i32) {
                for x in rect.x.max(0)..(rect.x + rect.width as i32).min(self.width as i32) {
                    self.draw_pixel(Point::new(x, y), color);
                }
            }
        } else {
            let top_left = Point::new(rect.x, rect.y);
            let top_right = Point::new(rect.x + rect.width as i32 - 1, rect.y);
            let bottom_left = Point::new(rect.x, rect.y + rect.height as i32 - 1);
            let bottom_right = Point::new(rect.x + rect.width as i32 - 1, rect.y + rect.height as i32 - 1);
            
            self.draw_line(top_left, top_right, color);
            self.draw_line(top_right, bottom_right, color);
            self.draw_line(bottom_right, bottom_left, color);
            self.draw_line(bottom_left, top_left, color);
        }
    }
    
    pub fn blit(&mut self, src: &FrameBuffer, src_rect: Rect, dst_point: Point) -> GraphicsResult<()> {
        // 異なるフォーマット間のブリットは簡略化のためサポートしない
        if self.format != src.format {
            return Err(GraphicsError::UnsupportedOperation);
        }
        
        let bytes_per_pixel = match self.format {
            PixelFormat::RGB888 => 3,
            PixelFormat::RGBA8888 | PixelFormat::BGRA8888 => 4,
            PixelFormat::RGB565 => 2,
            PixelFormat::GRAY8 | PixelFormat::ALPHA8 => 1,
            PixelFormat::YUYV => 2,
            PixelFormat::NV12 | PixelFormat::NV21 => 2, // 平均
            PixelFormat::Custom(_) => return Err(GraphicsError::UnsupportedOperation),
        };
        
        let dst_rect = Rect::new(
            dst_point.x,
            dst_point.y,
            src_rect.width,
            src_rect.height
        );
        
        // クリッピング
        let clip_rect = Rect::new(0, 0, self.width, self.height);
        let clipped_dst_rect = match dst_rect.intersect(&clip_rect) {
            Some(r) => r,
            None => return Ok(()), // 描画領域が画面外
        };
        
        // 転送元の対応する領域を計算
        let src_x_offset = clipped_dst_rect.x - dst_rect.x + src_rect.x;
        let src_y_offset = clipped_dst_rect.y - dst_rect.y + src_rect.y;
        
        for y in 0..clipped_dst_rect.height {
            let src_offset = ((src_y_offset + y as i32) as u32 * src.stride + 
                              src_x_offset as u32 * bytes_per_pixel) as usize;
            let dst_offset = ((clipped_dst_rect.y + y as i32) as u32 * self.stride + 
                              clipped_dst_rect.x as u32 * bytes_per_pixel) as usize;
            
            let row_bytes = clipped_dst_rect.width * bytes_per_pixel;
            self.data[dst_offset..dst_offset + row_bytes as usize]
                .copy_from_slice(&src.data[src_offset..src_offset + row_bytes as usize]);
        }
        
        Ok(())
    }
}

/// ディスプレイ情報
#[derive(Debug, Clone)]
pub struct DisplayInfo {
    pub id: u32,
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub refresh_rate: u32,
    pub physical_width_mm: u32,
    pub physical_height_mm: u32,
    pub supported_formats: Vec<PixelFormat>,
    pub connected: bool,
    pub primary: bool,
}

/// ディスプレイモード
#[derive(Debug, Clone)]
pub struct DisplayMode {
    pub width: u32,
    pub height: u32,
    pub refresh_rate: u32,
    pub format: PixelFormat,
}

/// グラフィックアダプタ能力
#[derive(Debug, Clone)]
pub struct AdapterCapabilities {
    pub device_name: String,
    pub vendor_id: u32,
    pub device_id: u32,
    pub dedicated_memory: u64,
    pub shared_memory: u64,
    pub supports_vulkan: bool,
    pub supports_opengl: bool,
    pub supports_directx: bool,
    pub supports_metal: bool,
    pub max_texture_size: u32,
    pub max_compute_units: u32,
}

/// グラフィックデバイスのトレイト
pub trait GraphicsDevice: Send + Sync {
    fn name(&self) -> &str;
    fn id(&self) -> u32;
    fn capabilities(&self) -> &AdapterCapabilities;
    
    fn create_framebuffer(&self, width: u32, height: u32, format: PixelFormat) -> GraphicsResult<FrameBuffer>;
    fn present_framebuffer(&self, fb: &FrameBuffer, display_id: u32) -> GraphicsResult<()>;
    
    fn get_displays(&self) -> GraphicsResult<Vec<DisplayInfo>>;
    fn get_display_modes(&self, display_id: u32) -> GraphicsResult<Vec<DisplayMode>>;
    fn set_display_mode(&self, display_id: u32, mode: &DisplayMode) -> GraphicsResult<()>;
    
    fn supports_acceleration(&self) -> bool;
    fn create_accelerated_context(&self) -> GraphicsResult<Box<dyn AcceleratedContext>>;
}

/// ハードウェアアクセラレーション機能トレイト
pub trait AcceleratedContext: Send + Sync {
    fn clear(&self, color: Color) -> GraphicsResult<()>;
    fn draw_rect(&self, rect: Rect, color: Color, fill: bool) -> GraphicsResult<()>;
    fn draw_texture(&self, texture_id: u32, src_rect: Rect, dst_rect: Rect) -> GraphicsResult<()>;
    fn create_texture(&self, width: u32, height: u32, format: PixelFormat, data: Option<&[u8]>) -> GraphicsResult<u32>;
    fn update_texture(&self, texture_id: u32, data: &[u8], rect: Option<Rect>) -> GraphicsResult<()>;
    fn delete_texture(&self, texture_id: u32) -> GraphicsResult<()>;
    fn present(&self) -> GraphicsResult<()>;
}

/// グラフィックマネージャ
pub struct GraphicsManager {
    devices: Vec<Box<dyn GraphicsDevice>>,
    next_device_id: AtomicU64,
    primary_device_id: Option<u32>,
}

impl GraphicsManager {
    pub fn new() -> Self {
        GraphicsManager {
            devices: Vec::new(),
            next_device_id: AtomicU64::new(1),
            primary_device_id: None,
        }
    }
    
    pub fn register_device(&mut self, device: Box<dyn GraphicsDevice>) -> u32 {
        let id = self.next_device_id.fetch_add(1, Ordering::SeqCst) as u32;
        
        // 最初に登録されたデバイスをプライマリとして設定
        if self.primary_device_id.is_none() {
            self.primary_device_id = Some(id);
        }
        
        self.devices.push(device);
        id
    }
    
    pub fn get_device(&self, id: u32) -> Option<&dyn GraphicsDevice> {
        self.devices.iter()
            .find(|dev| dev.id() == id)
            .map(|dev| dev.as_ref())
    }
    
    pub fn get_device_mut(&mut self, id: u32) -> Option<&mut dyn GraphicsDevice> {
        self.devices.iter_mut()
            .find(|dev| dev.id() == id)
            .map(|dev| dev.as_mut())
    }
    
    pub fn get_primary_device(&self) -> Option<&dyn GraphicsDevice> {
        self.primary_device_id.and_then(|id| self.get_device(id))
    }
    
    pub fn set_primary_device(&mut self, id: u32) -> GraphicsResult<()> {
        if self.get_device(id).is_some() {
            self.primary_device_id = Some(id);
            Ok(())
        } else {
            Err(GraphicsError::DeviceNotFound)
        }
    }
    
    pub fn list_devices(&self) -> Vec<u32> {
        self.devices.iter().map(|dev| dev.id()).collect()
    }
    
    pub fn create_framebuffer(&self, width: u32, height: u32, format: PixelFormat) -> GraphicsResult<FrameBuffer> {
        let device = self.get_primary_device()
            .ok_or(GraphicsError::DeviceNotFound)?;
            
        device.create_framebuffer(width, height, format)
    }
    
    pub fn present_framebuffer(&self, fb: &FrameBuffer, display_id: u32) -> GraphicsResult<()> {
        let device = self.get_primary_device()
            .ok_or(GraphicsError::DeviceNotFound)?;
            
        device.present_framebuffer(fb, display_id)
    }
}

static mut GRAPHICS_MANAGER: Option<GraphicsManager> = None;

/// グローバルグラフィックマネージャーの取得
pub fn get_graphics_manager() -> &'static mut GraphicsManager {
    unsafe {
        if GRAPHICS_MANAGER.is_none() {
            GRAPHICS_MANAGER = Some(GraphicsManager::new());
        }
        GRAPHICS_MANAGER.as_mut().unwrap()
    }
}

/// グラフィックスサブシステムの初期化
pub fn init() {
    let manager = get_graphics_manager();
    
    // 各グラフィックコンポーネントの初期化
    display::init();
    render::init();
    compositor::init();
    
    // グラフィックアダプタの初期化
    adapter::init();
    
    // ハードウェアアクセラレーションAPI
    vulkan::init();
    opengl::init();
    directx::init();
    metal::init();
} 