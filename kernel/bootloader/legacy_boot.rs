// レガシーBIOSブートローダーモジュール
//
// レガシーBIOS環境でカーネルを起動するブートローダー実装

use alloc::string::String;
use core::ptr;
use core::slice;
use core::mem;
use super::boot_info::BootInfo;
use super::memory_map::{MemoryMap, MemoryRegion, MemoryType};
use super::graphics::FramebufferInfo;
use super::boot_info::{BootDriveInfo, PartitionInfo};

/// BIOSメモリマップのエントリ形式（INT 15h, AX=E820h）
#[repr(C, packed)]
struct BiosMemoryMapEntry {
    base_addr: u64,
    length: u64,
    region_type: u32,
    extended_attributes: u32,
}

/// マルチブートヘッダ構造体
#[repr(C, align(4))]
pub struct MultibootHeader {
    magic: u32,
    flags: u32,
    checksum: u32,
    header_addr: u32,
    load_addr: u32,
    load_end_addr: u32,
    bss_end_addr: u32,
    entry_addr: u32,
    mode_type: u32,
    width: u32,
    height: u32,
    depth: u32,
}

/// マルチブート情報構造体
#[repr(C)]
pub struct MultibootInfo {
    flags: u32,
    mem_lower: u32,
    mem_upper: u32,
    boot_device: u32,
    cmdline: u32,
    mods_count: u32,
    mods_addr: u32,
    syms: [u32; 4],
    mmap_length: u32,
    mmap_addr: u32,
    drives_length: u32,
    drives_addr: u32,
    config_table: u32,
    boot_loader_name: u32,
    apm_table: u32,
    vbe_control_info: u32,
    vbe_mode_info: u32,
    vbe_mode: u16,
    vbe_interface_seg: u16,
    vbe_interface_off: u16,
    vbe_interface_len: u16,
    framebuffer_addr: u64,
    framebuffer_pitch: u32,
    framebuffer_width: u32,
    framebuffer_height: u32,
    framebuffer_bpp: u8,
    framebuffer_type: u8,
    color_info: [u8; 6],
}

/// VBEモード情報ブロック
#[repr(C, packed)]
struct VbeModeInfoBlock {
    attributes: u16,
    window_a: u8,
    window_b: u8,
    granularity: u16,
    window_size: u16,
    segment_a: u16,
    segment_b: u16,
    win_func_ptr: u32,
    pitch: u16,
    width: u16,
    height: u16,
    w_char: u8,
    y_char: u8,
    planes: u8,
    bpp: u8,
    banks: u8,
    memory_model: u8,
    bank_size: u8,
    image_pages: u8,
    reserved0: u8,
    red_mask: u8,
    red_position: u8,
    green_mask: u8,
    green_position: u8,
    blue_mask: u8,
    blue_position: u8,
    reserved_mask: u8,
    reserved_position: u8,
    direct_color_attributes: u8,
    framebuffer: u32,
    off_screen_mem_off: u32,
    off_screen_mem_size: u16,
    reserved1: [u8; 206],
}

/// BIOS割り込みを呼び出すためのヘルパー関数
unsafe fn bios_int(interrupt: u8, regs: &mut BiosRegisters) {
    // アセンブラコードで割り込みを呼び出す（本番実装）
    asm!(
        "int {int_num}",
        int_num = const interrupt,
        inout("eax") regs.eax,
        inout("ebx") regs.ebx,
        inout("ecx") regs.ecx,
        inout("edx") regs.edx,
        inout("esi") regs.esi,
        inout("edi") regs.edi,
        options(nostack, preserves_flags)
    );
}

/// BIOS レジスタ状態
#[repr(C)]
struct BiosRegisters {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    esi: u32,
    edi: u32,
}

/// BIOSメモリマップを取得
unsafe fn get_bios_memory_map() -> MemoryMap {
    let mut memory_map = MemoryMap::new();
    let mut regs = BiosRegisters {
        eax: 0xE820,
        ebx: 0, // Continuation value, start with 0
        ecx: 24, // Buffer size for BiosMemoryMapEntry
        edx: 0x534D4150, // "SMAP" signature
        esi: 0, // ACPI 3.0 extended attributes (if supported by BIOS)
        edi: 0, // Buffer pointer
    };

    // メモリマップエントリを保存する一時バッファ
    // このバッファは低メモリ（例: 1MB以下）に配置する必要がある場合がある
    let mut entry_buffer = [0u8; 24 * 8]; // 8エントリ分確保 (BIOSによっては一度に複数返す場合がある)
    let entry_base_ptr = entry_buffer.as_mut_ptr() as usize;

    serial_println!("[BIOS] Querying E820 memory map...");

    loop {
        regs.edi = entry_base_ptr as u32; // Buffer for the entry
        regs.ecx = 24; // Size of one entry structure

        // INT 15h, AX=E820h を呼び出してメモリマップエントリを取得
        bios_int(0x15, &mut regs);

        if regs.eax != 0x534D4150 {
            serial_println!("[BIOS] E820: Error or signature mismatch (EAX={:#x}).", regs.eax);
            break;
        }

        // Check for Carry Flag (CF), if set, an error occurred.
        // Note: `asm!` block does not directly expose CF. Assume success if EAX is SMAP.
        // A more robust implementation would check flags if possible.

        let entry = &*(entry_base_ptr as *const BiosMemoryMapEntry);

        if regs.ecx > 0 && entry.length > 0 {
            // メモリタイプを変換
            let memory_type_str: &str;
            let memory_type = match entry.region_type {
                1 => { memory_type_str = "Available"; MemoryType::Available },
                2 => { memory_type_str = "Reserved"; MemoryType::Reserved }, // Standard Reserved
                3 => { memory_type_str = "ACPI Reclaimable"; MemoryType::AcpiReclaimable },
                4 => { memory_type_str = "ACPI NVS"; MemoryType::AcpiNvs },
                5 => { memory_type_str = "Bad Memory"; MemoryType::BadMemory },
                // ACPI 3.0+ types
                6 => { memory_type_str = "Disabled (Reserved)"; MemoryType::Reserved }, // Disabled memory
                7 => { memory_type_str = "Persistent Memory (NVDIMM)"; MemoryType::Persistent }, // Persistent Memory
                _ => { memory_type_str = "Reserved (Other)"; MemoryType::Reserved },
            };

            serial_println!(
                "[BIOS] E820 Entry: Base={:#010x}, Length={:#010x} ({:>6} KB), Type={} ({})",
                entry.base_addr,
                entry.length,
                entry.length / 1024,
                entry.region_type,
                memory_type_str
            );

            let new_region = MemoryRegion {
                base: entry.base_addr as usize,
                length: entry.length as usize,
                memory_type,
            };

            // 整合性チェック: 重複や不正な領域がないか (簡易チェック)
            let mut overlap = false;
            for existing_region in memory_map.regions().iter() {
                let new_end = new_region.base + new_region.length;
                let existing_end = existing_region.base + existing_region.length;
                if new_region.base < existing_end && new_end > existing_region.base {
                    serial_println!(
                        "[BIOS] Warning: E820 region overlap detected: New({:#x}-{:#x}) with Existing({:#x}-{:#x})",
                        new_region.base, new_end, existing_region.base, existing_end
                    );
                    overlap = true;
                    // TODO: より高度な重複処理 (マージ、切り捨てなど)
                    break;
                }
            }
            if new_region.length == 0 {
                 serial_println!("[BIOS] Warning: E820 region with zero length detected at {:#x}", new_region.base);
            } else if !overlap {
                memory_map.add_region(new_region);
            }

        } else {
            serial_println!("[BIOS] E820: Received invalid entry (Length=0 or ECX=0).");
        }

        // 次のエントリがない場合は終了 (EBXが0になる)
        // または、BIOSが0を返さないがCFがセットされる場合もある
        if regs.ebx == 0 {
            serial_println!("[BIOS] E820: End of map (EBX=0).");
            break;
        }
    }

    // 伝統的な低メモリ領域（0-640KB）がない場合は追加
    // E820がこの領域を報告しない場合があるため
    let has_conventional_low_memory = memory_map.regions().iter().any(|r| {
        r.base == 0 && r.length >= 0xA0000 && r.memory_type == MemoryType::Available
    });

    if !has_conventional_low_memory {
        serial_println!("[BIOS] E820: Conventional low memory (0-640KB) not reported as available, adding manually.");
        // 他の予約領域と衝突しないか確認
        let conflict = memory_map.regions().iter().any(|r| {
            r.base < 0xA0000 && (r.base + r.length) > 0
        });
        if !conflict {
            memory_map.add_region(MemoryRegion {
                base: 0,
                length: 0xA0000, // 640KB
                memory_type: MemoryType::Available,
            });
        } else {
            serial_println!("[BIOS] Warning: Cannot add conventional low memory due to conflict.");
        }
    }
    
    // EBDA (Extended BIOS Data Area) の予約
    // 通常は 0x9FC00 やそれに近いアドレスから始まる短い領域
    // RSDP検索範囲と重なる可能性があるため、Reservedとしてマークする
    // EBDAの正確な位置とサイズはBDA(0x40:0x0E)からポインタで取得できるが、ここでは簡略化
    let ebda_candidates = [0x9FC00, 0x9F800, 0x9F400, 0x9F000]; // 一般的なEBDA開始アドレス
    for &ebda_base in &ebda_candidates {
        let is_available_or_unreported = memory_map.regions().iter().all(|r| {
            !(r.base < ebda_base + 1024 && r.base + r.length > ebda_base) || r.memory_type == MemoryType::Available
        });
        if is_available_or_unreported {
             // 既存のAvailable領域を分割または上書きしてEBDAを予約
            memory_map.mark_as_reserved(ebda_base, 1024); // 1KB予約 (EBDAは通常1KB-4KB程度)
            serial_println!("[BIOS] Marked potential EBDA at {:#x} as Reserved.", ebda_base);
            break; // 最初に見つかった候補を使用
        }
    }


    serial_println!("[BIOS] Final E820 Memory Map ({} regions):", memory_map.regions().len());
    for region in memory_map.regions().iter() {
        serial_println!(
            "  Base: {:#010x}, Length: {:#010x} ({:>7} KB), Type: {:?}",
            region.base,
            region.length,
            region.length / 1024,
            region.memory_type
        );
    }
    memory_map.sort_and_merge_regions(); // 領域をソートし、隣接する同種領域をマージ
    serial_println!("[BIOS] Sorted and Merged E820 Memory Map ({} regions):", memory_map.regions().len());
    for region in memory_map.regions().iter() {
        serial_println!(
            "  Base: {:#010x}, Length: {:#010x} ({:>7} KB), Type: {:?}",
            region.base,
            region.length,
            region.length / 1024,
            region.memory_type
        );
    }

    memory_map
}

/// VBEモード情報を取得
unsafe fn get_vbe_mode_info() -> Option<FramebufferInfo> {
    serial_println!("[VBE] Querying VBE information...");
    // VBE情報ブロックを取得 (INT 10h, AX=4F00h)
    let mut vbe_info_block = [0u8; 512]; // VBE Info Block is 512 bytes
    let vbe_info_ptr = vbe_info_block.as_mut_ptr() as usize;
    
    // "VBE2" シグネチャをバッファの先頭に書き込む (一部BIOSで必要)
    vbe_info_block[0..4].copy_from_slice(b"VBE2");

    let mut regs = BiosRegisters {
        eax: 0x4F00, // Get VBE Controller Information
        ebx: 0,
        ecx: 0,
        edx: 0,
        esi: 0,
        edi: vbe_info_ptr as u32,
    };
    bios_int(0x10, &mut regs);

    if (regs.eax & 0xFFFF) != 0x004F { // AL must be 4Fh, AH must be 00h (success)
        serial_println!("[VBE] Failed to get VBE Controller Information (EAX={:#x})", regs.eax);
        return None;
    }
    serial_println!("[VBE] VBE Controller Information retrieved successfully.");

    // VBEバージョンをログに出力
    let vbe_version_major = (vbe_info_block[5] as u16) >> 4; // BCD format High nibble
    let vbe_version_minor = vbe_info_block[4] as u16 & 0x0F; // BCD format Low nibble
    serial_println!("[VBE] VBE Version: {}.{}", vbe_version_major, vbe_version_minor);

    // サポートするモードリストへのポインタを取得
    let mode_list_ptr_far = u32::from_le_bytes([
        vbe_info_block[14], vbe_info_block[15], vbe_info_block[16], vbe_info_block[17]
    ]);
    let mode_list_seg = (mode_list_ptr_far >> 16) as u16;
    let mode_list_off = (mode_list_ptr_far & 0xFFFF) as u16;

    if mode_list_ptr_far == 0 || mode_list_ptr_far == 0xFFFFFFFF {
        serial_println!("[VBE] Invalid VBE mode list pointer.");
        return None;
    }
    // FARポインタをリニアアドレスに変換 (セグメント * 16 + オフセット)
    let mode_list_linear_addr = (mode_list_seg as usize * 16) + mode_list_off as usize;
    serial_println!("[VBE] Mode list pointer: Seg={:#x}, Off={:#x}, Linear={:#x}", mode_list_seg, mode_list_off, mode_list_linear_addr);


    // 試行するモード (解像度, BPP) - 優先度順
    let desired_modes = [
        (1920, 1080, 32), (1920, 1080, 24),
        (1600, 1200, 32), (1600, 1200, 24),
        (1280, 1024, 32), (1280, 1024, 24),
        (1024, 768, 32),  (1024, 768, 24),
        (800, 600, 32),   (800, 600, 24),
        (640, 480, 32),   (640, 480, 24),
    ];

    let mut preferred_mode_selection: Option<(u16, VbeModeInfoBlock)> = None;
    let mut any_lfb_mode_selection: Option<(u16, VbeModeInfoBlock)> = None;

    serial_println!("[VBE] Scanning available modes:");
    let mut available_modes_str = String::new();

    // モードリストをスキャンして、利用可能なモードをログに出力
    // また、最適なモードを探す
    let mut current_mode_num_ptr = mode_list_linear_addr as *const u16;
    'outer_scan: loop { // outer_scanループにラベルを付ける
        let mode_num = *current_mode_num_ptr;
        if mode_num == 0xFFFF { // List terminator
            break;
        }
        
        let mut temp_mode_info_block = core::mem::MaybeUninit::<VbeModeInfoBlock>::uninit();
        regs.eax = 0x4F01; // Get VBE Mode Information
        regs.ecx = mode_num;
        regs.edi = temp_mode_info_block.as_mut_ptr() as u32;
        bios_int(0x10, &mut regs);

        if (regs.eax & 0xFFFF) == 0x004F {
            let temp_info = temp_mode_info_block.assume_init();
            let mode_str = format!("Mode {:#x}: {}x{}x{} (Pitch: {}, FB: {:#x})\\n",
                mode_num, temp_info.width, temp_info.height, temp_info.bpp, temp_info.pitch, temp_info.framebuffer);
            available_modes_str.push_str(&mode_str);

            // リニアフレームバッファをサポートしているか、グラフィックスモードかなどをチェック
            let is_graphics = (temp_info.attributes & (1 << 4)) != 0; // Bit 4: Graphics mode
            let is_lfb_supported = (temp_info.attributes & (1 << 7)) != 0; // Bit 7: Linear Frame Buffer mode supported
            let is_supported_memory_model = temp_info.memory_model == 4 /* Packed Pixel */ || temp_info.memory_model == 6 /* Direct Color */;


            if is_graphics && is_lfb_supported && is_supported_memory_model {
                 serial_println!(
                    "  Found supported VBE mode: {:#03x} - {}x{} {}bpp, LFB: {:#x}, Attr: {:#x}, Model: {}",
                    mode_num, temp_info.width, temp_info.height, temp_info.bpp,
                    temp_info.framebuffer, temp_info.attributes, temp_info.memory_model
                );

                // Store the first valid LFB mode encountered as a general fallback
                if any_lfb_mode_selection.is_none() {
                    any_lfb_mode_selection = Some((mode_num, temp_info));
                    serial_println!("[VBE] Storing mode {:#x} as a potential general fallback.", mode_num);
                }

                for &(req_w, req_h, req_bpp) in desired_modes.iter() {
                    if temp_info.width == req_w as u16 && temp_info.height == req_h as u16 && temp_info.bpp == req_bpp as u8 {
                        if preferred_mode_selection.is_none() { // Take the first desired mode found
                            serial_println!("[VBE] Selecting mode {:#x} ({}x{}x{}) as preferred.", mode_num, req_w, req_h, req_bpp);
                            preferred_mode_selection = Some((mode_num, temp_info));
                            break 'outer_scan; // Found a preferred mode, stop scanning
                        }
                    }
                }
            }
        }
        current_mode_num_ptr = current_mode_num_ptr.add(1);
        if current_mode_num_ptr as usize > mode_list_linear_addr + 1024 { // 安全停止
            serial_println!("[VBE] Mode list scan exceeded 1KB, stopping.");
            break;
        }
    }
    serial_println!("[VBE] All Scanned Modes:\\n{}", available_modes_str);


    let (selected_mode_num, mut mode_info_to_set) = 
        if let Some((num, info)) = preferred_mode_selection {
            serial_println!("[VBE] Using selected preferred mode: {:#x} ({}x{}x{}bpp)", num, info.width, info.height, info.bpp);
            (num, info)
        } else if let Some((num, info)) = any_lfb_mode_selection {
            serial_println!("[VBE] No preferred VBE mode found. Using best available LFB mode: {:#x} ({}x{}x{}bpp)", num, info.width, info.height, info.bpp);
            (num, info)
        } else {
            serial_println!("[VBE] No suitable LFB mode found at all.");
            return None;
        };
    
    // VBEモードを設定 (INT 10h, AX=4F02h)
    // Bit 14 of EBX set for Linear Frame Buffer mode
    // Bit 15 of EBX set to not clear display memory (optional, but good for quick init)
    regs.eax = 0x4F02;
    regs.ebx = (selected_mode_num as u32) | (1 << 14) | (1 << 15); // Mode number + Linear FB + Don't Clear
    regs.ecx = 0; // Reserved, must be 0 for some VBE versions
    regs.edi = 0; // Pointer to CRTC information block (optional)
    bios_int(0x10, &mut regs);

    if (regs.eax & 0xFFFF) != 0x004F {
        serial_println!("[VBE] Failed to set VBE mode {:#x} (EAX={:#x})", selected_mode_num, regs.eax);
        // 失敗した場合、クリアフラグなしで再試行
        regs.ebx = (selected_mode_num as u32) | (1 << 14);
        bios_int(0x10, &mut regs);
        if (regs.eax & 0xFFFF) != 0x004F {
            serial_println!("[VBE] Failed to set VBE mode {:#x} (even without NO_CLEAR, EAX={:#x})", selected_mode_num, regs.eax);
            return None;
        }
    }
    serial_println!("[VBE] Mode {:#x} set successfully.", selected_mode_num);
    
    // モード設定が成功したので、再度モード情報を取得して最新の状態を確認
    // (一部のBIOSはモード設定時にpitchなどを変更する場合があるため)
    let mut final_mode_info_block = core::mem::MaybeUninit::<VbeModeInfoBlock>::uninit();
    regs.eax = 0x4F01; // Get VBE Mode Information
    regs.ecx = selected_mode_num; // 現在設定されているモード (のはず)
    regs.edi = final_mode_info_block.as_mut_ptr() as u32;
    bios_int(0x10, &mut regs);

    if (regs.eax & 0xFFFF) != 0x004F {
        serial_println!("[VBE] Failed to re-get mode info after setting mode (EAX={:#x}). Using previous info.", regs.eax);
        // 再取得に失敗した場合は、設定試行前の情報 (mode_info_to_set) を使う
    } else {
        mode_info_to_set = final_mode_info_block.assume_init();
        serial_println!("[VBE] Re-fetched mode info: {}x{} {}bpp, Pitch: {}, FB: {:#x}",
            mode_info_to_set.width, mode_info_to_set.height, mode_info_to_set.bpp,
            mode_info_to_set.pitch, mode_info_to_set.framebuffer);
    }

    // フレームバッファ情報を作成
    let physical_address = mode_info_to_set.framebuffer as usize;
    let width = mode_info_to_set.width as usize;
    let height = mode_info_to_set.height as usize;
    // let bytes_per_pixel = (mode_info_to_set.bpp / 8) as usize;
    let stride = mode_info_to_set.pitch as usize;

    // ピクセルフォーマットを判定
    let pixel_format = if mode_info_to_set.memory_model == 6 { // ダイレクトカラーモデル
        serial_println!("[VBE] Direct Color Model: R={}, G={}, B={}", 
            mode_info_to_set.red_mask, mode_info_to_set.green_mask, mode_info_to_set.blue_mask);
        if mode_info_to_set.red_position == 16 && mode_info_to_set.green_position == 8 && mode_info_to_set.blue_position == 0 {
            if mode_info_to_set.bpp == 32 || mode_info_to_set.bpp == 24 { // XRGB or RGB
                 super::graphics::PixelFormat::RGB
            } else {
                super::graphics::PixelFormat::Other(mode_info_to_set.memory_model as u32)
            }
        } else if mode_info_to_set.blue_position == 16 && mode_info_to_set.green_position == 8 && mode_info_to_set.red_position == 0 {
             if mode_info_to_set.bpp == 32 || mode_info_to_set.bpp == 24 { // XBGR or BGR
                super::graphics::PixelFormat::BGR
            } else {
                super::graphics::PixelFormat::Other(mode_info_to_set.memory_model as u32)
            }
        } else {
            // マスクとポジションから判断しようと試みる (より複雑)
            // 簡単のため、一般的なRGBかBGRでなければOtherとする
            serial_println!("[VBE] Unknown direct color layout, defaulting to Other.");
            super::graphics::PixelFormat::Other(mode_info_to_set.memory_model as u32)
        }
    } else if mode_info_to_set.memory_model == 4 { // Packed Pixel
        serial_println!("[VBE] Packed Pixel Model (assumed BGR for <= 8bpp, otherwise Other)");
        // 8bpp以下ならパレットモードかもしれないが、ここでは簡略化
        if mode_info_to_set.bpp <= 8 {
            super::graphics::PixelFormat::BGR // or indexed color
        } else {
            super::graphics::PixelFormat::Other(mode_info_to_set.memory_model as u32)
        }
    }
    else {
        serial_println!("[VBE] Non-Direct-Color/Non-Packed-Pixel memory model: {}", mode_info_to_set.memory_model);
        super::graphics::PixelFormat::Other(mode_info_to_set.memory_model as u32)
    };

    serial_println!(
        "[VBE] Framebuffer Info: Addr={:#x}, {}x{}, Stride={}, Format={:?}",
        physical_address, width, height, stride, pixel_format
    );

    Some(super::graphics::FramebufferInfo::new(
        physical_address,
        width,
        height,
        pixel_format,
        Some(stride),
    ))
}

/// ブートドライブ情報を取得
unsafe fn get_boot_drive_info() -> Option<BootDriveInfo> {
    serial_println!("[BIOS] Querying boot drive information...");
    // ブートドライブ番号を取得 (DLレジスタにブートドライブが入っていることが多い)
    // ただし、これはブートローダーの実装依存。INT 13h AH=08hで確認を試みる。
    
    let mut boot_drive_dl: u8;
    core::arch::asm!("mov {}, dl", out(reg_byte) boot_drive_dl, options(nomem, nostack, preserves_flags, pure, readonly));
    serial_println!("[BIOS] Boot drive from DL register (heuristic): {:#x}", boot_drive_dl);

    let mut regs = BiosRegisters { eax: 0, ebx: 0, ecx: 0, edx: 0, esi: 0, edi: 0 };

    // INT 13h, AH=15h - Get Disk Type / EDD Drive Parameters
    // まずはブートローダーが渡したDL値で試す
    regs.eax = 0x1500; // AH=15h, AL=00h
    regs.edx = boot_drive_dl as u32;
    bios_int(0x13, &mut regs);

    let mut drive_number_to_use = boot_drive_dl;
    let mut found_valid_drive = false;

    if (regs.eax & 0xFF00) == 0 || (regs.eax & 0xFF00) == 0x0100 { // AH=00 (success) or AH=01 (invalid command, try legacy)
        let disk_type_ah = (regs.eax >> 8) as u8;
        if disk_type_ah == 0x00 { // Success
            let num_heads = (((regs.ecx >> 8) & 0xFF) + 1) as u16; // DH = max head number (0-based)
            let sectors_per_track = (regs.ecx & 0x3F) as u16;       // CL bits 0-5 = max sector number (1-based)
            let num_cylinders = (((regs.ecx & 0xC0) as u16) << 2) | ((regs.edx >> 8) & 0xFF) as u16 + 1; // CH = low 8 bits of cyl, CL bits 6-7 = high 2 bits
            let total_sectors_low = regs.eax; // If AH=0, EAX contains low 32-bits of sector count (EDD 1.x)
            let total_sectors_high = regs.ebx; // EBX contains high 32-bits of sector count (EDD 1.x)
            let total_sectors = ((total_sectors_high as u64) << 32) | (total_sectors_low as u64);

            serial_println!("[BIOS EDD Check] Drive {:#x}: Type AH={:#x}. Heads: {}, Sect/Track: {}, Cyls: {}, Total Sectors: {}", 
                boot_drive_dl, disk_type_ah, num_heads, sectors_per_track, num_cylinders, total_sectors);
            
            if disk_type_ah == 0x00 && total_sectors > 0 { // Valid drive params
                found_valid_drive = true;
            }
        }
    }

    if !found_valid_drive {
        serial_println!("[BIOS] EDD check for drive {:#x} failed or returned no sectors. Trying legacy INT 13h, AH=08h.", boot_drive_dl);
        // INT 13h機能 8 - ドライブパラメータの取得 (レガシー)
        regs.eax = 0x0800; // AH=08h, AL=00h
        regs.edx = boot_drive_dl as u32; // DL = drive number
        bios_int(0x13, &mut regs);

        // CF=0なら成功。 regs.eax & 0xFF00 (AH) が0でなくてもエラーコードが入る場合がある
        // ここでは簡略化のためCFは見ないが、AH (regs.eax >> 8) が0かどうかで判断
        if (regs.eax & 0xFF00) == 0 { // Success if AH=0
            drive_number_to_use = (regs.edx & 0xFF) as u8; // Drive number returned in DL
            let num_drives = (regs.edx & 0xFF00) >> 8; // Number of hard drives
            let max_heads = ((regs.ecx & 0xFF00) >> 8) + 1; // Max head number (0-based) in DH
            let max_sectors = regs.ecx & 0x3F; // Max sector number (1-based) in CL bits 0-5
            serial_println!("[BIOS Legacy] Drive {:#x} (DL): Params found. Num Drives: {}, Max Heads: {}, Max Sectors: {}", 
                drive_number_to_use, num_drives, max_heads, max_sectors);
            found_valid_drive = true;
        } else {
            serial_println!("[BIOS Legacy] Failed to get drive parameters for {:#x} via AH=08h. EAX={:#x}", boot_drive_dl, regs.eax);
            // フォールバックとして一般的なブートドライブ (0x80) を試す
            if boot_drive_dl != 0x80 {
                serial_println!("[BIOS] Retrying with common boot drive 0x80.");
                regs.eax = 0x0800;
                regs.edx = 0x80;
                bios_int(0x13, &mut regs);
                if (regs.eax & 0xFF00) == 0 {
                    drive_number_to_use = 0x80;
                    found_valid_drive = true;
                    serial_println!("[BIOS Legacy] Drive 0x80: Params found.");
                } else {
                     serial_println!("[BIOS Legacy] Failed for 0x80 as well. EAX={:#x}", regs.eax);
                }
            }
        }
    }

    if !found_valid_drive {
        serial_println!("[BIOS] Could not determine valid boot drive information.");
        return None;
    }

    serial_println!("[BIOS] Using drive number: {:#x}", drive_number_to_use);

    // パーティションテーブルの読み取り (MBR)
    // 512バイトのバッファを低メモリに用意する必要がある
    let mut partition_buffer_storage = [0u8; 512];
    let partition_buffer_ptr = partition_buffer_storage.as_mut_ptr() as usize;

    // INT 13h, AH=02h - Read Sectors
    // DAP (Disk Address Packet) を使った拡張読み取り(AH=42h)の方が望ましいが、複雑なのでまずはレガシーリード
    regs.eax = 0x0201; // AH=02h (Read), AL=01 (1 sector)
    regs.ebx = partition_buffer_ptr as u32; // ES:BX pointer to buffer. Assume ES=DS.
    regs.ecx = 0x0001; // CH=00 (Cylinder 0), CL=01 (Sector 1)
    regs.edx = (0x0000 | drive_number_to_use) as u32; // DH=00 (Head 0), DL=drive

    bios_int(0x13, &mut regs);

    if (regs.eax & 0xFF00) == 0 { // AH=0, success
        serial_println!("[BIOS] MBR read successfully from drive {:#x}.", drive_number_to_use);
        // MBRシグネチャを確認 (0x55AA at offset 510)
        if partition_buffer_storage[510] == 0x55 && partition_buffer_storage[511] == 0xAA {
            serial_println!("[BIOS] MBR signature 0x55AA found.");
            // 最初のパーティションエントリを読み取る（オフセット446から16バイト）
            // パーティションテーブルは4エントリある
            for i in 0..4 {
                let entry_offset = 446 + (i * 16);
                let boot_indicator = partition_buffer_storage[entry_offset];
                let partition_type = partition_buffer_storage[entry_offset + 4];
                
                // 有効なパーティションタイプがあり、ブート可能フラグが立っているか、最初のパーティションか
                if partition_type != 0 && (boot_indicator == 0x80 || i == 0) {
                    let start_lba = u32::from_le_bytes([
                        partition_buffer_storage[entry_offset + 8],
                        partition_buffer_storage[entry_offset + 9],
                        partition_buffer_storage[entry_offset + 10],
                        partition_buffer_storage[entry_offset + 11],
                    ]);
                    
                    let sector_count = u32::from_le_bytes([
                        partition_buffer_storage[entry_offset + 12],
                        partition_buffer_storage[entry_offset + 13],
                        partition_buffer_storage[entry_offset + 14],
                        partition_buffer_storage[entry_offset + 15],
                    ]);

                    serial_println!(
                        "[BIOS] Partition {}: Bootable={}, Type={:#x}, StartLBA={}, Sectors={}",
                        i, boot_indicator == 0x80, partition_type, start_lba, sector_count
                    );

                    // 最初のブート可能または最初の有効なパーティション情報を採用
                    return Some(BootDriveInfo {
                        drive_number: drive_number_to_use,
                        partition: Some(PartitionInfo {
                            number: (i + 1) as u8, // 1-indexed partition number
                            partition_type,
                            start_lba: start_lba as u64,
                            sector_count: sector_count as u64,
                        }),
                    });
                }
            }
            serial_println!("[BIOS] No bootable or primary partition found in MBR.");
        } else {
            serial_println!("[BIOS] MBR signature not found. Drive may not be partitioned or MBR is corrupted.");
        }
    } else {
        serial_println!("[BIOS] Failed to read MBR from drive {:#x}. AH={:#x}", drive_number_to_use, (regs.eax >> 8) & 0xFF);
    }
    
    // パーティション情報が取得できなくても、ドライブ番号だけは返す (ドライブ自体は存在するかもしれない)
    serial_println!("[BIOS] No partition info found, returning drive number only.");
    Some(BootDriveInfo {
        drive_number: drive_number_to_use,
        partition: None,
    })
}

/// マルチブート情報からブート情報を取得
fn parse_multiboot_info(mb_info_addr: usize) -> Result<BootInfo, &'static str> {
    let mb_info = unsafe { &*(mb_info_addr as *const MultibootInfo) };
    
    // メモリマップを取得
    let memory_map = if (mb_info.flags & (1 << 6)) != 0 {
        // マルチブートからメモリマップを取得
        unsafe {
            MemoryMap::from_multiboot(mb_info.mmap_addr as usize, mb_info.mmap_length as usize)
        }
    } else {
        // BIOSからメモリマップを取得
        unsafe { get_bios_memory_map() }
    };
    
    // フレームバッファ情報を取得
    let framebuffer = if (mb_info.flags & (1 << 12)) != 0 {
        // マルチブートからフレームバッファ情報を取得
        Some(FramebufferInfo::new(
            mb_info.framebuffer_addr as usize,
            mb_info.framebuffer_width as usize,
            mb_info.framebuffer_height as usize,
            if mb_info.framebuffer_type == 1 {
                super::graphics::PixelFormat::RGB
            } else {
                super::graphics::PixelFormat::Other(mb_info.framebuffer_type as u32)
            },
            Some(mb_info.framebuffer_pitch as usize),
        ))
    } else {
        // VBEからフレームバッファ情報を取得
        unsafe { get_vbe_mode_info() }
    };
    
    // コマンドライン引数を取得
    let cmdline = if (mb_info.flags & (1 << 2)) != 0 {
        let cmdline_ptr = mb_info.cmdline as *const u8;
        let mut len = 0;
        
        // NULL終端までの長さを取得
        while unsafe { *cmdline_ptr.add(len) } != 0 {
            len += 1;
        }
        
        let cmdline_slice = unsafe { slice::from_raw_parts(cmdline_ptr, len) };
        String::from_utf8_lossy(cmdline_slice).to_string()
    } else {
        String::new()
    };
    
    // ブートドライブ情報を取得
    let boot_drive = if (mb_info.flags & (1 << 1)) != 0 {
        Some(BootDriveInfo {
            drive_number: (mb_info.boot_device >> 24) as u8,
            partition: Some(PartitionInfo {
                number: ((mb_info.boot_device >> 16) & 0xFF) as u8,
                partition_type: 0, // マルチブートでは指定されない
                start_lba: 0,      // マルチブートでは指定されない
                sector_count: 0,   // マルチブートでは指定されない
            }),
        })
    } else {
        unsafe { get_boot_drive_info() }
    };
    
    // ブート情報を作成
    let mut boot_info = BootInfo::from_legacy(
        memory_map,
        framebuffer,
        None,
        cmdline,
        boot_drive,
    );
    
    // モジュール情報を取得
    if (mb_info.flags & (1 << 3)) != 0 {
        let mods_addr = mb_info.mods_addr as usize;
        let mods_count = mb_info.mods_count as usize;
        
        for i in 0..mods_count {
            let mod_addr = mods_addr + i * 16;
            let mod_start = unsafe { *(mod_addr as *const u32) } as usize;
            let mod_end = unsafe { *((mod_addr + 4) as *const u32) } as usize;
            let mod_cmdline = unsafe { *((mod_addr + 8) as *const u32) } as *const u8;
            
            // モジュール名を取得
            let mut len = 0;
            while unsafe { *mod_cmdline.add(len) } != 0 {
                len += 1;
            }
            
            let cmd_slice = unsafe { slice::from_raw_parts(mod_cmdline, len) };
            let cmd_string = String::from_utf8_lossy(cmd_slice).to_string();
            
            // モジュールをブート情報に追加
            boot_info.add_module(mod_start, mod_end, cmd_string);
            
            // 最初のモジュールが初期RAMディスクの場合は設定
            if i == 0 && cmd_string.contains("initrd") {
                boot_info.set_initrd(mod_start, mod_end - mod_start);
            }
        }
    }
    
    Ok(boot_info)
}

/// ACPI RSDPを検索
fn find_acpi_rsdp(start_addr: usize, end_addr: usize) -> Option<usize> {
    // RSDPのシグネチャ "RSD PTR "
    let signature = b"RSD PTR "; // No null terminator in signature itself
    
    serial_println!("[ACPI] Searching for RSDP in range {:#x} - {:#x}", start_addr, end_addr);

    // 16バイト境界でのみ検索
    for current_addr in (start_addr..=(end_addr.saturating_sub(signature.len()))).step_by(16) {
        let mem_slice = unsafe { slice::from_raw_parts(current_addr as *const u8, signature.len()) };
        
        if mem_slice == signature {
            serial_println!("[ACPI] Found \"RSD PTR \" signature at {:#x}", current_addr);
            // ACPI 1.0 RSDPは20バイト (revision 0)
            // ACPI 2.0+ RSDPは36バイト (revision 2+)
            // まずは20バイトでチェックサムを検証
            let rsdp_v1_slice = unsafe { slice::from_raw_parts(current_addr as *const u8, 20) };
            let checksum_v1 = rsdp_v1_slice.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
            
            if checksum_v1 == 0 {
                serial_println!("[ACPI] RSDP v1 checksum is valid at {:#x}.", current_addr);
                let revision = rsdp_v1_slice[15]; // Revision field
                serial_println!("[ACPI] RSDP Revision: {}", revision);

                if revision >= 2 {
                    // ACPI 2.0+ : 36バイト全体のチェックサムも検証
                    if end_addr >= current_addr + 36 {
                        let rsdp_v2_slice = unsafe { slice::from_raw_parts(current_addr as *const u8, 36) };
                        let checksum_v2 = rsdp_v2_slice.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
                        if checksum_v2 == 0 {
                            serial_println!("[ACPI] RSDP v2 checksum is valid.");
                            return Some(current_addr);
                        } else {
                            serial_println!("[ACPI] RSDP v2 checksum is invalid. Using v1 (if applicable).");
                            // v1は有効なので、v1のアドレスを返す (XSDTではなくRSDTを使うことになる)
                            return Some(current_addr); 
                        }
                    } else {
                         serial_println!("[ACPI] Not enough space for v2 RSDP at {:#x}, using v1.", current_addr);
                         return Some(current_addr);
                    }
                } else {
                    // Revision 0 or 1, only v1 struct is valid
                    return Some(current_addr);
                }
            } else {
                serial_println!("[ACPI] RSDP v1 checksum invalid at {:#x}", current_addr);
            }
        }
    }
    serial_println!("[ACPI] RSDP not found in range {:#x} - {:#x}", start_addr, end_addr);
    None
}

/// レガシーBIOS環境からブート
pub fn boot() -> Result<super::BootInfo, &'static str> {
    // シリアルポートの初期化（デバッグ出力用）
    init_serial_port(0x3F8); // COM1
    serial_println!("------------------------------------");
    serial_println!(" AetherOS Legacy Bootloader Starting ");
    serial_println!("------------------------------------");


    // ブートローダーから渡された情報を取得
    // このアドレスは通常、マルチブート準拠ローダによってebxレジスタに格納されている
    let mb_info_addr = get_boot_address_from_registers();
    if mb_info_addr == 0 {
        serial_println!("[ERROR] Multiboot info address is null (EBX was zero).");
        // No alternative standard way to get this info, so error out.
        return Err("Multiboot info address is null");
    }
    serial_println!("[INIT] Multiboot info address (from EBX): {:#x}", mb_info_addr);

    // マルチブート情報をパース
    match parse_multiboot_info(mb_info_addr) {
        Ok(mut boot_info) => { // boot_infoをミュータブルに変更
            serial_println!("[INIT] Multiboot info parsed successfully.");
            
            // ACPI RSDPを検索 (標準的な検索範囲)
            // 1. EBDA (Extended BIOS Data Area) の最初の1KB (BDA 0040:000E からポインタ取得)
            //    ここでは簡略化のため、一般的なアドレス範囲を直接検索
            // 2. 0xE0000 から 0xFFFFF (128KB)
            let rsdp_addr = find_acpi_rsdp(0x80000, 0x9FFFF) // 一部のシステムではこの範囲にもある
                .or_else(|| find_acpi_rsdp(0xE0000, 0xFFFFF)); 
            
            if let Some(addr) = rsdp_addr {
                serial_println!("[ACPI] ACPI RSDP found at: {:#x}", addr);
                boot_info.rsdp_addr = Some(addr); // boot_infoにRSDPアドレスを保存
            } else {
                serial_println!("[WARN] ACPI RSDP not found in common areas.");
                 boot_info.rsdp_addr = None;
            }
            
            // グローバルなBootInfoに設定 (カーネルが後でアクセスできるように)
            // この関数は `kernel/src/boot.rs` などに定義されていることを想定
            unsafe { crate::boot::set_global_boot_info(boot_info.clone()); }

            serial_println!("[INIT] Performing final hardware checks and setup...");
            // ここで追加のハードウェアチェックや、低レベルな初期設定が可能
            // 例: CPUIDを通じたCPU機能の確認、APICの基本的な状態確認など

            // カーネルに制御を渡す前の最終準備
            // ページングの設定、保護モードへの移行、そしてロングモードへの移行（x86_64の場合）
            // この処理はアーキテクチャ依存であり、通常は `arch` モジュール内の関数が担当する。
            // `setup_paging_and_protection_mode` は既にその呼び出しを行っている。
            setup_paging_and_protection_mode();

            serial_println!("[BOOT] Boot process completed by legacy_boot. Handing over to kernel...");
            serial_println!("------------------------------------");
            Ok(boot_info)
        }
        Err(e) => {
            serial_println!("[FATAL] Error parsing multiboot info: {}", e);
            // 致命的なエラーなので、ここで停止するのが適切
            // panic!("Failed to parse Multiboot information: {}", e);
            Err(e)
        }
    }
}

/// シリアルポートの初期化
fn init_serial_port(port: u16) {
    unsafe {
        // ボーレート設定: 115200 bps
        outb(port + 1, 0x00);    // 割り込み無効
        outb(port + 3, 0x80);    // DLAB設定
        outb(port + 0, 0x01);    // 低バイト: 115200 / 115200 = 1
        outb(port + 1, 0x00);    // 高バイト
        outb(port + 3, 0x03);    // 8ビット、ノーパリティ、1ストップビット
        outb(port + 2, 0xC7);    // FIFO有効、64バイトFIFO、クリア
        outb(port + 4, 0x0B);    // IRQ有効、RTS/DTRセット
    }
}

/// シリアルポートに文字を出力
fn serial_putchar(port: u16, c: u8) {
    unsafe {
        // 送信バッファが空になるまで待機
        while (inb(port + 5) & 0x20) == 0 {}
        outb(port, c);
    }
}

/// シリアルポートに文字列を出力
fn serial_puts(port: u16, s: &str) {
    for c in s.bytes() {
        if c == b'\n' {
            serial_putchar(port, b'\r');
        }
        serial_putchar(port, c);
    }
}

// I/Oポートに1バイト書き込み
unsafe fn outb(port: u16, value: u8) {
    asm!("outb %al, %dx", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
}

// I/Oポートから1バイト読み込み
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    asm!("inb %dx, %al", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
    value
}

// シリアルポート出力用マクロ
macro_rules! serial_print {
    ($($arg:tt)*) => ({
        use core::fmt::Write;
        let _ = write!(SerialPort(0x3F8), $($arg)*);
    });
}

macro_rules! serial_println {
    () => (serial_print!("\n"));
    ($fmt:expr) => (serial_print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (serial_print!(concat!($fmt, "\n"), $($arg)*));
}

// シリアルポートラッパー（fmt::Writeの実装用）
struct SerialPort(u16);

impl core::fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial_puts(self.0, s);
        Ok(())
    }
}

/// ページングを設定し、保護モード（32ビットまたは64ビット）に移行する
///
/// ## 注意:
/// この関数は非常に低レベルな操作を行い、誤るとシステムが即座にクラッシュします。
/// 実際のOS開発では、アーキテクチャのマニュアルを熟読し、慎重なテストが必要です。
/// ここでは概念的な手順を示します。
///
/// ## 手順の概要 (x86の例):
/// 1. **GDT (Global Descriptor Table) の設定:**
///    - カーネルモードおよびユーザーモード用のコードセグメントとデータセグメントディスクリプタを定義。
///    - GDTレジスタ (GDTR) にGDTのベースアドレスとリミットを設定。
/// 2. **ページテーブルの構築:**
///    - PML4 (Page Map Level 4), PDPT (Page Directory Pointer Table), PD (Page Directory), PT (Page Table) を設定。
///    - 少なくともカーネル自身が存在する物理メモリ領域をアイデンティティマッピング（仮想アドレス=物理アドレス）する。
///    - フレームバッファなどのMMIO領域もマッピングする。
///    - 必要に応じて、より高いアドレス空間へのマッピング（例: ハイヤーハーフカーネル）も行う。
/// 3. **CR3レジスタの設定:**
///    - PML4テーブルの物理ベースアドレスをCR3レジスタにロードする。
/// 4. **CR0レジスタのページング有効化 (PGビット):**
///    - CR0レジスタのPGビット (ビット31) を1に設定してページングを有効にする。
///    - 同時にPEビット (ビット0, 保護モード有効化) も設定されていることを確認 (または設定する)。
///    - (ロングモードの場合) EFERレジスタのLMEビット (ロングモード有効) も設定する。
/// 5. **セグメントレジスタの再ロード:**
///    - 新しいGDTを参照するように、CS, DS, ES, SS, FS, GSセグメントレジスタをリロードする。
///    - 特にCSのリロードは `ljmp` (far jump) 命令で行うことが多い。
/// 6. **スタックポインタの再設定:**
///    - 新しいページング環境とセグメント設定に合わせたスタックポインタ (ESP/RSP) を設定する。
fn setup_paging_and_protection_mode() {
    serial_println!("Setting up paging and protection mode for x86_64...");

    // アーキテクチャ依存の初期化処理を呼び出す
    // この関数内でGDTの設定、ページテーブルの構築などを行う
    match unsafe { crate::arch::x86_64::mm::paging::init() } {
        Ok(_) => serial_println!("Paging and protection mode enabled successfully for x86_64."),
        Err(e) => {
            serial_println!("Error enabling paging and protection mode for x86_64: {:?}", e);
            // エラー発生時はパニックさせるか、適切なエラーハンドリングを行う
            panic!("Failed to initialize paging and protection mode: {:?}", e);
        }
    }

    // ロングモードへのジャンプと新しいスタックの設定
    // この処理もアーキテクチャ依存であり、archモジュール内で実行されるべき
    // 例: crate::arch::x86_64::cpu::jump_to_long_mode_and_set_stack(new_stack_top, kernel_entry_point);

    serial_println!("Paging and protection mode setup complete (delegated to arch-specific init).");
}

/// ブートローダーから渡されたMultiboot情報のアドレスを取得
/// (通常はebxレジスタに格納されている)
fn get_boot_address_from_registers() -> usize {
    let mut mb_info_addr: usize;
    unsafe {
        core::arch::asm!(
            "mov {}, ebx", // Multiboot standard: info struct pointer in EBX
            out(reg) mb_info_addr,
            options(nomem, nostack, preserves_flags, pure, readonly) // pureを追加
        );
    }
    // この段階でのシリアル出力は、Multiboot情報アドレスが有効であることの確認に役立つ
    // init_serial_portが呼ばれた後でないと意味がないので、呼び出し元でログを出す
    mb_info_addr
}

// テスト用のダミーBootInfoを生成する関数（必要に応じて）
#[cfg(test)]
fn create_dummy_boot_info() -> BootInfo {
    BootInfo {
        memory_map: MemoryMap::new(),
        framebuffer_info: None,
        rsdp_addr: None,
        cmdline: String::new(),
        boot_drive_info: None,
        acpi_info: None,
    }
} 