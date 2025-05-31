// AetherOS x86_64 高度CPU拡張機能サポート
//
// 最新のx86_64拡張命令セット(AVX-512、AMX、CET、VAES、VPCLMULQDQなど)をサポートします。
// これらの機能を検出し、適切に初期化・最適化する機能を提供します。

use alloc::string::String;
use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::registers::control::{Cr4, Cr4Flags, XCr0, XCr0Flags};
use x86_64::instructions::cpuid::{CpuId, ExtendedFunction, Function};

/// 高度なx86_64 CPU拡張機能フラグ
#[derive(Debug, Clone, Copy)]
pub struct AdvancedCpuFeatures {
    // AVX-512関連
    pub avx512f: bool,      // Foundation
    pub avx512bw: bool,     // Byte and Word Instructions
    pub avx512cd: bool,     // Conflict Detection
    pub avx512dq: bool,     // Doubleword and Quadword
    pub avx512vl: bool,     // Vector Length Extensions
    pub avx512ifma: bool,   // Integer Fused Multiply-Add
    pub avx512vbmi: bool,   // Vector Byte Manipulation Instructions
    pub avx512vbmi2: bool,  // Vector Byte Manipulation Instructions 2
    pub avx512vnni: bool,   // Vector Neural Network Instructions
    pub avx512bitalg: bool, // Bit Algorithms
    pub avx512vpopcntdq: bool, // Vector Population Count
    pub avx512fp16: bool,   // 16-bit Floating-Point

    // AMX関連 (Advanced Matrix Extensions)
    pub amx_bf16: bool,     // Brain Float 16-bit
    pub amx_int8: bool,     // 8-bit Integer
    pub amx_tile: bool,     // Tile Architecture

    // セキュリティ拡張
    pub cet_ss: bool,       // Control-flow Enforcement Technology - Shadow Stack
    pub cet_ibt: bool,      // Control-flow Enforcement Technology - Indirect Branch Tracking
    
    // その他の高度な拡張
    pub vaes: bool,         // Vector AES
    pub vpclmulqdq: bool,   // Vector Carryless Multiplication
    pub gfni: bool,         // Galois Field New Instructions
    pub sha: bool,          // SHA Extensions
    pub serialize: bool,    // Serialize Instruction
    pub tsxldtrk: bool,     // TSX Suspend Load Address Tracking
    pub pconfig: bool,      // Platform Configuration
    pub waitpkg: bool,      // Wait and Pause Enhancements
    pub uintr: bool,        // User Interrupts
    pub hreset: bool,       // History Reset
    pub kl: bool,           // Key Locker
}

/// 高度なCPU拡張機能を検出
pub fn detect_advanced_features() -> AdvancedCpuFeatures {
    let cpuid = CpuId::new();
    
    // 拡張機能 (CPUID.7:EBX/ECX/EDX)
    let leaf_7 = cpuid.get_extended_feature_info();
    
    let ebx_7_0 = leaf_7.map_or(0, |f| f.ebx());
    let ecx_7_0 = leaf_7.map_or(0, |f| f.ecx());
    let edx_7_0 = leaf_7.map_or(0, |f| f.edx());
    
    // CPUID.7.1 (サブリーフ1のEAX/EBX/ECX)
    let subleaf_7_1 = cpuid.get_extended_feature_info_subleaf(1);
    let eax_7_1 = subleaf_7_1.map_or(0, |f| f.eax());
    
    // CPUID.0xD:EAX (XSAVEに関する情報)
    let xcr0_eax = cpuid.get_extended_state_info()
                       .map_or(0, |f| f.xcr0_supported_bits());
    
    AdvancedCpuFeatures {
        // AVX-512 拡張
        avx512f: (ebx_7_0 & (1 << 16)) != 0,      // AVX-512 Foundation
        avx512dq: (ebx_7_0 & (1 << 17)) != 0,     // AVX-512 Doubleword and Quadword
        avx512ifma: (ebx_7_0 & (1 << 21)) != 0,   // AVX-512 Integer Fused Multiply-Add
        avx512cd: (ebx_7_0 & (1 << 28)) != 0,     // AVX-512 Conflict Detection
        avx512bw: (ebx_7_0 & (1 << 30)) != 0,     // AVX-512 Byte and Word
        avx512vl: (ebx_7_0 & (1 << 31)) != 0,     // AVX-512 Vector Length Extensions
        avx512vbmi: (ecx_7_0 & (1 << 1)) != 0,    // AVX-512 Vector Byte Manipulation Instructions
        avx512vbmi2: (ecx_7_0 & (1 << 6)) != 0,   // AVX-512 Vector Byte Manipulation Instructions 2
        avx512vnni: (ecx_7_0 & (1 << 11)) != 0,   // AVX-512 Vector Neural Network Instructions
        avx512bitalg: (ecx_7_0 & (1 << 12)) != 0, // AVX-512 Bit Algorithms
        avx512vpopcntdq: (ecx_7_0 & (1 << 14)) != 0, // AVX-512 Vector Population Count
        avx512fp16: (edx_7_0 & (1 << 23)) != 0,   // AVX-512 FP16

        // AMX 拡張
        amx_bf16: (edx_7_0 & (1 << 22)) != 0,     // AMX bf16 support
        amx_int8: (edx_7_0 & (1 << 24)) != 0,     // AMX int8 support
        amx_tile: (edx_7_0 & (1 << 25)) != 0,     // AMX Tile Architecture

        // セキュリティ拡張
        cet_ss: (ecx_7_0 & (1 << 7)) != 0,        // CET Shadow Stack
        cet_ibt: (edx_7_0 & (1 << 20)) != 0,      // CET Indirect Branch Tracking
        
        // その他の高度な拡張
        vaes: (ecx_7_0 & (1 << 9)) != 0,          // Vector AES
        vpclmulqdq: (ecx_7_0 & (1 << 10)) != 0,   // Vector Carryless Multiplication
        gfni: (ecx_7_0 & (1 << 8)) != 0,          // Galois Field New Instructions
        sha: (ebx_7_0 & (1 << 29)) != 0,          // SHA Extensions
        serialize: (edx_7_0 & (1 << 14)) != 0,     // SERIALIZE instruction
        tsxldtrk: (edx_7_0 & (1 << 16)) != 0,     // TSX Suspend Load Address Tracking
        pconfig: (edx_7_0 & (1 << 18)) != 0,      // Platform Configuration
        waitpkg: (ecx_7_0 & (1 << 5)) != 0,       // WAITPKG
        uintr: (edx_7_0 & (1 << 5)) != 0,         // User Interrupts
        hreset: (eax_7_1 & (1 << 22)) != 0,       // History Reset
        kl: (eax_7_1 & (1 << 23)) != 0,           // Key Locker
    }
}

/// AVX-512拡張命令セットを有効化
pub fn enable_avx512() {
    use x86_64::registers::control::{XCr0, XCr0Flags};
    
    unsafe {
        // XCR0.AVX512[ビット5,6,7]=1 (AVX-512状態の保存/復元有効化)
        let xcr0 = XCr0::read() | XCr0Flags::AVX512_OPMASK | XCr0Flags::AVX512_ZMM_HI256 | XCr0Flags::AVX512_ZMM_HI16;
        XCr0::write(xcr0);
    }
}

/// AMX (Advanced Matrix Extensions)を有効化
pub fn enable_amx() {
    use x86_64::registers::control::{XCr0};
    
    unsafe {
        // XCR0.AMX_TILE[ビット17]=1 (AMXタイルレジスタの保存/復元有効化)
        let xcr0 = XCr0::read() | (1 << 17); // AMX_TILE
        XCr0::write(xcr0);
        
        // AMXの構成 - MSR 0x00000513 (IA32_AMX_TILE_CFG)
        let msr_amx_tile_cfg = x86_64::registers::model_specific::Msr::new(0x00000513);
        msr_amx_tile_cfg.write(0xFFFF_FFFF_FFFF_FFFF);
    }
}

/// Control-flow Enforcement Technology (CET)を有効化
pub fn enable_cet() {
    unsafe {
        // MSR 0x6A2 (IA32_U_CET) - Userモード用CET設定
        let user_cet = x86_64::registers::model_specific::Msr::new(0x6A2);
        // ビット0: SHSTK(Shadow Stack)有効化
        // ビット1: ENDBR(Indirect Branch Tracking)有効化
        user_cet.write(0x3);
        
        // MSR 0x6A0 (IA32_S_CET) - Supervisorモード用CET設定
        let supervisor_cet = x86_64::registers::model_specific::Msr::new(0x6A0);
        supervisor_cet.write(0x3);
    }
}

/// 高度なプロセッサ拡張機能を初期化
pub fn init_advanced_features() {
    let features = detect_advanced_features();
    
    // 検出された機能に基づいて個別に有効化
    if features.avx512f {
        enable_avx512();
    }
    
    if features.amx_tile {
        enable_amx();
    }
    
    if features.cet_ss || features.cet_ibt {
        enable_cet();
    }
}

/// 高度なCPU機能の情報文字列を取得
pub fn advanced_cpu_features_info() -> String {
    let features = detect_advanced_features();
    let mut info = String::from("高度なCPU機能: ");
    
    if features.avx512f {
        info.push_str("AVX-512F ");
        if features.avx512bw { info.push_str("AVX-512BW "); }
        if features.avx512cd { info.push_str("AVX-512CD "); }
        if features.avx512dq { info.push_str("AVX-512DQ "); }
        if features.avx512vl { info.push_str("AVX-512VL "); }
        if features.avx512ifma { info.push_str("AVX-512IFMA "); }
        if features.avx512vbmi { info.push_str("AVX-512VBMI "); }
        if features.avx512vbmi2 { info.push_str("AVX-512VBMI2 "); }
        if features.avx512vnni { info.push_str("AVX-512VNNI "); }
        if features.avx512bitalg { info.push_str("AVX-512BITALG "); }
        if features.avx512vpopcntdq { info.push_str("AVX-512VPOPCNTDQ "); }
        if features.avx512fp16 { info.push_str("AVX-512FP16 "); }
    }
    
    if features.amx_tile {
        info.push_str("AMX-TILE ");
        if features.amx_bf16 { info.push_str("AMX-BF16 "); }
        if features.amx_int8 { info.push_str("AMX-INT8 "); }
    }
    
    if features.cet_ss { info.push_str("CET-SS "); }
    if features.cet_ibt { info.push_str("CET-IBT "); }
    if features.vaes { info.push_str("VAES "); }
    if features.vpclmulqdq { info.push_str("VPCLMULQDQ "); }
    if features.gfni { info.push_str("GFNI "); }
    if features.sha { info.push_str("SHA "); }
    
    info
} 