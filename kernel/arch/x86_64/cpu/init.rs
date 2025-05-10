//! x86_64 CPU初期化
//!
//! CPUの初期化と設定を行います。

use crate::arch::x86_64::idt::init_idt;
use crate::arch::x86_64::gdt::init_gdt;
use crate::arch::x86_64::paging::init_paging;
use crate::arch::x86_64::tss::init_tss;
use crate::arch::x86_64::boot::BootInfo;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::instructions::interrupts;

/// x86_64 CPU機能フラグ
#[derive(Debug, Clone, Copy)]
pub struct CpuFeatures {
    /// SSE対応フラグ
    pub sse: bool,
    /// SSE2対応フラグ
    pub sse2: bool,
    /// SSE3対応フラグ
    pub sse3: bool,
    /// SSSE3対応フラグ
    pub ssse3: bool,
    /// SSE4.1対応フラグ
    pub sse4_1: bool,
    /// SSE4.2対応フラグ
    pub sse4_2: bool,
    /// AVX対応フラグ
    pub avx: bool,
    /// AVX2対応フラグ
    pub avx2: bool,
    /// XSAVE対応フラグ
    pub xsave: bool,
    /// RDRAND対応フラグ
    pub rdrand: bool,
    /// RDSEED対応フラグ
    pub rdseed: bool,
    /// FSGSBASE対応フラグ
    pub fsgsbase: bool,
    /// SMEP対応フラグ
    pub smep: bool,
    /// SMAP対応フラグ
    pub smap: bool,
    /// UMIP対応フラグ
    pub umip: bool,
    /// APIC対応フラグ
    pub apic: bool,
    /// X2APIC対応フラグ
    pub x2apic: bool,
}

/// プロセッサID構造体
#[derive(Debug, Clone, Copy)]
pub struct ProcessorId {
    /// 製造元ID（例: "GenuineIntel", "AuthenticAMD"）
    pub vendor_id: [u8; 12],
    /// プロセッサ名文字列
    pub brand_string: [u8; 48],
    /// ファミリID
    pub family: u16,
    /// モデルID
    pub model: u8,
    /// ステッピングID
    pub stepping: u8,
}

// CPUは初期化されたか
static CPU_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// CPU機能を確認する
#[inline]
pub fn has_cpu_feature(feature: x86_64::registers::model_specific::Msr) -> bool {
    use x86_64::registers::model_specific::Msr;
    
    let value = unsafe { feature.read() };
    value != 0
}

/// CPUID命令を使用してCPU機能を検出
pub fn detect_cpu_features() -> CpuFeatures {
    if !x86_64::instructions::cpuid::has_cpuid() {
        // CPUID命令がサポートされていない（古すぎるCPU）
        return CpuFeatures {
            sse: false, sse2: false, sse3: false, ssse3: false,
            sse4_1: false, sse4_2: false, avx: false, avx2: false,
            xsave: false, rdrand: false, rdseed: false, fsgsbase: false,
            smep: false, smap: false, umip: false, apic: false, x2apic: false,
        };
    }

    use x86_64::instructions::cpuid::{CpuId, ExtendedFunction, Function};

    let cpuid = CpuId::new();
    
    // 基本機能
    let features_ecx = cpuid
        .get_feature_info()
        .map_or(0, |f| f.ecx());
    
    let features_edx = cpuid
        .get_feature_info()
        .map_or(0, |f| f.edx());
    
    // 拡張機能
    let ext_features = cpuid
        .get_extended_feature_info()
        .map_or((0, 0), |f| (f.ebx(), f.ecx()));
    
    // 拡張機能2
    let ext_features_7 = ext_features.0;
    let ext_features_7_ecx = ext_features.1;

    CpuFeatures {
        // ベーシック機能 (CPUID.1:EDX)
        sse: (features_edx & (1 << 25)) != 0,
        sse2: (features_edx & (1 << 26)) != 0,
        apic: (features_edx & (1 << 9)) != 0,
        
        // ベーシック機能 (CPUID.1:ECX)
        sse3: (features_ecx & (1 << 0)) != 0,
        ssse3: (features_ecx & (1 << 9)) != 0,
        sse4_1: (features_ecx & (1 << 19)) != 0,
        sse4_2: (features_ecx & (1 << 20)) != 0,
        avx: (features_ecx & (1 << 28)) != 0,
        xsave: (features_ecx & (1 << 26)) != 0,
        rdrand: (features_ecx & (1 << 30)) != 0,
        x2apic: (features_ecx & (1 << 21)) != 0,
        
        // 拡張機能 (CPUID.7:EBX)
        avx2: (ext_features_7 & (1 << 5)) != 0,
        fsgsbase: (ext_features_7 & (1 << 0)) != 0,
        smep: (ext_features_7 & (1 << 7)) != 0,
        smap: (ext_features_7 & (1 << 20)) != 0,
        rdseed: (ext_features_7 & (1 << 18)) != 0,
        
        // 拡張機能 (CPUID.7:ECX)
        umip: (ext_features_7_ecx & (1 << 2)) != 0,
    }
}

/// CPU製造元とモデル情報を取得
pub fn get_processor_id() -> ProcessorId {
    use x86_64::instructions::cpuid::CpuId;
    
    let cpuid = CpuId::new();
    
    // ベンダーID取得
    let vendor_id = cpuid.get_vendor_info()
        .map_or([0; 12], |vendor| {
            let mut result = [0; 12];
            let bytes = vendor.as_str().unwrap_or("Unknown").as_bytes();
            let len = bytes.len().min(12);
            result[..len].copy_from_slice(&bytes[..len]);
            result
        });
    
    // プロセッサブランド文字列取得
    let mut brand_string = [0; 48];
    if let Some(brand) = cpuid.get_processor_brand_string() {
        let brand_str = brand.as_str().unwrap_or("Unknown Processor");
        let bytes = brand_str.as_bytes();
        let len = bytes.len().min(48);
        brand_string[..len].copy_from_slice(&bytes[..len]);
    }
    
    // ファミリ、モデル、ステッピング情報取得
    let (family, model, stepping) = cpuid.get_feature_info()
        .map_or((0, 0, 0), |info| {
            let family_id = info.family_id();
            let model_id = info.model_id();
            let stepping_id = info.stepping_id();
            
            // 拡張ファミリ/モデルの処理
            let mut ext_family = 0;
            let mut ext_model = 0;
            
            if family_id == 0x0F {
                ext_family = ((info.eax() >> 20) & 0xFF) as u16;
            }
            
            if family_id == 0x06 || family_id == 0x0F {
                ext_model = ((info.eax() >> 16) & 0x0F) as u8;
            }
            
            let family = family_id as u16 + ext_family;
            let model = (ext_model << 4) | model_id;
            
            (family, model, stepping_id)
        });
    
    ProcessorId {
        vendor_id,
        brand_string,
        family,
        model,
        stepping,
    }
}

/// SSE拡張命令セットを有効化
pub fn enable_sse() {
    use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};
    
    unsafe {
        // CR0.EM[ビット2]=0, CR0.MP[ビット1]=1
        let mut cr0 = Cr0::read();
        cr0 &= !Cr0Flags::EMULATE_COPROCESSOR;
        cr0 |= Cr0Flags::MONITOR_COPROCESSOR;
        Cr0::write(cr0);
        
        // CR4.OSFXSR[ビット9]=1, CR4.OSXMMEXCPT[ビット10]=1
        let mut cr4 = Cr4::read();
        cr4 |= Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT;
        Cr4::write(cr4);
    }
}

/// AVX拡張命令セットを有効化
pub fn enable_avx() {
    use x86_64::registers::control::{Cr4, Cr4Flags, XCr0, XCr0Flags};
    
    unsafe {
        // CR4.OSXSAVE[ビット18]=1 (XSAVE命令を有効化)
        let mut cr4 = Cr4::read();
        cr4 |= Cr4Flags::OSXSAVE;
        Cr4::write(cr4);
        
        // XCR0.SSE[ビット1]=1, XCR0.AVX[ビット2]=1
        let xcr0 = XCr0::read() | XCr0Flags::SSE | XCr0Flags::AVX;
        XCr0::write(xcr0);
    }
}

/// パフォーマンスカウンタを有効化
pub fn enable_perfctr() {
    // 必要に応じて実装
}

/// FSGSBASEレジスタ命令を有効化
pub fn enable_fsgsbase() {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    
    unsafe {
        // CR4.FSGSBASE[ビット16]=1
        let mut cr4 = Cr4::read();
        cr4 |= Cr4Flags::FSGSBASE;
        Cr4::write(cr4);
    }
}

/// SMEPを有効化（スーパーバイザモード実行防止）
pub fn enable_smep() {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    
    unsafe {
        // CR4.SMEP[ビット20]=1
        let mut cr4 = Cr4::read();
        cr4 |= Cr4Flags::SMEP;
        Cr4::write(cr4);
    }
}

/// SMAPを有効化（スーパーバイザモードアクセス防止）
pub fn enable_smap() {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    
    unsafe {
        // CR4.SMAP[ビット21]=1
        let mut cr4 = Cr4::read();
        cr4 |= Cr4Flags::SMAP;
        Cr4::write(cr4);
    }
}

/// UMIPを有効化（ユーザモード命令防止）
pub fn enable_umip() {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    
    unsafe {
        // CR4.UMIP[ビット11]=1
        let mut cr4 = Cr4::read();
        cr4 |= Cr4Flags::UMIP;
        Cr4::write(cr4);
    }
}

/// CPUを初期化
pub fn init_cpu(boot_info: &BootInfo) -> Result<(), &'static str> {
    // 既に初期化済みならスキップ
    if CPU_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }
    
    // 割り込みを無効化して初期化
    interrupts::disable();
    
    // CPU機能を検出
    let features = detect_cpu_features();
    
    // GDT（グローバルディスクリプタテーブル）の初期化
    init_gdt();
    
    // TSS（タスクステートセグメント）の初期化
    init_tss();
    
    // IDT（割り込みディスクリプタテーブル）の初期化
    init_idt();
    
    // ページングの初期化
    init_paging(boot_info)?;
    
    // 各種CPU機能の有効化
    if features.sse {
        enable_sse();
    }
    
    if features.avx && features.xsave {
        enable_avx();
    }
    
    if features.fsgsbase {
        enable_fsgsbase();
    }
    
    if features.smep {
        enable_smep();
    }
    
    if features.smap {
        enable_smap();
    }
    
    if features.umip {
        enable_umip();
    }
    
    // 初期化完了フラグをセット
    CPU_INITIALIZED.store(true, Ordering::SeqCst);
    
    // すべて成功
    Ok(())
}

/// CPU情報を文字列で取得
pub fn cpu_info_string() -> alloc::string::String {
    use alloc::string::String;
    use alloc::format;
    
    let features = detect_cpu_features();
    let id = get_processor_id();
    
    let vendor = core::str::from_utf8(&id.vendor_id).unwrap_or("Unknown");
    let brand = core::str::from_utf8(&id.brand_string).unwrap_or("Unknown Processor");
    
    format!(
        "CPU: {}\nVendor: {}\nFamily: {}, Model: {}, Stepping: {}\nFeatures: SSE={}, SSE2={}, SSE3={}, SSSE3={}, SSE4.1={}, SSE4.2={}, AVX={}, AVX2={}, XSAVE={}, RDRAND={}, RDSEED={}, FSGSBASE={}, SMEP={}, SMAP={}, UMIP={}, APIC={}, X2APIC={}",
        brand.trim_end_matches('\0'),
        vendor.trim_end_matches('\0'),
        id.family, id.model, id.stepping,
        features.sse, features.sse2, features.sse3, features.ssse3,
        features.sse4_1, features.sse4_2, features.avx, features.avx2,
        features.xsave, features.rdrand, features.rdseed, features.fsgsbase,
        features.smep, features.smap, features.umip, features.apic, features.x2apic
    )
} 