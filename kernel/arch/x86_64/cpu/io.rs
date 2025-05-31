use core::arch::asm;

/// I/Oポートに1バイト書き込みます。
///
/// # Safety
/// この関数はI/Oポートに直接アクセスするため、安全ではありません。
/// 不適切なポートや値を書き込むと、ハードウェアに予期せぬ動作を引き起こす可能性があります。
#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    asm!("outb %al, %dx", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
}

/// I/Oポートから1バイト読み込みます。
///
/// # Safety
/// この関数はI/Oポートに直接アクセスするため、安全ではありません。
/// 不適切なポートから読み込むと、予期せぬ値を取得したり、ハードウェアの状態に影響を与える可能性があります。
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    asm!("inb %dx, %al", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
    value
} 