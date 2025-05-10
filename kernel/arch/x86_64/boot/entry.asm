; AetherOS x86_64 エントリポイント
;
; このファイルは x86_64 アーキテクチャの最初のエントリポイントを定義します。
; マルチブート2とUEFIの両方のブートをサポートしています。

global _start
global _stack_bottom
global _stack_top
global _bss_start
global _bss_end

extern kmain
extern detect_and_init_boot_protocol

%define MULTIBOOT2_MAGIC 0x36d76289
%define UEFI_MAGIC      0x33EF1551

section .multiboot
    ; Multiboot2ヘッダー
    align 8
multiboot_header:
    dd 0xe85250d6                ; マジックナンバー
    dd 0                        ; アーキテクチャ: 0 (i386)
    dd multiboot_header_end - multiboot_header
    dd -(0xe85250d6 + 0 + (multiboot_header_end - multiboot_header))

    ; 情報要求タグ
    align 8
    dw 1                        ; タグタイプ: 情報要求
    dw 0                        ; フラグ
    dd 12                       ; サイズ
    dd 1                        ; メモリマップを要求
    dd 5                        ; ブートデバイスを要求

    ; フレームバッファタグ
    align 8
    dw 5                        ; タグタイプ: フレームバッファ
    dw 0                        ; フラグ
    dd 20                       ; サイズ
    dd 0                        ; 幅（0=任意）
    dd 0                        ; 高さ（0=任意）
    dd 32                       ; ビット深度（32推奨）

    ; モジュールアラインメントタグ
    align 8
    dw 6                        ; タグタイプ: モジュールアラインメント
    dw 0                        ; フラグ
    dd 8                        ; サイズ

    ; コンソールタグ
    align 8
    dw 4                        ; タグタイプ: コンソール
    dw 0                        ; フラグ
    dd 12                       ; サイズ
    dd 1                        ; VGAテキストコンソールを要求
    dd 0                        ; 代替コンソールを要求しない

    ; 終端タグ
    align 8
    dw 0                        ; タグタイプ: 終端
    dw 0                        ; フラグ
    dd 8                        ; サイズ
multiboot_header_end:

section .bss
    align 16
    _bss_start:
    ; 初期スタック領域の確保（64KiB）
    _stack_bottom:
    resb 65536
    _stack_top:
    _bss_end:

section .text
    ; エントリポイント
    align 8
_start:
    cli                         ; 割り込み禁止
    cld                         ; 文字列操作方向をクリア

    ; フラグレジスタを保存
    pushfq
    pop rax
    mov rbx, rax                ; rbxにフラグを保存

    ; MULTIBOOT2/UEFIマジックナンバーの検証
    cmp eax, MULTIBOOT2_MAGIC
    je .multiboot2_boot
    cmp eax, UEFI_MAGIC
    je .uefi_boot
    
    ; 無効なマジックナンバーの場合はハルト
    mov rsi, invalid_boot_msg
    mov rdx, invalid_boot_msg_len
    call print_error
    jmp halt_cpu

.multiboot2_boot:
    ; マルチブート2で起動された場合
    mov [multiboot_magic], eax   ; マジックナンバーを保存
    mov [multiboot_info], rbx    ; ブート情報アドレスを保存
    jmp .common_boot

.uefi_boot:
    ; UEFIで起動された場合
    mov [uefi_magic], eax        ; マジックナンバーを保存 
    mov [uefi_info], rbx         ; ブート情報アドレスを保存

.common_boot:
    ; スタックポインタ設定
    mov rsp, _stack_top

    ; .bssセクションを0でクリア
    mov rdi, _bss_start
    mov rcx, _bss_end
    sub rcx, _bss_start
    xor eax, eax
    shr rcx, 3                  ; 8バイト単位で処理
    rep stosq

    ; パラメータをかみ合わせる
    ; ブートローダーが使用したマジックナンバーとブート情報アドレスを渡す
    mov rdi, [multiboot_magic]
    test rdi, rdi
    jnz .use_multiboot
    
    mov rdi, [uefi_magic]
    mov rsi, [uefi_info]
    jmp .call_boot_detect
    
.use_multiboot:
    mov rsi, [multiboot_info]
    
.call_boot_detect:
    ; ブートプロトコル検出と初期化
    call detect_and_init_boot_protocol

    ; カーネルメイン関数を呼び出し
    ; RDIに0をセット（スレッドID）
    xor rdi, rdi
    call kmain

    ; カーネルが返った場合はハルト
halt_cpu:
    cli
    hlt
    jmp halt_cpu

; エラーメッセージを出力するシンプルな関数
; rsi: メッセージアドレス
; rdx: メッセージ長
print_error:
    push rax
    push rbx
    push rcx
    push rdi
    
    ; VGAテキストモードバッファアドレス
    mov rdi, 0xB8000
    
    ; 赤テキスト属性（背景黒 = 0x4F）
    mov ah, 0x4F
    
    ; メッセージのコピー
    mov rcx, rdx
    xor rbx, rbx
    
.loop:
    test rcx, rcx
    jz .done
    
    mov al, [rsi + rbx]
    mov [rdi], ax
    add rdi, 2
    inc rbx
    dec rcx
    jmp .loop
    
.done:
    pop rdi
    pop rcx
    pop rbx
    pop rax
    ret

section .data
    ; ブート情報の保存用変数
    multiboot_magic: dq 0
    multiboot_info:  dq 0
    uefi_magic:      dq 0
    uefi_info:       dq 0
    
    ; エラーメッセージ
    invalid_boot_msg: db 'Invalid boot magic number! Halting...'
    invalid_boot_msg_len: equ $ - invalid_boot_msg 