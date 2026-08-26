; MIT-336: setcc E2E sample 的 MASM helper (MSVC x64 不支持 inline asm,
; 无法让 C++ 强制 codegen 出 setcc r/m8 —— MSVC 编译器把 `bool cond = a == b`
; 编译成 `cmp; sete; movzx` 但 movzx 0x0F B6 是 movzx 而不是 setcc 单独暴露;
; 此 helper 直接 emit 真 setcc 字节, 链接进 wvmp_setcc_sample。
;
; 函数语义: 在 marker_begin / marker_end 调用之间包含真 setcc REG-REG
; (`0F 90+cc+rm` 字节, mod=11). marker_scan 识别 WVMPBEG1/WVMPEND1 magic
; 字节 + 紧随的 E8 call, 标定区域. lifter 把区域内 cmp/setcc/movzx 一一
; 翻译为 VmOp::Cmp / VmOp::Setcc / VmOp::Movzx, asmgen 的 build_setcc handler
; 真正被 exercise。
;
; Win64 ABI: rcx/rdx = 前 2 个整型/指针参数, rax = 返回值. callee-saved:
; rbx, rbp, rdi, rsi, r12-r15. 此函数用 rbx 作临时寄存器, push/pop 守恒.
;
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), 必须在 call 前存到 stack, call 后还原。
;
; 栈布局 (沿用 xchg_helper.asm 模式):
;   push rbx → rsp -= 8 → saved rbx 在 [rsp] (即 original - 8)
;   sub rsp, 56 → rsp -= 56 → rsp = original - 64
;   [rsp+24] = 临时存 rax (跨 SDK 调用)
;   [rsp+32] = local 1: a
;   [rsp+36] = local 2: b
;   [rsp+56] = original - 8 = saved rbx

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXXZ (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; uint64_t setne_fn(int a, int b): returns (a != b) ? 1 : 0.
; 区域 emit 真 `cmp ecx, edx` + `setne al` (3 字节 0F 95 C0) + `movzx rax, al`.
setne_fn PROC
    push rbx
    sub  rsp, 56

    mov  dword ptr [rsp+32], ecx   ; save a
    mov  dword ptr [rsp+36], edx   ; save b

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ

    mov  ecx, dword ptr [rsp+32]
    mov  edx, dword ptr [rsp+36]
    cmp  ecx, edx
    setne al                      ; 真 setcc REG (mod=11), 0F 95 C0
    movzx rax, al
    mov  [rsp+24], rax            ; ⚠️ rax 在 marker_end 后会被 clobber
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]            ; 还原 setcc 结果
    ; ===== marker region end =====

    add  rsp, 56
    pop  rbx
    ret
setne_fn ENDP

; uint64_t sete_fn(int a, int b): returns (a == b) ? 1 : 0.
sete_fn PROC
    push rbx
    sub  rsp, 56

    mov  dword ptr [rsp+32], ecx
    mov  dword ptr [rsp+36], edx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ

    mov  ecx, dword ptr [rsp+32]
    mov  edx, dword ptr [rsp+36]
    cmp  ecx, edx
    sete  al                      ; 真 sete REG, 0F 94 C0
    movzx rax, al
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 56
    pop  rbx
    ret
sete_fn ENDP

; uint64_t setb_fn(int a, int b): returns (a <u b) ? 1 : 0 (unsigned below).
setb_fn PROC
    push rbx
    sub  rsp, 56

    mov  dword ptr [rsp+32], ecx
    mov  dword ptr [rsp+36], edx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ

    mov  ecx, dword ptr [rsp+32]
    mov  edx, dword ptr [rsp+36]
    cmp  ecx, edx
    setb  al                      ; 真 setb REG (unsigned below), 0F 92 C0
    movzx rax, al
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 56
    pop  rbx
    ret
setb_fn ENDP

; uint64_t seta_fn(int a, int b): returns (a >u b) ? 1 : 0 (unsigned above).
seta_fn PROC
    push rbx
    sub  rsp, 56

    mov  dword ptr [rsp+32], ecx
    mov  dword ptr [rsp+36], edx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ

    mov  ecx, dword ptr [rsp+32]
    mov  edx, dword ptr [rsp+36]
    cmp  ecx, edx
    seta  al                      ; 真 seta REG (unsigned above), 0F 97 C0
    movzx rax, al
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 56
    pop  rbx
    ret
seta_fn ENDP

; uint64_t setl_fn(int a, int b): returns (a <s b) ? 1 : 0 (signed less).
setl_fn PROC
    push rbx
    sub  rsp, 56

    mov  dword ptr [rsp+32], ecx
    mov  dword ptr [rsp+36], edx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ

    mov  ecx, dword ptr [rsp+32]
    mov  edx, dword ptr [rsp+36]
    cmp  ecx, edx
    setl  al                      ; 真 setl REG (signed less), 0F 9C C0
    movzx rax, al
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 56
    pop  rbx
    ret
setl_fn ENDP

; uint64_t setg_fn(int a, int b): returns (a >s b) ? 1 : 0 (signed greater).
setg_fn PROC
    push rbx
    sub  rsp, 56

    mov  dword ptr [rsp+32], ecx
    mov  dword ptr [rsp+36], edx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ

    mov  ecx, dword ptr [rsp+32]
    mov  edx, dword ptr [rsp+36]
    cmp  ecx, edx
    setg  al                      ; 真 setg REG (signed greater), 0F 9F C0
    movzx rax, al
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 56
    pop  rbx
    ret
setg_fn ENDP

_TEXT ENDS

END