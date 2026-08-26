; MIT-334: xchg E2E sample 的 MASM helper (MSVC x64 不支持 inline asm,
; 无法让 C++ 强制 codegen 出 xchg r, r —— std::swap 等高 level C++ 全部
; 编译成 mov+mov+mov, 不出 xchg. 此 helper 直接 emit xchg rax, rbx /
; xchg eax, ebx 真指令, 链接进 wvmp_xchg_sample.
;
; 函数语义: 在 marker_begin / marker_end 调用之间包含真 xchg REG-REG
; (REX.W = `48 87 C0` 类字节 / 无 REX.W = `87 C0` 类字节). marker_scan
; 识别 WVMPBEG1/WVMPEND1 magic 字节 + 紧随的 E8 call, 标定区域. lifter
; 把区域内 mov/xchg/mov/mov 一一翻译为 VmOp::mov / VmOp::Xchg /
; VmOp::mov / VmOp::mov, asmgen 的 build_xchg handler 真正被 exercise.
;
; Win64 ABI: rcx/rdx/r8 = 前 3 个整型/指针参数, rax = 返回值. callee-saved:
; rbx, rbp, rdi, rsi, r12-r15. 此函数用 rbx/rsi 作临时寄存器, push/pop 守恒.

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXXZ (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; uint64_t xchg64_fn(uint64_t x, uint64_t y)
;   返回交换后的 x (= 原 y).
xchg64_fn PROC
    push rbx
    sub  rsp, 56

    mov  [rsp+32], rcx
    mov  [rsp+40], rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ

    mov  rax, [rsp+32]            ; a := x
    mov  rbx, [rsp+40]            ; b := y
    xchg rax, rbx                 ; 真 xchg REG-REG (REX.W + 0x87 + ModR/M)
    mov  [rsp+32], rax            ; a := 原 y
    mov  [rsp+40], rbx            ; b := 原 x

    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    mov  rax, [rsp+32]            ; 返回新 a 值
    add  rsp, 56
    pop  rbx
    ret
xchg64_fn ENDP

; uint32_t xchg32_fn(uint32_t x, uint32_t y)
;   返回交换后的 x (= 原 y).
xchg32_fn PROC
    push rbx
    sub  rsp, 40

    mov  [rsp+32], ecx            ; low 32 of rcx = x
    mov  [rsp+36], edx            ; low 32 of rdx = y

    call ?marker_begin@sdk@wvmp@@YAXXZ

    mov  eax, [rsp+32]            ; a := x (低 32)
    mov  ebx, [rsp+36]            ; b := y (低 32)
    xchg eax, ebx                 ; 真 xchg REG-REG (无 REX.W, 32-bit)
    mov  [rsp+32], eax
    mov  [rsp+36], ebx

    call ?marker_end@sdk@wvmp@@YAXXZ

    mov  eax, [rsp+32]
    add  rsp, 40
    pop  rbx
    ret
xchg32_fn ENDP

; uint64_t xchg_chain_fn(uint64_t* a, uint64_t* b, uint64_t* c)
;   链式 xchg (a↔b, b↔c, a↔b 共 3 次). 验证 dst/src 顺序不影响 handler
;   语义, 且多次 xchg 链接正确. 返回最终 *a.
xchg_chain_fn PROC
    push rbx
    push rsi
    push rdi
    sub  rsp, 32

    mov  [rsp+32], rcx            ; save &a
    mov  [rsp+40], rdx            ; save &b
    mov  [rsp+48], r8             ; save &c

    call ?marker_begin@sdk@wvmp@@YAXXZ

    ; load *a / *b / *c into 3 scratch registers
    mov  rsi, [rsp+32]
    mov  rax, [rsi]               ; rax := *a
    mov  rsi, [rsp+40]
    mov  rbx, [rsi]               ; rbx := *b
    mov  rsi, [rsp+48]
    mov  rcx, [rsi]               ; rcx := *c

    xchg rax, rbx                 ; a↔b
    xchg rbx, rcx                 ; b↔c
    xchg rax, rbx                 ; a↔b

    ; store 3 values back to *a / *b / *c
    mov  rdi, [rsp+32]
    mov  [rdi], rax               ; *a := ...
    mov  rdi, [rsp+40]
    mov  [rdi], rbx               ; *b := ...
    mov  rdi, [rsp+48]
    mov  [rdi], rcx               ; *c := ...

    call ?marker_end@sdk@wvmp@@YAXXZ

    mov  rax, [rsp+32]
    mov  rax, [rax]               ; 返回最终 *a 值

    add  rsp, 32
    pop  rdi
    pop  rsi
    pop  rbx
    ret
xchg_chain_fn ENDP

_TEXT ENDS

END
