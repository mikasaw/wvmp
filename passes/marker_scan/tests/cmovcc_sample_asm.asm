; MIT-339: cmovcc E2E sample 的 MASM helper (MSVC x64 不支持 inline asm,
; 无法让 C++ 强制 codegen 出 cmovcc r, r/m —— MSVC 编译器把
; `if (a == b) x = c; else x = d;` 编译成 `cmp; jne skip; mov; skip:` 即 jcc+mov
; 而非 cmovcc; 此 helper 直接 emit 真 cmovcc 字节, 链接进 wvmp_cmovcc_sample。
;
; 函数语义: 在 marker_begin / marker_end 调用之间包含真 cmovcc REG-REG
; (`0F 40+cc+rm` 字节, mod=11). marker_scan 识别 WVMPBEG1/WVMPEND1 magic
; 字节 + 紧随的 E8 call, 标定区域. lifter 把区域内 cmp/cmovcc/mov 一一
; 翻译为 VmOp::Cmp / VmOp::Cmovcc / VmOp::Mov, asmgen 的 build_cmovcc handler
; 真正被 exercise。
;
; Win64 ABI: rcx/rdx/r8/r9 = 前 4 个整型参数, rax = 返回值. callee-saved:
; rbx, rbp, rdi, rsi, r12-r15. 此函数用 rbx 作临时寄存器, push/pop 守恒.
;
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), 必须在 call 前存到 stack, call 后还原 (pitfall #36)。
;
; 栈布局 (沿用 setcc_sample_asm.asm 模式):
;   push rbx → rsp -= 8 → saved rbx 在 [rsp] (即 original - 8)
;   sub rsp, 64 → rsp -= 64 → rsp = original - 72
;   [rsp+24] = 临时存 rax (跨 SDK 调用)
;   [rsp+32] = local 1: a (rcx)
;   [rsp+40] = local 2: b (rdx)
;   [rsp+48] = local 3: c (r8)
;   [rsp+56] = local 4: d (r9)
;   [rsp+72] = original - 8 = saved rbx

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXPEBD@Z (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; uint64_t cmove_fn(int a, int b, int c, int d):
;   returns (a == b) ? c : d. (mod=11 REG-REG cmove r64, r64, 0F 44 C0+rb form)
;
; 实现: 先 cmp a, b 设置 ZF, 然后 cmove rax, r8 (cond true → rax = c = r8,
; cond false → rax = d = r9, 因为 cmove 在 cond false 时保留 rax 内容,
; 所以先 mov rax, r9 = d 作 fallback, 再 cmove rax, r8 作条件覆盖).
;   rcx = a, rdx = b, r8 = c, r9 = d.
;   返回值放 rax.
cmove_fn PROC
    push rbx
    sub  rsp, 64

    mov  dword ptr [rsp+32], ecx   ; save a
    mov  dword ptr [rsp+40], edx   ; save b
    mov  dword ptr [rsp+48], r8d   ; save c
    mov  dword ptr [rsp+56], r9d   ; save d

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z

    mov  ecx, dword ptr [rsp+32]
    mov  edx, dword ptr [rsp+40]
    mov  r8d, dword ptr [rsp+48]
    mov  r9d, dword ptr [rsp+56]
    mov  eax, r9d                  ; eax = d (fallback)
    cmp  ecx, edx                  ; cmp a, b → ZF=1 iff a==b
    cmove eax, r8d                 ; 真 cmove REG-REG (mod=11), 0F 44 C0 (3 字节)
                                   ;   ZF=1 (a==b) → eax = r8d = c
                                   ;   ZF=0 (a!=b) → eax 保留 = r9d = d
    mov  [rsp+24], rax             ; ⚠️ rax 在 marker_end 后会被 clobber
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]             ; 还原 cmovcc 结果
    ; ===== marker region end =====

    add  rsp, 64
    pop  rbx
    ret
cmove_fn ENDP

; uint64_t cmovne_fn(int a, int b, int c, int d):
;   returns (a != b) ? c : d.
cmovne_fn PROC
    push rbx
    sub  rsp, 64

    mov  dword ptr [rsp+32], ecx
    mov  dword ptr [rsp+40], edx
    mov  dword ptr [rsp+48], r8d
    mov  dword ptr [rsp+56], r9d

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z

    mov  ecx, dword ptr [rsp+32]
    mov  edx, dword ptr [rsp+40]
    mov  r8d, dword ptr [rsp+48]
    mov  r9d, dword ptr [rsp+56]
    mov  eax, r9d                  ; fallback = d
    cmp  ecx, edx                  ; ZF=1 iff a==b
    cmovne eax, r8d                ; 真 cmovne REG-REG (mod=11), 0F 45 C0 (3 字节)
                                   ;   ZF=0 (a!=b) → eax = r8d = c
                                   ;   ZF=1 (a==b) → eax 保留 = r9d = d
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 64
    pop  rbx
    ret
cmovne_fn ENDP

; uint64_t cmovb_fn(int a, int b, int c, int d):
;   returns (a <u b) ? c : d. (unsigned below)
cmovb_fn PROC
    push rbx
    sub  rsp, 64

    mov  dword ptr [rsp+32], ecx
    mov  dword ptr [rsp+40], edx
    mov  dword ptr [rsp+48], r8d
    mov  dword ptr [rsp+56], r9d

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z

    mov  ecx, dword ptr [rsp+32]
    mov  edx, dword ptr [rsp+40]
    mov  r8d, dword ptr [rsp+48]
    mov  r9d, dword ptr [rsp+56]
    mov  eax, r9d                  ; fallback = d
    cmp  ecx, edx                  ; CF=1 iff a<u b (unsigned)
    cmovb eax, r8d                 ; 真 cmovb REG-REG (mod=11), 0F 42 C0 (3 字节)
                                   ;   CF=1 (a<u b) → eax = r8d = c
                                   ;   CF=0 → eax 保留 = r9d = d
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 64
    pop  rbx
    ret
cmovb_fn ENDP

; uint64_t cmovg_fn(int a, int b, int c, int d):
;   returns (a >s b) ? c : d. (signed greater)
cmovg_fn PROC
    push rbx
    sub  rsp, 64

    mov  dword ptr [rsp+32], ecx
    mov  dword ptr [rsp+40], edx
    mov  dword ptr [rsp+48], r8d
    mov  dword ptr [rsp+56], r9d

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z

    mov  ecx, dword ptr [rsp+32]
    mov  edx, dword ptr [rsp+40]
    mov  r8d, dword ptr [rsp+48]
    mov  r9d, dword ptr [rsp+56]
    mov  eax, r9d                  ; fallback = d
    cmp  ecx, edx                  ; SF!=OF iff a>s b (signed)
    cmovg eax, r8d                 ; 真 cmovg REG-REG (mod=11), 0F 4F C0 (3 字节)
                                   ;   (ZF=0 AND SF==OF) → eax = r8d = c
                                   ;   否则 → eax 保留 = r9d = d
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 64
    pop  rbx
    ret
cmovg_fn ENDP

; uint64_t cmovl_fn(int a, int b, int c, int d):
;   returns (a <s b) ? c : d. (signed less)
cmovl_fn PROC
    push rbx
    sub  rsp, 64

    mov  dword ptr [rsp+32], ecx
    mov  dword ptr [rsp+40], edx
    mov  dword ptr [rsp+48], r8d
    mov  dword ptr [rsp+56], r9d

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z

    mov  ecx, dword ptr [rsp+32]
    mov  edx, dword ptr [rsp+40]
    mov  r8d, dword ptr [rsp+48]
    mov  r9d, dword ptr [rsp+56]
    mov  eax, r9d                  ; fallback = d
    cmp  ecx, edx                  ; SF!=OF iff a<s b (signed)
    cmovl eax, r8d                 ; 真 cmovl REG-REG (mod=11), 0F 4C C0 (3 字节)
                                   ;   SF!=OF → eax = r8d = c
                                   ;   否则 → eax 保留 = r9d = d
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 64
    pop  rbx
    ret
cmovl_fn ENDP

; uint64_t cmovge_fn(int a, int b, int c, int d):
;   returns (a >=s b) ? c : d. (signed greater-or-equal)
cmovge_fn PROC
    push rbx
    sub  rsp, 64

    mov  dword ptr [rsp+32], ecx
    mov  dword ptr [rsp+40], edx
    mov  dword ptr [rsp+48], r8d
    mov  dword ptr [rsp+56], r9d

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z

    mov  ecx, dword ptr [rsp+32]
    mov  edx, dword ptr [rsp+40]
    mov  r8d, dword ptr [rsp+48]
    mov  r9d, dword ptr [rsp+56]
    mov  eax, r9d                  ; fallback = d
    cmp  ecx, edx                  ; SF==OF iff a>=s b (signed)
    cmovge eax, r8d                ; 真 cmovge REG-REG (mod=11), 0F 4D C0 (3 字节)
                                   ;   SF==OF → eax = r8d = c
                                   ;   否则 → eax 保留 = r9d = d
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 64
    pop  rbx
    ret
cmovge_fn ENDP

_TEXT ENDS

END
