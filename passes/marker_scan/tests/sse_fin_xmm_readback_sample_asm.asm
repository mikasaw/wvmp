; MIT-425 (G1b): SSE 收官包影子样本的 MASM helper — mul 族 + andnps/andnpd
; + SSE2 整数位运算族的 ctx.xmm 运行时读回断言 (与 wvmp_sse_fin_sample
; 同能力面配对、独立 exe, 沿用 MIT-389/408/411 影子样本模式)。
;
; 目的 (pitfall #79 纪律): 主样本 stdout 只断言最终值。本单新 handler 的
; 坑位: mul 族 / Andnps handler 若槽位偏移公式错 (MIT-371 空转形态) 或
; 写错 GPR 槽区, 主样本可能碰巧 PASS — 本影子把 8 槽 × 2×u64 全量打印:
; dst 槽 = 期望位图案, 其余槽必须 = 入口预载值 (误写无关槽即 FAIL)。
;
; 统一探针签名 (Win64 ABI): void fin_<name>(double a, double b,
;     const unsigned long long* in_slots, unsigned long long* out_slots):
;   - FP 探针: xmm0=a, xmm1=b (浮点参数位就位); 位图案探针: 全 8 槽从
;     in_slots 预载 (load_all, 参数忽略);
;   - out_slots[0..15] = xmm0..xmm7 各 2×u64 全量读回 (区域后落盘)。
;
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), out 指针必须放 callee-saved 寄存器 rbx (pitfall #36)。

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXXZ (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

; C 链接全局 (sse_fin_xmm_readback_sample_main.cpp extern "C")
EXTERNDEF g_sh_d  : QWORD     ; mulsd mem 源
EXTERNDEF g_sh_ps : XMMWORD   ; mulps mem 源
EXTERNDEF g_sh_pi : XMMWORD   ; pand mem 源

_TEXT SEGMENT

; ---- 公共尾声: xmm0..7 → out_slots[0..15] (rbx = out) ----
sink_slots MACRO
    movups xmmword ptr [rbx + 0*16], xmm0
    movups xmmword ptr [rbx + 1*16], xmm1
    movups xmmword ptr [rbx + 2*16], xmm2
    movups xmmword ptr [rbx + 3*16], xmm3
    movups xmmword ptr [rbx + 4*16], xmm4
    movups xmmword ptr [rbx + 5*16], xmm5
    movups xmmword ptr [rbx + 6*16], xmm6
    movups xmmword ptr [rbx + 7*16], xmm7
ENDM

; ---- 公共序幕 A (FP 探针): in_slots[2..7] → xmm2..xmm7 预载 (r8 = in) ----
load_slots MACRO
    movups xmm2, xmmword ptr [r8 + 2*16]
    movups xmm3, xmmword ptr [r8 + 3*16]
    movups xmm4, xmmword ptr [r8 + 4*16]
    movups xmm5, xmmword ptr [r8 + 5*16]
    movups xmm6, xmmword ptr [r8 + 6*16]
    movups xmm7, xmmword ptr [r8 + 7*16]
ENDM

; ---- 公共序幕 B (位图案探针): in_slots[0..7] → xmm0..xmm7 全量预载 ----
load_all MACRO
    movups xmm0, xmmword ptr [r8 + 0*16]
    movups xmm1, xmmword ptr [r8 + 1*16]
    load_slots
ENDM

; ---- float mulss 探针: void fin_mulss_rr(float a, float b, in, out) ----
; 区域 = mulss xmm0, xmm1 (F3 0F 59 C1, scalar single: 只改低 32 位,
; xmm0 高 96 位保持 — 读回可断言 "高位不变" 语义)。
fin_mulss_rr PROC
    push rbx
    sub  rsp, 32
    mov  rbx, r9
    load_slots

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mulss xmm0, xmm1                 ; F3 0F 59 C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
fin_mulss_rr ENDP

; ---- mulsd 探针: void fin_mulsd_rr(double a, double b, in, out) ----
; 区域 = mulsd xmm0, xmm1 (F2 0F 59 C1, 低 64 位, 高位保持)。
fin_mulsd_rr PROC
    push rbx
    sub  rsp, 32
    mov  rbx, r9
    load_slots

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mulsd xmm0, xmm1                 ; F2 0F 59 C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
fin_mulsd_rr ENDP

; ---- mulsd mem 源探针: void fin_mulsd_mem(double a, double b, in, out) ----
; 区域 = mulsd xmm0, [g_sh_d] (F2 0F 59 05 rel32, rip mem 源)。
fin_mulsd_mem PROC
    push rbx
    sub  rsp, 32
    mov  rbx, r9
    load_slots

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mulsd xmm0, qword ptr [g_sh_d]   ; F2 0F 59 05 rel32
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
fin_mulsd_mem ENDP

; ---- mulps 探针 (位图案, 全 8 槽预载): void fin_mulps_rr(a, b, in, out) ----
; 区域 = mulps xmm0, xmm1 (0F 59 C1, 4 lane 并行)。
fin_mulps_rr PROC
    push rbx
    sub  rsp, 32
    mov  rbx, r9
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mulps xmm0, xmm1                 ; 0F 59 C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
fin_mulps_rr ENDP

; ---- mulpd 探针 (位图案): void fin_mulpd_rr(a, b, in, out) ----
; 区域 = mulpd xmm0, xmm1 (66 0F 59 C1, 2 lane)。
fin_mulpd_rr PROC
    push rbx
    sub  rsp, 32
    mov  rbx, r9
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mulpd xmm0, xmm1                 ; 66 0F 59 C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
fin_mulpd_rr ENDP

; ---- mulps mem 源探针: void fin_mulps_mem(a, b, in, out) ----
; 区域 = mulps xmm0, [g_sh_ps] (0F 59 05 rel32)。
fin_mulps_mem PROC
    push rbx
    sub  rsp, 32
    mov  rbx, r9
    load_slots

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mulps xmm0, xmmword ptr [g_sh_ps]  ; 0F 59 05 rel32
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
fin_mulps_mem ENDP

; ---- andnps 探针 (位图案): void fin_andnps_rr(a, b, in, out) ----
; 区域 = andnps xmm0, xmm1 (0F 55 C1) — dst = ~dst & src, F0F0F0F0 基线
; 由 in_slots 位图案构造 (见 main.cpp g_in)。
fin_andnps_rr PROC
    push rbx
    sub  rsp, 32
    mov  rbx, r9
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    andnps xmm0, xmm1                ; 0F 55 C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
fin_andnps_rr ENDP

; ---- andnpd 探针 (66 0F 55): void fin_andnpd_rr(a, b, in, out) ----
fin_andnpd_rr PROC
    push rbx
    sub  rsp, 32
    mov  rbx, r9
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    andnpd xmm0, xmm1                ; 66 0F 55 C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
fin_andnpd_rr ENDP

; ---- pandn 探针 (66 0F DF): void fin_pandn_rr(a, b, in, out) ----
fin_pandn_rr PROC
    push rbx
    sub  rsp, 32
    mov  rbx, r9
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    pandn  xmm0, xmm1                ; 66 0F DF C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
fin_pandn_rr ENDP

; ---- pand 探针, dst=xmm2 槽变体: void fin_pand_rr(a, b, in, out) ----
; 区域 = pand xmm2, xmm3 (66 0F DB D3) — 结果落 xmm2 槽, 其余 7 槽必须
; = 预载不动 (误写无关槽即 FAIL)。
fin_pand_rr PROC
    push rbx
    sub  rsp, 32
    mov  rbx, r9
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    pand   xmm2, xmm3                ; 66 0F DB D3 (dst=xmm2 槽变体)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
fin_pand_rr ENDP

; ---- por 探针: void fin_por_rr(a, b, in, out) — por xmm0, xmm1 ----
fin_por_rr PROC
    push rbx
    sub  rsp, 32
    mov  rbx, r9
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    por    xmm0, xmm1                ; 66 0F EB C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
fin_por_rr ENDP

; ---- pxor 探针, dst=xmm2 槽变体: void fin_pxor_rr(a, b, in, out) ----
; 区域 = pxor xmm2, xmm3 (66 0F EF D3)。
fin_pxor_rr PROC
    push rbx
    sub  rsp, 32
    mov  rbx, r9
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    pxor   xmm2, xmm3                ; 66 0F EF D3 (dst=xmm2 槽变体)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
fin_pxor_rr ENDP

; ---- pand mem 源探针: void fin_pand_mem(a, b, in, out) ----
; 区域 = pand xmm0, [g_sh_pi] (66 0F DB 05 rel32)。
fin_pand_mem PROC
    push rbx
    sub  rsp, 32
    mov  rbx, r9
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    pand   xmm0, xmmword ptr [g_sh_pi]  ; 66 0F DB 05 rel32
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
fin_pand_mem ENDP

_TEXT ENDS
END
