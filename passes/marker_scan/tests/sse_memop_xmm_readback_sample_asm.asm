; MIT-411 (G1): SSE 尾扫包影子样本的 MASM helper —
; wvmp_sse_memop_xmm_readback_sample (与 wvmp_sse_memop_sample 同 IR 配对、
; 独立 exe, 沿用 MIT-389/408 影子样本模式: 把 "handler 是否真读写对
; ctx.xmm / ctx.flags" 变成显式可比对输出)。
;
; 目的 (pitfall #79 纪律): 主样本只看最终 stdout。本单新形态的坑位:
;   - comiss/comisd 折叠到 Ucomiss/Ucomisd handler — 正确性在 **VM flags 槽**
;     (比较不改 xmm); handler 若空转 (decode+advance 不写 flags), 紧随的
;     seta 读到 dispatch 残留 → 本影子把 seta 结果显式打印 (mop_comiss_gt /
;     mop_comisd_gt 的 out[16]) + xmm0..7 全槽读回 (证明比较不污染 xmm)。
;   - andpd/orpd/xorpd 折叠到 ps handler — 正确性在 **ctx.xmm 槽位落点**
;     (写错 GPR 槽区 / 宽度截断即暴露), 本影子把 8 槽 × 2×u64 全量打印。
;   - addsd 栈基址 mem 源 / 双访存 triple — XmmLoad/XmmStore/ALU 通路,
;     同样 8 槽全量读回。
;
; 统一探针签名 (Win64 ABI): void mop_<name>(double a, double b,
;     const unsigned long long* in_slots, unsigned long long* out_slots):
;   - xmm0=a, xmm1=b (浮点参数位就位; 位图案探针由 C++ 侧 memcpy 传入);
;   - in_slots[2..7] → xmm2..xmm7 预载互不相同的非零位图案 (判别"误写
;     无关槽"; in_slots[0..1] 的 xmm0/xmm1 预载值不覆盖参数);
;   - out_slots[0..15] = xmm0..xmm7 各 2×u64 全量读回 (区域后落盘);
;   - out_slots[16] = flags 结果 (mop_comiss_gt/mop_comisd_gt: seta;
;     其余探针保持 C++ 侧哨兵值 0xCCCC...)。
;
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), out 指针必须放 callee-saved 寄存器 rbx (pitfall #36);
; seta 结果 marker_end 前存 [rsp+24]、之后还原。

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXXZ (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_DATA SEGMENT
g_sh_f  DD 3.5                       ; float 源 (comiss mem 探针)
g_sh_d  DQ 2.5                       ; double 源 (comisd mem 探针)
ALIGN 16
g_sh_pd DQ 1.5, 2.5                  ; __m128d 源 (orpd mem 探针, 16B — orpd
                                     ;   内存操作数需 16B 对齐, #GP 语义对齐原生)
g_sh_g  DQ 2.25                      ; 双访存 triple 目标
_DATA ENDS
PUBLIC g_sh_f, g_sh_d, g_sh_pd, g_sh_g

_TEXT SEGMENT

; ---- 公共尾声: xmm0..7 → out_slots[0..15] (rbx = out) ----
; 各探针 marker_end 后调用 (rbx 已装 out 指针; xmm0..7 即区域后状态)。
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

; ---- 公共序幕: in_slots[2..7] → xmm2..xmm7 预载 (r8 = in_slots) ----
load_slots MACRO
    movups xmm2, xmmword ptr [r8 + 2*16]
    movups xmm3, xmmword ptr [r8 + 3*16]
    movups xmm4, xmmword ptr [r8 + 4*16]
    movups xmm5, xmmword ptr [r8 + 5*16]
    movups xmm6, xmmword ptr [r8 + 6*16]
    movups xmm7, xmmword ptr [r8 + 7*16]
ENDM

; void mop_comiss_gt(float a, double b, in_slots, out_slots):
;   区域 = comiss xmm0, [g_sh_f] + seta (a > g_sh_f → out[16]=1; comiss 只
;   比较 xmm0[31:0], 故 a 按 float 传参)。
;   flags 读回 + 比较不污染 xmm 双断言。
mop_comiss_gt PROC
    push rbx
    sub  rsp, 56
    mov  rbx, r9                      ; out_slots (第 4 参 → r9)
    load_slots

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    comiss xmm0, dword ptr [g_sh_f]   ; 0F 2F 05 rel32 (rip mem 源)
    seta   al                         ; a > g_sh_f → 1
    movzx rax, al
    mov   [rsp+24], rax               ; rax 跨 marker_end clobber (pitfall #36)
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov   rax, [rsp+24]
    ; ===== marker region end =====

    mov  dword ptr [rbx + 128], eax   ; out[16] = seta 结果 (flags readback)
    sink_slots

    add  rsp, 56
    pop  rbx
    ret
mop_comiss_gt ENDP

; void mop_comisd_gt(double a, double b, in_slots, out_slots):
;   区域 = comisd xmm0, [g_sh_d] + seta (a > g_sh_d → out[16]=1)。
mop_comisd_gt PROC
    push rbx
    sub  rsp, 56
    mov  rbx, r9
    load_slots

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    comisd xmm0, qword ptr [g_sh_d]   ; 66 0F 2F 05 rel32 (rip mem 源)
    seta   al                         ; a > g_sh_d → 1
    movzx rax, al
    mov   [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov   rax, [rsp+24]
    ; ===== marker region end =====

    mov  dword ptr [rbx + 128], eax   ; out[16] = seta 结果 (flags readback)
    sink_slots

    add  rsp, 56
    pop  rbx
    ret
mop_comisd_gt ENDP

; void mop_andpd_reg(double a, double b, in_slots, out_slots):
;   区域 = andpd xmm0, xmm1 (66 0F 54 C1) — xmm0 = a&b, 其余槽不动。
mop_andpd_reg PROC
    push rbx
    sub  rsp, 56
    mov  rbx, r9
    load_slots

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    andpd xmm0, xmm1                  ; 66 0F 54 C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots

    add  rsp, 56
    pop  rbx
    ret
mop_andpd_reg ENDP

; void mop_orpd_mem(double a, double b, in_slots, out_slots):
;   区域 = orpd xmm0, [g_sh_pd] (66 0F 56 05 rel32, 16B rip mem 源)。
mop_orpd_mem PROC
    push rbx
    sub  rsp, 56
    mov  rbx, r9
    load_slots

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    orpd  xmm0, xmmword ptr [g_sh_pd] ; 66 0F 56 05 rel32
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots

    add  rsp, 56
    pop  rbx
    ret
mop_orpd_mem ENDP

; void mop_xorpd_reg(double a, double b, in_slots, out_slots):
;   区域 = xorpd xmm0, xmm1 (66 0F 57 C1)。
mop_xorpd_reg PROC
    push rbx
    sub  rsp, 56
    mov  rbx, r9
    load_slots

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    xorpd xmm0, xmm1                  ; 66 0F 57 C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots

    add  rsp, 56
    pop  rbx
    ret
mop_xorpd_reg ENDP

; void mop_addsd_stack(double a, double b, in_slots, out_slots):
;   区域 = addsd xmm0, [rsp+40] (F2 0F 58 44 24 28, 栈基址 mem 源)。
mop_addsd_stack PROC
    push rbx
    sub  rsp, 64
    mov  rbx, r9
    movsd qword ptr [rsp+40], xmm0    ; 参 a 落栈槽 (区外)
    load_slots

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    addsd xmm0, qword ptr [rsp+40]    ; F2 0F 58 44 24 28
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots

    add  rsp, 64
    pop  rbx
    ret
mop_addsd_stack ENDP

; void mop_triple(double a, double b, in_slots, out_slots):
;   区域 = movsd xmm1,[g_sh_g] + addsd xmm1,xmm0 + movsd [g_sh_g],xmm1
;   (双访存读改写 triple, 全 rip)。
mop_triple PROC
    push rbx
    sub  rsp, 56
    mov  rbx, r9
    load_slots

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movsd xmm1, qword ptr [g_sh_g]    ; 读 (F2 0F 10 0D rel32)
    addsd xmm1, xmm0                  ; 算 (F2 0F 58 C8)
    movsd qword ptr [g_sh_g], xmm1    ; 写回 (F2 0F 11 0D rel32)
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots

    add  rsp, 56
    pop  rbx
    ret
mop_triple ENDP

_TEXT ENDS

END
