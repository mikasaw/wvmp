; MIT-376 影子样本 (flags readback 断言, 派活单 §D D2.1 决策) 的 MASM helper —
; 与主样本 wvmp_sse_bwcmp_sample 的 ucomiss+seta 同 IR、独立 exe。
;
; 为什么需要影子样本 (MIT-371 空转教训): ucomiss/ucomisd 的正确性不在 xmm 槽
; (比较指令**不改 xmm 操作数**), 而在 VM flags 槽 (ctx+0x98) — handler 若空转
; (decode+advance 不写 flags, pitfall #79), seta 读到的是 dispatch 循环残留的
; flags, stdout 结果随机, 主样本可能碰巧 PASS。本影子样本把两条断言做成显式:
;   1. flags readback: 区域内 ucomiss + seta 的结果字节是 Ucomiss handler 写的
;      VM flags 槽 → Setcc handler (cond=A 读 flags_ bit1/bit0) 的直接读回,
;      greater/less/equal/unordered 四态覆盖 Intel SDM UCOMISS 真值表 ZF/CF
;      全组合 (gt→1 / lt→0 / eq→0 / unordered→0, 各自与 native 逐字节比对)。
;   2. ctx.xmm 全量读回: 每次调用后 8 槽 × 4 lane 的 32-bit 位图案打印,
;      证明 Ucomiss handler **没有污染任何 xmm 槽** (比较指令不该写 xmm —
;      handler 若误写 dst 槽或偏移公式坏 → 某槽 ≠ 入口值 → 与原生不一致 FAIL)。
;
; 4 个 helper 对应 4 组操作数关系 (capstone 实证: 区域内唯一 SSE 字节 =
; ucomiss xmm0, xmm1 = 0F 2E C1, mod=11):
;   ufr_gt  : a=2.5  b=1.5  → greater than,  ZF=0 CF=0 → seta=1
;   ufr_lt  : a=0.5  b=1.5  → less than,     ZF=0 CF=1 → seta=0
;   ufr_eq  : a=1.5  b=1.5  → equal,         ZF=1 CF=0 → seta=0
;   ufr_nan : a=qNaN b=1.0  → unordered,     ZF=1 CF=1 PF=1 → seta=0
;
; 每个 helper 三段式 (沿用 sse_movss_xmm_readback_sample_asm.asm 模式):
;   区外: xmm0/xmm1 由 Win64 ABI 浮点参数直接就位; xmm2..xmm7 从 in_slots
;         预置互不相同的非零位图案 (8 槽全量读回判别"误写无关槽")。
;   区域: marker_begin / ucomiss + seta + movzx + store 结果 (≥5 字节) /
;         marker_end。seta/movzx/store 都在区域内 = 虚拟化路径下由 Setcc/
;         Movzx/Store handler 执行, 读的是 Ucomiss handler 写的 VM flags。
;   区外: seta 结果 + xmm0..xmm7 全 8 槽落到 out_slots (HALT 后 stub 恢复
;         路径把 ctx.xmm[0..7] 写回物理 xmm0..7 — ctx.xmm 读回的可见出口)。
;
; Win64 ABI (参数按位次取寄存器, 浮点参数占位后对应 GPR 不复用): xmm0=a, xmm1=b,
; r8=in_slots, r9=out_slots; 返回值 eax=seta。
; callee-saved: rbx, rbp, rdi, rsi, r12-r15。
;
; ⚠ rax 跨 marker_begin/marker_end 调用会被 clobber (SDK `mov rax, imm64` 装载
; magic 立即数), seta 结果先存 [rsp+24]、marker_end 后还原 (pitfall #36)。

; MSVC C++ 名称修饰 (x64): void marker_begin() / void marker_end()
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; int ufr_gt(float a, float b, const unsigned int* in_slots, unsigned int* out_slots):
;   r8=in_slots, r9=out_slots → eax = seta 结果。
;   out_slots[0..31] = xmm0..xmm7 全量读回; out_slots[32] = seta 结果。
ufr_gt PROC
    push rbx
    sub  rsp, 56
    mov  rbx, r9                      ; out_slots = 第 4 参数 → r9 (浮点 a/b 占前两个参数位 → xmm0/xmm1, 整型参数按位次对齐: 第 3 参→r8, 第 4 参→r9)

    ; ---- 区域外: xmm2..xmm7 预置 (xmm0/xmm1 = a/b 浮点参数已就位) ----
    movups xmm2, xmmword ptr [r8 + 2*16]
    movups xmm3, xmmword ptr [r8 + 3*16]
    movups xmm4, xmmword ptr [r8 + 4*16]
    movups xmm5, xmmword ptr [r8 + 5*16]
    movups xmm6, xmmword ptr [r8 + 6*16]
    movups xmm7, xmmword ptr [r8 + 7*16]

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    ucomiss xmm0, xmm1                 ; 真 ucomiss REG-REG (0F 2E C1, mod=11)
    seta   al                          ; a > b (CF=0 且 ZF=0) → 1
    movzx rax, al
    mov   [rsp+24], rax                ; rax 跨 marker_end 会被 clobber (pitfall #36)
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov   rax, [rsp+24]                ; 还原 setcc 结果
    ; ===== marker region end =====

    mov  dword ptr [rbx + 128], eax   ; out[32] = seta 结果 (flags readback)

    ; ---- 区域外: 8 槽全量读回 ctx.xmm 出口 (ucomis* 不应改动任何槽) ----
    movups xmmword ptr [rbx + 0*16], xmm0
    movups xmmword ptr [rbx + 1*16], xmm1
    movups xmmword ptr [rbx + 2*16], xmm2
    movups xmmword ptr [rbx + 3*16], xmm3
    movups xmmword ptr [rbx + 4*16], xmm4
    movups xmmword ptr [rbx + 5*16], xmm5
    movups xmmword ptr [rbx + 6*16], xmm6
    movups xmmword ptr [rbx + 7*16], xmm7

    add  rsp, 56
    pop  rbx
    ret
ufr_gt ENDP

; int ufr_lt(...): a < b → CF=1 ZF=0 → seta=0。
ufr_lt PROC
    push rbx
    sub  rsp, 56
    mov  rbx, r9

    movups xmm2, xmmword ptr [r8 + 2*16]
    movups xmm3, xmmword ptr [r8 + 3*16]
    movups xmm4, xmmword ptr [r8 + 4*16]
    movups xmm5, xmmword ptr [r8 + 5*16]
    movups xmm6, xmmword ptr [r8 + 6*16]
    movups xmm7, xmmword ptr [r8 + 7*16]

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    ucomiss xmm0, xmm1                 ; 真 ucomiss REG-REG (0F 2E C1, mod=11)
    seta   al                          ; less → CF=1 → seta=0
    movzx rax, al
    mov   [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov   rax, [rsp+24]
    ; ===== marker region end =====

    mov  dword ptr [rbx + 128], eax

    movups xmmword ptr [rbx + 0*16], xmm0
    movups xmmword ptr [rbx + 1*16], xmm1
    movups xmmword ptr [rbx + 2*16], xmm2
    movups xmmword ptr [rbx + 3*16], xmm3
    movups xmmword ptr [rbx + 4*16], xmm4
    movups xmmword ptr [rbx + 5*16], xmm5
    movups xmmword ptr [rbx + 6*16], xmm6
    movups xmmword ptr [rbx + 7*16], xmm7

    add  rsp, 56
    pop  rbx
    ret
ufr_lt ENDP

; int ufr_eq(...): a == b → ZF=1 CF=0 → seta=0。
ufr_eq PROC
    push rbx
    sub  rsp, 56
    mov  rbx, r9

    movups xmm2, xmmword ptr [r8 + 2*16]
    movups xmm3, xmmword ptr [r8 + 3*16]
    movups xmm4, xmmword ptr [r8 + 4*16]
    movups xmm5, xmmword ptr [r8 + 5*16]
    movups xmm6, xmmword ptr [r8 + 6*16]
    movups xmm7, xmmword ptr [r8 + 7*16]

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    ucomiss xmm0, xmm1                 ; 真 ucomiss REG-REG (0F 2E C1, mod=11)
    seta   al                          ; equal → ZF=1 → seta=0
    movzx rax, al
    mov   [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov   rax, [rsp+24]
    ; ===== marker region end =====

    mov  dword ptr [rbx + 128], eax

    movups xmmword ptr [rbx + 0*16], xmm0
    movups xmmword ptr [rbx + 1*16], xmm1
    movups xmmword ptr [rbx + 2*16], xmm2
    movups xmmword ptr [rbx + 3*16], xmm3
    movups xmmword ptr [rbx + 4*16], xmm4
    movups xmmword ptr [rbx + 5*16], xmm5
    movups xmmword ptr [rbx + 6*16], xmm6
    movups xmmword ptr [rbx + 7*16], xmm7

    add  rsp, 56
    pop  rbx
    ret
ufr_eq ENDP

; int ufr_nan(...): a=NaN → unordered, ZF=PF=CF=1 → seta=0 (SDM 真值表)。
ufr_nan PROC
    push rbx
    sub  rsp, 56
    mov  rbx, r9

    movups xmm2, xmmword ptr [r8 + 2*16]
    movups xmm3, xmmword ptr [r8 + 3*16]
    movups xmm4, xmmword ptr [r8 + 4*16]
    movups xmm5, xmmword ptr [r8 + 5*16]
    movups xmm6, xmmword ptr [r8 + 6*16]
    movups xmm7, xmmword ptr [r8 + 7*16]

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    ucomiss xmm0, xmm1                 ; 真 ucomiss REG-REG (0F 2E C1, mod=11)
    seta   al                          ; unordered → CF=1 → seta=0
    movzx rax, al
    mov   [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov   rax, [rsp+24]
    ; ===== marker region end =====

    mov  dword ptr [rbx + 128], eax

    movups xmmword ptr [rbx + 0*16], xmm0
    movups xmmword ptr [rbx + 1*16], xmm1
    movups xmmword ptr [rbx + 2*16], xmm2
    movups xmmword ptr [rbx + 3*16], xmm3
    movups xmmword ptr [rbx + 4*16], xmm4
    movups xmmword ptr [rbx + 5*16], xmm5
    movups xmmword ptr [rbx + 6*16], xmm6
    movups xmmword ptr [rbx + 7*16], xmm7

    add  rsp, 56
    pop  rbx
    ret
ufr_nan ENDP

_TEXT ENDS

END
