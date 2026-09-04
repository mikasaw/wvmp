; MIT-375: SSE 浮点传送 E2E 主样本的 MASM helper (MSVC x64 不支持 inline asm).
;
; 为什么必须用 MASM: MSVC /Od 下 _mm_move_ss / _mm_load_ps / _mm_load_pd 等高 level
; intrinsic 会**融合 load+mov 为 MEM 形式** (movss xmm,[mem] / movaps xmm,[mem]),
; 而本单只支持 REG-REG load (mod=11) → 区域内会被 lifter 拒 (C1 gate 整段保持
; 原生, 样本变成"没虚拟化"的假 PASS)。沿用 MIT-373 sse_sub_sample_asm.asm 的
; pitfall #35 做法: 由 .asm 直接 emit 真 REG-REG 字节。
;
; 5 个 helper = 5 形式 (字节模板经本单派活前 worktree 自带 capstone 5.0.6 实证):
;   sse_mov_ss   区域内 movss  xmm0, xmm1   F3 0F 10 C1  (标量, **只搬低 32 位: 高位保持**)
;   sse_mov_aps  区域内 movaps xmm2, xmm3   0F 28 D3     (全 128-bit 搬)
;   sse_mov_apd  区域内 movapd xmm4, xmm5   45 0F 28 E4  (全 128-bit 搬, 需 REX)
;   sse_mov_ups  区域内 movups xmm6, xmm7   41 0F 10 F7  (全 128-bit 搬, 需 REX)
;   sse_mov_upd  区域内 movupd xmm1, xmm3   66 0F 10 CB  (全 128-bit 搬)
; dst/src 槽刻意分散 (xmm0/1, 2/3, 4/5, 6/7, 1/3): 非 0 槽才能暴露 handler 的
; ctx.xmm 槽地址公式 0x140+(reg-24)*16 写错 (MIT-371 空转 bug 对 reg=26 算成
; (26-36)*16+0x140=0x40 落进 GPR 区, xmm0/xmm1 两槽看不出)。
;
; 三段式: 区外 load (movups/movss 从内存) → 区域 (marker_begin + 单条真 SSE
; REG-REG + 3 nop 补齐 ≥5 字节让 stub_link 写 E9 跳转 + marker_end) → 区外 store
; 结果与 src 槽。区域只含白名单单指令, 不含 rip-relative / printf / call。
;
; Win64 ABI: 整型参数 rcx/rdx/r8/r9; callee-saved: rbx, rbp, rdi, rsi, r12-r15.
; ⚠ rax 跨 marker_begin/marker_end 调用被 clobber (SDK `mov rax, imm64` 装载 magic
; 立即数), out 指针必须先存 callee-saved 寄存器 (pitfall #36)。

; MSVC C++ 名字修饰 (x64): void marker_begin() / void marker_end()
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; void sse_mov_ss(const float* dst4, const float* src4, float* out4, float* out_src4):
;   rcx=dst4 rdx=src4 r8=out4 r9=out_src4。dst 预置 != src (mov 类指令必须用
;   非平凡初值, 否则 handler 空转时"没搬也是同值")。
sse_mov_ss PROC
    push rbx
    push rdi
    sub  rsp, 32
    mov  rbx, r8                       ; out4     (callee-saved, pitfall #36)
    mov  rdi, r9                       ; out_src4

    ; ---- 区域外: dst=xmm0 预置非零 4 lane, src=xmm1 ----
    movups xmm0, xmmword ptr [rcx]
    movups xmm1, xmmword ptr [rdx]

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movss  xmm0, xmm1                  ; 真 movss REG-REG (F3 0F 10 C1, mod=11)
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movups xmmword ptr [rbx], xmm0     ; 区外 store 结果 (lane1-3 保持入口预置值)
    movups xmmword ptr [rdi], xmm1     ; src 槽必须未被越槽写
    add  rsp, 32
    pop  rdi
    pop  rbx
    ret
sse_mov_ss ENDP

; void sse_mov_aps(const float* dst4, const float* src4, float* out4, float* out_src4):
;   区域 = movaps xmm2, xmm3 (非 0 槽)。
sse_mov_aps PROC
    push rbx
    push rdi
    sub  rsp, 32
    mov  rbx, r8
    mov  rdi, r9

    movups xmm2, xmmword ptr [rcx]
    movups xmm3, xmmword ptr [rdx]

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movaps xmm2, xmm3                  ; 真 movaps REG-REG (0F 28 D3, mod=11)
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movups xmmword ptr [rbx], xmm2
    movups xmmword ptr [rdi], xmm3
    add  rsp, 32
    pop  rdi
    pop  rbx
    ret
sse_mov_aps ENDP

; void sse_mov_apd(const double* dst2, const double* src2, double* out2, double* out_src2):
;   区域 = movapd xmm4, xmm5 (非 0 槽 + REX 编码)。
sse_mov_apd PROC
    push rbx
    push rdi
    sub  rsp, 32
    mov  rbx, r8
    mov  rdi, r9

    movups xmm4, xmmword ptr [rcx]
    movups xmm5, xmmword ptr [rdx]

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movapd xmm4, xmm5                  ; 真 movapd REG-REG (45 0F 28 E4, mod=11)
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movups xmmword ptr [rbx], xmm4
    movups xmmword ptr [rdi], xmm5
    add  rsp, 32
    pop  rdi
    pop  rbx
    ret
sse_mov_apd ENDP

; void sse_mov_ups(const float* dst4, const float* src4, float* out4, float* out_src4):
;   区域 = movups xmm6, xmm7 (最高槽, xmm7 → VM 槽 31 = reg 字段 5 位上界)。
sse_mov_ups PROC
    push rbx
    push rdi
    sub  rsp, 32
    mov  rbx, r8
    mov  rdi, r9

    movups xmm6, xmmword ptr [rcx]
    movups xmm7, xmmword ptr [rdx]

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movups xmm6, xmm7                  ; 真 movups REG-REG (41 0F 10 F7, mod=11)
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movups xmmword ptr [rbx], xmm6
    movups xmmword ptr [rdi], xmm7
    add  rsp, 32
    pop  rdi
    pop  rbx
    ret
sse_mov_ups ENDP

; void sse_mov_upd(const double* dst2, const double* src2, double* out2, double* out_src2):
;   区域 = movupd xmm1, xmm3 (dst/src 皆非 0 槽且 dst!=src 的交叉组合)。
sse_mov_upd PROC
    push rbx
    push rdi
    sub  rsp, 32
    mov  rbx, r8
    mov  rdi, r9

    movups xmm1, xmmword ptr [rcx]
    movups xmm3, xmmword ptr [rdx]

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movupd xmm1, xmm3                  ; 真 movupd REG-REG (66 0F 10 CB, mod=11)
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movups xmmword ptr [rbx], xmm1
    movups xmmword ptr [rdi], xmm3
    add  rsp, 32
    pop  rdi
    pop  rbx
    ret
sse_mov_upd ENDP

_TEXT ENDS
END
