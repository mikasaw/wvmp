; MIT-375 影子样本 (ctx.xmm 运行时读回断言) 的 MASM helper —— 与主样本 wvmp_sse_mov_sample 同 IR、独立 exe。
;
; 为什么必须用 MASM: MSVC /Od 下对 _mm_move_ss / _mm_load_ps / _mm_load_pd 等高
; level intrinsic 会**融合 load+mov 为 MEM 形式** (movss xmm, [mem] / movaps
; xmm, [mem]), 而派活单 §B 只支持 REG-REG load (mod=11) —— 沿用 MIT-373
; sse_sub_sample_asm.asm 的 pitfall #35 做法: 由 .asm 直接 emit 真 REG-REG 字节,
; 让 marker 区域内只含白名单单指令。
;
; 5 个 helper 对应 5 形式 (capstone 5.0.6 实证, 本单派活前用 worktree 自带
; capstone 反汇编确认):
;   xr_mov_ss  区域内 movss  xmm0, xmm1  F3 0F 10 C1  (标量, **只搬低 32 位: 高位保持**)
;   xr_mov_aps 区域内 movaps xmm2, xmm3  0F 28 D3     (全 128-bit 搬)
;   xr_mov_apd 区域内 movapd xmm4, xmm5  45 0F 28 E4  (全 128-bit 搬, REX.R/B)
;   xr_mov_ups 区域内 movups xmm6, xmm7  41 0F 10 F7  (全 128-bit 搬, REX.B)
;   xr_mov_upd 区域内 movupd xmm1, xmm3  66 0F 10 CB  (全 128-bit 搬)
; 槽位刻意分散到 xmm0..xmm7 (含非 0 槽 xmm2..xmm7), 用于验证 handler 的
; ctx.xmm 槽地址公式 0x140 + (reg-24)*16 在非 0 槽同样成立 (MIT-371 空转 bug
; 对 reg=26 写成 (26-36)*16+0x140=0x40 落到 GPR 区, 只有非 0 槽能暴露)。
;
; 期望出口 (in = 8 槽 × 4 lane 互不相同的非零 u32 图案, 见 main 的 pattern()):
;   调用      dst槽  src槽   out[dst] 期望                 out[其余 7 槽] 期望
;   xr_mov_ss     0     1     {in[1].lane0, in[0].lane1..3} 全部保持 in
;   xr_mov_aps  2     3     in[3] 全 128-bit             全部保持 in
;   xr_mov_apd  4     5     in[5] 全 128-bit             全部保持 in
;   xr_mov_ups  6     7     in[7] 全 128-bit             全部保持 in
;   xr_mov_upd  1     3     in[3] 全 128-bit             全部保持 in
; ⇒ movss 与 movaps 族的**唯一**可观察差异在 dst 槽 lane1-3: 寄存器形式保持
;   预置值不变 (内存源形式才清零) → 必须逐 lane 断言, 否则"只搬低 32"与"全宽搬"
;   与"误清零高位"三种实现无法区分。

; 每个 helper 都是同一套三段式:
;   区外: 8×movups 从内存载入 xmm0..xmm7 (dst 槽与 src 槽取**互不相同**的
;         非平凡初值 —— mov 类指令 dst 预置 != src, 否则 handler 空转时
;         "没搬也是同值", 无法区分真假虚拟化)
;   区域: marker_begin / 单条 SSE mov + 3 nop 补齐 (≥5 字节让 stub_link 写跳转)
;         / marker_end
;   区外: 8×movups 把 xmm0..xmm7 全量落到 out_slots —— 这是 ctx.xmm 的可见出口
;         (HALT 后 stub 恢复路径把 ctx.xmm[0..7] 写回物理 xmm0..7), 未触碰槽
;         必须保持 VM 入口同步值 => 越槽写/漏清零一眼可辨。
;
; Win64 ABI: 整型参数 rcx/rdx/r8/r9; 浮点参数 xmm0-3; callee-saved: rbx, rbp,
; rdi, rsi, r12-r15。
;
; ⚠ rax 跨 marker_begin/marker_end 调用会被 clobber (SDK `mov rax, imm64` 装载
; magic 立即数), out_slots 指针必须先存 callee-saved 寄存器 (pitfall #36)。

; MSVC C++ 名字修饰 (x64): void marker_begin() / void marker_end()
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; void xr_mov_ss(const unsigned int* in_slots, unsigned int* out_slots):
;   Win64 ABI: rcx=in_slots (8 槽 × 16B), rdx=out_slots。
;   区域 = movss xmm0, xmm1 (寄存器形式) → out xmm0 槽 =
;     {in[1].lane0, in[0].lane1, in[0].lane2, in[0].lane3} (只改低 32 位), 其余 7 槽不变。
xr_mov_ss PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rdx                      ; out_slots (callee-saved, pitfall #36)

    ; ---- 区域外: 8 槽全量预置 (load 不进区域, lifter 不需要支持) ----
    movups xmm0, xmmword ptr [rcx + 0*16]
    movups xmm1, xmmword ptr [rcx + 1*16]
    movups xmm2, xmmword ptr [rcx + 2*16]
    movups xmm3, xmmword ptr [rcx + 3*16]
    movups xmm4, xmmword ptr [rcx + 4*16]
    movups xmm5, xmmword ptr [rcx + 5*16]
    movups xmm6, xmmword ptr [rcx + 6*16]
    movups xmm7, xmmword ptr [rcx + 7*16]

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movss  xmm0, xmm1                  ; 真 movss REG-REG (F3 0F 10 C1, mod=11)
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    ; ---- 区域外: 8 槽全量读回 ctx.xmm 出口 ----
    movups xmmword ptr [rbx + 0*16], xmm0
    movups xmmword ptr [rbx + 1*16], xmm1
    movups xmmword ptr [rbx + 2*16], xmm2
    movups xmmword ptr [rbx + 3*16], xmm3
    movups xmmword ptr [rbx + 4*16], xmm4
    movups xmmword ptr [rbx + 5*16], xmm5
    movups xmmword ptr [rbx + 6*16], xmm6
    movups xmmword ptr [rbx + 7*16], xmm7

    add  rsp, 32
    pop  rbx
    ret
xr_mov_ss ENDP

; void xr_mov_aps(const unsigned int* in_slots, unsigned int* out_slots):
;   区域 = movaps xmm2, xmm3 → out xmm2 槽 = in xmm3 槽全 128-bit, 其余不变。
xr_mov_aps PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rdx

    movups xmm0, xmmword ptr [rcx + 0*16]
    movups xmm1, xmmword ptr [rcx + 1*16]
    movups xmm2, xmmword ptr [rcx + 2*16]
    movups xmm3, xmmword ptr [rcx + 3*16]
    movups xmm4, xmmword ptr [rcx + 4*16]
    movups xmm5, xmmword ptr [rcx + 5*16]
    movups xmm6, xmmword ptr [rcx + 6*16]
    movups xmm7, xmmword ptr [rcx + 7*16]

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movaps xmm2, xmm3                  ; 真 movaps REG-REG (0F 28 D3, mod=11)
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movups xmmword ptr [rbx + 0*16], xmm0
    movups xmmword ptr [rbx + 1*16], xmm1
    movups xmmword ptr [rbx + 2*16], xmm2
    movups xmmword ptr [rbx + 3*16], xmm3
    movups xmmword ptr [rbx + 4*16], xmm4
    movups xmmword ptr [rbx + 5*16], xmm5
    movups xmmword ptr [rbx + 6*16], xmm6
    movups xmmword ptr [rbx + 7*16], xmm7

    add  rsp, 32
    pop  rbx
    ret
xr_mov_aps ENDP

; void xr_mov_apd(const unsigned int* in_slots, unsigned int* out_slots):
;   区域 = movapd xmm4, xmm5 (非 0 槽 + REX 编码) → 验证偏移公式对 reg=28/29 成立。
xr_mov_apd PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rdx

    movups xmm0, xmmword ptr [rcx + 0*16]
    movups xmm1, xmmword ptr [rcx + 1*16]
    movups xmm2, xmmword ptr [rcx + 2*16]
    movups xmm3, xmmword ptr [rcx + 3*16]
    movups xmm4, xmmword ptr [rcx + 4*16]
    movups xmm5, xmmword ptr [rcx + 5*16]
    movups xmm6, xmmword ptr [rcx + 6*16]
    movups xmm7, xmmword ptr [rcx + 7*16]

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movapd xmm4, xmm5                  ; 真 movapd REG-REG (45 0F 28 E4, mod=11)
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movups xmmword ptr [rbx + 0*16], xmm0
    movups xmmword ptr [rbx + 1*16], xmm1
    movups xmmword ptr [rbx + 2*16], xmm2
    movups xmmword ptr [rbx + 3*16], xmm3
    movups xmmword ptr [rbx + 4*16], xmm4
    movups xmmword ptr [rbx + 5*16], xmm5
    movups xmmword ptr [rbx + 6*16], xmm6
    movups xmmword ptr [rbx + 7*16], xmm7

    add  rsp, 32
    pop  rbx
    ret
xr_mov_apd ENDP

; void xr_mov_ups(const unsigned int* in_slots, unsigned int* out_slots):
;   区域 = movups xmm6, xmm7 (最高非 0 槽, xmm7 = ctx 槽 31 = 编码字段上界)。
xr_mov_ups PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rdx

    movups xmm0, xmmword ptr [rcx + 0*16]
    movups xmm1, xmmword ptr [rcx + 1*16]
    movups xmm2, xmmword ptr [rcx + 2*16]
    movups xmm3, xmmword ptr [rcx + 3*16]
    movups xmm4, xmmword ptr [rcx + 4*16]
    movups xmm5, xmmword ptr [rcx + 5*16]
    movups xmm6, xmmword ptr [rcx + 6*16]
    movups xmm7, xmmword ptr [rcx + 7*16]

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movups xmm6, xmm7                  ; 真 movups REG-REG (41 0F 10 F7, mod=11)
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movups xmmword ptr [rbx + 0*16], xmm0
    movups xmmword ptr [rbx + 1*16], xmm1
    movups xmmword ptr [rbx + 2*16], xmm2
    movups xmmword ptr [rbx + 3*16], xmm3
    movups xmmword ptr [rbx + 4*16], xmm4
    movups xmmword ptr [rbx + 5*16], xmm5
    movups xmmword ptr [rbx + 6*16], xmm6
    movups xmmword ptr [rbx + 7*16], xmm7

    add  rsp, 32
    pop  rbx
    ret
xr_mov_ups ENDP

; void xr_mov_upd(const unsigned int* in_slots, unsigned int* out_slots):
;   区域 = movupd xmm1, xmm3 (dst/src 都非 0 槽且 dst != xmm0, 交叉槽位组合)。
xr_mov_upd PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rdx

    movups xmm0, xmmword ptr [rcx + 0*16]
    movups xmm1, xmmword ptr [rcx + 1*16]
    movups xmm2, xmmword ptr [rcx + 2*16]
    movups xmm3, xmmword ptr [rcx + 3*16]
    movups xmm4, xmmword ptr [rcx + 4*16]
    movups xmm5, xmmword ptr [rcx + 5*16]
    movups xmm6, xmmword ptr [rcx + 6*16]
    movups xmm7, xmmword ptr [rcx + 7*16]

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movupd xmm1, xmm3                  ; 真 movupd REG-REG (66 0F 10 CB, mod=11)
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movups xmmword ptr [rbx + 0*16], xmm0
    movups xmmword ptr [rbx + 1*16], xmm1
    movups xmmword ptr [rbx + 2*16], xmm2
    movups xmmword ptr [rbx + 3*16], xmm3
    movups xmmword ptr [rbx + 4*16], xmm4
    movups xmmword ptr [rbx + 5*16], xmm5
    movups xmmword ptr [rbx + 6*16], xmm6
    movups xmmword ptr [rbx + 7*16], xmm7

    add  rsp, 32
    pop  rbx
    ret
xr_mov_upd ENDP

_TEXT ENDS
END
