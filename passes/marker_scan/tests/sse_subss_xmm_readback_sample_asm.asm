; MIT-389: WVmpVerifier 验收门 A.2 影子样本的 MASM helper —
; sse_subss_xmm_readback_sample (与 wvmp_sse_sub_sample 的 sse_subss 同 IR 配对)。
;
; 目的: 抓 SSE handler 空转 (MIT-371 类缺陷: handler 写回 GPR 槽区而非
; ctx.xmm 槽)。主样本 stdout 只看最终结果; 本影子样本把 "handler 是否真的
; 更新了 ctx.xmm[reg]" 变成显式可比对输出:
;   1) xr_subss_s01: 区域 subss xmm0,xmm1 —— 与主样本 sse_subss 同 IR。
;      返回值 = HALT 时 ctx.xmm[0] 经 stub 恢复路径的唯一出口, 即 ctx 读回。
;   2) xr_subss_s23: 区域 subss xmm2,xmm3 —— 不同槽位探针 (reg=26/27),
;      验证 handler 的 xmm 槽位偏移公式 0x140+(reg-24)*16 在非 0 槽也成立
;      (MIT-371 空转 bug 对 reg=26 写 (26-36)*16+0x140=0x40, GPR 区)。
;      返回值 = ctx.xmm[2] 读回; out_dst/out_src = 区域后 xmm2/xmm3 槽位状态
;      (src 槽必须仍等于输入 b —— handler 不得越槽写)。
;   3) xr_subss_keep: 区域 subss xmm0,xmm1, 区域后把 xmm0..xmm3 全部 128-bit
;      store 到缓冲 —— main 打印全部 4 槽 × 4 lane, 逐位比对 (未触碰槽位
;      必须保持 VM 入口同步值)。
;
; MSVC x64 不支持 inline asm; 区域只含白名单 SSE REG-REG (F3 0F 5C mod=11)。
; load / store / movaps 全部在区域外 (与 sse_sub_sample_asm.asm 模式一致)。
;
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), 必须在 call 前存到 callee-saved 寄存器 (pitfall #36)。
; out 指针放 rbx/rdi (callee-saved), 不依赖 marker stub 的寄存器行为。

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXPEBD@Z (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; float xr_subss_s01(float a, float b):
;   区域 = subss xmm0, xmm1 (与 wvmp_sse_sub_sample 的 sse_subss 同 IR)。
;   返回值 = a-b。虚拟化路径: stub 入口同步 xmm0..xmm7 → ctx.xmm[0..7],
;   Subss handler 更新 ctx.xmm[0], HALT 后 stub 恢复 xmm0..xmm7, xmm0 即
;   ctx.xmm[0] 的读回; handler 空转时读回 = 入口旧值 a (≠ 原生 a-b)。
xr_subss_s01 PROC
    push rbx
    sub  rsp, 32

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    subss xmm0, xmm1                 ; 真 subss REG-REG (F3 0F 5C C1, mod=11)
    nop
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    add  rsp, 32
    pop  rbx
    ret
xr_subss_s01 ENDP

; float xr_subss_s23(float a, float b, float* out_dst, float* out_src):
;   Win64 ABI: a=xmm0, b=xmm1, out_dst=r8, out_src=r9。
;   区域外: xmm2=a, xmm3=b (movaps); 区域 = subss xmm2, xmm3;
;   区域外: xmm0 = xmm2 (返回 ctx.xmm[2] 读回), [out_dst]=xmm2, [out_src]=xmm3。
xr_subss_s23 PROC
    push rbx
    push rdi
    sub  rsp, 32
    mov  rbx, r8                     ; out_dst (callee-saved, pitfall #36)
    mov  rdi, r9                     ; out_src

    ; 区域外: 把参数搬进 xmm2/xmm3 (load 不进区域, lifter 不需支持)
    movaps xmm2, xmm0
    movaps xmm3, xmm1

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    subss xmm2, xmm3                 ; 真 subss REG-REG (F3 0F 5C D3, mod=11)
    nop
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    ; 区域外: ctx.xmm[2] 读回出栈 — 返回值 + 两个槽位状态 store
    movaps xmm0, xmm2
    movups xmmword ptr [rbx], xmm2
    movups xmmword ptr [rdi], xmm3

    add  rsp, 32
    pop  rdi
    pop  rbx
    ret
xr_subss_s23 ENDP

; float xr_subss_keep(float a, float b, void* slots):
;   Win64 ABI 按参数**位置**分配寄存器: a=位置1→xmm0, b=位置2→xmm1,
;   slots=位置3→r8 (整型槽 rcx/rdx/r8/r9 与浮点槽 xmm0-xmm3 各自独立按位分配)。
;   区域 = subss xmm0, xmm1; 区域外把 xmm0..xmm3 全部 128-bit store 到 slots
;   (64 字节 = 4 槽 × 16B), main 打印全部 4×4 lane 逐位比对: 槽 0 = 结果,
;   槽 1..3 = 未触碰, 必须保持 VM 入口同步值 (handler 越槽写即暴露)。
xr_subss_keep PROC
    push rbx
    sub  rsp, 32
    mov  rbx, r8                     ; slots = 位置 3 → r8 (callee-saved, pitfall #36)

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    subss xmm0, xmm1                 ; 真 subss REG-REG (F3 0F 5C C1, mod=11)
    nop
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    ; 区域外: 4 个 xmm 槽位全量快照 (128-bit store, 不进区域)
    movups xmmword ptr [rbx],      xmm0
    movups xmmword ptr [rbx+16],   xmm1
    movups xmmword ptr [rbx+32],   xmm2
    movups xmmword ptr [rbx+48],   xmm3

    add  rsp, 32
    pop  rbx
    ret
xr_subss_keep ENDP

_TEXT ENDS

END
