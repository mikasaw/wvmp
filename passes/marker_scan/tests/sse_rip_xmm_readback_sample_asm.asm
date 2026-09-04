; MIT-408 (C4b): SSE mem 形式影子样本的 MASM helper —
; wvmp_sse_rip_xmm_readback_sample (与 wvmp_sse_rip_sample 同能力面配对,
; 沿用 MIT-389/374 影子样本模式: 把 "handler 是否真的读写对 ctx.xmm 槽" 变成
; 显式可比对输出)。
;
; 目的 (pitfall #79 纪律: byte-exact 对 SSE 写 GPR 槽形态不可见): 主样本只看
; 最终 stdout; 若 XmmLoad/XmmStore/ALU-mem 折条把 128-bit 值写进 **GPR 槽区**
; (v18..v23, 0x10+reg*8) 而非 ctx.xmm 区 (0x140+(reg-24)*16), 或宽度截断
; (movss 4B 替 movups 16B), 主样本可能仍 byte-exact。本影子样本把四条 mem
; 原语路径的槽位状态/宽度语义全部打出来:
;   1) xr_memld:  区域 movups xmm0,[g16_src] (16B 读, XmmLoad → xmm 槽) —
;                 区域后 128-bit store, 4 lane 全打: 槽位错/宽度截断即暴露
;                 (lane1-3 必须 = 源值, 非入口旧值)。
;   2) xr_memalu: 区域 addps xmm0,[g16_src] (ALU mem 源, XmmLoad → GP 双槽
;                 临时 + Addps 读回) — xmm0 预载 {5,6,7,8} 与源 16B 相加,
;                 结果 lane 全打: GP 双槽落点/读回错位即暴露。
;   3) xr_memst:  区域 movups [g16_dst],xmm0 (16B 写, XmmStore) — 预载
;                 {5,6,7,8} 写进全局, main 读回 g16_dst 全打。
;   4) xr_sd_ld:  区域 movsd xmm0,[g_sd_in] (8B 读) — 返回值 + 128-bit 全
;                 打: 低 64 = 源值, 高 64 必须 = 0 (movsd 内存源清零语义,
;                 SDM), 宽度错 (movss→低 32) 即暴露。
;   5) xr_sd_st:  区域 movsd [g_sd_out],xmm0 (8B 写) — 全局读回, 只写低
;                 64 位。
;
; MSVC x64 不支持 inline asm; 区域只含白名单 SSE mem 形式字节。
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), 指针必须放 callee-saved 寄存器 (pitfall #36)。

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXPEBD@Z (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_DATA SEGMENT
g16_src  DD 1.5, 2.5, 3.5, 4.5          ; 16B 源 (4xf32)
g16_dst  DD 0.0, 0.0, 0.0, 0.0          ; 16B 目的
g_sd_in  DQ 2.25                        ; 8B 标量 double 源
g_sd_out DQ 0.0                         ; 8B 标量 double 目的
_DATA ENDS
PUBLIC g16_src, g16_dst, g_sd_in, g_sd_out

_TEXT SEGMENT

; void xr_memld(float* out):
;   区域 = movups xmm0, [g16_src] (XmmLoad 16B, rip-relative 全局)。
;   区域外: 把 xmm0 全 128-bit store 到 out — 4 lane 全打。
;   槽位错 (写 GPR 区) → xmm0 = 入口同步值 (非源) → lane 不匹配; 宽度截断
;   (movss) → lane1-3 保持入口旧值。
xr_memld PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rcx                     ; out (callee-saved, pitfall #36)

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movups xmm0, xmmword ptr [g16_src]   ; 真 movups mem 读 (0F 10 05 disp32)
    nop
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movups xmmword ptr [rbx], xmm0    ; 区域外: 128-bit 槽位读回
    add  rsp, 32
    pop  rbx
    ret
xr_memld ENDP

; void xr_memalu(float a0, float a1, float a2, float a3, float* out):
;   Win64 ABI: a0..a3 → xmm0..xmm3 (位置 1..4); out 是第 5 参 → **栈上**
;   [rsp+40] (入口 rsp 上方 40 字节, 非 r9 — 整型/浮点按位置统一分配)。
;   区域外: xmm0 = {a0,a1,a2,a3} (4 lane 预载); 区域 = addps xmm0, [g16_src]
;   (ALU mem 源: XmmLoad → GP 双槽临时 + Addps(dst, 双槽))。
;   区域外: xmm0 128-bit store → out。
xr_memalu PROC
    push rbx
    sub  rsp, 32
    mov  rbx, qword ptr [rsp+80]      ; out (第 5 参: 入口 [rsp+40], push+sub 后 +40)

    ; 区域外: 4 lane 预载 (unpcklps 低 64 位交错, movlhps 搬高 64)
    unpcklps xmm0, xmm1               ; {a0, a1, .., ..}
    unpcklps xmm2, xmm3               ; {a2, a3, .., ..}
    movlhps  xmm0, xmm2               ; {a0, a1, a2, a3}

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    addps xmm0, xmmword ptr [g16_src]    ; 真 addps mem 读 (0F 58 05 disp32)
    nop
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movups xmmword ptr [rbx], xmm0    ; 区域外: 结果 128-bit 读回
    add  rsp, 32
    pop  rbx
    ret
xr_memalu ENDP

; void xr_memst(float a0, float a1, float a2, float a3):
;   Win64 ABI: a0..a3 → xmm0..xmm3。区域 = movups [g16_dst], xmm0 (XmmStore
;   16B 写) — xmm0 为预载 {a0,a1,a2,a3} 全 128-bit。main 读回 g16_dst。
xr_memst PROC
    sub  rsp, 32

    unpcklps xmm0, xmm1               ; 区域外: 4 lane 预载
    unpcklps xmm2, xmm3
    movlhps  xmm0, xmm2

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movups xmmword ptr [g16_dst], xmm0   ; 真 movups mem 写 (0F 11 05 disp32)
    nop
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    add  rsp, 32
    ret
xr_memst ENDP

; void xr_sd_ld(unsigned long long* out128):
;   区域 = movsd xmm0, [g_sd_in] (XmmLoad 8B 读)。区域外: xmm0 全 128-bit
;   store → out128: 低 64 = 源 double, 高 64 必须 = 0 (movsd 内存源清零
;   语义, SDM Vol.2: MOVSD xmm, m64 清 bits 64..127)。
xr_sd_ld PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rcx                     ; out128

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movsd xmm0, qword ptr [g_sd_in]      ; 真 movsd mem 读 (F2 0F 10 05 disp32)
    nop
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movups xmmword ptr [rbx], xmm0    ; 区域外: 128-bit 槽位读回 (含清零语义)
    add  rsp, 32
    pop  rbx
    ret
xr_sd_ld ENDP

; void xr_sd_st(double a):
;   Win64 ABI: a → xmm0 低 64。区域 = movsd [g_sd_out], xmm0 (XmmStore 8B
;   写, 只落低 64 位)。main 读回 g_sd_out。
xr_sd_st PROC
    sub  rsp, 32

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movsd qword ptr [g_sd_out], xmm0     ; 真 movsd mem 写 (F2 0F 11 05 disp32)
    nop
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    add  rsp, 32
    ret
xr_sd_st ENDP

_TEXT ENDS

END
