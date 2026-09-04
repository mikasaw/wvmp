; MIT-426 (G6a): VEX.128 档A 影子样本 MASM helper — 三态折叠 + D4 拷贝 +
; mem 通路的 ctx.xmm 运行时读回断言 (与 wvmp_vex128_sample 同能力面配对、
; 独立 exe, 沿用 MIT-389/408/411/425 影子样本模式)。
;
; 目的 (pitfall #79 纪律): 主样本 stdout 只断言低 64 位终值。三态③ 的
; 前置 Op::Movaps 若槽位写错 (误写无关槽 / GPR 槽区 — MIT-371 空转形态)
; 或标量高位语义错 (dst 高位应 ← s1 高位), 主样本可能碰巧 PASS — 本影子
; 把 8 槽 × 2×u64 全量打印: dst 槽 = 期望位图案, 其余 7 槽必须 = 入口
; 预载值 (误写无关槽即 FAIL); 标量 vmulss 的 "dst 高位 ← s1 高位" 同场
; 可断 (pre-Mov 16B 拷贝正确性的位级证据)。
;
; 统一探针签名 (Win64 ABI): void vex_<name>(const unsigned long long* in
;     [rcx], unsigned long long* out [rdx]): 位图案探针全 8 槽从 in 预载
;     (load_all, 无浮点参数); out[0..15] = xmm0..xmm7 各 2×u64 全量读回
;     (区域后落盘)。
;
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), out 指针必须放 callee-saved 寄存器 rbx (pitfall #36)。

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXPEBD@Z (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

; C 链接全局 (vex128_xmm_readback_sample_main.cpp extern "C")
EXTERNDEF g_sh_vex_ps : XMMWORD   ; vmovups mem load 位图案源

_TEXT SEGMENT

; ---- 公共尾声: xmm0..7 → out[0..15] (rbx = out) ----
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

; ---- 公共序幕: in[0..7] → xmm0..xmm7 全量预载 (rcx = in) ----
load_all MACRO
    movups xmm0, xmmword ptr [rcx + 0*16]
    movups xmm1, xmmword ptr [rcx + 1*16]
    movups xmm2, xmmword ptr [rcx + 2*16]
    movups xmm3, xmmword ptr [rcx + 3*16]
    movups xmm4, xmmword ptr [rcx + 4*16]
    movups xmm5, xmmword ptr [rcx + 5*16]
    movups xmm6, xmmword ptr [rcx + 6*16]
    movups xmm7, xmmword ptr [rcx + 7*16]
ENDM

; ---- ① vaddss d==s1 直走: 只改低 32 位, 高 96 位 = dst 残留 ----
vex_sh_addss PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rdx
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vaddss xmm0, xmm0, xmm1          ; 三态① (低 32 = lane 位加, 高位不动)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
vex_sh_addss ENDP

; ---- ② vaddps d==s2 交换 (packed): 全 128-bit lane 语义 ----
; native VEX: slot2 = slot3 + slot2 (逐 lane, 全 128 位); 交换折后 2-op
; 同式 — packed 全宽语义无高位分叉 (标量 d==s2 gate 见主样本 ⑳)。
vex_sh_addps_swap PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rdx
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vaddps xmm2, xmm3, xmm2          ; d==s2 (s2=xmm2, s1=xmm3) → 交换折
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
vex_sh_addps_swap ENDP

; ---- ③ vaddps d 独立: pre-Mov(xmm2←xmm0 全 16B) + addps(xmm2, xmm1) ----
; dst 槽 2 = slot0 + slot1 逐 lane; 其余槽 = 预载不动 (pre-Mov 误写即 FAIL)
vex_sh_addps_dindep PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rdx
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vaddps xmm2, xmm0, xmm1          ; 三态③ → 前置 Movaps + 2-op
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
vex_sh_addps_dindep ENDP

; ---- ④ vmulss d 独立 (标量高位语义): dst[127:32] ← s1[127:32] ----
; pre-Mov 16B 拷贝后 mulss: slot2 高 96 = slot0 高 96, 低 32 = 乘积
vex_sh_vmulss_dindep PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rdx
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vmulss xmm2, xmm0, xmm1          ; 三态③ 标量 → 高位语义断言面
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
vex_sh_vmulss_dindep ENDP

; ---- ⑤ vsubps d 独立 (非交换): pre-Mov + 2-op = s1 - s2 逐 lane ----
vex_sh_subps_dindep PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rdx
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vsubps xmm2, xmm0, xmm1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
vex_sh_subps_dindep ENDP

; ---- ⑥ vandnps d 独立: pre-Mov + 2-op = ~s1 & s2 (全 128 位) ----
vex_sh_andnps_dindep PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rdx
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vandnps xmm2, xmm0, xmm1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
vex_sh_andnps_dindep ENDP

; ---- ⑦ vmovaps 纯拷贝: slot3 = slot0 全 16B (D4 直折单条) ----
vex_sh_movaps PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rdx
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vmovaps xmm3, xmm0
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
vex_sh_movaps ENDP

; ---- ⑧ vpxor 清零惯用法: slot2 = 0 (d==s1==s2 直走) ----
vex_sh_vpxor PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rdx
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vpxor  xmm2, xmm0, xmm0          ; dst=2, s1=s2=0 (d==s1 直走)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
vex_sh_vpxor ENDP

; ---- ⑨ vmovups mem load: slot2 = [g_sh_vex_ps] (408 通路 VEX 编码) ----
vex_sh_vmovups_load PROC
    push rbx
    sub  rsp, 32
    mov  rbx, rdx
    load_all

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vmovups xmm2, xmmword ptr [g_sh_vex_ps]
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    sink_slots
    add  rsp, 32
    pop  rbx
    ret
vex_sh_vmovups_load ENDP

_TEXT ENDS
END
