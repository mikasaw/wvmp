; MIT-427 (G1c): SSE2 movd/movq GP↔xmm 桥影子样本 MASM helper — 桥 handler
; 的 ctx.xmm 运行时读回断言 (与 wvmp_sse_bridge_sample 同能力面配对、独立
; exe, 沿用 MIT-389/408/411/425 影子样本模式)。
;
; 目的 (pitfall #79 纪律): 主样本 stdout 只断言桥语义值。本影子把 8 槽 ×
; 2×u64 全量打印: dst 槽 = 期望位图案, 其余 7 槽必须 = 入口预载值 (误写
; 无关槽即 FAIL); movd 装入后高 96 位 / movq 装入后高 64 位 = 0 的清零
; 位级语义同场可断 (handler 若写 GPR 槽区 / 槽位公式错 sub 0x24 / 宽度
; 链错 → 与 native 不一致 → FAIL)。
;
; 统一探针签名: void bsh_<name>(const unsigned long long* in_slots,
;     unsigned long long* out_slots):
;   - in_slots[0..15] = xmm0..7 各 2×u64 位图案预载 (load_all, 区外 native);
;   - out_slots[0..15] = xmm0..7 全量读回 (区域后落盘);
;   - out_slots[16] = rax 读回 (GP 方向探针: movd 零扩展 / movq 截取位级
;     证据; 非 GP 探针写 0xKKKKKKKKKKKKKKKK 哨兵)。
;
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), out 指针必须放 callee-saved 寄存器 rbx (pitfall #36)。

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXPEBD@Z (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

; C 链接全局 (sse_bridge_xmm_readback_sample_main.cpp extern "C")
EXTERNDEF g_bsh32      : DWORD     ; movd mem 源
EXTERNDEF g_bsh64      : QWORD     ; movq mem 源
EXTERNDEF g_bshout64   : QWORD     ; movq mem store 目标

_TEXT SEGMENT

; ---- 公共尾声 A: xmm0..7 → out_slots[0..15] (rbx = out) ----
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

; ---- 公共序幕: in_slots[0..7] → xmm0..xmm7 全量预载 (rcx = in) ----
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

; ---- 公共尾声 B: rax → out_slots[16] + 哨兵填充 (GP 方向探针) ----
sink_rax MACRO
    mov qword ptr [rbx + 16*8], rax
ENDM

; ---- ① bsh_movd_in(in, out): region { mov eax, imm32; movd xmm0, eax }
;      → xmm0 = {00000000_00000000, ..., A5A5A5A5} (高 96 清零位级证据),
;      xmm1..7 = 预载保持 ----
bsh_movd_in PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    mov  eax, 0A5A5A5A5h
    movd xmm0, eax                  ; 66 0F 6E C0 (桥 load w4)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov rax, 0BBBBBBBBBBBBBBBBh   ; GP 哨兵 (mov r/m64, imm64 不可编码)
    mov [rbx + 16*8], rax
    sink_slots
    ret
bsh_movd_in ENDP

; ---- ② bsh_movq_in(in, out): region { mov rax, imm64; movq xmm0, rax }
;      → xmm0 = {imm64, 0} (高 64 清零位级证据) ----
bsh_movq_in PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    mov  rax, 1122334455667788h
    movq xmm0, rax                  ; 66 48 0F 6E C0 (桥 load w8)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov rax, 0BBBBBBBBBBBBBBBBh
    mov [rbx + 16*8], rax
    sink_slots
    ret
bsh_movq_in ENDP

; ---- ③ bsh_movd_out(in, out): region { movd eax, xmm0 } → rax =
;      zeroext(低 32 预载) = 00000000_11111111 (native movd r32 零扩展
;      位级证据); xmm 槽全保持 ----
; ---- ③ 观察 = 区内 Store: Rax 槽 64 位全量落盘 (native movd r32 零扩展
;      位级证据: out[16].lo = 11111111, out[16].hi = 0) ----
bsh_movd_out PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movd eax, xmm0                  ; 66 0F 7E C0 (桥 store w4)
    mov [rbx + 16*8], rax           ; 区内 Store: Rax 槽 64 位全量落盘
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    sink_slots
    ret
bsh_movd_out ENDP

; ---- ④ bsh_movq_out(in, out): region { movq rax, xmm0 } → rax = 低 64 预载 ----
bsh_movq_out PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movq rax, xmm0                  ; 66 48 0F 7E C0 (桥 store w8)
    mov [rbx + 16*8], rax           ; 区内 Store 落盘
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    sink_slots
    ret
bsh_movq_out ENDP

; ---- ⑤ bsh_movq_xmm_zero(in, out): region { db F3 0F 7E C1 } →
;      xmm0 = {低64(xmm1 预载), 0} (F3 形态高 64 清零), xmm1..7 保持 ----
bsh_movq_xmm_zero PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    db 0F3h, 0Fh, 7Eh, 0C1h         ; movq xmm0, xmm1 (F3, 高 64 清零)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov rax, 0BBBBBBBBBBBBBBBBh
    mov [rbx + 16*8], rax
    sink_slots
    ret
bsh_movq_xmm_zero ENDP

; ---- ⑥ bsh_movq_xmm_d6(in, out): region { db 66 0F D6 C1 } →
;      xmm0 = {低64(xmm1 预载), 0} — **#33 实测推翻 "高 64 保持" 先验**:
;      66 0F D6 reg-reg 与 F3 逐位同语义 (高 64 清零, d6_probe 实证)。 ----
bsh_movq_xmm_d6 PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    db 066h, 0Fh, 0D6h, 0C8h        ; movq xmm0, xmm1 (66 0F D6 reg-reg; C8 = dst r/m 位)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov rax, 0BBBBBBBBBBBBBBBBh
    mov [rbx + 16*8], rax
    sink_slots
    ret
bsh_movq_xmm_d6 ENDP

; ---- ⑦ bsh_movd_mem_in(in, out): region { movd xmm0, [rip+g_bsh32] }
;      → xmm0 = {zeroext(g_bsh32), 0} (mem load w4 清零) ----
bsh_movd_mem_in PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movd xmm0, dword ptr [g_bsh32]   ; 66 0F 6E 05 (mem load w4)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov rax, 0BBBBBBBBBBBBBBBBh
    mov [rbx + 16*8], rax
    sink_slots
    ret
bsh_movd_mem_in ENDP

; ---- ⑧ bsh_movq_mem_in(in, out): region { movq xmm0, [rip+g_bsh64] }
;      → xmm0 = {g_bsh64, 0} (mem load w8 清零) ----
bsh_movq_mem_in PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movq xmm0, qword ptr [g_bsh64]   ; 66 REX.W 0F 6E / F3 0F 7E (mem load w8)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov rax, 0BBBBBBBBBBBBBBBBh
    mov [rbx + 16*8], rax
    sink_slots
    ret
bsh_movq_mem_in ENDP

; ---- ⑨ bsh_movq_mem_out(in, out): region { movq [rip+g_bshout64], xmm0 }
;      → g_bshout64 = 低 64 预载 (mem store w8 截取; main 落盘后读回) ----
bsh_movq_mem_out PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movq qword ptr [g_bshout64], xmm0   ; 66 REX.W 0F 7E / 66 0F D6 (mem store w8)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov rax, 0BBBBBBBBBBBBBBBBh
    mov [rbx + 16*8], rax
    sink_slots
    ret
bsh_movq_mem_out ENDP

_TEXT ENDS
END
