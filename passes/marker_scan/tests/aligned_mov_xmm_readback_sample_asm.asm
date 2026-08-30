; MIT-428 (G1d): SSE2 对齐传送 movdqa/movdqu 影子样本 MASM helper — Movaps/
; Movups 既有 handler 的 ctx.xmm 运行时读回断言 (与 wvmp_aligned_mov_sample
; 同能力面配对、独立 exe, 沿用 MIT-389/408/411/425/426/427 影子样本模式)。
;
; 目的 (pitfall #79 纪律): 主样本 stdout 只断言传送语义值。本影子把 8 槽 ×
; 2×u64 全量打印: dst 槽 = 期望位图案 (16B 全宽, 高位 = 源高位 — movdqa/
; movdqu 无清零/截断语义, 与 427 桥装入清零同场对照), 其余 7 槽必须 = 入口
; 预载值 (误写无关槽即 FAIL)。本单零新 handler → 运行时走既有 Movaps/Movups
; 注册表 (dump 门 SSE_HANDLERS 集合恒等 = 零新 VmOp 机器证明, 426 §D.7)。
;
; 统一探针签名: void ash_<name>(const unsigned long long* in_slots,
;     unsigned long long* out_slots):
;   - in_slots[0..15] = xmm0..7 各 2×u64 位图案预载 (load_all, 区外 native);
;   - out_slots[0..15] = xmm0..7 全量读回 (区域后落盘);
;   - out_slots[16] = rax 哨兵 (本族无 GP 方向 — 恒 0xBBBBBBBBBBBBBBBB)。
;
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), out 指针必须放 callee-saved 寄存器 rbx (pitfall #36)。

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXXZ (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

; C 链接全局 (aligned_mov_xmm_readback_sample_main.cpp extern "C")
EXTERNDEF g_ash_src      : QWORD     ; 对齐 rip 源 (2×QWORD)
EXTERNDEF g_ash_out      : QWORD     ; 对齐 store 目标 (⑦)

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

; ---- 公共尾声 B: rax 哨兵 → out_slots[16] ----
sink_rax MACRO
    mov rax, 0BBBBBBBBBBBBBBBBh   ; GP 哨兵 (本族无 GP 方向)
    mov [rbx + 16*8], rax
ENDM

; ---- ① ash_dqa_rr(in, out): region { movdqa xmm0, xmm1 } →
;      xmm0 = xmm1 预载全宽 (高位 = 源高位, 无清零), xmm2..7 保持 ----
ash_dqa_rr PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movdqa xmm0, xmm1               ; 66 0F 6F C1 (全宽拷贝)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    sink_rax
    sink_slots
    ret
ash_dqa_rr ENDP

; ---- ② ash_dqa_rr7(in, out): region { db 66 0F 7F C8 } (7F 反写形) ----
ash_dqa_rr7 PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXXZ
    db 066h, 0Fh, 07Fh, 0C8h        ; movdqa xmm0, xmm1 (7F 形)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    sink_rax
    sink_slots
    ret
ash_dqa_rr7 ENDP

; ---- ③ ash_dqu_rr(in, out): region { movdqu xmm0, xmm1 } ----
ash_dqu_rr PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movdqu xmm0, xmm1               ; F3 0F 6F C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    sink_rax
    sink_slots
    ret
ash_dqu_rr ENDP

; ---- ④ ash_dqa_stack(in, out): region { movdqa xmm0, [rsp+20h] } →
;      xmm0 = 栈槽图案 (对齐栈槽, 区外预填) ----
ash_dqa_stack PROC
    push rbx
    sub  rsp, 30h
    mov  rbx, rdx
    load_all
    movups xmmword ptr [rsp+20h], xmm4   ; 栈槽预填 = xmm4 预载图案 (区外)
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movdqa xmm0, xmmword ptr [rsp+20h]   ; 66 0F 6F 44 24 20
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    sink_rax
    sink_slots
    add  rsp, 30h
    pop  rbx
    ret
ash_dqa_stack ENDP

; ---- ⑤ ash_dqu_stack_unal(in, out): region { movdqu xmm0, [rsp+8h] } →
;      xmm0 = 栈槽图案 ([rsp+8h] 非 16B 对齐 — movups 宽松语义行为钉) ----
ash_dqu_stack_unal PROC
    push rbx
    sub  rsp, 30h
    mov  rbx, rdx
    load_all
    movups xmmword ptr [rsp+8h], xmm5    ; 非对齐栈槽预填 = xmm5 图案
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movdqu xmm0, xmmword ptr [rsp+8h]    ; F3 0F 6F 44 24 08
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    sink_rax
    sink_slots
    add  rsp, 30h
    pop  rbx
    ret
ash_dqu_stack_unal ENDP

; ---- ⑥ ash_dqa_rip_load(in, out): region { movdqa xmm0, [rip+g_ash_src] }
;      → xmm0 = 全局图案 (对齐 rip load) ----
ash_dqa_rip_load PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movdqa xmm0, xmmword ptr [g_ash_src]   ; 66 0F 6F 05 (rip load)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    sink_rax
    sink_slots
    ret
ash_dqa_rip_load ENDP

; ---- ⑦ ash_dqa_rip_store(in, out): region { movdqa [rip+g_ash_out], xmm0 }
;      → g_ash_out = xmm0 预载图案 (16B 全宽 store; main 读回) ----
ash_dqa_rip_store PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movdqa xmmword ptr [g_ash_out], xmm0   ; 66 0F 7F 05 (rip store)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    sink_rax
    sink_slots
    ret
ash_dqa_rip_store ENDP

; ---- ⑧ ash_vdqa_rr(in, out): region { vmovdqa xmm0, xmm1 } (C5 F9 6F C1) ----
ash_vdqa_rr PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vmovdqa xmm0, xmm1              ; C5 F9 6F C1 (VEX 镜像)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    sink_rax
    sink_slots
    ret
ash_vdqa_rr ENDP

; ---- ⑨ ash_vdqu_rr(in, out): region { vmovdqu xmm0, xmm1 } (C5 FA 6F C1) ----
ash_vdqu_rr PROC
    mov rbx, rdx
    load_all
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vmovdqu xmm0, xmm1              ; C5 FA 6F C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    sink_rax
    sink_slots
    ret
ash_vdqu_rr ENDP

_TEXT ENDS
END
