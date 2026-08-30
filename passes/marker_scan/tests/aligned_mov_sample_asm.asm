; MIT-428 (G1d): SSE2 对齐传送 movdqa/movdqu 主样本 MASM helper — 双编码 ×
; 三形态 (reg-reg 6F/7F 反写 / 栈槽 / rip) + 非对齐栈槽行为钉 + VEX 镜像 +
; 负例区 (EVEX vmovdqa32 / vpaddd ymm / punpcklqdq / pmovmskb) 真字节直写。
;
; 形态依据 (#33 实测, vendored capstone 5.0.6 probe, 2026-08-31):
;   - movdqa/movdqu reg,reg 双编码: 66/F3 0F 6F (reg 字段=dst, MASM 助记符
;     直产) 与 66/F3 0F 7F (rm 字段=dst 反写合法形, MASM 不可表达 — db 直发,
;     423/427 先例)。capstone 对两编码均归一化 dst-first 报操作数 (probe
;     access W 位钉死) — ①~④ 折叠结果逐字段一致。
;   - 栈槽 load: [rsp+20h] 16B 对齐 (movdqa, 对齐语义基线) 与 [rsp+8h]
;     非 16B 对齐 (movdqu, movups 宽松语义行为钉) — sub rsp,30h 槽区在
;     marker_begin 调用两侧不受触碰 ( natives/VM 同一真实内存)。
;   - rip 全局: __declspec(align(16)) 对齐源 (movdqa) + 默认对齐非 16B
;     目标 (movdqu store) — 408 D2 对齐/非对齐同款配对。
;   - VEX vmovdqa/vmovdqu: ml64 直收 AVX 助记符 (C5 2B VEX 形; C4 3B 形由
;     lifter 单测钉, 427 B.3 惯例)。
;   - 负例 (函数级分区, 整函数 gate 可调用, 行为 byte-exact; 本机
;     AVX2 + AVX-512F/VL 实测在位 — _cpuid probe 2026-08-31):
;     vmovdqa32 (EVEX 62 F1 7D 08 6F C1, id=1026 白名单外) / vpaddd ymm
;     (位宽闸 + 白名单外) / punpcklqdq (交织语义 D4 不本单) / pmovmskb
;     (66 0F D7 D3 不本单)。
;
; Win64 ABI: 整型参数 rcx/rdx/r8; 返回值 rax。
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), out 指针必须放 callee-saved 寄存器 rbx (pitfall #36)。

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXXZ (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

; C 链接全局 (aligned_mov_sample_main.cpp extern "C"): MASM 直引 → rip-relative
EXTERNDEF g_amv_src    : QWORD     ; 对齐 rip 源
EXTERNDEF g_amv_out    : QWORD     ; 对齐 store 目标 (⑧⑫)
EXTERNDEF g_amv_out_u  : QWORD     ; 非对齐 store 目标 (⑨)

_TEXT SEGMENT

; ---- ① amv_dqa_rr6(dst16*, src16*): region { movdqa xmm0, xmm1 }
;      (66 0F 6F C1, reg 字段=dst) → out = src 16B 全宽 (含高位) ----
amv_dqa_rr6 PROC
    mov  rbx, rcx                    ; out (callee-saved, pitfall #36)
    movups xmm0, xmmword ptr [rdx]   ; dst 预载哨兵脏值 (16B)
    movups xmm1, xmmword ptr [rdx+16]; src 位图案
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movdqa xmm0, xmm1                ; 66 0F 6F C1 (G1d 对齐传送, 全宽)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0   ; 16B 全量落盘
    ret
amv_dqa_rr6 ENDP

; ---- ② amv_dqa_rr7(dst16*, src16*): region { db 66 0F 7F C8 }
;      (7F reg,reg 反写合法形, rm 字段=dst — MASM 不可表达, db 直发) ----
amv_dqa_rr7 PROC
    mov  rbx, rcx
    movups xmm0, xmmword ptr [rdx]   ; dst 预载哨兵
    movups xmm1, xmmword ptr [rdx+16]; src
    call ?marker_begin@sdk@wvmp@@YAXXZ
    db 066h, 0Fh, 07Fh, 0C8h         ; movdqa xmm0, xmm1 (7F 形, dst=r/m 位)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0
    ret
amv_dqa_rr7 ENDP

; ---- ③ amv_dqu_rr6(dst16*, src16*): region { movdqu xmm0, xmm1 } ----
amv_dqu_rr6 PROC
    mov  rbx, rcx
    movups xmm0, xmmword ptr [rdx]
    movups xmm1, xmmword ptr [rdx+16]
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movdqu xmm0, xmm1                ; F3 0F 6F C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0
    ret
amv_dqu_rr6 ENDP

; ---- ④ amv_dqu_rr7(dst16*, src16*): region { db F3 0F 7F C8 } ----
amv_dqu_rr7 PROC
    mov  rbx, rcx
    movups xmm0, xmmword ptr [rdx]
    movups xmm1, xmmword ptr [rdx+16]
    call ?marker_begin@sdk@wvmp@@YAXXZ
    db 0F3h, 0Fh, 07Fh, 0C8h         ; movdqu xmm0, xmm1 (7F 形)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0
    ret
amv_dqu_rr7 ENDP

; ---- ⑤ amv_dqa_stack(dst16*, src16*): 对齐栈槽 movdqa load —
;      region { movdqa xmm0, xmmword ptr [rsp+20h] } → out = src。
;      [rsp+20h] ≡ 0 (mod 16) (push rbx + sub 30h 后 rsp ≡ 0):
;      对齐语义基线 (movdqa 对齐形式, native/VM 一致)。 ----
amv_dqa_stack PROC
    push rbx
    sub  rsp, 30h
    mov  rbx, rcx
    movups xmm0, xmmword ptr [rdx]   ; dst 预载哨兵脏值
    movups xmm1, xmmword ptr [rdx+16]; src 位图案
    movups xmmword ptr [rsp+20h], xmm1   ; 栈槽预填 (区域外 native, 两跑同内存)
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movdqa xmm0, xmmword ptr [rsp+20h]   ; 66 0F 6F 44 24 20 (对齐栈槽 load)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0
    add  rsp, 30h
    pop  rbx
    ret
amv_dqa_stack ENDP

; ---- ⑥ amv_dqu_stack_unal(dst16*, src16*): **非对齐栈槽 movdqu load** —
;      region { movdqu xmm0, xmmword ptr [rsp+8h] } → out = src。
;      [rsp+8h] ≡ 8 (mod 16) 非 16B 对齐 — movups 宽松语义行为钉
;      (native movdqu 合法; VM XmmLoad movups 通路无对齐校验, 两跑一致)。 ----
amv_dqu_stack_unal PROC
    push rbx
    sub  rsp, 30h
    mov  rbx, rcx
    movups xmm0, xmmword ptr [rdx]
    movups xmm1, xmmword ptr [rdx+16]
    movups xmmword ptr [rsp+8h], xmm1    ; 非对齐栈槽预填
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movdqu xmm0, xmmword ptr [rsp+8h]    ; F3 0F 6F 44 24 08 (非对齐栈槽)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0
    add  rsp, 30h
    pop  rbx
    ret
amv_dqu_stack_unal ENDP

; ---- ⑦ amv_dqa_rip_load(dst16*): region { movdqa xmm0, [rip+g_amv_src] }
;      → out = g_amv_src (16B 对齐全局, 对齐形式 rip load) ----
amv_dqa_rip_load PROC
    mov  rbx, rcx
    movups xmm0, xmmword ptr [rdx]   ; 哨兵
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movdqa xmm0, xmmword ptr [g_amv_src]   ; 66 0F 6F 05 (rip load)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0
    ret
amv_dqa_rip_load ENDP

; ---- ⑧ amv_dqa_rip_store(src16*): region { movdqa [rip+g_amv_out], xmm0 }
;      → g_amv_out = src (16B 对齐 store; main 读回) ----
amv_dqa_rip_store PROC
    movups xmm0, xmmword ptr [rcx]
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movdqa xmmword ptr [g_amv_out], xmm0   ; 66 0F 7F 05 (rip store)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ret
amv_dqa_rip_store ENDP

; ---- ⑨ amv_dqu_rip_store(src16*): region { movdqu [rip+g_amv_out_u], xmm0 }
;      → g_amv_out_u = src (默认对齐 8B 全局 = 非 16B 对齐 store 目标,
;      408 D2 配对 — movdqu 宽松语义) ----
amv_dqu_rip_store PROC
    movups xmm0, xmmword ptr [rcx]
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movdqu xmmword ptr [g_amv_out_u], xmm0   ; F3 0F 7F 05 (rip store, 非对齐)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ret
amv_dqu_rip_store ENDP

; ---- ⑩ amv_vdqa_rr(dst16*, src16*): region { vmovdqa xmm0, xmm1 }
;      (C5 F9 6F C1 — ml64 直收 AVX 助记符) → out = src 16B 全宽 ----
amv_vdqa_rr PROC
    mov  rbx, rcx
    movups xmm0, xmmword ptr [rdx]
    movups xmm1, xmmword ptr [rdx+16]
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vmovdqa xmm0, xmm1               ; C5 F9 6F C1 (VEX 镜像)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0
    ret
amv_vdqa_rr ENDP

; ---- ⑪ amv_vdqu_rr(dst16*, src16*): region { vmovdqu xmm0, xmm1 } ----
amv_vdqu_rr PROC
    mov  rbx, rcx
    movups xmm0, xmmword ptr [rdx]
    movups xmm1, xmmword ptr [rdx+16]
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vmovdqu xmm0, xmm1               ; C5 FA 6F C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0
    ret
amv_vdqu_rr ENDP

; ---- ⑫ amv_vdqa_rip_store(src16*): region { vmovdqa [rip+g_amv_out], xmm0 }
;      (C5 F9 7F 05 — VEX store 方向; main 读回) ----
amv_vdqa_rip_store PROC
    movups xmm0, xmmword ptr [rcx]
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vmovdqa xmmword ptr [g_amv_out], xmm0  ; C5 F9 7F 05 (VEX rip store)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ret
amv_vdqa_rip_store ENDP

; ---- ⑬ 负例 amv_vmovdqa32_neg(a, out): region { db EVEX vmovdqa32 } —
;      EVEX (62 前缀) id=1026 白名单外 → C1 gate 整函数原生; 本机
;      AVX-512F/VL 在位 (cpuid probe), native 执行 → 行为 byte-exact。 ----
amv_vmovdqa32_neg PROC
    mov  rbx, rdx
    movups xmm0, xmmword ptr [rcx]
    movups xmm1, xmmword ptr [rcx+16]
    call ?marker_begin@sdk@wvmp@@YAXXZ
    db 062h, 0F1h, 07Dh, 008h, 06Fh, 0C1h  ; vmovdqa32 xmm0, xmm1 (EVEX, gate)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0
    ret
amv_vmovdqa32_neg ENDP

; ---- ⑭ 负例 amv_vpaddd_ymm_neg(a, out): region { vpaddd ymm0, ymm0, ymm1 }
;      — ymm 位宽闸 (op.size=32) + vpaddd 白名单外双 gate → 整函数原生
;      (本机 AVX2 在位)。注意 vpaddd 3-op VEX.NDS: ymm0 = ymm0 + ymm1。 ----
amv_vpaddd_ymm_neg PROC
    mov  rbx, rdx
    vmovdqu ymm0, ymmword ptr [rcx]
    vmovdqu ymm1, ymmword ptr [rcx+32]
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vpaddd ymm0, ymm0, ymm1          ; C5 FD FE C1 (ymm 位宽闸, gate)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    vmovdqu ymmword ptr [rbx], ymm0
    ret
amv_vpaddd_ymm_neg ENDP

; ---- ⑮ 负例 amv_punpcklqdq_neg(dst16*, src16*, out): region { punpcklqdq
;      xmm0, xmm1 } — 交织语义非纯拷贝 (D4 裁决不本单) → gate 可调用。 ----
amv_punpcklqdq_neg PROC
    mov  rbx, r8
    movups xmm0, xmmword ptr [rcx]
    movups xmm1, xmmword ptr [rdx]
    call ?marker_begin@sdk@wvmp@@YAXXZ
    punpcklqdq xmm0, xmm1            ; 66 0F 6C C1 (交织, gate)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0
    ret
amv_punpcklqdq_neg ENDP

; ---- ⑯ 负例 amv_pmovmskb_neg(bits, out): region { pmovmskb eax, xmm0 }
;      — 66 0F D7 D3 不本单 → gate 可调用 (427 桥样本同款形态)。 ----
amv_pmovmskb_neg PROC
    mov   rbx, rdx
    movq  xmm0, rcx
    call ?marker_begin@sdk@wvmp@@YAXXZ
    pmovmskb eax, xmm0               ; 66 0F D7 C0 (gate)
    mov   [rbx], rax
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ret
amv_pmovmskb_neg ENDP

_TEXT ENDS
END
