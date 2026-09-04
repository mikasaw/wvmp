; MIT-411 (G1): SSE 尾扫包主样本 MASM helper — 真字节直写本单新形态
; (MSVC x64 不支持 inline asm; /Od 不产以下形态的对照见各 helper 注释):
;
;   ① memop_triple_add : movsd load + addsd + movsd store 双访存读改写 triple
;                        (全 rip, "读→算→写回" 语义的指令级呈现)
;   ② memop_addsd_stack: addsd xmm0, [rsp+40] 栈基址 mem 源 (派活单 §A.3.1
;                        处方形态; 反汇编 F2 0F 58 44 24 28 → addsd xmm0,
;                        qword ptr [rsp+40] — "dst=mem" 在 x86 无编码,
;                        mem 恒为源, 见 x86_translate.cpp translate_sse_add)
;   ⑤ memop_comiss_mem : comiss xmm0, [g_f] (0F 2F 05 rel32, rip mem 源)
;                        + seta (flags 读回: Setcc handler 读折叠后的
;                        Ucomiss handler 写的 VM flags 槽)
;   ⑥ memop_comisd_mem : comisd xmm0, [g_d] (66 0F 2F 05 rel32) + seta
;   ⑧ memop_{and,or,xor}pd_reg : 66 0F 54/56/57 C1 REG-REG (pd 位运算族)
;   ⑨ memop_{and,or,xor}pd_mem : 66 0F 54/56/57 05 rel32 rip mem 源
;   ⑩ memop_andnps_neg  : andnps xmm0, xmm1 (0F 55 C1) — MIT-411 时代为
;                        负例 (gate); MIT-425 (G1b) andnps 入面→正例真虚
;                        拟化 (§B.4 翻转), 行为 byte-exact 不变。
;
; Win64 ABI: 整型参数 rcx/rdx; 浮点参数 xmm0/xmm1; 返回值 rax/xmm0。
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), seta/movzx 结果必须 marker_end 前存栈、之后还原
; (pitfall #36, 沿用 setcc_sample_asm.asm 的 [rsp+24] 模式)。

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXPEBD@Z (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

; C 链接全局 (sse_memop_sample_main.cpp extern "C"): MASM 直引 → rip-relative
EXTERNDEF g_d : QWORD
EXTERNDEF g_f : DWORD
EXTERNDEF g_pd : XMMWORD

_TEXT SEGMENT

; double memop_triple_add(double v): g_d += v; 返回新 g_d。
;   区域字节: movsd xmm1,[g_d] (F2 0F 10 0D rel32) + addsd xmm1,xmm0
;   (F2 0F 58 C8) + movsd [g_d],xmm1 (F2 0F 11 0D rel32) — 读→算→写回,
;   "双访存" 语义 = 三条指令 (x86 SSE ALU 无内存目标编码)。
memop_triple_add PROC
    push rbx
    sub  rsp, 32

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    movsd xmm1, qword ptr [g_d]      ; 读 (rip mem 源)
    addsd xmm1, xmm0                 ; 算 (v + g_d)
    movsd qword ptr [g_d], xmm1      ; 写回 (rip mem 目标)
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movsd xmm0, xmm1                 ; 返回值 (xmm1 在 marker_end 后仍存活)
    add  rsp, 32
    pop  rbx
    ret
memop_triple_add ENDP

; double memop_addsd_stack(double v): addsd xmm0, [rsp+40] (v + 栈槽)。
;   区域字节: F2 0F 58 44 24 28 (5 字节) — 栈基址 mem 源 (非 rip 形态)。
memop_addsd_stack PROC
    push rbx
    sub  rsp, 48
    movsd qword ptr [rsp+40], xmm0   ; 存参 (区外)

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    addsd xmm0, qword ptr [rsp+40]   ; F2 0F 58 44 24 28 (栈基址 mem 源)
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    add  rsp, 48
    pop  rbx
    ret
memop_addsd_stack ENDP

; int memop_comiss_mem(float v): comiss xmm0, [g_f] + seta → (v > g_f)。
;   区域字节: comiss(7) + seta(3) + movzx(4) + mov(4) = 18 字节。
;   comiss flags 语义与 ucomiss 逐位相同 (SDM) → 折叠 Ucomiss handler;
;   seta 读 VM flags 槽 (pitfall #79 真参与运行时)。
memop_comiss_mem PROC
    push rbx
    sub  rsp, 56

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    comiss xmm0, dword ptr [g_f]     ; 0F 2F 05 rel32 (rip mem 源)
    seta   al                        ; v > g_f (CF=0 且 ZF=0) → 1
    movzx rax, al
    mov   [rsp+24], rax              ; rax 跨 marker_end clobber (pitfall #36)
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov   rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 56
    pop  rbx
    ret
memop_comiss_mem ENDP

; int memop_comisd_mem(double v): comisd xmm0, [g_d] + seta → (v > g_d)。
;   区域字节: comisd(8) + seta(3) + movzx(4) + mov(4) = 19 字节。
memop_comisd_mem PROC
    push rbx
    sub  rsp, 56

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    comisd xmm0, qword ptr [g_d]     ; 66 0F 2F 05 rel32 (rip mem 源)
    seta   al                        ; v > g_d → 1
    movzx rax, al
    mov   [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov   rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 56
    pop  rbx
    ret
memop_comisd_mem ENDP

; ---- ⑧ pd 位运算族 REG-REG (66 0F 54/56/57 C1) ----
; unsigned long long memop_andpd_reg(a, b): andpd xmm0, xmm1 → 低 64 位。
memop_andpd_reg PROC
    push rbx
    sub  rsp, 32
    movq xmm0, rcx                   ; a (区外)
    movq xmm1, rdx                   ; b (区外)

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    andpd xmm0, xmm1                 ; 66 0F 54 C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0                   ; 取低 64 位 (区外)
    add  rsp, 32
    pop  rbx
    ret
memop_andpd_reg ENDP

; unsigned long long memop_orpd_reg(a, b): orpd (66 0F 56 C1)。
memop_orpd_reg PROC
    push rbx
    sub  rsp, 32
    movq xmm0, rcx
    movq xmm1, rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    orpd  xmm0, xmm1                 ; 66 0F 56 C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    add  rsp, 32
    pop  rbx
    ret
memop_orpd_reg ENDP

; unsigned long long memop_xorpd_reg(a, b): xorpd (66 0F 57 C1)。
memop_xorpd_reg PROC
    push rbx
    sub  rsp, 32
    movq xmm0, rcx
    movq xmm1, rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    xorpd xmm0, xmm1                 ; 66 0F 57 C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    add  rsp, 32
    pop  rbx
    ret
memop_xorpd_reg ENDP

; ---- ⑨ pd 位运算族 rip mem 源 (66 0F 54/56/57 05 rel32) ----
; unsigned long long memop_andpd_mem(a): andpd xmm0, [g_pd]。
memop_andpd_mem PROC
    push rbx
    sub  rsp, 32
    movq xmm0, rcx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    andpd xmm0, xmmword ptr [g_pd]   ; 66 0F 54 05 rel32 (rip mem 源)
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    add  rsp, 32
    pop  rbx
    ret
memop_andpd_mem ENDP

; unsigned long long memop_orpd_mem(a): orpd xmm0, [g_pd]。
memop_orpd_mem PROC
    push rbx
    sub  rsp, 32
    movq xmm0, rcx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    orpd  xmm0, xmmword ptr [g_pd]   ; 66 0F 56 05 rel32
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    add  rsp, 32
    pop  rbx
    ret
memop_orpd_mem ENDP

; unsigned long long memop_xorpd_mem(a): xorpd xmm0, [g_pd]。
memop_xorpd_mem PROC
    push rbx
    sub  rsp, 32
    movq xmm0, rcx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    xorpd xmm0, xmmword ptr [g_pd]   ; 66 0F 57 05 rel32
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    add  rsp, 32
    pop  rbx
    ret
memop_xorpd_mem ENDP

; unsigned int memop_andnps_neg(a, b): andnps xmm0, xmm1 (0F 55 C1) —
;   MIT-425 (G1b) 起为正例 (0F 55 入面, 折叠新 VmOp::Andnps)。
;   andnps 语义 = NOT(xmm0) & xmm1 (SDM: NOT 作用于第一操作数), 样本输入
;   a=0x0F0F0F0F, b=0xFFFFFFFF → 0xF0F0F0F0。
;   0F 55 系不在本单范围 (派活单 §C D4, 留 412+) → lifter unsupported →
;   C1 gate: 本区域保持原生执行, 行为 byte-exact (stdout 对比兜底)。
memop_andnps_neg PROC
    push rbx
    sub  rsp, 32
    movd xmm0, ecx
    movd xmm1, edx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    andnps xmm0, xmm1                ; 0F 55 C1 (MIT-425 起正例)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movd eax, xmm0
    add  rsp, 32
    pop  rbx
    ret
memop_andnps_neg ENDP

_TEXT ENDS

END
