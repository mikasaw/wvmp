; MIT-427 (G1c): SSE2 movd/movq GP↔xmm 桥主样本 MASM helper — 桥四形 +
; mem 形式 + all-xmm 两形态的真字节直写 (MSVC x64 不支持 inline asm)。
;
; 形态依据 (#33 实测, vendored capstone 5.0.6 probe + cl v145 /Od dumpbin
; probe, 2026-08-30):
;   - _mm_cvtsi32_si128 → movd xmm, r32 (66 0F 6E); _mm_cvtsi64_si128 →
;     movq xmm, r64 (66 REX.W 0F 6E); _mm_cvtsi128_si32 → movd r32, xmm
;     (66 0F 7E); _mm_cvtsi128_si64 → movq r64, xmm (66 REX.W 0F 7E) —
;     四 GP 形态 intrinsic 直产 (报告对照表)。
;   - /Od intrinsic 代码 __m128i 溢出直产 movdqa/movdqu (66/F3 0F 6F/7F)
;     — 本单砍面 → C++ intrinsic 函数全走 C1 gate (负例区, 函数级分区);
;     桥正例由本文件直写 (425 pand 同款纪律)。
;   - F3 0F 7E C1 与 66 0F D6 C8 (movq xmm0, xmm1) reg-reg 双形态 —
;     MASM 助记符不可区分, db 直发 (423 先例)。#33 实测两编码高 64 均
;     清零 (d6_probe), ⑤⑥ 对照钉死。
;   - 负例 paddq (66 0F D4) / psubq (66 0F FB) — B.2 砍面留档 (频率实测
;     shell32 16/854k + 其余 0, psubq 全零; 见 GAPS G1c 节) → C1 gate,
;     可调用, 行为 byte-exact。#33 纠正记录: 派单 §A.2 "paddq=66 0F FC"
;     实测为 PADDB (388), paddq 真值 66 0F D4 (425 原文正确); psubq 真值
;     66 0F FB (425 原文 5C 有误, 5C=SUBPD)。
;   - 负例 pmovmskb (66 0F D7) / pcmpeqd (66 0F 76) — D3 裁决不本单。
;   - 负例 MMX movq (NP 0F 6F, mm 操作数) — D2 MMX/X87 状态域永久 gate;
;     capstone 对 NP 0F 6F 报 id=MOVQ (与 SSE 形态同 id) — mm 操作数判据
;     是唯一可靠闸 (单测钉死)。
;
; Win64 ABI: 整型参数 rcx/rdx/r8; 返回值 rax。
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), out 指针必须放 callee-saved 寄存器 rbx (pitfall #36)。

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXXZ (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

; C 链接全局 (sse_bridge_sample_main.cpp extern "C"): MASM 直引 → rip-relative
EXTERNDEF g_brg32   : DWORD     ; movd mem 源
EXTERNDEF g_brg64   : QWORD     ; movq mem 源
EXTERNDEF g_bout32  : DWORD     ; movd mem store 目标
EXTERNDEF g_bout64  : QWORD     ; movq mem store 目标

_TEXT SEGMENT

; ---- ① brg_movd_in(unsigned long long* out): region { mov eax, imm32;
;      movd xmm0, eax } → out[0]=zeroext(imm32), out[1]=0 (高 96 清零位级证据) ----
; 区域内 GP 源用 imm32 装载 (marker_begin 调用 clobber 易失寄存器, 源值必须
; 区域内重建; mov imm32 为白名单指令)。
brg_movd_in PROC
    mov rbx, rcx                     ; out (callee-saved, pitfall #36)
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mov eax, 0A5A5A5A5h              ; GP 源 (白名单 mov imm32)
    movd  xmm0, eax                  ; 66 0F 6E C0 (G1c 桥 load w4, 高 96 清零)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0   ; 16B 全量落盘 (含高位)
    ret
brg_movd_in ENDP

; ---- ② brg_movq_in(unsigned long long* out): region { mov rax, imm64;
;      movq xmm0, rax } → out[0]=imm64, out[1]=0 (高 64 清零位级证据) ----
brg_movq_in PROC
    mov rbx, rcx
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mov  rax, 1122334455667788h      ; GP 源 (movabs imm64, 白名单)
    movq xmm0, rax                   ; 66 48 0F 6E C0 (G1c 桥 load w8)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0
    ret
brg_movq_in ENDP

; ---- ③ brg_movd_out(bits, out): 区外 movq xmm0, rcx 装载;
;      region { movd eax, xmm0; mov [rbx], rax } → out[0] = zeroext(低 32)。
;      观察路径 = 区内 Store (VM Store 通路读 Rax 槽落盘, 64 位全量可观察 —
;      native movd r32 零扩展语义位级等价)。⚠️ 不用 "stub 返回后捕获物理
;      rax" 形态: 桥 GP 方向的物理寄存器观察在本机实测出现异常 (详见报告
;      §known compromise), 区内 Store 是既有 42 样本通用观察通路 (404 等)。
brg_movd_out PROC
    mov rbx, rdx                     ; out (callee-saved, pitfall #36)
    movq xmm0, rcx                   ; 区外装载 (位图案)
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movd eax, xmm0                   ; 66 0F 7E C0 (G1c 桥 store w4)
    mov [rbx], rax                   ; 区内 Store: Rax 槽 64 位全量落盘 (零扩展可观察)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ret
brg_movd_out ENDP

; ---- ④ brg_movq_out(bits, out): region { movq rax, xmm0; mov [rbx], rax }
;      → out[0] = 低 64 截取 ----
brg_movq_out PROC
    mov rbx, rdx
    movq xmm0, rcx
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movq rax, xmm0                   ; 66 48 0F 7E C0 (G1c 桥 store w8)
    mov [rbx], rax                   ; 区内 Store 落盘
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ret
brg_movq_out ENDP

; ---- ⑤ brg_movq_xmm_zero(dst16*, src16*, out): region { db F3 0F 7E C1 }
;      → out = {低64(src), 0} — F3 形态高 64 清零 (66 0F D6 对照见 ⑥)。
;      ⚠️ 预载走 16B movups: movq xmm, r64 会清零高 64 (⑥ 保持语义观察
;      需要非零高位)。 ----
brg_movq_xmm_zero PROC
    mov rbx, r8
    movups xmm0, xmmword ptr [rcx]   ; dst 16B 预载 (高位 = dst_bits[1])
    movups xmm1, xmmword ptr [rdx]   ; src
    call ?marker_begin@sdk@wvmp@@YAXXZ
    db 0F3h, 0Fh, 7Eh, 0C1h          ; movq xmm0, xmm1 (F3 形态, 高 64 清零)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0
    ret
brg_movq_xmm_zero ENDP

; ---- ⑥ brg_movq_d6(dst16*, src16*, out): region { db 66 0F D6 C8 }
;      → out = {低64(src), 0} — **#33 实测推翻先验**: 66 0F D6 reg-reg 与
;      F3 0F 7E 逐位同语义 (高 64 清零, d6_probe 独立 native 探针实证;
;      SDM register-dest 伪码 DEST[127:64]←0 同口径); C8 = dst 走 r/m 位。
brg_movq_d6 PROC
    mov rbx, r8
    movups xmm0, xmmword ptr [rcx]   ; dst 16B 预载
    movups xmm1, xmmword ptr [rdx]   ; src
    call ?marker_begin@sdk@wvmp@@YAXXZ
    db 066h, 0Fh, 0D6h, 0C8h         ; movq xmm0, xmm1 (66 0F D6 reg-reg)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0
    ret
brg_movq_d6 ENDP

; ---- ⑦ brg_movd_mem_in(unsigned long long* out): region { movd xmm0,
;      dword ptr [rip+g_brg32] } → out = {zeroext(g_brg32), 0}
;      (mem 形式 → 既有 XmmLoad w4 通路, movsd/movd mem 清零语义) ----
brg_movd_mem_in PROC
    mov rbx, rcx
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movd xmm0, dword ptr [g_brg32]   ; 66 0F 6E 05 (mem load w4)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0
    ret
brg_movd_mem_in ENDP

; ---- ⑧ brg_movq_mem_in(unsigned long long* out): region { movq xmm0,
;      qword ptr [rip+g_brg64] } → out = {g_brg64, 0} ----
brg_movq_mem_in PROC
    mov rbx, rcx
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movq xmm0, qword ptr [g_brg64]   ; 66 REX.W 0F 6E / F3 0F 7E (mem load w8)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movups xmmword ptr [rbx], xmm0
    ret
brg_movq_mem_in ENDP

; ---- ⑨ brg_movd_mem_out(unsigned long long bits): region { movd dword
;      ptr [rip+g_bout32], xmm0 } — mem store w4 截取 (main 落盘后读回) ----
brg_movd_mem_out PROC
    movq xmm0, rcx
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movd dword ptr [g_bout32], xmm0   ; 66 0F 7E 05 (mem store w4)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ret
brg_movd_mem_out ENDP

; ---- ⑩ brg_movq_mem_out(unsigned long long bits): region { movq qword
;      ptr [rip+g_bout64], xmm0 } — mem store w8 ----
brg_movq_mem_out PROC
    movq xmm0, rcx
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movq qword ptr [g_bout64], xmm0   ; 66 REX.W 0F 7E / 66 0F D6 (mem store w8)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ret
brg_movq_mem_out ENDP

; ---- ⑪ 负例 brg_paddq_neg(a, b): 66 0F D4 C1 paddq — B.2 砍面留档 →
;      C1 gate (行为 byte-exact, 可调用) ----
brg_paddq_neg PROC
    movq  xmm0, rcx
    movq  xmm1, rdx
    call ?marker_begin@sdk@wvmp@@YAXXZ
    paddq xmm0, xmm1                ; 66 0F D4 C1 (gate 负例)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movq  rax, xmm0
    ret
brg_paddq_neg ENDP

; ---- ⑫ 负例 brg_psubq_neg(a, b): 66 0F FB C1 psubq — 同 ⑪ ----
brg_psubq_neg PROC
    movq  xmm0, rcx
    movq  xmm1, rdx
    call ?marker_begin@sdk@wvmp@@YAXXZ
    psubq xmm0, xmm1                ; 66 0F FB C1 (gate 负例)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movq  rax, xmm0
    ret
brg_psubq_neg ENDP

; ---- ⑬ 负例 brg_pmovmskb_neg(bits): 66 0F D7 C0 pmovmskb — D3 不本单 ----
brg_pmovmskb_neg PROC
    mov   rbx, rdx                  ; out (gate 负例整函数 native, rbx 直存)
    movq  xmm0, rcx
    call ?marker_begin@sdk@wvmp@@YAXXZ
    pmovmskb eax, xmm0              ; 66 0F D7 C0 (gate 负例)
    mov   [rbx], rax                ; 区内直存 (gate 函数 native 执行, 两跑一致)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ret
brg_pmovmskb_neg ENDP

; ---- ⑭ 负例 brg_pcmpeqd_neg(a, b): 66 0F 76 C1 pcmpeqd — D3 不本单 ----
brg_pcmpeqd_neg PROC
    movq  xmm0, rcx
    movq  xmm1, rdx
    call ?marker_begin@sdk@wvmp@@YAXXZ
    pcmpeqd xmm0, xmm1              ; 66 0F 76 C1 (gate 负例)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    movq  rax, xmm0
    ret
brg_pcmpeqd_neg ENDP

; ---- ⑮ 负例 brg_mmx_neg(a, b, out): NP 0F 6F/7F (mm 操作数) — D2
;      MMX/X87 状态域永久 gate (capstone 对 NP 0F 6F 报 id=MOVQ — 与 SSE
;      形态同 id 混入, mm 操作数判据唯一可靠闸, 单测钉死)。整函数 gate →
;      native 执行, 确定性输出 (mm 预载 rcx/rdx) → 可调用 byte-exact。
;      编码注记 (SDM): MMX movq mm, r/m64 = NP 0F 6F (mod=11 时 r/m 为
;      64 位 GP, rax..rdi 无需 REX); movq m64, mm = NP 0F 7F; MOVD 系
;      (0F 6E/7E) 为 32 位面。 ----
brg_mmx_neg PROC
    mov  rbx, r8
    ; ===== marker region begin (gate 负例区 — mm 操作数判据面) =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    movq mm0, rcx                   ; NP 0F 6F C1 (MMX movq mm0, r64, gate)
    movq mm1, rdx                   ; NP 0F 6F CA (gate)
    movq mm0, mm1                   ; NP 0F 6F C1 (MMX movq mm, mm — 判据面, gate)
    movq [rbx], mm0                 ; NP 0F 7F 03 (MMX movq m64, mm, gate)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====
    emms
    ret
brg_mmx_neg ENDP

_TEXT ENDS
END
