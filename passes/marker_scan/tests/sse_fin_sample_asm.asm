; MIT-425 (G1b): SSE 收官包主样本 MASM helper — mul 族 + andnps/andnpd +
; SSE2 整数位运算族 (pand/por/pxor/pandn) 的真字节直写 (MSVC x64 不支持
; inline asm)。
;
; 形态依据 (#33 实测, cl v145 /Od /arch:SSE2 /FAcs probe, 2026-08-30):
;   - mulsd/mulss: C++ 天然产物 (g_a *= g_b → movsd+mulsd [rip]+movsd),
;     由主样本 C++ 区域覆盖; REG-REG 形式与 mulps/mulpd intrinsic 形式
;     由本文件直写 (0F 59 系四编码)。
;   - andnps: _mm_andnot_si128/_mm_andnot_pd 的 MSVC 真产物 (0F 55) —
;     424 §B.1 "pand/andn legacy 直产" 先验被实测推翻: v145 对整数/double
;     andnot intrinsic 均直产 andnps (ps 编码); 真 andnpd/pandn 66 字节
;     由本文件直写 (66 0F 55 / 66 0F DF)。
;   - pand/por/pxor: MSVC 对 _mm_and_si128 直产 andps (ps 互换), pand 真
;     66 字节 (66 0F DB/EB/EF) 由本文件直写 (折叠 Andps/Orps/Xorps,
;     411 pd 折叠 ps 先例的整数扩展)。
;   - 负例 paddq (66 0F D4): R2 档② 砍面留 G1c (跳表预算 95 顶格) →
;     lifter unsupported → C1 gate 兜底, 可调用, 行为 byte-exact。
;
; Win64 ABI: 整型参数 rcx/rdx; 浮点参数 xmm0/xmm1; 返回值 rax/xmm0。
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), 位图案结果一律 region 后 movq rax, xmm0 提取。

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXXZ (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

; C 链接全局 (sse_fin_sample_main.cpp extern "C"): MASM 直引 → rip-relative
EXTERNDEF g_fin_d  : QWORD     ; double mem 源 (mulsd mem)
EXTERNDEF g_fin_ps : XMMWORD   ; 4xf32 mem 源 (mulps mem)
EXTERNDEF g_fin_pi : XMMWORD   ; __m128i 位图案 mem 源 (pand mem)

_TEXT SEGMENT

; ---- ① fin_mulss_rr(u32 a, u32 b): F3 0F 59 C1 mulss xmm0, xmm1 ----
; float 位图案入参 (movd 区外装入), 返回低 32 位乘积位图案。
fin_mulss_rr PROC
    movd xmm0, ecx                   ; 区外: a (float 位)
    movd xmm1, edx                   ; 区外: b

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mulss xmm0, xmm1                 ; F3 0F 59 C1 (scalar single)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movd eax, xmm0                   ; 低 32 位 (区外)
    ret
fin_mulss_rr ENDP

; ---- ② fin_mulsd_rr(u64 a, u64 b): F2 0F 59 C1 mulsd xmm0, xmm1 ----
fin_mulsd_rr PROC
    movq xmm0, rcx
    movq xmm1, rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mulsd xmm0, xmm1                 ; F2 0F 59 C1 (scalar double)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
fin_mulsd_rr ENDP

; ---- ③ fin_mulsd_mem(u64 a): F2 0F 59 05 rel32 mulsd xmm0, [g_fin_d] ----
; rip mem 源 (408 通路; C++ 天然 mulsd 同形态, 此处 MASM 钉死字节)。
fin_mulsd_mem PROC
    movq xmm0, rcx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mulsd xmm0, qword ptr [g_fin_d]  ; F2 0F 59 05 rel32 (rip mem 源)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
fin_mulsd_mem ENDP

; ---- ④ fin_mulps_rr(u64 a, u64 b): 0F 59 C1 mulps xmm0, xmm1 ----
; 全 128-bit packed single (4 lane 并行), 返回低 64 位 (lane0+lane1)。
fin_mulps_rr PROC
    movq xmm0, rcx
    movq xmm1, rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mulps xmm0, xmm1                 ; 0F 59 C1 (packed single)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
fin_mulps_rr ENDP

; ---- ⑤ fin_mulpd_rr(u64 a, u64 b): 66 0F 59 C1 mulpd xmm0, xmm1 ----
fin_mulpd_rr PROC
    movq xmm0, rcx
    movq xmm1, rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mulpd xmm0, xmm1                 ; 66 0F 59 C1 (packed double)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
fin_mulpd_rr ENDP

; ---- ⑥ fin_mulps_mem(u64 a): 0F 59 05 rel32 mulps xmm0, [g_fin_ps] ----
fin_mulps_mem PROC
    movq xmm0, rcx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mulps xmm0, xmmword ptr [g_fin_ps]  ; 0F 59 05 rel32 (rip mem 源)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
fin_mulps_mem ENDP

; ---- ⑦ fin_andnps_rr(u64 a, u64 b): 0F 55 C1 andnps xmm0, xmm1 ----
; dst = ~dst & src (SDM: NOT 作用于第一操作数)。
; 手算基线 (411 主样本 andnps_neg 同款): a=0x0F0F0F0F0F0F0F0F,
; b=0xFFFFFFFFFFFFFFFF → 低 64 = 0xF0F0F0F0F0F0F0F0。
fin_andnps_rr PROC
    movq xmm0, rcx
    movq xmm1, rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    andnps xmm0, xmm1                ; 0F 55 C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
fin_andnps_rr ENDP

; ---- ⑧ fin_andnpd_rr(u64 a, u64 b): 66 0F 55 C1 andnpd ----
; 与 andnps 逐位同语义 → 折叠 Andnps (411 ps/pd 互认先验)。
fin_andnpd_rr PROC
    movq xmm0, rcx
    movq xmm1, rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    andnpd xmm0, xmm1                ; 66 0F 55 C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
fin_andnpd_rr ENDP

; ---- ⑨ fin_pandn_rr(u64 a, u64 b): 66 0F DF C1 pandn ----
; SSE2 整数 andn — 与 andnps 逐位同语义 → 折叠 Andnps (R2 档①)。
fin_pandn_rr PROC
    movq xmm0, rcx
    movq xmm1, rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    pandn  xmm0, xmm1                ; 66 0F DF C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
fin_pandn_rr ENDP

; ---- ⑩ fin_pand_rr(u64 a, u64 b): 66 0F DB C1 pand ----
; 折叠 Andps (位运算逐位同语义, op 类型不解释)。
fin_pand_rr PROC
    movq xmm0, rcx
    movq xmm1, rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    pand   xmm0, xmm1                ; 66 0F DB C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
fin_pand_rr ENDP

; ---- ⑪ fin_por_rr(u64 a, u64 b): 66 0F EB C1 por → 折叠 Orps ----
fin_por_rr PROC
    movq xmm0, rcx
    movq xmm1, rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    por    xmm0, xmm1                ; 66 0F EB C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
fin_por_rr ENDP

; ---- ⑫ fin_pxor_rr(u64 a, u64 b): 66 0F EF C1 pxor → 折叠 Xorps ----
fin_pxor_rr PROC
    movq xmm0, rcx
    movq xmm1, rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    pxor   xmm0, xmm1                ; 66 0F EF C1
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
fin_pxor_rr ENDP

; ---- ⑬ fin_pand_mem(u64 a): 66 0F DB 05 rel32 pand xmm0, [g_fin_pi] ----
; pand rip mem 源 (408 通道; g_fin_pi = XMMWORD 整数位图案)。
fin_pand_mem PROC
    movq xmm0, rcx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    pand   xmm0, xmmword ptr [g_fin_pi]  ; 66 0F DB 05 rel32
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
fin_pand_mem ENDP

; ---- ⑭ 负例 fin_paddq_neg(u64 a, u64 b): 66 0F D4 C1 paddq ----
; R2 档② 砍面留 G1c (跳表预算 95 顶格, 派活单 §B.3/D1) → lifter
; unsupported → C1 gate 整函数保持原生, 行为 byte-exact (可调用)。
fin_paddq_neg PROC
    movq xmm0, rcx
    movq xmm1, rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    paddq  xmm0, xmm1                ; 66 0F D4 C1 (gate 负例)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
fin_paddq_neg ENDP

_TEXT ENDS
END
