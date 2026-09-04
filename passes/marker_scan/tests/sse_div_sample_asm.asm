; MIT-374: SSE 浮点除 E2E sample 的 MASM helper (MSVC x64 不支持 inline asm,
; MSVC /Od 对 _mm_div_ss/_mm_div_ps/_mm_div_pd 内部函数会**融合 load+div 为
; MEM 形式 divss xmm, [mem] / divps xmm, [mem] / divpd xmm, [mem]**（与
; 派活单限定 REG-REG only 冲突）。MASM helper 直接 emit 真 REG-REG SSE 除
; 字节 (F3 0F 5E / 0F 5E / 66 0F 5E mod=11), 链接进 wvmp_sse_div_sample,
; 让 marker 区域**只含白名单** SSE 除字节 (load/store movss/movups 在区域
; 外完成, 与 sse_sub_sample_asm.asm 的"区域外 load/区域中运算"模式一致)。
;
; 函数语义: 在 marker_begin / marker_end 调用之间包含**真 SSE 浮点除 REG-REG**
; (`F3 0F 5E+r` / `0F 5E+r` / `66 0F 5E+r` 字节, mod=11)。marker_scan 识别
; WVMPBEG1/WVMPEND1 magic 字节 + 紧随的 E8 call, 标定区域. lifter 把区域内
; xmm 除一一翻译为 VmOp::Divss/Divps/Divpd, asmgen 的
; build_divss/build_divps/build_divpd handler 真正被 exercise。
;
; Win64 ABI: 整型参数 rcx/rdx/r8/r9; 浮点参数 xmm0/xmm1/xmm2/xmm3; 返回值
; xmm0. callee-saved: rbx, rbp, rdi, rsi, r12-r15。
;
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), 必须在 call 前存到 stack, call 后还原 ( pitfall #36)。

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXPEBD@Z (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; float sse_divss(float a, float b):
;   Win64 ABI: 浮点参数 a 在 xmm0 低 32 位, b 在 xmm1 低 32 位, 返回值在 xmm0。
;   marker 区域**只含** divss + 4 NOP 填充 (凑齐 5+ 字节让 stub_link 写入跳转);
;   load/store 在区域外。
sse_divss PROC
    push rbx
    sub  rsp, 32

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    divss xmm0, xmm1                 ; 真 divss REG-REG (F3 0F 5E C1, mod=11)
    nop
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    add  rsp, 32
    pop  rbx
    ret
sse_divss ENDP

; void sse_divps(const float* a, const float* b, float* out):
;   Win64 ABI: rcx=a, rdx=b, r8=out.
;   区域外: load a → xmm0, load b → xmm1.
;   marker 区域**只含** divps + 6 NOP 填充 (凑齐 5+ 字节).
;   区域外: store xmm0 → [r8].
sse_divps PROC
    push rbx
    sub  rsp, 48

    ; 区域外: load (movups 不在 marker 区域, lifter 不需支持)
    movups xmm0, xmmword ptr [rcx]    ; xmm0 = packed a
    movups xmm1, xmmword ptr [rdx]    ; xmm1 = packed b

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    divps  xmm0, xmm1                 ; 真 divps REG-REG (0F 5E C1, mod=11)
    nop
    nop
    nop
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movups xmmword ptr [r8], xmm0     ; 区域外: store result

    add  rsp, 48
    pop  rbx
    ret
sse_divps ENDP

; void sse_divpd(const double* a, const double* b, double* out):
;   Win64 ABI: rcx=a, rdx=b, r8=out.
;   区域外: load a → xmm0, load b → xmm1.
;   marker 区域**只含** divpd + 6 NOP 填充 (凑齐 5+ 字节).
;   区域外: store xmm0 → [r8].
sse_divpd PROC
    push rbx
    sub  rsp, 48

    ; 区域外: load
    movups xmm0, xmmword ptr [rcx]    ; xmm0 = packed a (2xf64)
    movups xmm1, xmmword ptr [rdx]    ; xmm1 = packed b (2xf64)

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    divpd  xmm0, xmm1                 ; 真 divpd REG-REG (66 0F 5E C1, mod=11)
    nop
    nop
    nop
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movups xmmword ptr [r8], xmm0     ; 区域外: store result

    add  rsp, 48
    pop  rbx
    ret
sse_divpd ENDP

_TEXT ENDS

END
