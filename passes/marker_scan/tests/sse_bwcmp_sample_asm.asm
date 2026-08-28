; MIT-376: SSE 浮点位运算 + 浮点比较 E2E 主样本的 MASM helper (MSVC x64 不支持
; inline asm, /Od 下高 level intrinsic 会**融合 load+op 为 MEM 形式** (xorps
; xmm, [mem] / ucomiss xmm, [mem]), 与派活单限定 REG-REG only 冲突)。沿用
; pitfall #35 MASM helper 做法: 由 .asm 直接 emit 真 REG-REG 字节, 链接进
; wvmp_sse_bwcmp_sample, 让 marker 区域内只含白名单指令。
;
; 5 个 helper 对应 5 形式 (capstone 实证字节):
;   bw_xorps  区域内 xorps  xmm0, xmm1  0F 57 C1  (bitwise xor, 全 128-bit)
;   bw_orps   区域内 orps   xmm0, xmm1  0F 56 C1  (bitwise or,  全 128-bit)
;   bw_andps  区域内 andps  xmm0, xmm1  0F 54 C1  (bitwise and, 全 128-bit)
;   ucmp_ss_* 区域内 ucomiss xmm0, xmm1 0F 2E C1  (标量单精度无序比较)
;   ucmp_sd_* 区域内 ucomisd xmm0, xmm1 66 0F 2E C1 (标量双精度无序比较)
;   (F3 0F 2E 编码不存在; comiss/comisd = 0F 2F 系不在本单范围)
;
; 比较类断言 (派活单 §C 6): ucomiss 后**紧跟 seta**, 且 seta/movzx/store 都在
; marker 区域**内** —— 虚拟化路径下 seta 由 VmOp::Setcc handler 执行, 读的是
; VmOp::Ucomiss handler 写的 VM flags 槽 (ctx+0x98, 位布局 ZF/CF/OF/SF/PF=
; bit0..4), 由此证明 flags 真参与运行时 (seta 放区域外 = 读宿主 EFLAGS, VM
; flags 槽空转时读到的只是 dispatch 循环残留, 断言失真)。
;
; 函数语义: 在 marker_begin / marker_end 调用之间包含真 SSE REG-REG 字节。
; marker_scan 识别 WVMPBEG1/WVMPEND1 magic 字节 + 紧随的 E8 call, 标定区域。
;
; Win64 ABI: 整型参数 rcx/rdx/r8/r9; 浮点参数 xmm0/xmm1; 返回值 eax/rax;
; callee-saved: rbx, rbp, rdi, rsi, r12-r15。
;
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), seta 结果必须在 marker_end 之前存 stack、之后还原
; (pitfall #36, 沿用 setcc_sample_asm.asm 的 [rsp+24] 模式)。

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXXZ (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; unsigned int bw_xorps(unsigned int a, unsigned int b):
;   Win64 ABI: a 在 ecx, b 在 edx, 返回值 eax。
;   区域外: movd GPR→xmm 装载 (66 0F 6E); 区域 = xorps + 4 NOP (凑齐 ≥5 字节
;   让 stub_link 写跳转); 区域外: movd xmm→GPR (66 0F 7E) 取出位图案。
bw_xorps PROC
    push rbx
    sub  rsp, 32

    movd xmm0, ecx                    ; xmm0 = a (位图案)
    movd xmm1, edx                    ; xmm1 = b (位图案)

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    xorps xmm0, xmm1                  ; 真 xorps REG-REG (0F 57 C1, mod=11)
    nop
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movd eax, xmm0                    ; 取出 128-bit 位运算结果的低 32 位
    add  rsp, 32
    pop  rbx
    ret
bw_xorps ENDP

; unsigned int bw_orps(unsigned int a, unsigned int b): 同 bw_xorps, 换 orps。
bw_orps PROC
    push rbx
    sub  rsp, 32

    movd xmm0, ecx
    movd xmm1, edx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    orps  xmm0, xmm1                  ; 真 orps REG-REG (0F 56 C1, mod=11)
    nop
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movd eax, xmm0
    add  rsp, 32
    pop  rbx
    ret
bw_orps ENDP

; unsigned int bw_andps(unsigned int a, unsigned int b): 同 bw_xorps, 换 andps。
bw_andps PROC
    push rbx
    sub  rsp, 32

    movd xmm0, ecx
    movd xmm1, edx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    andps xmm0, xmm1                  ; 真 andps REG-REG (0F 54 C1, mod=11)
    nop
    nop
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movd eax, xmm0
    add  rsp, 32
    pop  rbx
    ret
bw_andps ENDP

; int ucmp_ss_gt(float a, float b): 区域 = ucomiss + seta (a > b → 1)。
;   区域字节: ucomiss(3) + seta(3) + movzx(4) + mov(4) = 14 字节 (≥5)。
;   栈布局沿用 setcc_sample_asm.asm: push rbx + sub rsp,56, [rsp+24] 存 seta 结果。
ucmp_ss_gt PROC
    push rbx
    sub  rsp, 56

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    ucomiss xmm0, xmm1                ; 真 ucomiss REG-REG (0F 2E C1, mod=11)
    seta   al                         ; a > b (CF=0 且 ZF=0) → 1, 否则 0
    movzx rax, al
    mov   [rsp+24], rax               ; rax 在 marker_end 后会被 clobber (pitfall #36)
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov   rax, [rsp+24]               ; 还原 setcc 结果
    ; ===== marker region end =====

    add  rsp, 56
    pop  rbx
    ret
ucmp_ss_gt ENDP

; int ucmp_ss_lt(float a, float b): a < b (CF=1, ZF=0) → seta = 0。
ucmp_ss_lt PROC
    push rbx
    sub  rsp, 56

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    ucomiss xmm0, xmm1                ; 真 ucomiss REG-REG (0F 2E C1, mod=11)
    seta   al                         ; less → CF=1 → seta=0
    movzx rax, al
    mov   [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov   rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 56
    pop  rbx
    ret
ucmp_ss_lt ENDP

; int ucmp_ss_eq(float a, float b): a == b (CF=0, ZF=1) → seta = 0。
ucmp_ss_eq PROC
    push rbx
    sub  rsp, 56

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    ucomiss xmm0, xmm1                ; 真 ucomiss REG-REG (0F 2E C1, mod=11)
    seta   al                         ; equal → ZF=1 → seta=0
    movzx rax, al
    mov   [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov   rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 56
    pop  rbx
    ret
ucmp_ss_eq ENDP

; int ucmp_ss_nan(float a, float b): NaN → unordered (ZF=PF=CF=1) → seta = 0。
;   证明 handler 按 Intel SDM UCOMISS 真值表处理 unordered (CF=1 → seta=0)。
ucmp_ss_nan PROC
    push rbx
    sub  rsp, 56

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    ucomiss xmm0, xmm1                ; 真 ucomiss REG-REG (0F 2E C1, mod=11)
    seta   al                         ; unordered → CF=1 → seta=0
    movzx rax, al
    mov   [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov   rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 56
    pop  rbx
    ret
ucmp_ss_nan ENDP

; int ucmp_sd_gt(double a, double b): ucomisd (66 0F 2E C1) + seta, a > b → 1。
ucmp_sd_gt PROC
    push rbx
    sub  rsp, 56

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    ucomisd xmm0, xmm1                ; 真 ucomisd REG-REG (66 0F 2E C1, mod=11)
    seta   al                         ; a > b (CF=0 且 ZF=0) → 1
    movzx rax, al
    mov   [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov   rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 56
    pop  rbx
    ret
ucmp_sd_gt ENDP

; int ucmp_sd_lt(double a, double b): ucomisd + seta, a < b → 0。
ucmp_sd_lt PROC
    push rbx
    sub  rsp, 56

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    ucomisd xmm0, xmm1                ; 真 ucomisd REG-REG (66 0F 2E C1, mod=11)
    seta   al                         ; less → CF=1 → seta=0
    movzx rax, al
    mov   [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov   rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 56
    pop  rbx
    ret
ucmp_sd_lt ENDP

_TEXT ENDS

END
