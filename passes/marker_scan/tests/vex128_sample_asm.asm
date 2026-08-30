; MIT-426 (G6a): VEX.128 档A 主样本 MASM helper — 38 id V-pair 折叠的真字节
; 直写 (MSVC x64 不支持 inline asm; /arch:AVX 编译档不在本仓构建面, ml64
; 助记符直收 AVX 形式, 编码由 ml64 决定 — 关键字节形态经 capstone probe
; 对账, 见报告实汇编对照表)。
;
; 区域覆盖 (派活单 §B.5: 标量 FP 三态 + packed + 整数位运算 + reg-mem +
; d 独立 Mov 前置 + 负例区; 负例与正例函数级分离, 禁跨区污染):
;   三态① d==s1 直走:   vaddss xmm0,xmm0,xmm1 (C5 短前缀)
;   三态② d==s2 可交换:  vmulps xmm2,xmm0,xmm2 (packed 交换 s1 上位;
;                        **标量 d==s2 一律 gate**, 见 ⑳/D2)
;   三态③ d 独立前置:    vaddps/vsubps/vmulss/vandnps xmm2,xmm0,xmm1
;                        (前置 Op::Movaps(dst←s1) 16B 拷贝 + 2-op 载体;
;                        标量形态断言 "dst 高位 ← s1 高位" 语义)
;   D4 纯拷贝直折:       vmovaps xmm0,xmm1 (2-op, 单条, 不进 binop 框架)
;   408 mem 通路:        vmovups load / vaddsd mem 源 (VEX 编码)
;   整数位运算 (425 镜像): vpxor 清零惯用法 (d==s1==s2)
;   flags 通路:          vucomiss + seta (区域内真比较结果读回)
;   D5 C4 全前缀:        db 直写 C4 E1 7B 58 C1 (vaddsd xmm0,xmm0,xmm1;
;                        ml64 对 0F 映射 WIG 形式恒产 C5 短前缀, C4 形态
;                        只能 db 直写 — 与 419 lock mov db 先例同纪律)
;   负例区 (每函数一条, C1 gate 整函数原生, 可调用, 行为 byte-exact):
;     ymm 同 mnemonic (B.4 位宽闸) / FMA (双舍入红线) / rorx (VEX-GP,
;     G8) / vzeroupper (档B ABI) / vpaddd (G1c 镜像) / vsubsd d==s2
;     (非交换) / vmulsd d==s2 (标量可交换族 — 高位语义不相容) /
;     vmovsd 插入 d≠s1 (§F.4 "假 Mov")
;
; Win64 ABI: 整型参数 rcx/rdx/r8; 返回值 rax/xmm0。
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), 位图案结果一律 region 后 movq rax, xmm0 提取。

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXXZ (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

; C 链接全局 (vex128_sample_main.cpp extern "C"): MASM 直引 → rip-relative
EXTERNDEF g_vex_d  : QWORD     ; double mem 源 (vaddsd mem)
EXTERNDEF g_vex_ps : XMMWORD   ; 4xf32 mem 源 (vmovups load)

_TEXT SEGMENT

; ---- ① vex_addss_d_s1(u32 a, u32 b): 三态① d==s1 直走 ----
; 1.5f + 2.25f = 3.75f (位图案 0x3FC00000 + 0x40100000 → 0x40700000)
vex_addss_d_s1 PROC
    movd xmm0, ecx                   ; 区外: a (float 位)
    movd xmm1, edx                   ; 区外: b

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vaddss xmm0, xmm0, xmm1          ; C5 FA 58 C1 (d==s1)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movd eax, xmm0                   ; 低 32 位 (区外)
    ret
vex_addss_d_s1 ENDP

; ---- ② vex_vmulps_d_s2(u64 s1, u64 d): 三态② d==s2 可交换 (packed) ----
; lanes [2.0f,2.0f] × [3.0f,1.5f] = [6.0f,3.0f]
; (低 64: 0x4040000040C00000; packed 全 128-bit 语义 — swap 折与 native
; VEX 逐位等价; **标量 d==s2 不在此列**, gate 见 ⑳)
vex_vmulps_d_s2 PROC
    movq xmm0, rcx                   ; 区外: s1
    movq xmm2, rdx                   ; 区外: dst (s2)

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vmulps xmm2, xmm0, xmm2          ; d==s2 (packed) → 交换折 (xmm2,xmm0)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm2
    ret
vex_vmulps_d_s2 ENDP

; ---- ③ vex_addps_dindep(u64 s1, u64 s2): 三态③ d 独立 (packed) ----
; lanes [2.0f,2.0f] + [3.0f,1.5f] = [5.0f,3.5f]
; (低 64: 0x4000000040000000 + 0x4040004040000040 → 0x4060000040A00000)
vex_addps_dindep PROC
    movq xmm0, rcx                   ; 区外: s1
    movq xmm1, rdx                   ; 区外: s2
    xor  ecx, ecx
    movq xmm2, rcx                   ; 区外: dst 预置 0 (断言 pre-Mov 覆盖)

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vaddps xmm2, xmm0, xmm1          ; d 独立 → 前置 Movaps(xmm2←xmm0)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm2
    ret
vex_addps_dindep ENDP

; ---- ④ vex_subps_dindep(u64 s1, u64 s2): 非交换族 d 独立 (同样前置折) ----
; lanes [3.0f,1.5f] - [2.0f,2.0f] = [1.0f,-0.5f]
; (低 64: 0x4040004040000040 - 0x4000000040000000 → 0xBF0000003F800000)
vex_subps_dindep PROC
    movq xmm0, rcx                   ; 区外: s1
    movq xmm1, rdx                   ; 区外: s2
    xor  ecx, ecx
    movq xmm2, rcx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vsubps xmm2, xmm0, xmm1          ; 非交换 d 独立 → pre-Mov + 2-op
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm2
    ret
vex_subps_dindep ENDP

; ---- ⑤ vex_vmulss_dindep(u64 s1, u64 s2): 标量 d 独立 (高位语义断言面) ----
; 2.0f × 3.0f = 6.0f; 标量 VEX "dst 高位 ← s1 高位" — 低 64 断言乘积,
; 高位语义由影子样本全槽读回钉死。
vex_vmulss_dindep PROC
    movq xmm0, rcx
    movq xmm1, rdx
    xor  ecx, ecx
    movq xmm2, rcx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vmulss xmm2, xmm0, xmm1          ; d 独立 → pre-Mov(xmm2←xmm0) + mulss
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm2
    ret
vex_vmulss_dindep ENDP

; ---- ⑥ vex_vandnps_dindep(u64 s1, u64 s2): andn d 独立 (非交换可折形态) ----
; ~0x0F0F0F0F0F0F0F0F & 0xFFFFFFFFFFFFFFFF → 低 64 = 0xF0F0F0F0F0F0F0F0
vex_vandnps_dindep PROC
    movq xmm0, rcx
    movq xmm1, rdx
    xor  ecx, ecx
    movq xmm2, rcx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vandnps xmm2, xmm0, xmm1         ; dst = ~s1 & s2 → pre-Mov + 2-op
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm2
    ret
vex_vandnps_dindep ENDP

; ---- ⑦ vex_vmovaps_copy(u64 a, u64 b): D4 纯拷贝 2-op 直折单条 ----
; 返回 b 的位图案 (xmm0 ← xmm1 全 128 位拷贝; 低 64 可观察)。
vex_vmovaps_copy PROC
    movq xmm0, rcx                   ; 区外: a (dst 初值, 应被覆盖)
    movq xmm1, rdx                   ; 区外: b

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vmovaps xmm0, xmm1               ; 2-op 纯拷贝 (op_count=2, 单条)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
vex_vmovaps_copy ENDP

; ---- ⑧ vex_vmovups_load(): 408 mem 通路 VEX 编码 load ----
; 返回 g_vex_ps 低 64 位。
vex_vmovups_load PROC

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vmovups xmm0, xmmword ptr [g_vex_ps]  ; 2-op mem load (rip)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
vex_vmovups_load ENDP

; ---- ⑨ vex_vaddsd_mem(u64 a): d==s1 + mem 源 (VEX 编码) ----
; a + g_vex_d(2.5); 1.5 + 2.5 = 4.0 (0x4010000000000000)
vex_vaddsd_mem PROC
    movq xmm0, rcx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vaddsd xmm0, xmm0, qword ptr [g_vex_d]  ; d==s1 直走 + mem 源折条
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
vex_vaddsd_mem ENDP

; ---- ⑩ vex_vpxor_zero(): 整数清零惯用法 (d==s1==s2, python314 主形态) ----
vex_vpxor_zero PROC
    movq xmm2, rcx                   ; 区外: dst 预置非零

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vpxor  xmm2, xmm2, xmm2          ; d==s1==s2 → 直走 2-op (xmm2, xmm2)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm2                   ; = 0
    ret
vex_vpxor_zero ENDP

; ---- ⑪ vex_vucomiss_seta(u32 a, u32 b): flags 通路 (比较 + setcc 读回) ----
; a > b (无序不成立) → al=1; 3.0f > 2.0f → 1
vex_vucomiss_seta PROC
    movd xmm0, ecx
    movd xmm1, edx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vucomiss xmm0, xmm1              ; 2-op 比较直通 (flags 真写)
    seta  al                         ; CF=0 且 ZF=0 (above) → 1
    movzx eax, al
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    ret
vex_vucomiss_seta ENDP

; ---- ⑫ vex_c4_enc_addsd(u64 a, u64 b): D5 C4 全前缀形态 (db 直写) ----
; db C4 E1 7B 58 C1 = vaddsd xmm0, xmm0, xmm1 (ml64 对 0F 映射 WIG 恒产
; C5 短前缀; C4 全前缀只能 db 直写 — 419 lock mov db 先例同纪律)。
; 6.0 + 2.5 = 15.0。
vex_c4_enc_addsd PROC
    movq xmm0, rcx
    movq xmm1, rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    db 0C4h, 0E1h, 07Bh, 058h, 0C1h  ; vaddsd xmm0, xmm0, xmm1 (C4 全前缀)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
vex_c4_enc_addsd ENDP

; ==================== 负例区 (函数级分离, 各自整函数 gate) ====================

; ---- ⑬ vex_ymm_neg(u64 a, u64 b): ymm 同 mnemonic — B.4 位宽闸钉死 ----
; vaddps ymm 与 xmm 同 INS id (X86_INS_VADDPS), 位宽闸按 32B 拒 → gate;
; 原生执行 [2.0f]+[3.0f] = [5.0f] (低 64 = 0x40A0000040A00000)。
vex_ymm_neg PROC
    movq xmm0, rcx
    movq xmm1, rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vaddps ymm0, ymm0, ymm1          ; ymm 形态 → 位宽闸 gate (原生执行)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
vex_ymm_neg ENDP

; ---- ⑭ vex_fma_neg(u64 a, u64 b, u64 c): FMA 双舍入红线 (triage §6.5) ----
; vfmadd213sd xmm1, xmm2, xmm0: xmm1 = xmm2*xmm1 + xmm0 = 1.0*2.5 + 6.0 = 8.5
vex_fma_neg PROC
    movq xmm0, rcx
    movq xmm1, rdx
    movq xmm2, r8

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vfmadd213sd xmm1, xmm2, xmm0     ; FMA → gate (永不拆 mul+add)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm1
    ret
vex_fma_neg ENDP

; ---- ⑮ vex_rorx_neg(u32 x): VEX-GP (BMI) — G8 独立缺口, 不在 SIMD 档A ----
; 0x80000001 ror 3 = 0x30000000
vex_rorx_neg PROC

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    rorx  eax, ecx, 3                ; VEX-GP → gate (原生执行)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    ret
vex_rorx_neg ENDP

; ---- ⑯ vex_vzeroupper_neg(): 档B ABI 面 (upper-half dirty) → gate ----
vex_vzeroupper_neg PROC

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vzeroupper                       ; gate (原生执行, 行为等价 no-op)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    mov eax, 7
    ret
vex_vzeroupper_neg ENDP

; ---- ⑰ vex_vpaddd_neg(u64 a, u64 b): SSE2 整数加法族 (G1c 镜像) → gate ----
; 0x1 + 0x2 = 0x3
vex_vpaddd_neg PROC
    movq xmm0, rcx
    movq xmm1, rdx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vpaddd xmm0, xmm0, xmm1          ; V-对随本体 paddq gate (原生执行)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm0
    ret
vex_vpaddd_neg ENDP

; ---- ⑱ vex_noncomm_ds2_neg(u64 s1, u64 d): D2 gate 裁决钉死 ----
; vsubsd xmm2, xmm0, xmm2 (非交换 d==s2): 6.0 - 2.0 = 4.0
; (0x4018000000000000 - 0x4000000000000000 → 0x4010000000000000)
vex_noncomm_ds2_neg PROC
    movq xmm0, rcx                   ; s1 = 6.0
    movq xmm2, r8                    ; dst = 2.0

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vsubsd xmm2, xmm0, xmm2          ; 非交换 d==s2 → D2 gate (原生执行)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm2
    ret
vex_noncomm_ds2_neg ENDP

; ---- ⑲ vex_movsd_insert_neg(u64 s1, u64 s2): §F.4 "假 Mov" 插入 gate ----
; vmovsd xmm2, xmm0, xmm1 (d≠s1): 低 64 ← s2 (2.5), 高 64 ← s1 高位
; (d 独立插入语义无 2-op 表达 → gate, 原生执行)。
vex_movsd_insert_neg PROC
    movq xmm0, rcx                   ; s1
    movq xmm1, rdx                   ; s2

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vmovsd xmm2, xmm0, xmm1          ; 插入 d≠s1 → gate (原生执行)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm2                   ; 低 64 = s2 = 2.5 位图案
    ret
vex_movsd_insert_neg ENDP

; ---- ⑳ vex_mulsd_ds2_neg(u64 s1, u64 d): 标量 d==s2 可交换族 gate ----
; vmulsd xmm1, xmm0, xmm1 (标量 d==s2): 6.0 × 2.5 = 15.0
; (标量 VEX "dst 高位 ← s1 高位" 无 2-op 表达序列 → D2 gate, 原生执行;
;  与 packed 交换 ② 对照 — 同为可交换, 位宽语义分叉)
vex_mulsd_ds2_neg PROC
    movq xmm0, rcx                   ; s1 = 6.0
    movq xmm1, rdx                   ; dst = 2.5

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    vmulsd xmm1, xmm0, xmm1          ; 标量 d==s2 → D2 gate (原生执行)
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====

    movq rax, xmm1
    ret
vex_mulsd_ds2_neg ENDP

_TEXT ENDS
END
