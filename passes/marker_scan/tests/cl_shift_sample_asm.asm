; MIT-349: popcnt E2E sample 的 MASM helper (MSVC x64 不支持 inline asm,
; MSVC __popcnt 内部函数 / __popcnt64 / _mm_popcnt_u32 / _mm_popcnt_u64 在
; /Od 下 emit `popcnt reg, [rsp+disp]` MEM 形式 (MSVC 把参数先 spill 到栈,
; popcnt 读栈), 派活单限定不支持 MEM form. 此 helper 直接 emit `popcnt
; rax, rax` / `popcnt eax, eax` 真 REG-REG 字节, 链接进 wvmp_cl_shift_sample.
;
; MIT-353: 沿用 popcnt 派活单模式 + lzcnt/tzcnt BMI1 bit-scan 助手函数.
; 同样用 MASM (.asm) helper emit 真 lzcnt/tzcnt REG-REG 字节. MSVC 没有直接
; intrinsic emit lzcnt/tzcnt (MSVC 提供 _lzcnt_u32 / _tzcnt_u32 等, 但 /Od 下
; 也可能 emit MEM form, 沿用 popcnt 派活单限定风格). 此 helper 直接 emit
; `lzcnt rax, rcx` / `tzcnt rax, rcx` 真 REG-REG 字节 (Win64 ABI 参数 RCX,
; 返回 RAX — 沿用 MIT-349 🟡 1 项非阻断教训: MASM helper C++ wrapper 应通过
; 寄存器传值, 而不是栈 [rsp+disp] 读栈).
;
; 函数语义: 在 marker_begin / marker_end 调用之间包含真 lzcnt/tzcnt/popcnt
; REG-REG (REX.W = `48 F3 0F BD/BC C0` 类字节 / 无 REX.W = `F3 0F BD/BC C0`
; 类字节). marker_scan 识别 WVMPBEG1/WVMPEND1 magic 字节 + 紧随的 E8 call,
; 标定区域. lifter 把区域内 mov/lzcnt-or-tzcnt/mov 一一翻译为 VmOp::mov /
; VmOp::Lzcount-or-Tzcount / VmOp::mov, asmgen 的 build_lzcnt + build_tzcnt
; handler 真正被 exercise.
;
; 注: 此 helper 放在独立的 .popcnt 节 (与 .text 分离, 由 C++ #pragma
; section(".popcnt", read, execute) 声明), 避免被链接器放到 marker 函数
; 附近 (kStubWindow=64 字节) 引发 marker_scan 把 call popcnt32_fn 或
; popcnt64_fn / lzcnt32_fn / lzcnt64_fn / tzcnt32_fn / tzcnt64_fn 误识别为
; marker_begin 调用。.popcnt 节起始偏移对齐远超 kStubWindow=64 (vs .text 结
; 束 + 256 字节对齐), 与 marker 函数距离 > 64 字节 (pitfall #39 候选,
; MIT-349 实证)。每个函数之间用 64-NOP 填充进一步加大间距。

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXXZ (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; 起始对齐 + 大量 NOP, 强制 popcnt32_fn 在 binary 中的偏移远 (>64 字节)
; 远离任意 marker_begin/marker_end 函数, 避免 marker_scan 误识别。
    align 16
    REPEAT 64
    nop
    ENDM

; unsigned int popcnt32_fn(unsigned int x)
;   返回 popcount(x), x 在 ECX (Win64 ABI).
; 注意: 此函数本身不调用 marker_begin / marker_end — 标记由调用方
; popcnt_32 (C++ wrapper, 在 WVMP_BEGIN/END 区域内) 提供, 否则嵌套
; marker 会破坏 marker_scan 的区域识别。
popcnt32_fn PROC
    sub  rsp, 40

    mov  [rsp+32], ecx            ; save x (32-bit)

    mov  eax, [rsp+32]            ; a := x
    popcnt eax, eax                ; 真 popcnt 32-bit REG-REG (F3 0F B8 C0)

    add  rsp, 40
    ret
popcnt32_fn ENDP

    align 16
    REPEAT 64
    nop
    ENDM

; unsigned int popcnt64_fn(unsigned long long x)
;   返回 popcount(x), x 在 RCX (Win64 ABI).
popcnt64_fn PROC
    push rbx
    sub  rsp, 40

    mov  [rsp+40], rcx            ; save x (64-bit)

    mov  rax, [rsp+40]            ; a := x
    popcnt rax, rax                ; 真 popcnt 64-bit REG-REG (48 F3 0F B8 C0)

    add  rsp, 40
    pop  rbx
    ret
popcnt64_fn ENDP

    align 16
    REPEAT 64
    nop
    ENDM

; MIT-353: lzcnt 32-bit (F3 0F BD C0) BMI1 前导零计数助手函数.
;   unsigned int lzcnt32_fn(unsigned int x) -> count_leading_zeros(x)
;   x 在 ECX (Win64 ABI, 32 位参数), 结果放 EAX (32 位返回).
; 沿用 MIT-349 🟡 1 项非阻断教训: MASM helper C++ wrapper 应通过寄存器传值,
; 而不是栈 [rsp+0Ch] 读栈 — 直接 emit `lzcnt eax, ecx` 一次完成, 不 spill 到栈.
lzcnt32_fn PROC
    lzcnt eax, ecx                 ; 真 lzcnt 32-bit REG-REG (F3 0F BD C8 / C1, mod=11)
    ret
lzcnt32_fn ENDP

    align 16
    REPEAT 64
    nop
    ENDM

; MIT-353: lzcnt 64-bit (48 F3 0F BD C0) BMI1 前导零计数助手函数.
;   unsigned int lzcnt64_fn(unsigned long long x) -> count_leading_zeros(x)
;   x 在 RCX (Win64 ABI, 64 位参数), 结果放 EAX (32 位返回 — 64-bit lzcnt
;   结果 0..64 仍 32-bit 表示足够).
; 同样通过寄存器传值, 不 spill 到栈 (沿用 MIT-349 🟡 教训).
lzcnt64_fn PROC
    lzcnt rax, rcx                 ; 真 lzcnt 64-bit REG-REG (48 F3 0F BD C8 / C1, REX.W)
    ret
lzcnt64_fn ENDP

    align 16
    REPEAT 64
    nop
    ENDM

; MIT-353: tzcnt 32-bit (F3 0F BC C0) BMI1 末尾零计数助手函数.
;   unsigned int tzcnt32_fn(unsigned int x) -> count_trailing_zeros(x)
;   x 在 ECX (Win64 ABI, 32 位参数), 结果放 EAX (32 位返回).
; 同样通过寄存器传值, 不 spill 到栈 (沿用 MIT-349 🟡 教训).
tzcnt32_fn PROC
    tzcnt eax, ecx                 ; 真 tzcnt 32-bit REG-REG (F3 0F BC C8 / C1, mod=11)
    ret
tzcnt32_fn ENDP

    align 16
    REPEAT 64
    nop
    ENDM

; MIT-353: tzcnt 64-bit (48 F3 0F BC C0) BMI1 末尾零计数助手函数.
;   unsigned int tzcnt64_fn(unsigned long long x) -> count_trailing_zeros(x)
;   x 在 RCX (Win64 ABI, 64 位参数), 结果放 EAX (32 位返回 — 64-bit tzcnt
;   结果 0..64 仍 32-bit 表示足够).
; 同样通过寄存器传值, 不 spill 到栈 (沿用 MIT-349 🟡 教训).
tzcnt64_fn PROC
    tzcnt rax, rcx                 ; 真 tzcnt 64-bit REG-REG (48 F3 0F BC C8 / C1, REX.W)
    ret
tzcnt64_fn ENDP

    align 16
    REPEAT 64
    nop
    ENDM

_TEXT ENDS

END