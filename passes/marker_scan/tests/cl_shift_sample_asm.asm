; MIT-349: popcnt E2E sample 的 MASM helper (MSVC x64 不支持 inline asm,
; MSVC __popcnt 内部函数 / __popcnt64 / _mm_popcnt_u32 / _mm_popcnt_u64 在
; /Od 下 emit `popcnt reg, [rsp+disp]` MEM 形式 (MSVC 把参数先 spill 到栈,
; popcnt 读栈), 派活单限定不支持 MEM form. 此 helper 直接 emit `popcnt
; rax, rax` / `popcnt eax, eax` 真 REG-REG 字节, 链接进 wvmp_cl_shift_sample.
;
; 函数语义: 在 marker_begin / marker_end 调用之间包含真 popcnt REG-REG
; (REX.W = `48 F3 0F B8 C0` 类字节 / 无 REX.W = `F3 0F B8 C0` 类字节).
; marker_scan 识别 WVMPBEG1/WVMPEND1 magic 字节 + 紧随的 E8 call, 标定区域.
; lifter 把区域内 mov/popcnt/mov 一一翻译为 VmOp::mov / VmOp::Popcnt /
; VmOp::mov, asmgen 的 build_popcnt handler 真正被 exercise.
;
; 注: 此 helper 放在独立的 .popcnt 节 (与 .text 分离, 由 C++ #pragma
; section(".popcnt", read, execute) 声明), 避免被链接器放到 marker 函数
; 附近 (kStubWindow=64 字节) 引发 marker_scan 把 call popcnt32_fn 或
; popcnt64_fn 误识别为 marker_begin 调用。.popcnt 节起始偏移对齐远超
; kStubWindow=64 (vs .text 结束 + 256 字节对齐), 与 marker 函数距离 > 64 字节。

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

_TEXT ENDS

END