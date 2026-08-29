; MIT-407 (MIT-D2): ExitNative 反例样本 — 超界形态 (oob) 的 MASM 宿主。
;
; wv_exit_oob_masm: 标记区域内含 `jmp wv_exit_far_helper`——直接跨函数
; 跳转。目标 = 另一函数的入口（其 .pdata RUNTIME_FUNCTION 条目在调用方
; EndAddress 之后/之前皆然）：
;   - helper 排在调用方之后 → target >= 本函数 .pdata end → 上界判定 gate；
;   - helper 排在调用方之前 → target < end_rva → 越区判定第一条件不满足 → gate。
; 两向都保守 gate，与修复前行为逐字节一致。MASM 直接 emit 保证形态确定性
; （/O2 尾调用是编译器行为，不保证；triage §4② 亦用显式构造）。
;
; 区域语义: 区域内仅 mov/shl/test/jnz/jmp 全白名单；jmp 目标为纯 native
; helper（无标记），gate 后原字节原样执行。
;
; Win64 ABI: rcx = n；jmp 时 rsp = entry rsp - 28h（prologue sub），与原生
; 执行路径完全一致（gate = 不虚拟化，行为逐位保持）。

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC
EXTERNDEF wv_exit_far_helper : PROC

_TEXT SEGMENT

wv_exit_oob_masm PROC
    sub  rsp, 28h                   ; shadow (marker stubs 写 [rsp+X])
    call ?marker_begin@sdk@wvmp@@YAXXZ
    ; ===== marker region begin =====
    mov  rax, rcx               ; r = n
    shl  rax, 1                 ; r = n * 2
    test rax, rax
    jnz  skip_zero
    mov  rax, 1                 ; r == 0 → 1
skip_zero:
    mov  rcx, rax               ; 尾调用参数 = r（Win64 第一参数寄存器）
    add  rsp, 28h               ; 还原调用帧（真尾调用形态, 编译器同款
                                ; `add rsp,X; jmp helper` 序列）
    jmp  wv_exit_far_helper     ; 跨函数直接 jmp → 超本函数 .pdata 界 → gate
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    ret
wv_exit_oob_masm ENDP

_TEXT ENDS
END
