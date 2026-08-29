; MIT-419 (G4): lock 前缀原子族 strip-and-execute E2E 样本 (MASM 宿主)。
; 真字节直写 — MSVC x64 不支持 inline asm; Interlocked* 的 C++ 形态由
; main 侧 (wvmp_atomic_ops_sample_main.cpp) 编译器真产物覆盖, 本文件补
; 编译器不产/难产的全谱形态 (派活单 §B.5 ②③④):
;
; 正样本 7 个 (全部 REQUIRE_REAL 真虚拟化):
;   ① wv_at_xadd32      —— lock xadd dword ptr [rcx], eax (InterlockedAdd
;                          真产物形态), 返回旧值
;   ② wv_at_xadd64      —— lock xadd qword ptr [rcx], rax (REX.W)
;   ③ wv_at_bts_imm     —— lock bts dword ptr [rcx], 3 (imm8 形式,
;                          InterlockedBitTestAndSet 真产物形态), 返回旧位
;   ④ wv_at_btr_imm     —— lock btr dword ptr [rcx], 3 (imm8 形式)
;   ⑤ wv_at_btc_reg     —— lock btc dword ptr [rcx], edx (reg 位号形式)
;   ⑥ wv_at_xchg_mem    —— xchg dword ptr [rcx], eax (**裸 xchg 无 F0**,
;                          InterlockedExchange 真产物形态 — xchg 访存隐式锁)
;   ⑦ wv_at_cmpxchg_rip —— lock cmpxchg qword ptr [g_at_cmpx], rcx
;                          (**rip-relative 目标**, 64 位全局 Interlocked* 真
;                          产物形态) + cmpxchg 后 je 惯用法 (B.5 ③: ZF 读回
;                          flags 探针 — Cmpxchg handler flags_tail 写槽 →
;                          Jcc cond_eval 读槽, 非空转)
; 负样本 2 个 (照旧 C1 gate, **禁入可执行路径** — 本机实测 lock mov/lock
; nop 原生执行即 #UD 崩溃, 415 同款教训: 仅断言 protect 日志 gate note,
; main 侧只取函数地址不调用):
;   ⑧ wv_at_neg_lock_mov —— db F0 89 01 (lock mov [rcx], eax; ml64 拒汇编
;                           "instruction prefix not allowed", 416 同族
;                           db 直发兜底) — capstone 拒解码 → skipped → gate
;   ⑨ wv_at_neg_lock_nop —— db F0 90 (lock nop; 同上 db 直发) — gate
;
; 区域语义: 每函数区域 = [call marker_begin 之后, call marker_end 处); 结果
; spill 到 [rsp+24] (marker_end clobber rax, pitfall #36); 无 rsp 调整
; (entry rsp 恒等, Halt 恢复契约)。

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC
EXTERNDEF g_at_cmpx : QWORD

_TEXT SEGMENT

; ============ ① lock xadd dword (InterlockedAdd 形态) ============
; u32 wv_at_xadd32(long* p, long v) → rax = 旧 [p]
wv_at_xadd32 PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mov  eax, edx                ; v
    lock xadd dword ptr [rcx], eax
    mov  [rsp+24], eax           ; spill 旧值 (marker_end clobber rax)
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  eax, [rsp+24]
    add  rsp, 56
    ret
wv_at_xadd32 ENDP

; ============ ② lock xadd qword (REX.W) ============
; u64 wv_at_xadd64(long long* p, long long v) → rax = 旧 [p]
wv_at_xadd64 PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mov  rax, rdx
    lock xadd qword ptr [rcx], rax
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    ret
wv_at_xadd64 ENDP

; ============ ③ lock bts imm8 (InterlockedBitTestAndSet 形态) ============
; u32 wv_at_bts_imm(long* p) → rax = 旧位 (CF 读回)
wv_at_bts_imm PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXXZ
    lock bts dword ptr [rcx], 3
    setc al
    movzx eax, al
    mov  [rsp+24], eax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  eax, [rsp+24]
    add  rsp, 56
    ret
wv_at_bts_imm ENDP

; ============ ④ lock btr imm8 ============
; u32 wv_at_btr_imm(long* p) → rax = 旧位
wv_at_btr_imm PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXXZ
    lock btr dword ptr [rcx], 3
    setc al
    movzx eax, al
    mov  [rsp+24], eax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  eax, [rsp+24]
    add  rsp, 56
    ret
wv_at_btr_imm ENDP

; ============ ⑤ lock btc reg 位号 ============
; u32 wv_at_btc_reg(long* p, long bit) → rax = 旧位
wv_at_btc_reg PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXXZ
    lock btc dword ptr [rcx], edx
    setc al
    movzx eax, al
    mov  [rsp+24], eax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  eax, [rsp+24]
    add  rsp, 56
    ret
wv_at_btc_reg ENDP

; ============ ⑥ 裸 xchg [m], r (InterlockedExchange 形态, 无 F0) ============
; u32 wv_at_xchg_mem(long* p, long v) → rax = 旧 [p]
wv_at_xchg_mem PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mov  eax, edx
    xchg dword ptr [rcx], eax
    mov  [rsp+24], eax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  eax, [rsp+24]
    add  rsp, 56
    ret
wv_at_xchg_mem ENDP

; ============ ⑦ lock cmpxchg rip 目标 + je 惯用法 (ZF 读回) ============
; u64 wv_at_cmpxchg_rip(long long old, long long new)
;   若 [g_at_cmpx] == old → [g_at_cmpx] = new, 返回 1 (je 命中)
;   否则                  返回 0
; [g_at_cmpx] 是 C++ 侧 extern "C" 全局 — MASM 对 [符号] 自动编 rip-relative
; (x64 无绝对寻址, div_sample 同款先例; 64 位全局 Interlocked* 真产物形态
; 实证: lock cmpxchg qword ptr [rip+disp], rcx)。
wv_at_cmpxchg_rip PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mov  rax, rcx                ; old → accumulator (cmpxchg 隐式 RAX)
    mov  rcx, rdx                ; new
    lock cmpxchg qword ptr [g_at_cmpx], rcx
    je   hit_1                   ; ZF=1 → 命中 (cmpxchg 写 flags 槽 → je 读回)
    mov  eax, 0
    jmp  done_1
hit_1:
    mov  eax, 1
done_1:
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    ret
wv_at_cmpxchg_rip ENDP

; ============ ⑧ 负例: lock mov (不可锁助记符) ============
; 禁入可执行路径 (原生 #UD): main 只取地址不调用; 断言 protect 日志 gate。
wv_at_neg_lock_mov PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXXZ
    db   0F0h, 089h, 001h        ; lock mov [rcx], eax — ml64 A2068 拒汇编,
                                 ; db 直发 (416 同族先例); capstone 拒解码
    call ?marker_end@sdk@wvmp@@YAXXZ
    add  rsp, 56
    ret
wv_at_neg_lock_mov ENDP

; ============ ⑨ 负例: lock nop ============
; 同上: 禁入可执行路径 (原生 #UD); 断言 protect 日志 gate。
wv_at_neg_lock_nop PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXXZ
    db   0F0h, 090h              ; lock nop — db 直发; capstone 拒解码
    call ?marker_end@sdk@wvmp@@YAXXZ
    add  rsp, 56
    ret
wv_at_neg_lock_nop ENDP

END
