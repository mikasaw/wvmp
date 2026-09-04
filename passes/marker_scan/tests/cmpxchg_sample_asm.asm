; MIT-341: cmpxchg E2E sample 的 MASM helper (MSVC x64 不支持 inline asm,
; 无法让 C++ 强制 codegen 出 cmpxchg r/m, r —— MSVC 编译器把
; `std::atomic::compare_exchange` 通常 emit `lock cmpxchg` (atomic) 字节,
; 但 v1 派活单限定不支持 lock prefix, 故必须手写 cmpxchg 非 lock 字节。
; 此 helper 直接 emit 真 cmpxchg 字节, 链接进 wvmp_cmpxchg_sample。
;
; 函数语义: 在 marker_begin / marker_end 调用之间包含真 cmpxchg REG-REG
; (`0F B1+rm` 字节, mod=11)。marker_scan 识别 WVMPBEG1/WVMPEND1 magic
; 字节 + 紧随的 E8 call, 标定区域. lifter 把区域内 mov/cmpxchg 一一翻译
; 为 VmOp::Mov / VmOp::Cmpxchg, asmgen 的 build_cmpxchg handler 真正被
; exercise。
;
; Win64 ABI: rcx/rdx/r8/r9 = 前 4 个整型参数, rax = 返回值. callee-saved:
; rbx, rbp, rdi, rsi, r12-r15. 此函数用 rbx 作临时寄存器, push/pop 守恒。
;
; ⚠️ rax 跨 marker_end/marker_begin 调用会被 clobber (SDK `mov rax, imm64`
; 加载 magic 立即数), 必须在 call 前存到 stack, call 后还原 (pitfall #36)。
;
; 栈布局 (沿用 cmovcc_sample_asm.asm 模式):
;   push rbx → rsp -= 8 → saved rbx 在 [rsp] (即 original - 8)
;   sub rsp, 64 → rsp -= 64 → rsp = original - 72
;   [rsp+24] = 临时存 rax (跨 SDK 调用)
;   [rsp+32] = local 1: expected (rcx)
;   [rsp+40] = local 2: desired (rdx)
;   [rsp+72] = original - 8 = saved rbx

; MSVC C++ 名称修饰 (x64): ?marker_begin@sdk@wvmp@@YAXPEBD@Z (void marker_begin())
EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; uint64_t cmpxchg64_eq(int64_t expected, int64_t desired):
;   模拟 cmpxchg r64, r64 equal case:
;     rax = expected
;     rcx = desired
;     cmpxchg rax, rcx   ← 0F B1 C8 (3 字节, REX.W 隐含 64-bit)
;     比较 rax(expected) 与 rax(隐式累加器): SAME register! 永远相等
;     ZF=1, rax = rcx(desired) — 但 caller 想看 equal case 下 rax 是不是保持
;   这种模式是不对的 (r/m 与 acc 是同一 reg), 改成:
;     rcx = expected; rax = desired
;     cmpxchg rcx, rax  ← 比较 rax(隐式 acc=desired) 与 rcx(expected)
;       equal: ZF=1; rcx = rax(=desired)
;       not equal: ZF=0; rax = rcx(=expected)
;   返回值放 rax: 在 equal case 下 rax 保持原 desired 值 (eax 路径).
;
; 实际更简单: 我们只测 equal case (expected == desired), 让 acc 也匹配 dst。
;
; wrapper 设计:
;   1. mov rax, expected  (acc = expected)
;   2. mov rcx, desired   (dst = desired, 同时也是 src)
;   3. cmpxchg rax, rcx   -- 但这又 self-compare! 改用 mov + cmpxchg
;   改用: mov rcx, expected (dst = expected); mov rax, desired (acc = desired);
;         cmpxchg rcx, rax
;   equal (expected == desired): rcx = rax = desired; 返回 rax = desired
;
; 注意: 此函数 cmpxchg 字节必须满足 r/m != acc (否则永远是 equal).
;
; 实现:
;   rcx = expected (1st arg)
;   rdx = desired (2nd arg)
;   mov rcx, expected  (load expected to rcx; dst = expected)
;   mov rax, desired   (load desired to rax; acc = desired)
;   cmpxchg rcx, rax   (compare rax==rcx; equal → rcx=rax=desired; rax 不变)
;   mov [rsp+24], rax  (save rax before marker_end)
;   call marker_end
;   mov rax, [rsp+24]  (restore rax)
;   返回 rax (= desired, equal case 下保留)
cmpxchg64_eq PROC
    push rbx
    sub  rsp, 64

    mov  qword ptr [rsp+32], rcx   ; save expected
    mov  qword ptr [rsp+40], rdx   ; save desired

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z

    mov  rcx, qword ptr [rsp+32]   ; rcx = expected (dst = expected)
    mov  rax, qword ptr [rsp+40]   ; rax = desired (acc = desired)
    cmpxchg rcx, rax               ; 真 cmpxchg REG-REG (mod=11), 48 0F B1 C8 (4 字节)
                                   ;   compare rax(acc) == rcx(dst)
                                   ;   equal → rcx = rax(desired); ZF=1; rax 不变
                                   ;   not equal → rax = rcx(expected); ZF=0; rcx 不变
                                   ; 这两种 case 都测, 用 caller 决定 expected vs desired
    mov  [rsp+24], rax             ; ⚠️ rax 在 marker_end 后会被 clobber
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]             ; 还原 rax (handler 后 Rax 槽的内容)
    ; ===== marker region end =====

    add  rsp, 64
    pop  rbx
    ret
cmpxchg64_eq ENDP

; uint64_t cmpxchg64_ne(int64_t initial, int64_t dst_val, int64_t desired):
;   三个参数模拟 "rax 累加器是 initial, dst 是 dst_val, src 是 desired"
;   cmpxchg dst, src 比较隐式 rax(initial) 与 dst(dst_val)
;     equal: dst ← src (rcx = rdx); rax 不变
;     not equal: rax ← dst (rax = rcx); rcx 不变
;   返回 rax (handler 后 Rax 槽的内容)
;
; 实现:
;   rcx = initial, rdx = dst_val, r8 = desired
;   mov rax, initial (acc = initial)
;   mov rcx, dst_val (dst = dst_val; 注意: 第一参数覆写 rcx 是对的 — 区域里我们要 dst = dst_val)
;   mov rdx, desired (src = desired; 覆写 rdx)
;   cmpxchg rcx, rdx
;     equal (initial == dst_val): rcx = rdx(desired); ZF=1; rax 不变
;     not equal: rax = rcx(dst_val); ZF=0; rcx 不变
;   返回 rax
cmpxchg64_ne PROC
    push rbx
    sub  rsp, 80

    mov  qword ptr [rsp+32], rcx   ; save initial
    mov  qword ptr [rsp+40], rdx   ; save dst_val
    mov  qword ptr [rsp+48], r8    ; save desired

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z

    mov  rax, qword ptr [rsp+32]   ; rax = initial (acc = initial)
    mov  rcx, qword ptr [rsp+40]   ; rcx = dst_val (dst = dst_val)
    mov  rdx, qword ptr [rsp+48]   ; rdx = desired (src = desired)
    cmpxchg rcx, rdx               ; 真 cmpxchg REG-REG (mod=11), 48 0F B1 D1 (4 字节)
                                   ;   compare rax(acc=initial) == rcx(dst=dst_val)
                                   ;   equal → rcx = rdx(desired); ZF=1; rax 不变
                                   ;   not equal → rax = rcx(dst_val); ZF=0; rcx 不变
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 80
    pop  rbx
    ret
cmpxchg64_ne ENDP

; uint32_t cmpxchg32_eq(uint32_t expected, uint32_t desired):
;   S32 equal case: eax = expected; ecx = desired; cmpxchg ecx, eax
;     compare eax(expected) == ecx(expected): equal; ecx = eax(desired); rax 不变
;   返回 rax (eax = desired after cmpxchg equal)
cmpxchg32_eq PROC
    push rbx
    sub  rsp, 48

    mov  dword ptr [rsp+32], ecx
    mov  dword ptr [rsp+40], edx

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z

    mov  ecx, dword ptr [rsp+32]   ; ecx = expected (dst = expected)
    mov  eax, dword ptr [rsp+40]   ; eax = desired (acc = desired)
    cmpxchg ecx, eax               ; 真 cmpxchg REG-REG (mod=11), 0F B1 C8 (3 字节, S32)
                                   ;   compare eax(acc=desired) == ecx(dst=expected)
                                   ;   equal (expected == desired): ecx = eax(desired); ZF=1; rax 不变
                                   ;   not equal: eax = rcx(expected); ZF=0; ecx 不变
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 48
    pop  rbx
    ret
cmpxchg32_eq ENDP

; uint32_t cmpxchg32_ne(uint32_t initial, uint32_t dst_val, uint32_t desired):
;   S32 not-equal case: eax = initial; ecx = dst_val; edx = desired;
;     cmpxchg ecx, edx
;     not equal (initial != dst_val): eax = ecx(dst_val); ZF=0
;   返回 rax (= dst_val after cmpxchg not-equal)
cmpxchg32_ne PROC
    push rbx
    sub  rsp, 64

    mov  dword ptr [rsp+32], ecx
    mov  dword ptr [rsp+40], edx
    mov  dword ptr [rsp+48], r8d

    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z

    mov  eax, dword ptr [rsp+32]   ; eax = initial (acc = initial)
    mov  ecx, dword ptr [rsp+40]   ; ecx = dst_val (dst = dst_val)
    mov  edx, dword ptr [rsp+48]   ; edx = desired (src = desired)
    cmpxchg ecx, edx               ; 真 cmpxchg REG-REG (mod=11), 0F B1 D1 (3 字节, S32)
                                   ;   compare eax(acc=initial) == ecx(dst=dst_val)
                                   ;   not equal → eax = ecx(dst_val); ZF=0; ecx 不变
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    ; ===== marker region end =====

    add  rsp, 64
    pop  rbx
    ret
cmpxchg32_ne ENDP

_TEXT ENDS

END