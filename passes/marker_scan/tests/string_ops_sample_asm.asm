; MIT-415 (G3): 串指令族 rep movs/stos/scas/cmps/lods 微程序展开 E2E 样本
; MASM 宿主 — 真字节直写 (MSVC x64 不支持 inline asm; /Od 的 memcpy/memset
; 走 call 不产 rep 串指令, 派活单 §A.3 先验, 故 MASM 拼写全族形态)。
;
; 正样本 7 个 (全部 REQUIRE_REAL 真虚拟化):
;   ① wv_str_movsb      —— rep movsb 逐字节语义 (B.4-①), 返回最终 rcx (恒 0)
;   ② wv_str_movsq_unaligned —— rep movsq 8B 语义 + 非对齐 [rdi] (B.4-⑤)
;   ③ wv_str_stosb      —— rep stosb (B.4-①), 含 rcx=0 空转 (B.4-②, main 侧)
;   ④ wv_str_scasb      —— repne scasb 早退 (B.4-③): 返回 (命中索引<<32)|剩余
;                          rcx (早退迭代不推进指针不减计数, SDM)
;   ⑤ wv_str_cmpsb      —— repe cmpsb 早退 (B.4-③): 返回 (首差异索引<<32)|剩余
;   ⑥ wv_str_lodsb      —— rep lodsb: 末字节 → dst[0] + rax 双可观测; n=0 空转
;   ⑦ wv_str_movsb_flags—— flags 通路探针: 区域内 cmp 置 ZF → rep movsb →
;                          sete 读回 (movs 不写 flags 的保全证据, B.4 flags
;                          语义; Setcc handler 读 VM flags 槽, 非空转)
; 负样本 1 个 (照旧 C1 gate, packed 与 native 逐字节一致):
;   ⑧ wv_str_neg_pause  —— 区域内 `pause` (F3 90 = rep nop, rep 前缀非串指令)
;                          → 白名单外 → gate 保持原生。
;   (lock rep movsb 负例只在 lifter 单测覆盖: 本机实测 F0 F3 A4 原生执行即
;   #UD (SIGILL), 无法作为可执行样本 — 披露于报告 §F.1)
;
; 区域语义: 每函数区域 = [call marker_begin 之后, call marker_end 处); 区域
; 内只含白名单指令 + 本单新放行的 rep 串指令; 结果 spill 到 [rsp+24]
; (marker_end clobber rax, pitfall #36); 无 rsp 调整 (entry rsp 恒等, Halt
; 恢复契约 — prologue 的 push/sub 均在 marker_begin 之前区外)。
; rsi/rdi 是 Win64 callee-saved: prologue/epilogue (区外) push/pop。

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; ============ ① rep movsb ============
; u64 wv_str_movsb(void* dst, const void* src, u64 n) → rax = 最终 rcx
wv_str_movsb PROC
    push rsi
    push rdi
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    mov  rsi, rdx                ; src
    mov  rdi, rcx                ; dst
    mov  rcx, r8                 ; n
    rep  movsb
    mov  [rsp+24], rcx           ; spill 最终计数 (marker_end clobber rax)
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    pop  rdi
    pop  rsi
    ret
wv_str_movsb ENDP

; ============ ② rep movsq 非对齐 (B.4-⑤) ============
; u64 wv_str_movsq_unaligned(void* dst, const void* src, u64 n) → rax = rcx
; 调用方传 dst = buf+1 (8B 非对齐) — VM Load/Store 非对齐语义与原生一致
; (movups 教训族: 展开侧全用非对齐语义指令)。
wv_str_movsq_unaligned PROC
    push rsi
    push rdi
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    mov  rsi, rdx
    mov  rdi, rcx
    mov  rcx, r8
    rep  movsq
    mov  [rsp+24], rcx
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    pop  rdi
    pop  rsi
    ret
wv_str_movsq_unaligned ENDP

; ============ ③ rep stosb ============
; u64 wv_str_stosb(void* dst, u8 v, u64 n) → rax = rcx (main 侧含 n=0 空转)
wv_str_stosb PROC
    push rdi
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    mov  rdi, rcx                ; dst
    mov  eax, edx                ; v (低 8 位 = al)
    mov  rcx, r8                 ; n
    rep  stosb
    mov  [rsp+24], rcx
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    pop  rdi
    ret
wv_str_stosb ENDP

; ============ ④ repne scasb 早退 (B.4-③) ============
; u64 wv_str_scasb(const void* buf, u8 needle, u64 n) →
;   rax = (index << 32) | 剩余 rcx; index = rdi - buf (命中位) 或 n (未命中);
;   剩余 rcx = n - index (早退迭代不减计数, SDM)
wv_str_scasb PROC
    push rdi
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    mov  [rsp+40], rcx           ; spill buf (rcx 将被 n 覆盖)
    mov  rdi, rcx                ; buf
    mov  eax, edx                ; needle (al)
    mov  rcx, r8                 ; n
    repne scasb
    mov  rax, rdi
    sub  rax, [rsp+40]           ; index = rdi - buf
    shl  rax, 32
    or   rax, rcx                ; | 剩余计数
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    pop  rdi
    ret
wv_str_scasb ENDP

; ============ ⑤ repe cmpsb 早退 (B.4-③) ============
; u64 wv_str_cmpsb(const void* a, const void* b, u64 n) →
;   rax = (首差异索引 << 32) | 剩余 rcx; 全等 → index = n, rem = 0
wv_str_cmpsb PROC
    push rsi
    push rdi
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    mov  [rsp+40], rcx           ; spill a (rcx 将被 n 覆盖)
    mov  rsi, rcx                ; a
    mov  rdi, rdx                ; b
    mov  rcx, r8                 ; n
    repe cmpsb
    mov  rax, rsi
    sub  rax, [rsp+40]           ; index = rsi - a
    shl  rax, 32
    or   rax, rcx
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    pop  rdi
    pop  rsi
    ret
wv_str_cmpsb ENDP

; ============ ⑥ rep lodsb ============
; u64 wv_str_lodsb(void* dst, const void* src, u64 n) → rax = 最终 al
; (末字节; n=0 空转时 = 预置 0x5A); dst[0] = 末字节 双可观测。
wv_str_lodsb PROC
    push rsi
    push rdi
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    mov  eax, 5A5A5A5Ah          ; 预置 acc (n=0 空转路径可观测)
    mov  rsi, rdx                ; src
    mov  rdi, rcx                ; dst
    mov  rcx, r8                 ; n
    rep  lodsb
    mov  [rdi], al               ; dst[0] = 末字节
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    pop  rdi
    pop  rsi
    ret
wv_str_lodsb ENDP

; ============ ⑦ flags 通路探针 (movs 不写 flags 保全) ============
; u64 wv_str_movsb_flags(u64 zf_in, void* dst, const void* src, u64 n) → rax = sete
; 区域内 `cmp rcx, 1` 置 ZF (zf_in==1 → ZF=1) → rep movsb → sete al: 原生
; movs 不写 flags → sete 读 cmp 的 ZF; VM 侧 GetFlags/SetFlags 全路径恢复
; → Setcc handler 读同一 VM flags 槽, 两路径必须同值 (空转/丢 flags 即 FAIL)。
wv_str_movsb_flags PROC
    push rsi
    push rdi
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    cmp  rcx, 1                  ; ZF = (zf_in == 1) — 区域内 flags 来源
    mov  rsi, r8                 ; src (mov 不写 flags)
    mov  rdi, rdx                ; dst
    mov  rcx, r9                 ; n
    rep  movsb
    sete al
    movzx eax, al
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    pop  rdi
    pop  rsi
    ret
wv_str_movsb_flags ENDP

; ============ ⑧ 负例: rep 前缀非串指令 (pause) → C1 gate ============
; u64 wv_str_neg_pause(u64 x) → rax = x。区域含 F3 90 (pause = rep nop) —
; rep 前缀非串指令, 三元组白名单外 → lifter unsupported → C1 gate → 整函数
; 保持原生, 行为 byte-exact。
wv_str_neg_pause PROC
    sub  rsp, 40
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    pause                        ; F3 90
    mov  [rsp+24], rcx
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 40
    ret
wv_str_neg_pause ENDP

_TEXT ENDS
END
