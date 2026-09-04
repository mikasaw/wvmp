; MIT-423 (G4b): lock inc/dec 原子补齐 E2E 样本 (MASM 宿主)。
; 裸 lock inc/dec 形态 MSVC 编译器不产 (#33 实测: _Interlocked* 真产物 =
; lock xadd ±1, 见 main 侧注释) — 本文件按派活单 §B.5 直写全谱:
;
; 正样本 7 个 (全部 REQUIRE_REAL 真虚拟化, 本体折条 D1: 零新 VmOp):
;   ① wv_id_inc32      —— lock inc dword ptr [rcx] (F0 FF 01)
;   ② wv_id_inc64      —— lock inc qword ptr [rcx] (F0 48 FF 01, REX.W)
;   ③ wv_id_dec32      —— lock dec dword ptr [rcx] (F0 FF 09)
;   ④ wv_id_dec64      —— lock dec qword ptr [rcx] (F0 48 FF 09)
;   ⑤ wv_id_inc_rip    —— lock inc qword ptr [g_id_rip] (rip-relative 目标,
;                          64 位全局计数器惯用形态)
;   ⑥ wv_id_loop_inc   —— lock inc 体 × 7 次 (dec r8d; jnz 循环计数惯用法
;                          — dec 写 ZF → jnz 读 VM flags 槽, B.5 ③)
;   ⑦ wv_id_inc_cf     —— CF 保真探针 (SDM: inc 不写 CF): add 写 CF=1 →
;                          lock inc → jc 必须命中; add CF=0 → lock inc →
;                          jc 必须不命中。返回位 0/位 1 双探针 + inc 结果。
; 负样本 2 个 (D2):
;   ⑧ wv_id_neg_lock_not     —— db F0 48 F7 11 (lock not qword ptr [rcx],
;          F7 /2 modrm 11h):
;          SDM 合法编码但无 MSVC 产物 → D2 裁决 gate。**可调用** (整函数
;          保持原生, 原生执行合法 — gate 行为保真正证); ml64 对 lock not
;          拒汇编与否不赌, db 直发 (416/419 先例, 确定性优先)。
;   ⑨ wv_id_neg_lock_inc_reg —— db F0 FF C1 (lock inc ecx, reg-dst 非法
;          编码): capstone 拒解码 → skipped_ranges → gate; 原生 #UD
;          禁入可执行路径 — main 只取地址不调用。
;
; 区域语义: 每函数区域 = [call marker_begin 之后, call marker_end 处); 结果
; spill 到 [rsp+24] (marker_end clobber rax, pitfall #36); 无 rsp 调整
; (entry rsp 恒等, Halt 恢复契约)。

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC
EXTERNDEF g_id_rip : QWORD

_TEXT SEGMENT

; ============ ① lock inc dword ============
; void wv_id_inc32(long* p)
wv_id_inc32 PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    lock inc dword ptr [rcx]
    mov  eax, [rcx]             ; 结果 spill (区域 ≥5B 供 stub_link 写 E9,
                                ; 419 同款; marker_end clobber rax)
    call ?marker_end@sdk@wvmp@@YAXXZ
    add  rsp, 56
    ret
wv_id_inc32 ENDP

; ============ ② lock inc qword (REX.W) ============
; void wv_id_inc64(long long* p)
wv_id_inc64 PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    lock inc qword ptr [rcx]
    mov  rax, [rcx]             ; 结果 spill (同上)
    call ?marker_end@sdk@wvmp@@YAXXZ
    add  rsp, 56
    ret
wv_id_inc64 ENDP

; ============ ③ lock dec dword ============
; void wv_id_dec32(long* p)
wv_id_dec32 PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    lock dec dword ptr [rcx]
    mov  eax, [rcx]             ; 结果 spill (同上)
    call ?marker_end@sdk@wvmp@@YAXXZ
    add  rsp, 56
    ret
wv_id_dec32 ENDP

; ============ ④ lock dec qword (REX.W) ============
; void wv_id_dec64(long long* p)
wv_id_dec64 PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    lock dec qword ptr [rcx]
    mov  rax, [rcx]             ; 结果 spill (同上)
    call ?marker_end@sdk@wvmp@@YAXXZ
    add  rsp, 56
    ret
wv_id_dec64 ENDP

; ============ ⑤ lock inc qword rip 目标 ============
; u64 wv_id_inc_rip() → 递增后 [g_id_rip]
; [g_id_rip] 是 C++ 侧 extern "C" 全局 — MASM 对 [符号] 自动编 rip-relative
; (x64 无绝对寻址, 419 cmpxchg_rip 同款先例)。
wv_id_inc_rip PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    lock inc qword ptr [g_id_rip]
    mov  rax, [g_id_rip]
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    ret
wv_id_inc_rip ENDP

; ============ ⑥ lock inc 体 × 7 (dec/jnz 循环计数惯用法) ============
; u64 wv_id_loop_inc(long* p) → 轮数 (7)
wv_id_loop_inc PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    mov  r8d, 7
loop_6:
    lock inc dword ptr [rcx]
    dec  r8d                    ; dec 写 ZF (VM flags 槽)
    jnz  loop_6                 ; jnz 读槽 — 循环计数语义校验 (B.5 ③)
    mov  rax, 7                 ; 轮数常量 (循环计数断言面在 main 侧 [p])
    mov  [rsp+24], rax
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    ret
wv_id_loop_inc ENDP

; ============ ⑦ CF 保真探针 (SDM: inc 不写 CF) ============
; u64 wv_id_inc_cf(long* p) → bit0 = CF=1 探针过 (jc 命中),
;                              bit1 = CF=0 探针过 (jc 未命中), [p] 增 2
wv_id_inc_cf PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    ; — 探针 1: add 0xFFFFFFFF+1 → CF=1 → lock inc 不得清 CF → jc 命中
    mov  eax, 0FFFFFFFFh
    add  eax, 1                 ; eax=0, CF=1, ZF=1 (Add handler 全量装配)
    lock inc dword ptr [rcx]    ; 不得动 CF (SDM)
    jc   cf1_kept               ; VM flags 槽 CF=1 → 必须跳
    xor  eax, eax               ; 探针 1 失败: bit0=0
    jmp  cf1_done
cf1_kept:
    mov  eax, 1
cf1_done:
    ; — 探针 2: add 5+1 → CF=0 → lock inc 不得置 CF → jc 不命中
    mov  edx, 5
    add  edx, 1                 ; edx=6, CF=0 (Add handler 重装配)
    lock inc dword ptr [rcx]    ; 不得动 CF
    jc   cf2_bad                ; CF 若被错误置位 → 探针 2 失败
    or   eax, 2                 ; bit1=1 (jc 未命中 = CF 保留为 0)
cf2_bad:
    mov  [rsp+24], rax          ; spill 探针位 (rax 高 32 位已零)
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    ret
wv_id_inc_cf ENDP

; ============ ⑧ D2 负例: lock not (gate 保持原生, 可调用) ============
; long long wv_id_neg_lock_not(long long* p) → 返回旧值; [p] 按位取反。
; db 直发 (416/419 先例): F0 48 F7 11 = lock not qword ptr [rcx] (F7 /2,
; modrm 11h = mod00 reg010(=/2 NOT) rm001=[rcx])。
; gate 后整函数原生执行 — 原生 lock not 合法 (probe3 实测本机 rc=7 正常
; 退出), 行为保真由双跑兜底。
wv_id_neg_lock_not PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    mov  rax, [rcx]
    mov  [rsp+24], rax          ; 旧值 spill (lock not 不动 rax)
    db   0F0h, 048h, 0F7h, 011h ; lock not qword ptr [rcx] — capstone 可解
                                ; (id=511) → translate_lock_op default →
                                ; unsupported → C1 gate (D2 裁决)
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    ret
wv_id_neg_lock_not ENDP

; ============ ⑨ D2 负例: lock inc reg-dst (非法编码, 禁调用) ============
; db 直发: F0 FF C1 = lock inc ecx — lock 必须作用内存操作数 (SDM #UD),
; capstone 拒解码 → skipped_ranges → gate; main 只取地址不调用 (419 同款)。
wv_id_neg_lock_inc_reg PROC
    sub  rsp, 56
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    db   0F0h, 0FFh, 0C1h       ; lock inc ecx — 原生 #UD, 禁入可执行路径
    call ?marker_end@sdk@wvmp@@YAXXZ
    add  rsp, 56
    ret
wv_id_neg_lock_inc_reg ENDP

END
