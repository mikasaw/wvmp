; MIT-442 (X2a): 形级 fork 面收口端到端主样本 — x64 可执行形态全链真虚拟化
; (B.5 D3 硬项; MASM 手编纪律 423/428/438 同款, 自含 marker 桩 433/438 同款)。
;
; 区域形态 (X0 §1.4 fork 面 → 本单收口后全部 x64 可虚拟化):
;   区1 wvmp_ff_leave   : leave (C9) 折条 [Mov rsp←rbp; Pop rbp] — 函数序尾
;                         (push rbp/mov rbp,rsp/sub rsp/leave/ret) 全在区内,
;                         栈平衡哨兵 bal=0 (438 形; leave 推翻前该形态 gate)
;   区3 wvmp_ff_string  : plain 单发串形 (A5 movsd ×2 / AD lodsd) + cld (D5
;                         no-op 放行) — 结构体拷贝惯用法 (dxcompiler 10116 级)
;   区4 wvmp_ff_s16     : p66 S16 通路 (66 B8/03/89 imm+ALU+store) + cwde (98
;                         两 IR 折条) + cbw (66 98 载体微程序) — B.3 全链试通
;   区2 wvmp_ff_callmem : call [mem] IAT 形 (call qword ptr [g_fnptr] = FF 15
;                         rip 形, `call [__imp_x]` 语义同构) — 负例: CallGate
;                         协议仅吃 aux RVA (asmgen step1 实读), reg-target 需
;                         asmgen 改动 → D4 停手 gate, 区域原生 byte-exact
;   区2b wvmp_ff_callreg: call rax (vtable/函数指针形) — 负例同上归 X3
;   区5 wvmp_ff_stdgate : std (F9) — 负例 D5 裁决 gate (DF←1 不可建模),
;                         区内 std/nop/cld 原生平衡
;   区6 wvmp_ff_addr67  : 67 前缀 (db 067h,08Bh,003h = mov eax,[ebx]) — 负例
;                         B.4 地址宽闸 gate; **main 只取地址不调用** (463
;                         禁调用负例纪律: gate 区域仍全量 lift, 行为无需保证)
;
; 分叉面: 全部区域 native 与 packed 行为 byte-exact (multiseed 逐字节比对);
; REQUIRE_REAL 断言 = 区1/3/4 至少 1 stub 真虚拟化 (multiseed_e2e_real.sh);
; 区2/2b/5/6 gate 证据 = protect 日志 gate note (region 2/2b: "call [mem]"/
; "间接 call ... X3", 区5: 未支持指令 std, 区6: 67 前缀 unsupported)。
;
; 区1 栈语义推演 (E = 函数入口 rsp, [E] = 返回地址; prologue 原生, 见下):
;   push rbp → [E-8]=旧rbp, rsp=E-8; mov rbp,rsp → rbp=E-8; sub rsp,20h →
;   rsp=E-28h; stub 入口 ns = E-28h (v4 预载), 保存区 [E-30h..E-68h];
;   区内 [rbp-8]/[rbp-4] 落盘 [E-16]/[E-12] (ns 上方, 保存区零触碰);
;   leave → v4:=v5=E-8, pop rbp → v5=旧rbp, v4=E; ret (MIT-438 build_ret) →
;   弹 [E], 出口 rsp=E+8 — 与原生逐位一致, caller 探针 bal = R0 - rsp = 0。

.code
; ---- 自含 marker 桩: magic 8 字节连续 (438 同款, 不链 wvmp::sdk) ----
marker_begin PROC
    mov rax, 31474542504D5657h   ; "WVMPBEG1" (kBeginMagic)
    ret
marker_begin ENDP
marker_end PROC
    mov rax, 31444E45504D5657h   ; "WVMPEND1" (kEndMagic)
    ret
marker_end ENDP

; C 链接全局 (wvmp_forkface_sample_main.cpp 定义)
EXTERNDEF g_wvmp_ff_bal       : DWORD
EXTERNDEF g_wvmp_ff_ret       : DWORD
EXTERNDEF g_wvmp_ff_fnptr     : QWORD
EXTERNDEF g_wvmp_ff_callmem   : DWORD
EXTERNDEF g_wvmp_ff_callreg   : DWORD
EXTERNDEF wvmp_ff_target_b    : PROC
EXTERNDEF g_wvmp_ff_src       : BYTE
EXTERNDEF g_wvmp_ff_dst       : BYTE
EXTERNDEF g_wvmp_ff_s16a      : WORD
EXTERNDEF g_wvmp_ff_s16b      : WORD
EXTERNDEF g_wvmp_ff_s16c      : WORD
EXTERNDEF g_wvmp_ff_s32       : DWORD

; ---- 区1 callee: leave 链 (prologue 原生在区域外, leave/ret 面收区内) ----
; ecx/edx = 参数; 返回 eax = ecx*8 + edx + 0x15 (区内计算)。
;
; ⚠️ #33 实测发现 (首版样本 push rbp/mov rbp,rsp 放区内 → packed bal 探针
; 分叉): stub 的 callee-saved 保存区位于 [ns-8 .. ns-0x40] (ns = stub 入口
; rsp = v4 预载值), 区内 push 写 [v4-8] 与保存区首槽直接重叠, 后续 [rbp-x]
; 落盘覆写保存的 rbx → 出口链 pop rbx 读到 guest 数据 (观察值 = 0x1E00000007
; 形态 = ecx/edx 合成值, 机制吻合)。438 build_ret 注释「guest 未配平 push
; 写穿 stub 保存区」登记面的 E2E 实证 + 规则化: **guest 栈写必须恒 ≥ ns**
; (保存区全在 ns 下方) — 函数序尾的 prologue (push rbp/mov rbp,rsp) 侧放
; 区域外原生执行, leave/epilogue 面收区内 (v4 = E-28h 帧基, leave 的
; Mov rsp←rbp + Pop 与 ret 全链仍被 E2E 钉死: v4:=v5 错则 ret 读 [E-28h]
; 必崩/必错, ret 值 + bal=0 探针即判定)。
wvmp_ff_leave PROC
    push rbp                    ; 原生序 (区域外 — 保存区冲突面, 见上注)
    mov  rbp, rsp
    sub  rsp, 20h
    call marker_begin           ; ==== region ==== (v4 = E-28h, v5 = rbp = E-8h)
    mov  dword ptr [rbp-8], ecx     ; [E-16] 落盘 (ns 上方, 保存区零触碰)
    mov  dword ptr [rbp-4], edx
    mov  eax, dword ptr [rbp-8]     ; Load S32
    shl  eax, 3                     ; *8 (imm shift)
    add  eax, dword ptr [rbp-4]
    add  eax, 15h                   ; 特征偏置
    leave                       ; ★ C9 折条: Mov rsp←rbp + Pop rbp
    ret                         ; plain ret (MIT-438 build_ret 通路, 出口 rsp=E+8)
    call marker_end             ; 死分隔符 (ret 已跳出区域)
    leave
    ret
wvmp_ff_leave ENDP

; ---- 区1 caller: 平衡探针 + 返回值落盘 ----
wvmp_ff_call_leave PROC
    push rbx
    sub  rsp, 20h
    mov  rbx, rsp               ; R0 (16 对齐)
    mov  ecx, 7
    mov  edx, 30
    call wvmp_ff_leave
    sub  rbx, rsp               ; 探针: 0 正确 / 失衡即分叉
    mov  DWORD PTR g_wvmp_ff_bal, ebx
    mov  DWORD PTR g_wvmp_ff_ret, eax
    add  rsp, 20h
    pop  rbx
    ret
wvmp_ff_call_leave ENDP

; ---- 区2 callee: call [mem] IAT 形 (负例 gate, 原生执行) ----
; g_wvmp_ff_fnptr 由 main 预置 = wvmp_ff_target; FF 15 rip 形 (dumpbin 双验)。
wvmp_ff_callmem PROC
    sub  rsp, 28h
    call marker_begin
    call QWORD PTR [g_wvmp_ff_fnptr]    ; ★ call [mem] → D4 停手 gate 归 X3
    call marker_end
    add  rsp, 28h
    ret
wvmp_ff_callmem ENDP

; ---- 区2b callee: call reg (负例 gate, 原生执行) ----
wvmp_ff_callreg PROC
    sub  rsp, 28h
    call marker_begin
    mov  rax, wvmp_ff_target_b
    call rax                            ; ★ call reg → CallGate reg-target 归 X3
    call marker_end
    add  rsp, 28h
    ret
wvmp_ff_callreg ENDP

; ---- 区3 callee: plain 单发串形 + cld (真虚拟化) ----
; rsi/rdi 由 caller 指向 src/dst; 区内: cld; movsd ×2 (8B 结构体拷贝);
; lodsd (取 src+8); mov [rdi], eax (落 dst+8)。
wvmp_ff_string PROC
    sub  rsp, 28h
    call marker_begin
    cld                         ; ★ D5 no-op 放行 (DF=0 假设一致)
    movsd                       ; ★ plain A5 单发: [rdi]←[rsi] dword, 双指针 +4
    movsd                       ; ★ 第二 dword (8B 拷贝完成)
    lodsd                       ; ★ plain AD 单发: eax←[rsi], rsi +4
    mov  dword ptr [rdi], eax   ; dst+8 ← src+8 值
    call marker_end
    add  rsp, 28h
    ret
wvmp_ff_string ENDP

; ---- 区3 caller: rsi/rdi 指向全局缓冲 ----
wvmp_ff_call_string PROC
    push rbx
    sub  rsp, 20h
    lea  rsi, g_wvmp_ff_src
    lea  rdi, g_wvmp_ff_dst
    call wvmp_ff_string
    add  rsp, 20h
    pop  rbx
    ret
wvmp_ff_call_string ENDP

; ---- 区4 callee: p66 S16 通路 + cwde/cbw (真虚拟化) ----
; bx = 0x0123 (caller 预置):
;   ax = 7F00h + bx = 8023h → s16a
;   ax ^= FFFFh = 7FDCh; cmp ax,bx ≠ → jne 跳过 +2 → s16b = 7FDCh
;   ax = 8123h; cwde → eax = FFFF8123h → s32
;   al = 80h; cbw → ax = FF80h → s16c
wvmp_ff_s16 PROC
    sub  rsp, 28h
    call marker_begin
    mov  ax, 7F00h              ; ★ p66: 66 B8 imm16 (S16 Mov)
    add  ax, bx                 ; ★ p66: 66 03 C3 (S16 Add)
    mov  WORD PTR [g_wvmp_ff_s16a], ax  ; ★ p66: 66 89 05 rip (S16 Store)
    mov  dx, 0FFFFh             ; ★ p66 S16 imm
    xor  ax, dx                 ; ★ p66: 66 31 D0 (S16 Xor)
    cmp  ax, bx                 ; ★ p66: 66 3B C3 (S16 Cmp)
    jne  s16_done               ; 非零 → 跳过 +2
    add  ax, 2
s16_done:
    mov  WORD PTR [g_wvmp_ff_s16b], ax
    mov  ax, 8123h              ; 负数形 (bit15=1)
    cwde                        ; ★ 98: eax = sx32(ax) 两 IR 折条
    mov  DWORD PTR [g_wvmp_ff_s32], eax
    mov  al, 80h                ; S8 Mov (B0)
    cbw                         ; ★ 66 98: ax = sx16(al) 载体微程序
    mov  WORD PTR [g_wvmp_ff_s16c], ax
    call marker_end
    add  rsp, 28h
    ret
wvmp_ff_s16 ENDP

; ---- 区4 caller: bx=0x0123 预置 ----
wvmp_ff_call_s16 PROC
    push rbx
    sub  rsp, 20h
    mov  ebx, 123h              ; S16 加法参数
    call wvmp_ff_s16
    add  rsp, 20h
    pop  rbx
    ret
wvmp_ff_call_s16 ENDP

; ---- 区5 callee: std (负例 D5 gate; 区内 std/cld 原生平衡) ----
wvmp_ff_stdgate PROC
    sub  rsp, 28h
    call marker_begin
    std                         ; ★ DF←1 → D5 gate (整函数原生)
    nop
    cld                         ; 原生 DF 平衡 (gate 后照常执行)
    call marker_end
    add  rsp, 28h
    ret
wvmp_ff_stdgate ENDP

; ---- 区6 callee: 67 前缀 (负例 B.4 gate; 禁调用 — main 只取地址) ----
wvmp_ff_addr67 PROC
    sub  rsp, 28h
    call marker_begin
    db 067h, 08Bh, 003h         ; ★ 67 8B 03 = mov eax,[ebx] (地址宽 32 截断形)
    call marker_end
    add  rsp, 28h
    ret
wvmp_ff_addr67 ENDP

_TEXT ENDS
END
