; MIT-492 (F3): CR-01 零次移位 flags 活跃性的 multiseed 入池样本 MASM。
;
; 形态来源: docs/CODE_REVIEW_2026-09-18.md CR-01 最小复现
;   `mov eax,0 / mov ecx,0 / cmp eax,0 / shl edx,cl / sete al`
; 修复前 (MIT-490 前基线): Shl/Shr/Sar 及 *Cl 列在 FlagSem::kWrite 无条件
; 覆盖集内 → liveness 把前序 cmp 判 dead → VM 宿主按"移位结果"重写 ZF →
; sete 捕到宿主状态 (edx=1 时 ZF=0) → 与 native 分叉。修复后
; FlagSem::kWriteConditional 保留输入 flags → byte-exact。
;
; 与 MIT-490 三层 ctest 的分工: ctest 钉的是 translator liveness 断言与
; runtime 语义电池; 4481 词池面当时 0 处 cond_or_size delta, 即全池只证明
; "零回踩"、不约束新行为。本样本是 CR-01 新语义在回归池里的唯一正向约束。
;
; 区结构 (7 区, 全真虚拟化, REQUIRE_REAL 期望 7 stub):
;   ① shl0_z:    mov eax,0/mov ecx,0/mov edx,1/cmp eax,0 → shl edx,cl
;                (cl=0, 前态 ZF=1 保留) → sete al  ← CR-01 复现原形
;                native 1 / 修复前 0 (判别区)
;   ② shr0_z:    同前态 → shr edx,cl → setz cl     native 1 / 修复前 0
;   ③ sar0_z:    同前态 → sar edx,cl → setz cl     native 1 / 修复前 0
;   ④ shl0_nz:   前态 ZF=0 (cmp eax,0 且 eax=1) → shl edx,cl (cl=0)
;                → setz cl                          native 0 (保留面反向对照)
;   ⑤ shlmask0_z: cl=32 → 有效计数 32 and 1Fh = 0 → 等价零移位
;                native 1 / 修复前 0 (掩码归零档)
;   ⑥ shlnz_z:   cl=1, edx=1 → shl 结果 2 按结果写 ZF=0
;                native 0 (控制区: 反证"改过头"——非零计数漏写 flags 即露形)
;   ⑦ shl0_jz:   前态 ZF=1 → shl edx,cl (cl=0) → jz 取分支落盘
;                native 1 / 修复前 0 (jcc 消费档, 非 setcc)
;
; MASM 手编纪律 (428/433 同款): setcc 目的寄存器优先用 cl (guest RCX 低字节,
; VM setcc handler 写别名槽, 区内 Store 经别名读 — 全 VM 内闭合); ① 例外用
; al 以逐字对齐 CR-01 复现原形。marker 桩 magic 与
; sdk/include/wvmp/sdk/markers.hpp kBeginMagic/kEndMagic 逐字节同步 (自含桩
; 不做编译期断言, 同步性由 marker_scan 定位成败兜底)。

.code
; ---- 自含 marker 桩: magic 8 字节连续 (433 原形) ----
marker_begin PROC
    mov rax, 31474542504D5657h   ; "WVMPBEG1" (kBeginMagic)
    ret
marker_begin ENDP
marker_end PROC
    mov rax, 31444E45504D5657h   ; "WVMPEND1" (kEndMagic)
    ret
marker_end ENDP

; C 链接全局 (wvmp_shift0_flags_sample_main.cpp 定义), 区内 Store 落盘槽
EXTERNDEF g_wv492_shl0_z     : BYTE
EXTERNDEF g_wv492_shr0_z     : BYTE
EXTERNDEF g_wv492_sar0_z     : BYTE
EXTERNDEF g_wv492_shl0_nz    : BYTE
EXTERNDEF g_wv492_shlmask0_z : BYTE
EXTERNDEF g_wv492_shlnz_z    : BYTE
EXTERNDEF g_wv492_shl0_jz    : BYTE

_TEXT SEGMENT

; ---- ① wv492_shl0_z: CR-01 复现原形 (sete al) ----
wv492_shl0_z PROC
    push rbx
    sub rsp, 20h
    call marker_begin
    mov eax, 0
    mov ecx, 0              ; CL 形计数 = 0
    mov edx, 1              ; 被移位值非零: 修复前宿主按结果写 ZF=0
    cmp eax, 0              ; 前态 ZF=1
    shl edx, cl             ; 零次移位: native 全部 flags 原样保留
    sete al                 ; native 1; 修复前 VM 0
    mov BYTE PTR g_wv492_shl0_z, al
    call marker_end
    add rsp, 20h
    pop rbx
    ret
wv492_shl0_z ENDP

; ---- ② wv492_shr0_z: shr 零次移位 ----
wv492_shr0_z PROC
    push rbx
    sub rsp, 20h
    call marker_begin
    mov eax, 0
    mov ecx, 0
    mov edx, 1
    cmp eax, 0              ; 前态 ZF=1
    shr edx, cl             ; 零次移位: flags 保留
    setz cl                 ; native 1; 修复前 VM 0
    mov BYTE PTR g_wv492_shr0_z, cl
    call marker_end
    add rsp, 20h
    pop rbx
    ret
wv492_shr0_z ENDP

; ---- ③ wv492_sar0_z: sar 零次移位 ----
wv492_sar0_z PROC
    push rbx
    sub rsp, 20h
    call marker_begin
    mov eax, 0
    mov ecx, 0
    mov edx, 1
    cmp eax, 0              ; 前态 ZF=1
    sar edx, cl             ; 零次移位: flags 保留
    setz cl                 ; native 1; 修复前 VM 0
    mov BYTE PTR g_wv492_sar0_z, cl
    call marker_end
    add rsp, 20h
    pop rbx
    ret
wv492_sar0_z ENDP

; ---- ④ wv492_shl0_nz: 前态 ZF=0 的保留面反向对照 ----
wv492_shl0_nz PROC
    push rbx
    sub rsp, 20h
    call marker_begin
    mov eax, 1
    mov ecx, 0
    mov edx, 1
    cmp eax, 0              ; 前态 ZF=0
    shl edx, cl             ; 零次移位: flags 保留 0
    setz cl                 ; native 0
    mov BYTE PTR g_wv492_shl0_nz, cl
    call marker_end
    add rsp, 20h
    pop rbx
    ret
wv492_shl0_nz ENDP

; ---- ⑤ wv492_shlmask0_z: cl=32 经位宽掩码归零档 ----
wv492_shlmask0_z PROC
    push rbx
    sub rsp, 20h
    call marker_begin
    mov eax, 0
    mov ecx, 32             ; 有效计数 32 and 1Fh = 0 → 等价零移位
    mov edx, 1
    cmp eax, 0              ; 前态 ZF=1
    shl edx, cl
    setz cl                 ; native 1; 修复前 VM 0
    mov BYTE PTR g_wv492_shlmask0_z, cl
    call marker_end
    add rsp, 20h
    pop rbx
    ret
wv492_shlmask0_z ENDP

; ---- ⑥ wv492_shlnz_z: 非零计数控制区 (反证漏写 flags) ----
wv492_shlnz_z PROC
    push rbx
    sub rsp, 20h
    call marker_begin
    mov eax, 0
    mov ecx, 1              ; 非零计数
    mov edx, 1
    cmp eax, 0              ; 前态 ZF=1
    shl edx, cl             ; 结果 2 → 按结果写 ZF=0
    setz cl                 ; native 0; 若改过头漏写 flags 则为 1
    mov BYTE PTR g_wv492_shlnz_z, cl
    call marker_end
    add rsp, 20h
    pop rbx
    ret
wv492_shlnz_z ENDP

; ---- ⑦ wv492_shl0_jz: jcc 消费前驱 flags (非 setcc 档) ----
wv492_shl0_jz PROC
    push rbx
    sub rsp, 20h
    call marker_begin
    mov eax, 0
    mov ecx, 0
    mov edx, 1
    cmp eax, 0              ; 前态 ZF=1
    shl edx, cl             ; 零次移位: flags 保留
    jz  wv492_j_taken       ; native 取分支; 修复前 ZF=0 → 不取
    xor ebx, ebx            ; 未取分支 → 0
    jmp wv492_j_end
wv492_j_taken:
    mov ebx, 1              ; 取分支 → 1
wv492_j_end:
    ; 汇合快照 445/atomic 同款形: 块首必须是区内 Store, 后随 marker_end。
    ; 块首若直落 marker_end call (= 区域末界), 该块落在 lift 域外 →
    ; "跳转目标块未找到（区域外/未 lift）" → 整函数 gate 保原生。
    mov BYTE PTR g_wv492_shl0_jz, bl
    call marker_end
    add rsp, 20h
    pop rbx
    ret
wv492_shl0_jz ENDP

_TEXT ENDS
END
