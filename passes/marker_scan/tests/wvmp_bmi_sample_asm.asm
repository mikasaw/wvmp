; MIT-434 (G8a): BMI 折条款目端到端主样本 MASM —
; andn/bzhi/rorx/shlx/sarx/shrx × {d==s1, d==s2, d 独立 91% 主形态, mem src} +
; flags 消费探针 (区内 setcc → Store 落盘, 427 披露① 观察纪律) + 负例区。
;
; 分叉面 (全部 probe 实测, %TEMP%\mit434, Zen5):
;   andn: CF=0/OF=0/ZF,SF,PF 按结果 (raw 0x286) — Op::Not+And 尾行折叠;
;   bzhi: idx 用 SRC2[7:0]; idx=0 → 结果 0; idx>=N → **原值不变 + CF=1**
;         (raw 0x287, 纠正 432 §2.1 预判); mask-clamp + CF 补丁微程序;
;   rorx/shlx/sarx/shrx: 五位 flags 全保留 (raw 0x247 全程, count=0 同) —
;         GetFlags/SetFlags 包裹 (D1 (i) 变体, 零新 VmOp)。
;
; 区结构 (16 正例区全部真虚拟化, REQUIRE_REAL; 1 负例区函数级 gate 可调用):
;   前态构造 (mov/or, 全白名单) → BMI 指令 → setcc 消费 → 区内 Store 落盘。
;   单基本块 (432 §6.3 前向分支块硬约束) — 无区内分支。
;   mem 形态用 [rsp+20h] (prologue sub rsp,28h 分配帧内, 不碰返回地址)。
;
; 操作数形态映射 (ml64 v145 + capstone 5.0.7 双验):
;   andn dst, s1(NOT 项, reg-only), s2(AND 项, r/m 可 mem)
;   bzhi dst, value(r/m 可 mem), index(reg-only)
;   rorx dst, value(r/m), imm8 / shlx/sarx/shrx dst, value(r/m), cnt(reg)
;
; MASM 手编纪律 (428 pp 位教训 / 433 setcc 纪律): setcc 目的用 cl
; (guest RCX 低字节, VM setcc handler 写别名槽, 区内 Store 经别名读);
; marker 桩 magic 与 sdk/include/wvmp/sdk/markers.hpp 逐字节同步 (自含桩)。

.code
; ---- 自含 marker 桩: magic 8 字节连续 (433 同款) ----
marker_begin PROC
    mov rax, 31474542504D5657h   ; "WVMPBEG1" (kBeginMagic)
    ret
marker_begin ENDP
marker_end PROC
    mov rax, 31444E45504D5657h   ; "WVMPEND1" (kEndMagic)
    ret
marker_end ENDP

; C 链接全局 (wvmp_bmi_sample_main.cpp 定义), 区内 Store 落盘槽
EXTERNDEF g_w434_andn_d1_v     : DWORD
EXTERNDEF g_w434_andn_d1_c     : BYTE
EXTERNDEF g_w434_andn_d2_v     : DWORD
EXTERNDEF g_w434_andn_d2_z     : BYTE
EXTERNDEF g_w434_andn_indep_v  : DWORD
EXTERNDEF g_w434_andn_mem_v    : DWORD
EXTERNDEF g_w434_andn_mem_z    : BYTE
EXTERNDEF g_w434_bzhi_d1_v     : DWORD
EXTERNDEF g_w434_bzhi_d1_z     : BYTE
EXTERNDEF g_w434_bzhi_indep_v  : DWORD
EXTERNDEF g_w434_bzhi_mem_v    : DWORD
EXTERNDEF g_w434_bzhi_mem_z    : BYTE
EXTERNDEF g_w434_bzhi_bnd_v    : DWORD
EXTERNDEF g_w434_bzhi_bnd_c    : BYTE
EXTERNDEF g_w434_bzhi_bnd_z    : BYTE
EXTERNDEF g_w434_bzhi_idx0_v   : DWORD
EXTERNDEF g_w434_bzhi_idx0_z   : BYTE
EXTERNDEF g_w434_rorx_d1_v     : DWORD
EXTERNDEF g_w434_rorx_indep_v  : DWORD
EXTERNDEF g_w434_rorx_mem_v    : DWORD
EXTERNDEF g_w434_rorx_fl_v     : DWORD
EXTERNDEF g_w434_rorx_fl_z     : BYTE
EXTERNDEF g_w434_rorx_fl_c     : BYTE
EXTERNDEF g_w434_rorx_fl_s     : BYTE
EXTERNDEF g_w434_rorx_fl_p     : BYTE
EXTERNDEF g_w434_shlx_v        : DWORD
EXTERNDEF g_w434_shlx_z        : BYTE
EXTERNDEF g_w434_sarx_v        : DWORD
EXTERNDEF g_w434_shrx_v        : DWORD
EXTERNDEF g_w434_neg_v         : DWORD

_TEXT SEGMENT

; ---- ① andn d==s1: eax = ~eax & ecx = ~0F0F0F0Fh & F0F0F0F0h = F0F0F0F0h ----
wv434_andn_d1 PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov eax, 0F0F0F0Fh
    mov ecx, 0F0F0F0F0h
    andn eax, eax, ecx              ; 期望 F0F0F0F0h
    setc cl                         ; andn 写 CF=0 (probe 0x286) → 0
    mov BYTE PTR g_w434_andn_d1_c, cl
    mov DWORD PTR g_w434_andn_d1_v, eax
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_andn_d1 ENDP

; ---- ② andn d==s2 (载体形): eax = ~ecx & eax ----
wv434_andn_d2 PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov eax, 12345678h
    mov ecx, 0F0F0F0Fh
    andn eax, ecx, eax              ; ~0F0F0F0Fh & 12345678h = 10305070h
    setz cl                         ; 结果非零 → 0
    mov BYTE PTR g_w434_andn_d2_z, cl
    mov DWORD PTR g_w434_andn_d2_v, eax
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_andn_d2 ENDP

; ---- ③ andn d 独立 (91% 主形态): r8d = ~eax & ecx ----
wv434_andn_indep PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov eax, 01234567h
    mov ecx, 089ABCDEFh
    andn r8d, eax, ecx              ; FEDCBA98h & 89ABCDEFh = 88888888h
    mov DWORD PTR g_w434_andn_indep_v, r8d
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_andn_indep ENDP

; ---- ④ andn mem AND 项 (probe: r/m 在第三操作数): r9d = ~r9d & [rsp+20h] ----
wv434_andn_mem PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov r9d, 55AA55AAh
    mov DWORD PTR [rsp+20h], 0FFFFFFFFh
    andn r9d, r9d, DWORD PTR [rsp+20h]  ; AA55AA55h & FFFFFFFFh = AA55AA55h
    setz cl
    mov BYTE PTR g_w434_andn_mem_z, cl
    mov DWORD PTR g_w434_andn_mem_v, r9d
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_andn_mem ENDP

; ---- ⑤ bzhi d==s1 (idx=10): eax = DEADBEEFh & 3FFh = 3EFh ----
wv434_bzhi_d1 PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov eax, 0DEADBEEFh
    mov ecx, 10                     ; idx=10 → mask=3FFh
    bzhi eax, eax, ecx              ; 3EFh, ZF=0
    setz cl
    mov BYTE PTR g_w434_bzhi_d1_z, cl
    mov DWORD PTR g_w434_bzhi_d1_v, eax
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_bzhi_d1 ENDP

; ---- ⑥ bzhi d 独立: r8d = FFFFFFFFh & ((1<<5)-1) = 1Fh ----
wv434_bzhi_indep PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov eax, 0FFFFFFFFh
    mov ecx, 5
    bzhi r8d, eax, ecx              ; 1Fh
    mov DWORD PTR g_w434_bzhi_indep_v, r8d
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_bzhi_indep ENDP

; ---- ⑦ bzhi mem value (probe: r/m=value): r9d = [rsp+20h] & FFh ----
wv434_bzhi_mem PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov DWORD PTR [rsp+20h], 0000FFFFh
    mov ecx, 8
    bzhi r9d, DWORD PTR [rsp+20h], ecx  ; FFh
    setz cl
    mov BYTE PTR g_w434_bzhi_mem_z, cl
    mov DWORD PTR g_w434_bzhi_mem_v, r9d
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_bzhi_mem ENDP

; ---- ⑧ bzhi 边界 idx=32 (probe 0x287: 原值不变 + CF=1) ----
wv434_bzhi_bnd PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov eax, 12345678h
    mov edx, 32                     ; idx = N → 边界
    bzhi eax, eax, edx              ; 原值 12345678h 不变!
    setc cl                         ; CF=1 (probe 修正面 — 折条 CF 补丁)
    mov BYTE PTR g_w434_bzhi_bnd_c, cl
    setz cl                         ; ZF=0
    mov BYTE PTR g_w434_bzhi_bnd_z, cl
    mov DWORD PTR g_w434_bzhi_bnd_v, eax
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_bzhi_bnd ENDP

; ---- ⑨ bzhi idx=0: mask=(1<<0)-1=0 → 结果 0 (与 shift count=0 no-op 不同) ----
wv434_bzhi_idx0 PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov eax, 0FFFFFFFFh
    mov edx, 0
    bzhi eax, eax, edx              ; 0
    setz cl                         ; ZF=1
    mov BYTE PTR g_w434_bzhi_idx0_z, cl
    mov DWORD PTR g_w434_bzhi_idx0_v, eax
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_bzhi_idx0 ENDP

; ---- ⑩ rorx d==s1: eax = F0F0F0F0h ror 7 = E1E1E1E1h ----
wv434_rorx_d1 PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov eax, 0F0F0F0F0h
    rorx eax, eax, 7                ; E1E1E1E1h
    mov DWORD PTR g_w434_rorx_d1_v, eax
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_rorx_d1 ENDP

; ---- ⑪ rorx d 独立 (ClipUp 100% 形态): r8d = 80000001h ror 1 ----
wv434_rorx_indep PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov eax, 80000001h
    rorx r8d, eax, 1                ; C0000000h
    mov DWORD PTR g_w434_rorx_indep_v, r8d
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_rorx_indep ENDP

; ---- ⑫ rorx mem value: r8d = [rsp+20h] ror 4 ----
wv434_rorx_mem PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov DWORD PTR [rsp+20h], 0DEADBEEFh
    rorx r8d, DWORD PTR [rsp+20h], 4    ; FDEADBEEh
    mov DWORD PTR g_w434_rorx_mem_v, r8d
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_rorx_mem ENDP

; ---- ⑬ rorx flagless 全五位保留: or 定旗 → rorx → setz/setc/sets/setp ----
; or eax,3 → eax=C0000003h, ZF=0/SF=1/CF=0/OF=0/PF=1 (0x03 偶) — rorx 不动,
; 四探针 native 与 VM 必须逐位一致 (修复前若照搬 translate_shift 全量装配
; 即分叉 — P1 机制的 G8a 面)。
wv434_rorx_fl PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov eax, 0C0000000h
    or  eax, 3
    rorx ecx, eax, 1                ; E0000001h, flags 原样
    setz cl                         ; 0
    mov BYTE PTR g_w434_rorx_fl_z, cl
    setc cl                         ; 0
    mov BYTE PTR g_w434_rorx_fl_c, cl
    sets cl                         ; 1
    mov BYTE PTR g_w434_rorx_fl_s, cl
    setp cl                         ; 1
    mov BYTE PTR g_w434_rorx_fl_p, cl
    mov DWORD PTR g_w434_rorx_fl_v, ecx
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_rorx_fl ENDP

; ---- ⑭ shlx cnt-in-reg (B.4 通路): r9d = 1 << (r11=5) = 20h ----
wv434_shlx PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov eax, 1
    mov r11d, 5
    shlx r9d, eax, r11d              ; 20h
    setz cl
    mov BYTE PTR g_w434_shlx_z, cl
    mov DWORD PTR g_w434_shlx_v, r9d
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_shlx ENDP

; ---- ⑮ sarx mem value: r8d = [rsp+20h] sar r11=4 = FF000000h ----
wv434_sarx PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov DWORD PTR [rsp+20h], 0F0000000h
    mov r11d, 4
    sarx r8d, DWORD PTR [rsp+20h], r11d
    mov DWORD PTR g_w434_sarx_v, r8d
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_sarx ENDP

; ---- ⑯ shrx d 独立: r9d = F0000000h shr r11=4 = 0F000000h ----
wv434_shrx PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov eax, 0F0000000h
    mov r11d, 4
    shrx r9d, eax, r11d              ; 0F000000h
    mov DWORD PTR g_w434_shrx_v, r9d
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_shrx ENDP

; ---- ⑰ 负例区 (D2 裁决: G8b/文档化 gate): mulx/pdep/pext/blsr/bextr/blsi/
; blsmsk 全部白名单外 → lifter skip → C1 gate 整函数原生保持 (行为 byte-exact,
; stub 数 0) — 证明零逃逸。 ----
wv434_neg PROC
    push rbx
    sub rsp, 28h
    call marker_begin
    mov eax, 2
    mov ecx, 0F0F0F0F0h
    mulx r8d, r9d, ecx              ; 0F0F0F0Fh * 2 → hi=r8, lo=r9
    mov r8d, 0
    pdep r10d, eax, r8d             ; 0 (mask=0)
    pext r11d, eax, ecx             ; pext(2, F0F0F0F0h)
    mov eax, 12345678h
    blsr edx, eax                   ; 12345677h
    mov r11d, 0408h                 ; BEXTR control: start=8, len=4 (reg-only,
                                    ;  probe bextr r,r,r 形)
    bextr r8d, eax, r11d
    blsi r9d, eax                   ; 8
    blsmsk edx, eax                 ; FFFFFFF8h
    and r8d, edx                    ; 白名单尾处理 (可虚拟化)
    mov DWORD PTR g_w434_neg_v, r8d
    call marker_end
    add rsp, 28h
    pop rbx
    ret
wv434_neg ENDP

_TEXT ENDS
END
