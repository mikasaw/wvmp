; MIT-413 (G2): 跳转表残余形态 E2E 样本 MASM 宿主 — 真字节直写本单新形态
; (MSVC x64 不支持 inline asm; clang/GCC 本机不存在, 派活单 §F.1 披露"无真
; 编译器产物, MASM 拼写等价字节形态"):
;
; 正样本 5 个 (全部 REQUIRE_REAL 真虚拟化, 匹配器新形态):
;   ① wv_jt8_abs    —— REG 源 8B 绝对表 (无 add): mov rax,[rcx+rax*8] + jmp rax,
;                      表项 = 完整 VA (dq case), 翻译期减 image_base 还原 RVA
;                      (G2-a abs; lea 表基址)。
;   ② wv_jt8_delta  —— REG 源 8B delta 表 (带 add): mov rax,[rcx+rax*8] +
;                      add rax,rcx + jmp rax, 表项 = case − 表基址 (负值两补码,
;                      表在函数后 .text: 同段算术 MASM 可算; G2-a delta)。
;   ③ wv_jt8_djmp   —— REG 源 delta-from-jmp (GCC `.L4` 风格): lea 基址 = jmp
;                      指令地址 (jt8j_site), 表项 = case − jt8j_site; 表体经
;                      位移 (jt8j_tbl−jt8j_site) 同基址单寄存器读取; add 还原。
;                      基址即跳转点时与 delta-from-base 静态不可分 (§F.3 实测
;                      裁决: 取区判据通过者), 匹配器 note 报 reg-8B-delta。
;   ④ wv_jtm_abs    —— MEM 源直跳 (G2-b): lea rcx,[rip+tbl] + jmp qword ptr
;                      [rcx+rax*8], 表项 = 完整 VA。mem 源跳转的目标即表项 —
;                      delta 表项在 x86 上原生即坏 (CPU 不加基址), 实测只有
;                      绝对 VA 语义可进 (如实披露, §A.3 三语义候选序)。
;   ⑤ wv_jtm_movabs —— MEM 源 + movabs 基址 (表基址 = disp 常量, 派活单 §A.3
;                      "表基址来自 disp 常量或 lea" 两形态之一):
;                      mov rcx, OFFSET tbl (48 B9 imm64) + jmp [rcx+rax*8]。
;
; 负样本 3 个 (照旧 C1 gate, packed 与 native 逐字节一致; main 只传安全 idx):
;   ⑥ wv_jt_undef   —— 同 ② 形态但前块尾部无 `cmp idx,7; ja` 防御 (表长不可推
;                      → G2-c 永久 gate, D2 裁决); 块边界用 test+jz 制造。
;   ⑦ wv_jt_oob     —— 8B 绝对表一项指向另一函数 wv_other_fn (区域外) → 区判据
;                      失败 → gate。
;   ⑧ wv_jt_data    —— 8B 绝对表一项指向数据段全局 g_data_var → 目标非已 lift
;                      指令地址 → gate。
;
; 区域语义: 每函数区域 = [call marker_begin 之后, call marker_end 处); case
; body 各为仅表可达的块 (409 lifter 死代码保留机制), join 块末尾
; `mov [rsp+24], rax` 结果 spill (marker_end clobber rax, pitfall #36) →
; fallthrough → Halt → stub 恢复 → jmp end_rva (marker_end call, 原生执行)。
; 区域无 rsp 调整 (entry rsp 恒等, Halt 恢复契约) — prologue 的 push/sub 均在
; marker_begin 之前 (区外)。
;
; Win64 ABI: rcx = idx (未用, 切换值经 g_sel 全局; volatile 防折叠)。
; ⚠️ 负例 native 执行会真读毒表项 — main 跳过毒 idx (oob/data 的 idx=3)。
; ⚠️ 表在函数 ret 之后 (.text 同段): 仅供 delta 同段算术; 绝对 VA 表在 .rdata
; (ADDR64 重定位, 链接期 VA — 翻译期减 optional header ImageBase 得 RVA,
; ASLR 无关: 文件内值与 header 同为链接期常量)。

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC
EXTERNDEF g_sel : QWORD
EXTERNDEF g_data_var : QWORD
EXTERNDEF wv_other_fn : PROC

_TEXT SEGMENT

; ============ ① REG 源 8B 绝对表 ============
wv_jt8_abs PROC
    push rbx
    sub  rsp, 56
    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mov  rax, QWORD PTR [g_sel]      ; idx 载入 (block A 首条)
    cmp  rax, 7
    ja   jt8a_default                ; 防御常数 (cmp idx,7; ja → K=8)
    mov  rax, QWORD PTR [g_sel]      ; il: idx 重载入 (block B, MSVC /Od 同款)
    lea  rcx, [jt8a_tbl]             ; 表基址 (rip-relative)
    mov  rax, QWORD PTR [rcx+rax*8]  ; 8B 表项读入 (无 add → 绝对 VA 语义)
    jmp  rax
jt8a_case0:: mov  rax, 100h
    jmp jt8a_join
jt8a_case1:: mov  rax, 101h
    jmp jt8a_join
jt8a_case2:: mov  rax, 102h
    jmp jt8a_join
jt8a_case3:: mov  rax, 103h
    jmp jt8a_join
jt8a_case4:: mov  rax, 104h
    jmp jt8a_join
jt8a_case5:: mov  rax, 105h
    jmp jt8a_join
jt8a_case6:: mov  rax, 106h
    jmp jt8a_join
jt8a_case7:: mov  rax, 107h
    jmp jt8a_join
jt8a_default: mov rax, 1FFh
jt8a_join: mov [rsp+24], rax         ; 结果 spill (marker_end clobber rax)
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    pop  rbx
    ret
wv_jt8_abs ENDP

; ============ ② REG 源 8B delta 表 (表基址) ============
wv_jt8_delta PROC
    push rbx
    sub  rsp, 56
    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mov  rax, QWORD PTR [g_sel]
    cmp  rax, 7
    ja   jt8d_default
    mov  rax, QWORD PTR [g_sel]
    lea  rcx, [jt8d_tbl]             ; 表基址
    mov  rax, QWORD PTR [rcx+rax*8]  ; 8B 表项
    add  rax, rcx                    ; delta + 基址 → 目标 VA
    jmp  rax
jt8d_case0:: mov  rax, 200h
    jmp jt8d_join
jt8d_case1:: mov  rax, 201h
    jmp jt8d_join
jt8d_case2:: mov  rax, 202h
    jmp jt8d_join
jt8d_case3:: mov  rax, 203h
    jmp jt8d_join
jt8d_case4:: mov  rax, 204h
    jmp jt8d_join
jt8d_case5:: mov  rax, 205h
    jmp jt8d_join
jt8d_case6:: mov  rax, 206h
    jmp jt8d_join
jt8d_case7:: mov  rax, 207h
    jmp jt8d_join
jt8d_default: mov rax, 2FFh
jt8d_join: mov [rsp+24], rax
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    pop  rbx
    ret
jt8d_tbl dq jt8d_case0 - jt8d_tbl, jt8d_case1 - jt8d_tbl, jt8d_case2 - jt8d_tbl, jt8d_case3 - jt8d_tbl
         dq jt8d_case4 - jt8d_tbl, jt8d_case5 - jt8d_tbl, jt8d_case6 - jt8d_tbl, jt8d_case7 - jt8d_tbl
wv_jt8_delta ENDP

; ============ ③ REG 源 delta-from-jmp (GCC .L4 风格) ============
wv_jt8_djmp PROC
    push rbx
    sub  rsp, 56
    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mov  rax, QWORD PTR [g_sel]
    cmp  rax, 7
    ja   jt8j_default
    mov  rax, QWORD PTR [g_sel]
    lea  rcx, [jt8j_site]            ; 基址 = jmp 指令地址 (.L4 语义)
    mov  rax, QWORD PTR [rcx+rax*8 + (jt8j_tbl - jt8j_site)] ; 表体经位移
                                     ; 偏移 (同段常量, 同基址单寄存器形态)
    add  rax, rcx                    ; 表项 + jmp 地址 → 目标 VA
jt8j_site:
    jmp  rax
jt8j_case0:: mov  rax, 300h
    jmp jt8j_join
jt8j_case1:: mov  rax, 301h
    jmp jt8j_join
jt8j_case2:: mov  rax, 302h
    jmp jt8j_join
jt8j_case3:: mov  rax, 303h
    jmp jt8j_join
jt8j_case4:: mov  rax, 304h
    jmp jt8j_join
jt8j_case5:: mov  rax, 305h
    jmp jt8j_join
jt8j_case6:: mov  rax, 306h
    jmp jt8j_join
jt8j_case7:: mov  rax, 307h
    jmp jt8j_join
jt8j_default: mov rax, 3FFh
jt8j_join: mov [rsp+24], rax
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    pop  rbx
    ret
jt8j_tbl dq jt8j_case0 - jt8j_site, jt8j_case1 - jt8j_site, jt8j_case2 - jt8j_site, jt8j_case3 - jt8j_site
         dq jt8j_case4 - jt8j_site, jt8j_case5 - jt8j_site, jt8j_case6 - jt8j_site, jt8j_case7 - jt8j_site
wv_jt8_djmp ENDP

; ============ ④ MEM 源直跳 (lea 基址) ============
wv_jtm_abs PROC
    push rbx
    sub  rsp, 56
    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mov  rax, QWORD PTR [g_sel]
    cmp  rax, 7
    ja   jtma_default
    mov  rax, QWORD PTR [g_sel]
    lea  rcx, [jtma_tbl]             ; 表基址 (lea)
    jmp  qword ptr [rcx+rax*8]       ; MEM 源直跳 (FF 24 C1)
jtma_case0:: mov  rax, 400h
    jmp jtma_join
jtma_case1:: mov  rax, 401h
    jmp jtma_join
jtma_case2:: mov  rax, 402h
    jmp jtma_join
jtma_case3:: mov  rax, 403h
    jmp jtma_join
jtma_case4:: mov  rax, 404h
    jmp jtma_join
jtma_case5:: mov  rax, 405h
    jmp jtma_join
jtma_case6:: mov  rax, 406h
    jmp jtma_join
jtma_case7:: mov  rax, 407h
    jmp jtma_join
jtma_default: mov rax, 4FFh
jtma_join: mov [rsp+24], rax
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    pop  rbx
    ret
wv_jtm_abs ENDP

; ============ ⑤ MEM 源直跳 (movabs 基址 = disp 常量) ============
wv_jtm_movabs PROC
    push rbx
    sub  rsp, 56
    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mov  rax, QWORD PTR [g_sel]
    cmp  rax, 7
    ja   jtmm_default
    mov  rax, QWORD PTR [g_sel]
    mov  rcx, OFFSET jtmm_tbl        ; movabs 基址 (48 B9 imm64, 链接期 VA)
    jmp  qword ptr [rcx+rax*8]
jtmm_case0:: mov  rax, 500h
    jmp jtmm_join
jtmm_case1:: mov  rax, 501h
    jmp jtmm_join
jtmm_case2:: mov  rax, 502h
    jmp jtmm_join
jtmm_case3:: mov  rax, 503h
    jmp jtmm_join
jtmm_case4:: mov  rax, 504h
    jmp jtmm_join
jtmm_case5:: mov  rax, 505h
    jmp jtmm_join
jtmm_case6:: mov  rax, 506h
    jmp jtmm_join
jtmm_case7:: mov  rax, 507h
    jmp jtmm_join
jtmm_default: mov rax, 5FFh
jtmm_join: mov [rsp+24], rax
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    pop  rbx
    ret
wv_jtm_movabs ENDP

; ============ ⑥ 无防御负例 (G2-c) ============
; 形态同 ② 但前块尾部无 `cmp idx,7; ja` — 用 test+jz 制造块边界 (cond=E
; 非 A/Ae → 防御解析失败 → "未检出防御常数" note)。native 执行 idx∈[0,7]
; 才安全 (无边界检查, 表外读取越界)。
wv_jt_undef PROC
    push rbx
    sub  rsp, 56
    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mov  rax, QWORD PTR [g_sel]      ; idx 载入 (block A)
    test rax, rax                    ; 块边界 (非防御 — cond=E)
    jz   jtun_case0
    mov  rax, QWORD PTR [g_sel]      ; il
    lea  rcx, [jtun_tbl]
    mov  rax, QWORD PTR [rcx+rax*8]
    add  rax, rcx
    jmp  rax
jtun_case0:: mov  rax, 600h
    jmp jtun_join
jtun_case1:: mov  rax, 601h
    jmp jtun_join
jtun_case2:: mov  rax, 602h
    jmp jtun_join
jtun_case3:: mov  rax, 603h
    jmp jtun_join
jtun_case4:: mov  rax, 604h
    jmp jtun_join
jtun_case5:: mov  rax, 605h
    jmp jtun_join
jtun_case6:: mov  rax, 606h
    jmp jtun_join
jtun_case7:: mov  rax, 607h
    jmp jtun_join
jtun_join: mov [rsp+24], rax
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    pop  rbx
    ret
jtun_tbl dq jtun_case0 - jtun_tbl, jtun_case1 - jtun_tbl, jtun_case2 - jtun_tbl, jtun_case3 - jtun_tbl
         dq jtun_case4 - jtun_tbl, jtun_case5 - jtun_tbl, jtun_case6 - jtun_tbl, jtun_case7 - jtun_tbl
wv_jt_undef ENDP

; ============ ⑦ 目标出区负例 ============
; 8B 绝对表一项 = wv_other_fn (另一函数入口) → 目标不在 [begin,end) → gate。
wv_jt_oob PROC
    push rbx
    sub  rsp, 56
    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mov  rax, QWORD PTR [g_sel]
    cmp  rax, 7
    ja   jtoo_default
    mov  rax, QWORD PTR [g_sel]
    lea  rcx, [jtoo_tbl]
    mov  rax, QWORD PTR [rcx+rax*8]
    jmp  rax
jtoo_case0:: mov  rax, 700h
    jmp jtoo_join
jtoo_case1:: mov  rax, 701h
    jmp jtoo_join
jtoo_case2:: mov  rax, 702h
    jmp jtoo_join
jtoo_case3:: mov  rax, 703h
    jmp jtoo_join
jtoo_case4:: mov  rax, 704h
    jmp jtoo_join
jtoo_case5:: mov  rax, 705h
    jmp jtoo_join
jtoo_case6:: mov  rax, 706h
    jmp jtoo_join
jtoo_case7:: mov  rax, 707h
    jmp jtoo_join
jtoo_default: mov rax, 7FFh
jtoo_join: mov [rsp+24], rax
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    pop  rbx
    ret
wv_jt_oob ENDP

; ============ ⑧ 表项指向数据段负例 ============
; 8B 绝对表一项 = g_data_var (.data 全局) → 目标非已 lift 指令地址 → gate。
wv_jt_data PROC
    push rbx
    sub  rsp, 56
    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXXZ
    mov  rax, QWORD PTR [g_sel]
    cmp  rax, 7
    ja   jtda_default
    mov  rax, QWORD PTR [g_sel]
    lea  rcx, [jtda_tbl]
    mov  rax, QWORD PTR [rcx+rax*8]
    jmp  rax
jtda_case0:: mov  rax, 800h
    jmp jtda_join
jtda_case1:: mov  rax, 801h
    jmp jtda_join
jtda_case2:: mov  rax, 802h
    jmp jtda_join
jtda_case3:: mov  rax, 803h
    jmp jtda_join
jtda_case4:: mov  rax, 804h
    jmp jtda_join
jtda_case5:: mov  rax, 805h
    jmp jtda_join
jtda_case6:: mov  rax, 806h
    jmp jtda_join
jtda_case7:: mov  rax, 807h
    jmp jtda_join
jtda_default: mov rax, 8FFh
jtda_join: mov [rsp+24], rax
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+24]
    add  rsp, 56
    pop  rbx
    ret
wv_jt_data ENDP

_TEXT ENDS

; ---- 绝对 VA 表 (.rdata, ADDR64 重定位: 文件内值 = 链接期 VA) ----
_RDATA SEGMENT READONLY
ALIGN 8
jt8a_tbl dq jt8a_case0, jt8a_case1, jt8a_case2, jt8a_case3
         dq jt8a_case4, jt8a_case5, jt8a_case6, jt8a_case7
jtma_tbl dq jtma_case0, jtma_case1, jtma_case2, jtma_case3
         dq jtma_case4, jtma_case5, jtma_case6, jtma_case7
jtmm_tbl dq jtmm_case0, jtmm_case1, jtmm_case2, jtmm_case3
         dq jtmm_case4, jtmm_case5, jtmm_case6, jtmm_case7
jtoo_tbl dq jtoo_case0, jtoo_case1, jtoo_case2, wv_other_fn
         dq jtoo_case4, jtoo_case5, jtoo_case6, jtoo_case7
jtda_tbl dq jtda_case0, jtda_case1, jtda_case2, g_data_var
         dq jtda_case4, jtda_case5, jtda_case6, jtda_case7
_RDATA ENDS

END
