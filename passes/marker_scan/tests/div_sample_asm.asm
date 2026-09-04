; MIT-404: 整数除法族 (cdq/cdqe/cqo + div/idiv) E2E 样本的 MASM helper。
; MSVC x64 不支持 inline asm; volatile 除法只能稳定产 cdq+idiv MEM 形式,
; REG 形式 div/idiv、cdqe、rip 形式除数无法由 C++ 强制 codegen — 真 REG-REG
; 字节由本 helper 直接 emit, 链接进 wvmp_div_sample。
;
; 区域覆盖 (派活单 §B.6):
;   div32_reg  cdq (99) + div ecx        REG 形式, 负被除数经 cdq 变无符号高位
;   div64_reg  cqo (48 99) + div rdi     REG 形式 S64, 商/余双出
;   div32_mem  cdq + div dword [rsp+..]  MEM 形式 (F7 /6 mod=01 SIB)
;   idiv64_reg cqo + idiv rdi            负被除数 -7/2 → q=-3 r=-1 (截断向零, D3.1)
;   idiv32_mem cdq + idiv dword [rsp+..] MEM 形式负数组合
;   cdqe_probe cdqe (48 98)              归一 Movsxd (D1.1), -5 → 0xFFFFFFFFFFFFFFFB
;   div32_rip  cdq + div dword [rip+g]   rip 形式除数 → LoadRva 读通路 (§B.4)
;
; Win64 ABI: rcx/rdx/r8 = 前 3 参, rax = 返回值; callee-saved rbx/rdi 跨
; marker 调用守恒。⚠️ rax 跨 marker_begin/marker_end 会被 clobber (SDK
; magic imm64), 结果先落栈再还原。
; 栈对齐: 调用前 rsp ≡ 0 (mod 16) — 0 push + sub 28h (8-40≡0) 或
; 2 push + sub 38h (8-16-56≡0)。
;
; 栈布局 (0 push + sub 28h): [rsp+0..20h) = shadow, [rsp+20h] = 局部 qword。

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC
EXTERNDEF g_rip_divisor : DWORD

_TEXT SEGMENT

; uint64_t div32_reg(uint32_t a, uint32_t b)
; 返回 (remainder << 32) | quotient。a=0x7FFFFFFF 为正: cdq → edx=0,
; 64 位被除数 = 0x7FFFFFFF, ÷7 商 32 位内。
; ⚠️ div 配负 a 必商溢出 #DE (0xC0000095): cdq 把负 eax 扩成 0xFFFFFFFF
; 高位, 商必超 32 位 — 负数语义属 idiv (D3.1), 主样本 div32 探针只用正 a。
div32_reg PROC
    sub  rsp, 28h
    mov  dword ptr [rsp+20h], ecx       ; a
    mov  dword ptr [rsp+24h], edx       ; b (与 a 共居一个 qword 局部)
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    ; ===== marker region begin =====
    mov  eax, dword ptr [rsp+20h]       ; eax = a
    mov  ecx, dword ptr [rsp+24h]       ; ecx = b
    cdq                                 ; 99: edx:eax = sext(eax)
    div  ecx                            ; F7 F1 (REG): eax=商, edx=余
    mov  r8d, eax                       ; r8 = 商
    mov  eax, edx                       ; eax = 余
    shl  rax, 32                        ; 余 << 32
    or   rax, r8                        ; 打包 (r<<32)|q
    mov  [rsp+20h], rax                 ; 落栈 (rax 跨 marker_end 被 clobber)
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+20h]
    add  rsp, 28h
    ret
div32_reg ENDP

; void div64_reg(uint64_t a, uint64_t b, uint64_t out[2])
; out[0] = 商, out[1] = 余 (cqo 正数 → rdx=0, 128 位被除数高半为 0)。
div64_reg PROC
    push rbx
    push rdi
    sub  rsp, 38h
    mov  [rsp+20h], rcx                 ; a
    mov  [rsp+28h], rdx                 ; b
    mov  rbx, r8                        ; out (callee-saved 跨 marker 调用)
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    ; ===== marker region begin =====
    mov  rax, [rsp+20h]                 ; rax = a
    mov  rdi, [rsp+28h]                 ; rdi = b (除数 REG)
    cqo                                 ; 48 99: rdx:rax = sext(rax)
    div  rdi                            ; 48 F7 F7 (REG): rax=商, rdx=余
    mov  [rbx], rax                     ; out[0] = 商 (Store base=rbx)
    mov  [rbx+8], rdx                   ; out[1] = 余
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    add  rsp, 38h
    pop  rdi
    pop  rbx
    ret
div64_reg ENDP

; uint64_t div32_mem(uint32_t a, uint32_t b)
; 除数走 MEM 形式 div dword ptr [rsp+24h] (F7 /6, mod=01 + SIB rsp)。
div32_mem PROC
    sub  rsp, 28h
    mov  dword ptr [rsp+20h], ecx       ; a
    mov  dword ptr [rsp+24h], edx       ; b — 除数留栈上 (MEM 形式)
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    ; ===== marker region begin =====
    mov  eax, dword ptr [rsp+20h]       ; eax = a
    cdq                                 ; edx:eax = sext(eax)
    div  dword ptr [rsp+24h]            ; F7 /6 MEM: eax=商, edx=余
    mov  r8d, eax
    mov  eax, edx
    shl  rax, 32
    or   rax, r8
    mov  [rsp+20h], rax
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+20h]
    add  rsp, 28h
    ret
div32_mem ENDP

; void idiv64_reg(int64_t a, int64_t b, int64_t out[2])
; 负被除数: -7/2 → out[0]=-3 out[1]=-1 (截断向零, D3.1 — cqo 把 rdx 填 -1,
; native idiv 直接处理符号)。
idiv64_reg PROC
    push rbx
    push rdi
    sub  rsp, 38h
    mov  [rsp+20h], rcx                 ; a
    mov  [rsp+28h], rdx                 ; b
    mov  rbx, r8
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    ; ===== marker region begin =====
    mov  rax, [rsp+20h]                 ; rax = a
    mov  rdi, [rsp+28h]                 ; rdi = b
    cqo                                 ; 48 99: rdx:rax = sext(rax) (负数 → rdx=-1)
    idiv rdi                            ; 48 F7 FF (REG): rax=商, rdx=余
    mov  [rbx], rax
    mov  [rbx+8], rdx
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    add  rsp, 38h
    pop  rdi
    pop  rbx
    ret
idiv64_reg ENDP

; uint64_t idiv32_mem(int32_t a, int32_t b)
; MEM 形式负数组合: -7/2 → (-1 << 32) | (-3) = 0xFFFFFFFFFFFFFFFD。
idiv32_mem PROC
    sub  rsp, 28h
    mov  dword ptr [rsp+20h], ecx       ; a
    mov  dword ptr [rsp+24h], edx       ; b
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    ; ===== marker region begin =====
    mov  eax, dword ptr [rsp+20h]       ; eax = a
    cdq                                 ; edx:eax = sext(eax)
    idiv dword ptr [rsp+24h]            ; F7 /7 MEM: eax=商, edx=余
    mov  r8d, eax
    mov  eax, edx
    shl  rax, 32
    or   rax, r8
    mov  [rsp+20h], rax
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+20h]
    add  rsp, 28h
    ret
idiv32_mem ENDP

; int64_t cdqe_probe(int32_t v)
; cdqe (48 98) — X86_INS_CDQE 分裂枚举, lifter 归一 Movsxd (D1.1)。
; v=-5 → 0xFFFFFFFFFFFFFFFB。
cdqe_probe PROC
    sub  rsp, 28h
    mov  dword ptr [rsp+20h], ecx       ; v
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    ; ===== marker region begin =====
    mov  eax, dword ptr [rsp+20h]       ; eax = v
    cdqe                                ; 48 98: rax = sext(eax)
    mov  [rsp+20h], rax                 ; 64 位结果落栈
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+20h]
    add  rsp, 28h
    ret
cdqe_probe ENDP

; uint64_t div32_rip(uint32_t a)
; rip 形式除数: div dword ptr [g_rip_divisor] — MASM 对标签操作数自动编
; RIP-relative (F7 35 disp32, mod=00 rm=101), capstone 解出 base=RIP →
; 翻译期 RVA + 运行时 LoadRva (+image_base) 读通路 (§B.4 搭车覆盖;
; 无 rip 写, StorRva 属 C4)。a=100, g=7 → 商 14 余 2。
div32_rip PROC
    sub  rsp, 28h
    mov  dword ptr [rsp+20h], ecx       ; a
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    ; ===== marker region begin =====
    mov  eax, dword ptr [rsp+20h]       ; eax = a
    cdq                                 ; edx:eax (正数 → edx=0)
    div  dword ptr [g_rip_divisor]
    mov  r8d, eax
    mov  eax, edx
    shl  rax, 32
    or   rax, r8
    mov  [rsp+20h], rax
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+20h]
    add  rsp, 28h
    ret
div32_rip ENDP

_TEXT ENDS

END
