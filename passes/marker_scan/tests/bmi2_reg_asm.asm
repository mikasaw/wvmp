; MIT-534 (G8b 通路 A): BMI2 reg 形样本 — mulx/pdep/pext 全 reg 操作数
; (v1 词面; /Od intrinsic 生成 mem 形走 C1 gate, 词面虚拟化由本 asm 证明)。
; ML64/keystone 语序 (2026-09-28 终审探针): mulx 首目的=高位。
;
; bmi2_reg(dst=rcx 16B, a=rdx, m=r8): mulx(a×a) + pdep(a,m) + pext(pdep,m)。

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

bmi2_reg PROC
    sub   rsp, 28h                    ; MIT-475: shadow space + alignment
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    mov   r9, rdx                     ; src (reg 形第三操作数)
    mulx  r11, r10, r9                ; MASM/keystone 语序首=高位: r11=hi, r10=lo (a × a)
    mov   [rcx], r10
    mov   [rcx+8], r11
    mov   rax, rdx                    ; 值 = a
    mov   r9, r8                      ; 掩码 = m
    pdep  r10, rax, r9                ; r10 = pdep(a, m)
    mov   [rcx+16], r10
    pext  r11, r10, r9                ; r11 = pext(pdep(a,m), m) = a 低 popcount 位
    mov   [rcx+24], r11
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    xor eax, eax
    add   rsp, 28h
    ret
bmi2_reg ENDP

_TEXT ENDS
END
