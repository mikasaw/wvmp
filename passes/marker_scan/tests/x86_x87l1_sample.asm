; MIT-510 (T62 x87 L1-L4): x87 L1-L4 E2E sample -- in-region faces virtualized
; through the physical-FPU-resident handlers:
;   1. fcom st(i) + fnstsw mem (C0 = SW bit8; st0=2.5 vs st(1)=1.5 → C0=0)
;   2. ftst (st0=0 → C3=1) + fnstsw ax + shr/and extract
;   3. fxch st(1) swap chain (1.25 / 3.75)
;   4. fcomi + fcmovnb (above → move st(1))
;   5. fldpi/fldl2e + fmulp + f2xm1 + fld1 + faddp  → e^π
;   6. fprem (1.5 mod 2.5 = 1.5, 截断商 0)
;   7. fninit 全复位 (CW=0x037F, SW=0x0000)
; All instructions are L1-L2 (fldenv/fsave L4 memory-block faces remain gated).

.686p
.model flat, c

.code

    align 16
    REPEAT 80
    nop
    ENDM

marker_begin PROC
    push ebp
    mov     ebp, esp
    sub     esp, 10h
    mov     eax, 31474542h
    mov     dword ptr [ebp-8], 504D5657h
    mov     dword ptr [ebp-4], eax
    mov     esp, ebp
    pop     ebp
    ret
marker_begin ENDP

marker_end PROC
    push ebp
    mov     ebp, esp
    sub     esp, 10h
    mov     eax, 31444E45h
    mov     dword ptr [ebp-8], 504D5657h
    mov     dword ptr [ebp-4], eax
    mov     esp, ebp
    pop     ebp
    ret
marker_end ENDP

PUBLIC rgn_x87l1
PUBLIC g_l1_fx0, g_l1_fx1, g_l1_cm, g_l1_sc, g_l1_pm
PUBLIC g_l1_c0, g_l1_c0b, g_l1_c3, g_l1_cw2, g_l1_sw2

rgn_x87l1 PROC
    call    marker_begin
    ; -- 1. fcom st(i) + fnstsw mem (C0 = SW bit8; st0=2.5 vs st(1)=1.5) --
    fld     dword ptr [g_l1_a]         ; st0 = 1.5f
    fld     dword ptr [g_l1_b]         ; st0 = 2.5f, st1 = 1.5f
    fcom    st(1)                      ; st0(2.5) vs st(1)(1.5) → above
    fnstsw  word ptr [g_l1_c0]         ; C0 位 = 0
    fstp    st(0)                      ; 清 2.5f
    fstp    st(0)                      ; 清 1.5f
    ; -- 1b. fcomp st(1) + 弹栈 (交换序 → below → C0 = 1) --
    fld     dword ptr [g_l1_b]         ; st0 = 2.5f
    fld     dword ptr [g_l1_a]         ; st0 = 1.5f, st1 = 2.5f
    fcomp   st(1)                      ; st0(1.5) vs st(1)(2.5) → below, 弹
    fnstsw  word ptr [g_l1_c0b]        ; C0 位 = 1
    fstp    st(0)                      ; 清 2.5f
    ; -- 2. ftst: st0=0 → equal → C3 (bit14); fnstsw ax + 抽位 --
    fldz
    ftst
    fnstsw  ax
    shr     eax, 14
    and     eax, 1
    mov     dword ptr [g_l1_c3], eax   ; C3 = 1
    fstp    st(0)
    ; -- 3. fxch st(1) 交换链 --
    fld     qword ptr [g_l1_x]         ; st0 = 1.25
    fld     qword ptr [g_l1_y]         ; st0 = 3.75, st1 = 1.25
    fxch    st(1)                      ; st0 = 1.25, st1 = 3.75
    fstp    qword ptr [g_l1_fx0]       ; fx0 = 1.25
    fstp    qword ptr [g_l1_fx1]       ; fx1 = 3.75
    ; -- 4. fcomi + fcmovnb (EFLAGS 面经物理捕获) --
    fld     dword ptr [g_l1_a]         ; st0 = 1.5f
    fld     dword ptr [g_l1_b]         ; st0 = 2.5f, st1 = 1.5f
    fcomi   st, st(1)                  ; 2.5 vs 1.5 → above (CF=0, ZF=0)
    fcmovnb st, st(1)                  ; nb 成立 → move
    fstp    dword ptr [g_l1_cm]        ; cm = 1.5f (被 move 的 st(1))
    fstp    st(0)                      ; 清 2.5f
    ; -- 5. 常量 + 超越: fldpi 入栈 → 0.5 → f2xm1 → +1 = √2 --
    fldpi                              ; st0 = π (常量面; 留栈)
    fld     dword ptr [g_l1_h]         ; st0 = 0.5, st1 = π
    f2xm1                              ; 2^0.5 − 1 = √2 − 1 (|x|≤1 合法域)
    fld1
    faddp  st(1), st(0)                ; √2 ≈ 1.41421356...
    fstp    qword ptr [g_l1_sc]        ; sc = √2 (REAL8 全精度)
    fstp    st(0)                      ; 清 π
    ; -- 6. fprem: 1.5 mod 2.5 = 1.5 (截断商 0) --
    fld     dword ptr [g_l1_b]         ; st0 = 2.5f
    fld     dword ptr [g_l1_a]         ; st0 = 1.5f, st1 = 2.5f
    fprem                              ; st0 = 1.5 (商 0)
    fstp    qword ptr [g_l1_pm]        ; pm = 1.5
    fstp    st(0)                      ; 清 2.5f
    ; -- 7. fninit 全复位 (CW=0x037F, SW=0x0000) --
    fninit
    fnstcw  word ptr [g_l1_cw2]
    fnstsw  word ptr [g_l1_sw2]
    call    marker_end
    ret
rgn_x87l1 ENDP

.data
ALIGN 8
g_l1_x   REAL8 1.25
g_l1_y   REAL8 3.75
g_l1_fx0 REAL8 0.0
g_l1_fx1 REAL8 0.0
g_l1_sc  REAL8 0.0
g_l1_pm  REAL8 0.0
g_l1_h   dword 0.5
g_l1_a   dword 1.5
g_l1_b   dword 2.5
g_l1_c0  word  0
g_l1_c0b word  0
g_l1_c3  dword 0
g_l1_cm  dword 0
g_l1_cw2 word  0
g_l1_sw2 word  0

END
