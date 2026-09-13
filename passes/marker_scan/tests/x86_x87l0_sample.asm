; MIT-509 (T61 x87 L0 restart): x87 L0 E2E sample -- in-region x87 faces
; virtualized through the physical-FPU-resident handlers (GAPS MIT-506/507):
;   1. fld/faddp/fstp m64 chain (1.5 + 2.5 = 4.0)
;   2. fild/faddp/fistp integer chain (42 + 8 = 50)
;   3. fld/fsqrt/fchs/fstp m32 (4.0 -> -2.0)
;   4. fcomi + fnstsw mem face (FCOMI only writes EFLAGS -- SW C0 stale)
;   5. fldcw control-word round trip (0x027F)
;   6. fsub D8 form (dst=st0) + fsubr DC form (dst=st(i), r-bit inverted)
;   7. fdivp/fsubrp DE pop forms
;   8. fcomip (self-pop) + seta EFLAGS capture
;   9. fnstsw ax (AX form -> guest Rax slot RMW) + shr/and C0 extract
; All instructions are L0 (no fimul/fprem/fsin L1-L3 faces). Native vs
; packed byte-exact (rc=0 sentinel).

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

PUBLIC rgn_x87l0
PUBLIC g_x_out, g_x_io, g_x_fout, g_x_sw, g_x_cwo
PUBLIC g_x_sub, g_x_subr, g_x_divp, g_x_subrp, g_x_cmp, g_x_swax

rgn_x87l0 PROC
    call    marker_begin
    ; -- 1. fld/faddp/fstp m64 chain --
    fld     qword ptr [g_x_a]
    fld     qword ptr [g_x_b]
    faddp   st(1), st(0)
    fstp    qword ptr [g_x_out]        ; 4.0

    ; -- 2. fild/faddp/fistp integer chain --
    fild    dword ptr [g_x_i]          ; st0 = 42
    fild    dword ptr [g_x_i2]         ; st0 = 8, st1 = 42
    faddp   st(1), st(0)               ; st0 = 50
    fistp   dword ptr [g_x_io]         ; 50
    ; -- 3. fld/fsqrt/fchs/fstp m32 --
    fld     dword ptr [g_x_f]          ; 4.0f
    fsqrt                              ; 2.0f
    fchs                                ; -2.0f
    fstp    dword ptr [g_x_fout]       ; -2.0f
    ; -- 4. fcomi + fnstsw mem (FCOMI 只写 EFLAGS; SW C0 保持陈旧值 --
    ;      两面同刻读 SW, main.c 以 face 9 的抽位互证) --
    fld     dword ptr [g_x_f2]         ; st0 = 1.5f
    fld     dword ptr [g_x_f]          ; st0 = 4.0f, st1 = 1.5f
    fcomi   st, st(1)                  ; 4.0 vs 1.5 -> above (EFLAGS)
    fnstsw  word ptr [g_x_sw]
    fstp    st(0)                      ; 清 4.0f
    fstp    st(0)                      ; 清 1.5f
    ; -- 5. fldcw / fnstcw round trip --
    fldcw   word ptr [g_x_cw]          ; 0x027F
    fnstcw  word ptr [g_x_cwo]         ; 0x027F
    ; -- 6. fsub D8 形 (目的=st0, 显式位=源) + fsubr DC 形 (目的=st(1),
    ;      r 位反转: DC E1 = FSUBR) --
    fld     qword ptr [g_x_a]          ; st0 = 1.5
    fld     qword ptr [g_x_b]          ; st0 = 2.5, st1 = 1.5
    fsub    st, st(1)                  ; st0 = 2.5 - 1.5 = 1.0
    fstp    qword ptr [g_x_sub]        ; 1.0
    fld     qword ptr [g_x_a]          ; st0 = 1.5
    fld     qword ptr [g_x_b]          ; st0 = 2.5, st1 = 1.5
    fsubr   st(1), st(0)               ; st(1) = 2.5 - 1.5 = 1.0
    fstp    st(0)                      ; 清 2.5
    fstp    qword ptr [g_x_subr]       ; 1.0
    ; -- 7. fdivp/fsubrp DE 弹栈矩阵 --
    fld     qword ptr [g_x_a]          ; st0 = 1.5
    fld     qword ptr [g_x_b]          ; st0 = 2.5, st1 = 1.5
    fdivp   st(1), st(0)               ; st(1) = 1.5/2.5 = 0.6, pop
    fstp    qword ptr [g_x_divp]       ; 0.6
    fld     qword ptr [g_x_a]          ; st0 = 1.5
    fld     qword ptr [g_x_b]          ; st0 = 2.5, st1 = 1.5
    fsubrp  st(1), st(0)               ; st(1) = 2.5 - 1.5 = 1.0, pop
    fstp    qword ptr [g_x_subrp]      ; 1.0
    ; -- 8. fcomip (自弹一次) + seta --
    fld     dword ptr [g_x_f2]         ; st0 = 1.5f
    fld     dword ptr [g_x_f]          ; st0 = 4.0f, st1 = 1.5f
    fcomip  st, st(1)                  ; 4.0 vs 1.5 -> above, CF=0,ZF=0, 弹
    fstp    st(0)                      ; 清 1.5f
    seta    byte ptr [g_x_cmp]         ; 1
    ; -- 9. fnstsw ax (AX 形) + shr/and 抽 C0 --
    fld     dword ptr [g_x_f2]         ; st0 = 1.5f
    fld     dword ptr [g_x_f]          ; st0 = 4.0f, st1 = 1.5f
    fnstsw  ax                         ; AX = SW (与 face 4 同 C0/TOP 状态;
                                       ; 两次 fld 不改 C0-C3)
    shr     eax, 8
    and     eax, 1                     ; C0 (SW bit8)
    mov     dword ptr [g_x_swax], eax  ; == (g_x_sw >> 8) & 1
    fstp    st(0)                      ; 清 4.0f
    fstp    st(0)                      ; 清 1.5f
    call    marker_end
    ret
rgn_x87l0 ENDP

.data
ALIGN 8
g_x_a    REAL8 1.5
g_x_b    REAL8 2.5
g_x_out  REAL8 0.0
g_x_sub  REAL8 0.0
g_x_subr REAL8 0.0
g_x_divp REAL8 0.0
g_x_subrp REAL8 0.0
g_x_i    dword 42
g_x_i2   dword 8
g_x_io   dword 0
g_x_f    REAL4 4.0
g_x_f2   REAL4 1.5
g_x_fout REAL4 0.0
g_x_sw   word  0
ALIGN 2
g_x_cw   word  0027Fh
g_x_cwo  word  0
g_x_cmp  dword 0
g_x_swax dword 0

END
