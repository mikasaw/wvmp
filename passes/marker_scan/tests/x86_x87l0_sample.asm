; MIT-508 (T60 x87 L0): x87 L0 E2E sample -- in-region x87 faces virtualized
; through the physical-FPU-resident handlers (GAPS MIT-506/507):
;   1. fld/fadd/fstp m64 chain (1.5 + 2.5 = 4.0)
;   2. fild/faddp/fistp integer chain (42 + 8 = 50)
;   3. fld/fsqrt/fchs/fstp m32 (4.0 -> -2.0)
;   4. fcomi + fnstsw face (1.5 vs 4.0 -> C0 bit = less)
;   5. fldcw control-word round trip (0x027F)
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

rgn_x87l0 PROC
    call    marker_begin
    ; -- 1. fld/fadd/fstp m64 chain --
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
    ; -- 4. fcomi + fnstsw (C0 = less: 1.5 < 4.0) --
    fld     dword ptr [g_x_f2]         ; st0 = 1.5f
    fld     dword ptr [g_x_f]          ; st0 = 4.0f, st1 = 1.5f
    fcomi   st, st(1)                  ; 4.0 vs 1.5 -> greater, C0=0
    fnstsw  word ptr [g_x_sw]
    fstp    st(0)                      ; 清 4.0f
    fstp    st(0)                      ; 清 1.5f
    ; -- 5. fldcw / fnstcw round trip --
    fldcw   word ptr [g_x_cw]          ; 0x027F
    fnstcw  word ptr [g_x_cwo]         ; 0x027F
    call    marker_end
    ret
rgn_x87l0 ENDP

.data
ALIGN 8
g_x_a    REAL8 1.5
g_x_b    REAL8 2.5
g_x_out  REAL8 0.0
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

END
