; MIT-450 (X5) B.3 (1): x86 x87 gate E2E sample -- R-SSE-only ruling face
; (x64 MIT-418 x87_gate_sample counterpart, dedicated per-function form).
;
; rgn_x87_gate -- DESIGNED permanent gate negative: the marked region contains
;                 x87 only (fld/fadd/fmul/fdiv/fstp); the lifter has no x87
;                 case -> the whole function stays native (C1 gate note in
;                 the protect log). Callable; byte-exact by native double run.
;                 Never extended: x87 is permanently unsupported (R-SSE-only).
; rgn_x87_helper -- pure GP integer face, provides the REQUIRE_REAL >=1 stub.
; fdiv (D8 /4) and fld (D9 /0) cover the GAPS x87-section face named in the
; dispatch (fld/fdiv native whole-function).

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

rgn_x87_gate PROC
    call    marker_begin
    fld     dword ptr [g_fx]                ; st0 = g_fx
    fadd    dword ptr [g_fx]                ; st0 = 2*g_fx
    fmul    dword ptr [g_fy]                ; st0 = 2*g_fx*g_fy
    fld     dword ptr [g_fy]
    fdiv    dword ptr [g_fx]                ; st0 = g_fy/g_fx, st1 = product
    fadd                                    ; st0 = product + ratio
    fstp    dword ptr [g_fx_out]            ; store + pop
    call    marker_end
    ret
rgn_x87_gate ENDP

; -- pure GP helper: REQUIRE_REAL >=1 stub source --
rgn_x87_helper PROC
    call    marker_begin
    mov     eax, 0C0DE0000h
    xor     eax, 0000BEEFh
    add     eax, 12345678h
    ror     eax, 11
    mov     dword ptr [g_xh_out], eax
    call    marker_end
    ret
rgn_x87_helper ENDP

.data
PUBLIC g_fx, g_fy, g_fx_out, g_xh_out
g_fx     dd 2.0
g_fy     dd 3.5
g_fx_out dd 0
g_xh_out dd 0

END
