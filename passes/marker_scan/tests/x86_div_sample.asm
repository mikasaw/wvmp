; MIT-X7 (MIT-455) B.2: x86 div/idiv E2E sample -- in-region division faces
; (unsigned div + signed idiv with cdq prologue) virtualized through the
; 32-bit build_div_idiv_x86 handlers (MIT-455 batch 2, x64 build_div_idiv
; mirror; 453 b59b residual face closure). Region content (net stack depth
; 0 at Halt):
;   1. div reg form: 100 / 7 -> q=14 r=2 (both halves observed).
;   2. div mem form: dividend 0xFFFFFFFF / divisor dword 10h -> q=0FFFFFFFh
;      r=Fh (translator folds the mem divisor via emit_load).
;   3. idiv with cdq: -100 / 7 -> q=-14 r=-2 (signed pair, edx:eax from
;      cdq sign extension -- the real-code idiv shape).
;   4. idiv negative divisor: 100 / -7 -> q=-14 r=2 (C truncation semantics).
; Native vs packed byte-exact (rc=0 sentinel). Divide-by-zero (#DE) is NOT
; executed here -- the crash-form parity is a documented D2.1 alignment
; (x64 build_div_idiv same-口径), not a battery/sample face.

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

PUBLIC rgn_div
PUBLIC g_dv_q1, g_dv_r1, g_dv_q2, g_dv_r2
PUBLIC g_dv_q3, g_dv_r3, g_dv_q4, g_dv_r4
PUBLIC g_dv_ten

rgn_div PROC
    call    marker_begin
    ; -- 1. div reg form: 100 / 7 -> q=14 r=2 (pinned real-code shape:
    ;       xor edx,edx before unsigned div) --
    mov     eax, 100
    xor     edx, edx
    mov     ecx, 7
    div     ecx                         ; F7 F1
    mov     [g_dv_q1], eax
    mov     [g_dv_r1], edx
    ; -- 2. div mem form: 0FFFFFFFFh / dword 10h -> q=0FFFFFFFh r=Fh --
    mov     eax, 0FFFFFFFFh
    xor     edx, edx
    div     dword ptr [g_dv_ten]        ; F7 35 (mem divisor)
    mov     [g_dv_q2], eax
    mov     [g_dv_r2], edx
    ; -- 3. idiv with cdq: -100 / 7 -> q=-14 r=-2 --
    mov     eax, -100
    cdq                                 ; 99 (edx = sext(eax))
    mov     ecx, 7
    idiv    ecx                         ; F7 F9
    mov     [g_dv_q3], eax
    mov     [g_dv_r3], edx
    ; -- 4. idiv negative divisor: 100 / -7 -> q=-14 r=2 --
    mov     eax, 100
    cdq
    mov     ecx, -7
    idiv    ecx                         ; F7 F9
    mov     [g_dv_q4], eax
    mov     [g_dv_r4], edx
    call    marker_end
    ret
rgn_div ENDP

.data
ALIGN 4
g_dv_q1   dword 0
g_dv_r1   dword 0
g_dv_q2   dword 0
g_dv_r2   dword 0
g_dv_q3   dword 0
g_dv_r3   dword 0
g_dv_q4   dword 0
g_dv_r4   dword 0
g_dv_ten  dword 10h

END
