; MIT-498 (T51 follow-up, T52): x86 fastcall / custom-convention callee E2E
; sample -- in-region callgates whose callees take REGISTER arguments:
;   1. fastcall two-reg-arg callee (ecx/edx = arg0/arg1) -- the MSVC
;      __fastcall face; bridge step 2.7 feeds guest ecx/edx.
;   2. custom-convention shift helper (edx:eax value + cl count, the
;      __aullshr pattern) -- the exact face whose mis-bridge produced the
;      wv_mul64hi wrong values (GAPS MIT-497).
;   3. fastcall callee returning the edx:eax 64-bit pair -- step 5.5
;      storeback face (__allmul-style high half).
; All callees are pure-register-convention (no stack args) so the region's
; net stack depth stays 0 at Halt (the arg_count/cleanup-convention static
; channel is a separate pending item, X5b #4). Native vs packed byte-exact
; (rc=0 sentinel).

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

PUBLIC rgn_fastcall
PUBLIC g_fc_add, g_fc_shr_hi, g_fc_shr_lo
PUBLIC g_fc_pair_hi, g_fc_pair_lo

; fastcall: eax = ecx + edx (arg0/arg1 live in ecx/edx per __fastcall).
fc_add PROC
    mov     eax, ecx
    add     eax, edx
    ret
fc_add ENDP

; custom convention (the __aullshr core): edx:eax >>= cl, in place.
fc_shr64 PROC
    shr     edx, 1
    rcr     eax, 1
    dec     cl
    jnz     fc_shr64
    ret
fc_shr64 ENDP

; fastcall: edx:eax = (ecx << 32) | edx -- register-arg in, 64-bit pair out.
fc_pair PROC
    mov     eax, edx
    mov     edx, ecx
    ret
fc_pair ENDP

rgn_fastcall PROC
    call    marker_begin
    ; -- 1. fastcall two-reg-arg callee (bridge ecx/edx) --
    mov     ecx, 11111111h
    mov     edx, 22222222h
    call    fc_add                     ; callgate RVA form
    mov     [g_fc_add], eax            ; 33333333h
    ; -- 2. custom-convention shift helper (cl count + edx:eax value) --
    mov     edx, 12345678h             ; hi
    mov     eax, 9ABCDEF0h             ; lo
    mov     cl, 4                      ; shift count via cl (__aullshr face)
    call    fc_shr64                   ; edx:eax >>= 4 in place
    mov     [g_fc_shr_hi], edx         ; 01234567h
    mov     [g_fc_shr_lo], eax         ; 89ABCDEFh
    ; -- 3. register-arg callee returning the edx:eax pair --
    mov     ecx, 100h                  ; out hi
    mov     edx, 200h                  ; out lo
    call    fc_pair                    ; edx:eax = 00000100:00000200
    mov     [g_fc_pair_lo], eax        ; 200h
    mov     [g_fc_pair_hi], edx        ; 100h
    call    marker_end
    ret
rgn_fastcall ENDP

.data
ALIGN 4
g_fc_add    dword 0
g_fc_shr_hi dword 0
g_fc_shr_lo dword 0
g_fc_pair_hi dword 0
g_fc_pair_lo dword 0

END
