; MIT-454 (X6 B.1): x86 push-imm E2E sample -- in-region push immediate
; shapes (multi-width + boundary forms) virtualized through the single-op
; Push/Imm path (a_kind=Imm, handler xpimm_ branch reads the aux dword).
; Region content (net stack depth 0 at Halt -- balanced push/pop pairs):
;   1. push imm32 (68 iv): 12345678h / FFFFFFFFh / 80h (imm8 unsigned
;      overflow boundary -> 68 form) -- each popped into a register and
;      stored to its own global.
;   2. push imm8 (6A ib): 0 / -5 (sext boundary) / 7Fh (positive boundary).
;   3. call-arg push-imm pair: push 22222222h / push 11111111h / call
;      helper (callgate reads the pushed dwords from the guard zone) /
;      add esp,8 (cdecl cleanup inside the region).
; Native vs packed byte-exact (rc=0 sentinel); MASM encoding faces are
; pinned by dumpbin in the X6 report (68 vs 6A per form).

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

PUBLIC rgn_pushimm
PUBLIC g_pi_imm32a, g_pi_imm32b, g_pi_imm32c
PUBLIC g_pi_imm8a, g_pi_imm8b, g_pi_imm8c
PUBLIC g_pi_ret, g_pi_arg
; cdecl helper: returns arg0 + arg1 (reads the pushed imm dwords from its
; stack frame; same shape as pf_helper in the pushform sample but the
; pushed values are immediates).
pi_helper PROC
    mov     eax, [esp+4]                ; arg0 = last push (22222222h)
    add     eax, [esp+8]                ; arg1 = 11111111h
    ret
pi_helper ENDP

rgn_pushimm PROC
    call    marker_begin
    ; -- 1. push imm32 (68 iv) forms, pop-and-observe each --
    push    12345678h                   ; 68 78 56 34 12
    pop     eax
    mov     [g_pi_imm32a], eax
    push    0FFFFFFFFh                  ; 68 FF FF FF FF (imm32 -1 face)
    pop     eax
    mov     [g_pi_imm32b], eax
    push    80h                         ; 68 80 00 00 00 (128 does not fit imm8)
    pop     eax
    mov     [g_pi_imm32c], eax
    ; -- 2. push imm8 (6A ib) forms --
    push    0                           ; 6A 00 (push-0 boundary)
    pop     eax
    mov     [g_pi_imm8a], eax
    push    -5                          ; 6A FB (sext -5 -> FFFFFFFB)
    pop     eax
    mov     [g_pi_imm8b], eax
    push    7Fh                         ; 6A 7F (positive imm8 boundary)
    pop     eax
    mov     [g_pi_imm8c], eax
    ; -- 3. call-arg push-imm pair (guard zone args, cdecl cleanup) --
    push    22222222h                   ; arg0 (imm)
    push    11111111h                   ; arg1 (imm)
    call    pi_helper                   ; callgate RVA form
    add     esp, 8                      ; cdecl cleanup inside the region
    mov     [g_pi_ret], eax             ; 33333333h
    call    marker_end
    ret
rgn_pushimm ENDP

.data
ALIGN 4
g_pi_imm32a dword 0
g_pi_imm32b dword 0
g_pi_imm32c dword 0
g_pi_imm8a  dword 0
g_pi_imm8b  dword 0
g_pi_imm8c  dword 0
g_pi_ret    dword 0
g_pi_arg    dword 0

END
