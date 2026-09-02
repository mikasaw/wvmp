; MIT-451 (X5b) B.5: x86 push-form E2E sample — real /Od-style in-region
; push shapes that the entry guard pad (kX86GuardBytes) makes safe to
; virtualize. Region content:
;   1. call-arg push form (mul64hi shape, cleanup INSIDE the region):
;      push arg2 / push arg1 / call helper (callgate reads [v4+4i], the
;      pushed dwords live in the guard zone) / add esp,8 (cdecl
;      caller-cleans, net depth back to 0 at Halt).
;   2. transient push/pop spill pair.
; Virtualization = guard absorbs the below-ns writes; native vs packed
; byte-exact (rc=0 sentinel).

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

PUBLIC rgn_pushform
PUBLIC g_pf_ret, g_pf_arg, g_pf_spill
; cdecl helper: returns arg0 + arg1 (reads the pushed args from its stack).
pf_helper PROC
    mov     eax, [esp+4]                ; arg0 = last push (2222h)
    add     eax, [esp+8]                ; arg1 = 1111h
    ret
pf_helper ENDP

rgn_pushform PROC
    call    marker_begin
    mov     eax, 1111h
    mov     ecx, 2222h
    push    eax                         ; arg1 -> [v4-4] (guard zone)
    push    ecx                         ; arg0 -> [v4-8]
    call    pf_helper                   ; callgate RVA form, args via window
    add     esp, 8                      ; cdecl cleanup inside the region
    mov     [g_pf_ret], eax             ; 3333h
    mov     [g_pf_arg], ecx             ; callee may clobber ecx (cdecl)
    mov     ebx, 3333h
    push    ebx                         ; transient spill (net +4)
    pop     ebx                         ; net back to 0
    mov     [g_pf_spill], ebx
    call    marker_end
    ret
rgn_pushform ENDP

.data
ALIGN 4
g_pf_ret   dword 0
g_pf_arg   dword 0
g_pf_spill dword 0

END
