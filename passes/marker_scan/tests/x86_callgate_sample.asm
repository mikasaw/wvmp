; MIT-446 (X4) B.4 ③: x86 E2E first-batch sample -- mixed integer + cdecl
; callgate argument window (MIT-446 build_callgate_x86 protocol,
; kX86CallgateArgDwords=4).
;
; Call protocol (synced handler<->sample, both runs byte-exact):
;   native run : args written to [esp+0..12] (prologue-reserved scratch,
;                addresses >= ns = 442 rule-safe), `call add3` pushes the
;                return address at [v4-4] natively (no stub there), add3
;                reads [esp+4..esp+12] as arg0..2 (cdecl).
;   packed run : CallGate copies [v4+0..15] (fixed 4 dwords) to the callee
;                window (arg0 lowest), calls; esp re-based from host_rsp.
;
; rgn_plain_int = second truly virtualized region (2 stubs total).

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

; ---- native cdecl callees (3-arg via window, 0-arg, and a function
;      pointer target). All read their args from the cdecl stack window
;      so native and packed (callgate window) runs share one convention.
add3 PROC
    mov     eax, [esp+4]                    ; arg0 (ret addr at [esp])
    add     eax, [esp+8]                    ; arg1
    add     eax, [esp+12]                   ; arg2
    ret
add3 ENDP

zero_fn PROC
    mov     eax, 0C0FFEE0h
    ret
zero_fn ENDP

adder2 PROC                              ; 2-arg via window
    mov     eax, [esp+4]
    xor     eax, [esp+8]
    ret
adder2 ENDP

g_fp_adder2 dword adder2

; ================================================================
; rgn_mixed_cg: mixed integer work + cdecl calls with stack args.
; Prologue (push ebp/mov ebp,esp/sub esp,0x20) is NATIVE (before the
; begin marker), so [v4 .. v4+0x1C] is prologue-reserved scratch and all
; arg writes stay >= ns (442 rule).
; ================================================================
rgn_mixed_cg PROC
    push    ebp
    mov     ebp, esp
    sub     esp, 20h
    call    marker_begin
    ; -- 3-arg cdecl call through the argument window --
    mov     dword ptr [esp+0], 1000h        ; arg0 at [v4] (deterministic)
    mov     dword ptr [esp+4], 200h         ; arg1
    mov     dword ptr [esp+8], 33h          ; arg2
    call    add3                            ; CallGate RVA form
    ; -- fold result through the integer face --
    mov     ecx, eax
    shl     ecx, 3
    xor     ecx, eax
    ror     ecx, 7
    mov     dword ptr [g_cg_out], ecx
    ; -- 0-arg call (fixed window pre-set is harmless: callee reads none) --
    call    zero_fn
    xor     dword ptr [g_cg_out], eax
    ; -- call [mem] with 2 stack args --
    mov     dword ptr [esp+0], 5A5A0000h
    mov     dword ptr [esp+4], 0A5A5h
    call    dword ptr [g_fp_adder2]         ; CallGate reg form (mem fold)
    mov     dword ptr [g_cg_out2], eax
    ; -- second 3-arg call reusing the same window slots --
    mov     dword ptr [esp+0], 7
    mov     dword ptr [esp+4], 700
    mov     dword ptr [esp+8], 70000
    call    add3
    add     dword ptr [g_cg_out2], eax
    call    marker_end
    mov     esp, ebp
    pop     ebp
    ret
rgn_mixed_cg ENDP

; ================================================================
; rgn_plain_int: second truly virtualized region.
; ================================================================
rgn_plain_int PROC
    call    marker_begin
    mov     eax, 31313131h
    mov     edx, 55555555h
    and     eax, edx
    or      eax, 0F0F0000h
    xor     eax, 0FF00FF00h
    not     eax
    neg     eax
    movzx   ecx, al
    add     eax, ecx
    rol     eax, 11
    shr     eax, 3
    mov     dword ptr [g_cg_out2], eax
    call    marker_end
    ret
rgn_plain_int ENDP

.data
PUBLIC g_cg_out, g_cg_out2
g_cg_out   dword 0
g_cg_out2  dword 0

END
