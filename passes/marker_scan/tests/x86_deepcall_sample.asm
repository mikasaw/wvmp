; MIT-450 (X5) B.1 (1): x86 deepcall E2E sample -- callgate recursion depth
; (x64 MIT-406 / MIT-E1 counterpart ported to the 4B window accounting).
;
; Layout mirrors x86_marker_sample.asm (MIT-437 recipe): hand-written marker
; stubs (/Od form, B8 hi -> C7 lo), >64B nop pad before the first anchor,
; regions between call marker_begin / call marker_end.
;
; deep_recurse is NATIVE cdecl recursion; only deepcall_entry's inner
; `call deep_recurse` sits in the marked region and goes through the x86
; CallGate (MIT-445/X3c), which preseeds kX86CallgateArgDwords=4 dwords from
; guest [v4+4i] into the callee window. Frame budget (static, per level):
;   ret addr(4) + push ebx(4) + sub esp,30h = 0x38
; 32 levels -> tree depth 0x700 < kX86CallgateWindow(0x1000): the whole
; recursion tree grows inside the callee window (pre-E1 it would smash the
; resident ctx; post-E1 zero overlap -- same discrimination as x64 406).
;
; Guest stack discipline (442 rule): args written into the prologue-reserved
; scratch at [esp+k] (>= ns); no push/pop inside the region; cdecl caller
; never cleans (window slots overwritten per call, callee is cdecl too).
; In-region scratch regs: eax/ecx/edx only.

.686p
.model flat, c

.code

; ---- >64B nop pad: keep the first anchor away from the .text start window
    align 16
    REPEAT 80
    nop
    ENDM

; ---- marker stubs (/Od form, hi->lo) ----
marker_begin PROC
    push ebp
    mov     ebp, esp
    sub     esp, 10h
    mov     eax, 31474542h                  ; hi "BEG1" (B8 imm32)
    mov     dword ptr [ebp-8], 504D5657h    ; lo "WVMP" (C7 imm32)
    mov     dword ptr [ebp-4], eax
    mov     esp, ebp
    pop     ebp
    ret
marker_begin ENDP

marker_end PROC
    push ebp
    mov     ebp, esp
    sub     esp, 10h
    mov     eax, 31444E45h                  ; hi "END1"
    mov     dword ptr [ebp-8], 504D5657h    ; lo "WVMP"
    mov     dword ptr [ebp-4], eax
    mov     esp, ebp
    pop     ebp
    ret
marker_end ENDP

; ================================================================
; uint32_t deep_recurse(uint32_t levels /*[esp+4]*/, uint32_t acc /*[esp+8]*/)
;   g(0,a) = a + 6*F          (F = 41424344h garbage fill, 6 dwords/level)
;   g(k,a) = g(k-1, a+G) + a + 6*F   (G = 9E3779B9h golden-ratio low dword)
; Per-level frame 0x38; the 6 fill dwords make pre-window corruption a
; deterministic wrong result, not a benign no-op (406 discipline).
; ================================================================
deep_recurse PROC
    push    ebx
    sub     esp, 30h
    mov     dword ptr [esp+08h], 41424344h  ; 6 garbage fill dwords
    mov     dword ptr [esp+0Ch], 41424344h
    mov     dword ptr [esp+10h], 41424344h
    mov     dword ptr [esp+14h], 41424344h
    mov     dword ptr [esp+18h], 41424344h
    mov     dword ptr [esp+1Ch], 41424344h
    mov     ebx, [esp+3Ch]                  ; ebx = acc (incoming arg1; esp = entry-34h)
    mov     eax, [esp+38h]                  ; levels (incoming arg0)
    test    eax, eax
    jz      deep_bottom
    dec     eax
    lea     edx, [ebx+9E3779B9h]            ; new acc = acc + G
    mov     [esp+0], eax                    ; OUTGOING arg0 = levels-1 (window
    mov     [esp+4], edx                    ; OUTGOING arg1 = new acc; at call
                                            ; time [esp]=arg0 -> callee sees
                                            ; [entry+4]=arg0 (cdecl). Writing
                                            ; the incoming slots [esp+38h/3Ch]
                                            ; instead is a no-op for the child
                                            ; (first-pass defect, caught by the
                                            ; native mirror sentinel).
    call    deep_recurse                    ; E8 direct call (native recursion)
    add     eax, ebx                        ; child result + this-level acc
    jmp     deep_ret
deep_bottom:
    mov     eax, ebx
deep_ret:
    add     eax, [esp+08h]                  ; consume the 6 fill slots
    add     eax, [esp+0Ch]
    add     eax, [esp+10h]
    add     eax, [esp+14h]
    add     eax, [esp+18h]
    add     eax, [esp+1Ch]
    add     esp, 30h
    pop     ebx
    ret
deep_recurse ENDP

; ================================================================
; uint32_t deepcall_entry(void) -- marker region host. Region content =
; Store imm + Store imm + CallGate + Store (all whitelist). Result stashed
; at [esp+8] because marker_end clobbers eax (pitfall #36).
; ================================================================
deepcall_entry PROC
    sub     esp, 20h
    call    marker_begin
    mov     dword ptr [esp+0], 20h          ; arg0 = levels = 32 (tree 0x700)
    mov     dword ptr [esp+4], 1234h        ; arg1 = acc seed
    call    deep_recurse                    ; CallGate -> native 32-level tree
    mov     [esp+8], eax
    call    marker_end
    mov     eax, [esp+8]
    add     esp, 20h
    ret
deepcall_entry ENDP

; ================================================================
; rgn_plain2: second truly virtualized region (2 stubs total).
; ================================================================
rgn_plain2 PROC
    call    marker_begin
    mov     eax, 5A5A0000h
    xor     eax, 0F0F0AAAAh
    not     eax
    add     eax, 12345678h
    rol     eax, 9
    shr     eax, 5
    mov     dword ptr [g_dc_out2], eax
    call    marker_end
    ret
rgn_plain2 ENDP

.data
PUBLIC g_dc_out2
g_dc_out2 dword 0

END
