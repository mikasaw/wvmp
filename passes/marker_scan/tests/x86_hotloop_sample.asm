; MIT-494m (T35): x86 hotloop E2E sample -- interpreter-dense microbenchmark
; (x64 MIT-494l counterpart; T31 wall-clock caveat applies to x86 too).
;
; Layout mirrors x86_deepcall_sample.asm (MIT-437/450 recipe): hand-written
; marker stubs (/Od form, B8 hi -> C7 lo), >64B nop pad before the first
; anchor, region between call marker_begin / call marker_end.
;
; Region = do-while xorshift32 ALU loop (mov/xor/shl/shr/add/inc/cmp/jb all
; whitelisted; /O1 cl builds the C side, region is pure asm so codegen is
; pinned). Loop shape follows the MIT-326/407 discipline: the only jump is
; the backward edge (jb hot_body); the exit falls through to marker_end --
; no forward jump crosses WVMP_END.
;
; Register plan (cdecl, volatile-only, no push/pop inside the region per the
; 442 stack rule): x=eax, i=ecx, tmp=edx; iters read from the incoming arg
; slot [esp+8] each iteration (stable: no push/pop).
;
; 5M iterations x ~15 words/iteration drives the x86 (KS_MODE_32) dispatch
; hard enough to quantify interpreter throughput (measure_hotloop.sh).

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
; uint32_t hotloop_x32(uint32_t seed /*[esp+4]*/, uint32_t iters /*[esp+8]*/)
;   x ^= x<<13; x ^= x>>17; x ^= x<<5; x += i; ++i  (5M iterations)
; Same math as the x64 hotloop sample (checksum anchor shared).
; ================================================================
hotloop_x32 PROC
    ; pitfall #36: marker_end clobbers eax (its END1 magic) -- stash the
    ; result in a prologue slot across the marker_end call (deepcall_entry
    ; same discipline). sub esp,4 shifts arg slots by +4.
    sub     esp, 4                          ; [esp+0] = result slot
    ; marker_begin FIRST, then load x -- marker_begin clobbers eax (its own
    ; magic constant), and volatile regs are dead across the call (the x64
    ; C sample keeps x in a stack slot across the same call; asm must order
    ; around it). No calls inside the loop, so regs stay stable per-iteration.
    call    marker_begin
    mov     eax, [esp+8]                    ; x = seed (arg0 = [esp+4+4])
    xor     ecx, ecx                        ; i = 0
hot_body:
    mov     edx, eax
    shl     edx, 13
    xor     eax, edx
    mov     edx, eax
    shr     edx, 17
    xor     eax, edx
    mov     edx, eax
    shl     edx, 5
    xor     eax, edx
    add     eax, ecx                        ; x += i
    inc     ecx                             ; ++i
    cmp     ecx, [esp+12]                   ; i < iters (arg1 = [esp+8+4];
                                            ; slot stable: no push/pop in
                                            ; region, 442)
    jb      hot_body                        ; backward edge only
    mov     [esp+0], eax                    ; stash result (pitfall #36)
    call    marker_end
    mov     eax, [esp+0]                    ; read back
    add     esp, 4
    ret
hotloop_x32 ENDP

END
