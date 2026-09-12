; MIT-494r (T41): x86 branch/flags-dense hotloop E2E sample -- word-mix
; matrix, x64 hotloop_br_sample.asm (MIT-494r) counterpart. Layout mirrors
; x86_hotloop_sample.asm (MIT-437/450 recipe): hand-written marker stubs,
; >64B nop pad, region between call marker_begin / call marker_end.
;
; Nested loop shape: inner jnz spin (3 taken iterations) + outer jb -- 4
; conditional-branch words + 3 flags-live dec words per outer iteration,
; against the ALU sample's single jb, isolating Jcc + flag-capture handler
; cost on the KS_MODE_32 dispatch.
;
; Region discipline (MIT-326/407): jumps are backward edges only (jnz inner,
; jb br_body); exit falls through. 442: no push/pop inside the region; iters
; read from the incoming arg slot [esp+12] (sub esp,4 shifts slots by +4).

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
; uint32_t hotloop_brx32(uint32_t seed /*[esp+4]*/, uint32_t iters /*[esp+8]*/)
;   Same math as hotloop_br64 (checksum anchor shared: 4106202882).
; ================================================================
hotloop_brx32 PROC
    sub     esp, 4                          ; [esp+0] = result slot (pitfall
                                            ; #36 stash; slots shift +4)
    call    marker_begin                    ; 先 call 后装载（marker_begin
                                            ; 毁 eax，易失寄存器跨 call 死亡）
    mov     eax, [esp+8]                    ; x = seed
    xor     ecx, ecx                        ; i = 0
br_body:
    mov     edx, 3                          ; inner counter
inner:
    xor     eax, edx                        ; x ^= d (d = 3,2,1)
    dec     edx                             ; --d (flags live: jnz 读 ZF)
    jnz     inner                           ; backward edge #1
    add     eax, ecx                        ; x += i
    inc     ecx                             ; ++i
    cmp     ecx, [esp+12]                   ; i < iters（槽稳定：区域内无
                                            ; push/pop，442）
    jb      br_body                         ; backward edge #2
    mov     [esp+0], eax                    ; stash result (pitfall #36)
    call    marker_end
    mov     eax, [esp+0]                    ; read back
    add     esp, 4
    ret
hotloop_brx32 ENDP

END
