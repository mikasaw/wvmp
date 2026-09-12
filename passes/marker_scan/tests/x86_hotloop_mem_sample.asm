; MIT-494r (T41): x86 LD/ST-dense hotloop E2E sample -- word-mix matrix,
; x64 hotloop_mem_sample.asm (MIT-494r) counterpart. Layout mirrors
; x86_hotloop_sample.asm (MIT-437/450 recipe): hand-written marker stubs
; (/Od form, B8 hi -> C7 lo), >64B nop pad before the first anchor, region
; between call marker_begin / call marker_end.
;
; Memory ops use absolute disp32 ([g_mem_buf] / [g_mem_buf+4] ...) -- the
; dominant real-world x86 form (imm32 absolute addressing everywhere), so
; the word stream carries the MIT-494j fold chains (Mov RVA + LeaRva) that
; the x64 rip-relative sample does not. The word-count difference IS part
; of the measurement (per-word normalization, t41_wordstats.py).
;
; Region discipline (MIT-326/407): single backward edge (jb mem_body); exit
; falls through. 442: no push/pop inside the region; iters read from the
; incoming arg slot [esp+12] (sub esp,4 shifts slots by +4).

.686p
.model flat, c

EXTERNDEF g_mem_buf : DWORD

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
; uint32_t hotloop_memx32(uint32_t seed /*[esp+4]*/, uint32_t iters /*[esp+8]*/)
;   Same math as hotloop_mem64 (checksum anchor shared: 3952819074).
; ================================================================
hotloop_memx32 PROC
    sub     esp, 4                          ; [esp+0] = result slot (pitfall
                                            ; #36 stash; slots shift +4)
    call    marker_begin                    ; 先 call 后装载（marker_begin
                                            ; 毁 eax，易失寄存器跨 call 死亡）
    mov     eax, [esp+8]                    ; x = seed
    xor     ecx, ecx                        ; i = 0
mem_body:
    mov     edx, dword ptr [g_mem_buf]      ; t = buf[0] (恒 0)
    add     eax, edx                        ; x += t
    mov     dword ptr [g_mem_buf+4], eax    ; buf[1] = x
    mov     edx, dword ptr [g_mem_buf+4]    ; t = buf[1] (RAW: 刚写)
    shl     edx, 3                          ; t <<= 3
    xor     eax, edx                        ; x ^= t
    mov     dword ptr [g_mem_buf+8], eax    ; buf[2] = x
    mov     edx, dword ptr [g_mem_buf+12]   ; t = buf[3] (恒 0)
    xor     eax, edx                        ; x ^= t
    mov     dword ptr [g_mem_buf+16], eax   ; buf[4] = x
    add     eax, ecx                        ; x += i（进位非线性破环）
    inc     ecx                             ; ++i
    cmp     ecx, [esp+12]                   ; i < iters（槽稳定：区域内无
                                            ; push/pop，442）
    jb      mem_body                        ; backward edge only
    mov     [esp+0], eax                    ; stash result (pitfall #36)
    call    marker_end
    mov     eax, [esp+0]                    ; read back
    add     esp, 4
    ret
hotloop_memx32 ENDP

END
