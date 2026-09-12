; MIT-494r (T41): x64 LD/ST-dense hotloop asm sample -- interpreter word-mix
; matrix (GAPS 494q pure-ALU counterpart). 3 loads + 3 stores per iteration
; on a resident static buffer isolate the Load/Store handler + address-chain
; word cost from the ALU baseline.
;
; Loop (14 instrs/iter): ld buf[0] -> add -> st buf[1]; RAW re-load buf[1]
; -> shl 3 -> xor -> st buf[2]; stale-load buf[3] -> xor -> st buf[4];
; add i; inc/cmp/jb. buf[0]/buf[3] read stale zero (never written); the
; buf[1] store-to-load edge + add-i (carry nonlinearity) keep the checksum
; chain live (pure XOR+shift maps are GF(2)-linear: f^(2^k) = identity
; once 2^k >= 32, so any iteration count divisible by 32 degenerates --
; python pitfall found while pinning the anchor).
;
; Region discipline (MIT-326/407): single backward edge (jb mem_body); exit
; falls through to marker_end. 442: no push/pop inside the region; r9 rides
; the buffer base (volatile, no calls inside the loop). pitfall #36: result
; stashed in the caller's shadow slot [rsp+20h] across marker_end.

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC
EXTERNDEF g_mem_buf : DWORD

_TEXT SEGMENT

; ================================================================
; uint32_t hotloop_mem64(uint32_t seed /*ecx*/, uint32_t iters /*edx*/)
; ================================================================
hotloop_mem64 PROC
    sub     rsp, 28h                        ; entry rsp ≡ 8 (mod 16) → call
                                            ; 前对齐 0（deepcall_entry 先例）
    call    ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    mov     eax, ecx                        ; x = seed
    mov     r8d, edx                        ; iters (volatile, stable)
    xor     ecx, ecx                        ; i = 0
    lea     r9, g_mem_buf                   ; rip-relative buffer base
mem_body:
    mov     edx, dword ptr [r9]             ; t = buf[0] (恒 0)
    add     eax, edx                        ; x += t
    mov     dword ptr [r9+4], eax           ; buf[1] = x
    mov     edx, dword ptr [r9+4]           ; t = buf[1] (RAW: 刚写)
    shl     edx, 3                          ; t <<= 3
    xor     eax, edx                        ; x ^= t
    mov     dword ptr [r9+8], eax           ; buf[2] = x
    mov     edx, dword ptr [r9+12]          ; t = buf[3] (恒 0)
    xor     eax, edx                        ; x ^= t
    mov     dword ptr [r9+16], eax          ; buf[4] = x
    add     eax, ecx                        ; x += i（进位非线性破环）
    inc     ecx                             ; ++i
    cmp     ecx, r8d                        ; i < iters
    jb      mem_body                        ; backward edge only
    mov     [rsp+20h], eax                  ; stash (pitfall #36)
    call    ?marker_end@sdk@wvmp@@YAXXZ
    mov     eax, [rsp+20h]                  ; read back
    add     rsp, 28h
    ret
hotloop_mem64 ENDP

_TEXT ENDS
END
