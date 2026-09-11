; MIT-494q (T40): x64 hotloop asm sample -- same-dword-density counterpart
; of x86_hotloop_sample.asm (MIT-494m), eliminating the word-density
; confounder in cross-arch interpreter throughput comparison (GAPS 494m
; disclosure: x64 C/Od sample = 62 words/iter vs x86 asm ~15 words/iter).
;
; Loop body = the SAME 13-instruction form as the x86 asm sample (mov/
; xor/shl/shr/add/inc/cmp/jb on 32-bit subregisters; word streams decode
; to 13 vs 16 words/iter -- the x86 cmp-mem operand expands to a 3-word
; address chain). Per-word cost is then comparable after normalization
; (measure_hotloop.sh, ARCH=x64asm).
;
; Region discipline (MIT-326/407): only a backward edge (jb hot_body); exit
; falls through to marker_end. 442: no push/pop inside the region; iters
; rides r8d (volatile); args consumed after the marker_begin call
; (see pitfall #36 note below).
;
; pitfall #36: marker_begin/marker_end clobber rax (SDK magic imm64) --
; load x AFTER the marker_begin call, stash the result in the caller's
; shadow slot [rsp+20h] across marker_end (deepcall_entry precedent).

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; ================================================================
; uint32_t hotloop_asm64(uint32_t seed /*ecx*/, uint32_t iters /*edx*/)
; ================================================================
hotloop_asm64 PROC
    sub     rsp, 28h                        ; entry rsp ≡ 8 (mod 16) → call
                                            ; 前对齐 0（deepcall_entry 先例）
    call    ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    mov     eax, ecx                        ; x = seed
    mov     r8d, edx                        ; iters (volatile, stable: no
                                            ; calls inside the loop)
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
    cmp     ecx, r8d                        ; i < iters
    jb      hot_body                        ; backward edge only
    mov     [rsp+20h], eax                  ; stash (pitfall #36)
    call    ?marker_end@sdk@wvmp@@YAXXZ
    mov     eax, [rsp+20h]                  ; read back
    add     rsp, 28h
    ret
hotloop_asm64 ENDP

_TEXT ENDS
END
