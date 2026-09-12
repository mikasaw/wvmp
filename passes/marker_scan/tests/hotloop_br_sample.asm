; MIT-494r (T41): x64 branch/flags-dense hotloop asm sample -- interpreter
; word-mix matrix (GAPS 494q pure-ALU counterpart). Nested loop shape:
; inner jnz spin (3 taken iterations) + outer jb -- 4 conditional-branch
; words + 3 flags-live dec words per outer iteration, against the ALU
; sample's single jb, isolating Jcc + flag-capture handler cost.
;
; Loop (14 instrs/outer-iter): inner x^=3,x^=2,x^=1 (net 0, exercises the
; Jcc edge 3x) + x += i; inc/cmp/jb. add-i carry nonlinearity keeps the
; checksum chain live.
;
; Region discipline (MIT-326/407): jumps are backward edges only (jnz inner,
; jb br_body); exit falls through to marker_end -- no forward jump crosses
; WVMP_END. 442: no push/pop inside the region. pitfall #36: result stashed
; in the caller's shadow slot [rsp+20h] across marker_end.

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; ================================================================
; uint32_t hotloop_br64(uint32_t seed /*ecx*/, uint32_t iters /*edx*/)
; ================================================================
hotloop_br64 PROC
    sub     rsp, 28h                        ; entry rsp ≡ 8 (mod 16) → call
                                            ; 前对齐 0（deepcall_entry 先例）
    call    ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    mov     eax, ecx                        ; x = seed
    mov     r8d, edx                        ; iters (volatile, stable)
    xor     ecx, ecx                        ; i = 0
br_body:
    mov     edx, 3                          ; inner counter
inner:
    xor     eax, edx                        ; x ^= d (d = 3,2,1)
    dec     edx                             ; --d (flags live: jnz 读 ZF)
    jnz     inner                           ; backward edge #1
    add     eax, ecx                        ; x += i
    inc     ecx                             ; ++i
    cmp     ecx, r8d                        ; i < iters
    jb      br_body                         ; backward edge #2
    mov     [rsp+20h], eax                  ; stash (pitfall #36)
    call    ?marker_end@sdk@wvmp@@YAXXZ
    mov     eax, [rsp+20h]                  ; read back
    add     rsp, 28h
    ret
hotloop_br64 ENDP

_TEXT ENDS
END
