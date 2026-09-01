; MIT-446 (X4) B.4 ②: x86 E2E first-batch sample -- SSE face.
;
; rgn_sse = marker-wrapped SSE region (movdqa/movdqu/movaps folded family,
; x86 forms on xmm0..xmm3). The x86 runtime has NO SSE handlers (GAPS X3b
; residual list) -> the stub_link x86 whitelist gate (MIT-446) keeps the
; whole function native (C1-class explicit gate, note in protect log).
; This is the x86-face counterpart of the x87 R-SSE-only gate ruling and
; the E2E evidence for the known gate surface disclosed to X5.
;
; rgn_int_helper = real virtualizable integer region (>=1 stub for
; REQUIRE_REAL; 407 pool discipline).
;
; SSE data ops below: movdqa/movdqu (66/F3 0F 6F/7F, G1d folded family) +
; movaps/movups (0F 28/29) both directions + paddd-less pure moves so the
; NATIVE behavior is deterministic and byte-exact regardless of gate.

.686p
.XMM
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

; ================================================================
; rgn_sse: SSE move family (DESIGNED x86 whitelist-gate negative).
; Loads/writes through .data buffers; results observable via globals.
; ================================================================
rgn_sse PROC
    call    marker_begin
    movdqa  xmm0, xmmword ptr [g_sse_a]     ; aligned load (66 0F 6F)
    movdqu  xmm1, xmmword ptr [g_sse_b]     ; unaligned load (F3 0F 6F)
    movaps  xmm2, xmm0                      ; reg-reg (0F 28)
    movups  xmm3, xmmword ptr [g_sse_a]     ; unaligned load (0F 10)
    movdqa  xmmword ptr [g_sse_out_buf], xmm2   ; aligned store (66 0F 7F)
    movdqu  xmmword ptr [g_sse_out_buf+16], xmm1 ; unaligned store (F3 0F 7F)
    movaps  xmmword ptr [g_sse_out_buf+32], xmm3 ; aligned store (0F 29)
    movups  xmm4, xmmword ptr [g_sse_b]
    movaps  xmm5, xmm4
    movdqa  xmmword ptr [g_sse_out_buf+48], xmm5
    mov     eax, dword ptr [g_sse_out_buf]  ; fold a dword into the output
    xor     dword ptr [g_sse_out], eax
    mov     eax, dword ptr [g_sse_out_buf+16]
    xor     dword ptr [g_sse_out], eax
    mov     eax, dword ptr [g_sse_out_buf+48]
    xor     dword ptr [g_sse_out], eax
    call    marker_end
    ret
rgn_sse ENDP

; ================================================================
; rgn_int_helper: real virtualizable region (REQUIRE_REAL >=1 stub).
; ================================================================
rgn_int_helper PROC
    call    marker_begin
    mov     ecx, 7
    mov     eax, 1
int_helper_loop:
    imul    eax, ecx                        ; 2-op: eax = eax*ecx
    add     eax, 0A5A5A5A5h
    bswap   eax
    dec     ecx
    jnz     int_helper_loop
    xor     eax, 13579BDFh
    mov     dword ptr [g_sse_out], eax
    call    marker_end
    ret
rgn_int_helper ENDP

.data
PUBLIC g_sse_out
g_sse_out   dword 0
align 16
g_sse_a      dd 11223344h, 55667788h, 99AABBCCh, 0DDEEFF00h
g_sse_b      dd 0F0F0F0F0h, 0CCCC3333h, 12345678h, 9ABCDEF0h
g_sse_out_buf dd 4 dup (0), 4 dup (0), 4 dup (0), 4 dup (0)

END
