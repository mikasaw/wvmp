; MIT-450 (X5) B.1 (3): x86 string-op E2E sample -- dword string family mix
; (G3 rep/repnz microprogram face, x86 S32 shapes; 442 plain-string carrier
; face included). All in one marked region, eax/ecx/edx scratch, esi/edi are
; callee-saved: saved to globals at region start and restored at region end
; (native face; 446 forkface-x86 rgn_strings discipline -- no push).
;
; Faces covered:
;   rep movsd aligned (8 dwords)          F3 A5
;   rep movsd unaligned (src+1, 7 dwords) F3 A5
;   rep stosd fill (6 dwords)             F3 AB
;   repe cmpsd early-exit (mismatch @ 2)  F3 A7  (post-state: esi/edi past the
;                                          mismatching element, ecx = remaining)
;   repne scasd not-found (ecx -> 0)      F2 AF
;   lodsd                                 AD
;   plain movsd x2 (no prefix, 442 face)  A5
;   cld (no-op)                           FC
; Results are deterministic; main asserts the mirror values (D4 native rc=0).

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

rgn_strops PROC
    call    marker_begin
    mov     [g_sv_esi], esi                 ; callee-saved via globals
    mov     [g_sv_edi], edi
    cld
    ; -- rep movsd aligned: g_sbuf -> g_dbuf, 8 dwords --
    mov     esi, offset g_sbuf
    mov     edi, offset g_dbuf
    mov     ecx, 8
    rep     movsd
    ; -- rep movsd unaligned: g_sbuf+1 -> g_dbuf+40h, 7 dwords --
    mov     esi, offset g_sbuf
    add     esi, 1
    mov     edi, offset g_dbuf + 40h
    mov     ecx, 7
    rep     movsd
    ; -- rep stosd: fill g_dbuf+80h with 5A5A5A5Ah, 6 dwords --
    mov     edi, offset g_dbuf + 80h
    mov     ecx, 6
    mov     eax, 5A5A5A5Ah
    rep     stosd
    ; -- repe cmpsd: g_sbuf vs g_mbuf, mismatch at dword 2 (third) --
    mov     esi, offset g_sbuf
    mov     edi, offset g_mbuf
    mov     ecx, 8
    repe    cmpsd
    jz      cmp_all_eq
    mov     edx, 8
    sub     edx, ecx                        ; 8 - remaining
    dec     edx                             ; index of mismatching element
    mov     [g_st_out], edx
    jmp     cmp_done
cmp_all_eq:
    mov     dword ptr [g_st_out], 0FFFFFFFFh
cmp_done:
    ; -- repne scasd: scan g_dbuf+80h for ABCD0001h (absent) -> ecx=0, ZF=0 --
    mov     edi, offset g_dbuf + 80h
    mov     ecx, 6
    mov     eax, 0ABCD0001h
    repne   scasd
    jne     scas_notfound
    mov     edx, 11111111h
    jmp     scas_common
scas_notfound:
    mov     edx, 22222222h
scas_common:
    xor     [g_st_out], edx
    ; -- lodsd: first dword of g_sbuf --
    mov     esi, offset g_sbuf
    lodsd
    add     [g_st_out], eax
    ; -- plain movsd x2 (no prefix, 442 carrier face): g_sbuf+8 -> g_dbuf+C0h --
    mov     esi, offset g_sbuf + 8
    mov     edi, offset g_dbuf + 0C0h
    movsd
    movsd
    ; -- fold: dword at g_dbuf+C0h == g_sbuf[8] (deterministic) --
    mov     eax, [g_dbuf+0C0h]
    xor     eax, 0DEB25E17h
    add     [g_st_out2], eax
    mov     esi, [g_sv_esi]                 ; restore callee-saved (native face)
    mov     edi, [g_sv_edi]
    call    marker_end
    ret
rgn_strops ENDP

; -- second truly virtualized region: plain integer face (2nd stub) --
rgn_strops_int PROC
    call    marker_begin
    mov     eax, 13579BDFh
    mov     ecx, 2468ACE0h
    and     eax, ecx
    or      eax, 0F00000FFh
    xor     eax, 0AAAA5555h
    mov     dword ptr [g_st_out3], eax
    call    marker_end
    ret
rgn_strops_int ENDP

.data
PUBLIC g_st_out, g_st_out2, g_st_out3, g_sv_esi, g_sv_edi, g_sbuf, g_dbuf
g_st_out   dword 0
g_st_out2  dword 0
g_st_out3  dword 0
g_sv_esi   dword 0
g_sv_edi   dword 0
g_sbuf     dd 10000001h, 20000002h, 30000003h, 40000004h
           dd 50000005h, 60000006h, 70000007h, 80000008h
g_mbuf     dd 10000001h, 20000002h, 0BADF00Dh, 40000004h
           dd 50000005h, 60000006h, 70000007h, 80000008h
g_dbuf     dd 64 dup (0)

END
