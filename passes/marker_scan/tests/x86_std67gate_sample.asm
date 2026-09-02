; MIT-450 (X5) B.3 (3): x86 std + 67 gate E2E sample -- D5/G2 lifter gate
; faces (x64 MIT-442 forkface 区5/区6 counterparts, dedicated per-function
; form).
;
; rgn_std_gate  -- DESIGNED gate negative (callable): std/nop/cld inside the
;                  region; the lifter has no std case (D5: DF=1 unmodelable)
;                  whole function stays native, std+cld balance natively,
;                  byte-exact by native double run.
; rgn_addr67    -- DESIGNED gate negative (NEVER CALLED): 67-prefixed
;                  instruction (db 067h,08Bh,003h = 16-bit-addressing form);
;                  main only takes its address so the packed image carries
;                  the region bytes for the scanner; native execution is
;                  forbidden (same discipline as x64 442 区6).
; rgn_std_helper -- pure GP face, provides the REQUIRE_REAL >=1 stub.

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

rgn_std_gate PROC
    call    marker_begin
    std                             ; DF <- 1 -> D5 gate (whole function native)
    nop
    nop
    cld                             ; DF <- 0 (native balance)
    call    marker_end
    ret
rgn_std_gate ENDP

rgn_addr67 PROC
    call    marker_begin
    db      067h, 08Bh, 003h        ; 67 8B 03 = 16-bit-addressing mov (G2 gate)
    nop
    call    marker_end
    ret
rgn_addr67 ENDP

rgn_std_helper PROC
    call    marker_begin
    mov     eax, 0B7B7B7B7h
    xor     eax, 0E7E7E7E7h
    sub     eax, 50000000h
    sar     eax, 2
    mov     dword ptr [g_sg_out], eax
    call    marker_end
    ret
rgn_std_helper ENDP

.data
PUBLIC g_sg_out
g_sg_out dd 0

END
