; MIT-450 (X5) B.3 (2): x86 SEH gate E2E sample -- G1 segment-override face.
;
; seh_fn (in x86_sehgate_main.c) is a real MSVC __try/__except function whose
; marked region body additionally reads the TEB via a fs:[...] override
; (realistic SEH/TEB inspection pattern): the lifter rejects segment
; overrides (G1) -> the whole function stays native (C1 gate note). The
; __except path is exercised with mode=0x77 (in-region AV, caught natively
; both runs -> identical output; the function itself is native, so no VM
; involvement by construction).
;
; This file carries the MIT-437 marker stubs plus the GP helper region that
; provides the REQUIRE_REAL >=1 stub.

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

; -- pure GP helper: REQUIRE_REAL >=1 stub source --
rgn_seh_helper PROC
    call    marker_begin
    mov     eax, 1234ABCDh
    xor     eax, 0F0F0F0F0h
    add     eax, 077777777h
    shl     eax, 3
    mov     dword ptr [g_sh_out], eax
    call    marker_end
    ret
rgn_seh_helper ENDP

.data
PUBLIC g_sh_out
g_sh_out dd 0

END
