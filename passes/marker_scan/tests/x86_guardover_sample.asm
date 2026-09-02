; MIT-451 (X5b) B.5: x86 guard-over-limit gate-negative sample. The marked
; region's net stack depth (sub esp,200h = 512B) exceeds the entry guard
; budget (kX86GuardBytes=128B) -> the translator stack-depth walk gates the
; whole function to native (C1 fallback, "stack-depth-gate" note). This is
; the exact shape that would silently corrupt the stub callee-saved save
; area ([ns-4..ns-0x10]) if virtualized unprotected: the deep write lands
; at ns-4 = saved-ebx slot. Callable natively (real dead-stack scratch),
; so the E2E run stays byte-exact while proving the gate actually fires
; (protect-log gate note = the assertion). The pure-push over-limit face
; (net > budget via unbalanced pushes) is covered by the translator walk
; unit tests (StackWalkX86HaltUnbalancedGatesMul64hiShape) and the x86
; battery; this sample carries the realistic /Od alloca shape.

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

PUBLIC rgn_guardover
PUBLIC g_go_val, g_go_deep, g_go_helper
rgn_guardover PROC
    call    marker_begin
    mov     eax, 7777h
    mov     ecx, 5555h
    sub     esp, 200h                  ; net depth 512B > 128B budget -> gate
    mov     dword ptr [esp+1FCh], eax  ; deep write = ns-4 (saved-ebx slot!)
    mov     ecx, [esp+1FCh]            ; read back (native-safe scratch)
    mov     [g_go_val], ecx
    mov     edx, 6666h
    mov     dword ptr [esp], edx       ; ns-200h: deepest byte of the frame
    mov     ecx, [esp]
    mov     [g_go_deep], ecx
    add     esp, 200h                  ; rebalance inside the region
    call    marker_end
    ret
rgn_guardover ENDP

; GP helper true-virtualization region (MIT-418 pattern: REQUIRE_REAL >=1
; stub assertion needs a real stub; the gate-negative face above stays the
; sample's point, the helper only satisfies the pool check).
rgn_guardover_helper PROC
    call    marker_begin
    mov     eax, 0A5A5A5A5h
    add     eax, 5
    mov     [g_go_helper], eax
    call    marker_end
    ret
rgn_guardover_helper ENDP

.data
ALIGN 4
g_go_val  dword 0
g_go_deep dword 0
g_go_helper dword 0

END
