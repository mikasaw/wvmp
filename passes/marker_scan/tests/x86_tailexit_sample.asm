; MIT-453 (X5c) B.2: x86 tailexit sample -- last-region .text-tail ExitNative
; fallback (D1 core) + beyond-tail gate negative.
;
; Layout mirrors x86_forkface_sample.asm (MIT-437 recipe): hand-written marker
; stubs, /Od form, >64B nop pad before the first anchor, regions between
; call marker_begin / call marker_end. No push/pop inside regions (guest
; stack writes >= ns; frame setup in the native prologue before marker_begin).
;
; Region order matters (begin_rva ascending):
;   1. rgn_exit_ok      -- has a successor region -> ub = next-region begin.
;                          Three ExitNative faces: cond->END-call (target ==
;                          end_rva boundary), cond->own epilogue (target in
;                          the tail gap), fallthrough -> Halt at block end.
;   2. rgn_tail_beyond  -- GATE NEGATIVE (address taken, never called):
;                          `jmp g_far_data` targets a .data VA >= .text tail
;                          (and >= next-region begin) -> condition D fails ->
;                          C1 gate, whole function stays native.
;   3. rgn_tailexit_ok  -- LAST marker region (no successor) -> ub = .text
;                          section tail (VirtualAddress + VirtualSize). Same
;                          three faces as region 1; this is the X5c D1 core
;                          scenario (wvmpTest 0xC972 shape) pinned in the pool.
;
; Expected protect log: 2 stubs (REQUIRE_REAL), 1 gate note for
; rgn_tail_beyond ("跳转目标块未找到"), exit-native notes for regions 1+3.

.686p
.model flat, c

.code

; ---- >64B nop pad: keep the first anchor away from the .text start window
    align 16
    REPEAT 80
    nop
    ENDM

; ---- marker stubs (/Od form, hi->lo), bytes verified MIT-437 ----
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
; rgn_exit_ok: acc = (g_in1 ^ 5A5A0001h) + g_in2 -> g_out1.
;   acc >  0: jg  tail_ret_1  (cond ExitNative -> own epilogue, in gap)
;   acc == 0: jz  endcall_1   (cond ExitNative -> END-call, target==end_rva)
;   acc <  0: fallthrough +0DEADh -> block end -> Halt (resume at END-call)
; ================================================================
rgn_exit_ok PROC
    push    ebp
    mov     ebp, esp
    sub     esp, 8
    call    marker_begin
    mov     eax, [g_in1]
    xor     eax, 5A5A0001h
    add     eax, [g_in2]
    mov     [g_out1], eax
    test    eax, eax
    jz      endcall_1
    jg      tail_ret_1
    add     dword ptr [g_out1], 0DEADh
endcall_1:
    call    marker_end                      ; == end_rva (region end boundary)
tail_ret_1:                                 ; in the tail gap [end_rva, next begin)
    mov     esp, ebp
    pop     ebp
    ret
rgn_exit_ok ENDP

; ================================================================
; rgn_tail_beyond: gate negative. Address taken by main, never called
; (the jmp target is beyond the .text tail -- executing it native would
; be meaningless; region stays whole-function native via C1 gate in the
; packed run, evidence = protect log gate note).
; Hand-encoded E9 rel32 (bitops db precedent): rel32 = +30000h ->
; target = next_insn_va + 30000h, beyond the .text tail (and beyond the
; next region begin) under any plausible link placement. A MASM
; `jmp g_far_data` to a .data label assembles INDIRECT (FF 25) which
; would gate via the indirect-jmp family instead of the beyond-tail
; shape this region pins.
; ================================================================
rgn_tail_beyond PROC
    call    marker_begin
    mov     eax, [g_in1]
    xor     eax, 31313131h
    test    eax, eax
    jz      beyond_zero
    inc     eax
beyond_zero:
    db      0E9h                            ; jmp rel32 (direct, imm target)
    dd      000030000h                      ; target = next_insn + 30000h >= .text tail
    call    marker_end                      ; scanner anchor (unreachable)
    ret
rgn_tail_beyond ENDP

; ================================================================
; rgn_tailexit_ok: LAST marker region -- no successor -> ub = .text tail.
; acc = (g_in1 ^ 5A5A0003h) + g_in2 -> g_out3. Same three faces as
; rgn_exit_ok; the cond sites here ExitNative through the .text-tail
; fallback (X5c D1 core, wvmpTest 0xC972 shape).
; ================================================================
rgn_tailexit_ok PROC
    push    ebp
    mov     ebp, esp
    sub     esp, 8
    call    marker_begin
    mov     eax, [g_in1]
    xor     eax, 5A5A0003h
    add     eax, [g_in2]
    mov     [g_out3], eax
    test    eax, eax
    jz      endcall_3
    jg      tail_ret_3
    add     dword ptr [g_out3], 0BEEFh
endcall_3:
    call    marker_end
tail_ret_3:
    mov     esp, ebp
    pop     ebp
    ret
rgn_tailexit_ok ENDP

.data
PUBLIC g_in1, g_in2, g_out1, g_out3
g_in1       dword 0
g_in2       dword 0
g_out1      dword 0
g_out3      dword 0

END
