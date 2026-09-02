; MIT-450 (X5) B.1 (4): x86 bit-op E2E sample -- popcount/byte-swap/compare-
; exchange family (x86 whitelist face).
;
; X5 first-pass finding (kept as design data, gate notes in the protect log):
;   - REG-REG bts/btr/btc/xadd are NOT in the x86 lifter face (the
;     X86_INS_XADD/BTS/BTR/BTC cases require a MEM destination -- they are
;     the G4 lock-family translations) -> whole-function C1 gate. Dropped
;     from the true region; REG-REG bit-test/atomic coverage is a lifter
;     gap to file separately (G8a-style per-family ticket).
;   - lock mem forms (lock xadd/bts/cmpxchg [m], r) go through
;     rgn_bitops_lock: lifter-accepted G4 face on both archs; the protect
;     log decides virtualize-vs-gate and the report discloses which.
; rgn_bitops      -- pure in-table REG-REG face (true virtualization).
; rgn_bitops_lock -- G4 lock mem forms (virtualize or gate, both byte-exact).
; Region discipline: eax/ecx/edx only, results folded into globals.

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

rgn_bitops PROC
    call    marker_begin
    ; -- popcnt / tzcnt / lzcnt (F3 0F B8/BC/BD) --
    ; MASM .686p has no popcnt/tzcnt/lzcnt mnemonics: hand-encoded
    ; (modrm D0 = reg=edx, rm=eax).
    mov     eax, 0F0F0CC32h
    db      0F3h, 00Fh, 0B8h, 0D0h          ; popcnt edx, eax
    mov     [g_b_pc], edx
    db      0F3h, 00Fh, 0BCh, 0D0h          ; tzcnt edx, eax
    mov     [g_b_tz], edx
    db      0F3h, 00Fh, 0BDh, 0D0h          ; lzcnt edx, eax
    mov     [g_b_lz], edx
    ; -- bswap --
    bswap   eax
    mov     [g_b_bs], eax
    ; -- cmpxchg reg,reg: eax == edx -> edx <- ecx, ZF=1 (equal path) --
    mov     eax, 12345678h
    mov     edx, 12345678h
    mov     ecx, 0AAAA5555h
    cmpxchg edx, ecx
    je      cx_eq
    mov     dword ptr [g_b_cx], 0FFFFFFFFh
    jmp     cx_done
cx_eq:
    mov     [g_b_cx], edx                   ; 0AAAA5555h on the equal path
cx_done:
    ; -- cmpxchg unequal path: eax <- dest, ZF=0 --
    mov     eax, 11111111h
    mov     edx, 22222222h
    mov     ecx, 33333333h
    cmpxchg edx, ecx
    sete    cl
    movzx   ecx, cl
    mov     [g_b_cx2], ecx                  ; 0 (unequal)
    mov     [g_b_cx2+4], edx                ; 22222222h (dest unchanged)
    mov     [g_b_cx2+8], eax                ; 22222222h (eax <- dest)
    ; -- xchg reg,reg --
    mov     eax, 0F0F00F0Fh
    mov     edx, 0CCCC3333h
    xchg    eax, edx
    mov     [g_b_xg], eax                   ; 0CCCC3333h
    mov     [g_b_xg+4], edx                 ; 0F0F00F0Fh
    call    marker_end
    ret
rgn_bitops ENDP

; -- G4 lock mem forms (lifter-accepted both archs; virtualize or gate,
;    native semantics identical by construction either way). --
rgn_bitops_lock PROC
    call    marker_begin
    mov     dword ptr [g_bm_slot], 0AAAA5555h
    mov     eax, 0AAAA5555h
    mov     ecx, 12345678h
    lock cmpxchg dword ptr [g_bm_slot], ecx ; equal: slot <- 12345678h
    sete    cl
    movzx   ecx, cl
    mov     [g_bm_cx], ecx                  ; ZF=1 -> 1
    mov     eax, 00000100h
    lock xadd dword ptr [g_bm_slot], eax    ; eax = old slot, slot += eax
    mov     [g_bm_xa], eax
    mov     eax, 3
    lock bts dword ptr [g_bm_slot], eax     ; CF = old bit3
    setc    cl
    movzx   ecx, cl
    mov     [g_bm_cf], ecx
    mov     edx, [g_bm_slot]
    mov     [g_bm_bts], edx
    call    marker_end
    ret
rgn_bitops_lock ENDP

; ---- 3: REG-REG bit-op family (MIT-451 X5b B.4) — xadd/bts/btr/btc reg,reg
;      forms (no lock prefix). Virtualized via the REG-dst VmOp path
;      (b_kind=None discriminant); observable output = globals below. Also
;      probes the bit-index masking (index 35 -> bit 3, register-form &31).
rgn_bitops_reg PROC
    call    marker_begin
    mov     eax, 1000h
    mov     ecx, 20h
    xadd    eax, ecx                          ; eax=1020h, ecx=1000h (old)
    mov     [g_br_xa], eax
    mov     [g_br_old], ecx
    mov     edx, 0
    mov     ebx, 5
    bts     edx, ebx                          ; CF=0 (bit5 of 0), edx=20h
    setc    al
    movzx   ecx, al
    mov     [g_br_cf], ecx
    mov     [g_br_bts], edx
    mov     edx, 20h
    mov     ebx, 5
    btr     edx, ebx                          ; CF=1 (bit was set), edx=0
    setc    al
    movzx   ecx, al
    mov     [g_br_cf2], ecx
    mov     [g_br_btr], edx
    mov     edx, 8
    mov     ebx, 3
    btc     edx, ebx                          ; CF=1, edx=0
    mov     [g_br_btc], edx
    mov     edx, 0
    mov     ebx, 35                           ; index 35: register-form masks &31
    bts     edx, ebx                          ; -> bit 3, edx=8, CF=0
    mov     [g_br_msk], edx
    call    marker_end
    ret
rgn_bitops_reg ENDP

.data
PUBLIC g_b_pc, g_b_tz, g_b_lz, g_b_bs, g_b_cx, g_b_cx2, g_b_xg
PUBLIC g_bm_slot, g_bm_cx, g_bm_xa, g_bm_cf, g_bm_bts, g_br_xa, g_br_old, g_br_cf, g_br_bts, g_br_cf2, g_br_btr, g_br_btc, g_br_msk
ALIGN 4
g_b_pc    dword 0
g_b_tz    dword 0
g_b_lz    dword 0
g_b_bs    dword 0
g_b_cx    dword 0
g_b_cx2   dword 0, 0, 0
g_b_xg    dword 0, 0
g_bm_slot dword 0
g_bm_cx   dword 0
g_bm_xa   dword 0
g_bm_cf   dword 0
g_bm_bts  dword 0
g_br_xa   dword 0
g_br_old  dword 0
g_br_cf   dword 0
g_br_bts  dword 0
g_br_cf2  dword 0
g_br_btr  dword 0
g_br_btc  dword 0
g_br_msk  dword 0

END
