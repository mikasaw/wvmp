; MIT-446 (X4) B.4 ①: x86 E2E first-batch sample -- integer + control flow
; (forkface-x86 port: arith/loop + leave/ret epilogue + rep strings + p66
; S16/cwde/cbw + call reg/call [mem] + ret imm16 + x87 gate negative zone).
;
; Layout mirrors x86_marker_sample.asm (MIT-437 recipe):
;   - hand-written marker stubs, /Od form (B8 hi -> C7 lo, 3B gap);
;   - >64B nop pad before the first anchor (MIT-349 pitfall #39: CRT
;     `call main` phantom-begin defense);
;   - regions between call marker_begin / call marker_end.
;
; Guest stack discipline (442 rule: guest stack writes always >= ns): no
; push/pop inside regions. rgn_epilogue's leave/ret operates on the native
; prologue frame (above ns); rgn_stdcall2 reads args above ns; rgn_callgate
; (sample 3) writes args into the prologue-reserved scratch at [v4+k] (>= ns).
; x87 region is a DESIGNED gate negative (R-SSE-only ruling): lifter has no
; x87 case -> whole function stays native (C1 gate note in protect log).

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

; ---- native helpers (call targets for call reg / call [mem]) ----
helper_a PROC
    mov     eax, 11111111h
    ret
helper_a ENDP

helper_b PROC
    mov     eax, 22222222h
    ret
helper_b ENDP

g_fp_a dword helper_a
g_fp_b dword helper_b

; ================================================================
; rgn_arith_ctrl: integer ALU + loop + control flow + bit ops, results
; accumulated into g_int_out. Pure VM-supported x86 integer face.
; ================================================================
rgn_arith_ctrl PROC
    call    marker_begin
    mov     dword ptr [g_acc], 0            ; acc in memory (no callee-saved regs)
    mov     dword ptr [g_i], 0              ; i in memory
loop_head:
    mov     eax, [g_i]
    imul    eax, eax, 31                    ; eax = i*31
    add     eax, [g_acc]
    xor     eax, 0DEADBEEFh
    mov     edx, eax
    sar     edx, 3                          ; arithmetic shift right
    xor     eax, edx
    mov     ecx, [g_i]
    and     ecx, 7
    shl     eax, cl                         ; cl-count shift
    or      eax, 1
    test    eax, 80000000h
    jz      skip_neg
    neg     eax
skip_neg:
    add     [g_acc], eax
    mov     eax, [g_i]
    inc     eax
    mov     [g_i], eax
    cmp     eax, 5
    jl      loop_head
    ; not/add/adc/sbb chain via flags (CF propagation)
    mov     eax, [g_acc]
    not     eax
    add     eax, 7FFFFFFFh
    adc     eax, 0
    sbb     eax, 1                          ; consume CF of adc
    ; bswap + movzx + setcc + cmovcc
    bswap   eax
    movzx   edx, al
    add     edx, 42
    cmp     edx, 100
    setb    cl
    movzx   ecx, cl
    mov     edx, 200
    cmp     edx, 100
    cmova   edx, ecx                        ; edx = 200 > 100 ? 1 : 200
    add     eax, edx
    ; xchg probe (reg-reg; bts/btr/btc are G4-lock-face, lifter-gated)
    mov     edx, eax
    xor     edx, 00F000F0h
    xchg    eax, edx
    sub     eax, edx
    ; rotate family
    rol     eax, 5
    ror     eax, 2
    mov     [g_int_out], eax
    call    marker_end
    ret
rgn_arith_ctrl ENDP

; ================================================================
; rgn_epilogue: leave + ret inside the region (prologue runs natively
; before the marker site; leave/pop touch [ebp-k] >= ns only).
; Returns ebp ^ 12345678h to the caller via eax; the end marker call is
; unreachable after ret (anchor bytes still present for the scanner).
; ================================================================
rgn_epilogue PROC
    push    ebp
    mov     ebp, esp
    sub     esp, 8
    call    marker_begin
    mov     dword ptr [ebp-4], 0BADB0B00h
    mov     eax, [ebp-4]
    xor     eax, ebp
    xor     eax, 12345678h
    mov     esp, ebp                        ; leave face (folded in VM)
    pop     ebp
    ret                                     ; plain ret inside region
    call    marker_end
rgn_epilogue ENDP

; ================================================================
; rgn_strings: cld + rep movsb (odd, unaligned) + rep stosd + repne scasb
; early-exit + lodsd. esi/edi/ecx are guest slots; DF=0 per ABI.
; ================================================================
rgn_strings PROC
    call    marker_begin
    mov     [g_sv_esi], esi                 ; callee-saved via globals (no push)
    mov     [g_sv_edi], edi
    cld
    mov     esi, offset g_src_buf
    add     esi, 3                          ; unaligned source
    mov     edi, offset g_dst_buf
    mov     ecx, 13
    rep     movsb                           ; 13 unaligned bytes
    mov     edi, offset g_dst_buf
    mov     ecx, 5
    mov     eax, 5A5A5A5Ah
    rep     stosd                           ; overwrite first 20 bytes
    mov     edi, offset g_dst_buf
    mov     ecx, 20
    mov     eax, 0ABCD0000h
    repne   scasd                           ; scan for first nonzero match slot
    jne     str_notfound
str_found:
    sub     edi, 4
    jmp     str_common
str_notfound:
    mov     edi, offset g_dst_buf
str_common:
    mov     esi, offset g_src_buf
    lodsd                                   ; eax = first dword of src
    xor     eax, dword ptr [edi]
    mov     [g_str_out], eax
    mov     esi, [g_sv_esi]                 ; restore callee-saved (native face)
    mov     edi, [g_sv_edi]
    call    marker_end
    ret
rgn_strings ENDP

; ================================================================
; rgn_s16: p66 operand-size face (S16 ALU + store) + cwde + cbw.
; ================================================================
rgn_s16 PROC
    call    marker_begin
    mov     ax, 0BEEFh                      ; 66 B8 imm16
    add     ax, 0123h                       ; 66 05 imm16
    sub     ax, 8
    mov     word ptr [g_s16_out], ax        ; 66 89 05 store S16
    cwde                                    ; 98: eax = sx32(ax)
    add     eax, 10000h
    mov     al, 88h
    cbw                                     ; 66 98: ax = sx16(al)
    add     dword ptr [g_s16_out], eax
    call    marker_end
    ret
rgn_s16 ENDP

; ================================================================
; rgn_indirect_calls: call [mem] (FF 15) + call reg (FF D0), 0-arg
; helpers; results xor-folded into g_call_out. CallGate reg/mem forms.
; ================================================================
rgn_indirect_calls PROC
    call    marker_begin
    mov     dword ptr [g_call_out], 0
    call    dword ptr [g_fp_a]              ; call [mem] (IAT-like form)
    mov     [g_call_out], eax
    call    dword ptr [g_fp_b]
    xor     [g_call_out], eax
    mov     eax, offset helper_a
    call    eax                             ; call reg
    xor     [g_call_out], eax
    call    marker_end
    ret
rgn_indirect_calls ENDP

; ================================================================
; rgn_stdcall2: ret imm16 (stdcall-style stack cleanup) inside the
; region. Args read at [esp+4]/[esp+8] (>= ns, native caller pushes).
; The ret 8 exits the VM straight to the caller (Ret 4B handler).
; ================================================================
run_stdcall2 PROC                          ; cdecl wrapper (native)
    push    5678h
    push    1234h
    call    rgn_stdcall2                    ; ret 8 cleans both
    ret
run_stdcall2 ENDP

rgn_stdcall2 PROC
    call    marker_begin
    mov     eax, [esp+4]
    xor     eax, [esp+8]
    xor     eax, 77777777h
    ret     8
    call    marker_end
rgn_stdcall2 ENDP

; ================================================================
; rgn_x87_gate: DESIGNED gate negative (x87 = R-SSE-only ruling, GAPS
; x87 section). The lifter has no x87 case -> whole function gates
; native (C1 note in the protect log); callable, byte-exact by native
; double run. Never extended: x87 is permanently unsupported.
; ================================================================
rgn_x87_gate PROC
    call    marker_begin
    fld     dword ptr [g_f32]
    fadd    dword ptr [g_f32]
    fstp    dword ptr [g_f32]
    call    marker_end
    ret
rgn_x87_gate ENDP

.data
PUBLIC g_int_out, g_str_out, g_s16_out, g_call_out, g_acc, g_i, g_sv_esi, g_sv_edi
g_int_out   dword 0
g_acc       dword 0
g_i         dword 0
g_sv_esi    dword 0
g_sv_edi    dword 0
g_str_out   dword 0
g_s16_out   word  0
            word  0
g_call_out  dword 0
g_src_buf  db 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
g_dst_buf  db 16 dup (0)
g_f32      dd 1.5

END
