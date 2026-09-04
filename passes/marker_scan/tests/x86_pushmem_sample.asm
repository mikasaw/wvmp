; MIT-456 (push-mem): x86 push [mem] E2E sample -- in-region memory-sourced
; push shapes virtualized through the address-slot + Load + single-op
; Push/Reg fold (asmgen zero-diff; handler a_kind=Reg branch). Region faces:
;   1. push [abs] (FF 35 disp32): global memory source.
;   2. push [reg+disp8] (FF 71 04): IAT-style register-indirect face.
;   3. push [esp+disp8] (FF 74 24 04): the core_os stack-window idiom --
;      reads with PRE-push esp ([esp+4] after two pushes = the first push).
;   4. call-arg push [mem] pair + callgate + cdecl cleanup inside region.
; Net stack depth 0 at Halt (balanced push/pop/add-esp); native vs packed
; byte-exact (rc=0 sentinel). MASM encoding faces pinned by dumpbin in the
; MIT-456 report (FF 35 / FF 71 04 / FF 74 24 04 per form).

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

PUBLIC rgn_pushmem
PUBLIC g_pm_a, g_pm_b, g_pm_stk, g_pm_ret
; cdecl helper: returns arg0 + arg1 (reads the pushed mem-sourced dwords
; from its stack frame; same shape as pi_helper in the pushimm sample but
; the pushed values come from memory, not immediates).
pm_helper PROC
    mov     eax, [esp+4]                ; arg0 = last push ([g_pm_arg1])
    add     eax, [esp+8]                ; arg1 = [g_pm_arg0]
    ret
pm_helper ENDP

rgn_pushmem PROC
    call    marker_begin
    ; -- 1. push [abs] (FF 35 disp32) --
    push    dword ptr [g_pm_src]        ; FF 35 <moffs>
    pop     eax
    mov     [g_pm_a], eax
    ; -- 2. push [reg+disp8] (FF 71 04, IAT thunk face) --
    mov     ecx, offset g_pm_tbl
    push    dword ptr [ecx+4]           ; reads g_pm_tbl+4
    pop     eax
    mov     [g_pm_b], eax
    ; -- 3. push [esp+disp8] (FF 74 24 04, stack-window idiom) --
    push    11111111h                   ; d=4   [esp+4] after next push
    push    22222222h                   ; d=8   [esp] now
    push    dword ptr [esp+4]           ; d=12  reads 11111111h (pre-push esp)
    pop     eax                         ; d=8
    mov     [g_pm_stk], eax
    add     esp, 8                      ; d=0, case balanced
    ; -- 4. call-arg push [mem] pair (guard zone args, cdecl cleanup) --
    push    dword ptr [g_pm_arg0]       ; d=4
    push    dword ptr [g_pm_arg1]       ; d=8
    call    pm_helper                   ; callgate RVA form
    add     esp, 8                      ; d=0
    mov     [g_pm_ret], eax             ; 11112222h
    call    marker_end
    ret
rgn_pushmem ENDP

.data
ALIGN 4
g_pm_src  dword 0AAAA1111h
g_pm_tbl  dword 0BBBB2222h
          dword 0CCCC3333h
g_pm_a    dword 0
g_pm_b    dword 0
g_pm_stk  dword 0
g_pm_arg0 dword 011110000h
g_pm_arg1 dword 000002222h
g_pm_ret  dword 0

END
