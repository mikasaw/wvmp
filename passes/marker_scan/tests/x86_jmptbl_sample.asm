; MIT-450 (X5) B.1 (2): x86 jump-table E2E sample -- 4B table forms.
;
; X5 first-pass finding (kept as designed gate negatives, evidence in the
; protect log): ALL five x86 jump-table shapes gate with "间接 jmp 未支持".
; The translator's jump-table matcher (try_match_jump_table) hardcodes the
; x64 word size at two points -- the base-load check (lea/movabs
; `size != ir::Size::S64` -> nullopt) and the delta-add check
; (`add.size != ir::Size::S64` -> nullopt) -- so x86 S32 chains never match
; and the indirect jmp falls back to the C1 gate. Byte-exact native
; fallback is CORRECT behavior (no silent wrong-target risk); making the
; matcher width-aware is a separate per-family ticket (G8a pattern), not
; done in X5 (D5 zero product diff).
;
; Forms covered (all callable natively; poison entries never selected):
;   wv_jt4_abs    REG-source 4B absolute table (entries = full VA)
;   wv_jt4_delta  REG-source 4B delta table (entries = case - table base)
;   wv_jtm4_abs   MEM-source direct jump (jmp dword ptr [ecx+eax*4])
;   wv_jt4_undef  negative: no cmp/ja defense (test+jz boundary)
;   wv_jt4_oob    negative: entry 3 -> wv_other_fn (out of region)
; rgn_jt_helper -- pure GP face, provides the REQUIRE_REAL >=1 stub.
; Region discipline: eax/ecx/edx only; result spill [esp+10h] (>= ns).

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

; ---- 1: REG-source 4B absolute table ----
wv_jt4_abs PROC
    sub     esp, 20h
    call    marker_begin
    mov     eax, [g_sel]
    cmp     eax, 7
    ja      jt4a_default                    ; defense constant (K=8)
    mov     eax, [g_sel]                    ; il: idx reload (MSVC /Od shape)
    mov     ecx, OFFSET jt4a_tbl
    mov     edx, [ecx+eax*4]                ; 4B entry, no add -> absolute VA
    jmp     edx
jt4a_case0:: mov eax, 100h
    jmp     jt4a_join
jt4a_case1:: mov eax, 101h
    jmp     jt4a_join
jt4a_case2:: mov eax, 102h
    jmp     jt4a_join
jt4a_case3:: mov eax, 103h
    jmp     jt4a_join
jt4a_case4:: mov eax, 104h
    jmp     jt4a_join
jt4a_case5:: mov eax, 105h
    jmp     jt4a_join
jt4a_case6:: mov eax, 106h
    jmp     jt4a_join
jt4a_case7:: mov eax, 107h
    jmp     jt4a_join
jt4a_default: mov eax, 1FFh
jt4a_join: mov [esp+10h], eax
    call    marker_end
    mov     eax, [esp+10h]
    add     esp, 20h
    ret
wv_jt4_abs ENDP

; ---- 2: REG-source 4B delta table (table follows the function in .text) ----
wv_jt4_delta PROC
    sub     esp, 20h
    call    marker_begin
    mov     eax, [g_sel]
    cmp     eax, 7
    ja      jt4d_default
    mov     eax, [g_sel]
    mov     ecx, OFFSET jt4d_tbl
    mov     edx, [ecx+eax*4]
    add     edx, ecx                        ; delta + table base -> target VA
    jmp     edx
jt4d_case0:: mov eax, 200h
    jmp     jt4d_join
jt4d_case1:: mov eax, 201h
    jmp     jt4d_join
jt4d_case2:: mov eax, 202h
    jmp     jt4d_join
jt4d_case3:: mov eax, 203h
    jmp     jt4d_join
jt4d_case4:: mov eax, 204h
    jmp     jt4d_join
jt4d_case5:: mov eax, 205h
    jmp     jt4d_join
jt4d_case6:: mov eax, 206h
    jmp     jt4d_join
jt4d_case7:: mov eax, 207h
    jmp     jt4d_join
jt4d_default: mov eax, 2FFh
jt4d_join: mov [esp+10h], eax
    call    marker_end
    mov     eax, [esp+10h]
    add     esp, 20h
    ret
jt4d_tbl dd jt4d_case0 - jt4d_tbl, jt4d_case1 - jt4d_tbl, jt4d_case2 - jt4d_tbl, jt4d_case3 - jt4d_tbl
         dd jt4d_case4 - jt4d_tbl, jt4d_case5 - jt4d_tbl, jt4d_case6 - jt4d_tbl, jt4d_case7 - jt4d_tbl
wv_jt4_delta ENDP

; ---- 3: MEM-source direct jump (FF 24 81), absolute entries ----
wv_jtm4_abs PROC
    sub     esp, 20h
    call    marker_begin
    mov     eax, [g_sel]
    cmp     eax, 7
    ja      jtma_default
    mov     eax, [g_sel]
    mov     ecx, OFFSET jtma_tbl
    jmp     dword ptr [ecx+eax*4]
jtma_case0:: mov eax, 300h
    jmp     jtma_join
jtma_case1:: mov eax, 301h
    jmp     jtma_join
jtma_case2:: mov eax, 302h
    jmp     jtma_join
jtma_case3:: mov eax, 303h
    jmp     jtma_join
jtma_case4:: mov eax, 304h
    jmp     jtma_join
jtma_case5:: mov eax, 305h
    jmp     jtma_join
jtma_case6:: mov eax, 306h
    jmp     jtma_join
jtma_case7:: mov eax, 307h
    jmp     jtma_join
jtma_default: mov eax, 3FFh
jtma_join: mov [esp+10h], eax
    call    marker_end
    mov     eax, [esp+10h]
    add     esp, 20h
    ret
wv_jtm4_abs ENDP

; ---- 4: negative, no defense constant (test+jz boundary, cond=E) ----
wv_jt4_undef PROC
    sub     esp, 20h
    call    marker_begin
    mov     eax, [g_sel]
    test    eax, eax                        ; block boundary, NOT a defense
    jz      jtun_case0
    mov     eax, [g_sel]
    mov     ecx, OFFSET jtun_tbl
    mov     edx, [ecx+eax*4]
    add     edx, ecx
    jmp     edx
jtun_case0:: mov eax, 400h
    jmp     jtun_join
jtun_case1:: mov eax, 401h
    jmp     jtun_join
jtun_case2:: mov eax, 402h
    jmp     jtun_join
jtun_case3:: mov eax, 403h
    jmp     jtun_join
jtun_case4:: mov eax, 404h
    jmp     jtun_join
jtun_case5:: mov eax, 405h
    jmp     jtun_join
jtun_case6:: mov eax, 406h
    jmp     jtun_join
jtun_case7:: mov eax, 407h
    jmp     jtun_join
jtun_join: mov [esp+10h], eax
    call    marker_end
    mov     eax, [esp+10h]
    add     esp, 20h
    ret
jtun_tbl dd jtun_case0 - jtun_tbl, jtun_case1 - jtun_tbl, jtun_case2 - jtun_tbl, jtun_case3 - jtun_tbl
         dd jtun_case4 - jtun_tbl, jtun_case5 - jtun_tbl, jtun_case6 - jtun_tbl, jtun_case7 - jtun_tbl
wv_jt4_undef ENDP

; ---- 5: negative, entry 3 -> wv_other_fn (out of region) ----
wv_jt4_oob PROC
    sub     esp, 20h
    call    marker_begin
    mov     eax, [g_sel]
    cmp     eax, 7
    ja      jtoo_default
    mov     eax, [g_sel]
    mov     ecx, OFFSET jtoo_tbl
    mov     edx, [ecx+eax*4]
    jmp     edx
jtoo_case0:: mov eax, 500h
    jmp     jtoo_join
jtoo_case1:: mov eax, 501h
    jmp     jtoo_join
jtoo_case2:: mov eax, 502h
    jmp     jtoo_join
jtoo_case3:: mov eax, 503h
    jmp     jtoo_join
jtoo_case4:: mov eax, 504h
    jmp     jtoo_join
jtoo_case5:: mov eax, 505h
    jmp     jtoo_join
jtoo_case6:: mov eax, 506h
    jmp     jtoo_join
jtoo_case7:: mov eax, 507h
    jmp     jtoo_join
jtoo_default: mov eax, 5FFh
jtoo_join: mov [esp+10h], eax
    call    marker_end
    mov     eax, [esp+10h]
    add     esp, 20h
    ret
wv_jt4_oob ENDP

; ---- target for the oob poison entry (out of every region) ----
wv_other_fn PROC
    mov     eax, 0DEADFACEh
    ret
wv_other_fn ENDP

; ---- pure GP helper: REQUIRE_REAL >=1 stub source ----
rgn_jt_helper PROC
    call    marker_begin
    mov     eax, 0ADD1E5Ah
    xor     eax, 00C0FFEEh
    sub     eax, 11111111h
    ror     eax, 7
    mov     dword ptr [g_jh_out], eax
    call    marker_end
    ret
rgn_jt_helper ENDP

.data
PUBLIC g_sel, g_jh_out
g_sel   dword 0
g_jh_out dword 0

; ---- absolute VA tables (.rdata; file value = link-time VA, ASLR-independent) ----
_RDATA SEGMENT READONLY
ALIGN 4
jt4a_tbl dd jt4a_case0, jt4a_case1, jt4a_case2, jt4a_case3
         dd jt4a_case4, jt4a_case5, jt4a_case6, jt4a_case7
jtma_tbl dd jtma_case0, jtma_case1, jtma_case2, jtma_case3
         dd jtma_case4, jtma_case5, jtma_case6, jtma_case7
jtoo_tbl dd jtoo_case0, jtoo_case1, jtoo_case2, wv_other_fn
         dd jtoo_case4, jtoo_case5, jtoo_case6, jtoo_case7
_RDATA ENDS

END
