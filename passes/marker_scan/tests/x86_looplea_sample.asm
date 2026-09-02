; MIT-450 (X5) B.1 (5): x86 nested-loop + complex-LEA E2E sample (x86
; emit_address face: base+index*scale+disp and disp+index*scale forms, x64
; MIT-424/409 integer-core counterpart shapes).
;
; Region discipline: eax/ecx/edx only; loop counters in globals (no push);
; complex memory operands exercise the S32 address-arithmetic chain.

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

rgn_looplea PROC
    call    marker_begin
    mov     dword ptr [g_l_acc], 0
    mov     dword ptr [g_l_acc2], 0
    mov     dword ptr [g_l_i], 0
outer:
    mov     eax, [g_l_i]
    lea     edx, [eax+eax*2]                ; 3i (scale x2 form)
    add     edx, 10h
    add     [g_l_acc], edx
    mov     dword ptr [g_l_j], 0
inner:
    mov     eax, [g_l_j]
    mov     ecx, [g_l_i]
    lea     edx, [eax+ecx*4+20h]            ; j + 4i + disp (base+index*scale+disp)
    add     [g_l_acc2], edx
    ; disp + index*scale memory ALU operand
    mov     eax, [g_l_j]
    add     eax, [g_l_tab + ecx*4]
    add     [g_l_acc2], eax
    ; x5 multiply by lea + xor fold
    mov     eax, [g_l_acc2]
    lea     eax, [eax+eax*4]
    mov     [g_l_acc2], eax
    mov     eax, [g_l_j]
    inc     eax
    mov     [g_l_j], eax
    cmp     eax, 4
    jl      inner
    mov     eax, [g_l_i]
    inc     eax
    mov     [g_l_i], eax
    cmp     eax, 5
    jl      outer
    ; final fold: (5*acc2) ^ acc + table checksum via [tab + ecx*4]
    mov     eax, [g_l_acc2]
    xor     eax, [g_l_acc]
    mov     ecx, 5
    add     eax, [g_l_tab + ecx*4]          ; tab[5]
    mov     [g_l_out], eax
    call    marker_end
    ret
rgn_looplea ENDP

.data
PUBLIC g_l_acc, g_l_acc2, g_l_out, g_l_tab
ALIGN 4
g_l_acc  dword 0
g_l_acc2 dword 0
g_l_out  dword 0
g_l_i    dword 0
g_l_j    dword 0
g_l_tab  dd 100h, 200h, 300h, 400h, 500h, 600h, 700h, 800h

END
