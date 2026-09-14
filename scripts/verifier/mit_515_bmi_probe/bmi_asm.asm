.code
; MIT-515 (T67) BMI G8b 决策备忘录实测探针 (Win64 x64)
;
; mulx_cf_probe(a=ecx, b=edx) -> eax = (CF_after << 1) | ZF_after
;   协议: 保存实参 → xor ecx,ecx 置 ZF=1 → stc 置 CF=1 →
;   mulx edi, ebx, r8d (dst=edi=hi, ebx=lo, src=r8d=b) →
;   pushfq 取标志镜像 → 提取 CF(bit0)/ZF(bit6)。
;   SDM 口径: MULX 不修改任何标志 → 期望返回 (1<<1)|1 = 3。
mulx_cf_probe PROC
    push rbx
    push rsi
    push rdi
    mov r8d, edx                 ; b
    mov edx, ecx                 ; EDX = a (MULX 隐式被乘数 = EDX; 验收 F1:
                                 ;   原版漏此行实算 b×b, 核心结论不受影响
                                 ;   但描述失真)
    xor ecx, ecx                 ; ZF = 1
    stc                          ; CF = 1
    mulx edi, ebx, r8d           ; edi=hi(a*b), ebx=lo(a*b)
    pushfq                       ; 保存 mulx 后标志镜像
    pop rsi
    mov eax, esi
    and eax, 1                   ; CF_after
    mov edx, esi
    shr edx, 6
    and edx, 1                   ; ZF_after
    shl eax, 1
    or eax, edx                  ; (CF<<1)|ZF
    pop rdi
    pop rsi
    pop rbx
    ret
mulx_cf_probe ENDP

; pdep_probe(x=ecx, mask=edx) -> eax
pdep_probe PROC
    mov eax, ecx
    pdep eax, eax, edx
    ret
pdep_probe ENDP

; pext_probe(x=ecx, mask=edx) -> eax
pext_probe PROC
    mov eax, ecx
    pext eax, eax, edx
    ret
pext_probe ENDP

END
