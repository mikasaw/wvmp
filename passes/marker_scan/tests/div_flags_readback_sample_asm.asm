; MIT-404 影子样本 (div_flags_readback) 的 MASM helper —— div/idiv 的
; Rax/Rdx 双槽 + flags 运行时读回断言 (对齐 MIT-376 bwcmpss flags readback
; 模式, 派活单 §B.6 / §C D4.1)。
;
; 为什么需要影子样本 (MIT-371 空转教训): Div/Idiv handler 的正确性在
; Rax/Rdx 双结果槽 (商→Rax 槽, 余→Rdx 槽) 与 VM flags 槽。handler 若空转
; (decode+advance) 或写错槽, 主样本 stdout 虽然也能对上 (区域结果没被
; 消费) — 本样本把断言做成显式输出:
;   1. out[0]/out[1] = 商/余 (区域内存 store, 槽写错即不一致 → FAIL);
;   2. out[2..6] = setz/setc/seto/sets/setp 五探针 — Setcc handler 读
;      Div/Idiv handler flags_tail 写的 VM flags 槽。flags 按 Intel
;      undefined, 但 VM 与 native 在同一 CPU 执行同一条 div/idiv →
;      真值逐位一致 (D4.1: 处置照抄 build_imul 的可观测推论)。
;
; Win64 ABI / 栈对齐 / rax clobber 约定同 div_sample_asm.asm。

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; void dfr_idiv64(int64_t a, int64_t b, uint64_t out[8])
;   out[0]=商 out[1]=余 out[2]=ZF out[3]=CF out[4]=OF out[5]=SF out[6]=PF
dfr_idiv64 PROC
    push rbx
    push rdi
    sub  rsp, 38h
    mov  [rsp+20h], rcx                 ; a
    mov  [rsp+28h], rdx                 ; b
    mov  rbx, r8                        ; out (callee-saved 跨 marker 调用)
    call ?marker_begin@sdk@wvmp@@YAXXZ
    ; ===== marker region begin =====
    mov  rax, [rsp+20h]                 ; rax = a
    mov  rdi, [rsp+28h]                 ; rdi = b
    cqo                                 ; 48 99
    idiv rdi                            ; 48 F7 FF (REG)
    mov  [rbx], rax                     ; out[0] = 商
    mov  [rbx+8], rdx                   ; out[1] = 余
    setz al                             ; 五探针: Setcc handler 读 VM flags 槽
    movzx rax, al
    mov  [rbx+10h], rax                 ; out[2] = ZF
    setc al
    movzx rax, al
    mov  [rbx+18h], rax                 ; out[3] = CF
    seto al
    movzx rax, al
    mov  [rbx+20h], rax                 ; out[4] = OF
    sets al
    movzx rax, al
    mov  [rbx+28h], rax                 ; out[5] = SF
    setp al
    movzx rax, al
    mov  [rbx+30h], rax                 ; out[6] = PF
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    add  rsp, 38h
    pop  rdi
    pop  rbx
    ret
dfr_idiv64 ENDP

; void dfr_div32(uint32_t a, uint32_t b, uint64_t out[8])
;   cdq + div ecx (REG 形式); 槽位布局同 dfr_idiv64。
dfr_div32 PROC
    push rbx
    sub  rsp, 30h
    mov  dword ptr [rsp+20h], ecx       ; a
    mov  dword ptr [rsp+24h], edx       ; b
    mov  rbx, r8                        ; out
    call ?marker_begin@sdk@wvmp@@YAXXZ
    ; ===== marker region begin =====
    mov  eax, dword ptr [rsp+20h]       ; eax = a
    mov  ecx, dword ptr [rsp+24h]       ; ecx = b
    cdq                                 ; 99
    div  ecx                            ; F7 F1 (REG)
    mov  [rbx], rax                     ; out[0] = 商 (高 32 位由 32 位写语义定)
    mov  [rbx+8], rdx                   ; out[1] = 余
    setz al
    movzx rax, al
    mov  [rbx+10h], rax                 ; out[2] = ZF
    setc al
    movzx rax, al
    mov  [rbx+18h], rax                 ; out[3] = CF
    seto al
    movzx rax, al
    mov  [rbx+20h], rax                 ; out[4] = OF
    sets al
    movzx rax, al
    mov  [rbx+28h], rax                 ; out[5] = SF
    setp al
    movzx rax, al
    mov  [rbx+30h], rax                 ; out[6] = PF
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    add  rsp, 30h
    pop  rbx
    ret
dfr_div32 ENDP

; void dfr_idiv32(int32_t a, int32_t b, uint64_t out[8])
;   cdq + idiv [rsp+24h] (MEM 形式); 负数组合; 槽位布局同 dfr_idiv64。
dfr_idiv32 PROC
    push rbx
    sub  rsp, 30h
    mov  dword ptr [rsp+20h], ecx       ; a
    mov  dword ptr [rsp+24h], edx       ; b (MEM 除数)
    mov  rbx, r8
    call ?marker_begin@sdk@wvmp@@YAXXZ
    ; ===== marker region begin =====
    mov  eax, dword ptr [rsp+20h]       ; eax = a
    cdq                                 ; 99
    idiv dword ptr [rsp+24h]            ; F7 /7 MEM
    mov  [rbx], rax
    mov  [rbx+8], rdx
    setz al
    movzx rax, al
    mov  [rbx+10h], rax
    setc al
    movzx rax, al
    mov  [rbx+18h], rax
    seto al
    movzx rax, al
    mov  [rbx+20h], rax
    sets al
    movzx rax, al
    mov  [rbx+28h], rax
    setp al
    movzx rax, al
    mov  [rbx+30h], rax
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    add  rsp, 30h
    pop  rbx
    ret
dfr_idiv32 ENDP

_TEXT ENDS

END
