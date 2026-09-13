; MIT-512 (T64 · 档B wave2①): ymm 数据通路样本 — vmov* ymm 传送词真虚拟化。
;
; 正例区 (真虚拟化, stub 携带 ymm 同步变体 — 区域词流含 Ymm* 词):
;   ① vmovups ymm load/store 32B 拷贝链 (基址寄存器 mem 形, 408 同款)
;   ② load → vmovaps reg-reg (YmmMov 折) → vmovdqa reg-reg (YmmMov 折) →
;      store 全词链
;   ③ vzeroupper + ymm 词共存 (vzeroupper 非 legacy SSE 词, 不触发混排
;      gate — MIT-512 判据面)
;   负例区 (整函数原生, 可调用, 行为 byte-exact):
;   ④ ymm + legacy SSE 混排 (wave2① 混排契约未落地的保守 gate)
;
; Win64 ABI: 整型参数 rcx/rdx; 返回值 rax。
; ⚠️ 面访问一律 vmovups (ctx 栈基址仅 16B 对齐, MIT-511 F3 口径)。

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; ---- ① ymm_copy32(dst=rcx, src=rdx): 32B 拷贝 (load+store) ----
ymm_copy32 PROC
    ; ===== marker region begin =====
    sub   rsp, 28h                    ; MIT-475: shadow space + alignment
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vmovups ymm0, [rdx]               ; YmmLoad
    vmovups [rcx], ymm0               ; YmmStore
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====
    xor eax, eax
    add   rsp, 28h
    ret
ymm_copy32 ENDP

; ---- ② ymm_chain32(dst=rcx, src=rdx): load→mov(aps)→mov(dqa)→store ----
ymm_chain32 PROC
    ; ===== marker region begin =====
    sub   rsp, 28h
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vmovups ymm0, [rdx]               ; YmmLoad
    vmovaps ymm1, ymm0                ; YmmMov (vmovaps 折叠)
    vmovdqa ymm2, ymm1                ; YmmMov (vmovdqa 折叠)
    vmovups [rcx], ymm2               ; YmmStore
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====
    xor eax, eax
    add   rsp, 28h
    ret
ymm_chain32 ENDP

; ---- ③ ymm_vzero_mix(dst=rcx, src=rdx): vzeroupper + ymm 词共存 ----
ymm_vzero_mix PROC
    ; ===== marker region begin =====
    sub   rsp, 28h
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vzeroupper                        ; MIT-511 ABI 词 (不进混排判据)
    vmovups ymm0, [rdx]               ; YmmLoad
    vmovups [rcx], ymm0               ; YmmStore
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====
    xor eax, eax
    add   rsp, 28h
    ret
ymm_vzero_mix ENDP

; ---- ④ ymm_mix_neg(dst=rcx, src=rdx): ymm + legacy SSE 混排 → 原生 gate ----
ymm_mix_neg PROC
    ; ===== marker region begin =====
    sub   rsp, 28h
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vmovups ymm0, [rdx]               ; Ymm 词
    addps   xmm0, xmm0                ; legacy SSE (混排判据命中 → gate)
    vmovups [rcx], ymm0
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====
    xor eax, eax
    add   rsp, 28h
    ret
ymm_mix_neg ENDP

_TEXT ENDS
END
