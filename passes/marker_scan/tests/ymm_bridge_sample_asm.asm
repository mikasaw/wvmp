; MIT-533 (wave2 桥): vextractf128/vinsertf128 真虚拟化样本。
;
; 正例区 (纯 ymm+桥+mem 词链, 无 legacy SSE 词 → 不触发混排 gate,
;           stub 携带 ymm 同步变体):
;   ① ymm_swap_hi(dst=rcx, src=rdx): extract lane1→xmm1 (reg 形) /
;      vinsert d!=s1 (前置 YmmMov 折叠) / extract lane0 / vinsert d==s1
;      直折 (幂等) / store —— 结果 = (src_hi, src_hi)。
;   ② ymm_bridge_mem(dst=rcx, src=rdx): vextract [rcx+32]←ymm0 lane1
;      (mem 形) + vinsert ymm1, ymm0, [rdx+16], 0 (mem 源, 前置 Mov) →
;      store —— dst[0..32) = (src[16..32), src[16..32)), dst[32..48) = hi。
; 负例区 (整函数原生, 行为 byte-exact):
;   ③ ymm_bridge_mix_neg: 桥 + addps legacy SSE 同函数 → 混排 gate
;      (store 在 addps 之前 —— T64 验收 F1 教训, 结果不依赖 addps)。
;
; Win64 ABI: 整型参数 rcx/rdx; 返回值 rax。

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; ---- ① ymm_swap_hi(dst=rcx, src=rdx): (hi, hi) ----
ymm_swap_hi PROC
    ; ===== marker region begin =====
    sub   rsp, 28h                    ; MIT-475: shadow space + alignment
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vmovups ymm0, [rdx]               ; YmmLoad
    vextractf128 xmm1, ymm0, 1        ; VextractF128 reg lane1 → xmm1 = hi
    vinsertf128 ymm2, ymm0, xmm1, 0   ; VinsertF128 d!=s1 → 前置 YmmMov; ymm2 = (hi, hi)
    vextractf128 xmm3, ymm2, 0        ; lane0 抽出 (= hi)
    vinsertf128 ymm2, ymm2, xmm3, 1   ; d==s1 直折 (幂等写回高车道)
    vmovups [rcx], ymm2               ; YmmStore
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====
    xor eax, eax
    add   rsp, 28h
    ret
ymm_swap_hi ENDP

; ---- ② ymm_bridge_mem(dst=rcx, src=rdx): mem 双形 ----
ymm_bridge_mem PROC
    ; ===== marker region begin =====
    sub   rsp, 28h
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vmovups ymm0, [rdx]               ; YmmLoad src[0..32)
    vextractf128 oword ptr [rcx+32], ymm0, 1    ; VextractF128 mem: dst[32..48) = src hi
    vinsertf128 ymm1, ymm0, oword ptr [rdx+16], 0 ; VinsertF128 mem 源 (前置): ymm1 = (src[16..32), hi)
    vmovups [rcx], ymm1               ; YmmStore
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====
    xor eax, eax
    add   rsp, 28h
    ret
ymm_bridge_mem ENDP

; ---- ③ ymm_bridge_mix_neg(dst=rcx, src=rdx): 混排 gate 负例 ----
ymm_bridge_mix_neg PROC
    ; ===== marker region begin =====
    sub   rsp, 28h
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vmovups ymm0, [rdx]               ; YmmLoad
    vmovups [rcx], ymm0               ; YmmStore (先落盘 — 结果不依赖 addps)
    vextractf128 xmm1, ymm0, 1        ; VextractF128 (桥词)
    addps  xmm1, xmm1                 ; legacy SSE → 混排 gate 整函数原生
    nop
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====
    xor eax, eax
    add   rsp, 28h
    ret
ymm_bridge_mix_neg ENDP

_TEXT ENDS
END
