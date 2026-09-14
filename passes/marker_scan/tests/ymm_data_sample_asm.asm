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

; ---- ③' ymm_arith(dst=rcx, src=rdx): packed 算术链 (MIT-513 wave2②) ----
; [rcx] = (2*src[0:32]) 逐 lane f32 翻倍；词流: load + vaddps(d==s1) +
; vxorps 清零 ymm1 + vaddps(dst, ymm0, ymm1) d 独立三地址 (extra pre-Mov)。
ymm_arith PROC
    ; ===== marker region begin =====
    sub   rsp, 28h
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vmovups ymm0, [rdx]               ; YmmLoad
    vaddps  ymm0, ymm0, ymm0          ; YmmAddps (d==s1 直走, 翻倍)
    vxorps  ymm1, ymm1, ymm1          ; YmmXorps (清零)
    vaddps  ymm2, ymm0, ymm1          ; YmmAddps (d 独立 → pre-Mov ymm0)
    vmovups [rcx], ymm2               ; YmmStore
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====
    xor eax, eax
    add   rsp, 28h
    ret
ymm_arith ENDP

; ---- ④ ymm_mix_neg(dst=rcx, src=rdx): ymm + legacy SSE 混排 → 原生 gate ----
; ⚠️ addps 置于 store 之后 (F1 修复): addps 破坏 xmm0 低半会随 32B store
; 落盘使拷贝非恒等 — 词流混排判据与指令序无关, gate 行为不变。
ymm_mix_neg PROC
    ; ===== marker region begin =====
    sub   rsp, 28h
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vmovups ymm0, [rdx]               ; Ymm 词
    vmovups [rcx], ymm0               ; 先 store (32B 恒等拷贝)
    addps   xmm0, xmm0                ; legacy SSE (混排判据命中 → gate)
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====
    xor eax, eax
    add   rsp, 28h
    ret
ymm_mix_neg ENDP

; ---- ⑥ ymm_pass_through(src=rcx): ymm 词后返回 — 物理 ymm0 读回钉 ----
; MIT-513 验收 F1 挂账 / T64 F4: 区域内 YmmLoad 写 ymm0 面 → 函数返回后
; stub 出口 ymm 回写使物理 ymm0 = 加载值, 宿主经 read_ymm0 thunk 观测
; (stub ymm 同步变体 disp32 行为级钉住, 字节计数之外的真值面)。
ymm_pass_through PROC
    ; ===== marker region begin =====
    sub   rsp, 28h
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vmovups ymm0, [rcx]               ; YmmLoad (单参 src=rcx; 返回值经 ymm0 出口回写)
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====
    add   rsp, 28h
    ret
ymm_pass_through ENDP

; ---- ⑦ ymm_mix_arith_neg(dst, src): ymm 算术 + legacy SSE 混排 → gate ----
; MIT-513 验收 F1: wave2① 混排 gate 值域判据 (含算术词) 的入池负例 —
; vaddps (Ymm 算术) + addps (legacy SSE) 同区 → 整函数原生, 行为 byte-exact。
; store 在 addps 之前 (恒等拷贝, addps 结果不落盘 — T64 验收 F1 教训)。
ymm_mix_arith_neg PROC
    ; ===== marker region begin =====
    sub   rsp, 28h
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    vmovups ymm0, [rdx]               ; YmmLoad
    vaddps  ymm0, ymm0, ymm0          ; Ymm 算术 (翻倍)
    vmovups [rcx], ymm0               ; store (翻倍值)
    addps   xmm1, xmm1                ; legacy SSE (混排判据命中 → gate)
    nop
    call ?marker_end@sdk@wvmp@@YAXXZ
    ; ===== marker region end =====
    xor eax, eax
    add   rsp, 28h
    ret
ymm_mix_arith_neg ENDP

; ---- read_ymm0(dst=rcx): 物理 ymm0 32B 捕获 thunk (区域外, 不虚拟化) ----
read_ymm0 PROC
    vmovups [rcx], ymm0
    ret
read_ymm0 ENDP

_TEXT ENDS
END
