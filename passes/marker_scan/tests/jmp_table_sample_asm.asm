; MIT-409 (MIT-A6): 跳转表负样本的 MASM 宿主 — opaque 间接 jmp。
;
; wv_opaque_jmp_masm: 标记区域内仅两条指令:
;   mov rax, QWORD PTR [g_fp]   ; rip-relative 全局函数指针读 (白名单 ✓)
;   jmp rax                     ; 计算跳转目标, 翻译期不可枚举 — 非四件套
;                               ; 跳转表形态 → C1 gate (函数保持原生)
; gate 后原字节原样执行: jmp rax 尾跳 → g_fp(n) → 其 ret 直接回到本函数
; 调用方 (尾调用语义, 与未打标行为完全一致)。
;
; 区域语义: marker_begin/marker_end 调用点界定区域; 区域尾 = marker_end
; call (不可达, 仅界定)。jmp 无 fallthrough, 区域无越区边。
;
; Win64 ABI: rcx = n (未用, 透传给 g_fp)。entry rsp ≡ 8 (mod 16) —
; marker_begin 是真实 call, 需 sub 8 对齐; 尾跳前加回, 使 jmp rax 时
; rsp = entry rsp (目标函数 ret 直接弹本函数调用方的返回址, 尾调用语义)。
; ⚠️ 禁止在尾跳前 sub 28h 之类栈调整——目标 ret 会弹错返回址 (首版事故)。

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXXZ : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC
EXTERNDEF g_fp : QWORD

_TEXT SEGMENT

wv_opaque_jmp_masm PROC
    sub  rsp, 8                      ; 对齐: entry ≡ 8 → call 前 ≡ 0
    call ?marker_begin@sdk@wvmp@@YAXXZ
    add  rsp, 8                      ; 恢复 entry rsp, 尾跳目标 ret 直通
    ; ===== marker region begin =====
    mov  rax, QWORD PTR [g_fp]      ; 全局函数指针 (rip-relative, 白名单)
    jmp  rax                        ; opaque 间接跳转 → 保守 gate
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    ret
wv_opaque_jmp_masm ENDP

_TEXT ENDS
END
