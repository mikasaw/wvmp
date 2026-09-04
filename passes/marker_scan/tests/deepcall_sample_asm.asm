; MIT-406 (MIT-E1): callee 专用栈窗口 E2E 样本的 MASM helper — 深 call 递归链。
;
; 背景 (派活单 §A): callgate 的 native callee 树原本从 native_sp-0x28 向下
; 生长, 与驻留同栈的 VmContext (kCtxSize=0x1C8, 驻留 [native_sp-0x208,
; native_sp-0x40)) 只隔 0x1D8 预算 — wvmpTest sha256 (调用树深 ~0x250B)
; 砸穿 ctx → packed.exe 0xC0000005。既有 call_gate 样本 callee 全浅帧
; (<=0x30B), 从未测过预算边界。本样本提供**静态可核算**的深递归链:
;
;   帧深核算 (每层, 从 parent 的 call 指令起):
;     call 压返回地址        8
;     push rbx               8
;     sub  rsp, 50h         0x50   (0x50 % 16 == 0, 保持 call 前 rsp 16 对齐)
;     合计每层              0x60
;   递归 32 层 (levels=0x20): 总树深 = 32 x 0x60 = 0xC00
;     - MIT-407 (D2) 加深: 16 层 0x600 时 pre-E1 反证不复现 (E1 裁定 §4 疑云,
;       L1 遗留"未压到旧预算痛点")。0xC00 = 3.2x 旧预算 0x1D8, 且 < 窗口
;       0x1000 (最深 ns-0x28-0xC00 = ns-0xC28 > 窗口底 ns-0x1028, 余量
;       0x400) —— pre-E1 必砸 ctx, post-E1 窗口内零重叠, 区分度闭合。
;   旧预算 0x1D8 (native_sp-0x28 到 ctx 顶 native_sp-0x208) << 0xC00
;   → 修复前该样本必砸穿 VmContext (反证, 验收 #8); 修复后树在 host_rsp
;   下方 0x1000 专用窗口内生长 (最深 ns-0xC28 > 窗口底 ns-0x1028), 与
;   ctx / stub 保存区零重叠。
;
; 垃圾填充: 每层帧内 6 个 qword 写入 4142434445464748h — 修复前这些写入
; 物理落进 VmContext 槽区 (pc/bytecode/native_sp/base_save 全被覆盖),
; CallGate 返回后解释器从垃圾槽恢复 pc/base → 野跳 0xC0000005, 崩溃形态
; 确定可复现, 不是偶发错值。
;
; 区域语义: deepcall_entry 的标记区域只含 mov r32/r64,imm + call (E8 直接
; call → CallGate) + nop + mov [rsp+20h],rax (Store, v4 相对) — 全白名单。
; deep_recurse 本体在区域外, 纯 native 递归。
;
; Win64 ABI: rcx = levels, rdx = acc, 返回 rax。rbx 保存 acc 跨子调用。
; 栈对齐: 区域入口 rsp = deepcall_entry entry rsp - 8(ret) - 28h(sub),
; entry rsp ≡ 8 (mod 16) → 区域入口 ≡ 8 → CallGate call 前 rsp = ns-28h
; (修复前) / ns-28h-1000h (修复后) 均 ≡ 0 (mod 16) ✓。deep_recurse 递归
; call 前 rsp ≡ 0 (mod 16) ✓ (push 8 + sub 0x50 均保 16 对齐)。
;
; rax 跨 marker_end/marker_begin 调用会被 clobber (SDK magic imm64,
; pitfall #36) — 结果经 [rsp+20h] 落栈中转。

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC

_TEXT SEGMENT

; uint64_t deep_recurse(uint64_t levels /*rcx*/, uint64_t acc /*rdx*/)
; 递归链: g(0,a) = a + 6*F (F=4142434445464748h);
;         g(k,a) = g(k-1, a+G) + a + 6*F (G=9E3779B97F4A7C15h)。
; 每层帧深 0x60 (静态可核算), 32 层 → 树深 0xC00 (MIT-407 加深)。
deep_recurse PROC
    push rbx
    sub  rsp, 50h
    mov  rax, 4142434445464748h     ; 垃圾填充 pattern (砸 ctx 证据源)
    mov  [rsp+20h], rax
    mov  [rsp+28h], rax
    mov  [rsp+30h], rax
    mov  [rsp+38h], rax
    mov  [rsp+40h], rax
    mov  [rsp+48h], rax
    mov  rbx, rdx                   ; acc → rbx (callee-saved, 跨子调用守恒)
    test rcx, rcx
    jz   deep_bottom
    dec  rcx
    mov  rax, 9E3779B97F4A7C15h     ; golden ratio 常量
    add  rax, rbx
    mov  rdx, rax                   ; 新 acc = acc + G
    call deep_recurse               ; E8 直接 call — 递归下一层
    add  rax, rbx                   ; rax = 子结果 + 本层 acc
    jmp  deep_ret
deep_bottom:
    mov  rax, rbx
deep_ret:
    add  rax, [rsp+20h]             ; 消费本层 6 个填充槽 (值确定 → 对拍确定)
    add  rax, [rsp+28h]
    add  rax, [rsp+30h]
    add  rax, [rsp+38h]
    add  rax, [rsp+40h]
    add  rax, [rsp+48h]
    add  rsp, 50h
    pop  rbx
    ret
deep_recurse ENDP

; uint64_t deepcall_entry(void) — 标记区域宿主: 区域内 call deep_recurse。
; 区域 = marker_begin 返回点 .. marker_end 调用点之间 (marker_scan E8 回溯)。
deepcall_entry PROC
    sub  rsp, 28h                   ; 0x28 % 16 == 8 → 区域入口 rsp ≡ 8 (mod 16)
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    ; ===== marker region begin =====
    mov  rdx, 1234h                 ; acc 种子 (7 字节, 区域首条 ≥5B 供 stub 织入)
    mov  ecx, 20h                   ; levels = 32 (MIT-407 加深, 树深 0xC00)
    call deep_recurse               ; E8 直接 call → CallGate (native 递归链)
    nop
    nop
    nop
    nop
    nop
    mov  [rsp+20h], rax             ; 结果落栈 (rax 跨 marker_end 被 clobber)
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  rax, [rsp+20h]
    add  rsp, 28h
    ret
deepcall_entry ENDP

_TEXT ENDS
END
