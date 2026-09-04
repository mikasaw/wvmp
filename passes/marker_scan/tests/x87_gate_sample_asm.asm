; MIT-418 (G5r-R3): x87 永久 gate 回归样本 MASM 宿主 — x87 五族真字节直写
; (MSVC x64 不产 x87: long double = double, /arch:IA32 不存在于 x64 目标;
; MASM 是 x64 上唯一合法 x87 构造路, 416 §A 裁定①; ml64 对 D8-DF 全族无障碍,
; 416 §A.2 实测)。
;
; 函数形态 (D1 决策: MASM 全族混合 + GP helper 真区, 一箭双雕):
;
;   ① wv_x87_gate_fn —— 区域内 x87 五族各 ≥1 条 (派活单 §B.1 最小集):
;        - 数据传输族: fld / fstp (DD 05 / DD 1D, qword mem)
;        - 算术族:     fadd (DE C1, 无操作数栈顶加)
;        - 比较族:     fcomip st(1) (DF F1, 比较 ST0 vs ST1 + 弹栈 + 直置 EFLAGS)
;                     ⚠️ ml64 实测**拒收** fcomi/fcomip/fucomi/fucomip 助记符
;                     (A2008/A2070, DF F0-F7 组全灭, 2026-08-30 本单探针实测);
;                     fcom/fcomp 组 (D8/DC) 与 fxch/fadd/fld 的 st(n) 均收。
;                     fcomip 字节改 db 直发 (popcnt 样本同款纪律), 语义不变。
;        - 超越族:     fsin (D9 FE, 硬件微码)
;     预期行为链: lifter 未支持 'fld'/'fadd'/'fstp'/'fcomip'/'fsin' → skipped
;     ranges 累积 → C1 gate 整函数保持原生 → **零 stub**, packed 与 native
;     byte-identical (416 §0 实测行为链)。区域内其余指令全为白名单 (mov/lea),
;     gate 的唯一诱因 = x87, 排除其他跳过源。
;     栈守恒: fld 对 fstp 严格配对, 函数返回时 x87 栈空 (Win64 调用约定),
;     fsin 输入 |x|<2^63 且用 0.5 小角, 无归约路径风险。
;     无 rsp 调整 (entry rsp 恒等): 区域内无 push/sub, gate 后原生执行与
;     marker 无关, 但保持与虚拟化样本同构纪律 (Halt 恢复契约面)。
;
;   ② wv_gp_helper —— 纯 GP 白名单真虚拟化区 (REQUIRE_REAL ≥1 stub 满足源):
;       mov eax, ecx + add eax, 100 + [rsp+24] spill, 无 rip 无 call —— 区域
;       完整可翻译 → 真虚拟化 → stub 计数 = 1。与 wv_x87_gate_fn 同 exe,
;       stub 总数 1 = 仅 helper 虚拟化 → "x87 区零 stub" 由计数相等钉死
;       (B.2 断言③)。
;
; Win64 ABI: wv_x87_gate_fn 无参无返回值 (结果写全局); wv_gp_helper 参 = ecx,
; 返回值 = eax (区域外恢复)。

EXTERNDEF ?marker_begin@sdk@wvmp@@YAXPEBD@Z : PROC
EXTERNDEF ?marker_end@sdk@wvmp@@YAXXZ   : PROC
EXTERNDEF g_a : QWORD
EXTERNDEF g_b : QWORD
EXTERNDEF g_c : QWORD
EXTERNDEF g_d : QWORD
EXTERNDEF g_e : QWORD
EXTERNDEF g_res_sum : QWORD
EXTERNDEF g_res_cmp : QWORD
EXTERNDEF g_res_sin : QWORD

_TEXT SEGMENT

; ============ ① x87 五族 gate 函数 ============
wv_x87_gate_fn PROC
    push rbx
    sub  rsp, 56
    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    ; -- 数据传输族: fld / fstp (qword 宽) --
    fld  QWORD PTR [g_a]
    fld  QWORD PTR [g_b]
    ; -- 算术族: fadd (ST0 = ST0 + ST1) --
    fadd
    fstp QWORD PTR [g_res_sum]       ; ST 弹空
    ; -- 比较族: fcomip (DF F1: ST0 vs ST(1), 弹 ST0, 直置 ZF/PF/CF) --
    ;    ml64 拒收 fcomip 助记符 (FCOMI 族全灭), db 直发字节 (语义即 DF F1);
    ;    capstone 解为 FCOMPI (枚举名) / mnemonic "fcomip" (404 教训)。
    fld  QWORD PTR [g_c]
    fld  QWORD PTR [g_d]
    db 0DFh, 0F1h              ; fcomip st(1)
    fstp QWORD PTR [g_res_cmp]       ; 剩值 (g_c) 弹空
    ; -- 超越族: fsin (硬件微码, 结果替换 ST0) --
    fld  QWORD PTR [g_e]
    fsin
    fstp QWORD PTR [g_res_sin]       ; ST 弹空
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    add  rsp, 56
    pop  rbx
    ret
wv_x87_gate_fn ENDP

; ============ ② 纯 GP helper (真虚拟化, REQUIRE_REAL 满足源) ============
wv_gp_helper PROC
    push rbx
    sub  rsp, 56
    ; ===== marker region begin =====
    call ?marker_begin@sdk@wvmp@@YAXPEBD@Z
    mov  eax, ecx                    ; 参数 (Win64: rcx)
    add  eax, 100
    mov  [rsp+24], eax               ; 结果 spill (marker_end clobber rax)
    ; ===== marker region end =====
    call ?marker_end@sdk@wvmp@@YAXXZ
    mov  eax, [rsp+24]
    add  rsp, 56
    pop  rbx
    ret
wv_gp_helper ENDP

_TEXT ENDS

END
