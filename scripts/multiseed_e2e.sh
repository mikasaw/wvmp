#!/usr/bin/env bash
# Multi-seed e2e regression test.
#   - MIT-249 follow-up (issue-08): wvmp_call_gate_sample / wvmp_call_gate_simple_sample /
#     wvmp_rol_sample against 5 different seeds, asserts all PASS (callee-saved 池).
#   - MIT-300: extend to wvmp_snake_sample (贪吃蛇核心逻辑真实业务 PE).
#   - MIT-301: extend to wvmp_cl_shift_sample (cl 变体 shift 真虚拟化).
#   - MIT-302: extend to wvmp_imul_sample (有符号乘法真虚拟化).
#   - MIT-333: extend to wvmp_bswap_sample (bswap reg32/reg64 真虚拟化).
#   - MIT-334: extend to wvmp_xchg_sample (xchg r, r REG-REG 真虚拟化).
#   - MIT-336: extend to wvmp_setcc_sample (setcc REG-REG 真虚拟化).
#   - MIT-339: extend to wvmp_cmovcc_sample (cmovcc REG-REG 真虚拟化).
#   - MIT-341: extend to wvmp_cmpxchg_sample (cmpxchg REG-REG 真虚拟化).
#   - MIT-345: extend to wvmp_cl_shift_sample (movzx 8→16/16→64 真虚拟化).
#   - MIT-347: extend to wvmp_cl_shift_sample (movsx 4 形式 8→32/8→64/16→32/
#     16→64 真虚拟化, sign-extend, 与 movzx 对偶 zero-extend).
#   - MIT-371: extend to wvmp_sse_add_sample (SSE 浮点加 addss/addps/addpd 3 形式真虚拟化).
#   - MIT-373: extend to wvmp_sse_sub_sample (SSE 浮点减 subss/subps/subpd 3 形式真虚拟化).
#   - MIT-389: extend to wvmp_sse_subss_xmm_readback_sample (验收门 A.2 影子样本:
#     subss 的 ctx.xmm 运行时读回断言, 与主样本 sse_subss 同 IR 配对; 后续
#     SSE/VMX/AVX 派活单每条新指令 1 个影子样本 1:1 配对).
#   - MIT-374: extend to wvmp_sse_div_sample (SSE 浮点除 divss/divps/divpd 3 形式
#     真虚拟化) + wvmp_sse_divss_xmm_readback_sample (divss 的 ctx.xmm 读回影子样本).
#   - MIT-376: extend to wvmp_sse_bwcmp_sample (SSE 浮点位运算 xorps/orps/andps +
#     浮点比较 ucomiss/ucomisd 5 形式真虚拟化) + wvmp_sse_bwcmpss_flags_readback_sample
#     (ucomiss+seta 的 VM flags 读回影子样本, 派活单 §D D2.1 1:1 配对).
#   - MIT-404: extend to wvmp_div_sample (整数除法族 cdq/cdqe/cqo + div/idiv
#     REG/MEM/rip 形式真虚拟化, 末尾除零 #DE 对拍 native==packed rc) +
#     wvmp_div_flags_readback_sample (Rax/Rdx 双槽 + 五 flags 探针读回影子样本).
#     另注册既有但从未进 multiseed 的 wvmp_rip_relative_sample /
#     wvmp_rip_relative_simple_sample (MIT-248 C4 读/写路径首次 multiseed
#     覆盖; 若 FAIL 如实报告, StorRva 缺口属 C4 后续单).
#     Total: 24 samples × 5 seeds = 120 runs.
#   - MIT-406: extend to wvmp_deepcall_sample (16 层 MASM 递归链, 树深
#     0x600B 静态可核算) + wvmp_deepcall_div_sample (div/idiv 与深 call
#     共存) — callgate callee 专用栈窗口 (MIT-E1) 预算边界覆盖.
#     Total: 26 samples × 5 seeds = 130 runs.
#   - MIT-407 (MIT-D2): extend to wvmp_exitnative_pos_sample (ExitNative
#     越区单向退出两类形态: END-call 等价退出 + 早返回 jcc 退出).
#     Total: 27 samples × 5 seeds = 135 runs.
#   - MIT-408 (MIT-C4b): extend to wvmp_sse_rip_sample (SSE mem 形式主样本:
#     movsd/movss/movaps/movups 读/写 + addsd/addps 等 ALU mem 源 + ucomisd,
#     rip 全局与非 rip 数组下标 + 栈基址 + D2 对齐/非对齐) +
#     wvmp_sse_rip_xmm_readback_sample (XmmLoad/XmmStore/ALU-mem 折条的
#     ctx.xmm 读回影子样本).
#     Total: 29 samples × 5 seeds = 145 runs.
#   - MIT-409 (MIT-A6): extend to wvmp_jmp_table_sample (MSVC 跳转表正样本:
#     switch 8 路 + default + 边界, 翻译期读表静态展开比较链真虚拟化;
#     负样本 opaque 间接 jmp 同 exe 内照旧 gate, 行为 byte-exact 兜底).
#     Total: 30 samples × 5 seeds = 150 runs.
#   - MIT-411 (G1): extend to wvmp_sse_memop_sample (SSE 尾扫包主样本: 双访存
#     读改写 triple + comiss/comisd (0F 2F 系折叠 ucomis, MSVC 天然 comiss +
#     MASM mem 源) + pd 位运算族 andpd/orpd/xorpd (66 0F 54/56/57 折叠 ps,
#     零新 VmOp) + andnps (MIT-425 起正例翻转)) +
#     wvmp_sse_memop_xmm_readback_sample
#     (comiss/comisd flags + pd 位运算 ctx.xmm 读回影子样本).
#     Total: 32 samples × 5 seeds = 160 runs.
#   - MIT-413 (G2): extend to wvmp_jmp_table8_sample (跳转表残余形态主样本:
#     REG 源 8B 绝对表 / REG 源 8B delta 表 / REG 源 delta-from-jmp (GCC .L4
#     风格) / MEM 源 jmp [tbl+idx*8] (lea 基址) / MEM 源 movabs 基址 五形态
#     真虚拟化; 同 exe 3 负例 (无防御/目标出区/表项指向数据段) 照旧 gate,
#     行为 byte-exact 由双跑兜底).
#     Total: 33 samples × 5 seeds = 165 runs.
#   - MIT-415 (G3): extend to wvmp_string_ops_sample (串指令族 rep
#     movsb/movsq 非对齐/stosb/scasb/cmpsb/lodsb + flags 通路探针主样本,
#     微程序展开真虚拟化; 同 exe 负例 rep nop (pause) 照旧 gate; lock rep
#     movsb 负例本机 #UD 不可执行, 仅 lifter 单测覆盖).
#     Total: 34 samples × 5 seeds = 170 runs.
#   - MIT-417 (P0): extend to wvmp_fp_callgate_sample (CallGate FP 参数/返回
#     值通路修复主样本: 区域内 3 次 callgate 全 FP 参数形态 — double×4
#     (xmm0..3 全槽) + float×2 入参, 返回值参与后续 VM 运算 (addsd/addss),
#     g5r_p0 等价构造的回归盲区消灭样本; REQUIRE_REAL 主函数真虚拟化).
#   - MIT-418 (G5r-R3): extend to wvmp_x87_gate_sample (x87 永久 gate 回归
#     样本: 标记区域内 x87 五族 fld/fadd/fstp/fcomip/fsin → lifter 未支持 →
#     C1 gate 整函数保持原生零 stub, byte-identical; 同 exe 1 个纯 GP
#     helper 真虚拟化区满足 REQUIRE_REAL). ⚠️ B.5 登记: 本样本的 helper
#     真区是 REQUIRE_REAL ≥1 stub 断言的结构性依赖, **禁止后人删掉 helper
#     区把它改成纯 gate-only 样本**——gate-only 形态会与 REQUIRE_REAL=1
#     全局校验冲突 (multiseed_e2e_real.sh), 需另行注册白名单机制。
#     Total: 36 samples × 5 seeds = 180 runs.  (项目主链式合并 417+418:
#     两单各自单边报 35/175, 合并态样本数组 = 36, 此为合并后权威口径。)
#   - MIT-419 (G4): extend to wvmp_atomic_ops_sample (lock 前缀原子族主
#     样本: C++ Interlocked* 真产物形态 lock xadd/lock and-or-xor imm/裸
#     xchg mem/lock cmpxchg 直发内联入区 + MASM 全谱 lock xadd 32/64/bts/
#     btr imm8/btc reg 位号/裸 xchg mem/lock cmpxchg rip 目标 + cmpxchg 后
#     je ZF 读回; F0 白名单放行 strip-and-execute 真虚拟化, D1 原子性边界
#     note 披露; 负例 lock mov/lock nop db 直发 → capstone 拒解码 → C1
#     gate, 原生 #UD 禁入可执行路径, gate 证据 = protect 日志; REQUIRE_REAL
#     8 函数真虚拟化)。单边新增 1 样本 → 37 × 5 = 185 runs。
#   - MIT-423 (G4b): extend to wvmp_atomic_incdec_sample (lock inc/dec 原子
#     补齐主样本: MASM 裸 lock inc/dec dword/qword 双宽 + rip 目标 + dec
#     r8d;jnz 循环计数惯用法 + add→CF→lock inc→jc CF 保真探针 (SDM: inc/
#     dec 不写 CF) 本体折条真虚拟化 (D1 零新 VmOp, lock-strip note); C++
#     _InterlockedIncrement/Decrement 真产物区域 (#33 实测 cl v145 产
#     lock xadd ±1 内联 — 走 419 Xadd 原子通路); 负例 lock not (D2 gate,
#     可调用, 原生行为保真) + lock inc ecx (reg-dst 非法, db 直发, 禁调用)。
#     单边新增 1 样本 → 38 × 5 = 190 runs。
#   - MIT-425 (G1b): extend to wvmp_sse_fin_sample (SSE 收官包主样本: mul
#     族 mulss/mulsd/mulps/mulpd — C++ 天然 /Od mulsd/mulss [rip] mem 形式
#     + MASM 0F 59 系四编码 REG-REG/rip mem 源; andnps/andnpd 0F 55 系 —
#     411 负例 §B.4 正例翻转, 新 VmOp::Andnps; SSE2 整数位运算 pand/por/
#     pxor/pandn 66 0F DB/EB/EF/DF 折叠 ps 位运算零新 VmOp; 负例 paddq
#     66 0F D4 → R2 档② 砍面留 G1c, 照旧 gate 行为 byte-exact) +
#     wvmp_sse_fin_xmm_readback_sample (13 探针 ctx.xmm 8 槽全量读回影子
#     样本)。单边新增 2 样本 → 40 × 5 = 200 runs。
#   - MIT-433 (P1): extend to wvmp_flags_rol_sample (rol/ror flags
#     partial-preserve 主样本: p432 复现样本转正, 自含 MASM marker 桩,
#     5 区 = ror/rol ZF + rol SF + ror PF 消费 + shl 对照, 区内 Store
#     落盘; 修复前 stdout 分叉必 FAIL, 修复后 byte-exact)。
#     单边新增 1 样本 → 47 × 5 = 235 runs。
#   - MIT-306: REQUIRE_REAL=1 校验日志含 "已生成 N 个入口 stub" 防止 C1 gate
#     兜底被误判 PASS（仅 byte-exact 不够, C1 gate 函数被跳过仍能输出相同
#     stdout+rc）。与 multiseed_e2e_real.sh 配套使用。

set -u

repo="$(cd "$(dirname "$0")/.." && pwd)"

# CLI 双探测（MIT-B2 B.3）：Ninja 现行布局优先，缺则回退旧 VS 布局，
# 都缺则明确报错退出——消灭"镜像目录 hack"（mkdir build/vs/cli/Debug && cp）。
if [[ -f "$repo/build/cli/wvmp_cli.exe" ]]; then
    cli="$repo/build/cli/wvmp_cli.exe"
elif [[ -f "$repo/build/vs/cli/Debug/wvmp_cli.exe" ]]; then
    cli="$repo/build/vs/cli/Debug/wvmp_cli.exe"
else
    echo "[multiseed] ERROR: wvmp_cli.exe 未找到（探测过 build/cli/ 与 build/vs/cli/Debug/），请先跑 scripts\\build.bat" >&2
    exit 2
fi

# MIT-306: REQUIRE_REAL 强校验. 设 1 时除 byte-exact 外, 还需 CLI 日志含
# "已生成 N 个入口 stub" 标记（stub_link 在 virtualize 至少产生 1 个
# VirtualizedFunction 时输出; C1 gate 兜底或无已虚拟化函数则不会出此标记）。
REQUIRE_REAL="${REQUIRE_REAL:-0}"

samples=(
    "build/passes/marker_scan/tests/wvmp_call_gate_sample.exe"
    "build/passes/marker_scan/tests/wvmp_call_gate_simple_sample.exe"
    "build/passes/marker_scan/tests/wvmp_rol_sample.exe"
    "build/passes/marker_scan/tests/wvmp_snake_sample.exe"
    "build/passes/marker_scan/tests/wvmp_cl_shift_sample.exe"
    "build/passes/marker_scan/tests/wvmp_imul_sample.exe"
    "build/passes/marker_scan/tests/wvmp_bswap_sample.exe"
    "build/passes/marker_scan/tests/wvmp_xchg_sample.exe"
    "build/passes/marker_scan/tests/wvmp_setcc_sample.exe"
    "build/passes/marker_scan/tests/wvmp_cmovcc_sample.exe"
    "build/passes/marker_scan/tests/wvmp_cmpxchg_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_add_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_sub_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_subss_xmm_readback_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_div_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_divss_xmm_readback_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_mov_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_movss_xmm_readback_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_bwcmp_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_bwcmpss_flags_readback_sample.exe"
    # MIT-404: 整数除法族主样本 + 影子样本 + 既有 rip_relative 2 样本注册.
    "build/passes/marker_scan/tests/wvmp_div_sample.exe"
    "build/passes/marker_scan/tests/wvmp_div_flags_readback_sample.exe"
    "build/passes/marker_scan/tests/wvmp_rip_relative_sample.exe"
    "build/passes/marker_scan/tests/wvmp_rip_relative_simple_sample.exe"
    # MIT-406 (MIT-E1): 深 call 递归链 + div/深 call 组合样本 — callee 专用
    # 栈窗口预算边界覆盖 (32 层 x 0x60B = 0xC00B / 12 层 0x480B 树深, MIT-407 加深)。
    "build/passes/marker_scan/tests/wvmp_deepcall_sample.exe"
    "build/passes/marker_scan/tests/wvmp_deepcall_div_sample.exe"
    # MIT-407 (MIT-D2): ExitNative 正样本 — END-call 等价退出 + 早返回 jcc
    # 退出两类越区形态, 两函数须真虚拟化 (REQUIRE_REAL ≥1 stub)。
    # 反例样本 (回跳/超界 → gate) 不进 REQUIRE_REAL 列表, 由 e2e.sh 单独验。
    "build/passes/marker_scan/tests/wvmp_exitnative_pos_sample.exe"
    # MIT-408 (MIT-C4b): SSE mem 形式主样本 + ctx.xmm 读回影子样本 —
    # 纯 C++ /Od 天然 mem 形式 (rip 全局 / 非 rip 数组下标 / 栈基址 / D2
    # 对齐与 非对齐), REQUIRE_REAL 保证真虚拟化非 gate。
    "build/passes/marker_scan/tests/wvmp_sse_rip_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_rip_xmm_readback_sample.exe"
    # MIT-409 (MIT-A6): MSVC 跳转表正样本 — switch 8 路 + default + 边界,
    # 翻译期读表静态展开比较链真虚拟化 (REQUIRE_REAL ≥1 stub); 同 exe 负
    # 样本 opaque 间接 jmp 照旧 gate, 行为 byte-exact 由双跑兜底。
    "build/passes/marker_scan/tests/wvmp_jmp_table_sample.exe"
    # MIT-411 (G1): SSE 尾扫包主样本 + ctx.xmm/flags 读回影子样本 — 双访存
    # 读改写 triple / comiss/comisd (折叠 ucomis) / andpd/orpd/xorpd (折叠 ps),
    # andnps 同 exe 内真虚拟化 (MIT-425 (G1b) §B.4 正例翻转, 行为 byte-exact);
    # REQUIRE_REAL 保证新形态真虚拟化非 gate。
    "build/passes/marker_scan/tests/wvmp_sse_memop_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_memop_xmm_readback_sample.exe"
    # MIT-413 (G2): 跳转表残余形态主样本 — REG 8B 绝对/delta/delta-from-jmp
    # + MEM 源 jmp [tbl+idx*8] (lea/movabs 基址) 五形态真虚拟化
    # (REQUIRE_REAL ≥1 stub); 同 exe 3 负例 (无防御/目标出区/表项指向数据段)
    # 照旧 gate, 行为 byte-exact 由双跑兜底。
    "build/passes/marker_scan/tests/wvmp_jmp_table8_sample.exe"
    # MIT-415 (G3): 串指令族主样本 — rep movsb/movsq 非对齐/stosb/scasb/
    # cmpsb/lodsb 微程序展开真虚拟化 (REQUIRE_REAL ≥1 stub) + 区域内 flags
    # 通路探针 (movs 保全 ZF 的 sete 读回); 同 exe 负例 rep nop (pause)
    # 照旧 gate, 行为 byte-exact 由双跑兜底。
    "build/passes/marker_scan/tests/wvmp_string_ops_sample.exe"
    # MIT-417 (P0): CallGate FP 参数/返回值通路主样本 — 区域内 3 次 callgate
    # 全 FP 参数形态 (double×4 xmm0..3 全槽 + float×2), 返回值参与 VM 内
    # addsd/addss 运算后落全局 + 经函数返回; g5r_p0 等价构造 (修复前静默
    # 错乱), REQUIRE_REAL 保证真虚拟化非 gate。
    "build/passes/marker_scan/tests/wvmp_fp_callgate_sample.exe"
    # MIT-418 (G5r-R3): x87 永久 gate 回归样本 — 区域内 x87 五族
    # fld/fadd/fstp/fcomip/fsin 整函数保持原生 (零 stub, gate 证据);
    # 同 exe 纯 GP helper 真虚拟化 (REQUIRE_REAL ≥1 stub 满足源)。
    "build/passes/marker_scan/tests/wvmp_x87_gate_sample.exe"
    # MIT-419 (G4): lock 前缀原子族主样本 — C++ Interlocked* 真产物形态
    # (lock xadd / lock and-or-xor imm / 裸 xchg mem / lock cmpxchg 直发
    # 内联入区) + MASM 全谱 (lock xadd 32/64 / lock bts/btr imm8 / lock
    # btc reg 位号 / 裸 xchg mem / lock cmpxchg rip 目标 + cmpxchg 后 je
    # ZF 读回), F0 白名单放行 strip-and-execute 真虚拟化 (REQUIRE_REAL
    # 8 函数); 负例 lock mov/lock nop db 直发 → capstone 拒解码 → C1 gate
    # (原生 #UD 禁入可执行路径, main 只取地址, gate 证据 = protect 日志)。
    "build/passes/marker_scan/tests/wvmp_atomic_ops_sample.exe"
    # MIT-423 (G4b): lock inc/dec 原子补齐主样本 — MASM 裸 lock inc/dec
    # dword/qword + rip 目标 + dec/jnz 循环 + CF 保真探针本体折条真虚拟化
    # (REQUIRE_REAL ≥1 stub); C++ _Interlocked* 真产物区域 (lock xadd ±1
    # 内联展开); 负例 lock not (D2 gate, 可调用) + lock inc ecx (禁调用)。
    "build/passes/marker_scan/tests/wvmp_atomic_incdec_sample.exe"
    # MIT-425 (G1b): SSE 收官包主样本 + ctx.xmm 读回影子样本 — mul 族
    # (mulss/mulsd/mulps/mulpd, C++ 天然 + MASM 0F 59 系四编码) +
    # andnps/andnpd (0F 55 系, 411 负例正例翻转, 新 VmOp::Andnps) +
    # SSE2 整数位运算族 (pand/por/pxor/pandn 折叠 ps 零新 VmOp);
    # 负例 paddq (66 0F D4) 砍面留 G1c 照旧 gate (行为 byte-exact)。
    "build/passes/marker_scan/tests/wvmp_sse_fin_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_fin_xmm_readback_sample.exe"
    # MIT-426 (G6a): VEX.128 档A 主样本 + ctx.xmm 读回影子样本 — 38 id
    # V-pair 三地址折叠 (标量 FP 三态 / packed 交换 / d 独立 Mov 前置 /
    # D4 拷贝 / 408 mem 通路 / vpxor 惯用法 / flags 通路 / C4 全前缀 db);
    # 负例区七族全 gate (ymm 位宽闸 / FMA / rorx / vzeroupper / vpaddd /
    # 非交换+标量 d==s2 / vmovsd 插入) 可调用行为 byte-exact。
    # 单边新增 2 样本 → 42 × 5 = 210 runs。
    "build/passes/marker_scan/tests/wvmp_vex128_sample.exe"
    "build/passes/marker_scan/tests/wvmp_vex128_xmm_readback_sample.exe"
    # MIT-427 (G1c): movd/movq GP↔xmm 桥主样本 + ctx.xmm 读回影子样本 —
    # 桥四形 REG (66 0F 6E / 66 REX.W 0F 6E / 66 0F 7E / 66 REX.W 0F 7E,
    # 新 VmOp::XmmFromGp/GpFromXmm) + mem 双向 (408 通路) + all-xmm 双形态
    # (F3 0F 7E 清零 / 66 0F D6 保持); 负例区 (paddq/psubq 砍面 + pmovmskb/
    # pcmpeqd + MMX mm 判据 + movdqa/movdqu C++ 真产物) 各自函数级 gate
    # 可调用, 行为 byte-exact。B.5 harness 崩溃盲区修随本单搭载。
    # 单边新增 2 样本 → 44 × 5 = 220 runs。
    "build/passes/marker_scan/tests/wvmp_sse_bridge_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_bridge_xmm_readback_sample.exe"
    # MIT-428 (G1d): movdqa/movdqu 对齐传送主样本 + ctx.xmm 读回影子样本 —
    # 双编码 (6F/7F 反写) × 三形态 (reg-reg/栈槽/rip) + VEX vmovdqa/vmovdqu +
    # /Od intrinsic 翻转正例 (427 #33④ 闭环); 负例区 EVEX vmovdqa32/vpaddd
    # ymm/punpcklqdq/pmovmskb 各自函数级 gate 可调用 byte-exact。
    # 单边新增 2 样本 → 46 × 5 = 230 runs。
    "build/passes/marker_scan/tests/wvmp_aligned_mov_sample.exe"
    "build/passes/marker_scan/tests/wvmp_aligned_mov_xmm_readback_sample.exe"
    # MIT-433 (P1): rol/ror flags partial-preserve 主样本 — p432 复现样本
    # 转正 (自含 MASM marker 桩, 5 区 setcc 消费 + 区内 Store 落盘):
    # ror/rol ZF + rol SF + ror PF 消费面 (修复前 stdout 分叉必 FAIL) +
    # shl 对照。修复前反证用旧 CLI (0ac661a 同产物) 双跑观察分叉值。
    # 单边新增 1 样本 → 47 × 5 = 235 runs。
    "build/passes/marker_scan/tests/wvmp_flags_rol_sample.exe"
    # MIT-434 (G8a): BMI 折条款目主样本 — 16 正例区 (andn/bzhi/rorx/shlx/
    # sarx/shrx × {d==s1, d==s2, d 独立, mem src} + flags 消费探针 setcc →
    # 区内 Store 落盘; bzhi 边界 idx=N 原值+CF=1 probe 修正面; rorx 五位
    # 保留 setz/setc/sets/setp) 真虚拟化 (16 stub) + 1 负例区 (mulx/pdep/
    # pext/blsr/bextr/blsi/blsmsk) 函数级 gate 可调用 byte-exact。
    # 单边新增 1 样本 → 48 × 5 = 240 runs。
    "build/passes/marker_scan/tests/wvmp_bmi_sample.exe"
    # MIT-438 (X1b): ret imm16 清栈语义主样本 — 3 区 x64 ret N 直写真编码
    # (8/0/88h, 区域末条 = ret N) + caller 平衡探针/返回值断言; 修复前旧 CLI
    # 反证 stdout 分叉必 FAIL (VmOp::Ret 原无 handler → Halt), 修复后
    # byte-exact (REQUIRE_REAL 3 stub 真虚拟化)。
    # 单边新增 1 样本 → 49 × 5 = 245 runs。
    "build/passes/marker_scan/tests/wvmp_retimm_sample.exe"
    # MIT-442 (X2a): 形级 fork 面收口主样本 — 区1 leave 链 (折条真虚拟化 +
    # bal=0 平衡哨兵) + 区3 plain 串形 (movsd×2/lodsd + cld no-op) + 区4
    # p66 S16 (66 前缀 imm/ALU/store + cwde 两 IR 折条 + cbw 载体微程序)
    # 真虚拟化 (REQUIRE_REAL ≥1 stub); 负例区2 call [mem] IAT 形 / 区2b
    # call reg (D4 停手 gate 归 X3) / 区5 std (D5 gate) / 区6 67 前缀
    # (B.4 闸, 禁调用) 行为 byte-exact。
    # 单边新增 1 样本 → 50 × 5 = 250 runs。
    "build/passes/marker_scan/tests/wvmp_forkface_sample.exe"
)

# MIT-442 (X2a) B.7: x86 (PE32) 样本池架子 — X5 收口单填池 (空池不跑)。
# 语义: 样本产物路径按 build/x86_samples/*.exe 约定; 填池即自动 ×5 seeds
# 入 multiseed 口径 (与 x64 同一 protect/byte-exact/REQUIRE_REAL 判据 —
# 唯一差异 = 输入 PE32, x86 管道翻硬拒为声明后生效)。本单预铺只验证
# "空池零开销不误伤" 与数组/循环就位, 不放任何样本 (x86 管道 rc=2 硬拒
# 维持, D1 不回退 — X0 §6 表 X1 行的基建参数化切片预铺, 填池归 X5)。
# MIT-446 (X4) B.4: 首批填池 — 3 族级样本 × 5 seeds = 15 runs (基线
# 250 → 265)。REQUIRE_REAL 断言按样本登记: forkface 6 stub / callgate
# 2 stub; sse 样本 = 1 stub (SSE 函数走 x86 白名单 gate 整函数原生 —
# 池判据只要求 ≥1 stub, helper 真虚拟化满足)。每样本 protect 日志附
# machine=0x14C 断言见 .multica 交付报告 (dumpbin 亲验)。
# MIT-450 (X5) B.1+B.3: 池扩量 3→11 — B.1 五族 (deepcall / jmptbl /
# strops / bitops / looplea) + B.3 gate 负例族 (x87gate / sehgate /
# std67gate, 各含 ≥1 GP helper 真虚拟化区满足 REQUIRE_REAL; gate 区
# 证据 = protect 日志 gate note)。11 × 5 = 55 runs (基线 250 → 305)。
x86_samples=(
    "build/x86_samples/wvmp_x86_forkface_sample.exe"
    "build/x86_samples/wvmp_x86_sse_sample.exe"
    "build/x86_samples/wvmp_x86_callgate_sample.exe"
    "build/x86_samples/wvmp_x86_deepcall_sample.exe"
    "build/x86_samples/wvmp_x86_jmptbl_sample.exe"
    "build/x86_samples/wvmp_x86_strops_sample.exe"
    "build/x86_samples/wvmp_x86_bitops_sample.exe"
    "build/x86_samples/wvmp_x86_looplea_sample.exe"
    "build/x86_samples/wvmp_x86_x87gate_sample.exe"
    "build/x86_samples/wvmp_x86_sehgate_sample.exe"
    "build/x86_samples/wvmp_x86_std67gate_sample.exe"
    # MIT-451 (X5b) B.5: stack-fix pair (pool 11 -> 13, x86 65 runs, total
    # 315). pushform = guard-pad virtualization positive (call-arg push +
    # transient spill + callgate window from the guard zone); guardover =
    # stack-depth walk gate-negative (sub esp,200h > 128B budget, whole
    # function native, protect-log gate note).
    "build/x86_samples/wvmp_x86_pushform_sample.exe"
    "build/x86_samples/wvmp_x86_guardover_sample.exe"
    # MIT-453 (X5c) B.2: tailexit (pool 13 -> 14, x86 70 runs, total 320).
    # last-region .text-tail ExitNative fallback positive (region 3 no
    # successor -> ub = .text tail; endcall target==end_rva + earlyret in
    # gap) + region 1 next-begin ub positive + region 2 gate negative
    # (jmp .data VA >= .text tail, address-taken never-called, C1 gate
    # note in protect log; REQUIRE_REAL 2 stubs).
    "build/x86_samples/wvmp_x86_tailexit_sample.exe"
)

# Seeds: 1 (small), 12345 (default), 99999 (large), 0xDEADBEEF (magic), 0xCAFEBABE (magic).
seeds=(1 12345 99999 3735928559 3405691582)

pass=0
fail=0

# MIT-442 (X2a) B.7: 单样本×单 seed 执行体提为函数 — x64 主池与 x86 预铺池
# 共用同一判据 (protect rc=0 + REQUIRE_REAL stub 标记 + stdout/rc byte-exact +
# 427 B.5 crash guard), 消除双池双份逻辑漂移面。pass/fail 为全局计数器。
run_one_seed() {
    local sample="$1"
    local seed="$2"
        tmp="$(mktemp -d)"
        cfg="$tmp/e2e.toml"
        out_win="$(cygpath -m "$tmp")/wvmp_e2e_out.exe"
        cat > "$cfg" <<EOF
input  = "$sample_win"
output = "$out_win"
seed   = $seed

[[passes]]
name = "pe_loader"
[[passes]]
name = "marker_scan"
[[passes]]
name = "lifter"
[[passes]]
name = "virtualize"
[[passes]]
name = "stub_link"
[[passes]]
name = "pe_writer"
EOF
        rc=0
        out="$("$cli" protect --config "$cfg" 2>&1)" || rc=$?
        if [[ $rc -ne 0 ]]; then
            echo "[multiseed] FAIL seed=$seed sample=$sample protect rc=$rc" >&2
            echo "$out" >&2
            fail=$((fail + 1))
            rm -rf "$tmp"
            return
        fi
        # MIT-306: REQUIRE_REAL 校验日志含 "已生成 N 个入口 stub" 标记。
        # stub_link 在 virtualize pass 至少产生 1 个 VirtualizedFunction 时输出此
        # Note; C1 gate (virtualize 放弃) 或无已虚拟化函数则不会出此标记。
        # 仅 byte-exact 不够, C1 gate 函数被跳过仍能输出相同 stdout+rc, 这是假
        # PASS——REQUIRE_REAL=1 时必须含 stub 生成标记才视为真虚拟化。
        if [[ "$REQUIRE_REAL" == "1" ]]; then
            if ! echo "$out" | grep -q "已生成 [1-9][0-9]* 个入口 stub"; then
                echo "[multiseed] FAIL seed=$seed sample=$sample is C1 gate, not real virtualization" >&2
                echo "$out" | tail -5 >&2
                fail=$((fail + 1))
                rm -rf "$tmp"
                return
            fi
        fi
        # Run both, compare stdout + rc byte-exact.
        "$sample" > "$tmp/stdout.expected" 2>/dev/null
        echo $? > "$tmp/rc.expected"
        "$out_win" > "$tmp/stdout.actual" 2>/dev/null
        echo $? > "$tmp/rc.actual"
        # MIT-427 (G1c) B.5: harness segfault 假 PASS 盲区修 (426 §4 登记, 搭载)。
        # 实测机制 (#33, Git Bash/MSYS, 2026-08-30): native crash 的 rc 是 MSYS
        # 映射后的信号值 (STATUS_ACCESS_VIOLATION → 139 = 128+SIGSEGV), 不是裸
        # Windows 异常码; cmd/PowerShell 口径才报裸码 (rc ≥ 0x80000000 或负值)。
        # 修复前 "双崩 + 双空 stdout" byte-exact = 假 PASS (426 影子样本首版
        # 实证; 本单注入 segfault 样本复现 5/5 假 PASS → 修复后 5/5 FAIL)。
        # 派单 §B.5 的 "rc ≥ 0x80000000 (或负值) 显式 FAIL" 按实测口径修正为
        # "映射信号 rc (≥128) 或裸异常码 (≥0x80000000/负) 一律 abnormal"。
        # 处置: 任一侧 abnormal → FAIL, 唯一例外 = 设计性崩溃对拍 (双侧 abnormal
        # + rc 相等 + stdout 非空, wvmp_div_sample #DE 对拍 404 AC#5 依赖)。
        # 残余边界 (披露): "双崩 + 相同非空部分输出" 仍走 byte-exact (无法区分
        # 设计对拍与巧合崩); 127 (command-not-found/未知异常映射) 仅在 stdout
        # 为空时计 abnormal (wvmp_div_sample 127+194B 不受影响)。
        rc_e="$(cat "$tmp/rc.expected")"
        rc_a="$(cat "$tmp/rc.actual")"
        crash_e=0
        crash_a=0
        if (( rc_e >= 128 || rc_e >= 2147483648 || rc_e < 0 )) ||            [[ "$rc_e" == "127" && ! -s "$tmp/stdout.expected" ]]; then
            crash_e=1
        fi
        if (( rc_a >= 128 || rc_a >= 2147483648 || rc_a < 0 )) ||            [[ "$rc_a" == "127" && ! -s "$tmp/stdout.actual" ]]; then
            crash_a=1
        fi
        if [[ "$crash_e" == "1" || "$crash_a" == "1" ]]; then
            if [[ "$crash_e" == "1" && "$crash_a" == "1" && "$rc_e" == "$rc_a"                   && -s "$tmp/stdout.actual" ]]; then
                echo "[multiseed] PASS seed=$seed sample=$(basename "$sample") (designed crash pair rc=$rc_e)"
                pass=$((pass + 1))
            else
                echo "[multiseed] FAIL seed=$seed sample=$sample abnormal rc (native=$rc_e packed=$rc_a, MIT-427 B.5 crash guard)" >&2
                fail=$((fail + 1))
            fi
        elif ! cmp -s "$tmp/stdout.expected" "$tmp/stdout.actual"; then
            echo "[multiseed] FAIL seed=$seed sample=$sample stdout mismatch" >&2
            diff "$tmp/stdout.expected" "$tmp/stdout.actual" >&2
            fail=$((fail + 1))
        elif [[ "$rc_e" != "$rc_a" ]]; then
            echo "[multiseed] FAIL seed=$seed sample=$sample rc mismatch $rc_e vs $rc_a" >&2
            fail=$((fail + 1))
        else
            echo "[multiseed] PASS seed=$seed sample=$(basename "$sample")"
            pass=$((pass + 1))
        fi
        rm -rf "$tmp"
}

for sample in "${samples[@]}"; do
    if [[ ! -f "$sample" ]]; then
        echo "[multiseed] 样本文件不存在: $sample" >&2
        fail=$((fail + 1))
        continue
    fi
    sample_win="$(cygpath -m "$sample")"
    for seed in "${seeds[@]}"; do
        run_one_seed "$sample" "$seed"
    done
done

# MIT-442 (X2a) B.7: x86 (PE32) 样本池 — 空池不跑 (零开销); X5 收口单填池后
# 自动 ×5 seeds 入同一口径 (x86 管道翻硬拒为声明后生效; 现网 rc=2 硬拒维持,
# 填池样本会 protect rc=2 FAIL — 这是 X5 的接线验收, 不是本单的)。
for sample in "${x86_samples[@]}"; do
    if [[ ! -f "$sample" ]]; then
        echo "[multiseed] x86 样本文件不存在: $sample" >&2
        fail=$((fail + 1))
        continue
    fi
    sample_win="$(cygpath -m "$sample")"
    for seed in "${seeds[@]}"; do
        run_one_seed "$sample" "$seed"
    done
done

echo "[multiseed] TOTAL: $pass pass / $fail fail"
exit $((fail > 0))