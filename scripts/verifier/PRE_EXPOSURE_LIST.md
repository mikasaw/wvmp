# PRE-EXPOSURE LIST — SSE/VMX/AVX 类 issue 复核清单 (MIT-389 产出, AC #7)

> 生成: 2026-08-28, WVmpVerifier (MIT-389 验收门加固任务 B 段)。
> 用途: 列出**在 MIT-389 三道验收门生效之前**已完成验收、但**未跑新门**的
> SSE/VMX/AVX 类 commit, 供项目主按 D3 决策立一个批量复核 follow-up 单
> ("SSE/VMX/AVX 加固门复核批量重跑"), **本单不自动 rerun**。

## 新验收门 (MIT-389 后对 SSE/VMX/AVX 类 issue 强制)

| 门 | 脚本/产物 | 抓什么 |
|---|---|---|
| A.1 裸立即数静态扫描 | `scripts\verifier\static_scan_bare_immediates.ps1` | Keystone Intel 语法裸多位十进制立即数按 16 进制解析 (MIT-371 空转根因形态); 扫 `vm\regvm\runtime\src\asmgen.cpp` |
| A.2 运行时 ctx.xmm 读回 | 影子样本 `wvmp_sse_subss_xmm_readback_sample` (与主样本 1:1 配对) + multiseed REQUIRE_REAL=1 | handler 是否真的更新 ctx.xmm[reg]: 返回值 + 未触碰槽位保持, native vs virtualized byte-exact |
| A.3 handler 字节级 dump 校验 | `scripts\verifier\dump_handler_xmm_check.py` (capstone 反汇编 wvmp_runtime_dump.bin) | 每个 SSE handler: FP 指令 xmm,xmm + 槽位偏移公式常数 (sub 0x18 / shl 4 / add 0x140) + movups 读写; MIT-371 bug (`sub rbx,0x24`) 实测可抓 |

判定口径 (VmOp 枚举名匹配): `*ss/*ps/*pd` / `vfmadd*` / `vpadd*` / `vmov*` /
`aes*` 等及一切涉及 xmm/ymm/zmm 跟踪区 (VmContext.xmm @ +0x140, kCtxSize
0x1C8) 的指令 → 必须跑满 A.1 + A.2 + A.3。

## 建议重验清单 (未跑新门的既有 SSE/xmm 类 commit)

| # | Issue | commit(s) | 内容 | 暴露风险 | 状态标注 |
|---|---|---|---|---|---|
| 1 | MIT-371 | `23f0e25` | SSE 浮点加 addss/addps/addpd (lifter + IR Op + VmOp + translator + asmgen + sse_add 样本) | **已实证空转** (handler 写回 GPR 槽区而非 ctx.xmm, 根因 = 裸立即数 24→0x24); 空转本身已在 MIT-373 (8ed50b0) 中顺带修复, 但修复后的 addss/addps/addpd handler **未在真虚拟化 E2E + A.3 dump 门下独立复核** | 🔴 **未跑新门** (历史验收仅 dry-run + ctest, 实际空转漏网) |
| 2 | MIT-371 | `67a1905` | stub_link 测试适配 kCtxSize 0x140→0x1C8 (xmm 跟踪区) + stub 入口/出口 xmm 同步代码落地 | xmm 同步路径 (stub_gen.cpp 入口同步 8×movups / 出口恢复 8×movups) 是 A.2 读回断言的依赖前提, 同步 bug 会让读回恒等 (假 PASS) | 🟡 **未跑新门** |
| 3 | MIT-373 | `8ed50b0` | SSE 浮点减 subss/subps/subpd + imm() 根因修复 + 独立 blob 探针 | 本次 MIT-389 已用新门复跑: multiseed 15/15 (sse_add + sse_sub + 影子样本 × 5 seeds) + A.3 全 6 handler PASS → **事实证据已具备**, 但 MIT-373 formal re-acceptance 留项目主 | 🟢 **新门下已复跑** (本单, 证据见 MIT-389 验证报告) |

## 排除说明 (核实过, 非遗漏)

- **MIT-345** (issue 描述点名怀疑 "xmm 测试是否同样空转"): 经查为 **movzx
  8→16/16→64 扩展** (GPR 零扩展, multiseed 注释及 commit 落点均为 GPR 指令),
  不涉及 ctx.xmm 跟踪区 → 不在本清单。结论: MIT-345 无 SSE 空转暴露面。
- **MIT-299 (`9ac3d53`) / MIT-249 (`b880720`)**: 命中 `0x1C8` 字样仅为栈帧
  尺寸算术 (callgate sub rsp), 不涉及 xmm 跟踪区 → 不在本清单。
- **MIT-380** (`882df68`): backend `front()` 退化修复 + 单测; 其验证段**披露**
  了机器基线 sse_add 错值 (即 MIT-371 空转的既有缺陷), 但该 commit 本身不改
  SSE/xmm 代码 → 列为上下文关联, 不单列重验项。
- **MIT-374/375/376** (SSE 除/传送/位运算+比较): backlog 未实现, 尚无 commit
  → 不在本清单; 其各自派发验收时直接适用新门 (含每条指令 1 个影子样本)。

## 复核执行建议 (给 follow-up 单)

1. 对 #1/#2: 重跑 A.1 (asmgen.cpp) + A.3 (对 sse_add 样本 protect 产物
   capstone dump 校验 addss/addps/addpd) + multiseed REQUIRE_REAL=1 (sse_add
   5/5); A.2 影子样本当前仅配对 subss, addss 影子样本按 D1 "每条新指令 1 个
   影子样本" 由后续派活单补齐后再跑。
2. 批量单一次派发, 不按 issue 拆散 (D3)。
