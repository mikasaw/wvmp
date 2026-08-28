# SSE/Block Backlog 派活单统一模板

> 产出: MIT-390(2026-08-28), 取代 MIT-371 旧派活单模板。
> 用途(决策 D2): **仅人类参考** —— 项目主/verifier 在派活前复制"派活单正文"整段,
> 手工 patch 派活单 description(或 `multica issue update --description-file` 重写 backlog 单)。
> 本模板不被 WVmp agent 体系自动识别, 不嵌入自动加载逻辑。
> 适用: SSE/Block 类"新指令虚拟化支持"backlog 派活单(MIT-374 / 375 / 376 及后续 Block F LOOP / BSF / BT 等)。
> 背景: MIT-371 旧模板有三处基线错误 —— ① SSE handler 空转可被 Accept 假阳性;
> ② `multica issue run-messages` AC 项不可执行; ③ ctest 15/15 已过期(实际 16/16)。

## 使用方法

1. 复制下方"派活单正文"整段到 issue description。
2. 替换全部 `{{PLACEHOLDER}}` 占位符, 删除不适用段。
3. 标 🔒 的强制项**不得删改字句** —— verifier 按这些字句验收(MIT-390 AC#3 验证方式:
   `multica issue get <id>` 输出 description 必须含新基线语句)。

---

# 派活单正文(复制以下全部)

# WVmp 派活单 — lifter + translator + asmgen 加 {{INSTRUCTION_SET}} 指令支持 ({{BLOCK_PHASE}})

> 派活单版本: MIT-390 统一模板(2026-08-28), 取代 MIT-371 旧模板
> 关联: {{RELATED_ISSUES}}
> 预期工作量: {{EFFORT}}
> 串行派发顺序: {{DISPATCH_ORDER}}

## Context(基线认知)

🔒 强制语句(逐字保留):

**MIT-373 commit 8ed50b0 imm() 修复已落地, SSE/VMX/AVX handler 空转根因已堵, 本单基于真虚拟化基线。**

- MIT-371 SSE add 曾在 handler 全部空转的状态下被 verifier Accept: 输出恰等于输入,
  byte-exact 假阳性。根因 = Keystone Intel 语法裸多位立即数按十六进制解析(`sub T9, 24` → 0x24)。
- 修复后 `wvmp_sse_add_sample` / `wvmp_sse_sub_sample` 真虚拟化。本单新增 handler 禁止复现空转模式。
- verifier 加固门(MIT-389, 草案编号 MIT-378)落地前, 本单验收自带 ctx.xmm 读回断言要求(验收 #5)。

## 核心目标

{{CORE_GOAL}}(沿用 MIT-371/373 六件套模式: lifter case + ir::Op + VmOp + translator + asmgen build/handlers 注册 + 新 E2E 样本)。

**只改**: {{FILE_LIST}}

**明确不支持**: {{EXCLUSIONS}}

## 验收标准

1. **build**: `scripts\build.bat` rc=0, 0 错误 0 警告, 仅改本单限定文件。
2. 🔒 **ctest 16/16 (基线含 regvm_backend_tests)** — 报告必贴 ctest 实际输出。
   旧模板 "ctest 15/15" 已过期(MIT-380 新增 regvm_backend_tests), 禁止再写 15/15。
3. **E2E 新样本**: seed=12345 输出 `[e2e] PASS（虚拟化后行为与原生一致）`。
4. 🔒 **multiseed 13 samples × 5 seeds = 65 runs, 其中本单新增样本 + sse_add_sample + sse_sub_sample
   全 PASS, 其余沿用 MIT-373 时点基线(40/65, 其余为既有 segfault, 5 样本 × 5 seeds)**。
   本单只对本单新增样本 + sse_add + sse_sub 负责, 不对既有 segfault 样本负责;
   禁止为凑全绿放宽、隐瞒或改写既有样本。跑法: `scripts\multiseed_e2e_real.sh` + REQUIRE_REAL=1。
5. 🔒 **ctx.xmm 读回断言**: 本单新增 SSE/VMX/AVX 样本必须以可观察输出证明 handler 真写 ctx 跟踪区
   (影子样本 `sse_x_xmm_readback_sample` 模式, MIT-389 决策 D1: 与主样本同 IR、独立 exe、
   native vs virtualized 都打 ctx.xmm[reg] 并 byte-exact 比对)。仅 stdout byte-exact 不构成验收 ——
   MIT-371 空转假阳性教训。
6. **回归零退化**: 既有可 PASS 样本 multiseed 结果零退化。
7. **冻结契约核查**: `git diff --stat` 与改动清单一致。
8. **报告**: Multica issue 评论结构化报告(改动清单/验证结果/遗留风险/验收逐条回应),
   验证结论必附实际命令输出, 禁止无证据断言。

## 冻结契约

- 🔒 **本单新增 handler 必须使用 `imm()` 辅助拼立即数, 禁止裸多位数字写入 Keystone 文本
  (陷阱 #1 现行犯, MIT-373 root cause)**。
- 通用冻结: `common/include/wvmp/common/`、`framework/include/wvmp/framework/`、
  `vm/include/wvmp/vm/backend.hpp`; VmContext 布局 / kCtxSize; 现有 E2E 样本主体。
- enum 只允许 additive append-only(`ir::Op` / `VmOp`), 不改既有字段。
- {{SCOPE_EXCLUSIONS}}

## 工程纪律(沿用 MIT-371/373 有效部分)

- 派活单假设不一定是真根因: 假设真对 → 字面执行; 假设真错 → 诚实披露 + 改修复方向;
  编造发现掩盖 → REJECT(MIT-322 反例)。
- 不需 MASM helper 强制 codegen(MSVC /Od 对 SSE 浮点已 emit 真 SSE 字节);
  注意 pitfall #57: SSE codegen 字节可能因 MSVC /Od 优化而变化, 派活前 capstone 实证。
- 不跨 issue 并发改 asmgen.cpp / translator.cpp / stub_link_pass.cpp; 有冲突先报"需要等 XXX 先 commit"。

## AC 禁令(MIT-390 新增)

- 派活单/验收**不得包含 `multica issue run-messages` 相关 AC 项**(整段删)。
  该子命令历史上对 issue 维度 404, 且属 CLI 可用性检查而非交付验收, 写进 AC 只会产生不可执行的 FAIL。
- 验收数字禁止写 "全样本真虚拟化"、"65/65 全 PASS"、"70/70 / 75/75 / 80/80" 类与实际基线
  (13 samples × 5 seeds = 65 runs, MIT-373 时点 40/65 + 既有 segfault)矛盾的数字。

## 硬约束 4 条(同步复制进 WVmpCppDev agent instructions, MIT-390 决策 D2)

1. **新指令立即数必须用 imm()**: 新增 handler/织入代码的一切立即数与位移必须经 `imm()` / `hex()`
   辅助拼进 Keystone 文本, 禁止裸多位数字直写 —— Keystone Intel 语法按十六进制解析("24"→0x24),
   这是 MIT-371 SSE add handler 全部空转、Accept 假阳性的根因(MIT-373 commit 8ed50b0 修复)。
2. **SSE/VMX/AVX handler 必须真写 ctx 跟踪区**: 禁止写回 GPR 槽区空转; 新增样本必须有
   ctx.xmm 读回可观察输出(影子样本模式), 仅 stdout byte-exact 不构成验收。
3. **ctest 基线 16/16 (基线含 regvm_backend_tests)**: 旧 "15/15" 字样已过期(MIT-380 起);
   报告数字必须来自实际 ctest 输出, 禁止沿用过期数字。
4. **multiseed 口径**: 13 samples × 5 seeds = 65 runs; 新派单只对本单新增样本 + sse_add_sample +
   sse_sub_sample 全 PASS 负责, 其余沿用 MIT-373 时点基线(40/65, 5 样本既有 segfault),
   禁止为凑全绿放宽或隐瞒。
