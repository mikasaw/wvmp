MIT-378: WVmpVerifier 验收门加固 — 抓 SSE 类 handler 空转缺陷(imm() 裸多位立即数 + 运行时 readback 双重门)

> Issue generated: 2026-08-28, hermes (project owner)
> Linked: MIT-373 status=in_review (commit 8ed50b0, "顺带修复" MIT-371 SSE add 空转根因 + 新增 subss/subps/subpd)
> MIT-371 status=done (Accept 时 SSE handler 实际空转 — verifier 未抓到)
> MIT-380 status=done (披露机器基线 sse_add 错值但未定位根因)

== Context ==
MIT-371 SSE add addss/addps/addpd (commit 23f0e25) 被 verifier Accept,
但实际所有 3 个 SSE handler **空转**(写回 GPR 槽区,非 ctx.xmm[0])。
MIT-373 (8ed50b0) 才把根因定位:Keystone Intel 语法下裸多位数字按十六进制
解析(`sub T9, 24` → `sub rbx, 0x24` = 36),xmm 槽位偏移公式坏。
修复后 SSE handler 真虚拟化。

**结论:现有 verifier 验收门对"handler 实际是否动了 ctx.xmm"无直接断言。**
byte-exact + REQUIRE_REAL 都没抓到,因为输出值恰好等于输入值
(sub 未生效 → 输出仍是原值,与"原生"一致)。

== Goal ==
加固 WVmpVerifier 验收门,使 SSE/VMX/AVX 类涉及 ctx 跟踪区的指令
**必须**有"运行时读回 ctx.xmm[reg] 与原生 byte-exact"的断言,
而不仅靠 stdout + REQUIRE_REAL。

== Hard requirement: ToolSearch select: syntax FIRST (pitfall #75) ==
Verifier agent MUST first run ToolSearch query="select:Bash,Edit,Read,Write,Glob,Grep" max_results=10.
- Expect: 6 core tools returned (Read/Write/Edit/Bash/Glob/Grep)
- If empty or fewer than 6: IMMEDIATE structured FAIL, do NOT fabricate
DO NOT use generic keyword ToolSearch (MIT-381 v1 anti-pattern).

== Scope (本单) ==

**A. 加固 WVmpVerifier 验收门(本单核心):**
WVmpVerifier 接到 SSE/VMX/AVX 类 issue (由 VmOp 枚举名匹配
*ss/*ps/*pd / vfmadd* / vpadd* / vmov* / aes* 等,以及
涉及 xmm/ymm/zmm 跟踪区的指令)时,**必须**执行以下步骤
(在现有 build + ctest + multiseed REQUIRE_REAL=1 之外):

1. **裸多位立即数静态扫描**:
   `Select-String -Path vm\regvm\runtime\src\asmgen.cpp -Pattern "sub [^,]+, [0-9]{2,}|shl [^,]+, [0-9]{2,}|add [^,]+, 0x[0-9a-fA-F]+"`
   任意非零命中 → FAIL。命中必须经过 `imm()` 辅助或显式 `0x` 前缀。
   附 scan 输出 + 命中文件:行号。

2. **运行时 ctx 读回断言** (multiseed 内嵌):
   对每个 SSE/VMX 样本,在 E2E 脚本里增加:
   - 在被测样本 main 里新增 `printf("[ctx_xmm0]=%.6f\n", ctx.xmm[0])`
     或同等机制(若允许改 sse_*_sample_main.cpp)
   - 派活单若冻结 samples,verifier 改为加一个**影子样本**
     sse_x_xmm_readback_sample (与主样本用同一 IR,但额外打 ctx.xmm[reg])
   - native run vs virtualized run 都打这个,byte-exact 比对
   - 不一致 → FAIL

3. **handler 字节级 dump 校验**:
   `python` 用 capstone 反汇编 `wvmp_runtime_dump.bin`(或 generate_runtime
   产物的入口),确认每个 SSE handler 实际 emit 了 `subss xmm0, xmm1`
   而非 `sub ebx, 0x24`。任一 handler 的第一个算术指令不含 xmm 寄存器
   → FAIL。附 capstone 输出 + 失败/通过的 handler 列表。

**B. 标注"加固前"已知洞**(本单披露):
列出所有 MIT-371 之前已完成、但未跑新加固门验收的 SSE/VMX/AVX 类
issue。建议优先复核:
- MIT-371 (SSE add — 已暴露空转)
- 其他 SSE/VMX/AVX 类 commit (如 MIT-345 的 xmm 测试是否同样空转?)
- 给出"建议重验清单"(issue 列表 + commit),**不自动 rerun**(留给后续单)
- 这些清单项作为本单 AC #7

**C. WVmpVerifier instructions 更新:**
找到 WVmpVerifier agent 的 instructions 文本(用 `multica agent get WVmpVerifier --output json`),
按本单 AC 的 A.1/A.2/A.3 三步 patch。patch 后用 `multica agent update` 写回。
**不要**新增 agent,避免 agent 散乱。

== 决策点(项目主已拍板 2026-08-28) ==
**D1. 影子样本 sse_x_xmm_readback_sample**(✅ 已定):
本单强制走影子样本路径 —— 不改 sse_*_sample_main.cpp 主体。
影子样本作为独立 exe(CMakeLists.txt 注册),与主样本同 IR 但额外
打 ctx.xmm[reg] 读回。后续 SSE/VMX/AVX 派活单沿用此模式,
每条新指令各加 1 个影子样本,与主样本 1:1 配对。

**D2. handler 字节级 dump 用 wvmp_runtime_dump.bin 反汇编**(✅ 已定):
直接对已有 `wvmp_runtime_dump.bin` 用 capstone(MIT-371 已使用,
python capstone 5.0.7)反汇编。不新增 IDA-style hook 或 generate_runtime
产物改造。dump 校验脚本路径:
scripts\verifier\dump_handler_xmm_check.py

**D3. 已知 SSE/VMX/AVX 复核清单 — 1 个总单批量做**(✅ 已定):
本单 B 段(AC #7)产出脚本目录 scripts\verifier\PRE_EXPOSURE_LIST.md
列清单 + **不自动 rerun**,但新增 1 个 follow-up issue
(MIT-389 完成后由项目主立单 "MIT-XXX: SSE/VMX/AVX 加固门复核批量重跑")。
follow-up 单一次派发,所有待复核 commit 在同一单内做,
避免 N 个单散乱 + 重复派发 verifier。

== AC (Acceptance Criteria) ==
#1 build.bat rc=0, WVmp 自有代码 0 错误
#2 ctest 16/16 PASS(零回归)
#3 A.1 静态扫描脚本可在 WVmpVerifier instructions 里被引用
    (新增文件 scripts\verifier\static_scan_bare_immediates.ps1)
#4 A.2 影子样本 sse_subss_xmm_readback_sample 跑通
    (native vs virtualized byte-exact, ctx.xmm[0] 一致)
#5 A.3 字节级 dump 校验脚本可在 WVmpVerifier instructions 里引用
    (新增文件 scripts\verifier\dump_handler_xmm_check.py)
#6 multiseed REQUIRE_REAL=1 跑新加固门, 13 samples × 5 seeds
    至少 sse_add + sse_sub + 影子样本 = 15/15 PASS
#7 B 披露文档产出: scripts\verifier\PRE_EXPOSURE_LIST.md
    含建议重验清单(issue 号 + commit hash + "未跑新门"标注)
#8 C WVmpVerifier instructions patch 成功, agent update 后
    `multica agent get WVmpVerifier` 输出含本单 A.1/A.2/A.3 引用
#9 冻结契约未触碰: git diff --stat 仅本单新增的 scripts\verifier\ 目录
    + WVmpVerifier instructions(其他源文件零改动)
#10 git log --all 线性干净, 仅 main 分支, status clean

== 冻结契约 ==
- vm/regvm/runtime/src/asmgen.cpp: 只允许新增 build_subss/build_subps/build_subpd
  的辅助 `imm()` 已存在(MIT-371 已建),**不动**。本单验收脚本不要求改它。
- vm/regvm/translator/src/translator.cpp: 不动
- passes/lifter/src/x86_translate.cpp: 不动
- ir/include/wvmp/ir/insn.hpp / vm_op.hpp: 不动(enum append-only)
- VmContext 布局 / stub_gen kCtxSize: 不动
- 现有 E2E 样本(13 个): 不动样本主体, 影子样本新增独立 exe

== commit 纪律 ==
- type(scope): 中文描述, 不写"完成"
- 1 commit 1 task
- 验收前不发 PR / merge, 等 verifier Accept

== 出 issue 时不要带 ID 前缀 ==
multica 自动分配 MIT-NNN, 标题里不要写 "MIT-378: "