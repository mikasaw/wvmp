MIT-379: SSE/Block backlog 派活单模板更新 — 基线认知修正 + run-messages AC 移除 + ctest 基线对齐

> Issue generated: 2026-08-28, hermes (project owner)
> Linked: MIT-373 status=in_review, MIT-378(同步创建,verifier 验收门加固)
> Backlog 待更新派活单(沿用 MIT-371 模板,需同步基线):
>   MIT-374 SSE div / MIT-375 SSE mul / MIT-376 SSE 位运算 /
>   MIT-405 LOOP / MIT-406 BSF / MIT-407 BT(Block F)

== Context ==
MIT-373 暴露了 3 类 SSE backlog 派活单基线认知错误:

**1. SSE handler 验收基线错误**:
MIT-371 SSE add (addss/addps/addpd) 在 commit 23f0e25 时 verifier
Accept 成功,但 handler 全部空转(MIT-373 才定位根因:Keystone 裸
多位立即数十六进制解析)。后续沿用 MIT-371 模板的 SSE backlog
(MIT-374 div / MIT-375 mul / MIT-376 位运算)若按现有模板派活,
**新指令会同样空转**,即使 multiseed byte-exact PASS 也会 Accept
假阳性。

**2. `multica issue run-messages` 子命令 404**:
MIT-371/MIT-373 派单 AC #? 里包含的 `multica issue run-messages`
子命令在当前 multica CLI 不存在(实测 404)。backlog 派活单
若沿用旧模板,agent 会在该项 FAIL,但其实不可执行。

**3. ctest 基线数字漂移**:
MIT-371 派单写 "ctest 15/15", MIT-380 新增 regvm_backend_tests 后
实际基线 16/16。MIT-373 agent 自行在报告里纠正(MIT-371 派单写
"ctest 15/15"已过期,本次 16/16 派单自动适应)。backlog 派活单
继续写 15/15 会让 verifier 误判 fail。

== Goal ==
统一更新 SSE/Block backlog 派活单模板,使之:
- 反映 MIT-373 的 imm() 修复基线认知(MIT-371 后续不再有 handler 空转风险)
- 移除不可执行的 `multica issue run-messages` AC 项
- ctest 基线对齐 16/16
- 加 MIT-378 加固门的引用,使 backlog 派活单自带"ctx.xmm 读回断言"硬要求

== Scope ==

**A. 派活单模板更新(本单核心):**
新增统一模板:
.hermes/templates/SSE_BLOCK_BACKLOG_DISPATCH.md

模板内容(强制项):
- Context 段必须含 "MIT-373 commit 8ed50b0 imm() 修复已落地,
  SSE/VMX/AVX handler 空转根因已堵,本单基于真虚拟化基线"
- AC #? "multiseed 65/65" → "multiseed 13 samples × 5 seeds = 65 runs,
  其中本单新增样本 + sse_add_sample + sse_sub_sample 全 PASS,
  其余沿用 MIT-373 时点基线(40/65,其余为既有 segfault,
  5 样本 × 5 seeds)"
- AC #? "ctest 15/15" → "ctest 16/16 (基线含 regvm_backend_tests)"
- 移除 `multica issue run-messages` 相关 AC 项(整段删)
- 冻结契约段添加:
  "本单新增 handler 必须使用 `imm()` 辅助拼立即数,
  禁止裸多位数字写入 Keystone 文本(陷阱 #1 现行犯,
  MIT-373 root cause)"

**B. backlog 派活单整改清单:**
列出现有 backlog 派活单 + 标"是否需重发/补救":
- MIT-374 SSE div (divss/divps/divpd) — 派活单存在,但未跑过
  加固门。**需要**:在 backlog 派发前重写派活单用新模板
- MIT-375 SSE mul (mulss/mulps/mulpd) — 同上
- MIT-376 SSE 位运算 (andps/andpd/xorps/xorpdorps) — 同上
- MIT-405 LOOP / MIT-406 BSF / MIT-407 BT (Block F) — 非 SSE,
  不受 imm() 根因影响,但仍需新模板的 ctest 16/16 + 移除
  run-messages AC

每条给 "整改要求"(rewrite 派活单描述 或 补 patch)

**C. WVmpCppDev instructions 同步:**
找到 WVmpCppDev agent 的 instructions,用 `multica agent get WVmpCppDev --output json`,
按本单 patch 加 "新指令立即数必须用 imm()" 硬约束(对应陷阱 #1)。
避免 backlog 派活时再次踩坑。

== 决策点(项目主已拍板 2026-08-28) ==
**D1. backlog 整改用 `multica issue update --description-file` 重写**(✅ 已定):
本单对 MIT-374 / MIT-375 / MIT-376(SSE 3 单)+ MIT-405 / MIT-406 /
MIT-407(Block F 3 单)共 **6 个 backlog 派活单**的 description
**全部 rewrite**(用 `multica issue update --description-file <new_md>`)。
不在 comment 补 patch —— agent 可能漏看 comment。
整改后 AC #3 验证:`multica issue get MIT-374` 等输出 description
必须含新基线语句。

**D2. 模板仅人类参考**(✅ 已定):
`.hermes/templates/SSE_BLOCK_BACKLOG_DISPATCH.md` 不被 WVmp agent
体系自动识别(实测 agent instructions 由派活单 description 直接驱动)。
模板只用于:项目主/verifier 人在派活前复制 + 手工 patch 派活单 description。
模板内不嵌入自动加载逻辑(避免给 WVmp agent 体系埋误识别风险)。
C 段 patch WVmpCppDev instructions 时,直接把模板里"硬约束 4 条"
复制到 instructions(项目主已验证 WVmpCppDev instructions 是
agent 实际读取路径)。

== AC ==
#1 .hermes/templates/SSE_BLOCK_BACKLOG_DISPATCH.md 存在,内容含 A 段全部强制项
#2 backlog 派活单整改清单产出(.hermes/docs/SSE_BLOCKLOG_AUDIT.md):
    - 现有 SSE/Block issue 列表
    - 每条标 "需 rewrite / 仅 patch / 已 done 无需动"
#3 MIT-374/375/376/405/406/407 中 "需 rewrite" 项的派活单 description
    全部更新(用 multica issue update --description-file),
    整改后 `multica issue get MIT-374` 等输出 description 含新基线语句
#4 WVmpCppDev instructions 含 "新指令立即数必须用 imm()" 硬约束
    (multica agent get WVmpCppDev 输出验证)
#5 WVmpVerifier instructions 含 "SSE/VMX/AVX issue 必须跑
    scripts/verifier/static_scan_bare_immediates.ps1" 引用
    (若 MIT-378 已落地;否则引用 MIT-378 待完成)
#6 冻结契约未触碰: git diff --stat 仅 .hermes/ 目录新增文件
    + 派活单 description 文本改动(其他源文件零改动)
#7 git log --all 线性干净, 仅 main, status clean

== 冻结契约 ==
- 源文件零改动(asmgen.cpp / translator.cpp / lifter 等都不动)
- 不新建 agent
- 不动 VmContext 布局 / kCtxSize / 现有 E2E 样本主体

== commit 纪律 ==
- type(scope): 中文描述
- 1 commit 1 task
- 不写"完成"

== 出 issue 时不要带 ID 前缀 ==
multica 自动分配 MIT-NNN, 标题里不要写 "MIT-379: "