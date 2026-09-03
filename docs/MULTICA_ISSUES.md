# WVmp multica 工单整理

> 本文档是 WVmp 项目自 2026-08-29 起通过 [multica](https://github.com/multica-ai/multica) 派发的工程任务的全景归档。
>
> **不在本仓库内**的原始记录：
> - 每个工单的完整裁定全文（`.multica/mitNNN-ruling.md`，110 个文件）
> - 侦察类报告（`.multica/mit-XXX-triage.md`，10 个文件）
> - 派活单原文（`.hermes/issues/mitXXX_desc.md`，45 个文件）
> - 打包下载：`docs/multica-archive.tar.gz`（451 KB，155 条目 — **本仓库不入 git**，由 GitHub Release 托管）

## 阅读方式

| 你的需求 | 看什么 |
|---|---|
| 看项目主线交付节奏 | 本文档「阶段总览」三张表 |
| 了解某一单做了什么 | 本文档「逐单简表」21 单 → `multica-archive` 内裁定全文 |
| 想复跑某单的派发逻辑 | `multica-archive/hermes-issues/mitNNN_desc.md` |
| 看扫描/侦察类报告 | `multica-archive/multica/mit-XXX-triage.md` |

---

## 阶段总览

WVmp 派单经历两个主里程碑：**M2.5-G（指令虚拟化阶段）** 与 **M2.5-X（多目标平台里程碑）**。
后续主力线已挂账 park（详见「挂账主线」节），X 波实施欠账在 X7 已数据裁决清零。

### 里程碑一：M2.5-G（指令虚拟化阶段，2026-08-29 ~ 2026-08-31）

主线目标 = 把 MSVC x64 自然指令产物中所有真实出现的指令族（G1~G9 分族）逐一真虚拟化，每单必须既有独立复验又有全基线回归。

| 单 | 阶段代号 | 主交付 | main |
|---|---|---|---|
| MIT-419 | G4 | lock 原子族（xadd/bts）走硬件原子保真 | `92b21cb` |
| MIT-423 + 424 | G4b + G6r | G4b lock_inc/dec + G6r 侦察 R2 路线裁决 | `123bf09` |
| MIT-425 | G1b | SSE 收官包，指令虚拟化阶段 SSE 线清零 | `e652eff` |
| MIT-426 | G6a | VEX.128 档 A（零新 VmOp 机器证明成立） | `b8dbde4` |
| MIT-427 | G1c | movd/movq SSE→GP 桥接 | `35ea03d` |
| MIT-428 | G1d | movdqa/movdqu 折叠（零新 VmOp 教科书折叠单） | `0ac661a` |
| MIT-432 | G9r | 收官三路侦察（全出数零跳过） | `624e900` |
| MIT-433 | P1 | rol/ror flags 修复（P1 现网缺口亲验闭环） | `cdc218d` |
| MIT-434 | G8a | BMI 折条款目（三陷阱全拆） | `df3c2f1` |
| MIT-435 | GZ | **阶段收官文档波**（指令虚拟化阶段正式完成） | `9a74896` |

**M2.5-G 终态**：基线 **240/240**（48 样本×5 seeds），kVmOpMax=97，跳表余量 30；x64 量产指令面（MSVC 自然产物）几乎全覆盖。

### 里程碑二：M2.5-X（多目标平台里程碑，2026-08-31 ~ 2026-09-03）

主线目标 = 在 x64 量产面稳态后，把同一保护壳流水线**完整搬运到 x86 (PE32)**，并以客户态真实语料（System32 / SysWOW64）量化覆盖率。

| 单 | 阶段代号 | 主交付 | main |
|---|---|---|---|
| MIT-436 | X0 | x86 侦察（95.74%/98.72% direct，x87 占 missing 六成，x87 三路线数字齐） | `f7a865c` |
| MIT-437 | X1a | marker_scan x86 锚点（双方向同窗判据推翻派单先验） | `2dad6ff` |
| MIT-438 | X1b | ret imm16 清栈（x64 静默炸弹修复 + SEH/FS gate 文档 + CLI arch 字段） | `110a6aa` |
| MIT-442 | X2a | 形级 fork 面收口（call[mem] / plain 串 / leave / S16 / cwde / cbw / cld 全折条） | `5ce27c7` |
| MIT-443 | X3a | asmgen x86 核心（KS_MODE_32 双模 + 池 14→6 spill 重构） | `4050a4c` |
| MIT-444 | X3b | asmgen x86 整数面（真可跑面 19→57） | `9c00962` |
| MIT-445 | X3c | 协议面收口（call [mem] x64 翻案 + ExitNative 4B + CallGate reg-target） | `e20b383` |
| MIT-446 | X4 | **x86 生产可用达成**（E2E 3/3 项目主亲手 WOW64 byte-exact） | `dc2f21a` |
| MIT-450 | X5 | **M2.5-X 里程碑收口**（§F.1 反向条款完美兑现：真实语料挖出 C2 缺陷不伪全绿） | `df6b751` |
| MIT-451 | X5b | mul64hi 崩溃销账 + 跳表匹配器 S32 翻正 + REG-REG 位测试族入面 | `ae194d3` |
| MIT-452 | X5cr | 跳转目标块侦察（裁决 a：接线级缺口实锤） | `9647a13` |
| MIT-453 | X5c | ExitNative x86 上界接线修复（407 机制在 PE32 复活，en 0→17） | `4083b1f` |
| MIT-454 | X6 | **并单**：push-imm 开面（11→0）+ SSE 32 op 全入面（0→92） | `bf2a41d` |
| MIT-455 | X7 | **重扫 + 数据裁决制**：双 arch 三层口径（x64 99.26% / x86 95.15%）+ x87 B 路线正式销案 | `0b6c5ba` |

**M2.5-X 终态**：基线 **330/330**（66 样本×5 seeds），x86 真虚拟化率 **12/14 区 = 85.7%**，残面 2 = 永久挂账（间接 jmp L 级数据销案 + mul64hi 栈深永久 gate）。X 波实施欠账全部清零。

---

## 逐单简表（M2.5-G + M2.5-X 全 24 单）

**阶段**列缩写：**G** = M2.5-G / **X** = M2.5-X

| 编号 | 阶段 | 标题 | 状态 | main | 关键数字 / 物证 |
|---|---|---|---|---|---|
| MIT-419 | G | lock 原子族（xadd/bts）走硬件原子保真 | ✅ ACCEPT | `92b21cb` | 185/185 |
| MIT-423 | G | G4b lock_inc/dec | ✅ ACCEPT | `123bf09` | 190/190 |
| MIT-424 | G | G6r 侦察（路线 R2 裁决） | ✅ ACCEPT | `123bf09` | 三路基线出数 |
| MIT-425 | G | SSE 收官包（指令虚拟化阶段 SSE 线清零） | ✅ ACCEPT | `e652eff` | 200/200 |
| MIT-426 | G | VEX.128 档 A（零新 VmOp 机器证明） | ✅ ACCEPT | `b8dbde4` | 210/210 |
| MIT-427 | G | movd/movq 桥 + harness 盲区三步反证 | ✅ ACCEPT | `35ea03d` | 220/220 |
| MIT-428 | G | movdqa/movdqu 折叠（教科书级单） | ✅ ACCEPT | `0ac661a` | 230/230 |
| MIT-432 | G | 收官三路侦察（P1 缺口亲验） | ✅ ACCEPT | `624e900` | 三路基线出数 |
| MIT-433 | G | rol/ror flags 修复（P1 现网缺口） | ✅ ACCEPT | `cdc218d` | 235/235 |
| MIT-434 | G | BMI 折条款目（三陷阱全拆） | ✅ ACCEPT | `df3c2f1` | 240/240 |
| MIT-435 | G | 阶段收官文档波（指令虚拟化阶段完成） | ✅ ACCEPT | `9a74896` | **🏁 M2.5-G 收官** |
| MIT-436 | X | x86 侦察（多目标平台行图定版） | ✅ ACCEPT | `f7a865c` | 95.74%/98.72% direct |
| MIT-437 | X | marker_scan x86 锚点（双方向同窗判据） | ✅ ACCEPT | `2dad6ff` | #33 推翻派单先验 |
| MIT-438 | X | ret imm16 清栈 + CLI arch 字段 | ✅ ACCEPT | `110a6aa` | x64 静默炸弹修复 |
| MIT-442 | X | 形级 fork 面收口（7 类折条） | ✅ ACCEPT | `5ce27c7` | kVmOpMax=97 不动 |
| MIT-443 | X | asmgen x86 核心（KS_MODE_32 双模） | ✅ ACCEPT | `4050a4c` | x64 恒等铁证 |
| MIT-444 | X | asmgen x86 整数面全支持 | ✅ ACCEPT | `9c00962` | 真可跑 19→57 |
| MIT-445 | X | 协议面收口（call [mem] 翻案 + ExitNative） | ✅ ACCEPT | `e20b383` | 442 挂账闭环 |
| MIT-446 | X | x86 全管道打通（**生产可用达成**） | ✅ ACCEPT | `dc2f21a` | E2E 3/3 WOW64 byte-exact |
| MIT-450 | X | 多目标平台里程碑收口（§F.1 兑现） | ✅ ACCEPT | `df6b751` | **🏁 M2.5-X 收档** |
| MIT-451 | X | mul64hi 崩溃销账 + 跳表匹配器 S32 | ✅ ACCEPT | `ae194d3` | 103-kernel 双跑 diff-0 |
| MIT-452 | X | 跳转目标块侦察（接线级缺口实锤） | ✅ ACCEPT | `9647a13` | 裁决 (a) |
| MIT-453 | X | ExitNative x86 上界接线修复 | ✅ ACCEPT | `4083b1f` | en 0→17 |
| MIT-454 | X | push-imm + SSE 32 op 并单 | ✅ ACCEPT | `bf2a41d` | stubs 9→11 |
| MIT-455 | X | 重扫 + 数据裁决制（双 arch 三层口径） | ✅ ACCEPT | `0b6c5ba` | 85.7% / 99.26% |

---

## 派活单纪律（沉淀）

24 张能力单全绿不是运气，是七条纪律**机械执行**的结果。GitHub 上者阅读裁定全文可一一对照：

1. **验收铁律**：不盲信 agent 自报——项目主独立 fresh verify（build + ctest + multiseed(REQUIRE_REAL=1) + 代码层核查 + worktree 隔离）；agent 单方粘贴的"修复前必崩反证"不算数（MIT-406 教训）。
2. **命名分支铁律**：交付必须落 main 外命名分支，违者退回重交（MIT-415 新铁律）。
3. **零扰动口径**：涉 runtime 码体尺寸变更的单，**逐 handler 对账 + 行为恒等**，禁用 packed sha 恒等（MIT-433 教训）。
4. **载体域纪律**：冻结 `ir::Op` 下用 imm 值域做侧信道，每次新用必须全域对账（419/425/434/442 四次踩/预防）。
5. **派发纪律**：`multica issue create --assignee-id <UUID>` 一步直派=唯一 run；创建后禁再 rerun/comment 双触发竞态。
6. **D6 边界亲核**：agent 越权 ff 合入 main 必须 reset 还原，分支链保留照常验收（MIT-453 事件模板）。
7. **数据先行 + 预登记阈值**：批一侦察出表→批二按预登记规则机械执行；"维持 gate 是满分结论不是失败"（MIT-455 设计）。

七条纪律在派活单原文（`multica-archive/hermes-issues/mitNNN_desc.md`）的 §A/§B/§C/§D 节均一致标注。

## 平台事故族汇总（沉淀，非阻断交付）

派发平台偶发工具集缺失 / daemon 重启 / 网络抖动——七起事故全由 `issue rerun` 自动恢复，**零丢交付**：
- MIT-417 / MIT-418：claude exit 1
- MIT-427：claude exit 1（同类）
- MIT-434 attempt-1：工具集缺失 → rerun 即愈
- MIT-435：3 次 Connection refused → attempt-4 即愈
- MIT-450：attempt-1/2/3 三连败 → attempt-4 即愈（事故族第 6 起）
- MIT-451 attempt-1：daemon 重启 → 自动重开即愈（事故族第 7 起）
- MIT-453：agent 自合入 main（**非平台故障**，是字面条款问题）

monitor 模板历经 446 起从钉死 RUN_ID 改为盯"最新 attempt"，避免单 RUN 重开后盲退。

---

## 挂账主线

X 波实施欠账 455 全部清零后，下一战役候选：

| 编号 | 主题 | 状态 |
|---|---|---|
| MIT-410 | M3 加密保护线（X0 triage 已列出 F1/F2 加密需求） | park，等于主战场 |
| — | push_mem x86（1.845%，x86 第一大非 x87 shape gate） | 数据入册，待按族裁量派单 |
| — | 客户态真实占比二次扫描（X7 方法学重跑） | 量化面板就绪，重扫周期未定 |

---

## 致谢

multica 作为派活/裁定/留样平台，让 WVmp 在 6 天内完成两个里程碑共 24 单全绿。GitHub 仓库同步时建议保留 GitHub Release 同步 `docs/multica-archive.tar.gz`（451 KB），便于读者下钻单级裁定全文。