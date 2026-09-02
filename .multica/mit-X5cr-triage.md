# MIT-X5cr 侦察报告 — "跳转目标块未找到"17 处根因分型 + exit-native=0 之谜

> 交付: 2026-09-02 | 分支 `mit-x5cr-jtbn-recon` (基于 main `ae194d3`) | 纯文档+离线脚本, 零产品代码
> 方法: 全部数字自测 (protect 双 arch 亲跑 + 离线复刻脚本 `scripts/verifier/mit_x5cr_jtbn_triage.py`),
> 判定链逐条件走查以 `translator.cpp` 现码为准 (前置链行号已重钉, 见 §5)。

## 总体结论 (先行)

**裁决 = §B.2 选项 (a): x86 ExitNative 前置链存在 arch 假设漏洞——上界 provider 硬绑 .pdata,
x86 无 .pdata → 判定链条件 D 恒失败 → 17 处全落 skip、en=0。** 17 处目标是同一批源级跳转
(x64↔x86 逐站点配对 17↔17, 操作码 0 失配), 全部落在本函数尾 gap (end 桩 call + 尾声),
语义上正是 ExitNative 的设计目标类。**修一个判据点 (backend 上界 lambda 的 x86 分支) 即 17 处全翻正,
预计 x86 wvmpTest 虚拟化 0 → 10 stubs。** X5c 实施单建议按 §3 推荐 F1 组合立项。

## 1. §A.2 锚复测 (全部亲跑, main CLI @ ae194d3, 输出落 %TEMP%\mit452)

| 锚 | 项目主 §A | 本单复测 | 对账 |
|---|---|---|---|
| x86 "跳转目标块未找到" | 17 | **17** (`protect_x86.log` grep -c) | ✅ |
| x86 exit-native | 0 | **0** | ✅ |
| x64 exit-native (同 toml 同构) | 17 | **17** (`protect_x64.log`) | ✅ |
| x64 本类 skip | 0 | **0** | ✅ |
| x86 skip 函数总面 | 30 (push-imm 11/其他) | **30** = jtbn 17 + push-imm 11 + 间接 jmp 1 + stack-depth 1 | ✅ |
| x86 虚拟化 | — (§A.3: 0 stubs) | **"没有任何函数被虚拟化" + 0 stub** | ✅ |
| x64 stubs | 14 | **"已生成 14 个入口 stub"** | ✅ |
| 分布 12 marker | aa18×3/aa7b×2/ab3b×2/ad5b×2/addb×1/aebb×2/… | aa18×3/aa7b×2/ab3b×2/ad5b×2/addb×1/**aebb×1**/b04c/b0e5/b4ab/b59b/bc3c/bd2c 各×1 | ⚠️ 见下 |

⚠️ 失配披露 (B.5 纪律): 派活单 §A.2 分布草记 "aebb×2" 与实跑不符——`marker@0xaebb` 实为
**jtbn×1 (0xBADA) + 间接 jmp×1 (0xBAE3)**; 12 marker/17 总数/单函数 1-3 处全部吻合, 仅该格
把间接 jmp 误计入 jtbn。§A.2 其余锚 (3+2+2+2+1 首五格、17、30、en=0) 逐一对上。
另: x64 同 idx 区域站点分布与 x86 完全同构 (3,2,2,2,1,1,1,1,·,1,1,·,1,1), idx8/11 双 arch 均无本类站点。

## 2. 17 处互斥分型表 (B.1, 单一型: **T1 = 前置链条件 D 系统性不命中**)

判定链 (`translator.cpp:1631-1671`, `translate_jump` 目标不在 `block_of_addr` 时):
A) op∈{Jmp,Jcc} 且目标 Imm → B) `upper_bound_of_` 非空 → C) `target >= end_rva_`
→ D) `upper.has_value() && target < *upper` → E) `fits_aux(target)`; 全真 emit ExitNative, 否则 skip。

复刻脚本对 x86 全部 17 处逐条件走查 (capstone CS_MODE_32), 结果:**17/17 唯一失败条件 = D**,
A/B/C/E 全真; 目标落点全为 "本函数尾 gap [end_rva, 下一区域 begin)"。区域表由脚本复刻
marker_scan (x86 双段 magic + E8 归因 + 栈配对) 求得, 14 区域与日志命名一一对应。

| # | marker(区域) | site rva | 指令 | 目标 | 落点 | 失败 |
|---|---|---|---|---|---|---|
| 1 | aa18(idx0) | 0xB625 | `jmp` | 0xB668 | gap[0xB640,0xB67B) | **D** |
| 2 | aa18 | 0xB62B | `jne` | 0xB640 | gap (end 桩 call) | **D** |
| 3 | aa18 | 0xB63E | `jmp` | 0xB668 | gap | **D** |
| 4 | aa7b(idx1) | 0xB6A8 | `jae` | 0xB722 | gap[0xB722,0xB73B) | **D** |
| 5 | aa7b | 0xB6D9 | `jmp` | 0xB72A | gap | **D** |
| 6 | ab3b(idx2) | 0xB88D | `jmp` | 0xB931 | gap (end 桩 call) | **D** |
| 7 | ab3b | 0xB89B | `jne` | 0xB931 | gap (end 桩 call) | **D** |
| 8 | ad5b(idx3) | 0xB971 | `jg` | 0xB9B8 | gap[0xB9B8,0xB9DB) | **D** |
| 9 | ad5b | 0xB992 | `jmp` | 0xB9C0 | gap | **D** |
| 10 | addb(idx4) | 0xBA72 | `je` | 0xBAA4 | gap[0xBAA4,0xBABB) | **D** |
| 11 | aebb(idx5) | 0xBADA | `ja` | 0xBC09 | gap[0xBC09,0xBC4C) | **D** |
| 12 | b04c(idx6) | 0xBC65 | `jge` | 0xBCBD | gap[0xBCBD,0xBCE5) | **D** |
| 13 | b0e5(idx7) | 0xBDA2 | `jge` | 0xBEEF | gap[0xBEEF,0xBF8D) | **D** |
| 14 | b4ab(idx9) | 0xC0DB | `jae` | 0xC163 | gap[0xC163,0xC19B) | **D** |
| 15 | b59b(idx10) | 0xC1E4 | `jge` | 0xC234 | gap[0xC234,0xC278) | **D** |
| 16 | bc3c(idx12) | 0xC882 | `jge` | 0xC8E9 | gap[0xC8E9,0xC92C) | **D** |
| 17 | bd2c(idx13) | 0xC972 | `jge` | 0xC9D5 | gap[0xC9D5,EOB) 末区 | **D** |

落点内容实测 (idx0 为例): 区域末 0xB640 = `call 0xb3d0` (END 桩), 尾部 0xB668 = `pop ebp; ret`
(共享尾声), 之后 int3 填充 + 下一个 kernel 的 prologue `push ebp…call 0xb3b0` (BEGIN 桩)。
**目标全部是本函数自己的尾声/收尾段——正是 x64 ExitNative 已在消化的一类。**

互斥性: 不存在 T2 (区内未 lift: 17 处 C 全真即全在区域外)、T3 (越入其他区域: 0 处)、
T4 (越过下一区域 begin: 0 处)。**单型, 无混合。**

## 3. exit-native=0 之谜裁决 (B.2) — 机制 + 双 arch 对照证据

### 3.1 机制 (精确判据行)

- x64: `regvm_backend.cpp:96-111` 上界 lambda → `pe->find_function_end_rva(begin_rva)`
  (.pdata RUNTIME_FUNCTION EndAddress, `pe_image.cpp:177-193` 二分)。x64 test_target.exe
  Exception Directory = RVA 0x10D000 / size 0x549C → 条件 D 有界 → 17 处全 emit。
- x86: 同 lambda 第一行 `if (pe == nullptr || pe->pdata_empty) return std::nullopt;`
  (`regvm_backend.cpp:98`)。x86 test_target.exe **Exception Directory = 0/0 (dumpbin 实测)**,
  `pe_image.cpp:139` `pdata_rva != 0` 不成立 → `pdata_empty=true` (`:169`) → lambda 恒 nullopt
  → **条件 D 对所有候选恒失败** → 17 处全落 skip, en=0。
- 关键: PE32 (x86) 本无 .pdata (表式 SEH 是 x64 专属), 这是 **.pdata 依赖被写进 ExitNative
  接线** 的 arch 假设漏洞, 不是 x86 跳转语义不该走 ExitNative。

### 3.2 对照实验证据 (三组, 全部命令输出在案)

1. **判定链模型复验**: 复刻脚本对 x64 17 处以同一链模型走查 → **17/17 emit=True**, 与产品
   日志逐站点一致 (含条件/目标值)——模型可信。
2. **双 arch 站点配对**: 区域序+区内序配对 → **17↔17, 操作码 0 失配** (jmp/jne/jae/jg/je/ja/jge
   逐对同构)。"两个 17" 就是同一批源级跳转 (跳尾声/跳 end 桩 call), 非巧合。
3. **落点同构**: x64 17 处落点同样全为 "本函数尾 gap [end_rva, 下一区域 begin)"
   (如 idx0: 0xD55F→0xD59F gap[0xD57C,0xD5C7)); 与 x86 逐一对应。

### 3.3 三选一裁决

- **(a) x86 前置链 arch 假设 bug ✅ (采纳)**: 点位 = `regvm_backend.cpp:98` 的
  `pdata_empty → nullopt` 短路; 最小修法见 §4 F1。
- (b) "skip 即正确设计" ❌: 同批跳转在 x64 走 ExitNative 且 315/315 全绿; x86 runtime
  **已有** ExitNative handler (`asmgen.cpp:5299 build_x86_exitnative`, MIT-445 X3c B.2,
  真执行电池 `test_runtime_x86.cpp:2165-2258`)。语义前提 (目标=本函数尾 native 字节,
  不被 stub 覆写) 双 arch 同真。
- (c) "目标真未 lift (归 lifter)" ❌: 17 处 C 全真 (全在区域外), 非"区内未 lift"。

### 3.4 修后无回跳干扰

lifter 回跳检出 (`lifter_core.cpp:34-44` BFS ≤3 层/256 预算, `lifter_pass.cpp:81-88` 接线)
为 arch 共享码, fix 后照常生效; 复刻 BFS 对 x86 17 处目标全部 **backjump=False (0/17)** →
`exit_native_blocked` 不会拦截任何一处。

## 4. 修复选项对比 (B.3, X5c 实施输入)

| 项 | F1: 下一区域 begin 兜底 (推荐) | F2: .text 节尾 + 落点守卫 | F0: 维持现状 |
|---|---|---|---|
| 方案 | `regvm_backend.cpp` lambda 加 x86 分支: `pdata_empty` 时 ub = min{fr.begin_rva > fn.begin_rva} (来自 `ctx.functions`), 无后继时回退 .text 节尾 | 同点, ub = .text 节尾; 需在 `translator.cpp:1647` 追加 "target 不入任何其他区域" 守卫 | 不修, 文档化 |
| 改动面 | 仅 `regvm_backend.cpp` (~15 行) + 单测 | backend + **translator** 两处 | 0 |
| 预估 | **S** | M | — |
| 翻正数 | **17/17** (16 处 next-begin 命中 + 末区 0xC972 靠 .text 兜底) | 17/17 | 0/17 |
| x64 回归风险 | 最低 (x64 恒有 .pdata, 走原短路前分支, 字节不动) | translator 链改动, 面大 | 0 |
| 回归验证 | multiseed 315/315 + wvmpTest x86 双跑 + dumpbin 入口字节 | 同左 | — |

**推荐组合**: F1 单点 (backend lambda), 不动 translator。安全性论证: 区域表 disjoint 且
单调递增 (marker 栈配对产物, 本单 14 区域实测), [own_end, next_begin) ⊆ 本函数尾
(下一 kernel 的 BEGIN call 在其 prologue 之后), 目标不被 stub 覆写; 无后继区域时 .text 节尾
兜底仍受 C (target≥own_end) 约束, 落点只能是自己尾部或 int3 填充 (17 处无此类)。

**修后 wvmpTest x86 预期读数** (X5c 验收锚):
- `exit-native @` ×**17** (含仍在 gate 函数内的 4 处 diag——aa18×3/aebb×1 翻译期照发 note);
- 虚拟化 stub **0 → 10**: 14 区域 − 4 个仍有他族 gate 的函数 = aa18 (push-imm 0xB62D)、
  aebb (间接 jmp 0xBAE3)、b38d (stack-depth)、b678 (push-imm ×10);
- 本类 skip 17→0; skip 总面 30→13 (push-imm 11 + 间接 jmp 1 + stack-depth 1);
- x64 侧产物逐字节不变; multiseed 63 样本 315/315 应保持。

## 5. 泛化评估 (B.4, 口径如实)

- 可量化域 (仅 wvmpTest x86, 自家 kernel 语料): 12/14 kernel 函数 (86%) 携带 ≥1 处本类跳转,
  占 skip 面 17/30 (57%)。MSVC /Od x86 "跳共享尾声" 生成习惯是主因。
- 客户面: 真实第三方 x86 产物**不带 SDK marker**, 无法直接套区域表统计 (436 的 SysWOW
  100 文件覆盖率扫的是 lifter 指令覆盖, 与本类不同构)。本类影响的是**接入 SDK 且函数含
  "跳过 END marker 落尾声" 形态**的客户函数——该形态在 x86 MSVC 产物极常见 (wvmpTest
  86% 函数携带), 但客户面占比需 X5c 落地后按 436 方法学对带 marker 的抽样重扫才能给数。
  本单不编造该数字。
- 机制面结论可泛化: **任何 x86 (或任何无 .pdata 的 PE) 目标, ExitNative 现状恒不可达**——
  这不是 wvmpTest 特有, 是接线级缺口; F1 修后同样惠及全部此类目标。

## 6. 纪律对账 (§D.2 / §E)

- 硬条款: 命名分支 `mit-x5cr-jtbn-recon` ✅ | diff = 本报告 + `scripts/verifier/mit_x5cr_jtbn_triage.py`
  (离线只读脚本, 复刻 marker_scan/判定链/BFS, 依赖 capstone) ✅ | main 未动、零脏、
  worktree 自拆、切回 main、ff-safe ✅ | 全程 ≥30 分钟 (09:54 接单起, 见 issue 时间线与
  commit 时间) ✅
- 锚重钉 (#33): skip 行 `translator.cpp:1671` **未漂移**; ExitNative 前置链实际
  `:1644-1669` (派活单记 :1638-1670, 区间注释行 :1633-1643 属实); 上界接线
  `regvm_backend.cpp:96-111` (短路点 :98); pdata 解析 `pe_image.cpp:139/169`; 区域命名
  `marker_scan_pass.cpp:185` (marker@hex = begin **文件偏移**, begin_rva 另经换算)。
- D1 边界: 仅本类 17 处; stack-depth/push-imm/间接 jmp 族只做对账未展开。
- D3: 对照实验 wvmpTest 只读, protect 输出/log 全落 `%TEMP%\mit452\`; x64 用 main CLI 亲跑。
- §F.1 预判兑现: 泛化只能给抽样估计, 已注明口径; §F.2: 判定均以运行时产物
  (protect 日志/反汇编/dumpbin) 为准, 读码仅定位点位。

## 7. 给项目主的决策建议

X5c 实施单可立项: 按 §4 F1 (backend lambda 单点, S 估) 走; 验收锚用 §4 "修后预期读数"
(en=17 / stubs=10 / 本类 skip=0 / x64 恒等 / multiseed 315/315)。若倾向保守, 可先只翻正
16/17 (纯 next-begin, 无 .text 兜底), stubs 预期 9, 其余同上——请拍板。
