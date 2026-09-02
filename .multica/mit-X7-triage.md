# MIT-X7 triage 报告 — 客户态重扫（双 arch 三层口径）+ X6b 三候选面数据裁决 + x87 B 路线触发判定

- 执行: WVmpCppDev（批一·零产品代码侦察单，派活单 mitX7 §B.1）
- 静态基线: main `bf2a41d`（454 X6 合入后；基线 65 样本 325/325、x64 dump 底稿 `ffd47289`、二十二连）；本单分支 `mit-x7-rescan-x6b`（worktree 隔离，合入权在项目主——D0）
- 交付面: `scripts/verifier/mit_x7_rescan.py`（唯一扫描工具，零产品代码）+ 留样 `scripts/verifier/mit_x7_rescan_out/`（mit_x7_rescan.jsonl 112+99 文件全计数 4.9MB + mit_x7_summary.json）+ 本报告
- 采集时间: 2026-09-03 00:1x–01:0x (+0800)，全量扫描 2 次定稿（分类器 3 轮修正后重扫），run 对账 ≥ 3 小时（接单勘察 4 篇文档 + 3 轮全量扫描 + 本报告）
- 工具链: Python 3.14.6 + capstone 5.0.7（CS_MODE_32/64 双模；本绑定 `insn.detail` shim 不可用，走 `operands`/`prefix` 访问器 + disasm_lite 快速主通道——两通道交叉校验见 §5.3）
- 结论置信度: 高（白名单一致性断言 + 双通道形级交叉校验 + 递归对账 + X0 旧锚四路互证）；个别标注中者见内文

## §0 结论（裁决）

**一句话: X6b 三面按预登记阈值机械裁决 = push-imm x64 维持 gate 销案（0.028% ≪ 0.5%）、间接 jmp 维持 gate 销案（区域占比 1.79% 过门但表形仅 28 条 = 形态门失败）、Div 族 x86 实施（默认做，密度 0.033% 全语料 89/112 文件命中）；x87 B 路线触发条件不满足（x64 .pdata 函数域含 x87 函数占比 = 0%，连 d3dx9 的 x64 版都走 SSE）；x64 侧首次扫描 direct 覆盖率 99.26%，x86 重扫形级口径 95.15%——x86 战役收官数据就位。**

| 面 | 预登记阈值（D2） | 实测读数 | 判定 |
|---|---|---|---|
| push-imm x64 | 助记符占比 ≥0.5% → 实施 | **5,009 / 17,626,439 = 0.0284%**（最高层 old_runtime 0.084% 仍 6 倍低于阈值） | **维持 gate，GAPS 记数据销案** |
| 间接 jmp | 区域占比 ≥1% **且**可实施形态明确（表形/任意形分档） | 门1: x64 .pdata 函数占比 **4,294/240,277 = 1.787% ≥1% 过门**；门2: 表形（mem 带 index×8）x64 全语料仅 **28 条（0.0002%）**，主导形 = 任意 mem 14,675（84.7%）+ reg 2,628（15.2%）= L 拒做挂账 | **门2 失败 → 维持 gate，数据销案** |
| Div 族 x86 | 不依赖数据，默认做 | x86 div/idiv 8,976（0.033%），**89/112 文件命中**（79.5%）；453 b59b 实撞在案；D4 实读 x64 = 真 handler（§3.3） | **批二实施** |
| x87 B 路线（445 §6） | 客户语料 x87 区域命中率实证 | x86 密度与 X0 同构（old_runtime 7.81%）；x64 助记符 0.033% 且 **.pdata 函数域含 x87 函数 = 0 个** | **触发条件不满足，维持 R-SSE-only（A 路线）** |

## §1 三层口径表（批一主交付）

### §1.1 语料（D5：系统目录 + 436 第三方家族；X0 留样 jsonl 已随 %TEMP% 失效 → 按 X0 §1.2 口径重建，405 坐标纪律）

| 层 | x86 (SysWOW64) | x64 (System32) | 说明 |
|---|---|---|---|
| core_os（点名列） | 37 文件，7.66M clean | 37 文件，5.89M clean | X0 §1.2 点名集重建，缺位 0（名单随脚本入仓） |
| old_runtime（逐名 12） | 12 文件，5.61M clean | 11 文件，5.14M clean（msvbvm60 x64 天然缺位） | d3dx9×4 / msvcrt / mfc42 等逐名复现 |
| modern_ucrt | 7 文件，1.94M clean | 7 文件，1.33M clean | 5 逐名 + 2 同族补位 |
| random（八分位抽样） | 48 文件，4.77M clean | 48 文件，5.26M clean | 大小×mtime 八分位 ×8 格各抽 6，seed=436；**与 X0 原随机样本逐文件不同**（X0 未留样清单，重建口径披露） |
| third_party（436 家族现存子集） | 8 文件，7.43M clean | —（对称层不设） | 家族 = VMware×5 / IncrediBuild×2 / GoogleUpdater×1（PE32 机器感知选取）；**X0 家族 5/8 缺位**（PhysX/Steam/dxcompiler/hha/wab32 本机不在位）+ VMware 大 DLL 已转 x64，该层与 X0 不可逐文件对齐，如实披露 |
| 合计 | 112 文件，27.41M clean | 103 文件，17.63M clean | 机器过滤跳过计入 skipped_machine |

扫描口径: capstone 线性全扫 .text + skipdata；噪声指纹族（outsd/insb/popal/arpl/aas/daa/das/bound/les/lds/into/int3 等）剔除出分母（原始计数留样）；`.byte` 数据字节单列。

### §1.2 层①+②: direct 覆盖率（X6 后白名单，形级口径；判据 = x86_translate.cpp 逐 case + GAPS X6 收口节）

| 层 | x86 direct | x64 direct | 对照 X0（x86 侧，mnemonic 级） |
|---|---|---|---|
| core_os | 96.70% | **99.68%** | X0: 98.26%（形级修正前）/ 诚实下界带 92-94% |
| old_runtime | 89.01% | 98.67% | X0: 90.80%（x87 主导缺口，本扫同构 7.81%） |
| modern_ucrt | 95.15% | 99.48% | X0: 96.78% |
| random | 96.15% | 99.30% | X0: 94.29%（样本不同不可逐文件比） |
| third_party | 97.55% | — | X0: 98.73%（家族构成已变，披露） |
| **库域合计（core+old+ucrt+random）** | **94.26%** | **99.32%** | **X0: 95.74%**（mnemonic 级） |
| **全语料合计** | x86 **95.15%** | x64 **99.26%**（**X0 从未扫过 x64 域——本单新数据**） | — |

**口径声明（X7 与 X0 对照必读）**: X0 的 95.74% 是 **mnemonic 级**（push [mem]/call [mem] 等 shape 面记 direct、fork 单列），本单 94.26% 是**形级诚实口径**（shape 级 gate 直接扣出）——X7 数字落在 X0 自报的"诚实下界 92-94%"带内且构成已翻新: call [mem]/call reg（X3c）、ret imm16（X1b）、plain 串形/cld/leave/cwde/cbw（X2a）、S16 GP（X2a）、push imm（X6）、SSE 32 op+桥+ucomis（X6）全部入面；新精确化 gate 面 = push_mem（1.85%，X0 仅估 ~0.5%）+ div_x86（0.033%，453 起为 gate）+ sse_residual（0.13%，X6 D 精确清单）。**X1-X6 六单的净效果: 形级构成从"fork 面大量未开"变为"gate 面全部可点名"。**

### §1.3 层③: 区域级纸面 lift 通过率

- **x64（.pdata 真函数域，函数域扫描法 x64 合法——X0 §1.1）**: 240,277 函数，任一 gate 族命中 12,650（5.26%）→ **纸面无 gate 函数 = 94.74%**。分族函数占比: sse_residual 2.41%（5,793）/ indirect_jmp 1.79%（4,294）/ system_legacy 1.35%（3,236）/ push_imm 0.049%（117）/ x87 **0.000%**（0 函数）。口径披露: 纸面 = 白名单闸（lifter/translator/stub_link）；translator 栈深 walk、跳表预扫、ExitNative 上界等深门不在此口径（离线不可测，与 451 measure 工具口径衔接）。
- **x86（无 .pdata，436 §E 钉死不可平抄）**: 文件级 any-hit 代理（112 文件）——间接 jmp 92.0% 文件命中、div 79.5%、x87 95.5%、push_mem 92.9%；递归对账 5 文件（X0 §1.1 纪律，4 文件触 150k 上限截断如实披露）: msvcrt reachable 150k 中 x87 878（0.59%）/ div 238 / sse_res 574；ucrtbase seg_override 534。**"函数级虚拟化率"严格口径 x86 侧离线不可得（A.2 已论证），本表仅文件级+递归对账双代理。**

## §2 gate 族命中分布（双 arch；分母 = clean 指令）

### x86（合计 27,413,848 clean，gate 831,561 = 3.03%）

| 族 | 条数 | 占比 | 文件 any-hit | 备注 |
|---|---|---|---|---|
| x87 | 529,718 | 1.933% | 95.5% | old_runtime 层 7.81%（d3dx9×4 = 437k 条）——与 X0 同构复现 |
| push_mem（`push [mem]`，translate_push Mem skip 残面） | 505,828 | 1.845% | 92.9% | **X0 估 ~0.5% → X7 实测 1.85%**（core_os IAT/栈窗惯用面重）；X6b 范围外，GAPS 记数据行 |
| system_legacy（int/in/out/std/lahf/retf/lcall/ud2/fence/…） | 131,797 | 0.481% | 98.2% | 段覆盖另计（seg_override 含在此族计数内，fs/gs 分列留样） |
| other_missing（clc/rcl/rcr/sal/stc/cmc/3DNow/salc/xlatb/bsr/adcx/adox/mulx…） | 71,774 | 0.262% | 97.3% | `sal` = capstone 别名（产品仅 case SHL → gate 如实）；3DNow = 数据噪声级 |
| indirect_jmp（jmp reg/mem） | 40,762 | 0.149% | 92.0% | X6b 面②，§3.2 |
| sse_residual（cvt/sqrt/maxmin/unpck/shuf/pcmpeq/punpck/psll/…） | 35,913 | 0.131% | 90.2% | X6 D 裁决残余清单精确化 |
| div_x86（div/idiv，runtime handler 缺） | 8,976 | 0.033% | 79.5% | X6b 面③ → 批二实施 |
| bt（bt 本体，产品无 case） | 3,122 | 0.011% | 43.8% | bts/btr/btc 已随 X5b B.4 翻正 direct（bitreg_form 23,993 条 informational） |
| shld_shrd（挂账观察清单） | 3,116 | 0.011% | 52.7% | X3c 挂账维持 |
| string_s16（S16 串形砍面） | 711 | 0.003% | 63.4% | G3 维持 |

### x64（合计 17,626,439 clean，gate 137,024 = 0.78%）

| 族 | 条数 | 占比 | 函数 any-hit | 备注 |
|---|---|---|---|---|
| sse_residual | 45,395 | 0.258% | 2.41% | cvt/sqrt/maxmin/shuf 面无 ir 载体（X6 D） |
| system_legacy | 29,025 | 0.165% | 1.35% | |
| other_missing | 20,020 | 0.114% | — | ud2/clc/adcx/adox/mulx（G8b 挂账）/bsr/retf… |
| indirect_jmp | 17,331 | 0.098% | **1.79%** | X6b 面②，§3.2 |
| bt | 12,881 | 0.073% | — | bitreg 翻正面外本体 |
| x87 | 5,815 | 0.033% | **0.000%**（0 函数） | 命中全在 .pdata 函数域外 = 数据噪声（连 d3dx9 x64 版 x87 仅 696-1,006 条/文件且 0 函数） |
| **push_imm_x64** | **5,009** | **0.028%** | 0.049%（117 函数） | X6b 面①，§3.1 |
| push_mem | 580 | 0.003% | — | x64 侧极薄 |
| string_s16 / shld_shrd | 122 / 5 | ~0 | — | |

## §3 X6b 三候选面裁决数据（预登记阈值机械执行，D1/D2）

### §3.1 push-imm x64 → **维持 gate，销案**

- 读数: 5,009 / 17,626,439 = **0.0284%**（core_os 32 / old_runtime 4,339 / ucrt 11 / random 627）。阈值 0.5% 的 **17.6 倍余量**才触发；最高单层 old_runtime 0.084% 仍差 6 倍。
- 编码形态（实施面观察，随销案一并入档）: push_imm8_sext（6A）791 / push_imm32（68）3,314——x64 侧 68 形主导，6A imm8 sext 形少量；453 MASM `push 0FFFFFFFFh` = 6A FF 先例与本扫一致。
- 处置: translator :1611 `push 操作数形态未支持` skip 维持；GAPS X7 节数据行入册。**销案 = 满分结论（D2 显式句）。**

### §3.2 间接 jmp → **维持 gate，销案（门1 过、门2 败）**

- 门1（区域占比 ≥1%）: x64 .pdata 函数域 **4,294 / 240,277 = 1.787%**（core_os 1.77% / old 1.87% / ucrt 3.34% / random 1.34%）——过门。x86 文件级代理 92.0% 文件命中（占比 0.149% 条数级）。
- 门2（可实施形态明确）: **失败**。x64 全语料形态分档 = 表形（mem 带 index×8，413 匹配器可复用形）**28 条（0.0002%）**、任意 mem 形 14,675（84.7%）、reg 形 2,628（15.2%）。主导形态 = 任意 mem/reg（call 表分发 D6 边界，442 立）= L 级拒做挂账；可静态表化形在真实语料近乎不存在（wvmpTest aebb 实撞 1 例属任意 mem 形）。
- 处置: translator :1652 skip 维持；跳表匹配器（413/X5b S32）现网已覆盖 REG/MEM-abs/REG-delta 三正形，本面维持"表形已收、任意形 gate"现状；GAPS X7 节数据行入册。

### §3.3 Div 族 x86 → **批二实施（默认做，数据支持充分）**

- 密度: x86 div/idiv 8,976 条（0.033%），**89/112 文件（79.5%）含 div 族指令**——453 b59b 实撞（VmOp::Div/Idiv 78/79 折叠 Halt → x86 白名单闸整函数 gate）非孤例；对照 x64 侧 div 直通 5,462 条（0.031%），密度同量级（双 arch 对称需求成立）。
- D4 语义基准实读（先测再写，434 #33 教训）: x64 Div/Idiv = **真 handler** `build_div_idiv`（asmgen.cpp:2349-2411）：除数→T0 → 物理 RDX:RAX ← 双槽 → native `div/idiv` 直通 → 商/余双槽写回 → setcc5 捕 native flags 真值（Intel undefined 处置照抄 build_imul 同序）；**除零/商溢出 = 真 #DE，崩溃形态与未加壳一致，不做 VM 内拦截（D2.1 显式注释）**；S8/S16 defensive no-op。
- 实施口径（批二）: x86 镜像 x64，不造第三套语义——native 32 位 `div/idiv t0`（dividend edx:eax = S32 主形）、商 eax/余 edx 双槽写回、#DE 真异常直通、setcc5_x86 落帧 + flags_tail_x86 装配；kVmOpMax=97 不动（VmOp::Div/Idiv 既有 op，D3 冻结面）；解禁面 = asmgen（限 x86 Div/Idiv handler 新建）。

## §4 x87 B 路线触发判定读数（445 §6 呼应）

| 读数 | x86 | x64 |
|---|---|---|
| 助记符密度（分层） | core_os 0.115% / **old_runtime 7.809%** / ucrt 1.005% / random 0.968% / third_party 0.231% | core_os 0.002% / old_runtime 0.070% / ucrt 0.004% / random 0.038%（合计 0.033%） |
| 区域级"含 x87 函数占比" | 严格口径不可得（无 .pdata）；递归对账: msvcrt 0.59% reachable、d3dx9 密度带 7-13% 与 X0 同构 | **0.000%（240,277 函数中 0 个含 x87）** |
| 与 X0 对照 | 同构复现（X0: 0.12/6.76/0.92 层密度带；本扫 0.115/7.809/1.005）——老运行时层 x87 密度未衰减 | 全新数据: x64 侧 x87 ≈ 0 且函数域零命中（**d3dx9 x64 版内部已 SSE 化，x87 命中全是 .pdata 外数据噪声**） |

**判定: B 路线（x87 L0，~80 op + 跳表扩容）触发条件不满足**——x86 侧密度与 X0 时点同构（无新增触发证据），x64 侧函数级读数为零。维持 R-SSE-only（A 路线，X3c 定稿）+ x87 整函数 gate byte-identical 兜底。GAPS x87 节追加本读数（append-only）。

## §5 方法学披露与 #33 对账

1. **锚重钉**: translator.cpp :1611（push 兜底 skip）/:1652（间接 jmp skip）/:1665（"间接 jmp / ret 目标不入此路"注）/:3144 邻域（间接 jmp 不入栈深 gate 双 note 注）——**全部与派活单 A.1 一致，零漂移**（@bf2a41d）。
2. **A.2 "X0 从未扫 x64" 与留样有效性**: %TEMP%\mit436_x0\ 已不存在（实测）→ 语料按 X0 §1.2 分层口径重建；core_os/old_runtime/modern_ucrt 三层点名集可复现（名单入仓），random 层与 X0 逐文件不同（seed 口径重建、披露），third_party 家族 5/8 缺位（披露）。**mnemonic 新旧对照数字的层间可比性以点名三层为准。**
3. **扫描脚本 ↔ 产品 lifter 规则一致性断言（§E）**: (a) 脚本启动解析 x86_translate.cpp 全部 `case X86_INS_*`（208 id），断言脚本 direct 151 助记符 ⊆ 产品 case 集（不等即 Fatal——漂移即误报数据）；(b) 形级双通道交叉校验: disasm_lite+op_str 主通道 vs capstone detail+operands 通道在 System32/SysWOW kernel32 双文件全量对账（8,064 shape 项 + 39,641 shape 项，零 diff 通过）；(c) 产品有而脚本未直接分类 10 id（DIV/IDIV/MOVSXD/CQO/MOVSW…全部为 arch 分叉面或 STRING_S16 gate 面，逐一在 classify() 点名处置，无遗漏）。
4. **known compromise 兑现（§F）**: (1) 函数级虚拟化率严格口径不可得 → 三层替代口径 + x64 .pdata 函数域实证锚，§1.3 口径声明；(2) x64 语料同源镜像偏置 → System32 对称分层 + 文件清单全量入留样供对账；(3) 间接 jmp 可表化判定 = 启发式 → 阈值+形态双门拦截（门1 过、门2 28 条 ≈ 0，判定不受启发式误差影响——即便表形判据放大 100 倍仍不足门）。
5. **新发现**: push_mem x86 残面 1.845%（X0 估 0.5%）是 x86 第一大非 x87 shape gate——不在 X6b 范围（D2 未含），GAPS 记数据行供后续派单裁量。
6. **批二/批三联动预告**: 批二 = Div/Idiv x86 handler（§3.3 口径）+ 电池 + 样本 + multiseed；预期 wvmpTest x86 残面 3→2（b59b 翻正，stubs 11→12）。批三 = 六件套 + GAPS X7 收口节（三面数据行 + x87 读数入册）+ STATUS 里程碑 + X0 对照注记。

## §6 留样与复跑

- 脚本: `scripts/verifier/mit_x7_rescan.py`（--quick 冒烟档 / 全量约 4 分钟）
- 留样: `scripts/verifier/mit_x7_rescan_out/mit_x7_rescan.jsonl`（211 文件记录: 全 mnemonic 计数 + families/shapes/segments + x64 逐文件 .pdata 函数归因）+ `mit_x7_summary.json`（层汇总 + 断言输出 + 披露清单）
- 复跑: `python scripts/verifier/mit_x7_rescan.py`（只读扫描，产物仅写仓库留样目录；项目主抽查 ≥2 族归因建议从 jsonl `shapes`/`gate_hits` 字段入手——push_imm 5,009 与 indirect_jmp 4,294 两族均已函数级钉死）

== MIT-X7 triage 完 ==
