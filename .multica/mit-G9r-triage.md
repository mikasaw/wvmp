# MIT-G9r triage 报告 — SIMD 尾族频率 + G8-BMI 载体成本 + 跳表扩容前置量化 (侦察三合一)

- verifier: WVmpVerifier (裁定型 / 纯侦察零代码单, 零产品代码改动; spike 按 D4 走隔离 worktree, 已拆除)
- 静态基线: main `0ac661a` (MIT-428, multiseed 230/230, kVmOpMax=97 @ vm/regvm/isa/include/wvmp/regvm/isa/vm_op.hpp:582)
- 实验环境: `%TEMP%\mit432_g9r\` (4+14 语料扫描 jsonl、6 个 intrinsic 列表 /FAcs、BMI MASM flags probe ×2 轮、E2E 样本 ×2、256-entry spike worktree 及其全量 build) — **主仓 tracked 零改动, 未切分支前 main 在 0ac661a 零脏**
- 本机: AMD Ryzen 7 9800X3D (Zen 5), cpuid leaf7 EBX=0xF1BF97A9 → **BMI1=1 BMI2=1 AVX2=1** (pdep/pext 原生 probe 有效, §F.2 退化未触发)
- 采集时间: 2026-08-31 11:17–12:5x (+0800), 全部数字来自实测输出; run 对账 ≈ 100 分钟 ≥ 30 分钟红线
- 结论置信度: **高** (capstone .pdata 域扫描 + cl /FAcs 列表 + MASM 原生 flags probe + E2E 全链 protect/run/cmp + spike 全量回归, 五路互证); 个别标注中者见内文
- 留样: %TEMP% 会被清理 → 关键源码/命令/diff 内嵌本报告 §1.3/§2.5/§3.2; spike diff 单行见 §3.2
- 方法声明: 424 数字二次引用处均标注"引用 424"; 本 run 重扫的数字全部为自测 (与 424 重叠项逐一对账, 全部吻合, 见 §1.1 表注)

## §0 结论 (裁定)

**三路全部实测完毕, 无一路跳过 (D1 兑现)。** 一句话结论: **路1 三族 = 分层 gate (lqdq/hqdq 一个小折条例外); 路2 BMI = 拆 G8a/G8b 两档, 但 flags 语义比派单预判复杂 (两个预判被实测修正, 一个 P1 新发现); 路3 扩容 = S 级实锤, 不必独立立单, 建议作为首个溢出批次的前置 commit。**

| 路 | 核心数字 | 裁决 |
|---|---|---|
| 路1 SIMD 尾族 | 三族在 424 阳性语料真实高频 (punpck 1180/572/538, pmovmskb 288/177/129, pcmpeq/gt 318/206/180); **14 个新抽客户 exe 全零**; 编译器 /Od+/O2 直出三族, `_mm_set_epi64x` /Od 溢出产 punpckldq (428 残留机制源级证实) | **文档化 gate 分层维持**; punpcklqdq/punpckhqdq (q 粒度) 单列低成本折条候选, lbw/lwd 永久性 gate 证据充足 |
| 路2 G8-BMI | rorx/mulx/andn 高频已证 (424 数字全复现; BioIso mulx 898 条 97% mem 形); blsr/blsi/blsmsk **语料=0**; flags 实测: rorx/shlx/sarx/shrx/pdep/pext 全保留基线 ✓, **mulx 在 Zen5 上连 CF 都不写 (与 SDM 分叉)**; 现网 E2E 6 区域 C1 gate 零逃逸 + 正例 stub=1 | **拆两档**: G8a (andn/bzhi 零新 VmOp 折条 + rorx/shlx/sarx/shrx 需 flagless 变体, M) / G8b (mulx/pdep/pext native 直执行 + CPUID gate, L, 后置) |
| 路3 跳表扩容 | spike (128→256 单行改) → build 408/408, ctest **16/16**, multiseed **230/230** (REQUIRE_REAL); 码体 +1032B/壳 (含 dispatch imm 加宽 +8B), PE 文件 +1024B, handler 布局整体平移、entry=+0x0 不变 | **成本 S 级实锤**; 不建议独立立波——触发条件出现时作为前置 commit 随单落地 |

**🔴 P1 新发现 (先于一切排波结论): 现 main 0ac661a 存在 rol/ror 的 ZF/SF/PF 语义分叉, E2E 逐字节比对可复现 FAIL** — `ror` 后读 ZF, 保护后行为与原生不一致 (`scripts/e2e.sh` 实测 "stdout 不一致": native `ror_zdiv=0` vs 保护后 `ror_zdiv=1`)。这是**现网既有缺口** (非本波引入; 230/230 样本集未覆盖 "rotate 后消费 ZF/SF/PF" 形态), 机制/SDM/原生 probe/E2E 四路证据齐 (§6.1)。**它直接命中路2 命门**: rorx 折叠若照搬 translate_shift 将继承同款分叉; 且 rol/ror 自身必须先修。建议把 "flags partial-preserve 修复" 作为 G8a 的硬前置或并入其第一张单。

## §1 路1 (B.1): SIMD 尾族频率实测

### §1.1 语料计数 (方法 = 424 同款: .pdata 函数域 capstone 全扫, 分母 = 域内总指令数)

424 的 %TEMP% 留样已被清理 → 按派单 D2 "重跑其扫法脚本化计数" 执行 (未重跑 4354 预扫): 重写 .pdata 域扫描脚本 (capstone 5.0.7 / Python 3.14, 与 424 vendored 同核), 对 424 报告点名的 13 个阳性二进制**重测** + 14 个 424 阳性集外的新客户 exe **新扫**。与 424 数字重叠项逐一对账: ClipUp rorx **288=288** ✓、smartscreen rorx **1088=1088** ✓、BioIso mulx **898=898** ✓、ntdll shlx+pdep **42=28+14** ✓、ucrtbase shlx **30(d-indep)=30** ✓ (424 计的是真三地址形; 全形 41, 差异已在表注披露)。**引用 424 的其余数字 (VEX 密度等) 未重扫, 沿用。**

**A 组: 424 阳性重测** (格式: 总指令 | 三族计数 (legacy+VEX)):

| 二进制 | 总指令 | pmovmskb | pcmpeq/pcmpgt | punpck | BMI (细分) |
|---|---|---|---|---|---|
| smartscreen.dll | 773,116 | 37 (20v) | 180 (37v) | **572** (287v) | 1480 (rorx 1088 / mulx 224 / andn 168) |
| ThreatAssessment.dll | 695,529 | 23 (1v) | 161 (32v) | **538** (286v) | 1440 (rorx 1088 / mulx 184 / andn 168) |
| ucrtbase.dll | 236,672 | **129** (56v) | 139 (59v) | 9 (1v) | 62 (shlx 41 / andn 15 / shrx 6) |
| onnxruntime.dll | 1,925,024 | **288** (1v) | 318 (19v) | **1180** (669v) | 0 |
| amdhip64_6.dll | 2,074,178 | **177** (10v) | 206 (10v) | 209 (4v) | 4 (shlx) |
| ntdll.dll | 360,112 | 14 (1v) | 20 (1v) | 29 | 42 (shlx 28 / pdep 14) |
| WindowsCodecs.dll | 397,388 | 2 (1v) | 74 (23v) | **330** | 0 |
| python314.dll | 820,181 | 6 (1v) | 9 (2v) | 43 (8v) | 38 (shrx 18 / shlx 12 / bzhi 8) |
| vcruntime140.dll | 29,856 | 7 (1v) | 13 (1v) | 1 | 0 |
| msvcrt.dll | 128,935 | 14 (1v) | 20 (1v) | 0 | 0 |
| ClipUp.exe | 127,410 | 0 | 1 | 42 | **336** (rorx 288 / andn 48) |
| AsusUpdateCheck.exe | 75,738 | 12 | 18 | 3 (1v) | 0 |
| BioIso.exe | 120,202 | 0 | 6 | 6 | **898 (mulx 全部)** |

**B 组: 客户态 exe 新抽 14 个 (424 49 阳性集之外, System32 同源)**: AgentService / AppVClient / ByteCodeGenerator / CiTool / CompPkgSrv / BdeUISrv / CloudNotifications / AuthHost / CameraSettingsUIHost / CastSrv / CertEnrollCtrl / CheckNetIsolation / BitLockerWizard / ClipDLS — **三族计数全零 ×14** (对照组 movaps/movups/movdqa 照常出现, 扫描方法有效)。合计 1 组 + B 组共 27 文件, 满足派单 "≥10 新面" 且超额。

**判读 (424 分层结论的延续, §F.1 预判命中)**: 三族 = "经典 exe 全零 + hash/安全/编解码/ML/CRT 高频" 的分层分布。密度量级: punpck 在 SIMD 域 0.06–0.074% (onnxruntime 1180/1.93M, smartscreen 572/773k), pmovmskb 在 CRT/ML 域 0.015–0.055% (ucrtbase 129/237k — **ucrtbase 的 pcmpeqw 49 条即宽字符串函数指纹, 静态链 CRT 的客户 exe 会在标记区域外执行它们**)。

### §1.2 punpck 粒度细分 (裁决 q 粒度预判的关键表)

| 二进制 | d/q 粒度 (ldq/lqdq/hdq/hqdq) | b/w 粒度 (lbw/lwd/hbw/hwd) | 主粒度 |
|---|---|---|---|
| smartscreen.dll | 460 | 64 | **d/q 88%** |
| ThreatAssessment.dll | 458 | 32 | **d/q 93%** |
| ClipUp.exe | 42 | 0 | **d/q 100%** |
| onnxruntime.dll | 563 | 583 | **对半** |
| WindowsCodecs.dll | 98 | 263 | **b/w 73%** |
| amdhip64_6.dll | 90 | 132 | b/w 偏多 |

**判读**: 派单 A.2 预判 "q 粒度交织本质是 8B 搬运重组" 在 hash/安全二进制成立, 但在 codec/ML 语料 **b/w 粒度同量级或占优** — "punpck 全族按 q 粒度折条" 会漏掉一半真实形态。裁决必须按粒度分裂 (见 §1.4)。

### §1.3 探针矩阵 (cl v14.51.36256, /FAcs 列表 = TU 本体 ground truth, 默认 /arch:SSE2)

| 探针 | /Od | /O2 | 关键实测行 |
|---|---|---|---|
| probe_pmovmskb (`_mm_movemask_epi8` 循环) | pmovmskb ×1 + **punpckldq/lqdq ×3** | pmovmskb ×1 | /Od 下 `_mm_set_epi32` 常量装配溢出产 punpck — **428 cpp_movdqa_neg "intrinsic 溢出也会产 punpck" 机制源级证实** |
| probe_pcmpeq (`_mm_cmpeq_epi8/32`+`_mm_cmpgt_epi32`) | pcmpeqd/pcmpeqb/pcmpgtd **mem 形** ×3 + punpckldq ×4 | pcmpeqb/pcmpeqd/pcmpgtd reg 形 ×3 | /Od 走 mem 形 (408 通路形态) / /O2 走 reg 形 — 折条两形态都要收 |
| probe_punpck (显式 unpack intrinsics + set_epi64x) | punpcklqdq/punpckhdq/punpckldq | 同左 (×3) | 显式 `_mm_unpacklo_epi64` 在两档都直出, 无优化档位依赖 |

复现: 源码三文件 (probe_pmovmskb/probe_pcmpeq/probe_punpck, `_mm_set_epi32`/`_mm_set_epi64x` 装配 + 循环消费) + `cl /c /Od|/O2 /FAcs` → 数 .asm 列表目标 mnemonic。

### §1.4 裁决矩阵 (三行)

| 族 | 频率档 | 折叠成本档 | 建议 |
|---|---|---|---|
| pmovmskb | 中频集中 (CRT/ML/哈希域; 经典 exe 零) | **桥近亲**: native 直执行 handler 1 个新 VmOp (SSE2 指令, 宿主必有; 419 xadd/425 Andnps 模板) — 或 GP 域 16-lane 循环 (爆面, 否决) | **文档化 gate 留档**, 随 G1 下一波按频率评估; 不紧急 (真实客户标记区域内命中率为零的语料面) |
| pcmpeq/pcmpgt 系 | 中频集中 (同上; 编译器 /Od mem 形 + /O2 reg 形都直出) | **新 VmOp 群 ~8** (4 宽 × eq/gt; native lane-compare handler, 425 模板) 或按宽度渐进 (eqd/eqw 先行 — ucrtbase 指纹) | **文档化 gate 留档 + 观察清单**: 客户产物出现 SIMD 比较热点时按 G1b 模式小批开 |
| punpck 系 | SIMD 域高频 (最高族), 但**粒度分裂** | **q 粒度 (lqdq/hqdq) = 低成本折条候选**: {dst.lo 保持, dst.hi←src.lo} = 8B 半宽重组 — XmmStore(8B)+XmmStore(8B)+XmmLoad(16B) 经 scratch 三连 (既有 408 通路, 零新 VmOp; 设计点 = lifter 需 16B scratch 栈槽) — **预判 "零新 op 折条" 基本成立但非零成本**。**b/w 粒度 = lane 爆面, gate** | **分裂裁决**: lqdq/hqdq 若下一 G1 波顺路可折 (S); lbw/lwd 文档化永久 gate (频率 + 8-lane 语义成本双否) |

## §2 路2 (B.2): G8-BMI 载体设计成本

### §2.1 flags 语义钉死 (D3: SDM 逐条 + native probe 双验)

probe 方法: MASM 每指令 `xor eax,eax` (ZF=1,PF=1) + `stc` (CF=1) 基线 → 执行目标指令 → pushfq 读回; **对照组 ror 用 LSB=0 输入实测 CF 0→写入**, 证明 probe 能区分"写/不写" (方法自证)。CPU = 9800X3D (Zen 5), BMI1/2 在位。

| 指令 | SDM 语义 (Vol.2A 条目, 页码随版本浮动) | 本机 probe (Zen 5) | 与既有 Op 的映射冲突 |
|---|---|---|---|
| rorx r,r,imm8 | **不写任何 flags** (unaffected) | 全保留 (raw=基线 0x247) ✓ | Op::Ror 走 build_shift **写全量 flags** → 冲突 |
| shlx/sarx/shrx r,r,r | **不写任何 flags** | 全保留 ✓ ×3 | Op::Shl/Sar/Shr 写全量 → 冲突 |
| pdep/pext r,r,r | **不写任何 flags** | 全保留 ✓ ×2 | 无既有 op (微程序或 native 直执行) |
| andn r,r,r | CF=0, OF=0, ZF/SF/PF 按结果, AF undef | CF 清零 + ZF 按结果 ✓ | **Op::Not(无 flags)+Op::And(AND 语义) 双折天然一致** (AND 的 CF=0/OF=0/ZF/SF/PF = andn 全集) |
| bzhi r,r,r | CF=0, OF=0, ZF 按结果, SF=dst[msb], PF/AF undef | CF=0, ZF 按结果 ✓ | **Op::Mov+Shl+Sub+And 尾行 And flags = bzhi 全集** (中间行 flags 被尾行覆盖) |
| blsr r,r | CF=(src==0), ZF=(dst==0), SF=dst[msb], OF=0 | src=0→CF=1; 0x10→CF=0,ZF=1; 0x17→CF=0,ZF=0 ✓ | 折条尾行无法同时命中 CF=(src==0) 与 AND 的 CF=0 → **CF 边缘分叉** (src==0 形态) |
| **mulx** | **CF 按 MUL 定义写**, 其余 undefined | **4/4 对照全保留基线 — Zen 5 实测连 CF 都不写** (hi=0xFFFFFFFE 非零仍 CF=1) | **厂商分叉**: Intel 按 SDM 写 CF / AMD 观测不写 → VM 无论选哪种语义都与一 家 native 不一致, 必须披露择一 |

置信度注: mulx 行为为**本机实测事实** (高); "Intel 侧写 CF" 为 SDM 文本记忆 (中), G8b 实施前应查当前版 SDM 复核; rorx/shlx 族 "unaffected" 为架构定义 (高), 且 AMD 实测吻合。

**核心判定① (推翻派单 A.3 预判的一半)**: "rorx/shlx/sarx/shrx/blsr 预判零新 VmOp 折条可行" — **值语义成立, flags 语义不成立**。现 VM flags 模型是 eager 的 (asmgen.cpp:542-556 `flags_tail` 每个 ALU handler 把 CF/OF/ZF/SF/PF 全量写回 ctx+0x98), 而 native 侧这五条是 "flags 不受影响" 的架构语义。照搬既有 Op 会让 "后续 Jcc 读 flags" 的 guest 代码行为分叉。可行出路二选一: (a) **flagless 变体 VmOp** (载体域 22.. 标记, 同 handler 跳过 flags 尾部 — 实现面小, 估 +4 op 或 1 个标记域); (b) 惰性 flags/liveness 分析 (大工程, 不建议)。**andn/bzhi 不受此影响** (它们的尾行 flags 语义与 native 一致, 逐位对齐见上表)。

**核心判定② (mulx 厂商分叉)**: E2E 逐字节不变的验收跑在本机 (AMD) → 若 VM 选 "CF 按 SDM 写", 本机 native-vs-VM 分叉; 若选 "保留", Intel 客户机分叉。侦察期只能钉死事实, 择一决策留给实施单 (建议: 与 rol/ror 修复 (§6.1) 一起做 "flags partial-preserve" 机制, mulx 按保留语义, 披露 Intel 偏差)。

### §2.2 三地址形态分布 (折叠成本第二判决数, 本 run 重扫实测)

| 二进制 | 3reg 形态 | dst==src1 | dst==src2 | dst 独立 | reg-mem |
|---|---|---|---|---|---|
| smartscreen.dll | 1480 | 0% | 0.4% | **91%** (1346) | 8.7% (128) |
| ThreatAssessment.dll | 1440 | 0% | 0.4% | **91%** (1306) | 8.9% (128) |
| BioIso.exe (mulx) | 24 | — | — | 24 | **97% (874)** |
| ntdll.dll | 42 | 0 | 52% (22) | 45% (19) | 1 |
| python314.dll | 38 | 42% (16) | 11% | 37% | 11% |
| ClipUp.exe (rorx) | 336 | 0 | 0 | **100%** | 0 |

**判读**: 与 424 VEX.128 的 §2.3 (dst 独立 26–70%) 相比, BMI 的 dst 独立占比更高 (91–100%) → 426 三地址折叠器 "dst 独立 → 前置 Mov" 路径是**主路径而非边角**; mulx 的 mem 源形态 (BioIso 97%) 决定 G8b 必须收 mem 形 (408 通路复用)。

### §2.3 载体域对账 (源码亲验)

src2=imm 标记域现役: string **0..4** / lock **5..13** / SSE mul **14..17** / andn **18** / bridge **19..21** (x86_translate.cpp:1358-1360, :1378 enum) → **下一可用自 22 起** ✓ 派单 A.3 数字精确。G8a 若走 "(Op::Shl/Ror, src2=imm(22..)=kFlagless)" 方案, 每个宽度/指令一个标记, 域空间充足 (imm14 上限 16384)。

### §2.4 E2E 三态 (全链真跑, seed 12345, main 现 cli)

MASM 直写 7 个标记区域 (链接 build/sdk/wvmp_sdk.lib):

| 区域 | 指令 | 预期 | 实测 |
|---|---|---|---|
| bmi_rorx / bmi_mulx / bmi_andn / bmi_shlx / bmi_pdep_pext / bmi_bzhi_blsr | rorx/mulx/andn/shlx/pdep+pext/bzhi+blsr | gate | ✅ 逐条 "未支持指令 'vXXX'，已跳过" → 6 函数 C1 gate 整函数保持原生 |
| ctl_ror (正例对照) | mov/ror/mov | 真虚拟化 | ✅ stub 唯一来源 |
| **合计** | | | **"已生成 1 个入口 stub，.wvmp 节 28403 字节"** — BMI 区域零 stub, 零逃逸; 保护后 stdout 与 native 逐字节一致, rc=0=0 |

复现源码内嵌: bmi_sample.asm 每函数 `push rbx/rdi; sub rsp,28h; mov rbx,rcx; mov edi,edx; call marker_begin; <BMI 指令, ml64 v145 直收助记符>; 存结果 [rbx]; call marker_end`; main.cpp 打印 7 行结果; `ml64 /c + cl /c /Od + cl link wvmp_sdk.lib` → `scripts/e2e.sh`。

### §2.5 拆单蓝图

**G8a — BMI 折条款目 (M, ≈2–3 天)**: ① andn = Op::Not+Op::And 折条 (零新 VmOp, flags 天然一致; 425 Andnps 整数版先例) + dst==s2 形态需 scratch (C4b v18..v23 双槽先例); ② bzhi = Mov+Shl+Sub+And 折条 (零新 VmOp; 尾行 And flags 全对齐); ③ rorx/shlx/sarx/shrx = flagless 变体 (载体域 22.., handler 跳过 flags 尾部 — **前置: §6.1 rol/ror partial-preserve 修复同机制**); ④ blsr = 折条 + CF 边缘分叉披露, 或并入 ③ flagless native 直执行; ⑤ 验收门: A.1 静态扫描 + A.2 multiseed 影子样本 (BMI 影子×1: rorx/andn/shlx 读回) + A.3 handler dump 校验集合扩展。**前置: §6.1 P1 修复**。
**G8b — mulx/pdep/pext native 直执行档 (L, 后置)**: 3 个新 VmOp native 直执行 handler (BMI2 指令, 宿主 CPUID gate + 不支持机器降级 C1 gate — 424 档B B-3 同款基建); mulx flags 择一披露 (§2.1 判定②); mem 形复用 408。依赖: G8a 的 flagless 机制 + CPUID gate 基建。
**频率侧输入**: rorx/mulx/andn 高频已证 (§2.2), pdep/低频 (ntdll 14), bzhi 低频 (python314 8), **blsr/blsi/blsmsk 语料 = 0** — blsr 建议文档化 gate 即可, 不入 G8a。

## §3 路3 (B.3): 跳表 128→256 扩容前置量化

### §3.1 机制直读 (源码亲验)

- `constexpr u64 kTableEntries = 128;` (asmgen.cpp:194) — **唯一常数点**; dispatch 掩码自动派生 `imm(kTableEntries - 1)` (:449), 表项循环与 reserve 派生 (:3445/:3453/:3469), `static_assert(isa::kVmOpMax < kTableEntries)` (:195)。
- 全仓 grep `0x7F/0x7f`: **代码零硬编码** (仅注释); A.3 dump 校验脚本从 dump 文本解析 table 偏移, 无 128 常数。
- 文档联动点: asmgen.cpp:14 注释 ("=0x7F") 与 vm_op.hpp:8-13 注释 (128 项叙述) 需随实施同步。

### §3.2 spike (D4: 隔离 worktree, 已拆除, 主仓零扰动)

```
--- a/vm/regvm/runtime/src/asmgen.cpp
+++ b/vm/regvm/runtime/src/asmgen.cpp
@@ -194 +194 @@
-constexpr u64 kTableEntries = 128;
+constexpr u64 kTableEntries = 256;
```
`git worktree add --detach <tmp>/spike 0ac661a` → 上述单行改 → `scripts\build.bat` (deps-cache 只读挂接 -DWVMP_DEPS_CACHE, 408/408 targets) → `scripts\test.bat` → **16/16 Passed (44.41s)** → `REQUIRE_REAL=1 multiseed_e2e_real.sh` → **230/230, 0 fail**。

### §3.3 四冲击面逐项量化

1. **码体/壳**: runtime blob total 0x6D30→0x7138 (**+1032B**: 表 +1024 + dispatch 掩码立即数 0x7F→0xFF 编码加宽 +8); .wvmp 节 28403→29443 (**+1040** 含节对齐垫); PE 文件 172,544→173,568 (**+1024**, raw 对齐吸收)。pe_writer 无需改动 (节尺寸自 blob 派生, build+回归实证)。
2. **build_dispatch 掩码/断言回归**: 掩码自动派生零手改; static_assert 原样通过; 16/16 全绿 = 回归面干净。
3. **三债务共享触发点精确化**: 现役 **98/128 项** (Halt 哨兵 0 + op id 1..97), 余量 **30**。x87 L0 ~80 op (引用 416 估) → 98+80=**178 > 128 溢出** = 唯一必然触发者 (424 §4 B-2 指认证实); ymm 档B 群 20–30 (引用 424) → 98+30=128 **恰好临界** (kVmOpMax=127 < 128, 零余量, 实质也是触发者); BMI 若走 G8a flagless +4 / G8b +3 → ≤102 **不触发**。
4. **stub 侧无感 (423 后宿主布局) 实测钉**: runtime 表在码尾、vm_entry=+0x0 两版一致 (dump 首行 entry=+0x0/0x0), stub E9 rel32 目标 RVA 不变; handler 偏移整体 +8 平移 (掩码立即数加宽), 表内条目结构不变; **A.3 dump_handler_xmm_check.py 对 256 dump + 保护后 PE 重跑 PASS** (25 个 SSE handler 逐个校验通过) — 验证工具链无 128 假设。

### §3.4 成本卡

**S 级** (实测: 单行常量 + 两处注释同步 + 全量回归 ~15 分钟机器时)。**触发阈值建议**: "任何使 kVmOpMax+1 ≥ 128 的 op 批次, 其实施单必须内置扩容前置 commit (先行合入、独立可回滚), 不单独立波" — x87 L0 是当前已知唯一必然触发者; ymm 若 >30 op 同触发; 若阶段收官波次全部落为文档化 gate (§1.4/§2.5), 扩容单**无限期挂起** (观察清单: x87 L0 / ymm 立项即触发)。

## §4 路线裁决 (B.4): G 线收官波次排序建议

**建议排序**: ① **§6.1 P1 修复单** (rol/ror + flags partial-preserve 机制, M 中偏 S) → ② **G8a** (andn/bzhi 折条 + rorx/shlx/sarx/shrx flagless, M) → ③ G8b (mulx/pdep/pext native 直执行, L, 随 CPUID gate 基建排) ∥ 路1 全族维持文档化 gate (lqdq/hqdq 可作 ② 内顺路项或独立 S 单) → ④ 跳表扩容 = ①..③ 期间任一批次 op 计数触界时的前置 commit (S, 不独立)。若项目主只要收官: **①+② 完成后指令虚拟化阶段即可收官** (三族 gate 文档化 + BMI G8a 覆盖高频形态), ③④ 均可挂观察清单延后。

**反方陈述 (派单 §D.3 要求, "全部文档化 gate 即刻收官" 侧)**:
- 现状零逃逸、不产坏壳 (§2.4 E2E + 424 §3 全谱 gate 实证), "不保护" 的底线安全与 x87 418 收口前同构 — 立即收官的成本 = 0。
- 高频证据 (rorx 1088+288、mulx 898) 全部来自 **OS 安全组件与厂商 exe 的库域**, 客户态 exe 新抽 14 个全零 — "客户标记区域内出现 BMI/尾族" 目前是**假想需求**, 无实证客户痛点。
- G8a 的真实价值上限 = 覆盖 "客户用 /arch:AVX2 或手写 BMI intrinsic 且热点落在标记区域" 的假想客户; 为假想需求投 M+L 两档, 违背 "先完成阶段目标再开新内容" 的既定纪律。
- 反方代价 (正方必须回答的): 收官即冻结 "flags partial-preserve" 缺口 (§6.1) — 但该缺口**与 G8 无关也应在收官前独立修复** (它是现网正确性缺口, 不是能力缺口), 所以不构成反对收官的充分理由。
- **裁决**: 排序建议维持 (P1 修复 → 视项目主意愿决定 G8a 是否入收官波), 但 "即刻收官" 是可辩护选项, 数字已备齐, 由项目主拍板。

## §5 B.5 文档联动草案 (只进报告, 拍板后实施)

1. **GAPS.md 不支持面段 (现 190-200 行) 精确化**: "pmovmskb（66 0F D7）/ pcmpeq/pcmpgt 系 / punpckldq/punpcklqdq" 追加 G9r 实测数据行: "三族频率分层 (MIT-G9r 实测: 经典 exe 14/14 全零; SIMD 域 punpck 0.06–0.074% / pmovmskb 0.015–0.055% 密度); punpck 按粒度分裂 — q 粒度 (lqdq/hqdq) = 8B 半宽重组低成本折条候选, b/w 粒度 lane 爆面 gate"。
2. **GAPS.md G6a ①行 (现 288-290 行) BMI 追加**: "① VEX-GP（BMI1/2）… 现状 gate" 后接 "G9r 裁决: 拆 G8a (andn/bzhi 零新 VmOp 折条 + rorx/shlx/sarx/shrx flagless 变体) / G8b (mulx/pdep/pext native 直执行 + CPUID gate); blsr/blsi/blsmsk 语料 0 → 文档化 gate; mulx CF 厂商分叉 (Zen5 实测不写 vs SDM) 披露在案"。
3. **GAPS.md:337 跳表行刷新**: kVmOpMax 95→**97** (MIT-427), 98/128 项已用余量 30; 扩容实测 S 级 (MIT-G9r spike 230/230), 触发 = 任一批次使 kVmOpMax+1≥128 (x87 L0 唯一必然)。
4. **STATUS.md** M3 技术债段同步: BMI 两档蓝图 + rol/ror flags 缺口登记 (§6.1)。
5. **观察清单转录**: 客户产物抽样出现 BMI/尾族标记区域命中 → 提 G8a/对应族; x87 L0 或 ymm 立项 → 触发扩容前置 commit。

## §6 新发现 (派单 §A 未列)

### §6.1 🔴 P1: rol/ror 写 ZF/SF/PF 与 native "不受影响" 语义分叉 (现网既有, E2E 实证 FAIL)

- **行为**: guest 在 rol/ror 后消费 ZF/SF/PF 时, 保护后行为与原生不一致。`scripts/e2e.sh flags_div_sample.exe` **实测 "stdout 不一致（虚拟化改变了行为）"**: native `ror_zdiv=0 shl_zdiv=0` vs 保护后 `ror_zdiv=1 shl_zdiv=0`。
- **复现样本** (单基本块, 无分支): `xor eax,eax; or eax,1 (ZF=0); [region] ror eax,1; setz cl; [region end]` — native ror 保留 ZF=0 → cl=0; VM ror → ctx ZF=1 → setz 读 1。shl 对照双跑一致 (shl 本身按结果写 ZF)。
- **机制** (源码钉死): build_shift (asmgen.cpp:707-739) 在 native 指令前 zero5 (:591, 清 T3/T4/T6/T7/T9 — 内部 xor 自身会置宿主 ZF=1/PF=1/SF=0) → native ror 执行 (只动 CF/OF) → setcc5 (:582) setz/sets/setp 捕获的是**宿主 handler 内部状态** (恒 ZF=1/SF=0/PF=1) → flags_tail (:542) 写回 ctx。而 native rol/ror 的 SDM 语义 = 只写 CF/OF, ZF/SF/PF **保留**。本机原生 probe 独立证实 (ror LSB=0 → CF 写 0, ZF/SF/PF 原样)。
- **注释根因**: asmgen.cpp:2478-2490 注释断言 "ROL/ROR … SF=结果 MSB, ZF=结果==0, PF=结果低 8 位偶校验" — 这是对 SDM 的误读 (该组语义属于 SHL/SHR/SAR; ROL/ROR 仅 CF/OF)。
- **波及面**: rorx/shlx/sarx/shrx 若照搬 translate_shift 折叠将继承同款分叉 (派单 D3 "禁照搬" 红线被证实为必要); 修复方向 = flags_tail 支持 "部分位保留" (rol/ror/未来 flagless BMI op 共用机制)。230/230 未覆盖此形态 = 样本集盲区 (非回归)。
- **置信度**: 高 (四路证据: 机制 + SDM + 原生 probe + E2E 逐字节 FAIL, 全部本 run 实测)。

### §6.2 kStubWindow 幻影 begin 复现 (P2, 424 §3.2 同款第二例)

branchy 版复现样本中 `marker_scan: begin@0x428 没有配对的 end（区域被丢弃）` 再现 — printf/多分支形态下 begin/end 配对失败静默丢区域。424 建议的 "目标必须指向 stub 入口±少量字节" 收紧仍未落地, 建议随任意 marker_scan 触碰单顺路收。

### §6.3 branchy 区域的块提升限制 (信息项)

jz/jmp 双路径区域报 "跳转目标块未找到（区域外/未 lift）" 整函数 gate — 区域内**前向分支目标块**需与主链同批 lift 才可虚拟化; 现样本 (snake 前向跳) 均为单链形态。对 BMI/尾族折叠单的验收样本设计是硬约束 (影子样本必须单基本块)。

### §6.4 blsr/blsi/blsmsk 语料零 (信息项)

真实二进制 27 文件语料 (含 424 全部 BMI 阳性) 中 BMI1 位操作三兄弟零命中 — G8 蓝图可安全裁掉 blsr (与派单 A.3 列举相比收窄)。

## §7 结论

✅ **侦察三合一完成, 三路全部出数, 无跳过**: 路1 = 三族文档化 gate 分层维持 (lqdq/hqdq 单列 S 级候选); 路2 = G8a/G8b 拆档蓝图 (两个派单预判实测修正: "rorx 族零新 VmOp" 半推翻 — flags 分叉; "lqdq 零新 op" 基本成立 — 非零成本) + **P1 rol/ror flags 缺口现网实锤 (E2E FAIL)**; 路3 = 扩容 S 级实锤, 挂触发条件不独立立波。排序建议: P1 修复 → (可选) G8a → 收官; 反方陈述已备, 阶段边界由项目主按 §4 数字拍板。主仓 main 零扰动 (spike worktree 已拆除, tracked 零脏), run 对账 ≈100 分钟。

== MIT-G9r triage 完 ==
