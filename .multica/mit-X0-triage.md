# MIT-X0 triage 报告 — x86 (PE32) 真产物侦察：白名单覆盖率 + x87 三路线裁决输入 + asmgen XL 改造面量化

- verifier: WVmpVerifier (裁定型 / 纯侦察零代码单, 零产品代码改动; triage 按 D4 走隔离 worktree, 已拆除)
- 静态基线: main `9a74896` (MIT-GZ 435, multiseed 48×5=240/240, kVmOpMax=97, 跳表余量 30); CLI = `build/cli/wvmp_cli.exe` (mtime 21:39 > HEAD 21:18, 新鲜 main 产物)
- 实验环境: `%TEMP%\mit436_x0\` (SysWOW64 语料 106 文件扫描 jsonl + 第三方 17 文件 + 20 个 MSVC x86 探针 DLL + ml.exe 手编 7 区域 marker 样本 + 硬拒亲验), 主仓 tracked 零改动
- 工具链: Python 3.14.6 + capstone 5.0.7 (CS_MODE_32 **模式亲验**: 与 424 x64 扫描脚本唯一差异 = arch 参数, 见 §1.1) | cl v19.51.36256 / ml.exe (32 位 MASM, Hostx64/x86 @ VC/Tools/MSVC/14.51.36231) | vcvarsamd64_x86.bat 实测可用
- 采集时间: 2026-08-31 22:3x – 09-01 00:5x (+0800), 全部数字来自实测输出; run 对账 ≈ 140 分钟 ≥ 30 分钟红线
- 结论置信度: **高** (capstone .text 线性全扫 + 6 文件递归遍历误差界 + cl 探针矩阵 ×9 档 + ml.exe 手编样本运行 + CLI 硬拒 rc=2 双输入形态亲验, 五路互证); 个别标注中者见内文
- 留样: %TEMP% 会被清理 → 扫描脚本 `scan_pe32.py` / 映射脚本 `map3.py` / 探针源码 / marker 样本源码 / 构建命令的关键可复现部分**内嵌本报告 §9 附录** (416/424/426 纪律)
- 方法声明: 424/432 数字二次引用处均标注"引用 424/432"; 416 x87 频率结论引用处标注"引用 416"; 本 run 重扫的数字全部为自测

## §0 结论 (裁定)

**一句话: x86 自然产物被现 x64 白名单的助记符级直接覆盖率 = SysWOW64 库域 95.74% / 第三方存量 98.72%; 全部缺口的 61.3% 由 x87 一族贡献 —— 项目主 A.2 预登记的 x87 冲突被实测坐实, 且"现代 UCRT 也含 x87"(ucrtbase x86 2.49%) 推翻"x87 只在老代码"的直觉。** SSE-only x86 子集路线 (x87 维持 gate) 即可拿 ~97-98% 覆盖; x87 L0 实施 = 唯一必然触发跳表扩容的路线 (98+80=178>128, 引用 432 §3.3)。asmgen XL 的量化核心不是编码翻译 (单点 RIP-relative + rs() 尺寸表已就位), 而是**物理池 14→6 导致临时寄存器 10→2 的 spill 重构**。

| 问 | 核心数字 | 裁决 |
|---|---|---|
| B.1 覆盖率 | SysWOW64 (100 文件 22.53M 指令) direct=95.74%, missing=4.26% (x87 占 missing 61.3%); 第三方 (17 文件 15.59M) direct=98.72% | 现白名单"一台打两制"的底子真实成立; 形级 fork 面 (call [mem]/ret imm16/plain movsd/S16) 另计 2-4% |
| B.2 x87 | 分层密度: core_os 0.12% / modern_ucrt 1.00% / random 4.20% / **old_runtime 7.55%** (d3dx9 单文件 8-15%); 探针矩阵: /arch:IA32→x87, /arch:SSE→**double 仍 x87**, 默认 SSE2→x87≈0 | 三路线可裁决: R-SSE-only 覆盖 ~97-98% 且零扩容; R-x87-L0 +2.61% 但 +~80 op 触发扩容; R-浮点整函数 gate 最省 (现 gate 机制即兜底) |
| B.3 asmgen XL | 池 14→6 (−esp −ecx 保留), callee-saved 4 个全被 ctx/base/t0/t5 占用 → 临时 10→**2** (zero5 需重构); RIP-relative 全运行时**仅 1 处** (asmgen.cpp:417 取码基址); ctx 访存全部 [reg+disp] x86 原生支持 | XL 定级维持 (412 §4), 拆解为 A 档参数化 ~45 handler / B 档语义分叉 ~25 / C 档结构性重写 5 块 (§3.2) |
| B.4 冻结面 | VmContext 全 u64 字段 + xmm[8]@0x140 恰好完整覆盖 x86 的 8 个 xmm (无 REX → xmm8-15 在 32 位模式不可编码) | kCtxSize 保持 0x1C8 零触碰 (指针域钉 u64 即可); xmm 议题反转确认; 414 硬拒面亲验 rc=2 不回退 |
| B.5 现网 | rc=2 硬拒双形态亲验 (probe DLL + SysWOW64\TRACERT.EXE), 无产物落盘; ml.exe 7 区域 marker 样本 build+run rc=0; 纸面 lift: 整数/SSE 区域 100%, x87 区域 9% | 现状行为钉死; X 波样本池起步样本已产出 (留样内嵌 §5) |

## §1 B.1 语料分布与对账矩阵 (主交付)

### §1.1 方法学 (x86 与 424 x64 方法的差异, 显式披露)

1. **无 .pdata**: x86 PE32 无运行时函数表 (SEH 时代产物) → 函数域界定退化为**整 .text 线性扫** (skipdata 单字节重同步) + 递归遍历误差界 (6 个代表文件: 入口 + 导出表 ≤300 种子, 直接跳转 BFS)。误差界实测 (linear vs recursive): kernel32 **0.0%** / user32 +1.8% / gdi32 +11.5% / oleaut32 −14% (递归种子/单跑 15 万指令上限截断) / msvcrt +3.0% / msvbvm60 +1.9% → **±1-12% 为噪声带**。递归法在 skipdata 下有数据区磨穿问题 (ntdll/comctl32 递归成本爆炸, 按上限截断后放弃) —— **方法学差异本身是发现**: X 波 E2E 若做 x86 函数级对账, 需要新的函数域重建手段 (导出表链 or SEH scope 表), 424 的 .pdata 域扫法不可平抄。
2. **数据伪指令噪声**: 线性扫含 .text 内嵌数据 (对齐垫/跳转表/字符串) 误解码。噪声指纹族 (outsd/insb/popal/pushal/arpl/aas/daa/das/bound/les/lds/into/int3) 全语料 2.57%, top-10 文件贡献 50% (iertutil 10.2% / mavinject 21.9% 等) → 汇总时按指纹族剔除 (原始计数保留在留样 json)。**x87 计数器 (首字节 D8-DF) 同样受数据噪声抬升, 但递归对账 6 文件显示代码密集 DLL 的 x87 计数 linear≈recursive (kernel32 23/23, msvcrt 3165/3256, msvbvm60 3394/3414) → x87 结论可信**。
3. **capstone CS_MODE_32 亲验**: 扫描脚本与 424 唯一差异 = `Cs(CS_ARCH_X86, CS_MODE_32)`; skipdata 语义实测 ('.byte' 伪指令, user32 全节 344,491 项含 1,114 数据字节); VEX 计数器修正 —— 32 位模式下 C4/C5 首字节是 LES/LDS 老编码, 仅 mnemonic 带 v 前缀才计 VEX (修正后全语料 VEX=0.0063%)。
4. **movsd 双形态拆分**: 助记符级无法区分串 (A5) 与 SSE (F2 0F 10), 补做字节级 shape 扫描 (§1.4): msvbvm60 = 串形 1311 / SSE 0; dxcompiler = 串形 10116 / SSE 491 —— **plain movsd (无前缀结构体拷贝惯用法) 是真实高频形态**, G3 白名单只收 F3/F2 前缀形 → fork 项。

### §1.2 语料分层 (D2: 库域 + 探针双路; 分母 = 剔指纹族后指令数)

| 层 | 文件数 | 指令数 (clean) | 说明 |
|---|---|---|---|
| core_os (SysWOW64 核心 OS DLL) | 37 | 10,750,980 | kernel32/user32/gdi32/ntdll/shell32/ole32/…/jscript 全点名集 |
| old_runtime (SysWOW64 老运行时) | 12 | 4,187,745 | msvcrt/msvcp60/mfc42/mfc42u/msvbvm60/msdart/d3dx9_{24,30,35,40}/xactengine2_0/xinput1_1 (2005-2011 时代, mtime 佐证) |
| modern_ucrt | 7 | 1,869,489 | ucrtbase/vcruntime140/msvcp140/mfc140/ucrtbase_clr0400/… |
| random_syswow (大小×时间八分位随机) | 45 | 5,723,921 | 随机样本 (seed=436), 含 mmc.exe/vssapi/pla.dll 等 |
| 第三方存量 (Program Files (x86)) | 17 | 15,594,476 | VMware×5 / NVIDIA PhysX×3 / Steam×2 / GoogleUpdate / IncrediBuild (Delphi 构建者) / dxcompiler (clang) / hha / wab32 (PF(x86) 5285 个 PE32 中按 CLR 目录过滤出 native, §F.2 妥协: 本机无 1990s 存量, 最老为 2015) |
| MSVC x86 探针 (自有源码) | 20 | ~178,000 | 6 探针 × {/Od,/O1,/O2} × {默认 SSE2, /arch:IA32, /arch:SSE} + AVX cell (§2.2) |

SysWOW64 全量 = 2827 个 PE32 (B.1 预扫实测), 本 run 扫 106 文件 (84.3MB 文件字节) —— 库域覆盖率 3.7% (按文件数), 大 DLL 全点名。

### §1.3 频率表 (top-40, SysWOW64 clean, 完整 top-80+ 见留样)

| # | 助记符 | 计数 | 占比 | 累计 | 三态 |
|---|---|---|---|---|---|
| 1 | mov | 5,201,385 | 23.08% | 23.08% | direct (S16 形 fork) |
| 2 | push | 3,128,667 | 13.89% | 36.97% | direct (4B 栈宽 fork / push [mem] 形) |
| 3 | add | 2,674,931 | 11.87% | 48.84% | direct |
| 4 | call | 1,442,822 | 6.40% | 55.24% | direct (call [mem] fork→X3) |
| 5 | pop | 851,225 | 3.78% | 59.02% | direct (4B 栈宽 fork) |
| 6 | je | 810,891 | 3.60% | 62.62% | direct |
| 7 | cmp | 779,823 | 3.46% | 66.08% | direct |
| 8 | lea | 740,270 | 3.29% | 69.37% | direct |
| 9 | test | 720,257 | 3.20% | 72.56% | direct |
| 10 | jmp | 534,692 | 2.37% | 74.94% | direct (jmp [mem] 走 G2 模板) |
| 11 | xor | 524,513 | 2.33% | 77.27% | direct |
| 12 | jne | 459,594 | 2.04% | 79.30% | direct |
| 13 | inc | 453,437 | 2.01% | 81.32% | direct |
| 14 | and | 376,765 | 1.67% | 82.99% | direct |
| 15 | sub | 284,649 | 1.26% | 84.25% | direct |
| 16 | ret | 279,043 | 1.24% | 85.49% | direct (ret imm16 fork→§1.4) |
| 17 | adc | 229,529 | 1.02% | 86.51% | direct |
| 18 | or | 227,127 | 1.01% | 87.52% | direct |
| 19 | dec | 203,194 | 0.90% | 88.42% | direct |
| 20 | jb | 189,023 | 0.84% | 89.26% | direct |
| 21 | fld | 161,072 | 0.72% | 89.97% | **missing (x87)** |
| 22 | imul | 160,010 | 0.71% | 90.68% | direct |
| 23 | jae | 114,419 | 0.51% | 91.19% | direct |
| 24 | movzx | 107,190 | 0.48% | 91.67% | direct |
| 25 | fstp | 102,040 | 0.45% | 92.12% | **missing (x87)** |
| 26 | fmul | 88,606 | 0.39% | 92.51% | **missing (x87)** |
| 27 | js | 84,876 | 0.38% | 92.89% | direct |
| 28 | leave | 82,693 | 0.37% | 93.26% | **missing (x86 栈帧)** |
| 29 | movsd | 75,362 | 0.33% | 93.59% | direct (SSE 形) / plain 串形 fork |
| 30 | sbb | 72,134 | 0.32% | 93.91% | direct |
| 31 | jbe | 68,756 | 0.31% | 94.22% | direct |
| 32 | jo | 61,941 | 0.28% | 94.49% | direct |
| 33 | jl | 61,917 | 0.28% | 94.77% | direct |
| 34 | jns | 48,344 | 0.22% | 94.98% | direct |
| 35 | shl | 45,756 | 0.20% | 95.18% | direct |
| 36 | ja | 45,728 | 0.20% | 95.39% | direct |
| 37 | nop | 43,399 | 0.19% | 95.58% | direct |
| 38 | shr | 40,364 | 0.18% | 95.76% | direct |
| 39 | xchg | 32,715 | 0.15% | 95.90% | direct |
| 40 | faddp | 31,962 | 0.14% | 96.05% | **missing (x87)** |

### §1.4 对账矩阵 (三态, ≥50 行; 判据出处 = x86_translate.cpp 源读 @9a74896)

**总数字 (D3 第一页)**:

| 语料 | direct | fork | missing | missing 中 x87 占比 |
|---|---|---|---|---|
| SysWOW64 库域 (22.53M) | **95.74%** | ~0% (助记符级) | 4.26% | **61.3%** (2.61% of 总量) |
| 第三方存量 (15.59M) | **98.72%** | ~0% | 1.27% | 47.7% |
| 形级 fork 修正面 (助记符级 direct 内) | call [mem] ≈1-3% (dxcompiler 1.5% ↔ msvbvm60 35% 间) + ret imm16 ≈0.6-1% (msvbvm60 82% of ret / dxcompiler 49%) + plain movsd ≈0.3% + S16 (p66) 0.82% + push [mem] ≈0.5% | | | **诚实 direct 下界 ≈ 92-94%** |

| 助记符/族 | 现白名单映射 | 三态 | 备注 |
|---|---|---|---|
| mov r, r/m/imm (S8/S32) | MOV → Op::Mov/Load/Store | 可直用 | data_size 1/2/4/8→S8/S16/S32/S64 全宽在案 |
| mov r, r/m (S16, 66 前缀) | MOV (prefix[2] 不拦) | 需 arch 分叉 | p66 全语料 0.82% (msvbvm60 2.6%); VM S16 通路"现成"声明 (G3) 需 x86 实测 |
| movabs imm64 | MOVABS | n/a | x86 不产 (imm32 即可), 白名单不碍事 |
| lea (32 位 ModRM/SIB) | LEA → Op::Lea | 可直用 | 16 位寻址 (bx+si) capstone 可解但 base/index 映射哨兵, 编译器不产 |
| add/adc/sub/sbb/and/or/xor/cmp/test | ALU 族 | 可直用 | S32 主面; adc 0.995%/sbb 0.32% 高频 (x86 64 位仿真主载体) |
| inc/dec/neg/not | unary | 可直用 | inc/dec x86 高频 2.01%+0.90% (x86 无 sub $1 偏好) |
| shl/shr/sar/rol/ror (imm/cl) | shift 族 | 可直用 | MIT-433 flags partial-preserve 已收口, x86 同享 |
| push r/imm | PUSH | 可直用 (形级 fork) | push [mem] 形 (msvbvm60 19,397) lifter is_data_operand 收, runtime Push 4B 语义待验 |
| pop r | POP | 可直用 (形级 fork) | pop [mem] 非法编码无 |
| call rel32 (E8) | CALL → CallGate | 可直用 | 412 §3 已证 x64 管道在 32 位 PE 全跑通 (pe_loader bug 已修) |
| call reg | CALL | 可直用 | vtable/函数指针 reg 形 (dxcompiler 4,167) |
| call r/m32 ([mem]) | CALL 拒 | **缺失 (C3 fork)** | IAT thunk `call [__imp_x]`/`call [esp+..]`; msvbvm60 35% 的 call 是 mem 形 |
| ret (C3) | RET | 可直用 | — |
| ret imm16 (C2) | RET (src=imm 已 lift) | 需 arch 分叉 | **stdcall 被调方清栈是 x86 ABI 主形**: msvbvm60 7,829 vs ret 1,755 (82%), dxcompiler 23,230 vs 24,104 (49%); translator/runtime 的栈清理语义 v1 未实现 (x64 Win64 无此形态) |
| jcc rel8/32 (16 条) | Jcc | 可直用 | 66 前缀 rel16 形老代码罕见 |
| jmp rel8/32 | Jmp | 可直用 | — |
| jmp r/m32 | Jmp (G2 模板) | 可直用 (受限) | 跳转表防御常数模板; 越界 C1 gate 兜底 (409/G2 先例) |
| movzx/movsx (S8/S16→S32) | MOVZX/MOVSX | 可直用 | x86 主面 (movsxd 是 x64 专属, 白名单对 x86 显式拒, 不冲突) |
| movsd (SSE, F2 0F 10/11) | SSE 族 | 可直用 | — |
| movsd (串, A5 plain) | G3 只收 F3/F2 前缀 | 需 arch 分叉 | 结构体拷贝惯用法 (dxcompiler 10,116; msvbvm60 1,311); G3 开 plain 形或编译器面披露 |
| rep movsb/movsd/stosd/… (F3) | G3 串族 | 可直用 | rcx 语义/DF=0 披露先例全部适用 |
| lodsd/stosd/scasd (plain 无前缀) | G3 白名单外 | **缺失** | rgn_str 样本实测; plain 单发形 (msvbvm60 1,311 lodsd 级) |
| cld | — | **缺失** | 串操作前置惯用 (rgn_str 实测); 语义 = flags DF 位, VM flags 模型无 DF 位 (G3 D1 裁决引用) |
| cdq | CDQ | 可直用 | x86 S32 主形 (11,581) |
| cwde/cbw (98) | — | **缺失** | x86 符号扩展主形之一, 低频 (MSVC 偏好 movsx) |
| imul (3 形) | IMUL | 可直用 | MIT-302/306 三形+MEM 通路 x86 同享 |
| mul/div/idiv | MUL/DIV/IDIV | 可直用 | x86 双寄存器 (edx:eax) 协议 S32 化 |
| shld/shrd | — | **缺失** | 64 位移位仿真惯用 (probe_64 实测); 语料低频 (64 位算术偏走 CRT __allshl 调用) 但结构性必收 |
| bt reg,reg | — | **缺失** | _bittest intrinsic 形; bts/btr/btc 在面但 bt 本体不在 |
| bts/btr/btc mem (lock) | G4 | 可直用 | reg 形 gate (G4 残余披露引用) |
| xchg/cmpxchg/xadd | G4 | 可直用 | Interlocked* 真产物 x86 同构 (cdecl 侧 xadd/cmpxchg 形不变) |
| setcc (16 条) | SETCC | 可直用 | — |
| cmovcc (16 条) | CMOVCC | 可直用 | 0.06-0.12% 中频 |
| leave | — | **缺失** | **0.37% 全语料, x86 缺口第一名非 FP 项**; MSVC x86 epilogue 惯用 (esp=ebp;pop ebp), VC6/O1 档直出; 样本 rgn 实测 |
| enter | — | **缺失** | 噪声主导 (37), 老编译器罕见 |
| x87 全族 (fld/fstp/fmul/fadd(p)/fsub(p/r)/fdiv(r)/fst/fxch/fcomp/fnstsw/fld1/fldz/fild/fisttp/fiadd/…) | — | **缺失 (x87 L0)** | 588,549 条 = missing 的 61.3%; 密度分层见 §2.1 |
| SSE1/2 全族 (addss…/pand/movdqa/ucomiss/…) | SSE 白名单 38 id + G1b/c/d | 可直用 | **编码 x86/x64 完全相同** (无 REX); movss/mulss/movups/movaps/xorps/movq 全部 top-80 内 |
| SSE2 转换/数学族 (cvtsi2sd/cvttss2si/sqrtsd/maxsd/minsd…) | — | **缺失** | 探针 fp_default 的 int→double 转换即 cvtsi2sd/x87 混合; 语料 0.03-0.1% 量级 |
| movlpd/movhpd/movhps/movlps | — | **缺失** | SSE2 mem 传送缺口 (语料 0.03%, 部分 noise) |
| BMI (andn/bzhi/rorx/shlx/sarx/shrx) | G8a 折条 | 可直用 (VEX) | 32 位模式 VEX 编码合法; 语料 0.006% (dxcompiler/Steam 有真 VEX 1.3-1.5k 条) |
| popcnt/lzcnt/tzcnt | 白名单 | 可直用 | F3/B8 前缀 REX 修正纪律 x86 不触发 (无 REX) |
| loop/loope/loopne | — | **缺失** | 0.065% (loopne 14,604, 部分噪声), 老编译器循环 |
| jecxz/jcxz | — | **缺失** | 语料 12 (noise 级) |
| pushad/popad (60/61) | — | **缺失** | 0.077% (17,861+93,417 popal 多为噪声指纹); 真实出现于上下文保存/老防拷 |
| lahf/sahf | — | **缺失** | 77 条, 老代码 flag 搬运 |
| int (CC/2Bh/29h) | — | **缺失** | 20 条真 int + int3 15.4% (对齐垫, 非 code) |
| in/out | — | **缺失** | 0.13%, ring0 专属 (进程内不可达) + 噪声 |
| daa/aas/aam/aad/das/aaa | — | **缺失** | BCD legacy, 语料全是噪声指纹 |
| arpl/les/lds/bound | — | **缺失** | 噪声指纹主导 (递归对账 kernel32 仅 10/167k) |
| fs:[..] 段覆盖 (TLS/TEB/SEH 链) | prefix[1] 入口拒 | **缺失 (设计项)** | 全语料 0.32% (vmwarecui 1.7% / Delphi 0.68%); SEH 交互见 §7 #6 |
| VEX/AVX (vaddss/vmovss/…) | G6a V-pair | 可直用 (低频) | x86 语料 0.006% (386 模式无 xmm8-15 → 高位寄存器全族天然 gate) |
| fence (sfence/mfence/lfence) | — | **缺失** | 多线程面, 语料 noise 级 |
| MMX (movd/pand mm 形) | mm 判据 gate (G1c D2) | 缺失 (维持) | 老代码 MMX 直出形 |

### §1.5 分层覆盖率

| 层 | direct+fork | missing(x87) | missing(其他) |
|---|---|---|---|
| core_os | 98.26% | 0.12% | 1.62% |
| old_runtime | 90.80% | **7.55%** | 1.65% |
| modern_ucrt | 96.78% | 1.00% | 2.22% |
| random_syswow | 94.29% | 4.20% | 1.51% |
| 第三方存量 | 98.73% | 0.60% | 0.67% |

## §2 B.2 x87 裁决输入 (D1 正面回答)

### §2.1 x87 密度分层 (仿 424 §2.2 密度表, 本 run 自测)

| 层/文件 | x87 条数 | 占本层 | 备注 |
|---|---|---|---|
| core_os | 14,527 / 12.35M raw | 0.12% | kernel32 23 条 (0.014%), 递归对账 23/23 |
| old_runtime | 316,344 / 4.68M raw | 6.76% | **d3dx9_40 121,526 (8.0%) / d3dx9_35 121,939 (9.7%) / d3dx9_24 93,401 (13.0%) / d3dx9_30 89,958 (11.4%)** — 2005-2011 D3DX 数学库 x87 矩阵/向量流水; msvcrt 3,165; msvbvm60 3,394 |
| modern_ucrt | 19,323 / 2.11M raw | 0.92% | **ucrtbase.dll 2949 条 = 2.49%** (printf/atof 浮点格式化内部), ucrtbase_clr0400 4.4% —— "x87 只在老代码"被推翻 |
| random_syswow | 240,932 / 6.38M raw | 3.78% | 零星小文件高占比 (小分母效应: ntdll 5.9%/460 条, MSDvbNP.ax 4.8%) |
| 第三方 | PhysXCore 3.39% / APEX 1.39% / GRB 1.22% / SteamService 0.38% / dxcompiler 0.028% / Delphi 0.13% | | 游戏中间件是 x87 第三方主源 |

**判读**: x64 的"x87≈0 (0.0000-0.0032%, 引用 416)"结论**不可平移到 x86**。x86 语料 x87 总占比 2.61% (SysWOW clean), 且分三层: OS 核心≈0 → 现代 UCRT 残留 1% → 老运行时/游戏数学 7-13%。目标客户 (老 32 位软件保护需求) 命中 x87 标记区域的概率显著非零。

### §2.2 "SSE-only x86 子集"可行性 (探针矩阵, D2 档位×arch 双矩阵, 416 教训兑现)

cl v19.51.36256, probe_fp (vec_dot/poly/hypot2/fcmp/lerp/vec4_add/int_to_fp), capstone .text 扫描:

| 探针档 | /Od | /O1 | /O2 | 判读 |
|---|---|---|---|---|
| 默认 (/arch:SSE2) | x87=6 | x87=6 | x87=9 | **MSVC x86 默认档 = SSE2 浮点**, 残留 6-9 条 x87 = int→double 转换路径 (_s$ 的 fld/fadd/fstp) |
| /arch:IA32 | x87=39 | 41 | 63 | 老代码基线档 = 纯 x87 流水 (fld/fmul/faddp 风暴) |
| /arch:SSE | x87=41 | 41 | 63 | **float=SSE1 但 double 仍走 x87** — "SSE1 档"不等于"SSE 浮点" |
| /arch:AVX (/O2) | — | — | vex=58, x87=9 | 32 位 AVX 真实可产 (对应第三方 Delphi/Steam 的 VEX 1.3-1.5k 条) |

整数/字符串/结构体/stdcall/64 位仿真探针 x87 = 0-2 条 (全档) —— 整数世界零 x87。

**判读**: (a) 默认编译的 x86 新代码 = SSE 浮点 → R-SSE-only 路线覆盖"现代/近期客户"; (b) /arch:IA32 显式档 (老工程遗留工程文件常见) 与 /arch:SSE 的 double 全走 x87 → R-SSE-only 对"老客户"的保护打折 = FP 函数整函数 gate; (c) x87 残留 (转换路径) 意味着 SSE-only 路线下默认代码也可能零星 gate —— 需要 x87 gate 的整函数保持语义 (416 已建 wvmp_x87_gate_sample 先例) 兜底, 不产坏壳。

### §2.3 三路线对比表 (D1 可裁决形态)

| | R-x87-实施 (x87 L0 进 X 波) | R-SSE-only (x87 维持 gate) | R-浮点整函数 gate (首波纯整数面) |
|---|---|---|---|
| 覆盖率增益 | +2.61% (SysWOW) / 老运行时层 +7.55% | 非x87 部分 ~98.3% (2.1); x87 函数整函数原生保持 (byte-identical, 416 先例) | 浮点函数 (SSE 亦然) 整函数原生保持 |
| 实施成本档 | **XL 级另加**: ST 栈模型 (8 寄存器栈拓扑 + fxch 交换优化) + ~80 新 VmOp (引用 416 L0 估) → **98+80=178 > 128 必然触发跳表扩容** (引用 432 §3.3/§3.4: 扩容实测 S 级, 单行改 + 全量回归) + fnstsw/ax 状态桥 (x87 状态字→VM flags C0-C3 映射是语义雷区) | x87 gate 机制**已存在** (416/418, wvmp_x87_gate_sample); 本路线 = 零额外实施 | SSE gate 同机制扩到全部浮点函数 = 白名单收窄, 亦零新实施 |
| 保护打折度 | 无打折 (x87 函数可虚拟化) | FP 老/混合函数不保护 (性能零影响, 安全面收缩 — 与 x64 战役同承诺) | 所有 FP 函数不保护 (打折度最高) |
| 风险 | x87 语义电池 (栈顶环/fnstsw C0-C3/精度控制) 是全新语义面; fuzz 万条预算 ×80 op | 残留 x87 (int→double 转换) 使默认编译代码也可能整函数 gate — 披露即可 | 客户感知最差 ("浮点函数保护不了") |
| 建议 | 若 B.2 数字判老客户 (IA32/d3dx9 类) 是主市场 → 后置波 X4 全量投 | **侦察侧推荐**: 首波默认; 与 x64 的 x87 永久 gate 承诺一致 (GAPS x87 节), 数字足以后续升级 | 仅当 X 波预算被砍半时 |

## §3 B.3 asmgen XL 改造面细化 (412 §4 唯一 XL 级拆单输入)

### §3.1 ① 物理池与 spill 重排

实测 (asmgen.cpp:169-179, :319-406):
- 现池 = 16 GPR − rsp − rcx(移位保留) = **14** (kPhys 表 r64/r32/r16/r8 四名列齐备 — 32 位名字面已存在, 零新增表); 持久 = ctx_/base_ (callee-saved 硬约束) + pc_/flags_ + t0/t5 (callgate 参数寄存器避让 callee-saved 约束), 临时 t1..t9 共 **10 个**。
- x86 面: 可分配 = {eax,ebx,ecx,edx,esi,edi,ebp} − esp − ecx = **6**; 其中 callee-saved 仅 4 (ebx/ebp/esi/edi) 且**恰好被 ctx_/base_/t0/t5 占满** → pc_/flags_ + 10 临时必须挤进 {eax,edx} (+ecx 非移位期) = **临时 10→2**。
- 用量证据 (T0..T9 token 计数): T1=109 / T0=66 / T6=51 / T9=38 / T5=30 / T4=23 / T3=21 / T7=18 / T8=10 / T2=9; **zero5 (:629) 在 ALU/shift 前清 5 个临时** (T3/T4/T6/T7/T9, 引用 432 §6.1 机制描述) —— x86 池 2 临时下 zero5 纪律必须重构 (改为 2-3 清零 + 复用, 或 flags 捕获序列改写 — 433 flags_tail_partial 已把 rot 族尾部独立, 是机制先例)。
- 拆单建议: **S/M/L = L** (非独立 XL 单: 它是 X2 整单的内容轴)。工作量集中在 (a) 临时生命周期重排 per handler (~45 个 A 档 handler 逐一过) (b) zero5/zero_xmm 纪律重设计 (c) callgate 跨 native call 的寄存器保护 (现依赖 callee-saved 池, x86 需显式 push/pop)。

### §3.2 ② 97 op handler 32 位编码重核分组 (95 表项 + Halt, 实测 :3336-3520)

| 档 | handler 数 | 判据 | 代表 |
|---|---|---|---|
| A 档: 同模板换宽度 (可脚本化) | **~45** | emit 序列已经过 rs() 尺寸派生 (kPhys 四名列), S32 路径在 x64 build 上本来就活跃 (S32 VmOp 常态); x86 改造 = keystone KS_MODE_64→32 切换 + 断言 qword/REX 形不可达 | add/sub/and/or/xor/cmp/test/inc/dec/neg/not/mov/load/store/movzx/movsx/imul/mul/div/idiv/adc/sbb/shl/shr/sar/rol/ror(+cl)/bswap/xchg/setcc/cmovcc/popcnt/lzcnt/tzcnt/andn/bzhi/rorx/shlx/sarx/shrx + SSE 全族 (编码双平台相同, 34 个) |
| B 档: 32 位语义分叉 (人肉小改) | **~25** | 栈宽/地址宽/立即数宽差异, 但结构不变 | Push/Pop (4B 槽), Jmp/Jcc (S32 目标), LoadRva/StoreRva/LeaRva (image_base u32 直载, 比 x64 的 imm64 还简单), XmmFromGp/GpFromXmm (movq→movd), 串族 (SIB 32 位), GetFlags/SetFlags (pushfq→pushfd), flags_tail/setcc5 (32 位 setcc), Cmpxchg/Xadd/Bts 族 (G4, 编码 32 位化) |
| C 档: 结构性重写 (人肉大改) | **5 块** | 协议/ABI/布局级 | (1) entry ( callee-saved 8 push→5/4 push + BASE 取址改 call/pop, :417 唯一 rip 点) (2) dispatch (跳表 8B 表项→4B 决策: [BASE+T0*8+disp] ModRM 下 x86 可保 8B 表项 (寄存器间接寻址无宽度惩罚), 亦可 4B 减半表体积 — 实施单拍板) (3) callgate (:1233-1380, 见 ③) (4) ExitNative (:1096, 槽协议 4B 化 + rsp 重基数) (5) Halt (写回链 4B) |

### §3.3 ③ callgate cdecl

- Win64 (现): RCX/RDX/R8/R9 参数 + shadow 0x28 + 16 对齐 + xmm0-3 FP (MIT-417 通路 :1289-1302) + callee 4KB 窗口 (MIT-406 :249-291)。
- x86 cdecl 对应面: **全部参数栈传** `[esp+N]` (现 step5 的 4 参数寄存器写入改 4 次 push 或 sub esp+mov — 形态变简单); **FP 参数走 st(0)** (cdecl FP = x87 栈顶, 无 xmm 参与!) → MIT-417 的 xmm0 通路在 x86 要换 fld/fstp 桥或 fstp qword [esp] 伪栈传 — **这是 callgate x86 的最大语义分叉**, 417 修复的"FP 参数断链=静默坏壳首例"教训直接适用; **调用方清栈** `add esp, N*4` (被调方不留栈) — 现 step7 回退公式 (kCallgateSpRollback, :239-246) 整体重导, 全部常量已从 kCtxSize 派生 (423 纪律) → 重导成本可控; callee-saved 保护: 现依赖 Win64 callee-saved 集合不变式, x86 下 callee 只保 ebx/esi/edi/ebp → ctx_/base_/t0/t5 的 callee-saved 约束**恰好仍成立** (§3.1), 但 pc_/flags_ 若落 caller-saved 需 callgate 前后显式 push/pop。
- 拆单建议: **M** (独立单, 415 串指令/callgate FP 417 的 x86 对应面全部集中于此)。

### §3.4 ④ [ctx+0x98] 等位移偏移的 32 位寻址

- 实测: flags = `[CTX + 0x98]` (:436/:560/:594...)、xmm = `[CTX + 0x140 + 16*N]` (:1302)、字节码取指 = `[BYTE + PC*8]`、跳表 = `[BASE + T0*8 + disp]` —— **全部是寄存器间接 + disp/SIB 寻址, x86 ModRM/SIB 原生支持, 零改造**。
- 全运行时 emit 的 RIP-relative **仅 1 处**: entry 的 `lea BASE, [rip-7]` (asmgen.cpp:417, 位置无关取码基址)。x86 对应 = `call next; next: pop ebp`(5B 经典 32 位 PIC idiom) 或 PE32 base-reloc (pe_writer 扩 reloc 面)。**派单 A.2 "x86 无 RIP-relative, ctx 基址怎么给"的冲击面 = 一条指令的取址惯用法, 不是访存体系** (预判命中但量级比预想小一个数量级)。
- 拆单建议: **S** (并入 X2a entry/dispatch 块)。

## §4 B.4 冻结面触碰预判

1. **kCtxSize / VmContext 布局**: 全字段 u64 (u8* bytecode / u64 regs[32] / u64 native_sp / XmmSlot xmm[8])。x86 宿主指针 4B → 两个选项: (a) **指针域钉宽** (u8* → u64 存 VA, 或 struct 内 padding) → sizeof 不变 → kCtxSize 0x1C8 与全部 offsetof 静态断言 (:111 native_sp==0x120) 原样, **零冻结触碰**; (b) 放任 4B 指针 → 布局整体收缩, 全部硬编码偏移检查通道 (E1/380 先例) 重走。**建议 (a)**, 成本 S (一个字段类型 + 派生常量自动跟随), 把 0x1C8 变成双架构公共常数。native_sp 槽 (stub_gen 一次性写入) 同理 4B 值零扩展入 8B 槽。
2. **xmm8-15 议题反转 (A.2 预判实测确认)**: 32 位模式无 REX 前缀 → xmm8-15 **编码不可达**, 语料实测 0 条; ctx.xmm[0..7]@0x140 恰好全覆盖 → x86 SIMD 跟踪面**完整无 gate** (x64 的"高位寄存器 gate"议题在 x86 自然消失)。VEX 3-operand 高位 dst 形在 x86 同样受限 (VEX.vvvv 4 位编码可达 xmm8-15? VEX 编码在 32 位模式下可编 xmm8-15 — 但语料 0.006% 且 G6a 位宽闸/映射闸现成, gate 兜底)。
3. **跳表扩容触发 (432 §3.4 文本引用)**: 现役 98/128, 余量 30。**x87 L0 (~80 op, 引用 416) 是唯一必然触发者 (178>128)**; R-SSE-only 路线零新 op → 不触发; ymm 档B 与 x86 无关。若走 R-x87-L0: 扩容前置 commit 随 X4 首批落地 (S 级, 432 spike 230/230 已验)。
4. **414 硬拒面 (D4)**: pe_loader 解析层已接受 0x014C (pe_image.cpp:49-51) + CLI/管道显式 ERROR diag。X 波翻"硬拒"为"声明支持"时, 对 machine ∉ {0x014C, 0x8664} 的**未知 machine 硬拒必须保留** (pass 层白名单显式逐 machine 扩展), 本 run 亲验 rc=2 原样 (§5.1)。

## §5 B.5 现网三态 E2E (x86 现状行为钉)

### §5.1 硬拒亲验 (rc=2 原样, 双输入形态)

| 输入 | 结果 |
|---|---|
| probe_stdcall_O2.dll (本 run 产 PE32) | `[error] pe_loader: 32 位目标 (x86) 未支持 (GAPS C5); 不产出保护壳`, **rc=2**, 无输出文件落盘 |
| TRACERT.EXE (SysWOW64 真产物, 副本) | 同上 rc=2, 无输出文件 |

### §5.2 ml.exe 手编 x86 marker 样本 (412 §6 形态纪律, 423/428 ml 纪律)

- 7 区域 × craft32 连续 magic (jmp 越过 8 字节 magic, 避 412 §6 坑①"编译器吞 ret"): rgn_alu (整数 ALU+jcc 环) / rgn_mem (load/store/lea/push/pop/movzx/movsx) / rgn_sse (movss/addss/mulss/divss/movaps/movups/ucomiss/xorps/andps) / rgn_x87 (fld/fmul/faddp/fstp/fnstsw/fxch/fcomp) / rgn_wide (adc/sbb/shld/shrd 64 位仿真) / rgn_indirect (call [mem]/jmp [mem]) / rgn_str (rep movsd + plain movsd + lodsd/stosd/cld)。
- 构建: `ml /c /Coff` (MASM 语法坑: `_emit` 是 C 内联汇编形, ml 源用 `db`; SSE mem 操作数需显式 size 指定) + `cl /c main.c` + `link /MACHINE:X86` → **build+run 成功 rc=0** (输出 529/39/…/99/5)。留样源码全文随 triage 提交。
- **坑 (写进实施单)**: ml.exe (32 位 MASM) 与 ml64 的差异 = db 替 _emit / .XMM 指令集开关必加 / SSE mem 形 size 前缀必写; `call dword ptr [edx]` 等 mem 形需 dword ptr。

### §5.3 纸面 lift 可行性表 (不经产品, capstone 区域映射预演, ≥5 函数含三型)

| 区域 | 指令数 | direct | missing (gate) | 判读 |
|---|---|---|---|---|
| rgn_alu (整数) | 25 | 25 | 0 | **100% 可虚拟化** (现白名单即可) |
| rgn_mem (访存) | 21 | 21 | 0 | **100%** |
| rgn_sse (SSE FP) | 13 | 13 | 0 | **100%** (x86/x64 编码相同) |
| rgn_x87 (x87 FP) | 11 | 1 | 10 (fld/fmul/faddp/fstp/fnstsw/fxch/fcomp) | **9%** → R-SSE-only 下整函数 gate |
| rgn_wide (64 位仿真) | 16 | 14 | 2 (shld/shrd) | 88%; shld/shrd 收面后 100% |
| rgn_indirect (间接) | 10 | 8 (形级修正) | 2 (call [mem] / jmp [mem]) | call [mem] = X3 必收; jmp [mem] 走 G2 模板 |
| rgn_str (串) | 13 | 10 | 3 (cld/lodsd/stosd) | plain 串形单发 = G3 开口或披露; cld = DF 位设计项 |

(注: 助记符级分类器对 call/jmp 的 mem 形不敏感, rgn_indirect/rgn_str 的形级修正已手工标注 — 分类器局限披露。)

**判读**: 三型函数中, 整数与 SSE 区域在现白名单下**纸面全可虚拟化** — 与 §1.4 覆盖率互证; 纸面预演 ≠ 实测 (X2 前 x86 通路不存在), 三态表按派单 §F.3 标"纸面"级证据。

## §6 B.6 X1-X5 拆单蓝图 (412 §4 依赖图 × 本单数字 → 定版)

| 单 | 范围 | 依赖 | 预算 | 验收锚 (multiseed x86 样本池起步数) |
|---|---|---|---|---|
| **X1** 平台开门 (S) | marker_scan arch 从 machine 读 + SDK x86 锚点 (craft 形已验) + CLI/pe_loader 翻硬拒为声明 (未知 machine 硬拒保留, D4) + translator S32 分叉 (412 §2 五处 S64 硬编码) + multiseed x86 基建参数化 | — | **S+M** | 本 run 7 区域 marker 样本 + probe 20 DLL 中抽 4 + 2 个 SysWOW64 静态对照 = 起步 7-10 样本 |
| **X2a** asmgen x86 核心 (XL) | 池 14→6 + spill/zero5 重构 + A 档 ~45 handler 宽度断言 + entry/dispatch (call/pop 取基址, 跳表决策) + B 档 GP 面 (Push/Pop/Jmp/Jcc/RVA 族) | X1 | **XL** (412 §4 唯一 XL 维持) | 整数/访存/串区域样本 ≥6 |
| **X2b** asmgen x86 SIMD+桥 (M) | SSE 族 34 handler 32 位核验 + XmmLoad/Store/桥 (movq→movd) + flags/setcc5 32 位 | X2a | **M** | SSE 影子样本 ≥4 (A.2 三门 SSE 纪律平移: 裸立即数扫描 / ctx.xmm 读回 / dump 校验 — A.3 脚本 SSE_HANDLERS 集合扩展) |
| **X3** stub_gen x86 + callgate cdecl (M) | stub 5 callee-saved / ctx 栈传 / image_base imm32 / callgate 重导 (栈传参+st0 FP+调用方清栈+窗口对齐) | X2a | **M** | callgate 样本 ≥3 (含 FP 参数 + stdcall 被调) |
| **X4** x87 三路线落地 (按 D1 裁决) | R-SSE-only: gate 文档化 + x87 gate 样本转正 x86 版 (S) / R-x87-L0: 跳表扩容前置 commit + ~80 op 分批 + fnstsw 语义电池 (L, 拆 2-3 单) | X2b | **S 或 L** | x87 gate/影子样本 ≥3 |
| **X5** E2E 矩阵 + 收口 (M) | Release|x64 构建 + x86 multiseed 池定版 (样本起步 7-10 → 定版 ≥15) + 硬拒回归 (未知 machine rc=2) + GAPS/STATUS 文档波 | X1..X4 | **M** | 15×5 = 75/240 新增 |

**x87 路线落点**: 三路线选择不改 X1-X3 (整数/存/SSE/callgate 全共享), 只改 X4 体量与 X5 验收面 — **D1 悬置可以保留到 X2a 落地后再裁**, 不阻塞 X 波开工。
**410(M3) 排程互斥声明**: x86 战役与 M3 插件池的代码面**零重叠** (x86 = lifter 后段/translator/asmgen/stub_gen/基建; M3 = crypt/mutate/anti_debug/integrity_crc/import_protect 占位 pass + codec 织入点, GAPS 保护强度缺口节) — 互斥只在预算维度。建议: x86 里程碑的 XL 锚 (X2a) 无并行替代, 是排期关键路径; 若总预算只能保一条, **M3 单价低且直接兑现"保护强度"卖点, x86 X2a 投入大且价值面 (客户形态) 依赖本单数字的裁读** — 侦察侧建议 M3 先行一个波次、X1 (S+M) 并行开工, X2a 在 M3 首波收官后接排。终裁项目主拍板。

## §7 项目主预判实测对账 (#33 纪律: 实测兜底优先) + 新发现

1. **A.2 "x87 是 x86 主路径冲突" — 实测坐实且加码**: missing 的 61.3% 是 x87; d3dx9 单文件 8-13%; **modern_ucrt 1.00% / ucrtbase 2.49% 推翻"x87 只在老代码"** — R-SSE-only 路线也无法宣称"现代客户零 gate"。
2. **A.2 "xmm8-15 反转反而完整" — 确认**: 无 REX → xmm8-15 编码不可达, ctx.xmm[0..7] 全覆盖, x64 的 SIMD 高位寄存器 gate 议题在 x86 自然消失。
3. **A.2 "无 RIP-relative 冲击" — 确认且降级**: 冲击面 = 1 条取码基址指令 (asmgen.cpp:417), 非访存体系; call/pop idiom 或 base-reloc 两种 S 级出路。
4. **A.3 "VEX/EVEX x86 密度需实测" — 实测**: VEX 0.006% (但非零: Delphi/Steam/dxcompiler 有真 AVX 1.3-1.5k 条/文件); EVEX 槽位 (0x62=BOUND) 在 32 位模式是 legacy 指令, 语料 0.074% 全为 noise。
5. **A.2 "int 2Bh/in/out/pushad 存量出现率" — 实测**: in/out 0.13% (ring0 不可达+噪声), pushad 0.08% (部分真), int 20 条真 — 均可文档化 gate, 无一进 X 波必需面。
6. **🔴 新发现 #1: SEH/FS 面比预判更近**: seg_fs 全语料 0.32% (Delphi 0.68%/vmwarecui 1.7%) — FS:[0] SEH 链安装/消费进标记区域即 gate (段覆盖前缀入口拒); callgate 的 callee 装自己的 SEH 无碍 (原生栈)。**X1 的 gate 文档化必须显式点名 SEH 形态** (32 位 push scope/trap frame 是客户存量常态), 建议观察清单单列。
7. **🟡 新发现 #2: ret imm16 (stdcall 清栈) 是被低估的 ABI 主形**: msvbvm60 82% / dxcompiler 49% 的 ret 是 imm 形; lifter 已 lift (translate_ret :290-302 src=imm) 但 translator/runtime 的栈清理语义 v1 从未实现 (x64 无此形态) — X1 的 translator 分叉必须含此项, 否则 stdcall 函数虚拟化后栈失衡 = **行为错误 (非 gate 非静默)**, 属 C2 级地雷形态。置信度高 (源码直读 + 探针双形态编译)。
8. **🟡 新发现 #3: plain movsd/lodsd/stosd/cld 串形**: dxcompiler 10,116 条 plain movsd (结构体拷贝) — G3 只收 F3/F2; 开口 = X1 顺手项 (S), 不开 = 高频 gate 披露。
9. **信息项 #4: leave 0.37%** 是非 FP 缺口第一名 (MSVC x86 epilogue 惯用); 折条 = Load+Mov+Store 组合零新 VmOp (C4b 先例), 建议 X2a 顺路收。
10. **信息项 #5: 递归法成本爆炸** — 无 .pdata 的 x86 做函数域重建, BFS 递归在 skipdata 下有数据区磨穿问题 (ntdll 20 分钟不收敛); X5 的 x86 E2E 对账设计必须预先选定函数域手段 (本 run 线性全扫 + 误差界披露为可辩护底线)。
11. **信息项 #6: SysWOW64 与 x64 同源偏置** (§F.2) — 本 run 用 d3dx9/msvbvm60/mfc42 (2005-2011) + PhysX/Delphi/Steam 第三方缓解; 1990s 存量仍缺, x87 三角洲 (d3dx9 层 7-13%) 是可得数字的**下界**。

## §8 结论

✅ **侦察五路全部出数**: 覆盖率总数字 (95.74%/98.72%, 形级诚实下界 92-94%) + 对账矩阵 50+ 行 + x87 三路线可裁决表 + asmgen XL 四子项拆解 (A45/B25/C5 档 + 池 14→6 临时 10→2 + callgate st0 FP + 单点 RIP) + 冻结面零触碰方案 + X1-X5 蓝图 (x87 悬置可保留到 X2a 后, 不阻塞开工)。
**两个 🔴/🟡 级实施输入**: ret imm16 栈清理语义必须在 X1 落地 (否则 stdcall 虚拟化 = 行为错误); SEH/FS gate 文档化必须显式点名。
主仓 main 零扰动 (worktree 已拆, tracked 零脏), run 对账 ≈ 140 分钟。x87 三路线数字已备, D1 裁决权在项目主。

## §9 留样附录 (关键源码/命令内嵌, 416/424/426 纪律)

### §9.1 扫描脚本 scan_pe32.py (核心; 完整版 = 线性 + 递归双通道, 见 §1.1 方法)

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
X87_FIRST = set(range(0xD8, 0xE0)) | {0x9B}   # x87 = 首字节 D8..DF (+9B)
SEG_FIRST = {0x2E:'cs',0x36:'ss',0x3E:'ds',0x26:'es',0x64:'fs',0x65:'gs'}
# PE32 判定: MZ + PE\0\0 + machine==0x14C; .text 域 = 节表 raw ptr/size (可执行节回退)
md = Cs(CS_ARCH_X86, CS_MODE_32)              # 与 424 唯一差异 = CS_MODE_32
md.skipdata = True                            # 单字节重同步; '.byte' 伪指令计入 data_bytes
for insn in md.disasm(raw_text, text_va):     # 线性全扫 (无 .pdata → 整节)
    m = insn.mnemonic; mn[m] += 1
    b0 = insn.bytes[0]
    if b0 in X87_FIRST: fam['x87'] += 1       # 递归对账: 代码密集 DLL 下 linear≈recursive
    if b0 in (0xC4,0xC5) and m.startswith('v'): fam['vex'] += 1   # C4/C5 在 32 位是 LES/LDS!
    if b0 in SEG_FIRST: fam['seg_'+SEG_FIRST[b0]] += 1
    if b0 == 0x66: fam['p66'] += 1
# 噪声指纹族 (剔除): outsd/outsb/insb/insd/popal/pushal/arpl/aas/daa/das/bound/aaa/aam/aad/les/lds/into/int3
# 递归通道: 种子 = entry + 导出表(≤300), 直接 jmp/jcc/call BFS, 单跑 ≤15 万指令上限
```

### §9.2 映射脚本 map3.py 判据 (三态字典, 全文见扫描 jsonl 留样思路)

```python
DIRECT = {'mov','lea','add','sub','and','or','xor','cmp','test','inc','dec','neg','not',
          'shl','shr','sar','rol','ror','adc','sbb','imul','mul','div','idiv','cdq',
          'movzx','movsx','bswap','xchg','xadd','cmpxchg', setcc16, cmovcc16, jcc16,
          'jmp','call','ret','nop','push','pop',
          'rep movsb','rep movsd','rep stosb','rep stosd','repne scasb','repe cmpsb',...,
          # SSE/AVX-legacy 全族 (编码 x86/x64 相同): movss/movsd/movaps/movups/movdqa/movdqu/
          # movd/movq/addss..divpd/xorps..andnpd/pand/por/pxor/pandn/ucomiss..comisd + BMI G8a
          'andn','bzhi','rorx','shlx','sarx','shrx','popcnt','lzcnt','tzcnt'}
FORK   = {'movsd':'plain A5 串形不在 G3 F3/F2 闸内',
          'ret':'ret imm16 stdcall 清栈 (msvbvm60 82%/dxcompiler 49% of ret), VM 语义未实现',
          'call':'call [mem] (IAT thunk) 拒 → C3 x86 fork', 'push':'push [mem]+4B 栈宽',
          'bts':'reg 形 gate (G4 mem-only)','movq':'mm 形 gate (G1c D2)',...}
# 其余 = missing: x87 全族 / leave / shld/shrd / bt / lahf/sahf / loop 族 / jecxz / pushad /
#         cwde / plain lodsd/stosd / cld / int/in/out / BCD legacy / SSE2 转换数学族 /
#         movlpd(movh*) / fence 族 / fs:[..] 段覆盖 / MMX mm 形 (维持 G1c D2)
# 局限披露: 助记符级分类对 call/jmp/ret 的 mem/imm 形不敏感 → 形级修正人工标注 (§5.3 注)
```

### §9.3 探针源码 (probe_fp.c 全文; 其余 5 探针同构, /Od+/O2 双档)

```c
#include <stddef.h>
double vec_dot(const double* a, const double* b, int n){ double s=0; for(int i=0;i<n;i++) s+=a[i]*b[i]; return s; }
float poly(float x){ return ((2.5f*x + 1.2f)*x - 0.7f)*x + 3.14f; }
double hypot2(double a, double b){ return a*a + b*b; }
int fcmp(double a, double b){ return a > b ? 1 : (a < b ? -1 : 0); }
double lerp(double t, double a, double b){ return a + t*(b-a); }
float vec4_add(const float* x, const float* y, float* out){ for(int i=0;i<4;i++) out[i]=x[i]+y[i]; return out[0]; }
double int_to_fp(int i){ return (double)i * 1.5; }
```

构建命令 (探针 DLL 化便于扫描):

```
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvarsamd64_x86.bat"
cl /nologo /utf-8 /Zi /LD /MD /O2 /FAcs /Fafp_O2_sse2.asm /Fefp_O2_sse2.dll probe_fp.c
cl ... /arch:IA32 → fp_O2_ia32.dll ; /arch:SSE → fp_O2_sse.dll ; /arch:AVX → fp_O2_avx.dll
```

### §9.4 ml.exe marker 样本 (rgn_sse/rgn_x87 区域全文; 全 7 区域同构)

```asm
.586
.XMM                          ; 缺此行 → SSE 全部 A2085 "instruction not accepted in current CPU mode"
.model flat, c
.code
rgn_sse PROC
    jmp @F
    db 057h,056h,04Dh,050h,042h,045h,047h,031h   ; "WVMPBEG1" (ml 源用 db, 非内联 _emit)
@@:
    movss xmm0, dword ptr [esp+4]                ; SSE mem 形必须显式 size 前缀
    movss xmm1, dword ptr [esp+8]
    addss xmm0, xmm1
    mulss xmm0, xmm1
    divss xmm0, xmm2
    subss xmm0, xmm1
    movaps xmm3, xmm0
    movups xmmword ptr [esp-24], xmm3
    ucomiss xmm0, xmm1
    jae  sse_done
    xorps xmm4, xmm4
    andps xmm4, xmm3
sse_done:
    jmp @F
    db 057h,056h,04Dh,050h,045h,04Eh,044h,031h   ; "WVMPEND1"
@@:
    ret
rgn_sse ENDP
; rgn_x87: fld dword ptr [esp+4] / fld / fmul st, st(1) / faddp st(2), st /
;          fstp qword ptr [esp-32] / fnstsw ax / fxch st(1) / fcomp (同构 magic 包裹)
END
```

```
ml /nologo /c /Coff x86_marker_sample.asm
cl /nologo /utf-8 /O1 /MD /c main_x86.c
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 main_x86.obj x86_marker_sample.obj /OUT:x86_marker_sample.exe
x86_marker_sample.exe   → rc=0 (输出 529 39 536870911 99 5)
```

### §9.5 硬拒亲验命令

```
wvmp_cli.exe protect --config hard_reject.toml
; toml: input = "<PE32 副本>" / output / seed=12345 / 六 pass 管道 (e2e.sh 同款)
; → [error] pe_loader: 32 位目标 (x86) 未支持 (GAPS C5); 不产出保护壳 ; rc=2 ; 无输出落盘
```

== MIT-X0 triage 完 ==
