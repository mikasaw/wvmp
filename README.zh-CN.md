# WVmp（中文）

一个自研的 PE 虚拟机保护壳。将 x86/x64 Windows 可执行文件中的标记区域翻译为自研的寄存器式虚拟机（97 ops，跳表调度），通过 stub-link 派发回原 native 代码。

![x64 direct](https://img.shields.io/badge/x64_direct-99.26%25-brightgreen)
![x86 direct](https://img.shields.io/badge/x86_direct-95.15%25-green)
![wvmpTest x86](https://img.shields.io/badge/wvmpTest_x86-85.7%25-yellowgreen)
![main](https://img.shields.io/badge/main-0b6c5ba-blue)
![baseline](https://img.shields.io/badge/baseline-330%2F330-brightgreen)

> **语言**： [English](README.md) | **简体中文**

## 支持目标

| 架构 | Machine | 状态 |
|---|---|---|
| **x64 (PE32+)** | 0x8664 | **生产可用** |
| **x86 (PE32)** | 0x14C | **生产可用**（WOW64 已验证）|

Native 客户端代码路径不变。被标记的区域（两段连续 8 字节 magic）翻译为自研寄存器式虚拟机（97 ops，跳表 128 项）。输出在 `byte-exact` 校验下保持行为字节级一致——完整支持矩阵见 [docs/GAPS.md](docs/GAPS.md)。

## 永久 gate 边界（已文档化，非缺陷）

WVmp 把下列指令族**显式标记为永久 gate**——含这些指令的区域保持 native 执行，输出字节级一致，但**不进行虚拟化**：

| 指令族 | 为何永久 |
|---|---|
| **x87 FPU (D8-DF)** | MSVC 默认对浮点用 SSE ，x87 仅出现在 legacy 或 `/arch:IA32` 构建中。实现 x87 handler 会为极罕见的真实场景占用跳表槽位。（MIT-418 R3、MIT-445 §6 B 路线、MIT-455 B 路线关闭。）|
| **间接 jmp（`jmp [mem]`/`jmp reg`）** | 静态可分析的"表形"在 System32 / SysWOW64 全语料中占比 < 0.001%。主导形态（任意 mem/reg）需要 L 级运行时分析。（MIT-455 §3.2 关闭——维护销案。）|
| **mul64hi 类栈深边界** | x86 栈帧保存区是有限的。外层依赖需要前瞻式 ESP 同步——延后处理。|
| **SEH（`fs:[...]`）/段覆盖** | 需要与 Windows 异常派发器协作，超出当前研究线范围。 |

完整图景见 [docs/GAPS.md](docs/GAPS.md) §X7 收口节与 §Gate 分布表。

## 构建（Windows / MSVC / Ninja，需 VS 18 Insiders）

```bat
scripts\build.bat
```

首次运行通过 CMake FetchContent 拉取第三方依赖（googletest、capstone、keystone、tomlplusplus）到 `.deps/`，其中 keystone 编译较久。

## 测试

```bat
scripts\test.bat
```

## 端到端烟测（GitHub 复跑入口）

烟测脚本走完整流水线：构建 wvmpTest 靶 → 跑 native → 用 WVmp CLI 打壳 → 跑 packed → diff 输出。

```bat
:: 先克隆 wvmpTest 同级仓库:
git clone https://github.com/YOUR/wvmpTest ..\wvmpTest

:: 在 WVmp 仓根目录:
tests\wvmpTest\smoke_test.bat
```

脚本默认自动探测 `..\wvmpTest`；若放在其他位置用 `set WVMPTEST_DIR=path\to\wvmpTest` 覆盖。期望结果：

- native 与 packed 返回码均为 0
- diff 行数为 0（`image   :` 这一行被排除——它嵌入了绝对路径）
- native 的 SUMMARY 显示 `passed=94`

靶源码与构建脚本见 [tests/wvmpTest/](tests/wvmpTest/)。

## 覆盖率（X7 重扫，2026-09-03）

| 指标 | 数值 |
|---|---|
| **x64 助记符级 direct 覆盖率**（System32 103 文件 / 17.6M clean 指令）| **99.26%** |
| **x86 助记符级 direct 覆盖率**（SysWOW64 100 文件 + 第三方 + 扩展 / 27.4M clean 指令）| **95.15%** |
| **x64 函数级无 gate**（.pdata 函数域，240,277 函数）| **94.74%** |
| **wvmpTest x86 真虚拟化**（103 kernels，标记区域）| **12/14 = 85.7%** |

重扫脚本：[`scripts/verifier/mit_x7_rescan.py`](scripts/verifier/mit_x7_rescan.py)，产物在 [`scripts/verifier/mit_x7_rescan_out/`](scripts/verifier/mit_x7_rescan_out/)（215 行 jsonl + summary.json）。约 4 分钟可复跑：

```bat
python scripts\verifier\mit_x7_rescan.py
```

关于方法论的深度说明（x86 上无法严格函数级覆盖率的三层替代口径、双通道一致性断言）见 [docs/GAPS.md](docs/GAPS.md) §X7 收口节。

## Multica 工程化工作流

WVmp 自 2026-08-29 起通过 [multica](https://github.com/multica-ai/multica) 驱动开发——每一次能力扩展都是一条带项目主验证的派活单。

**24 单全部 ACCEPTED，0 拒绝 / 0 取消，覆盖两个里程碑：**
- **M2.5-G（指令虚拟化阶段）**——MIT-419 至 MIT-435，基线 240/240，已收官
- **M2.5-X（多目标平台阶段）**——MIT-436 至 MIT-455，基线 330/330，已收官

完整工单目录、纪律沉淀、累积教训见 [docs/MULTICA_ISSUES.md](docs/MULTICA_ISSUES.md)。

**原始 multica 工件**（155 文件 /451KB）单独打包供下载：`docs/multica-archive.tar.gz`。**此文件不入 git**，**（保持仓轻量）**。日常运营以 multica 面板为权威源。

## 项目状态

| 阶段 | 状态 |
|---|---|
| M2.5-G 指令虚拟化（x64） | 已完成（2026-08-31）|
| M2.5-X 多目标平台（x86 生产可用）| 已完成（2026-09-03）|
| X3d SSE-32 精化 | 数据已就绪，未排期 |
| `push_mem` x86（1.845%——x86 第一大非 x87 shape gate）| 数据已就绪，下一派活单候选 |
| M3 加密保护线（MIT-410）| park，待定优先级 |

## 后续开发计划

M2.5-G + M2.5-X 收官后还排有三条工作流，按**就绪度**（数据 → 决策 → 执行）排序，而非优先级。

### 工作流 1：`push_mem` x86（下一派活单候选）

**为何排第一**：单 shape gate、爆炸半径最小、ROI 最高。

- **目标 shape**：`push [mem]`——x86 上**最大**的非 x87 shape gate，影响 **1.845%** 全指令、跨 **92.9%** 语料文件。（X7 2026-09-03 实测，比 X0 预估值高 3.7 倍。）
- **形分布**（x86-only，X7 数据）：
  - `push_mem` 在非 x87 shape gate 中**绝对主导**（其他形状 sse_residual 2.41% / indirect_jmp 1.79% / system_legacy 1.35% / push_imm 0.049%——这些是 x64 侧数字；x86 侧分布完全反转）。
  - `push_mem` 家族本身在派单前需进一步 shape-class 拆解（memory 操作数形：`[reg]` / `[reg+disp]` / `[reg+reg*scale+disp]` / 段覆盖）。shape-class 拆解是本工作流的数据侧前置条件。
- **派单前的开放问题**：
  - **覆盖率**：实施 `push_mem` 后 wvmpTest x86 真虚拟化会从 12/14 → 几？需按 shape 测覆盖率再定规模。
  - **Stub-link 调度成本**：128 项跳表当前余量 31 项（97/128）。`push_mem` 单 shape 预计耗 ~3 项（按 memory 操作数形拆分可能更多）。
  - **x64 联动**：handler 是否同时服务 x64 对称情形？x86 memory 操作数编码与 x64 差异足够大需独立 handler 吗？——决策延后到派单时。
- **预期工作量**：1 张单架构派活单（X6 类），1-2 天。无跨架构影响。

### 工作流 2：X3d SSE-32 精化

**为何排第二**：已在 X6 部分实施（32 个 SSE op 覆盖），精化为增量工作。

- **当前状态**：32 个 SSE op 在 x86 handler 表中已生效（X6、MIT-454）。"32"指冻结枚举中含 SSE 形编码的 VmOp；Cvt/Shuf/Unpck/Sqrt 在冻结枚举中无对应 VmOp，走窄门（narrow-bar）路由。（见 GAPS.md §Cvt）
- **精化目标**：
  - 内存对齐 SSE 移动（`movaps` 与非对齐形）——目前折叠到单一 `VmOp::Movups`，非对齐形正确性未单独验证。
  - SSE 比较标志位：`ucomiss` / `ucomisd` 产出 EFLAGS 位，全标志位进位语义未单独验证。
  - `cvt*` 家族（整型↔浮点 / 浮点精度转换）：当前无 VmOp，走窄门路由。
- **开放问题**：
  - 真实语料频率：非对齐 SSE moves 与 `cvt*` 在 X7 语料中各出现多少？X0 估两者合计 ~0.5%；X7 数据未单独枚举这些 shape。
  - 标志位精度 vs 跳表槽位成本的权衡：实施标志位正确的 `cvt*` 可能为边际语料收益占多个跳表槽位。
- **预期工作量**：小到中等，取决于 X3d 侦察子任务数据；若派单可能 2-3 天。

### 工作流 3：M3 加密保护线（MIT-410）

**为何排第三（且当前 park）**：这是下一条主要研究线，不是 M2.5-X 的延续。范围与前置条件完全不同。

- **起源**：W14（2026-08-29）park，参见 `.multica/mit419-ruling.md` 第 7 行——"MIT-410 (M3 line)"反向引用。F1（marker-pair magic 的密码学混淆）与 F2（stub 调度中的密钥包）被勾勒为两个产品特性。
- **恢复前置条件**：
  - **F1 设计选择**：密码原语（AES-NI vs 自研 S-box vs VM 仿真密码）。每种威胁模型与性能特征不同。
  - **威胁模型定义**：对手是谁？调试器下的逆向工程师？自动污点分析？不同模型驱动不同密码选择。
  - **F2 密钥包分发**：密钥放在哪？每目标嵌入（marker magic 当前方式）vs 服务端拉取（防篡改）。影响离线 vs 在线运行时模型。
- **当前 park 的原因**：M2.5-X 收官确立保护原语在**非密码学**轴上已稳健（自研 VM 操作码）。密码学层是严格升级而非修补——没有产品 bug 强制推进。park 是**优先级问题**而非放弃。
- **预期工作量**：5-10 天设计 + 2-3 派活单循环，取决于 F1/F2 切分。

### 排序原则

三条工作流按**就绪度**（而非优先级）排序：

1. **`push_mem` x86**——执行侧数据已全；只差派活单决策。
2. **X3d SSE-32 精化**——X6 工作增量；可复用 X6 基线。
3. **M3 加密保护线**——新研究线；需设计决策后才能动数据侧。

若团队收到外部新优先级（如客户要求加密保护），顺序可对调——但 `push_mem` 默认仍是下一派活单候选。

### 明确延后（Out of scope）

以下事项**刻意不上路线图**，因为与当前研究方向不一致：

- **跨平台（Linux/macOS ELF/Mach-O）**——工具链与调用约定不同；需独立项目线。
- **反调试 / 反 VM / 反 DBI 加固**——反 RE 是不同产品层；不在本项目范围内。
- **GUI / IDE 插件**——CLI 唯一是有意为之。
- **x87 实施（B 路线）**——MIT-455 已正式销案（X7 数据：x64 .pdata 域含 x87 函数 = 0 个）。R-SSE-only 是永久定。

## 架构

```
[PE file]
   ↓ pe_loader
[Parsed image]（PE sections、imports、.pdata/.xdata）
   ↓ marker_scan            ← 检测两段连续 8 字节 magic
[Marked regions]
   ↓ lifter                 ← capstone 解码 → IR
[IR]                       ← 冻结载体域（ir::Op）
   ↓ virtualize             ← IR → VmOp 表（kVmOpMax=97）
[VmOp sequence]
   ↓ stub_link              ← 生成 stub 派发入口
[Protected PE]
```

实现位于 `vm/regvm/{backend,lifter,translator,runtime}/`，passes 注册在 `passes/{pe_loader,marker_scan,lifter,virtualize,stub_link,pe_writer}/`，CLI 在 `cli/`。

## 仓库结构

```
WVmp/
├── cli/                       # WVmp CLI（protect 子命令）
├── passes/                    # 流水线 passes（pe_loader、marker_scan、…）
├── vm/regvm/                  # VM 实现（lifter、translator、runtime、backend）
├── sdk/include/wvmp/          # 公共 SDK 头文件
├── docs/
│   ├── STATUS.md              # 当前权威阶段状态
│   ├── GAPS.md                # 完整支持矩阵 + X7 收口节
│   ├── MULTICA_ISSUES.md      # multica 工单目录（24 单）
│   └── multica-archive.tar.gz # 原始 multica 工件（不入 git）
├── scripts/
│   ├── build.bat              # MSVC + Ninja 构建
│   ├── test.bat               # ctest
│   ├── multiseed_e2e.sh       # 5-seed × 66 样本回归
│   └── verifier/
│       └── mit_x7_rescan.py   # 客户态覆盖率扫描器
├── tests/wvmpTest/            # 103-kernel 功能测试靶
│   ├── src/                   # test kernels 源码
│   ├── build.bat              # 构建 test_target.exe
│   ├── kernels.toml           # 靶的 WVmp CLI 配置
│   └── smoke_test.bat         # 端到端烟测入口
└── LICENSE                    # MIT
```

## 许可证

MIT。详见 [LICENSE](LICENSE)。

## 致谢

作为 CMake FetchContent 依赖的 capstone、keystone、googletest、tomlplusplus 项目以各自许可证包含。