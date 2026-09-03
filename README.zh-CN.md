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
:: tests/wvmpTest/ 已在主仓内（与 WVmp 同源）；直接构建再跑烟测:
cd tests\wvmpTest
call build.bat x64
cd ..\..
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
| M3 保护表面（下方工作流 1-5）| 六条工作流排队待派（见后续开发计划）|
| 扩展表面（下方工作流 7-9）| 三条工作流 park，等触发（见后续开发计划）|
| 产品表面（下方工作流 6）| 一条工作流，依赖工作流 1-5（见后续开发计划）|

## 后续开发计划

M2.5-G + M2.5-X 收官后，还排有 **9 条能力工作流**。它们是 WVmp 的**独立产品**（不是 M2.5-X 的"阶段"）——每条都有自己的范围、前置条件、派单计划。按**路线图顺序**（数据侧 → 产品表面）排序，而非优先级。

`passes/` 下五个保护 pass（`anti_debug` / `crypt` / `integrity_crc` / `import_protect` / `mutate`）以及 `vm/regvm/codecs/` 模块当前都是占位（见 `docs/STATUS.md`「M3 插件池 ⏳ 未开始」）。工作流 1-5 是这些占位如何变成实产品的路径。工作流 7-9 把保护表面扩展到更宽范围（驱动 / VM 检测 / 主机 OS 表层）并显式 park 等外部触发。

### 工作流 1：字节码密码学混淆

填实 `passes/crypt/src/crypt_pass.cpp` 的占位，并实现 `vm/regvm/codecs/` 中的 codec 接口占位。

- **做什么**：虚拟化后对 VM 字节码流加密，把解密元数据嵌入 stub，入口处按需解码。marker-pair magic 与 VM 程序与运行时解码器不可分割。
- **为何排第一**：爆炸半径最小（一个 pass + 一个 codec 模块）、无跨 pass 依赖、可端到端验证 codec / 往返契约。
- **派单前需锁定的开放设计决策**：
  - **密码原语**——AES-NI（快、可识别签名）/ 自研 S-box（无签名、较慢）/ VM 仿真（与现有保护同态、最慢）。
  - **密钥包**——每目标嵌入（当前 marker-magic 方式、离线运行时）/ 服务端拉取（防篡改、需在线运行时）。
  - **威胁模型**——交互式调试器 / 自动污点分析 / 大规模扫描器——不同模型偏向不同密码选择。
- **工作量**：1 张单架构派活单，2-3 天。

### 工作流 2：指令级代码变异

填实 `passes/mutate/src/mutate_pass.cpp` 的占位。

- **做什么**：在 VM 字节码产出**之前**改写 lifted IR——死码插入、等价替换、伪控制流——以 `ctx.seed` 为种子确定性执行。提升反语义成本但不变更语义。
- **为何排第二**：低风险（纯 IR 变换、无运行时依赖），复用现有冻结的 IR 载体域。
- **开放问题**：
  - **强度/成本权衡**——变异密度同时影响运行时性能与反语义难度；需校准到目标比值。
  - **确定性**——种子可复现是硬要求（测试基线稳定性）。
- **工作量**：1 张单架构派活单，2-3 天。

### 工作流 3：反调试 / 反插桩加固

填实 `passes/anti_debug/src/anti_debug_pass.cpp` 的占位。

- **做什么**：产出反调试检查（PEB.BeingDebugged、硬件断点、NtQuery 变体、时序攻击）与反插桩护栏（ProcessInstrumentationCallback、debug break-in hooks），写入保护镜像。
- **为何排第三**：与密码/变异独立，但需要**运行时 stub 表面**——当前 `stub_link` 接口尚未提供。在 pass 有意义前需要先做一次小扩展。
- **开放问题**：
  - **仅用户态** vs **用户态 + 内核态**——内核 hook 需要独立的 SYS 运行时；当前范围仅用户态。
  - **反 DBI 策略**——ProcessInstrumentationCallback 是 Win10+ 特性；XP/Vista 覆盖需要替代方案。
- **工作量**：2 张子派活单（stub 扩展 + pass 实施），合计 3-4 天。

### 工作流 4：导入保护（IAT 加固）

填实 `passes/import_protect/src/import_protect_pass.cpp` 的占位。

- **做什么**：改写导入目录，让 API 调用通过保护 stub 路由。IAT 项加密、首次调用惰性解析、每函数独立密钥。
- **为何排第四**：与字节码密码（工作流 1）互补——合在一起防止 VM 程序与 API 调用面被静态提取。复用现有 `passes/stub_link/` 基础设施。
- **开放问题**：
  - **惰性 vs 即时解析**——即时更简单但泄露"含哪些导入"；惰性需 stub 内的运行时解码器。
  - **SDK API 分离**——SDK 函数（加载期辅助）需与用户导入 API 走独立代码路径。
- **工作量**：1 张单架构派活单，2-3 天。

### 工作流 5：运行时完整性校验

填实 `passes/integrity_crc/src/integrity_crc_pass.cpp` 的占位。

- **做什么**：构建时对保护段算摘要、嵌入校验数据；运行时加载期自检（含防篡改响应）。
- **为何排第五**：收尾防篡改环——即使工作流 1-4 被绕过，运行时仍可检测到保护镜像构建后被修改。
- **开放问题**：
  - **校验粒度**——整段 / 每函数 / 每 VM 区域。每区域最强但开销最大。
  - **触发策略**——仅加载期 / 周期性 / 敏感调用时检测。各有不同性能/防篡改权衡。
- **工作量**：1 张单架构派活单，1-2 天。

### 工作流 6：独立 GUI

全新顶层交付物。当前 CLI（`cli/src/main.cpp`）是唯一接口。工作流 6 在 CLI 子进程基础上增加独立 GUI。

- **做什么**：项目管理（加载/保存 WVmp 项目文件）、保护区域选择可视化、按 pass 配置面板、实时编译日志、带 marker 高亮的代码预览。
- **为何排第六**：依赖工作流 1-5 都有可配置的真实选项。无真实 pass 选项的 GUI 只是 CLI 的 chrome 壳。
- **派单前需锁定的范围决策**：
  - **GUI 框架**——Qt（工业标准，商业用途付费许可）/ wxWidgets（宽松许可、生态较小）/ Dear ImGui + 原生窗口（开发者友好、不够精致）。每种选择需检查与 WVmp MIT 许可的兼容性。
  - **OS 目标**——先 Windows-only，跨平台延后（与当前 WVmp 范围匹配）。
  - **进程模型**——GUI 是薄壳层，spawn `wvmp_cli.exe` 子进程并解析其输出。**不**与 passes/ 直接进程内链接。
- **工作量**：设计 + 骨架 2-3 天，功能完整 5-7 天。这是**单张大派活单**（或两张——GUI 骨架 + 功能接线），而非多工作流。

### 工作流 7：Windows 内核驱动保护

独立代码路径，有自己的 SYS 运行时。当前 WVmp 严格只做用户态 PE 可执行文件。

- **做什么**：保护 `.sys` 驱动二进制——独立的 VM 运行时，在 IRQL ≥ DISPATCH_LEVEL 运行，针对内核调试器附加（KdDebuggerEnabled / KdTransportMaxPacketSize）硬化，DriverUnload hook 透明化。
- **当前状态**：park，未派。
- **为何 park**：
  - 需要**独立 SYS 运行时**（现有用户态运行时依赖用户态 API 表）。
  - **测试基础设施不同**（内核验证器、WinDbg 内核模式、驱动加载测试工具）。
  - **威胁模型不同**（内核态对手：内核补丁保护、PatchGuard、签名驱动旁路）。
  - **当前无客户拉动**内核驱动保护。
- **解 park 触发条件**（任一）：
  - 客户明确请求 `.sys` 驱动保护场景。
  - 内部决定进入驱动保护产品线（商业决策）。
  - 相邻研究需求（例如某项新技术只在内核态有意义）。
- **工作量**：5-10 天设计 + 2-3 派活单循环（与工作流 1-5 独立）。

### 工作流 8：反 VM / 反沙箱检测

检测保护程序是否在分析环境（hypervisor、沙箱、DBI 框架）内运行。

- **做什么**：产出分析环境检测例程——CPUID hypervisor-present 位、固件表厂商扫描、沙箱 API 痕迹、时序检测变体。挂接在现有 `passes/anti_debug/` 基础设施上但作用于不同轴。
- **当前状态**：部分覆盖（部分保护工具中已有 CPUID 厂商扫描），未作为聚焦工作量派发。
- **为何未作为早期独立工作流**：
  - **相邻工作流已有部分覆盖**（反调试检查、完整性校验）；提升为独立是增量而非绿地。
  - **启发式维护代价**：VM/沙箱检测签名比 VM 加固的 churn 快得多（分析厂商持续增加规避策略）。需要持续维护，不是一次性派单。
  - **误报风险**：激进 VM 检测会破坏合法用户（如在 Hyper-V、WSL2、杀毒沙箱下运行的用户）。
- **解 park 触发条件**（任一）：
  - 客户明确请求"挫败大规模扫描器管线"（工作流 1 威胁模型变种）。
  - 真实世界规避事件（某主要分析厂商成功绕过当前保护）。
  - 内部决定针对特定对手类硬化。
- **工作量**：1-2 次设计会话 + 1-2 派活单，**外加**后续维护预算。

### 工作流 9：虚拟文件系统 / 虚拟注册表

基于 hook 的主机 OS 文件与注册表 I/O 重定向——模拟资源加密内嵌在保护镜像内。

- **做什么**：改写 Win32 文件/注册表 API 调用（`CreateFile`、`RegOpenKeyEx` 等）让其路由到自定义派发器。资源看似来自"虚拟"位置，实际是按需解密自内嵌 bundle。
- **当前状态**：park，未派。**无占位基础设施**。
- **为何 park**：
  - **主机 OS 表层，非 VM 保护层**——保护原语的价值在 IR → VM 字节码层；OS 表层保护是不同产品层。
  - **需要 inline API hook 框架**——ntdll/kernel32 hook 链、hook 安全性验证、WoW64 分割。基础设施成本巨大。
  - **维护负担高**——Windows API 表跨版本变化；hook 点位置漂移。
- **解 park 触发条件**（任一）：
  - 客户请求"加密内嵌资源"（商业产品特性）。
  - 相邻需求（例如工作流 1 密钥包可自然延伸为虚拟文件系统密钥）。
  - 内部决定硬化 OS 表层（产品线决策）。
- **工作量**：2-3 周设计 + 3-4 派活单循环。**注意**：与工作流 1-5 全部加起来量级相当——是重大承诺。

### 排序原则

9 条工作流按**路线图顺序**（而非优先级）排序：

**主动表面（工作流 1-5）**：用户态 PE 可执行文件的保护 pass。

1. **工作流 1（crypt）**——执行侧范围最小；codec 占位可验证往返契约。
2. **工作流 2（mutate）**——IR 层、无运行时依赖，与工作流 1 的 codec 共享发射形态时协同。
3. **工作流 3（anti_debug）**——需 stub 表面扩展，搭在工作流 1+2 的发射器之上。
4. **工作流 4（import_protect）**——依赖工作流 1 的惰性解析 codec，搭在 `passes/stub_link/` 之上。
5. **工作流 5（integrity_crc）**——最后一道保护层，收尾防篡改环。

**产品表面（工作流 6）**：独立 GUI 消费工作流 1-5。

6. **工作流 6（GUI）**——完全依赖工作流 1-5 提供可暴露的真实选项。

**扩展表面（工作流 7-9）**：park，需外部触发。

7. **工作流 7（kernel-driver）**——独立运行时；需客户拉动。
8. **工作流 8（anti-VM/anti-sandbox）**——部分覆盖；需针对特定对手决策。
9. **工作流 9（virtual FS / virtual registry）**——主机 OS 表层；量级巨大，需产品线决策。

若团队收到外部新优先级（如客户紧急需要反调试），工作流 1-5 可前跳；若客户明确拉动工作流 7-9，那些可前跳。每条工作流的前置条件应被尊重。**工作流 1-5**组成 **M3 保护表面**；**工作流 6**是 **M3 产品表面**；**工作流 7-9**组成 **扩展表面**，park 等外部触发。

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