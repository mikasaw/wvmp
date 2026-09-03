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