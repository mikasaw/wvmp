# WVmp 架构总览

WVmp 是完全插件化的 PE x86/x64 虚拟机保护壳：输入一个 PE 文件，经加载、
标记扫描、提升为 IR、变形/虚拟化、壳代码发射，最后写出受保护的 PE。

## 目录职责

| 目录 | 目标 | 职责 |
|---|---|---|
| `common/` | `wvmp_common` | 基础类型别名、确定性 RNG、LE 字节读写 |
| `ir/` | `wvmp_ir` | 指令级中间表示（Op/Operand/Insn/BasicBlock/FunctionRegion） |
| `framework/` | `wvmp_framework` | Pass 抽象、管道、注册表、诊断、保护上下文 |
| `vm/` | `wvmp_vm` | VM 后端契约（`VMBackend`/`BytecodeCodec`/`create_backend`） |
| `vm/regvm/` | `wvmp_regvm` | 默认 RegVM 后端：`isa` / `translator` / `runtime` / `codecs` |
| `passes/` | `wvmp_passes_all` | 11 个内置 pass（OBJECT 库聚合为 STATIC，防 MSVC 丢弃自注册对象） |
| `sdk/` | `wvmp_sdk` | 受保护程序使用的标记宏 SDK（`WVMP_BEGIN`/`WVMP_END`） |
| `cli/` | `wvmp_cli` | 命令行入口 |
| `tools/` | `wvmp_tool` | 开发辅助工具 |
| `tests/` | `wvmp_unit_tests` | 单元测试 |

## 依赖方向（只允许向下）

```
cli / tools
   └─> passes (wvmp_passes_all) ──> framework ──> ir ──> common
              └────────> vm (契约: 依赖 framework + ir)
                            └─> regvm (实现 vm 契约)
```

- `common` 不依赖任何人；`ir` 只依赖 `common`；`framework` 依赖 `ir`（context 引用 ir 类型）与 `common`；
  `vm` 契约依赖 `framework`+`ir`；`passes` 依赖 `framework`/`ir`/`vm`；`cli`/`tools` 依赖 `wvmp_passes_all`。
- Phase 顺序：`Load → Analyze → Transform → Emit → Write`（`framework/phase.hpp`）。

## 默认管道

概念流程（`[]` 为可选阶段）：

```
parse_pe → scan_markers → lift → [mutate] → [virtualize] → [bytecode_encrypt] → [anti_debug] → emit_stub → write_pe
```

对应注册 pass 名：

| 概念阶段 | Pass | Phase | requires / provides |
|---|---|---|---|
| parse_pe | `pe_loader` | Load | provides `image` |
| scan_markers | `marker_scan` | Analyze | provides `functions` |
| lift | `lifter` | Analyze | requires `functions`，provides `ir.lifted` |
| [mutate] | `mutate` | Transform | — |
| [virtualize] | `virtualize` | Transform | requires `ir.lifted`，provides `vm.program` |
| [bytecode_encrypt] | `crypt` | Transform | —（作用于 `vm.program`） |
| [anti_debug] | `anti_debug` | Transform | — |
| emit_stub | `stub_link` | Emit | requires `vm.program` |
| write_pe | `pe_writer` | Write | requires `image` |

（`integrity_crc`、`import_protect` 为 Transform 阶段的可选增强 pass。）

## 构建与测试

- `scripts\build.bat`：vcvars64 + CMake(Ninja, Debug) 配置并构建（FetchContent 依赖落在 `.deps/`）
- `scripts\test.bat`：ctest 运行单元测试

详见 `README.md` 与 `docs/contracts.md`。
