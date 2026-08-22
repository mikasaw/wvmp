# WVmp 契约与扩展点（P0 冻结版）

本文档描述 WVmp 的三类扩展点、三层粒度模型、跨模块 key 常量以及契约变更流程。
所有列出的头文件为**冻结契约**：接口语义不得在泳道内擅自变更。

## 1. 三类扩展点

| 扩展点 | 契约头文件 | 接入方式 | 说明 |
|---|---|---|---|
| 流程 Pass | `framework/include/wvmp/framework/pass.hpp`、`registry.hpp` | 实现抽象类 `Pass`，源文件内 `WVMP_REGISTER_PASS(Type)` 静态注册到 `PassRegistry`，由 `Pipeline::from_names` 组装执行 | 管道中的任意阶段：加载、分析、变换、发射、写出 |
| VM 后端 | `vm/include/wvmp/vm/backend.hpp`（`VMBackend`） | `wvmp::vm::create_backend(name)` 工厂按名创建 | IR → 虚拟机字节码编译 + 运行时镜像生成；RegVM（`vm/regvm/`）为默认后端 |
| 字节码编解码器 | `vm/include/wvmp/vm/backend.hpp`（`BytecodeCodec`） | `VMBackend::set_codec(codec)` 注入 | 字节码流的加密/解密策略，与后端正交组合（`vm/regvm/codecs/` 提供实现） |

## 2. 三层粒度（红线）

1. **插件层**：新增/替换 Pass、VM 后端、BytecodeCodec 时，只能通过上述三个注册机制接入；不允许修改管道骨架、根 `CMakeLists.txt` 与 `passes/CMakeLists.txt`（后两者归协调者）。
2. **契约层**：各模块 `include/wvmp/**` 下的冻结头文件（见 §4 清单）是模块间唯一合法接口；跨模块引用只能 include 契约头。
3. **私有实现红线**：各模块 `src/**` 与模块内部结构（含 `vm/regvm/{isa,translator,runtime,codecs}` 的内部实现）属于模块私有；其他泳道不得依赖、不得 include、不得修改。

## 3. 跨模块 key 常量（`framework/include/wvmp/framework/keys.hpp`）

| 常量 | 值 | 产出者 | 消费者 |
|---|---|---|---|
| `kImage` | `image` | `pe_loader`（核心字段 `ctx.image`） | 所有读取/改写 PE 的 pass（`pe_writer` requires） |
| `kFunctions` | `functions` | `marker_scan`（核心字段 `ctx.functions`） | `lifter` |
| `kLiftedIr` | `ir.lifted` | `lifter` | `mutate`、`virtualize` |
| `kVmProgram` | `vm.program` | `virtualize` | `crypt`、`stub_link` |
| `kVmRuntime` | `vm.runtime` | `stub_link` | `pe_writer`、完整性校验 |
| `kNewSections` | `pe.new_sections` | 需要新增节的 pass | `pe_writer` |

核心字段只有六个（`input_path`/`output_path`/`image`/`functions`/`seed`/`rng`，外加 `diag`）；
其余一切跨 pass 数据必须通过 `ctx.slot<T>(key)` 类型安全扩展槽传递。

## 4. 冻结契约头文件清单

- `common/include/wvmp/common/`：`types.hpp`、`rng.hpp`、`bytes.hpp`
- `ir/include/wvmp/ir/`：`arch.hpp`、`reg.hpp`、`operand.hpp`、`insn.hpp`、`region.hpp`
- `framework/include/wvmp/framework/`：`phase.hpp`、`diagnostics.hpp`、`context.hpp`、`pass.hpp`、`keys.hpp`、`registry.hpp`、`pipeline.hpp`
- `vm/include/wvmp/vm/`：`backend.hpp`

## 5. 契约变更流程

任何对上述头文件的接口变更（增删函数、改签名/语义、改枚举值）**必须报协调者**，
由协调者评估影响面、同步所有受影响泳道后统一落地；泳道内自行修改契约视为事故，
回滚并重做。新增 key 常量同样先在本文档登记再使用。
