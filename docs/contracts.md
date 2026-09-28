# WVmp 契约与扩展点（P0 冻结版）

本文档描述 WVmp 的三类扩展点、三层粒度模型、跨模块 key 常量、契约变更流程，以及
`[[functions]]` 配置选择器的口径与仲裁序（§6，契约 C-A2）。
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
- `common/include/wvmp/`：`pe_layout.hpp`（MIT-531 起：OptionalHeader 目录偏移全仓单一真源，跨 pass 只读常量）
- `ir/include/wvmp/ir/`：`arch.hpp`、`reg.hpp`、`operand.hpp`、`insn.hpp`、`region.hpp`
- `framework/include/wvmp/framework/`：`phase.hpp`、`diagnostics.hpp`、`context.hpp`、`pass.hpp`、`keys.hpp`、`registry.hpp`、`pipeline.hpp`
- `vm/include/wvmp/vm/`：`backend.hpp`

## 5. 契约变更流程

任何对上述头文件的接口变更（增删函数、改签名/语义、改枚举值）**必须报协调者**，
由协调者评估影响面、同步所有受影响泳道后统一落地；泳道内自行修改契约视为事故，
回滚并重做。新增 key 常量同样先在本文档登记再使用。

## 6. `[[functions]]` 配置选择器与仲裁序（契约 C-A2，MIT-491）

适用面：`default_level` + `[[functions]]` 规则集。落点在
`framework/include/wvmp/framework/protect_levels.hpp`（**不在** §4 冻结清单内，
接口可按 §5 流程演进）：`wvmp::ProtectRules` 由 CLI 解析 TOML 后整体写入扩展槽
`kProtectRules`，消费方为 `virtualize` / `mutate`（档位面）与 `crypt`（加密覆写面）。

### 6.1 三个选择器的口径（唯一真源 = CLI 打印的区域清单）

| 选择器 | 口径 | 稳定性 |
|---|---|---|
| `rva = 0x…` | 区域 begin 标记 RVA（= `ir::FunctionRegion::begin_rva`，TOML 支持 `0x` 字面量） | 同版本产物内稳定 |
| `index = N` | `ctx.functions` 的**原始扫描序，0-based** | 跨重编译不稳（调试/临时用） |
| `name = "…"` | 标记函数真名（C++ SDK `WVMP_BEGIN(fn)` 串化；未解析到名字时 marker_scan 回退 `(marker@0x偏移)`） | 跨重编译稳定 |

三口径同源：`wvmp_cli protect` 的 stdout 行 `[wvmp] 区域清单: [0] tick rva=0x1110 [1] …`
—— 第 1 列就是 `index`、第 2 列就是 `name`、`rva=` 就是 `rva`。

⚠️ `index` **不是** `kVmProgram`（VM 程序列表）的下标。VirtualizePass 会跳过
`level=none`、无已 lift 基本块、C1 不可翻译 gate、`require_avx=false` gate 等区域，
`kVmProgram` 是被压缩后的列表；其下标只作为 `CryptPlan::vfs_index` 存在（stub_link
的密文↔程序配对键），与配置里的 `index` 无关。配置 `index` 由
`VirtualizedFunction::src_index`（VirtualizePass 赋的原始扫描序号）解释——
前置区域被跳过不改变后续区域的序号。手工构造 `kVmProgram`（未经 VirtualizePass）
时 `src_index` 保持 `kNoSrcIndex` 哨兵 = 不匹配任何 `index` 规则。

### 6.2 查询面签名（两面对等）

```cpp
ProtectLevel      level_for(u64 begin_rva, u64 src_index, std::string_view name) const;
std::optional<bool> crypt_for(u64 begin_rva, u64 src_index, std::string_view name) const;
// 上面两个查询的披露增强版（命中列表可读回，判定与 level_for / crypt_for 完全一致）
ProtectRules::LevelDecision  resolve_level(u64 begin_rva, u64 src_index, std::string_view name) const;
ProtectRules::CryptDecision  resolve_crypt(u64 begin_rva, u64 src_index, std::string_view name) const;
```

`src_index` 一律是 §6.1 的原始扫描序号。两面**共用同一套遍历**
（`matching_rule_indices`），不允许再出现第二套仲裁序。

### 6.3 仲裁序：声明序单遍，后声明者胜

1. 按 `[[functions]]` 的**声明顺序**单遍扫描全部规则；
2. 任一选择器（`name` / `index` / `rva`）命中该函数即覆写当前结果，**后声明者胜**；
3. **不存在选择器之间的优先级**（`rva` 不比 `index` 优先，`index` 不比 `name` 优先）；
4. 一条都没命中 → 档位面落到 `default_level`；crypt 面落到"无覆写 = 跟随管道全局行为"；
5. crypt 面只统计**显式写了** `crypt = true/false` 的规则；只写 `level` 的规则不参与
   crypt 仲裁（反之亦然：只写 `crypt` 的规则仍带 `level`，缺省 `level = "virtualize"`）。

> 历史：MIT-457~MIT-461 期间 `level_for` 不接 `name`，且是"index 先评、rva 后评"的两遍
> 序。后果即 CR-02：按 `name` 配 `level` 解析成功却永远查不到，保护面与用户意图相反。
> C-A2 起废除两遍序，本小节是唯一判据。

### 6.4 冲突处理：解析期拒同选择器，运行期披露跨选择器

| 情形 | 判定 |
|---|---|
| 同一条目写两个选择器（如 `name` + `rva`） | 解析期拒：`'rva'/'index'/'name' 只能选其一` |
| 同一选择器值出现两条规则（两条 `name="x"` / 两条 `index=1` / 两条 `rva=0x1000`） | 解析期拒：`选择器与前文规则重复（同一函数只允许一条规则）`——同选择器各只允许一条 |
| 不同选择器命中同一函数（如 `name="x"` level=none + `index=0` level=virtualize） | 解析期**不可**静态判定（`index` 要落到实际区域才知），故解析放行，按 §6.3 后评胜；消费方对命中 >1 条规则的函数记一条 Note 披露生效者与被覆写者，不留静默仲裁：**档位面**由 `virtualize` 披露（`resolve_level` 的 hits），**加密面**由 `crypt` 披露（`resolve_crypt` 的 hits） |

披露 Note 形态（`index=0` 声明在 `name` 之后 ⇒ index 条生效）：

```
[note] virtualize: 函数 (marker@0xca11) 命中 2 条 level 规则（跨选择器撞同一函数，按声明序后评胜）：生效 = 第 1 条 index=0 level=virtualize；被覆写 = 第 0 条 name='(marker@0xca11)' level=none
```

`第 k 条` = 该规则在 `[[functions]]` 中的声明序号（0-based）。`mutate` 消费同一档位面
但不重复披露（同一规则集下 `virtualize` 的 Note 已覆盖全部撞车点）。

### 6.5 可直接跑的实例与预测法

> 本小节的"实例"由 MIT-521（2026-09-19，分支 `mit-debt-a-docs` @ `0db5abf`）逐份真跑复算，
> 输入输出全部落在仓库内（MIT-492 语料内聚后，仓外 `wvmpTest` 已不是输入面）。
> §6.1~§6.4 的规则正文（选择器口径 / 查询面签名 / 仲裁序 / 冲突处理）**一字未改**——
> 本小节动的只是实例路径与期望读数。
>
> **无规则基线的实测出处**（两份实例共用同一个靶标）：在仓库根跑
> `build\cli\wvmp_cli.exe protect --config tests\wvmpTest\kernels.toml`（既无 `default_level`
> 也无 `[[functions]]`）⇒ `区域清单` 打印 `[0]`~`[29]` 共 **30** 条 + `stub_link: 已生成 29 个
> 入口 stub`。差的 1 区 = `[12] (marker@0xd73d)`（`kernels.cpp` 里的 `wv_lcg_next`）是**空打标
> 区域**：lifter 判"RVA 区间为空/非法，跳过"、virtualize 判"无已 lift 的基本块，跳过虚拟化"
> ⇒ 30−1=29。口径与成因见 `docs/GAPS.md`「语料口径：30 marker 区 − 1 空区 = 29 stub」小节。

实例 A —— 只放行按名字点名的一个函数进 VM（靶标 = `tests\wvmpTest\smoke_test.bat`
用的同一个 x64 test_target，区域清单 30 个 / 无规则基线 29 个入口 stub）：

```toml
# 在仓库根执行：input/output 是**进程 CWD** 的相对路径（与 tests\wvmpTest\kernels.toml 同口径）。
# input 先由 `tests\wvmpTest\build.bat x64` 产出（smoke_test.bat 走的同一个靶标）。
input  = "tests/wvmpTest/build/x64/test_target.exe"
output = "tests/wvmpTest/build/x64/packed_level_by_name.exe"
seed   = 12345

default_level = "none"          # 缺省：全部保持原生

[[functions]]                   # 只点名一个
name  = "(marker@0xca11)"       # 名字口径 = 区域清单第 2 列
level = "virtualize"

[[passes]]                      # 管道必须显式列出。缺这一段 = 空管道，CLI 只回显配置就
name = "pe_loader"              # 退出，一个 stub 也不生成（MIT-521 实测：修前两份实例都
[[passes]]                      # 漏了 [[passes]]，"可直接跑的实例"名不副实）
name = "marker_scan"
[[passes]]
name = "lifter"
[[passes]]
name = "virtualize"
[[passes]]
name = "stub_link"
[[passes]]
name = "pe_writer"
```

```
已生成 1 个入口 stub            ← 29 条 "按配置 level=none 保持原生" Note
```

（MIT-521 复算 = 实测值：`已生成 1 个入口 stub`，`按配置 level=none 保持原生` 的 Note **29**
条 = 30 区 − 被点名进 VM 的 1 区。）

CR-02 修复前同一配置的实读数：`无已虚拟化函数，跳过 stub 生成`（0 个 stub）——
`name` 规则对档位面完全无效。反向配置（`default_level` 缺省 virtualize + 同一条规则
改 `level = "none"`）实测 29 → **28** 个 stub（修复前恒为 29，排除不生效）。

实例 B —— 跨选择器撞同一函数（区域 `[0]` 同时被 `name` 与 `index=0` 指到），
两条都写、后声明者胜：

```toml
# 同上：仓库根执行、路径按 CWD 相对，input 由 `tests\wvmpTest\build.bat x64` 产出。
input  = "tests/wvmpTest/build/x64/test_target.exe"
output = "tests/wvmpTest/build/x64/packed_collision.exe"
seed   = 12345

[[functions]]                   # 声明序号 0
name  = "(marker@0xca11)"
level = "none"
[[functions]]                   # 声明序号 1 —— 与上条同指一函数，本条胜
index = 0
level = "virtualize"

[[passes]]                      # 管道必须显式列出。缺这一段 = 空管道，CLI 只回显配置就
name = "pe_loader"              # 退出，一个 stub 也不生成（MIT-521 实测：修前两份实例都
[[passes]]                      # 漏了 [[passes]]，"可直接跑的实例"名不副实）
name = "marker_scan"
[[passes]]
name = "lifter"
[[passes]]
name = "virtualize"
[[passes]]
name = "stub_link"
[[passes]]
name = "pe_writer"
```

```
已生成 29 个入口 stub           ← 与无规则基线同数（name 条的排除被 index 条覆写）
[note] virtualize: 函数 (marker@0xca11) 命中 2 条 level 规则（跨选择器撞同一函数，按声明序后评胜）：生效 = 第 1 条 index=0 level=virtualize；被覆写 = 第 0 条 name='(marker@0xca11)' level=none
```

同一对规则只动**声明序**、或只动**档位**，四种组合的实读（`index=0` 与 `name` 都指到区域
`[0]`；2026-09-19 MIT-521 逐组真跑，末列即该组 `stub_link` 的实际打印）：

| 声明序 0（先） | 声明序 1（后） | 生效者（后声明者胜） | 入口 stub 实读 |
|---|---|---|---|
| `name` = none | `index=0` = virtualize | 第 1 条 `index=0` virtualize | **29** ← 实例 B 本身 |
| `index=0` = virtualize | `name` = none | 第 1 条 `name` none | **28** ← 实例 B 两条**只对调顺序** |
| `name` = virtualize | `index=0` = none | 第 1 条 `index=0` none | **28** |
| `index=0` = none | `name` = virtualize | 第 1 条 `name` virtualize | **29** |

即：生效者只由声明序决定，**没有任何"选择器优先级"可依赖**；而最终生效的档位取的是**胜者
自己**那条的 `level`，不是"两条里较松的那个"——所以把实例 B 两条顺序对调，结果就从 29 翻到 28。

> **435 注记（上表由 MIT-521 立，被替换的原句照录于此、不回改历史）**：此处此前的表述按字面
> 跑会翻车，原文为：「两条对调声明序（`index = 0` 在前、`name` 在后）⇒ `生效 = 第 1 条
> name='(marker@0xca11)' level=virtualize`，读数仍是 29。」实例 B 两条的档位是 `name=none` /
> `index=virtualize`，只对调顺序 ⇒ 胜者换成 `name` 那条、档位随胜者 = none ⇒ 实读 **28** 而非
> 29；原文的"仍是 29"只对上表第 4 行（对调顺序**且**同时互换两条档位）才成立。§6.5 是现行为
> 口径而非历史读数，故按判据 3 改真值，原句留在本注记里可查。

预测任一配置对某函数的实际效果，四步：

1. 跑一次取 `区域清单`，得到该函数的 `index` / `name` / `rva` 三口径；
2. 收集**所有**命中它的规则（三选择器任一相等即命中；crypt 面还要求写了 `crypt`）；
3. 有命中 → 取声明序最后一条的 `level`（crypt 面同理取其 `crypt`）；
4. 无命中 → `default_level`（crypt 面无覆写 = 跟随管道全局行为）。

