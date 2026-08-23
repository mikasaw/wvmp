# WVmp 开发状态快照

> 更新时间：2026-08-23（M2 虚拟化集成完成、端到端验收通过）

## 里程碑总览

| 里程碑 | 状态 | 提交 | 验收证据 |
|---|---|---|---|
| M0 契约冻结 | ✅ | `94da01f` `b463ecd` | 全部契约头编译通过，11 pass 占位注册可发现 |
| B 阶段六泳道 | ✅ | `4fa7507`…`0363a44` | 各泳道单测绿（详见下表） |
| M1 空管道集成 | ✅ | `63ebe19` | 真管道 E2E：保护后程序行为逐字节一致，唯一差异为补算 CheckSum |
| P5 翻译器 | ✅ | `95822ac` | 17 用例（含参考解释器语义端到端） |
| P6 运行时+stub | ✅ | `1263bd4` | RWX 真执行语义电池 + 5 种子随机化稳定性 |
| VS 解决方案支持 | ✅ | `b9eb605` | `build\vs\wvmp.slnx`（CMake 4.x 新格式），MSBuild 验证通过 |
| **M2 虚拟化集成** | ✅ | `d88357c`…`c8dd070`（M2-1~M2-4） | 标记区域在生成解释器内真实执行，行为与原生逐字节一致（见下） |
| **MIT-243 C1 保守拦截** | ✅ | （本批次） | 翻译器 skip notes 经扩展槽传回，virtualize gate 遇 note 放弃虚拟化，区域保持原生；既有 M2-4 E2E 路径仍绿（M2-4 真实闭环白名单路径 + gate 路径均演示） |
| M3 插件池 | ⏳ 未开始 | — | T1~T9：mutate / 两档 crypt / anti_debug / integrity_crc / import_protect 等 |

## M2 交付明细

- **M2-1**（`d88357c`）：regvm 后端工厂接入 + virtualize pass 接线
  （lifted IR → `create_backend("regvm")` → translate → `vm.program` 入槽）。
- **M2-2**（`8067783`）：pe_writer 节注入 `add_sections`（`.wvmp` 新节 +
  section_builder，含独立单测套件）。
- **M2-3**（`6434b77`）：stub_link 完整 payload——运行时镜像 + blob + 入口 stub，
  原区域覆写跳板。
- **M2-4**（`c8dd070`）：端到端验收。带多轮循环的标记区域（真实内存 load/store、
  add、cmp、条件回跳）在解释器内执行，输出与原生逐字节一致。
  关键修复：stub 曾把自己 push/sub 后的 rsp 当 v4 预载，导致区域内 `[rsp+X]`
  全部落到调用者栈下方；改为 lea 恢复原始 rsp（经典 frame-base 陷阱，
  经单 store 二分样本 + asm dump + VM 指令解码器定位）。

## 测试清单（15/15 套件绿，本地 MSVC 19.51 / Debug / x64）

framework_tests(9) · regvm_isa_tests(9, 含万条 fuzz) · regvm_translator_tests(17) ·
regvm_runtime_tests(3 套) · pe_loader_tests(10) · pe_writer_tests(7) ·
section_builder_tests · marker_scan(18) · lifter_tests(30) · virtualize_tests ·
stub_link_tests(3) · cli_config_and_args(12) · cli_default_config(2) ·
p0_smoke · pass_registration

E2E：`scripts/e2e.sh build/m2_e2e/sample.exe` → PASS
（protect → run → stdout+退出码逐字节比对，入口 stub 断言）。

构建：`scripts\build.bat`（Ninja）/ `scripts\open-vs.bat`（VS 解决方案）；
测试：`scripts\test.bat`。

## 已知重要教训（写代码前先读）

1. **Keystone Intel 语法裸多位数字按十六进制解析**（"22"→0x22=34）。生成汇编里
   所有立即数/位移必须经 `imm()`/`hex()` 辅助（P6 排查中四处中招，其一在测试自身）。
2. **MSVC 链接器丢弃静态库中未引用的自注册对象**：消费 `wvmp_passes_all` 必须
   `$<LINK_LIBRARY:WHOLE_ARCHIVE,...>`；OBJECT 库作为 SOURCES 消费不传播 usage
   requirements，capstone 对象显式挂聚合库 INTERFACE。
3. **测试侧汇编同样会踩 1**；调试 JIT 生成码死循环的有效手段：dispatch 织入 pc
   镜像探针 + 看门狗线程采样（P6 实战）；M2 复用为 `WVMP_STUB_DUMP` asm dump 钩子。
4. VS 生成器与 Ninja 不能共享 FetchContent subbuild（generator mismatch），
   VS preset 用独立 `.deps-vs`。
5. **stub 的 rsp 语义 = 原始帧基址**：预载进 VM context 的必须是进入 stub 时刻的
   rsp（lea 恢复），不是 push/sub 之后的新栈顶（M2-4 实战）。

## 关键语义裁定（已固化在代码注释）

- `VmInsn.cond_or_size` 双语义：Jcc 存 ir::Cond，其余存 ir::Size。
- 翻译器 aux 立即数零扩展；负 disp 用 `Sub acc,|disp|`；mem-ALU 目的地址只算一次。
- Halt 写回 pc+1（恢复友好）；flags 位布局 ZF/CF/OF/SF/PF = bit0..4。
- `kPeImage` 为框架共享 key；marker_scan 经 PeImage 做偏移→RVA 换算。

## 正确性缺口（开工前必读 → docs/GAPS.md）

M2 验收通过 ≠ 完整加壳器。逐项核查确认的缺口按严重度记录在
`docs/GAPS.md`：C1 无 gate 回退（不支持指令被静默丢弃后原区域已被覆写）、
C2 运行时缺 Sar/Adc/Sbb handler（翻译成功但运行时中途 Halt）、
C3 区域内 call、C4 rip-relative、C5 x86 扫描不可用。
**当前仅"纯白名单指令、无调用、栈上计算"的区域可安全虚拟化。**

## M3 待办（下次开工清单）

前置：先做 GAPS.md 的 C1 保守拦截 + C2 handler 补齐（工作量小、
消灭静默破坏），再进入插件池：

按依赖与风险排序：

1. **crypt（blob 级）**：`BytecodeCodec::encrypt_stream` 已有实现，接线最短；
   注意 stub 侧解密路径与 seed 传递。
2. **mutate**：lifted IR 变换（死代码/替换/置换模板库），独立性最强；
   与虚拟化叠加时注意顺序（Transform 阶段 mutate 先于 virtualize）。
3. **anti_debug**：作为插件开发流程的验收样板（含 TLS 目录改动面，
   参考计划文档 loader.cc:1699 起）。
4. **integrity_crc / import_protect**：作用于 `.wvmp` 节与导入目录改写。
5. **配置系统**：每函数选 virtualization/mutation/ultra 及加密/反调试档位
   （TOML 已有基础）。
6. **多 VM 实例 / flags 活跃性消除**：性能与强度优化，最后做。

## 技术债（规划内，非缺陷；正确性问题见 docs/GAPS.md）

- lifter：cl 变体移位、rol/ror v1 跳过（`x86_translate.cpp` 记 TODO）。
- call / rip-relative 走 gate 回退路径（native 执行）——gate 本身未实现，见 GAPS C3/C4。
- flags 跨指令污染：待 M3 活跃性分析消除。
- marker_scan：仅 x64（GAPS C5）；O2 尾调用编成 E9 jmp（不产生 E8）不覆盖；
  函数名解析 TODO(P7-names)。
- x86 目标整体对齐仍在 backlog（当前主攻 x64）。

## 测试补强方向（按优先级）

CI 实跑 E2E + Release 构建矩阵 → pe_loader 畸形输入 fuzz →
保护后 PE 在全新环境运行验证 → 覆盖率报告。
