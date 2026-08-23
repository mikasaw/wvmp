# WVmp 开发状态快照

> 更新时间：2026-08-23（M0/M1 完成后、M2 集成前的收尾点）

## 里程碑总览

| 里程碑 | 状态 | 提交 | 验收证据 |
|---|---|---|---|
| M0 契约冻结 | ✅ | `94da01f` `b463ecd` | 全部契约头编译通过，11 pass 占位注册可发现 |
| B 阶段六泳道 | ✅ | `4fa7507`…`0363a44` | 各泳道单测绿（详见下表） |
| M1 空管道集成 | ✅ | `63ebe19` | 真管道 E2E：保护后程序行为逐字节一致，唯一差异为补算 CheckSum |
| P5 翻译器 | ✅ | `95822ac` | 17 用例（含参考解释器语义端到端） |
| P6 运行时+stub | ✅ | `1263bd4` | RWX 真执行语义电池 + 5 种子随机化稳定性 |
| VS 解决方案支持 | ✅ | `b9eb605` | `build\vs\wvmp.slnx`（CMake 4.x 新格式），MSBuild 验证通过 |
| **M2 虚拟化集成** | ⏳ 未开始 | — | 三组件（lifter/translator/runtime）各自就绪待串联 |
| M3 插件池 | ⏳ 未开始 | — | T1~T9 |

## 测试清单（13/13 套件绿，本地 MSVC 19.51 / Debug / x64）

framework_tests(9) · regvm_isa_tests(9, 含万条 fuzz) · regvm_translator_tests(17) ·
regvm_runtime_tests(3 套) · pe_loader_tests(10) · pe_writer_tests(7) ·
marker_scan(18) · lifter_tests(30) · stub_link_tests(3) ·
cli_config_and_args(12) · cli_default_config(2) · p0_smoke · pass_registration

构建：`scripts\build.bat`（Ninja）/ `scripts\open-vs.bat`（VS 解决方案）；
测试：`scripts\test.bat`。

## 已知重要教训（写代码前先读）

1. **Keystone Intel 语法裸多位数字按十六进制解析**（"22"→0x22=34）。生成汇编里
   所有立即数/位移必须经 `imm()`/`hex()` 辅助（P6 排查中四处中招，其一在测试自身）。
2. **MSVC 链接器丢弃静态库中未引用的自注册对象**：消费 `wvmp_passes_all` 必须
   `$<LINK_LIBRARY:WHOLE_ARCHIVE,...>`；OBJECT 库作为 SOURCES 消费不传播 usage
   requirements，capstone 对象显式挂聚合库 INTERFACE。
3. **测试侧汇编同样会踩 1**；调试 JIT 生成码死循环的有效手段：dispatch 织入 pc
   镜像探针 + 看门狗线程采样（P6 实战）。
4. VS 生成器与 Ninja 不能共享 FetchContent subbuild（generator mismatch），
   VS preset 用独立 `.deps-vs`。

## 关键语义裁定（已固化在代码注释）

- `VmInsn.cond_or_size` 双语义：Jcc 存 ir::Cond，其余存 ir::Size。
- 翻译器 aux 立即数零扩展；负 disp 用 `Sub acc,|disp|`；mem-ALU 目的地址只算一次。
- Halt 写回 pc+1（恢复友好）；flags 位布局 ZF/CF/OF/SF/PF = bit0..4。
- `kPeImage` 为框架共享 key；marker_scan 经 PeImage 做偏移→RVA 换算。

## M2 待办（下次开工清单）

1. virtualize pass 接线：lifted IR → `create_backend("regvm")` → translate → VmProgram 入槽（注意 `vm/src/backend.cpp` 的 nullptr 兜底要换成 regvm 工厂）。
2. pe_writer 实现 add_section：新增 `.wvmp` 节，布局 `[runtime | blob | stubs]`（P6 的 stub_link 已产出 payload 雏形）。
3. 入口覆写：原区域 JMP stub；stub 保存现场→解释器→HALT→恢复。
4. 端到端验收：标记函数虚拟化后运行正确；启用 scripts/e2e.sh 实管道比对块。
5. P5/P6 遗留 TODO：call/rip-relative 走 gate 回退；flags 跨指令污染（M3 活跃性消除）。

## 测试补强方向（按优先级）

M2 端到端 → CI 实跑 + Release 矩阵 → pe_loader 畸形输入 fuzz → 覆盖率报告。
