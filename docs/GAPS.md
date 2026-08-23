# WVmp 正确性缺口清单（M2 完成后评估）

> 记录时间：2026-08-23。基于对 lifter / translator / runtime / stub_link /
> virtualize 源码的逐项核查。
>
> 结论：**最小垂直切片已真实闭环（白名单区域可真虚拟化），但尚不具备
> "任意标记函数都能安全处理"的完整加壳能力**。下述缺口按严重度排序，
> 其中 C1/C2 会在无告警的情况下产出行为错误的 PE，须优先解决。

## C1 无 gate 回退：不支持的指令被静默丢弃 🔴 最高优先级

**现状**

- 翻译器 `Translator::skip()`（`vm/regvm/translator/src/translator.cpp:192`）
  遇到不支持的操作只把 note 追加进 `result.notes`，然后丢弃该指令、返回 false；
- 后端 `RegVmBackend::compile()`（`vm/regvm/backend/src/regvm_backend.cpp:20-23`）
  调用 `translate_function(fn)` 后**只取 `.program`，notes 整个被丢掉**；
- virtualize pass 不感知任何 skip，照常入槽；
- stub_link 照常覆写 `.text` 原始字节（E9 rel32 + INT3 填充，
  `passes/stub_link/src/stub_link_pass.cpp:130-135`）。

**后果**：标记区域含任何白名单外指令 → 字节码缺一块 → 原始字节已被覆写
无法回头 → **产出行为错误的 PE，全程零告警**。

**修复方案（两步）**

1. 保守拦截（半天级）：backend 把 notes 传回；virtualize 凡发现该函数有
   任一 skip note 即放弃虚拟化（保持原生）。立刻消灭静默破坏。
2. 完整方案：VMProtect 式 native gate——区域按"可翻译段 / 不可翻译段"
   切块，不可翻译段回退原生执行后再 re-enter VM。工作量大，独立排期。

**验收**：含白名单外指令的标记函数保护后，输出 PE 行为与原生一致
（该函数整体保持原生），且 diag 有明确 Note。

## C2 运行时 handler 与翻译器能力不匹配：Sar/Adc/Sbb/Rol/Ror 是地雷

**现状**

- 翻译器能发射 `VmOp::Adc/Sbb/Sar/Rol/Ror`
  （translator.cpp:68-81，ir Op 映射齐全）；lifter 也接受对应 x86 指令
  （sar/adc/sbb 在白名单内，rol/ror 是 TODO 跳过所以实际到不了 runtime 的只有前三个+未来 rol/ror）；
- 但运行时 handler 表没有这几项，表项指向 **Halt**
  （`vm/regvm/runtime/src/asmgen.cpp:866-867` 注释明说："Adc/Sbb/Sar/Rol/Ror/
  Call/Ret 的表项指向 Halt"）。

**后果**：含 `sar`（有符号除法/取模极常见）、`adc/sbb`（多精度运算）的区域
会"翻译成功"，运行时却在中途停机、跳过剩余全部代码——同样是静默破坏，
且比 C1 更隐蔽（翻译层完全干净）。

**修复方案**：P6 方法论现成（RWX 真执行语义电池），为每个 op 补 handler +
语义用例 + 万条 fuzz 扩展。rol/ror 需先解除 lifter 的 todo()（x86_translate.cpp:374）
并处理 flags 中 CF/OF 的循环位语义。

**验收**：每个新 op 的真执行电池用例绿；含 sar/adc/sbb 循环的 E2E 样本 PASS。

## C3 区域内 call 不支持

- 翻译器直接 skip（translator.cpp:216-218，注释"建议 gate"）；runtime 同样落 Halt。
- 真实函数几乎必然调用其他函数/API。M2-4 样本是刻意避开调用的。
- 短期随 C1 的保守拦截兜底；长期需要 call gate（VM 内切原生 → 原生返回后
  re-enter）或 VM 间调用协议。依赖 C1 的分段基础设施。

## C4 rip-relative 内存操作数不支持

- lifter 能识别（映射到 `ir::Reg::Rip`，x86_translate.cpp:320），翻译器
  emit_address 明确拒绝（translator.cpp:193-194 "rip-relative 未支持"）。
- x64 下这是访问全局变量的标准形态（`mov eax, [rip+g_n]`），不支持则
  任何碰全局的函数都无法安全虚拟化。
- 短期随 C1 兜底；实现上可在翻译期把 rip 基址换算成绝对 RVA 并经
  stub 传入的 image base 计算（blob 里存 RVA，运行时加基址寄存器）。
  注意与重定位/ASLR 的配合。

## C5 x86 目标实际不可用

- marker_scan 仅支持 x64：magic 在 x86 上被拆成两条 imm32，不连续
  （marker_scan_pass.cpp:172 TODO(P7-x86)）。
- ISA/lifter 层有 X86 枚举与部分支持，但扫描这一环断了，双架构承诺
  目前只在底层兑现。作为 M3 后的独立里程碑排期。

## 保护强度缺口（= M3 内容，非正确性问题）

以下不影响"是否产出正确的 PE"，只影响保护强度：

| 项 | 现状 |
|---|---|
| crypt（blob 加密） | pass 占位；codec 织入点已预留未接线（regvm_backend.cpp:14-18） |
| mutate | pass 占位 |
| anti_debug | pass 占位 |
| integrity_crc / import_protect | pass 占位 |
| W^X 分离 | 单 RWX 节，解释器/字节码/stub 同节共存（stub_link_pass.cpp:27 注释明示 v1 取舍） |
| flags 活跃性消除 | 未做，跨指令污染靠全量更新兜底 |

## 建议处理顺序

1. **C1-保守拦截**（半天级）→ 消灭最大的静默破坏面
2. **C2 handler 补齐**（sar 最急，其次 adc/sbb）→ 白名单内不再有地雷
3. C4 rip-relative（解锁"访问全局的真实函数"）→ E2E 样本升级为含全局读写
4. C3 call gate（工作量最大，依赖 C1 分段）→ 解锁真实函数
5. C5 x86 对齐（独立里程碑）
6. 与 M3 插件池并行推进不冲突（不同代码面）
