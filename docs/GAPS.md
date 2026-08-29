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

1. **保守拦截（MIT-243，已落地）**：backend 把 notes 经 `ctx` 扩展槽
   `regvm.last_translate_notes` 传回；virtualize 凡发现该函数有任一 skip
   note 即放弃虚拟化（保持原生）。立刻消灭静默破坏。
2. 完整方案：VMProtect 式 native gate——区域按"可翻译段 / 不可翻译段"
   切块，不可翻译段回退原生执行后再 re-enter VM。工作量大，独立排期。

**验收**（MIT-243 全部命中）：
- 含白名单外指令的标记函数保护后，输出 PE 行为与原生一致（该函数整体
  保持原生），PE 差异仅剩 checksum 重算；
- diag 出现 `Severity::Note`：函数名 + 跳过原因（来自翻译器 notes）；
- 现有 15/15 单元测试 + E2E 全部仍绿；
- 新增正路径样本 `wvmp_whitelist_sample`（区域内纯 Mov/Add，无 loop/jcc/
  rip-relative），虚拟化正确生成 stub、行为在 VM 内执行、与原生逐字节一致。

**MIT-409 + MIT-413 (G2) 收口：跳转表特化（`jmp reg` / `jmp [mem]` 间接跳转）**
- 翻译期预扫描受限模板匹配（D1 决策 + G2 三参数扩面：宽度 / 基址语义 /
  MEM 源），`lea <b>,[rip+T]`（或 `mov <b>,VA` movabs 基址）→ `mov <ix>,
  [<b>+<idx>*scale+off]`（u32/u64 双宽度）→ [可选 `add <t>,<b>`] → `jmp
  <t>`（REG 源）或 `jmp [<b>+<idx>*scale+off]`（MEM 源，G2-b clang/GCC
  风格）；表长 K 仅认前块尾部防御常数——MSVC `cmp idx,K-1; ja`（K=imm+1）
  与 GCC `cmp idx,K; jae`（K=imm）双编码，严禁靠"扫到非法值"推导；
- 表项语义候选（首个全项通过者入选，区判据是唯一裁决者）：DeltaFromBase
  （表项 = 目标 RVA − 表基址 RVA，8B signed 含负 delta）/ DeltaFromJmp
  （GCC `.L4` 风格，基址即跳转点时与 DeltaFromBase 静态不可分）/ AbsoluteVa
  （表项 = 完整 VA，翻译期减 image_base 还原 RVA，G2-a）；
- 全部目标 ∈ 区域且为已 lift 指令地址才展开为比较链（`Mov s,rva_i;
  LeaRva s,s; Cmp t,s; Jcc eq → 块_i` ×K，MEM 源先物化表项
  `Mov s,idx; Shl; Add s,base; Load t,[s]` + delta 系锚定，零新 VmOp，
  预算 ≤32）；任一环节不符 → 照旧 gate（保守底线零让步），gate note 以
  "jump-table-gate" 前缀与命中 note 区分（backend diag 过滤不吞 gate）；
- 无防御表（G2-c）→ **永久 gate**（D2 裁决：表长不可推是保守哲学非
  laziness），以"疑似表形态但未检出防御常数"note 披露原因链。
- 残余间接跳转形态（留未来单，越界即 C1 gate 兜底）：
  - 不可枚举 `jump reg`（函数指针全局尾跳、运行时计算目标——MIT-409 负
    样本 wv_opaque_jmp_masm 实证照旧 gate 且行为一致）
  - `movsxd` 符号扩展表项读入（4B 负 delta 形态，MSVC 部分 codegen）
  - clang/GCC 真编译器产物兼容性未验证（本机无工具链，G2 样本为 MASM
    拼写等价字节形态；未来环境到位复跑，钩子见 .multica/mit413-ruling）
  - 表项含数据段交叉（表项指向 .data/.rdata 目标 → gate，G2 负例实证）

**已知遗留 / 范围外**
- SDK 桩函数去参清理（`marker_begin/end()` 不再带 `const char* name`）：
  因带参版本在每次 E8 调用点之前会生成 `lea rcx,[rip+name]`，该 lea 是
  rip-relative、白名单外，会被 C1 gate 拦下整段区域；带参实参从未被使用
  （见 `sdk/src/sdk.cpp` 原 `(void)name`），去参零行为差清理。
- 翻译器遇到越区 jcc（jcc 目标落在保护区域外，比如 `jge` 跳到 end E8）
  仍记 note 并被 gate 拦下——这是翻译器层面的待改进点（C1 已正确兜底，
  实际行为"行为正确但区域不虚拟化"，符合保守策略）。MIT-248（C4）
  或后续 native-gate 任务（M3+）可一并处理。

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

## C4 rip-relative 内存操作数不支持（GP 已 done；SSE mem 由 MIT-408 收口）

**现状（MIT-408 实测修正，旧文 "翻译器明确拒绝" 作废）**

- **GP(整数) rip 读/写路径已全线实现**（MIT-248，main eaa73af 起）：
  translator 五处 dst-rip→`StoreRva` + src-rip→`LoadRva` + `LeaRva`，
  movzx/movsx/alu-mem/单目全走 `emit_address`（翻译期把 [rip+disp] 换算成
  绝对 RVA，运行时经 LoadRva/StoreRva/LeaRva 加 image_base 还原 VA）；
  非 rip（base/index/scale 数组下标）走普通 Load/Store。MIT-248 双样本 +
  MIT-404 起注册 multiseed。
- **SSE 族 memory 形式由 MIT-408 收口**：lifter 五处 translate_sse_* 放开
  `X86_OP_MEM`（mem_operand 通用通道）；translator 经 `emit_address` +
  `LeaRva`（rip）→ 新原语 `XmmLoad`/`XmmStore`（宽度 4/8/16 经 aux，
  运行时一律 movups 非对齐语义）；ALU/ucomis 的 mem 源折条走 GP scratch
  双槽临时（v18..v23 两两作 xmm 宽，指令边界后即死，不动 VmContext 布局）。
  支持面：addss/addps/addpd/addsd、subss/subps/subpd/subsd、
  divss/divps/divpd/divsd、movss/movsd/movaps/movapd/movups/movupd、
  xorps/orps/andps、ucomiss/ucomisd（读 src=mem / 写 dst=mem 两类）。
- **MIT-411 (G1) 收口**：comiss/comisd（0F 2F / 66 0F 2F）折叠复用
  Ucomiss/Ucomisd（flags 语义逐位相同，SDM 真值表；#IA-on-QNaN 异常语义
  v1 不模拟，披露于 MIT-411 报告）；andpd/orpd/xorpd（66 0F 54/56/57）
  零新 VmOp 折叠复用 Andps/Orps/Xorps（128-bit 按位与后缀宽度无关，MSVC
  对 _mm_and_pd 等 intrinsic 自身即直出 ps 编码）。"`add/sub [mem],xmm`
  双访存"（C4c）经 MIT-411 实测判伪：SSE ALU 指令目标恒为 XMM 寄存器、
  内存只可能是源（ml64 A2000 + capstone 实证），真实"读→算→写回"语义 =
  movsd/addsd/movsd 三连，逐条已支持。
- **不支持面（越界即 C1 gate 兜底）**：andnps/andnpd（0F 55 系，留 412+）、
  AVX/x87/SSE2 整数族（movd/movdqa p 形式）、SSE mul 族
  （mulss/mulps/mulpd）。（string movsd 双形态已由 MIT-415 收口，见下节。）
- 注意与重定位/ASLR 的配合：RVA + image_base 在运行时还原，不依赖静态 VA。

## C5 x86 (32 位) 目标未支持 —— 显式硬拒绝（MIT-414 G7p2 收口）

**状态（2026-08-29）：32 位输入显式硬失败，不再静默。** `machine==0x014C`
的输入在 pe_loader 解析完成后输出 ERROR diag
`"32 位目标 (x86) 未支持 (GAPS C5); 不产出保护壳"` 并抛错（CLI 非零退出）。
消灭两态：**静默无操作**（SDK magic 被拆成两条 imm32、锚点不连续时旧行为
rc=0 输出≈输入，用户以为受保护）与**产坏壳**（手造连续锚点时 x64 管道在
32 位 PE 上覆写 .text，加载器 WinError 193）。完整证据链：
`.multica/mit-G7r-triage.md`（项目主亲验复现）。

**GAPS C5 旧主张逐条审计（triage §1 裁定：1 条成立，3 条过时/归因不完整）**

1. ✅ **真缺口（实证成立）**：marker_scan 锚点 x86 不连续——SDK magic 在 x86
   上拆成两条 imm32（`c7 45 f8 57 56 4d 50` / `c7 45 fc 42 45 47 31`，
   marker32.exe 反汇编实证），8 字节 needle 不连续
   （marker_scan_pass.cpp TODO(P7-x86)）。
2. ⚠️ **过时（程度低估）**：lifter 不是"部分支持"而是真参数化——双 Capstone
   会话（lifter_pass.cpp:54-77，capstone_session.cpp CS_MODE_32/64 分支）、
   x86_translate.cpp pointer_size S32/S64 分叉、EAX..EDI/EIP→Rax..Rip map、
   movsxd 显式拒 x86。
3. ⚠️ **过时（归因不完整）**：真实断层除扫描外还有两大块——asmgen.cpp:85 与
   stub_gen.cpp:155 硬编码 `KS_MODE_64` + Win64 ABI（14 物理寄存器池 /
   cdecl 变体 / 无 REX 等价物），pe_loader 双架构解析本身已就位。
   x86 全量对齐 = **P1 backlog**（G7x-1..8 拆分，asmgen 为唯一 XL 排期锚，
   依赖图见 triage §4）。
4. ⚠️ **部分过时**："不可用"的一部分根因是 pe_loader PE32 解析 bug（BaseOfData
   漏读，三字段错位 4B，见下）——非纯设计缺口，MIT-414 已修复并单测固化。

**MIT-414 附带修复的正确性缺口（独立于 x86 支持本身）**

- **pe_loader PE32 分支 BaseOfData 漏读**（pe_image.cpp）：修复前
  image_base=BaseOfData / section_alignment=ImageBase / file_alignment=
  SectionAlignment 三字段错位 4B；section_alignment 误读为 0x400000 →
  stub_link 把 `.wvmp` RVA 对齐到 0x400000 → 加载器节 VA 连续性拒绝
  （WinError 193）。修复 + `test_pe_loader` PE32 fixture 逐字段断言
  （image_base=0x400000 / section_alignment=0x1000 / file_alignment=0x200）。
- **section_builder 节 VA 连续性防御**：追加节（requested_rva）必须与前一节
  对齐端连续（对齐后 start == prev end），空洞显式失败非静默——Windows
  加载器实测拒绝空洞布局（既有节端 0x5000 时 .wvmp 落 0x5000 可加载、
  0x6000 起全拒，triage §3.3 变异体二分）。

**16-bit 目标：不可行（登记）**——PE 格式只接受 Machine 白名单
0x014C/0x8664（pe_image.cpp），16 位 NE/LE 文件过不了 PE 签名检查；保护壳
生态无 16 位 PE 现实需求（triage §4）。

**观察清单（triage §8 新耦合转录）**

- **CRT 初始化区 E8 误归属**（triage §8 #4）：32 位 CRT 初始化近距调用密集，
  kStubWindow=64 窗口内 E8 目标落入锚点前 ≤64B 的概率高于 x64（craft32 实测
  2 个误归属 begin）。规则内设计行为，低危（只产生多余 warning + 潜在空区域）；
  未来归属规则可加"目标与锚点间无可执行指令"类强校验或降窗口。
- **ExitNative .pdata 依赖在 x86 天然失效**（triage §8 #6）：x86 通常无
  .pdata → find_function_end_rva 退 nullopt → 保守 gate 兜底，行为差异非缺陷。
- **CLI 无 arch 表达面**（triage §8 #7）：config 无 arch 字段、无 --help 子命令，
  32 位全支持需配置面扩口（P1 G7x-7）。

## G3 串指令族 rep movs/stos/scas/cmps/lods（MIT-415 收口）

**状态（2026-08-29，main 92928e0 后）：rep/repnz 串指令已入面**——lifter 前缀闸
按 detail 级三元组白名单（mnemonic + prefix[0] F3/F2 + 宽度）放行；翻译器按
D2 选型展开为既有 VmOp 组合微循环（零新 VmOp 零新 handler），运行时 rcx 值
语义保留（禁按 rcx 展开代码）。multiseed 34 样本 × 5 = 170/170，wvmpTest
14/14 满贯 + 双跑 103/103 保持。

**支持面**：F3（rep/repe）{movs, stos, scas, cmps, lods} 全族 + F2（repne）
{scas, cmps}，宽度 S8/S32/S64。string movsd（A5）与 SSE movsd（F2 0F 10）
同 id=X86_INS_MOVSD，由双 MEM 操作数形状互斥区分（408 规则）。

**残余（越界即 C1 gate 兜底，保持原生）**：
- 16 位操作数（66 前缀，movsw/stosw/scasw/cmpsw/lodsw）——砍面披露，MSVC
  不产，未来如需按同构展开（runtime S16 通路现成）；
- 67 地址宽（ECX 计数 + 32 位指针语义）与段覆盖前缀；
- lock 前缀（F0）——capstone 对 `F0 F3 A4` 吸收 F0 只报 F3，lifter 字节级
  扫描拒；本机实测 lock rep movsb 原生即 #UD，无法作为可执行样本，负例
  仅在 lifter 单测覆盖；
- F2 + movs/stos/lods（Intel undefined）；
- 无前缀单发形态（plain movsb 等）；
- **DF=1 输入**（手写 asm 置 DF）：翻译期无法静态证 DF，微程序按 DF=0
  （指针递增）展开，note 级 `string-op DF=0 assumption` 披露（D1 裁决，
  不建 DF 位——kFlagsMask 冻结）；MSVC/主流编译器产物 DF 恒 0（cld ABI
  惯例），实际行为=原生；
- 重叠区域拷贝（rep movs 原生未定义，样本禁依赖）。

**capstone REX.W 实证缺陷（Q 形必知）**：`48 F3 A5`（ml64 `rep movsq` 规范
编码）被解为 `rep movsd` dword（id=MOVSD、rex=0、op_size=4）——F3 先于 REX
的 `F3 48 A5` 才正确报 MOVSQ qword；movsq/stosq/scasq/cmpsq/lodsq 一律按
"op_size==4 且字节流含 REX.W → S64" 修正（串指令无 ModRM/立即数，0x40..0x4F
必为 REX，与 popcnt REX 扫描同纪律）。

**早退语义实测（E2E 对拍）**：repne scasb/repe cmpsb 命中/失配终止时，
RDI/RSI 指向比较元素**之后**、RCX 已含终止迭代的递减（strlen
`lea rax,[rdi-1]` 惯用法同证）——展开的早退出口同样推进指针减计数，
flags 恢复为末次比较值。

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
3. C4 rip-relative（解锁"访问全局的真实函数"）→ **GP 已 done（MIT-248）；
   SSE mem 已收口（MIT-408）**；剩余面 = `add/sub [mem],xmm` 双访存形态
   （C4c，D3 砍面）
4. C3 call gate（工作量最大，依赖 C1 分段）→ 解锁真实函数
5. C5 x86：**安全拒绝面已收口（MIT-414：PE32 bug 修复 + 显式硬 gate + 文档）**；
   全量对齐 = P1 backlog（G7x-1..8，asmgen 为排期锚）
6. 与 M3 插件池并行推进不冲突（不同代码面）
