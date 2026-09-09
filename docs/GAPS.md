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

**MIT-433 (P1) 收口：rol/ror flags 语义分叉（G9r triage §6.1，2026-08-31）**

- **缺口（MIT-432 项目主独立复现认定，406 铁律）**：`build_rol/build_ror`
  复用 `build_shift` 全量 `flags_tail` 装配，而 SDM Vol.2 ROL/ROR **只写
  CF/OF、ZF/SF/PF unaffected**——zero5 的 `xor r,r` 宿主污染（ZF=1/SF=0/PF=1）
  被 setcc5 捕获后覆写 guest 应保留位。实测：native `ror eax,1` 后 `setz`=0，
  packed=1（旋转结果非零、ZF 应保留前态 0）。230/230 基线全绿是**盲区**
  （无"rotate 后消费 ZF/SF/PF"形态），非无缺口。
- **修复 = flags_tail_partial partial-preserve 装配**（Inc/Dec cf_preset
  先例的三位推广）：CF/OF 照旧 setcc5 捕获装配，ZF/SF/PF 三位从 ctx+0x98
  旧值（经 flags_ 活镜像）`and 0x19` 原位保留；rol/ror/rolcl/rorcl 四
  handler 换 partial 尾（其余 handler 生成字节码零扰动——asmgen dump 逐
  case 对账：91/95 handler 体逐字节相同，差异恰为 4 个 rot handler 尾部；
  非 rot 样本 packed 差异 = 内嵌解释器镜像尺寸 -48 字节 @seed12345（4 rot
  尾部变短的纯位置效应，跳表 delta 全为该值的整数倍），bytecode/stub 零变）。
- **注释同步修正**：asmgen.cpp ROL/ROR 段旧文"SF/ZF/PF 按结果"系把
  SHL/SHR/SAR 组语义误安到 ROL/ROR 头上的 SDM 误读，已按实义重写并引本案。
- **测试面**：`RotFlagsPartialPreserve` 12 组矩阵（rol/ror × {ZF,SF,PF}
  保留 + shl/shr/sar 全量写对照 + count=0 全 5 位不动 + count>1 保留 +
  RolCl/RorCl 同面，5 seed 随机分配）；样本 `wvmp_flags_rol_sample`
  （p432 复现样本转正：自含 MASM marker 桩，ror/rol ZF + rol SF + ror PF
  消费区 + shl 对照，消费值经区内 Store 落盘——427 披露①观察纪律；
  修复前旧 CLI 双跑 stdout 分叉必 FAIL，修复后 byte-exact）。
- **G8a 前置**：flags_tail_partial 的"保留掩码 + 部分或入"骨架即 flagless
  变体（rorx/shlx/sarx/shrx，全不写 flags）的接入点声明（asmgen.cpp 接口
  文本已留；G8a 只需把 CF/OF 并入保留掩码，零新 VmOp，本单不实现）。
- **D4 OF 语义保留**：count==1 defined（seto 捕真值）、count>1 undefined
  （捕 host 值与 SDM 不冲突）——现状保留，未顺手改。

**样本集设计纪律（盲区教训，后续样本设计必读）**：样本的观察面必须覆盖
"指令写入面 × 消费形态"矩阵——指令写了哪些 flags，就要有对应的 setcc/jcc
消费探针；写入面没有被消费，行为对拍就观察不到分叉（rol/ror 在 230/230
全绿下仍带三级分叉缺口即本教训的实例）。

## C3 区域内 call 支持（callgate；整数 + FP 参数/返回值，MIT-417 起）

**现状（MIT-417 改写，旧文 "翻译器直接 skip" 为 pre-M2-9 遗留，作废）**

- 区域内直接 call（E8 disp32）已由 M2-9 起经 callgate 支持：翻译器 emit
  `VmOp::CallGate`（目标 RVA 存 aux），运行时 handler 切 rsp 到 caller 原始
  frame（MIT-B2 栈回退链 + MIT-406 callee 专用 4KB 窗口 + 运行时 16 对齐，
  深树如 sha256 54-call 实测通过），调 native callee 后回解释器继续 dispatch。
- **整数参数通路**（M2-9 起）：regs[1/2/8/9]（VM 的 rcx/rdx/r8/r9）→ reserved
  槽 +0xD0..0xE8 → 物理 rcx/rdx/r8/r9，RAX 返回值写回 regs[v0]。
- **FP 参数/返回值通路**（MIT-417 P0，2026-08-30 起）：call 前 4 条
  `movups xmmN, [ctx.xmm + 16*N]`（N=0..3，全 16B 搬运，Win64 FP 参数槽），
  call 后 1 条 `movups [ctx.xmm], xmm0` 捕获标量 FP 返回值（xmm base 经
  kCtxXmmBase 编译期派生）。修复前 FP 参数断链 = **静默坏壳首例**（G5r
  triage §6.1 / MIT-416 登记：区域内带 double/float 参数的 native 调用
  虚拟化后错值零告警，如 g5r_p0 fp_sum=15.00→3.00；对 x87 路线的意义：
  区域内调 CRT 数学函数 sin/pow 等必经此通路，是本缺陷的前置依赖）。
- **残余面（登记，非 v1）**：
  1. `__vectorcall` 多 xmm 返回 / 128 位结构返回不在 v1 面（Win64 标量 FP
     返回恒 xmm0 单槽，无需 xmm1）；
  2. 可变参 FP（printf 类）：variadic FP 参数按 ABI 需 caller 侧 `al` 计数
     xmm 使用数，VM 通路未实测（MIT-417 D4 决策：不预设，进样本或披露，
     当前未进样本——区域内 printf 拉入格式化字符串寻址等形态，留后续实测）；
  3. callee 返回 double 但调用点按 float 读（类型错配）= 上游翻译缺陷，
     出现即披露（MIT-417 §F.3）。
- 其他形态：间接 call（O3 优化产物）、跨 stub 递归调用（callee 也是标记
  函数）不在 v1 支持面，遇之由 C1 gate 兜底。

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
- **MIT-425 (G1b) 收口 (2026-08-30)**：SSE mul 族 mulss/mulsd/mulps/mulpd
  （0F 59 系，reg-reg + mem 源含 rip，408 通路；IR 层 (Op::Mul,
  src2=imm 14..17) 载体标记折叠 4 个新 VmOp——ir::Op 冻结下 (Op,Size)
  双语义被 GP mul (S32/S64) 占用装不下 4 形态，D2 授权选型见标记域注释）、
  andnps/andnpd（0F 55/66 0F 55，dst=~dst&src 非纯位运算三元组，VM 无
  128-bit NOT 原故双折不可行 → 新 VmOp::Andnps；411 负例样本按 §B.4
  正例翻转）、SSE2 整数位运算档① pand/por/pxor/pandn（66 0F
  DB/EB/EF/DF，与 ps 位运算逐位同语义，零新 VmOp 折叠
  Andps/Orps/Xorps/Andnps——411 pd 折叠 ps 先例的整数扩展；#33 实测修正：
  cl v145 对 _mm_and_si128/_mm_andnot_si128 直产 andps/andnps，编译器
  自身即 ps/p 互认证据，pand 真 66 字节由 MASM 样本直写）。multiseed
  40 样本 × 5 = 200/200。
- **MIT-427 (G1c) 收口 (2026-08-31)**：SSE2 整数档② movd/movq GP↔xmm 桥
  （MOVD 66 0F 6E/7E + MOVQ 66 REX.W 0F 6E/7E + all-xmm F3 0F 7E 与
  66 0F D6 + VEX vmovd/vmovq 镜像）——REG 形式折叠 2 个新 VmOp
  （XmmFromGp/GpFromXmm，高位清零/截取语义由 handler 内 movd/movq/movsd
  mem 形式直产）；mem 形式直接复用既有 (Op::Movss, mem) 载体 →
  XmmLoad/XmmStore（408 通路）；all-xmm 双编码 #33 实测逐位同语义
  （d6_probe：66 0F D6 C8 与 F3 0F 7E C1 高 64 均清零——"高 64 保持"
  先验被推翻，SDM register-dest 伪码 DEST[127:64]←0 同口径；"仅写 8 字节
  不触碰高位" 只对 mem-dest 成立）→ 全部折叠 kBridgeFromXmm。
  MMX 裸 0F 6E/6F/7E/7F（mm 操作数）D2 永久 gate——capstone 对 NP 0F 6F
  报 id=MOVQ 与 SSE 形态同 id 混入，mm 操作数判据唯一可靠闸（单测钉死）。
  IR 层 (Op::Movss, src2=imm 19..21) 载体标记（19=GP→xmm / 20=xmm→GP /
  21=xmm→xmm 清零拷贝；域 14..18 连续后延，movss 常规构造从不写 src2）。
  kVmOpMax 95→97（跳表余量 30）。multiseed 44 样本 × 5 = 220/220。
- **MIT-428 (G1d) 收口 (2026-08-31)**：SSE2 对齐传送 movdqa/movdqu
  （66/F3 0F 6F load + 66/F3 0F 7F store，id 468/469）零新 VmOp 折叠入面
  （translate_sse_mov 直复用，与 movaps/movups 全宽 16B 拷贝语义同构；
  §A.4 方向 probe 实测 6F/7F 双编码 reg-reg capstone 均归一化 dst-first，
  零调度层修正；VEX vmovdqa/vmovdqu 1028/1033 经 vex_desc_of 镜像入面）；
  427 桥样本 C++ intrinsic 负例翻转闭环（cpp_movdqu_neg 全翻真虚拟化、
  cpp_movdqa_neg movdqa 翻走仅剩 punpck 族 gate）。详见下节 G1d。
- **不支持面（越界即 C1 gate 兜底）**：SSE2 整数算术档② paddq/psubq
  （**真值 66 0F D4 / 66 0F FB**——425 原文 "D4/5C" 的 5C 有误
  （5C=SUBPD），MIT-427 派单自纠 "paddq=66 0F FC" 亦误（FC=PADDB），
  #33 probe 实测钉死）——B.2 频率双向授权砍面：实测 6 二进制
  854,020 指令 psubq=0、paddq=16（全部 shell32.dll，其余二进制 0，
  约 0.002%）且与砍面 movdqa 共生（/Od intrinsic probe 实测 paddq 必伴随
  movdqa 溢出）→ 支持面不可达，砍面留档按频率单开（**movdqa/movdqu 一半
  已由 MIT-428/G1d 翻转——paddq/psubq 本体仍砍面**，本体翻转需重测频率
  与 G1d 通路叠加）；SIMD 尾族三行——分层 gate 定稿（MIT-GZ B.1，2026-08-31；频率数据与
  裁决出处 = `.multica/mit-G9r-triage.md` §1/§1.4，MIT-432）：pmovmskb
  （66 0F D7；CRT/ML 域密度 0.015–0.055%，经典 exe 与客户态新抽 14 exe
  全零）/ pcmpeq/pcmpgt 系（SSE 整数比较族；同上分层分布，语料计数见
  432 §1.1 表）/ punpckldq/punpcklqdq（66 0F 62/6C 交织语义，D4 裁决
  非纯拷贝不入拷贝通路；SIMD 域最高密度族 0.06–0.074%，但粒度分裂
  d/q 88–100% hash/安全域 vs b/w 73% codec 域，全族按单粒度折条必漏
  一半形态）——三族全部维持文档化 gate（零逃逸 byte-identical 兜底
  实证不变）；lqdq/hqdq 按 MIT-GZ D1 拍板 = gate 文档化不折（客户态
  零命中 + 纯 intrinsic 溢出形态，S 级预算让位 M3）；AVX/VEX 残余面（档A 已收口
  38 id V-pair，精确残余见下节 G6a——VEX-GP BMI/ymm/FMA/加密/EVEX
  保持 gate）。
  （string movsd 双形态已由 MIT-415 收口，见 G3 节；
  x87 已拆出独立小节，见下节 "x87 (永久 gate, R3 裁决)"——不是简单"不支持
  兜底"，而是有独立频率数据与行为承诺的裁决面。）
- 注意与重定位/ASLR 的配合：RVA + image_base 在运行时还原，不依赖静态 VA。

## 指令族支持矩阵（阶段总览，MIT-GZ 收口定稿 2026-08-31）

> 读者五分钟全景：什么被保护、什么保持原生、为什么。每行一个可点名的
> triage/裁定出处；数字全部回溯权威源（权威基线 multiseed 48 样本 × 5 =
> 240/240、kVmOpMax=97、跳表余量 30，main `df3c2f1`）。“支持” = 编译器
> 自然产物真虚拟化（byte-identical 验收）；“gate” = 文档化不保护（越界即
> C1 gate 整函数原生保持，零逃逸实证）。

| 指令族 | 状态 | 裁决/实现要点 | 出处 |
|---|---|---|---|
| GP 算术/逻辑/移位/位技巧（含 div/idiv、movzx/movsx、popcnt/lzcnt/tzcnt、shift/rot 全谱） | ✅ 支持 | C2 handler 真执行语义电池 + 万条 fuzz；rol/ror flags partial-preserve（SDM：只写 CF/OF） | MIT-351~355 / MIT-404 / C2 收口 / MIT-433 (P1) |
| 区域内 ret / ret imm16（C3/C2 iw，清栈返回） | ✅ 支持（MIT-438 起） | D2 (i) aux 载 imm 零新 VmOp；出口 = handler 内清栈返回（终态物理 rsp := guest rsp，不走 HALT 通道）；imm=0 ≡ ret；`retf` 不在面 gate | MIT-438 (X1b) |
| 浮点 SSE 全族（add/sub/mul/div/mov/位运算/比较/andnps，标量+packed+mem 形） | ✅ 支持 | XmmLoad/XmmStore mem 通路；ctx.xmm 读回影子样本 | MIT-371~376 / MIT-408 / MIT-411 / MIT-425 |
| SSE2 整数位运算档①（pand/por/pxor/pandn）+ GP↔xmm 桥（movd/movq）+ 对齐传送（movdqa/movdqu） | ✅ 支持 | 档② paddq/psubq 本体砍面（实测 16/854k ≈ 0.002%）；桥双编码逐位对齐 | MIT-425 / MIT-427 (G1c) / MIT-428 (G1d) |
| VEX.128 档A（38 id V-pair 三地址折叠） | ✅ 支持 | 零新 VmOp、零新 handler，复用 translate_sse_* 通路 | MIT-426 (G6a) |
| BMI1/2 六条（andn/bzhi/rorx/shlx/sarx/shrx） | ✅ 支持 | andn/bzhi 零新 VmOp 折条 + flagless 载体域 22；bzhi 边界 idx≥N = 原值不变+CF=1（probe 实测修正） | MIT-434 (G8a) / 432 §2 |
| lock 前缀原子族（ALU 族折条 + xadd/cmpxchg/bts 系 + inc/dec） | ✅ 支持 | strip-and-execute，硬件原子性保真；D1 多线程并发边界登记 | MIT-419 / MIT-423 (G4/G4b) |
| 串指令 rep {movs,stos,scas,cmps,lods} | ✅ 支持 | 前缀闸放行 + 微程序展开；DF=0 假定 note 披露 | MIT-415 (G3) |
| 跳转表（jmp reg / jmp [mem]） | ✅ 支持（受限模板） | 防御常数双编码（MSVC ja / GCC jae）；无防御表永久 gate | MIT-409 / MIT-413 (G2) |
| callgate FP 参数/返回值通路（xmm0..3 入参 + xmm0 返回） | ✅ 支持 | 修复静默坏壳首例；callee 专用栈窗口 | MIT-417 (P0) / MIT-406 |
| x87 全族（D8-DF） | ⛔ 永久 gate（文档化不保护） | x64 MSVC 世界频率 ≈0（0.0000–0.0032%）；含 x87 标记函数整函数原生 byte-identical | MIT-416 / MIT-418 (G5r/R3)，`.multica/mit-G5r-triage.md` |
| SIMD 尾族三行（pmovmskb / pcmpeq/pcmpgt / punpck 系） | ⛔ gate（分层定稿） | 频率分层：客户态新抽 14 exe 全零 vs SIMD/CRT 域 punpck 0.06–0.074% / pmovmskb 0.015–0.055% 密度；punpck 粒度分裂 d/q 88–100% hash/安全域 vs b/w 73% codec 域；lqdq/hqdq D1 拍板 gate 不折 | MIT-432 §1/§1.4（`.multica/mit-G9r-triage.md`）+ MIT-GZ D1 |
| G8b 三条（mulx/pdep/pext）+ blsr 族四条（blsr/blsi/blsmsk/bextr） | ⛔ gate（挂账/永久） | mulx/pdep/pext = G8b 档 native 直执行 + CPUID gate 基建挂账，mulx CF Zen5 实测不写 vs SDM 厂商分叉待决；blsr 族 27 文件语料 0 永久 gate | MIT-432 §2/§6.4 + MIT-GZ B.1 |
| ymm / EVEX / FMA / 加密（AES 等） | ⛔ gate（档B） | xmm 跟踪区 kCtxSize 0x1C8 冻结面；档B 立项即触发跳表扩容评估 | MIT-424 (档B) |
| x86 (PE32) 平台（MIT-446 (X4) 翻正，MIT-450 (X5) 收口扩证，MIT-454 (X6) SSE+push-imm 翻正，MIT-455 (X7) Div 族+重扫收官，MIT-456 (push-mem) 第一大非 x87 shape gate 翻正） | ✅ 支持 | 全管道：D1 解禁 + stub x86 cdecl + cdecl callgate 参数窗（X5 裁决 = 可见参数桥，8 dword）+ x86 白名单 gate；样本池 17 族级样本 byte-exact（X6 池 14→15 pushimm，X7 15→16 div，MIT-456 16→17 pushmem）；ExitNative x86 上界接线已翻正（X5c F1）；SSE 32 op x86 全入面 + push-imm x86 开面（X6）+ Div/Idiv x86 真 handler（X7 批二：cdq x86 开面随之）+ push [mem] x86 开面（MIT-456：地址槽+Load+Push/Reg 折条，asmgen 零 diff，native 序 = 地址读值先于减 esp）；wvmpTest 103-kernel 14 标记区真虚拟化 **12 = 85.7%**（靶标无 push [mem] 位点；全 103 面 11.7%）；残余 gate 面 = 间接 jmp 1（aebb）+ 栈深 1（mul64hi，X5b 永久 gate）（X7 起 3→2 维持）；X7 客户态重扫：x64 direct 99.26% / x86 95.15%（形级口径，留样入仓；MIT-456 后 push_mem 1.845% 面出 gate 入 direct） | MIT-446 (X4) / MIT-450 (X5) / MIT-453 (X5c) / MIT-454 (X6) / MIT-455 (X7) / MIT-456 (push-mem) |
| 16-bit 目标 | ⛔ 不可行 | PE 格式白名单只收 0x014C/0x8664 | MIT-412（GAPS C5 交叉引用） |

> 观察清单与挂账联动见 `docs/STATUS.md`「指令虚拟化阶段（M2.5-G）收口」节；
> 本矩阵为定稿口径，逐族实现细节以上文各 G/C 节与 `.multica/` triage 为准。

## G1d SSE2 对齐传送 movdqa/movdqu（MIT-428 收口：零新 VmOp 折叠 + 427 桥溢出负例翻转）

**状态（2026-08-31，MIT-428，G1d 落地）**：movdqa/movdqu（legacy 66/F3
0F 6F load / 66/F3 0F 7F store，id 468/469）+ VEX vmovdqa/vmovdqu（1028/
1033）零新 VmOp 折叠入面——语义 = 16B 全宽拷贝，与 movaps/movups 同构，
lifter 两个 case 直复用 `translate_sse_mov`（(Movaps,S64)/(Movups,S64)
既有载体，REG 三形 + mem 408 通路全现成）；VEX 经 426 `vex_desc_of`
Fam::Mov 挂载（D4 纯拷贝 2-op 直折先例）。**零新 VmOp（kVmOpMax=97 不动）、
零新 handler、translator/asmgen/VM 逐字节不动**（dump 门 SSE_HANDLERS
集合恒等 = 零新 VmOp 机器证明，426 §D.7 同款）。

**§A.4 编码方向矩阵（#33 probe 实测，vendored capstone 5.0.6，2026-08-31）**：
movdqa/movdqu 仅 6F（load）/7F（store）两 opcode，但 **reg,reg 形态两编码
都能编**（66/F3 0F 7F reg,reg = rm 字段为 dst 的反写合法形）。probe 实测
（每编码×每形态）：6F（reg 字段=dst）与 7F（rm 字段=dst，如 66 0F 7F C8）
双编码 capstone **均归一化为 dst-first 报操作数**（access W 位钉死）——
先验 "7F 反写需调度层手动换位" 被实测推翻，`translate_sse_mov` 零方向
修正。EVEX VMOVDQA32/64/8/16（x86.h:1413-1419，62 前缀独立 INS id）显式
不入面 → 白名单外 C1 gate；ymm（C5 FD/FE 6F）由 translate_vex128 位宽闸
按操作数 32B 拒；xmm8..15 由 xmm_idx 不可映射拒（426 §F.3 同口径）。

**对齐语义（D2 沿用 375 :1188 先例）**：movdqa 对齐陷阱 #GP 不模拟——
mem 形式折 XmmLoad/XmmStore（408 通路，运行时 movups 非对齐宽松语义）；
reg-reg 折 Op::Movaps（handler 中间行 = native movaps xmm0, xmm1 寄存器
形态，无对齐语义面）。D2 对账实测：既有 build_movaps 与 build_movups
handler 唯一差异 = 中间行助记符（寄存器间拷贝无对齐分叉），槽位读写全走
movups——**无对齐强校验分叉需统一**。宽松化论证：MSVC /Od 产物仅对保证
对齐的目标（__m128i 16B 对齐栈槽 / alignas 全局）emit movdqa，运行时分歧
仅存在于程序显式依赖 #GP trap 的场景（真实代码不存在）；native 对非对齐
地址 movdqa 会 #GP 而 VM 宽松放行——known compromise，样本行为钉用
movdqu 非对齐栈槽/全局（⑥⑨）与 movdqa 对齐栈槽/全局（⑤⑦⑧）配对表达。

**样本**：`wvmp_aligned_mov_sample`（正例 12 区真虚拟化：movdqa/movdqu
双编码 × reg-reg/栈槽/rip 三形态 + VEX vmovdqa/vmovdqu 三形 + /Od
intrinsic 翻转正例 3 函数；负例 4 族函数级 gate 可调用 byte-exact：
EVEX vmovdqa32 / vpaddd ymm / punpcklqdq / pmovmskb）+
`wvmp_aligned_mov_xmm_readback_sample`（9 探针 ctx.xmm 8 槽全量读回：
16B 全宽高位语义 / 7F 反写归一化 / 对齐与非对齐栈槽 / rip load+store /
VEX 双形式）。multiseed 46 样本 × 5 = **230/230**。

**残余（精确登记，防误当漏项）**：punpckldq/punpcklqdq（66 0F 62/6C，
交织语义非纯拷贝——D4 裁决，427 桥样本 cpp_movdqa_neg 由此保持 gate）/
pmovmskb（66 0F D7）/ pcmpeq/pcmpgt 系 / paddq/psubq 本体（66 0F D4/FB
砍面）+ G8b 三条 mulx/pdep/pext（G8b 档：native 直执行 + CPUID gate 基建，
  mulx 含 Zen5/Intel CF 厂商分叉待决——432 §2.1 判定②）+ blsr 族四条
  blsr/blsi/blsmsk/bextr（语料 0 永久 gate——432 §6.4） + 档B ymm + EVEX 全谱——照旧 C1 gate。

## G6a VEX.128 档A（MIT-426 收口：38 id V-pair 三地址折叠，零新 VmOp）

**状态（2026-08-30，MIT-426，R2 裁决档A 落地）**：既有 SSE 白名单 38 id 的
V-pair（VADDSS..VPANDN，vendored capstone x86.h 全量对账 EXISTS）经 lifter
三地址折叠（`translate_vex128`）复用既有 translate_sse_* 通路——**零新 IR
语义、零新 VmOp、零新 handler**（asmgen.cpp 逐字节不动，dump 门
SSE_HANDLERS 集合与 main 完全一致）。VEX 前缀（C4/C5）被 capstone 吸收进
id（prefix=[0,0,0,0]），不经入口前缀闸直达白名单 case；白名单外 VEX id 落
default → C1 gate 整函数原生保持（424 E2E 实证链不破坏，零逃逸）。

**支持面**（D3 标量 FP 优先：/arch:AVX 下 100% 标量浮点走 VEX = 本档价值锚；
真产物验证 cl v145 /arch:AVX 两函数 vmulsd/vaddsd/vdivsd 全折叠）：
- 三态折叠（VEX.NDS：op[0]=dst R，op[1]=src1 R=vvvv 只读，op[2]=src2 R/M）：
  ① dst==src1 → 2-op (dst, s2) 直走；② dst==src2 且可交换（**仅 packed/位
  运算**，全 128-bit 语义）→ 交换 s1 上位；③ dst 独立 → 前置既有
  Op::Movaps(dst←src1) 16B 纯拷贝（VEX "dst 高位 ← s1 高位" + 2-op "高位
  保持" 逐位等价）+ 2-op (dst, s2)。
- 家族：vaddss/sd/ps/pd、vsubss/sd/ps/pd、vdivss/sd/ps/pd、
  vmulss/sd/ps/pd（(Op::Mul, src2=14..17) 载体同 legacy）、vmovss/sd/
  aps/apd/ups/upd（2-op 直通 + 3-op 插入形态 d==s1 折）、vxorps/pd、
  vorps/pd、vandps/pd、vpxor/por/vpand（折叠既有 ps 位运算）、
  vandnps/pd/vpandn（(Op::Andps, src2=18) 载体）、vucomiss/sd、
  vcomiss/sd（2-op flags 通路）。mem 源（含 rip）复用 408 通路。

**gate 面（保守退化整函数原生，行为 byte-identical，非坏壳）**：
- **d==s2 标量族（可交换含内）**：VEX 标量 "dst 高位 ← s1 高位" 与 2-op
  "高位保持" 不相容（swap 后高位 = dst 原值错；pre-Mov 又先摧毁 s2==dst
  的值），正确序列需 xmm→GP 双槽暂存原 dst——既有 VmOp 无此原语
  （build_xmm_transfer 写路径仅 xmm 区），新 VmOp 违反 D1 → gate。
  频率实测（MIT-426 B.3，.pdata 域 capstone 全扫）：d==s2 全形态
  ucrtbase 2.19%（含标量）/ smartscreen 0.00%，合并 0.75% < 1%。
- d==s2 非交换族（vsub*/vdiv*/vandn*）：同上（无交换出路）。
- vmovss/vmovsd 3-op 插入形态 d≠s1（§F.4 "假 Mov"：dst 低位 ← s2、
  高位 ← s1，非纯拷贝非 2-op 可表达）。
- xmm8..15 任何形态：SSE 跟踪区 ctx.xmm[0..7] 不可映射，与 legacy SSE
  同口径 gate。
- ymm/zmm 任何形态（32B 操作数）：**位宽闸按操作数尺寸拒**（X86_INS_VADDPS
  等 id 同时覆盖 128/256 两宽——仅 mnemonic 白名单会放 ymm 进来错误 lift，
  必须判 16B 才入面），单测钉死同 mnemonic 双宽负例。

**范围外（显式声明，防误当漏项）**：① **VEX-GP（BMI1/2：rorx/mulx/andn/
shlx/pdep/bzhi）不在 SIMD 档A 内**——VEX id 但 GP 域，独立缺口（triage
§6.2，真实二进制高频如 ClipUp rorx:288）；② ymm/zmm（档B，kCtxSize 冻结
面 + 跳表扩容前置）；③ FMA 族（双舍入红线，永不拆 mul+add，triage §6.5）；
④ vpaddd/vpaddq/psubq 系（MIT-427 实测砍面：paddq 16/854k、psubq 0、vpaddd 0——本体与 V-对镜像均 gate，见 G1c 节）；
⑤ vzeroupper/vzeroall（档B ABI 面）；⑥ 加密 vaes/vpclmulqdq（直执行另议）；
⑦ EVEX/AVX-512 全谱（62 前缀独立 INS 空间，天然不入白名单）。

**回归样本**：`wvmp_vex128_sample`（正例 12 区真虚拟化 + 负例 8 族各自
函数级 gate 可调用）+ `wvmp_vex128_xmm_readback_sample`（9 探针 ctx.xmm
8 槽全量读回：d==s1 高位残留 / packed 交换全宽 / d 独立 pre-Mov 槽位 /
标量高位语义 / D4 拷贝 / vpxor 清零 / mem load）。multiseed 42 样本 × 5 =
**210/210**。

## G8a BMI1/2 折条款目（MIT-434 收口：andn/bzhi 零新 VmOp + rorx/shlx/sarx/shrx flagless）

**状态（2026-08-31，main cdc218d 基线，分支 mit-g8a-bmi-fold）**：G6a 范围外
①（VEX-GP BMI）按 G9r §2.5 蓝图入面——**零新 VmOp（kVmOpMax=97 不动）、
零新 handler（asmgen.cpp 逐字节零改动，P1 红线"新增函数允许"以零 diff 兑
现）、零冻结契约触碰**。D1 选型 = (i) 变体：lifter 载体标记 → translator
层展开（(ii) +4 VmOp 方案实测对照后弃，见下）。

**载体域对账（419 D1 铁律，陷阱②选型）**：判据 = **src2.kind≠None 骑在
"全仓从不写 src2"的 op 上**（andn/bzhi 三操作数、imm 标记无槽可占，src2
骑真操作数；Imm(22) 骑 shift 族）：
- `(Op::{Shl,Shr,Sar,Rol,Ror}, src2=Imm(22)=kFlagless)` = rorx/shlx/sarx/
  shrx——原生 shift 的 count 走 **src**（Imm/CL），src2 恒 None，陷阱②
  担心的"count 值域撞标记域"被 kind 判据绕开（`ror eax,24` 不误拦，单测
  + 样本双钉）；
- `(Op::And, src2=Reg)` = andn d==s2 载体形（src=NOT 项 reg-only、
  src2=AND 项）；`(Op::Sub, src2=Reg)` = bzhi（src=value r/m 可 mem、
  src2=Reg(index)）。全仓 src2 写入点审计（425 §B.1 同款）：imul 3-op
  （op=Imul）/ string 0..4 / lock 5..13 / SSE mul 14..17 / andnps 18 /
  bridge 19..21 / 本域——op+kind 双限定下零碰撞；域 22 与 0..21 连续零重叠。

**probe 实测修正（Zen5 + ml64 v145 + capstone 5.0.7，2026-08-31）**：
- **🔴 bzhi 边界（index≥N）：结果 = value 原值不变 + CF=1**（G9r §2.1
  "CF=0" 仅对 index<N 成立；"index≥op_size→结果 0" 预判被推翻——0xFFFFFFFF
  idx=32 → 0xFFFFFFFF、ZF=0、CF=1）。折条含 mask-clamp（Cmovcc 到 -1）+
  CF 补丁（Sbb/Not/And/Or/SetFlags），值+五位 flags 全对齐含边界；
- bzhi index=0 → 结果 0（(1<<0)-1=0，与 shift count=0 no-op 不同）；index
  用 SRC2[7:0]（0x105→5，高位垃圾忽略，Movzx 钉入微程序）；
- **操作数 mem-ability 反转**：andn 的 r/m 在**第三**操作数（AND 项，
  `andn r8d, eax, [m]` 收 / `andn r8d, [m], ecx` ml64 拒），NOT 项 vvvv
  reg-only；bzhi/rorx/shlx/sarx/shrx 的 r/m 在**第二**（value 可 mem），
  第三项（bzhi index / shlx 族 cnt）reg-only——SDM "ANDN r32a, r/m32,
  r32b" 记法直读会得出相反结论，以 ml64 逐形双验为准；
- rorx/shlx/sarx/shrx 五位 flags 全不受影响（raw 0x247 全程，count=0 同、
  count 掩码 &N-1 与 cl 通路一致）。

**折条结构（D1 两路实测对照后选 (i) 变体）**：
- (i) 原案"同 op 双尾分叉 handler"需触碰 build_shift 函数体 → P1 红线
  违规，不可行；落地 = translator 层 `[GetFlags(s); 既有 shift VmOp;
  SetFlags(s)]` 包裹（G3 串指令 GetFlags s0/SetFlags s0 同款先例；
  build_setflags 同步 flags_ 活镜像不变量）——既有 handler 原样复用，
  cost = 每指令 +2 word 字节码 / +2 dispatch（§F.1 预判可接受）；
- (ii) +4 VmOp（97→101）+4 新 handler：省 2 word/2 dispatch，但付 enum
  扩张 + 4 个安全敏感 handler 面 + dump 门集合变化；本单选 (i)，G8b 若
  需要可再议；
- andn：d==s1 → `[Not; And]` 2 IR；d 独立 → `[Mov; Not; And]` 3 IR
  （纯 lifter 折叠零 translator 成本）；d==s2 → 载体 → translator
  `[Mov(s0,s1); Not(s0); And(d,s0)]`（scratch，C4b 先例）；s2=mem 主 And
  直带 mem src（alu-binop src_mem 通道）——flags = 尾行 And 全集
  （CF=0/OF=0/ZF,SF,PF 按结果 = 原生 andn 逐位，probe 0x286）；
- bzhi：恒走载体，d==value 16 op / d≠value 17 op 微程序（低频面，
  §F.1 字节码膨胀披露）；
- 负例族 mulx/pdep/pext/blsr/blsi/blsmsk/bextr 照旧 default → C1 gate
  （G8b native 直执行 + CPUID gate 后置；blsr 语料 0 文档化 gate 维持，
  432 §6.4）。

**样本**：`wvmp_bmi_sample`（16 正例区真虚拟化 = 16 stub：andn×4 含
d==s2 载体形与 mem AND 项形 / bzhi×5 含 mem value、边界 idx=32 原值+CF=1、
idx=0 结果 0 / rorx×4 含 mem value 与全五位保留 setz/setc/sets/setp 四探针 /
shlx cnt-in-reg、sarx mem、shrx 独立；1 负例区 7 指令各自 gate note 整函数
原生保持）+ translator/lifter/runtime 三层单测矩阵（载体派发与碰撞回归、
D4 双 andn 串扰钉、真执行语义电池 6 case × 5 seed 期望值 = probe 逐位）。
multiseed 48 样本 × 5 = **240/240**（REQUIRE_REAL 同）。

## Ret imm16 清栈返回（MIT-438 收口：x64 现网同类地雷兼修，D2 选型 (i) 零新 VmOp）

**状态（2026-09-01，分支 `mit-x1b-ret-imm16` 基于 main 2dad6ff）**：X0 triage
§A.1 升级定性的机制链收口——lifter 双 arch 共享 `translate_ret` 已把 imm 放进
IR.src（x86_translate.cpp `translate_ret`，`ret imm16` 含 66 前缀形实测钉死），
但 translator 丢弃 in.src（aux 蒸发），且 runtime 跳表**无 Ret handler**（表项
指向 Halt）——区域内含 ret 的函数翻译成功零告警、运行时停机走 stub 终态出口：
返回地址不弹、清栈丢失、控制流落错。**不止 x86 战役需要：`ret imm16`（C2 iw）
在 x64 也是合法编码**（手写/第三方汇编可现），属现网 x64 既有正确性缺口——
433「230/230 全绿 ≠ 通路已验」**样本集盲区教训第二例**（现样本集无任何区域内
ret 形态；X0 §7：msvbvm60 82% of ret = imm16 形，x86 stdcall 被调方清栈主形）。

**语义（SDM Vol.2 RET.Near imm16）**：ret_addr = [v4]；v4 += 8 + imm（imm 按
字节数加 rsp，无符号零扩展，x64 同）；imm=0 ≡ plain ret（D3 边界）；上界
0xFFFF（C2 iw 编码域）。病态形（清栈量越过返回地址槽/越帧）SDM 定义为普通
加法——VM 跟随 native 语义不加 gate（D3 钉：handler 恒加 imm）。`retf`
（16 位远返回）不在面：语料未现，遇之白名单外 C1 gate 兜底（文档一句，D3）。

**实现（D2 选型 (i)：闲置参数槽，零新 VmOp / 零跳表扩容 / asmgen 既有 handler
逐字节零扰动）**：

- translator `case ir::Op::Ret`：in.src（Imm 形）按低 16 位掩码载入 aux（掩码
  = 编码域忠实行为，capstone 域 0..0xFFFF 不可能越界，防御非法源）；plain ret
  （src=None）→ aux=0 ≡ plain ret。双 arch 共享此路径（imm 恒按字节加）。
- runtime `build_ret`（asmgen.cpp 新增）：ret_addr = [v4] → v4' = v4+8+imm →
  v4' 持久化 ctx+0x30 → **出口不走 stub HALT 通道**（stub 终态恒在 rsp =
  native_sp 处转移，物理 rsp 无法表达清栈）：handler 内直接完成 stub 终态链
  （易失寄存器 rax/rcx/rdx/r8-r11 + xmm0-7 写回 → 弃解释器帧 0x210 → pop stub
  8 push 恢复宿主 callee-saved）→ `mov rsp,[rsp-0x1D8]`（ctx+0x30 读于 rsp
  变更前）→ `jmp qword ptr [rsp-8]`（[v4'-8] 终态槽 = handler 早期预写的
  ret_addr，死栈区）——终态物理 rsp = 清栈后 guest rsp，与原生 ret 后 caller
  视角逐字节一致；终态零活寄存器依赖（ret_addr/v4' 先落盘，写回/pop 可任意
  覆盖暂存）。出口机制沿用 ExitNative「handler 内直接退出」先例，差异 = 终态
  物理 rsp 是 guest rsp 而非 entry rsp（stdcall 清栈正是本 op 的意义）。
- pop 宽度：x64 = 8（本单实测面）；x86 = 4 由 IR size 字段携带（cond_or_size
  已含 S32/S64），handler 分叉属 X4 asmgen 参数化面（纸面级披露，§F.1）。
- 继承既有边界：guest 未配平 push 的区域会把 push 写进 stub 保存区（ExitNative
  同款「区域含未配平 push」登记面），本 handler 不新增防线；[v4'-8] 终态槽与
  EXIT_SLOT（native_sp-0x288）重叠仅在 v4' < native_sp 的病态形出现。
- #33 对账（派单 §E）：本 op 此前无 handler（跳表指向 Halt），无既有 aux 读
  路径可冲突；X0 §3.1 所指「pop-ret-addr 的 handler」即本函数（此前不存在）。

**回归**：

- 样本 `wvmp_retimm_sample`：3 区 x64 `ret N` 直写真编码（10h / 0(C3 形，MASM
  将 `ret 0` 优化为 C3——plain-ret 形态亦走本 handler aux=0 通路)/ 90h；良构
  caller 的清栈量 ≡0 mod 16，qword 参数 + 16 对齐垫并入 N，imm=8 档由 runtime
  电池覆盖）+ caller 侧平衡探针/返回值断言（区1 = 2 轮调用链 + 栈参数消费，
  每轮各自复分配参数槽——上轮 ret 已清，不复分配即 call 点错对齐，本单调参
  实测过的真陷阱）。修复前旧 CLI（main 2dad6ff，ret 路径 = f7a865c）保护零
  告警（3 stub 照常生成，无任何 gate note）→ packed 崩溃 rc=139（3/3 确定性，
  stdout 空）→ 修复后 byte-exact PASS（433 同款反证纪律）。
- 单测三层：translator `RetImm*` 4 矩阵（imm 进 aux / x86 S32 形派发 / imm=0
  与 0xFFFF 边界 / 16 位掩码）；lifter `RetImm16LiftIntoSrc`（x64 C2 / 66 C2
  前缀形 / x86 C2 双 arch lift 进 IR.src 回归钉——X2 重构防回退）；
  runtime 语义电池 g2 段：stub 帧同构自汇编 driver + guest continuation 镜像，
  4 imm 档（0/8/0x88/0xFFFF）× {终态 rsp = v4+8+imm、rax/rdx/xmm0 写回、gc
  命中} RWX 真执行。
- multiseed 48→49 样本 × 5 = **245 runs**（REQUIRE_REAL 同）。
- kVmOpMax=97 不动；冻结契约零触碰（runtime.hpp / backend.hpp / callgate /
  kCtxSize / 载体域 0..22 零 diff）；asmgen 仅新增 build_ret + 2 派生常量
  （static_assert 钉 0x210/0x1D8）+ handler 表 1 行。

## x86 支持面：SEH/FS 段寻址显式 gate（MIT-438 B.4 收口，🔴2）——「x86 战役已知 gate 清单」首块

**现状实测（派单 §A.3；vendored capstone 5.0.6 + lifter 判据直读，单测钉死）**：

- seg_fs 语料（X0 §7）：Delphi 0.68% / vmwarecui 1.7%；`mov reg,[fs:0]` =
  SEH TEB 惯用法（FS:[0] = SEH 链头）。
- **capstone x86 32 位模对 `64 8B 05 ...`（mov eax, fs:[disp32]）的报法**：
  段覆盖前缀字节落 **prefix[1]**（G3 串指令 probe 同款布局：prefix[0]=rep/
  lock、prefix[1]=段覆盖、prefix[2]=66、prefix[3]=67）；mem 操作数的段寄存器
  报在 **mem.segment** 字段（X86_REG_FS），**不占 mem.base**（base =
  X86_REG_INVALID）。x64 64 位 SIB 无基址形（`64 8B 04 25 ...`）与 GS 前缀
  （65）同面。单测 `SehFsSegmentOverrideGate` 逐字段断言钉死（换 capstone
  版本报法漂移即红）。
- **lifter 判据链**：`translate_insn` 入口闸 `prefix[0]!=0 || prefix[1]!=0 →
  unsupported`（段覆盖在入口统一拒）→ skipped_ranges 入 LiftMetadata → C1
  整函数原生保持。mem_operand 的 base=Flags 哨兵路径天然看不到 FS
  （map_reg(X86_REG_FS)=nullopt 已由 LifterRegMap 钉）——**不存在「FS 被
  静默当 flat disp 处理」的旁路**。
- **「扫得到 ≠ 放得进」零逃逸同构**：扫描层（marker_scan）能定位含 FS 的
  区域（X1a 起含 x86 双段锚点形），lift 层显式 gate → 整函数原生
  byte-identical，与 418 x87 / 424 档B gate 同构。
- **callgate callee 自装 SEH 无碍情形**（两情形文本区分）：区域内 call 的
  native callee（callgate 通路）在原生栈上自装/撤销 SEH（fs:[0] 链操作）完全
  无碍——callgate 是真 native 执行、不经 lift；本 gate 只拦**区域指令流内**
  的 fs/gs 段寻址（VM 无段基址模型；Win64 平坦模型中 FS/GS 是唯一非 flat 段）。

**x86 战役已知 gate 清单（首块，为 X 波后续单立模板；每行 = 扫得到但显式
gate，整函数原生 byte-identical 零逃逸）**：

| # | 形态 | gate 层 | 依据/出处 |
|---|---|---|---|
| G1 | 段覆盖前缀（64/65/26/2E/36/3E = prefix[1]）——FS:[0] SEH 链 / GS TLS 访问 | lifter 入口闸 unsupported → skipped_ranges | MIT-438 B.4；单测 SehFsSegmentOverrideGate（x86 32 位模 + x64 SIB 形 + GS 前缀三形） |
| G2 | 67 地址宽覆盖前缀（prefix[3]）——16 位寻址（x86）/ 地址截断 32 位（x64），编译器不产（X0 §1.4 lea 行判） | lifter 入口闸（67 闸先于段覆盖闸，位域正交互不误伤） | MIT-442 (X2a) B.4；单测 AddressSize67Gate（双 arch + 66+67 组合 + 段+67 组合）；样本负例区6（禁调用） |
| G3 | std（DF←1）——DF 语义不可建模（VM flags 无 DF 位，kFlagsMask 冻结，G3 D1 在案）；DF=1 输入下串微程序方向错 = 行为错误 | lifter unsupported（无 case → switch default） | MIT-442 (X2a) D5 裁决；单测 CldNopStdGate；cld（DF←0）与 VM DF=0 假设一致 → Op::Nop 放行（对齐 415 既定 DF 判，禁新语义发明） |
| G4 | 串指令 S16 形（66 A5/A6/AA/AC/AE/A7/2E 系 movsw/stosw/…）——G3 S16 串形砍面维持（runtime 元素宽参数化属 asmgen X3 面） | lifter translate_string_op 前缀三元组（prefix[2]=66 拒） | MIT-415 §B.7 残余维持 + MIT-442 复核；单测 RepStringOpNegativesStillGated（66 F3 A5 + 66 A5 双钉） |
| G5 | call [mem] / call reg（目标 = 运行时值）——CallGate 协议仅吃 aux RVA（asmgen build_callgate step1 直读），reg-target 通路需 asmgen 改动 → **D4 停手归 X3**（IAT thunk `call [__imp_x]` msvbvm60 35% of call / vtable call reg dxcompiler 4167 级） | lifter 已 lift（Call dst=Mem/Reg，409 Jmp 先例）→ translator skip 带 X3 披露 note → C1 整函数原生 | MIT-442 (X2a) ① #33 实测推翻「Load+Call(reg) 零新 VmOp 高置信」预判（call-reg "可直用" 系 lifter 白名单级，runtime 从未有 E2E）；单测 CallMemGateNoteX3；样本负例区2/2b |
| G6 | cbw 之外的低频尾族：shld/shrd（X3 结构性必收）/ enter（噪声）/ cwd（66 99，无折条）——X0 §1.4 缺失行维持 | lifter default | X0 §1.4 + MIT-442 分工（shld/shrd 归 X3，本单不动）；单测 CwdeCbwFoldForkFace（cwd 66 99 gate 钉） |
| G7 | SSE 全族（x86 面 32 op：Addss..GpFromXmm + Ucomiss/Ucomisd）——**MIT-454 (X6) 翻正**：32 VmOp 全部入 x86 handler 表（表 60→92 行，加行即自动放行，stub_link 零改动），批迁含 stub xmm 同步（x86 stub 入口 host→ctx.xmm + 出口 ctx→host，X6 A 面配套）+ ExitNative/Ret 直退 handler 内联 xmm 恢复；样本 wvmp_x86_sse_sample 翻案 gate→真虚拟化（stub 1→2，输出 byte-exact，428 翻转先例） | ~~stub_link emit 层 gate~~ → 真虚拟化；Cvt/Sqrt/Unpck/Shuf 指令面无 ir 载体无 VmOp（冻结枚举域内不存在），双 arch 同为 lifter 层 gate | MIT-446 (X4) 立面 → MIT-454 (X6) A=X3d 批次二/三收口 |
| G8 | Div/Idiv（x86 面）——**MIT-X7 (MIT-455) 批二翻正**：`build_div_idiv_x86` 真 handler 入 x86 表（92→94 行，除零/商溢出 = 真 #DE 直通 = x64 build_div_idiv D2.1 同口径镜像，flags setcc5_x86 捕真值；除数临时静态避 {eax,edx} 双位）+ lifter translate_cdq x86 S32 开面（真实 idiv 恒有 cdq 前置，Div face 必要条件；cqo REX.W 防御拒维持）+ 样本 wvmp_x86_div_sample（div reg/mem + idiv cdq + 负除数，池 15→16）+ 电池 DivIdivQuotRem（43→44）；wvmpTest b59b 翻正 stubs 11→12 | ~~stub_link x86 白名单 gate（同 G7 通道）~~ → 真虚拟化 | MIT-444 (X3b) D2 拍板 + MIT-446 (X4) gate 化 → MIT-X7 批二翻正（X7 批一 triage §3.3：x86 div 族 89/112 文件命中，D4 x64 真行为实读后镜像） |

## X2a 形级 fork 面收口（MIT-442）：六形态折叠 + x64 全链实证

**状态（2026-09-01，分支 `mit-x2a-fork-fold` 基于 main 110a6aa）**：X0 §1.4
fork 面六块落地——**kVmOpMax=97 不动（全折条）、零新 handler（asmgen.cpp
零 diff 机器证明）、冻结契约零触碰**。

| X0 §1.4 行 | 本单裁决 | 折条/门形态 | 证据级 |
|---|---|---|---|
| leave（0.37% 非 FP 缺口第一） | ✅ 收 | `[Mov rsp←rbp; Pop rbp]` 两既有 IR（extra 通道，426 先例）+ translator push/pop 栈宽按 size 派生 | x64 全链 E2E（样本区1，bal=0 + ret 值断言） |
| plain 串形 movsd/lodsd/scasd/stosd/cmpsd（dxcompiler 10116 级） | ✅ 收 | 单发微程序 = G3 rep 微程序"循环一次"（载体域 23..27，kStrPlainBase）；movs/stos/lods 无 flags 包裹、scas/cmps Cmp 后直落（flags=末次比较） | x64 全链 E2E（样本区3，movsd×2+lodsd+cld） |
| cld | ✅ 收（D5） | DF←0 与 VM DF=0 假设一致 → Op::Nop 放行（对齐 415 DF 判）；std → gate（G3 行） | x64 E2E（区3 区内 cld）+ 单测 |
| call [mem]（msvbvm60 35% of call）/ call reg | ⛔ gate（D4 停手） | lifter 开口（Call dst=Mem/Reg）→ translator X3 披露 note；CallGate reg-target 通路 = asmgen 改动归 X3 | x64 E2E 负例区2/2b（IAT 形 FF 15 / call reg FF D0）+ 代码直读证据（asmgen.cpp step1） |
| **call [mem] / call reg（X3c 翻正, 本行取代上行）** | ✅ 支持 | **MIT-445 (X3c) B.1**：translator 双 skip 解除 + asmgen build_callgate reg 值目标形（a_kind=Reg 判别, 零新 VmOp）；mem 形折条 Load/LoadRva(S64)+CallGate(reg)；x64 全链实证 forkface 区2/2b 翻案（stub 3→5, gate note 全消, 输出串恒同）；x86 电池真执行 3 用例 | 分支 c24e159；x86 CallGateRvaFormRealCall/CallGateRegFormRealCall/CallGateRegFormComputedTarget |
| S16/p66（0.82%） | ✅ 收（D2 双向授权实测通过） | GP 面 S16 全通（lifter data_size / translator size_field / runtime size_chain 4 路分派 + S16 别名写回——G3「S16 通路现成」声明首次真验成立）；栈面例外：S16 push/pop 栈推进 2B 不在 VM 栈模型 → gate（修复旧静默错形）；S16 串形维持砍面（G4 行） | ctest S16 语义电池（Mov/Add/Sub/Load/Store/Cmp+Jcc/别名保高 48 位）+ x64 E2E（区4，66 B8/03/89/BA/33/3B/83） |
| cwde/cbw（98，低频） | ✅ 收 | cwde = `[Movsx{Rax←Rax,S32,S16}; Mov{Rax←Rax,S32}]` 两 IR（build_movsx qword 写回高位污染 → "mov eax,eax" 零扩展 idiom 补偿——单条直折不可行实测钉死）；cbw（66 98，高 48 位保持）= translator 载体微程序（Op::Movsx + src2=Imm(28)=kExtCbw，GetFlags/SetFlags 包裹 8 VmOp） | ctest 槽语义电池（CwdeFoldSlotSemantics/CbwCarrierSlotSemantics）+ x64 E2E（区4，98/66 98 MASM 直编） |
| shld/shrd | ⛔ 维持（X3） | 结构性必收但归 X3（派单分工），本单不动 | — |

**B.2 五处 412 时代 S64 硬编码点复核（逐点披露）**：412 §2 所记
translator.cpp:127-145（跳转表）/ :316-323（imm64 split）/ :328-346（rip 地址
拼装）/ :370、:403（mem disp）五点，行号按 main 110a6aa 重定位后逐一复核——
**全部为常量误名（VM 64 位槽内部宽度，非架构宽度）**：跳转表表项宽 = scale
4/8 双架构同款；imm64 拆条在 x86 不可达（RVA 恒 u32，fits_aux 恒真）；槽算术
S64 是 VM 槽宽与 arch 无关。**真 arch 分叉点 = 栈宽**（push/pop/leave 的
stride 与访存宽——已按 IR.size 派生分叉，x64 8B/S64 逐字节不变，x86 4B/S32
纸面级）+ runtime pop 宽度（build_ret，asmgen X3/X4 参数化面，438 已登记）。
x64 零 diff 由 multiseed 245 既有全绿 + wvmpTest stubs=14 双跑 diff 0 兜底。

**区内 push 写穿 stub 保存区（#33 E2E 实证，边界规则化）**：样本首版把
`push rbp; mov rbp,rsp` 放区内 → packed bal 探针分叉。机制：stub callee-saved
保存区位于 [ns-8 .. ns-0x40]（ns = stub 入口 rsp = v4 预载值），区内 push 写
[v4-8] 与保存区首槽重叠，后续局部槽写覆写保存的 rbx → 出口链 pop rbx 读到
guest 数据（观察值 = 入参合成值 0x1E00000007，机制吻合）。438 build_ret 注释
「guest 未配平 push 写穿」登记面的 E2E 实证 + 规则化：**guest 栈写必须恒
≥ ns**——样本区1 改为 prologue（push rbp/mov rbp,rsp）原生在区域外、
leave/epilogue 面收区内（局部槽写 [E-16] 在 ns 上方零触碰），修复后
byte-exact。此规则对后续含栈帧形态样本（X3 epilogue 面）为设计约束前置。

**X0 §1.4 行号更新对照（交付后 fork→direct 翻正行）**：leave → 折条收；
plain movsd/lodsd/stosd/scasd/cmpsd（S8/S32/S64）→ 单发收（S16 形维持砍面）；
cld → Nop 收；cwde/cbw → 折条收；mov r/m16（p66 GP 面 S16）→ 全宽收（S16
push/pop 与 S16 串形除外）；call [mem]/call reg → gate 面（G5 行，X3）；
shld/shrd → 维持（X3）；std → gate 面（G3 行）。x86 侧全部为纸面级（rc=2
硬拒维持，X0 §F.3 证据分级），x64 侧 = 全链 E2E 实证。

## x87 (永久 gate, R3 裁决) —— 文档化不保护

**状态（2026-08-30，MIT-416/G5r triage 实测 + MIT-418/R3 收口）：x87 全族
（D8-DF）入标记区 → lifter "未支持指令" note → C1 gate 整函数保持原生 →
输出 byte-identical，不产坏壳。行为承诺 = 永久 gate（文档化不保护），
回归样本 `wvmp_x87_gate_sample`（区域内五族 fld/fadd/fstp/fcomip/fsin 各
≥1 条 + 同 exe 纯 GP helper 真虚拟化区）钉死该行为（multiseed 35 样本 × 5
= 175/175）。**

**全族清单（8 组，416 §1 表，真实出现频率 = 实测样本命中密度）**：

| # | 家族 | 指令 | 真实世界频率 |
|---|---|---|---|
| 1 | 数据传输 | fld/fst/fstp/fild/fist/fistp/fbld/fbstp/fld1/fldz/fldpi/fldl2e/fldl2t/fldlg2/fldln2 | 高 |
| 2 | 算术 | fadd/fsub/fmul/fdiv(±r,±p)/fi*/fabs/fchs/fsqrt/frndint/fprem/fprem1/fscale/fxtract | 高 |
| 3 | 超越 | fsin/fcos/fsincos/fptan/fpatan/f2xm1/fyl2x/fyl2xp1 | 中（仅 CRT/运行时实现） |
| 4 | 比较 | fcom/fcomp/fcompp/fucom*/fcomi/fcomip/fucomi/fucomip/ftst/fxam | 中 |
| 5 | 条件移动 | fcmovb/be/e/nb/nbe/ne/nu/u（8） | 低–中 |
| 6 | 状态控制 | fldcw/fnstcw/fnstsw/fstsw/fclex/fnclex/finit/fninit/fldenv/fnstenv/fnsave/frstor/fnop | 中 |
| 7 | 常数加载 | fld1/fldz/fldpi/fldl2e/fldl2t/fldlg2/fldln2 | 中 |
| 8 | 杂项/栈管理 | ffree/fincstp/fdecstp/fxch/fnop | 低–中 |

**频率数据摘要（416 实测，26 真实二进制 + 30 探针，方法/样本集/反例见
`.multica/mit-G5r-triage.md` §1/§2）**：x64 MSVC 世界 x87 ≈ 0（0.0000–
0.0032%，全伪影点检）；mingw x64 0.0006–2.12%（msys runtime/CRT 类库）；
32 位世界 0.01–0.88%（OS 运行时/CRT 集中）；x64 上唯一合法入口 = 手写 asm。
v145 MSVC x86 默认 /arch:SSE2（cl /help 实测），显式 /arch:IA32 才涌出
（2.17–11.45%）。x64 长期保持原生零成本，受保护函数含 x87 时整函数不保护
（性能零影响，安全面收缩）。

**路线记录（防未来考古困惑）**：
- **R1（全量 x87 排波）不排波**——x64 频率 ≈ 0 支撑不足；蓝图（L0–L4 分级 +
  ST 栈模型成本量化）留档 `.multica/mit-G5r-triage.md` §4/§5，若未来 G7 x86
  P1 立项且走 IA32，IA32 浮点档口重开、蓝图直接生效；
- **R2（32 位目标捆绑）随 G7 P1 立项时评估**，不单独投；
- **跳表 128→256 扩容** = x87/ymm 未来前置（kTableEntries=128；现
  kVmOpMax=97（MIT-427），98 项已用（0 哨兵 + 1..97）、余量 30——历史：
  MIT-425/G1b 后曾为 95（96 项、余量 32）；G9r §3.3 重算：x87 L0 ~80 op
  → 98+80=178 > 128 溢出（唯一必然触发者），ymm 档B 群 20–30 op → 128
  恰好临界（实质触发者），BMI G8a flagless +4 / G8b +3 → ≤102 不触发；
  扩容成本 S 级实锤（G9r §3.2 spike：128→256 单行改，build 408/408、
  ctest 16/16、multiseed 230/230，码体 +1032B/壳、PE 文件 +1024B）；
  触发条件 = 任一批次使 kVmOpMax+1 ≥ 128，届时作为该批次前置 commit 随单
  落地（先行合入、独立可回滚），不独立立波——432 §3.4；x87 全族 ~80 新
  VmOp 会把 128 撑爆，拆单蓝图预埋，见 triage §6 #2）；
- **callgate FP 参数/返回值修复** = x87 任何路线的前置依赖（P0，独立派单
  MIT-417，当前 SSE 世界即中招，见 triage §6 #1）；
- 16-bit 目标不可行（交叉引用 C5 节，PE 格式白名单只收 0x014C/0x8664）。

**裁决边界（D2）**：本面是"文档化不保护"承诺，**不是实现级支持面**——
若未来实测发现 x87 某条（如前缀组合）绕过 gate 进了 VM 产出坏壳，属 P0
级新洞，立即上报，不归本面兜底。

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
生态无 16 位 PE 现实需求（triage §4）。x87 面交叉引用：16 位 x87 形态
（x87 数学协处理器 / 16 位栈拓扑）随 16 位目标整体不可行，见 x87 节路线
记录。

**观察清单（triage §8 新耦合转录）**

- **CRT 初始化区 E8 误归属**（triage §8 #4）：32 位 CRT 初始化近距调用密集，
  kStubWindow=64 窗口内 E8 目标落入锚点前 ≤64B 的概率高于 x64（craft32 实测
  2 个误归属 begin）。规则内设计行为，低危（只产生多余 warning + 潜在空区域）；
  未来归属规则可加"目标与锚点间无可执行指令"类强校验或降窗口。
- **ExitNative .pdata 依赖在 x86 天然失效**（triage §8 #6）：x86 通常无
  .pdata → find_function_end_rva 退 nullopt → 保守 gate 兜底，行为差异非缺陷。
  **【MIT-453 (X5c) 翻正】**该面已按 F1 收口（区域表回退 + 末区 .text 节尾
  兜底 + 节尾 cap），x86 ExitNative 17 处全翻正——见「X5c 收口」节。
- **CLI 无 arch 表达面**（triage §8 #7）：config 无 arch 字段、无 --help 子命令，
  32 位全支持需配置面扩口（P1 G7x-7）。

> **里程碑归属（MIT-GZ D3，2026-08-31）**：x86 (PE32) 目标支持已由项目主
> 拍板剥离出指令虚拟化阶段，独立里程碑“**多目标平台**”（计划后续另立，
> 见 `docs/STATUS.md` 阶段宣告节）；本节内容按 MIT-412/414 收口原样保留。

> **X1a 增补（MIT-437，2026-09-01）**：x86 扫描面已就位（X1a，marker_scan
> 双段 magic 识别 + `fr.arch` X86 落位 + SDK x86 产物位），管道路径保持
> rc=2 硬拒原样，虚拟化消费由后续单接力；实测形态与判据见
> `passes/marker_scan/include/wvmp/passes/marker_scan/scan_core.hpp` 双段
> 注释（上列旧主张 1 的"不连续"实证即本单收口对象）。

> **X3a 增补（MIT-443，2026-09-01）**：asmgen x86 核心就位（KS_MODE_32 双模
> + 池 6/临时 4 分配器 + entry/dispatch + 电池集 19 handler 真执行电池），
> C5 的 asmgen 断层（旧主张 3）对 x86 码体生成面**翻正为已闭合**；全管道
> 解禁仍维持 D1 红线（X5 收口拍板），x86 (PE32) 平台行保持显式硬拒。详见
> 下节「asmgen x86 核心」。

> **X4 增补（MIT-446，2026-09-02）**：**D1 解禁落地**——pe_loader x86 通行
> （auto（槽缺省）/ 显式 arch=x86 双形放行；mismatch（arch=x64 + 0x014C /
> arch=x86 + 0x8664）维持 rc=2 硬拒；上文 X1a/X3a 增补中的"rc=2 硬拒维持 /
> 不随本单解禁"表述自本单起翻正）。全管道 = marker_scan 双段 magic → lifter
> pointer_size → translator（S64 tag 改形后）→ runtime_x86 → stub x86 cdecl
> → pe_writer，E2E 首批 3 族级样本 WOW64 byte-exact。详见下节「x86 全管道
> 打通（MIT-446 X4 收口）」。

## asmgen x86 核心：KS_MODE_32 双模 + 池重构 + x86 runtime 电池（MIT-443 X3a 收口）

**状态（2026-09-01，分支 `mit-x3a-asmgen-core`）**：asmgen.cpp 双模化合入
（x64 输出路径按 D6 逐字节恒等），`generate_runtime_x86`（新头
`runtime_x86.hpp`；runtime.hpp/kCtxSize 零 diff，D4 冻结不破）产出 32 位
解释器码体，11 用例 x86 电池在 32 位测试进程（WOW64）真执行全绿
（`ctest --test-dir build\x86 -R x86_runtime_battery`，构建 =
`scripts\build_x86_tests.bat` vcvarsamd64_x86 交叉链）。

**池重构设计（验收 §D.3 映射表）**

| 角色 | x64（池 14） | x86（池实测 6） |
|---|---|---|
| ctx_ | callee-saved 池随机（callgate 约束） | callee-saved {ebx,ebp,esi,edi} 随机其一 |
| base_ | callee-saved 池随机（其余） | callee-saved 随机另一（dispatch 跳表基址） |
| pc_ | 寄存器（pool[0]） | **内存常驻 [ctx+0x8]**（既有持久槽，零新字段） |
| flags_ | 寄存器（pool[1]） | **内存常驻 [ctx+0x98]**（= regs[17] 同槽） |
| t_[0]/t_[5] | callee-saved 固定（callgate 参数避让） | 数据临时 t_[0]/t_[1]：**字节可编码集 {eax,edx,ebx} 均匀抽 2**（al/dl/bl 可编码；bpl/sil/dil REX 专属名 32 位不可编码 —— B.1 rs() 复用度真验结论：四名列对 32/16 位全就位，字节档仅部分就位） |
| t_[1..4]/t_[6..9]（8 个临时） | pool 洗牌 | 寻址临时 t_[2]/t_[3]：池剩余 2 位洗牌 |
| spill 纪律 | 不需要（10 临时充裕） | **固定宿主栈帧 kX86FrameSize=0x24**：entry `sub esp,0x24` 常量槽（insn_lo/aux/reg_a/reg_b/size/a_kind/b_kind + setcc 捕获区 5 字节），esp 跨指令稳定，零动态 push/pop；池尽溢出走帧槽（非 ctx 扩容，D4） |
| zero5 | 清 T3/T4/T6/T7/T9 五寄存器 | **空**（setcc 直写帧槽全字节 + movzx 全字节读取，无需预清零）；x86 形影响 handler 清单 = 全部 flags 捕获族（本单 9 个：add/sub/and/or/xor/cmp/test/inc/dec；X3b 批迁同模板） |

**entry/dispatch（D2/D3 按拍板默认）**：BASE 取址 = call/pop idiom（
`push base(1B); call next(5B); next: pop base; sub base,6`，确定性偏移回指
码基址，不涉 pe_writer reloc 面）；跳表保 8B 表项（x86 读表项低 dword，表
字节格式与 x64 逐位一致，掩码/两遍法零改动）；dispatch 双字取指落帧。

**保存区裁决（B.4，验收 §D.4）**：**维持 442 规则 "guest 栈写恒 ≥ ns"，
不重排**。理由：(a) x86 epilogue 与 x64 同构（4 callee-saved push/pop +
ret），保存区冲突形完全同构（x86 侧 [ns-4..ns-0x10] 更小），442 反例形
（区内 push 撞保存区）由 lifter 保守 gate 整函数兜底，行为已规则化；
(b) 重排保存区必牵 stub_gen 布局 = X4 单范围，越单；(c) x86 电池（本波
真验证通道）无 stub 无区内 push，规则维持零成本。证据 = 442 区1 反例的
E2E 分叉记录（GAPS 本文件前节）+ 本单 x86 epilogue 对称性设计。

**x86 handler 面（X3b 收口后，MIT-444 2026-09-01 —— 本节为 X3c 权威输入）**：
真可跑（x86 表 57 行，全部带真执行语义电池 + dump 门登记）= 电池集 19
（Mov/Lea/Add/Sub/And/Or/Xor/Cmp/Test/Inc/Dec/Load/Store/Jcc/Jmp/Nop/Halt/
GetFlags/SetFlags）+ A 档整数面 29（Not/Neg/Adc/Sbb/Imul/Mul/Cdq；Shl/Shr/
Sar/Rol/Ror + ShlCl/ShrCl/SarCl/RolCl/RorCl；Movzx/MovzxMem/Movsx/MovsxMem/
Bswap/Xchg；Setcc/Cmovcc；Popcnt/Lzcnt/Tzcnt/Cmpxchg）+ 锁原子 4（Xadd/Bts/
Btr/Btc）+ B 档 GP 5（Push/Pop/LoadRva/StoreRva/LeaRva）。三宽度 S8/S16/S32；
S64 块/不可达形防御 no-op（经 size_chain_x86 链尾出口）。
**仍纸面（跳表折叠 Halt，恢复友好）精确清点 = 39**：Div/Idiv（2，D2 拍板
除零折叠，真 #DE 语义未定义，X3c/未来单评估）、Movsxd/MovsxdMem（2，x86
native 无 movsxd 且 lifter translate_movsxd arch!=X64 拒 —— x86 不可达面，
且 32→64 符号扩展写满 8B 槽会破 "槽高半字恒 0" 不变量，永久纸面合理）、
CallGate/ExitNative/Ret（3，协议面 4B 化 = X3c 主体；Call 无 x64 行不在
96 集内）、SSE 族 32（Addss..GpFromXmm 去 Xadd/Bts/Btr/Btc —— 编码双平台
相同，槽位偏移公式按 x86 帧/寄存器面重核 = X2b/X3c 面）。粗数对账（#33）：
派单/GAPS 旧文 "仍纸面 ~77/78 op、A 档 ~45、SSE 34" 按实表修正为
77 = 38 批迁 + 2 D2 + 2 不可达 + 3 协议 + 32 SSE；批迁 38 而非 45（差值
= D2 Div/Idiv 2 + Movsxd 2 + SSE 误计入 A 档面 3+）。电池可扩展设计
（X3a 设计兑现）：`tests/test_runtime_x86.cpp` 加 TEST + handler 表加行 +
`scripts/verifier/verify_x86_dump.py` BATTERY_HANDLERS 同步，三处每 handler
齐动（本单 38 op 全数践行）。

**X3b 三项裁决（MIT-444 实测钉死）**：
1. **Push/Pop 4B 槽**：guest esp 步进 4B（S32 栈宽）⨯ ctx rsp 槽 8B（VM 槽
   宽，442 "rsp 槽算术恒 S64" 注的真义）—— 槽内值恒 32 位零扩展（"槽高半
   字恒 0" 不变量）⇒ dword 低半字 sub/add 等价 64 位槽算术且回绕 = 32 位
   esp native 语义（build_push_x86/build_pop_x86 落地）。⚠️ X4 挂账：翻译
   器 emit_address/translate_push·pop 的 rsp 步进 VmOp::Sub/Add 与 rip-RVA
   VmOp::Mov 均带 size_field(S64)（VM 槽宽 tag）—— x86 运行时 3 路链把 S64
   折防御 no-op，x86 全管道解锁（X4 stub + X5）前必须改为 VmOp::Push/Pop
   单 op 形（本单已备好 4B 正确 handler）或 S32 步进参数化，否则静默空转。
2. **x86 移位计数掩码 = 0x1F 全宽**（32 位模式 legacy/compat 恒 5 位掩码，
   SDM 6 位掩码仅 64 位模式 REX.W）：count=0x20 → 计数 0 出口（值+flags 双
   不变，电池钉死）；count=0x21 → 移 1 位。x64 S32 档沿用 0x3F handler 掩
   码（64 位模式下无 REX 的 S32 native 仍内掩 0x1F）—— count∈32..63 且消
   费 flags 时存在同形污染窗口，属 x64 既有面，X3b 未触碰（零 diff），记
   观察项。
3. **RVA 族 = base+RVA 非 identity**：PE32 VA = ImageBase + RVA 仍成立
   （battery RvaFamily 以 base≠0 反证钉死）；image_base 经 ctx+0x110
   scratch_mem 低 dword 参与运算，u32 值域零溢出顾虑。

**B.3 translator 收口证据（MIT-444，零代码改动面）**：
- **pop 位宽对称面**：派单 A.2 "442 只 gate 了 push S16/S8" 与实况失配 ——
  `git log -S "pop 位宽未支持"` 定位 5ce27c7（MIT-442）同时引入
  translate_push/translate_pop 的 S16/S8 gate（translator.cpp:1508/1522），
  pop 对称面 442 已收口，X3b 核对 = 零 diff 兑现。
- **S16 串形元素宽**：维持 gate（不做）。做不动证据链：lifter 是唯一 S16
  串形来源闸（x86_translate.cpp translate_string_op ① prefix[2]!=0 拒 +
  ⑤ width∉{1,4,8} 拒），而 lifter 冻结（D3 唯二解禁 = asmgen/translator）；
  translator 侧 inc 派生 `S64?8:S32?4:1` 对 S16 恒错（应为 2），单改
  translator 不开闸 = 不可达死代码。X3c/未来单开面配方（两文件最小 diff）：
  lifter ⑤ 放行 width==2（size=S16）+ 翻译器 inc 派生补 `S16?2` 分支 +
  Load/Store/Cmp VmOp S16 槽通路（x86 电池 28 用例已证 S16 handler 全绿，
  运行时零改动）。442 负例区行为对账：S16 串形样本仍走 C1 gate 兜底
  （multiseed 250/250 含 forkeface 样本全绿 = 证据）。

**验证铁证（X3b 增补）**：x64 零扰动 = 同 seed（12345）snake protect 的
asm_dump 逐字节 cmp 恒等（main 4050a4c 底稿 vs 分支每 commit 批次复验，
161756 B，sha f67c2d40…）+ multiseed 250/250（REQUIRE_REAL）+ wvmpTest
stubs=14 + jump-table@0xDD84 entries=8 + exit-native 17 + 双跑 103/103
diff 0 + ctest 16/16；x86 = 电池 28 用例（真执行语义 + capstone CS_MODE_32
反汇编断言 + 5 seed 稳定性 + 批迁面 ≥15 op 抽样链）+ x86 dump 门 PASS
（57 handler 登记全覆盖 + 首条可解码）+ 静态立即数扫描双跑 PASS（asmgen.cpp
源面 + x86 dump 文本面）。批迁过程缺陷实录（#33，电池当场炸出当场修）：
xadd 旧值写回误用 kind 值槽代索引槽（写错槽）、cmpxchg S8 源载体未约束字
节可编码集（seed 相关 ks_errno=512）、setcc tail 复用 cond 载体作槽索引
（写错槽）——三处均为 x86 emit 面缺陷，x64 恒等逐批次复验未受扰。

## asmgen x86 协议面收口：CallGate reg-target 双 arch + ExitNative 4B + Ret x86 形（MIT-445 X3c 收口）

**状态（2026-09-01，分支 `mit-x3c-protocol`，三批次 c24e159/a5f6848/9d9b38e）**：
协议三件套（X3b 纸面清单中 CallGate/ExitNative/Ret）全数收口为真执行；唯二解禁
asmgen.cpp + translator.cpp（限 translate_call 通路）全程遵守；冻结契约
（runtime.hpp/vm_op 97/kCtxSize/backend/lifter/cli/sdk/载体域 0..28）零 diff；
kVmOpMax=97 不动、零新 VmOp。

**B.1 CallGate reg-target（双 arch 同收, 442 D4 停手挂账翻案）**：
- **字节级编码布局（D1 拍板报告项）**：VmOp::CallGate 双形共用, 判别位 = a_kind——
  RVA 形（既有）: a_kind=None, reg_a 无义, aux=目标 RVA → VA = aux+image_base；
  reg 形（新增）: a_kind=Reg, reg_a=目标槽(0..31), aux=0 → VA = regs[reg_a]
  （槽值 = 绝对 VA；x64 槽全宽 u64 读 / x86 低 dword 读）。
- **x64 handler**：目标 VA 双形分派置于参数快照（rax 搬运）之前——T3/T4 可能=rax,
  先读后快照（首版顺序被 forkface 区2 E2E 当场炸出, cdb 崩点 [rsi+rax*8+0x10]
  索引=快照残渣）；先读附带防御 reg_a∈24..27 reserved 覆写病态形。标签固定名
  （不吃 seq()）——seq 号被消费会让后续 handler 内部标签顺移, 污染 dump 对账口径。
- **translator**：Reg 形 emit CallGate(a_kind=Reg, reg_a)；Mem 形折条
  emit_load（rip 形→LoadRva / 非 rip→Load, S64 载目标值入 fresh scratch）+
  CallGate(reg)；双 skip（442 X3 披露 note）删除。
- **x86 handler（build_callgate_x86, 表 57→58）**：结构差异 5 点对账入注（cdecl
  0-arg 参数窗留 X4 / 窗口锚 = host_rsp [ctx+0x128] 自洽无需 native_sp /
  pc·flags 内存常驻零 save-restore / eax 低 dword 写回 / esp 窗口切换纪律）；
  窗口 kX86CallgateWindow=0x1000 16 对齐 + 探针写（406 同款）。
- **x64 全链实证**：forkface 区2/2b 从 C1 gate → 真虚拟化（stub 3→5、双 skip
  note 全消、stdout byte-exact rc=0：bal=0 哨兵 / callmem=997 / callreg=998 /
  str=… / s16 全组恒同）；callee-saved 影响 = ctx_/base_ 恒 callee-saved 跨
  call 存活（roll 约束）+ pc/flags/base 快照恢复链不变, 逐 step 对账零新增面。
- **dump 对账（B.7, 分级口径）**：x64 @12345 f67c2d40(161756B)→ffd47289(161861B)：
  entry 逐字节恒等、dispatch 仅 1 行表偏移（0x69C8→0x69D8）、**唯一码体 delta =
  callgate handler（+6 行 a_kind 分支）**、跳表 20 项机械顺移。⚠️ 口径勘误（#33
  亲测钉死）：asm_dump 是 seed 的纯函数（与样本无关——snake/forkface @12345 同
  sha 实证），派单"48 样本恒等 + forkface 例外"的前提机械上不成立——callgate 码
  体 delta 以同形出现在全部样本 dump；等价口径 = 逐 handler 对账（唯一 delta 段
  = callgate）+ 行为恒等（multiseed 250/250 输出串逐字节恒同）。
- **x86 电池**：CallGateRvaFormRealCall（base≠0 非 identity 反证）/ 
  CallGateRegFormRealCall（reg 形真调用, g_xcg_calls 递增 + 返回值写回）/
  CallGateRegFormComputedTarget（LeaRva 运行时算出目标）。

**B.2 ExitNative x86 形（表 58→59）**：无条件 a_kind=Imm(2) / 条件 a_kind=None +
cond_or_size=Cond 16 路链（build_jcc_x86 同构）；4B 退出槽 = dword [native_sp −
kX86ExitSlotDepth(=4*4+kCtxSize+0x80=0x258)]（asmgen.cpp 单一来源派生,
runtime.hpp 冻结零触碰; **X4 stub_gen 读侧对接锚**）; epilogue = add esp,0x24 +
4 callee-saved 逆序 pop + ret（build_halt_x86 同构）; 退出不 advance（x64 同）。
电池：ExitNativeUncondSlotProtocol（槽落账 0x401234 + pc 不写回）+
ExitNativeCondTakenAndFallthrough（cond E 双路）。

**B.3 Ret x86 形（表 59→60）**：ret_addr = dword [v4]; v4' = v4+4+imm（aux 槽,
translator 0xFFFF 掩码既有; dword 回绕 = native esp 语义, 444 裁决表"零扩展不
变量+dword 低半字算术"）; ret_addr → [v4'-4] 死槽; 出口 = 弃帧(0x28)+4 pop+
物理 esp := v4'（宿主栈 push 暂存 + [esp−0x38] 坐标读, 常量
kX86RetV4SlotFromExitRsp=0x38 派生 + static_assert）+ jmp [esp−4]。⚠️ 实战缺
陷修正（cdb 铁证 eip=0/esp=guest_top−4）：push 暂存必须在死槽指针 (t0−=4) 之
前——先减后 push 把死槽地址当 v4' 存入。438"guest 栈写恒 ≥ ns"对账：[v4'-4]
死槽写与 x64 [v4'-8] 同形, 与 x86 保存区 [ns-4..ns-0x10] 重叠仅在未配平 ret
病态形（同 x64 EXIT_SLOT 重叠披露）。电池：RetPlainStackBalance（naked
landing + longjmp; v4'=top 平衡 + eax=0xBEEF 写回 + [ctx+0x30] 持久化）+
RetImm16StackBalance（stdcall 栈序 ret 8 清栈回原点）。

**x86 dump 对账口径（X3b→X3c）**：57→60 handler 每波重立底稿（X3b 19→57 同
款机制）：新表行改变 shuffle 排列 → seq 标签号分配序漂移 → 既有 handler 文本
标签号变化（归一化后码体结构零 diff——X3c 实测 40/40 纯标签）；x64 面无此效
应（callgate 标签固定名 + build_ret_x86 仅入 x86 表 → x64 dump 三批次恒等
ffd47289）。

**X4 交接注记**：
1. **S64 tag 改形精确点位（444 挂账, translator.cpp）**——x86 全管道解锁前必改,
   否则 rsp 步进/地址算术在 x86 运行时 3 路尺寸链折防御 no-op 静默空转：
   ① translate_push / translate_pop 的 rsp 步进（emit_ri(Sub/Add, rsp, 8u/4u,
   sz64)）；② emit_address 双形全链（rip 形 :710-732 / 非 rip :738-772, Mov/
   Shl/Add/Sub 全 sz64）；③ emit_imm64_split（:680-684）；④ LeaRva 通路
   （:875-876）；⑤ G3 串微程序 rsi/rdi/rcx 步进（:1119-1241 域内多处）。
   改形方向：栈步进改 VmOp::Push/Pop 单 op（X3a 已备 4B handler）或 sz 参数化;
   地址算术改 S32 步进 tag。改形必须与 x86 电池联动（S64 防御出口改后需防回归）。
2. **stub ABI 对齐锚**：B.1-B.3 未动 x86 entry/帧形（kX86FrameSize=0x24 不变）
   ——x86 stub_gen 对接锚 = ① ExitNative 槽读 [ns−0x258]（kX86ExitSlotDepth,
   asmgen.cpp 单一来源）；② callgate 窗口锚 = host_rsp 自洽（stub 无需预置
   native_sp 之外的量——但 ExitNative 仍需 [ctx+0x120] native_sp）；③ Ret 出口
   坐标 0x38 在"entry 4 push + 0x24 帧"不变量下成立, stub 帧形若变需同步该常量；
   ④ x86 callgate 参数窗（cdecl 栈参数预置）= X4 落（D2 拍板不特化）——落参窗
   时 build_callgate_x86 与 stub_gen 两处同步。
3. **S16 串形配方留档核对**（444 遗留）：lifter ⑤ 放行 width==2 + translator
   inc 派生补 S16?2 分支 + Load/Store/Cmp S16 槽通路——两文件最小 diff 配方
   仍有效（lifter 冻结未触, 本单未动）。

**B.5 shld/shrd/cwd 评估（442 挂账④, 只出数裁决不实施）**：
- **shld/shrd**：语料低频——X0 missing 表内无独立频数（64 位算术偏走 CRT
  __allshl 调用）, probe_64 rgn_wide 16 条中 2 条（12.5%, 收面后 100%）但"结构
  性必收"（64 位移位仿真惯用）。**裁决 = 折条可行, 挂观察清单**：imm/cl 形可零
  新 VmOp 折条（d = (d<<(c&31)) | (s>>(32−(c&31))) 微程序 5-7 op + flags 尾部
  Or, 同 G8a 折条模式）, 但 lifter 无 lift 形（442 grep 亲验）→ 需先开 lifter
  （冻结面, 同 S16 串形"两文件最小 diff 配方"模式）。触发条件 = 客户语料命中。
- **cwd**：capstone 双 id 归 cwde 系（442 亲验"cwd 双 id 仅 cwde/cbw 系"）, X0
  missing 表**无独立条目**（语料 0/噪声级——MSVC 16 位 DX:AX 仿真不产现代产物）。
  **裁决 = 不立项**；cwde/cbw 已由 442 收口覆盖符号扩展语义面。若未来语料命中,
  折条 = Movsx(S16 源) 写 dx 槽 + ax 保留, 同款两文件配方。

## x86 全管道打通：stub cdecl 重写 + S64 tag 改形 + D1 解禁 + E2E 首批入池（MIT-446 X4 收口）

**状态（2026-09-02，分支 `mit-x4-stub-e2e` 基于 main e20b383）**：x86 战役
"从 0 到 1"一棒收口——PE32 输入→全 pass 链→packed PE32→WOW64 真执行，
main 自本单起具备 x86 生产能力。x64 零扰动铁证 = asm_dump @12345 sha
`ffd4728901812932…`/161,861B 逐字节恒等（全批次五次 cmp 实证）。

**B.2 S64 tag 改形（444 X3b 挂账，五点位 + 同族残段 ×3）**：Translator 新增
`arch_/sz_step_` 单一来源（translate_function 按 fn.arch 派生，x64 = S64
现形 / x86 = S32）。点位：① translate_push/pop x86 分叉改 VmOp::Push/Pop
单 op 形（X3b 4B handler），x64 Sub+Store 现形逐字节不动；② emit_address
双形全链；③ emit_imm64_split（x86 fits_aux 恒真不可达，防御形）；④
LeaRva 通路（emit_sse_mem_addr / lock xadd / lock bit）；⑤ G3 串微程序
步进 + flags 包裹。清单外同族残段 ×3 一并参数化（披露）：跳转表比较链
（413 面先于 442 审计，同"地址算术折 no-op"类）/ bzhi 边界 CF 补丁段 /
cbw 载体 stash 合并段（x86 S32 形 = 66 98 native 位 31:16 保持语义，
"槽高半字恒 0" 相容）。fallthrough Jmp 维持 S64（x86 build_jmp 无尺寸链
实测无害）。防回归 = translator 双 arch 快照 ×3（X86 Push/Pop 单 op 形 =
复辟探测器）+ 电池 StepTagS32LiveAndS64NoopGuard（S32 真块推进+访存 vs
S64 链尾 no-op 双钉）。

**B.1 stub x86 cdecl 形（stub_gen.cpp 双形化）**：`StubArch` 注入通道 +
`build_stub_asm_x64`（逐字保留）/`build_stub_asm_x86`。差异清单：4
callee-saved push（kStubPushBytesX86=0x10，mod-16 static_assert，与
kX86ExitSlotDepth 派生式互锁）；ctx 经 `push esp` 栈参对接 runtime_x86
entry `[esp+0x14]`；ctx 区 `rep stosd` 清零（"槽高半字恒 0" 不变量的栈帧
来源；eax/ecx/edx/edi 四寄存器临时捕获——⚠️ **edi 必须恢复**：Ret 直退
路径不经 stub 出口 pop，runtime 出口恢复"进入时刻" callee-saved，碎 edi
污染 guest caller 帧，E2E 首通实录 stdout 空 + 0xC0000029）；预载 eax..edi
8 槽（保存区读回偏移 = kCtxSize + 0x10 − 4(i+1)，**先 push 在高址**——
首通实录：顺序写反致 slot5(ebp)=原 esi 值，[ebp−4] 写飞，cdb 铁证
`mov [edx],ebx` edx=0x7717667C=原 esi−4）；易失回写 eax/ecx/edx 三槽
（callee-saved 绝不从 ctx 回写——区域未含 epilogue 时 guest 槽值不可信）；
ExitNative/HALT 共用 `jmp dword ptr [esp − kX86ExitSlotDepth]`（4B 槽，
kX86ExitSlotDepth 单一来源上移 runtime_x86.hpp）；blob 指针 imm32 VA（32
位无 rip 寻址，免 x64 disp32 回填）；xmm 同步不适用（x86 无 SSE handler，
Win32 xmm 全易失）。

**B.1 callgate cdecl 参数窗（445 D2"不特化"挂账翻案）**：`kX86CallgateArgDwords=4`
协议（asmgen 与 stub 两处同步锚④）——handler step 2.5 从 guest
`[v4 + 4i]`（i=3..0 逆序 push，arg0 落最低）固定预置 4 dword 到 callee
窗口；guest 侧约定 = 区域把参数写 prologue 预留的 esp 上方 scratch
（`mov [esp+k], arg; call f`，写址 ≥ ns 合 442 规则）；cdecl caller-cleans
语义下多预置无害（0-arg callee 不读、esp 由 host_rsp 重基回收）；翻译层
零 arg_count 通路（cond_or_size 维持 0）。

**x86 白名单 gate（C2 类静默错的结构性封堵）**：asmgen x86 handler 表提为
`x86_handler_table()` 单一来源 + 导出 `x86_handler_opcodes()`（runtime_x86.hpp
契约）；stub_link 按 PeImage.machine 分叉：x86 目标逐条解码 blob，字节码含
跳表缺项 VmOp 的函数整函数保持原生（覆写 .text 前把"跳表折叠 Halt"C2 类
静默错拦成 C1 类显式 gate）。证据 = sse 样本 gate note（opcode: 85 68 85 86
85 68 86）+ 1 stub（helper 真虚拟化满足 REQUIRE_REAL）。

**B.3 D1 四象限（pe_loader）**：auto+x86 放行 / x86+x86 放行 / x64decl+x86
拒 / x86decl+x64 拒（mismatch 文案原样）；2.6 块限定 machine≠x86（修放行
路径落旧 x86 全局拒块的误伤，亲测当场炸）。单测 AutoDeclX86InputPassesAfterD1Unlock
+ TargetArchDeclGate 翻正。

**B.4 E2E 首批（3 族级样本，build/x86_samples/，multiseed 首次填池
250→265）**：① forkface-x86 移植形（整数 ALU/循环/位操作 + leave/ret 面
（prologue 原生收区外）+ rep movsb 非对齐/stosd/repne scasd/lodsd + p66
S16/cwde/cbw + call reg/call [mem] + ret imm16（asm wrapper 压参）+ x87 区
R-SSE-only 定稿 gate 负例）6 stub byte-exact；② SSE 面（movdqa/movdqu/
movaps/movups 折叠族 x86 形，**设计性 x86 白名单 gate 负例**——SSE 函数整
函数保原生 + 整数 helper 真虚拟化）1 stub byte-exact；③ 混合+cdecl
callgate 参数窗（3-arg/2-arg/0-arg/call [mem] 全经参数窗 + 第二真虚拟化区）
2 stub byte-exact。样本 ABI 纪律（D4 native 全绿先）：区域内只用
eax/ecx/edx + 全局内存、无 push（callee-saved 保护区不回写 + 442 guest≥ns
规则）；stdcall 面经 asm wrapper（C 主 cdecl 调 wrapper，ret 8 清栈在
VM 内）。B.5 pe_writer 评估结论：SizeOfImage(+56)/SizeOfHeaders(+60)/
CheckSum(+64)/节表追加以 PE32/PE32+ 同布局，零代码改动即就绪（E2E 实证）；
reloc/ASLR 口径 = 对齐 x64 现网事实（仅 ImageBase 声明 + 清 DYNAMIC_BASE，
不发布 reloc——pe_writer:39-42 注释同口径文档化，不扩面）。

**B.6 六件套（全绿）**：build 0 错 0 警 / ctest 16/16 / multiseed
265/265（REQUIRE_REAL，x64 250 + x86 15）/ wvmpTest stubs=14 双跑 diff 0 /
x86 电池 36/36（35+1）/ dump 门 60 项 PASS + x64 dump `ffd47289…` 恒等。

**已知 gate/缺口面清单（X5 交接）**：x86 运行时 60 handler 之外的折叠面 =
SSE 族 32（X2b/未来单，x86 白名单 gate 整函数原生）/ Div/Idiv 2（D2 除零
折叠维持）/ Movsxd·MovsxdMem 2（x86 不可达，永久纸面）；lifter 面 gate =
x87 全族（R-SSE-only 永久 gate）/ SEH·段覆盖（G1）/ 67 地址宽（G2）/ std
（G3）/ S16 串形（G4）/ shld/shrd·enter·cwd（G6）；B.2 同族残段已收
（跳表链/bzhi/cbw 一并参数化，x86 真块）。跳表余量 = kVmOpMax 97/128（30，
不动）。

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
  仅在 lifter 单测覆盖；（**lock 白名单族 = G4 面，见 G4 节**）
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

## G4 lock 前缀原子族 (MIT-419 收口 + MIT-423 G4b inc/dec 补齐, strip-and-execute + D1 原子性边界显式声明)

**状态 (2026-08-30, MIT-423 后): lock 前缀原子指令族全谱入面**——lifter
F0 前缀闸按白名单三元组放行 (add/adc/sub/sbb/and/or/xor × mem-dst + cmpxchg/
xchg/xadd mem 形式 + bts/btr/btc mem 形式 + **inc/dec × mem-dst S32/S64
(MIT-423 G4b)**, D4 仅 F0 独前缀 +REX), strip-and-execute 折条 (ALU 族 +
inc/dec 零新 VmOp) 或单 VmOp 直执行 (Xadd/Bts/Btr/Btc 新 handler 内 native
lock 指令 — **硬件原子性保真**)。multiseed 38 样本 × 5 = **190/190**,
wvmpTest 14/14 + 双跑 103/103 diff 0 保持。

**支持面**：`lock {add,adc,sub,sbb,and,or,xor} [m], r/imm`（本体折条）、
`lock cmpxchg [m], r`（折条）、`lock xchg [m], r` 与**裸 `xchg [m], r`**
（InterlockedExchange 真产物，xchg 访存隐式锁；折条）、`lock xadd [m], r`
（单 VmOp::Xadd，handler 内 native lock xadd 一条指令完成读改写，原子性
保真）、`lock {bts,btr,btc} [m], r/imm8`（单 VmOp，handler 内 native lock
指令直执行）、**`lock {inc,dec} [m]` S32/S64（MIT-423 G4b，本体折条
Load→Inc/Dec→Store，标记域 12..13）**。宽度 S8/S32/S64（bts 系与 inc/dec
S32/S64，inc/dec 字节形式 gate 见残余）；rip-relative 目标全支持（emit_address
+ LeaRva 通道；64 位全局 Interlocked* 真产物形态实证）。C++ Interlocked*
intrinsic 真产物形态（cl v145 14.51 实测 2026-08-30，/O2 与 /Od 双档 /FAcs
实证）：ExchangeAdd/Increment/Decrement(+64)→**lock xadd [m],±1 内联展开**
（_InterlockedIncrement 不产裸 lock inc —— 派活单 §A.3 "f0 ff 06" 先验被
实测推翻；真产物走 Xadd 硬件原子通路）、And/Or/Xor→lock and/or/xor [m],imm、
Exchange→裸 xchg [m],r、CompareExchange→lock cmpxchg [m],r——全部入面。
裸 lock inc/dec 形态属手写/第三方汇编（折条覆盖）。

**D1 原子性语义边界（项目主拍板，显式登记，非静默）**：
- **多线程并发原子性不保证**：VM 单线程解释器内 Load→op→Store 折条序列
  不被自身打断 → VM 线程视角原子性成立；但宿主进程其他原生线程并发 RMW
  同一地址时，折条路径存在撕裂竞态窗口（lock 前缀被 strip）。折条族 =
  ALU 族 + **inc/dec (G4b)**。inc/dec 折条 D1 论证（MIT-423 B.3）：真产物
  _InterlockedIncrement/Decrement 实测走 lock xadd ±1（Xadd 硬件原子通路
  覆盖），裸 lock inc/dec 无编译器产物 → 撕裂窗口暴露面限手写/第三方代码，
  与 ALU 折条同类；VM 内折条 inc/dec 复用 build_incdec 既有 CF 保留语义
  （旧 VM CF 保存→native inc/dec→ZF/OF/SF/PF 捕获→CF 回填），SDM
  "inc/dec 不写 CF" 逐位成立（样本 CF 探针 add→CF=1→lock inc→jc 全 VM
  往返实证）。xadd/bts/btr/btc 单 VmOp 路径由 handler 内 native lock 指令
  直执行，硬件原子性保真，不在本边界内。
- lock 的 MFENCE 全序附带语义（store-buffer 全序）在 VM 内不建模（单线程
  等价；多线程见上）。
- 行为承诺：**结果值/旧值返回/flags（cmpxchg 后 je 惯用法、inc/dec 后 jcc
  循环计数惯用法）在单线程 VM 内与原生逐位一致**——回归样本
  `wvmp_atomic_ops_sample` + `wvmp_atomic_incdec_sample`（dec r8d;jnz ×7
  循环 + CF 双探针，8 函数真虚拟化）钉死；双跑 byte-exact。

**src2=imm 载体域对账记录（MIT-423 B.1，419 铁律第 4 次教训固化）**：
lock 标记域现为 5..13（5..8=Mov 载体 xadd/bts/btr/btc，9..11=本体
ALU/Cmpxchg/Xchg，12..13=本体 Inc/Dec）；string family 0..4 分域。
全仓 src2=imm 任意值写入点仅 translate_imul 3-op 形式一处（op=Imul 不入
is_lock_carrier_op → 12/13 同 7 不误拦，回归用例
ImulThreeOpImmAtNewMarkerValuesNotIntercepted / ImulThreeOpImmInLockMarkerRange
NotIntercepted 双锁）；Inc/Dec 唯一构造点 translate_unary 不写 src2
（Operand 默认 kind=None, operand.hpp:6），加载体面无碰撞。

**残余（越界即 C1 gate 兜底，保持原生）**：
- `lock inc/dec byte ptr [m]`（S8，FE /0 编码合法、capstone 可解 id=230）
  —— 白名单 pin S32/S64（MSVC 无字节宽 InterlockedIncrement 产物，无
  _InterlockedIncrement8 intrinsic），gate 保守收面（MIT-423 B.2）；
- 16 位操作数（66 F0 组合前缀，D4 砍面）、67 地址宽、段覆盖、组合前缀；
- `lock not/neg`（**MIT-423 D2 裁决 gate**：SDM 合法编码 F7 /2、/3，
  capstone id=511/509 可解至 translate_lock_op default；无 MSVC 产物——
  无 InterlockedNot/Neg intrinsic，仅手写/第三方形态；native 执行实测
  合法（probe rc=7/8），gate 后原生运行行为保真，样本可调用负例钉死）；
- `lock mov`/`lock nop`（不可锁助记符，capstone 拒解码 → skipped → gate；
  原生执行 #UD，禁入可执行路径，回归样本仅日志断言）；`F0 F3 A4`（lock
  rep movsb，415 字节级扫描拒，原生 #UD）；
- `lock inc/dec reg`（reg-dst 非法编码，capstone 拒解码 → skipped → gate；
  原生 #UD，样本负例只取地址不调用）；
- 多字节 lock 前缀（F0 F0 xx）capstone 折叠为单 F0 正常放行（语义不变）；
- 无锁 bts/btr/btc reg 形式（非 Interlocked 语义，_bittestandset 系低频，
  未入面，照旧 gate）。

## 保护强度缺口（= M3 内容，非正确性问题）

以下不影响"是否产出正确的 PE"，只影响保护强度：

| 项 | 现状 |
|---|---|
| crypt（blob 加密） | ✅ **MIT-458 (crypt-v1) 收口（2026-09-05）**：xor_chain blob 级加密 + stub 入口 one-shot 解密（密钥 seed 派生、每目标嵌入）。D1 边界：首入口并发双重解密未防护（单线程初始化威胁模型）；首次执行后明文驻留内存（对抗静态提取，不对抗运行时转储）；指令级加密（C 点取指织入）仍预留未接线 |
| mutate | ✅ **MIT-459 (mutate-v1) 首版（2026-09-05）**：Nop 密度填充（P=0.10，确定性 seed 派生）；junk-Mov（死寄存器垃圾注入）**默认关闭挂账**——首通 E2E 实录见下节 |
| anti_debug | ✅ **MIT-463 (anti_debug-v1) 首版（2026-09-05）**：PEB.BeingDebugged + NtGlobalFlag 检查（stub 入口前缀，FailFast）。D1 边界：检查面仅入口 stub（gate 函数原生无检查）；rdtsc/DRx/NtQuery 面留后续；响应 = FailFast（ExitProcess 需 import 解析）；⚠️ 验收补充边角：目标自装 SEH/VEH 理论上可吞 FailFast AV——命中路径栈不平衡（pop 未执行），执行被恢复即失衡（非干净终止）；v1 威胁模型影响极低，后续响应策略重构时处理 |
| integrity_crc | ✅ **MIT-464 (integrity_crc-v1) 首版（2026-09-05）**：密文流 CRC32（尾区 reserved 槽兑现）+ stub 解密前校验（FailFast）——封死 xor 可延展盲翻面。D1：仅密文流面；bitwise 无表（表驱动优化后续）；.wvmp 其余部分属 init 钩子面（MIT-465） |
| import_protect | pass 占位 |
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

## X5 收口（MIT-450）——x86 战役终稿与缺陷实录

**状态（2026-09-02，分支 mit-x5-closure）**：多目标平台 M2.5-X 收口单交付。
产品代码零 diff；multiseed 305/305（x64 250 + x86 55）；x64 dump `ffd47289…`
恒等维持。收口全文见 STATUS「多目标平台（M2.5-X）收口」节，此处登记 GAPS 面：

1. **x86 跳转表匹配器 S64 硬编码（新实测 gate 面，X5b 按族提单素材）**：
   `try_match_jump_table`（translator.cpp）基址载入判据（lea/movabs
   `size != ir::Size::S64` → nullopt）与 delta 判据（`add.size != S64` →
   nullopt）在 x86 S32 链上永不通过 → 一切 x86 跳表形态落"间接 jmp 未支持"
   C1 gate（行为保真）。X4 交接注记"x86 链已随 B.2 参数化真块"实测修正：
   参数化覆盖步进 tag（点位①-⑤），不含匹配器尺寸判据。样本
   `wvmp_x86_jmptbl_sample`（REG-abs/REG-delta/MEM-abs + undef/oob 负例，
   全 gate byte-exact + helper 真 1 stub）。
2. **REG-REG bts/btr/btc/xadd 不在 x86 lifter 面**：X86_INS_XADD/BTS/BTR/BTC
   用例仅收 MEM-dst（= G4 lock 族翻译，kLockXadd 载体标记）；REG-REG 形
   unsupported → C1 gate。lock mem 形在 x86 通（strip-and-execute，样本
   `wvmp_x86_bitops_sample` lock 探针区 3 note 真虚拟化）。REG-REG 位测试
   开面归 X5b/lifter 族单。
3. **真实产物 in-region push = C2 类静默帧破坏（X5 核心缺陷实录）**：
   wvmpTest x86 打包唯一虚拟化 kernel `kern.mul64hi_closed_forms` 打壳后
   确定性崩溃（cdb：崩溃点 `mov eax,[ebp-0x28]`、ebp=FFFFFFFF、eax/ecx =
   "WVMP"/"END1" marker magic；症状随栈残渣 ASLR 摆动）。根因与
   `wvmp_x86_jmptbl_sample` 同单的 5 参探针③同链（实测 post 寄存器
   ebx=00010000/esi=00000100/edi=00000010 = push 值精确落位
   [v4-4..v4-0x10]）：区域内 push 写真实内存 < ns → 覆写 stub callee-saved
   保存区 → VM 退出还原垃圾。**442 规则升级为产品正确性边界**；修复 =
   X5b 翻译期栈深 gate（v4 将 < ns 的函数整函数 C1 gate）。
4. **callgate 参数窗裁决（X5 B.4）**：kX86CallgateArgDwords=4 = 每调用
   可见参数桥非调用上限；mov 形 >4 参 arg4 确定性丢失、push-imm 形 C1 gate、
   push-reg 形帧破坏（上条）→ 维持 4 dword 窗，扩窗最小 diff = 单常量
   （asmgen loop 已参数化、stub_gen 无第二份），留 X5b 备选。
5. **x86 样本池终稿（11 样本，machine=0x14C 全验）**：X4 三样本 + deepcall /
   jmptbl / strops / bitops / looplea / x87gate / sehgate / std67gate，
   全数 native rc=0 哨兵 + protect stub 计数 1-2 + 双跑 byte-exact；
   gate 负例（x87/SEH-fs/std/67/跳表/无防御）行为保真 note 断言。
   x87 R-SSE-only 定稿面复核：入册完整（本节 + 上节 x87 小节），无遗漏。
6. **wvmpTest x86 全量 E2E（缺陷实录）**：重建对齐源 103 kernel native
   全绿；打包 13/14 位点 gate（分布：跳转目标块未找到 17 / push-imm 11 /
   间接 jmp 1）+ 1 stub mul64hi 崩溃（第 3 条）→ 全量双跑 diff-0 口径在
   X5b 修复前不可达成；x64 对照 14 stubs / 0 gate / 双跑 diff 0 复现。

## X5b 收口（MIT-451）——x86 保存区冲突修复（guard 垫栈 + 栈深 gate）+ 两缺口顺收

**状态（2026-09-02，分支 `mit-x5b-stackfix`，批次一~五 8a44ca1…批次五）**：
X5 三条实测 gate 面（in-region push / 跳表匹配器 S64 硬编码 / REG-REG 位
测试族）全数收口。**mul64hi 崩溃销账**（修复前 main CLI 打包 rc=139 复现 →
修复后 rc=0 byte-exact）。

1. **entry guard 垫栈（D1 路线 (v)，B.2 主修复）**：stub x86 序言最前
   `sub esp, kX86GuardBytes(=128)`——guard 区 [ns-128..ns-4] 吸收 guest
   push/[esp-负位移]/[ebp-X]（别名帧指针）写，保存区/ctx 整体下移；保存区
   读回偏移 esp-相对公式不变；v4/native_sp 恒 = ns（lea 补 G）；出口槽
   kX86ExitSlotDepth = G+0x10+kCtxSize+0x80 = **0x2D8**（runtime_x86.hpp
   单一来源派生）；尾声 4 pop 后 `add esp,G` 回 esp=ns 再终态 jmp
   （ExitNative 落点 esp=ns 语义保持）。N=128 = B.1 实测 p99(64B) × 2
   （wvmpTest x86 14 区：net p50=0/p90=8/p99=64/max=64，reach 全 0；
   (i)@0 存活 9/14=64.3%，(v)@128 = 13/14=92.9%，@256/@512 无增益）。
   工具 = scripts/verifier/measure_x86_stack_depth.py（离线镜像产品 walk）。
2. **翻译期栈深 walk gate（D1 路线 (i)，双 arch 共享 D4）**：
   translator walk_region_stack_depth——push/pop 净值(字节) + rsp-ALU
   (Sub/Add imm) + rsp/别名基负位移 reach（mov ebp,esp 别名跟踪，
   caller-saved 跨 call 失效）+ 回边增长检查 + **ExitNative/Halt 出口
   d==0硬检查** + rsp 绝对改写 gate。预算：x86 = kX86GuardBytes、
   **x64 = 0**（无 guard，区内栈下探即 gate——手写/第三方 x64 盲区预防；
   wvmpTest x64 实测 0 新增 gate）。违例 → stack-depth-gate note → 整函数
   C1 gate（既有 note 通道）。S16/S8 push/pop 不建模（translate 既有 gate
   兜底，避免双 note）。**披露折打面**：值未知基（未跟踪寄存器）负位移不
   检查；diamond 路径不平衡按线性 carry 保守 gate；未别名 mov esp,reg 按
   "帧上移"假定 d 不变。
3. **Halt/ExitNative 出口平衡规则的 mul64hi 裁决**：mul64hi（16 个
   call-arg push、`add esp` 清栈在区域外延迟执行）→ Halt时 d=64 ≠ 0 →
   gate。理由 = 出口物理 esp=ns 而真实 esp=ns-d，延续代码 esp 敏感（/O2
   esp 帧 [esp±X]）即静默错——**宁 gate 勿错**（D5）。行为保真（崩溃→
   gate-native byte-exact）。后续项挂账：esp-resync 前瞻（静态验证
   end_rva 后延续代码 `mov esp,ebp` 型重同步后放行 d≠0 形态）。
4. **callgate 参数窗 4→8 dword（X5 B.4 留 X5b 备选行使）**：guard 使
   push 形参数安全后，4 dword 窗成 5+ 参调用确定性丢参点；扩窗 =
   单常量 kX86CallgateArgDwords=8（多预置 cdecl 无害语义不变）；
   **>8 dword 仍超窗静默丢参**（披露，arg_count 静态通路 = 后续单裁决面）。
5. **跳表匹配器 S32 参数化（B.3）**：try_match_jump_table 三点尺寸判据
   （delta add / lea rip / mov-imm 基址——第三点 = 派单点名两处外的实测
   同族）按 ptr_sz 派生（x86 S32 / x64 S64，与 sz_step_ 同机制）；
   jt_entry_to_rva 4B delta 分支改 native dword 回绕加法（表 .text 尾随
   函数 → 负 delta 2 的补码为 MSVC x86 常态；8B 分支维持 signed i64）。
   jmptbl 池样本三正形翻正（stub 1→4），2 负例维持 gate，byte-exact。
6. **REG-REG 位测试族（B.4）**：lifter 四 case（x86 专属，x64 照旧 G4
   残余 gate）→ 载体域 5..8 零新增 → translator dst=Reg 分支单 VmOp
   **b_kind=None 判别**（编码零改动、vm_op.hpp 冻结面零触碰）→ asmgen
   x86 handler b_kind==0 分支（lea 槽址 + native lock RMW 直打 ctx 槽）。
   **位号 and 0x1F 语义修正**（电池 v2=35 当场炸出 0x800000000）：槽实现
   RMW 目标 = 内存形（位号不掩码跨界摸邻槽），寄存器形 native 语义须掩码
   ——and 后对齐。同寄存器 xadd gate（写序冲突）；REG-IMM / REG-MEM 裸形
   照旧 gate。bitops 池样本 stub 2→3（rgn_bitops_reg 三区真虚拟化 +
   掩码探针）。
7. **wvmpTest x86 全量双跑 diff-0 达成（450 遗留 1 销账）**：native rc=0 /
   packed rc=0 ×2 / native-vs-packed 逐字节恒等 / SUMMARY 103/103。
   gate 位点分布（修复后）：跳转目标块未找到 17 / push-imm 11 / 间接 jmp 1
   （既有面不变）+ stack-depth-gate 1（mul64hi）= 14/14 位点全 gate。
   **wvmpTest 翻正数 = 0**——主导 gate = 既有 lifter 面"跳转目标块未找到"
   （X5 已实录，非本单范围），guard 翻正价值落在池样本（jmptbl 3 正形 +
   bitops REG 区 + pushform 新样本）。**"跳转目标块未找到"= x86 下一最大
   gate 面**（按族提单素材）。
8. **样本池 11→13**：pushform（call-arg push + callgate 窗 + 瞬态
   push/pop，guard 垫栈真虚拟化正形）+ guardover（sub esp,0x200 > 预算 →
   walk gate 负形 + GP helper 满足 REQUIRE_REAL）。multiseed 口径 =
   **63 样本 × 5 = 315/315**（x64 250 + x86 65，REQUIRE_REAL=1）。
9. **B.6 六件套**：build 0/0（产品面；keystone 第三方告警既有）、ctest
   16/16（lifter 159 / translator 91 用例）、multiseed 315/315、
   wvmpTest x64 14 stubs / 0 gate / 双跑 diff-0、x86 电池 37 用例 PASS +
   dump 门 60 登记 PASS + 静态立即数扫描双面 PASS、**x64 dump
   `ffd4728901812932…`/161,861B sha256 逐字节恒等 = D6 机器证明**。
   冻结契约零 diff（kCtxSize 0x1C8 / runtime.hpp / vm_op 97 / 载体域
   0..28 / 跳表 128）。
## X5c 收口（MIT-453）——ExitNative x86 上界接线修复（backend 单点 F1 + 末区 .text 兜底专项反证）

**状态（2026-09-02，分支 `mit-x5c-exitbound` 基于 main 9647a13，批次 d2edaac/c675e07）**：
452 (X5cr) 裁定的 T1 单型缺口（上界 lambda 硬绑 .pdata → x86 恒 nullopt →
判定链条件 D 恒败 → 17 处 jtbn、en=0、stubs=0）按派单 F1 单点位收口。
**translator 判定链零 diff**（D3：translate_jump 本体一字未动，452 结论
"链无 bug 只缺上界供给" 保持成立）。

1. **F1 实施（regvm_backend.cpp 上界 lambda，单点位）**：pdata_empty 分支
   补区域表回退——ub = min{fr.begin_rva > begin_rva}（ctx.functions 逐元素
   取 min，不依赖排序；嵌套/重叠按定义式保守：ub < 自身 end_rva 时 C/D 联合
   不可满足 → gate）；无后继（末区）→ 所在节节尾；**节尾兼作收紧上界
   （cap）**——下一区域 begin 落在节尾之后（多执行节病态布局）时
   [节尾, next_begin) 是零填充/他节内存，cap 保证"目标出节尾=gate"裁决表
   在任意布局下成立（单 .text 产物 next-begin 恒 < 节尾，cap 不绑定）。
   **节尾口径** = VirtualAddress + VirtualSize（链接器内容实长；vsz==0 回退
   SizeOfRawData），**不对齐到 SectionAlignment**——[内容尾, 对齐面) 是零
   填充，放进即崩，内容实长 = "不吞真函数体"的最大安全值。pe==nullptr 与
   无 .text（区域不在任何节内容面）维持 nullopt 保守 gate；回跳检出
   （exit_native_blocked）提前至双路共用（452 §3.4：BFS 为 arch 共享码，
   x86 17 处实测 0/17 blocked）；x64 路径（pdata 分支在前）条件序与修复前
   一致。
2. **B.2 末区专项反证（D1 核心条款）**：① wvmpTest x86 末区 0xC972 走查
   （修复后实测读数）——site `jge 0xC9D5`（cond=13）@ marker@0xbd2c
   （idx13，begin_rva=0xC92C），end_rva=0xC9D5（END-call 位置，452 脚本
   复现），bd2c 无后继区域 → ub = .text 节尾 = **0xAE7AA**（实读
   VirtualAddress 0x1000 + VirtualSize 0xAD7AA）；判定链 A) jge+Imm ✓ /
   B) upper 非空 ✓ / C) 0xC9D5 ≥ 0xC9D5 ✓（边界）/ D) 0xC9D5 < 0xAE7AA ✓ /
   E) fits_aux ✓ → **emit ExitNative**；产品日志实证 `exit-native @ 0xC972
   -> 0xC9D5 (cond=13)`。② 新样本 `wvmp_x86_tailexit_sample`（446 MASM 链，
   池 13→14）：rgn_exit_ok（next-begin ub，endcall target==end_rva /
   earlyret 目标落 gap / fallthrough Halt 三面）+ rgn_tailexit_ok（末区
   .text 兜底 ub，同三面，即 0xC972 形）+ rgn_tail_beyond（gate 负例，
   E9+rel32 手编码目标越节尾、禁调用、C1 gate note rva=0x11EF；MASM
   `jmp g_far_data` 对 .data 标签产 FF 25 间接形，会归因错族——手编码直跳
   形才钉得住越节尾语义）。③ 兜底语义裁决表：末区 + 目标 ∈ [end_rva, 节尾)
   = **放行**（ExitNative）；末区 + 目标 ≥ 节尾 = **gate**；非末区 + 目标 ≥
   min(节尾, next_begin) = gate。单测 ③④⑤ 钉死（B.3）。
3. **B.3 病态形防护单测 ×10**（regvm_backend_tests，ctest 16/16 维持）：
   常规面 / 末区节尾兜底 / 越节尾 gate / cap 收紧（next_begin > 节尾）/
   嵌套外层 gate / 区域表空退化 / pe==nullptr / blocked 组合 / 无 .text /
   pdata 非空对照（x64 路径原样钉）。
4. **A.3 读数表逐项对账（D5）**：en **0→17** ✓ / jtbn **17→0** ✓ / 残面
   **30→13** ✓（push-imm 11 + 间接 jmp 1 + stack-depth 1，逐 site 归因
   grep 实证）/ **stubs 9（452 预估 10，失配点名 #33）**——452 §4 "4 个
   他族 gate 函数（aa18/aebb/b38d/b678）" 漏记第 5 个：**marker@0xb59b 含
   `div` → VmOp::Div(78) 撞 x86 运行时白名单（G8 已入册面，D2 除零折叠
   维持纸面）→ stub_link C2 gate**。修复前该缺口被 jtbn 掩盖（b59b 当时
   在翻译期 gate），翻译翻正后 C2 面如实浮出——保守方向正确（宁 gate 勿
   错），C2 handler 补面归后续 C2 类派单。wvmpTest x86 **103 kernel 双跑
   diff-0 达成**（12 处 ExitNative 真执行首次全量真跑；9 stubs）。
5. **当场修：translate_imul REG-3op src≠dst 丢源缺陷**（B.4 双跑首炸，
   §E 当场炸当场修条款）：wvmpTest x86 packed 首次全量真跑在
   kern.md5_block_vectors 确定性 AV（rc=139 双跑）。cdb 铁证：eip =
   .wvmp+0x693（Load handler xsz2 分支），`Load(dst, [rsp 槽])` 地址槽 =
   0xCF288CB3（md5 F 值）——字节码解码定位 idx7（md5，CallGate 0xb3f0 =
   md5_T）round-4 分支：`Mov(slot2←16)`（guest `mov ecx,10h`）+ `Imul(slot0
   ← slot0*slot18)`——guest 实码 `imul edx, ecx, 3` 系 3-op **src≠dst** 形
   （idx7 实测 4 处 + `imul ecx, eax, 0` 系 imm=0 形 3 处，后者结果恰 0
   掩盖），旧折叠假设 "MSVC /Od imul r,r,imm 恒 src==dst" 把 src 丢成
   dst*imm。修复 = src≠dst 时先 `Mov(dst, src)` 物化（同函数 MEM-3op 路径
   同款），src==dst 字节不动（**x64 恒等保持**：multiseed x64 250 + dump
   恒等复验）。D3 边界披露：改动位于 translate_imul，**不在 ExitNative
   判定链内**，不推翻 452 结论；单测
   ImulThreeOpRegSrcNeDstMaterializesSrc / ImulThreeOpRegSrcEqDstNoExtraMov
   双向钉死，GpMulUnaffectedByMarkerDomain 随新折条更新。
6. **B.4 六件套**：build 0/0（项目码 0 警告；C4335 sse_bridge 既有）、
   ctest 16/16（+ backend UpperBound 10 例 + translator imul 2 例）、
   multiseed **320/320**（REQUIRE_REAL=1，x64 250 + x86 70，池 50+14，
   §F.3 预估精确命中）、wvmpTest x86 9 stubs / en 17 / 残面 13 / 双跑
   diff-0 ×2、wvmpTest x64 14 stubs / en 17 / 0 gate / 双跑 diff-0、
   x86 电池 37 PASS + dump 门 60 项 PASS + 静态立即数扫描双面 PASS、
   **x64 dump `ffd4728901812932…`/161,861B sha256 双 CLI cmp 逐字节恒等**
   （D2 机器证明，全 hash 首录 =
   ffd4728901812932d4d85dfed13f80be4edd8f78f93c6f483ff415bfd5d06206）。
   冻结契约零 diff（kCtxSize / runtime.hpp / vm_op 97 / 载体域 / 跳表 128）。
7. **B.6 文档**：本节 + §8 观察清单 ExitNative x86 行翻正 + 支持矩阵
   x86 行读数刷新（103-kernel：14 标记区 9 真虚拟化 = 64.3%，全 103 面
   真虚拟化率 8.7%；残 gate 面 13 = push-imm 11 / 间接 jmp 1 / 栈深 1，
   另 C2 面 b59b Div 白名单 gate 由 jtbn 掩盖转明）+ STATUS 里程碑行。

## X6 收口（MIT-454）——x86 残 gate 双面包翻正（push-imm 开面 + SSE 32 op 批迁）

**状态（2026-09-02，分支 `mit-x6-pushimm-sse` 基于 main 4083b1f，三批
5c7e3b2 / 026b7a6 / aba35e1）**：B 族（X5d push-imm 11 处）与 A 族（X3d
SSE 32 op）分批全绿收口，wvmpTest x86 残面 **13→3**，stubs **9→11**，
103-kernel 标记区真虚拟化率 **64.3%→78.6%**（11/14，全 103 面 10.7%）。

1. **#33 定位修正（B.1 首项）**：X6 派单 A.1 "卡点在 lifter
   （x86_translate.cpp:219 is_data_operand 拒 imm 形）"被实测推翻——
   `is_data_operand` 本就接受 Imm（Reg/Imm/Mem 三形），push imm 一直被
   lift 为 Op::Push dst=Imm；wvmpTest x86 基线 11 处 push-imm gate note
   全部为 translator skip 文本（"push 操作数形态未支持"，aa18×1 +
   b678×10 逐 site grep 实证）。真卡点 = translator `translate_push` 的
   dst.kind != Reg skip；运行时 `build_push_x86` 的 a_kind 双形
   （xpimm_ 分支读 aux）X3b 已备且电池已覆盖（PushPopStack LIFO 首推
   即 imm）。
2. **B.1 push-imm 开面（x86-only，D2）**：translator Imm 分支（值域
   [-2^31, 2^32-1] 低 32 位截取 = x86 32 位存储语义；capstone imm(i64,
   sext) 的 -1 与 0xFFFFFFFF 同映 0xFFFFFFFF；超域防御 skip）+ S16/S8
   位宽 gate 前置（66 68 push imm16 维持 442 口径）。x64 维持 skip
   （sext 64 位值域不同面，挂 X6b）。lifter 钉测试 PushImmLiftsDstImm
   （68+6A 双编码）防"开面"误改回流；dumpbin 钉编码面：MASM 把
   `push 0FFFFFFFFh` 编为 6A FF（imm8 sext），存储值同 0xFFFFFFFF。
3. **B.2/B.3 SSE 批迁（30+2 op）**：x64 32 op SSE 表逐 op 32 位镜像
   （共通模板 build_x86_sse_binop：dst 预读 → src 双语义寻址 → native →
   写回）+ XmmLoad/XmmStore 三宽 mem 原语 + XmmFromGp/GpFromXmm 桥 +
   ucomiss/ucomisd flags 面（setcc5_x86 落帧 + flags_tail_x86 装配，
   x86 无 zero5）。编码双平台同逐 op 断言（DisasmX86SseEncodingDualMode：
   26 mnemonics Keystone KS_MODE_32/64 装配同字节 + capstone 双解同
   text）。**批迁缺陷当场修（D4）**：build_xmm_store_x86 地址临时与 src
   寻址临时同用 t_[1] → store 写野地址（电池 3b 块 AV 实录，x64 版
   T1/T9 分工缺位）→ 地址 t_[0]/src t_[1] 分工修复。
4. **stub xmm 同步（A 面配套）**：x86 stub 入口 host xmm0..7 → ctx.xmm +
   出口 ctx.xmm → host（446 "xmm 同步不适用" 注的前提"x86 运行时无 SSE
   handler"随批迁翻转；Win32 ABI xmm 全易失，区域读进入时刻 xmm 值须有
   源）；ExitNative/Ret x86 直退 handler 内联 ctx→xmm 恢复（不经 stub
   出口，x64 build_ret 步 3 镜像；x64 ExitNative 经 Halt→stub 出口吃同
   步故 x64 无需）。x64 stub 形逐字未动。
5. **读数表（D1 分栏）**：
   - **B 列（push-imm 族）**：gate 11→**0**（aa18、b678 两函数翻正，
     stubs +2）；残余 0。
   - **A 列（SSE 族）**：wvmp_x86_sse_sample 翻案 gate→真虚拟化（stub
     1→2，输出串 byte-exact 亲验，D5 铁律）；wvmpTest 103 kernel 无 SSE
     标记函数，wvmpTest 侧 stub 读数不变（如实披露，不虚增）。
   - **总读数**：stubs 9→11 / 残面 13→3（间接 jmp 1（aebb，挂账）+ 栈
     深 1（mul64hi，X5b 永久）+ Div 1（b59b，G8 D2 维持另单））/ x86
     handler 表 60→**92** 行 / x86 电池 37→**43** / multiseed 320→**325**
     （池 14→15 pushimm，x86 75 runs）。
6. **B.4 病态与边界**：push imm S16/S8 维持 gate（电池 + translator 单测
   钉）；push imm 值域超 32 位防御 gate（单测无 E2E 形，x86 capstone 不
   产）；间接 jmp aebb 不在本单（挂账维持，未顺手做）。SSE 涉 ymm 天然
   拦（x86 无 ymm 编码，结构性不可达）。
7. **B.5 x64 零扰动铁证**：三批各批复验 x64 dump `ffd4728901812932…`
   （161,861B）逐字节恒等（sha256 三次复跑同值）；multiseed x64 250 × 3
   批全绿；wvmpTest x64 14 stubs / 17 en / 0 gate 三批复验不变。
8. **冻结契约（D3）**：kVmOpMax=97（零新 VmOp，Push Imm/SSE 全既有
   op）/ 载体域 / kCtxSize / runtime.hpp / 判定链 / ExitNative / 协议面
   零触碰。解禁清单披露：stub_gen.cpp（x86 路径 xmm 同步）超出 D3 字面
   清单，依据 = 派单 A.2 "stub xmm 同步 Win64 ABI 面 371" + 446 交接
   原文"槽偏移公式按 x86 帧重核" + stub 注释自带的条件翻转句；x64 路径
   逐字未动（D2 恒等机器证明）。

## X7 收口（MIT-455）——客户态重扫（双 arch 三层口径）+ X6b 三面数据裁决 + Div 族 x86 开面

**状态（2026-09-03，分支 `mit-x7-rescan-x6b` 基于 main bf2a41d，三批
2cd5fad / f6c9277 / 本节）**：批一零产品代码重扫 + 批二数据裁决制实施 +
批三文档收口。x86 战役残面收官读数：wvmpTest x86 stubs **11→12**，残面
**3→2**（间接 jmp 1 + 栈深 1，均为永久/挂账 gate），103-kernel 14 标记区
真虚拟化率 78.6%→**85.7%**。

### 批一：客户态重扫（`scripts/verifier/mit_x7_rescan.py` + 留样入仓）

- **语料**（X0 §1.2 口径重建，X0 留样 jsonl 已随 %TEMP% 失效）：x86 = SysWOW64
  点名 core_os 37 + old_runtime 12 + modern_ucrt 7 + random 48（八分位
  seed=436）+ 436 第三方家族现存子集 8（PhysX/Steam/dxcompiler/hha/wab32
  缺位如实披露）= 112 文件 27.41M clean 指令；x64 = System32 对称层 103
  文件 17.63M clean（**X0 从未扫过 x64 域，本单新数据**）。
- **覆盖率读数（X6 后白名单，形级口径）**：x64 direct **99.26%**（core_os
  99.68% / old_runtime 98.67% / ucrt 99.48% / random 99.30%）；x86 direct
  **95.15%**（库域 94.26% / third_party 97.55%）——落 X0 自报诚实下界带
  92-94% 上沿且构成翻新（call mem/reg、ret imm16、plain 串、S16 GP、
  push-imm、SSE 32 op 全入面；gate 面全部可点名）。
- **区域级（x64 .pdata 真函数域 240,277 函数）**：任一 gate 族命中
  12,650（5.26%）→ 纸面无 gate 函数 94.74%；分族：sse_residual 2.41% /
  indirect_jmp 1.79% / system_legacy 1.35% / push_imm 0.049% / **x87 0%**。
  x86 无 .pdata：文件级 any-hit 代理 + 递归对账（X0 §1.1 纪律）。
- **一致性断言（§E）**：脚本 direct 151 助记符 ⊆ 产品 lifter case 208 id
  （不等即 Fatal）+ 形级双通道交叉校验（disasm_lite/op_str vs detail/
  operands，双文件 47,705 shape 项零 diff）。

### 批二裁决（预登记阈值 D2 机械执行，数据→裁决→实施链闭环）

| 面 | 读数 | 判定 |
|---|---|---|
| push-imm x64 | 5,009 / 17,626,439 = **0.0284%** < 0.5%（最高层 old_runtime 0.084% 仍差 6 倍；68 形 3,314 / 6A 形 791） | **维持 gate 销案**（translator :1611 skip 维持；D2：销案 = 满分结论） |
| 间接 jmp | 门1 x64 函数占比 **1.787%**（4,294/240,277）≥1% 过门；门2 表形（mem 带 index×8）全语料仅 **28 条（0.0002%）**，任意 mem 形 84.7% + reg 形 15.2% 主导 | **门2 败 → 维持 gate 销案**（任意/reg 形 = call 表分发 D6 边界 = L 拒做挂账；413 跳表匹配器现网三正形维持） |
| Div 族 x86 | x86 div/idiv 8,976 条（0.033%），**89/112 文件命中**；453 b59b 实撞在案；D4 实读 x64 = build_div_idiv 真 handler（#DE 直通，setcc5 捕真值） | **批二实施**（见下） |
| x87 B 路线（445 §6 触发判定） | x86 密度与 X0 同构（old_runtime 7.81% / ucrt 1.00% / core_os 0.115%）；x64 0.033% 且 **.pdata 函数域含 x87 函数 = 0 个**（d3dx9 x64 版已 SSE 化，x87 命中全为 .pdata 外数据噪声） | **B 路线（x87 L0）触发条件不满足，维持 R-SSE-only（A 路线）**——本读数即 445 §6 B 路线立项数据，append-only 入册 |

### 批二实施：Div/Idiv x86 真 handler（G8 行翻正，见上表）

- `build_div_idiv_x86`（asmgen.cpp）：x64 build_div_idiv D4 镜像——native
  `div/idiv r/m32` 直通（dividend edx:eax，商 eax/余 edx 双槽写回）、除零/
  商溢出 = 真 #DE 崩溃形态与未加壳一致（D2.1，不做 VM 内拦截）、flags
  Intel undefined = setcc5_x86 捕 native 真值（照抄 build_imul 处置）。
  排布纪律新增：除数临时 ts 静态避 {eax,edx} **双位**（build_mul_x86 只避
  eax；div 装载 EDX:EAX，ts 与 EDX 重合会被 dividend 装载覆盖）。
- lifter `translate_cdq` x86 S32 开面（**D3 字面清单超出披露**，454
  stub_gen xmm 同步先例）：真实 idiv 代码恒有 cdq 前置，无 cdq lift 则
  Div face 只剩无符号 div 孤形，派单 §B.2 交付不成形；MIT-404 时点 x86
  asmgen 未存在故当时限 x64，X3b 已备 build_cdq_x86 S32 真面，本单接线；
  cqo（REX.W）x64 专属维持（32 位模式无 REX，防御拒）。
- 联动：x86 handler 表 92→**94** 行（stub_link 白名单单源自动跟随）；
  电池 DivIdivQuotRem ×6 组（43→44）；lifter 钉测试
  CdqX86LiftAndCqoBoundary（x86 cdq lift + cqo/cwd 边界 + idiv reg/mem/S8
  钉）；dump 门 BATTERY_HANDLERS +2；静态立即数扫描双面 PASS；样本
  `wvmp_x86_div_sample`（div reg + div mem + idiv cdq + 负除数，native
  首绿 byte-exact，池 15→16）。

### 新数据行（非本单范围，留档供裁量）

- **push_mem x86（`push [mem]`，translate_push Mem skip 残面）**：505,828
  条 = 1.845%（92.9% 文件命中）——X0 估 ~0.5%，实测 3 倍余（core_os IAT/
  栈窗惯用面重），为 x86 第一大非 x87 shape gate。不在 X6b 三面（D2 未
  含），维持 gate，后续派单按族评估。

### 验证六件套（X7 收口读数）

build 0/0（本方源零警告）/ ctest 16/16 / multiseed **330/330**（REQUIRE_REAL=1，
x64 250 + x86 80，池 50+16）/ wvmpTest x64 14 stubs 0 gate 双跑 diff-0、
x86 **12 stubs** 双跑 diff-0（103×3 全 PASS）/ x86 电池 44 + dump 门 94
登记项 PASS / **x64 dump @12345 `ffd4728901812932…`/161,861B sha256 逐字节
恒等**（底稿复跑锚 = 新增 WVMP_X64_ASM_DUMP 落盘钩子 +
`--gtest_filter=Interpreter.MovdBridgeSemantic`，生成命令首次入仓）。

冻结契约零 diff（kVmOpMax=97 / 载体域 0..28 / kCtxSize / runtime.hpp /
backend.hpp / 判定链 / ExitNative 协议 / 跳表 128）。解禁清单披露：lifter
x86_translate.cpp（translate_cdq x86 开面）超出 D3 字面清单（原文仅"间接
jmp 需 lift 形"），依据 = Div face 交付必要条件 + 404 注释自带的时点前提
（"x86 asmgen 未存在"已随 X3a 翻转）；x64 路径行为逐字节不动（dump 恒等
机器证明）。


## MIT-456（push-mem）收口——x86 push [mem] 开面（X7 新数据行翻正，2026-09-05）

**状态（2026-09-05，分支 `mit-pushmem-x86` 基于 main `1e909ac`，无派单直接
开发，项目主授权）**：X7 批三"新数据行"记录的 push_mem 残面
（`push [mem]`，translate_push Mem skip）翻正为 x86 真虚拟化。

**数据依据（X7 批一留样）**：x86 push [mem] 505,828 条 = 1.845%（92.9%
文件命中；core_os IAT/栈窗惯用面重）= x86 第一大非 x87 shape gate。

**实施（translator 单点，零新 VmOp、零新 handler）**：

- `translate_push`（translator.cpp）Mem 分支（x86 专属，D2）：emit_address
  （地址槽，translate_load 同款含 rip/负 disp/非法 scale 防御）→ Load/LoadRva
  （值槽）→ 单 op `Push a_kind=Reg`（handler 既有 Reg 分支，asmgen.cpp
  **逐字节零 diff**）。S16/S8 位宽 gate 前置沿用（442 口径）。
- **语义序 = native 序**：地址计算/读值在 Push 减 esp **之前**发射——
  `push [esp+4]` 读减前 esp（IAT 栈窗形语义锚）。
- 栈深 walk 零改动即覆盖：IR 级 `Op::Push` 净深 +4 既有建模 + 负位移
  reach 检查对 `dst.kind==Mem` 既有覆盖（`push [esp-200]` → 栈深 gate，
  单测钉）。
- x64 维持 skip（D2 x86-only：x64 无 push_mem 数据行，且 x64 push 现形 =
  Sub+Store 双 op，Mem 开面属独立数据裁决面）；形 note 文本逐字节不变。

**测试**：

- lifter 钉 `PushMemLiftsDstMem`（FF 30 / FF 77 08 x86 双编码 + FF 30 x64
  同字节 S64 面，防 lifter 误改回流）。
- translator ×4：`X86PushMemAddressLoadPush`（3 VmOp 折条形）/ 
  `X86PushMemDispIndexForm`（index×4+disp 全展开 7 VmOp）/
  `X86PushMemNegativeDispReachGate`（walk 负位移 gate）/
  `X64PushMemStillGated`（D2 钉）。
- x86 电池 `PushMemFromMemory`（真执行：内存源值两形 push + LIFO 弹出 +
  esp 步进 + 栈内存逐 dword；⚠️ 电池槽位纪律沉淀：VM 槽 0..7 = 客机 GPR
  槽 1:1（槽 4 = RSP 槽），数据槽误用槽 4 = Load 值写进 esp 槽 → 下一次
  Push 以值为地址访存（cdb 实录 `mov [ebx],edx` @ 值地址），x86 电池
  44→**45** 用例）。
- 样本 `wvmp_x86_pushmem_sample`（四面：FF 35 abs 全局 / FF 71 04 reg+disp8
  IAT 形 / FF 74 24 04 esp 栈窗惯用形读减前 esp / call-arg push [mem] 对 +
  callgate + 区内 cdecl 清栈；net 深度 0）池 16→**17**。

**验证六件套**：build 0/0 / ctest 16/16 / multiseed **335/335**
（REQUIRE_REAL=1，x64 250 + x86 85，池 50+17）/ wvmpTest x64 14 stubs
双跑 diff-0 + x86 12 stubs 双跑 diff-0（靶标无 push [mem] 位点，读数
12/14=85.7% 维持，残面 2 = aebb 间接 jmp + b38d 栈深，均永久 gate）/
x86 电池 45 + dump 门 94 登记项 PASS（asmgen 零 diff 表级证据）+ 静态
立即数扫描双面 PASS / **x64 dump @12345 `ffd4728901812932…`/161,861B
sha256 逐字节恒等**（x64 零扰动机器证明）。

冻结契约零 diff（kVmOpMax=97 / 载体域 0..28 / kCtxSize / runtime.hpp /
backend.hpp / 判定链 / ExitNative 协议 / 跳表 128 / asmgen.cpp）。


## mutate junk-Mov 挂账（MIT-459 收口裁定 + 首通实录，2026-09-05）

**结论**：死寄存器垃圾 Mov 注入（块内向后 liveness）实现保留于
`passes/mutate/src/mutate_pass.cpp`，`kEnableJunkMov=false` 默认关闭；v1
只发 Nop 填充（E2E byte-exact 已证）。翻案前置 = 系统性审计 VM 槽的
隐式消费面（候选：callgate 参数/返回 marshal、ExitNative/Ret 出口坐标、
stub xmm 同步、x86 参数窗），当前证据不足以定位残余消费点。

**首通实录**（wvmpTest x64，mutate+crypt 全栈 8 passes，seed 12345）：
1. 137 个 junk Mov 注入 → kern.md5 首测 `mov dword ptr [0],2Ah` 崩溃
   （+0x47720 原生代码，野指针写）。
2. 修正一（有效，入册）：**callgate 隐式读**——x64 `Op::Call` 经 callgate
   把客户 rcx/rdx/r8/r9 槽作为 Win64 原生参数传被调方（rax 低 8 位 = 变参
   浮标）；块内 liveness 修复为 Call 处强制 rcx/rdx/r8/r9/rax 活。
3. 修正一后仍崩（同址发散）→ 剩余未定位消费点存在 → 挂账。
4. 对照：nop-only（P=0.10，99-105 Nop 注入）双跑 byte-exact、14 stubs
   （junk Mov 曾致 cf88 跳表匹配器失配 gate——Nop 同样会断模式链，gate
   行为安全；本实录 nop-only 下 cf88 恢复真虚拟化，因 rng 序不同插入位置
   不同，非普遍结论：跳表函数遇 mutate 可能 gate，属安全面）。

**教训入册**：VM 槽的消费者不止 IR 读集——运行时把客户槽 Marshal 进
原生 ABI 的每条通路（callgate/ExitNative/xmm 同步）都是隐式读；IR 级
变换的 liveness 必须把"槽 → 原生 ABI"面纳入读集后才能安全写槽。

## MIT-465-G1（改判：探针缺陷假象，2026-09-06 复核）——TLS 回调在本机全目标执行

**原记录**（2026-09-05）：认为本机 loader 对部分 exe 本体（CMake 管产
snake 系）静默跳过 TLS 回调，并附"PE 头结构差异全排除"的对照记录。

**改判依据（EB FE 探针，无吞噬歧义）**：TLS 自检探针（scripts/
tls_selfcheck.sh，把合并数组第 0 项改为 `jmp $` 死循环，挂起=执行）对
snake/string_ops/x86 全部管产目标 + plain-cl 目标均报"回调在入口前执行"，
且 x64 镜像解析面（dd1 重指后运行期 != 文件态乱数）全部成立。**"G1 跳过"
不存在**；此前三路证据全部为测量缺陷：

1. **int3/异常探针**：TLS 回调期的异常可被 loader init SEH 吞噬（回调后
   流程继续）——int3 rc=0 ≠ 回调未执行；
2. **syscall 终止桩**：NtTerminateProcess 桩在已知-good 目标上同样 rc=0
   （校准失败），探针本身失效；
3. **cdb 初始断点法**：TLS 回调执行于初始断点之前，断点观测不到（x64
   成立；x86 WOW64 初始断点甚至早于 TLS——反而给了 post-TLS 前的观测窗）；
4. **TEB.ThreadLocalStoragePointer=NULL**：零长 TLS 数据不分配向量，正常。

**保留的有效结论**：EB FE 挂起探针是 TLS 面唯一可靠观测手段，已产品化为
`scripts/tls_selfcheck.sh`；核验过 wvmp_tls_sample 池 + multiseed 池全目标。
若未来主机/目标形态出现真"跳过"，自检脚本 FAIL 分支即哨兵。


## MIT-466 v1 裁剪披露（2026-09-05）

- IAT 迁移 v1 = 「镜像化 + dd1 重指 + TLS 回填」：INT（名字面）原位保留
  明文，原 IAT 区运行时回填真实地址——文件态掩盖了地址面（镜像 = 乱数），
  但名字面与运行时最终 IAT 仍可被高级静态/动态分析还原。完整方案
  （引用重写 + 转发桩 + 惰性解码，VMProtect 级）留 T9.1。
- 硬依赖 kernel32!VirtualProtect 已在目标 IAT：未导入的目标整单保守回退
  （不迁移），后续可改为经 ntdll 解析消除依赖。
- 依赖 T8 回调执行时机：MIT-465-G1 所列 loader 跳过形态的目标上，回填
  不会发生（原 IAT 停留文件态 → 原生导入调用会崩）。E2E 用可触发样本池；
  发行目标需先跑回调自检探针（后续 ticket）。


## MIT-473（C 点取指级加密）收口——位置键流 + x86-64 32 位写零扩展实录（2026-09-06）

**设计定稿**：C 点取指级加密（逐指令解密）与 blob 级 one-shot 互斥
（config `[crypt] fetch = true` / ProtectRules.has_crypt_fetch）。键流 =
**位置键**：K_i = key0 + i×STEP（u32 环加，STEP = 0x9E3779B1），字 i 的
lo/hi 两半同 xor K_i——K 只依赖字序（PC），不依赖取指历史 → 跳转/回跳/
imm aux 字直读全兼容（链式键流在此翻车后改位置键，链式方案作废）。key0
存 blob 头 seed 字段（offset 16，明文头 32B 内），解释器经
`[bytecode - 0x10]` 读取——**codec（加密）与 asmgen（解密）的常数/布局/
半字语义三处同步纪律**：改任一侧必须复跑双架构 FetchDecryptSemanticParity
+ fetch_crypt_e2e.sh。

**永久纪律 1（asmgen x64 面）：绝不对 T8（指令字寄存器）做 32 位写。**
x86-64 任何 32 位寄存器写（含 xor r32, r32）零扩展清零高 32 位——高半字
恰是加密的 aux/imm 面，首次 32 位 xor 即毁。实测：K=0（明文直通）同样
炸，首次误诊为"K 语义不一致"延误一轮；VEH int3 + TF 单步抓出
（off=0x49：rdx 0x0000004D_000E4001 → 0x00000000_000E4001）。正解 = 键
在 32 位域算完 → mov/shl 32/or 复制双半 → 一次 64 位 xor。

**永久纪律 2（asmgen x86 面）：织入块用 eax/ecx 前必须核对分配池。**
kX86ByteCapable = {eax, edx, ebx}——t0/t1 可为 eax；kX86 池 6 槽
（eax/edx/ebx/ebp/esi/edi），ecx 保留移位计数不在池内（唯一绝对安全的
织入暂存）。两坑实录：① PC 必须取寄存器值（`mov ecx, t1`），加 [] 是把
PC 当地址解引用（pc=0 → 读 0 页 segfault）；② 顺序纪律 = 先取 PC（ecx）
再读 key0（eax）——t1==eax 时先毁 eax 再读 t1 = 把 key0 当 PC。

**面矩阵**：fetch 模式 × integrity_crc = 跳过（无尾区，Note 披露）；
fetch × blob 级 crypt = 互斥（crypt pass 内 fetch 分支短路 one-shot）；
fetch × 每函数豁免 = 豁免被忽略（整流加密，披露）；fetch × W^X 拆节 =
兼容（blob 解密期写 .wmp 数据节，代码节只读执行）——fetch_crypt_e2e.sh
双架构断言 .wvmpc=RX / .wvmp=RW。

**取证方法论沉淀**（T15 EB FE 探针之后第二件）：VM 级分歧用
**VEH int3 + TF 单步**定位——RWX 页内动态识别指令边界（FF E? jmp r64 +
REX 前缀归位；8B + mod00/rm100 + SIB scale=11 识别取指），int3 一次性补
丁 + 异常处理器逐指令打印关键寄存器。int3 的 RIP 报告在 CC 处或其后一字
节（两种都要接）；TF 每步自动清零须逐步重装；补丁点若落指令中间，还原
后从中间恢复执行 = jmp 落垃圾（实测炸栈）。


## MIT-474（flags 活跃性消除）收口——cond 位 2 标记协议与 liveness 语义裁决（2026-09-06）

**标记协议**（encoding.hpp 单一来源，三处消费）：cond_or_size 位 2 =
flags-dead。① 4 处 tail（x64/x86 × 全量/合并）test+jnz 跳过捕获装配；
② 尺寸链链头 and 3（标记不入尺寸比较）；③ 翻译期 mark_dead_flag_writes
独占置位。**正确性契约：欠实现安全**（运行时忽略标记 = 旧行为仍正确），
过实现禁止（非写 op 携带标记 = 未定义）——flag_sem_of 分类表是唯一授
权源，新 VmOp 入表前不得借道。

**liveness 语义裁决**（词流 CFG，区域级；验收 REJECT 后修订稿）：
kRead=live 源头；kWrite=kill；**kWriteReadMerge=透传**（live_in =
live_out）——旧状态位只流入 flags 输出（rol 保 ZF/SF/PF、inc 保 CF），
前驱可观察性经合并延续，atomic_incdec 样本 inc_cf 探针（SDM: inc 不写
CF）实证 kill 语义错、透传对。**kWriteReadReg（adc/sbb 专属）=输入侧恒
读者**（live_in = 1）——验收 B1 实证 adc/sbb 的 CF_in 流入**目的寄存器
值**（dst = a + b + CF_in），与 merge 的"旧位只进 flags"本质不同：透传
只保证"合并结果无读者 ⇒ 前写可跳"，对寄存器依赖不成立（`add; adc; halt`
中 add 被透传规则标记 → adc 用陈旧 CF_in 算 dst → 寄存器值错，128 位加
法惯用法即触）。自身 flags 写三类均仍可标记。ExitNative = kRead（条件
形式 cond_eval；无条件直退形保守同判）。区域末端真死：stub 每区清零
ctx，VM flags 不跨区。

**G4a 行翻正**：flags 活跃性消除 ✅（本节）。强度面遗留 = 无（标记不改
变可观察行为，纯性能）；对照优化（同 seed 字节码差异披露）：死写 tail
在解释器侧静态跳过，blob 不变（标记位本身是唯一字节差异）。

**锚点换代**：x64 dump 锚 ffd47289…/161,861B → 67cfa727…/164,329B
（+2,468B = 33 处 tail 的 test/jnz/skip 出口 + 尺寸链掩码 + 标签）。此
为 D2 口径的**计划内换代**（首例）：换代纪律 = ① STATUS 披露新锚全值；
② 旧锚在全部消费点（stub_gen/translator 注释、dump 测试注释）同步作废；
③ 换代后 5 seeds 复跑 dump 稳定（同 seed 逐字节可复现不因换代失效）。


## MIT-475（样本面 shadow space 缺陷）收口——asm 调 C++ 桩的 ABI 纪律（2026-09-07）

**教训**：MASM .asm 直接 `call` C++ SDK 桩（marker_begin/end）时，x64
ABI 的 shadow space（32B）与 16 字节栈对齐是**硬要求**——即使桩体
"看起来不写栈"（/Od 的参数 home 写 `mov [rsp+8], rcx` 在 entry 即发生，
早于任何"桩体是否用栈"的判断）。未预留时该写落在调用者返回地址槽，
覆盖值 = rcx 当前值；若 rcx 恰是位型参数（SSE 样本的 float 位图案），
ret 即跳入数据。**asm 侧调用任何 C++ 函数的样板** = PROC 入口
`sub rsp, 28h` + 每个 ret 前 `add rsp, 0x28`（0x28 = 32B shadow + 8B
对齐垫；有 push 的帧各自计算，保证 call 前 rsp%16==0）。

**为什么 MIT-425 验收漏过**：G1b 验收以打包面（gate note/虚拟化语义）
为准，六样本 native 面当时已崩但被 MIT-427 的 crash guard 文档化为
"已知既状"而未清偿——**样本 native rc=0 应为样本入库验收的一等判据**
（本单起补入纪律）。

**marker_begin 首参契约澄清**：`const char*` 名字指针不被桩体解引用
（仅为让编译器在调用点前物化字符串地址供 marker_scan 解析区域名）——
asm 裸调 rcx=垃圾不直接崩，崩的是 shadow space 缺失的 home 写。两回事，
勿混。


## MIT-476（stub_link 布局健壮化）收口——Emit 预留区协议 + roll_x86 去重纪律（2026-09-07）

**预留区协议**（pe_image.hpp 单一来源）：stub_link 预扩 .wvmp 至
blobs + kEmitReserveBytes（8KB）并置 kEmitReserveBase 游标槽；消费方
（import_protect/tls_hook）emit_reserve_take 对齐分配、推进游标、写回
槽。协议不变量：① 节最终尺寸恒定（blobs + 8KB）→ 代码节连续性恒成立；
② 追加超预算 = 显式 throw（优于静默重叠/对齐垫片侥幸）；③ 游标槽缺席
= 旧尾部追加语义（单测夹具零改动）。预算依据：实测追加峰值 ~2KB
（CONTEXT 0x4D0 + 镜像 IAT + TLS 面），8KB ≈ 4× 余量；代价 = 每个打包
产物 .wvmp 恒 +8KB 文件体积（换确定性）。扩预算须同步 pe_image.hpp 注。

**roll_x86 去重纪律**：多角色寄存器抽取（ctx_/base_/t0/t1/rest）必须
在**抽取时**剔除已占角色（本单修复：字节可编码集 {eax,edx,ebx} 与
callee-saved {ebx,ebp,esi,edi} 交于 ebx）；越界写发生在 j!=2 校验**之
前**（rest[j++] 先写后查）——"事后校验"兜不住"写入时越界"。触发面 =
x86 roll 的 rng 状态（seed 0 复现；生产 multiseed 未命中——推断：历史
x86 pack 的 ctx.rng 状态恰好未撞，属时间 bomb 而非不可能事件）。

**T16 三票清偿口径**：余量耦合 → 预留协议；空数据节 → 预留恒非空；
诊断微损 → note 带 opcode 名（isa::to_string 单一来源，截断 8 + 省略）。


## MIT-477（IAT 引用重写）收口——rip 引用扫描范式 + 残留风险披露（2026-09-07）

**扫描范式**（x64 PE 内联引用重写的通用配方）：线性反汇编（同步区高效）
+ 锚点模式补漏（FF 15/25、(REX)? 8B /r mod=00 rm=101——IAT 引用的支配编
码集），共享守卫 = 目标落 span + 槽对齐（8B）+ disp 回读校验（addr +
size + disp == target）+ int32 界。幂等性由"重写后 target 不再落原
span"天然保证。**三个工程契约**：cs_malloc/detail 契约；disp32 读必须
u32→i32 符号扩展；capstone 地址游标推进语义（以 insn->address 为准）。

**v1 砍面披露**：① x86 绝对寻址引用不重写（imm32 + .reloc 联动：改写
imm32 后旧 reloc 项会把 load-time delta 加到新地址上——需同步增删 reloc
项，独立工作量）；② 数据段函数指针表指向 IAT 槽的形态不重写（.reloc
目标扫描可判，留 T9.2）；两者均被 TLS 回填兜底覆盖（原 IAT 运行期有效），
正确性无损，仅少拿"原 IAT 恒乱数"的混淆增益。

**回填保留裁定**（D 级默认）：跳过回填可移除 .rdata 页 VirtualProtect
翻转面（检测敏感），但依赖"重写完备"证明（reloc 全扫 + 数据指针零命中
+ 代码全重写），证据链不足即冒险；v1 = 重写 + 回填双轨（零风险），完备
性证明与跳回填 = T9.2。


## MIT-478（junk-Mov 二次翻案）收口——IR 侧审计的边界实证（2026-09-07）

**审计表定稿**（IR 操作数未声明的 VM 槽消费面，截至本单）：Call(x64) →
{rcx,rdx,r8,r9,rax}；Ret → {rax}；Div/Idiv → {rax}；Mul → {rax}；
Cmpxchg → {rax}；Cdq → {rax}。Div/Idiv/Mul 的 Rdx 经 dst-tag 非
pure-def 读路径覆盖。cl 族移位经 reg_b 声明覆盖；string-op 翻译期展开
为显式 ops 覆盖；rsp/rip/flags 恒排除。

**二次翻案实证**（CFG 活跃度 + 审计表完备后仍失败，wvmpTest seed
12345）：① junk rcx @ b64 wrapper（注入点后紧跟 `mov ecx,eax` 重定义，
再经 callgate 调原生 0xd540）→ 进程崩溃；② junk rax @ region[1] →
b64 内核软失败；③ **nop-only 换落位同崩**——MIT-459 时代的"绿色"实为
落位幸运。结论：消费面在 IR 不可见的 VM 级（callgate 邻域：Win64 参数
marshal 面、影子空间、或嵌套 VM 的槽语义——三个候选未分辨）。IR 级
liveness 对该面**原理性不可见**（消费发生在 VM 执行期，不在 IR 操作数
图内）。

**重启启用前置（T6.2）**：VM 级 dataflow 工具——消费 asmgen handler 表
+ translator 发射面，生成"VmOp × VM 槽"精确读写矩阵；mutate 直接消费
矩阵做注入判定（替代 IR 级推断）。或等价：callgate 前强制**全槽活**
（Kill 面 = callgate 参数槽之外的槽全部不可注入——粗但可能已足够，因
失败样本全部位于含 callgate 的区域）。**快速通道候选：含 Call 的块内
禁止注入**（本单未验证，T6.2 首试）。

## MIT-479（T6.2 快速通道实测）——callgate 假设被否 + 单 Nop 复现 + T6.3 立案（2026-09-07）

**快速通道实测（否定）**：含 Call 块禁注入（142 Mov 全落无 Call 块）→
kern.md5 仍崩。callgate 邻域假设**被否**。

**二分深化（决定性）**：WVMP_NOP_LIMIT/WVMP_JUNK_LIMIT 钩子（rng 前缀
确定性保持）逐级收缩——
- junk 全禁（limit=0，仅 Nop 新落位）**仍崩** → 与 junk Mov 无关；
- **单个 Nop** 即复现：region[1]（marker@0xc9c7，kern.b64 wrapper）
  block=0xD65B host=0xD65F 注入 1 个 Nop → kern.b64_rfc4648_vectors
  软失败（结果错）；
- 该块 IR 地址含 **lifter 微展开合成地址**（0xD65F/0xD666/0xD66A/0xD66D
  均非原生指令边界——原生 0xD65D 为 `and eax,0xFF` 5 字节立即数内），
  mutate 以 `下一条 IR insn 的 addr` 作 host 插入 → 出现 **同地址插入
  对**（NOP 与 Sub 同键 0xD65F），指向 translator/lifter 地址键行为
  （next_ip_of/bidx/载体匹配等 insert_or_assign 面）在 mutate 同址插
  入下的未定义序。

**T6.3 立案**：mutate 同址插入 × 地址键 translator 行为——修复方向：
① mutate 插入物 addr 改为"前一条真实 insn 的 addr + 插入序偏移"或直接
复用前一条 addr 的既有同址纪律（MIT-426 Movaps 先例审计）；② 审计
next_ip_of/载体匹配/jump-table 匹配在同址对下的取值序。修复后重跑本单
的单 Nop 复现（确定性最小用例）→ 绿色再议 junk-Mov 重启用。

**方法论**：二分钩子（注入上限 env，rng 前缀确定性保持——先取全部
rng 再决定发射）是确定性变换失败定位的通用工具；"nop-only 绿色"不能作
为机制安全证据（落位幸运），必须以注入/不注入对照实验分离变量。


## MIT-480（T6.3 第一阶段）——VM blob 解码 diff 锁定 divergence + 函数级门控（2026-09-07）

**blob 解码方法论**（wvmpTest kern 崩调查沉淀）：.wvmp 节按 "WVMP"
magic 走多 blob；blob 头 offset+12 = 流 word 数，流起于 offset+16；解码
= 每 8B word：op=低 14 位、reg_a=22..26、reg_b=27..31、aux=32..63。
对拍两包（仅注入数不同）→ blob1（region[1] b64 wrapper）词数 130↔124，
divergence 起点 word[94]：Callgate aux 36→30（目标错位 = 野 call）+
word[96] 中途 Halt 折叠（跳表匹配半成功 fallback）。

**门控现状**：share-prev 地址纪律（修复同址对 next_ip_of 自指——历史
落位全绿实证）+ 含 Reg 间接跳转函数整函数禁注入（拦 1 函数）双门控下
kern.md5 仍崩 → 跳表候选不止 Reg-Jmp 形态（或半翻译 fallback 面 wider）。
**下轮首步 = 函数级二分**：WVMP_MUTATE_ONLY_FN=N 只注入第 N 个函数，14
次实验锁定肇事函数 → 读该函数 IR/发射面 → 精确修复。

## MIT-480 续（T6.3 函数级二分结果，2026-09-07）——系统性 translator 插入敏感缺陷

**函数级二分实测**（无 crypt 7-pass，全部注入仅落在单个函数 N）：
fn=0 绿 / **fn=1 崩** / **fn=2 崩** / fn=3 绿 / **fn=4 崩** / fn=5 绿 /
**fn=6 崩** / **fn=7 崩**（fn=8..13 未测，模式已明）——多个函数任一插
入即崩，且崩点均在 kern.md5 入口（byte 7023 一致）。**系统性 translator
插入敏感缺陷**，非单函数/单模式问题。

**证据链汇总**（T6.3 修复输入）：
1. 单 Nop（block 0xD65B host=0xD65B）→ 崩；单 Nop（host=0xD678）→ b64
   软失败；同块不同位置不同症状。
2. blob1 解码 diff（全注入 vs 零注入，词数 130↔124）：divergence 起点
   word[94] Callgate aux 36→30（目标错位）+ word[96] Halt 中途折叠。
3. 致命块 IR 全量 dump 在案（14 insn，全走 RCX 的 /Od 溢出码形）。
4. 多函数任一插入均崩 → 与具体函数无关，与"插入了东西"本身相关。

**根因候选（按概率）**：① translator Scratch 分配器对插入敏感（sc.take
序改变 → 后续 VM 词的 scratch 槽变化，若某 handler 对 scratch 槽有隐含
假设即断）；② next_ip_of/块切分地址键的同址/移位序；③ Emitter 的
pending-jump 回填在插入后的序数漂移。修复需 VM 级 trace（per-word 执行
对拍）或 translator 不变量审计——**独立专项，非 mutate 侧可修**。

**现状裁定**：junk-Mov 关闭（维持）；Nop 注入也受同一缺陷影响（ mutate
nop-only 新落位可崩——**生产建议：mutate 密度 ≥1 时对含 callgate/复杂
区域的产物跑双跑对拍**；历史绿色包属落位幸运）。

## MIT-481（T6.3 定案，2026-09-07）——二分混杂变量揭示：Nop 面 share-prev 已修复，无系统性 translator 缺陷

**推翻 MIT-480 续的裁定**。"系统性 translator 插入敏感缺陷"系**混杂变量
误诊**：adce88f 的函数级二分在 `kEnableJunkMov=true` 下运行（175e2f6 翻
案时刻的遗留值，且该次"翻案成功"结论本身是乐观误判——kern.md5 全量回归
未跑；adce88f 入册时又漏翻转本位，main 一度处于"代码开着已证伪的
junk-Mov"的自相矛盾状态）。二分观察到的 fn=1/2/4/6/7 崩溃**需 junk
Mov 参与方能解释**（E2 为 Mov+Nop 复合实验：新增变量 = 144 Mov，其
Nop 数 101 低于 E1 已证全绿的 113，Nop 密度不是区分变量；未隔离
"Mov 单独"vs"Mov×Nop 交互"——junk 精确归因归 T6.4），与 Nop 注入
本身无关（E1 独立证明）。

**决定性对照实验**（wvmpTest x64，seed 12345，7-pass 无 crypt，当前
share-prev 地址纪律 + 跳表候选门控，mutate 密度默认 10%）：
- E1 `kEnableJunkMov=false`：全量注入 **113 Nop / 40 块** →
  packed rc=0，**103/103 全绿**（含 kern.md5 / kern.b64 历史必崩面）；
- E2 `kEnableJunkMov=true`：全量注入 144 Mov + 101 Nop →
  **segfault 于 kern.md5_block_vectors 入口**（历史崩点签名逐字节一致，
  末条 [RUN] = kern.md5）。可比性：E2 的 Nop 数（101）**低于** E1 全绿
  的 113——两实验的差异变量恰是 144 个 Mov，注入数不同不破坏对拍。

**结论链**：
1. **Nop 注入面已被 share-prev 纪律修复**（MIT-480 一阶段的地址纪律修复
   本来就是充分修复）；全密度（113 落位）全绿，"落位幸运"论作废。
2. **junk Mov 在 share-prev 下仍崩**（E2）——MIT-478 的缺陷独立于地址纪
   律存在。注意 MIT-478/479 时代的全部 junk 实验（含"含 Call 块禁注入仍
   崩"、"junk rcx/rax 定点复现"）都跑在 share-NEXT 纪律下，其"callgate
   邻域假设被否"等中间结论同样被 share-NEXT 混杂，**junk-Mov 调查需在
   share-prev 基线上重启**（T6.4 候选）。
3. MIT-480 续列的三个根因候选（Scratch 分配 / 地址键同址序 / pending
   回填序漂移）全部不成立——blob 词流平移自洽性审计（静态）+ E1 实证
   （动态）双确认。
4. 历史单 Nop 复现（MIT-479 share-NEXT 时代 + MIT-480 续时代）与二分崩
   溃，均为 share-NEXT 自指缺陷或 junk Mov 缺陷的复合表现，无第三缺陷。

**状态修复**：`kEnableJunkMov = false`（恢复 + 注释改写为最终裁定）；
mutate Nop 注入面恢复生产可用（默认 10% 密度，无需双跑对拍）。

## MIT-482（T6.4 定案 + T6.5 立案，2026-09-07）——def-kill 次序缺陷修复 + 基线 seed/布局脆弱性

**junk 首恶根因修复**：MIT-478/479/481 时代全部 junk 崩溃的首个实锤根因
= mutate `insn_transfer` 的**纯定义杀/use 标记次序缺陷**。活性语义应为
live_in(i) = (live_out(i) \ def(i)) ∪ use(i)，原实现先 use 后 kill → 目的
与自身 mem 基址/变址重叠的纯写指令把同指令正要读的槽误杀成"边界死"。
实录：md5 区域 `movzx ecx, byte ptr [rdx + rcx]`（host 0xDF21，region
marker@0xd298 b3/i23）→ junk `Mov v1, 0x496E4B90` 注入紧邻读者指令之前
→ VM 词流 word[89] 写 ctx[1]、word[91-93] 读作变址 → Load 野指针
segfault（cdb + blob 词流解码 + 单区域 ALLOW 钩子三重实证）。修复 =
kill 先于 use；回归专测 MutateLiveness.PureDefKillMustNotEraseMemOperandUse。
修复后 seed 12345 全量 165 junk Mov → 103/103 绿。

**T6.5 立案（阻塞 junk 重启用）**：宽 seed 扫描暴露**基线 seed/布局脆弱
缺陷**——无 mutate 基线包 seed 3/9/11 崩于 kern.md5、seed ≥12 有挂死
（VM 循环）；wvmpTest 基线历史只验过 seed 12345。且 seed 12345 下不同
注入布局（96 Nop / 165 Mov / 239 混合）绿崩不一 → 缺陷对 blob 布局敏
感（asmgen roll/jump-table/handler 布局随 seed 变化），注入内容只是布
局随机化器。MIT-480 续的"word[94] Callgate aux 36→30"疑云与此同源待
验。调查入口 = 基线包 seed 3 的 kern.md5 blob 词流静态解码 + asmgen
x64 roll 分配审计。**junk-Mov 重启用（kEnableJunkMov）保持 false，待
T6.5 修复 + 全 seed 扫描转绿。**

**诊断资产**（本单落地）：① mutate 逐注入点 site_log note（含 slot/imm/
host，VM 级消费面对账主键）；② WVMP_MUTATE_ALLOW_RVA 诊断钩子（fn.name
子串匹配、发射级丢弃、rng 抽取序保持——注意 begin_rva 匹配会因 region
begin ≠ marker 名静默失配，本单已修正并以此踩坑入册）。

**验收补强（2026-09-07）**：① read_mem(in.src2) Mem 形补录是行为变更
（use 面扩大 → 注入面收紧，seed 12345 默认布局 239→240 站点）；② 钩子
更名 WVMP_MUTATE_ALLOW_FN（fn.name 子串匹配，激活报 Note，消除 RVA 命
名误导）；③ junk 分支 dead[i] 空集 uniform 下溢 UB 守卫（T6.5 重启用前
置守卫项，验收建议采纳）。

## MIT-483（T6.5 调查一阶段，2026-09-07）——blob 跨 seed 恒等（translator 免罪）+ 缺陷收敛到解释器/桩面

**决定性实验**（base 包 seed 12345 vs seed 3，无 mutate）：
- `.wvmp`（全部 blob 词流）SHA256 **恒等** → translator 词流与 seed 零关
  联，MIT-480 续的"blob 词流 diff"方法论对基线缺陷**失效**（当年对比的
  两包内容本就不同——junk 与非 junk——divergence 是内容差的平移，非病）。
- `.wvmpc` 尺寸 0x84b3 vs 0x8653（**+0x1A0**）且哈希不同 → seed 进入解
  释器生成（asmgen x64 roll 的寄存器角色/编码差异）。**T6.5 缺陷面收敛
  = 解释器/桩生成，非 translator、非 mutate。**

**崩溃链静态解码**（base seed 3，cdb ctx+0=流指针/ctx+8=入口词序号 +
blob 词流静态解码，词流与绿 seed 逐位同源）：
- 崩 handler = Load 家族 S32 分支（`mov esi,[r14]`，地址槽 ctx[18]=0）；
- 崩词 [435] `Load s20,[s18]`，前置链 [431] `Mov s18,v2` ← [430]
  `Load v2,[s18']` ← [428-429] `Mov s18,v4; Add s18,0x48`——即
  `v2 = *(v4 + 0x48)`：**经 VM rsp 镜像槽（v4）寻址原生栈帧的槽加载返
  回 0** → 后续 `v2 + v1<<2` 解引用崩。
- 嫌疑收敛：v4（rsp 镜像槽）在 seed-3 roll 构建下的初始化/维护——stub
  entry 的 push 序与 rsp 捕获、callgate step 4-8 的 rsp 切换与 v4 槽同
  步、或 roll 改变 push 序后某处硬编码偏移失配（asmgen:348 有同类前
  科：宿主 RBP 槽错开 0x88 → ctx_=0）。

**下轮首步**：① 对比 seed 12345/3 两构建的 stub entry（vm_entry push 序
+ rsp 捕获点）与 callgate step 4/7 的 rsp 常量链（kPushCtxDepth/
kCallgateSpRollback 派生）；② 用 WVMP_X64_ASM_DUMP 式钩子给真实 pack 的
解释器生成落盘 diff roll 表（ctx_/base_/pc_/flags_/t_[0..9] 的物理映射
+ size_perm_/cond_perm_）；③ 修复判据 = seeds 0..41 基线全绿（含挂死
面）+ junk-Mov 重启用后全 seed 扫描绿。junk-Mov（kEnableJunkMov）维持
false 至此判据达成。

## MIT-483 续（T6.5 二阶段，2026-09-08）——崩构建控制流断裂实证：后向 Jmp 直落

**追踪方法**（入册复现）：cdb 条件断点钉在分派取指指令（崩构建
0x14011e032），过滤目标 blob 流 VA（ctx+0），log 词序号 r15 + ctx 槽
（CTX2=ctx+0x20、CTX18=ctx+0xA0、CTX4=ctx+0x30）；`--filter=kern` 缩短
到达路径；⚠️ cdb 命令 printf 换行需四层转义（`\\n`），且全量 suite 的
逐词断点开销巨大——坏构建因中途崩停可 500s 内跑完，**好构建全 suite 追
踪超时**（808s 仅到 ~test25），需 --filter 直达或更廉价断点。

**关键实证**（base seed 3 崩构建，md5 blob 流 0x1179f0，1657 次分派全
序列）：词 [102] = `Jmp`（op23，aux=0xffffffa0 = 有符号 -96，语义应回
跳至词 6/7 = fn A 循环头）**未跳转、直落 [103]**——控制流断裂。前链：
区域双入口（词 0 = fn A：~1500 次分派的循环体；词 99 = fn B 入口，
首词 [99] `CallGate 0xd290` 回调 fn A），fn B 顺序直落执行 [100..435]
→ [430] `Load v2,[v4+0x48]` 读到 0（fn A 未按控制流写回）→ [435]
`Load [v2+v1<<2]` 地址 0 → segfault。与绿构建的逐词序列对比因追踪开销
未完成（好构建 trace 五次尝试均 0 命中或超时——断点地址 0x11e02e 与
命中行为待复查，建议下轮改用 --filter=kern + 两构建对称探针）。

**嫌疑收敛（asmgen 审计输入）**：Jmp/Jcc handler 的 pc 更新在特定 roll
分配下失效——候选：① Jmp aux 的符号扩展/加法用了某个被 roll 分配为
caller-saved 且被 decode_prelude 前序指令影响的寄存器；② Jcc/Jmp 的
advance 与 aux 加法路径在某 t_[n] == 物理rax/rdx 时被 spill 防护误伤
（spill_pcflags_raxrdx 只护 pc_/flags_）；③ 条件码/尺寸 perm（cond_
perm_/size_perm_）在 Jmp（无条件）路径的 unused-field 校验位翻转。
下轮首步 = 读 build_jmp/build_jcc 模板 + 在 seed 3 构建的反汇编中对照
Jmp handler 机器码与 12345 构建逐条 diff（地址：分派表 entry[23] →
handler 起始）。

## MIT-483 续二（T6.5 三阶段，2026-09-08）——自区域 CallGate 重入失效实锤

**词级状态追踪**（崩构建，IDX+V0/V1/V2 槽值，1657 分派全序列）：
词 [99] `CallGate 0xd290`（目标 = 本区域 fn A 的原生入口 0xd290 = 已被
stub_link 打补丁的地址 → 语义 = VM 自重入执行 fn A 词 0..98）执行后
**IDX 直落 100、V0=0**——fn A 的分派（应再现 IDX 0..98）**一次都没发
生**，callgate 返回 0。对照：同 blob 在绿构建（seed 12345）下该调用重
入 fn A 并返回正确值（.wvmp 恒等 → 词流与数据全同）。

**缺陷定性**：特定 roll 分配下，**自区域 CallGate 重入路径失效**——
候选面：① stub 的 vm-active 嵌套检查（stub 侧全局/ctx 标志在重入时
误判）；② callgate handler step 0 目标解析（t_[3] 判别位读到了错误
槽 → 走了 reg 形分支拿 0 目标？）；③ callgate 的 arg 桥（step 1 预
留槽 0xD0..0xE8）在重入场景被第一个 stub 覆写。**注意 V1=0xf/V2=
0x15f7f0（参数槽）在 callgate 前后完好** → 参数桥无罪，嫌疑集中
②③（目标解析/重入机制）。

**下轮首步**：① 反汇编双构建 CallGate handler（分派表 entry[35]）
全量 diff——重点 step 0 的 `cmp t3,1/jne` 判别与 step 9-11 恢复序；
② 查 stub_gen 对"已打补丁区域入口"的重入语义（vm-active 标志位）；
③ 修复判据不变（seeds 0..41 基线全绿 + junk 全 seed 扫描绿）。

**方法论补丁（复现工具链）**：cdb 追踪必须 `sxd av; sxd c0000094` 双
flag（缺 c0000094 会被 exc 用例中断）；printf 换行四层转义；全 suite
逐词断点好构建超时 → 只追目标流（ctx+0 == 流 VA）。

## MIT-483 续三（T6.5 四阶段，2026-09-08）——callgate 空返回确认 + native_sp 合成栈列首要嫌疑

**新实证**：① RVA 0xd290 在两个 base 包中**均未被 E9 打补丁**（原始字
节 40 53 48 83 ec 完好）——callgate 调的是**真原生函数**（非 stub 重
入）；② 词级追踪确认 V0 在词[99] CallGate 后即变 0（此前 V0=0x10），
V1=0xf/V2=0x15f7f0 参数完好——**原生 callee 以相同参数在坏构建返回 0、
好构建返回非 0**。

**首要嫌疑 = callgate 给 callee 的合成栈**：native_sp（ctx+0x120）由
stub 捕获（stub_gen.cpp:311-315 `lea rax,[rsp+0x208]`，v4 与 native_sp
同源）；callgate step 4 切 rsp 到 native_sp - 0x28垫 - callee 窗口。
若 seed 相关因素（roll → 解释器代码尺寸 → 无关；但 stub 布局/entry
_rsp 深度随调用链变）使 [v4+0x48] 落进 stub 自身保存区/ctx 区而非
caller 帧，native callee 的栈帧读写即错。**实测 [v4+0x48]=0x15f758 已
越出 ctx 界（0x15f508+0x1C8=0x15f6D0）**，落在 stub 保存区/caller 帧
交界——该地址归属两构建是否一致待验。

**下轮首步**：① 干净重试 bp 0x1400d290（callee 入口）log rcx/rdx/rsp
——callee 是否被执行、栈深多少；② 对比双构建同地址 [v4+0x48]=0x15f758
的内存归属（GCCTEX？caller 帧？stub 保存区？）与生命周期；③ 审
build_callgate step 9-11 + stub_gen 的 kStubPushBytes/kCtxSize/kPushCtx
Depth 常量链在多深调用链下的一致性。

## MIT-484（T6.5 定案，2026-09-08）——callgate 双缺陷根因实锤与修复：step1 rax scratch 覆写 + epilogue 恢复冲掉返回值

**根因（asmgen.cpp build_callgate 两处，均为 roll 洗牌敏感）**：

**缺陷① step 1 参数快照 scratch = 物理 rax**。四对"regs 槽 → reserved
槽"搬运（0x18/0x20/0x48/0x50 → 0xD0/0xD8/0xE0/0xE8）用 `mov rax,…;
mov [ctx+…],rax` 走物理 rax。roll() 的 10 寄存器 pool 恒含 rax/rdx，
flags_/pc_ 可被分到 rax（实录 seeds 3/9/11/23/29 等）——快照一覆写
rax，step 2 的 `mov [ctx+0x98], flags_` 存进去的就是快照残值（v9 残
值），native callee 收到的 flags/pc 已坏。

**缺陷② epilogue 恢复次序颠倒**。恢复 pc/flags/base 的
`mov rax,[ctx+0x98]`（flags_==rax 时）先于 v0 写回
`mov [ctx+0x10],rax` 执行——rax 里的 native 返回值先被 flags 槽值冲
掉，v0 写入污染值。实录 seed 3 构建：`mov rax,[ctx+0x98];
mov [ctx+0x10],rax` → V0 恒 0 → kern.md5 野指针 av（四阶段词级追踪
V0 在词[99] CallGate 后即变 0 与此完全吻合）。

**修复**（vm/regvm/runtime/src/asmgen.cpp）：
① 快照 scratch 改 `t_[1]`（角色互斥保证 ≠ ctx_/base_/pc_/flags_，
原值 step 4 才消费、快照处已死）；② v0 写回提前到 pc/flags/base 恢
复之前（rax 仍持 native 返回时先落槽）。

**验证全绿**：seed 3 基线 103/103（原 kern.md5 野指针 av 面）；seeds
0..41 全扫（基线，含挂死面 timeout 90/跑）ALL GREEN；ctest 23/23；
wvmpTest 双跑（kern_base seed 12345 / kern_mutate seed 3）各 103/103。

**dump 锚换代**：asmgen 模板变更 → 旧锚 67cfa727…/164,329B 作废，
新锚 **fb8c65cb47d129fadd04ac960f1981341fb899f4eb3423e9ba05069ab16c2
bac / 164,321B**（WVMP_X64_ASM_DUMP + gtest_filter=Interpreter.MovdB
ridgeSemantic 重新生成入册，布局头 entry=+0x0/dispatch=+0x2B/table=+
0x6BB8 不变）。multiseed 335 回归结果随附（见提交）。

**锚盲区警示**：dump 锚生成于 seed 12345（roll 后 flags_=r10/pc_=r14，
rax 非角色寄存器），**对该缺陷类不敏感**——单拿锚做回归门测不出本单
缺陷；缺陷面只在 flags_/pc_ 落 rax 的 seed（3/9/11/23/29 等）显形。
回归门必须含多 seed E2E（multiseed/全 seed 扫描），锚仅守模板漂移。

**方法论沉淀**：cdb `bu module+off` + ctx+0 流 VA 过滤 + `poi(ctx+0x
10+N*8)` 槽值日志是好/坏构建同构比对的有效路径；"哪个构建先坏"不如
"同一词流两构建槽值差异"定位快。

## MIT-485（T6.6 裁定，2026-09-08）——junk-Mov 生产重启用：全 seed 扫描转绿，MIT-478/T1 挂账正式关闭

**裁定**：kEnableJunkMov **true**（passes/mutate/src/mutate_pass.cpp），
junk-Mov 自 T1（MIT-459）挂账以来首次进入生产缺省面（Nop 面保持）。

**门槛证据**（MIT-482 立案时定判据"基线修复 + 全 seed 扫描绿"）：
① 前置基线缺陷已修（MIT-482 def-kill 次序 + MIT-484 callgate 双缺陷），
seeds 0..41 基线全扫 ALL GREEN；② 本单 junk 面全 seed 扫描：seeds
0..41 逐 seed 以 kern_mutate.toml 派生 TOML（mutate 7-pass，junk=true）
打包 wvmpTest + timeout 90 运行，**42/42 PASS**（判据 SUMMARY
passed=103 failed=0）；③ ctest 23/23；④ wvmpTest 双跑（base seed
12345 / mut seed 3）各 103/103；⑤ multiseed 335/335（mutate 面不在
multiseed 管道内，作零回踩门）。

**生效实证**：seed 3 注入统计 note「已注入 239 个垃圾指令（Mov 128 /
Nop 111，60 个基本块）」——junk 面真实发射非静默 no-op；注入点清单
note（MIT-482 site_log 资产）逐点可审计。

**安全背书链回顾**（junk-Mov 曾两次炸出真实缺陷，均已修复并有专测）：
MIT-478 审计（callgate 隐式读盲区 + liveness 区域级 CFG 反向不动点）→
MIT-482（insn_transfer kill-before-use 次序 + PureDefKillMustNotErase
MemOperandUse 专测）→ MIT-484（callgate step1 scratch + epilogue 次序
——**该缺陷在 junk 面同样会触发**，快照/恢复路径与注入内容无关）。
jmp-face 教训入方法论：锚对角色寄存器落 rax 类缺陷不敏感，回归门必须
含多 seed E2E（本单 42 seed 扫描即为该纪律的执行样板）。

**遗留**：junk 密度/概率常量（kJunkMovProbability 等）未配置化（T11
[mutate] 表仅 Nop 密度），需要时另立单；x86 面 junk 候选集与 x64 同
代码路径，x86 电池不受本单影响。

## MIT-485 补（验收建议落地，2026-09-08）——rng 抽取序单向差异与计数口径披露

① 翻动 kEnableJunkMov 经 else-if 短路改变 mutate 局部 rng 抽取序
（关闭态不抽 chance(kJunkMovProbability)）——**同 seed 产物相对关闭
态构建必然不同**（单方向差异，启用固有后果）；下游 ctx.rng 流不受扰
（mutate Rng 独立 salt：`ctx.seed ^ kMutateSeedSalt`，验收核实）。
② 注入统计 note 的 Mov 计数为"rng 语义计数"（junk_movs 在
region_allowed 判定前自增，白名单丢弃也计入），与产物字节对账需知悉
口径（Nop 侧同口径，:337 原注已言明）。

## MIT-486（T9.2，2026-09-08）——MIT-477 砍面清偿：x86 abs32 代码引用重写 + 数据段指针重写（.reloc 扫描）

**砍面① 复盘定案（reloc 联动不必复杂）**：abs32 站点（PE32 代码节内
HIGHLOW reloc 项）的 delta 修正作用于站点值本身——改写前后站点值均为
preferred-base 同镜像 VA，delta 线性作用于两者等价成立（镜像槽重定向
不改变"值随基址平移"的性质），**无需增删 reloc 项**；且 pe_writer 恒
清 DYNAMIC_BASE（delta=0，M2-8 起），stale reloc 项惰性，双保险。
MIT-477 时代"绝对寻址 + .reloc 联动复杂"的评估就此推翻。

**实现**（passes/import_protect/src/import_protect_pass.cpp）：
① `rewrite_iat_code_refs_x86`：CS_MODE_32 两级扫描（线性 + 锚点），
锚点集 = FF 15/25（call/jmp [abs]）、A1/A3（mov eax,[abs] /
mov [abs],eax）、泛 modrm mod=00/rm=101。守卫差异 vs x64 rip 范式：
abs32 disp 承载**全 VA**（须减 image_base 转 RVA 再对 span，实测踩坑）
+ 槽对齐 %4（PE32 槽宽 4B）+ raw32==abs 位置回读校验。改写 =
镜像槽全 VA（ib + mirror_rva + Δ），无 disp32 界。
② `rewrite_iat_data_refs`：dd[5] BASERELOC 全扫，非 EXECUTE 节内
DIR64 (PE32+) / HIGHLOW (PE32) 站点值（preferred-base VA）落原 IAT
span 的重写为镜像槽 VA；EXECUTE 节站点归代码面（x86 abs32 站点的
HIGHLOW 项分流，避免双路径重复处理）。reloc 项保留：站点位置不变、
新值同镜像 VA，delta 线性等价照旧。

**真靶实证**（wvmp_tls_sample 11-pass 全栈）：x64 代码引用重写 39 处 /
x86 abs32 重写 40 处 / 数据指针 0 处（样本无静态数据指针形态；
wvmpTest .fptable 亦运行期填充）。静态校验
scripts/verifier/check_import_rewrite.py（本单扩展：PE32 abs32 面 +
数据指针残留面）双架构 **exec-hits=0 data-hits=0**。

**验证**：单测 +2（X86Abs32CodeRefRewrite 三形改写 + 非对齐/span 外
负例；DataRefRewriteRelocScan 双架构参数化 DIR64/HIGHLOW + span 外 +
EXECUTE 分流负例）；ctest 23/23；x86 电池绿；tls_e2e 2/2（断言升级：
双架构重写计数 >0 + 校验器零残留——旧"梅 x86 不重写"断言随砍面清偿
作废）；multiseed 335/335；wvmpTest 双跑 103/103×2。

**跳回填未动**（MIT-477 裁定维持）：完备性证明（"重写完备"→ 可移除
TLS 回填 + .rdata 页 VirtualProtect 翻转）另立票——需证明无其他引用
形态（含 drift 假阳面），收益 = 去检测敏感面；风险 = 漏引从"兜底可用"
变"必崩"。证据链门槛：锚点集穷举论证 + 全样本池零残留 + 漏引红线
（FailFast 探针）三件套。

**工程坑实录**：① abs32 disp = 全 VA 不是 RVA（x64 rip 相对思维定势，
单测抓获）；② 合成夹具 .reloc blob 落节终点（rva_to_offset 排他界
返回空 → 整体静默返回 0，负例变假绿需以断言值判真伪）。

## MIT-486 补（验收建议落地，2026-09-08）——锚点残面备案与校验器判据对齐

**锚点集残面备案**（未来跳回填票"锚点集穷举论证"须显式处置的三族）：
① `FF 35`（push [abs32]，0x35 & 0xC7 ≠ 0x05 锚不中，线性兜底）；
② `0F` 前缀 modrm(00/101) 形（movzx/movsx/SSE mem，锚点仅匹配单字节
opcode，线性兜底）；③ `B8+r imm32`（立即数直接载荷 IAT VA，非 MEM
操作数，两重写面模型外）。附：校验器与重写器线性路径同盲（无锚点
路径），零残留是必要非充分证据；高基址 PE32（base ≥ 0x80000000，
capstone 符号扩展）双盲——保守安全，回填兜底。
**判据对齐**：校验器数据站点判据改为与 rewriter 全含式一致
（site + w ≤ va + vs，消除节尾假阳面）。

## MIT-487（T9.3a，2026-09-08）——跳回填完备性证据基座：锚点加固 + 模型外负扫 + 全池零残留

**完备性论证结构**（跳回填决策的证据链第一层）：
① **引用形态全域普查**（native 70 样本 = multiseed 双架构池 + tls 双架构
+ wvmpTest 靶标）：残面四族——FF 35（push [abs/rip]）、A1/A3（x64 为
moffs64，x86 为 abs32 mov eax 形）、B8+r imm32 直接载荷、moffs64——
**70/70 全零**。即池内 IAT 引用形态全集 = {x64 rip 相对 MEM /
x86 abs32 MEM}，恰为两 rewriter 的建模面。
② **重写面语义完备**：线性 capstone 路径按指令语义（MEM 操作数）
覆盖全部形态，锚点仅为 drift 防线（本单加固：x64 锚加 FF 35 + 0F 前
缀 mem 系（movups/movaps/movzx/movsx 白名单）、x86 锚加 0F movzx/
movsx 系；FF 35 x86 面已由泛 modrm(00/101) 分支覆盖（0x35 & 0xC7 ==
0x05）；x86 锚点循环上界 i+2→i+3 修正（0F 锚读 b[2] 越界））。
③ **迁移样本零残留**（校验器，本单加 imm 负扫 B8-r/moffs64）：
tls 双架构 + test_target 迁移 3/3，exec/data/imm-hits 全 0；其余 67
样本未导入 kernel32!VirtualProtect → v1 硬依赖保守回退（无迁移面，
原 IAT 引用本就正当，不在残面前提内）。
**工具**：scripts/verify_pool_imports.sh（全池打包 + 逐样本校验，70/70
PASS；注意"放弃 IAT 迁移"含"IAT 迁移"子串，回退分流必须先行）。

**限制披露**：迁移面覆盖 3/70（v1 VP 硬依赖——回填需经既有 VP IAT 槽
调 VirtualProtect；无 VP 导入样本不支持迁移，属能力边界非完备性缺陷，
census 论证覆盖全部 70）；x64 PE32+ 低基址（<2GB）abs32 编址在
long 模式不存在（modrm(00/101) = rip 相对），moffs64 MSVC 不生成 +
校验器负扫兜底。

**结论**：在池域内"重写完备"证据链闭合（形态全域普查 + 语义面覆盖 +
迁移零残留）。跳回填行为票（T9.3b）剩余前置 = FailFast 红线桩（漏引
从野指针变受控崩溃）+ 漏引风险最后一环（drift 假阴双保险论证）。

**工程坑**：x64 INT 槽 8 字节步进——4 字节步进普查脚本 IAT span 全算
小（slot0 高半字 0 提前终止），"零存在"结论曾建立于错误分母；修正后
重扫方为有效证据。

## MIT-487 补（验收 MUST-FIX 落地，2026-09-08）——校验器同源 span 步进缺陷修复

验收代理 MUST-FIX（有效）：check_import_rewrite.py 的 iat_span 与被
披露的 census 脚本**同源缺陷**——INT 槽 4 字节步进在 PE32+ 下于首个
8B 槽高半字 0 处提前终止 → span 少算（52/52 x64 样本，漏检 280–944
字节；test_target 仅覆盖 6%）。MIT-477 时代既有，非本单引入；代理以
dd[12] 正确 span 独立复扫 3 个迁移样本 exec/imm/data 三面仍全 0，
"迁移零残留"结论不受影响，但证据工具覆盖面有洞。**修复**：① INT 按
w 步进；② 新增 span 自检（native dd[12].Size 非零时必须与 INT 计数
一致，不一致退出码 1——分母错误自动捕获）。其余建议随落：x86 0F 锚
点补 SSE 系（与 x64 对称）；imm 负扫注释澄清 C7 /0 归 MEM 面 + x64
B8 >4GB 结构性缺席；x64 0F 锚"prefix 变体被 size 排除"注释更正为
"尾解码落点与真指令一致，守卫照常生效"。修复后全链复跑：ctest、
tls_e2e、池扫（见提交数字）。

## MIT-488（T9.3b，2026-09-08）——跳回填行为票落地：[import] skip_backfill + FailFast 红线桩

**语义**（opt-in，缺省 false = 回填模式零变化）：配置 `[import]
skip_backfill = true` → import_protect 迁移后把**原 IAT 全槽（含 NULL
终止槽）**写入 FailFast 桩 VA（.wvmpc 内 16 对齐 8 字节
`31 C0 C7 00 00 00 00 00` = `xor eax,eax; mov [eax],0`，双架构同字节，
写 0 地址确定性 AV）；ImportPlan 携带 skip_backfill/failfast_stub_rva；
tls_hook 回调体据此**整段省略回填循环**（无 VP 调用、无 rep movs——
.rdata 页翻转面消失；adb/rdtsc/drx 前缀照常）。.wvmpc 缺席（旧夹具）
→ 保守回退回填模式（Note）。

**依据与红线**：MIT-487 完备性证据链（形态全域普查四族零 + 迁移零残
留 + 锚点加固）成立 → 域内无引用落原 IAT，回填兜底成为纯冗余面；域
外形态一旦漏引，槽中桩 VA 使调用侧**确定性受控崩溃**（而非野指针静
默错行为）——漏引从"静默"变"响亮"，这正是跳回填的安全前提。

**运行期验证**（本单新增的最强实证）：
① **零漏引正面**：tls 双架构 skip 模式打包 → native vs packed stdout/rc
**byte-exact**（tls_e2e 4/4：backfill 2 + skip 2）；
② **红线负例**（x86，B8 imm32 结构可编码面）：把执行路径上的
`call [IAT 槽]`（FF 15）等长替换为 `mov eax,<槽VA>; call rax`
（B8+FF D0，重写器模型外）→ skip 模式打包运行 **rc=3221225477
（0xC0000005）确定性 AV**——红线桩按设计工作。x64 同构面结构性不可
编码（基址 0x140000000 > 4GB，imm32 装不下全 VA），恰为完备性论证的
一部分（MIT-487）；
③ **静态断言**：packed .wvmpc 回调区无 rep movsq/movsd（x64/x86 面
tls_e2e skip 分支自动化）；原 IAT 全槽（x64 42 / x86 43）唯一值 = 桩
VA（同上自动化）。

**工程坑实录**：① x86 样本侦察连踩三坑——描述符在 .rdata 而非 .text
（r2o 硬编码单节映射全读飞）、x86 abs32 目标是全 VA 须减 ib 再对
RVA span、span 上界误减 ib 变负数——三次"零命中"全是扫描器错而非靶
真零；② x64 B8 负例注入测试在 pack 前即不可行（imm32 溢出），属论证
性面非测试面。

**验证**：ctest 23/23（**+6 用例**：config [import] 三态 +
SkipBackfillSlotsFilledWithFailFastStub + SkipBackfillTlsCallbackOmits
BackfillLoop + SkipBackfillWithoutCodeSectionFallsBack）；tls_e2e 4/4
（skip 分支静态断言复活后全绿）；multiseed 335/335（默认关断零回踩）；
池扫 70/70。

**披露**：skip_backfill 仅在"目标进程无第三方注入补丁"前提下安全——
外部工具若依赖原 IAT 布局（罕见且本就破坏者视角），跳回填语义为显式
opt-in，缺省关闭。

## MIT-488 补（验收 REJECT 落地，2026-09-08）——R1 阻塞缺陷与 R2 测试缺陷修复

**R1（阻塞，验收代理有效否决）**：FailFast 桩发射误用 kEmitReserveBase
游标（.wvmp 数据节专属预算，stub_link 仅给 .wvmp 预扩 8KB）作为
.wvmpc 落点——游标值 ≪ .wvmpc 代码节尺寸，桩被写进**解释器代码正中
间**（实录：x64 tls 样本 .wvmpc+0x1B0 覆写 `add r12,1; jmp` 推进尾，
≥5 个 handler 臂直达该地址；x86 同构覆写 handler 解码中段）→ 每个
skip 产物被挖 8 字节解释器，踩中即 VM 内确定性 AV。tls 两样本恰未踩
中，e2e 全绿假象——C2 级静默损坏。**修复**：桩改 .wvmpc **尾部追加**
（16 对齐 grow 语义，与 tls_hook 回调桩同款；.wvmpc 为末节，追加不破
坏任何后续节 RVA；本 pass 先行无冲突）。**教训**：kEmitReserveBase 是
节专属预算不是全局偏移——跨节复用游标值 = 把数据节坐标当代码节坐标；
单测夹具 .wvmpc 仅 16B 恰好让错误落点 == 尾部，假绿（夹具尺寸应足以
区分"游标落点"与"尾部落点"两种语义）。
**R2（测试缺陷）**：tls_e2e skip 静态断言两处叠加失效——① span 走
packed dd[1]，FirstThunk 已重指镜像 → 扫的是镜像随机字节；② `if !
python; then : else FAIL` 极性反转 → 断言永不生效（死代码）。**修复**：
span 从 native 侧取；极性改正；增补回调区 rep movs 扫描（x86 F3 A5
面首次自动化）。红例自证：篡改 skip 产物单槽 → 断言判 2 值非一值
转红。
**随落**：槽映射预检（任一原 IAT 槽不可映射 → 保守回退回填模式，漏填
槽静默 continue 取消）；无 .wvmpc 回退单测补齐。修复后全链复跑：重建
0 错、ctest 23/23、tls_e2e 4/4、红线负例（x86）rc=0xC0000005、池扫
70/70。

## MIT-489（T21，2026-09-09）——[mutate] junk_density 配置化（MIT-485 披露遗留清偿）

**语义**：`[mutate] junk_density = 0..100`（百分比，在场时覆写缺省
15%；0 = 关闭 junk 面保留 Nop 面；严格 schema 同 density：未知子键/
非整数/超界拒绝）。ProtectRules 携 has_mutate_junk_density/
mutate_junk_density（缺省哨兵 15）；mutate pass 以
junk_probability = rules / 100.0 替代 kJunkMovProbability 直读。
**rng 抽取序不变**（chance() 消费序恒定，仅阈值变）——同 seed 产物在
"配置缺省"与"代码常量缺省"下逐字节一致（实测：缺省注入 239 = Mov 128
/ Nop 111，与 MIT-485 基线逐字相同）。

**行为验证**（wvmpTest seed 3）：junk_density=0 → Mov 0 / Nop 103
（junk 关断面）103/103 绿；junk_density=100 → Mov 912 / Nop 101（每
eligible 位全注入）103/103 绿——两端密度 + 缺省零漂移三面取证。

**验证**：ctest 23/23（+4 config 用例：junk_density 解析/0 值/超界/
非整数）；wvmpTest 双端密度运行绿；multiseed 335/335（管道无 mutate，
零回踩门）。asmgen 零触碰。

## MIT-490（T22 测试卫生单，2026-09-09）——三项验收遗留小测试打包

① config 哨兵缺省守卫（MIT-489 建议 2）：[mutate] 缺 junk_density 时
has_mutate_junk_density=false + 值 15 断言（守卫"缺席→消费方走代码
常量路径"契约；density=10 串写即双红）。② 不可映射槽预检单测
（MIT-488 建议 2）：FT 连续改指节间空洞（避开区间连续性回退、让预检
成为触发点）→ 保守回退。③ tls_e2e rep-movs 扫描窗随回调尺寸化
（[cb0, .wvmpc raw 末端)；窗内越界自动钳制 + 缺节 fail-loud）。

**红例自证教训（② 首版 REJECT）**：夹具缺 .wvmpc 节 → 回退条件
`wvmpc == nullptr || !all_mappable` 短路，测试实际走"缺节回退"分支
而非预检分支——断言全过但对预检零敏感（死测试）；且原"预检移除则
skip_backfill=true 断言失败"的红例推理链不成立（短路下删预检回退依旧
发生）。**修正**：夹具补 .wvmpc + diag 消息断言（点名"不可映射槽"）
使分支可观测 + iat_base_rva==0x2800 钉死 FT 篡改生效。方法论：死测试
鉴别 = "该断言在其目标分支被移除时是否转红"必须逐字推演，分支短路条
件是首查项。

## MIT-491（T23，2026-09-09）——Emit 预留区高水位观测（MIT-476 验收建议落地）

**语义**：pe_writer run() 前置观测——.wvmp 数据节预留区
（[size - kEmitReserveBytes, size)，游标为节专属预算，MIT-488 R1 教
训）使用超过 75% 预算 → Note「Emit 预留区高水位：N / 8192 字节
（P%）——逼近预算上限，请评估 kEmitReserveBytes 扩容」。无游标槽
（旧夹具）/ .wvmp 缺席 → 静默跳过（零改动面）。观测点在 pe_writer
（流水线末端）= 三消费方（stub_link 初始 + import_protect 镜像/
oldprot + tls_hook CONTEXT/rdtsc/TLS 面）游标推进的最终汇点，单点覆
盖全部预算消耗。

**测试**：高水位（85%）出 Note / 低水位（12%）静默 / 无游标槽静默，
三用例。红例即正例本身（Note 出现即被断言捕获；篡改阈值两侧即翻转）。
夹具坑：.wvmp requested_rva 必须紧接最小 PE 节尾 0x2000（连续性硬拒
≠ 水位逻辑问题）；游标语义 = reserve_start + used（勿从节尾倒推）。

## MIT-493（T25 侦察单，2026-09-09）——ASLR 兼容性调查：MIT-340 误诊反转，可行性定案

**背景**：M2-8 起保护后恒清 DYNAMIC_BASE 强制加载到声明 ImageBase；
MIT-340 时代 .reloc 扩展在 snake 样本 segfault，"Windows 加载器对保护
后 .reloc 扩展存在未排查的行为差异"挂账至今。

**绝对 VA 全域普查**（x64 tls 样本 seed 1 skip 模式，字节粒度）：92 处
= native 面 79（.rdata 77 + 头部 2；其中原 .reloc 实际覆盖 34 处，42
个 skip 桩值 IAT 槽由 loader 导入机制原生处理）+ packer 面 13（.wvmpc
7 代码 imm：TLS 回调 adb/drx/rdtsc/backfill 即时数 + **stub
scratch_mem 写入 `movabs rax, ImageBase`**；.wvmp 6：TLS 目录/回调数
组 VA）。**packer 面在原 .reloc 中零覆盖**。

**决定性对照实验**（脚本化：scripts/experiments/aslr_poc.py）：
- PoC：.reloc 节 slack 内追加 3 页 DIR64 块（55 站点，+144B）+ 置
  DYNAMIC_BASE → ASLR 加载 **rc=0，stdout 与 native byte-exact**；
- 对照：仅置 DYNAMIC_BASE 不扩展 reloc → **rc=139 segfault**
  （MIT-340 崩溃形态复现）。

**裁定反转**：MIT-340"加载器行为差异"系**误诊**——加载器对扩展 reloc
块行为完全正常；当年崩因 = 覆盖不全（未登记站点 delta 未应用 → 错位
访问）。**ASLR 兼容技术可行**。

**实现方案（另立实现单）**：① 站点登记——import_protect/tls_hook 发
射绝对 VA 时同步记录站点 RVA 至 ctx 槽（比事后扫描精确：skip 桩值站
点、backfill 模式差异、未来新面均在发射点闭环）；② pe_writer 追加
reloc 块——.reloc slack 预算有限（tls 样本 436B≈208 站点、wvmpTest
仅 168B≈84 站点，**大镜像不足**），预算策略 = 将原 reloc 数据整体拷
入 .wvmp 预留区（8KB，RW 节 reloc 合法）后追加新块，dd[5] 重指（单
区间连续，预算永久充裕）；③ DYNAMIC_BASE 保留不清（pe_writer 清除
逻辑改配置化或删除）；④ x86 面 HIGHLOW 同构。

**风险与未决**：① ASLR 下 TLS 回调先于重定位？——否，reloc 处理在
loader 锁内先于 TLS 回调（PoC 中 adb/rdtsc 面即依赖此序，byte-exact
为证）；② 强签名/强制完整性镜像的 reloc 语义（FORCE_INTEGRITY 仍清
除，无关）；③ 大样本池 ASLR 全量回归为实现单验收主体。

## MIT-494（T26，2026-09-09）——ASLR 兼容实现：发射点登记 + reloc 目录 .wvmp 预留区扩展

**架构（MIT-493 方案落地）**：
① **发射点登记**（framework keys 新槽 kRelocSites = vector<u32>）——
stub_link（stub/data payload 成品处自产 buffer 扫描）、tls_hook（TLS 目录
4 VA 字段精确登记 + 回调数组 + 回调桩 blob 扫描）、import_protect
（skip 模式原 IAT 全槽）。生产方只扫自产 buffer：命中即真 VA。
② **pe_writer 消费**：原 reloc 块整体拷入 .wvmp 预留区（单连续区间，
dd[5] 重指；预算 = 8KB 预留 ≫ 典型 3KB reloc + 数百站点），追加登记
站点分页 DIR64/HIGHLOW 块；原覆盖站点去重（双重 delta 防线，单测断
言 native 站点恰现一次）。
③ **DllCharacteristics 条件化**：FORCE_INTEGRITY 恒清；DYNAMIC_BASE
仅在「native 声明 + [pe] aslr≠false + 扩展成功（含无新站点的原目录自
足分支）」时保留，否则清除（native 未 opt-in → 保守回退 M2-8 行为）。
④ **配置**：[pe] aslr（缺省 true；false = 关断维持旧行为）。

**开发实录三坑**：① plus 判定 `image[opt+1] == 0x20` 应为 `0x02`
（0x020B 高字节）——错值使扩展静默跳过（gate 无 Note 掩盖）；② 全镜
像扫描路线（初版）在 wvmpTest 登记出 2194 个 .rdata 假阳站点（结构化
数据 (rva, 0x01000040) 对恰好别名 VA 区间）——误登记 = loader 对非
VA 值加 delta = 静默损坏，本次运行侥幸全绿不可依赖；返工为发射点登
记后 wvmpTest 站点数 1087→28（纯 stub 面）。③ 单测夹具 .wvmpc 落点
须取 .wvmp 虚拟末端**向上**对齐（align(0x4100,0x1000)=0x5000，向下的
0x4000 触发连续性硬拒）。

**验证**：ctest 23/23（+6 用例：pe_writer 扩展三策略分支 + config 三
态）；wvmpTest 双跑（base/mutate，ASLR 路径全走）各 103/103；tls_e2e
4/4；multiseed 335/335（全部产物走 ASLR 路径）；**迁移真值对照**：撤
销 dd[5] 扩展 + 保留 DYNAMIC_BASE → base 面崩（127）/ mutate 面
0xC0000409，扩展产物 rc=0——delta≠0 下扩展为必要性证明。

## MIT-494 开发实录（T26 ASLR 实现分支挂起，2026-09-09）——三处实证发现与未决破缺

**实现现状**（分支 mit-494-t26-aslr-impl 挂起，未合入）：发射点登记
架构（kRelocSites：stub_link 已知 VA 集精确匹配 / tls_hook TLS 面 + 回
调 blob / import_protect skip 槽）+ pe_writer 消费生成扩展块 +
DllCharacteristics 条件化 + [pe] aslr 配置。wvmpTest/tls_e2e 全绿，
multiseed 290/335。

**实证发现**（对 ASLR 兼容实现单极具价值，勿重新推导）：
① **x86 blob 词内嵌首选基址 VA**：x86 翻译器无 rip-relative，IAT 槽
   引用等以完整 VA 烙进 VM 词流（实录：x86 looplea blob 内 22 处
   0x403000 = ib+IAT 槽 RVA）。ASLR 下全数错位 → x86 样本崩溃。
   修复方向 = x86 词流 RVA 化（对齐 x64 M2-8 模型，翻译器大改）或
   blob 词 VA 站点全量登记（假阳风险需评估）。
② **全镜像扫描假阳实锤**：wvmpTest 上泛扫描登记 2194 个 .rdata
   "站点"（结构化数据 (rva, 0x01000040) 对别名 VA 区间），误登记 =
   loader 对非 VA 值加 delta = 静默损坏风险。发射点/已知 VA 集精确
   匹配（wvmpTest 仅 28 站点）为唯一可接受登记形态。
③ **x64 forkface 单点之谜——T26a cdb 定位已破案（2026-09-09），原"补
   登记复活"结论作废为假绿**：野跳指令 = `jmp <stub>` 桩跳板
   `E9 rel32` @ .text 0x13DC（callreg 虚拟化入口），rel32 文件值
   0x00013FAF（→ 桩 0x15390 合法），运行时被毒化为 0xAB013FAF（第 4
   字节 0x00→0xAB）。**根因链**：native 原指令 `mov rax, 0x140001020`
   （绝对 imm64，DIR64 条目 @ 0x13DE）→ 虚拟化跳板（E9+rel32+CC 填充
   共 12B）覆写该 imm64 → 扩展 reloc 拷贝原样保留 0x13DE 孤儿条目 →
   loader 对跳板尾字节+CC 填充的 qword 加 delta（实测 delta
   0x7FF651AB0000 的第 3 字节 0xAB 恰落 0x13E0，算术逐字节吻合 cdb
   实证）→ rel32 毒变 → 执行流进 .text 缝隙野跳。**"0x4a4d 站点"
   真相**：0x4a4d 是文件偏移（= .rdata RVA 0x5C4D），其"裸 image_base
   qword"是 [3B 节间填充]+[IMAGE_LOAD_CONFIG_DIRECTORY64.Size=0x140
   LE 字节]+[TimeDateStamp 首字节] 的 8 字节假窗口——VA 扫描假阳，非
   真指针。补登记 0x5C4D 后 10/10 "复活"机制 = DIR64 对该假窗口加
   delta 腐化 LoadConfig.Size（0x140→~8MB）→ **Windows loader 判配置
   无效放弃重定位整像，按优先基址 0x140000000 加载（delta=0，cdb 实
   证 fe 全程 0x14000xxxx）** → 一切基址相关缺陷被 delta=0 掩盖 =
   ASLR 被腐化关掉的假绿，非兼容修复。0x5C4D 条目禁止进入 T26c。
   **真修复（T26c）**：pe_writer 生成扩展目录时，剪枝与 .text 覆写
   区（桩跳板 patch [resume_rva, resume_rva+patch_len)）相交的 native
   拷贝条目（孤儿条目 = 原指针已不存在于内存）；同族排查：IAT 槽/
   TLS 面/其它覆写点同规则套用。**测试铁律**：ASLR 判据必须断言
   运行时基址 ≠ 优先基址（delta≠0），否则 0x5C4D 类假绿无法区分。
④ **ASLR 测试方法论**：基址随机化使单次运行可能 delta=0 假绿——判据
   必须 = 每产物 ≥10 次重复运行统计 + 撤销扩展对照组（对照崩 = 证明
   delta≠0 且扩展必要）。

**multiseed 数据**：全镜像扫描 304/335（31 红 = forkface + 9 x86 样
本）；精确登记 290/335（45 红，under-registration 更差）。两形态均未
达 335 全绿，合并阻断正确。

**T26 v2 入场条件**（2026-09-09 更新：② 已完成，①③ 待做）：① x86
词流 RVA 化方案（独立大单）；② ~~forkface 0x4a4d 消费路径定位~~
**已完成 = T26a cdb 定位**（谜底见③，真根因 = 跳板覆写区孤儿 reloc
条目未剪枝，0x5C4D 复活 = LoadConfig 腐化 delta=0 假绿）；③ ASLR 重
复运行统计框架（multiseed 扩展 ×N 次判据）+ **delta≠0 断言**（本次
新增，防假绿）。全部实证已入本节与分支提交历史。

## MIT-494b/c/d（T26b/c/d，2026-09-09）——ASLR 统计框架 + 两层真修复 + 首个真 delta≠0 缺陷暴露

**T26b（已提交，验收 ACCEPT）**：scripts/multiseed_aslr.sh = ASLR 模式
multiseed。三道判据：① cdb 基址探针（运行时基址 ≠ 优先 ImageBase，
delta=0 一票 FAIL——0x5C4D 类假绿的机械化防线；DYNAMIC_BASE 清除 =
声明回退返回 3 不误伤）② ×REPEATS 重复 byte-exact（MIT-427 crash
guard 口径移植）③ REQUIRE_REAL。池/seeds 运行时提取自
multiseed_e2e.sh 零漂移。**本框架首个战果 = 立即抓出 T26d（下述）**。

**T26c 两层真修复**（forkface x64 单点全链）：
- 第一层（reloc 剪枝）：kPatchedRanges 槽（keys.hpp）+ stub_link 跳板
  覆写成功即登记 {begin_rva, len} + pe_writer 扩展拷贝剪枝相交孤儿条
  目。剪枝重组三铁律：幸存条目垫 **4 条目倍数**（块 8 字节对齐——
  loader 以 pos+=bsz 顺序遍历，4 字节垫 + 尾部补零会产生零洞假头，
  遍历提前终止）；type-0(ABSOLUTE) 哑条目补齐；只含 type-0 的块整体
  删除（功能性空块发射会骗 loader 重定位无活站点的目录）。单测 3 +
  stub_link 登记面 1。
- 第二层（blob VA 折条）：x64 `mov r64, imm64` 落在映像窗口
  [image_base, base+2^32) 时 → Mov(d, imm32(RVA)) + LeaRva(d,d)（RVA
  + ctx scratch 槽运行时真基址），零新 VmOp（LeaRva 复用，读先于写原
  位安全），asmgen 零 diff。**MIT-494a 第二层实证**：跳板修剪后
  forkface 仍野跳 rbx=rip=0x140001020——native `mov rax, imm64`（绝
  对函数指针）的值经 imm64 拆条原值烙进 blob，loader 无法重定位字节
  码。这是 x86 词流 VA 嵌入（MIT-494 实录①）的 x64 孪生类，本折条即
  其 x64 特化解；x86 全量 RVA 化仍归 T27。
- x86（PE32）自动回退：pe_writer 遇 PE32 直接清 DYNAMIC_BASE + Note
  （词流 RVA 化为 T27；delta=0 成声明行为）。
- 验证：ctest 23/23；forkface ONLY 池 ×10 = **10/10 PASS**（x64 探针
  delta≠0 + 真基址 ×10 byte-exact；x86 声明回退 NOTE + ×10）。

**T26d（两层根因，2026-09-09 定案——初版"真 delta≠0 缺陷"定性反转）**：
div_flags_readback x64 stdout PF 位逐次漂移。**根因分解**：
- **层 1（已修，translator）**：合成（非 guest 语义）flag-writing 指令
  污染 guest flags 视界——`mov [rbx+disp], rax` 降低为 Mov/Add(合成)/
  Store，合成 Add 的 flags_tail 把**指针低位奇偶**写进 [ctx+0x98]，后
  续 setcc 整排读到合成值（实测 PF 全排 111111/000000 随堆栈熵翻转）。
  修复 = Emitter::mark_last_dead 五类合成发射点（寻址拼装 Add/Sub/Shl、
  imm64 拆条 Shl/Or、x64 栈调整 Sub/Add、跳表表项物化、锚定 Add）+
  mark_dead_flag_writes 对预标记**写族**指令按透明（kNone）处理（⚠️
  仅写族——Jcc/Setcc/Cmovcc/ExitNative 的 cond 域是 4 位条件码，bit2 =
  条件数据非标记，首版透明化误伤 Jcc 读链被 FlagsLiveness 单测当场拦
  下）。修复后前 5 条输出行 flags 恒正确（合成污染清除，读到真 div 后
  test 前的值），仅第 6 输出行（idiv32_neg）PF 残留漂移 → 暴露层 2。
  验收补充：plain 形串指令尾随步进 Add 同族残留一并打标（movs/stos/
  lods/scas/cmps 五路径 7 处，scas/cmps 防步进覆写比较 flags）。
- **层 2（已修，夹具重设计）**：MIT-404 的 "div/idiv flags undefined
  但同 CPU 同输入逐位一致" 前提在高熵堆栈随机化下不成立——undefined
  值随微架构状态漂移，VM 捕获值永远无法可靠对拍 native 捕获值。修复
  = 夹具（div_flags_readback_sample_asm.asm 三函数）除法后插
  `test rax/eax, rax/eax` 探测**有定义** flags（ZF/SF/PF 由商决定，
  CF=OF=0），槽位路由 + flags 管线验证价值不变，双侧确定。
- **验证**：ctest 23/23（+3 合成透明化用例）；div_flags 重打包 ×20 =
  20/20；基线 multiseed **335/335**；tls_e2e 4/4；全池 multiseed_aslr
  门见 STATUS MIT-494d 节。
- **口径更正（重要）**：本缺陷与 delta 数值**无关**——高熵栈随机化挂
  DYNAMIC_BASE 位，低熵栈下 pointer parity 恒定故历史绿；MIT-474
  liveness 算法本身无罪（python 逐指令复刻与 C++ 行为一致），它忠实建
  模了被合成指令污染的降低层。

**方法论新增**：① 产物字节→pinned 基址→delta 命运的混淆链：任何
"A 构建稳/B 构建飘"的对比必须先 probe 双方基址，否则二分结论无效；
② reloc 目录连续性 = loader pos+=bsz 遍历的硬约束，重排块必须 8 字
节块对齐 + 零洞；③ "335/335 走 ASLR 路径"类历史口径在 delta≠0 断言
缺失时一律视为 delta=0 测量，不可作为 ASLR 兼容证据引用。

## MIT-494e（T27 · x86 词流 RVA 化 + x86 真 ASLR 启用，2026-09-09）

**背景**：T26c 对 x86 采取声明回退（清 DYNAMIC_BASE）——x86 翻译器无
rip-relative，绝对寻址与 mov r32,imm32 把映像窗口 VA 原值烙进词流
（MIT-494 实录①：looplea blob 22 处 0x403000）。T27 收口后 x86 与
x64 同享真 ASLR。

**T27a（词流 RVA 化）**：
- emit_address 绝对形（base==Flags && disp≥0 ∈ [ib, ib+extent)）→
  `Mov acc, RVA + LeaRva acc,acc`（替代 Mov 0 + Add VA），index 链照
  旧叠加；窗口外绝对地址（跨模块 VA 等）维持原语义（披露）。
- translate_mov 统一窗口折叠（双 arch）：imm ∈ [ib, ib+extent) →
  Mov(RVA)+LeaRva；x86 S32 面由此启用，x64 窗口从 T26c 的 2^32 宽收
  紧为 SizeOfImage（降低非指针常量误转面；4 参版 extent=0 回退 2^32
  宽保单测兼容）。
- 布线：translate_function 五参重载（image_extent = PE SizeOfImage，
  backend 直读 optional header +56）。
- **验证**：looplea 词流裸 VA **22 → 0**（t27_va_scan.py 解包扫描）。

**T27b（撤 x86 回退）**：pe_writer 的 `!plus` 声明回退分支删除，
HIGHLOW 扩展与 x64 同管道（want_type=3 已布线；stub imm32 站点面
is_x86?4:8 已布线）。单测 EmitRelocX86ExtendsHighLow（PE32 夹具
dd@opt+96、类型 3 条目、DYNAMIC_BASE 保留）。

**T27c（x86 TLS 回归 + 修复）**：撤回退后 tls_e2e x86 回填腿 FAIL
（hit 全局读到 0）——**tls_hook 回调桩 rdtsc 双 dword 槽漏登记
[scratch+4]（edx 半字发射点）**，delta≠0 下 edx 写落优先基址野地址
（高熵栈时代不可达路径首次真执行）。修复 = abs_vas 补
scratch_va+4（仅 x86，x64 用 r11 无槽写）。**验证**：tls_e2e 4/4；
基线 multiseed 335/335；全池 multiseed_aslr REPEATS=10 全绿
（x86 85 产物升级为真基址 delta≠0）。

**方法论**：① 32 位产物调试 = WOW64（x64 cdb 需 .effmach x86，写断
点走 32 位上下文）；② 站点登记核对必须用**位置口径**（登记值 =
字段所在 RVA），用"目标值 ∈ 站点集"核对会双重视为命中/未命中而误
判；③ 撤声明回退 = 首次真执行该架构全部初始化路径——回归面（如
tls 回调双 dword 槽）在低熵时代不可见，E2E 必须覆盖全 pass 组合。

## MIT-494f（T29 · undefined-flags 夹具依赖普查，2026-09-09）——零新增发现
- 普查面：div_flags 勘误（MIT-494d）同款依赖 = "探测 SDM undefined
  flags 位并逐位对拍 native"的夹具。结论：**唯一命中 = div_flags
  （已修）**。
- 逐族核查：① imul——无 MASM flags 探针夹具（imul_sample 为 C++ 面，
  CF/OF 本身 defined；build_imul 的 D4.1 处置是 handler 内部设计非夹
  具依赖）；② x87——永久 gate 双侧原生，VM 不执行不产 flags；③
  flags_rol——rol/ror 的 ZF/SF/PF 语义 = unaffected（保留读合法）；
  ④ sse bwcmp——ucomis 的 ZF/PF/CF defined；⑤ setcc/jcc 主面——
  cmp/add/test 后的读全部 defined。
- T28 同批：X86* 折条三单测切换真 x86 夹具 fn86_of（arch=X86，S32
  tag）——T27 验收建议落地。Park "MIT-476 多 .wvmp continue" 条目维
  持挂起（W^X 拆节后语义待重估，非当前阻塞）。

## MIT-494g（T30 · crypt×ASLR 全栈组合门首跑 + 首缺陷立案，2026-09-10）
- 组合门首跑（multiseed_crypt 8-pass：+mutate+crypt，真 ASLR 姿态）：
  **19/20**。红面 = wvmp_string_ops_sample × seed 99999，packed rc=2，
  rep scasb 探针 idx=32/rem=0（全扫未命中）vs native idx=17/rem=14。
- **判别刀**：① 6-pass ASLR（无 mutate/crypt）同 seed = 5/5 绿；②
  8-pass delta=0（aslr=false）同 seed = 红复现 → **与 ASLR/delta 无
  关**，是 crypt/mutate 栈 × roll(seed99999) 的既有缺陷（rep scasb
  微程序 × 变异布局交互；该套件在当前池构成下未跑过，非本会话回
  归）。
- 立案 **T30-d**：rep 串微程序 × mutate×crypt × roll 交互修复。复现
  资产 /tmp/t30/（so99999.exe / so0.exe + toml）。组合门维持红至修
  复；多iseed_aslr（6-pass）335/335 不受影响。
