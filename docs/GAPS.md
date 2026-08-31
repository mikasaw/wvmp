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
  与 G1d 通路叠加）；pmovmskb（66 0F D7）/ pcmpeq/pcmpgt 系（SSE 整数
  比较族）/ punpckldq/punpcklqdq（66 0F 62/6C 交织语义，D4 裁决非纯拷贝
  不入拷贝通路）；AVX/VEX 残余面（档A 已收口
  38 id V-pair，精确残余见下节 G6a——VEX-GP BMI/ymm/FMA/加密/EVEX
  保持 gate）。
  （string movsd 双形态已由 MIT-415 收口，见 G3 节；
  x87 已拆出独立小节，见下节 "x87 (永久 gate, R3 裁决)"——不是简单"不支持
  兜底"，而是有独立频率数据与行为承诺的裁决面。）
- 注意与重定位/ASLR 的配合：RVA + image_base 在运行时还原，不依赖静态 VA。

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
砍面）+ G8-BMI + 档B ymm + EVEX 全谱——照旧 C1 gate。

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
- **跳表 128→256 扩容** = G7/x87 未来前置（kTableEntries=128；kVmOpMax=95
  即 96 项已用（0 哨兵 + 1..95），MIT-425/G1b 后实测 vm_op.hpp——mul 族
  4 op + Andnps 顶格预算 95，余量 32；x87 全族 ~80 新 VmOp 会把 128 撑爆，
  拆单蓝图预埋，见 triage §6 #2）；
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
