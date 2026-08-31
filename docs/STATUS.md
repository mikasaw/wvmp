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

| **MIT-415 G3 串指令族** | ✅ | （本批次） | rep/repnz {movs,stos,scas,cmps,lods} 前缀闸放行 + 翻译器微程序展开（零新 VmOp）；multiseed 34×5=170/170、wvmpTest 14/14、双跑 103/103；DF=0 假定 note 披露（D1） |

| **MIT-418 G5r-R3 x87 永久 gate** | ✅ | （本批次） | x87 全族（D8-DF）文档化不保护：gate→原生执行 byte-identical；回归样本 `wvmp_x87_gate_sample`（五族 fld/fadd/fstp/fcomip/fsin + GP helper 真区）；multiseed 35×5=175/175、ctest 16/16；R1 蓝图/R2 捆绑/跳表扩容路线留档 GAPS x87 节 |

| **MIT-419 G4 lock 前缀原子族** | ✅ | （本批次） | lock {add,adc,sub,sbb,and,or,xor}×mem-dst + cmpxchg/xchg/xadd + bts/btr/btc 白名单放行 strip-and-execute（ALU 族零新 VmOp 折条；Xadd/Bts/Btr/Btc 单 VmOp native lock 直执行原子性保真）；D1 多线程并发原子性边界显式登记 GAPS G4 节；回归样本 `wvmp_atomic_ops_sample`（C++ Interlocked* 真产物 + MASM 全谱 8 函数 + 11 lock-strip note + 2 负例 gate）；multiseed 37×5=185/185、ctest 16/16、双跑 byte-exact |

| **MIT-423 G4b lock inc/dec 原子补齐** | ✅ | （本批次） | lock inc/dec ×mem-dst (S32/S64) 白名单放行，本体折条（D1: 零新 VmOp，Load→Inc/Dec→Store；CF 保真由 build_incdec 既有语义逐位对齐 SDM "inc/dec 不写 CF"，样本 CF 探针实证）；#33 实测推翻先验：MSVC v145 对 _Interlocked* 产 lock xadd ±1（真产物走 419 Xadd 原子通路），裸 lock inc/dec 无编译器产物；标记域 12..13 + 全域对账（B.1）；样本 `wvmp_atomic_incdec_sample`（MASM 双宽 + rip + 循环 + CF 探针 8 函数真虚拟化 + lock not D2-gate 可调用负例）；multiseed 38×5=**190/190**（REQUIRE_REAL 同）、ctest 16/16、wvmpTest 14/14 + 双跑 103/103 diff 0 |

| **MIT-425 G1b SSE 收官包** | ✅ | （本批次） | SSE mul 族 mulss/mulsd/mulps/mulpd（0F 59 系 reg-reg + mem 源含 rip；IR 层 (Op::Mul, src2=imm 14..17) 载体标记折叠 4 新 VmOp——ir::Op 冻结下 (Op,Size) 被 GP mul 占用装不下 4 形态，D2 授权选型披露）+ andnps/andnpd（dst=~dst&src，VM 无 128-bit NOT 原语双折不可行 → 新 VmOp::Andnps；411 负例 §B.4 正例翻转）+ SSE2 整数档① pand/por/pxor/pandn（66 0F DB/EB/EF/DF 逐位同语义零新 VmOp 折叠 ps 位运算，411 先例整数扩展）；#33 实测修正 424 先验：cl v145 对 _mm_and_si128/_mm_andnot_si128 直产 andps/andnps（ps/p 互认），pand 真 66 字节 MASM 直写；R2 档② movd/movq 桥 + paddq/psubq 跳表预算顶格砍面留 G1c（G6a movd 依赖需知会）；kVmOpMax 90→95 顶格（跳表余量 32）；样本 `wvmp_sse_fin_sample` + `wvmp_sse_fin_xmm_readback_sample`（13 探针 ctx.xmm 8 槽全量读回）；multiseed 40×5=**200/200**（REQUIRE_REAL 同）、ctest 16/16、双跑 diff 0 |

| **MIT-426 G6a VEX.128 档A** | ✅ | （本批次） | 38 id V-pair（VADDSS..VPANDN，既有 SSE 白名单逐行镜像）三地址折叠进既有 SSE 通路：d==s1 直走 / packed d==s2 可交换 / d 独立前置 Op::Movaps(16B)+2-op——**零新 VmOp/零新 handler**（asmgen 逐字节不动，dump 门 SSE_HANDLERS 集合不变，kVmOpMax=95 不动）；D2 gate 面（标量 d==s2 高位语义不相容 / 非交换 d==s2 / vmovss/sd 插入 d≠s1 / xmm8..15 / ymm 位宽闸按操作数 32B 拒）+ 范围外显式声明（**VEX-GP BMI 不在 SIMD 档A 内** / FMA 双舍入 / 档B ymm / vpaddd 系 / EVEX，见 GAPS G6a 节）；x86_translate.cpp:1929 邻域 "vpxor 57/56/54" 名实错配注释修正；样本 `wvmp_vex128_sample`（正例 12 区真虚拟化 + 负例 8 族函数级 gate 可调用）+ `wvmp_vex128_xmm_readback_sample`（9 探针 ctx.xmm 8 槽读回）；/arch:AVX cl 真产物 2 函数 vmulsd/vaddsd/vdivsd 全折叠验证；multiseed 42×5=**210/210**（REQUIRE_REAL 同）、ctest 16/16（lifter 135 用例）、wvmpTest 14/14 + 双跑 103/103 diff 0 |

| **MIT-427 G1c movd/movq 桥** | ✅ | （本批次） | SSE2 movd/movq GP↔xmm 桥入面：REG 四形（66 0F 6E/7E + REX.W）折叠 2 新 VmOp（XmmFromGp/GpFromXmm，高位清零/截取零扩展语义 native 直产）+ mem 形式复用 408 通路 + all-xmm 双编码（F3 0F 7E 与 66 0F D6 reg-reg #33 实测逐位同语义：高 64 均清零，"保持"先验被 d6_probe 推翻）+ VEX vmovd/vmovq 镜像随本体（426 §F.4 ④ 清偿，ymm 位宽闸/xmm8..15 闸继承）；MMX mm 操作数 D2 永久 gate（NP 0F 6F 同 id 混入 MOVQ，mm 判据唯一闸）；paddq/psubq B.2 频率砍面（6 二进制 854k 指令 psubq=0、paddq=16 仅 shell32 且与砍面 movdqa 共生；#33 双纠正：425 "5C"=SUBPD 误、派单 "paddq=66 0F FC"=PADDB 误，真值 66 0F D4/66 0F FB）；IR 载体 (Op::Movss, src2=imm 19..21) 域 14..18 连续后延；kVmOpMax 95→97（余量 30）；harness 段载 B.5 崩溃盲区修（426 §4 登记：双崩+双空 stdout 假 PASS → abnormal rc 显式 FAIL，设计性崩溃对拍白名单路径保留；MSYS 实测 crash rc=139 映射值非裸码，派单 "≥0x80000000" 口径按实测修正）；样本 wvmp_sse_bridge_sample（10 正例真虚拟化 + 7 负例函数级 gate 含 C++ movdqa/movdqu 真产物）+ wvmp_sse_bridge_xmm_readback_sample（9 探针 8 槽读回 + rax 零扩展区内 Store 观察）；multiseed 44×5=**220/220**（REQUIRE_REAL 同）、ctest 16/16（lifter 140 用例）、双门（dump/static）PASS、wvmpTest 14/14 面零回踩 |
| M3 插件池 | ⏳ 未开始 | — | T1~T9：mutate / 两档 crypt / anti_debug / integrity_crc / import_protect 等 |

| **MIT-428 G1d movdqa/movdqu 对齐传送** | ✅ | （本批次） | SSE2 对齐传送 movdqa/movdqu（66/F3 0F 6F/7F，id 468/469）零新 VmOp 折叠入面——translate_sse_mov 直复用（(Movaps,S64)/(Movups,S64) 载体，REG 三形 + mem 408 通路）；§A.4 方向 probe 实测：6F/7F 双编码 reg-reg（7F rm=dst 反写合法形）capstone 均归一化 dst-first，零调度层修正（先验"7F 需手动换位"被推翻）；VEX vmovdqa/vmovdqu（1028/1033）经 vex_desc_of Fam::Mov 镜像（426 D4 先例），ymm 位宽闸/xmm8..15 闸继承，EVEX VMOVDQA32/64（1413-1419）显式不入面；kVmOpMax=97 不动 + handler 集合恒等（零新 VmOp 机器证明）；D2 对齐披露：movdqa #GP 不模拟（375 :1188 先例），build_movaps/build_movups handler 无对齐分叉实测确认；427 桥样本负例翻转对账：cpp_movdqu_neg 全翻真虚拟化（stub 10→11）、cpp_movdqa_neg 精确演进（8→3 skips，punpck 族 D4 保留 gate）、5 gate 负例原样；样本 wvmp_aligned_mov_sample（正例 12 区 + intrinsic 翻转 3 函数 + 负例 EVEX vmovdqa32/vpaddd ymm/punpcklqdq/pmovmskb 可调用）+ wvmp_aligned_mov_xmm_readback_sample（9 探针 8 槽读回）；multiseed 46×5=**230/230**（REQUIRE_REAL 同）、ctest 16/16（lifter 142 用例）、wvmpTest 14/14 + 双跑 103/103 diff 0、双门 PASS |



| **MIT-433 P1 rol/ror flags partial-preserve** | ✅ | （本批次） | G9r triage §6.1 现网正确性缺口收口（MIT-432 项目主独立复现：native ror 后 setz=0、packed=1）：SDM Vol.2 ROL/ROR 只写 CF/OF、ZF/SF/PF unaffected，而 build_rol/build_ror(+rolcl/rorcl) 复用 build_shift 全量装配把 zero5 宿主污染（xor 致 ZF=1/SF=0/PF=1）覆写 guest flags。修复 = 新 flags_tail_partial partial-preserve 装配（Inc/Dec cf_preset 先例三位推广）：CF/OF 照旧 setcc5 捕获，ZF/SF/PF 从 ctx+0x98 旧值 and 0x19 原位保留；kVmOpMax=97 不动、VmOp 零增、非 rot handler 字节码零扰动（asmgen dump 逐 case 对账 91/95 体逐字节相同，差异恰 4 rot 尾部；非 rot 样本 packed 差异 = 解释器镜像 -48B @seed12345 纯位置效应）；asmgen.cpp ROL/ROR 段 SDM 误读注释（旧文 SF/ZF/PF 按结果）按实义重写；样本 wvmp_flags_rol_sample（p432 复现样本转正，自含 MASM marker 桩，ror/rol ZF + rol SF + ror PF 消费 + shl 对照，区内 Store 落盘观察；旧 CLI 反证 stdout 分叉必 FAIL → 分支 byte-exact PASS，5 stub 真虚拟化）；单测 RotFlagsPartialPreserve 12 组（rol/ror×{ZF,SF,PF} 保留 + shl/shr/sar 对照 + count=0 全不动 + count>1 + RolCl/RorCl 同面）× 5 seed；multiseed 47×5=**235/235**（REQUIRE_REAL 同）、ctest 16/16、wvmpTest 14/14 + jump-table@0xDD84 + ExitNative 17 + note 面逐字节原样 + 双跑 103/103、静态扫描/dump 门 PASS；G8a flagless（rorx/shlx/sarx/shrx）接入点接口文本已留 flags_tail_partial（本单不实现） |

| **MIT-434 G8a BMI 折条款目** | ✅ | （本批次） | andn/bzhi 零新 VmOp 折条 + rorx/shlx/sarx/shrx flagless 变体（G9r §2.5 蓝图，P1 机制首客户，main cdc218d 基线）：**零新 VmOp（kVmOpMax=97 不动）、零新 handler（asmgen.cpp 逐字节零 diff）、零冻结契约触碰**。D1 选型 = (i) 变体 translator 层 GetFlags/SetFlags 包裹（G3 微程序先例；(i) 原案触碰 build_shift 触 P1 红线不可行、(ii) +4 VmOp 对照后弃——零 enum/零 handler/零 asmgen 风险占优，字节码 +2 word/指令披露）；载体 = src2.kind≠None 骑"从不写 src2 的 op"（shift+Imm(22)=flagless / And+Reg=andn d==s2 / Sub+Reg=bzhi；`ror eax,24` 不误拦——count 在 src、判据是 kind 非值域，陷阱②绕开；全域对账 419 B.1 同款 + 单测样本双钉）；probe 修正三事实（Zen5+ml64+capstone 双验）：**bzhi 边界 idx≥N = 原值不变+CF=1（推翻 432 §2.1 "结果 0/CF=0" 预判，折条 mask-clamp+CF 补丁五位全对齐）**、idx=0→结果 0、andn 的 r/m 在第三操作数（AND 项）NOT 项 reg-only / bzhi·rorx·shlx 族 r/m=value 在第二——SDM 记法直读会反，以 ml64 逐形双验为准；andn flags = Op::And 尾行全集（probe 0x286）；bzhi 微程序 16-17 op（低频面膨胀披露）；andn d==s1/d 独立纯 IR 折叠零 translator 成本；负例 mulx/pdep/pext/blsr/blsi/blsmsk/bextr 照旧 C1 gate（G8b 后置）；426 时代 VexRorxGate 负例翻转正例（425 §B.4 先例）；样本 wvmp_bmi_sample（16 正例区 = 16 stub 真虚拟化 + flags 消费探针区内 Store 落盘 + 1 负例区 7 指令 gate note 零逃逸）+ 三层单测（lifter 148 / translator 60 / runtime 语义电池期望值 = probe 逐位 × 5 seed）；multiseed 48×5=**240/240**（REQUIRE_REAL 同）、ctest 16/16、dump 门 handler 集合恒等 + static 门 PASS |

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
- flags 部分写入面：rot 族已修（MIT-433 flags_tail_partial，SDM: ROL/ROR 只写 CF/OF）；G8a flagless 族（rorx/shlx/sarx/shrx 全不写 flags）已由 MIT-434 以 translator 层 GetFlags/SetFlags 包裹接入（零新 VmOp、asmgen 零改动）；bzhi 边界语义（idx≥N = 原值不变+CF=1，probe 修正 432 预判）已全对齐（GAPS G8a 节）。
- BMI 残余：G8a done（MIT-434，andn/bzhi 零新 VmOp 折条 + rorx/shlx/
  sarx/shrx flagless 变体）；**G8b 挂账**（mulx/pdep/pext native 直执行 +
  CPUID gate 基建，mulx CF 厂商分叉 Zen5 实测不写 vs SDM 择一披露——
  432 §2.1 判定②）；blsr/blsi/blsmsk/bextr 语料 0 永久 gate（432 §6.4）。

- marker_scan：x86 锚点未支持（GAPS C5；32 位输入已在 pe_loader 显式硬拒绝，

  MIT-414）；O2 尾调用编成 E9 jmp（不产生 E8）不覆盖；函数名解析 TODO(P7-names)。

- x86 目标整体对齐在 P1 backlog（G7x-1..8）；当前支持目标 = **x64 PE**（32 位

  输入显式拒绝，MIT-414）；**浮点 = x87 全族（D8-DF）保持原生（永久 gate，

  MIT-418 R3 裁决，文档化不保护）**——含 x87 的标记函数整函数不虚拟化，

  行为 byte-identical；SSE 浮点（add/sub/div/mov/位运算/比较族）已真虚拟化

  （MIT-371~376/408/411）。



## 测试补强方向（按优先级）



CI 实跑 E2E + Release 构建矩阵 → pe_loader 畸形输入 fuzz →

保护后 PE 在全新环境运行验证 → 覆盖率报告。

## 指令虚拟化阶段（M2.5-G）收口（2026-08-31）

> 口径注：本节为指令虚拟化阶段的唯一现行权威口径。本文中部「正确性缺口 /
> M3 待办」等节为 M2 时代存档口径（append-only 审计史原则，不回改），现行
> 缺口状态以 `docs/GAPS.md`（含指令族支持矩阵）与本节为准；仓根
> `WVmp_HANDOVER_2026-08-28.md` 为 2026-08-28 历史交接件，同样不回改。

**阶段定义（项目主 D2 拍板）**：MSVC x64 目标 · 编译器自然产物全覆盖 +
gate 边界文档化——不承诺“全部 x86-64 指令”（那是 ymm/EVEX/x87 的伪承诺）。

**完成定义三要素**：
1. **编译器自然产物全形态入面实测**：G 线 13 张能力单全收口——G1(411)、
   G2(413)、G3(415)、G4(419/423)、G5r(416/417/418)、G6a(426)、
   G7r/G7p2(412/414)、G1b(425)、G1c(427)、G1d(428)、G9r(432)、P1(433)、
   G8a(434)；覆盖 /Od+/O2 双档编译器直出形态（424/432 实测口径）。
2. **gate 残余全部数据裁决 + 零逃逸**：不支持面逐族带频率/语料数据与裁定
   出处（GAPS「指令族支持矩阵」；尾族/G8b 定稿引
   `.multica/mit-G9r-triage.md` §1/§2/§6.4）；全谱 gate 实证
   byte-identical 零逃逸（424 §3 / 432 §2.4 E2E 证据链）。
3. **权威基线 + 条款史**：main `df3c2f1` 基线 = build 0 错 0 警 / ctest
   16/16（基线含 regvm_backend_tests）/ multiseed 48 样本 × 5 = **240/240**
   （REQUIRE_REAL=1）/ wvmpTest 14/14；kVmOpMax=97（跳表余量 30）；硬条款
   （命名分支 / main 未动 / tracked 零脏 / 切回 main / ff-safe / ≥30 分钟 /
   时间对账）连续满分史九连（至 MIT-434，main `df3c2f1`），本收口单
   （MIT-GZ，分支 `mit-gz-phase-close`）按同条款交付，合入即十连收官。

**两挂账（明确不在本阶段内）**：
1. **x86 (PE32) 目标支持** → 独立里程碑「**多目标平台**」（项目主
   2026-08-31 拍板，计划后续另立；GAPS C5 节仅加指针不改写）。
2. **档B ymm / x87 L0 / 跳表 128→256 扩容** → 观察清单挂起，触发条件
   （432 §3.4 阈值文本转录）：
   - 客户产物抽样出现 BMI/尾族（pmovmskb/pcmpeq/punpck）标记区域命中 →
     按族提单（G8a 模式小批开；lqdq/hqdq 客户态命中 → 随尾族单开）；
   - x87 L0 或 ymm 立项 → 触发跳表扩容前置 commit（任何使 kVmOpMax+1 ≥ 128
     的 op 批次，其实施单必须内置扩容前置 commit：先行合入、独立可回滚、
     不单独立波。x87 L0 ~80 op = 唯一必然触发者；ymm 档B 20–30 op = 临界
     触发者；G8b +3 → ≤102 不触发）；
   - xmm8-15 / kCtxSize（0x1C8）冻结面议题 → 归入档B（ymm）包随立项处理。
   观察清单挂起期间扩容单无限期挂起（G8a flagless/折条路线已证不触发）。

**M3（MIT-410 插件池：crypt / mutate / anti_debug / integrity_crc /
import_protect）恢复为主推线。**

