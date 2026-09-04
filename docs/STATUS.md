# WVmp 开发状态快照



> 更新时间：2026-09-05（MIT-456 push-mem：**x86 `push [mem]` 开面——X7 新数据行第一大非 x87 shape gate 翻正**（无派单，项目主授权直接开发，验收由独立子智能体执行）：translator 单点 Mem 分支（emit_address 地址槽 + Load 值槽 + 单 op Push/Reg，handler 既有 Reg 分支 asmgen.cpp **逐字节零 diff**）；native 序 = 地址/读值先于减 esp（`push [esp+4]` IAT 栈窗形语义锚）；x64 维持 skip（D2，无 push_mem 数据行）；栈深 walk 零改动即覆盖（IR 级 Push 净深 + 负位移 reach 对 dst=Mem 既有）；样本池 16→**17**（pushmem：FF 35 abs / FF 71 04 IAT 形 / FF 74 24 04 栈窗形 / call-arg push [mem] 对）+ multiseed 330→**335**（x64 250 + x86 85）；x86 电池 44→**45**（PushMemFromMemory 真执行；⚠️ 沉淀电池槽位纪律：VM 槽 0..7 = 客机 GPR 槽 1:1，槽 4 = RSP 槽，数据槽误用 = Load 值写进 esp 槽下次 Push 即以值为地址崩）；wvmpTest 双 arch 双跑 diff-0 维持（x86 靶标无 push [mem] 位点，12/14=85.7% 不变，残面 2 均永久）；x64 dump `ffd47289…` 恒等复验（x64 零扰动机器证明）；x86 客户态形级覆盖 95.15% → push_mem 1.845% 面出 gate 入 direct（重扫重估 ≈97.0%））



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

| **多目标平台 X1a (MIT-437)：marker_scan x86 双段 magic 锚点 + SDK x86 构建形态** | ✅ | mit-x1a-scan-anchors | scan_core 双段识别（cl v19.51.36256 x86 实测：/O1 /O2 = C7×2 lo→hi 紧邻、/Od = B8 hi→C7 lo 间隔 3B，两方向同窗 kX86MaxHalfGap=8，单一来源派生自 8B 模式）+ marker_scan_pass 按 PeImage.machine 分叉（x64 路径死代码级隔离）+ SDK x86 产物位 wvmp_sdk_x86.lib（构建即形态守卫：dumpbin 立即数断言）+ ml.exe 手编真产物 E2E fixture（双形态桩对 + nop 哨兵区域边界逐字节钉 + fr.arch=X86 落位；桩前 >64B nop 垫实弹防御 412 §8 #4 CRT `call main` 幻影 begin 误归属）；ctest 16/16（marker_scan 套件 28 用例，x86 新增 10）、multiseed 240/240 零回踩、x86 全管道 rc=2 硬拒原样无产物落盘 |
| **多目标平台 X1b (MIT-438)：ret imm16 清栈返回（x64 现网同类地雷兼修）+ SEH/FS gate 文档 + CLI arch 字段** | ✅ | mit-x1b-ret-imm16 | D2 选型 (i) 零新 VmOp（kVmOpMax=97 不动）：translator aux 载 imm（低 16 位掩码，imm=0 ≡ ret）+ runtime build_ret 清栈返回——出口不走 HALT 通道（ExitNative 先例的新形态：终态物理 rsp := guest 清栈后 rsp、[v4'-8] 终态槽、终态零活寄存器依赖）；433 盲区教训第二例收口（区域内 ret 形态样本集为零 → 翻译成功零告警 + 运行 Halt 静默错）；样本 wvmp_retimm_sample 3 区 x64 ret N 直写（10h / C3 / 90h，良构清栈量 ≡0 mod 16 对账披露）+ caller 平衡探针/返回值断言 + 2 轮调用链（每轮复分配参数槽陷阱实测）；旧 CLI 零告警 3 stub → packed 崩 rc=139（3/3 确定性）反证 → 修复后 byte-exact；三层单测（translator 4 矩阵 / lifter 双 arch lift 钉含 66 C2 前缀形 / runtime 电池 stub 同构 driver + guest continuation 4 imm 档×5 断言）；B.4 SEH/FS gate 实测钉（capstone 段覆盖=prefix[1]+mem.segment 字段、不占 base——SehFsSegmentOverrideGate 逐字段）+ GAPS「x86 战役已知 gate 清单」首块（G1 段覆盖行）+ callgate callee 自装 SEH 无碍文本；B.5 CLI arch 字段（auto/x64/x86）+ pe_loader 校验挂点（u8 槽 + 穷举 switch 映射防漂移）CLI 四象限 rc 亲验（x64decl+x64 rc=0 / x86decl 两侧 rc=2 显式拒 / auto+x86 rc=2 C5 不回退）；multiseed 49×5=**245/245**（REQUIRE_REAL 同）、ctest 16/16；冻结契约零触碰、X1a 面（marker_scan/sdk）零 diff |
| **多目标平台 X2a (MIT-442)：形级 fork 面收口——leave/plain 串形/cld/S16·p66/cwde·cbw 六形态折叠 + call [mem] D4 停手 + x64 全链实证（asmgen XL 前置单）** | ✅ | mit-x2a-fork-fold | X0 §1.4 fork 面六块：leave（0.37%）= [Mov rsp←rbp; Pop rbp] 两 IR 折条（extra 通道）+ plain 串形（movsd/lodsd/stosd/scasd/cmpsd S8/S32/S64）= G3 微程序"循环一次"（载体域 23..27，无 flags 包裹/scas·cmps 直落）+ cld = Op::Nop 放行（D5，对齐 415 DF 判；std gate）+ S16/p66 全链实测收（GP 面 S16 语义电池 + 别名写回保高 48 位；S16 push/pop 栈推进 2B gate 修旧静默错形；S16 串形维持砍面）+ cwde 两 IR 折条（build_movsx qword 写回高位污染 → mov eax,eax 零扩展 idiom 补偿）+ cbw translator 载体微程序（Op::Movsx src2=Imm(28)，8 VmOp flags 包裹）；**call [mem]/call reg D4 停手归 X3**（#33 实测推翻派单「Load+Call(reg) 零新 VmOp 高置信」预判：CallGate 协议仅吃 aux RVA 无 reg-target 通路，asmgen.cpp step1 直读，lifter 开口 + translator X3 披露 note + 样本负例区2/2b 钉 gate）；B.4 前缀四位判据（prefix[0]=rep/lock、[1]=段 SEH 闸、[2]=66、[3]=67 闸新增）互不误伤 probe 单测钉死；B.2 412 时代五处 S64 硬编码点复核 = 全部常量误名（VM 槽宽），真 arch 分叉点 = 栈宽（push/pop/leave 按 IR.size 派生，x64 逐字节不变）；**#33 实测发现：区内 push 写穿 stub callee-saved 保存区 [ns-8..ns-0x40]**（438 登记面 E2E 实证 → 规则化 guest 栈写恒 ≥ ns，样本区1 prologue 侧放区域外）；样本 wvmp_forkface_sample 6 区（leave 链 bal=0/串形+cld/S16+cwde·cbw 真虚拟化 3 stub + call [mem] IAT 形 FF 15/call reg/std/67 禁调用负例 gate byte-exact）+ MASM 手编双验 dumpbin 实字节（C9/A5/AD/FC/66 B8/98/66 98/FF 15/67 8B 03）；B.6 双 arch 矩阵 ≥20 例（lifter 7 新 TEST + translator 8 新 TEST + runtime 3 新 TEST）；B.7 multiseed x86 池架子（空池不跑，X5 填池）；kVmOpMax=97 不动、asmgen.cpp 零 diff（机器证明）、冻结契约零触碰、437 扫描面/sdk 零 diff；multiseed 50×5=**250/250**（REQUIRE_REAL 同）、ctest 16/16、wvmpTest stubs=14 + jump-table@0xDD84 + ExitNative 17 + 双跑 103/103 diff 0、dump 门/static 门 PASS |
| **多目标平台 X3c (MIT-445)：asmgen x86 协议面收口——CallGate reg-target 双 arch 同收（442 D4 挂账翻案）+ ExitNative 4B 退出槽 + Ret x86 4B 清栈返回 + x87 D1 备忘/shld 评估随报** | ✅ | mit-x3c-protocol | **B.1**：translator 双 skip 解除 + CallGate a_kind=Reg 判别形（零新 VmOp, 字节级布局入 GAPS X3c 节）+ mem 形折条 Load/LoadRva(S64)+CallGate(reg)；x64 全链实证 forkface 区2/2b 翻案（stub 3→5、gate note 全消、stdout byte-exact：bal=0/callmem=997/callreg=998 恒同）；⚠️ handler 目标分派须在参数快照（rax 搬运）之前——顺序倒置被 E2E 当场炸出（cdb 崩点 = 快照残渣索引）；x86 build_callgate_x86（窗口锚 host_rsp 自洽、cdecl 0-arg 参数窗留 X4）+ 电池 3 用例真调用。**B.2**：x86 ExitNative 4B 槽 [ns−0x258] + epilogue 对齐 + 条件/无条件双路电池 2 用例；槽深 kX86ExitSlotDepth=0x258 asmgen 单一来源（runtime.hpp 冻结零触碰, X4 stub 读侧锚）。**B.3**：x86 Ret 4B 清栈（dword 低半字算术 = 444 裁决表）+ [v4'-4] 死槽 + 出口坐标 push 暂存（⚠️ push 须在 t0−=4 之前——先减后 push 实证 jmp 落零页 eip=0）+ naked landing/longjmp 电池 2 用例（栈平衡+eax 写回双断言）。**验证**：x64 build 0/0、ctest 16/16、multiseed 250/250（REQUIRE_REAL）、x64 dump @12345 f67c2d40→ffd47289（唯一码体 delta=callgate +6 行, entry 恒等, dispatch 仅表偏移 1 行, 三批次恒等）；x86 交叉链 rc=0、电池 **35/35**（31+2+2）、dump 门 60 登记项 PASS、静态扫描双面 PASS（x86 dump 对账 = 60 行 shuffle 洗牌 seq 标签号漂移归一化后零 diff——X3b 19→57 同款重立口径）。**B.7 口径勘误**：asm_dump 是 seed 纯函数与样本无关（snake/forkface 同 sha 实证）——"48 样本 dump 恒等+forkface 例外"前提机械不成立, 等价口径 = 逐 handler 对账（唯一 delta 段=callgate）+ 行为恒等。**B.5/B.6**：shld/shrd 折条可行挂观察清单（语料低频, lifter 开面=冻结面配方）+ cwd 不立项（capstone 双 id 归 cwde 系、X0 语料无独立条目）；x87 D1 备忘三路线随报（默认定稿 R-SSE-only）。冻结契约零 diff（vm_op 97/kCtxSize/runtime.hpp/lifter/cli/sdk）；唯二解禁 asmgen+translator(限 translate_call) 全程遵守；X4 交接 = S64 tag 改形点位×5 + stub ABI 对齐锚×4（GAPS X3c 节） |
| **多目标平台 X4 (MIT-446)：x86 全管道打通——stub_gen cdecl 重写 + S64 tag 改形（点位×5+同族残段×3）+ D1 解禁 + x86 E2E 首批 3 族级样本入池** | ✅ | mit-x4-stub-e2e | **B.2**：Translator arch_/sz_step_ 单一来源（x64=S64 现形 / x86=S32）——①push/pop x86 改 VmOp::Push/Pop 单 op ②emit_address 双形 ③imm64_split 防御形 ④LeaRva 通路 ⑤G3 串微程序 + 清单外同族残段×3（跳转表链/bzhi CF 补丁/cbw 载体，披露）一并参数化；D5 防回归 = translator 双 arch 快照×3 + 电池 StepTagS32LiveAndS64NoopGuard。**B.1**：stub_gen 双形化（x64 逐字保留）——4 callee-saved push 0x10+mod-16 钉 / ctx 经 push esp 栈参 [esp+0x14] / ctx 区 rep stosd 清零（⚠️ edi 临时捕获：Ret 直退路径不经 stub pop，实录 stdout 空 0xC0000029）/ 保存区读回偏移 = kCtxSize+0x10−4(i+1)（⚠️ 首push在高档，顺序反致 slot5=原 esi，cdb 铁证 0x7717667C）/ 易失回写 eax/ecx/edx / 终态 jmp dword [esp−0x258] / blob 指针 imm32 免回填；kX86ExitSlotDepth 单一来源上移 runtime_x86.hpp；**callgate cdecl 参数窗** kX86CallgateArgDwords=4（guest [v4+4i] 逆序预置，caller-cleans 多预置无害，445 挂账翻案）；stub_link x86 白名单 gate（x86_handler_table 单一来源 + x86_handler_opcodes 导出，跳表缺项 C2 静默错拦成 C1 显式 gate）。**B.3**：D1 四象限——auto+x86 / x86+x86 放行，mismatch 双向拒（2.6 块限定 machine≠x86 修误伤亲测）；GAPS C5 行/支持矩阵行翻正 + 已知 gate 清单 G7(SSE)/G8(Div/Idiv) 入册。**B.4**：三族级样本（forkface-x86 移植形 6 stub / SSE 面 1 stub+设计性 gate 负例 / 混合+cdecl 参数窗 2 stub）native 全绿先 + machine=0x14C dumpbin 断言 + WOW64 byte-exact 全数 PASS；multiseed 首次填池 **265/265**（REQUIRE_REAL，x64 250+ x86 15）。**B.5**：pe_writer PE32 面零改动就绪实测（SizeOfImage/节表/checksum 同布局）+ reloc/ASLR 口径对齐 x64 现网文档化。**B.6 六件套**：build 0/0、ctest 16/16、multiseed 265/265、wvmpTest stubs=14 双跑 diff 0、x86 电池 36/36（35+1）、dump 门 60 项 PASS；**x64 dump @12345 `ffd4728901812932…`/161,861B 五批次逐字节恒等 = D2 机器证明**。冻结契约零 diff（kCtxSize/vm_op 97/runtime.hpp/lifter/SDK/markers）；解禁清单全程遵守（stub_gen/stub_link/translator 限 B.2/pe_loader/pe_writer/tests/scripts/docs + asmgen 限参数窗与表提函数）。**X5 交接**：样本池扩量优先级（整数面真函数 → 跳转表/ExitNative 真样本 → callgate 深链）+ 已知 gate 面清单（GAPS G7/G8 + x87 永久）+ 跳表余量 97/128（30）不变 |
| **多目标平台 X3b (MIT-444)：asmgen x86 整数面全支持——A 档 29 op 宽度模板批迁 + 锁原子 4 + B 档 GP 5（Push/Pop 4B 槽裁决 + RVA 族）+ B.3 translator 收口证据** | ✅ | mit-x3b-asmgen-int | x86 handler 表 19→**57 行**（补集对账：x64 表 96 唯一 VmOp − x86 19 = 77 纸面 = 38 批迁 + Div/Idiv 2（D2 除零折叠维持）+ Movsxd/MovsxdMem 2（x86 native 无 movsxd + lifter arch 拒 = 不可达，且 32→64 写满 8B 槽破"槽高半字恒 0"不变量 → 永久纸面合理）+ CallGate/ExitNative/Ret 3（X3c 协议面）+ SSE 族 32（X2b/X3c）——#33 粗数修正：派单 "A 档 ~45/SSE 34/纸面 77-78" 按实表点名）：批次一 Not/Neg/Adc/Sbb/Imul/Mul/Cdq（bt [ctx+0x98],1 CF_in 通路 + Mul 双结果槽 + 生成期源槽 ≠ 物理 eax）→ 批次二 Shift 族 10（**x86 计数掩码 0x1F 全宽实测钉**：SDM 6 位掩码仅 64 位模式 REX.W，count=0x20 值+flags 双不变电池钉死；rol/ror 走新 flags_tail_partial_x86 —— MIT-433 案 32 位平移）→ 批次三 Movzx/Movsx(+Mem)/Bswap/Xchg（aux[0] 源宽位 MIT-345 编码）→ 批次四 Setcc/Cmovcc（cond 帧槽链 + aux[31..28] + bitwise 双边合并）→ 批次五 Popcnt/Lzcnt/Tzcnt/Cmpxchg/Xadd/Bts/Btr/Btc（cmpxchg 内存目的形式直打 dst 槽 + 生成期非 eax 载体选取；lock 前缀 32 位编码同形）→ 批次六 Push/Pop（**4B 槽裁决**：guest esp 步进 4B ⨯ ctx rsp 槽 8B —— dword 低半字槽算术 = 32 位回绕 native 语义；⚠️ X4 挂账：translator rsp 步进 Sub/Add 与 rip-RVA Mov 带 S64 槽宽 tag，x86 运行时折 no-op，X4 须改 VmOp::Push/Pop 单 op 形或 S32 参数化）+ LoadRva/StoreRva/LeaRva（**base+RVA 非 identity** 实判钉死）+ Jmp/Jcc far-forward 回归；电池 11→**28 用例**（真执行语义 + 边界值 + S8/S16/S64 防御面钉 + FiveSeed 批迁面 ≥15 op 五链抽样）；dump 门 BATTERY_HANDLERS 57 全覆盖 + 静态立即数扫描双面（asmgen.cpp 源 + x86 dump 文本）PASS；B.3 收口 = **pop 位宽对称面 442 已收**（git log -S 实证 5ce27c7 同带 push/pop gate，派单 A.2 锚失配点名）+ **S16 串形维持 gate**（lifter 冻结为唯一闸 + translator inc 派生 S16 恒错，单改 translator = 死代码；X3c 两文件开面配方入 GAPS X3b 节）；批迁缺陷实录（电池当场炸当场修，x64 恒等未受扰）：xadd 写回误用 kind 值槽 / cmpxchg S8 源载体越字节可编码集（seed 相关 ks_errno=512）/ setcc tail 复用 cond 载体作槽索引；**x64 零扰动 = snake seed12345 asm_dump 逐批次 vs main 4050a4c 底稿逐字节恒等（161756B sha f67c2d40…）** + multiseed 250/250（REQUIRE_REAL）+ wvmpTest stubs=14 + jt@0xDD84 entries=8 + exit-native 17 + 双跑 103/103 diff 0 + ctest 16/16；冻结契约零 diff（kVmOpMax=97 不动、零新 VmOp、translator/lifter/runtime.hpp/backend/SDK 零触——唯二解禁 asmgen.cpp 全程遵守）；X3c 输入 = GAPS X3b 节精确清单（SSE 32 + 协议面 3 + D2 除零 2） |
| **多目标平台 X3a (MIT-443)：asmgen x86 核心——KS_MODE_32 双模 + 池 14→6 重构 + entry/dispatch + x86 runtime 真执行电池（X 波关键路径首张）** | ✅ | mit-x3a-asmgen-core | asmgen.cpp 双模化（HostArch 分叉收敛五处：KsSession 模式/roll/build_entry/build_dispatch/handler 表；x64 路径逐字保留）：D2 entry BASE=call/pop idiom（push 1B+call rel32 5B 确定性 6B 回指，sub base,6）+ D3 跳表保 8B 表项（x86 读低 dword，表格式/掩码零改动）+ B.2 池重构（x86 池实测 = kPhys[0..5] 6 个：ctx_/base_ 占 callee-saved 随机 2、pc_/flags_ 内存常驻既有 ctx 槽 +0x8/+0x98 零新字段（D4 kCtxSize 冻结不破）、临时 10→4（数据临时 t_[0]/t_[1] 字节可编码集 {eax,edx,ebx} 约束 —— bpl/sil/dil REX 专属名 32 位不可编码，X0 粗算 2 的实测修正）+ spill 纪律 = 固定宿主栈帧 0x24 常量槽（setcc 捕获区落帧 ⇒ zero5 x86 形 = 空））；x86 handler 电池集 19（Mov/Lea/Add/Sub/And/Or/Xor/Cmp/Test/Inc/Dec/Load/Store/Jcc/Jmp/Nop/Halt/GetFlags/SetFlags，S8/S16/S32 三路 + S64 防御 no-op；其余 op 跳表折叠 Halt）+ `generate_runtime_x86`（新头 runtime_x86.hpp）+ 32 位测试进程电池 11 用例全绿（真执行语义 + capstone CS_MODE_32 反汇编断言 + 5 seed 稳定性；`ctest --test-dir build\x86 -R x86_runtime_battery`，构建 `scripts\build_x86_tests.bat` vcvarsamd64_x86 交叉链 + FETCHCONTENT 隔离 .deps）+ x86 dump 门 `scripts/verifier/verify_x86_dump.py` PASS（entry idiom/dispatch 掩码/19 handler 首条可解码）+ 保存区裁决 = 维持 guest≥ns 规则不重排（GAPS X3a 节）；**x64 零扰动铁证 = 同 seed asm_dump 逐字节 cmp 恒等（D6，161756B）** + multiseed 250/250 + wvmpTest 双跑 diff 0；电池首跑炸出并修复 size_chain_x86 S16 空转缺陷（三路尺寸须三 cmp 显式分派，链尾顺延 = S64 防御出口）；冻结契约（runtime.hpp/vm_op/backend/SDK）零 diff、cli/lifter/translator/stub_gen 零触；X3b 交接 = 电池可扩展（加 TEST 行 + handler 表加行 + dump 门 BATTERY_HANDLERS 同步），X3c = callgate/ExitNative/Ret 协议 4B 化 |

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

| **多目标平台 X5 (MIT-450)：M2.5-X 收口——x86 池扩量 3→11 + wvmpTest x86 全量 E2E + 参数窗裁决 + gate 负例族** | ✅ | mit-x5-closure | **B.1** 五族样本入池：deepcall（callgate 递归 32 层×0x38=0x700<0x1000 窗口，C 镜像 rc=0 哨兵；首通实录: 递归参数误写进参槽该写出参槽，原生镜像哨兵当场抓获）/ jmptbl（4B 表 REG-abs/REG-delta/MEM-abs 3 正形 + 无防御/出区 2 负例）/ strops（rep movsd 对齐+非对齐/stosd/repe cmpsd 早退/repne scasd/lodsd/plain movsd×2）/ bitops（popcnt/tzcnt/lzcnt——MASM .686p 无助记符 db F3 0F B8/BC/BD 手编码 + bswap/cmpxchg 双路/xchg；lock mem 形经 strip-and-execute 真虚拟化）/ looplea（嵌套循环+复杂 LEA）；首通实录: 9 位十六进制立即数×3 处。**B.3** x87gate（R-SSE-only 专属）/sehgate（真 __try/__except + fs:[18h] 区内 TEB 读 = G1 gate + except 实弹路径）/std67gate（std D5 + 67 G2 禁调用）三负例族 + gate note 断言 + 双跑 byte-exact。**B.2** wvmpTest x86 重建对齐源（94→103 kernel，旧产物 9 kernel 陈旧）native 103/103；打包 13/14 位点 gate（分布: 跳转目标块未找到 17 / push-imm 11 / 间接 jmp 1）+ **1 stub = kern.mul64hi_closed_forms 确定性崩溃实录**（cdb 铁证: 崩溃点 `mov eax,[ebp-0x28]`、ebp=FFFFFFFF、eax=504D5657" WVMP"/ecx=31444E45" END1" marker magic 活在寄存器；根因 = 真实 /Od codegen 在区域内发 push → stub callee-saved 保存区破坏（C2 类）→ X5b 修复单素材，本单 D5 零产品 diff 不修）；x64 对照: 14 stubs / 0 gate / 双跑 diff 0（X4 基线复现）。**B.4** 参数窗裁决: kX86CallgateArgDwords=4 = 每调用"可见参数桥"非调用次数上限（step 2.5 每调用从 guest [v4+4i] 预置 + host_rsp 重基 caller-cleans 回收）；5 参 cdecl 三形实测: mov 形 arg4 确定性丢失（0x11111→0x01111，帧完好）/ push-imm 形整函数 C1 gate（translate_push 拒 imm）/ push-reg 形真虚拟化但 callee-saved 破坏实证（post: ebx=00010000/esi=00000100/edi=00000010 = push 值精确落位 [v4-4..v4-0x10]）→ **裁决 = 维持 4 dword 窗**（真实 /Od 以 push 形为主，扩窗救不了 push 形；mov 形扩窗最小 diff = 单常量 kX86CallgateArgDwords（loop 已参数化、stub 侧无第二份）留 X5b 备选）+ **442 规则升级为产品正确性边界**（guest 栈写 < ns = 静默帧破坏，X5b 立翻译期栈深 gate）。**B.6 六件套**: build 0/0、ctest 16/16、multiseed **305/305**（REQUIRE_REAL=1，x64 250 + x86 55）、wvmpTest x64 14 stubs 双跑 diff 0、x86 11 样本 machine=0x14C dumpbin 全验 + protect stub 1-2 + 双跑 byte-exact、**x64 dump `ffd4728901812932…`/161,861B sha256 逐字节恒等 = D5 机器证明**。冻结契约零 diff；**产品代码零 diff（本单交付全为样本/测试脚本/文档面）**。新实测 gate 面（X5b/按族提单素材）: ① x86 跳转表匹配器 S64 硬编码 2 点位（try_match_jump_table 基址载入与 delta add 的 size!=S64 → S32 链永不匹配；446"参数化"仅指步进 tag，本单实测修正）；② REG-REG bts/btr/btc/xadd 不在 x86 lifter 面（仅收 G4 lock MEM 形）|
| **多目标平台 X5b (MIT-451)：x86 保存区冲突修复——entry guard 垫栈(N=128) + 翻译期栈深 walk gate + 跳表匹配器 S32 + REG-REG 位测试族** | ✅ | mit-x5b-stackfix | **B.1** 离线实测工具（scripts/verifier/measure_x86_stack_depth.py，镜像产品 walk）：wvmpTest x86 14 区 net p99=64B/max=64、reach 全 0；(i)@0=9/14=64.3% vs (v)@128=13/14=92.9%（@256/@512 无增益）→ **kX86GuardBytes=128**（p99×2 余量）。**B.2 主修复**：stub x86 序言 `sub esp,128`（guard 区 [ns-128..ns-4] 吸收 guest 栈写，保存区/ctx 下移，保存区读回公式 esp-相对不变，v4 恒=ns，出口槽 0x258→**0x2D8** 单源派生，尾声 add esp,G 回 esp=ns）+ translator 栈深 walk（push/pop 净值 + rsp-ALU + 别名帧指针 reach + 回边增长 + **ExitNative/Halt d==0 硬检查**；x86 预算=128B/**x64=0**——D4 双 arch 共享，wvmpTest x64 实测 0 新增 gate）+ **callgate 参数窗 4→8**（X5 B.4 备选行使，>8 dword 超窗披露）。**mul64hi 裁决**：16 个 call-arg push + 区外延迟清栈 → Halt d=64≠0 → gate（出口物理 esp=ns vs 真实 ns-d，延续代码 esp 敏感即静默错——宁 gate 勿错；esp-resync 前瞻挂账）→ **修复前 main 打包 rc=139 复现 / 修复后 rc=0 全绿**。**B.3** 匹配器三点尺寸判据 ptr_sz 参数化（delta add/lea rip/mov-imm 基址）+ 4B delta dword 回绕语义（负 delta 2 的补码 = MSVC x86 .text 尾随表常态）→ jmptbl 三正形翻正 stub 1→4、2 负例维持 gate、byte-exact。**B.4** lifter 四 case（x86 专属）→ 载体域 5..8 零新增 → **b_kind=None 判别**单 VmOp（编码零改动、vm_op 冻结面零触碰）→ x86 handler b_kind==0 分支（native lock RMW 直打 ctx 槽）+ **位号 and 0x1F 修正**（电池 v2=35 当场炸出 0x800000000：内存形位号不掩码跨界摸邻槽）；同寄存器 xadd gate；bitops 池样本 stub 2→3（rgn_bitops_reg 掩码探针）。**B.5** 池 11→13（pushform guard 垫栈真虚拟化正形 + guardover walk gate 负形+GP helper）。**B.6 六件套**：build 0/0、ctest 16/16（lifter 159/translator 91）、multiseed **315/315**（REQUIRE_REAL=1，x64 250+x86 65）、wvmpTest x64 14 stubs/0 gate/双跑 diff 0、**x64 dump `ffd4728901812932…`/161,861B sha256 逐字节恒等**、x86 电池 37 PASS + dump 门 60 项 PASS + 静态立即数扫描双面 PASS、wvmpTest x86 **103 kernel 双跑 diff-0 达成**（450 遗留 1 销账；gate 分布=跳转目标块未找到 17/push-imm 11/间接 jmp 1 + stack-depth-gate 1（mul64hi）；**wvmpTest 翻正数=0——主导 gate=既有 lifter 面"跳转目标块未找到"= x86 下一最大 gate 面**）。冻结契约零 diff（kCtxSize/runtime.hpp/vm_op 97/载体域 0..28/跳表 128）|
| **多目标平台 X5c (MIT-453)：ExitNative x86 上界接线修复——backend 单点 F1 + 末区 .text 兜底专项反证** | ✅ | mit-x5c-exitbound | **B.1 F1**（regvm_backend.cpp 单点位）：pdata_empty 分支补区域表回退——ub = min{fr.begin_rva > begin_rva}（逐元素取 min 不依赖排序）+ 无后继 → 所在节节尾（VirtualAddress+VirtualSize，不对齐——[内容尾,对齐面) 零填充放进即崩）+ **节尾 cap 收紧**（多执行节病态布局下 next_begin > 节尾时 [节尾,next_begin) 不放行，裁决表 "目标出节尾=gate" 任意布局成立；单 .text 产物 cap 不绑定读数零差）；pe==nullptr / 无 .text 维持 nullopt；回跳检出提前双路共用；x64 路径（pdata 分支在前）条件序不变（D2）。**B.2 末区专项**：0xC972 走查（bd2c end=0xC9D5、节尾=0xAE7AA 实读，A–E 全真 → emit，产品日志 `exit-native @ 0xC972 -> 0xC9D5 (cond=13)`）+ 样本 `wvmp_x86_tailexit_sample`（rgn_exit_ok next-begin 三面 + rgn_tailexit_ok 末区节尾三面 + rgn_tail_beyond E9 手编码越节尾 gate 负例禁调用；MASM 对 .data 标签 jmp 产 FF 25 间接形会归因错族——手编码直跳才钉得住）+ 裁决表（末区目标 ∈ [end_rva,节尾) 放行 / ≥节尾 gate）。**B.3 单测 ×10**（backend UpperBound 组：常规/末区兜底/越节尾/cap/嵌套/空表/pe-null/blocked/无.text/pdata 对照）。**A.3 对账（D5）**：en 0→17 / jtbn 17→0 / 残面 30→13（push 11+间接 1+栈深 1）/ **stubs 9 ≠ 452 预估 10——失配归因 = marker@0xb59b `div`→VmOp 78 撞 G8 x86 白名单 C2 gate**（修复前被 jtbn 掩盖，翻正后如实浮出，宁 gate 勿错；C2 补面归后续派单）。**当场修（§E）**：B.4 双跑首炸 kern.md5_block_vectors 确定性 AV（cdb 铁证 .wvmp+0x693 Load handler 地址槽=md5 F 值）→ 根因 translate_imul REG-3op 折叠丢 src（注释先验 "MSVC /Od src==dst" 被 `imul edx,ecx,3` 等实测推翻，idx7 4 处 + imm=0 形 3 处被结果恰 0 掩盖）→ 修复 = src≠dst 先 Mov(dst,src) 物化（MEM-3op 同款），src==dst 字节不动；D3 边界披露：改动在 translate_imul **不在判定链内**，452 结论不动摇；imul 双向单测钉死 + GpMul 更新。**B.4 六件套**：build 0/0、ctest 16/16、multiseed **320/320**（x64 250+x86 70，池 50+14）、wvmpTest x86 双跑 diff-0 ×2（12 处 ExitNative 真执行首次全量真跑）、wvmpTest x64 14/17/0 + diff-0、x86 电池 37 + dump 门 60 项 + 静态扫描 PASS、**x64 dump 双 CLI cmp 逐字节恒等（全 hash 首录 ffd4728901812932d4d85dfed13f80be4edd8f78f93c6f483ff415bfd5d06206 / 161,861B）**。冻结契约零 diff（kCtxSize/runtime.hpp/vm_op 97/载体域/跳表 128） |

| **多目标平台 X6 (MIT-454)：x86 残 gate 双面包翻正——push-imm 开面（translator 单点，#33 定位修正）+ X3d SSE 32 op 批迁（x64 表 32 位镜像 + stub xmm 同步 + ucomis flags 面）** | ✅ | mit-x6-pushimm-sse | **B.1 批一（X5d）**：#33 实测修正派单 A.1——is_data_operand 本就接受 Imm（push imm 恒被 lift 为 Op::Push dst=Imm），真卡点 = translate_push dst.kind!=Reg skip（wvmpTest 11 处 gate note 全为该文本，aa18×1+b678×10 逐 site 实证）；x86 Imm 分支（值域 [-2^31,2^32-1] 低 32 位截取 = 32 位存储语义，超域防御 skip）+ S16/S8 gate 前置；x64 维持 skip（D2，sext 64 位面挂 X6b）；lifter 钉测试防回流；dumpbin 钉 MASM 把 push 0FFFFFFFFh 编为 6A FF（sext 存储值同 0xFFFFFFFF）；新样本 x86_pushimm_sample（68/6A 双编码 7 形 + call-arg imm 对，池 14→15）+ 电池 PushImmMultiValueStack（push 0/0xDEADBEEF/0xFFFFFFFB esp 步进 12B + LIFO 逐 dword）。**B.2/B.3 批二/三（X3d）**：x64 32 op SSE 表逐 op 32 位镜像——共通模板 build_x86_sse_binop（dst 预读 xmm0 → src 双语义寻址 → native → 写回）×16 算术+6 传送+4 位运算 + XmmLoad/XmmStore 三宽 + XmmFromGp/GpFromXmm 桥 + ucomiss/ucomisd flags 面（setcc5_x86 落帧+flags_tail_x86，x86 无 zero5）；xmm 帧公式 (slot-24)*16+0x140 拆步 imm() 纪律；编码双平台同逐 op 断言（26 mnemonics Keystone 双模装配同字节+capstone 双解同 text）；stub xmm 同步（x86 stub 入口 host→ctx.xmm + 出口 ctx→host——446 "xmm 同步不适用" 前提翻转；ExitNative/Ret 直退 handler 内联 ctx→xmm 恢复；x64 形逐字未动）；**批迁缺陷当场修（D4）**：build_xmm_store_x86 地址/src 临时同用 t_[1] 致 store 写野地址（电池 AV 实录，x64 T1/T9 分工缺位）→ t_[0]/t_[1] 分工修复；wvmp_x86_sse_sample 翻案 gate→真虚拟化（stub 1→2）byte-exact（D5）；Cvt/Sqrt/Unpck/Shuf 面无 ir 载体无 VmOp（冻结枚举域内不存在）= 双 arch lifter 层 gate 如实披露。**读数（D1 分栏）**：B 列 push-imm 11→0（aa18/b678 翻正 stubs +2）；A 列 sse 样本翻正 +1 stub、wvmpTest 无 SSE 标记函数（如实读数）；总 stubs 9→11 / 残面 13→3（间接 jmp 1 + 栈深 1 + Div 1 均挂账维持）/ 表 60→92 / 电池 37→43 / multiseed 320→325（池 50+15）。**B.5**：三批 x64 dump ffd4728901812932…（161,861B）逐字节恒等复验 + multiseed x64 250×3 + wvmpTest x64 14/17/0 三批复验。**D3 披露**：stub_gen.cpp x86 路径 xmm 同步超出解禁字面清单，依据 = 派单 A.2 446 交接原文 + stub 注释条件翻转句，x64 零触。冻结契约零 diff（kVmOpMax=97/载体域/kCtxSize/runtime.hpp） |
| **多目标平台 X7 (MIT-455)：客户态重扫（双 arch 三层口径）+ X6b 数据裁决 + Div 族 x86 开面（x86 战役残面收官）** | ✅ | mit-x7-rescan-x6b | **B.1 批一（零产品代码）**：X0 留样 jsonl 已随 %TEMP% 失效 → 语料按 X0 §1.2 口径重建（core_os 37/old_runtime 12/modern_ucrt 7 点名三层 + random 八分位 seed=436 + 436 第三方家族现存子集 8，PhysX/Steam/dxcompiler/hha/wab32 缺位披露）+ **x64 System32 首扫**（X0 从未扫过 x64 域）；覆盖率形级口径：x64 direct **99.26%** / x86 **95.15%**（库域 94.26%，落 X0 诚实下界带 92-94% 上沿且构成翻新）；区域级 = x64 .pdata 真函数域 240,277 函数逐函数归因（无 gate 函数 94.74%）+ x86 文件级/递归对账代理；一致性断言 = 脚本 direct 151 助记符 ⊆ 产品 lifter case 208 id + 形级双通道交叉校验 47,705 shape 项零 diff（§E 漂移即误报）。**B.2 批二（预登记阈值 D2 机械执行）**：push-imm x64 5,009/17,626,439 = **0.0284% < 0.5% → 维持 gate 销案**（最高层 old_runtime 0.084% 仍差 6 倍；68/6A 形拆分留档）；间接 jmp 门1 x64 函数占比 1.787% ≥1% 过门但门2 表形（index×ptr）全语料仅 28 条 = 0.0002%（任意 mem 84.7% + reg 15.2% 主导 = call 表分发 D6 边界）→ **门2 败维持 gate 销案**；Div 族 x86 = 实施（89/112 文件命中 + D4 实读 x64 build_div_idiv 真行为后镜像）：build_div_idiv_x86 真 handler（native 直通 + 除零=真 #DE D2.1 同口径 + 商/余双槽写回 + setcc5_x86 捕真值；除数临时 ts 静态避 {eax,edx} 双位 = 较 mul 多一位约束）+ 表 92→94 + **lifter translate_cdq x86 S32 开面**（真实 idiv 恒有 cdq 前置 = Div face 必要条件，D3 字面清单超出披露 + 404 时点前提已翻转，cqo REX.W 防御拒维持）+ 电池 DivIdivQuotRem ×6 + lifter 钉 CdqX86LiftAndCqoBoundary + 样本 wvmp_x86_div_sample（div reg/mem + idiv cdq + 负除数，池 15→16）。**B.3 批三**：G8 行翻正 + 支持矩阵翻正 + X7 收口节（含 x87 B 路线触发判定入册：x86 密度与 X0 同构、x64 函数域 0 命中 → B 路线不满足维持 R-SSE-only；push_mem x86 1.845% 新数据行留档）+ STATUS 里程碑。**读数**：wvmpTest x86 stubs 11→12 / 残面 3→2（b59b 翻正）/ 14 标记区真虚拟化率 78.6%→85.7%；multiseed 325→330（REQUIRE_REAL，池 50+16）；x86 电池 43→44；x64 dump @12345 ffd4728901812932…/161,861B sha256 逐字节恒等（底稿复跑锚 = 新增 WVMP_X64_ASM_DUMP 钩子 + MovdBridgeSemantic 过滤，生成命令首次入仓）；wvmpTest x64 14/0 基线不变；静态立即数扫描双面 PASS。冻结契约零 diff（kVmOpMax=97/载体域/kCtxSize/runtime.hpp/backend）；D0 禁自行 merge，合入权在项目主 |

| **MIT-456 (push-mem)：x86 `push [mem]` 开面——X7 新数据行第一大非 x87 shape gate 翻正（无派单直接开发 + 子智能体验收）** | ✅ | mit-pushmem-x86 | **实施（translator 单点，零新 VmOp/零新 handler）**：translate_push Mem 分支（x86 专属 D2）= emit_address（translate_load 同款：rip/负 disp Sub 展开非法 scale 防御全继承）→ Load/LoadRva 值槽 → 单 op **Push a_kind=Reg**（X3b handler 既有 Reg 分支，asmgen.cpp 逐字节零 diff）；**native 序锚** = 地址/读值在 Push 减 esp 之前发射（push [esp+4] 读减前 esp = IAT 栈窗惯用形语义）；S16/S8 位宽 gate 前置沿用（442 口径）；x64 维持 skip（D2：无 push_mem 数据行 + x64 push 现形 = Sub+Store 双 op 独立面），形 note 文本逐字节不变。**栈深 walk 零改动即覆盖**：IR 级 Op::Push 净深 +4 既有建模 + 负位移 reach 对 dst=Mem 既有（push [esp-200] → gate，单测钉）。**测试**：lifter 钉 PushMemLiftsDstMem（FF 30/FF 77 08 x86 + FF 30 x64 双 arch）+ translator ×4（折条形/index×4+disp 全展开 7 VmOp/负位移 walk gate/X64PushMemStillGated D2 钉）+ x86 电池 PushMemFromMemory 真执行（内存源两形 push + LIFO + esp 步进 + 栈内存逐 dword；⚠️ 沉淀电池槽位纪律 = VM 槽 0..7 客机 GPR 1:1、槽 4 = RSP 槽，数据槽误用槽 4 → Load 值写进 esp 槽 → 下次 Push 以值为地址访存崩，cdb 实录 mov [ebx],edx @ bbbb221e）+ 样本 wvmp_x86_pushmem_sample 四面（FF 35 abs / FF 71 04 reg+disp8 IAT 形 / FF 74 24 04 esp 栈窗形读减前 esp / call-arg push [mem] 对 + callgate + 区内 cdecl 清栈，net 深度 0，native 首绿 pm=AAAA1111 CCCC3333 11111111 11112222）池 16→**17**。**验证六件套**：build 0/0 / ctest 16/16 / multiseed **335/335**（REQUIRE_REAL=1，x64 250 + x86 85，池 50+17）/ wvmpTest x64 14 stubs 双跑 diff-0 + x86 **12 stubs** 双跑 diff-0（靶标无 push [mem] 位点 → 12/14=85.7% 读数维持，残面 2 = aebb 间接 jmp + b38d 栈深均永久 gate）/ x86 电池 44→**45** + dump 门 94 登记项 PASS（asmgen 零 diff 表级证据）+ 静态立即数扫描双面 PASS / **x64 dump @12345 `ffd4728901812932…`/161,861B sha256 逐字节恒等**（x64 零扰动机器证明）。冻结契约零 diff（kVmOpMax=97/载体域 0..28/kCtxSize/runtime.hpp/backend.hpp/判定链/ExitNative 协议/跳表 128/asmgen.cpp）。X7 交付面零回踩（multiseed 330 基线全数含于 335） |

## X4 交付与 X5 交接（MIT-446，2026-09-02）

**x86 生产能力就绪宣告面**：main 在 X4 合入后即具备 x86 (PE32) 生产能力
（D1 拍板：解禁不再等 X5）。X5 职责 = 样本池扩量 + 回归加固 + 阶段宣告，
交接清单：

1. **样本池扩量优先级**：整数面真函数（MSVC /Od 产物形态）→ 跳转表
   （REG 4B/8B 表，x86 链已随 B.2 参数化真块）→ ExitNative 真样本（4B 槽
   `[ns−0x258]` stub 通道已实证）→ callgate 深链/递归（窗口 0x1000 预算
   同 x64 406 纪律）→ SSE 族 handler 开面（X2b 单立项，开面即解除 G7
   gate）。每样本延续 D4：native 全绿先 + ≥1 真可虚拟化函数 + machine
   dumpbin 断言 + byte-exact。
2. **已知 gate 面清单**（GAPS「x86 战役已知 gate 清单」G1–G8 + x87 永久
   gate 节）：段覆盖/67/std/S16 串形/shld 系（lifter 层）；SSE 族 32 /
   Div/Idiv（x86 白名单 gate，整函数原生零逃逸）；Movsxd（x86 不可达永久
   纸面）。扩量若撞面 → 按族提单（G8a 模式），禁绕 gate。
3. **跳表余量现状**：kVmOpMax 97 / kTableEntries 128（余量 30）——本单
   零新 VmOp 不变；x87 L0 / ymm 立项仍触发扩容前置 commit（GZ 既有条款）。
4. **B.2 同族残段披露**（跳转表比较链 / bzhi 边界 CF 补丁段 / cbw 载体
   stash 合并段已随五点位一并参数化，x86 真块）：X5 扩量遇新面按同款
   `sz_step_` 纪律处理，禁逐点新增 S64 tag。
5. **stub 帧形不变量**（改动须同步两侧）：kStubPushBytesX86=0x10 + 4 push
   序（ebx→edi，先 push 在高址）+ kX86ExitSlotDepth=0x258（runtime_x86.hpp
   单一来源）+ kX86CallgateArgDwords=4 参数窗协议（asmgen/stub 两处同步）+
   kX86RetV4SlotFromExitRsp=0x38（runtime 帧自洽，stub 帧形若变须重核）。

## 多目标平台（M2.5-X）收口（MIT-450, X5, 2026-09-02）

**完成口径**：x86 (PE32) 生产可用宣告维持 X4 定稿；X5 完成池扩量、wvmpTest
x86 全量 E2E、参数窗真语义对账、gate 负例族与本文档收口。权威基线 = 分支
`mit-x5-closure`（main `dc2f21a` + X5 批次，产品代码零 diff）：build 0/0、
ctest 16/16、multiseed **305/305**（REQUIRE_REAL=1，x64 250 + x86 55）、
x64 dump `ffd4728901812932…`/161,861B sha256 逐字节恒等、wvmpTest x64
14 stubs 双跑 diff 0。

**触发条件（下一战役）**：410(M3 插件池) 或 X3d(SSE 32 折叠) 恢复/立项；
X3d 立项数据 = 本单 x86 客户态分布表（wrapped 位点 14，gate 13/14，
gate 率 92.9%）；X5b（区域内 push 栈深 gate + 可选参数窗扩宽 + 跳表匹配器
S32 参数化 + REG-REG 位测试 lifter 面）按缺陷优先级另立项。
