# MIT-454 (X6) 交付纪要 — x86 残 gate 双面包翻正（push-imm 开面 + SSE 32 op 批迁）

> 完成: 2026-09-02, 分支 `mit-x6-pushimm-sse`（基于 main 4083b1f, 三批
> 5c7e3b2 / 026b7a6 / aba35e1 + 文档批; **D6: 禁自行 merge, 合入权在项目主**）

## #33 定位修正（派单 A.1 首项）

- 派单 A.1 称"卡点在 lifter（x86_translate.cpp:219 is_data_operand 拒 imm 形）"——
  **实测推翻**: `is_data_operand` 本就接受 Imm（Reg/Imm/Mem 三形），push imm 一直
  被 lift 为 `Op::Push dst=Imm`。wvmpTest x86 基线 11 处 push-imm gate note 全部为
  **translator skip 文本**（"push 操作数形态未支持"），aa18×1 + b678×10 逐 site grep
  实证。真卡点 = `translate_push` 的 `dst.kind != Reg` skip。
- 运行时 `build_push_x86` 的 a_kind 双形（xpimm_ 读 aux）X3b 已备，且 x86 电池
  PushPopStack 早已覆盖 imm push（LIFO 首推即 imm）——"Imm 形分支存在性"实测核完成。

## 三批交付（D1 一批一读数）

| 批 | 内容 | 提交 | 读数 |
|---|---|---|---|
| B.1 | push-imm x86 开面（translator 单点 + 新样本 pushimm 池 14→15） | `5c7e3b2` | push-imm gate 11→0（B 列） |
| B.2 | SSE 基础族 30 op 批迁（算术/传送/位运算/mem/桥 + stub xmm 同步） | `026b7a6` | sse 样本翻案 stub 1→2（A 列） |
| B.3 | ucomiss/ucomisd flags 面（32 op 收尾） | `aba35e1` | x86 SSE VmOp 面全覆盖 |

## 总读数（B/A 列分栏）

- wvmpTest x86: stubs **9→11**（B 列 +2: aa18/b678；A 列 wvmpTest 无 SSE 标记函数，
  如实读数不虚增）、残面 **13→3**（间接 jmp aebb 1 + 栈深 mul64hi 1 + Div b59b 1，
  均挂账维持）、双跑 stdout byte-exact（7687B）。
- 103-kernel: 14 标记区真虚拟化 9→**11** = **78.6%**（全 103 面 10.7%）。
- x86 handler 表 60→**92** 行（单一来源自动放行，stub_link 零改动）。
- x86 电池 37→**43**；multiseed 320→**325**（REQUIRE_REAL，x64 250 + x86 75）。
- x64: dump `ffd4728901812932…`（161,861B）三批复验逐字节恒等；multiseed x64
  250×3；wvmpTest x64 14 stubs / 17 en / 0 gate 三批复验不变。

## 批迁缺陷当场修（D4 归属标注）

- **X3d 族**: `build_xmm_store_x86` 地址临时与 src 寻址临时同用 t_[1] → store 写
  野地址（电池 X86SseMovBitwiseBridgeRealExec 3b 块 AV 实录；x64 版 T1/T9 分工在
  32 位镜像时缺位）→ 地址 t_[0] / src t_[1] 分工修复。
- **X5d 族**: 电池 PushImmMultiValueStack 首版断言 LIFO 方向写反（测试缺陷，非产
  品缺陷），push 先减后写 = 末推最低址，修正断言后绿。

## D3 解禁披露

- stub_gen.cpp（x86 路径 xmm 同步）超出 D3 解禁字面清单。依据: 派单 A.2 引 446
  交接原文"**stub xmm 同步 Win64 ABI 面 371**——槽偏移公式按 x86 帧重核" +
  stub 注释自带的条件翻转句（"x86 运行时无 SSE handler，ctx.xmm 面未消费"——批迁
  后前提不成立）。x64 路径逐字未动（D2 恒等机器证明）。
- 其余解禁面（x86_translate.cpp 未触 / translator 限 Push 通路 / asmgen x86 表区 /
  runtime_x86.hpp 未触 / 测试样本脚本 docs）遵守。

## 挂账（交报后 x86 残面 = 3）

1. 间接 jmp（aebb 0xBAE3）——挂账维持（派单 B.4 显式排除）。
2. 栈深（mul64hi）——X5b 永久 gate。
3. Div/Idiv 族（b59b）——G8 D2 除零折叠维持，另单评估。
4. push-imm x64 扩面——证据不足不并批（D2/§F.3），挂 X6b。
5. Cvt/Sqrt/Unpck/Shuf 指令面——无 ir 载体无 VmOp（冻结枚举域内不存在），
   双 arch 同为 lifter 层 gate（以 x64 handler 表对账补集为准，不硬凑 mnemonic 全绿）。
