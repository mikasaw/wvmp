#pragma once
#include "wvmp/ir/operand.hpp"
namespace wvmp::ir {
enum class Op : u16 { Mov, Lea, Add, Sub, Adc, Sbb, And, Or, Xor, Not, Neg, Inc, Dec,
                      Shl, Shr, Sar, Rol, Ror, Cmp, Test, Push, Pop, Jmp, Jcc, Call, Ret,
                      Load, Store, Nop,
                      // MIT-302: 有符号/无符号乘法。
                      // Imul 三形式（dst=Reg, src=Reg, src2=Imm 仅 3-op imm 形式）；
                      // Mul 单操作数（dst=Rdx 上半, src=Reg, Rax 下半硬编码）。
                      Imul, Mul,
                      // MIT-307: 32→64 位符号扩展（x64 专用）。
                      //   - REG-REG: src=Reg（含 32-bit 子寄存器折叠）, dst=Reg
                      //   - REG-MEM: src=Mem, dst=Reg（lifter 直接 emit Operand::mem_;
                      //              翻译器折 Load + Movsxd 或 MovsxdMem 一条）
                      // size 恒为 S64（movsxd 必 32→64），updates_flags=false
                      //（movsxd 不影响 CF/OF/SF/ZF/PF）。
                      Movsxd,
                      // MIT-315: 8→32/64 位零扩展（x64/x86 都支持）。
                      //   - REG-REG: src=Reg（含 8-bit 子寄存器折叠）, dst=Reg
                      //   - REG-MEM: src=Mem, dst=Reg（lifter 直接 emit Operand::mem_;
                      //              翻译器折 movzxMem）
                      // size 取目的位宽：8→32 为 S32, 8→64（REX.W）为 S64。
                      // src_size 取源位宽：0F B6 为 S8, 0F B7 为 S16（区分
                      // 8→32/16→32 等 asmgen 需 byte ptr vs word ptr 的场景）。
                      // updates_flags=false（movzx 不影响 CF/OF/SF/ZF/PF）。
                      Movzx,
                      // MIT-333: 字节序反转（bswap reg32/reg64）。
                      //   - REG only: src 空, dst=Reg, no mem 形式（bswap r/m 不存在）
                      //   - 字节结构：[48] (REX.W 可选) | 0F C8+rd（ModR/M 直接编码 dst reg）
                      //   - size 由 REX.W 决定：无 REX.W → S32, 有 REX.W → S64
                      //   - bswap 不影响 flags (updates_flags=false)
                      //   - x86 不存在 S8/S16 bswap, lifter 仅产 S32/S64, 翻译器
                      //     直产 VmOp::Bswap (1 操作数 dst only), 运行时 handler
                      //     按 cond_or_size 选 S32/S64 emit native bswap eax/rax.
                      // 32-bit 操作时 native bswap 自动 zero-extend 上 32 位（x86-64
                      // 32 位寄存器写语义），handler 用 qword 写回 vm 槽清零。
                      Bswap,
                      // MIT-334: 寄存器/内存交换 (xchg r, r / xchg r, m)。
                      //   - REG-REG 2 操作数 (dst + src), size 由 REX.W 决定 (S32/S64)
                      //   - 字节结构：[48] (REX.W 可选) | 87 (opcode) | ModR/M
                      //   - 特殊：`48 90` 是 xchg rax, rax 当 NOP, capstone 自动识别
                      //     为 X86_INS_NOP, lifter 走 X86_INS_NOP case emit ir::Op::Nop
                      //     (沿用现有 Nop Op, 不加新 enum)
                      //   - xchg 是对称操作: xchg a, b == xchg b, a (Intel SDM);
                      //     IR.dst 与 IR.src 编码为 VmOp::Xchg 的 a + b 槽
                      //   - xchg 不影响 flags (updates_flags=false)
                      //   - MEM 形式（xchg [reg], reg）派活单限定 REG-REG，
                      //     lifter 拒 MEM-REG → C1 gate 兜底
                      Xchg,
                      // MIT-336: 条件设置字节 (setcc r/m8, 16 variants: sete/setne/
                      // setb/setbe/seta/setae/sets/setns/setp/setnp/setl/setle/setg/
                      // setge/seto/setno)。
                      //   - 单操作数 (dst only, no src), size 恒为 S8 (r/m8, 1 字节固定)
                      //   - 字节结构：[0F] [90+cc] [ModR/M] (3 字节；mod=11 REG, mod=00 MEM)
                      //   - 条件码复用 ir::Cond（与 Jcc 同一枚举；16 variants 与 setcc 1:1 对应），
                      //     保 Insn.cond 字段（已有），lifter 走 X86_INS_SETE/SETNE/... 16 个 case
                      //     直接 map 到 ir::Cond
                      //   - setcc **read** flags (CF/OF/SF/ZF/PF), **write** r/m8 = 0/1, **不**改
                      //     flags（updates_flags=false, 与 test/cmp 的标志"产生"语义相反）
                      //   - MEM 形式 (setcc [reg]) lifter 直接 emit Operand::mem_(...); 翻译器
                      //     折 Load + Setcc (REG-REG 路径) 或 SetccMem (MEM 路径), 类似 movsxd/movzx
                      //   - 派活单 §D 决策 4: Setcc 必 append-only 在 Xchg=49 之后 = 50 (pitfall #34)
                      Setcc,
                      // MIT-339: 条件移动 (cmovcc r, r/m, 16 variants: cmovo/cmovno/
                      // cmovb/cmovae/cmove/cmovne/cmovbe/cmova/cmovs/cmovns/cmovp/
                      // cmovnp/cmovl/cmovge/cmovle/cmovg)。
                      //   - 2 操作数 (dst + src, src 可 REG 或 MEM)
                      //   - 字节结构：[48] (REX.W 可选) | 0F 40+cc | ModR/M (3 字节 REX.W;
                      //     3 字节无 REX.W; mod=11 REG-REG, mod=00 MEM)
                      //   - 条件码复用 ir::Cond（与 Jcc/Setcc 同一枚举；16 variants
                      //     与 cmovcc 1:1 对应），保 Insn.cond 字段（已有）
                      //   - cmovcc **read** flags (CF/OF/SF/ZF/PF) 决定是否赋值,
                      //     **不**改 flags（updates_flags=false, 与 setcc 同语义）
                      //   - size 由 REX.W 决定: 无 REX.W → S32, 有 REX.W → S64
                      //   - MEM 形式 (cmovcc [reg]) lifter 直接 emit Operand::mem_(...);
                      //     翻译器折 Load + Cmovcc (REG-REG 路径, src 用 [addr] 的值)
                      //     一条, 类似 movzx MEM 路径
                      //   - 派活单 §D 决策 4: Cmovcc 必 append-only 在 Setcc=50 之后 = 51
                      //     (pitfall #34 additive enum append-only)
                      Cmovcc,
                      // MIT-341: 比较并交换 (cmpxchg r/m, r, 隐式 rax/al 累加器)。
                      //   - 2 操作数 (dst=r/m + src=r, accumulator 隐式 Rax 槽)
                      //   - 字节结构：[48] (REX.W 可选) | 0F B0/B1+rm (mod=11 REG,
                      //     mod=00 MEM)；S8 用 0F B0, S16/S32/S64 用 0F B1
                      //   - size 字段：S8/S16/S32/S64 由 ModR/M 与 REX.W 共同决定
                      //   - 隐式 acc 字段（vm 寄存器槽 Reg::Rax, 不加新 IR 字段；
                      //     沿用 pitfall #34 additive enum append-only 严格不破坏
                      //     Insn 布局/大小；size 由 IR.size 决定，runtime 读 Rax 槽
                      //     即可知道宽度）。
                      //   - cmpxchg **read** Rax 槽 + dst, **write** dst 与 Rax 槽
                      //     （依 cmp 结果：equal→dst=src; not equal→Rax=dst），
                      //     同时 **write** flags (CF/OF/SF/ZF/PF 全更新，与 cmp 同
                      //     语义)；updates_flags=true。
                      //   - MEM 形式 (cmpxchg [m], r) lifter 直接 emit Operand::mem_
                      //     到 dst；翻译器折 Load(tmp, [m], size) + Cmpxchg(tmp, r)
                      //     + Store([m], tmp, size) 三条拆条（与 setcc MEM 路径同
                      //     结构）。派活单限定不支持 lock prefix 与 mod=01/10。
                      //   - 派活单 §D 决策 4: Cmpxchg 必 append-only 在 Cmovcc 之后
                      //     (pitfall #34 additive enum append-only)。
                      Cmpxchg,
                      // MIT-347: 8/16→32/64 位有符号扩展 (movsx r, r/m8 / r, r/m16)。
                      //   - REG-REG: src=Reg（含 8-bit 子寄存器折叠）, dst=Reg
                      //   - REG-MEM: src=Mem, dst=Reg（lifter 直接 emit Operand::mem_;
                      //              翻译器折 movsxMem）
                      //   - 字节结构：[48] (REX.W 可选) | 0F BE (opcode, 8 位源)
                      //              / 0F BF (16 位源) | ModR/M | 可选 SIB | 可选 disp
                      //   - 关键：movsx 本身完成 8/16 位 load + 符号扩展（不分两条 Load + SignExt）。
                      //     lifter 不拆分，emit Operand::mem_(...); 翻译器折 MovsxMem。
                      //   - size 取目的位宽（无 REX.W → S32, 有 REX.W → S64）。
                      //   - src_size 取源位宽：0F BE → S8, 0F BF → S16。
                      //   - updates_flags=false（movsx 不影响 CF/OF/SF/ZF/PF）。
                      //   - 派活单 §D 决策: Movsx 必 append-only 在 Cmpxchg 之后
                      //     (pitfall #34 additive enum append-only)；派活单限定不支
                      //     持 movsx r16, r/m16 (16→16 no-op, 编译器不 emit)。
                      Movsx,
                      // MIT-349: 比特计数 (popcnt r, r/m, SSE4.2)。
                      //   - REG-REG (mod=11): popcnt r, r
                      //     字节结构: [48] (REX.W 可选) | F3 0F B8 | ModR/M
                      //     (3 字节无 REX.W → S32; 4 字节 REX.W → S64)
                      //   - REG-MEM 派活单限定不支持 (沿用 movzx/movsx 限定风格,
                      //     完全不支持 MEM 不像 movzx/movsx 沿用 MovzxMem/MovsxMem
                      //     单独处理)
                      //   - size 由 REX.W 决定: 无 REX.W → S32, 有 REX.W → S64
                      //   - updates_flags=false (popcnt 不改 CF/OF/SF/ZF/PF;
                      //     SSE4.2 popcnt 仅设 ZF 根据结果 0/非0, lifter 不关心)
                      //   - 派活单 §D 决策 4: Popcnt 必 append-only 在 Movsx 之后
                      //     (pitfall #34 additive enum append-only)。
                      Popcnt,
                      // MIT-353: 前导零计数 (lzcnt r, r/m, BMI1)。
                      //   - REG-REG (mod=11): lzcnt r, r
                      //     字节结构: [48] (REX.W 可选) | F3 0F BD | ModR/M
                      //     (3 字节无 REX.W → S32; 4 字节 REX.W → S64)
                      //   - REG-MEM 派活单限定不支持 (沿用 popcnt 限定风格,
                      //     完全不支持 MEM, 不像 movzx/movsx 沿用 MovzxMem/MovsxMem
                      //     单独处理)
                      //   - size 由 REX.W 决定: 无 REX.W → S32, 有 REX.W → S64
                      //   - updates_flags=false (lzcnt 不改 CF/OF/SF/ZF/PF;
                      //     BMI1 lzcnt 仅设 ZF 根据结果 0/非0, lifter 不关心,
                      //     与 popcnt 派活单限定一致)
                      //   - src 不被修改 (lzcnt 是 dst = count_leading_zeros(src),
                      //     与 popcnt 派活单 "src 被消耗 in-place" 不同 —
                      //     asmgen handler 必 save src to T6 first, pitfall #37)
                      //   - 派活单 §D 决策 4: Lzcount 必 append-only 在 Popcnt 之后
                      //     (pitfall #34 additive enum append-only)。
                      Lzcount,
                      // MIT-353: 末尾零计数 (tzcnt r, r/m, BMI1)。
                      //   - REG-REG (mod=11): tzcnt r, r
                      //     字节结构: [48] (REX.W 可选) | F3 0F BC | ModR/M
                      //     (3 字节无 REX.W → S32; 4 字节 REX.W → S64)
                      //   - REG-MEM 派活单限定不支持 (沿用 popcnt 限定风格,
                      //     完全不支持 MEM)
                      //   - size 由 REX.W 决定: 无 REX.W → S32, 有 REX.W → S64
                      //   - updates_flags=false (tzcnt 不改 CF/OF/SF/ZF/PF;
                      //     BMI1 tzcnt 仅设 ZF 根据结果 0/非0, lifter 不关心,
                      //     与 popcnt 派活单限定一致)
                      //   - src 不被修改 (tzcnt 是 dst = count_trailing_zeros(src),
                      //     与 popcnt 派活单 "src 被消耗 in-place" 不同 —
                      //     asmgen handler 必 save src to T6 first, pitfall #37)
                      //   - 派活单 §D 决策 4: Tzcount 必 append-only 在 Lzcount 之后
                      //     (pitfall #34 additive enum append-only)。
                      Tzcount,
                      // MIT-371: SSE 浮点加 (addss / addps / addpd)。
                      //   - 字节结构 (REG-REG):
                      //       addss xmm1, xmm2/m32  F3 0F 58 /r  (scalar single)
                      //       addps xmm1, xmm2/m128 0F 58 /r     (packed single, 4 elem)
                      //       addpd xmm1, xmm2/m128 66 0F 58 /r  (packed double, 2 elem)
                      //   - REG-REG 派活单限定 (mod=11): xmm1 += xmm2 (3 形式)。
                      //     MEM 形式派活单限定不支持 (lifter 拒 MEM → C1 gate 兜底)。
                      //   - 操作数: dst=xmm1 (reg), src=xmm2 (reg) — IR.dst/src 编码 2 槽。
                      //   - 大小编码 (cond_or_size): 沿用 ir::Size 字段 —
                      //     Addss=S32 (scalar single), Addps=S64 (4xf32 packed,
                      //     对应 xmm 寄存器 128-bit 整体读), Addpd=S64 (2xf64)。
                      //     派活单 §D 决策: Addss/Addps/Addpd 必 append-only 在
                      //     Tzcount 之后 (pitfall #34 additive enum append-only)。
                      //   - updates_flags=false (SSE 浮点加不影响 x86 EFLAGS; MXCSR
                      //     rounding mode 在 v1 不追踪)。
                      Addss, Addps, Addpd,
                      // MIT-373: SSE 浮点减 (subss / subps / subpd)。
                      //   - 字节结构 (REG-REG):
                      //       subss xmm1, xmm2/m32  F3 0F 5C /r  (scalar single)
                      //       subps xmm1, xmm2/m128 0F 5C /r     (packed single, 4 elem)
                      //       subpd xmm1, xmm2/m128 66 0F 5C /r  (packed double, 2 elem)
                      //   - REG-REG 派活单限定 (mod=11): xmm1 -= xmm2 (3 形式)。
                      //     MEM 形式派活单限定不支持 (lifter 拒 MEM → C1 gate 兜底)。
                      //   - 操作数: dst=xmm1 (reg), src=xmm2 (reg) — IR.dst/src 编码 2 槽。
                      //   - 大小编码 (cond_or_size): 沿用 ir::Size 字段 —
                      //     Subss=S32 (scalar single), Subps=S64 (4xf32 packed,
                      //     对应 xmm 寄存器 128-bit 整体读), Subpd=S64 (2xf64)。
                      //     派活单 §D 决策: Subss/Subps/Subpd 必 append-only 在
                      //     Addss/Addps/Addpd 之后 (pitfall #34 additive enum append-only)。
                      //   - updates_flags=false (SSE 浮点减不影响 x86 EFLAGS; MXCSR
                      //     rounding mode 在 v1 不追踪)。
                      Subss, Subps, Subpd,
                      // MIT-374: SSE 浮点除 (divss / divps / divpd)。
                      //   - 字节结构 (REG-REG, capstone 5.0.7 实证):
                      //       divss xmm1, xmm2/m32  F3 0F 5E /r  (scalar single)
                      //       divps xmm1, xmm2/m128 0F 5E /r     (packed single, 4 elem)
                      //       divpd xmm1, xmm2/m128 66 0F 5E /r  (packed double, 2 elem)
                      //   - REG-REG 派活单限定 (mod=11): xmm1 /= xmm2 (3 形式)。
                      //     MEM 形式派活单限定不支持 (lifter 拒 MEM → C1 gate 兜底)。
                      //   - 操作数: dst=xmm1 (reg), src=xmm2 (reg) — IR.dst/src 编码 2 槽。
                      //   - 大小编码 (cond_or_size): 沿用 ir::Size 字段 —
                      //     Divss=S32 (scalar single), Divps=S64 (4xf32 packed,
                      //     对应 xmm 寄存器 128-bit 整体读), Divpd=S64 (2xf64)。
                      //     派活单 §D 决策: Divss/Divps/Divpd 必 append-only 在
                      //     Subss/Subps/Subpd 之后 (pitfall #34 additive enum append-only)。
                      //   - updates_flags=false (SSE 浮点除不影响 x86 EFLAGS; MXCSR
                      //     rounding mode 在 v1 不追踪; 除零/NaN 语义由 native
                      //     handler 内真 div* 指令保真, 与 MIT-371/373 同口径)。
                      Divss, Divps, Divpd,
                      // MIT-375: SSE 浮点传送 5 op (movss / movaps / movapd / movups / movupd)。
                      //   - load 方向 REG-REG (mod=11); store 方向与 MEM 形式 lifter 拒。
                      //   - updates_flags=false。
                      Movss, Movaps, Movapd, Movups, Movupd,
                      // MIT-376: SSE 浮点位运算 + 浮点比较 5 op
                      // (xorps / orps / andps / ucomiss / ucomisd)。
                      //   - 字节结构 (REG-REG, capstone 实证):
                      //       xorps xmm1, xmm2  0F 57 /r   (bitwise xor, 全 128-bit)
                      //       orps  xmm1, xmm2  0F 56 /r   (bitwise or,  全 128-bit)
                      //       andps xmm1, xmm2  0F 54 /r   (bitwise and, 全 128-bit)
                      //       ucomiss xmm1, xmm2 0F 2E /r  (标量单精度无序比较)
                      //       ucomisd xmm1, xmm2 66 0F 2E /r (标量双精度无序比较)
                      //   - REG-REG 派活单限定 (mod=11): dst=xmm1, src=xmm2 —
                      //     IR.dst/src 编码 2 槽 (借用 ir::Reg 0..7 = xmm0..7)。
                      //     MEM 形式派活单限定不支持 (lifter 拒 MEM → C1 gate 兜底)。
                      //   - 大小编码 (cond_or_size): 沿用 ir::Size 字段 —
                      //     Xorps/Orps/Andps=S64 (128-bit 整体读写), Ucomiss=S32
                      //     (scalar single), Ucomisd=S64 (scalar double)。
                      //   - updates_flags: 位运算 3 条=false (xorps/orps/andps 不影响
                      //     EFLAGS); ucomiss/ucomisd=**true** (真写 VM flags 槽 ZF/PF/CF,
                      //     沿用 setcc/jcc 的 flags 通路, 派活单 §D D1.1 决策 — 禁止
                      //     decode+advance 空转, pitfall #79; NaN → unordered →
                      //     ZF=PF=CF=1 按 Intel SDM UCOMISD/UCOMISS 真值表)。
                      //   - 派活单 §C 决策: 5 op 必 append-only 在 Movupd 之后、
                      //     enum 闭合之前 (pitfall #34 + MIT-375 v2 bug 教训)。
                      Xorps, Orps, Andps, Ucomiss, Ucomisd,
                      // MIT-404: 整数除法族 + 符号扩展 3 op (Cdq / Div / Idiv)。
                      //   - Cdq: 隐式 rax → rdx 符号扩展, 零显式操作数
                      //     (cdq=99 → S32; cqo=48 99 → S64)。cdqe (48 98) 不加
                      //     新 Op——lifter 归一到既有 Movsxd (D1.1 决策, dst=src=
                      //     Rax 槽, 语义 == movsxd rax,eax)。updates_flags=false
                      //     (Intel SDM: CDQ/CQO 不影响 EFLAGS)。
                      //   - Div/Idiv: 无符号/有符号除, 单显式操作数 = 除数
                      //     (src=Reg 或 Mem, MEM 由翻译器折 Load + Div/Idiv);
                      //     隐式 dividend = rdx:rax (S32: edx:eax) **不经 IR
                      //     表达**, dst=Rdx 槽 tag (对齐 Mul 约定), VM handler
                      //     内部从 Rax/Rdx 双槽拼装; 商写 Rax 槽、余写 Rdx 槽
                      //     (native 语义直通)。除零/商溢出 = 真 #DE, handler
                      //     native 直通 (D2.1 决策, 不做 VM 内拦截)。
                      //     size 取 S32/S64 (S8 dividend=AX 语义不符拒收 §F;
                      //     S16 需 0x66 prefix, translate_insn 入口已拒)。
                      //     updates_flags=true — flags 按 Intel undefined,
                      //     处置照抄 build_imul (setcc5 捕获同 CPU 真值)。
                      //   - 派活单 §B: 3 op 必 append-only 在 Ucomisd 之后、
                      //     enum 闭合之前 (pitfall #34 additive append-only)。
                      Cdq, Div, Idiv,

                      // MIT-506/507 (T60): x87 L0 族——物理 FPU 驻留直执行
                      // (架构定案 GAPS MIT-506: guest ST = 物理 st0-st7,
                      // handler 直发真实 x87 指令; kCtxSize 零触碰)。x86
                      // 专属 (x64 解释器不触 x87 词)。操作数约定:
                      //   - Mem 形 src=Mem (宽度 = size: S32/S64; tbyte 10B
                      //     经独立 op 承载); st(i) 形 dst=Reg(Rax 占位) +
                      //     src=Imm(栈位 i); Fst/Fstp/Fist 的 Reg 目标形
                      //     dst=Imm(i) 承载栈位。
                      //   - updates_flags 仅 Fcomi/Fcomip (物理 EFLAGS
                      //     ZF/PF/CF → ctx flags 捕获链, 同 Ucomiss 真写
                      //     通路); fnop 折 Op::Nop 零新 op。
                      //   - L1/L2/L3 全族 (fcom/ftst/fcmov/超越/状态控制/
                      //       env/save) 维持 gate 未收录。
                      //   - 派活单 §D 决策: 22 op 必 append-only 在 Idiv
                      //     之后、enum 闭合之前 (pitfall #34)。
                      Fld87Mem, Fld87St, Fld87Const,
                      Fst87Mem, Fstp87Mem, Fst87St, Fstp87St,
                      Fild87Mem, Fist87Mem, Fistp87Mem,
                      Fadd87, Fmul87, Fsub87, Fdiv87,
                      Fchs87, Fabs87, Fsqrt87,
                      Fcomi87, Fcomip87,
                      Fldcw87, Fnstcw87, Fnstsw87,

                      // MIT-510 (T62): x87 L1-L4 续延——同物理 FPU 驻留架构
                      // append-only 续批（kVmOpMax 141 ≥ 128 → 跳表 256 扩
                      // 容为本批前置，冻结契约允许的批量前置条款）。操作数
                      // 约定沿 L0：mem 形 a_kind=Reg(acc 槽) + aux 位图
                      // (bit0=pop / bit1=u 或 rev / bit2=dword / bit3=qword)；
                      // st(i) 形 b=Imm(reg_b=i)（Fld87St 词域惯例）或
                      // a=Imm 0 + b=Imm i；无域词全 None。FCOM 族只写 SW
                      // (C0/C2/C3) 不触 guest EFLAGS → flag_sem kNone；
                      // Fcmov87 读 guest EFLAGS → flag_sem kRead（MIT-474
                      // liveness 必须建模，否则前驱 Fcomi 写被死写消除）。
                      // L4 env/save 族（fldenv/fstenv/fsave/frstor）永久
                      // gate（内存块布局面，罕见），披露 vm_op.hpp。
                      Fcom87, Fcompp87, Ftst87, Fxam87, Fcmov87,
                      Fxch87, Ffree87, Fincdecstp87,
                      F2xm187, Fyl2x87, Fyl2xp187, Fscale87, Fpatan87,
                      Fprem87, Fsin87, Fcos87, Fsincos87, Fptan87,
                      Frndint87, Fxtract87,
                      Fnclex87, Fninit87,

                      // MIT-511 (T63): AVX 档B wave1 —— kCtxSize 冻结合同
                      // bump (0x1C8→0x3C8, ctx.ymm[16] 512B 面) + vzero
                      // ABI 词。x64 专属 (x86 架构 gate: MSVC x86 语料无
                      // VEX 发射面, 保持 gate 披露)；无操作数词，不写
                      // guest EFLAGS。
                      Vzeroupper, Vzeroall,

                      // MIT-512 (T64): AVX 档B wave2① —— ymm 数据通路。
                      // 寄存器编码沿用 SSE 惯例：IR.dst/src.reg 借用
                      // ir::Reg 值 0..7 代表 ymm0..7（翻译器 +24 映射到
                      // v24..31 槽位，VmOp 已含 ymm 域语义，无编码歧义）。
                      // ymm8..15 与 x86 架构维持 gate。混排一致性由
                      // virtualize 函数级 gate 保证（含 Ymm* 词的函数
                      // 不得含 legacy SSE 词，否则整函数原生）。
                      YmmMov, YmmLoad, YmmStore,

                      // MIT-513 (T65): wave2② —— VEX.256 packed
                      // 算术全谱 (命名/惯例同 T64; 可交换族 =
                      // add/mul/xor/or/and/p* 三地址 swap; sub/
                      // div/pandn 非交换 d==s2 gate)。
                      YmmAddps, YmmAddpd, YmmSubps, YmmSubpd, YmmMulps, YmmMulpd, YmmDivps, YmmDivpd, YmmXorps, YmmXorpd, YmmOrps, YmmOrpd, YmmAndps, YmmAndpd, YmmPxor, YmmPor, YmmPand, YmmPandn };
enum class Size : u8 { S8, S16, S32, S64 };
enum class Cond : u8 { O, No, B, Ae, E, Ne, Be, A, S, Ns, P, Np, L, Ge, Le, G };
constexpr u64 bits(Size s) { return s==Size::S8?8: s==Size::S16?16: s==Size::S32?32:64; }
struct Insn {
    Op op = Op::Nop; Size size = Size::S32; Cond cond{};
    Operand dst, src;
    // MIT-302: 第三个操作数。仅 imul 3-op imm 形式用 (src2 = Operand::imm_(imm32))。
    // 默认空 Operand 不破坏既有指令的语义/布局——append 字段，sizeof(Insn) 增大，
    // 但所有现存构造路径不读 src2，结果不变。
    Operand src2;
    bool updates_flags = false;
    u64 addr = 0;
    // MIT-345: 源操作数宽度（仅 Movzx 用）。0F B6 → S8, 0F B7 → S16。
    // 默认 S8 兼容既有构造路径；movzx asmgen 据此选 byte ptr vs word ptr 读 src。
    Size src_size = Size::S8;
};
std::string_view to_string(Op); std::string_view to_string(Size); std::string_view to_string(Cond);
}
