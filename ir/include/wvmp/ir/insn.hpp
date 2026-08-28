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
                      Subss, Subps, Subpd };
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
