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
                      Xchg };
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
};
std::string_view to_string(Op); std::string_view to_string(Size); std::string_view to_string(Cond);
}
