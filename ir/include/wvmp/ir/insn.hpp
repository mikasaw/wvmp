#pragma once
#include "wvmp/ir/operand.hpp"
namespace wvmp::ir {
enum class Op : u16 { Mov, Lea, Add, Sub, Adc, Sbb, And, Or, Xor, Not, Neg, Inc, Dec,
                      Shl, Shr, Sar, Rol, Ror, Cmp, Test, Push, Pop, Jmp, Jcc, Call, Ret,
                      Load, Store, Nop,
                      // MIT-302: 有符号/无符号乘法。
                      // Imul 三形式（dst=Reg, src=Reg, src2=Imm 仅 3-op imm 形式）；
                      // Mul 单操作数（dst=Rdx 上半, src=Reg, Rax 下半硬编码）。
                      Imul, Mul };
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
