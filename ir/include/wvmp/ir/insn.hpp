#pragma once
#include "wvmp/ir/operand.hpp"
namespace wvmp::ir {
enum class Op : u16 { Mov, Lea, Add, Sub, Adc, Sbb, And, Or, Xor, Not, Neg, Inc, Dec,
                      Shl, Shr, Sar, Rol, Ror, Cmp, Test, Push, Pop, Jmp, Jcc, Call, Ret,
                      Load, Store, Nop };
enum class Size : u8 { S8, S16, S32, S64 };
enum class Cond : u8 { O, No, B, Ae, E, Ne, Be, A, S, Ns, P, Np, L, Ge, Le, G };
constexpr u64 bits(Size s) { return s==Size::S8?8: s==Size::S16?16: s==Size::S32?32:64; }
struct Insn {
    Op op = Op::Nop; Size size = Size::S32; Cond cond{};
    Operand dst, src;
    bool updates_flags = false;
    u64 addr = 0;
};
std::string_view to_string(Op); std::string_view to_string(Size); std::string_view to_string(Cond);
}
