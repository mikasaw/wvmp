#include "wvmp/ir/insn.hpp"

namespace wvmp::ir {

std::string_view to_string(Op op) {
    switch (op) {
    case Op::Mov: return "mov";
    case Op::Lea: return "lea";
    case Op::Add: return "add";
    case Op::Sub: return "sub";
    case Op::Adc: return "adc";
    case Op::Sbb: return "sbb";
    case Op::And: return "and";
    case Op::Or: return "or";
    case Op::Xor: return "xor";
    case Op::Not: return "not";
    case Op::Neg: return "neg";
    case Op::Inc: return "inc";
    case Op::Dec: return "dec";
    case Op::Shl: return "shl";
    case Op::Shr: return "shr";
    case Op::Sar: return "sar";
    case Op::Rol: return "rol";
    case Op::Ror: return "ror";
    case Op::Cmp: return "cmp";
    case Op::Test: return "test";
    case Op::Push: return "push";
    case Op::Pop: return "pop";
    case Op::Jmp: return "jmp";
    case Op::Jcc: return "jcc";
    case Op::Call: return "call";
    case Op::Ret: return "ret";
    case Op::Load: return "load";
    case Op::Store: return "store";
    case Op::Nop: return "nop";
    case Op::Imul: return "imul";
    case Op::Mul: return "mul";
    case Op::Movsxd: return "movsxd";
    // MIT-315/MIT-333/MIT-334/MIT-336/MIT-339/MIT-341 新增 Op 的 to_string。
    // append-only 字符串（pitfall #34）；asm_dump / 日志可读性增强。原 insn.cpp
    // 此前漏了 Movzx/Bswap/Xchg/Setcc/Cmovcc — 此处一并补齐保持 to_string 完备。
    case Op::Movzx: return "movzx";
    case Op::Bswap: return "bswap";
    case Op::Xchg: return "xchg";
    case Op::Setcc: return "setcc";
    case Op::Cmovcc: return "cmovcc";
    case Op::Cmpxchg: return "cmpxchg";
    }
    return "?";
}

std::string_view to_string(Size size) {
    switch (size) {
    case Size::S8: return "s8";
    case Size::S16: return "s16";
    case Size::S32: return "s32";
    case Size::S64: return "s64";
    }
    return "?";
}

std::string_view to_string(Cond cond) {
    switch (cond) {
    case Cond::O: return "o";
    case Cond::No: return "no";
    case Cond::B: return "b";
    case Cond::Ae: return "ae";
    case Cond::E: return "e";
    case Cond::Ne: return "ne";
    case Cond::Be: return "be";
    case Cond::A: return "a";
    case Cond::S: return "s";
    case Cond::Ns: return "ns";
    case Cond::P: return "p";
    case Cond::Np: return "np";
    case Cond::L: return "l";
    case Cond::Ge: return "ge";
    case Cond::Le: return "le";
    case Cond::G: return "g";
    }
    return "?";
}

} // namespace wvmp::ir
