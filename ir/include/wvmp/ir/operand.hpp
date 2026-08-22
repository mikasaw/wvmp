#pragma once
#include "wvmp/ir/reg.hpp"
namespace wvmp::ir {
struct MemOperand { Reg base = Reg::Flags /*哨兵=无*/; Reg index = Reg::Flags; u8 scale = 0; i64 disp = 0; };
struct Operand {
    enum class Kind : u8 { None, Reg, Imm, Mem };
    Kind kind = Kind::None;
    Reg reg{};        // Kind::Reg
    i64 imm{};        // Kind::Imm
    MemOperand mem{}; // Kind::Mem
    static Operand none(); static Operand reg_(Reg r); static Operand imm_(i64 v); static Operand mem_(MemOperand m);
};
}
