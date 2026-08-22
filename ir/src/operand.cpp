#include "wvmp/ir/operand.hpp"

namespace wvmp::ir {

Operand Operand::none() {
    return Operand{};
}

Operand Operand::reg_(Reg r) {
    Operand o;
    o.kind = Kind::Reg;
    o.reg = r;
    return o;
}

Operand Operand::imm_(i64 v) {
    Operand o;
    o.kind = Kind::Imm;
    o.imm = v;
    return o;
}

Operand Operand::mem_(MemOperand m) {
    Operand o;
    o.kind = Kind::Mem;
    o.mem = m;
    return o;
}

} // namespace wvmp::ir
