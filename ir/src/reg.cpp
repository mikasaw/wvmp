#include "wvmp/ir/reg.hpp"

namespace wvmp::ir {

std::string_view to_string(Reg r) {
    switch (r) {
    case Reg::Rax: return "rax";
    case Reg::Rcx: return "rcx";
    case Reg::Rdx: return "rdx";
    case Reg::Rbx: return "rbx";
    case Reg::Rsp: return "rsp";
    case Reg::Rbp: return "rbp";
    case Reg::Rsi: return "rsi";
    case Reg::Rdi: return "rdi";
    case Reg::R8: return "r8";
    case Reg::R9: return "r9";
    case Reg::R10: return "r10";
    case Reg::R11: return "r11";
    case Reg::R12: return "r12";
    case Reg::R13: return "r13";
    case Reg::R14: return "r14";
    case Reg::R15: return "r15";
    case Reg::Rip: return "rip";
    case Reg::Flags: return "flags";
    case Reg::Count: break;
    }
    return "?";
}

} // namespace wvmp::ir
