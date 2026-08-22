#pragma once
#include "wvmp/common/types.hpp"
#include <string_view>
namespace wvmp::ir {
enum class Reg : u8 { Rax,Rcx,Rdx,Rbx,Rsp,Rbp,Rsi,Rdi,R8,R9,R10,R11,R12,R13,R14,R15,Rip,Flags,Count };
constexpr bool is_gpr(Reg r) { return r >= Reg::Rax && r <= Reg::R15; }
std::string_view to_string(Reg r); // "rax".."r15","rip","flags"
}
