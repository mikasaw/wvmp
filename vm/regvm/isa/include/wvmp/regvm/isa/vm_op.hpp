#pragma once
#include "wvmp/common/types.hpp"

namespace wvmp::regvm::isa {

// VM 操作码：与 ir::Op 一一同义（值从 1 起，0 为非法哨兵），外加 VM 专属操作。
// 编码空间上限 14 位（kVmOpLimit），当前仅用低 6 位。
enum class VmOp : u16 {
    Mov = 1, Lea, Add, Sub, Adc, Sbb, And, Or, Xor, Not, Neg, Inc, Dec,
    Shl, Shr, Sar, Rol, Ror, Cmp, Test, Push, Pop, Jmp, Jcc, Call, Ret,
    Load, Store, Nop,

    // —— VM 专属 ——
    Halt,       // 停机：解释器退出执行循环
    GetFlags,   // 读 v16(flags) 到 reg_a（S64 语义）
    SetFlags,   // 将 reg_a 低 5 位写入 v16(flags)
};

inline constexpr u16 kVmOpMax = static_cast<u16>(VmOp::SetFlags);
inline constexpr u16 kVmOpLimit = 1u << 14;  // 14 位编码空间上限

constexpr const char* to_string(VmOp op) {
    switch (op) {
        case VmOp::Mov: return "mov";   case VmOp::Lea: return "lea";
        case VmOp::Add: return "add";   case VmOp::Sub: return "sub";
        case VmOp::Adc: return "adc";   case VmOp::Sbb: return "sbb";
        case VmOp::And: return "and";   case VmOp::Or: return "or";
        case VmOp::Xor: return "xor";   case VmOp::Not: return "not";
        case VmOp::Neg: return "neg";   case VmOp::Inc: return "inc";
        case VmOp::Dec: return "dec";   case VmOp::Shl: return "shl";
        case VmOp::Shr: return "shr";   case VmOp::Sar: return "sar";
        case VmOp::Rol: return "rol";   case VmOp::Ror: return "ror";
        case VmOp::Cmp: return "cmp";   case VmOp::Test: return "test";
        case VmOp::Push: return "push"; case VmOp::Pop: return "pop";
        case VmOp::Jmp: return "jmp";   case VmOp::Jcc: return "jcc";
        case VmOp::Call: return "call"; case VmOp::Ret: return "ret";
        case VmOp::Load: return "load"; case VmOp::Store: return "store";
        case VmOp::Nop: return "nop";   case VmOp::Halt: return "halt";
        case VmOp::GetFlags: return "getflags";
        case VmOp::SetFlags: return "setflags";
    }
    return "?";
}

} // namespace wvmp::regvm::isa
