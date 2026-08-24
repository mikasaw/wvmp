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

    // —— M2-8 rip-relative 变种 ——
    // LoadRva/StoreRva 与 Load/Store 形态相同（a=Reg, b=Reg-地址），但
    // 运行时会**额外**加上 VmContext.scratch_mem（=image_base）来还原
    // RVA → VA. 用于翻译期把 [rip+disp] 转 RVA 的场景——RVA 与 image_base
    // 都是 32 位内值, 相加不溢出（PE ImageBase < 0x1'0000'0000 典型 < 0x8000'0000）.
    // Load/Store 不加 scratch_mem: 译码的地址已是绝对 VA（来自 host 寄存器
    // 拷贝 / 算术, 直接落地访存）。
    LoadRva, StoreRva,

    // —— M2-9 call gate ——
    // VM 字节码遇到 call 时由翻译器发出；运行时 handler 把 VM 上下文切到
    // native caller frame（Win64 ABI），调目标 RVA 处的 native 函数，callee
    // ret 后把 RAX 写回 regs[v0] 继续 dispatch。aux = 目标 RVA（u32）；
    // cond_or_size = arg_count（v1 仅支持 0；非零暂按 0 兜底并 diag warn）。
    // a_kind / b_kind / reg_a / reg_b 一律 None（gate 与 VM 操作数无关）。
    CallGate,
};

inline constexpr u16 kVmOpMax = static_cast<u16>(VmOp::CallGate);
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
        case VmOp::LoadRva: return "loadrva";
        case VmOp::StoreRva: return "storeriva";
        case VmOp::CallGate: return "callgate";
    }
    return "?";
}

} // namespace wvmp::regvm::isa
