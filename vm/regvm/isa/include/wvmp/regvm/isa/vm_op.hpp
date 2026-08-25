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

    // —— MIT-301 cl 变体 shift ——
    // 计数源自 RCX 低 8 位（cl），而非 aux 立即数。lifter 接住 D3 /5（D3 /r）
    // 后用 Operand::Kind::Reg + Reg::Rcx 表示 src, 翻译器据此发射以下 5 个
    // VmOp（b_kind=OpKind::Reg, reg_b=RCX 槽）。运行时 handler 复用 build_shift
    // 逻辑——读 regs[RCX], 按宽度掩码（8/16 &31, 32/64 &63）, count=0 走 no-op
    // 出口不更新 flags, 其余走 native shift + setcc5 + writeback。ShlCl/ShrCl/
    // SarCl/RolCl/RorCl 与 Shl/Shr/Sar/Rol/Ror 编码一一对应, 调用 build_shift
    // 时仅 native op 不同（"shl"/"shr"/"sar"/"rol"/"ror"）。
    ShlCl, ShrCl, SarCl, RolCl, RorCl,

    // —— MIT-302 有符号/无符号乘法 ——
    // Imul 2-op reg 形式（dst = dst * src, native "imul <sz> reg_a, reg_b"）。
    // b_kind=OpKind::Reg, reg_b=src, aux=0, cond_or_size=size。
    // flags 语义同 native imul（CF/OF 当低半 != 高半时 set, SF/ZF/PF 按结果），
    // setcc5 直读 host CPU flags。
    // 3-op imm 形式（dst = src * imm）由翻译器拆为 mov_scratch + Imul(dst, scratch)
    // 两条：先 mov scratch, imm（VmOp::Mov w/ aux=imm32），再 Imul(dst, scratch)
    // 复用本 handler 的 2-op 路径——避免 native imul 第 3 操作数必须为静态立即数的
    // 硬限制（x86 imul r, r, imm 形式要求 imm 是汇编期常量，运行时不可)。
    Imul,
    // Mul 单操作数（unsigned rdx:rax = rax * src, native "mul <sz> reg_b"）。
    // reg_a 不参与（native mul 无显式 dst）；reg_b=src，隐式 RAX 作被乘数。
    // 运行时 handler 读 regs[Rax]，native mul 后将物理 rax/rdx 写回 regs[Rax]/regs[Rdx]。
    // flags 语义同 native mul（CF/OF 当低半 != 高半时 set）。
    Mul,
};

inline constexpr u16 kVmOpMax = static_cast<u16>(VmOp::Mul);
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
        case VmOp::ShlCl: return "shlcl";
        case VmOp::ShrCl: return "shrcl";
        case VmOp::SarCl: return "sarcl";
        case VmOp::RolCl: return "rolcl";
        case VmOp::RorCl: return "rorcl";
        case VmOp::Imul: return "imul";
        case VmOp::Mul: return "mul";
    }
    return "?";
}

} // namespace wvmp::regvm::isa
