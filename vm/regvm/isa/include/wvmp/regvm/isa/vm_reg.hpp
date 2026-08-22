#pragma once
#include "wvmp/common/types.hpp"
#include "wvmp/ir/reg.hpp"

namespace wvmp::regvm::isa {

// 32 个虚拟寄存器（5 位编码）。号位与 ir::Reg 枚举值严格对齐：
// ir::Rip==16、ir::Flags==17（见 ir/reg.hpp），故 v16=rip、v17=flags。
inline constexpr u8 kRegGprCount = 16;   // v0..v15 ↔ ir::Reg Rax..R15
inline constexpr u8 kRegRip = 16;        // = ir::Reg::Rip
inline constexpr u8 kRegFlags = 17;      // = ir::Reg::Flags，位布局见下
inline constexpr u8 kScratchFirst = 18;  // 翻译器地址计算临时寄存器
inline constexpr u8 kScratchCount = 6;   // v18..v23
inline constexpr u8 kRegCount = 32;      // v24..v31 保留
inline constexpr u8 kInvalidReg = 0xFF;

// ir::Reg ↔ VM 寄存器号：ir::Reg 值域 0..17 恰与 VM 号对齐（GP/Flags/Rip）。
constexpr u8 vm_reg_of(ir::Reg r) { return static_cast<u8>(r); }
constexpr ir::Reg ir_reg_of(u8 vm) { return static_cast<ir::Reg>(vm); }
constexpr bool is_valid_vm_reg(u8 r) { return r < kRegCount; }

// v16(flags) 的位布局（仅低 5 位有定义）。
inline constexpr u64 kFlagZF = 1ull << 0;
inline constexpr u64 kFlagCF = 1ull << 1;
inline constexpr u64 kFlagOF = 1ull << 2;
inline constexpr u64 kFlagSF = 1ull << 3;
inline constexpr u64 kFlagPF = 1ull << 4;
inline constexpr u64 kFlagsMask = kFlagZF | kFlagCF | kFlagOF | kFlagSF | kFlagPF;

} // namespace wvmp::regvm::isa
