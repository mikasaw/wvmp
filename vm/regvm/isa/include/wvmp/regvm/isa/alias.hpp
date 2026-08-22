#pragma once
#include "wvmp/common/types.hpp"
#include "wvmp/ir/insn.hpp"

namespace wvmp::regvm::isa {

// x86-64 子寄存器读写语义（别名规则）——寄存器式 VM 正确性的最关键一环。
// 约定：VM 寄存器文件按 64 位存储"全寄存器"值，子寄存器访问经下面两个函数折叠。

// 读：低位截取并零扩展（读 al/ax/eax 一律零扩展到 64 位返回值）。
[[nodiscard]] u64 alias_read(u64 full, ir::Size size);

// 写：S8/S16 只替换低 8/16 位（高位保留）；S32 零扩展（x86-64 规则：写 32
// 位寄存器自动清零高 32 位）；S64 整体替换。
[[nodiscard]] u64 alias_write(u64 old, u64 val, ir::Size size);

} // namespace wvmp::regvm::isa
