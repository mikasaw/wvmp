#pragma once
#include "wvmp/ir/arch.hpp"
#include "wvmp/ir/insn.hpp"
#include <string>
#include <vector>
namespace wvmp::ir {
struct BasicBlock { u64 addr = 0; std::vector<Insn> insns; std::vector<u64> succs, preds; };
struct FunctionRegion { std::string name; Arch arch = Arch::X64; u64 begin_rva = 0, end_rva = 0; std::vector<BasicBlock> blocks; };
}
