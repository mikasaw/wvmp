#pragma once
#include "wvmp/ir/arch.hpp"
#include "wvmp/ir/insn.hpp"
#include <string>
#include <vector>
namespace wvmp::ir {
struct BasicBlock { u64 addr = 0; std::vector<Insn> insns; std::vector<u64> succs, preds; };
struct FunctionRegion {
    std::string name;
    Arch arch = Arch::X64;
    u64 begin_rva = 0, end_rva = 0;
    std::vector<BasicBlock> blocks;
    // MIT-497 (T50, X5b 挂账落地): esp-resync 前瞻验证通过的出口目标 RVA 集。
    // lifter 填充（仅 X86；x64 budget=0 下 d≠0 出口不可达），translator 栈深
    // walk 规则 5 消费——d≠0 出口目标 ∈ 本集 = 延续代码以绝对恢复
    // （mov esp,ebp / leave）收口，出口物理 esp=ns 冻结协议下安全放行。
    std::vector<u64> resync_ok_exits;
};
}
