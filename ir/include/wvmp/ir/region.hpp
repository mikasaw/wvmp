#pragma once
#include "wvmp/ir/arch.hpp"
#include "wvmp/ir/insn.hpp"
#include <string>
#include <utility>
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
    // MIT-500 (T54): callgate 清理约定表（<目标 RVA, ret imm 字节数>）。
    // lifter 对越区直接 call 的目标做有界终态扫描（callee_ret_imm）：callee
    // 全部终态 `ret imm` 一致 → 记 imm（imm>0 = stdcall 自清）；任何歧义/
    // 越界/含 call → 不入表（fail-closed，维持 cdecl 保守模型）。消费方 =
    // translator 两处：栈深 walk 在该 callgate 记 d -= imm（native esp 语义
    // 精确化）；translate_call 在 CallGate 词后合成 `Add Rsp, imm`（guest rsp
    // 槽真实推进，守卫区用量与模型恒对齐）。
    std::vector<std::pair<u64, u32>> callgate_cleanup;
};
}
