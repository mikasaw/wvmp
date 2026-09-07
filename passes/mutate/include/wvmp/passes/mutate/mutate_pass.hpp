#pragma once
#include "wvmp/framework/pass.hpp"
#include "wvmp/ir/insn.hpp"
#include "wvmp/ir/region.hpp"

#include <vector>

namespace wvmp::passes {

// MIT-482 (T6.4) 测试面：块内边界死集计算（mutate_pass.cpp 匿名空间实现
// 的导出包装）。专测纯定义杀/use 标记序（def-kill 不得抹掉同指令的
// mem 基址/变址 use——kern.md5 野指针实录）。
std::vector<std::vector<ir::Reg>> dead_at_boundaries_for_test(
    const ir::BasicBlock& block, const std::vector<ir::Reg>& candidates,
    ir::Arch arch, const std::vector<char>& live_out);

// Optional IR-level mutation (obfuscation) applied before virtualization.
// P0: interface placeholder; mutate lane implements it.
class MutatePass final : public Pass {
public:
    std::string_view name() const override { return "mutate"; }
    Phase phase() const override { return Phase::Transform; }
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
