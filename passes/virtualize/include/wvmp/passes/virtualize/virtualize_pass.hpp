#pragma once
#include "wvmp/common/types.hpp"
#include "wvmp/framework/pass.hpp"
#include "wvmp/vm/backend.hpp"

#include <string>
#include <vector>

namespace wvmp::passes {

// kVmProgram 槽的元素类型：程序与其来源区域配对（stub_link 需要
// begin/end_rva 生成入口覆写与恢复跳转；名字用于诊断）。
struct VirtualizedFunction {
    std::string name;
    u64 begin_rva = 0;
    u64 end_rva = 0;
    vm::VmProgram program;
};

// Compiles protected regions to VM bytecode via wvmp::vm::create_backend and
// stores a vector<VirtualizedFunction> under key kVmProgram.
class VirtualizePass final : public Pass {
public:
    std::string_view name() const override { return "virtualize"; }
    Phase phase() const override { return Phase::Transform; }
    std::span<const std::string_view> requires_keys() const override;
    std::span<const std::string_view> provides_keys() const override;
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
