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
    // 契约 C-A2 规则 4（MIT-491 / CR-03）：本程序来源区域在
    // ProtectionContext.functions 里的**原始扫描序号**（VirtualizePass 用它
    // 档位查询的同一个 fn_index 赋值）。kVmProgram 是被档位/空块/gate 压缩过
    // 的列表，其下标不可用来解释配置里的 index —— 前置区域一旦被跳过就让后续
    // 规则整体错位。下游（CryptPass）经本字段回查原始序号。
    // 手工构造（未经 VirtualizePass）的条目保持 kNoSrcIndex = 不匹配任何
    // index 规则，宁可不豁免也不误豁免。
    static constexpr u64 kNoSrcIndex = ~u64{0};
    u64 src_index = kNoSrcIndex;
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
