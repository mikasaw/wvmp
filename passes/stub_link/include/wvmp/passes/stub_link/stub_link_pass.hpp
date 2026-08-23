#pragma once
#include "wvmp/framework/pass.hpp"

namespace wvmp::passes {

// Emits the VM runtime image (kVmRuntime) and links entry stubs into the
// protected image for each virtualized region.
// v1（P6）：生成解释器机器码并装配 [blob | runtime] 载荷；
// v2（M2）：add_section 注入 PE + 入口覆写 + gate。
class StubLinkPass final : public Pass {
public:
    std::string_view name() const override { return "stub_link"; }
    Phase phase() const override { return Phase::Emit; }
    std::span<const std::string_view> requires_keys() const override;
    std::span<const std::string_view> provides_keys() const override;
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
