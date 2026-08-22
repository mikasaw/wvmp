#pragma once
#include "wvmp/framework/pass.hpp"

namespace wvmp::passes {

// Emits the VM runtime image (kVmRuntime) and links entry stubs into the
// protected image for each virtualized region.
// P0: interface placeholder; stub_link lane implements it.
class StubLinkPass final : public Pass {
public:
    std::string_view name() const override { return "stub_link"; }
    Phase phase() const override { return Phase::Emit; }
    std::span<const std::string_view> requires_keys() const override;
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
