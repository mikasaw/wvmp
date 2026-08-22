#pragma once
#include "wvmp/framework/pass.hpp"

namespace wvmp::passes {

// Injects anti-debug/anti-analysis checks into the protected image.
// P0: interface placeholder; anti_debug lane implements it.
class AntiDebugPass final : public Pass {
public:
    std::string_view name() const override { return "anti_debug"; }
    Phase phase() const override { return Phase::Transform; }
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
