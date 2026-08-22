#pragma once
#include "wvmp/framework/pass.hpp"

namespace wvmp::passes {

// Loads the input PE file into `ctx.image` and validates DOS/NT headers.
// P0: interface placeholder; implementation lands in the pe_loader lane.
class PeLoaderPass final : public Pass {
public:
    std::string_view name() const override { return "pe_loader"; }
    Phase phase() const override { return Phase::Load; }
    std::span<const std::string_view> provides_keys() const override;
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
