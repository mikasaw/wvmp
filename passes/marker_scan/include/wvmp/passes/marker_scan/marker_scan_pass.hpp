#pragma once
#include "wvmp/framework/pass.hpp"

namespace wvmp::passes {

// Scans the loaded image for protection markers (SDK-emitted) and produces
// the protected regions `ctx.functions`.
// P0: interface placeholder; marker_scan lane implements it.
class MarkerScanPass final : public Pass {
public:
    std::string_view name() const override { return "marker_scan"; }
    Phase phase() const override { return Phase::Analyze; }
    std::span<const std::string_view> requires_keys() const override;
    std::span<const std::string_view> provides_keys() const override;
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
