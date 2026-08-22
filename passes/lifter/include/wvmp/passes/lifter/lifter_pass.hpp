#pragma once
#include "wvmp/framework/pass.hpp"

namespace wvmp::passes {

// Lifts each protected region from machine code to IR basic blocks
// (capstone-driven) and stores the result under key kLiftedIr.
// P0: interface placeholder; lifter lane implements it.
class LifterPass final : public Pass {
public:
    std::string_view name() const override { return "lifter"; }
    Phase phase() const override { return Phase::Analyze; }
    std::span<const std::string_view> requires_keys() const override;
    std::span<const std::string_view> provides_keys() const override;
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
