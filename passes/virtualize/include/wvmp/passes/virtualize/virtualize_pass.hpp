#pragma once
#include "wvmp/framework/pass.hpp"

namespace wvmp::passes {

// Compiles protected regions to VM bytecode via wvmp::vm::create_backend and
// stores the program under key kVmProgram.
// P0: interface placeholder; virtualize lane implements it.
class VirtualizePass final : public Pass {
public:
    std::string_view name() const override { return "virtualize"; }
    Phase phase() const override { return Phase::Transform; }
    std::span<const std::string_view> requires_keys() const override;
    std::span<const std::string_view> provides_keys() const override;
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
