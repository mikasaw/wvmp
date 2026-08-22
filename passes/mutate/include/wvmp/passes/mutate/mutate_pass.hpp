#pragma once
#include "wvmp/framework/pass.hpp"

namespace wvmp::passes {

// Optional IR-level mutation (obfuscation) applied before virtualization.
// P0: interface placeholder; mutate lane implements it.
class MutatePass final : public Pass {
public:
    std::string_view name() const override { return "mutate"; }
    Phase phase() const override { return Phase::Transform; }
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
