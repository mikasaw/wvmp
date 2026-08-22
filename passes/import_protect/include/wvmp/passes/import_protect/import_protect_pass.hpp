#pragma once
#include "wvmp/framework/pass.hpp"

namespace wvmp::passes {

// Obfuscates the import table (import redirection / lazy resolution).
// P0: interface placeholder; import_protect lane implements it.
class ImportProtectPass final : public Pass {
public:
    std::string_view name() const override { return "import_protect"; }
    Phase phase() const override { return Phase::Transform; }
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
