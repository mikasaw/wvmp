#pragma once
#include "wvmp/framework/pass.hpp"

namespace wvmp::passes {

// Writes the protected image (`ctx.image`, including any new sections) to
// `ctx.output_path`. P0: interface placeholder; pe_writer lane implements it.
class PeWriterPass final : public Pass {
public:
    std::string_view name() const override { return "pe_writer"; }
    Phase phase() const override { return Phase::Write; }
    std::span<const std::string_view> requires_keys() const override;
    void run(ProtectionContext& ctx) override;
};

} // namespace wvmp::passes
