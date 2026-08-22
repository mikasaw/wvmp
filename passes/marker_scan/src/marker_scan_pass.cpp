#include "wvmp/passes/marker_scan/marker_scan_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"

namespace wvmp::passes {

std::span<const std::string_view> MarkerScanPass::provides_keys() const {
    static constexpr std::string_view kProvides[] = {kFunctions};
    return kProvides;
}

void MarkerScanPass::run(ProtectionContext& /*ctx*/) {
    // TODO(marker_scan lane): locate SDK marker byte sequences in ctx.image
    // and populate ctx.functions (ir::FunctionRegion per protected region).
}

WVMP_REGISTER_PASS(MarkerScanPass)

} // namespace wvmp::passes
