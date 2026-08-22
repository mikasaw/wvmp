#include "wvmp/passes/lifter/lifter_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"

namespace wvmp::passes {

std::span<const std::string_view> LifterPass::requires_keys() const {
    static constexpr std::string_view kRequires[] = {kFunctions};
    return kRequires;
}

std::span<const std::string_view> LifterPass::provides_keys() const {
    static constexpr std::string_view kProvides[] = {kLiftedIr};
    return kProvides;
}

void LifterPass::run(ProtectionContext& /*ctx*/) {
    // TODO(lifter lane): disassemble ctx.functions with capstone and fill
    // ctx.slot<...>(kLiftedIr) with ir::FunctionRegion basic blocks.
}

WVMP_REGISTER_PASS(LifterPass)

} // namespace wvmp::passes
