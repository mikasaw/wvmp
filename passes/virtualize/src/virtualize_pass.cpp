#include "wvmp/passes/virtualize/virtualize_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"

namespace wvmp::passes {

std::span<const std::string_view> VirtualizePass::requires_keys() const {
    static constexpr std::string_view kRequires[] = {kLiftedIr};
    return kRequires;
}

std::span<const std::string_view> VirtualizePass::provides_keys() const {
    static constexpr std::string_view kProvides[] = {kVmProgram};
    return kProvides;
}

void VirtualizePass::run(ProtectionContext& /*ctx*/) {
    // TODO(virtualize lane): for each lifted region, call
    // wvmp::vm::create_backend(...)->compile(...) and collect the VmProgram
    // under ctx.slot<...>(kVmProgram).
}

WVMP_REGISTER_PASS(VirtualizePass)

} // namespace wvmp::passes
