#include "wvmp/passes/stub_link/stub_link_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"

namespace wvmp::passes {

std::span<const std::string_view> StubLinkPass::requires_keys() const {
    static constexpr std::string_view kRequires[] = {kVmProgram};
    return kRequires;
}

void StubLinkPass::run(ProtectionContext& /*ctx*/) {
    // TODO(stub_link lane): VMBackend::generate_runtime(...) -> kVmRuntime;
    // patch region entries to jump into the stub (keystone-assembled).
}

WVMP_REGISTER_PASS(StubLinkPass)

} // namespace wvmp::passes
