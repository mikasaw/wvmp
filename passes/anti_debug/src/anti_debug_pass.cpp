#include "wvmp/passes/anti_debug/anti_debug_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/registry.hpp"

namespace wvmp::passes {

void AntiDebugPass::run(ProtectionContext& /*ctx*/) {
    // TODO(anti_debug lane): emit anti-debug checks (BeingDebugged, NtQuery,
    // timing, hardware breakpoints, ...) into the protected image/runtime.
}

WVMP_REGISTER_PASS(AntiDebugPass)

} // namespace wvmp::passes
