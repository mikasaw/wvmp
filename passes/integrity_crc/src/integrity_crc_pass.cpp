#include "wvmp/passes/integrity_crc/integrity_crc_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/registry.hpp"

namespace wvmp::passes {

void IntegrityCrcPass::run(ProtectionContext& /*ctx*/) {
    // TODO(integrity_crc lane): compute digests over protected sections and
    // register verification data consumed by the runtime.
}

WVMP_REGISTER_PASS(IntegrityCrcPass)

} // namespace wvmp::passes
