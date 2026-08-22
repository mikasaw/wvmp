#include "wvmp/passes/import_protect/import_protect_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/registry.hpp"

namespace wvmp::passes {

void ImportProtectPass::run(ProtectionContext& /*ctx*/) {
    // TODO(import_protect lane): rewrite the import directory to route
    // through the protection stub (obfuscated/lazy resolution).
}

WVMP_REGISTER_PASS(ImportProtectPass)

} // namespace wvmp::passes
