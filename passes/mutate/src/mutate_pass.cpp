#include "wvmp/passes/mutate/mutate_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/registry.hpp"

namespace wvmp::passes {

void MutatePass::run(ProtectionContext& /*ctx*/) {
    // TODO(mutate lane): rewrite the lifted IR (dead code, substitutions,
    // bogus control flow) deterministically from ctx.seed.
}

WVMP_REGISTER_PASS(MutatePass)

} // namespace wvmp::passes
