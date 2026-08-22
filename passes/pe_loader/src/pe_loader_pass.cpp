#include "wvmp/passes/pe_loader/pe_loader_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"

namespace wvmp::passes {

std::span<const std::string_view> PeLoaderPass::provides_keys() const {
    static constexpr std::string_view kProvides[] = {kImage};
    return kProvides;
}

void PeLoaderPass::run(ProtectionContext& /*ctx*/) {
    // TODO(pe_loader lane): read ctx.input_path into ctx.image, validate
    // DOS/NT headers, and stash parser metadata via ctx.slot<T>(key).
}

WVMP_REGISTER_PASS(PeLoaderPass)

} // namespace wvmp::passes
