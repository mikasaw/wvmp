#include "wvmp/passes/pe_writer/pe_writer_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/registry.hpp"

namespace wvmp::passes {

std::span<const std::string_view> PeWriterPass::requires_keys() const {
    static constexpr std::string_view kRequires[] = {kImage};
    return kRequires;
}

void PeWriterPass::run(ProtectionContext& /*ctx*/) {
    // TODO(pe_writer lane): flush ctx.image (with kNewSections payloads and
    // fixups applied) to ctx.output_path.
}

WVMP_REGISTER_PASS(PeWriterPass)

} // namespace wvmp::passes
