#include "wvmp/framework/pipeline.hpp"
#include "wvmp/framework/context.hpp"

namespace wvmp {

// P0 stubs: assembly, dependency validation and execution land in P1.

Pipeline Pipeline::from_names(const std::vector<std::string>& /*pass_names*/) {
    /* TODO(P1) */
    return {};
}

void Pipeline::validate() const { /* TODO(P1) */ }

void Pipeline::run(ProtectionContext& /*ctx*/) const { /* TODO(P1) */ }

const std::vector<Pass*>& Pipeline::stages() const {
    /* TODO(P1) */
    return stages_;
}

} // namespace wvmp
