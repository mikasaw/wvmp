#include "wvmp/framework/registry.hpp"

namespace wvmp {

// P0 stubs: registration/lookup semantics land in P1. Only the singleton
// accessor is real (a Meyers singleton) so that early linkers get a stable,
// well-defined symbol instead of a dangling one.

PassRegistry& PassRegistry::instance() {
    /* TODO(P1) */
    static PassRegistry inst;
    return inst;
}

void PassRegistry::register_pass(std::unique_ptr<Pass> /*p*/) { /* TODO(P1) */ }

Pass* PassRegistry::find(std::string_view /*name*/) const { /* TODO(P1) */ return nullptr; }

std::vector<std::string_view> PassRegistry::names() const { /* TODO(P1) */ return {}; }

void PassRegistry::clear() { /* TODO(P1) */ }

PassRegistrar::PassRegistrar(std::unique_ptr<Pass> /*p*/) { /* TODO(P1) */ }

} // namespace wvmp
