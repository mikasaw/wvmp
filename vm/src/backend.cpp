#include "wvmp/vm/backend.hpp"

namespace wvmp::vm {

// P0 fallback: no backend is wired up yet. The regvm lane replaces this with
// the real factory (including its backend registry) once RegVM exists.
std::unique_ptr<VMBackend> create_backend(std::string_view /*name*/) {
    return nullptr;
}

} // namespace wvmp::vm
