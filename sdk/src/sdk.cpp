#include "wvmp/sdk/markers.hpp"

namespace wvmp::sdk {

// P0 placeholder: the real SDK surface (marker emission, runtime queries)
// is designed in the sdk lane.
int api_version() {
    return kApiVersion;
}

} // namespace wvmp::sdk
