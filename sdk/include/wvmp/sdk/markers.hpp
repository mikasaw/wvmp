#pragma once

// WVmp protection markers for target applications.
//
// P0 placeholder: the macro names are reserved, the expansion is
// intentionally empty. The real byte-sequence emission contract lands with
// the sdk lane and must stay in sync with the marker_scan pass.

#define WVMP_BEGIN(name)
#define WVMP_END()

namespace wvmp::sdk {

inline constexpr int kApiVersion = 0;

// Non-inline anchor so the SDK always links as a real library.
int api_version();

} // namespace wvmp::sdk
