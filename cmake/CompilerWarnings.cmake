# -----------------------------------------------------------------------------
# Warning policy for WVmp-owned targets.
#
# Project code compiles with /W4 /WX. Third-party dependencies fetched in
# cmake/Dependencies.cmake never call this function, so their warnings (and
# keystone's legacy LLVM sources in particular) can never break the build:
# strict warnings are per-target opt-in, never global.
# -----------------------------------------------------------------------------

function(wvmp_target_warnings target)
    if(MSVC)
        # /utf-8: sources contain UTF-8 comments (e.g. contract notes in
        # Chinese); without it MSVC on a GBK code page misparses them (C4819,
        # sometimes fatal C1071 inside comments).
        target_compile_options(${target} PRIVATE /W4 /WX /utf-8)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()
