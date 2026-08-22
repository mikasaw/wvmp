# -----------------------------------------------------------------------------
# WVmp third-party dependencies (FetchContent; cached under <root>/.deps).
#
# Third-party targets never receive our /W4 /WX settings (see
# cmake/CompilerWarnings.cmake) and none of our global compile options leak
# into them beyond the C++ standard, which is explicitly lowered back to 14
# for keystone's vendored (pre-C++17) LLVM sources.
# -----------------------------------------------------------------------------

include(FetchContent)

# Parallel development lanes each configure their own build tree; giving them
# a per-tree FetchContent cache (via -DWVMP_FETCHCONTENT_DIR=...) keeps their
# populates from racing on the shared .deps directory. The tarball mirror
# directory (WVMP_DEPS_CACHE, below) still dedupes the actual downloads.
set(WVMP_FETCHCONTENT_DIR "${CMAKE_SOURCE_DIR}/.deps" CACHE PATH
    "FetchContent download/build cache (per build tree for parallel lanes)")
set(FETCHCONTENT_BASE_DIR "${WVMP_FETCHCONTENT_DIR}")

# Everything we consume is static; keeps the MSVC runtime story uniform.
set(BUILD_SHARED_LIBS OFF)

option(WVMP_WITH_CAPSTONE "Fetch and build capstone 5.0.6 (disassembler)" ON)

# Some networks block the TLS revocation endpoints that CMake's schannel-based
# curl insists on checking (CRYPT_E_NO_REVOCATION_CHECK), which breaks
# FetchContent downloads. WVMP_DEPS_CACHE (default: <workspace>/deps-cache,
# the sibling directory of the repository) allows using pre-downloaded
# archives; when a mirror file is absent the canonical GitHub URL is used, so
# CI and fresh checkouts keep working unchanged.
set(WVMP_DEPS_CACHE "${CMAKE_SOURCE_DIR}/../deps-cache" CACHE PATH
    "Optional directory with pre-downloaded dependency archives")

function(wvmp_dep_url out_var local_file github_url)
    if(EXISTS "${local_file}")
        set(${out_var} "${local_file}" PARENT_SCOPE)
    else()
        set(${out_var} "${github_url}" PARENT_SCOPE)
    endif()
endfunction()

# --- googletest 1.15.2 -------------------------------------------------------
if(WVMP_BUILD_TESTS)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    wvmp_dep_url(WVMP_GTEST_URL
        "${WVMP_DEPS_CACHE}/googletest-v1.15.2.tar.gz"
        "https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz")
    FetchContent_Declare(googletest URL ${WVMP_GTEST_URL})
    FetchContent_MakeAvailable(googletest)
    add_library(wvmp::gtest ALIAS gtest)
endif()

# --- capstone 5.0.6 (disassembler) -------------------------------------------
if(WVMP_WITH_CAPSTONE)
    set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
    wvmp_dep_url(WVMP_CAPSTONE_URL
        "${WVMP_DEPS_CACHE}/capstone-5.0.6.tar.gz"
        "https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.6.tar.gz")
    FetchContent_Declare(capstone URL ${WVMP_CAPSTONE_URL})
    FetchContent_MakeAvailable(capstone)
    add_library(wvmp::capstone ALIAS capstone)
endif()

# --- keystone 0.9.2 (assembler) ----------------------------------------------
if(WVMP_WITH_KEYSTONE)
    # Keystone's CMake scripts declare policy versions older than CMake 4 is
    # willing to emulate; lower the policy floor while configuring it and
    # restore the previous value afterwards.
    if(DEFINED CMAKE_POLICY_VERSION_MINIMUM)
        set(WVMP_SAVED_POLICY_MIN "${CMAKE_POLICY_VERSION_MINIMUM}")
    endif()
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

    # Build the X86 backend only (WVmp protects PE x86/x64); the full set of
    # architectures would multiply build time for no benefit.
    set(LLVM_TARGETS_TO_BUILD "X86" CACHE STRING "Keystone: LLVM targets to build" FORCE)
    set(LIB_ONLY ON CACHE BOOL "Keystone: build the library only (no kstool)" FORCE)

    # Its vendored LLVM predates C++17: std::unary_function/std::binary_function
    # were removed in C++17, so keystone must stay on C++14 (its native era).
    set(WVMP_SAVED_CXX_STANDARD "${CMAKE_CXX_STANDARD}")
    set(CMAKE_CXX_STANDARD 14)

    wvmp_dep_url(WVMP_KEYSTONE_URL
        "${WVMP_DEPS_CACHE}/keystone-0.9.2.tar.gz"
        "https://github.com/keystone-engine/keystone/archive/refs/tags/0.9.2.tar.gz")
    # CMP0051 OLD in keystone 0.9.2 is rejected by CMake >= 4; patch it to NEW
    # right after extraction (see cmake/PatchKeystone.cmake).
    FetchContent_Declare(keystone
        URL ${WVMP_KEYSTONE_URL}
        PATCH_COMMAND ${CMAKE_COMMAND} -P "${CMAKE_CURRENT_LIST_DIR}/PatchKeystone.cmake")
    FetchContent_MakeAvailable(keystone)

    set(CMAKE_CXX_STANDARD "${WVMP_SAVED_CXX_STANDARD}")
    if(DEFINED WVMP_SAVED_POLICY_MIN)
        set(CMAKE_POLICY_VERSION_MINIMUM "${WVMP_SAVED_POLICY_MIN}")
        unset(WVMP_SAVED_POLICY_MIN)
    else()
        unset(CMAKE_POLICY_VERSION_MINIMUM)
    endif()
    add_library(wvmp::keystone ALIAS keystone)
    # TODO(P2, regvm/stub_link lanes): keystone's vendored LLVM selects the
    # static CRT (/MT) on MSVC by default. Align runtimes (or isolate assembly
    # emission in a tool process) before linking wvmp::keystone into our /MD
    # targets.
endif()

# --- tomlplusplus 3.4.0 (config parsing; header-only INTERFACE) ---------------
set(TOMLPLUSPLUS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(TOMLPLUSPLUS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
wvmp_dep_url(WVMP_TOMLPLUSPLUS_URL
    "${WVMP_DEPS_CACHE}/tomlplusplus-v3.4.0.tar.gz"
    "https://github.com/marzer/tomlplusplus/archive/refs/tags/v3.4.0.tar.gz")
FetchContent_Declare(tomlplusplus URL ${WVMP_TOMLPLUSPLUS_URL})
FetchContent_MakeAvailable(tomlplusplus)
# v3.4.0 defines the real target as tomlplusplus_tomlplusplus (plus its own
# namespaced alias); mirror it under our wvmp:: namespace.
add_library(wvmp::tomlplusplus ALIAS tomlplusplus_tomlplusplus)
