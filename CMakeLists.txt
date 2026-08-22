cmake_minimum_required(VERSION 3.24)

project(wvmp
    VERSION 0.1.0
    DESCRIPTION "WVmp - fully pluginized PE x86/x64 virtual-machine protector"
    LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(WVMP_BUILD_TESTS "Build the WVmp unit tests" ON)
option(WVMP_WITH_KEYSTONE "Fetch and build keystone 0.9.2 (assembler engine)" ON)

include(cmake/CompilerWarnings.cmake)
include(cmake/Dependencies.cmake)

enable_testing()

# -----------------------------------------------------------------------------
# Frozen module list. NEVER edit this file: all future work happens inside the
# existing subdirectories (see docs/ARCHITECTURE.md and docs/contracts.md).
# -----------------------------------------------------------------------------
add_subdirectory(common)     # wvmp_common
add_subdirectory(ir)         # wvmp_ir
add_subdirectory(framework)  # wvmp_framework
add_subdirectory(vm)         # wvmp_vm (contract) + wvmp_regvm (backend)
add_subdirectory(passes)     # wvmp_passes_all
add_subdirectory(sdk)        # wvmp_sdk
add_subdirectory(cli)        # wvmp_cli
add_subdirectory(tools)      # wvmp_tool
add_subdirectory(tests)      # wvmp_unit_tests
