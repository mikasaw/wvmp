# VM layer: frozen backend contract (VMBackend / BytecodeCodec / create_backend).
# The single compiled TU is the documented nullptr fallback for create_backend,
# so early linkers of wvmp::vm never hit an unresolved symbol.
add_library(wvmp_vm
    src/backend.cpp
)
add_library(wvmp::vm ALIAS wvmp_vm)
target_include_directories(wvmp_vm PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_vm PUBLIC
    wvmp::framework
    wvmp::ir
    wvmp::common
)
wvmp_target_warnings(wvmp_vm)

add_subdirectory(regvm)
