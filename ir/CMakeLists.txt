add_library(wvmp_ir
    src/insn.cpp
    src/operand.cpp
    src/reg.cpp
)
add_library(wvmp::ir ALIAS wvmp_ir)
target_include_directories(wvmp_ir PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_ir PUBLIC wvmp::common)
wvmp_target_warnings(wvmp_ir)
