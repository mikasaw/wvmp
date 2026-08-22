add_library(wvmp_pass_anti_debug OBJECT
    src/anti_debug_pass.cpp
)
target_include_directories(wvmp_pass_anti_debug PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_pass_anti_debug PRIVATE wvmp::framework wvmp::ir wvmp::common)
wvmp_target_warnings(wvmp_pass_anti_debug)
