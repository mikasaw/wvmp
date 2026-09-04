# anti_debug pass：反调试检查注入（MIT-463 anti_debug-v1，PEB 面 + FailFast）。
add_library(wvmp_pass_anti_debug OBJECT
    src/anti_debug_pass.cpp
)
target_include_directories(wvmp_pass_anti_debug PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_pass_anti_debug PRIVATE wvmp::framework wvmp::ir wvmp::common)
wvmp_target_warnings(wvmp_pass_anti_debug)

# anti_debug ↔ stub_link 契约头（anti_debug_plan.hpp）独立 INTERFACE 目标：
# stub_link 只需要头，不吸 anti_debug 的 OBJECT（自注册丢弃教训规避）。
add_library(wvmp_pass_anti_debug_plan INTERFACE)
target_include_directories(wvmp_pass_anti_debug_plan INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

if(WVMP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
