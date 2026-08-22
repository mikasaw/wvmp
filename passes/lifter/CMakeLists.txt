# Lifter lane: capstone x86/x64 -> ir lifter.

add_library(wvmp_pass_lifter OBJECT
    src/lifter_pass.cpp
    src/capstone_session.cpp
    src/x86_translate.cpp
    src/lifter_core.cpp
    src/pe_map.cpp
)
target_include_directories(wvmp_pass_lifter PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_pass_lifter PRIVATE wvmp::framework wvmp::ir wvmp::common)

# capstone 仅在 WVMP_WITH_CAPSTONE=ON 时存在 wvmp::capstone 别名目标。
# lifter 是 kLiftedIr 的唯一产出者，没有 capstone 就无法工作。
#
# 注意：capstone 5.x 的 FetchContent 目标 `capstone` 本体是 OBJECT 库
# （其 CMakeLists 另提供 capstone_static STATIC 归档）。OBJECT 库经
# 另一个 OBJECT 库的 INTERFACE_LINK_LIBRARIES 传递时，对象文件不会
# 进入最终目标的链接行（只有 include 目录等 usage requirement 能传），
# 因此除别名外还需显式把 $<TARGET_OBJECTS:capstone> 挂到接口上。
if(TARGET wvmp::capstone)
    target_link_libraries(wvmp_pass_lifter PUBLIC wvmp::capstone)
    target_link_libraries(wvmp_pass_lifter INTERFACE
        $<BUILD_INTERFACE:$<TARGET_OBJECTS:capstone>>)
else()
    message(FATAL_ERROR "wvmp_pass_lifter requires capstone (set -DWVMP_WITH_CAPSTONE=ON)")
endif()
wvmp_target_warnings(wvmp_pass_lifter)

# --- lane tests --------------------------------------------------------------
if(WVMP_BUILD_TESTS AND TARGET wvmp::gtest)
    add_executable(wvmp_lifter_tests tests/test_lifter.cpp)
    # lifter 私有头（capstone_session / x86_translate / lifter_core / pe_map）。
    target_include_directories(wvmp_lifter_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(wvmp_lifter_tests PRIVATE
        wvmp_pass_lifter
        wvmp::framework
        wvmp::ir
        wvmp::common
        wvmp::gtest
        gtest_main
    )
    wvmp_target_warnings(wvmp_lifter_tests)
    add_test(NAME lifter_tests COMMAND wvmp_lifter_tests)
endif()
