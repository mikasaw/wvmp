# MIT-463：anti_debug pass 单测。
add_executable(wvmp_anti_debug_tests
    test_anti_debug_pass.cpp
)
target_link_libraries(wvmp_anti_debug_tests PRIVATE
    wvmp_pass_anti_debug
    $<TARGET_OBJECTS:wvmp_pass_anti_debug>
    wvmp_pass_anti_debug_plan
    wvmp::framework
    wvmp::ir
    wvmp::common
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_anti_debug_tests)
add_test(NAME anti_debug_tests COMMAND wvmp_anti_debug_tests)
