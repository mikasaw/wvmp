# MIT-459：mutate pass 单测。
add_executable(wvmp_mutate_tests
    test_mutate.cpp
)
target_link_libraries(wvmp_mutate_tests PRIVATE
    wvmp_pass_mutate
    $<TARGET_OBJECTS:wvmp_pass_mutate>
    wvmp::framework
    wvmp::ir
    wvmp::common
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_mutate_tests)
add_test(NAME mutate_tests COMMAND wvmp_mutate_tests)
