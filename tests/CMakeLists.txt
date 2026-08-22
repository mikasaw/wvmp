if(NOT WVMP_BUILD_TESTS)
    return()
endif()

add_executable(wvmp_unit_tests
    unit/test_p0_smoke.cpp
)
target_link_libraries(wvmp_unit_tests PRIVATE
    wvmp::common
    wvmp::framework
    wvmp::ir
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_unit_tests)

add_test(NAME p0_smoke COMMAND wvmp_unit_tests)
