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

# 验证 11 个 pass 的静态自注册链路（需要把 wvmp_passes_all 链进来）。
# MSVC 链接器会丢弃归档中未被引用的对象（自注册静态对象正属此类），
# 必须整包链接（WHOLE_ARCHIVE）。capstone 对象经 lifter 的 INTERFACE
# 单独走链接行，不会被重复打包。
add_executable(wvmp_pass_registration_tests
    unit/test_pass_registration.cpp
)
target_link_libraries(wvmp_pass_registration_tests PRIVATE
    "$<LINK_LIBRARY:WHOLE_ARCHIVE,wvmp_passes_all>"
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_pass_registration_tests)
add_test(NAME pass_registration COMMAND wvmp_pass_registration_tests)
