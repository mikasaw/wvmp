# stub_link 泳道测试：空 slot 告警路径 + 伪 program 的载荷产出与端到端执行。
add_executable(wvmp_pass_stub_link_tests
    test_stub_link.cpp
)
target_link_libraries(wvmp_pass_stub_link_tests PRIVATE
    wvmp_pass_stub_link
    wvmp_regvm_runtime
    wvmp_regvm_isa
    wvmp::vm
    wvmp::ir
    wvmp::framework
    wvmp::common
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_pass_stub_link_tests)
add_test(NAME stub_link_tests COMMAND wvmp_pass_stub_link_tests)
