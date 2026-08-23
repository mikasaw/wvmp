# M2-3：入口覆写 + .wvmp 节请求 + stub 结构。
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
# M2-3 新增依赖：virtualize 槽类型 / pe_loader 模型。
target_link_libraries(wvmp_pass_stub_link_tests PRIVATE
    wvmp_pass_virtualize
    wvmp_pass_pe_loader
)
# stub_gen.hpp（stub_link 内部工具头，测试直接包含）
target_include_directories(wvmp_pass_stub_link_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
