# P6 泳道测试：RWX 执行 + 语义验收（算术/别名/flags+jcc/循环/访存/栈/
# 现场保存）+ 多种子随机化重生成稳定性 + asm_dump 结构。
add_executable(wvmp_regvm_runtime_tests
    test_runtime.cpp
)
target_link_libraries(wvmp_regvm_runtime_tests PRIVATE
    wvmp_regvm_runtime
    wvmp_regvm_isa
    wvmp::vm
    wvmp::ir
    wvmp::common
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_regvm_runtime_tests)
add_test(NAME regvm_runtime_tests COMMAND wvmp_regvm_runtime_tests)
