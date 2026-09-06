# P6 泳道测试：RWX 执行 + 语义验收（算术/别名/flags+jcc/循环/访存/栈/
# 现场保存）+ 多种子随机化重生成稳定性 + asm_dump 结构。
add_executable(wvmp_regvm_runtime_tests
    test_runtime.cpp
)
target_link_libraries(wvmp_regvm_runtime_tests PRIVATE
    wvmp_regvm_runtime
    wvmp_regvm_isa
    wvmp_regvm_codecs
    wvmp::vm
    wvmp::ir
    wvmp::common
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_regvm_runtime_tests)
add_test(NAME regvm_runtime_tests COMMAND wvmp_regvm_runtime_tests)

# MIT-443 (X3a)：x86 runtime 真执行电池 —— 仅 32 位工具链构建时注册。
# x86 码体不可在 64 位进程执行、x64 电池不可在 32 位进程跑（指针宽度门控
# 两层互斥）：x64 构建（build/）目标集合与 ctest 面零变化；x86 交叉构建经
# scripts\build_x86_tests.bat（vcvarsamd64_x86）到 build\x86，跑法
#   ctest --test-dir build\x86 -R x86_runtime_battery --output-on-failure
if(WVMP_WITH_CAPSTONE AND CMAKE_SIZEOF_VOID_P EQUAL 4)
    add_executable(wvmp_regvm_runtime_tests_x86
        test_runtime_x86.cpp
    )
    target_link_libraries(wvmp_regvm_runtime_tests_x86 PRIVATE
        wvmp_regvm_runtime
        wvmp_regvm_isa
        wvmp_regvm_codecs
        wvmp::vm
        wvmp::ir
        wvmp::common
        wvmp::capstone
        wvmp::gtest
        gtest_main
    )
    wvmp_target_warnings(wvmp_regvm_runtime_tests_x86)
    add_test(NAME x86_runtime_battery COMMAND wvmp_regvm_runtime_tests_x86)
endif()
