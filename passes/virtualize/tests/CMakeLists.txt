add_executable(wvmp_virtualize_tests test_virtualize.cpp)
target_link_libraries(wvmp_virtualize_tests PRIVATE
    wvmp_pass_virtualize
    wvmp_regvm_backend     # 取其 PUBLIC include（regvm_backend.hpp）
    # OBJECT 库经 OBJECT 库的传递链接不可靠：最终消费者直列全部 regvm 对象
    # （与 runtime/translator 测试同一模式）。
    wvmp_regvm_isa
    wvmp_regvm_translator
    wvmp_regvm_runtime
    wvmp::framework
    wvmp::ir
    wvmp::common
    wvmp::vm
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_virtualize_tests)
add_test(NAME virtualize_tests COMMAND wvmp_virtualize_tests)
