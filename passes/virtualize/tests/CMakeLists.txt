add_executable(wvmp_virtualize_tests test_virtualize.cpp)
target_link_libraries(wvmp_virtualize_tests PRIVATE
    wvmp_pass_virtualize
    wvmp_regvm_backend     # 取其 PUBLIC include（regvm_backend.hpp）
    # OBJECT 库经 OBJECT 库的传递链接不可靠：最终消费者直列全部 regvm 对象
    # （与 runtime/translator 测试同一模式）。
    wvmp_regvm_isa
    wvmp_regvm_translator
    wvmp_regvm_runtime
    # MIT-407: regvm_backend 编译期调用 PeImage::find_function_end_rva
    # (Pass wvmp_pass_pe_loader 提供). OBJECT 链不可靠, 显式列。
    wvmp_pass_pe_loader
    # MIT-491 (CR-03)：档位 + 加密选择器的跨 pass 回归需要 CryptPass 在场
    # （原始扫描序号漂移只能在真 VirtualizePass 压缩后的 kVmProgram 上复现）。
    wvmp_pass_crypt
    $<TARGET_OBJECTS:wvmp_pass_crypt>
    wvmp_pass_crypt_plan
    wvmp_regvm_codecs
    $<TARGET_OBJECTS:wvmp_regvm_codecs>
    wvmp::framework
    wvmp::ir
    wvmp::common
    wvmp::vm
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_virtualize_tests)
add_test(NAME virtualize_tests COMMAND wvmp_virtualize_tests)
