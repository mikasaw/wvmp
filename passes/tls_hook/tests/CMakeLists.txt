# MIT-465：tls_hook 单测（桩/数组/目录装配 + 原目录合并 + pe_writer 表项）。
add_executable(wvmp_tls_hook_tests
    test_tls_hook.cpp
)
target_link_libraries(wvmp_tls_hook_tests PRIVATE
    wvmp_pass_tls_hook
    $<TARGET_OBJECTS:wvmp_pass_tls_hook>
    wvmp_pass_tls_plan
    wvmp_pass_import_plan
    wvmp_pass_anti_debug_plan
    wvmp_pass_pe_loader
    wvmp_pass_pe_writer
    wvmp::framework
    wvmp::common
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_tls_hook_tests)
# tls_hook 对象引用 ks_*（keystone），OBJECT 私有链接不传播，测试行补齐。
if(TARGET wvmp::keystone)
    target_link_libraries(wvmp_tls_hook_tests PRIVATE wvmp::keystone)
endif()
add_test(NAME tls_hook_tests COMMAND wvmp_tls_hook_tests)
