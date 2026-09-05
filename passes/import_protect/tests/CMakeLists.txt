# MIT-466：import_protect 单测（合成导入面迁移 + 回退路径 + tls_hook 联动）。
add_executable(wvmp_import_protect_tests
    test_import_protect.cpp
)
target_link_libraries(wvmp_import_protect_tests PRIVATE
    wvmp_pass_import_protect
    $<TARGET_OBJECTS:wvmp_pass_import_protect>
    wvmp_pass_import_plan
    wvmp_pass_tls_hook
    $<TARGET_OBJECTS:wvmp_pass_tls_hook>
    wvmp_pass_tls_plan
    wvmp_pass_pe_loader
    wvmp::framework
    wvmp::common
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_import_protect_tests)
if(TARGET wvmp::keystone)
    target_link_libraries(wvmp_import_protect_tests PRIVATE wvmp::keystone)
endif()
add_test(NAME import_protect_tests COMMAND wvmp_import_protect_tests)
