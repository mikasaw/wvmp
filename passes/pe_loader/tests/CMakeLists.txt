# pe_loader 泳道测试：手工拼装的最小合法 PE 的解析/映射单元测试 +
# pass 级（文件 IO / 校验失败路径）测试。

add_executable(wvmp_pe_loader_tests test_pe_loader.cpp)
target_link_libraries(wvmp_pe_loader_tests PRIVATE
    wvmp_pass_pe_loader # OBJECT 库：传播其 PUBLIC include 并链入对象
    wvmp::framework
    wvmp::ir
    wvmp::common
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_pe_loader_tests)

add_test(NAME pe_loader_tests COMMAND wvmp_pe_loader_tests)
