# pe_writer 泳道测试：checksum 算法已知向量 + 写出/幂等 + 系统 PE
# （notepad x64/x86）loader→writer 逐字节往返。

add_executable(wvmp_pe_writer_tests test_pe_writer.cpp)
target_link_libraries(wvmp_pe_writer_tests PRIVATE
    wvmp_pass_pe_writer
    wvmp_pass_pe_loader # PeLoaderPass（往返测试的前级）
    wvmp::framework
    wvmp::ir
    wvmp::common
    wvmp::gtest
    gtest_main
)
# pe_checksum.hpp（pe_writer 内部工具头，单元测试直接包含）
target_include_directories(wvmp_pe_writer_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
wvmp_target_warnings(wvmp_pe_writer_tests)

add_test(NAME pe_writer_tests COMMAND wvmp_pe_writer_tests)
