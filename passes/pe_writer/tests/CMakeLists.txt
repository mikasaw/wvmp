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

# M2-2：新节追加（section_builder）。
add_executable(wvmp_section_builder_tests test_section_builder.cpp)
target_link_libraries(wvmp_section_builder_tests PRIVATE
    wvmp_pass_pe_writer
    wvmp_pass_pe_loader
    wvmp::framework
    wvmp::ir
    wvmp::common
    wvmp::gtest
    gtest_main
)
target_include_directories(wvmp_section_builder_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
wvmp_target_warnings(wvmp_section_builder_tests)
add_test(NAME section_builder_tests COMMAND wvmp_section_builder_tests)
