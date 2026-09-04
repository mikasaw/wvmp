# MIT-464：integrity_crc pass 单测（CRC32 已知向量 + plan 写入 + 篡改检测面）。
add_executable(wvmp_integrity_crc_tests
    test_integrity_crc.cpp
)
target_link_libraries(wvmp_integrity_crc_tests PRIVATE
    wvmp_pass_integrity_crc
    $<TARGET_OBJECTS:wvmp_pass_integrity_crc>
    wvmp_pass_crypt_plan
    wvmp_pass_crypt
    $<TARGET_OBJECTS:wvmp_pass_crypt>
    wvmp_pass_virtualize
    wvmp_regvm_codecs
    $<TARGET_OBJECTS:wvmp_regvm_codecs>
    wvmp_regvm_isa
    $<TARGET_OBJECTS:wvmp_regvm_isa>
    wvmp::framework
    wvmp::ir
    wvmp::common
    wvmp::vm
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_integrity_crc_tests)
add_test(NAME integrity_crc_tests COMMAND wvmp_integrity_crc_tests)
