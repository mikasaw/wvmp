# MIT-458：crypt pass 单测。INTERFACE 契约头 + codecs 对象（加密引用面）
# + virtualize 头（VirtualizedFunction）。
add_executable(wvmp_crypt_tests
    test_crypt_pass.cpp
)
target_link_libraries(wvmp_crypt_tests PRIVATE
    wvmp_pass_crypt
    $<TARGET_OBJECTS:wvmp_pass_crypt>
    wvmp_pass_crypt_plan
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
wvmp_target_warnings(wvmp_crypt_tests)
add_test(NAME crypt_tests COMMAND wvmp_crypt_tests)
