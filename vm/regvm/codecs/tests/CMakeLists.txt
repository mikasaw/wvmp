# MIT-458：xor_chain codec 单测。本目录仅在 WVMP_BUILD_TESTS 时经上层
# add_subdirectory 进入。
add_executable(wvmp_regvm_codec_tests
    test_xor_chain.cpp
)
target_link_libraries(wvmp_regvm_codec_tests PRIVATE
    wvmp_regvm_codecs
    $<TARGET_OBJECTS:wvmp_regvm_codecs>
    wvmp::vm
    wvmp::common
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_regvm_codec_tests)
add_test(NAME regvm_codec_tests COMMAND wvmp_regvm_codec_tests)
