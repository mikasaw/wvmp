# RegVM bytecode codecs：BytecodeCodec 实现（MIT-458 起 xor_chain 落地，
# 替换占位 TU；后续 codec 并列新增——create_codec 工厂单一来源在本模块）。
add_library(wvmp_regvm_codecs OBJECT
    src/xor_chain.cpp
)
target_include_directories(wvmp_regvm_codecs PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_regvm_codecs PUBLIC
    wvmp::vm
    wvmp::common
)
wvmp_target_warnings(wvmp_regvm_codecs)

if(WVMP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
