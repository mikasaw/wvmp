# RegVM translator: ir::Insn -> RegVM bytecode（翻译约定见 include/.../translator.hpp）。
add_library(wvmp_regvm_translator OBJECT
    src/translator.cpp
)
target_include_directories(wvmp_regvm_translator PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
# 注意：OBJECT 库经另一个 OBJECT/STATIC 库的链接行传不动对象文件，
# 聚合器 wvmp_regvm 与下方测试均显式挂 $<TARGET_OBJECTS:wvmp_regvm_isa>。
target_link_libraries(wvmp_regvm_translator PUBLIC
    wvmp_regvm_isa
    wvmp::vm
    wvmp::ir
    wvmp::common
)
wvmp_target_warnings(wvmp_regvm_translator)

if(WVMP_BUILD_TESTS)
    add_executable(wvmp_regvm_translator_tests tests/test_translator.cpp)
    target_link_libraries(wvmp_regvm_translator_tests PRIVATE
        wvmp_regvm_translator
        $<TARGET_OBJECTS:wvmp_regvm_isa>
        wvmp::vm
        wvmp::ir
        wvmp::common
        wvmp::gtest
        gtest_main
    )
    wvmp_target_warnings(wvmp_regvm_translator_tests)
    add_test(NAME regvm_translator_tests COMMAND wvmp_regvm_translator_tests)
endif()
