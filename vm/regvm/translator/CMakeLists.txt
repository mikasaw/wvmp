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
    wvmp_regvm_runtime
    # MIT-451 (X5b) B.2：translator 栈深 walk 预算消费 runtime_x86.hpp 的
    # kX86GuardBytes（单一来源）——本链接仅为头路径传播（OBJECT 库对象文件
    # 由聚合器显式挂，注释见上）。
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
