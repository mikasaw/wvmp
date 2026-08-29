# MIT-380：regvm 后端单元测试 —— LiftMetadata 按 begin_rva 匹配。
# 本目录仅在 WVMP_BUILD_TESTS 时经上层 add_subdirectory 进入。
add_executable(wvmp_regvm_backend_tests
    test_regvm_backend_metadata.cpp
)
# OBJECT 库的 PRIVATE 链接只传播 usage requirements 不携带对象文件（见
# 上层 CMakeLists 注释）：plain link 拿 include 路径（含 lifter 的
# lift_metadata.hpp），TARGET_OBJECTS 把后端 / 翻译器 / 运行时 / isa 对象
# 实际挂进链接行，同聚合库 wvmp_regvm 的做法。
target_link_libraries(wvmp_regvm_backend_tests PRIVATE
    wvmp_regvm_backend
    $<TARGET_OBJECTS:wvmp_regvm_backend>
    $<TARGET_OBJECTS:wvmp_regvm_translator>
    $<TARGET_OBJECTS:wvmp_regvm_runtime>
    $<TARGET_OBJECTS:wvmp_regvm_isa>
    $<TARGET_OBJECTS:wvmp_pass_pe_loader>
    wvmp::vm
    wvmp::ir
    wvmp::common
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_regvm_backend_tests)
add_test(NAME regvm_backend_tests COMMAND wvmp_regvm_backend_tests)
