# RegVM 后端：VMBackend 契约实现 + 工厂注册（M2-1）。
add_library(wvmp_regvm_backend OBJECT
    src/regvm_backend.cpp
)
target_include_directories(wvmp_regvm_backend PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    # MIT-249 follow-up (issue-09): backend 检查 lifter 跳过的字节范围
    # (LiftMetadata), 需可见 lifter header。
    ${CMAKE_SOURCE_DIR}/passes/lifter/include
)
# OBJECT 直链各组件对象（OBJECT-as-SOURCES 不传播 usage requirements 的
# 老问题对编译期 include 路径同样成立，故显式列出全部依赖）。
target_link_libraries(wvmp_regvm_backend PUBLIC
    wvmp_regvm_isa
    wvmp_regvm_translator
    wvmp_regvm_runtime
    wvmp::vm
    wvmp::ir
    wvmp::common
)
wvmp_target_warnings(wvmp_regvm_backend)

if(WVMP_BUILD_TESTS)
    # MIT-380：LiftMetadata 按 begin_rva 匹配的多函数场景回归测试。
    add_subdirectory(tests)
endif()
