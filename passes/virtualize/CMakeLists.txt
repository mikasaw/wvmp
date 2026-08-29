add_library(wvmp_pass_virtualize OBJECT
    src/virtualize_pass.cpp
)
target_include_directories(wvmp_pass_virtualize PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
# INTERFACE：OBJECT 库的 PRIVATE 依赖不会把对象传给消费者；virtualize 的
# 消费者（cli/测试）必须连带拿到 regvm 全部对象与 keystone 链接。
target_link_libraries(wvmp_pass_virtualize PRIVATE
    wvmp::framework
    wvmp::ir
    wvmp::common
    wvmp::vm
    wvmp_regvm_backend     # PRIVATE：取其（及其 PUBLIC 链上的）include 供本目标编译
)
target_link_libraries(wvmp_pass_virtualize INTERFACE
    wvmp_regvm_isa
    wvmp_regvm_translator
    wvmp_regvm_runtime
    wvmp_regvm_backend
    # MIT-407: regvm_backend 编译期经 lambda 引用 PeImage::find_function_end_rva
    # (OBJECT-as-SOURCES 不传播, 显式 INTERFACE 列, 保证 cli/测试链接时不
    # 出现 unresolved external)。
    wvmp_pass_pe_loader
)
wvmp_target_warnings(wvmp_pass_virtualize)

if(WVMP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
