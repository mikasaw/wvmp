# marker_scan 泳道测试：
#  1) wvmp_marker_sample —— 样例用户程序（静态链接 wvmp::sdk），作为
#     集成测试的真实扫描对象；
#  2) wvmp_marker_scan_tests —— scan_core 纯函数单元测试 + 真实 exe 的
#     pass 集成测试。

# —— 样例用户程序（测试夹具，不是交付物，不套 /W4 /WX）——
add_executable(wvmp_marker_sample sample_main.cpp)
target_link_libraries(wvmp_marker_sample PRIVATE wvmp::sdk)
# 固定 O0：/Ob0 关内联展开；MSVC 后写的 /Od 覆盖 Debug/Release 的优化级别，
# 保证 marker 调用保持 E8 call 形态（O2 尾调用 jmp 为 v1 已知 TODO）。
target_compile_options(wvmp_marker_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
# 关闭增量链接：Debug 默认 /INCREMENTAL 会把 call 引到 ILT thunk（E9 跳板），
# E8 目标不再落在桩窗口内，扫描必然失配。
target_link_options(wvmp_marker_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# —— gtest：单元 + 集成 ——
add_executable(wvmp_marker_scan_tests
    test_scan_core.cpp
    test_marker_scan_pass.cpp
)
target_link_libraries(wvmp_marker_scan_tests PRIVATE
    wvmp_pass_marker_scan # OBJECT 库：传播其 PUBLIC include 并链入对象
    wvmp_pass_pe_loader   # marker_scan 的 run() 消费 PeImage（offset_to_rva），对象需直链
    wvmp::framework
    wvmp::ir
    wvmp::common
    wvmp::sdk   # 仅为了 magic 常量同步性断言（含 sdk 契约头）
    wvmp::gtest
    gtest_main
)
target_compile_definitions(wvmp_marker_scan_tests PRIVATE
    WVMP_MARKER_SAMPLE_EXE="$<TARGET_FILE:wvmp_marker_sample>"
)
wvmp_target_warnings(wvmp_marker_scan_tests)

add_test(NAME marker_scan COMMAND wvmp_marker_scan_tests)

# M2-4：端到端虚拟化样例（区域仅含白名单指令）。
add_executable(wvmp_virt_sample virtual_sample_main.cpp)
target_link_libraries(wvmp_virt_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_virt_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_virt_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)

# MIT-243：端到端正路径样本——区域内**无 loop、无条件跳转、无 rip-relative**，
# 完全白名单直算，验证 C1 保守拦截未误杀可虚拟化区域。
add_executable(wvmp_whitelist_sample whitelist_sample_main.cpp)
target_link_libraries(wvmp_whitelist_sample PRIVATE wvmp::sdk)
target_compile_options(wvmp_whitelist_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/Od;/Ob0;/utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O0>
)
target_link_options(wvmp_whitelist_sample PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/INCREMENTAL:NO>
)
