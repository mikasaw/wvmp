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
