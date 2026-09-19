# MIT-465：tls_hook 单测（桩/数组/目录装配 + 原目录合并 + pe_writer 表项）。
add_executable(wvmp_tls_hook_tests
    test_tls_hook.cpp
)
target_link_libraries(wvmp_tls_hook_tests PRIVATE
    wvmp_pass_tls_hook
    $<TARGET_OBJECTS:wvmp_pass_tls_hook>
    wvmp_pass_tls_plan
    wvmp_pass_import_plan
    wvmp_pass_anti_debug_plan
    wvmp_pass_pe_loader
    wvmp_pass_pe_writer
    wvmp::framework
    wvmp::common
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_tls_hook_tests)
# tls_hook 对象引用 ks_*（keystone），OBJECT 私有链接不传播，测试行补齐。
if(TARGET wvmp::keystone)
    target_link_libraries(wvmp_tls_hook_tests PRIVATE wvmp::keystone)
endif()
add_test(NAME tls_hook_tests COMMAND wvmp_tls_hook_tests)

# MIT-526 (CR-04)：x64 TLS 回调 ABI 真执行反证。探针 = 独立 exe（把 tls_hook
# 产出的回调桩镜像进 RWX 内存真跳进去，被调侧写脏 4 个 home slot）；修前的
# 失败形态是回飞 AV，asm 帧无 unwind 信息 ⇒ 只能在子进程里观测退出码，故
# gtest 侧只做"spawn + 读 readings + 断言物理量"。
add_executable(wvmp_tls_abi_probe
    tls_abi_probe.cpp
)
target_link_libraries(wvmp_tls_abi_probe PRIVATE
    wvmp_pass_tls_hook
    $<TARGET_OBJECTS:wvmp_pass_tls_hook>
    wvmp_pass_tls_plan
    wvmp_pass_import_plan
    wvmp_pass_anti_debug_plan
    wvmp_pass_pe_loader
    wvmp::framework
    wvmp::common
    wvmp::keystone
)
wvmp_target_warnings(wvmp_tls_abi_probe)
if(DEFINED keystone_SOURCE_DIR)
    target_include_directories(wvmp_tls_abi_probe PRIVATE
        $<BUILD_INTERFACE:${keystone_SOURCE_DIR}/include>)
else()
    target_include_directories(wvmp_tls_abi_probe PRIVATE
        $<BUILD_INTERFACE:${WVMP_FETCHCONTENT_DIR}/keystone-src/include>)
endif()

add_executable(wvmp_tls_abi_exec_tests
    test_tls_abi_exec.cpp
)
target_link_libraries(wvmp_tls_abi_exec_tests PRIVATE
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_tls_abi_exec_tests)
add_dependencies(wvmp_tls_abi_exec_tests wvmp_tls_abi_probe)
add_test(NAME tls_abi_exec_tests COMMAND wvmp_tls_abi_exec_tests)

# MIT-527 (CR-05)：x64 rdtsc 计时面「注入时间戳」真执行反证。探针 = 独立 exe
# （真实发射的回调桩镜像进 RWX，两处 rdtsc 指令等长换成 int3+nop，VEH 在断点
# 现场写 EDX:EAX 当返回值；判定比较处用 TF 单步从真机上下文读回代码算出的差值）。
# 超时判定 = 撞 FailFast 写零红线（asm 帧无 unwind 信息）⇒ 只能子进程观测退出码
# + readings，gtest 侧只做 spawn + 断言物理量。
add_executable(wvmp_rdtsc_wrap_probe
    rdtsc_wrap_probe.cpp
)
target_link_libraries(wvmp_rdtsc_wrap_probe PRIVATE
    wvmp_pass_tls_hook
    $<TARGET_OBJECTS:wvmp_pass_tls_hook>
    wvmp_pass_tls_plan
    wvmp_pass_anti_debug_plan
    wvmp_pass_pe_loader
    wvmp::framework
    wvmp::common
    wvmp::keystone
)
wvmp_target_warnings(wvmp_rdtsc_wrap_probe)

add_executable(wvmp_rdtsc_wrap_tests
    test_rdtsc_wrap.cpp
)
target_link_libraries(wvmp_rdtsc_wrap_tests PRIVATE
    wvmp::gtest
    gtest_main
)
wvmp_target_warnings(wvmp_rdtsc_wrap_tests)
add_dependencies(wvmp_rdtsc_wrap_tests wvmp_rdtsc_wrap_probe)
add_test(NAME rdtsc_wrap_tests COMMAND wvmp_rdtsc_wrap_tests)
