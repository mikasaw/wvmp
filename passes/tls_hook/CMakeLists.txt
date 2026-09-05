# tls_hook pass：TLS 回调基建（MIT-465，v1 占位回调 + 原目录合并）。
add_library(wvmp_pass_tls_hook OBJECT
    src/tls_hook_pass.cpp
)
target_include_directories(wvmp_pass_tls_hook PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_pass_tls_hook PRIVATE
    wvmp::framework
    wvmp::common
    wvmp_pass_pe_loader    # NewSection / PeImage 模型
    wvmp_pass_import_plan  # MIT-466: ImportPlan 契约头（INTERFACE，可选消费）
)
wvmp_target_warnings(wvmp_pass_tls_hook)

# keystone：回调桩汇编（与 regvm_runtime 同法：目标不传播头路径，显式补）。
if(TARGET wvmp::keystone)
    target_link_libraries(wvmp_pass_tls_hook PRIVATE wvmp::keystone)
    if(DEFINED keystone_SOURCE_DIR)
        target_include_directories(wvmp_pass_tls_hook PRIVATE
            $<BUILD_INTERFACE:${keystone_SOURCE_DIR}/include>)
    else()
        target_include_directories(wvmp_pass_tls_hook PRIVATE
            $<BUILD_INTERFACE:${WVMP_FETCHCONTENT_DIR}/keystone-src/include>)
    endif()
else()
    message(FATAL_ERROR "wvmp_pass_tls_hook requires keystone (configure with -DWVMP_WITH_KEYSTONE=ON)")
endif()

# tls_hook ↔ pe_writer 契约头（tls_plan.hpp）独立 INTERFACE 目标：
# pe_writer 只需要头，不吸 tls_hook 的 OBJECT（自注册丢弃教训规避）。
add_library(wvmp_pass_tls_plan INTERFACE)
target_include_directories(wvmp_pass_tls_plan INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

if(WVMP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
