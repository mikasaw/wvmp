add_library(wvmp_pass_stub_link OBJECT
    src/stub_link_pass.cpp
)
target_include_directories(wvmp_pass_stub_link PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_pass_stub_link PRIVATE wvmp::framework wvmp::ir wvmp::common)

# v1 直连 regvm 运行时生成器（M2 经 vm::create_backend 解耦）。
# 链接形态注记：wvmp_regvm_runtime 是 OBJECT 库，其 usage requirements（含
# keystone）只在直接 target_link_libraries 消费时传播；经 $<TARGET_OBJECTS>
# 聚合进 wvmp_passes_all 的最终消费者（cli 等）需要在 passes/CMakeLists.txt
# 参照 capstone 的既有做法显式补挂 keystone（协调者文件，见 P6 报告）。
if(TARGET wvmp_regvm_runtime)
    target_link_libraries(wvmp_pass_stub_link PRIVATE
        wvmp_regvm_runtime
        wvmp_regvm_isa
        wvmp::vm
    )
else()
    message(FATAL_ERROR "wvmp_pass_stub_link requires the regvm runtime lane target")
endif()
wvmp_target_warnings(wvmp_pass_stub_link)

# --- 泳道测试 ---------------------------------------------------------------
if(WVMP_BUILD_TESTS AND TARGET wvmp::gtest)
    add_subdirectory(tests)
endif()
