# RegVM runtime：保护期经 Keystone 生成位置无关 x64 解释器机器码（P6 泳道）。
add_library(wvmp_regvm_runtime OBJECT
    src/asmgen.cpp
)
target_include_directories(wvmp_regvm_runtime PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_regvm_runtime PUBLIC
    wvmp_regvm_isa   # VmOp/编码布局/别名契约（头 + 同 arch 对象）
    wvmp::vm         # RuntimeImage 契约头
    wvmp::common
    wvmp::ir
)

# keystone：运行时生成的核心依赖（WVMP_WITH_KEYSTONE=ON 时存在 wvmp::keystone）。
# 注意（CRT）：keystone 的 vendored LLVM 在 MSVC 上默认选静态 CRT（/MT），
# 与我们的 /MD(/MDd) 直接链接会触发 LNK2038（RuntimeLibrary 指令不匹配）。
# 正确解法是在配置期让 keystone 与主工程同 CRT：
#   -DLLVM_USE_CRT_DEBUG=MDd -DLLVM_USE_CRT_RELEASE=MD
# （keystone 的 ChooseMSVCCRT.cmake 会把它们写进其 CMAKE_CXX_FLAGS_<CONFIG>；
#  根 Dependencies.cmake 属协调者文件，集成时建议在其中固化这两个 cache 变量。）
# keystone 目标自身只做了 include_directories(目录级)，不传播头路径，
# 这里显式补上（FetchContent 源目录变量 keystone_SOURCE_DIR 由根目录设置）。
if(TARGET wvmp::keystone)
    target_link_libraries(wvmp_regvm_runtime PUBLIC wvmp::keystone)
    if(DEFINED keystone_SOURCE_DIR)
        target_include_directories(wvmp_regvm_runtime PUBLIC
            $<BUILD_INTERFACE:${keystone_SOURCE_DIR}/include>)
    else()
        target_include_directories(wvmp_regvm_runtime PUBLIC
            $<BUILD_INTERFACE:${WVMP_FETCHCONTENT_DIR}/keystone-src/include>)
    endif()
else()
    message(FATAL_ERROR "wvmp_regvm_runtime requires keystone (configure with -DWVMP_WITH_KEYSTONE=ON)")
endif()
wvmp_target_warnings(wvmp_regvm_runtime)

# --- 泳道测试 ---------------------------------------------------------------
if(WVMP_BUILD_TESTS AND TARGET wvmp::gtest)
    add_subdirectory(tests)
endif()
