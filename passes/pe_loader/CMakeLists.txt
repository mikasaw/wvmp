add_library(wvmp_pass_pe_loader OBJECT
    src/pe_loader_pass.cpp
    src/pe_image.cpp
)
target_include_directories(wvmp_pass_pe_loader PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_pass_pe_loader PRIVATE wvmp::framework wvmp::ir wvmp::common)
wvmp_target_warnings(wvmp_pass_pe_loader)

# MIT-438 (X1b) B.5: wvmp_cli 需要本泳道的 target_arch.hpp（arch 声明槽的
# 值域常量），但 OBJECT 库被聚合成 wvmp_passes_all 后 usage requirements 不
# 传播，直接链 wvmp_pass_pe_loader 又会二次链入自注册对象——挂一个纯
# INTERFACE 面（零对象）给 CLI 消费 include。
add_library(wvmp_pe_loader_includes INTERFACE)
target_include_directories(wvmp_pe_loader_includes INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
add_library(wvmp::pe_loader_includes ALIAS wvmp_pe_loader_includes)

# --- lane tests --------------------------------------------------------------
if(WVMP_BUILD_TESTS AND TARGET wvmp::gtest)
    add_subdirectory(tests)
endif()
