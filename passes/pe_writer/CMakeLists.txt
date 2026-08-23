add_library(wvmp_pass_pe_writer OBJECT
    src/pe_writer_pass.cpp
    src/pe_checksum.cpp
    src/section_builder.cpp
)
target_include_directories(wvmp_pass_pe_writer PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_include_directories(wvmp_pass_pe_writer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src # pe_checksum.hpp / section_builder.hpp（内部工具头）
)
# 同泳道跨 pass 依赖：复用 pe_loader 的 PeImage 模型与解析（pe_image.hpp）。
target_link_libraries(wvmp_pass_pe_writer PRIVATE
    wvmp::framework
    wvmp::ir
    wvmp::common
    wvmp_pass_pe_loader
)
wvmp_target_warnings(wvmp_pass_pe_writer)

# --- lane tests --------------------------------------------------------------
if(WVMP_BUILD_TESTS AND TARGET wvmp::gtest)
    add_subdirectory(tests)
endif()
