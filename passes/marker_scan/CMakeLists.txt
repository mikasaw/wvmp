add_library(wvmp_pass_marker_scan OBJECT
    src/marker_scan_pass.cpp
    src/scan_core.cpp
)
target_include_directories(wvmp_pass_marker_scan PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
# M1：消费 pe_loader 的 PeImage（RVA 统一换算）——同聚合库内的 pass 间依赖。
target_link_libraries(wvmp_pass_marker_scan PRIVATE
    wvmp::framework
    wvmp::ir
    wvmp::common
    wvmp_pass_pe_loader
)
wvmp_target_warnings(wvmp_pass_marker_scan)

if(WVMP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
