add_library(wvmp_pass_pe_loader OBJECT
    src/pe_loader_pass.cpp
)
target_include_directories(wvmp_pass_pe_loader PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_pass_pe_loader PRIVATE wvmp::framework wvmp::ir wvmp::common)
wvmp_target_warnings(wvmp_pass_pe_loader)
