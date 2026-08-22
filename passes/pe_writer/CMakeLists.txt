add_library(wvmp_pass_pe_writer OBJECT
    src/pe_writer_pass.cpp
)
target_include_directories(wvmp_pass_pe_writer PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_pass_pe_writer PRIVATE wvmp::framework wvmp::ir wvmp::common)
wvmp_target_warnings(wvmp_pass_pe_writer)
