add_library(wvmp_pass_import_protect OBJECT
    src/import_protect_pass.cpp
)
target_include_directories(wvmp_pass_import_protect PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_pass_import_protect PRIVATE wvmp::framework wvmp::ir wvmp::common)
wvmp_target_warnings(wvmp_pass_import_protect)
