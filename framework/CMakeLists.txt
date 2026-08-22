add_library(wvmp_framework
    src/pipeline.cpp
    src/registry.cpp
)
add_library(wvmp::framework ALIAS wvmp_framework)
target_include_directories(wvmp_framework PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_framework PUBLIC
    wvmp::ir
    wvmp::common
)
wvmp_target_warnings(wvmp_framework)
