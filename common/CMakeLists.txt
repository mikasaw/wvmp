add_library(wvmp_common
    src/bytes.cpp
)
add_library(wvmp::common ALIAS wvmp_common)
target_include_directories(wvmp_common PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
wvmp_target_warnings(wvmp_common)
