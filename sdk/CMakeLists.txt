add_library(wvmp_sdk
    src/sdk.cpp
)
add_library(wvmp::sdk ALIAS wvmp_sdk)
target_include_directories(wvmp_sdk PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
wvmp_target_warnings(wvmp_sdk)
