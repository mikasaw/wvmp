add_library(wvmp_pass_crypt OBJECT
    src/crypt_pass.cpp
)
target_include_directories(wvmp_pass_crypt PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_pass_crypt PRIVATE wvmp::framework wvmp::ir wvmp::common)
wvmp_target_warnings(wvmp_pass_crypt)
