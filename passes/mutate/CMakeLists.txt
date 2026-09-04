add_library(wvmp_pass_mutate OBJECT
    src/mutate_pass.cpp
)
target_include_directories(wvmp_pass_mutate PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_pass_mutate PRIVATE wvmp::framework wvmp::ir wvmp::common)
wvmp_target_warnings(wvmp_pass_mutate)

if(WVMP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
