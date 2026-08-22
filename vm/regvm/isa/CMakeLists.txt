# RegVM ISA: opcode set / 8-byte fixed encoding / sub-register aliasing / blob.
add_library(wvmp_regvm_isa OBJECT
    src/encoding.cpp
    src/alias.cpp
    src/blob.cpp
)
target_include_directories(wvmp_regvm_isa PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_regvm_isa PUBLIC
    wvmp::ir
    wvmp::common
)
wvmp_target_warnings(wvmp_regvm_isa)

if(WVMP_BUILD_TESTS)
    add_executable(wvmp_regvm_isa_tests tests/test_isa.cpp)
    target_link_libraries(wvmp_regvm_isa_tests PRIVATE
        wvmp_regvm_isa
        wvmp::gtest
        gtest_main
    )
    wvmp_target_warnings(wvmp_regvm_isa_tests)
    add_test(NAME regvm_isa_tests COMMAND wvmp_regvm_isa_tests)
endif()
