add_library(wvmp_pass_integrity_crc OBJECT
    src/integrity_crc_pass.cpp
)
target_include_directories(wvmp_pass_integrity_crc PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_pass_integrity_crc PRIVATE
    wvmp::framework wvmp::ir wvmp::common
    wvmp_pass_crypt_plan    # MIT-464: CryptPlan 契约头（INTERFACE）
)
wvmp_target_warnings(wvmp_pass_integrity_crc)

if(WVMP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
