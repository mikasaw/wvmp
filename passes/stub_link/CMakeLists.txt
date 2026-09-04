add_library(wvmp_pass_stub_link OBJECT
    src/stub_link_pass.cpp
    src/stub_gen.cpp
)
target_include_directories(wvmp_pass_stub_link PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_include_directories(wvmp_pass_stub_link PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src # stub_gen.hpp（内部工具头）
)
target_link_libraries(wvmp_pass_stub_link PRIVATE
    wvmp::framework
    wvmp::ir
    wvmp::common
    wvmp::vm
    wvmp_pass_virtualize    # VirtualizedFunction 槽类型
    wvmp_pass_crypt_plan    # MIT-458: CryptPlan 契约头（INTERFACE，不吸 crypt 对象）
    wvmp_pass_pe_loader     # PeImage 模型
    wvmp_regvm_runtime
    wvmp_regvm_isa
    wvmp_regvm_codecs       # MIT-458: kXorChainMult（解密块常数单一来源）
)
wvmp_target_warnings(wvmp_pass_stub_link)

# --- 泳道测试 ---------------------------------------------------------------
if(WVMP_BUILD_TESTS AND TARGET wvmp::gtest)
    add_subdirectory(tests)
endif()
