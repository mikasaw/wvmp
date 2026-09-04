# crypt pass：VM 字节码 blob 级加密（MIT-458 crypt-v1，xor_chain codec）。
add_library(wvmp_pass_crypt OBJECT
    src/crypt_pass.cpp
)
target_include_directories(wvmp_pass_crypt PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_pass_crypt PRIVATE
    wvmp::framework wvmp::ir wvmp::common
    wvmp_regvm_codecs
    wvmp_pass_virtualize    # VirtualizedFunction 槽类型（kVmProgram）
)
wvmp_target_warnings(wvmp_pass_crypt)

# crypt ↔ stub_link 契约头（crypt_plan.hpp）独立 INTERFACE 目标：stub_link
# 只需要头，不链 crypt 的 OBJECT（避免把 crypt pass 的自注册对象吸进
# stub_link 消费面——MSVC 丢弃未引用自注册对象问题，见 STATUS 教训 2）。
add_library(wvmp_pass_crypt_plan INTERFACE)
target_include_directories(wvmp_pass_crypt_plan INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

if(WVMP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
