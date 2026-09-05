# import_protect pass：IAT 迁移 + TLS 回填（MIT-466 v1，保守回退）。
add_library(wvmp_pass_import_protect OBJECT
    src/import_protect_pass.cpp
)
target_include_directories(wvmp_pass_import_protect PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_pass_import_protect PRIVATE
    wvmp::framework
    wvmp::common
    wvmp_pass_pe_loader    # NewSection / PeImage 模型
)
wvmp_target_warnings(wvmp_pass_import_protect)

# import_protect ↔ tls_hook 契约头（import_plan.hpp）独立 INTERFACE 目标：
# tls_hook 只需要头，不吸 import_protect 的 OBJECT（自注册丢弃教训规避）。
add_library(wvmp_pass_import_plan INTERFACE)
target_include_directories(wvmp_pass_import_plan INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

if(WVMP_BUILD_TESTS)
    add_subdirectory(tests)
endif()
