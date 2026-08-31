# CLI（P8 泳道）：TOML 配置 + protect/version 子命令。
#
# 可测试部分（配置解析、参数解析）拆进 wvmp_cli_core，main.cpp 只做
# 编排；这样测试目标无需链接整包 passes 就能覆盖大部分逻辑。

add_library(wvmp_cli_core
    src/config.cpp
    src/args.cpp
)
add_library(wvmp::cli_core ALIAS wvmp_cli_core)
target_include_directories(wvmp_cli_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(wvmp_cli_core PUBLIC
    wvmp::framework
    wvmp::tomlplusplus
)
wvmp_target_warnings(wvmp_cli_core)

add_executable(wvmp_cli
    src/main.cpp
)
# 与 tests/CMakeLists.txt 的 pass_registration 相同：MSVC 链接器会丢弃
# 归档中未被引用的对象，而 pass 的自注册静态对象（WVMP_REGISTER_PASS）
# 恰属此类，必须整包（WHOLE_ARCHIVE）链接，否则 PassRegistry 是空的。
target_link_libraries(wvmp_cli PRIVATE
    wvmp_cli_core
    "$<LINK_LIBRARY:WHOLE_ARCHIVE,wvmp_passes_all>"
    wvmp::pe_loader_includes   # MIT-438 B.5: target_arch.hpp（arch 声明槽）
    wvmp::tomlplusplus
    wvmp::framework
)
wvmp_target_warnings(wvmp_cli)

if(WVMP_BUILD_TESTS)
    # 配置解析 + 参数解析（不依赖 pass 注册表）。
    add_executable(wvmp_cli_tests
        tests/test_config.cpp
        tests/test_args.cpp
    )
    target_link_libraries(wvmp_cli_tests PRIVATE
        wvmp::cli_core
        wvmp::gtest
        gtest_main
    )
    wvmp_target_warnings(wvmp_cli_tests)
    add_test(NAME cli_config_and_args COMMAND wvmp_cli_tests)

    # 默认配置守卫：default.toml 必须能解析，且其 pass 名单必须能装配出
    # 阶段序正确的完整管道（"默认配置可运行"）。需要全部 pass 的自注册
    # 对象，同上必须 WHOLE_ARCHIVE。
    add_executable(wvmp_cli_default_config_tests
        tests/test_default_config.cpp
    )
    target_compile_definitions(wvmp_cli_default_config_tests PRIVATE
        WVMP_DEFAULT_CONFIG_PATH="${CMAKE_CURRENT_SOURCE_DIR}/configs/default.toml"
    )
    target_link_libraries(wvmp_cli_default_config_tests PRIVATE
        wvmp::cli_core
        "$<LINK_LIBRARY:WHOLE_ARCHIVE,wvmp_passes_all>"
        wvmp::framework
        wvmp::gtest
        gtest_main
    )
    wvmp_target_warnings(wvmp_cli_default_config_tests)
    add_test(NAME cli_default_config COMMAND wvmp_cli_default_config_tests)
endif()
