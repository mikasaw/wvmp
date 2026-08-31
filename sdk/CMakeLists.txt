add_library(wvmp_sdk
    src/sdk.cpp
)
add_library(wvmp::sdk ALIAS wvmp_sdk)
target_include_directories(wvmp_sdk PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
# markers.hpp 使用契约头 common/types.hpp（仅类型别名，无链接产物）。
target_link_libraries(wvmp_sdk PUBLIC wvmp::common)
wvmp_target_warnings(wvmp_sdk)

# —— X1a (MIT-437): SDK x86 产物位 ——
# 交叉编译 sdk.cpp 为 32 位静态库（/MACHINE:X86），不进任何消费链（x86
# 管道在 X2+ 接力）；本产物同时是形态探针：scripts/build_sdk_x86.bat 内
# dumpbin 断言 magic 两半 imm32 物化齐现，MSVC x86 形态漂移在构建期显式
# 失败。独立输出目录（本子目录的二进制树），x64 产物路径零触碰。
# 与 scripts/build.bat 同源约定：本机唯一 VS 目录硬编码。
set(WVMP_VS_DIR "C:/Program Files/Microsoft Visual Studio/18/Insiders")
if(WIN32 AND MSVC AND EXISTS "${WVMP_VS_DIR}/VC/Auxiliary/Build/vcvarsamd64_x86.bat")
    set(WVMP_SDK_X86_LIB "${CMAKE_CURRENT_BINARY_DIR}/wvmp_sdk_x86.lib")
    add_custom_command(
        OUTPUT "${WVMP_SDK_X86_LIB}"
        COMMAND "${CMAKE_SOURCE_DIR}/scripts/build_sdk_x86.bat" "${WVMP_SDK_X86_LIB}"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/sdk.cpp"
                "${CMAKE_SOURCE_DIR}/scripts/build_sdk_x86.bat"
        COMMENT "sdk x86 交叉构建 + 锚点形态守卫 (X1a)"
        VERBATIM)
    add_custom_target(wvmp_sdk_x86 ALL DEPENDS "${WVMP_SDK_X86_LIB}")
endif()
