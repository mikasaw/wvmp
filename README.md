# WVmp

WVmp 是一个完全插件化的 PE x86/x64 虚拟机保护壳（参考 VMProtect/VMPilot 的自研实现）。

A fully pluginized PE x86/x64 virtual-machine protector (self-researched,
VMProtect/VMPilot-inspired).

## 构建（Windows / MSVC / Ninja，需 VS 18 Insiders）

    scripts\build.bat

从 Git Bash 调用：

    cmd //c "$(cygpath -w scripts/build.bat)"

首次构建会通过 CMake FetchContent 拉取第三方依赖（googletest / capstone /
keystone / tomlplusplus）到 `.deps/`，keystone 编译较久。

## 测试

    scripts\test.bat
