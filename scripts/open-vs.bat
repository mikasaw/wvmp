@echo off
rem 生成 Visual Studio 解决方案并打开。
rem 注意：CMake 4.x 的 VS 生成器产出新格式 wvmp.slnx（XML 解决方案），
rem VS 17.13+/VS 18 原生支持；旧 .sln 不再生成。
set "VSDIR=C:\Program Files\Microsoft Visual Studio\18\Insiders"
set "PATH=%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%PATH%"
set "SLNX=%~dp0..\build\vs\wvmp.slnx"

cmake -S "%~dp0.." --preset vs-debug
if errorlevel 1 (
    echo [wvmp] 解决方案生成失败。
    exit /b 1
)

if exist "%SLNX%" (
    echo [wvmp] 打开 %SLNX%
    start "" "%SLNX%"
) else (
    echo [wvmp] 未找到 wvmp.slnx，检查 build\vs\ 目录。
    exit /b 1
)
