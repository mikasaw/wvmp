@echo off
set "VSDIR=C:\Program Files\Microsoft Visual Studio\18\Insiders"
set "PATH=%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
if not exist "%~dp0..\build" (
    echo [wvmp] build directory missing; run scripts\build.bat first
    exit /b 1
)
ctest --test-dir "%~dp0..\build" --output-on-failure
