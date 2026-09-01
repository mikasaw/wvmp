@echo off
rem ============================================================
rem MIT-443 (X3a): x86 (KS_MODE_32) runtime battery build script.
rem
rem MIT-442 proved vcvarsamd64_x86 cross-build works on this host
rem (env note: VS Installer dir must be on PATH for vswhere).
rem FetchContent uses its own deps tree under build/x86 so the
rem x64 Ninja build tree (.deps) is never shared across arch
rem configs (same discipline as the VS preset .deps-vs, trap #4).
rem
rem Usage:
rem   scripts\build_x86_tests.bat            configure + build battery target
rem   ctest --test-dir build\x86 -R x86_runtime_battery --output-on-failure
rem ============================================================
setlocal
set "VSDIR=C:\Program Files\Microsoft Visual Studio\18\Insiders"
set "PATH=%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"
set "PATH=C:\Program Files (x86)\Microsoft Visual Studio\Installer;%PATH%"
call "%VSDIR%\VC\Auxiliary\Build\vcvarsamd64_x86.bat" >nul
if errorlevel 1 (
    echo [x86] ERROR: vcvarsamd64_x86 failed
    exit /b 1
)
cmake -S "%~dp0.." -B "%~dp0..\build\x86" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DWVMP_WITH_KEYSTONE=ON -DWVMP_WITH_CAPSTONE=ON -DWVMP_FETCHCONTENT_DIR="%~dp0..\build\x86\.deps" %*
if errorlevel 1 exit /b 1
cmake --build "%~dp0..\build\x86" --target wvmp_regvm_runtime_tests_x86
if errorlevel 1 exit /b 1
echo [x86] OK: battery target ready under build\x86
