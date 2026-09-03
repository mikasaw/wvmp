@echo off
rem ============================================================
rem  Build the functional test target with MSVC (x64 by default,
rem  pass "x86" to build the 32-bit flavor).
rem    build.bat        -> build\x64\test_target.exe
rem    build.bat x86    -> build\x86\test_target.exe
rem ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set ARCH=%1
if "%ARCH%"=="" set ARCH=x64

set VCVARS=C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat
if "%ARCH%"=="x86" set VCVARS=C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars32.bat

if not exist "%VCVARS%" (
    echo [!] vcvars not found at "%VCVARS%"
    echo     Adjust VCVARS in this script to your VS installation.
    exit /b 2
)

call "%VCVARS%" >nul || exit /b 2

if not exist build mkdir build
if not exist build\%ARCH% mkdir build\%ARCH%

set OUT=build\%ARCH%\test_target.exe
set COMMONFLAGS=/nologo /std:c++17 /EHsc /O2 /W3 /DNDEBUG /D_WIN32_WINNT=0x0601 /utf-8 /D_CRT_SECURE_NO_WARNINGS

echo [i] compiling (%ARCH%) ...
cl %COMMONFLAGS% ^
   src\main.cpp src\testfw.cpp ^
   src\targets\kernels.cpp ^
   src\tests\t_math.cpp src\tests\t_controlflow.cpp src\tests\t_string.cpp ^
   src\tests\t_memory.cpp src\tests\t_datastruct.cpp src\tests\t_hashcrypto.cpp ^
   src\tests\t_exception.cpp src\tests\t_stl.cpp src\tests\t_oop.cpp ^
   src\tests\t_thread.cpp src\tests\t_winapi.cpp src\tests\t_float_sse.cpp ^
   src\tests\t_kernels.cpp ^
   advapi32.lib ^
   /Fe:%OUT% /Fo:build\%ARCH%\ || exit /b 3

echo [ok] %OUT%
exit /b 0
