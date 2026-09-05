@echo off
rem MIT-465 (T8): build the TLS-aware sample (tls_sample_main.cpp) for both
rem architectures with the plain-cl recipe proven to keep TLS callbacks
rem dispatched by the loader on this host (see docs/GAPS.md MIT-465-G1 for
rem why CMake-built bodies are NOT used here).
rem Usage: build_tls_sample.bat <x64-out.exe> <x86-out.exe>
rem A trailing native run (rc=0 sentinel) proves build+run works before the
rem pipeline touches anything (D4 native-green-first discipline).
rem NOTE: batch files must stay ASCII-only (cmd parses them in the OEM
rem codepage; UTF-8 Chinese comments get split into bogus commands).
setlocal
if "%~1"=="" exit /b 1
if "%~2"=="" exit /b 1
set "PATH=C:\Program Files (x86)\Microsoft Visual Studio\Installer;%PATH%"
set "SRCDIR=%~dp0"
set "SDKLIB=%SRCDIR%..\..\..\build\sdk"

rem ---- x64 ----
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
pushd "%~1\.." || exit /b 1
cl /nologo /utf-8 /O1 /MDd /std:c++17 /I"%SRCDIR%..\..\..\sdk\include" /I"%SRCDIR%..\..\..\common\include" /I"%SRCDIR%..\..\..\ir\include" /c "%SRCDIR%tls_sample_main.cpp" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE tls_sample_main.obj "%SDKLIB%\wvmp_sdk.lib" /OUT:"%~1" || goto :fail
popd
"%~1" || goto :fail

rem ---- x86 ----
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvarsamd64_x86.bat" >nul || exit /b 1
pushd "%~2\.." || exit /b 1
cl /nologo /utf-8 /O1 /MDd /std:c++17 /I"%SRCDIR%..\..\..\sdk\include" /I"%SRCDIR%..\..\..\common\include" /I"%SRCDIR%..\..\..\ir\include" /c "%SRCDIR%tls_sample_main.cpp" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 tls_sample_main.obj "%SDKLIB%\wvmp_sdk_x86.lib" /OUT:"%~2" || goto :fail
popd
"%~2" || goto :fail

endlocal
exit /b 0

:fail
popd 2>nul
exit /b 1
