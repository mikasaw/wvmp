@echo off
rem MIT-437 (X1a): build the ml.exe hand-written x86 marker sample under the
rem vcvarsamd64_x86 cross environment. Usage:
rem   build_x86_marker_sample.bat <output exe full path>
rem NOTE: batch files must stay ASCII-only (cmd parses them in the OEM
rem codepage; UTF-8 Chinese comments get split into bogus commands).
rem Artifacts land in %~dp1 (build tree); sources are referenced via %~dp0 so
rem the repo source tree stays clean. A trailing sample run (rc=0 sentinel)
rem proves build+run works and the 412 section-6 pitfalls stay avoided.
setlocal
if "%~1"=="" exit /b 1
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvarsamd64_x86.bat" >nul || exit /b 1
pushd "%~dp1" || exit /b 1
ml /nologo /c /Coff "%~dp0x86_marker_sample.asm" || goto :fail
cl /nologo /utf-8 /O1 /MD /c "%~dp0x86_marker_main.c" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 x86_marker_main.obj x86_marker_sample.obj /OUT:"%~f1" || goto :fail
popd
"%~f1" || exit /b 1
exit /b 0
:fail
popd
exit /b 1
