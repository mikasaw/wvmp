@echo off
rem MIT-446 (X4) B.4: build the three x86 E2E first-batch samples (forkface /
rem SSE / callgate) under the vcvarsamd64_x86 cross environment.
rem Usage: build_x86_e2e_samples.bat <output dir>
rem NOTE: batch files must stay ASCII-only (cmd parses them in the OEM
rem codepage; UTF-8 Chinese comments get split into bogus commands).
rem Each sample: ml.exe hand-written region asm (marker stubs, /Od form,
rem MIT-437 recipe) + cl C main + link /MACHINE:X86. A trailing native run
rem (rc=0 sentinel per sample) proves build+run works before the pipeline
rem touches anything (D4: native-green-first discipline, 428 lesson).
setlocal
if "%~1"=="" exit /b 1
rem vswhere is needed by vcvarsamd64_x86.bat (same as build_x86_tests.bat).
set "PATH=C:\Program Files (x86)\Microsoft Visual Studio\Installer;%PATH%"
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvarsamd64_x86.bat" >nul || exit /b 1
pushd "%~1" || exit /b 1

ml /nologo /c /Coff "%~dp0x86_forkface_sample.asm" || goto :fail
cl /nologo /utf-8 /O1 /MD /c "%~dp0x86_forkface_main.c" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 x86_forkface_main.obj x86_forkface_sample.obj /OUT:"%~1\wvmp_x86_forkface_sample.exe" || goto :fail
.\wvmp_x86_forkface_sample.exe || goto :fail

ml /nologo /c /Coff "%~dp0x86_sse_sample.asm" || goto :fail
cl /nologo /utf-8 /O1 /MD /c "%~dp0x86_sse_main.c" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 x86_sse_main.obj x86_sse_sample.obj /OUT:"%~1\wvmp_x86_sse_sample.exe" || goto :fail
.\wvmp_x86_sse_sample.exe || goto :fail

ml /nologo /c /Coff "%~dp0x86_callgate_sample.asm" || goto :fail
cl /nologo /utf-8 /O1 /MD /c "%~dp0x86_callgate_main.c" || goto :fail
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 x86_callgate_main.obj x86_callgate_sample.obj /OUT:"%~1\wvmp_x86_callgate_sample.exe" || goto :fail
.\wvmp_x86_callgate_sample.exe || goto :fail

popd
exit /b 0
:fail
popd
exit /b 1
