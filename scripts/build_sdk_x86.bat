@echo off
rem MIT-437 (X1a): SDK x86 product slot -- cross-compile sdk.cpp into a 32-bit
rem static lib. Usage: build_sdk_x86.bat <output lib full path>
rem NOTE: batch files must stay ASCII-only (cmd parses them in the OEM
rem codepage; UTF-8 Chinese comments get split into bogus commands).
rem Not consumed by any target yet (x86 pipeline lands in X2+); building it is
rem also the anchor-form probe: dumpbin assertions require both magic halves
rem to materialize as imm32 immediates (/Od measured form B8+C7). MSVC x86
rem form drift fails the build explicitly, before any scan mismatch.
setlocal
if "%~1"=="" exit /b 1
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvarsamd64_x86.bat" >nul || exit /b 1
pushd "%~dp1" || exit /b 1
set "WVMP_SDK_INC=/I"%~dp0..\sdk\include" /I"%~dp0..\common\include""
cl /nologo /std:c++17 /TP /utf-8 /Od /MD %WVMP_SDK_INC% /c "%~dp0..\sdk\src\sdk.cpp" /Fo:sdk_x86.obj || goto :fail
lib /nologo /MACHINE:X86 /OUT:"%~f1" sdk_x86.obj || goto :fail
dumpbin /disasm sdk_x86.obj > sdk_x86.disasm || goto :fail
rem form guard (immediate text, wrap-free): lo"WVMP"=504D5657h, begin hi"BEG1"=31474542h, end hi"END1"=31444E45h
findstr /c:"504D5657h" sdk_x86.disasm >nul || goto :fail
findstr /c:"31474542h" sdk_x86.disasm >nul || goto :fail
findstr /c:"31444E45h" sdk_x86.disasm >nul || goto :fail
popd
exit /b 0
:fail
popd
exit /b 1
