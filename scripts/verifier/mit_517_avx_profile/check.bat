@echo off
set "VSDIR=C:\Program Files\Microsoft Visual Studio\18\Insiders"
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
cl /nologo /EHsc /std:c++17 /O2 /arch:AVX avx_kernels.cpp /Fe:avx_build.exe
