@echo off
rem MIT-517 (T69): 双变体构建（AVX 实验组 / SSE2 对照组）
set "VSDIR=C:\Program Files\Microsoft Visual Studio\18\Insiders"
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
cl /nologo /EHsc /std:c++17 /O2 /utf-8 /arch:AVX  avx_kernels.cpp /Fe:avx_build.exe
cl /nologo /EHsc /std:c++17 /O2 /utf-8 /arch:SSE2 avx_kernels.cpp /Fe:sse2_build.exe
echo [ok] avx_build.exe / sse2_build.exe
