@echo off
set "VSDIR=C:\Program Files\Microsoft Visual Studio\18\Insiders"
set "PATH=%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
cmake --build "%~dp0..\build" --target %1 -j 8
