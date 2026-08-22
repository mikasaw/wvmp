@echo off
set "VSDIR=C:\Program Files\Microsoft Visual Studio\18\Insiders"
set "PATH=%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%VSDIR%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
cmake -S "%~dp0.." -B "%~dp0..\build" -G Ninja -DCMAKE_BUILD_TYPE=Debug %*
if errorlevel 1 exit /b 1
cmake --build "%~dp0..\build"
