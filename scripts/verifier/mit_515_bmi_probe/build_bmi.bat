@echo off
set "VSDIR=C:\Program Files\Microsoft Visual Studio\18\Insiders"
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d C:\Users\www\AppData\Local\Temp\probe511
ml64 /nologo /c /Fo bmi_asm.obj bmi_asm.asm
cl /nologo /EHsc /std:c++17 /utf-8 bmi_main.cpp bmi_asm.obj /Fe:bmi_probe.exe
