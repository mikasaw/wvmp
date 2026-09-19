@echo off
rem ============================================================
rem  Run unpacked and packed targets back-to-back and compare.
rem    run_compare.cmd unpacked.exe [packed.exe]
rem  Verdict logic:
rem    * both exit 0 AND byte-identical logs            -> PASS rc 0
rem    * SUMMARY mismatch / failed counts differ        -> FAIL rc 1
rem    * negative crash code on either side             -> FAIL (broken feature)
rem  MIT-492: the diff verdict is now load-bearing - it used to be printed
rem  and then ignored (both-rc-0 alone returned PASS, so a missing out\ dir
rem  or a diverging log still exited 0).
rem ============================================================
setlocal enabledelayedexpansion
if "%~1"=="" ( echo usage: run_compare.cmd unpacked.exe packed.exe & exit /b 2 )
rem Absolutize the two binaries against the caller's CWD first, then move to
rem this script's own dir so the out\ log mirror always lands in tests\wvmpTest.
set UNPACKED=%~f1
set PACKED=%~f2
if "%~2"=="" set PACKED=%UNPACKED%
cd /d "%~dp0"

rem The target mirrors its own log into out\; the dir is not in git, so a
rem clean clone has to create it or both fc and Compare-Object read nothing.
if not exist out mkdir out

"%UNPACKED%" --compact --log=out\base_unpacked.log
set RC1=%ERRORLEVEL%
"%PACKED%" --compact --log=out\base_packed.log
set RC2=%ERRORLEVEL%

echo unpacked rc=%RC1%    packed rc=%RC2%

powershell -NoProfile -Command "$a = Get-Content 'out\base_unpacked.log'; $b = Get-Content 'out\base_packed.log'; $d = Compare-Object $a $b | Where-Object { $_.InputObject -notmatch '^image   :' }; if ($d) { $d.Count } else { 0 }" > "out\diffcount.txt"
set /p DIFF_COUNT=<"out\diffcount.txt"
echo diff count = %DIFF_COUNT%

fc /n out\base_unpacked.log out\base_packed.log >nul
if "%DIFF_COUNT%"=="0" (
    echo [SAME] byte-identical outputs.
) else (
    echo [DIFF] outputs differ - inspect the two logs.
)

if "%RC1%"=="0" if "%RC2%"=="0" if "%DIFF_COUNT%"=="0" (
    echo [PASS] both binaries report success with identical output.
    exit /b 0
)
echo [FAIL] rc or diff verdict above.
exit /b 1
