@echo off
rem ============================================================
rem  Run unpacked and packed targets back-to-back and compare.
rem    run_compare.cmd unpacked.exe [packed.exe]
rem  Verdict logic:
rem    * both exit 0 with identical SUMMARY lines  -> PASS
rem    * SUMMARY mismatch / failed counts differ    -> FAIL
rem    * negative crash code on either side         -> FAIL (broken feature)
rem ============================================================
setlocal
set UNPACKED=%~1
if "%UNPACKED%"=="" ( echo usage: run_compare.cmd unpacked.exe packed.exe & exit /b 2 )
set PACKED=%~2
if "%PACKED%"=="" set PACKED=%UNPACKED%

"%UNPACKED%" --compact --log=out\base_unpacked.log
set RC1=%ERRORLEVEL%
"%PACKED%" --compact --log=out\base_packed.log
set RC2=%ERRORLEVEL%

echo unpacked rc=%RC1%    packed rc=%RC2%

fc /n out\base_unpacked.log out\base_packed.log >nul
if errorlevel 1 (
    echo [DIFF] outputs differ - inspect the two logs.
) else (
    echo [SAME] byte-identical outputs.
)

if "%RC1%"=="0" if "%RC2%"=="0" (
    echo [PASS] both binaries report success.
    exit /b 0
)
echo [FAIL] return codes indicate problems above.
exit /b 1
