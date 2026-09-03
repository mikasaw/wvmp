@echo off
REM ============================================================
REM WVmp end-to-end smoke test - GitHub reproduction entry
REM ============================================================
REM Note: ASCII-only (no BOM); cmd /c chokes on BOM before @echo off
chcp 65001 > nul
set WVMP_ROOT=%~dp0..\..
pushd "%WVMP_ROOT%"
if not exist "build\cli\wvmp_cli.exe" (
  echo [error] build\cli\wvmp_cli.exe missing - run scripts\build.bat first
  exit /b 1
)
echo STEP1_OK
if defined WVMPTEST_DIR goto WT_RESOLVED
set WT_DIR=%~dp0..\..\..\wvmpTest
goto WT_NORMALIZE
:WT_RESOLVED
set WT_DIR=%WVMPTEST_DIR%
:WT_NORMALIZE
set WT_DIR=%WT_DIR:/=\%
if not exist "%WT_DIR%\build.bat" (
  echo [error] wvmpTest build.bat not found at %WT_DIR%
  echo   Clone it as a sibling repo, or set WVMPTEST_DIR env var.
  exit /b 1
)
echo STEP2_OK WT_DIR=%WT_DIR%
if not exist "%WT_DIR%\build\x64\test_target.exe" (
  echo [1/4] building wvmpTest x64 first run
  pushd "%WT_DIR%"
  call build.bat x64
  set RC_BUILD=%ERRORLEVEL%
  popd
  if not "%RC_BUILD%"=="0" (
    echo [error] wvmpTest build failed rc=%RC_BUILD%
    exit /b 1
  )
)
echo STEP3_OK
set TMPDIR=%TEMP%
echo [2/4] running native target
"%WT_DIR%\build\x64\test_target.exe" > "%TMPDIR%\wsmoke_native.txt" 2>&1
set RC_NATIVE=%ERRORLEVEL%
echo [3/4] packing with WVmp CLI
build\cli\wvmp_cli.exe protect --config tests\wvmpTest\kernels.toml > nul 2>&1
if errorlevel 1 (
  echo [error] pack failed
  exit /b 1
)
echo [4/4] running packed target
"%WT_DIR%\build\x64\packed.exe" > "%TMPDIR%\wsmoke_packed.txt" 2>&1
set RC_PACKED=%ERRORLEVEL%
powershell -NoProfile -Command "$a = Get-Content '%TMPDIR%\wsmoke_native.txt'; $b = Get-Content '%TMPDIR%\wsmoke_packed.txt'; $diff = Compare-Object $a $b | Where-Object { $_.InputObject -notmatch '^image   :' }; if ($diff) { $diff.Count } else { 0 }" > "%TMPDIR%\wsmoke_diffcount.txt"
set /p DIFF_COUNT=<"%TMPDIR%\wsmoke_diffcount.txt"
echo.
echo === Result ===
echo   native rc = %RC_NATIVE%
echo   packed rc = %RC_PACKED%
echo   diff count = %DIFF_COUNT%
if "%RC_NATIVE%"=="0" if "%RC_PACKED%"=="0" if "%DIFF_COUNT%"=="0" (
  echo [PASS] protector preserves behavior - WVmp end-to-end OK
  exit /b 0
) else (
  echo [FAIL] see %TMPDIR%\wsmoke_*.txt
  exit /b 1
)
