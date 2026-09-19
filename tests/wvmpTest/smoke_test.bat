@echo off
REM ============================================================
REM WVmp end-to-end smoke test - GitHub reproduction entry
REM   smoke_test.bat        -> x64 leg (build\x64, SUMMARY 106)
REM   smoke_test.bat x86    -> x86 leg (build\x86, SUMMARY 105)
REM ============================================================
REM Note: ASCII-only (no BOM); cmd /c chokes on BOM before @echo off
chcp 65001 > nul
set ARCH=%1
if "%ARCH%"=="" set ARCH=x64
set WVMP_ROOT=%~dp0..\..
pushd "%WVMP_ROOT%"
if not exist "build\cli\wvmp_cli.exe" (
  echo [error] build\cli\wvmp_cli.exe missing - run scripts\build.bat first
  exit /b 1
)
echo STEP1_OK ARCH=%ARCH%
REM MIT-492: corpus lives inside this repo - the test target dir is this
REM script's own directory, so a clean clone needs nothing outside WVmp/.
set WT_DIR=%~dp0
set WT_DIR=%WT_DIR:/=\%
if not exist "%WT_DIR%\build.bat" (
  echo [error] wvmpTest build.bat not found at %WT_DIR%
  exit /b 1
)
set CFG=tests\wvmpTest\kernels.toml
if "%ARCH%"=="x86" set CFG=tests\wvmpTest\kernels_x86.toml
echo STEP2_OK WT_DIR=%WT_DIR% CFG=%CFG%
if not exist "%WT_DIR%\build\%ARCH%\test_target.exe" (
  echo [1/4] building wvmpTest %ARCH% first run
  pushd "%WT_DIR%"
  call build.bat %ARCH%
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
"%WT_DIR%\build\%ARCH%\test_target.exe" > "%TMPDIR%\wsmoke_native.txt" 2>&1
set RC_NATIVE=%ERRORLEVEL%
echo [3/4] packing with WVmp CLI
build\cli\wvmp_cli.exe protect --config %CFG% > "%TMPDIR%\wsmoke_protect.txt" 2>&1
if errorlevel 1 (
  echo [error] pack failed
  exit /b 1
)
powershell -NoProfile -Command "Select-String -Path '%TMPDIR%\wsmoke_protect.txt' -Pattern '入口 stub|不可翻译指令' | ForEach-Object { $_.Line }"
echo [4/4] running packed target
"%WT_DIR%\build\%ARCH%\packed.exe" > "%TMPDIR%\wsmoke_packed.txt" 2>&1
set RC_PACKED=%ERRORLEVEL%
powershell -NoProfile -Command "Select-String -Path '%TMPDIR%\wsmoke_native.txt','%TMPDIR%\wsmoke_packed.txt' -Pattern '^SUMMARY' | ForEach-Object { $_.Filename + ' ' + $_.Line }"
powershell -NoProfile -Command "$a = Get-Content '%TMPDIR%\wsmoke_native.txt'; $b = Get-Content '%TMPDIR%\wsmoke_packed.txt'; $diff = Compare-Object $a $b | Where-Object { $_.InputObject -notmatch '^image   :' }; if ($diff) { $diff.Count } else { 0 }" > "%TMPDIR%\wsmoke_diffcount.txt"
set /p DIFF_COUNT=<"%TMPDIR%\wsmoke_diffcount.txt"
echo.
echo === Result ===
echo   arch        = %ARCH%
echo   native rc   = %RC_NATIVE%
echo   packed rc   = %RC_PACKED%
echo   diff count  = %DIFF_COUNT%
if "%RC_NATIVE%"=="0" if "%RC_PACKED%"=="0" if "%DIFF_COUNT%"=="0" (
  echo [PASS] protector preserves behavior - WVmp end-to-end OK
  exit /b 0
) else (
  echo [FAIL] see %TMPDIR%\wsmoke_*.txt
  exit /b 1
)
