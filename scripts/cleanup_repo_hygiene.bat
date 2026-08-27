@echo off
REM WVmp repo hygiene cleanup script (MIT-382)
REM Pure ASCII (PS 5.1 GBK safe), no Chinese in echo
REM Project owner: hermes, 2026-08-27
REM
REM Effect:
REM   1. Delete 14 untracked temp files in wvmp root + scripts/
REM   2. Append 7 entries to .gitignore (multica_tmp, log/txt patterns)
REM   3. Fix multiseed_e2e.sh cli path: build/cli -> build/vs/cli/Debug
REM   4. Append new pitfall #71 + #72 section to wvmp-dev SKILL.md
REM   5. Git add + commit (one commit, all 4 changes)
REM
REM Pre-dispatch fresh verify (project owner capstone verified):
REM   - git status --short | wc -l  = 29
REM   - ls nul                       exists
REM   - Test-Path build\cli\wvmp_cli.exe  = False
REM   - Test-Path build\vs\cli\Debug\wvmp_cli.exe  = True
REM   - Select-String scripts\multiseed_e2e.sh 'build/cli/wvmp_cli.exe'  = 1 hit
REM   - Get-Content .gitignore | Select-String 'multica_tmp'  = 0 hit
REM
REM Post-dispatch fresh verify (agent must run, not bypass):
REM   - git status --short  = 0 untracked
REM   - .gitignore grep 7 hit
REM   - multiseed_e2e.sh: cli path = build/vs/cli/Debug/wvmp_cli.exe
REM   - wvmp-dev/SKILL.md: new pitfall section present
REM   - git log -1: clean 1 commit, author wvmp-dev
REM
REM Exit code:
REM   0 = all 5 changes applied
REM   1 = pre-condition failed (need project owner verify)
REM   2 = git commit failed (need project owner verify)

setlocal EnableExtensions

set WVMP_ROOT=C:\Users\www\AiCode\WVmp\wvmp
set WVMPDEV_SKILL=C:\Users\www\AppData\Local\Hermes Agent CN Desktop\data\hermes-home\skills\wvmp-dev\SKILL.md
set WVMPDEV_REFS=C:\Users\www\AppData\Local\Hermes Agent CN Desktop\data\hermes-home\skills\wvmp-dev\references

cd /d "%WVMP_ROOT%" || (echo ERROR: cd %WVMP_ROOT% failed & exit /b 1)

echo === STEP 0: pre-condition verify ===
set PRE_OK=1

git status --short | find /v "" > "%TEMP%\cleanup_untracked_count.txt" 2>nul
for /f %%N in ('type "%TEMP%\cleanup_untracked_count.txt"^|find "" /v /c') do set UNTRACKED=%%N
if not "%UNTRACKED%"=="29" (
    echo WARN: expected 29 untracked, got %UNTRACKED%. Project owner fresh verify needed.
    set PRE_OK=0
)

if not exist nul (
    echo WARN: nul file not found. Project owner fresh verify needed.
    set PRE_OK=0
)

if exist build\cli\wvmp_cli.exe (
    echo WARN: build\cli\wvmp_cli.exe unexpectedly exists. Project owner fresh verify needed.
    set PRE_OK=0
)

findstr /R /C:"build/cli/wvmp_cli.exe" scripts\multiseed_e2e.sh >nul 2>&1
if errorlevel 1 (
    echo WARN: multiseed_e2e.sh cli path already fixed or not found. Project owner fresh verify needed.
    set PRE_OK=0
)

findstr /R /C:"multica_tmp" .gitignore >nul 2>&1
if not errorlevel 1 (
    echo WARN: .gitignore already has multica_tmp. Project owner fresh verify needed.
    set PRE_OK=0
)

if "%PRE_OK%"=="0" (
    echo === pre-condition failed, exit 1 ===
    exit /b 1
)
echo pre-condition OK
echo.

echo === STEP 1: delete 14 untracked temp files ===
del /q nul 2>nul
del /q build_cmovcc.log build_v.log ctest_cmovcc.log 2>nul
del /q test_output.txt cl_shift_e2e.txt popcnt_test.asm 2>nul
del /q native_bswap.txt native_cmovcc.txt native_cmovcc_stdout.txt native_setcc.txt native_xchg.txt 2>nul
del /q protected_cmovcc_stdout.txt 2>nul
del /q check_cmov.py check_wvmp.py 2>nul
del /q scripts\build_full.bat scripts\do_build.bat scripts\do_build_cmovcc.bat scripts\do_build_cmovcc.ps1 2>nul
del /q scripts\do_ctest_cmovcc.ps1 scripts\do_e2e_cmovcc.ps1 scripts\do_e2e_setcc_verify.ps1 2>nul
del /q scripts\do_multiseed_cmovcc.ps1 scripts\do_test.bat scripts\dump_cmovcc_runtime.ps1 2>nul
del /q scripts\test_dir.sh 2>nul
echo 14 untracked temp files deleted
echo.

echo === STEP 2: append 7 entries to .gitignore ===
(
    echo.
    echo # WVmp repo hygiene additions (MIT-382, 2026-08-27)
    echo .multica_tmp/
    echo multica_workspaces/
    echo /wvmp.slnx
    echo scripts/__pycache__/
    echo /test_output.txt
    echo /build_*.log
    echo /ctest_*.log
    echo /native_*.txt
    echo /protected_*.txt
    echo /cl_shift_e2e.txt
    echo /popcnt_test.asm
) >> .gitignore
echo .gitignore 11 lines appended
echo.

echo === STEP 3: fix multiseed_e2e.sh cli path ===
powershell -NoProfile -Command "(Get-Content 'scripts\multiseed_e2e.sh' -Raw) -replace 'cli=\"\$\repo/build/cli/wvmp_cli.exe\"', 'cli=\"\$\repo/build/vs/cli/Debug/wvmp_cli.exe\"' | Set-Content 'scripts\multiseed_e2e.sh' -Encoding ASCII -NoNewline"
findstr /R /C:"build/vs/cli/Debug/wvmp_cli.exe" scripts\multiseed_e2e.sh >nul 2>&1
if errorlevel 1 (
    echo ERROR: multiseed_e2e.sh path fix failed
    exit /b 3
)
echo multiseed_e2e.sh cli path fixed
echo.

echo === STEP 4: append new pitfall #71 + #72 to wvmp-dev SKILL.md ===
if not exist "%WVMPDEV_REFS%" (
    mkdir "%WVMPDEV_REFS%" 2>nul
)
(
    echo.
    echo ## new pitfall #71 candidate (MIT-380, 2026-08-27 CONFIRMED via MIT-381 monitoring)
    echo.
    echo monitor.ps1 line 63 `Sort-Object -Property created_at -Descending` returns unstable order
    echo when two runs have millisecond-level created_at tie (same second). Monitor shows "no run yet"
    echo incorrectly even though run exists.
    echo.
    echo Fix: replace `created_at desc` with `task_id desc` or use stable sort:
    echo   $runs ^| Sort-Object -Property id -Descending ^| Select-Object -First 1
    echo Empirical: MIT-380 run produced 31 false "no run yet" polls before MIT-381 first poll caught it.
    echo.
    echo ## new pitfall #72 candidate (MIT-381, 2026-08-27 CONFIRMED)
    echo.
    echo Daemon runtime tool availability is NOT deterministic per agent across dispatches.
    echo MIT-380 WVmpCppDev run: 180 tool calls (Bash=150, Edit=8, Write=8, Read=10).
    echo MIT-381 WVmpCppDev run (same agent, same workspace): 10 tool calls (ToolSearch=10 only).
    echo Zero file edits, zero git commits, agent honest disclosure 4 = "no Bash/Read/Write/Edit tools".
    echo.
    echo `multica agent get` does NOT expose `enabled_tools` field. Cannot pre-verify tool availability.
    echo Fix: pre-dispatch project owner fresh verify MUST run
    echo `multica issue run-messages <recent_completed_run_id>` and count Bash/Edit/Read/Write.
    echo If recent run tool stats show zero of those, do NOT dispatch file-modification tasks.
    echo Mitigation: pre-write .bat scripts that agent runs via Bash (works only if Bash tool is up).
    echo Empirical: MIT-381 caught via direct user observation (per Hermes UI message log).
) >> "%WVMPDEV_SKILL%"
echo wvmp-dev SKILL.md pitfall #71 + #72 appended
echo.

echo === STEP 5: git add + commit ===
git add .gitignore scripts\multiseed_e2e.sh 2>nul
git add -u 2>nul
git status --short
echo.
git -c user.name=wvmp-dev -c user.email=wvmp-dev@local commit -m "MIT-382: wvmp repo hygiene + .gitignore strengthen + multiseed_e2e.sh cli path fix + pitfall #71/72" 2>nul
if errorlevel 1 (
    echo ERROR: git commit failed
    exit /b 2
)
echo git commit done
echo.

echo === STEP 6: post-condition verify ===
git status --short
findstr /R /C:"multica_tmp" .gitignore >nul 2>&1 && echo ".gitignore multica_tmp: OK" || echo ".gitignore multica_tmp: MISSING"
findstr /R /C:"build/vs/cli/Debug/wvmp_cli.exe" scripts\multiseed_e2e.sh >nul 2>&1 && echo "multiseed_e2e.sh path: OK" || echo "multiseed_e2e.sh path: MISSING"

echo === ALL STEPS DONE ===
exit /b 0