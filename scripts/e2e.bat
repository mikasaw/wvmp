@echo off
rem WVmp end-to-end wrapper (Windows-native entrypoint)
rem
rem Usage: scripts\e2e.bat <sample.exe> [extra args passed to e2e.sh]
rem
rem Why this exists: scripts/e2e.sh is a bash script (uses mktemp, cygpath,
rem arrays, etc.) and cannot run directly under cmd / PowerShell. Windows
rem users can call this .bat which delegates to Git Bash transparently.
rem
rem Exit codes mirror e2e.sh (0 pass, 1 usage, 2 cli/protect failure,
rem 3 cli not built).

setlocal EnableExtensions EnableDelayedExpansion

set "BASH_EXE="
for %%P in ("C:\Program Files\Git\bin\bash.exe" "C:\Program Files\Git\usr\bin\bash.exe") do (
    if exist "%%~P" if not defined BASH_EXE set "BASH_EXE=%%~fP"
)
if not defined BASH_EXE (
    for /f "delims=" %%B in ('where bash 2^>nul') do (
        if not defined BASH_EXE set "BASH_EXE=%%B"
    )
)
if not defined BASH_EXE (
    echo [e2e] bash.exe not found. Install Git for Windows or add bash to PATH. 1>&2
    exit /b 3
)

set "E2E_SH=%~dp0e2e.sh"
if not exist "%E2E_SH%" (
    echo [e2e] e2e.sh not found next to e2e.bat: %E2E_SH% 1>&2
    exit /b 3
)

rem Forward each %* arg to bash via positional parameters. Inside the
rem bash -c string, "$@" expands to the args bash received. We pass the
rem sample path as $1 by appending it to the bash command line after --.
rem Because cmd's %* and bash's quoting interact badly with spaces, we
rem route through an env var: WVMP_E2E_ARGS holds the raw sample path.
set "WVMP_E2E_ARGS=%~1"

"%BASH_EXE%" -c "WVMP_E2E_ARGS=\"$WVMP_E2E_ARGS\"; export WVMP_E2E_ARGS; exec bash \"%E2E_SH%\" \"$WVMP_E2E_ARGS\""
exit /b %ERRORLEVEL%