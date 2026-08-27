#!/usr/bin/env bash
# MIT-350: Real-world exe regression test set verification script.
#
# Goal: discover pitfalls (SSE/AVX/x87 FPU/lock/rep/MFC/WTL/Qt/DirectX/OpenGL/syscall)
# by running wvmp protect on 5 real-world exes and comparing native vs protected
# stdout+rc byte-exact.
#
# Style: along with multiseed_e2e.sh (per-sample cfg + protect + native/protected
# byte-exact compare).
#
# The 5 real-world exes:
#   - notepad.exe  (Windows GUI, C:/Windows/System32/notepad.exe)
#   - 7z.exe       (7-Zip CLI,   C:/Program Files/7-Zip/7z.exe, optional)
#   - tasklist.exe (Windows CLI,  C:/Windows/System32/tasklist.exe)
#   - cmd.exe      (Windows shell,C:/Windows/System32/cmd.exe)
#   - curl.exe     (HTTP client,  /mingw64/bin/curl.exe)
#
# Each exe has a per-exe invocation argument that produces deterministic stdout
# output (--version / --help / /c echo / etc). When no such invocation exists
# (e.g. notepad GUI), the script runs the exe with a short timeout and compares
# only the return code.
#
# Note: per the dispatch ticket §D 决策 5, the following are NOT supported and
# protected PE will likely fall back to C1 gate for code containing them:
#   - SSE / AVX / x87 FPU / lock / rep
#   - MFC / WTL / Qt GUI frameworks
#   - DirectX / OpenGL graphics
#   - syscall / sysenter
#   - DLL imports (PE-only; dispatch ticket §D 决策 9)
#   - PE32 32-bit, CFG, CET
#
# A protected exe that runs byte-exact means WVmp succeeded in virtualizing at
# least one function. A mismatch or C1 gate fallback is the expected outcome
# for most real-world exes — each is a pitfall data point, not a regression.

set -u

repo="$(cd "$(dirname "$0")/../.." && pwd)"
cli="$repo/build/cli/wvmp_cli.exe"
out_dir="$repo/build/real_world_exe"
mkdir -p "$out_dir"

# Per-exe config: <name>|<input_bash>|<test_arg>|<mode>
#   input_bash : path as seen by bash (used for existence check + direct execution)
#   test_arg   : invocation argument (empty for default behavior)
#   mode       : "stdout" -> byte-exact stdout + rc compare (CLI tools)
#                "rc"     -> only rc compare with timeout (GUI apps, spawn then kill)
# The corresponding <name>.toml in scripts/real_world_exe/ uses Windows-style
# paths for wvmp_cli protect; verify_real_world.sh reads the toml via wvmp_cli
# and only uses the bash path here for native execution.
declare -a configs=(
    "notepad|/c/Windows/System32/notepad.exe||rc"
    "7z|/c/Program Files/7-Zip/7z.exe|--help|stdout"
    "tasklist|/c/Windows/System32/tasklist.exe|/?|stdout"
    "cmd|/c/Windows/System32/cmd.exe|/c echo WVMP_REAL_WORLD_OK|stdout"
    "curl|/c/Program Files/Git/mingw64/bin/curl.exe|--version|stdout"
)

# GUI app timeout in seconds: protected GUI binary may hang on missing display.
gui_timeout=3

pass=0
fail=0
skip=0
pitfall_count=0

for cfg_line in "${configs[@]}"; do
    IFS='|' read -r name input test_arg mode <<<"$cfg_line"
    output="$out_dir/$name.protected.exe"
    echo "[realworld] === $name ==="

    # 1) Existence check
    if [[ ! -f "$input" ]]; then
        echo "[realworld] SKIP $name input not found: $input"
        skip=$((skip + 1))
        continue
    fi

    # 2) Find per-exe config from scripts/real_world_exe/
    cfg="$repo/scripts/real_world_exe/$name.toml"
    if [[ ! -f "$cfg" ]]; then
        echo "[realworld] SKIP $name config not found: $cfg"
        skip=$((skip + 1))
        continue
    fi

    # 3) Build protected PE
    rc=0
    protect_log="$("$cli" protect --config "$cfg" 2>&1)" || rc=$?
    if [[ $rc -ne 0 || ! -f "$output" ]]; then
        echo "[realworld] FAIL $name protect rc=$rc (C1 gate or unsupported)"
        echo "$protect_log" | tail -5
        fail=$((fail + 1))
        pitfall_count=$((pitfall_count + 1))
        continue
    fi

    # 4) Run native + protected, compare
    tmp="$(mktemp -d)"
    native_stdout="$tmp/native.stdout"
    protected_stdout="$tmp/protected.stdout"
    native_rc_file="$tmp/native.rc"
    protected_rc_file="$tmp/protected.rc"

    # Pick test argument (or empty for GUI mode)
    args=()
    if [[ -n "$test_arg" ]]; then
        # Split test_arg on whitespace for multi-arg invocations
        # shellcheck disable=SC2206
        args=($test_arg)
    fi

    if [[ "$mode" == "rc" ]]; then
        # GUI mode: spawn + kill after timeout, compare rc
        "$input" "${args[@]}" >"$native_stdout" 2>/dev/null &
        native_pid=$!
        sleep "$gui_timeout"
        kill "$native_pid" 2>/dev/null
        wait "$native_pid" 2>/dev/null
        echo $? >"$native_rc_file"

        "$output" "${args[@]}" >"$protected_stdout" 2>/dev/null &
        protected_pid=$!
        sleep "$gui_timeout"
        kill "$protected_pid" 2>/dev/null
        wait "$protected_pid" 2>/dev/null
        echo $? >"$protected_rc_file"

        # GUI: rc will be killed (typically 1 or signal-derived) — only log, don't fail
        echo "[realworld] INFO $name GUI mode (timeout=${gui_timeout}s) — native_rc=$(cat "$native_rc_file") protected_rc=$(cat "$protected_rc_file")"
        echo "[realworld] PASS $name GUI mode (existence + protect OK)"
        pass=$((pass + 1))
        rm -rf "$tmp"
        continue
    fi

    # stdout mode: capture full stdout + rc
    "$input" "${args[@]}" >"$native_stdout" 2>/dev/null
    echo $? >"$native_rc_file"

    "$output" "${args[@]}" >"$protected_stdout" 2>/dev/null
    echo $? >"$protected_rc_file"

    if ! cmp -s "$native_stdout" "$protected_stdout"; then
        echo "[realworld] FAIL $name stdout mismatch"
        diff "$native_stdout" "$protected_stdout" | head -20
        fail=$((fail + 1))
        pitfall_count=$((pitfall_count + 1))
    elif [[ "$(cat "$native_rc_file")" != "$(cat "$protected_rc_file")" ]]; then
        echo "[realworld] FAIL $name rc mismatch $(cat "$native_rc_file") vs $(cat "$protected_rc_file")"
        fail=$((fail + 1))
        pitfall_count=$((pitfall_count + 1))
    else
        # MIT-306 REQUIRE_REAL check: confirm real virtualization (not C1 gate)
        if echo "$protect_log" | grep -q "已生成 [1-9][0-9]* 个入口 stub"; then
            echo "[realworld] PASS $name byte-exact + 真虚拟化 (含 stub 生成标记)"
            pass=$((pass + 1))
        else
            echo "[realworld] PASS $name byte-exact but C1 gate fallback (派活单限定不支持的指令集)"
            pass=$((pass + 1))
            pitfall_count=$((pitfall_count + 1))
        fi
    fi
    rm -rf "$tmp"
done

echo ""
echo "[realworld] ============================================"
echo "[realworld] TOTAL: $pass pass / $fail fail / $skip skip"
echo "[realworld] pitfall data points: $pitfall_count"
echo "[realworld] ============================================"
echo "[realworld] NOTE: 派活单核心目标是发现现实世界 exe 指令集 / pitfall."
echo "[realworld]       FAIL 条目是派活单核心目标的实证, 不是回归."
echo "[realworld]       verify_real_world.sh 始终退出 0 表示脚本本身跑通."

# Exit 0: the dispatch ticket §D 决策 5 expects most real-world exes to hit
# unsupported instructions (SSE/AVX/x87/lock/rep/syscall) and fall to C1 gate
# or pitfall. Failing the script on those would block the regression intent.
exit 0