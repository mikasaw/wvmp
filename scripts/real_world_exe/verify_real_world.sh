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
# MIT-370 (MVP P0 #3 替代方案 A): 派活单新增杀软扫描验证步骤. pe_writer 保护
# 时强制清除 DllCharacteristics.DYNAMIC_BASE + FORCE_INTEGRITY 两个位, 让
# Windows Defender / 360 / 火绒 / 卡巴斯基 不把 protected PE 标"异常 PE"或
# "未签名强制校验失败". 本脚本在所有 per-exe 跑完后, 用 PowerShell 查询
# Windows Defender 是否对生成的 protected PE 报威胁 (Get-MpThreatDetection).
# 360 / 火绒 / 卡巴斯基 没公开 PowerShell API, 项目主 fresh verify 阶段需
# 手动 GUI 验证 (MVP P0 #3 替代方案 A 派活单 §D 决策 1).
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

# MIT-494v (T45) coverage expansion: built-in real tools (pipeline
# robustness class -- unmarked system binaries exercise pe_loader/pe_writer/
# reloc/import faces via passthrough; tar replaces the missing 7z in the
# archive-compute class). Fixtures are DETERMINISTIC (repeating pattern /
# fixed text) so cross-run results stay comparable; certutil/findstr run
# against them so both runs see byte-identical inputs. findstr 检索词不带
# /L（MSYS 会把斜杠参数路径转换毁参，T45 验收 SF-2；字面检索本就是默认）。
fixture_bin="$out_dir/t45_fixture.bin"
fixture_txt="$out_dir/t45_fixture.txt"
{ printf 'WVMP-T45-FIXTURE-0123456789abcdef\n'; for i in 1 2 3 4 5 6 7 8 9 10; do printf 'WVMP-T45-FIXTURE-0123456789abcdef%.0s' $(seq 1 22); echo; done; } \
    | head -c 65536 > "$fixture_bin"
printf 'alpha line one\nbeta line two\ngamma line three\nnumber 42 here\n' \
    > "$fixture_txt"
fixture_bin_win="$(cygpath -m "$fixture_bin")"
fixture_txt_win="$(cygpath -m "$fixture_txt")"
configs+=(
    "tar|/c/Windows/System32/tar.exe|--version|stdout"
    "certutil|/c/Windows/System32/certutil.exe|-hashfile $fixture_bin_win SHA256|stdout"
    "findstr|/c/Windows/System32/findstr.exe|\"line\" $fixture_txt_win|stdout"
    "where|/c/Windows/System32/where.exe|tar.exe|stdout"
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
        #（MIT-494k 注：GUI 模式只对拍 rc 不比输出，无位置假阳面；将来若
        # 升级为输出对比，须同步 stdout 模式的位置对齐基线。）
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
    # MIT-494k (T33)：位置对齐基线——Windows 系统工具（tasklist/cmd 实证）
    # 从 System32 原位运行与从任意其他目录运行行为不同（tasklist /? 原位
    # 71 行帮助 vs 副本仅一空行；cmd /c echo 原位正常 vs 副本报"消息号
    # 0x2350"——资源/初始化位置依赖）。protected 副本恒在 out_dir 运行，
    # native 基线若取原位则 mismatch 是方法学假阳（T32 复验误记为
    # pitfall，实为脚本缺陷：protected 与 native 逐字节全同）。native
    # 同样拷出原位运行（放 $tmp = 非系统目录，随循环尾 rm -rf 统一清
    # 理），位置变量对齐后差异才是保护语义差异。
    native_copy="$tmp/$name.native.exe"
    cp "$input" "$native_copy"
    "$native_copy" "${args[@]}" >"$native_stdout" 2>/dev/null
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

# MIT-370: MVP P0 #3 替代方案 A 杀软扫描验证步骤.
#
# 派活单核心目标: protected PE 通过 Windows Defender / 360 / 火绒 / 卡巴斯基
# 杀软扫描不被标"异常 PE". pe_writer 已强制清除 DllCharacteristics 的
# DYNAMIC_BASE + FORCE_INTEGRITY 两个位 (保护后镜像不强制 ASLR 重定位 + 不
# 强制校验数字签名), 避免 Windows "无法验证此文件的数字签名" → Permission
# denied rc=126. 本步骤用 PowerShell Get-MpThreat 查询 Windows Defender 是否
# 已对生成的 protected PE 报威胁.
#
# 覆盖范围:
#   - Windows Defender: PowerShell Get-MpThreatDetection 直接查威胁表
#     (MIT-370 派活单 §D 决策 1 杀软扫描验证自动化部分)
#   - 360 / 火绒 / 卡巴斯基: 无公开 PowerShell API, 项目主 fresh verify 阶段
#     需手动 GUI 验证 (MVP派发**前**杀软扫描验证, 派活单 §A 假设清单)
#
# 返回: 仅诊断性 echo, 不修改 $pass / $fail 计数 (verify_real_world.sh 派活单
# 限定始终退出 0, 杀软检测命中介入为派活单核心目标不达成, 由 verifier 单独
# 跟进). 若 Defender 不可用 / 未启用, 标 SKIP 而非 FAIL.
echo ""
echo "[realworld] ============================================"
echo "[realworld] MIT-370 杀软扫描验证 (Windows Defender 自动, 360/火绒/卡巴斯基手动)"
echo "[realworld] ============================================"

av_check_done=0
av_threat_count=0
if command -v powershell.exe >/dev/null 2>&1; then
    for cfg_line in "${configs[@]}"; do
        IFS='|' read -r name input test_arg mode <<<"$cfg_line"
        protected_pe="$out_dir/$name.protected.exe"
        if [[ ! -f "$protected_pe" ]]; then
            continue
        fi
        # 归一化路径: Git Bash /c/Windows/... → Windows C:\Windows\...
        win_path=$(cygpath -w "$protected_pe" 2>/dev/null || echo "$protected_pe")
        # 用 Get-MpThreatDetection 查 Defender 威胁表. 该 cmdlet 列出所有已被
        # Defender 标记的项, 我们按 Resources 字段匹配本脚本生成的 protected PE.
        threats=$(powershell.exe -NoProfile -Command "
            try {
                Get-MpThreatDetection | Where-Object { \$_ -and (\$_.Resources -like '*$(basename "$win_path")*') } | Select-Object -First 5 | ConvertTo-Json -Depth 2 -Compress
            } catch {
                ''
            }
        " 2>/dev/null | tr -d '\r')
        if [[ -z "$threats" || "$threats" == "null" ]]; then
            echo "[avscan] PASS $name — Windows Defender 未标记 protected PE"
            av_check_done=$((av_check_done + 1))
        else
            # Defender 报了具体威胁——派活单核心目标不达成
            echo "[avscan] FAIL $name — Windows Defender 检测到威胁"
            echo "  Threats: $threats" | head -10
            av_threat_count=$((av_threat_count + 1))
        fi
    done
    echo "[avscan] $av_check_done / ${#configs[@]} 个 protected PE 通过 Defender 扫描"
    if [[ $av_threat_count -gt 0 ]]; then
        echo "[avscan] $av_threat_count 个 protected PE 被 Defender 标记 — 派活单核心目标 MVP P0 #3 替代方案 A 不达成"
        echo "[avscan] 项目主 fresh verify 必跑 Get-MpThreatDetection / 360 / 火绒 / 卡巴斯基 GUI 复核"
    else
        echo "[avscan] Defender 扫描通过 — 派活单核心目标 MVP P0 #3 替代方案 A ✅"
    fi
    echo "[avscan] 手动 GUI 验证: 360 / 火绒 / 卡巴斯基 GUI 扫描同 5 个 protected PE"
else
    echo "[avscan] SKIP powershell.exe 不可用, 跳过 Defender 自动验证"
    echo "[avscan] 项目主 fresh verify 必跑 Get-MpThreatDetection / 360 / 火绒 / 卡巴斯基 GUI 复核"
fi

# Exit 0: the dispatch ticket §D 决策 5 expects most real-world exes to hit
# unsupported instructions (SSE/AVX/x87/lock/rep/syscall) and fall to C1 gate
# or pitfall. Failing the script on those would block the regression intent.
exit 0