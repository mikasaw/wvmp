#!/usr/bin/env bash
# MIT-372: MV P0 #5 性能性能验证脚本 (MVP派发**前**项目主 fresh verify 必 capstone 实证 baseline).
#
# 派活单核心目标:
#   protected PE 启动时间 / 内存占用 / on/off5x 测时间 baseline. 沿用 MIT-326 cherry-pick
#   派活单已知妥协 startup overhead. MVP P0 #1 + #2 + #3 都 done (snake 真虚拟化 byte-exact 闭环
#   + 5 个现实世界 exe 回归测试集 + PE 重写 + 杀软扫描兼容), MVP P0 #4 (PE 签名 EV 证书) 用户
#   决定不做, Block C 阶段 3 SSE 浮点加 (MIT-371) 派发中.
#
# 用法:
#   scripts/measure_perf.sh [--iterations N] [--output FILE] [--seed N] [--force-reprotect]
#                           <sample.exe> [<sample2.exe> ...]
#
# 默认行为:
#   - iterations: 5 (on/off 5x 测时间 baseline, 派活单核心目标)
#   - seed: 12345 (与 e2e.sh / multiseed_e2e.sh 默认 seed 一致)
#   - force-reprotect: 不设置时若 <sample>.protected.exe 已存在则跳过 protect 步骤, 节省时间
#
# 对每个 sample:
#   1) 查找 wvmp_cli.exe (沿用 e2e.sh 的 find_cli 多泳道查找)
#   2) 若 <sample>.protected.exe 不存在 (或 --force-reprotect), 运行 wvmp_cli protect
#      生成 inline TOML 配置 (沿用 e2e.sh 的 inline TOML 模式)
#   3) 运行 N 次 native, N 次 protected, 通过 PowerShell 采样 PeakWorkingSet64 /
#      PrivateMemorySize64 / PeakPagedMemorySize64 + runtime ms (PowerShell 直接拿不到
#      peak 内存——只能 polling 拿到 max, 这是已知妥协, 派活单 §A 假设 2)
#   4) 输出 markdown 表格: native vs protected, overhead 倍数 (protected/native)
#
# 输出 (stdout, 同时可写 --output FILE):
#   | Sample | Mode | Run | RuntimeMs | PeakWS_KB | PeakPriv_KB | PeakPaged_KB |
#   然后聚合:
#   | Sample | Mode | MinMs | MedianMs | MaxMs | MinWS_KB | MedianWS_KB | MaxWS_KB |
#
# 退出码: 0 全测成功; 1 用法错; 2 wvmp_cli protect 失败; 3 wvmp_cli 未构建;
#         4 测量失败; 5 native / protected 行为不一致 (MVP P0 #1 byte-exact 退化检测).
#
# 冻结契约: 派活单限定 scripts/measure_perf.sh (派活单新增), 不改 lifter + translator + asmgen +
#           VM runtime + pe_writer + stub_link + 16 个自测样本 + MASM helper + 冻结契约头文件.

set -u

repo="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
    cat >&2 <<'EOF'
usage: scripts/measure_perf.sh [--iterations N] [--output FILE] [--seed N] [--force-reprotect]
                                <sample.exe> [<sample2.exe> ...]

  --iterations N        每个 sample 每个 mode 跑 N 次 (默认 5, 即派活单核心 on/off5x)
  --output FILE         把 markdown 表格追加到 FILE (同时仍打印到 stdout)
  --seed N              wvmp_cli protect 的 seed (默认 12345)
  --force-reprotect     即使 <sample>.protected.exe 已存在也重新 protect
  -h | --help           显示本帮助
EOF
}

# 沿用 e2e.sh find_cli: 优先 WVMP_BUILD_DIR, 其次本泳道 build/p8, 主 build, 全盘查找.
find_cli() {
    local d c
    d="${WVMP_BUILD_DIR:-}"
    if [[ -n "$d" && -f "$d/cli/wvmp_cli.exe" ]]; then echo "$d/cli/wvmp_cli.exe"; return 0; fi
    for c in "$repo/build/p8/cli/wvmp_cli.exe" "$repo/build/cli/wvmp_cli.exe"; do
        [[ -f "$c" ]] && { echo "$c"; return 0; }
    done
    c="$(find "$repo"/build* -type f -name wvmp_cli.exe 2>/dev/null | head -1)"
    [[ -n "$c" ]] && { echo "$c"; return 0; }
    return 1
}

# 测一次: PowerShell 启动进程, polling 拿 peak 内存, 等退出后算 runtime. 返回四个值.
# stdout 走 $MS_OUT (临时文件), 验证 byte-exact 一致 (MVP P0 #1 退化检测). rc 0 = 行为一致.
measure_one() {
    local exe="$1" tag="$2" ms_out="$3" tmp_dir="$4"
    local script rc_file ws_file
    rc_file="$tmp_dir/${tag}.rc"
    ws_file="$tmp_dir/${tag}.metrics"
    script="$tmp_dir/${tag}.ps1"

    # -NoNewWindow + RedirectStandardOutput + CreateNoWindow: 避免弹窗与控制台缓冲.
    # -Wait 不可靠 (子进程太快, Wait-Process 偶发 timeout). 用 .NET Process 类 polling.
    # Stdout: redirect pipe + sync ReadToEnd (snake 输出极少, 不会 deadlock).
    cat > "$script" <<'PWSH'
param([string]$Exe, [string]$RcFile, [string]$MetricsFile, [string]$StdoutFile)
$ErrorActionPreference = 'Stop'
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $Exe
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi
$null = $p.Start()
$peakWS = 0; $peakPriv = 0; $peakPage = 0
while (-not $p.HasExited) {
    try { $p.Refresh() } catch { break }
    if ($p.HasExited) { break }
    if ($p.PeakWorkingSet64 -gt $peakWS) { $peakWS = $p.PeakWorkingSet64 }
    if ($p.PrivateMemorySize64 -gt $peakPriv) { $peakPriv = $p.PrivateMemorySize64 }
    if ($p.PeakPagedMemorySize64 -gt $peakPage) { $peakPage = $p.PeakPagedMemorySize64 }
    Start-Sleep -Milliseconds 2
}
$stdoutText = $p.StandardOutput.ReadToEnd()
$stderrText = $p.StandardError.ReadToEnd()
$p.WaitForExit()
$runtimeMs = [Math]::Round(($p.ExitTime - $p.StartTime).TotalMilliseconds, 2)
# PowerShell 5.1 Set-Content -Encoding UTF8 写 BOM, 与 bash read 冲突. 用 .NET File.WriteAllText + UTF8Encoding($false).
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($StdoutFile, $stdoutText, $utf8NoBom)
[System.IO.File]::WriteAllText($RcFile, [string]$p.ExitCode, $utf8NoBom)
$metricsLine = "{0}|{1}|{2}|{3}" -f $runtimeMs, $peakWS, $peakPriv, $peakPage
[System.IO.File]::WriteAllText($MetricsFile, $metricsLine, $utf8NoBom)
PWSH

    local out
    local script_win
    script_win="$(cygpath -w "$script" 2>/dev/null || echo "$script")"
    out="$(powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$script_win" \
        -Exe "$(cygpath -w "$exe" 2>/dev/null || echo "$exe")" \
        -RcFile "$(cygpath -w "$rc_file" 2>/dev/null || echo "$rc_file")" \
        -MetricsFile "$(cygpath -w "$ws_file" 2>/dev/null || echo "$ws_file")" \
        -StdoutFile "$(cygpath -w "$ms_out" 2>/dev/null || echo "$ms_out")" 2>&1)"
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "[measure] PowerShell 测次失败 ($tag): $out" >&2
        return 4
    fi
    if [[ ! -f "$ws_file" ]]; then
        echo "[measure] metrics 文件未生成 ($tag): $out" >&2
        return 4
    fi
    cat "$ws_file"
    return 0
}

# 生成 inline TOML (沿用 e2e.sh 模式), 调 wvmp_cli protect 产出 protected.exe.
protect_one() {
    local cli="$1" sample="$2" protected_out="$3" seed="$4"
    local tmp sample_win out_win cfg
    tmp="$(mktemp -d)"
    sample_win="$(cygpath -m "$sample" 2>/dev/null || echo "$sample")"
    out_win="$(cygpath -m "$protected_out" 2>/dev/null || echo "$protected_out")"
    cfg="$tmp/protect.toml"
    cat > "$cfg" <<EOF
# MIT-372 measure_perf.sh 自动生成
input  = "$sample_win"
output = "$out_win"
seed   = $seed

[[passes]]
name = "pe_loader"
[[passes]]
name = "marker_scan"
[[passes]]
name = "lifter"
[[passes]]
name = "virtualize"
[[passes]]
name = "stub_link"
[[passes]]
name = "pe_writer"
EOF
    local out rc
    out="$("$cli" protect --config "$cfg" 2>&1)" || rc=$?
    rc="${rc:-0}"
    rm -rf "$tmp"
    if [[ "$rc" -ne 0 || ! -f "$protected_out" ]]; then
        echo "[protect] wvmp_cli protect 失败 ($sample rc=$rc):" >&2
        echo "$out" >&2
        return 2
    fi
    echo "[protect] OK $sample -> $protected_out (含 '已生成 N 个入口 stub' 标记 = 真虚拟化)"
    return 0
}

# 求 min / median / max. 输入一组数字 (stdin, 一行一个).
# 输出 "min|median|max", 整数化 (毫秒四舍五入到 0.1ms, KB 整数).
stats() {
    awk '
    BEGIN { min=1e18; max=-1; n=0 }
    { a[n++]=$1; sum+=$1; if ($1<min) min=$1; if ($1>max) max=$1 }
    END {
        if (n==0) { print "0|0|0"; exit }
        # median: 排序后取中间. n 奇 = a[(n-1)/2], 偶 = (a[n/2-1]+a[n/2])/2
        for (i=0;i<n-1;i++) for (j=i+1;j<n;j++) if (a[j]<a[i]) {t=a[i];a[i]=a[j];a[j]=t}
        if (n%2==1) med=a[int(n/2)]
        else med=(a[n/2-1]+a[n/2])/2
        printf "%.1f|%.1f|%.1f\n", min, med, max
    }'
}

# 解析参数.
iterations=5
output_file=""
seed=12345
force_reprotect=0
samples=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iterations)
            [[ $# -ge 2 ]] || { usage; exit 1; }
            iterations="$2"; shift 2 ;;
        --output)
            [[ $# -ge 2 ]] || { usage; exit 1; }
            output_file="$2"; shift 2 ;;
        --seed)
            [[ $# -ge 2 ]] || { usage; exit 1; }
            seed="$2"; shift 2 ;;
        --force-reprotect)
            force_reprotect=1; shift ;;
        -h|--help)
            usage; exit 0 ;;
        --)
            shift; while [[ $# -gt 0 ]]; do samples+=("$1"); shift; done ;;
        -*)
            echo "[measure] 未知选项: $1" >&2; usage; exit 1 ;;
        *)
            samples+=("$1"); shift ;;
    esac
done

if [[ ${#samples[@]} -eq 0 ]]; then
    echo "[measure] 至少需要一个 <sample.exe> 参数" >&2
    usage; exit 1
fi

if ! [[ "$iterations" =~ ^[1-9][0-9]*$ ]]; then
    echo "[measure] --iterations 必须是正整数, 收到 '$iterations'" >&2; exit 1
fi

if ! cli="$(find_cli)"; then
    echo "[measure] 未找到 wvmp_cli.exe: 请先构建 (VS 环境下)" >&2
    echo "[measure]   cmake -S . -B build/p8 -G Ninja -DWVMP_WITH_KEYSTONE=OFF -DWVMP_WITH_CAPSTONE=ON" >&2
    echo "[measure]   cmake --build build/p8 --target wvmp_cli" >&2
    exit 3
fi

echo "[measure] CLI       : $cli"
echo "[measure] iterations: $iterations"
echo "[measure] seed      : $seed"
echo "[measure] samples   : ${#samples[@]}"

if [[ -n "$output_file" ]]; then
    mkdir -p "$(dirname "$output_file")"
    : > "$output_file"  # truncate, 避免重复运行叠加
fi
# 输出缓冲: 所有 echo 既打到 stdout 也写到 output_file (若指定).
emit() {
    echo "$@"
    if [[ -n "$output_file" ]]; then
        echo "$@" >> "$output_file"
    fi
}

emit
emit "## MIT-372 perf baseline (native vs protected)"
emit
emit "- iterations: $iterations (on/off5x baseline, 派活单核心目标)"
emit "- seed: $seed"
emit "- CLI: $cli"
emit "- generated: $(date '+%Y-%m-%d %H:%M:%S')"
if command -v git >/dev/null 2>&1 && [[ -d "$repo/.git" ]]; then
    head_sha=$(git -C "$(cygpath -w "$repo")" rev-parse --short HEAD 2>/dev/null || git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo "unknown")
    head_msg=$(git -C "$(cygpath -w "$repo")" log -1 --pretty=%s 2>/dev/null || git -C "$repo" log -1 --pretty=%s 2>/dev/null || echo "unknown")
    emit "- git HEAD: ${head_sha} — ${head_msg}"
fi
emit
emit "| Sample | Mode | Run | RuntimeMs | PeakWS_KB | PeakPriv_KB | PeakPaged_KB |"
emit "|---|---|---:|---:|---:|---:|---:|"

overall_fail=0

for sample in "${samples[@]}"; do
    if [[ ! -f "$sample" ]]; then
        echo "[measure] 样本不存在: $sample" >&2
        overall_fail=1; continue
    fi

    sample_abs="$(cd "$(dirname "$sample")" && pwd)/$(basename "$sample")"
    sample_dir="$(dirname "$sample_abs")"
    sample_name="$(basename "$sample_abs")"
    base="${sample_name%.exe}"
    protected="$sample_dir/${base}.protected.exe"

    if [[ "$force_reprotect" -eq 1 || ! -f "$protected" ]]; then
        if ! protect_one "$cli" "$sample_abs" "$protected" "$seed"; then
            overall_fail=1; continue
        fi
    else
        echo "[measure] 复用已存在的 protected: $protected"
    fi

    # 字节数 (KB): 体现 binary footprint 增量.
    native_bytes=$(stat -c '%s' "$sample_abs" 2>/dev/null || stat -f '%z' "$sample_abs")
    protected_bytes=$(stat -c '%s' "$protected" 2>/dev/null || stat -f '%z' "$protected")

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    declare -a native_ms=() protected_ms=()
    declare -a native_ws=() protected_ws=()
    declare -a native_priv=() protected_priv=()
    declare -a native_page=() protected_page=()

    # 验证 native vs protected stdout 一致 (MVP P0 #1 byte-exact 退化检测).
    # 先各跑 1 次取 stdout 比较, 不一致直接判失败, 跳过本 sample 余下测量.
    native_out_file="$tmp/${base}.native.stdout.check"
    protected_out_file="$tmp/${base}.protected.stdout.check"
    measure_one "$sample_abs" "${base}.native.check" "$native_out_file" "$tmp" >/dev/null || {
        echo "[measure] native stdout 采样失败 ($sample)" >&2; overall_fail=1; rm -rf "$tmp"; continue; }
    measure_one "$protected" "${base}.protected.check" "$protected_out_file" "$tmp" >/dev/null || {
        echo "[measure] protected stdout 采样失败 ($sample)" >&2; overall_fail=1; rm -rf "$tmp"; continue; }
    if ! cmp -s "$native_out_file" "$protected_out_file"; then
        echo "[measure] FAIL byte-exact 退化 ($sample): native vs protected stdout 不一致" >&2
        diff "$native_out_file" "$protected_out_file" | head -5 >&2
        overall_fail=1; rm -rf "$tmp"; continue
    fi

    for ((i=1; i<=iterations; i++)); do
        # native run.
        ms="$(measure_one "$sample_abs" "${base}.native.${i}" "$tmp/native.${i}.stdout" "$tmp")" || {
            echo "[measure] native 测次失败 ($sample iter=$i)" >&2; overall_fail=1; continue; }
        IFS='|' read -r rt ws priv page <<<"$ms"
        native_ms+=("$rt"); native_ws+=("$ws"); native_priv+=("$priv"); native_page+=("$page")
        # 把 ws / priv / page 转 KB (PowerShell 输出是 bytes).
        ws_kb=$(awk -v b="$ws" 'BEGIN{printf "%d", b/1024}')
        priv_kb=$(awk -v b="$priv" 'BEGIN{printf "%d", b/1024}')
        page_kb=$(awk -v b="$page" 'BEGIN{printf "%d", b/1024}')
        emit "| $sample_name | native | $i | $rt | $ws_kb | $priv_kb | $page_kb |"

        # protected run.
        ms="$(measure_one "$protected" "${base}.protected.${i}" "$tmp/protected.${i}.stdout" "$tmp")" || {
            echo "[measure] protected 测次失败 ($sample iter=$i)" >&2; overall_fail=1; continue; }
        IFS='|' read -r rt ws priv page <<<"$ms"
        protected_ms+=("$rt"); protected_ws+=("$ws"); protected_priv+=("$priv"); protected_page+=("$page")
        ws_kb=$(awk -v b="$ws" 'BEGIN{printf "%d", b/1024}')
        priv_kb=$(awk -v b="$priv" 'BEGIN{printf "%d", b/1024}')
        page_kb=$(awk -v b="$page" 'BEGIN{printf "%d", b/1024}')
        emit "| $sample_name | protected | $i | $rt | $ws_kb | $priv_kb | $page_kb |"
    done

    # 聚合.
    emit
    emit "| Sample | Mode | MinMs | MedianMs | MaxMs | MinWS_KB | MedWS_KB | MaxWS_KB | MinPriv_KB | MedPriv_KB | MaxPriv_KB |"
    emit "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    nstats=$(printf '%s\n' "${native_ms[@]}" | stats)
    pstats=$(printf '%s\n' "${protected_ms[@]}" | stats)
    nws_stats=$(printf '%s\n' "${native_ws[@]}" | awk '{printf "%d\n", $1/1024}' | stats)
    pws_stats=$(printf '%s\n' "${protected_ws[@]}" | awk '{printf "%d\n", $1/1024}' | stats)
    npriv_stats=$(printf '%s\n' "${native_priv[@]}" | awk '{printf "%d\n", $1/1024}' | stats)
    ppriv_stats=$(printf '%s\n' "${protected_priv[@]}" | awk '{printf "%d\n", $1/1024}' | stats)
    emit "| $sample_name | native | $(echo "$nstats" | awk -F'|' '{print $1, $2, $3}' | tr ' ' '|') | $(echo "$nws_stats" | awk -F'|' '{print $1, $2, $3}' | tr ' ' '|') | $(echo "$npriv_stats" | awk -F'|' '{print $1, $2, $3}' | tr ' ' '|') |"
    emit "| $sample_name | protected | $(echo "$pstats" | awk -F'|' '{print $1, $2, $3}' | tr ' ' '|') | $(echo "$pws_stats" | awk -F'|' '{print $1, $2, $3}' | tr ' ' '|') | $(echo "$ppriv_stats" | awk -F'|' '{print $1, $2, $3}' | tr ' ' '|') |"

    # Overhead 倍数 (median), 派活单 §D 期望值: 启动时间 overhead ≤ 1.5x = PASS, > 5x = FAIL.
    n_med=$(echo "$nstats" | awk -F'|' '{print $2}')
    p_med=$(echo "$pstats" | awk -F'|' '{print $2}')
    n_ws_med=$(echo "$nws_stats" | awk -F'|' '{print $2}')
    p_ws_med=$(echo "$pws_stats" | awk -F'|' '{print $2}')
    if [[ -n "$n_med" ]] && awk -v n="$n_med" 'BEGIN{exit !(n+0>0)}'; then
        rt_overhead=$(awk -v n="$n_med" -v p="$p_med" 'BEGIN{printf "%.2f", p/n}')
    else
        rt_overhead="inf"
    fi
    if [[ -n "$n_ws_med" ]] && awk -v n="$n_ws_med" 'BEGIN{exit !(n+0>0)}'; then
        ws_overhead=$(awk -v n="$n_ws_med" -v p="$p_ws_med" 'BEGIN{printf "%.2f", p/n}')
    else
        ws_overhead="inf"
    fi
    native_kb=$(awk -v b="$native_bytes" 'BEGIN{printf "%d", b/1024}')
    protected_kb=$(awk -v b="$protected_bytes" 'BEGIN{printf "%d", b/1024}')
    bin_overhead=$(awk -v n="$native_kb" -v p="$protected_kb" 'BEGIN{printf "%.2f", p/n}')
    emit
    emit "| Sample | RuntimeOverhead (median ratio) | WSOverhead (median ratio) | BinarySizeOverhead | NativeKB | ProtectedKB |"
    emit "|---|---:|---:|---:|---:|---:|"
    emit "| $sample_name | ${rt_overhead}x | ${ws_overhead}x | ${bin_overhead}x | $native_kb | $protected_kb |"

    rm -rf "$tmp"
done

emit
emit "## Notes"
emit "- on/off5x 测时间 baseline: 每个 sample 每个 mode 跑 ${iterations} 次 (派活单核心目标)"
emit "- RuntimeMs: PowerShell polling 测得的 ExitTime - StartTime (毫秒, 2 位小数)"
emit "- PeakWS_KB / PeakPriv_KB / PeakPaged_KB: polling 采样的 PeakWorkingSet64 / PrivateMemorySize64 / PeakPagedMemorySize64 / 1024 (派活单 §A 妥协: polling 2ms 粒度, 极短进程可能漏掉)"
emit "- byte-exact 退化检测: 每 sample 先各跑 1 次 native / protected, stdout 不一致直接 FAIL (MVP P0 #1 保持)"
emit "- 不改 lifter / translator / asmgen / VM runtime / pe_writer / stub_link / 16 个自测样本 / 冻结契约"

if [[ "$overall_fail" -ne 0 ]]; then
    echo "[measure] 至少一个 sample 失败, 详见上表 / 上文" >&2
    exit 4
fi

echo "[measure] ALL OK"
exit 0