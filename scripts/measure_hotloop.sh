#!/usr/bin/env bash
# MIT-494l (T34): 解释器密集微基准测量——wvmp_hotloop_sample
# （5M 次 xorshift32 ALU 循环单区域，QPC 区域内计时）。
#
# T31 口径建议落地：进程 wall clock 由启动主导（~14-15ms），解释器真实
# 开销需循环密集靶标量化。本脚本 = 打包（6-pass 基础管道）+ native /
# protected 各 N 次运行取循环计时中位 + checksum 一致性哨兵。
#
# 用法：scripts/measure_hotloop.sh [REPEATS]   （默认 5）
# 退出码：0 计时完成；2 CLI/样本未构建；3 checksum 不一致（语义红）。
#
# 注意：本样本 stdout 含非确定计时行，不进 multiseed byte-exact 池。

set -u

repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

cli="build/cli/wvmp_cli.exe"
sample="build/passes/marker_scan/tests/wvmp_hotloop_sample.exe"
repeats="${1:-5}"
[[ "$repeats" =~ ^[1-9][0-9]*$ ]] || { echo "[hotloop] REPEATS 须为正整数" >&2; exit 2; }
[[ -f "$cli" && -f "$sample" ]] || { echo "[hotloop] 未找到 $cli / $sample" >&2; exit 2; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# checksum 值提取（区域计算结果，native 与 protected 必须一致）。
checksum_of() { grep -oE 'checksum=[0-9]+' "$1" | head -1 | cut -d= -f2; }
# 循环计时行提取（毫秒）。
ms_of() { grep -oE 'ms=[0-9.]+' "$1" | head -1 | cut -d= -f2; }

median() { sort -n | awk '{a[NR]=$1} END {print (NR%2 ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2)}'; }

out="$(cygpath -m "$tmp")/hotloop_packed.exe"
cfg="$tmp/e2e.toml"
sample_win="$(cygpath -m "$sample")"
cat > "$cfg" <<EOF
input  = "$sample_win"
output = "$out"
seed   = 12345

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

rc=0
log="$("$cli" protect --config "$(cygpath -w "$cfg")" 2>&1)" || rc=$?
if [[ $rc -ne 0 || ! -f "$out" ]]; then
    echo "[hotloop] protect 失败 rc=$rc" >&2; echo "$log" | tail -3 >&2; exit 2
fi
stubs="$(echo "$log" | grep -oE '已生成 [0-9]+ 个入口 stub' | tail -1)"
echo "[hotloop] protect OK ($stubs)"

"$sample" > "$tmp/native.out" 2>/dev/null
native_rc=$?
packed_ck="$(checksum_of "$tmp/native.out")"

native_mss=()
packed_mss=()
for ((i = 1; i <= repeats; ++i)); do
    "$sample" > "$tmp/n.out" 2>/dev/null
    native_mss+=("$(ms_of "$tmp/n.out")")
    "$out" > "$tmp/p.out" 2>/dev/null
    rc_p=$?
    ck_p="$(checksum_of "$tmp/p.out")"
    if [[ $rc_p -ne 0 || "$ck_p" != "$packed_ck" ]]; then
        echo "[hotloop] FAIL 语义：protected rc=$rc_p checksum=$ck_p != native=$packed_ck" >&2
        exit 3
    fi
    packed_mss+=("$(ms_of "$tmp/p.out")")
done

n_med="$(printf '%s\n' "${native_mss[@]}" | median)"
p_med="$(printf '%s\n' "${packed_mss[@]}" | median)"
ratio="$(awk -v a="$p_med" -v b="$n_med" 'BEGIN {printf "%.1f", a/b}')"
echo "[hotloop] native 循环中位: ${n_med} ms ($repeats 次)"
echo "[hotloop] protected 循环中位: ${p_med} ms ($repeats 次, checksum=$packed_ck 一致)"
echo "[hotloop] 解释器减速比: ${ratio}x"
[[ "$native_rc" -eq 0 ]] || { echo "[hotloop] native rc=$native_crc ≠ 0" >&2; exit 3; }
exit 0
