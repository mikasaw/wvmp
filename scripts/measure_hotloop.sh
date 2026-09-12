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
# MIT-494m (T35)：ARCH=x86 切 x86 靶标（build/x86_samples 池约定路径）。
arch="${ARCH:-x64}"
# T35 验收 SH1：未知 ARCH fail-closed（静默回退 x64 会让拼错大小写的
# x86 测量被当 x64 数据记录）。
if [[ "$arch" == "x86" ]]; then
    sample="build/x86_samples/wvmp_x86_hotloop_sample.exe"
elif [[ "$arch" == "x64" ]]; then
    sample="build/passes/marker_scan/tests/wvmp_hotloop_sample.exe"
elif [[ "$arch" == "x64asm" ]]; then
    # T40 同词密度对照：x64 asm 区域（与 x86 asm 样本逐词同形）
    sample="build/passes/marker_scan/tests/wvmp_hotloop_asm_sample.exe"
elif [[ "$arch" == "x64mem" || "$arch" == "x64br" || "$arch" == "x86mem" || "$arch" == "x86br" ]]; then
    # T41 词形态矩阵：LD/ST 密度（*mem）与分支/标志密度（*br）
    if [[ "$arch" == x64* ]]; then
        sample="build/passes/marker_scan/tests/wvmp_hotloop_${arch#x64}_sample.exe"
    else
        sample="build/x86_samples/wvmp_x86_hotloop_${arch#x86}_sample.exe"
    fi
else
    echo "[hotloop] 未知 ARCH='$arch'（支持 x64/x86/x64asm/x64mem/x64br/x86mem/x86br）" >&2
    exit 2
fi
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
# MIT-306 REQUIRE_REAL 纪律：区域整函数 gate 退化时脚本须红灯而非静默 ~1.0x。
if ! echo "$stubs" | grep -qE '已生成 [1-9]'; then
    echo "[hotloop] FAIL 非真虚拟化（$stubs / C1 gate 退化）" >&2; exit 3
fi
echo "[hotloop] protect OK ($stubs)"

"$sample" > "$tmp/native.out" 2>/dev/null
native_rc=$?
if [[ $native_rc -ne 0 ]]; then
    echo "[hotloop] FAIL native rc=$native_rc ≠ 0（样本哨兵/锚漂移）" >&2; exit 3
fi
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
echo "[hotloop] native 循环中位: ${n_med} ms ($arch, $repeats 次)"
echo "[hotloop] protected 循环中位: ${p_med} ms ($arch, $repeats 次, checksum=$packed_ck 一致)"
echo "[hotloop] 解释器减速比: ${ratio}x"
exit 0
