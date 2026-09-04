#!/usr/bin/env bash
# MIT-462: crypt+mutate 全栈管道自动回归（multiseed 口径的加密/变异变体）。
#
# 背景：MIT-458 (crypt) / MIT-459 (mutate) 落地后，其 E2E 验收依赖手工
# protect+双跑；本脚本把"mutate+crypt 全栈 8-pass 管道"纳入自动回归——
# 代表性样本池 × 5 种子，判据与 multiseed_e2e.sh 一致：
#   protect rc=0 + REQUIRE_REAL stub 标记 + native vs packed byte-exact
#   + abnormal rc (≥128 / 负值) FAIL（427 B.5 crash guard 口径）。
#
# 用法: scripts/multiseed_crypt.sh
# 退出码: 0 全 PASS; 非 0 有失败。
# 独立脚本（不改 multiseed_e2e.sh）: 基线 335-run 口径不受影响。

set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
REQUIRE_REAL=1

if [[ -f "build/cli/wvmp_cli.exe" ]]; then
    cli="build/cli/wvmp_cli.exe"
else
    echo "[crypt-regress] FAIL: wvmp_cli.exe not found (run scripts\\build.bat first)" >&2
    exit 1
fi

# 代表性样本池（4 样本覆盖：x64 整数+callgate / x64 串指令+跳表邻近面 /
# x86 push-imm+callgate / x86 除法）。路径按 multiseed_e2e.sh 池约定。
samples=(
    "build/passes/marker_scan/tests/wvmp_snake_sample.exe"
    "build/passes/marker_scan/tests/wvmp_string_ops_sample.exe"
    "build/x86_samples/wvmp_x86_pushimm_sample.exe"
    "build/x86_samples/wvmp_x86_div_sample.exe"
)

seeds=(1 12345 99999 3735928559 3405691582)

pass=0
fail=0

run_one_seed() {
    local sample="$1"
    local seed="$2"
    local sample_win
    sample_win="$(cygpath -m "$sample")"
    local tmp cfg out_win rc out rc_e rc_a
    tmp="$(mktemp -d)"
    cfg="$tmp/e2e.toml"
    out_win="$(cygpath -m "$tmp")/wvmp_crypt_out.exe"
    # mutate+crypt 全栈 8-pass（MIT-459/458）。
    cat > "$cfg" <<EOF
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
name = "mutate"
[[passes]]
name = "virtualize"
[[passes]]
name = "crypt"
[[passes]]
name = "stub_link"
[[passes]]
name = "pe_writer"
EOF
    rc=0
    out="$("$cli" protect --config "$(cygpath -w "$cfg")" 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "[crypt-regress] FAIL seed=$seed sample=$sample protect rc=$rc" >&2
        echo "$out" | tail -5 >&2
        fail=$((fail + 1))
        rm -rf "$tmp"
        return
    fi
    if ! echo "$out" | grep -q "已生成 [1-9][0-9]* 个入口 stub"; then
        echo "[crypt-regress] FAIL seed=$seed sample=$sample is C1 gate, not real virtualization" >&2
        fail=$((fail + 1))
        rm -rf "$tmp"
        return
    fi
    if ! echo "$out" | grep -q "已加密"; then
        echo "[crypt-regress] FAIL seed=$seed sample=$sample no crypt note (加密面缺失)" >&2
        fail=$((fail + 1))
        rm -rf "$tmp"
        return
    fi
    "$sample" > "$tmp/stdout.expected" 2>/dev/null
    rc_e=$?
    "$out_win" > "$tmp/stdout.actual" 2>/dev/null
    rc_a=$?
    # crash guard（427 B.5 简化口径）：任一侧 abnormal rc → FAIL。
    if (( rc_e >= 128 || rc_e < 0 )) || (( rc_a >= 128 || rc_a < 0 )); then
        echo "[crypt-regress] FAIL seed=$seed sample=$sample abnormal rc native=$rc_e packed=$rc_a" >&2
        fail=$((fail + 1))
        rm -rf "$tmp"
        return
    fi
    if [[ $rc_e -ne $rc_a ]] || ! cmp -s "$tmp/stdout.expected" "$tmp/stdout.actual"; then
        echo "[crypt-regress] FAIL seed=$seed sample=$sample stdout/rc mismatch (native=$rc_e packed=$rc_a)" >&2
        fail=$((fail + 1))
        rm -rf "$tmp"
        return
    fi
    echo "[crypt-regress] PASS seed=$seed sample=$(basename "$sample")"
    pass=$((pass + 1))
    rm -rf "$tmp"
}

for sample in "${samples[@]}"; do
    [[ -f "$sample" ]] || {
        echo "[crypt-regress] FAIL missing sample: $sample" >&2
        fail=$((fail + 5))
        continue
    }
    for seed in "${seeds[@]}"; do
        run_one_seed "$sample" "$seed"
    done
done

echo "[crypt-regress] TOTAL: $pass pass / $fail fail"
if (( fail == 0 )); then
    exit 0
fi
exit 1
