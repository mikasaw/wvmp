#!/usr/bin/env bash
# Multi-seed e2e regression test.
#   - MIT-249 follow-up (issue-08): wvmp_call_gate_sample / wvmp_call_gate_simple_sample /
#     wvmp_rol_sample against 5 different seeds, asserts all PASS (callee-saved 池).
#   - MIT-300: extend to wvmp_snake_sample (贪吃蛇核心逻辑真实业务 PE).
#     Total: 4 samples × 5 seeds = 20 runs.

set -u

repo="$(cd "$(dirname "$0")/.." && pwd)"
cli="$repo/build/cli/wvmp_cli.exe"

samples=(
    "build/passes/marker_scan/tests/wvmp_call_gate_sample.exe"
    "build/passes/marker_scan/tests/wvmp_call_gate_simple_sample.exe"
    "build/passes/marker_scan/tests/wvmp_rol_sample.exe"
    "build/passes/marker_scan/tests/wvmp_snake_sample.exe"
)

# Seeds: 1 (small), 12345 (default), 99999 (large), 0xDEADBEEF (magic), 0xCAFEBABE (magic).
seeds=(1 12345 99999 3735928559 3405691582)

pass=0
fail=0

for sample in "${samples[@]}"; do
    if [[ ! -f "$sample" ]]; then
        echo "[multiseed] 样本文件不存在: $sample" >&2
        fail=$((fail + 1))
        continue
    fi
    sample_win="$(cygpath -m "$sample")"
    for seed in "${seeds[@]}"; do
        tmp="$(mktemp -d)"
        cfg="$tmp/e2e.toml"
        out_win="$(cygpath -m "$tmp")/wvmp_e2e_out.exe"
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
name = "virtualize"
[[passes]]
name = "stub_link"
[[passes]]
name = "pe_writer"
EOF
        rc=0
        out="$("$cli" protect --config "$cfg" 2>&1)" || rc=$?
        if [[ $rc -ne 0 ]]; then
            echo "[multiseed] FAIL seed=$seed sample=$sample protect rc=$rc" >&2
            echo "$out" >&2
            fail=$((fail + 1))
            rm -rf "$tmp"
            continue
        fi
        # Run both, compare stdout + rc byte-exact.
        "$sample" > "$tmp/stdout.expected" 2>/dev/null
        echo $? > "$tmp/rc.expected"
        "$out_win" > "$tmp/stdout.actual" 2>/dev/null
        echo $? > "$tmp/rc.actual"
        if ! cmp -s "$tmp/stdout.expected" "$tmp/stdout.actual"; then
            echo "[multiseed] FAIL seed=$seed sample=$sample stdout mismatch" >&2
            diff "$tmp/stdout.expected" "$tmp/stdout.actual" >&2
            fail=$((fail + 1))
        elif [[ "$(cat "$tmp/rc.expected")" != "$(cat "$tmp/rc.actual")" ]]; then
            echo "[multiseed] FAIL seed=$seed sample=$sample rc mismatch $(cat "$tmp/rc.expected") vs $(cat "$tmp/rc.actual")" >&2
            fail=$((fail + 1))
        else
            echo "[multiseed] PASS seed=$seed sample=$(basename "$sample")"
            pass=$((pass + 1))
        fi
        rm -rf "$tmp"
    done
done

echo "[multiseed] TOTAL: $pass pass / $fail fail"
exit $((fail > 0))