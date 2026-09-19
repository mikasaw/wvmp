#!/usr/bin/env bash
# MIT-505 (B0-2) 移位计数掩码全网格真值表采集（可复跑读数）。
#
# 用法（仓库根）：
#   bash scripts/verifier/mit505_grid_capture.sh report [outdir] [label]   # 出全网格表，不判失败
#   bash scripts/verifier/mit505_grid_capture.sh strict                    # 逐格 EXPECT（回归钉）
#
# report 落两份读数的同一目录：CSV 网格（值列/flags 列各自独立成格）+ stdout
# 摘要日志（cells / diverge_value / diverge_flags + 逐条背离明细）。label 缺省
# 取 HEAD 短 sha + 工作树脏标记，base/head 两侧文件名不得相同（否则后采一侧会
# 覆掉修复前的真值读数——那张表才是本单的立项判据）。
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
mode="${1:-report}"
exe="build/vm/regvm/runtime/tests/wvmp_regvm_runtime_tests.exe"
[[ -f "$exe" ]] || { echo "[mit505-grid] 缺 $exe，先跑 scripts\\build.bat" >&2; exit 2; }

head_sha=$(git rev-parse --short HEAD)
dirty=$(git diff --quiet && git diff --cached --quiet || echo -dirty)
branch=$(git rev-parse --abbrev-ref HEAD)
stamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
label="${3:-${head_sha}${dirty}}"
tag="branch=$branch head=${head_sha}${dirty} label=$label utc=$stamp mode=$mode"

if [[ "$mode" == report ]]; then
    out="${2:-scripts/verifier/mit505_shiftmask_out}"
    mkdir -p "$out"
    WVMP_SHIFT_GRID_OUT="$(cygpath -m "$PWD/$out/grid_${label}.csv")" \
    WVMP_SHIFT_GRID_TAG="$tag" \
        "$exe" --gtest_filter=Interpreter.ShiftCountMaskOracleGrid \
            | tee "$out/grid_${label}.log"
    echo "[mit505-grid] tag: $tag"
    echo "[mit505-grid] CSV: $out/grid_${label}.csv"
    echo "[mit505-grid] log: $out/grid_${label}.log"
elif [[ "$mode" == strict ]]; then
    WVMP_SHIFT_GRID_STRICT=1 WVMP_SHIFT_GRID_TAG="$tag" \
        "$exe" --gtest_filter=Interpreter.ShiftCountMaskOracleGrid
    echo "[mit505-grid] STRICT PASS ($tag)"
else
    echo "[mit505-grid] mode = report | strict" >&2
    exit 2
fi
