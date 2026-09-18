#!/usr/bin/env bash
# MIT-490 (CR-01) 差分表采集：一次 protect 出 asm_dump + 保护后 PE，按 handler
# 切片码体字节 → CSV。用法（在仓库根）：
#   bash scripts/verifier/mit490_capture.sh outdir            # 默认 seed 12345
#   bash scripts/verifier/mit490_capture.sh outdir 12345
# 两侧各采一次（base = 改动前构建，head = 改动后构建），再对照出表：
#   python scripts/verifier/mit490_flags_delta.py diff --base base/x.csv --head head/x.csv --all
set -u
cd "$(cd "$(dirname "$0")/../.." && pwd)"
out="${1:-_mit490_diff}"
seed="${2:-12345}"
cli="build/cli/wvmp_cli.exe"
[[ -f "$cli" ]] || { echo "[mit490-capture] 缺 $cli，先跑 scripts\\build.bat" >&2; exit 2; }

# 采样面：默认三个移位主力样本；`all` = 直接解析 multiseed_e2e.sh 的 x64 主池
# （单一真源，池漂移不改本脚本），逐样本 protect + 采集。
samples=(
    "build/passes/marker_scan/tests/wvmp_cl_shift_sample.exe"
    "build/passes/marker_scan/tests/wvmp_rol_sample.exe"
    "build/passes/marker_scan/tests/wvmp_snake_sample.exe"
)
if [[ "${3:-}" == "all" ]]; then
    mapfile -t samples < <(sed -n '/^samples=(/,/^)/p' scripts/multiseed_e2e.sh \
        | sed -n 's/^[[:space:]]*"\(build\/[^"]*\.exe\)".*/\1/p')
    echo "[mit490-capture] 池取自 multiseed_e2e.sh samples=(...)：${#samples[@]} 样本"
fi
mkdir -p "$out"
for s in "${samples[@]}"; do
    tag=$(basename "$s" .exe)
    if [[ ! -f "$s" ]]; then
        echo "[mit490-capture] SKIP（样本产物不存在）: $s" >&2
        continue
    fi
    cfg="$out/$tag.toml"
    cat > "$cfg" <<EOF
input  = "$(cygpath -m "$PWD/$s")"
output = "$(cygpath -m "$PWD/$out")/$tag.protected.exe"
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
    WVMP_RUNTIME_DUMP="$(cygpath -m "$PWD/$out")/$tag.asm.txt" \
        "$cli" protect --config "$cfg" > "$out/$tag.protect.log" 2>&1 \
        || { echo "[mit490-capture] FAIL protect $tag" >&2; exit 1; }
    python scripts/verifier/mit490_flags_delta.py collect \
        --asm "$out/$tag.asm.txt" --pe "$out/$tag.protected.exe" \
        --out "$out/$tag.handlers.csv" --out-bin "$out/$tag.bin" || exit 1
    # 词面：.wvmp 数据节里的 WVMP blob 即翻译器落地的原始词流（v1 codec 直通），
    # flags-dead 位（cond 位 2）的 delta 在这张表上逐词可读。
    python scripts/verifier/mit490_flags_delta.py words \
        --pe "$out/$tag.protected.exe" --out "$out/$tag.words.csv" || exit 1
done
echo "[mit490-capture] OK: $out（${#samples[@]} 样本 × seed=$seed）"
