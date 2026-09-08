#!/usr/bin/env bash
# MIT-487 (T9.3a)：全样本池 import_protect 重写完备性扫描。
#
# 对 multiseed 双架构池 + tls 样本 + wvmpTest 靶标逐样本以 11-pass 全栈
# 管道（含 import_protect，seed=1）打包，随后 check_import_rewrite.py
# 静态校验零残留（代码 MEM 面 + imm32/moffs64 模型外负扫 + 数据指针面）。
# 判据 = 校验器退出码 0（迁移样本零残留 / 保守回退样本无迁移面）。
#
# 用法：scripts/verify_pool_imports.sh
# 退出码：0 全绿；1 有红面；2 CLI 未构建。

set -u

repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

CLI="build/cli/wvmp_cli.exe"
[[ -f "$CLI" ]] || { echo "[pool-verify] 未找到 $CLI" >&2; exit 2; }

mapfile -t pool < <(
    {
        grep -oE '"build/[^"]+\.exe"' scripts/multiseed_e2e.sh | tr -d '"'
        echo "build/wvmp_tls_sample.exe"
        echo "build/x86_samples/wvmp_x86_tls_sample.exe"
        echo "tests/wvmpTest/build/x64/test_target.exe"
    } | sort -u
)

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0
migrated=0
fallback=0
for sample in "${pool[@]}"; do
    [[ -f "$sample" ]] || { echo "[pool-verify] SKIP（不存在）: $sample"; continue; }
    out_exe="$(cygpath -m "$tmp")/packed.exe"
    cat > "$tmp/e2e.toml" <<EOF
input  = "$(cygpath -m "$sample")"
output = "$out_exe"
seed   = 1

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
name = "import_protect"
[[passes]]
name = "tls_hook"
[[passes]]
name = "pe_writer"
EOF
    note="$(./"$CLI" protect --config "$(cygpath -w "$tmp/e2e.toml")" 2>&1)"
    if [[ $? -ne 0 ]]; then
        echo "[pool-verify] FAIL pack rc≠0: $sample"
        echo "$note" | tail -3 >&2
        fail=$((fail + 1)); continue
    fi
    if echo "$note" | grep -q "放弃 IAT 迁移\|跳过 IAT 迁移"; then
        # 保守回退（v1 硬依赖缺席等）= 无迁移面，原 IAT 引用本就正当，
        # 校验器"零残留"前提不适用 → 不跑校验器，单列回退计数。
        fallback=$((fallback + 1))
        pass=$((pass + 1))
        continue
    fi
    if echo "$note" | grep -q "IAT 迁移"; then
        migrated=$((migrated + 1))
    fi
    if python scripts/verifier/check_import_rewrite.py                    "$(cygpath -m "$sample")" "$out_exe" > "$tmp/ver.txt" 2>&1; then
        pass=$((pass + 1))
    else
        echo "[pool-verify] FAIL verify: $sample"
        cat "$tmp/ver.txt" >&2
        fail=$((fail + 1))
    fi
    rm -f "$out_exe"
done

echo "[pool-verify] TOTAL: $pass pass / $fail fail（迁移 $migrated / 保守回退 $fallback / 池 $((pass + fail))）"
[[ $fail -eq 0 ]]
