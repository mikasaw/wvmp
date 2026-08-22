#!/usr/bin/env bash
# WVmp 端到端冒烟（Git Bash 端）。
#
# 用法：scripts/e2e.sh <sample.exe>
#
# 现阶段（占位 pass）：生成临时 TOML -> wvmp_cli protect --dry-run ->
# 断言退出码 0 且输出含装配出的管道。真实管道的运行与行为比对在 M1
# 联调时启用（见文件尾部的预留块）。
#
# 退出码：0 通过；1 用法/断言失败；2 CLI 运行失败；3 CLI 未构建。

set -u

repo="$(cd "$(dirname "$0")/.." && pwd)"

usage() { echo "usage: scripts/e2e.sh <sample.exe>" >&2; }

# 定位 wvmp_cli.exe：优先 WVMP_BUILD_DIR，其次本泳道 build/p8、主 build，
# 最后在 build* 下全盘查找（多泳道并行时各有各的构建树）。
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

[[ $# -eq 1 ]] || { usage; exit 1; }
sample="$1"
[[ -f "$sample" ]] || { echo "[e2e] 找不到样本文件: $sample" >&2; exit 1; }

if ! cli="$(find_cli)"; then
    echo "[e2e] 未找到 wvmp_cli.exe：请先构建（VS 环境下），例如" >&2
    echo "[e2e]   cmake -S . -B build/p8 -G Ninja -DWVMP_WITH_KEYSTONE=OFF -DWVMP_WITH_CAPSTONE=ON" >&2
    echo "[e2e]   cmake --build build/p8 --target wvmp_cli" >&2
    exit 3
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# TOML 基本串里反斜杠是转义符；cygpath -m 输出 C:/... 正斜杠形式，安全。
sample_win="$(cygpath -m "$sample" 2>/dev/null || echo "$sample")"
out_win="$(cygpath -m "$tmp" 2>/dev/null || echo "$tmp")/wvmp_e2e_out.exe"

cfg="$tmp/e2e.toml"
cat > "$cfg" <<EOF
# scripts/e2e.sh 自动生成
input  = "$sample_win"
output = "$out_win"
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
name = "pe_writer"
EOF

echo "[e2e] CLI    : $cli"
echo "[e2e] config : $cfg"

# ---- dry-run：配置解析 + 管道装配，不落盘 -----------------------------------
dry_out="$("$cli" protect --config "$cfg" --dry-run 2>&1)"
dry_rc=$?
if [[ $dry_rc -ne 0 ]]; then
    echo "[e2e] protect --dry-run 失败 (rc=$dry_rc):" >&2
    echo "$dry_out" >&2
    exit 2
fi
echo "$dry_out"
echo "$dry_out" | grep -q "Load: pe_loader" \
    || { echo "[e2e] dry-run 输出缺少 'Load: pe_loader'" >&2; exit 2; }
echo "[e2e] dry-run OK"

# ---- 真实管道（M1 联调启用）-------------------------------------------------
# 前提：pe_loader/pe_writer（P2 泳道）等占位 pass 全部真实化。启用后：
#   1) out_exe="$tmp/wvmp_e2e_out.exe"; "$cli" protect --config "$cfg"
#        -> 断言退出码 0 且 $out_exe 存在
#   2) "$sample" > "$tmp/stdout.expected"; echo $? > "$tmp/rc.expected"
#      "$out_exe" > "$tmp/stdout.actual";  echo $? > "$tmp/rc.actual"
#   3) 比对 rc 与 stdout 逐字节一致（保护不改行为是硬约束）
# ---------------------------------------------------------------------------

echo "[e2e] PASS"
