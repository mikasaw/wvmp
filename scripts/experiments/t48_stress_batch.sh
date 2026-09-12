#!/usr/bin/env bash
# MIT-495 (T48) 施压批: 3×6GB commit 压力下重测 packed callgate (T32 同款
# 产物) 的 delta=0 事件率。有界设计: 18GB 提交 (物理 32GB/空余 ~12GB +
# 页面文件 32GB 内), 批后立即回收。
set -u
repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"
outdir="build/t48"
exe="$outdir/packed_x86callgate.exe"
[[ -f "$exe" ]] || { echo "missing $exe (先跑 t48_pack_and_measure.sh)" >&2; exit 2; }

# 可用物理内存读数 (MB): bash 单引号内纯 PS, 无嵌套转义。
free_mb() {
    powershell -NoProfile -Command '$os = Get-CimInstance Win32_OperatingSystem; [int]($os.FreePhysicalMemory/1KB)'
}

echo "[stress] commit before: $(free_mb) MB free"

for i in 1 2 3; do
    python scripts/experiments/t48_stress_hog.py 6 > "$outdir/hog_$i.log" 2>&1 &
    eval "hog_$i=$!"
done
# T48 验收 2[S]：异常终止时不留 18GB 孤儿 hog。
trap 'kill $hog_1 $hog_2 $hog_3 2>/dev/null' EXIT
sleep 25
echo "[stress] hogs up; commit now: $(free_mb) MB free"
for i in 1 2 3; do
    eval "cat \"\$outdir/hog_$i.log\""
done

bash scripts/experiments/aslr_jitter_stat.sh "$(cygpath -m "$repo/$exe")" 150 stressedX86callgate "$outdir"

kill $hog_1 $hog_2 $hog_3 2>/dev/null
sleep 3
echo "[stress] hogs down; commit after: $(free_mb) MB free"
