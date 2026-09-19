#!/usr/bin/env bash
# MIT-505 (B0-2) 逐 handler 码体差分表：base ↔ head 全池采样 + 改动面自证。
#
# 判据 5 的口径：受影响的移位 handler 允许有 delta，其余 handler 必须 0 差异，
# 差异清单逐条点名；⚠️ 禁以 packed sha 恒等论证（镜像整体内嵌每个 packed exe，
# 码体一动后续偏移全体平移——MIT-433 教训，见 .multica/mit433-ruling.md）。
#
# 用法（仓库根，先各自采过一次）：
#   bash scripts/verifier/mit505_handler_diff.sh _mit505_base _mit505_head
# 采集用既有工具：
#   bash scripts/verifier/mit490_capture.sh <outdir> 12345 all
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
base="${1:?usage: $0 <base_dir> <head_dir>}"
head="${2:?usage: $0 <base_dir> <head_dir>}"
out="scripts/verifier/mit505_shiftmask_out/handler_diff_all.log"
mkdir -p "$(dirname "$out")"

# 本单预期且仅预期的改动面：build_shift 的 10 个 x64 复用者（asmgen.cpp
# build_shl/shr/sar + build_rol/ror(partial) + 五个 *_cl 变体）。
# ⚠️ adc/sbb 不在列——build_adc/build_sbb 不复用 build_shift（zero5 清宿主 CF
# 会丢 CF_in），它们出现即为改动越界。
EXPECT="rol rolcl ror rorcl sar sarcl shl shlcl shr shrcl"

{
    echo "# MIT-505 逐 handler 码体差分（base=$base head=$head，seed 12345，全池）"
    echo "# 采集=mit490_capture.sh all / 工具=mit490_flags_delta.py diff"
    echo "# 预期改动面 = {$EXPECT}"
    printf '%-46s %6s %8s  %s\n' sample handlers changed changed_handlers
} >"$out"

bad=0
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
for f in "$base"/*.handlers.csv; do
    s=$(basename "$f" .handlers.csv)
    [[ -f "$head/$s.handlers.csv" ]] || { echo "[mit505-diff] head 缺样本 $s" | tee -a "$out"; bad=$((bad + 1)); continue; }
    set +e
    PYTHONIOENCODING=utf-8 python scripts/verifier/mit490_flags_delta.py diff \
        --base "$f" --head "$head/$s.handlers.csv" --all --details 400 >"$tmp" 2>&1
    rc=$?
    set -e
    if [[ $rc -ge 2 ]]; then
        echo "[mit505-diff] 工具错误 rc=$rc: $s" | tee -a "$out"; bad=$((bad + 1)); continue
    fi
    ident=$(grep -ac 'IDENTICAL$' "$tmp" || true)
    changed=$(grep -ac 'CHANGED' "$tmp" || true)
    # 两侧 handler 集合规模（缺项/多项会在此暴露，不依赖工具的中文判词）。
    nb=$(($(wc -l <"$f") - 1))
    nh=$(($(wc -l <"$head/$s.handlers.csv") - 1))
    list=$(grep -a 'CHANGED' "$tmp" | awk '{print $1}' | LC_ALL=C sort | tr '\n' ' ')
    printf '%-46s %6s %8s  %s\n' "$s" "$nb/$nh" "$changed" "${list%-}" >>"$out"
    if [[ "${list% }" != "$EXPECT" || $((ident + changed)) -ne $nb || $nb -ne $nh ]]; then
        echo "[mit505-diff] 越界/缺项: $s (base/head=$nb/$nh ident=$ident changed=$changed) '${list%-}'" \
            | tee -a "$out"
        bad=$((bad + 1))
    fi
done

echo "---" | tee -a "$out"
echo "[mit505-diff] 改动面与预期集合完全一致的样本数不匹配计数 = $bad" | tee -a "$out"

# ---- 相位②：逐 handler 字节级 delta（比 sha 更硬的读数）----
# 期望：10 个移位 handler 各恰 1 字节变化（S32 档 `and cl, imm8` 的操作数字节
# 3f→1f，尺寸/偏移恒等），其余 handler 恰 0 字节。出现多字节或尺寸变化即为
# 越界。mit490_capture.sh 的 --out-bin 已把整块码体镜像落盘，直接对拍。
echo "--- 字节级 delta（逐 handler，全池）---" | tee -a "$out"
set +e
python - "$base" "$head" "$out" <<'PY'
import csv, os, sys
base_dir, head_dir, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
expect = {"rol", "rolcl", "ror", "rorcl", "sar", "sarcl", "shl", "shlcl", "shr", "shrcl"}
bad_rows, samples = [], 0
for fn in sorted(os.listdir(base_dir)):
    if not fn.endswith(".handlers.csv"):
        continue
    s = fn[: -len(".handlers.csv")]
    bp, hp = f"{base_dir}/{s}.bin", f"{head_dir}/{s}.bin"
    if not (os.path.exists(bp) and os.path.exists(hp)):
        continue
    b, h = open(bp, "rb").read(), open(hp, "rb").read()
    rows = list(csv.DictReader(open(f"{base_dir}/{fn}", newline="")))
    per, n = [], 0
    for r in rows:
        off, size = int(r["off"], 16), int(r["size"])
        bb, hh = b[off:off + size], h[off:off + size]
        d = [i for i in range(min(len(bb), len(hh))) if bb[i] != hh[i]]
        if len(bb) != len(hh):
            bad_rows.append(f"{s}:{r['handler']} 尺寸变了 {len(bb)}->{len(hh)}")
        n += len(d)
        if r["handler"] in expect:
            if len(d) != 1 or bb[d[0]] != 0x3F or hh[d[0]] != 0x1F:
                bad_rows.append(f"{s}:{r['handler']} 期望 1 字节 3f->1f，实得 {len(d)} "
                                f"{[hex(x) for x in d[:4]]}")
            per.append(f"{r['handler']}@{d[0]:#x}" if len(d) == 1 else f"{r['handler']}?")
        elif d:
            bad_rows.append(f"{s}:{r['handler']} 越界 delta={len(d)}")
    samples += 1
    if samples <= 2 or n != 10:
        print(f"{s:<46} total_delta={n}  offsets={' '.join(per)}")
with open(out_path, "a", encoding="utf-8") as f:
    f.write(f"# 样本 {samples} 个 × 移位 handler 10 个：期望每 handler 恰 1 字节 3f->1f，"
            f"其余 handler 0 字节\n")
    for r in bad_rows:
        f.write(f"# 越界 {r}\n")
    f.write(f"# 字节级越界计数 = {len(bad_rows)}\n")
print(f"[mit505-diff] 字节级越界计数 = {len(bad_rows)}（样本 {samples} 个）")
sys.exit(1 if bad_rows or samples == 0 else 0)
PY
rc_bytes=$?
set -e
[[ $rc_bytes -eq 0 ]] || bad=$((bad + 1))
echo "[mit505-diff] 读数 = $out" | tee -a "$out"
[[ $bad -eq 0 ]]
