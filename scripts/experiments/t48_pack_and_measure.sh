#!/usr/bin/env bash
# MIT-495 (T48) 驱动: 打包 4 个实验产物 (与 multiseed_aslr 同 6-pass 管道)
# 并串行跑 aslr_jitter_stat.sh 测量批。
#
# 批次设计 (对照矩阵):
#   A x86 native pushimm  — OS 基线 (无 VM stub, 同 MSVC DYNAMIC_BASE 面)
#   B x86 packed pushimm@12345 — T47 抖动同款产物
#   C x86 packed callgate@1    — T32 抖动同款产物
#   D x86 packed pushmem@1     — T30 同款样本
#   E x64 packed rol@1         — 跨架构对照 (HIGHENTROPYVA 面预期 per-launch)
set -u
repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"

cli="build/cli/wvmp_cli.exe"
outdir="build/t48"
mkdir -p "$outdir"

pack() {
    local sample="$1" seed="$2" tag="$3"
    local out_win
    out_win="$(cygpath -m "$repo/$outdir")/packed_${tag}.exe"
    local cfg="$outdir/pack_${tag}.toml"
    cat > "$cfg" <<EOF
input  = "$(cygpath -m "$repo/$sample")"
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
    "$cli" protect --config "$cfg" > "$outdir/pack_${tag}.log" 2>&1
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "[t48] FAIL pack $tag rc=$rc" >&2
        tail -5 "$outdir/pack_${tag}.log" >&2
        return 1
    fi
    echo "[t48] packed $tag -> $out_win"
}

echo "=== PE heads (native) ==="
for s in build/x86_samples/wvmp_x86_pushimm_sample.exe \
         build/x86_samples/wvmp_x86_callgate_sample.exe \
         build/x86_samples/wvmp_x86_pushmem_sample.exe \
         build/passes/marker_scan/tests/wvmp_rol_sample.exe; do
    python - "$(cygpath -m "$repo/$s")" <<'PYEOF'
import struct, sys
img = open(sys.argv[1], 'rb').read()
e = struct.unpack_from('<I', img, 0x3C)[0]
opt = e + 24
magic = struct.unpack_from('<H', img, opt)[0]
dll = struct.unpack_from('<H', img, opt + 0x46)[0]
print('%s dllchars=0x%04X heva=%s dynbase=%s' % (
    sys.argv[1].rsplit('/', 1)[-1], dll,
    'Y' if dll & 0x20 else 'n', 'Y' if dll & 0x40 else 'n'))
PYEOF
done

echo "=== packing ==="
pack build/x86_samples/wvmp_x86_pushimm_sample.exe    12345 x86pushimm || exit 1
pack build/x86_samples/wvmp_x86_callgate_sample.exe   1     x86callgate || exit 1
pack build/x86_samples/wvmp_x86_pushmem_sample.exe    1     x86pushmem || exit 1
pack build/passes/marker_scan/tests/wvmp_rol_sample.exe 1   x64rol || exit 1

echo "=== batch A: x86 native pushimm (OS baseline) ==="
bash scripts/experiments/aslr_jitter_stat.sh "$(cygpath -m "$repo/build/x86_samples/wvmp_x86_pushimm_sample.exe")" 200 nativeX86pushimm "$outdir"
echo "=== batch B: x86 packed pushimm@12345 (T47) ==="
bash scripts/experiments/aslr_jitter_stat.sh "$(cygpath -m "$repo/$outdir/packed_x86pushimm.exe")" 200 packedX86pushimm "$outdir"
echo "=== batch C: x86 packed callgate@1 (T32) ==="
bash scripts/experiments/aslr_jitter_stat.sh "$(cygpath -m "$repo/$outdir/packed_x86callgate.exe")" 200 packedX86callgate "$outdir"
echo "=== batch D: x86 packed pushmem@1 (T30) ==="
bash scripts/experiments/aslr_jitter_stat.sh "$(cygpath -m "$repo/$outdir/packed_x86pushmem.exe")" 200 packedX86pushmem "$outdir"
echo "=== batch E: x64 packed rol@1 ==="
bash scripts/experiments/aslr_jitter_stat.sh "$(cygpath -m "$repo/$outdir/packed_x64rol.exe")" 200 packedX64rol "$outdir"
echo "=== ALL BATCHES DONE ==="
