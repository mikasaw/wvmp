#!/usr/bin/env bash
# MIT-495 (T48): ASLR 探针 delta=0 抖动统计实验.
#
# 背景: multiseed_aslr.sh 的 cdb 基址探针三次记录单轮 delta=0 假绿签名
# (T30 pushmem / T32 wvmp_x86_callgate / T47 pushimm@12345), 复跑即恢复。
# 现有防线 = 单次重试 (sleep 1), T47 证明抖动可连续两次 delta=0。
#
# 本脚本对一个已打包(或 native) exe 连续 N 次启动, 每次用 cdb 记录运行时
# 主模块基址 (ModLoad 行, SizeOfImage 匹配——与 probe_delta 同口径), 输出:
#   <out.csv>   每行: idx,epoch_s,base,delta0
#   stdout 摘要: 启动数 / delta=0 次数 / 首基址 / 不同基址数
#
# 判读:
#   - 不同基址数 >1 → 基址 per-launch 随机 (高熵位生效), T32 "per-boot
#     恒定"假设对该 arch 不成立。
#   - delta=0 率 >0 (含 native 对照) → OS/加载器层回落, 非产物缺陷。
#   - delta=0 连发段 (连续多次) → 抖动持续期 > 单次重试窗口, 重试预算
#     需按持续期分布定 (退避)。
#
# 用法: aslr_jitter_stat.sh <exe-win-path> [N=200] [tag=run] [outdir]
# 依赖: cdb.exe (同 multiseed_aslr.sh 探测逻辑), python。

set -u

exe_win="$1"
n="${2:-200}"
tag="${3:-run}"
outdir="${4:-build/t48}"
CDB="${CDB:-/c/Program Files (x86)/Windows Kits/10/Debuggers/x64/cdb.exe}"
if [[ ! -f "$CDB" ]]; then
    CDB="/c/Program Files/Windows Kits/10/Debuggers/x64/cdb.exe"
fi
if [[ ! -f "$CDB" ]]; then
    echo "[jitter-stat] ERROR: cdb.exe 未找到" >&2
    exit 2
fi

mkdir -p "$outdir"
csv="$outdir/t48_${tag}.csv"
echo "idx,epoch,base,delta0" > "$csv"

# PE 头解析: 优先基址 / SizeOfImage / DllCharacteristics。
head="$(python - "$exe_win" <<'PYEOF'
import struct, sys
img = open(sys.argv[1], 'rb').read()
e = struct.unpack_from('<I', img, 0x3C)[0]
opt = e + 24
magic = struct.unpack_from('<H', img, opt)[0]
plus = magic == 0x20B
v = struct.unpack_from('<Q', img, opt + 24)[0] if plus else struct.unpack_from('<I', img, opt + 28)[0]
soi = struct.unpack_from('<I', img, opt + 56)[0]
dll = struct.unpack_from('<H', img, opt + 0x46)[0]
print('0x%X 0x%X 0x%04X %s' % (v, soi, dll, 'PE32+' if plus else 'PE32'))
PYEOF
)"
pref="$(echo "$head" | awk '{print $1}')"
soi_hex="$(echo "$head" | awk '{print $2}')"
dll_hex="$(echo "$head" | awk '{print $3}')"
pekind="$(echo "$head" | awk '{print $4}')"
echo "[jitter-stat] tag=$tag exe=$exe_win pref=$pref soi=$soi_hex dllchars=$dll_hex ($pekind) n=$n"

parse_base() {
    python - "$1" "$soi_hex" <<'PYEOF'
import re, sys
soi = int(sys.argv[2], 16)
for line in open(sys.argv[1], errors='replace'):
    m = re.match(r'ModLoad: ([0-9a-f`]+) ([0-9a-f`]+)\s', line)
    if m and int(m.group(2).replace('`', ''), 16) - int(m.group(1).replace('`', ''), 16) == soi:
        print(m.group(1).replace('`', ''))
        break
PYEOF
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
delta0=0
first_base=""
declare -A bases=()
for ((i = 1; i <= n; i++)); do
    log="$tmp/probe_$i.log"
    # T48 验收 2[S]：与主脚本同款 timeout 封装（挂死形态 = EOF-stdin 无限等待）。
    printf 'g\nq\n' | timeout "${CDB_TIMEOUT:-30}" "$CDB" -G -logo "$log" "$exe_win" > /dev/null 2>&1
    base="$(parse_base "$log")"
    now="$(date +%s)"
    if [[ -z "$base" ]]; then
        echo "$i,$now,PARSE_FAIL," >> "$csv"
        echo "[jitter-stat] WARN run#$i 基址未解析 (ParseFail)" >&2
        continue
    fi
    [[ -z "$first_base" ]] && first_base="$base"
    bases["$base"]=1
    if (( 16#${base#0x} == 16#${pref#0x} )); then
        delta0=$((delta0 + 1))
        echo "$i,$now,$base,1" >> "$csv"
        echo "[jitter-stat] ** delta=0 @ run#$i (epoch=$now)" >&2
    else
        echo "$i,$now,$base,0" >> "$csv"
    fi
done

distinct=${#bases[@]}
echo "[jitter-stat] SUMMARY tag=$tag n=$n delta0=$delta0 distinct_bases=$distinct first_base=$first_base"
for b in "${!bases[@]}"; do
    echo "[jitter-stat]   base=$b"
done
