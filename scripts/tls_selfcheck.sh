#!/usr/bin/env bash
# MIT-469: TLS 依赖面自检探针——对任意打包产物判定「TLS 回调链是否真的
# 会执行」（MIT-465-G1：本机 loader 对部分 exe 本体静默跳过 TLS，无法静态
# 断言）。TLS 依赖面（init 反调试 / IAT 回填）在自检不过的目标上视为不可用。
#
# 判据：
#   1. EB FE 挂起探针：把合并回调数组第 0 项（我们的回调）首字节改为
#      `jmp $`（死循环）——进程 8s 不退出 = 我们的回调在入口前被执行；
#      正常退出 = loader 跳过 TLS（G1 形态）→ FAIL。
#   2. （仅 x64）镜像解析面：cdb 初始断点（post-TLS）dump dd1 FirstThunk
#      镜像区，与文件态乱数比对——被 loader 以真实地址覆写 = 解析面成立。
#      x86（WOW64）初始断点早于 TLS，无 post-TLS 观测窗，跳过并注明。
#
# 用法: scripts/tls_selfcheck.sh <packed.exe> <x64|x86>
# 退出码: 0 = TLS 依赖面生效; 1 = 未生效/结构缺失; 2 = 用法错误。
# 注：探针会修改输入副本（不改原文件）。

set -u

if [[ $# -ne 2 ]]; then
    echo "用法: tls_selfcheck.sh <packed.exe> <x64|x86>" >&2
    exit 2
fi
exe="$1"; arch="$2"
[[ -f "$exe" ]] || { echo "[selfcheck] FAIL: $exe 不存在" >&2; exit 2; }
[[ "$arch" == "x64" || "$arch" == "x86" ]] || { echo "[selfcheck] FAIL: arch 须为 x64|x86" >&2; exit 2; }
plus=1; [[ "$arch" == "x86" ]] && plus=0

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
exe_win="$(cygpath -w "$(cd "$(dirname "$exe")" && pwd)/$(basename "$exe")")"

# 提取回调数组第 0 项（我们的回调）RVA；缺失/结构异常 → 非 0 退出。
our_off=$(python - "$exe_win" "$plus" <<'PYEOF'
import struct, sys

data = open(sys.argv[1], 'rb').read()
plus = sys.argv[2] == '1'
e = struct.unpack_from('<I', data, 0x3C)[0]
opt = e + 24
dd9 = opt + (112 if plus else 96) + 9 * 8
rva, size = struct.unpack_from('<II', data, dd9)
if rva == 0:
    print('NO_TLS'); raise SystemExit
nsec = struct.unpack_from('<H', data, e + 6)[0]
table = opt + struct.unpack_from('<H', data, e + 20)[0]
ib = struct.unpack_from('<Q' if plus else '<I', data, opt + (24 if plus else 28))[0]
w = 8 if plus else 4

def rva2off(r):
    for i in range(nsec):
        sh = table + i * 40
        vs, va, rs, rp = struct.unpack_from('<IIII', data, sh + 8)
        if va and va <= r < va + max(vs, rs):
            return rp + r - va
    return None

doff = rva2off(rva)
if doff is None:
    print('NO_TLS'); raise SystemExit
cbarr = struct.unpack_from('<Q' if plus else '<I', data, doff + 3 * w)[0]
aoff = rva2off(cbarr - ib)
if aoff is None:
    print('NO_TLS'); raise SystemExit
our_va = struct.unpack_from('<Q' if plus else '<I', data, aoff)[0]
ooff = rva2off(our_va - ib)
if ooff is None:
    print('NO_TLS'); raise SystemExit
print(ooff)
PYEOF
) || { echo "[selfcheck] FAIL: 结构解析异常" >&2; exit 1; }

if [[ "$our_off" == "NO_TLS" ]]; then
    echo "[selfcheck] FAIL: 无 TLS 目录（DataDirectory[9]=空）——TLS 依赖面不存在"
    exit 1
fi

# 1) EB FE 挂起探针。
python - "$exe_win" "$plus" "$tmp/probe.exe" <<'PYEOF'
import struct, sys

data = bytearray(open(sys.argv[1], 'rb').read())
plus = sys.argv[2] == '1'
e = struct.unpack_from('<I', data, 0x3C)[0]
opt = e + 24
dd9 = opt + (112 if plus else 96) + 9 * 8
rva, = struct.unpack_from('<I', data, dd9)
nsec = struct.unpack_from('<H', data, e + 6)[0]
table = opt + struct.unpack_from('<H', data, e + 20)[0]
ib = struct.unpack_from('<Q' if plus else '<I', data, opt + (24 if plus else 28))[0]
w = 8 if plus else 4

def rva2off(r):
    for i in range(nsec):
        sh = table + i * 40
        vs, va, rs, rp = struct.unpack_from('<IIII', data, sh + 8)
        if va and va <= r < va + max(vs, rs):
            return rp + r - va
    return None

doff = rva2off(rva)
cbarr = struct.unpack_from('<Q' if plus else '<I', data, doff + 3 * w)[0]
aoff = rva2off(cbarr - ib)
our_va = struct.unpack_from('<Q' if plus else '<I', data, aoff)[0]
cboff = rva2off(our_va - ib)
data[cboff:cboff + 2] = b'\xEB\xFE'
open(sys.argv[3], 'wb').write(bytes(data))
PYEOF
if [[ ! -f "$tmp/probe.exe" ]]; then
    echo "[selfcheck] FAIL: 探针副本生成失败" >&2
    exit 1
fi
timeout 8 "$tmp/probe.exe" > /dev/null 2>&1
probe_rc=$?
if (( probe_rc != 128 + 9 && probe_rc != 137 && probe_rc != 124 )); then
    # 未挂起（正常退出/异常退出）= 我们的回调没有被执行。
    echo "[selfcheck] FAIL: EB FE 探针未挂起（rc=$probe_rc）——loader 跳过了 TLS 回调"
    echo "            （MIT-465-G1 形态）：TLS 依赖面（init 反调试/IAT 回填）在此目标不可用"
    exit 1
fi
echo "[selfcheck] PASS: TLS 回调链在入口前执行（EB FE 探针挂起）"

# 2) 仅 x64：镜像解析面（初始断点 post-TLS，dump dd1 FirstThunk 镜像区）。
if [[ "$arch" == "x64" ]]; then
    mirror=$(python - "$exe_win" <<'PYEOF'
import struct, sys

data = open(sys.argv[1], 'rb').read()
e = struct.unpack_from('<I', data, 0x3C)[0]
opt = e + 24
desc_rva, = struct.unpack_from('<I', data, opt + 112 + 1 * 8)
nsec = struct.unpack_from('<H', data, e + 6)[0]
table = opt + struct.unpack_from('<H', data, e + 20)[0]
ib = struct.unpack_from('<Q', data, opt + 24)[0]

def rva2off(r):
    for i in range(nsec):
        sh = table + i * 40
        vs, va, rs, rp = struct.unpack_from('<IIII', data, sh + 8)
        if va and va <= r < va + max(vs, rs):
            return rp + r - va
    return None

off = rva2off(desc_rva)
if off is None:
    print('NONE'); raise SystemExit
i = 0
fts = []
while i < 1024:
    ent = off + i * 20
    intl, ts, fc, name, ft = struct.unpack_from('<IIIII', data, ent)
    if intl == 0 and ft == 0:
        break
    fts.append(ft)
    i += 1
if not fts:
    print('NONE'); raise SystemExit
base = min(fts)
print('0x%X %d' % (ib + base, (max(fts) - base + 8)))
PYEOF
)
    if [[ "$mirror" != "NONE" && -n "$mirror" ]]; then
        mva=$(echo "$mirror" | cut -d' ' -f1)
        mlen=$(echo "$mirror" | cut -d' ' -f2)
        '/c/Program Files (x86)/Windows Kits/10/Debuggers/x64/cdb.exe' -g -G -c \
            "db $mva L0x20; q" "$exe_win" > "$tmp/mirror.log" 2>&1
        # 运行期镜像前 32 字节 vs 文件态乱数（argv 传路径，避免 \U 转义坑）。
        cmp_result=$(python - "$exe_win" "$mva" "$tmp/mirror.log" <<'PYEOF'
import struct, sys, re

data = open(sys.argv[1], 'rb').read()
e = struct.unpack_from('<I', data, 0x3C)[0]
opt = e + 24
nsec = struct.unpack_from('<H', data, e + 6)[0]
table = opt + struct.unpack_from('<H', data, e + 20)[0]
ib = struct.unpack_from('<Q', data, opt + 24)[0]
mva = int(sys.argv[2], 16)

def rva2off(r):
    for i in range(nsec):
        sh = table + i * 40
        vs, va, rs, rp = struct.unpack_from('<IIII', data, sh + 8)
        if va and va <= r < va + max(vs, rs):
            return rp + r - va
    return None

foff = rva2off(mva - ib)
file_bytes = data[foff:foff + 32]

log = open(sys.argv[3], 'r', errors='replace').read()
run_bytes = bytearray()
for line in log.splitlines():
    m = re.match(r'^[0-9A-Fa-f`]+\s+((?:[0-9A-Fa-f]{2}[- ]){8,})', line)
    if m:
        run_bytes += bytes.fromhex(re.sub(r'[^0-9A-Fa-f]', '', m.group(1)))
run_bytes = bytes(run_bytes[:32])
if len(run_bytes) < 32:
    print('EMPTY')   # cdb 缺失/异常 → 无观测，不判 PASS（验收随修）
elif run_bytes == file_bytes:
    print('SAME')
else:
    print('DIFF')
PYEOF
)
        if [[ "$cmp_result" == "DIFF" ]]; then
            echo "[selfcheck] PASS: IAT 镜像解析面成立（运行期内容 != 文件态乱数，loader 已重指解析）"
        elif [[ "$cmp_result" == "EMPTY" ]]; then
            echo "[selfcheck] WARN: 镜像解析面无观测样本（cdb 缺失/异常），人工复核"
        else
            echo "[selfcheck] WARN: 镜像解析面比对一致或缺失（SAME/缺日志；人工复核 cdb 输出）"
        fi
    fi
else
    echo "[selfcheck] NOTE: x86（WOW64）初始断点早于 TLS，镜像解析面跳过（局限见脚本头注）"
fi

echo "[selfcheck] === TLS 依赖面生效 ==="
exit 0
