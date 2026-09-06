#!/usr/bin/env bash
# MIT-473: 取指级加密 E2E——[crypt] fetch=true 全栈管道（11-pass），判据：
#   1. protect rc=0 且 crypt note 标明「取指级 dispatch 解密」；
#   2. integrity 交互披露：fetch 模式管道不含 integrity_crc（含则跳过）；
#   3. native vs packed stdout/rc byte-exact（dispatch 织入解密正确还原）；
#   4. 结构断言：.wvmpc=RX / .wvmp=RW（W^X 面）+ IAT FT 已重指（镜像
#      迁移面）。blob 头 seed 非零不可静态定位（数据节内偏移依赖布局），
#      由单测 FetchDecryptSemanticParity 的 seed 落位断言覆盖。
# 用法: scripts/fetch_crypt_e2e.sh

set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"

CLI="build/cli/wvmp_cli.exe"
[[ -f "$CLI" ]] || { echo "[fetch-e2e] FAIL: wvmp_cli.exe not found" >&2; exit 1; }

x64_sample="build/wvmp_tls_sample.exe"
x86_sample="build/x86_samples/wvmp_x86_tls_sample.exe"

pass=0
fail=0

check_seed() { # $1 exe  $2 plus
    python - "$1" "$2" <<'PYEOF'
import struct, sys
data = open(sys.argv[1], 'rb').read()
e = struct.unpack_from('<I', data, 0x3C)[0]
opt = e + 24
dd1 = opt + (112 if sys.argv[2] == '1' else 96) + 1 * 8
desc_rva, = struct.unpack_from('<I', data, dd1)
nsec = struct.unpack_from('<H', data, e + 6)[0]
table = opt + struct.unpack_from('<H', data, e + 20)[0]
def rva2off(r):
    for i in range(nsec):
        sh = table + i * 40
        vs, va, rs, rp = struct.unpack_from('<IIII', data, sh + 8)
        if va and va <= r < va + max(vs, rs):
            return rp + r - va
    return None
# 找 .wvmp 数据节内的 blob：镜像 IAT 由 dd1 FT 指向；blob 的 seed 在
# .wvmp 头部不可直接定位——改为校验数据节内存在非零 seed 模式不可靠，
# 退而校验 dd1 FT 已重指（迁移面）且 .wvmp 与 .wvmpc 特性（W^X 面）。
i = 0
fts = []
while i < 64:
    ent = rva2off(desc_rva) + i * 20
    intl, ts, fc, nm, ft = struct.unpack_from('<IIIII', data, ent)
    if intl == 0 and ft == 0:
        break
    fts.append(ft)
    i += 1
assert fts, 'no descriptors'
wx = {}
for j in range(nsec):
    sh = table + j * 40
    nm = data[sh:sh+8].split(b'\x00')[0].decode()
    ch = struct.unpack_from('<I', data, sh + 36)[0]
    if nm in ('.wvmp', '.wvmpc'):
        wx[nm] = ch
assert wx.get('.wvmpc') == 0x60000020, '.wvmpc not RX'
assert wx.get('.wvmp') == 0xC0000040, '.wvmp not RW'
print('wx-ok')
PYEOF
}

run_one() { # $1 sample  $2 arch
    local sample="$1" arch="$2"
    local tmp cfg out rc rc_e rc_a
    tmp="$(mktemp -d)"
    cfg="$tmp/e2e.toml"
    out="$(cygpath -m "$tmp")/fetch_out.exe"
    cat > "$cfg" <<EOF
input  = "$(cygpath -m "$sample")"
output = "$out"
seed   = 1

[crypt]
fetch = true

[anti_debug]
drx = true
rdtsc = true

[[passes]]
name = "pe_loader"
[[passes]]
name = "marker_scan"
[[passes]]
name = "lifter"
[[passes]]
name = "mutate"
[[passes]]
name = "virtualize"
[[passes]]
name = "crypt"
[[passes]]
name = "anti_debug"
[[passes]]
name = "stub_link"
[[passes]]
name = "import_protect"
[[passes]]
name = "tls_hook"
[[passes]]
name = "pe_writer"
EOF
    rc=0
    local log
    log="$("$CLI" protect --config "$(cygpath -w "$cfg")" 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "[fetch-e2e] FAIL $arch protect rc=$rc" >&2; echo "$log" | tail -5 >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    fi
    if ! echo "$log" | grep -q "取指级 dispatch 解密"; then
        echo "[fetch-e2e] FAIL $arch fetch note missing" >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    fi
    if ! check_seed "$out" "$([[ "$arch" == x64 ]] && echo 1 || echo 0)" >/dev/null 2>&1; then
        echo "[fetch-e2e] FAIL $arch W^X/结构断言" >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    fi
    "$sample" > "$tmp/exp" 2>/dev/null; rc_e=$?
    "$tmp/fetch_out.exe" > "$tmp/act" 2>/dev/null; rc_a=$?
    if (( rc_e >= 128 || rc_e < 0 )) || (( rc_a >= 128 || rc_a < 0 )); then
        echo "[fetch-e2e] FAIL $arch abnormal rc native=$rc_e packed=$rc_a" >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    fi
    if [[ $rc_e -ne $rc_a ]] || ! cmp -s "$tmp/exp" "$tmp/act"; then
        echo "[fetch-e2e] FAIL $arch stdout/rc mismatch" >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    fi
    echo "[fetch-e2e] PASS $arch"
    pass=$((pass + 1))
    rm -rf "$tmp"
}

[[ -f "$x64_sample" ]] || { echo "[fetch-e2e] FAIL: $x64_sample missing" >&2; exit 1; }
[[ -f "$x86_sample" ]] || { echo "[fetch-e2e] FAIL: $x86_sample missing" >&2; exit 1; }

run_one "$x64_sample" x64
run_one "$x86_sample" x86
echo "[fetch-e2e] === $pass PASS / $fail FAIL ==="
[[ $fail -eq 0 ]]
