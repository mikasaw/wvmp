#!/usr/bin/env bash
# MIT-465/466: TLS 回调基建 + IAT 迁移 E2E 回归（tls_hook + import_protect）。
#
# 样本 = wvmp_tls_sample（双架构，.CRT$XLB 自带用户 TLS 回调 + sdk marker
# 区域；构建配方见 build_tls_sample.bat 头注）。
#
# 判据（每架构）：
#   1. protect rc=0 且 tls_hook 报告「并入原回调 1 个」（合并面成立）、
#      import_protect 报告「IAT 迁移」（迁移面成立）；
#   2. PE 结构解析：DataDirectory[9] 指向合法 IMAGE_TLS_DIRECTORY，回调数组
#      = [占位回调][原回调][NULL]；
#   3. native vs packed stdout/rc byte-exact（打包后用户回调照常打印、虚拟化
#      行为不变、IAT 回填正确——loader 在入口前调用了合并后的回调链）；
#   4. EB FE 挂起探针打在数组第 0 项（我们的占位回调）上：进程 8s 不退出
#      = 我们的 v1 回调确实在入口前被执行（无 SEH 吞噬歧义的铁判据）。
#
# 用法: scripts/tls_e2e.sh
# 退出码: 0 全 PASS; 非 0 有失败。独立脚本（不动 multiseed_* 口径）。

set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"

CLI="build/cli/wvmp_cli.exe"
[[ -f "$CLI" ]] || { echo "[tls-e2e] FAIL: wvmp_cli.exe not found (run scripts\\build.bat)" >&2; exit 1; }

x64_sample="build/wvmp_tls_sample.exe"
x86_sample="build/x86_samples/wvmp_x86_tls_sample.exe"

pass=0
fail=0

# 解析打包产物 TLS 目录：断言 dd9 合法、数组=[our][orig][NULL]，打印回调 RVA。
parse_tls() { # $1 = exe, $2 = plus(1|0)
    python - "$1" "$2" <<'PYEOF'
import struct, sys

path, plus = sys.argv[1], sys.argv[2] == '1'
data = open(path, 'rb').read()
e = struct.unpack_from('<I', data, 0x3C)[0]
opt = e + 24
w = 8 if plus else 4
num = struct.unpack_from('<I', data, opt + (108 if plus else 92))[0]
dd_rva, dd_size = struct.unpack_from('<II', data, opt + (112 if plus else 96) + 9 * 8)
assert num >= 10, 'NumberOfRvaAndSizes < 10'
assert dd_rva != 0, 'DataDirectory[9] is zero'
assert dd_size == (40 if plus else 24), 'TLS dir size mismatch'
nsec = struct.unpack_from('<H', data, e + 6)[0]
table = opt + struct.unpack_from('<H', data, e + 20)[0]
ib = struct.unpack_from('<Q' if plus else '<I', data, opt + (24 if plus else 28))[0]

def rva2off(rva):
    for i in range(nsec):
        sh = table + i * 40
        vs, va, rs, rp = struct.unpack_from('<IIII', data, sh + 8)
        if va and va <= rva < va + max(vs, rs):
            return rp + rva - va
    return None

doff = rva2off(dd_rva)
assert doff is not None, 'TLS dir RVA not mapped'
fmt = '<QQQQII' if plus else '<IIIIII'
start, end, index, cbarr, zf, ch = struct.unpack_from(fmt, data, doff)
aoff = rva2off(cbarr - ib)
assert aoff is not None, 'callback array not mapped'
ents = []
for i in range(4):
    v = struct.unpack_from('<Q' if plus else '<I', data, aoff + i * w)[0]
    ents.append(v)
    if v == 0:
        break
assert len(ents) == 3, 'array expected [our][orig][NULL], got %r' % (ents,)
assert ents[2] == 0 and ents[0] != 0 and ents[1] != 0, 'bad entries'
our_rva = ents[0] - ib
# MIT-472 W^X 节属性断言：.wvmpc = RX（0x60000020）、.wvmp = RW（0xC0000040）
wchars = {}
for i in range(nsec):
    sh = table + i * 40
    nm = data[sh:sh+8].split(b'\x00')[0].decode()
    ch = struct.unpack_from('<I', data, sh + 36)[0]
    if nm in ('.wvmp', '.wvmpc'):
        wchars[nm] = ch
assert wchars.get('.wvmpc') == 0x60000020, '.wvmpc must be RX, got %X' % wchars.get('.wvmpc', -1)
assert wchars.get('.wvmp') == 0xC0000040, '.wvmp must be RW, got %X' % wchars.get('.wvmp', -1)
orig_rva = ents[1] - ib
assert rva2off(our_rva) is not None and rva2off(orig_rva) is not None, 'callback not mapped'
print('dir_rva=0x%X arr_rva=0x%X our_rva=0x%X orig_rva=0x%X' % (dd_rva, cbarr - ib, our_rva, orig_rva))
PYEOF
}

# EB FE 挂起探针：把数组第 0 项（我们的回调）首两字节改 jmp $，8s 超时判据。
hang_probe() { # $1 = exe, $2 = plus(1|0), $3 = out
    python - "$1" "$2" "$3" <<'PYEOF'
import struct, sys

path, plus, out = sys.argv[1], sys.argv[2] == '1', sys.argv[3]
data = bytearray(open(path, 'rb').read())
e = struct.unpack_from('<I', data, 0x3C)[0]
opt = e + 24
w = 8 if plus else 4
dd_rva, = struct.unpack_from('<I', data, opt + (112 if plus else 96) + 9 * 8)
nsec = struct.unpack_from('<H', data, e + 6)[0]
table = opt + struct.unpack_from('<H', data, e + 20)[0]
ib = struct.unpack_from('<Q' if plus else '<I', data, opt + (24 if plus else 28))[0]

def rva2off(rva):
    for i in range(nsec):
        sh = table + i * 40
        vs, va, rs, rp = struct.unpack_from('<IIII', data, sh + 8)
        if va and va <= rva < va + max(vs, rs):
            return rp + rva - va
    return None

doff = rva2off(dd_rva)
cbarr = struct.unpack_from('<Q' if plus else '<I', data, doff + 3 * w)[0]
aoff = rva2off(cbarr - ib)
our_va = struct.unpack_from('<Q' if plus else '<I', data, aoff)[0]
cboff = rva2off(our_va - ib)
assert cboff is not None, 'our callback not mapped'
data[cboff:cboff + 2] = b'\xEB\xFE'  # jmp $（死循环：执行到即挂起）
open(out, 'wb').write(bytes(data))
PYEOF
}

run_one() { # $1 = sample, $2 = plus(1|0), $3 = arch
    local sample="$1" plus="$2" arch="$3"
    local tmp cfg out_win out rc rc_e rc_a tls_line
    tmp="$(mktemp -d)"
    cfg="$tmp/e2e.toml"
    out_win="$(cygpath -m "$tmp")/wvmp_tls_out.exe"

    # 11-pass：multiseed_crypt 全栈 + anti_debug（stub 前缀 + TLS init 面 +
# [anti_debug] drx=true 的 DRx 检查面 + rdtsc=true 的计时面）+ import_protect + tls_hook
    # （stub_link 之后、pe_writer 之前；import 镜像先于 TLS 块追加）。
    cat > "$cfg" <<EOF
input  = "$(cygpath -m "$sample")"
output = "$out_win"
seed   = 1

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
    out="$("$CLI" protect --config "$(cygpath -w "$cfg")" 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "[tls-e2e] FAIL $arch protect rc=$rc" >&2; echo "$out" | tail -5 >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    fi
    if ! echo "$out" | grep -q "TLS 回调桩"; then
        echo "[tls-e2e] FAIL $arch tls_hook note missing" >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    fi
    if ! echo "$out" | grep -q "并入原回调 1 个"; then
        echo "[tls-e2e] FAIL $arch merge note missing (期望并入原回调 1 个)" >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    fi
    if ! echo "$out" | grep -q "IAT 迁移"; then
        echo "[tls-e2e] FAIL $arch import migrate note missing" >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    fi

    if ! tls_line="$(parse_tls "$tmp/wvmp_tls_out.exe" "$plus")"; then
        echo "[tls-e2e] FAIL $arch TLS parse: $tls_line" >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    fi

    # 行为 byte-exact（native vs packed；样本 main 自带 rc 哨兵）。
    "$sample" > "$tmp/stdout.expected" 2>/dev/null
    rc_e=$?
    "$tmp/wvmp_tls_out.exe" > "$tmp/stdout.actual" 2>/dev/null
    rc_a=$?
    if (( rc_e >= 128 || rc_e < 0 )) || (( rc_a >= 128 || rc_a < 0 )); then
        echo "[tls-e2e] FAIL $arch abnormal rc native=$rc_e packed=$rc_a" >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    fi
    if [[ $rc_e -ne $rc_a ]] || ! cmp -s "$tmp/stdout.expected" "$tmp/stdout.actual"; then
        echo "[tls-e2e] FAIL $arch stdout/rc mismatch" >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    fi

    # EB FE 挂起探针：我们的回调执行 => 进程挂起（超时）。
    hang_probe "$tmp/wvmp_tls_out.exe" "$plus" "$tmp/wvmp_hang.exe" || {
        echo "[tls-e2e] FAIL $arch hang probe patch failed" >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    }
    if [[ ! -f "$tmp/wvmp_hang.exe" ]]; then
        echo "[tls-e2e] FAIL $arch hang probe file missing (探针未生成=误判防线)" >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    fi
    if timeout 8 "$tmp/wvmp_hang.exe" > /dev/null 2>&1; then
        echo "[tls-e2e] FAIL $arch hang probe exited normally (回调未被执行)" >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    fi

    echo "[tls-e2e] PASS $arch ($tls_line)"
    pass=$((pass + 1))
    rm -rf "$tmp"
}

[[ -f "$x64_sample" ]] || { echo "[tls-e2e] FAIL: $x64_sample missing (build target wvmp_tls_samples)" >&2; exit 1; }
[[ -f "$x86_sample" ]] || { echo "[tls-e2e] FAIL: $x86_sample missing (build target wvmp_tls_samples)" >&2; exit 1; }

run_one "$x64_sample" 1 x64
run_one "$x86_sample" 0 x86

echo "[tls-e2e] === $pass PASS / $fail FAIL ==="
[[ $fail -eq 0 ]]
