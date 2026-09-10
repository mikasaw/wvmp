#!/usr/bin/env bash
# MIT-494b (T26b): ASLR 模式 multiseed —— 统计判据 + delta≠0 假绿防线.
#
# 基线 multiseed_e2e.sh 的 335-run 口径不受影响 (独立脚本, 对齐
# multiseed_crypt.sh 先例)。样本池/seeds 运行时从 multiseed_e2e.sh 提取
# (eval 数组定义, 自动同步不漂移)。
#
# 每 artifact (= 样本 × seed) 三道判据:
#   (1) cdb 基址探针: 运行时模块基址 ≠ PE 优先 ImageBase (delta≠0)。
#       MIT-494a cdb 实证: 0x5C4D 类 LoadConfig.Size 腐化会让 Windows
#       loader 放弃重定位整像 → delta=0 加载 → 一切基址相关缺陷被掩盖
#       = 假绿, 常规 byte-exact 判据无法区分。探针 delta=0 一票 FAIL。
#   (2) ×REPEATS (缺省 10) 重复运行, 每次与 native stdout+rc byte-exact
#       (含 MIT-427 B.5 crash guard 口径: 双侧 abnormal + rc 相等 + 非
#       空 stdout = 设计性崩溃对拍)。
#   (3) REQUIRE_REAL=1 时校验 protect 日志含真实虚拟化 stub 标记
#       (与 multiseed_e2e_real.sh 同口径)。
#
# 用法: scripts/multiseed_aslr.sh
#   REPEATS=10        每产物重复运行次数 (缺省 10)
#   REQUIRE_REAL=1    真虚拟化标记校验 (缺省 0)
#   ASLR_PROBE=0      跳过 cdb 基址探针 (快速迭代用; 正式口径必须开)
#   ONLY=<子串>       只跑路径含该子串的样本 (定位用, 如 ONLY=forkface)
#   CDB=<路径>        cdb.exe 路径覆盖
# 退出码: 0 全 PASS; 非 0 有失败。

set -u

repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

if [[ -f "$repo/build/cli/wvmp_cli.exe" ]]; then
    cli="$repo/build/cli/wvmp_cli.exe"
elif [[ -f "$repo/build/vs/cli/Debug/wvmp_cli.exe" ]]; then
    cli="$repo/build/vs/cli/Debug/wvmp_cli.exe"
else
    echo "[aslr-multiseed] ERROR: wvmp_cli.exe 未找到, 请先跑 scripts\\build.bat" >&2
    exit 2
fi

REPEATS="${REPEATS:-10}"
if [[ ! "$REPEATS" =~ ^[1-9][0-9]*$ ]]; then
    echo "[aslr-multiseed] ERROR: REPEATS 必须为正整数 (got '$REPEATS') — 零/负次重复 = 产物零验证直通, 拒绝运行" >&2
    exit 2
fi
REQUIRE_REAL="${REQUIRE_REAL:-0}"
ASLR_PROBE="${ASLR_PROBE:-1}"
ONLY="${ONLY:-}"
CDB="${CDB:-/c/Program Files (x86)/Windows Kits/10/Debuggers/x64/cdb.exe}"
if [[ ! -f "$CDB" ]]; then
    CDB="/c/Program Files/Windows Kits/10/Debuggers/x64/cdb.exe"
fi
if [[ "$ASLR_PROBE" == "1" && ! -f "$CDB" ]]; then
    echo "[aslr-multiseed] ERROR: cdb.exe 未找到 ($CDB); 装 WinDbg 或用 CDB= 指路, 或 ASLR_PROBE=0 (不推荐)" >&2
    exit 2
fi

# 池与 seeds 运行时提取 — 数组定义整体 eval, 与基线脚本永远同源。
eval "$(sed -n -E '/^(x86_)?samples=\(/,/^\)/p' scripts/multiseed_e2e.sh)"
eval "$(grep -E '^seeds=\(' scripts/multiseed_e2e.sh)"

pass=0
fail=0

# 判据 (1): cdb 基址探针. $1 = packed exe (win 路径).
# 返回 0 = delta≠0 (好); 1 = DYNAMIC_BASE 置位但 delta=0 (MIT-494a 假绿
# 签名, FAIL); 3 = DYNAMIC_BASE 已清除 (声明回退, delta=0 是声明行为,
# 探针不适用); 2 = 探针自身出错 (基址没解析到, FAIL 以防静默)。
probe_delta() {
    local exe_win="$1"
    local tmp pref base log dll soi_hex
    tmp="$(mktemp -d)"
    log="$tmp/probe.log"
    pref="$(python - "$exe_win" <<'PYEOF'
import struct, sys
img = open(sys.argv[1], 'rb').read()
e = struct.unpack_from('<I', img, 0x3C)[0]
opt = e + 24
magic = struct.unpack_from('<H', img, opt)[0]
v = (struct.unpack_from('<Q', img, opt + 24)[0] if magic == 0x20B
     else struct.unpack_from('<I', img, opt + 28)[0])
soi = struct.unpack_from('<I', img, opt + 56)[0]
dll = struct.unpack_from('<H', img, opt + 0x46)[0]
print('0x%X' % v, hex(soi), 'NOASLR' if not (dll & 0x40) else 'ASLR')
PYEOF
)" || { rm -rf "$tmp"; return 2; }
    dll="$(echo "$pref" | awk '{print $3}')"
    soi_hex="$(echo "$pref" | awk '{print $2}')"
    pref="$(echo "$pref" | awk '{print $1}')"
    if [[ "$dll" == "NOASLR" ]]; then
        rm -rf "$tmp"
        return 3
    fi
    printf 'g\nq\n' | "$CDB" -G -logo "$log" "$exe_win" > /dev/null 2>&1
    # 主 exe 识别 = ModLoad 行中 (end-start) == SizeOfImage 的首行。x86
    # (WOW64) 进程的加载顺序存在抖动（gate 实测一次首行歧义致 delta 误
    # 判），首行假设不鲁棒；映像尺寸才是主键。去掉 cdb 地址里的反引号。
    base="$(python - "$log" "$soi_hex" <<'PYEOF'
import re, sys
soi = int(sys.argv[2], 16)
for line in open(sys.argv[1], errors='replace'):
    m = re.match(r'ModLoad: ([0-9a-f`]+) ([0-9a-f`]+)\s', line)
    if m and int(m.group(2).replace('`', ''), 16) - int(m.group(1).replace('`', ''), 16) == soi:
        print(m.group(1).replace('`', ''))
        break
PYEOF
)"
    rm -rf "$tmp"
    if [[ -z "$base" || -z "$pref" ]]; then
        return 2
    fi
    # 16# 强制十六进制 (base 无 0x 前缀且含前导零, printf/$(( )) 都会误判八进制)。
    (( 16#${base#0x} != 16#${pref#0x} ))
}

# 判据 (2)+(3): 打包 + 重复 byte-exact。$1 = native 样本, $2 = seed。
run_aslr_seed() {
    local sample="$1"
    local seed="$2"
    local tmp cfg out_win out rc i rc_e rc_a crash_e crash_a pd=0
    tmp="$(mktemp -d)"
    cfg="$tmp/e2e.toml"
    out_win="$(cygpath -m "$tmp")/wvmp_aslr_out.exe"
    cat > "$cfg" <<EOF
input  = "$sample_win"
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
    rc=0
    out="$("$cli" protect --config "$cfg" 2>&1)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "[aslr] FAIL seed=$seed sample=$sample protect rc=$rc" >&2
        echo "$out" >&2
        fail=$((fail + 1)); rm -rf "$tmp"; return
    fi
    if [[ "$REQUIRE_REAL" == "1" ]]; then
        if ! echo "$out" | grep -q "已生成 [1-9][0-9]* 个入口 stub"; then
            echo "[aslr] FAIL seed=$seed sample=$sample is C1 gate, not real virtualization" >&2
            fail=$((fail + 1)); rm -rf "$tmp"; return
        fi
    fi
    # 判据 (1): delta≠0 探针 (每 artifact 一次; loader 是否重定位是映像
    # 的确定性属性, 同机同产物逐次一致 — MIT-494a fe 全程优先基址实证)。
    # rc=1 = delta=0 假绿签名; rc=2 = 探针自身故障 (基址未解析) — 消息
    # 分开, 全池跑批时 cdb 瞬时故障才不会被误诊为假绿。
    if [[ "$ASLR_PROBE" == "1" ]]; then
        probe_delta "$out_win"
        pd=$?
        if [[ $pd == 1 ]]; then
            echo "[aslr] FAIL seed=$seed sample=$sample ASLR probe: runtime base == preferred ImageBase (delta=0, MIT-494a 假绿签名)" >&2
            fail=$((fail + 1)); rm -rf "$tmp"; return
        elif [[ $pd == 3 ]]; then
            echo "[aslr] NOTE seed=$seed sample=$(basename "$sample") DYNAMIC_BASE 清除（声明回退，探针不适用）" >&2
        elif [[ $pd != 0 ]]; then
            echo "[aslr] FAIL seed=$seed sample=$sample ASLR probe error (rc=$pd, cdb/base 解析失败 — fail-closed)" >&2
            fail=$((fail + 1)); rm -rf "$tmp"; return
        fi
    fi
    # native 参考一次, packed 重复 REPEATS 次。
    "$sample" > "$tmp/ref.out" 2>/dev/null
    rc_e=$?
    local probe_tag="probe ok"
    [[ "$pd" == "3" ]] && probe_tag="probe n/a (declared fallback)"
    for ((i = 1; i <= REPEATS; i++)); do
        "$out_win" > "$tmp/act.out" 2>/dev/null
        rc_a=$?
        # MIT-427 B.5 crash guard 口径 (移植 multiseed_e2e.sh): 映射信号
        # rc (>=128) 或裸异常码 (>=0x80000000/负) 一律 abnormal; 唯一例外
        # = 双侧 abnormal + rc 相等 + stdout 非空 (设计性崩溃对拍)。
        crash_e=0; crash_a=0
        if (( rc_e >= 128 || rc_e >= 2147483648 || rc_e < 0 )) || \
           [[ "$rc_e" == "127" && ! -s "$tmp/ref.out" ]]; then
            crash_e=1
        fi
        if (( rc_a >= 128 || rc_a >= 2147483648 || rc_a < 0 )) || \
           [[ "$rc_a" == "127" && ! -s "$tmp/act.out" ]]; then
            crash_a=1
        fi
        if [[ "$crash_e" == "1" || "$crash_a" == "1" ]]; then
            if [[ "$crash_e" == "1" && "$crash_a" == "1" && "$rc_e" == "$rc_a" && -s "$tmp/act.out" ]]; then
                :  # 设计性崩溃对拍, 本轮通过
            else
                echo "[aslr] FAIL seed=$seed sample=$sample repeat#$i abnormal rc (native=$rc_e packed=$rc_a)" >&2
                fail=$((fail + 1)); rm -rf "$tmp"; return
            fi
        elif ! cmp -s "$tmp/ref.out" "$tmp/act.out"; then
            echo "[aslr] FAIL seed=$seed sample=$sample repeat#$i stdout mismatch" >&2
            diff "$tmp/ref.out" "$tmp/act.out" >&2 | head -5 >&2
            fail=$((fail + 1)); rm -rf "$tmp"; return
        elif [[ "$rc_e" != "$rc_a" ]]; then
            echo "[aslr] FAIL seed=$seed sample=$sample repeat#$i rc mismatch $rc_e vs $rc_a" >&2
            fail=$((fail + 1)); rm -rf "$tmp"; return
        fi
    done
    echo "[aslr] PASS seed=$seed sample=$(basename "$sample") ($probe_tag, x$REPEATS byte-exact)"
    pass=$((pass + 1))
    rm -rf "$tmp"
}

run_pool() {
    local pool_name="$1"
    shift
    local sample
    for sample in "$@"; do
        if [[ -n "$ONLY" && "$sample" != *"$ONLY"* ]]; then
            continue
        fi
        if [[ ! -f "$sample" ]]; then
            echo "[aslr] 样本文件不存在: $sample" >&2
            fail=$((fail + 1))
            continue
        fi
        sample_win="$(cygpath -m "$sample")"
        local seed
        for seed in "${seeds[@]}"; do
            run_aslr_seed "$sample" "$seed"
        done
    done
}

run_pool x64 "${samples[@]}"
run_pool x86 "${x86_samples[@]}"

echo "[aslr-multiseed] TOTAL: $pass pass / $fail fail (REPEATS=$REPEATS, ASLR_PROBE=$ASLR_PROBE, REQUIRE_REAL=$REQUIRE_REAL)"
exit $((fail > 0))
