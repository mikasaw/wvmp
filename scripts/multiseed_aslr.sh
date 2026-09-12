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
#   PROBE_ATTEMPTS=4  delta=0 退避重试次数含首发 (T48, 间隔 1/2/4s)
#   ONLY=<子串>       只跑路径含该子串的样本 (定位用, 如 ONLY=forkface)
#   CDB=<路径>        cdb.exe 路径覆盖
#   CDB_TIMEOUT=30    单次 cdb 启动超时秒数 (T48, 超时 = 探针故障 fail-closed)
# 退出码: 0 全 PASS; 非 0 有失败。

set -u

# T48 预检: 残留 cdb 进程 = 上一轮中断的探针尸体，实测会系统性污染后续
# 池跑的基址探针读数（当日 335/335 首启 delta=0 事件批与 3 个残留 cdb
# 共存；清理后所有孤立复现均转正常）。fail-closed 拒绝运行。
if [[ "${ASLR_PROBE:-1}" == "1" ]]; then
    stale_cdb="$(powershell -NoProfile -Command '(Get-Process cdb -ErrorAction SilentlyContinue | Measure-Object).Count' 2>/dev/null || true)"
    # 验收 1d：查询失败不可静默放行（残留 cdb 实证污染探针读数，查询失败
    # 恰是最该暴露的状态）→ fail-closed exit 2。
    if [[ -z "${stale_cdb:-}" ]]; then
        echo "[aslr-multiseed] ERROR: 残留 cdb 预检查询失败 (powershell 不可用/被拦截) — fail-closed (T48 验收 1d)" >&2
        exit 2
    fi
    if [[ "$stale_cdb" -gt 0 ]]; then
        echo "[aslr-multiseed] ERROR: 检测到 $stale_cdb 个残留 cdb 进程 — 先清理 (Stop-Process -Name cdb) 再跑, 残留调试态会污染基址探针 (T48)" >&2
        exit 2
    fi
fi

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
# T48: delta=0 退避重试次数（含首发，间隔 1/2/...s 指数退避；4 = 覆盖
# T47 实测连两次 delta=0 形态外加倍余量）。ASLR_PROBE=0 时无意义。
PROBE_ATTEMPTS="${PROBE_ATTEMPTS:-4}"
if [[ ! "$PROBE_ATTEMPTS" =~ ^[1-9][0-9]*$ ]]; then
    echo "[aslr-multiseed] ERROR: PROBE_ATTEMPTS 必须为正整数 (got '$PROBE_ATTEMPTS')" >&2
    exit 2
fi
JITTER_EVENTS=0          # 全池抖动恢复事件计数（TOTAL 行披露）
PROBE_ATTEMPTS_USED=1    # 最近一次探针实际启动次数（PASS 标签披露）
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
# T48: parse_modbase 抽取（原两份内联 python 重复块）+ 退避重试（见函数内
# 注释）；JITTER_EVENTS/PROBE_ATTEMPTS_USED = 抖动可见性披露通道。
parse_modbase() {
    # $1 = cdb 日志, $2 = SizeOfImage (hex) → stdout = 主模块基址（空 = 未解析）。
    python - "$1" "$2" <<'PYEOF'
import re, sys
soi = int(sys.argv[2], 16)
for line in open(sys.argv[1], errors='replace'):
    m = re.match(r'ModLoad: ([0-9a-f`]+) ([0-9a-f`]+)\s', line)
    if m and int(m.group(2).replace('`', ''), 16) - int(m.group(1).replace('`', ''), 16) == soi:
        print(m.group(1).replace('`', ''))
        break
PYEOF
}

probe_delta() {
    local exe_win="$1"
    local tmp pref base log dll soi_hex attempt=1
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
    # T48: cdb 调用加 timeout 封装——T48 当日实测 debuggee 不退出时 cdb
    # 携 EOF-stdin 无限等待（探针挂死整池）。超时 = 探针故障 (rc=2)
    # fail-closed，不产生半截日志误读。
    printf 'g\nq\n' | timeout "${CDB_TIMEOUT:-30}" "$CDB" -G -logo "$log" "$exe_win" > /dev/null 2>&1
    # 主 exe 识别 = ModLoad 行中 (end-start) == SizeOfImage 的首行。x86
    # (WOW64) 进程的加载顺序存在抖动（gate 实测一次首行歧义致 delta 误
    # 判），首行假设不鲁棒；映像尺寸才是主键。去掉 cdb 地址里的反引号。
    base="$(parse_modbase "$log" "$soi_hex")"
    # T48 验收 C1 修复：首启探针故障 fail-closed 守卫（重写时曾遗失——
    # cdb 超时/启动失败/日志不可解析 → base 空 → 无守卫则下游 16# 空操作
    # 数算术假 → return 0 "probe ok" = 静默假绿通道）。恢复旧 rc=2 契约。
    if [[ -z "$base" || -z "$pref" ]]; then
        rm -rf "$tmp"
        return 2
    fi
    # T48 调试钩子: ASLR_DEBUG_KEEP=<dir> 时保留 delta=0 首启日志（诊断用，
    # 正式口径不设 → 零行为差异）。
    if [[ -n "${ASLR_DEBUG_KEEP:-}" && -n "$base" && -n "$pref" ]] && \
       (( 16#${base#0x} == 16#${pref#0x} )); then
        cp "$log" "${ASLR_DEBUG_KEEP}/dbg_attempt1_$$.log"
    fi
    # T32：delta=0 抖动复测 → T48 升级为退避重试（PROBE_ATTEMPTS 次，
    # 间隔 1/2/4s，自 attempt=2 起）。实证依据（scripts/experiments/
    # t48_pack_and_measure.sh + t48_stress_batch.sh，2026-09-12）：
    #   ① 空闲态 5 产物 × 200 = 1000 次 + 18GB commit 压力 150 次，
    #      delta=0 零出现——抖动率 <1/1150，空闲/受压受控条件均未复现；
    #      三例历史事件（T30 pushmem / T32 callgate / T47 pushimm）全部
    #      发生在全池跑批负载窗口（打包连发 + Defender 逐产物扫描 + cdb
    #      内存峰值组合，无法受控隔离 → 按环境偶发通道管理）。
    #   ② 同产物基址"窗口内恒定"：批内 200/200 同基址；两批间隔 ~40min
    #      基址重掷（0x920000→0x460000）——T32 的"per-boot 恒定"表述
    #      修正为"窗口内恒定"（重掷事件级 trigger 未定位）。
    #   语义不变量：重试窗口（秒级）内基址稳定 → 真假绿（loader 放弃
    #   重定位的映像级缺陷）跨次稳定 delta=0，重试不会误放行；T47 实测
    #   抖动可连续两次 delta=0（T32 单次重试不足）→ 4 次覆盖全部三例
    #   单点事件形态。
    #   ⚠️ 仅当首启 delta=0 才进入重试（T32 原门语义；返工记录：一度
    #   丢门致无条件重试把正常产物全误标 jitter——attempt2 正常恢复被
    #   计为"抖动恢复"，335/335 幻影计数）。
    if [[ -n "$base" ]] && (( 16#${base#0x} == 16#${pref#0x} )); then
        for ((attempt = 2; attempt <= PROBE_ATTEMPTS; attempt++)); do
            sleep $((1 << (attempt - 2)))
            printf 'g\nq\n' | timeout "${CDB_TIMEOUT:-30}" "$CDB" -G -logo "$log" "$exe_win" > /dev/null 2>&1
            base="$(parse_modbase "$log" "$soi_hex")"
            if [[ -z "$base" ]]; then
                rm -rf "$tmp"
                return 2
            fi
            if (( 16#${base#0x} != 16#${pref#0x} )); then
                break
            fi
        done
    fi
    PROBE_ATTEMPTS_USED=$attempt
    rm -rf "$tmp"
    if (( 16#${base#0x} == 16#${pref#0x} )); then
        # 持续 delta=0：FAIL 前记录内存水位（未来事件归因线索，T48 披露面）。
        local mem_state
        mem_state="$(powershell -NoProfile -Command '$os = Get-CimInstance Win32_OperatingSystem; "phys_free={0:N0}MB" -f ($os.FreePhysicalMemory/1KB)' 2>/dev/null)" || mem_state="mem n/a"
        echo "[aslr] probe: delta=0 持续 $PROBE_ATTEMPTS 次（退避重试未恢复; $mem_state）" >&2
        return 1
    fi
    if (( PROBE_ATTEMPTS_USED > 1 )); then
        JITTER_EVENTS=$((JITTER_EVENTS + 1))
        echo "[aslr] NOTE probe: delta=0 抖动，重试 $((PROBE_ATTEMPTS_USED - 1)) 次恢复（jitter#$JITTER_EVENTS）" >&2
    fi
    # 16# 强制十六进制 (base 无 0x 前缀且含前导零, printf/$(( )) 都会误判八进制)。
    return 0
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
    # 判据 (1): delta≠0 探针 (每 artifact 一次, 含 T48 退避重试)。
    # T48 实证修正: 基址"窗口内恒定"（非 per-boot 绝对恒定，~40min 级
    # 重掷事件存在），且 delta=0 存在低率负载相关抖动（T30/T32/T47 +
    # T48 活体观测）——重试语义见 probe_delta 内注释。
    # rc=1 = 持续 delta=0 假绿签名; rc=2 = 探针自身故障 (基址未解析) —
    # 消息分开, 全池跑批时 cdb 瞬时故障才不会被误诊为假绿。
    if [[ "$ASLR_PROBE" == "1" ]]; then
        PROBE_ATTEMPTS_USED=1
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
    [[ "$pd" == "0" && "$PROBE_ATTEMPTS_USED" -gt 1 ]] && probe_tag="probe ok (jitter x$((PROBE_ATTEMPTS_USED - 1)))"
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

echo "[aslr-multiseed] TOTAL: $pass pass / $fail fail (REPEATS=$REPEATS, ASLR_PROBE=$ASLR_PROBE, REQUIRE_REAL=$REQUIRE_REAL, PROBE_ATTEMPTS=$PROBE_ATTEMPTS, jitter_events=$JITTER_EVENTS)"
exit $((fail > 0))
