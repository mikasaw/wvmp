#!/usr/bin/env bash
# Multi-seed e2e regression test.
#   - MIT-249 follow-up (issue-08): wvmp_call_gate_sample / wvmp_call_gate_simple_sample /
#     wvmp_rol_sample against 5 different seeds, asserts all PASS (callee-saved 池).
#   - MIT-300: extend to wvmp_snake_sample (贪吃蛇核心逻辑真实业务 PE).
#   - MIT-301: extend to wvmp_cl_shift_sample (cl 变体 shift 真虚拟化).
#   - MIT-302: extend to wvmp_imul_sample (有符号乘法真虚拟化).
#   - MIT-333: extend to wvmp_bswap_sample (bswap reg32/reg64 真虚拟化).
#   - MIT-334: extend to wvmp_xchg_sample (xchg r, r REG-REG 真虚拟化).
#   - MIT-336: extend to wvmp_setcc_sample (setcc REG-REG 真虚拟化).
#   - MIT-339: extend to wvmp_cmovcc_sample (cmovcc REG-REG 真虚拟化).
#   - MIT-341: extend to wvmp_cmpxchg_sample (cmpxchg REG-REG 真虚拟化).
#   - MIT-345: extend to wvmp_cl_shift_sample (movzx 8→16/16→64 真虚拟化).
#   - MIT-347: extend to wvmp_cl_shift_sample (movsx 4 形式 8→32/8→64/16→32/
#     16→64 真虚拟化, sign-extend, 与 movzx 对偶 zero-extend).
#   - MIT-371: extend to wvmp_sse_add_sample (SSE 浮点加 addss/addps/addpd 3 形式真虚拟化).
#   - MIT-373: extend to wvmp_sse_sub_sample (SSE 浮点减 subss/subps/subpd 3 形式真虚拟化).
#   - MIT-389: extend to wvmp_sse_subss_xmm_readback_sample (验收门 A.2 影子样本:
#     subss 的 ctx.xmm 运行时读回断言, 与主样本 sse_subss 同 IR 配对; 后续
#     SSE/VMX/AVX 派活单每条新指令 1 个影子样本 1:1 配对).
#   - MIT-374: extend to wvmp_sse_div_sample (SSE 浮点除 divss/divps/divpd 3 形式
#     真虚拟化) + wvmp_sse_divss_xmm_readback_sample (divss 的 ctx.xmm 读回影子样本).
#   - MIT-376: extend to wvmp_sse_bwcmp_sample (SSE 浮点位运算 xorps/orps/andps +
#     浮点比较 ucomiss/ucomisd 5 形式真虚拟化) + wvmp_sse_bwcmpss_flags_readback_sample
#     (ucomiss+seta 的 VM flags 读回影子样本, 派活单 §D D2.1 1:1 配对).
#     Total: 20 samples × 5 seeds = 100 runs.
#   - MIT-306: REQUIRE_REAL=1 校验日志含 "已生成 N 个入口 stub" 防止 C1 gate
#     兜底被误判 PASS（仅 byte-exact 不够, C1 gate 函数被跳过仍能输出相同
#     stdout+rc）。与 multiseed_e2e_real.sh 配套使用。

set -u

repo="$(cd "$(dirname "$0")/.." && pwd)"
cli="$repo/build/vs/cli/Debug/wvmp_cli.exe"

# MIT-306: REQUIRE_REAL 强校验. 设 1 时除 byte-exact 外, 还需 CLI 日志含
# "已生成 N 个入口 stub" 标记（stub_link 在 virtualize 至少产生 1 个
# VirtualizedFunction 时输出; C1 gate 兜底或无已虚拟化函数则不会出此标记）。
REQUIRE_REAL="${REQUIRE_REAL:-0}"

samples=(
    "build/passes/marker_scan/tests/wvmp_call_gate_sample.exe"
    "build/passes/marker_scan/tests/wvmp_call_gate_simple_sample.exe"
    "build/passes/marker_scan/tests/wvmp_rol_sample.exe"
    "build/passes/marker_scan/tests/wvmp_snake_sample.exe"
    "build/passes/marker_scan/tests/wvmp_cl_shift_sample.exe"
    "build/passes/marker_scan/tests/wvmp_imul_sample.exe"
    "build/passes/marker_scan/tests/wvmp_bswap_sample.exe"
    "build/passes/marker_scan/tests/wvmp_xchg_sample.exe"
    "build/passes/marker_scan/tests/wvmp_setcc_sample.exe"
    "build/passes/marker_scan/tests/wvmp_cmovcc_sample.exe"
    "build/passes/marker_scan/tests/wvmp_cmpxchg_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_add_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_sub_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_subss_xmm_readback_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_div_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_divss_xmm_readback_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_mov_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_movss_xmm_readback_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_bwcmp_sample.exe"
    "build/passes/marker_scan/tests/wvmp_sse_bwcmpss_flags_readback_sample.exe"
)

# Seeds: 1 (small), 12345 (default), 99999 (large), 0xDEADBEEF (magic), 0xCAFEBABE (magic).
seeds=(1 12345 99999 3735928559 3405691582)

pass=0
fail=0

for sample in "${samples[@]}"; do
    if [[ ! -f "$sample" ]]; then
        echo "[multiseed] 样本文件不存在: $sample" >&2
        fail=$((fail + 1))
        continue
    fi
    sample_win="$(cygpath -m "$sample")"
    for seed in "${seeds[@]}"; do
        tmp="$(mktemp -d)"
        cfg="$tmp/e2e.toml"
        out_win="$(cygpath -m "$tmp")/wvmp_e2e_out.exe"
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
            echo "[multiseed] FAIL seed=$seed sample=$sample protect rc=$rc" >&2
            echo "$out" >&2
            fail=$((fail + 1))
            rm -rf "$tmp"
            continue
        fi
        # MIT-306: REQUIRE_REAL 校验日志含 "已生成 N 个入口 stub" 标记。
        # stub_link 在 virtualize pass 至少产生 1 个 VirtualizedFunction 时输出此
        # Note; C1 gate (virtualize 放弃) 或无已虚拟化函数则不会出此标记。
        # 仅 byte-exact 不够, C1 gate 函数被跳过仍能输出相同 stdout+rc, 这是假
        # PASS——REQUIRE_REAL=1 时必须含 stub 生成标记才视为真虚拟化。
        if [[ "$REQUIRE_REAL" == "1" ]]; then
            if ! echo "$out" | grep -q "已生成 [1-9][0-9]* 个入口 stub"; then
                echo "[multiseed] FAIL seed=$seed sample=$sample is C1 gate, not real virtualization" >&2
                echo "$out" | tail -5 >&2
                fail=$((fail + 1))
                rm -rf "$tmp"
                continue
            fi
        fi
        # Run both, compare stdout + rc byte-exact.
        "$sample" > "$tmp/stdout.expected" 2>/dev/null
        echo $? > "$tmp/rc.expected"
        "$out_win" > "$tmp/stdout.actual" 2>/dev/null
        echo $? > "$tmp/rc.actual"
        if ! cmp -s "$tmp/stdout.expected" "$tmp/stdout.actual"; then
            echo "[multiseed] FAIL seed=$seed sample=$sample stdout mismatch" >&2
            diff "$tmp/stdout.expected" "$tmp/stdout.actual" >&2
            fail=$((fail + 1))
        elif [[ "$(cat "$tmp/rc.expected")" != "$(cat "$tmp/rc.actual")" ]]; then
            echo "[multiseed] FAIL seed=$seed sample=$sample rc mismatch $(cat "$tmp/rc.expected") vs $(cat "$tmp/rc.actual")" >&2
            fail=$((fail + 1))
        else
            echo "[multiseed] PASS seed=$seed sample=$(basename "$sample")"
            pass=$((pass + 1))
        fi
        rm -rf "$tmp"
    done
done

echo "[multiseed] TOTAL: $pass pass / $fail fail"
exit $((fail > 0))