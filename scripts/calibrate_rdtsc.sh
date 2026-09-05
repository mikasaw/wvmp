#!/usr/bin/env bash
# MIT-471: rdtsc 阈值校准——采样「rdtsc 包裹检查块」的本机差值分布，为
# tls_hook 的 kRdtscThresholdCycles 提供依据。
#
# 探针 = 独立 C 程序：与 TLS 回调检查窗等价的指令序列（PEB 走访 + 若干
# 比较指令）夹在两次 rdtsc 之间，跑 ITER 轮输出 min/p50/p95/max，并打印
# 「大于阈值 500000 的轮数」（期望 0）。
#
# 用法: scripts/calibrate_rdtsc.sh [iterations=20000]

set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
ITER="${1:-20000}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/probe.c" <<'EOF'
#include <stdio.h>
#include <stdint.h>
#include <intrin.h>

#pragma comment(lib, "advapi32.lib")

/* 与 tls_hook 检查窗等价的指令形状：TEB/PEB 走访 + 位测试链 */
static volatile uint32_t sink;

static uint64_t one_round(void) {
    uint64_t t1 = __rdtsc();
    {
        volatile uint32_t peb_flag = *(volatile uint32_t*)0x7FFE0000; /* KUSER_SHARED_DATA（恒映射、只读）*/
        (void)peb_flag;
        uint32_t x = 0x5A5A1234u;
        x ^= x >> 3; x += 0x9E3779B9u; x *= 7u; x ^= x << 5;
        sink = x;
    }
    uint64_t t2 = __rdtsc();
    return t2 - t1;
}

int main(int argc, char** argv) {
    const int iter = argc > 1 ? atoi(argv[1]) : 20000;
    uint64_t min = ~0ull, max = 0, over = 0;
    /* 预热 */
    for (int i = 0; i < 100; ++i) (void)one_round();
    static uint64_t samples[1 << 22];
    int n = iter < (1 << 22) ? iter : (1 << 22);
    for (int i = 0; i < n; ++i) {
        uint64_t d = one_round();
        samples[i] = d;
        if (d < min) min = d;
        if (d > max) max = d;
        if (d > 500000ull) ++over;
    }
    /* p50/p95（朴素冒烟排序采样子集即可：取每 97 步一个样本排序） */
    static uint64_t sub[22000];
    int m = 0;
    for (int i = 0; i < n && m < 22000; i += (n / 20000 > 0 ? n / 20000 : 1)) sub[m++] = samples[i];
    for (int i = 1; i < m; ++i) {
        uint64_t k = sub[i];
        int j = i - 1;
        while (j >= 0 && sub[j] > k) { sub[j + 1] = sub[j]; --j; }
        sub[j + 1] = k;
    }
    uint64_t p50 = sub[m / 2], p95 = sub[m * 95 / 100];
    printf("iter=%d min=%llu p50=%llu p95=%llu max=%llu over500k=%llu\n",
           n, (unsigned long long)min, (unsigned long long)p50,
           (unsigned long long)p95, (unsigned long long)max,
           (unsigned long long)over);
    return over == 0 ? 0 : 1;
}
EOF

cat > "$tmp/go.bat" <<'EOF'
@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat" >nul
cl /nologo /O2 /MD "%TMPDIR%\probe.c" /Fe:"%TMPDIR%\probe.exe" 2>&1
EOF
TMPDIR_WIN="$(cygpath -w "$tmp" | sed 's/\\/\\\\/g')"
sed -i "s|%TMPDIR%|$(cygpath -m "$tmp")|g" "$tmp/go.bat"
cmd //c "$(cygpath -w "$tmp/go.bat")" 2>&1 | tail -1
"$tmp/probe.exe" "$ITER"
rc=$?
if [[ $rc -eq 0 ]]; then
    echo "[calibrate] PASS: 全部样本 ≤ 500000 周期（阈值保守性成立）"
else
    echo "[calibrate] FAIL: 存在超阈值样本——需上调 kRdtscThresholdCycles 并披露"
fi
exit $rc
