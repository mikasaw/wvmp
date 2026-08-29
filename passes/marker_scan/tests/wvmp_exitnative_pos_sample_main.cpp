// MIT-407 (MIT-D2): ExitNative 正样本 — 越区跳转单向退出两类形态。
//
//   1) endcall 形态 (wv_exit_endcall): `if (n==0) goto done; ... done:`
//      —— goto 目标落在 WVMP_END 的 call 指令上 (target == end_rva，
//      与 triage 13/17 站点同形态)。goto 目标 = END-call 本身，越区
//      目标即 stub 的 resume 点，ExitNative 与 Halt 语义等价。
//   2) earlyret 形态 (wv_exit_earlyret): `if ((n&1)!=0) return t;` ——
//      早返回分支目标 = 函数 epilogue (end_rva 之后、.pdata 界内，
//      与 triage 4/17 站点同形态)。jcc 条件退出，不满足时 VM 继续。
//
// 验收 (multiseed REQUIRE_REAL=1): 两函数都须被虚拟化 (≥1 入口 stub)，
// packed 与 native stdout+rc 逐字节一致。
//
// 注意: volatile 防止 MSVC 常量折叠; __declspec(noinline) 防内联吞标记。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

volatile unsigned long long g_sink = 0;

// 形态 1: 越区 goto → END-call (target == end_rva)。
__declspec(noinline) static unsigned long long wv_exit_endcall(unsigned long long n) {
    volatile unsigned long long s = 0;
    WVMP_BEGIN(wv_exit_endcall);
    s = n * 7ull + 3ull;
    if (n == 0) goto done;      // jcc → END-call (end_rva)，区域外但同函数
    s = s * 2ull - 1ull;
done:
    WVMP_END(wv_exit_endcall);
    g_sink = s;
    return s;
}

// 形态 2: 早返回 jcc → 函数 epilogue (end_rva 之后)。
__declspec(noinline) static unsigned long long wv_exit_earlyret(unsigned long long n) {
    volatile unsigned long long t = 0;
    WVMP_BEGIN(wv_exit_earlyret);
    t = n * 3ull + 1ull;
    if ((n & 1ull) != 0) return t;  // jcc → epilogue（越区，.pdata 界内）
    t = t * 5ull + 2ull;
    WVMP_END(wv_exit_earlyret);
    return t;
}

int main() {
    g_sink = 0;
    unsigned long long ok = 1;
    // 两组输入都覆盖: n==0 (endcall 的 goto 必走) / n!=0 (不走);
    // 奇偶各一 (earlyret 的条件两向)。
    for (unsigned long long n = 0; n <= 4; ++n) {
        const unsigned long long a = wv_exit_endcall(n);
        const unsigned long long b = wv_exit_earlyret(n);
        ok &= (g_sink == a);
        std::printf("n=%llu endcall=%llx earlyret=%llx\n", n, a, b);
    }
    std::printf("ok=%llu\n", ok);
    return ok == 1 ? 0 : 2;
}
