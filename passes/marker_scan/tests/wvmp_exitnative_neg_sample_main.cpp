// MIT-407 (MIT-D2): ExitNative 反例样本 — 两类危险形态必须维持 C1 gate。
//
//   1) 回跳形态 (wv_exit_backjump, C): 区域内 `if (n==0) goto L_out` 越区到
//      WVMP_END 之后；**L_out 自身**的代码 `if (r>100000) goto L_in` 回跳
//      进区域 (L_in ∈ [begin, end))。区域字节将被 stub_link 覆写为
//      E9+INT3，native 回跳进区域 = 执行 stub 代码 → 行为错/崩溃。
//      lifter 的 ≤3 层可达集 walker 必须检出 → ExitNative 禁用 → 整函数
//      gate（保持原生执行，与修复前逐字节一致）。
//   2) 超界形态 (wv_exit_oob_masm, MASM): 区域内直接 `jmp` 到**另一函数**
//      （跨 .pdata 界）——目标落在 helper 自己的 RUNTIME_FUNCTION 条目，
//      超出本函数 EndAddress → 上界判定 gate。MASM 保证确定性（/O2 尾
//      调用是编译器行为，不保证）。
//
// 验收: 两函数都不得虚拟化，packed 与 native stdout+rc 逐字节一致
// （gate = 原字节原样执行）。保护日志须含对应 gate note。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

extern "C" unsigned long long wv_exit_far_helper(unsigned long long x);  // MASM 尾跳目标
extern "C" unsigned long long wv_exit_oob_masm(unsigned long long n);    // MASM 标记宿主

volatile unsigned long long g_sink = 0;

// 回跳形态: 越区目标 L_out 的可达集含回跳进区域的边。
__declspec(noinline) static unsigned long long wv_exit_backjump(unsigned long long n) {
    volatile unsigned long long r = 0;
    WVMP_BEGIN(wv_exit_backjump);
    r = n + 1ull;
    if (n == 0) goto L_out;   // 越区 jcc → L_out（end_rva 之后）
    r = r * 3ull;
L_in:                         // 区域内回跳目标（被覆写区）
    r = r + 7ull;
    WVMP_END(wv_exit_backjump);
    // ---- 区域外 native 代码：L_out 可达集必须含回跳进区域的边 ----
L_out:
    if (r > 100000ull) goto L_in;  // 回跳进区域 → walker 必须检出
    return r;
}

// MASM 侧的超界宿主（见 wv_exitnative_neg_sample_asm.asm）内联在 C 的
// extern 声明之上；helper 保持简单纯计算。
extern "C" unsigned long long wv_exit_far_helper(unsigned long long x) {
    return x * 11ull + 1ull;
}

int main() {
    g_sink = 0;
    unsigned long long ok = 1;
    for (unsigned long long n = 0; n <= 3; ++n) {
        const unsigned long long b = wv_exit_backjump(n);
        const unsigned long long o = wv_exit_oob_masm(n);
        std::printf("n=%llu backjump=%llx oob=%llx\n", n, b, o);
    }
    std::printf("ok=%llu\n", ok);
    return ok == 1 ? 0 : 2;
}
