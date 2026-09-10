// wvmp_hotloop_sample: 解释器密集微基准样本（MIT-494l / T34）。
//
// 背景：MIT-494i (T31) 正式基线显示进程 wall clock 由启动（~14-15ms）主导，
// T26/T27/T30 的词流增量在该口径下不可辨——结论建议"后续性能工作应采用
// 解释器密集的微基准（长循环/大区域）而非进程级 wall clock"。本样本即该
// 口径的落地：
//   - 区域内 = 单个 5M 次迭代的 xorshift32 ALU 循环（mov/add/xor/shl/shr/
//     cmp/jb 全在白名单内，/Od codegen 无乘除/SSE）——protected 版每次迭
//     代走解释器 dispatch 十余词，循环时间为解释器吞吐主导；
//   - 区域外 = QPC（QueryPerformanceCounter）计时包裹对区域函数的调用。
//
// ⚠️ byte-exact 口径：stdout 含毫秒计时值，native 与 protected 必然不同
// ——本样本**不进 multiseed byte-exact 池**，仅作 measure 管道计时靶标
// （checksum 行固定，作正确性锚）。
//
// ⚠️ 区域形态（MIT-326 教训）：循环用 do-while——/Od codegen 出口为
// fallthrough 到 WVMP_END、唯一跳转为向后回边（jb body），不存在跨 END
// 的前向跳（会触发 C1 gate）；迭代次数 ≥1 由调用侧常量保证。
//
// 编译（与现有 sample 一致）：/Od /Ob0 /utf-8 + /INCREMENTAL:NO。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>
#include <cstdint>
#include <windows.h>

using u32 = std::uint32_t;

static volatile u32 g_sink;  // 防常量折叠；区域内写、区域外读

// 区域函数：xorshift32 + add 热循环（do-while，见上形态说明）。
__declspec(noinline) static u32 hotloop_fn(u32 seed, u32 iters) {
    u32 x = seed;
    u32 i = 0;

    WVMP_BEGIN(hotloop);

    do {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x += i;
        ++i;
    } while (i < iters);

    WVMP_END(hotloop);

    return x;
}

int main() {
    constexpr u32 kSeed = 2463534242u;  // xorshift32 标准测试种子
    constexpr u32 kIters = 5000000u;

    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    const u32 r = hotloop_fn(kSeed, kIters);
    QueryPerformanceCounter(&t1);

    g_sink = r;
    const double ms =
        static_cast<double>(t1.QuadPart - t0.QuadPart) * 1000.0 /
        static_cast<double>(freq.QuadPart);
    // checksum 行（固定，正确性锚）与计时行（天然非确定）分行。
    std::printf("hotloop checksum=%u\n", r);
    std::printf("hotloop ms=%.3f\n", ms);
    // native 锚：seed 2463534242 / 5M 迭代 xorshift+add 的确定结果（首次
    // 以 native 运行值钉入；运行时校验防样本被改后静默漂移）。
    if (r != 785016842u) {
        std::printf("hotloop UNEXPECTED checksum (native anchor drift)\n");
        return 1;
    }
    return 0;
}
