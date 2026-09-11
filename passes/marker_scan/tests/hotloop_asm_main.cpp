// wvmp_hotloop_asm_sample: x64 same-dword-density microbenchmark main
// (MIT-494q / T40). Mirrors hotloop_sample_main.cpp (QPC timing outside
// the region, checksum anchor shared across all three hotloop samples).
//
// Not in the multiseed byte-exact pools (stdout carries the ms line).

#include "wvmp/sdk/markers.hpp"

#include <cstdio>
#include <cstdint>
#include <windows.h>

using u32 = std::uint32_t;

extern "C" u32 hotloop_asm64(u32 seed, u32 iters);

static volatile u32 g_sink;

int main() {
    constexpr u32 kSeed = 2463534242u;
    constexpr u32 kIters = 5000000u;

    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    const u32 r = hotloop_asm64(kSeed, kIters);
    QueryPerformanceCounter(&t1);

    g_sink = r;
    const double ms =
        static_cast<double>(t1.QuadPart - t0.QuadPart) * 1000.0 /
        static_cast<double>(freq.QuadPart);
    std::printf("hotloop checksum=%u\n", r);
    std::printf("hotloop ms=%.3f\n", ms);
    if (r != 785016842u) {
        std::printf("hotloop UNEXPECTED checksum (native anchor drift)\n");
        return 1;
    }
    return 0;
}
