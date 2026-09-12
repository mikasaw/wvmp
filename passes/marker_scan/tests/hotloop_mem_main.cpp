// wvmp_hotloop_mem_sample: x64 LD/ST-dense microbenchmark main (MIT-494r /
// T41 word-mix matrix). Same QPC + checksum-anchor protocol as
// hotloop_asm_main.cpp. Not in the multiseed byte-exact pools (ms line).

#include "wvmp/sdk/markers.hpp"

#include <cstdio>
#include <cstdint>
#include <windows.h>

using u32 = std::uint32_t;

extern "C" u32 hotloop_mem64(u32 seed, u32 iters);

// Region buffer (asm references via rip-relative lea). Contents evolve in
// place; only the asm region touches it.
extern "C" u32 g_mem_buf[16] = {};

static volatile u32 g_sink;

int main() {
    constexpr u32 kSeed = 2463534242u;
    constexpr u32 kIters = 5000000u;

    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    const u32 r = hotloop_mem64(kSeed, kIters);
    QueryPerformanceCounter(&t1);

    g_sink = r;
    const double ms =
        static_cast<double>(t1.QuadPart - t0.QuadPart) * 1000.0 /
        static_cast<double>(freq.QuadPart);
    std::printf("hotloop checksum=%u\n", r);
    std::printf("hotloop ms=%.3f\n", ms);
    if (r != 3952819074u) {
        std::printf("hotloop UNEXPECTED checksum (native anchor drift)\n");
        return 1;
    }
    return 0;
}
