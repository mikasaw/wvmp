/* MIT-494m (T35): x86 hotloop E2E sample main. Drives the xorshift32 ALU
 * region (5M iterations) and times it with QPC outside the region; the
 * native rc=0 sentinel (D4) also pins the checksum anchor (shared with the
 * x64 hotloop sample: same xorshift32 math). Packed runs must land on the
 * same checksum; the ms line is inherently non-deterministic so this sample
 * stays out of the byte-exact pools (measure-only target).
 * Build: cl /O1 (see build_x86_e2e_samples.bat). */
#include <stdio.h>
#include <stdint.h>
#include <windows.h>

extern uint32_t hotloop_x32(uint32_t seed, uint32_t iters);

static volatile uint32_t g_hl_sink;

int main(void) {
    const uint32_t seed = 2463534242u;
    const uint32_t iters = 5000000u;

    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    const uint32_t r = hotloop_x32(seed, iters);
    QueryPerformanceCounter(&t1);

    g_hl_sink = r;
    printf("hotloop checksum=%u\n", r);
    printf("hotloop ms=%.3f\n",
           (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart);
    /* Native anchor: xorshift32 + add, seed 2463534242, 5M iterations. */
    if (r != 785016842u) {
        printf("hotloop UNEXPECTED checksum (native anchor drift)\n");
        return 1;
    }
    return 0;
}
