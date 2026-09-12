/* MIT-494r (T41): x86 LD/ST-dense hotloop sample main. Same QPC +
 * checksum-anchor protocol as x86_hotloop_main.c (anchor shared with
 * hotloop_mem64: 3952819074). Packed runs must land on the same checksum;
 * the ms line is non-deterministic so this stays out of the byte-exact
 * pools (measure-only target).
 * Build: cl /O1 (see build_x86_e2e_samples.bat). */
#include <stdio.h>
#include <stdint.h>
#include <windows.h>

extern uint32_t hotloop_memx32(uint32_t seed, uint32_t iters);

/* Region buffer (asm absolute disp32 references). Contents evolve in
 * place; only the asm region touches it. */
uint32_t g_mem_buf[16];

static volatile uint32_t g_hlm_sink;

int main(void) {
    const uint32_t seed = 2463534242u;
    const uint32_t iters = 5000000u;

    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    const uint32_t r = hotloop_memx32(seed, iters);
    QueryPerformanceCounter(&t1);

    g_hlm_sink = r;
    printf("hotloop checksum=%u\n", r);
    printf("hotloop ms=%.3f\n",
           (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart);
    if (r != 3952819074u) {
        printf("hotloop UNEXPECTED checksum (native anchor drift)\n");
        return 1;
    }
    return 0;
}
