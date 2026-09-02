/* MIT-450 (X5) B.1 (4): x86 bit-op E2E sample main. Mirrors every probe
 * value (D4 native rc=0). The lock-face region is asserted with the same
 * arithmetic regardless of virtualize-vs-gate (behavior is identical). */
#include <stdio.h>
#include <stdint.h>

extern void rgn_bitops(void);
extern void rgn_bitops_lock(void);
extern volatile uint32_t g_b_pc, g_b_tz, g_b_lz, g_b_bs, g_b_cx;
extern volatile uint32_t g_b_cx2[3], g_b_xg[2];
extern volatile uint32_t g_bm_slot, g_bm_cx, g_bm_xa, g_bm_cf, g_bm_bts;

int main(void) {
    rgn_bitops();
    rgn_bitops_lock();
    int ok = 1;
    ok &= (g_b_pc == 15u);                       /* popcnt(0F0F0CC32h) */
    ok &= (g_b_tz == 1u);                        /* tzcnt: lowest set bit 1 */
    ok &= (g_b_lz == 0u);                        /* lzcnt: bit31 set */
    ok &= (g_b_bs == 0x32CCF0F0u);               /* bswap(0F0F0CC32h) */
    ok &= (g_b_cx == 0xAAAA5555u);               /* cmpxchg equal path */
    ok &= (g_b_cx2[0] == 0u && g_b_cx2[1] == 0x22222222u &&
           g_b_cx2[2] == 0x22222222u);
    ok &= (g_b_xg[0] == 0xCCCC3333u && g_b_xg[1] == 0x0F0F00F0Fu);
    /* lock face: slot 0xAAAA5555 ->(cmpxchg eq) 0x12345678 ->(xadd +0x100)
     * old=0x12345678, slot=0x12345778 ->(bts bit3 already set) CF=1, slot
     * unchanged */
    ok &= (g_bm_slot == 0x12345778u) && (g_bm_cx == 1u) &&
          (g_bm_xa == 0x12345678u) && (g_bm_cf == 1u) &&
          (g_bm_bts == 0x12345778u);
    printf("pc=%u tz=%u lz=%u bs=%08X cx=%08X xg=%08X\n",
           g_b_pc, g_b_tz, g_b_lz, g_b_bs, g_b_cx, g_b_xg[0]);
    printf("bm=%08X %08X %08X\n", g_bm_slot, g_bm_xa, g_bm_bts);
    return ok ? 0 : 1;
}
