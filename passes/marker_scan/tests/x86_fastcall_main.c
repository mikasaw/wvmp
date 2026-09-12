/* MIT-498 (T51 follow-up, T52): x86 fastcall sample main. The region is
 * expected to virtualize through the register-arg bridge (asmgen step
 * 2.6/2.7/5.5); gate fallback keeps it native and byte-exact either way.
 * Native rc=0 sentinel; the printed values pin all three callee faces. */
#include <stdio.h>
#include <stdint.h>

extern void rgn_fastcall(void);
extern volatile uint32_t g_fc_add, g_fc_shr_hi, g_fc_shr_lo;
extern volatile uint32_t g_fc_pair_hi, g_fc_pair_lo;

int main(void) {
    rgn_fastcall();
    int ok = 1;
    ok &= (g_fc_add == 0x33333333u);    /* fastcall ecx+edx */
    ok &= (g_fc_shr_hi == 0x01234567u); /* edx:eax >>= cl (__aullshr face) */
    ok &= (g_fc_shr_lo == 0x89ABCDEFu);
    ok &= (g_fc_pair_hi == 0x00000100u); /* edx:eax pair storeback */
    ok &= (g_fc_pair_lo == 0x00000200u);
    printf("fc=%08X %08X %08X %08X %08X\n",
           g_fc_add, g_fc_shr_hi, g_fc_shr_lo, g_fc_pair_hi, g_fc_pair_lo);
    return ok ? 0 : 1;
}
