/* MIT-450 (X5) B.3 (1): x86 x87 gate E2E sample main. The x87 region result
 * is float-printed (identical native both runs -- the function gates whole);
 * the helper region value is asserted (REQUIRE_REAL stub source). */
#include <stdio.h>
#include <stdint.h>

extern void rgn_x87_gate(void);
extern void rgn_x87_helper(void);
extern volatile float g_fx, g_fy, g_fx_out;
extern volatile uint32_t g_xh_out;

int main(void) {
    rgn_x87_gate();
    rgn_x87_helper();
    /* (2*2.0)*3.5 + 3.5/2.0 = 14 + 1.75 = 15.75 */
    const uint32_t v = (0xC0DE0000u ^ 0x0000BEEFu) + 0x12345678u;
    const uint32_t r = (v >> 11) | (v << 21);   /* ror 11 mirror */
    const int ok = (g_fx_out == 15.75f) && (g_xh_out == r);
    printf("fx=%.6f xh=%08X\n", (double)g_fx_out, g_xh_out);
    return ok ? 0 : 1;
}
