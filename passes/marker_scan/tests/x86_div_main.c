/* MIT-X7 (MIT-455) B.2: x86 div/idiv sample main. Mirrors the probe values
 * (D4 native rc=0). The region is expected to virtualize through the 32-bit
 * Div/Idiv handlers after the MIT-455 batch-2 opening; behavior is identical
 * either way (gate fallback keeps it native and byte-exact). */
#include <stdio.h>
#include <stdint.h>

extern void rgn_div(void);
extern volatile uint32_t g_dv_q1, g_dv_r1, g_dv_q2, g_dv_r2;
extern volatile uint32_t g_dv_q3, g_dv_r3, g_dv_q4, g_dv_r4;

int main(void) {
    rgn_div();
    int ok = 1;
    ok &= (g_dv_q1 == 14u);           /* div 100 / 7 */
    ok &= (g_dv_r1 == 2u);
    ok &= (g_dv_q2 == 0x0FFFFFFFu);   /* div 0FFFFFFFFh / 10h (mem divisor) */
    ok &= (g_dv_r2 == 0xFu);
    ok &= (g_dv_q3 == 0xFFFFFFF2u);   /* idiv -100 / 7 -> -14 */
    ok &= (g_dv_r3 == 0xFFFFFFFEu);   /* remainder -2 */
    ok &= (g_dv_q4 == 0xFFFFFFF2u);   /* idiv 100 / -7 -> -14 */
    ok &= (g_dv_r4 == 2u);            /* remainder 2 (truncate toward zero) */
    printf("dv=%u %u %08X %08X %08X %08X %08X %08X\n",
           g_dv_q1, g_dv_r1, g_dv_q2, g_dv_r2, g_dv_q3, g_dv_r3, g_dv_q4, g_dv_r4);
    return ok ? 0 : 1;
}
