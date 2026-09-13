/* MIT-510 (T62 x87 L1-L4): x87 L1 sample main. The region virtualizes through
 * the physical-FPU-resident handlers; gate fallback keeps it native and
 * byte-exact either way. Native rc=0 sentinel. */
#include <stdio.h>
#include <stdint.h>

extern void rgn_x87l1(void);
extern volatile uint64_t g_l1_fx0, g_l1_fx1, g_l1_sc, g_l1_pm;
/* .asm 中为 word —— 按真实尺寸声明 (MIT-509 教训)。 */
extern volatile uint16_t g_l1_c0, g_l1_c0b, g_l1_cw2, g_l1_sw2;
extern volatile uint32_t g_l1_c3, g_l1_cm;

int main(void) {
    rgn_x87l1();
    int ok = 1;
    union { uint64_t u; double d; } fx0, fx1, sc, pm;
    fx0.u = g_l1_fx0;
    fx1.u = g_l1_fx1;
    sc.u = g_l1_sc;
    pm.u = g_l1_pm;
    union { uint32_t u; float f; } cm;
    cm.u = g_l1_cm;
    ok &= ((g_l1_c0 & 0x0100) == 0u);    /* fcom: 2.5 > 1.5 → C0(bit8)=0 */
    ok &= ((g_l1_c0b & 0x0100) == 0x0100u); /* fcomp: 1.5 < 2.5 → C0=1 */
    ok &= (g_l1_c3 == 1u);               /* ftst: 0.0 → equal → C3 抽位=1 */
    ok &= (fx0.d == 1.25);               /* fxch st(1) 后低位 */
    ok &= (fx1.d == 3.75);               /* fxch 后高位 */
    ok &= (cm.f == 1.5f);                /* fcomi + fcmovnb (above → move) */
    ok &= (sc.d > 1.414213 && sc.d < 1.414214); /* f2xm1(0.5)+1 = sqrt(2) */
    ok &= (pm.d == 1.5);                 /* fprem: 1.5 mod 2.5, 商 0 */
    ok &= (g_l1_cw2 == 0x037F);          /* fninit CW */
    ok &= (g_l1_sw2 == 0x0000);          /* fninit SW 全清 */
    printf("l1=%.2f,%.2f,%.2f,%.2f %04X %04X %04X %04X %u\n",
           fx0.d, fx1.d, sc.d, pm.d,
           (unsigned)g_l1_cw2, (unsigned)g_l1_sw2,
           (unsigned)g_l1_c0, (unsigned)g_l1_c0b,
           (unsigned)g_l1_cm);
    return ok ? 0 : 1;
}
