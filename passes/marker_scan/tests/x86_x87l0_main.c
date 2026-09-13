/* MIT-508 (T60 x87 L0): x87 L0 sample main. The region virtualizes through
 * the physical-FPU-resident handlers; gate fallback keeps it native and
 * byte-exact either way. Native rc=0 sentinel. */
#include <stdio.h>
#include <stdint.h>

extern void rgn_x87l0(void);
extern volatile uint64_t g_x_out;
extern volatile uint32_t g_x_io, g_x_fout, g_x_sw, g_x_cwo;

int main(void) {
    rgn_x87l0();
    int ok = 1;
    union { uint64_t u; double d; } o;
    o.u = g_x_out;
    ok &= (o.d == 4.0);                              /* fld/fadd/fstp m64 */
    ok &= (g_x_io == 50u);                           /* fild/faddp/fistp */
    union { uint32_t u; float f; } fo;
    fo.u = g_x_fout;
    ok &= (fo.f == -2.0f);                           /* fsqrt/fchs */
    ok &= ((g_x_sw & 0x41) == 0u);                   /* fcomi: 4.0 > 1.5 -> C0=0,ZF=0 */
    ok &= (g_x_cwo == 0x027Fu);                      /* fldcw/fnstcw round trip */
    printf("x87=%d %u %d %04X %04X\n", (int)o.d, g_x_io,
           (int)fo.f, g_x_sw & 0xFFFF, g_x_cwo);
    return ok ? 0 : 1;
}
