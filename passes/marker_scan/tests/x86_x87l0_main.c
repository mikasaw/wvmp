/* MIT-509 (T61 x87 L0 restart): x87 L0 sample main. The region virtualizes
 * through the physical-FPU-resident handlers; gate fallback keeps it native
 * and byte-exact either way. Native rc=0 sentinel.
 * Face-4 semantics per X87FcomipFnstswHwTruth (host-measured): FCOMI writes
 * EFLAGS only, so SW C0 stays stale; faces 4 and 9 sample the same SW state
 * and main cross-checks the extracted C0 bit. */
#include <stdio.h>
#include <stdint.h>

extern void rgn_x87l0(void);
extern volatile uint64_t g_x_out;
extern volatile uint64_t g_x_sub, g_x_subr, g_x_divp, g_x_subrp;
extern volatile uint32_t g_x_io, g_x_fout;
/* .asm 中为 word —— 按真实尺寸声明 (T60 误用 uint32_t, 靠尾部零填充侥幸;
 * 相邻 g_x_cmp 的 seta 写入使高字非零, dword 声明即假性断言失败)。 */
extern volatile uint16_t g_x_sw, g_x_cwo;
extern volatile uint32_t g_x_cmp, g_x_swax;

int main(void) {
    rgn_x87l0();
    int ok = 1;
    union { uint64_t u; double d; } o, s, sr, dp, srp;
    o.u = g_x_out;
    s.u = g_x_sub;
    sr.u = g_x_subr;
    dp.u = g_x_divp;
    srp.u = g_x_subrp;
    ok &= (o.d == 4.0);                              /* fld/faddp/fstp m64 */
    ok &= (g_x_io == 50u);                           /* fild/faddp/fistp */
    union { uint32_t u; float f; } fo;
    fo.u = g_x_fout;
    ok &= (fo.f == -2.0f);                           /* fsqrt/fchs */
    /* face 4 + face 9 互证: 同一 SW 状态, mem 面存全量, AX 面抽 C0。 */
    ok &= (g_x_swax == ((g_x_sw >> 8) & 1u));        /* fnstsw ax C0 抽位 */
    ok &= (g_x_cwo == 0x027Fu);                      /* fldcw/fnstcw */
    ok &= (s.d == 1.0);                              /* fsub st,st(1) D8 */
    ok &= (sr.d == 1.0);                             /* fsubr st(1),st(0) DC */
    ok &= (dp.d == 0.6);                             /* fdivp (1.5/2.5) */
    ok &= (srp.d == 1.0);                            /* fsubrp pop */
    ok &= (g_x_cmp == 1u);                           /* fcomip above -> seta */
    printf("x87=%d %u %d %04X %04X %.1f %.1f %.1f %.1f %u %u\n",
           (int)o.d, g_x_io, (int)fo.f, (unsigned)g_x_sw, (unsigned)g_x_cwo,
           s.d, sr.d, dp.d, srp.d, g_x_cmp, g_x_swax);
    return ok ? 0 : 1;
}
