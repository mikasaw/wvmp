/* MIT-450 (X5) B.1 (2): x86 jump-table E2E sample main. Exercises all three
 * positive forms over the boundary range (0..7 in-table, 8..9 default) plus
 * the undef and oob negatives (poison idx=3 skipped both sides). All five
 * jt functions gate whole-function native on x86 (X5 finding: matcher S64
 * hardcode) -- behavior is byte-exact native either way; the helper value
 * carries the REQUIRE_REAL stub. rc=0 = native sentinel (D4). */
#include <stdio.h>
#include <stdint.h>

extern uint32_t wv_jt4_abs(void);
extern uint32_t wv_jt4_delta(void);
extern uint32_t wv_jtm4_abs(void);
extern uint32_t wv_jt4_undef(void);
extern uint32_t wv_jt4_oob(void);
extern void rgn_jt_helper(void);
extern volatile uint32_t g_sel, g_jh_out;

int main(void) {
    rgn_jt_helper();
    uint32_t ok = 1;
    for (uint32_t i = 0; i < 10; ++i) {
        g_sel = i;
        const uint32_t a = wv_jt4_abs();
        const uint32_t d = wv_jt4_delta();
        const uint32_t m = wv_jtm4_abs();
        const uint32_t ea = i < 8 ? 0x100u | i : 0x1FFu;
        const uint32_t ed = i < 8 ? 0x200u | i : 0x2FFu;
        const uint32_t em = i < 8 ? 0x300u | i : 0x3FFu;
        ok &= (a == ea) && (d == ed) && (m == em);
        printf("i=%u abs=%03X delta=%03X mem=%03X\n", i, a, d, m);
    }
    for (uint32_t i = 0; i < 8; ++i) {
        g_sel = i;
        const uint32_t u = wv_jt4_undef();
        ok &= (u == (0x400u | i));
        printf("undef(%u)=%03X\n", i, u);
    }
    for (uint32_t i = 0; i < 8; ++i) {
        if (i == 3) continue;
        g_sel = i;
        const uint32_t o = wv_jt4_oob();
        ok &= (o == (0x500u | i));
        printf("oob(%u)=%03X\n", i, o);
    }
    {   /* helper mirror: ror7((0x0ADD1E5A ^ 0x00C0FFEE) - 0x11111111) */
        const uint32_t v0 = (0x0ADD1E5Au ^ 0x00C0FFEEu) - 0x11111111u;
        ok &= (g_jh_out == ((v0 >> 7) | (v0 << 25)));
    }
    printf("ok=%u jh=%08X\n", ok, g_jh_out);
    return ok == 1 ? 0 : 1;
}
