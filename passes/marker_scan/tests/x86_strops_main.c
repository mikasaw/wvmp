/* MIT-450 (X5) B.1 (3): x86 string-op E2E sample main. Asserts the mirror
 * of every region probe so the native rc=0 sentinel (D4) is a real check;
 * the packed run must reproduce stdout+rc byte-exact. */
#include <stdio.h>
#include <stdint.h>

extern void rgn_strops(void);
extern void rgn_strops_int(void);
extern volatile int32_t g_st_out, g_st_out2, g_st_out3;

extern uint32_t g_sbuf[8];
extern uint32_t g_dbuf[32];

int main(void) {
    rgn_strops();
    rgn_strops_int();
    /* g_st_out = (mismatch idx) ^ 0x22222222 (scas not-found) + g_sbuf[0] */
    const int32_t expect_out =
        (int32_t)(2u ^ 0x22222222u) + (int32_t)0x10000001u;
    /* g_st_out2 = g_dbuf[0xC0/4] (= g_sbuf[2] = 0x30000003) ^ 0xDEB25E17 */
    const int32_t expect_out2 = (int32_t)(0x30000003u ^ 0xDEB25E17u);
    /* g_st_out3 = ((0x13579BDF & 0x2468ACE0) | 0xF00000FF) ^ 0xAAAA5555 */
    const int32_t expect_out3 =
        (int32_t)(((0x13579BDFu & 0x2468ACE0u) | 0xF00000FFu) ^ 0xAAAA5555u);
    const int ok = (g_st_out == expect_out) && (g_st_out2 == expect_out2) &&
                   (g_st_out3 == expect_out3) && (g_dbuf[2] == 0x30000003u) &&
                   (g_dbuf[16] == 0x02100000u) && (g_dbuf[0x20] == 0x5A5A5A5Au) &&
                   (g_dbuf[0x30] == 0x30000003u) && (g_dbuf[0x31] == 0x40000004u);
    printf("out=%08X out2=%08X out3=%08X dbuf=%08X\n",
           (unsigned)g_st_out, (unsigned)g_st_out2, (unsigned)g_st_out3,
           g_dbuf[2]);
    return ok ? 0 : 1;
}
