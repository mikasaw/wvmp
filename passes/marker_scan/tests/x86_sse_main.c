/* MIT-446 (X4) B.4 ②: x86 E2E SSE-face sample main. The SSE region is a
 * designed x86 whitelist-gate negative (kept native, byte-exact); the
 * integer helper is truly virtualized (>=1 stub). */
#include <stdio.h>

extern void rgn_sse(void);
extern void rgn_int_helper(void);
extern int g_sse_out;

int main(void) {
    g_sse_out = 0;
    rgn_sse();
    rgn_int_helper();
    printf("sse=%08X\n", g_sse_out);
    return 0;
}
