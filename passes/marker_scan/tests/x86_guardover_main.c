/* MIT-451 (X5b) B.5: x86 guard-over-limit gate-negative sample main. The
 * marked region is gated to native by the translator stack-depth walk (its
 * deep write would corrupt the stub save area if virtualized); native and
 * packed therefore run the ORIGINAL code and stay byte-exact. rc=0. */
#include <stdio.h>
#include <stdint.h>

extern void rgn_guardover(void);
extern void rgn_guardover_helper(void);
extern volatile uint32_t g_go_val, g_go_deep;
extern volatile uint32_t g_go_helper;

int main(void) {
    rgn_guardover();
    rgn_guardover_helper();
    int ok = 1;
    ok &= (g_go_val == 0x7777u);  /* deep write + readback, native scratch */
    ok &= (g_go_deep == 0x6666u); /* deepest frame byte roundtrip */
    ok &= (g_go_helper == 0xA5A5A5AAu); /* GP helper true region (A5A5A5A5+5) */
    printf("go=%08X %08X %08X\n", g_go_val, g_go_deep, g_go_helper);
    return ok ? 0 : 1;
}
