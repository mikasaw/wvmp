/* MIT-456 (push-mem): x86 push [mem] sample main. Mirrors the probe values
 * (D4 native rc=0). The region is expected to virtualize through the
 * address-slot + Load + Push/Reg fold after the MIT-456 opening; behavior
 * is identical either way (gate fallback keeps it native and byte-exact). */
#include <stdio.h>
#include <stdint.h>

extern void rgn_pushmem(void);
extern volatile uint32_t g_pm_a, g_pm_b, g_pm_stk, g_pm_ret;

int main(void) {
    rgn_pushmem();
    int ok = 1;
    ok &= (g_pm_a == 0xAAAA1111u);   /* push [g_pm_src] (FF 35 abs) */
    ok &= (g_pm_b == 0xCCCC3333u);   /* push [ecx+4] (FF 71 04 IAT form) */
    ok &= (g_pm_stk == 0x11111111u); /* push [esp+4] reads pre-push esp */
    ok &= (g_pm_ret == 0x11112222u); /* pm_helper([arg0],[arg1]) callgate */
    printf("pm=%08X %08X %08X %08X\n", g_pm_a, g_pm_b, g_pm_stk, g_pm_ret);
    return ok ? 0 : 1;
}
