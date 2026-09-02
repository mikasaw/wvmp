/* MIT-451 (X5b) B.5: x86 push-form sample main. Mirrors the probe values
 * (D4 native rc=0). The region is expected to virtualize through the entry
 * guard pad; behavior is identical either way. */
#include <stdio.h>
#include <stdint.h>

extern void rgn_pushform(void);
extern volatile uint32_t g_pf_ret, g_pf_arg, g_pf_spill;

int main(void) {
    rgn_pushform();
    int ok = 1;
    ok &= (g_pf_ret == 0x3333u);  /* pf_helper(2222h, 1111h) */
    ok &= (g_pf_spill == 0x3333u);/* transient push/pop roundtrip */
    printf("pf=%08X %08X\n", g_pf_ret, g_pf_spill);
    return ok ? 0 : 1;
}
