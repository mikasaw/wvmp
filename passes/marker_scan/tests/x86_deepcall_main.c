/* MIT-450 (X5) B.1 (1): x86 deepcall E2E sample main. Drives the callgate
 * recursion region and the plain second region; the C mirror recomputes the
 * recursion so the native rc=0 sentinel (D4) also proves the math, and the
 * packed run must land on the same stdout+rc (byte-exact). */
#include <stdio.h>
#include <stdint.h>

extern uint32_t deepcall_entry(void);
extern void rgn_plain2(void);
extern volatile uint32_t g_dc_out2;

/* C mirror of deep_recurse (k=32 recursion depth is fine in C). */
static uint32_t deep_ref(uint32_t k, uint32_t a) {
    const uint32_t f6 = 6u * 0x41424344u;
    if (k == 0) return a + f6;
    return deep_ref(k - 1, a + 0x9E3779B9u) + a + f6;
}

int main(void) {
    const uint32_t r = deepcall_entry();
    const uint32_t ref = deep_ref(32, 0x1234);
    rgn_plain2();
    printf("dc=%08X ref=%08X p2=%08X\n", r, ref, g_dc_out2);
    return (r == ref) ? 0 : 1;
}
