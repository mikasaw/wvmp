/* MIT-450 (X5) B.1 (5): x86 nested-loop + complex-LEA E2E sample main.
 * Mirror computed with the same arithmetic (D4 native rc=0). */
#include <stdio.h>
#include <stdint.h>

extern void rgn_looplea(void);
extern volatile uint32_t g_l_acc, g_l_acc2, g_l_out;
extern uint32_t g_l_tab[8];

int main(void) {
    rgn_looplea();
    uint32_t acc = 0, acc2 = 0;
    for (uint32_t i = 0; i < 5; ++i) {
        acc += 3u * i + 0x10u;
        for (uint32_t j = 0; j < 4; ++j) {
            acc2 += j + i * 4u + 0x20u;
            acc2 += j + g_l_tab[i];
            acc2 *= 5u;
        }
    }
    const uint32_t out = (acc2 ^ acc) + g_l_tab[5];
    const int ok = (g_l_acc == acc) && (g_l_acc2 == acc2) && (g_l_out == out);
    printf("acc=%08X acc2=%08X out=%08X\n", g_l_acc, g_l_acc2, g_l_out);
    return ok ? 0 : 1;
}
