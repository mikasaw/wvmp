/* MIT-450 (X5) B.3 (3): x86 std+67 gate E2E sample main. rgn_std_gate and
 * rgn_addr67 are designed gate negatives (gate notes asserted by the E2E
 * runner in the protect log); rgn_addr67 is never called (address taken
 * only). The helper value is asserted (REQUIRE_REAL stub source). */
#include <stdio.h>
#include <stdint.h>

extern void rgn_std_gate(void);
extern void rgn_addr67(void);
extern void rgn_std_helper(void);
extern volatile uint32_t g_sg_out;

int main(void) {
    rgn_std_gate();
    rgn_std_helper();
    /* address taken, never called (442 区6 discipline) */
    volatile void* p67 = (void*)&rgn_addr67;
    const uint32_t v = (((0xB7B7B7B7u ^ 0xE7E7E7E7u) - 0x50000000u) >> 2);
    /* C >> is arithmetic for signed, logical for unsigned; MASM sar = signed.
     * (0xB7B7B7B7 ^ 0xE7E7E7E7) - 0x50000000 fits in the positive int range,
     * so uint32_t >> 2 equals sar 2 here. */
    const int ok = (g_sg_out == v) && (p67 != 0);
    printf("sg=%08X\n", g_sg_out);
    return ok ? 0 : 1;
}
