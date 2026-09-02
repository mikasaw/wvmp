/* MIT-453 (X5c) B.2: x86 tailexit sample main -- drives the two ExitNative
 * regions across all three branch directions each (endcall / earlyret /
 * fallthrough) and takes the gate-negative region's address (never calls
 * it: the beyond-tail jmp target would be meaningless to execute; the
 * region must stay whole-function native via C1 gate in the packed run,
 * evidence = protect log gate note).
 *
 * Native/packed determinism: every call's output is folded into printf
 * and the final rc; both branch directions of both cond sites are
 * exercised (acc == 0 / > 0 / < 0). */
#include <stdio.h>

extern void rgn_exit_ok(void);
extern void rgn_tailexit_ok(void);
extern void rgn_tail_beyond(void);   /* address taken, never called */

extern int g_in1;
extern int g_in2;
extern int g_out1;
extern int g_out3;

static void run_case(int a, int b) {
    g_in1 = a;
    g_in2 = b;
    rgn_exit_ok();
    rgn_tailexit_ok();
    /* Mirror of the region computation (native ground truth):
     * acc = (a ^ K) + b; g_out = acc + bias (fallthrough face only). */
    {
        const int acc1 = (int)((unsigned)a ^ 0x5A5A0001u) + b;
        const int exp1 = acc1 < 0 ? acc1 + (int)0xDEAD : acc1;
        const int acc3 = (int)((unsigned)a ^ 0x5A5A0003u) + b;
        const int exp3 = acc3 < 0 ? acc3 + (int)0xBEEF : acc3;
        printf("a=%d b=%d out1=%08X out3=%08X\n", a, b,
               (unsigned)g_out1, (unsigned)g_out3);
        if (g_out1 != exp1 || g_out3 != exp3) {
            printf("MISMATCH exp1=%08X exp3=%08X\n",
                   (unsigned)exp1, (unsigned)exp3);
        }
    }
}

int main(void) {
    void (*volatile keep)(void) = rgn_tail_beyond;  /* defeat /OPT:REF */
    (void)keep;

    run_case(0, 5);                     /* acc > 0: earlyret face both regions */
    run_case(0, -(int)0x5A5A0001u);     /* region1 acc == 0: endcall face */
    run_case(0, -(int)0x5A5A0003u);     /* region1 acc < 0; region3 acc == 0 */
    run_case(0, -(int)0x5A5A0005u);     /* both acc < 0: fallthrough face */
    printf("done\n");
    return 0;
}
