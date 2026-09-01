/* MIT-446 (X4) B.4 ③: x86 E2E mixed + cdecl callgate argument-window
 * sample main. The cdecl calls carry stack args through the fixed
 * argument window protocol (native and packed share one convention). */
#include <stdio.h>

extern void rgn_mixed_cg(void);
extern void rgn_plain_int(void);
extern int g_cg_out;
extern int g_cg_out2;

int main(void) {
    rgn_mixed_cg();
    rgn_plain_int();
    printf("cg=%08X cg2=%08X\n", g_cg_out, g_cg_out2);
    return 0;
}
