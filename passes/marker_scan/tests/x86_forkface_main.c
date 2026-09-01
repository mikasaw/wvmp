/* MIT-446 (X4) B.4 ①: x86 E2E first-batch sample main -- integer + control
 * flow (forkface-x86 port). Drives all marker regions, prints results and
 * returns a folded checksum so packed/native stdout+rc must match. */
#include <stdio.h>

extern void rgn_arith_ctrl(void);
extern void rgn_epilogue(void);
extern void rgn_strings(void);
extern void rgn_s16(void);
extern void rgn_indirect_calls(void);
extern int  run_stdcall2(void);
extern void rgn_x87_gate(void);

extern int g_int_out;
extern int g_str_out;
extern short g_s16_out;
extern int g_call_out;

int main(void) {
    rgn_arith_ctrl();
    rgn_epilogue();
    rgn_strings();
    rgn_s16();
    rgn_indirect_calls();
    rgn_x87_gate();
    {
        int r = run_stdcall2();
        printf("int=%08X str=%08X s16=%04X call=%08X stdcall=%08X\n",
               g_int_out, g_str_out, (unsigned)(unsigned short)g_s16_out,
               g_call_out, (unsigned)r);
    }
    return 0;
}
