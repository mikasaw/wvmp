/* MIT-454 (X6 B.1): x86 push-imm sample main. Mirrors the probe values
 * (D4 native rc=0). The region is expected to virtualize through the
 * single-op Push/Imm path after the X6 B.1 opening; behavior is identical
 * either way (gate fallback keeps it native and byte-exact). */
#include <stdio.h>
#include <stdint.h>

extern void rgn_pushimm(void);
extern volatile uint32_t g_pi_imm32a, g_pi_imm32b, g_pi_imm32c;
extern volatile uint32_t g_pi_imm8a, g_pi_imm8b, g_pi_imm8c;
extern volatile uint32_t g_pi_ret, g_pi_arg;

int main(void) {
    rgn_pushimm();
    int ok = 1;
    ok &= (g_pi_imm32a == 0x12345678u);   /* push 12345678h (68 iv) */
    ok &= (g_pi_imm32b == 0xFFFFFFFFu);   /* push FFFFFFFFh (imm32 -1 face) */
    ok &= (g_pi_imm32c == 0x00000080u);   /* push 80h (imm8 overflow -> 68) */
    ok &= (g_pi_imm8a == 0x00000000u);    /* push 0 (6A 00 boundary) */
    ok &= (g_pi_imm8b == 0xFFFFFFFBu);    /* push -5 (6A FB sext) */
    ok &= (g_pi_imm8c == 0x0000007Fu);    /* push 7Fh (6A 7F boundary) */
    ok &= (g_pi_ret == 0x33333333u);      /* pi_helper(22222222h, 11111111h) */
    printf("pi=%08X %08X %08X %08X %08X %08X %08X\n",
           g_pi_imm32a, g_pi_imm32b, g_pi_imm32c,
           g_pi_imm8a, g_pi_imm8b, g_pi_imm8c, g_pi_ret);
    return ok ? 0 : 1;
}
