/* MIT-450 (X5) B.3 (2): x86 SEH gate E2E sample main. seh_fn is a real
 * __try/__except function whose marked region body contains a fs:[...] TEB
 * read (G1 segment override -> designed whole-function native gate, gate
 * note asserted by the E2E runner in the protect log). The except path is
 * exercised with mode 0x77 (in-region AV caught natively, identical both
 * runs). */
#include <stdio.h>
#include <stdint.h>
#include <excpt.h>

extern void marker_begin(void);
extern void marker_end(void);
extern void rgn_seh_helper(void);
extern volatile uint32_t g_sh_out;

__declspec(noinline) static uint32_t seh_fn(uint32_t mode) {
    volatile uint32_t r = 0;
    volatile uint32_t teb_self = 0;
    marker_begin();
    /* real SEH-adjacent TEB inspection inside the region: fs override -> G1 */
    __asm {
        mov eax, fs:[18h]       ; TEB self pointer
        mov teb_self, eax
    }
    __try {
        r = mode * 7u + 3u;
        if (mode == 0x77u) {
            *(volatile uint32_t*)0 = 1u;    /* AV -> __except path */
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        r = 0x5A5A5A5Au;
    }
    marker_end();
    return r ^ (teb_self != 0 ? 1u : 0u);
}

int main(void) {
    rgn_seh_helper();
    const uint32_t a = seh_fn(11u);     /* plain path */
    const uint32_t b = seh_fn(0x77u);   /* AV -> __except path */
    const uint32_t v = (((0x1234ABCDu ^ 0xF0F0F0F0u) + 0x77777777u) << 3);
    const int ok = (a == 11u * 7u + 3u + 1u) && (b == 0x5A5A5A5Au + 1u) &&
                   (g_sh_out == v) && (a != b);
    printf("seh=%08X %08X sh=%08X\n", a, b, g_sh_out);
    return ok ? 0 : 1;
}
