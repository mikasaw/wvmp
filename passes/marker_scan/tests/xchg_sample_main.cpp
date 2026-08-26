// MIT-334: 端到端正路径样本——区域内含 xchg（REG-REG 32-bit / 64-bit），
// 验证 xchg 修复后: 翻译成功、运行时走真 Xchg handler、行为与原生逐字节一致
// （保护 → 运行 → stdout+退出码比对）。
//
// 设计要点:
//   - MSVC x64 **不支持 inline asm**, std::swap 等高 level C++ 全部编译成
//     mov+mov+mov, 不出 xchg. 因此真 xchg 字节由 xchg_helper.asm (MASM)
//     直接 emit, 链接进本 sample. 函数体内 marker_begin/marker_end 之间
//     是 xchg 真指令 (rax ↔ rbx, eax ↔ ebx).
//   - 区域**只含白名单** ALU: mov/xchg, 不含 rip-relative / printf / call
//     （printf 在区域外的 main 中）.
//   - 含链式 xchg (a↔b, b↔c, a↔b 共 3 次) 覆盖多次 xchg 链接正确.

#include "wvmp/sdk/markers.hpp"

#include <cstdint>
#include <cstdio>

extern "C" uint64_t xchg64_fn(uint64_t x, uint64_t y);
extern "C" uint32_t xchg32_fn(uint32_t x, uint32_t y);
extern "C" uint64_t xchg_chain_fn(uint64_t* a, uint64_t* b, uint64_t* c);

volatile uint64_t g_x64 = 0x0123456789ABCDEFull;
volatile uint64_t g_y64 = 0xFEDCBA9876543210ull;
volatile uint32_t g_x32 = 0x12345678u;
volatile uint32_t g_y32 = 0xABCDEF01u;

int main() {
    // 区域外: 加载全局 + printf (printf 是 libc, 不在白名单).
    const uint64_t x64 = g_x64;
    const uint64_t y64 = g_y64;
    const uint32_t x32 = g_x32;
    const uint32_t y32 = g_y32;

    const uint64_t a = xchg64_fn(x64, y64);          // 0x0123456789ABCDEF → 0xFEDCBA9876543210
    const uint32_t b = xchg32_fn(x32, y32);          // 0x12345678 → 0xABCDEF01

    // 链式 xchg: a↔b, b↔c, a↔b 后, a=b_orig, b=c_orig, c=a_orig
    // 故最终 *a = c_orig = x64 ^ y64
    uint64_t ca = x64;
    uint64_t cb = y64;
    uint64_t cc = x64 ^ y64;
    const uint64_t c = xchg_chain_fn(&ca, &cb, &cc); // ca 最终 = cc_orig

    std::printf("xchg64=%016llx xchg32=%08x chain=%016llx\n",
                static_cast<unsigned long long>(a),
                b,
                static_cast<unsigned long long>(c));
    return 0;
}
