// MIT-333: 端到端正路径样本——区域内含 bswap（32-bit / 64-bit），验证
// bswap 修复后: 翻译成功、运行时走真 Bswap handler、行为与原生逐字节一致
// （保护 → 运行 → stdout+退出码比对）。
//
// 设计要点 (沿用 cl_shift / imul / rol 模式):
//   - bswap 测试 32-bit 和 64-bit 两种 size（分别对应无 REX.W 与有 REX.W）；
//   - 用 _byteswap_ulong / _byteswap_uint64 强制 MSVC /Od 下 codegen 为真
//     `bswap eax` / `bswap rax` 指令（不用 `>>` / `<<` + `|` 拼装——编译器
//     会识别 intrinsic 并直接 emit bswap）；
//   - 用 volatile 全局变量传参数，防止 MSVC 常量折叠把 bswap 挪出 marker
//     区域；
//   - 区域**只含白名单** ALU: mov/bswap, 不含 rip-relative / printf / call
//     （printf 在区域外）；
//   - 含链式 bswap（bswap(bswap(x)) = x 验证 identity）。

#include "wvmp/sdk/markers.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>

volatile uint32_t g_in32 = 0x12345678u;
volatile uint64_t g_in64 = 0x123456789ABCDEF0ull;

// bswap32: r = bswap32(x) (unsigned int, 32-bit, no REX.W).
// MSVC /Od 下 _byteswap_ulong codegen 为 `bswap eax`（无 REX.W → S32）。
__declspec(noinline) static uint32_t bswap32(uint32_t x) {
    WVMP_BEGIN(bswap32);
    uint32_t r = _byteswap_ulong(x);
    WVMP_END(bswap32);
    return r;
}

// bswap64: r = bswap64(x) (unsigned long long, 64-bit, REX.W).
// MSVC /Od 下 _byteswap_uint64 codegen 为 `bswap rax`（REX.W → S64）。
__declspec(noinline) static uint64_t bswap64(uint64_t x) {
    WVMP_BEGIN(bswap64);
    uint64_t r = _byteswap_uint64(x);
    WVMP_END(bswap64);
    return r;
}

// bswap32_chain: bswap(bswap(x)) 应该等于 x (identity)，验证 bswap 之外的
// 区域指令（mov）仍走得通，且 bswap 嵌套不会破坏上下文。
__declspec(noinline) static uint32_t bswap32_chain(uint32_t x) {
    WVMP_BEGIN(bswap32_chain);
    uint32_t r = _byteswap_ulong(x);
    r = _byteswap_ulong(r);          // identity: r = x
    WVMP_END(bswap32_chain);
    return r;
}

int main() {
    // 区域外: 加载全局 + printf (printf 是 libc, 不在白名单)。
    const uint32_t in32 = g_in32;
    const uint64_t in64 = g_in64;

    const uint32_t a = bswap32(in32);          // 0x12345678 → 0x78563412
    const uint64_t b = bswap64(in64);          // 0x123456789ABCDEF0 → 0xF0DEBC9A78563412
    const uint32_t c = bswap32_chain(in32);    // identity: 0x12345678

    std::printf("bswap32=%08x bswap64=%016llx chain=%08x\n",
                a,
                static_cast<unsigned long long>(b),
                c);
    return 0;
}