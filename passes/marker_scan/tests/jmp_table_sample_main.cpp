// MIT-409 (MIT-A6): MSVC 跳转表特化 E2E 样本 — 正/负双形态。
//
// 1) 正样本 (wv_switch8): switch 8 路 + default + 边界 (idx 越界走 default)。
//    MSVC /Od 对稠密 0..7 case 恒 emit 四件套跳转表 (cmp idx,7; ja default;
//    mov idx 载入; lea rip 表基址; mov 读表 u32; add; jmp reg) —— 翻译期
//    读表静态展开比较链, 区域真虚拟化 (REQUIRE_REAL ≥1 stub)。
//    case body 各为仅表可达的 mid-block 代码 (块切分机制覆盖), break → join
//    (= marker_end call = end_rva) → ExitNative END-call 等价退出。
//    默认 case (idx ≥ 8) 走 ja 直落, 与 r06 的死防御不同——这里是活防御。
// 2) 负样本 (wv_opaque_jmp_masm, MASM): 区域内 `mov rax,[g_fp]; jmp rax`
//    —— 目标从全局函数指针加载, 翻译期不可枚举, 非四件套形态 → 照旧 C1
//    gate (函数保持原生), packed 与 native 行为逐字节一致。
//
// 验收: multiseed REQUIRE_REAL=1 (≥1 stub + byte-exact); e2e 日志含
// "jump-table @ ... targets-in-region" 命中证据 + 负样本函数 gate note。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

extern "C" unsigned long long wv_helper(unsigned long long n);
extern "C" unsigned long long (*volatile g_fp)(unsigned long long);
extern "C" unsigned long long wv_opaque_jmp_masm(unsigned long long n);

// 负样本的目标函数 + 全局函数指针（extern "C" 保证 MASM 可 EXTERNDEF）。
extern "C" unsigned long long wv_helper(unsigned long long n) {
    return n * 3ull + 7ull;
}
extern "C" unsigned long long (*volatile g_fp)(unsigned long long) = wv_helper;

// 正样本: switch 8 路 + default + 边界。volatile 防常量折叠;/Od 固定表形态。
__declspec(noinline) static unsigned long long wv_switch8(unsigned long long idx,
                                                           unsigned long long base) {
    volatile unsigned long long r = 0;
    WVMP_BEGIN(wv_switch8);
    switch (idx) {
    case 0: r = base + 0x10ull; break;
    case 1: r = base + 0x21ull; break;
    case 2: r = base + 0x32ull; break;
    case 3: r = base + 0x43ull; break;
    case 4: r = base + 0x54ull; break;
    case 5: r = base + 0x65ull; break;
    case 6: r = base + 0x76ull; break;
    case 7: r = base + 0x87ull; break;
    default: r = base ^ 0xA5A5A5A5A5A5A5A5ull; break; // idx ≥ 8: 活防御路径
    }
    WVMP_END(wv_switch8);
    return r;
}

// 负样本 (C++ 侧包装, 区域在 asm 内): opaque 间接跳转 → gate。
__declspec(noinline) static unsigned long long wv_opaque_jmp(unsigned long long n) {
    return wv_opaque_jmp_masm(n);
}

int main() {
    volatile unsigned long long ok = 1;
    // 边界全覆盖: 0..7 表内 8 路 + 8..15 越界走 default。
    for (unsigned long long i = 0; i < 16; ++i) {
        const unsigned long long r = wv_switch8(i, 0x1000ull);
        std::printf("switch8(%llu)=0x%llX\n", i, r);
    }
    // 负样本: 函数指针全局尾跳, gate 后原生执行, 行为与 packed 逐字节一致。
    for (unsigned long long i = 0; i < 4; ++i) {
        const unsigned long long r = wv_opaque_jmp(i);
        ok &= (r == i * 3ull + 7ull);
        std::printf("opaque(%llu)=0x%llX\n", i, r);
    }
    std::printf("ok=%llu\n", ok);
    return ok == 1 ? 0 : 2;
}
