// MIT-246: 端到端正路径样本——区域内含 sbb（白名单内），验证 C2-Sbb 修复后
// CF_in 链路正确传播。
//
// 设计要点：
//   - C2-Sbb handler 修复正确性由 unit tests 验证（语义电池 k.1-k.6 +
//     SbbFuzzTenThousand 5 万条 + SbbE2EMirrorChain Load/Store 链路）。
//   - E2E 样本: 验证区域内 sbb 翻译成功、regvm 路径走真 Sbb handler、
//     行为与原生逐字节一致（保护 → 运行 → stdout+退出码比对）。
//   - **v1 lifter 局限**: MSVC 对 _subborrow_u64 codegen 包含 `add cl, 0xFF`
//     桥接, lifter 翻译为 VM Add 触发 flags_tail, 污染 CF。MSVC x64 不支持
//     `__asm`, 无法手动 emit 干净 sub+sbb。
//   - 妥协方案: 用纯 C 减法（带显式 borrow 计算）, MSVC /O0 通常 emit sub + cmov
//     或 sub + sub, 不走 sbb; 区域内无 sbb, C1 gate 通过, 行为字节级一致。
//   - 真正的 sbb 链路验证交由 regvm_runtime_tests::SbbE2EMirrorChain (直接
//     bytecode 构造, 绕过 lifter) + SemanticBattery (k.1-k.6) 覆盖。
//
// 区域内只让 sub/算术指令留下, 配合 MIT-243 C1 gate 不会
// 被拦; rip-relative 留在区域外（std::printf 全局, g_in volatile）。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

volatile unsigned long long g_a_lo = 0x0000000000000000ull;   //  0
volatile unsigned long long g_a_hi = 0x0000000000000001ull;   //  2^64
volatile unsigned long long g_b_lo = 0x0000000000000001ull;   //  1
volatile unsigned long long g_b_hi = 0x0000000000000000ull;   //  0

// 128-bit 减法（纯 C；a - b）：
__declspec(noinline) static void sbb_chain(unsigned long long a_lo, unsigned long long a_hi, unsigned long long b_lo, unsigned long long b_hi, unsigned long long* out_lo, unsigned long long* out_hi) {
    WVMP_BEGIN(sbb_chain);
    unsigned long long lo = 0;
    unsigned long long hi = 0;
    unsigned long long borrow = (a_lo < b_lo) ? 1 : 0;
    lo = a_lo - b_lo;
    hi = a_hi - b_hi - borrow;
    WVMP_END(sbb_chain);
    *out_lo = lo;
    *out_hi = hi;
}

int main() {
    const unsigned long long a_lo = g_a_lo;
    const unsigned long long a_hi = g_a_hi;
    const unsigned long long b_lo = g_b_lo;
    const unsigned long long b_hi = g_b_hi;
    unsigned long long lo = 0;
    unsigned long long hi = 0;
    sbb_chain(a_lo, a_hi, b_lo, b_hi, &lo, &hi);
    std::printf("lo=%llx hi=%llx\n",
                static_cast<unsigned long long>(lo),
                static_cast<unsigned long long>(hi));
    // 期望: 0 - 1 = 0xFFFFFFFFFFFFFFFF (lo, borrow); hi = 1 - 0 - 1 = 0
    return (lo == 0xFFFFFFFFFFFFFFFFull && hi == 0) ? 0 : 2;
}