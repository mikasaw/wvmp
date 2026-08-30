// MIT-427 (G1c): SSE2 movd/movq GP↔xmm 桥端到端主样本。保护 → 运行 →
// stdout+退出码逐字节比对 (native vs virtualized)。
//
// 能力面 (派活单 §B.1/B.3, #33 实测判据见 sse_bridge_sample_asm.asm 头):
//   B.1 桥 (核心必做): movd/movq 双向四形 REG (66 0F 6E / 66 REX.W 0F 6E /
//     66 0F 7E / 66 REX.W 0F 7E) + mem 双向 (→ 既有 XmmLoad/XmmStore 408
//     通路) + all-xmm 双形态 (F3 0F 7E 高 64 清零 → 新 VmOp::XmmFromGp
//     xmm 源路径; 66 0F D6 高 64 保持 → 既有 (Movss,S64)=Movsd 通路)。
//   B.2 paddq/psubq: **砍面留档** (D1 频率双向授权, 实测 shell32 16/854k
//     且与砍面 movdqa 共生, 其余二进制 0, psubq 全零 — 见 GAPS G1c 节)
//     → 负例区照旧 gate (可调用 byte-exact)。sse_fin_sample 的 paddq
//     负例不受影响 (425 面 note 原样)。
//   B.3 VEX 镜像: vmovd/vmovq 随桥本体入面 (426 §F.4 ④ 挂账清偿);
//     vpaddq/vpsubq 随本体砍面照旧 gate。VEX 正例由 lifter 单测钉
//     (test_lifter.cpp MIT-427 块), 样本主面为 legacy 编码。
//   负例 (函数级分区, 426 惯例): paddq / psubq / pmovmskb / pcmpeqd /
//     MMX movq (mm 操作数 D2 永久 gate) / movdqa+movdqu (C++ intrinsic
//     真产物 — /Od 溢出直产, 66/F3 0F 6F/7F 本单砍面照旧 gate)。
//
// 桥语义值断言 (AC#3): int↔SIMD 往返恒等 (①② 装入 → ③④ 提取) +
// movd/movq 装入后高位 = 0 (①② 16B 全量落盘位级证据; 影子样本 8 槽
// 全量读回配对)。区域只含白名单指令, printf 在 main 区域外。REQUIRE_REAL:
// MASM helper 正例区域真虚拟化 (stub ≥1), 负例函数 gate 由 protect 日志
// Note 验证 (报告附 grep 输出)。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>
#include <emmintrin.h>
#include <cstdint>

// C 链接全局: MASM helper 直引符号 (rip-relative 由链接器解析)。
extern "C" unsigned int      g_brg32  = 0xDEADBEEFu;                  // movd mem 源
extern "C" unsigned long long g_brg64 = 0x0F0F0F0F12345678ull;        // movq mem 源
extern "C" unsigned int      g_bout32 = 0;                           // movd mem store 目标
extern "C" unsigned long long g_bout64 = 0;                          // movq mem store 目标

// MASM helper (sse_bridge_sample_asm.asm): 区域 = 本单新形态的真字节。
extern "C" void brg_movd_in(unsigned long long* out);                    // ① 桥 load w4 + 高位清零
extern "C" void brg_movq_in(unsigned long long* out);                    // ② 桥 load w8 + 高位清零
extern "C" void brg_movd_out(unsigned long long bits, unsigned long long* out);  // ③ 桥 store w4 + 零扩展
extern "C" void brg_movq_out(unsigned long long bits, unsigned long long* out);  // ④ 桥 store w8
extern "C" void brg_movq_xmm_zero(const unsigned long long* dst16,
                                  const unsigned long long* src16,
                                  unsigned long long* out);              // ⑤ F3 0F 7E 清零形态
extern "C" void brg_movq_d6(const unsigned long long* dst16,
                                  const unsigned long long* src16,
                                  unsigned long long* out);              // ⑥ 66 0F D6 (实测同 F3 清零)
extern "C" void brg_movd_mem_in(unsigned long long* out);                // ⑦ mem load w4
extern "C" void brg_movq_mem_in(unsigned long long* out);                // ⑧ mem load w8
extern "C" void brg_movd_mem_out(unsigned long long bits);               // ⑨ mem store w4
extern "C" void brg_movq_mem_out(unsigned long long bits);               // ⑩ mem store w8
extern "C" unsigned long long brg_paddq_neg(unsigned long long a,
                                            unsigned long long b);       // ⑪ 负例 gate
extern "C" unsigned long long brg_psubq_neg(unsigned long long a,
                                            unsigned long long b);       // ⑫ 负例 gate
extern "C" void brg_pmovmskb_neg(unsigned long long bits, unsigned long long* out); // ⑬ 负例 gate
extern "C" unsigned long long brg_pcmpeqd_neg(unsigned long long a,
                                              unsigned long long b);     // ⑭ 负例 gate
extern "C" void brg_mmx_neg(unsigned long long a, unsigned long long b,
                            unsigned long long* out);                    // ⑮ 负例 gate (MMX)

// ⑯⑰ C++ intrinsic 真产物负例 (gate 面): /Od 溢出直产 movdqa/movdqu
// (dumpbin probe 实测, 见报告对照表) — 本单砍面 → 整函数 C1 gate,
// 行为 byte-exact (可调用)。
static int cpp_movdqa_neg(int a) {
    int r = 0;
    WVMP_BEGIN(cpp_movdqa_neg);
    __m128i v = _mm_set_epi32(a + 3, a + 2, a + 1, a);   // /Od 溢出直产 movdqa → gate
    r = _mm_cvtsi128_si32(v);
    WVMP_END(cpp_movdqa_neg);
    return r;
}
static unsigned long long cpp_movdqu_neg(const unsigned long long* p) {
    unsigned long long r = 0;
    WVMP_BEGIN(cpp_movdqu_neg);
    __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));  // movdqu → gate
    r = static_cast<unsigned long long>(_mm_cvtsi128_si64(v));
    WVMP_END(cpp_movdqu_neg);
    return r;
}

int main() {
    unsigned long long o[2] = {0, 0};

    // ①② 桥 load: 装入后高位清零位级证据 (out[1] 必为 0)
    brg_movd_in(o);                       // = {00000000A5A5A5A5, 0}
    const unsigned long long d_in0 = o[0], d_in1 = o[1];
    brg_movq_in(o);                       // = {1122334455667788, 0}
    const unsigned long long q_in0 = o[0], q_in1 = o[1];

    // ③④ 桥 store: 区内 Store 落盘观察 (③ 含零扩展: 低 32 装入 → 64 位全量)
    brg_movd_out(0x89ABCDEF12345678ull, o);                               // = 89ABCDEF (零扩展)
    const unsigned long long d_out = o[0];
    brg_movq_out(0x89ABCDEF12345678ull, o);                               // = 89ABCDEF12345678
    const unsigned long long q_out = o[0];
    static const unsigned long long d16[2] = {0x1111111122222222ull, 0x5555555566666666ull};
    static const unsigned long long s16[2] = {0x3333333344444444ull, 0x7777777788888888ull};
    brg_movq_xmm_zero(d16, s16, o);                                       // = {4444444433333333, 0}
    const unsigned long long xz0 = o[0], xz1 = o[1];
    brg_movq_d6(d16, s16, o);                                       // = {4444444433333333, 0} (D6 实测同 F3)
    const unsigned long long xk0 = o[0], xk1 = o[1];

    // ⑦⑧ mem load: 高位清零 (mem 形式 → XmmLoad 通路)
    brg_movd_mem_in(o);                   // = {00000000DEADBEEF, 0}
    const unsigned long long dm0 = o[0], dm1 = o[1];
    brg_movq_mem_in(o);                   // = {0F0F0F0F12345678, 0}
    const unsigned long long qm0 = o[0], qm1 = o[1];

    // ⑨⑩ mem store: 截取落盘 → 区域外读回
    brg_movd_mem_out(0xCAFEBABE01234567ull);   // g_bout32 = 01234567
    brg_movq_mem_out(0xCAFEBABE01234567ull);   // g_bout64 = CAFEBABE01234567

    // ⑪~⑮ 负例: C1 gate (行为 byte-exact; 派单报告附 protect 日志 note)
    const unsigned long long pq  = brg_paddq_neg(0x1ull, 0x2ull);          // = 0x3
    const unsigned long long ps  = brg_psubq_neg(0x5ull, 0x2ull);          // = 0x3
    brg_pmovmskb_neg(0x0000000000FF00FFull, o);
    const unsigned int       pms = static_cast<unsigned int>(o[0]);       // = 0x5 (字节符号位 0101)
    const unsigned long long peq = brg_pcmpeqd_neg(0x1111111111111111ull,
                                                   0x2222222211111111ull); // = 00000000FFFFFFFF (lane0 相等)
    brg_mmx_neg(0xAAAABBBBCCCCDDDDull, 0xEEEEFFFF00001111ull, o);          // = {EEEEFFFF00001111, -}
    const unsigned long long mx = o[0];
    // ⑯⑰ C++ intrinsic 真产物负例 (movdqa/movdqu gate)
    const int cqa = cpp_movdqa_neg(0x40);                                  // = 0x40
    static const unsigned long long cqw_src[2] = {0x123456789ABCDEF0ull,
                                                  0x0FEDCBA987654321ull};
    const unsigned long long cqw = cpp_movdqu_neg(cqw_src);                // = 123456789ABCDEF0

    std::printf("movd_in=%016llX,%016llX movq_in=%016llX,%016llX\n",
                d_in0, d_in1, q_in0, q_in1);
    std::printf("movd_out=%016llX movq_out=%016llX\n", d_out, q_out);
    std::printf("xmm_f3=%016llX,%016llX xmm_d6=%016llX,%016llX\n", xz0, xz1, xk0, xk1);
    std::printf("movd_mem=%016llX,%016llX movq_mem=%016llX,%016llX\n", dm0, dm1, qm0, qm1);
    std::printf("mem_store32=%08X mem_store64=%016llX\n", g_bout32, g_bout64);
    std::printf("paddq_neg=%016llX psubq_neg=%016llX\n", pq, ps);
    std::printf("pmovmskb_neg=%08X pcmpeqd_neg=%016llX mmx_neg=%016llX\n", pms, peq, mx);
    std::printf("cpp_movdqa_neg=%08X cpp_movdqu_neg=%016llX\n",
                static_cast<unsigned int>(cqa), cqw);
    return 0;
}
