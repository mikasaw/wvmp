// MIT-425 (G1b): SSE 收官包端到端主样本 — mul 族 + andnps/andnpd + SSE2
// 整数位运算族。保护 → 运行 → stdout+退出码逐字节比对 (native vs virtualized)。
//
// 能力面 (派活单 §B.1/B.2/B.3, #33 先验实测修正见 sse_fin_sample_asm.asm 头):
//   R1 mul 族 (mulss/mulsd/mulps/mulpd): C++ 天然区域 (g_fa *= g_fb /
//     g_da *= g_db, /Od 直产 movss/mulsd [rip] mem 形式 — cl v145 实测)
//     + MASM 真 0F 59 系四编码 (REG-REG + rip mem 源)。
//   R3 andnps/andnpd (0F 55 系): dst = ~dst & src — 非纯位运算三元组,
//     VM 无 128-bit NOT 原语, 双折不可行 → 新 VmOp::Andnps (派活单 §B.2
//     "两条折 或 新 VmOp 你实测选")。F0F0F0F0 手算基线见 ⑦。
//   R2 档① SSE2 整数位运算族 (pand/por/pxor/pandn, 66 0F DB/EB/EF/DF):
//     与 ps 位运算逐位同语义 → 零新 VmOp 折叠 Andps/Orps/Xorps/Andnps
//     (411 pd 折叠 ps 先例的整数扩展); pandn 折叠 Andnps。
//   负例: paddq (66 0F D4) — R2 档② 砍面留 G1c (跳表预算 95 顶格) →
//     区域 ⑭ unsupported → C1 gate 兜底, 行为 byte-exact (可调用)。
//
// 区域只含白名单 (SSE + mov/lea/nop), printf 在 main 区域外。REQUIRE_REAL:
// main 区域 + MASM helper 区域真虚拟化 (stub ≥1), 负例函数 gate 由 protect
// 日志 Note 验证 (报告附 grep 输出)。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

// C 链接全局: MASM helper 直引符号 (rip-relative 由链接器解析)。
// ⚠️ packed mem 源 (mulps/pand) 原生要求 16B 对齐 (#GP 语义) — align(16)
// 必带; VM 侧经 XmmLoad 一律 movups 非对齐语义不受影响 (408 D2)。
extern "C" double g_fin_d = 2.5;      // mulsd mem 源 (8B 对齐默认满足)
extern "C" __declspec(align(16)) float g_fin_ps[4] = {2.0f, 3.0f, 4.0f, 5.0f};  // mulps mem 源
extern "C" __declspec(align(16)) unsigned long long g_fin_pi[2] = {
    0x0F0F0F0F0F0F0F0Full, 0xF0F0F0F0F0F0F0F0ull};          // pand mem 源位图案

// C++ 天然区域载体 (/Od 直产 mulss/mulsd [rip] mem 形式)
static double g_da = 6.0, g_db = 2.5;
static float g_fa = 3.0f, g_fb = 4.0f;

// MASM helper (sse_fin_sample_asm.asm): 区域 = 本单新形态的真字节。
extern "C" unsigned int      fin_mulss_rr(unsigned int a, unsigned int b);   // ① float 位
extern "C" unsigned long long fin_mulsd_rr(unsigned long long a, unsigned long long b);  // ②
extern "C" unsigned long long fin_mulsd_mem(unsigned long long a);           // ③ rip mem
extern "C" unsigned long long fin_mulps_rr(unsigned long long a, unsigned long long b);  // ④
extern "C" unsigned long long fin_mulpd_rr(unsigned long long a, unsigned long long b);  // ⑤
extern "C" unsigned long long fin_mulps_mem(unsigned long long a);           // ⑥ rip mem
extern "C" unsigned long long fin_andnps_rr(unsigned long long a, unsigned long long b); // ⑦ F0F0 基线
extern "C" unsigned long long fin_andnpd_rr(unsigned long long a, unsigned long long b); // ⑧
extern "C" unsigned long long fin_pandn_rr(unsigned long long a, unsigned long long b);  // ⑨
extern "C" unsigned long long fin_pand_rr(unsigned long long a, unsigned long long b);   // ⑩
extern "C" unsigned long long fin_por_rr(unsigned long long a, unsigned long long b);    // ⑪
extern "C" unsigned long long fin_pxor_rr(unsigned long long a, unsigned long long b);   // ⑫
extern "C" unsigned long long fin_pand_mem(unsigned long long a);            // ⑬ rip mem
extern "C" unsigned long long fin_paddq_neg(unsigned long long a, unsigned long long b); // ⑭ 负例 gate

int main() {
    // C++ 天然 mul 区域 (/Od: movsd+mulsd [rip]+movsd / movss+mulss [rip]
    // +movss — mul 族编译器自然产物高频形态, 派活单 §A.3)
    WVMP_BEGIN(fin_natural);
    g_da *= g_db;                      // 6.0 * 2.5 = 15.0
    g_fa *= g_fb;                      // 3.0f * 4.0f = 12.0f
    WVMP_END(fin_natural);

    // MASM 真字节区域 (各 helper 区域内 = 目标指令 + nop 垫)
    // ①② mul REG-REG: float 位图案 0x41C80000 (25.0f) × 0x40000000 (2.0f)
    //    = 0x42C80000 (100.0f); double 位图案 6.0 × 2.5 = 15.0。
    const unsigned int m_ss =
        fin_mulss_rr(0x41C80000u, 0x40000000u);                    // = 0x42C80000
    const unsigned long long m_sd = fin_mulsd_rr(0x4018000000000000ull,   // 6.0
                                                 0x4004000000000000ull);  // 2.5 → 15.0
    // ③ mulsd rip mem: 位图案 1.5 × g_fin_d(2.5) = 3.75
    const unsigned long long m_sdm = fin_mulsd_mem(0x3FF8000000000000ull);
    // ④⑤ mulps/mulpd REG-REG (低 64 位 lane 位图案)
    const unsigned long long m_ps = fin_mulps_rr(0x4000000040000000ull,   // lane0/1 = 2.0f
                                                 0x4040004040000040ull);  // 3.0f/1.5f
    const unsigned long long m_pd = fin_mulpd_rr(0x4008000000000000ull,   // lane0 = 3.0
                                                 0x4004000000000000ull);  // 2.5 → 7.5
    // ⑥ mulps rip mem: 2.0f lane × {2,3,4,5} = {4,6,8,10}
    const unsigned long long m_psm = fin_mulps_mem(0x4000000040000000ull);
    // ⑦ andnps F0F0F0F0 基线 (411 手算基线沿用): ~a & b
    const unsigned long long n_ps = fin_andnps_rr(0x0F0F0F0F0F0F0F0Full,
                                                  0xFFFFFFFFFFFFFFFFull); // = 0xF0F0F0F0F0F0F0F0
    // ⑧⑨ andnpd / pandn (66 0F 55 / 66 0F DF) — 逐位同语义
    const unsigned long long n_pd = fin_andnpd_rr(0x0F0F0F0F0F0F0F0Full,
                                                  0xFFFFFFFFFFFFFFFFull);
    const unsigned long long n_pn = fin_pandn_rr(0x0F0F0F0F0F0F0F0Full,
                                                 0xFFFFFFFFFFFFFFFFull);
    // ⑩⑪⑫ pand/por/pxor (66 0F DB/EB/EF) 位图案精确
    const unsigned long long p_and = fin_pand_rr(0xFF00FF00FF00FF00ull,
                                                 0xFFFF0000FFFF0000ull);  // = 0xFF000000FF000000
    const unsigned long long p_or  = fin_por_rr(0xF0F0F0F0F0F0F0F0ull,
                                                0x0F0F0F0F0F0F0F0Full);   // = 0xFFFFFFFFFFFFFFFF
    const unsigned long long p_xor = fin_pxor_rr(0x0F0F0F0F0F0F0F0Full,
                                                 0x33CC33CC33CC33CCull);  // = 0x3CC33CC33CC33CC3
    // ⑬ pand rip mem: a & g_fin_pi[0]
    const unsigned long long p_am  = fin_pand_mem(0xFFFFFFFFFFFFFFFFull);  // = 0x0F0F0F0F0F0F0F0F
    // ⑭ 负例: paddq → C1 gate (行为 byte-exact; 0x1 + 0x2 = 0x3 整数加)
    const unsigned long long pq = fin_paddq_neg(0x1ull, 0x2ull);

    std::printf("natural g_da=%g g_fa=%g\n", g_da, g_fa);
    std::printf("mulss=%08X mulsd=%016llX mulsd_mem=%016llX\n", m_ss, m_sd, m_sdm);
    std::printf("mulps=%016llX mulpd=%016llX mulps_mem=%016llX\n", m_ps, m_pd, m_psm);
    std::printf("andnps=%016llX andnpd=%016llX pandn=%016llX\n", n_ps, n_pd, n_pn);
    std::printf("pand=%016llX por=%016llX pxor=%016llX pand_mem=%016llX\n",
                p_and, p_or, p_xor, p_am);
    std::printf("paddq_neg=%016llX\n", pq);
    return 0;
}
