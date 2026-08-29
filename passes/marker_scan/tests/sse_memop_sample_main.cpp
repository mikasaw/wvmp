// MIT-411 (G1): SSE 尾扫包端到端主样本 — 双访存语义 + comiss/comisd + pd 位运算族。
// 保护 → 运行 → stdout+退出码逐字节比对 (native vs virtualized)。
//
// 能力面 (派活单 §A.2 三挂点, §A.3 编译器形态先验实测定形):
//   G1-a 双访存 (读→算→写回): x86 SSE ALU 指令的目标恒为 XMM 寄存器, 内存
//     只可能是源 (SDM + ml64 A2000 + capstone 实证, 见 x86_translate.cpp
//     translate_sse_add 注释) — "dst=mem" 是编码学幻影。真实双访存语义 =
//     movsd load + addsd mem源 + movsd store 三条指令 (本样本区域 ① 原样
//     覆盖, 全 rip); 另按派活单 §A.3.1 处方用 MASM 直写 `addsd xmm0,
//     [rsp+40]` 栈基址 mem 源形态 (区域 ②)。
//   G1-b comiss/comisd (0F 2F / 66 0F 2F): 与 ucomis* flags 语义逐位相同
//     (SDM: ZF/PF/CF 按结果, OF/SF/AF 清 0), 折叠复用 Ucomiss/Ucomisd
//     handler。MSVC /Od 对 `g_f < 常量` 天然 emit comiss reg-reg + jbe
//     (有序比较, 区域 ③ 实测字节), 对 `==` 用 ucomiss (区域 ④ 对照);
//     comiss/comisd mem 源 (含 rip) 由 MASM 直写 (区域 ⑤⑥)。
//   G1-c pd 位运算族 (66 0F 54/56/57): 逐位同语义 → 零新 VmOp 折叠 ps。
//     MSVC 对 _mm_and_pd/_mm_or_pd/_mm_xor_pd 直出 andps/orps/xorps
//     (ps/pd 互换无损, 编译器自身即证据, 区域 ⑦); 真 66-prefix pd 字节
//     由 MASM 直写 (区域 ⑧⑨, REG-REG + rip mem 源)。
//   负例: andnps (0F 55) 不在本单范围 (派活单 §C D4, 留 412+) → 区域 ⑩
//     unsupported → C1 gate 兜底, 行为 byte-exact。
//
// 区域只含白名单 (SSE + mov/lea/jcc/setcc/movzx/mov 等), printf 在 main
// 区域外。REQUIRE_REAL: main 区域 + MASM helper 区域真虚拟化 (stub ≥1),
// 负例函数 gate 由 protect 日志 Note 验证 (报告附 grep 输出)。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>
#include <emmintrin.h>
#include <limits>

// C 链接全局: MASM helper 直引符号 (rip-relative 由链接器解析), 同时也是
// main 区域里 MSVC 天然 rip 形态的载体。
extern "C" double g_d = 2.5;
extern "C" float g_f = 3.5f;
extern "C" __m128d g_pd = {1.5, 2.5};
extern "C" __m128d g_pd2 = {10.0, 20.0};

// MASM helper (sse_memop_sample_asm.asm): 区域 = 本单新形态的真字节。
extern "C" double memop_triple_add(double v);           // ① movsd+addsd+movsd 全 rip
extern "C" double memop_addsd_stack(double v);          // ② addsd xmm0,[rsp+40]
extern "C" int memop_comiss_mem(float v);               // ⑤ comiss xmm0,[g_f] + seta
extern "C" int memop_comisd_mem(double v);              // ⑥ comisd xmm0,[g_d] + seta
extern "C" unsigned long long memop_andpd_reg(unsigned long long a, unsigned long long b);  // ⑧
extern "C" unsigned long long memop_orpd_reg(unsigned long long a, unsigned long long b);   // ⑧
extern "C" unsigned long long memop_xorpd_reg(unsigned long long a, unsigned long long b);  // ⑧
extern "C" unsigned long long memop_andpd_mem(unsigned long long a);                        // ⑨ rip mem 源
extern "C" unsigned long long memop_orpd_mem(unsigned long long a);                         // ⑨
extern "C" unsigned long long memop_xorpd_mem(unsigned long long a);                        // ⑨
extern "C" unsigned int memop_andnps_neg(unsigned int a, unsigned int b);  // ⑩ 负例 gate

int main() {
    int r = 0;

    WVMP_BEGIN(main);
    // ① 双访存语义 triple (movsd xmm,[rip+g_d] + addsd xmm,[rip+1.0] +
    //    movsd [rip+g_d],xmm — 读→算→写回, 全 rip)
    g_d += 1.0;                        // 2.5 + 1.0 = 3.5
    // ③ MSVC 天然 comiss (有序比较): movss+movss+comiss reg-reg + jbe
    if (g_f < 4.0f) r += 1;            // 3.5 < 4.0 → 真 → r = 1
    // ④ double 判等 (ucomisd + jp/jne, 既有能力同区域对照)
    if (g_d == 3.5) r += 10;           // r = 11
    // ⑦ MSVC 对 _mm_and_pd 等 intrinsic 直出 andps/orps/xorps (ps 编码,
    //    mem 源) — pd/ps 互换无损的编译器证据 (movaps+op+movaps 栈落)
    __m128d a = _mm_and_pd(g_pd, g_pd2);
    __m128d o = _mm_or_pd(g_pd, g_pd2);
    __m128d x = _mm_xor_pd(g_pd, g_pd2);
    WVMP_END(main);

    // ② 栈基址 mem 源双访存形态 (MASM 直写 addsd xmm0,[rsp+40])
    const double st = memop_addsd_stack(100.0);       // 100.0 + 3.5 = 103.5
    // ⑤⑥ comiss/comisd mem 源 + seta (flags 真参与运行时, pitfall #79)
    const int c_f = memop_comiss_mem(5.0f);           // 5.0 > 3.5 → seta=1
    const int c_fnan = memop_comiss_mem(std::numeric_limits<float>::quiet_NaN());  // unordered → 0
    const int c_d = memop_comisd_mem(4.0);            // 4.0 > 3.5 → seta=1
    const int c_dnan = memop_comisd_mem(std::numeric_limits<double>::quiet_NaN()); // → 0
    // ① 双访存 triple 的 MASM 形态 (g_d 读改写)
    const double tr = memop_triple_add(0.5);          // g_d = 3.5 + 0.5 = 4.0
    // ⑧⑨ pd 位运算族真 66-prefix 字节 (REG-REG + rip mem 源), 位图案精确
    const unsigned long long p_and = memop_andpd_reg(0xFF00FF00FF00FF00ull, 0xFFFF0000FFFF0000ull);
    const unsigned long long p_or  = memop_orpd_reg(0xF0F0F0F0F0F0F0F0ull, 0x0F0F0F0F0F0F0F0Full);
    const unsigned long long p_xor = memop_xorpd_reg(0x0F0F0F0F0F0F0F0Full, 0x33CC33CC33CC33CCull);
    const unsigned long long p_am  = memop_andpd_mem(0xFFFF0000FFFF0000ull);   // & g_pd
    const unsigned long long p_om  = memop_orpd_mem(0x0F0F0F0F0F0F0F0Full);    // | g_pd
    const unsigned long long p_xm  = memop_xorpd_mem(0x33CC33CC33CC33CCull);   // ^ g_pd
    // ⑩ 负例: andnps → C1 gate (行为 byte-exact; andnps = NOT(dst) & src,
    //    SDM: NOT 作用于第一操作数 — 0x0F0F0F0F & ~0xFFFFFFFF = 0xF0F0F0F0)
    const unsigned int n = memop_andnps_neg(0x0F0F0F0Fu, 0xFFFFFFFFu);

    std::printf("g_d=%g g_f=%g r=%d\n", g_d, static_cast<double>(g_f), r);
    std::printf("a=[%g,%g] o=[%g,%g] x=[%g,%g]\n",
                a.m128d_f64[0], a.m128d_f64[1], o.m128d_f64[0], o.m128d_f64[1],
                x.m128d_f64[0], x.m128d_f64[1]);
    std::printf("stack_addsd=%g triple_g_d=%g\n", st, tr);
    std::printf("comiss gt=%d nan=%d comisd gt=%d nan=%d\n", c_f, c_fnan, c_d, c_dnan);
    std::printf("pd_and=%016llX pd_or=%016llX pd_xor=%016llX\n", p_and, p_or, p_xor);
    std::printf("pd_and_mem=%016llX pd_or_mem=%016llX pd_xor_mem=%016llX\n", p_am, p_om, p_xm);
    std::printf("andnps_neg=%08X\n", n);
    return 0;
}
