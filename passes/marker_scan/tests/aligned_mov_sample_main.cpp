// MIT-428 (G1d): SSE2 对齐传送 movdqa/movdqu 端到端主样本。保护 → 运行 →
// stdout+退出码逐字节比对 (native vs virtualized)。
//
// 能力面 (派活单 §B.3/B.5, #33 实测判据见 aligned_mov_sample_asm.asm 头):
//   B.5 主面: movdqa/movdqu 双编码 × 三形态真虚拟化 — reg-reg 6F (MASM 直产)
//     与 7F 反写形 (db 直发) / 栈槽 ([rsp+20h] 对齐 / [rsp+8h] 非对齐) /
//     rip 全局 (对齐 load/store + 非对齐 movdqu store); VEX vmovdqa/vmovdqu
//     三形 (rr 双向 + rip store)。
//   对齐语义 (D2, 375 :1188 先例): movdqa 对齐陷阱 #GP 不模拟 — 非对齐
//     栈槽 movdqu load (⑥) 与非对齐全局 movdqu store (⑨) 行为钉 (native
//     movdqu 合法, VM XmmLoad/XmmStore movups 通路无对齐校验, 两跑一致)。
//     对齐地址的 movdqa (①②⑤⑦⑧) 走同一 handler 家族 (Op::Movaps 中间行
//     = native movaps reg-reg 无对齐语义面), GAPS G1d 节披露。
//   B.3③ intrinsic 真产物翻转正例 (427 #33④ 闭环): /Od 下 _mm_cvtsi32_si128
//     / _mm_cvtsi64_si128 / _mm_loadu_si128 等 + __m128i 栈溢出 (movdqa/
//     movdqu spill/reload) — 427 时点因 movdqa/movdqu gate, 本单起真虚拟化
//     (protect 日志 stub note 为证, dumpbin 对照表见报告)。
//   负例 (函数级分区, 整函数 gate 可调用, 行为 byte-exact): EVEX vmovdqa32
//     (id=1026 白名单外) / vpaddd ymm (位宽闸 + 白名单外) / punpcklqdq
//     (交织语义 D4) / pmovmskb (66 0F D7 D3)。
//
// 区域只含白名单指令 (movups 预载 + 区域内本族指令 + nop), printf 在区域外。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>
#include <cstdint>
#include <emmintrin.h>
#include <immintrin.h>

// C 链接全局: MASM helper (aligned_mov_sample_asm.asm) EXTERNDEF 直引符号。
__declspec(align(16)) extern "C" unsigned long long g_amv_src[2] = {
    0x1122334455667788ull, 0x99AABBCCDDEEFF00ull};         // 对齐 rip 源
__declspec(align(16)) extern "C" unsigned long long g_amv_out[2] = {
    0, 0};                                                 // 对齐 store 目标 (⑧⑫)
extern "C" unsigned long long g_amv_out_u[2] = {0, 0};     // 非对齐 store 目标 (⑨)

// MASM helper 正例 (区域 = 本单新形态真字节)。
extern "C" void amv_dqa_rr6(unsigned long long* out, const unsigned long long* src);   // ①
extern "C" void amv_dqa_rr7(unsigned long long* out, const unsigned long long* src);   // ② 7F 反写
extern "C" void amv_dqu_rr6(unsigned long long* out, const unsigned long long* src);   // ③
extern "C" void amv_dqu_rr7(unsigned long long* out, const unsigned long long* src);   // ④ 7F 反写
extern "C" void amv_dqa_stack(unsigned long long* out, const unsigned long long* src); // ⑤ 对齐栈槽
extern "C" void amv_dqu_stack_unal(unsigned long long* out, const unsigned long long* src); // ⑥ 非对齐
extern "C" void amv_dqa_rip_load(unsigned long long* out, const unsigned long long* sentinel); // ⑦
extern "C" void amv_dqa_rip_store(const unsigned long long* src);                      // ⑧
extern "C" void amv_dqu_rip_store(const unsigned long long* src);                      // ⑨ 非对齐
extern "C" void amv_vdqa_rr(unsigned long long* out, const unsigned long long* src);   // ⑩ VEX
extern "C" void amv_vdqu_rr(unsigned long long* out, const unsigned long long* src);   // ⑪ VEX
extern "C" void amv_vdqa_rip_store(const unsigned long long* src);                     // ⑫ VEX
// MASM 负例 (整函数 gate, native 执行, 行为 byte-exact)。
extern "C" void amv_vmovdqa32_neg(const unsigned long long* in, unsigned long long* out); // ⑬ EVEX
extern "C" void amv_vpaddd_ymm_neg(const unsigned long long* in, unsigned long long* out); // ⑭ ymm
extern "C" void amv_punpcklqdq_neg(const unsigned long long* d, const unsigned long long* s,
                                   unsigned long long* out);                            // ⑮
extern "C" void amv_pmovmskb_neg(unsigned long long bits, unsigned long long* out);     // ⑯

// ---- B.3③ intrinsic 真产物翻转正例 (427 #33④ 闭环): /Od 下 __m128i 局部
// 变量溢出直产 movdqa/movdqu 栈槽 spill/reload (dumpbin 实测对照表见报告)
// — 427 时点整函数 C1 gate, 本单起真虚拟化。 ----

// 翻正例 1: movd 装入 → movdqa spill/reload → movd 提取 (int 往返恒等)。
static int amv_cpp_dqa_flip(int a) {
    int r = 0;
    WVMP_BEGIN(amv_cpp_dqa_flip);
    __m128i v = _mm_cvtsi32_si128(a);   // movd xmm0, eax (427 桥) + movdqa spill
    r = _mm_cvtsi128_si32(v);           // movdqa reload + movd eax, xmm0
    WVMP_END(amv_cpp_dqa_flip);
    return r;
}
// 翻正例 2: movq 装入 → movdqa spill/reload → movq 提取 (u64 往返恒等)。
static unsigned long long amv_cpp_movq_flip(unsigned long long x) {
    unsigned long long r = 0;
    WVMP_BEGIN(amv_cpp_movq_flip);
    __m128i v = _mm_cvtsi64_si128(static_cast<__int64>(x));  // movq xmm0, rax + spill
    r = static_cast<unsigned long long>(_mm_cvtsi128_si64(v));
    WVMP_END(amv_cpp_movq_flip);
    return r;
}
// 翻正例 3: movdqu load → movdqa spill → movdqu store (16B 全宽搬运)。
static void amv_cpp_dqu_chain(const unsigned long long* p, unsigned long long* out) {
    WVMP_BEGIN(amv_cpp_dqu_chain);
    __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));  // movdqu + movdqa spill
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), v);              // movdqu store
    WVMP_END(amv_cpp_dqu_chain);
}

int main() {
    // asm 探针签名: [rdx]=dst 哨兵 16B + [rdx+16]=源图案 16B (32B 连续窗)
    static const unsigned long long src4[4] = {0xDEADDEADDEADDEADull,
                                               0xBEEFBEEFBEEFBEEFull,   // dst 哨兵 16B
                                               0x0F0F0F0F12345678ull,
                                               0xA5A5A5A5A5A5A5A5ull};  // 源位图案 16B
    static const unsigned long long* const pat = src4 + 2;
    // o = 32B (4×u64): ⑭ vpaddd ymm 负例落盘 32B (16B 越界写 → 退出期栈损坏
    // rc=3 空 stdout — cdb 实测根因, 修正记录)
    unsigned long long o[4] = {0, 0, 0, 0};

    // ①~④ reg-reg 双编码: out = 源图案全宽 (哨兵被覆写 = 拷贝位级证据)
    amv_dqa_rr6(o, src4);  const unsigned long long r1 = pat[0], r2 = pat[1];
    amv_dqa_rr7(o, src4);  const unsigned long long r3 = pat[0], r4 = pat[1];
    amv_dqu_rr6(o, src4);  const unsigned long long r5 = pat[0], r6 = pat[1];
    amv_dqu_rr7(o, src4);  const unsigned long long r7 = pat[0], r8 = pat[1];

    // ⑤⑥ 栈槽: 对齐 movdqa / 非对齐 movdqu — 同一源图案两跑一致
    amv_dqa_stack(o, src4);       const unsigned long long s1 = pat[0], s2 = pat[1];
    amv_dqu_stack_unal(o, src4);  const unsigned long long u1 = pat[0], u2 = pat[1];

    // ⑦ rip 对齐 load
    amv_dqa_rip_load(o, src4);   const unsigned long long g1 = g_amv_src[0],
                                 g2 = g_amv_src[1];

    // ⑧⑨⑫ rip store: 对齐 movdqa / 非对齐 movdqu / VEX 对齐 — main 读回
    amv_dqa_rip_store(pat);      const unsigned long long so1 = g_amv_out[0],
                                                 so2 = g_amv_out[1];
    g_amv_out_u[0] = g_amv_out_u[1] = 0;
    amv_dqu_rip_store(pat);      const unsigned long long uo1 = g_amv_out_u[0],
                                                 uo2 = g_amv_out_u[1];
    g_amv_out[0] = g_amv_out[1] = 0;
    amv_vdqa_rip_store(pat);     const unsigned long long vo1 = g_amv_out[0],
                                                 vo2 = g_amv_out[1];

    // ⑩⑪ VEX reg-reg
    amv_vdqa_rr(o, src4);         const unsigned long long v1 = pat[0], v2 = pat[1];
    amv_vdqu_rr(o, src4);         const unsigned long long v3 = pat[0], v4 = pat[1];

    // ⑬~⑯ 负例: C1 gate (整函数 native, 行为 byte-exact)。
    // nsrc = 64B 窗: ⑬ 读 [rcx]+[rcx+16] (前 32B); ⑭ ymm 负例读 [rcx] 32B
    // + [rcx+32] 32B — 前 4 元素 2×u32 加后 4 元素 (lane 和, 无进位越 lane)。
    static const unsigned long long nsrc[8] = {0x1111111122222222ull,
                                               0x3333333344444444ull,
                                               0x5555555566666666ull,
                                               0x7777777788888888ull,
                                               0x0102030405060708ull,
                                               0x090A0B0C0D0E0F10ull,
                                               0x1112131415161718ull,
                                               0x191A1B1C1D1E1F20ull};
    amv_vmovdqa32_neg(nsrc, o);  const unsigned long long e1 = o[0], e2 = o[1];
    amv_vpaddd_ymm_neg(nsrc, o); const unsigned long long e3 = o[0], e4 = o[1];
    amv_punpcklqdq_neg(&nsrc[0], &nsrc[2], o);
                                 const unsigned long long e5 = o[0], e6 = o[1];
    amv_pmovmskb_neg(0x0000000000FF00FFull, o);
                                 const unsigned int       e7 = static_cast<unsigned int>(o[0]);

    // B.3③ intrinsic 翻转正例 (真虚拟化证据 = protect 日志 stub note)
    const int                    f1 = amv_cpp_dqa_flip(0x40);             // = 0x40
    const unsigned long long     f2 = amv_cpp_movq_flip(0x123456789ABCDEF0ull);
    unsigned long long f3o[2] = {0, 0};
    amv_cpp_dqu_chain(pat, f3o);                                          // = pat 全宽
    const unsigned long long     f3 = f3o[0], f4 = f3o[1];

    std::printf("dqa_rr6=%016llX,%016llX dqa_rr7=%016llX,%016llX\n", r1, r2, r3, r4);
    std::printf("dqu_rr6=%016llX,%016llX dqu_rr7=%016llX,%016llX\n", r5, r6, r7, r8);
    std::printf("dqa_stack=%016llX,%016llX dqu_stack_unal=%016llX,%016llX\n", s1, s2, u1, u2);
    std::printf("dqa_rip_load=%016llX,%016llX\n", g1, g2);
    std::printf("rip_store dqa=%016llX,%016llX dqu=%016llX,%016llX vex=%016llX,%016llX\n",
                so1, so2, uo1, uo2, vo1, vo2);
    std::printf("vdqa_rr=%016llX,%016llX vdqu_rr=%016llX,%016llX\n", v1, v2, v3, v4);
    std::printf("neg_evex=%016llX,%016llX neg_ymm=%016llX,%016llX\n", e1, e2, e3, e4);
    std::printf("neg_punpck=%016llX,%016llX neg_pmovmskb=%08X\n", e5, e6, e7);
    std::printf("cpp_flip dqa=%08X movq=%016llX dqu=%016llX,%016llX\n",
                static_cast<unsigned int>(f1), f2, f3, f4);
    return 0;
}
