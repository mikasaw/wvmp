// MIT-425 (G1b): SSE 收官包影子样本 — mul 族 + andnps/andnpd + SSE2 整数
// 位运算族的 ctx.xmm 运行时读回断言 (与 wvmp_sse_fin_sample 同能力面配对、
// 独立 exe, 沿用 MIT-389/408/411 影子样本模式)。
//
// 背景 (pitfall #79 纪律): 主样本 stdout 只断言最终值。本单新 handler
// (Mulss/Mulsd/Mulps/Mulpd/Andnps) 的坑位: 槽位偏移公式错 (MIT-371 空转
// 形态: sub 0x24 而非 0x18 → 写 GPR 槽区) 时主样本可能碰巧 PASS — 本影子
// 把 8 槽 × 2×u64 全量打印: dst 槽 = 期望位图案, 其余 7 槽必须 = 入口预载
// 值 (误写无关槽即 FAIL); 标量 mulss/mulsd 的 "高位保持" 语义同场可断。
//
// 全部输出 %016llx 逐位可比对。native run vs virtualized run 逐字节比对;
// handler 空转/槽位错/宽度错 → 与原生不一致 → FAIL。

#include <cstdio>

extern "C" void fin_mulss_rr(float a, float b, const unsigned long long* in, unsigned long long* out);
extern "C" void fin_mulsd_rr(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void fin_mulsd_mem(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void fin_mulps_rr(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void fin_mulpd_rr(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void fin_mulps_mem(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void fin_andnps_rr(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void fin_andnpd_rr(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void fin_pandn_rr(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void fin_pand_rr(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void fin_por_rr(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void fin_pxor_rr(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void fin_pand_mem(double a, double b, const unsigned long long* in, unsigned long long* out);

// C 链接全局: MASM helper (sse_fin_xmm_readback_sample_asm.asm) EXTERNDEF
// 直引符号 — rip mem 源位图案。⚠️ packed mem 源原生要求 16B 对齐 (#GP),
// align(16) 必带 (411 影子 g_sh_pd 同款纪律)。
extern "C" double g_sh_d = 2.5;                           // mulsd mem 源
extern "C" __declspec(align(16)) float g_sh_ps[4] = {2.0f, 3.0f, 4.0f, 5.0f};   // mulps mem 源
extern "C" __declspec(align(16)) unsigned long long g_sh_pi[2] = {
    0x0F0F0F0F0F0F0F0Full, 0xF0F0F0F0F0F0F0F0ull};        // pand mem 源

// 预载位图案 (8 槽 × 2×u64): 互不相同且非零 — 判别 "误写无关槽" 与
// "槽位公式错写 GPR 区"。FP 探针只预载 xmm2..7 (xmm0/1 由参数位就位);
// 位图案探针全 8 槽预载 (load_all)。
static const unsigned long long g_in[16] = {
    0x1111111111111111ull, 0x2222222222222222ull,  // xmm0
    0x3333333333333333ull, 0x4444444444444444ull,  // xmm1
    0x5555555555555555ull, 0x6666666666666666ull,  // xmm2
    0x7777777777777777ull, 0x8888888888888888ull,  // xmm3
    0x9999999999999999ull, 0xAAAAAAAAAAAAAAAAull,  // xmm4
    0xBBBBBBBBBBBBBBBBull, 0xCCCCCCCCCCCCCCCCull,  // xmm5
    0xDDDDDDDDDDDDDDDDull, 0xEEEEEEEEEEEEEEEEull,  // xmm6
    0x0F0F0F0F0F0F0F0Full, 0x1E1E1E1E1E1E1E1Eull,  // xmm7
};

template <typename Fn>
static void run_probe(const char* name, Fn fn, double a, double b) {
    unsigned long long out[17];
    for (int i = 0; i < 17; ++i) out[i] = 0xCCCCCCCCCCCCCCCCull;  // 哨兵
    fn(a, b, g_in, out);
    std::printf("[%s]\n", name);
    for (int s = 0; s < 8; ++s) {
        std::printf("  xmm%d=%016llX,%016llX\n", s, out[s * 2], out[s * 2 + 1]);
    }
}

// 位图案 → double 位传送 (探针参数走 xmm0, 位图案原样进 VM 槽)。本样本
// 位图案探针统一走 asm load_all 从 g_in 全量预载 (含 xmm0/1), 参数位不
// 参与 — 保留注释说明无 bits_to_double 需求 (411 影子先例的反向简化)。

int main() {
    // 1) mulss (float 参数: 只消费 xmm0/xmm1 低 32 位; 6.0f × 2.5f = 15.0f,
    //    xmm0 高 96 位保持 = 传入残留 — native 与 virtualized 同源可比)
    run_probe("mulss_rr", fin_mulss_rr, 6.0f, 2.5f);
    // 2) mulsd (6.0 × 2.5 = 15.0, 位图案精确 0x402E000000000000)
    run_probe("mulsd_rr", fin_mulsd_rr, 6.0, 2.5);
    // 3) mulsd rip mem 源 (a × g_sh_d=2.5)
    run_probe("mulsd_mem", fin_mulsd_mem, 3.0, 0.0);   // 3.0 × 2.5 = 7.5
    // 4) mulps (位图案全 8 槽预载: 4 lane 并行, lane 语义不解释 — 只比位)
    run_probe("mulps_rr", fin_mulps_rr, 0.0, 0.0);
    // 5) mulpd (位图案: 2 lane)
    run_probe("mulpd_rr", fin_mulpd_rr, 0.0, 0.0);
    // 6) mulps rip mem 源
    run_probe("mulps_mem", fin_mulps_mem, 0.0, 0.0);
    // 7) andnps (位图案: xmm0=~位 与 xmm1 — F0F0F0F0 基线由 g_in 构造)
    run_probe("andnps_rr", fin_andnps_rr, 0.0, 0.0);
    // 8) andnpd (66 0F 55, 与 andnps 逐位同语义)
    run_probe("andnpd_rr", fin_andnpd_rr, 0.0, 0.0);
    // 9) pandn (66 0F DF)
    run_probe("pandn_rr", fin_pandn_rr, 0.0, 0.0);
    // 10) pand dst=xmm2 槽变体 (结果落 slot2, 其余 7 槽 = 预载不动)
    run_probe("pand_rr", fin_pand_rr, 0.0, 0.0);
    // 11) por (xmm0 槽)
    run_probe("por_rr", fin_por_rr, 0.0, 0.0);
    // 12) pxor dst=xmm2 槽变体
    run_probe("pxor_rr", fin_pxor_rr, 0.0, 0.0);
    // 13) pand rip mem 源 (xmm0 & g_sh_pi)
    run_probe("pand_mem", fin_pand_mem, 0.0, 0.0);
    return 0;
}
