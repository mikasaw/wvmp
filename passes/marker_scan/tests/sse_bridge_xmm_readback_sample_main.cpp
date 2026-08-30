// MIT-427 (G1c): SSE2 movd/movq GP↔xmm 桥影子样本 — 桥 handler 的 ctx.xmm
// 运行时读回断言 (与 wvmp_sse_bridge_sample 同能力面配对、独立 exe, 沿用
// MIT-389/408/411/425 影子样本模式)。
//
// 背景 (pitfall #79 纪律): 主样本 stdout 只断言桥语义值。本影子把 8 槽 ×
// 2×u64 全量打印: dst 槽 = 期望位图案, 其余 7 槽必须 = 入口预载值 (误写
// 无关槽即 FAIL); movd/movq 装入后高位清零 (高 96 / 高 64) 与 GpFromXmm
// w4 零扩展 (movd r32 写 32 位寄存器本机零扩展) 的位级语义同场可断。
//
// 全部输出 %016llx 逐位可比对。native run vs virtualized run 逐字节比对;
// handler 空转/槽位错/宽度错/清零缺失 → 与原生不一致 → FAIL。

#include <cstdio>
#include <cstdint>

extern "C" void bsh_movd_in(const unsigned long long* in, unsigned long long* out);
extern "C" void bsh_movq_in(const unsigned long long* in, unsigned long long* out);
extern "C" void bsh_movd_out(const unsigned long long* in, unsigned long long* out);
extern "C" void bsh_movq_out(const unsigned long long* in, unsigned long long* out);
extern "C" void bsh_movq_xmm_zero(const unsigned long long* in, unsigned long long* out);
extern "C" void bsh_movq_xmm_d6(const unsigned long long* in, unsigned long long* out);
extern "C" void bsh_movd_mem_in(const unsigned long long* in, unsigned long long* out);
extern "C" void bsh_movq_mem_in(const unsigned long long* in, unsigned long long* out);
extern "C" void bsh_movq_mem_out(const unsigned long long* in, unsigned long long* out);

// C 链接全局: MASM helper (sse_bridge_xmm_readback_sample_asm.asm)
// EXTERNDEF 直引符号 — rip mem 源 / store 目标。
extern "C" unsigned int g_bsh32 = 0xDEADBEEFu;
extern "C" unsigned long long g_bsh64 = 0x0F0F0F0F12345678ull;
extern "C" unsigned long long g_bshout64 = 0;

// 预载位图案 (8 槽 × 2×u64): 互不相同且非零 — 判别 "误写无关槽" 与
// "槽位公式错写 GPR 区"。全 8 槽预载 (load_all)。
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

// out: 16 × xmm 槽 u64 + 1 × rax 读回 (GP 方向探针)
using ProbeFn = void (*)(const unsigned long long*, unsigned long long*);

static void run_probe(const char* name, ProbeFn fn) {
    unsigned long long out[17];
    for (int i = 0; i < 17; ++i) out[i] = 0xCCCCCCCCCCCCCCCCull;  // 哨兵
    fn(g_in, out);
    std::printf("[%s]\n", name);
    for (int s = 0; s < 8; ++s) {
        std::printf("  xmm%d=%016llX,%016llX\n", s, out[s * 2], out[s * 2 + 1]);
    }
    std::printf("  rax=%016llX\n", out[16]);
}

int main() {
    // ① movd 装入: xmm0 = {00000000_00000000, ..., 00000000A5A5A5A5} —
    //    高 96 清零位级证据 (位图案预载被覆盖为 0), xmm1..7 保持预载。
    run_probe("movd_in", bsh_movd_in);
    // ② movq 装入: xmm0 = {1122334455667788, 0} — 高 64 清零。
    run_probe("movq_in", bsh_movq_in);
    // ③ movd 提取: rax = 0000000011111111 (native movd r32 零扩展),
    //    xmm 槽全保持。
    run_probe("movd_out", bsh_movd_out);
    // ④ movq 提取: rax = 1111111111111111。
    run_probe("movq_out", bsh_movq_out);
    // ⑤ F3 0F 7E (清零形态): xmm0 = {3333333333333333, 0}。
    run_probe("movq_xmm_zero", bsh_movq_xmm_zero);
    // ⑥ 66 0F D6 reg-reg: xmm0 = {3333333333333333, 0} — #33 实测同 F3
    //    清零 (高 64 保持先验被 d6_probe 推翻, 预载高位 2222... 必为 0)。
    run_probe("movq_xmm_d6", bsh_movq_xmm_d6);
    // ⑦ movd mem 装入: xmm0 = {00000000DEADBEEF, 0}。
    run_probe("movd_mem_in", bsh_movd_mem_in);
    // ⑧ movq mem 装入: xmm0 = {0F0F0F0F12345678, 0}。
    run_probe("movq_mem_in", bsh_movq_mem_in);
    // ⑨ movq mem store: g_bshout64 = 1111111111111111 (截取落盘, 探针后读回)。
    run_probe("movq_mem_out", bsh_movq_mem_out);
    std::printf("g_bshout64=%016llX\n", g_bshout64);
    return 0;
}
