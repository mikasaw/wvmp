// MIT-426 (G6a): VEX.128 档A 影子样本 — 三态折叠 + D4 拷贝 + mem 通路的
// ctx.xmm 运行时读回断言 (与 wvmp_vex128_sample 同能力面配对、独立 exe,
// 沿用 MIT-389/408/411/425 影子样本模式)。
//
// 背景 (pitfall #79 纪律): 主样本 stdout 只断言低 64 位终值。三态③ 的
// 前置 Op::Movaps 若槽位写错 (误写无关槽 / GPR 槽区 — MIT-371 空转形态)
// 或标量高位语义错 (dst 高位应 ← s1 高位), 主样本可能碰巧 PASS — 本影子
// 把 8 槽 × 2×u64 全量打印: dst 槽 = 期望位图案, 其余 7 槽必须 = 入口
// 预载值 (误写无关槽即 FAIL); 标量 vmulss 的 "dst 高位 ← s1 高位" 同场
// 可断 (pre-Mov 16B 拷贝正确性的位级证据)。
//
// 全部输出 %016llx 逐位可比对。native run vs virtualized run 逐字节比对;
// handler 空转/槽位错/宽度错 → 与原生不一致 → FAIL。

#include <cstdio>

extern "C" void vex_sh_addss(const unsigned long long* in, unsigned long long* out);
extern "C" void vex_sh_addps_swap(const unsigned long long* in, unsigned long long* out);
extern "C" void vex_sh_addps_dindep(const unsigned long long* in, unsigned long long* out);
extern "C" void vex_sh_vmulss_dindep(const unsigned long long* in, unsigned long long* out);
extern "C" void vex_sh_subps_dindep(const unsigned long long* in, unsigned long long* out);
extern "C" void vex_sh_andnps_dindep(const unsigned long long* in, unsigned long long* out);
extern "C" void vex_sh_movaps(const unsigned long long* in, unsigned long long* out);
extern "C" void vex_sh_vpxor(const unsigned long long* in, unsigned long long* out);
extern "C" void vex_sh_vmovups_load(const unsigned long long* in, unsigned long long* out);

// C 链接全局: MASM helper (vex128_xmm_readback_sample_asm.asm) EXTERNDEF
// 直引符号 — rip mem 源位图案。⚠️ packed mem 源原生要求 16B 对齐 (#GP),
// align(16) 必带 (411 影子先例纪律)。
extern "C" __declspec(align(16)) unsigned long long g_sh_vex_ps[2] = {
    0x0F0F0F0F0F0F0F0Full, 0xF0F0F0F0F0F0F0F0ull};

// 预载位图案 (8 槽 × 2×u64): 互不相同且非零 — 判别 "误写无关槽" 与
// "槽位公式错写 GPR 区"。全 8 槽预载 (load_all), 无浮点参数。
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
static void run_probe(const char* name, Fn fn) {
    unsigned long long out[17];
    for (int i = 0; i < 17; ++i) out[i] = 0xCCCCCCCCCCCCCCCCull;  // 哨兵
    fn(g_in, out);
    std::printf("[%s]\n", name);
    for (int s = 0; s < 8; ++s) {
        std::printf("  xmm%d=%016llX,%016llX\n", s, out[s * 2], out[s * 2 + 1]);
    }
}

int main() {
    // ① vaddss d==s1 直走: 只改低 32 位, 高 96 位 = dst 残留 (槽 0)
    run_probe("addss_d_s1", vex_sh_addss);
    // ② vaddps d==s2 交换 (packed 全 128-bit): slot2 = slot3+slot2 逐 lane
    run_probe("addps_d_s2_swap", vex_sh_addps_swap);
    // ③ vaddps d 独立: pre-Mov(slot2←slot0) + slot2+slot1 (其余槽不动)
    run_probe("addps_dindep", vex_sh_addps_dindep);
    // ④ vmulss d 独立 (标量高位语义): slot2 高 96 = slot0 高 96, 低 32 乘积
    run_probe("mulss_dindep", vex_sh_vmulss_dindep);
    // ⑤ vsubps d 独立 (非交换)
    run_probe("subps_dindep", vex_sh_subps_dindep);
    // ⑥ vandnps d 独立: ~slot0 & slot1 全 128 位
    run_probe("andnps_dindep", vex_sh_andnps_dindep);
    // ⑦ vmovaps 纯拷贝: slot3 = slot0 全 16B (D4 直折)
    run_probe("movaps_copy", vex_sh_movaps);
    // ⑧ vpxor 清零: slot2 = 0
    run_probe("vpxor_zero", vex_sh_vpxor);
    // ⑨ vmovups mem load: slot2 = [g_sh_vex_ps]
    run_probe("vmovups_load", vex_sh_vmovups_load);
    return 0;
}
