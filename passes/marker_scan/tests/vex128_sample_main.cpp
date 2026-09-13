// MIT-426 (G6a): VEX.128 档A 端到端主样本 — 38 id V-pair 三地址折叠。
// 保护 → 运行 → stdout+退出码逐字节比对 (native vs virtualized)。
//
// 能力面 (派活单 §B.5, 字节形态见 vex128_sample_asm.asm 头 + 报告对照表):
//   三态折叠: ① d==s1 直走 (vaddss) / ② d==s2 可交换 packed (vmulps —
//             标量 d==s2 高位语义不相容 → gate, 负例 ⑳) /
//             ③ d 独立 Mov 前置 (vaddps/vsubps/vmulss/vandnps — 语义值
//             手算 + 目标寄存器终值断言, 影子样本 #79 ctx.xmm 读回配对);
//   D4 vmovaps 2-op 纯拷贝直折单条; 408 mem 通路 (vmovups load /
//   vaddsd mem 源); vpxor 清零惯用法 (425 整数位运算镜像); vucomiss+seta
//   flags 通路; D5 C4 全前缀 db 直写 (vaddsd)。
//   负例区 (各族全 gate, 可调用, 原生执行行为 byte-exact): ymm 同
//   mnemonic (B.4 位宽闸) / FMA (双舍入) / rorx (VEX-GP) / vpaddd
//   (G1c 镜像) / vsubsd 非交换 d==s2 (D2 裁决) / vmulsd 标量 d==s2
//   (高位语义不相容) / vmovsd 插入 d≠s1 (§F.4 假 Mov)。
//   MIT-511 (档B wave1): 原 vzeroupper 负例 (档B ABI) 翻正例 —— 词入面
//   真虚拟化, 行为语义不变 (SSE-only 观察者透明), stub 计数 +1。
//
// 区域只含白名单 (VEX V-pair + mov/lea/setcc/movzx/nop), printf 在 main
// 区域外。REQUIRE_REAL: 正例区域真虚拟化 (stub ≥1), 负例函数 gate 由
// protect 日志 Note 验证 (报告附 grep 输出)。

#include <cstdio>

// C 链接全局: MASM helper 直引符号 (rip-relative 由链接器解析)。
// ⚠️ packed mem 源原生要求 16B 对齐 (#GP 语义) — align(16) 必带; VM 侧
// 经 XmmLoad 一律 movups 非对齐语义不受影响 (408 D2)。
extern "C" double g_vex_d = 2.5;
extern "C" __declspec(align(16)) float g_vex_ps[4] = {2.0f, 3.0f, 4.0f, 5.0f};

// MASM helper (vex128_sample_asm.asm): 各 helper 区域内 = 本单新形态真字节。
extern "C" unsigned int      vex_addss_d_s1(unsigned int a, unsigned int b);      // ① 3.75f
extern "C" unsigned long long vex_vmulps_d_s2(unsigned long long s1, unsigned long long d); // ② packed swap
extern "C" unsigned long long vex_addps_dindep(unsigned long long s1, unsigned long long s2); // ③
extern "C" unsigned long long vex_subps_dindep(unsigned long long s1, unsigned long long s2); // ④
extern "C" unsigned long long vex_vmulss_dindep(unsigned long long s1, unsigned long long s2); // ⑤
extern "C" unsigned long long vex_vandnps_dindep(unsigned long long s1, unsigned long long s2); // ⑥
extern "C" unsigned long long vex_vmovaps_copy(unsigned long long a, unsigned long long b); // ⑦
extern "C" unsigned long long vex_vmovups_load();                                 // ⑧
extern "C" unsigned long long vex_vaddsd_mem(unsigned long long a);               // ⑨ 4.0
extern "C" unsigned long long vex_vpxor_zero(unsigned long long x);               // ⑩ 0
extern "C" unsigned int      vex_vucomiss_seta(unsigned int a, unsigned int b);   // ⑪ 1
extern "C" unsigned long long vex_c4_enc_addsd(unsigned long long a, unsigned long long b); // ⑫ 15.0
extern "C" unsigned long long vex_ymm_neg(unsigned long long a, unsigned long long b);   // ⑬ gate
extern "C" unsigned long long vex_fma_neg(unsigned long long a, unsigned long long b, unsigned long long c); // ⑭ gate
extern "C" unsigned int      vex_rorx_neg(unsigned int x);                        // ⑮ gate
extern "C" unsigned int      vex_vzeroupper_pos();                                // ⑯ MIT-511 入面
extern "C" unsigned long long vex_vpaddd_neg(unsigned long long a, unsigned long long b); // ⑰ gate
extern "C" unsigned long long vex_noncomm_ds2_neg(unsigned long long s1, unsigned long long d); // ⑱ gate
extern "C" unsigned long long vex_movsd_insert_neg(unsigned long long s1, unsigned long long s2); // ⑲ gate
extern "C" unsigned long long vex_mulsd_ds2_neg(unsigned long long s1, unsigned long long d); // ⑳ gate

int main() {
    // 正例区 (语义值手算, 派活单 §D.2 "mul/add 语义值手算"):
    const unsigned int addss = vex_addss_d_s1(0x3FC00000u, 0x40100000u);      // 1.5f+2.25f=3.75f
    // ② mulps d==s2 交换 (packed): [2,2]×[3,1.5]=[6,3]
    const unsigned long long mulps = vex_vmulps_d_s2(0x4000000040000000ull,
                                                     0x4040004040000040ull);
    // ③ addps d 独立: [2.0f,2.0f]+[3.0f,1.5f]=[5.0f,3.5f] (dst=xmm2 终值断言)
    const unsigned long long addps = vex_addps_dindep(0x4000000040000000ull,
                                                      0x4040004040000040ull);
    // ④ subps d 独立 (非交换): [3.0f,1.5f]-[2.0f,2.0f]=[1.0f,-0.5f]
    const unsigned long long subps = vex_subps_dindep(0x4000000040000000ull,
                                                      0x4040004040000040ull);
    // ⑤ vmulss d 独立: 2.0f×3.0f=6.0f (高位语义=影子样本钉死面)
    const unsigned long long mulss = vex_vmulss_dindep(0x4000000040000000ull,
                                                       0x4040000040000000ull);
    // ⑥ vandnps d 独立: ~0x0F0F... & 0xFFFF... = 0xF0F0...
    const unsigned long long andn = vex_vandnps_dindep(0x0F0F0F0F0F0F0F0Full,
                                                       0xFFFFFFFFFFFFFFFFull);
    // ⑦⑧⑨ D4 拷贝 + 408 mem 通路
    const unsigned long long movaps = vex_vmovaps_copy(0xAAAAAAAAAAAAAAAAull,
                                                       0xBEEFFACE12345678ull);
    const unsigned long long movups = vex_vmovups_load();                    // = {2,3} lanes
    const unsigned long long addsdm = vex_vaddsd_mem(0x3FF8000000000000ull); // 1.5+2.5=4.0
    // ⑩⑪⑫ 清零惯用法 + flags 通路 + C4 全前缀
    const unsigned long long pxor = vex_vpxor_zero(0x1234567812345678ull);   // = 0
    const unsigned int seta = vex_vucomiss_seta(0x40400000u, 0x40000000u);   // 3.0f>2.0f → 1
    const unsigned long long c4sd = vex_c4_enc_addsd(0x4018000000000000ull,  // 6.0+2.5=15.0
                                                     0x4004000000000000ull);
    // 负例区 (gate → 原生执行, 行为 byte-exact; gate 证据 = protect 日志)
    const unsigned long long ymm = vex_ymm_neg(0x4000000040000000ull,        // [2,2]+[3,3]=[5,5]
                                               0x4040000040400000ull);
    const unsigned long long fma = vex_fma_neg(0x4018000000000000ull,        // 1.0*2.5+6.0=8.5
                                               0x4004000000000000ull,
                                               0x3FF0000000000000ull);
    const unsigned int rorx = vex_rorx_neg(0x80000001u);                     // ror3 = 0x30000000
    const unsigned int vzero = vex_vzeroupper_pos();                         // = 7 (MIT-511 入面)
    const unsigned long long paddr = vex_vpaddd_neg(0x0000000100000001ull,   // +0x2 → 0x3
                                                    0x0000000200000002ull);
    const unsigned long long ds2 = vex_noncomm_ds2_neg(0x4018000000000000ull, // 6.0-2.0=4.0
                                                       0x4000000000000000ull);
    const unsigned long long mins = vex_movsd_insert_neg(0x4018000000000000ull, // 低64←s2=2.5
                                                         0x4004000000000000ull);
    const unsigned long long mulds2 = vex_mulsd_ds2_neg(0x4018000000000000ull, // 6.0×2.5=15.0
                                                        0x4004000000000000ull);

    std::printf("addss=%08X mulps=%016llX\n", addss, mulps);
    std::printf("addps=%016llX subps=%016llX mulss=%016llX\n", addps, subps, mulss);
    std::printf("andn=%016llX movaps=%016llX\n", andn, movaps);
    std::printf("movups=%016llX addsd_mem=%016llX\n", movups, addsdm);
    std::printf("pxor=%016llX seta=%u c4addsd=%016llX\n", pxor, seta, c4sd);
    std::printf("ymm=%016llX fma=%016llX rorx=%08X vzero=%u\n", ymm, fma, rorx, vzero);
    std::printf("vpaddd=%016llX subds2=%016llX movsdins=%016llX\n", paddr, ds2, mins);
    std::printf("mulds2neg=%016llX\n", mulds2);
    return 0;
}
