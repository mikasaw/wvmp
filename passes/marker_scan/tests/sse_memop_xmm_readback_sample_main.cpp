// MIT-411 (G1): SSE 尾扫包影子样本 — comiss/comisd 折叠 + pd 位运算族折叠
// + 双访存形态的 ctx.xmm / VM-flags 运行时读回断言 (与 wvmp_sse_memop_sample
// 同 IR 配对、独立 exe, 沿用 MIT-389/408 影子样本模式)。
//
// 背景 (pitfall #79 纪律): 主样本 stdout 只断言最终值; 本单新形态的坑位:
//   - comiss/comisd 折叠复用 Ucomiss/Ucomisd handler — 正确性在 **VM flags
//     槽** (比较指令不改 xmm 操作数)。handler 若空转 (decode+advance 不写
//     flags), 紧随的 seta 读到 dispatch 残留 flags, 主样本可能碰巧 PASS。
//     本影子把 comiss/comisd 后的 seta 结果 (Setcc handler 读 Ucomiss
//     handler 写的 flags 槽) 显式打印 (out[16]).
//   - andpd/orpd/xorpd 折叠复用 ps handler — 正确性在 **ctx.xmm 槽位落点**
//     (写错 GPR 槽区 v18..23 / 宽度截断即暴露)。8 槽 × 2×u64 全量打印:
//     dst 槽 = 期望位图案, 其余 7 槽必须 = 入口预载值 (误写无关槽即 FAIL)。
//   - addsd 栈基址 mem 源 + 双访存读改写 triple — XmmLoad/XmmStore/ALU
//     通路, 同样 8 槽全量读回。
//
// 全部输出 %016llx 逐位可比对 (位图案不经浮点打印, 无舍入歧义)。
// native run vs virtualized run 逐字节比对; handler 空转/槽位错/宽度错 →
// 与原生不一致 → FAIL。

#include <cstdio>
#include <cstring>

extern "C" void mop_comiss_gt(float a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void mop_comisd_gt(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void mop_andpd_reg(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void mop_orpd_mem(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void mop_xorpd_reg(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void mop_addsd_stack(double a, double b, const unsigned long long* in, unsigned long long* out);
extern "C" void mop_triple(double a, double b, const unsigned long long* in, unsigned long long* out);

// 预载位图案 (xmm2..xmm7 共 6 槽 × 2×u64): 互不相同且非零 — 判别"误写
// 无关槽"。16 个 u64 覆盖 8 槽 (xmm0..1 的参数位图案由调用方直接传入,
// 此处对应项不用)。
static const unsigned long long g_in[16] = {
    0x1111111111111111ull, 0x2222222222222222ull,  // xmm0 位 (参数覆盖)
    0x3333333333333333ull, 0x4444444444444444ull,  // xmm1 位 (参数覆盖)
    0x5555555555555555ull, 0x6666666666666666ull,  // xmm2
    0x7777777777777777ull, 0x8888888888888888ull,  // xmm3
    0x9999999999999999ull, 0xAAAAAAAAAAAAAAAAull,  // xmm4
    0xBBBBBBBBBBBBBBBBull, 0xCCCCCCCCCCCCCCCCull,  // xmm5
    0xDDDDDDDDDDDDDDDDull, 0xEEEEEEEEEEEEEEEEull,  // xmm6
    0x0F0F0F0F0F0F0F0Full, 0x1E1E1E1E1E1E1E1Eull,  // xmm7
};

// 模板化 fn 类型: comiss 探针参数是 float (comiss 只比较 xmm0[31:0]),
// 其余探针是 double — 调用点按各探针真实签名做隐式转换, 保证 xmm0 位
// 图案正确。
template <typename Fn>
static void run_probe(const char* name, Fn fn, double a, double b) {
    unsigned long long out[17];
    for (int i = 0; i < 17; ++i) out[i] = 0xCCCCCCCCCCCCCCCCull;  // 哨兵
    fn(a, b, g_in, out);
    std::printf("[%s]\n", name);
    for (int s = 0; s < 8; ++s) {
        std::printf("  xmm%d=%016llX,%016llX\n", s, out[s * 2], out[s * 2 + 1]);
    }
    std::printf("  flags_gt=%d\n", static_cast<int>(out[16]));
}

// 位图案 → double 位传送 (探针参数走 xmm0, 位图案原样进 VM 槽)。
static double bits_to_double(unsigned long long hi, unsigned long long lo) {
    unsigned long long v[2] = {lo, hi};
    double d = 0.0;
    memcpy(&d, &v[0], sizeof(d));  // 低 64 位进 xmm0 (探针只消费低 64)
    return d;
}

int main() {
    // 1) comiss mem 源 + seta: a=5.0f > g_sh_f=3.5f → 1 (flags 真读回;
    //    comiss 比较 xmm0[31:0] → 参数必须 float, double 高位会被截断)
    run_probe("comiss_gt", mop_comiss_gt, 5.0f, 0.0);
    // 2) comisd mem 源 + seta: a=4.0 > g_sh_d=2.5 → 1
    run_probe("comisd_gt", mop_comisd_gt, 4.0, 0.0);
    // 3) andpd reg: a&b = 0xFF00FF00FF00FF00 & 0xFFFF0000FFFF0000
    //    = 0xFF000000FF000000 (xmm0 槽 = 期望; 其余槽 = 预载不动)
    run_probe("andpd_reg", mop_andpd_reg,
              bits_to_double(0xFFFFFFFFFFFFFFFFull, 0xFF00FF00FF00FF00ull),
              bits_to_double(0xFFFFFFFFFFFFFFFFull, 0xFFFF0000FFFF0000ull));
    // 4) orpd mem 源: a | g_sh_pd = 0x0F0F.. | {1.5, 2.5} 位图案
    run_probe("orpd_mem", mop_orpd_mem,
              bits_to_double(0xFFFFFFFFFFFFFFFFull, 0x0F0F0F0F0F0F0F0Full), 0.0);
    // 5) xorpd reg: 0x0F0F.. ^ 0x33CC.. = 0x3CC33CC33CC33CC3
    run_probe("xorpd_reg", mop_xorpd_reg,
              bits_to_double(0xFFFFFFFFFFFFFFFFull, 0x0F0F0F0F0F0F0F0Full),
              bits_to_double(0xFFFFFFFFFFFFFFFFull, 0x33CC33CC33CC33CCull));
    // 6) addsd 栈基址 mem 源: a + [rsp+40] = a + a (栈槽存 a) = 2*a
    run_probe("addsd_stack", mop_addsd_stack, 100.0, 0.0);
    // 7) 双访存 triple: g_sh_g = g_sh_g + a (2.25 + 0.5 = 2.75; xmm1 槽 = 新值)
    run_probe("triple", mop_triple, 0.5, 0.0);
    return 0;
}
