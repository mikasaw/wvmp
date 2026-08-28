// MIT-376 影子样本 (flags readback 断言, 派活单 §D D2.1 决策) —— ucomiss+seta
// 组合的 VM flags 运行时读回, 与主样本 wvmp_sse_bwcmp_sample 的 ucomiss+seta
// 同 IR、独立 exe。
//
// 为什么需要影子样本 (MIT-371 空转教训): ucomiss/ucomisd 的正确性不在 xmm 槽
// (比较指令**不改 xmm 操作数**), 而在 VM flags 槽 (ctx+0x98)。handler 若空转
// (decode+advance 不写 flags, pitfall #79), seta 读到的是 dispatch 循环残留
// flags, 结果随机 — 本样本把两条断言做成显式输出:
//   1. flags readback: 每个探针打印区域内 ucomiss + seta 的结果字节 — 它由
//      VmOp::Setcc handler 读 VmOp::Ucomiss handler 写的 VM flags 槽产生,
//      greater/less/equal/unordered 四态覆盖 Intel SDM UCOMISS 真值表 ZF/CF
//      全组合; handler 空转/真值表错 → 与原生不一致 → byte-exact FAIL。
//   2. ctx.xmm 全量读回: 每个探针打印 8 槽 × 4 lane 的 32-bit 位图案 —
//      证明 Ucomiss handler 没有污染任何 xmm 槽 (比较指令不该写 xmm; dst 槽
//      预置 = a/b 本身, 其余槽 = 互不相同非零图案; 任何误写/越槽写都会使
//      某槽 ≠ 入口值, 与原生不一致 FAIL)。
//
// 虚拟化路径下区域代理解执行, xmm 状态全活在 VmContext.xmm[8] (@ +0x140,
// stub 入口把物理 xmm0..7 同步进 ctx / HALT 出口恢复, 见 stub_gen.cpp);
// ctx 槽对样本唯一的可见出口 = 区域后的原生 store (值 = HALT 恢复后的物理
// xmm, 即 ctx 读回状态)。

#include <cstdio>
#include <cstring>
#include <limits>

extern "C" int ufr_gt(float a, float b, const unsigned int* in_slots,
                      unsigned int* out_slots);
extern "C" int ufr_lt(float a, float b, const unsigned int* in_slots,
                      unsigned int* out_slots);
extern "C" int ufr_eq(float a, float b, const unsigned int* in_slots,
                      unsigned int* out_slots);
extern "C" int ufr_nan(float a, float b, const unsigned int* in_slots,
                       unsigned int* out_slots);

namespace {

// 每槽每 lane 一个唯一非零图案 (与 sse_movss_xmm_readback_sample 同源, 只用于
// xmm2..xmm7 预置 — xmm0/xmm1 由浮点参数 a/b 占用, ucomis* 不该改动任何槽)。
unsigned int pattern(int slot, int lane) {
    return 0x31000000u + static_cast<unsigned int>(slot + 1) * 0x00010100u +
           static_cast<unsigned int>(lane + 1) * 0x00000001u;
}

// 跑一个探针: 重置 out (填 0xEE 哨兵, 使"helper 根本没写 out 区"也可分辨),
// 调 MASM helper, 打印 seta 结果 + 8 槽 × 4 lane 原始位图案。
void run_probe(const char* tag, int (*probe)(float, float, const unsigned int*,
                                             unsigned int*),
               float a, float b, const unsigned int* in8) {
    unsigned int out8[36];
    std::memset(out8, 0xEE, sizeof(out8));
    const int seta = probe(a, b, in8, out8);
    std::printf("[%s] seta=%d\n", tag, seta);
    for (int s = 0; s < 8; ++s) {
        std::printf("[%s s%d]=%08X %08X %08X %08X\n", tag, s, out8[s * 4 + 0],
                    out8[s * 4 + 1], out8[s * 4 + 2], out8[s * 4 + 3]);
    }
}

} // namespace

int main() {
    unsigned int in8[32];
    for (int s = 0; s < 8; ++s) {
        for (int l = 0; l < 4; ++l) in8[s * 4 + l] = pattern(s, l);
    }

    // 四态探针 (Intel SDM UCOMISS 真值表 ZF/CF 全组合):
    //   gt  (2.5, 1.5)  → ZF=0 CF=0 → seta=1
    //   lt  (0.5, 1.5)  → ZF=0 CF=1 → seta=0
    //   eq  (1.5, 1.5)  → ZF=1 CF=0 → seta=0
    //   nan (qNaN, 1.0) → unordered, ZF=1 CF=1 PF=1 → seta=0 (D1.1 决策)
    const float qnan = std::numeric_limits<float>::quiet_NaN();
    run_probe("ucmpss_gt", ufr_gt, 2.5f, 1.5f, in8);
    run_probe("ucmpss_lt", ufr_lt, 0.5f, 1.5f, in8);
    run_probe("ucmpss_eq", ufr_eq, 1.5f, 1.5f, in8);
    run_probe("ucmpss_nan", ufr_nan, qnan, 1.0f, in8);
    return 0;
}
