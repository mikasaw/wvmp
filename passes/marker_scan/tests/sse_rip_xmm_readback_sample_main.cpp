// MIT-408 (C4b): SSE mem 形式影子样本 — XmmLoad/XmmStore/ALU-mem 折条的
// ctx.xmm 运行时读回断言 (与 wvmp_sse_rip_sample 同能力面配对, 沿用
// MIT-389 sse_subss_xmm_readback 模式)。
//
// 背景 (pitfall #79 纪律): 主样本 stdout 只断言最终结果; handler 写错槽位
// (写回 GPR 槽区而非 ctx.xmm 槽) 或宽度截断 (movss 4B 替 movups 16B) 时
// 若结果碰巧一致即漏网。本影子样本把四条 mem 原语路径的槽位状态/宽度语义
// 变成显式输出 (全部 %a / %016llx 逐位可比对):
//   - xr_memld:  movups 16B 读 → 4 lane 全打 (XmmLoad xmm 槽落点 + 宽度);
//   - xr_memalu: addps mem 源 → 4 lane 全打 (XmmLoad GP 双槽临时 + Addps
//     双槽读回链路);
//   - xr_memst:  movups 16B 写全局 → 读回全打 (XmmStore 槽读 + 宽度);
//   - xr_sd_ld:  movsd 8B 读 → 低 64 = 源 + 高 64 必须 = 0 (movsd 内存源
//     清零语义, SDM);
//   - xr_sd_st:  movsd 8B 写全局 → 读回 (XmmStore 8B 截断)。
//
// %a (hex float) / %016llx (hex u64) 输出保证逐位可比对 (无十进制舍入歧义,
// -0.0/NaN 也可辨)。native run vs virtualized run 逐字节比对。

#include <cstdio>
#include <cstring>

extern "C" void xr_memld(float* out);
extern "C" void xr_memalu(float a0, float a1, float a2, float a3, float* out);
extern "C" void xr_memst(float a0, float a1, float a2, float a3);
extern "C" void xr_sd_ld(unsigned long long* out128);
extern "C" void xr_sd_st(double a);

extern "C" {
extern float g16_src[4];
extern float g16_dst[4];
extern double g_sd_in;
extern double g_sd_out;
}

int main() {
    // 1) movups 16B 读 → XmmLoad 落点 + 全宽 (lane1-3 必须 = 源, 非入口旧值)
    alignas(16) float ld_out[4] = {-1.0f, -1.0f, -1.0f, -1.0f};
    xr_memld(ld_out);
    for (int l = 0; l < 4; ++l) {
        std::printf("[memld_lane%d]=%a\n", l, static_cast<double>(ld_out[l]));
    }

    // 2) addps mem 源 (GP 双槽临时链路): {5,6,7,8} + {1.5,2.5,3.5,4.5}
    //    = {6.5,8.5,10.5,12.5}
    alignas(16) float alu_out[4] = {-1.0f, -1.0f, -1.0f, -1.0f};
    xr_memalu(5.0f, 6.0f, 7.0f, 8.0f, alu_out);
    for (int l = 0; l < 4; ++l) {
        std::printf("[memalu_lane%d]=%a\n", l, static_cast<double>(alu_out[l]));
    }

    // 3) movups 16B 写全局 → 读回 (XmmStore)
    xr_memst(5.0f, 6.0f, 7.0f, 8.0f);
    for (int l = 0; l < 4; ++l) {
        std::printf("[memst_lane%d]=%a\n", l, static_cast<double>(g16_dst[l]));
    }

    // 4) movsd 8B 读: 低 64 = 2.25, 高 64 必须 = 0 (清零语义)
    unsigned long long sd128[2] = {0xDEADBEEFDEADBEEFull, 0xDEADBEEFDEADBEEFull};
    xr_sd_ld(sd128);
    double sd_lo = 0.0;
    memcpy(&sd_lo, &sd128[0], sizeof(sd_lo));
    std::printf("[sdld_lo]=%a [sdld_hi]=%016llx\n", sd_lo, sd128[1]);

    // 5) movsd 8B 写全局 → 读回
    xr_sd_st(7.75);
    std::printf("[sdst]=%a\n", g_sd_out);

    // 顺带打印源全局, 证明源数据两侧一致
    std::printf("[src]=%a,%a,%a,%a sd_in=%a\n",
                static_cast<double>(g16_src[0]), static_cast<double>(g16_src[1]),
                static_cast<double>(g16_src[2]), static_cast<double>(g16_src[3]),
                g_sd_in);
    return 0;
}
