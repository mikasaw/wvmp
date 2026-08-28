// MIT-374: SSE 浮点除 divss 的 ctx.xmm 运行时读回断言影子样本
// (WVmpVerifier 验收门 A.2 模式, 沿用 MIT-389 的 sse_subss 影子样本;
//  与 wvmp_sse_div_sample 的 sse_divss 同 IR 配对)。
//
// 背景 (MIT-371 空转缺陷): 主样本 stdout 只断言最终结果, handler 写错槽位
// (写回 GPR 槽区而非 ctx.xmm 槽) 时若结果碰巧等于输入即漏网。本影子样本把
// "handler 是否真的更新了 ctx.xmm[reg]" 变成显式输出:
//
//   虚拟化路径下, 区域代码在 VM 内执行, xmm 状态全部活在 VmContext.xmm[0..7]
//   (@ +0x140, stub 入口同步 / HALT 恢复, 见 stub_gen.cpp)。ctx 槽位对样本
//   的唯一可见出口 = HALT 后 stub 的恢复路径:
//     - 虚拟化函数的返回值 (xmm0 = ctx.xmm[0] 于 HALT 时);
//     - 区域后对寄存器的原生 store (值为 HALT 恢复后的槽位状态)。
//   本样本把这两个出口全部打印, native run vs virtualized run 逐字节比对;
//   handler 空转 (写错槽) → 读回值 = 入口旧值 → 与原生不一致 → FAIL。
//
//   1) s01: divss xmm0,xmm1 (与主样本同 IR) → 返回值 = ctx.xmm[0] 读回;
//   2) s23: divss xmm2,xmm3 (不同槽位探针, reg=26/27) → 返回值 + dst/src
//      槽位状态 (src 槽必须等于输入 b, handler 不得越槽写);
//   3) keep: divss xmm0,xmm1 后 xmm0..xmm3 全量 128-bit 快照 → 4 槽 × 4 lane
//      全部打印, 未触碰槽位必须保持入口同步值。
//
// %a (hex float) 输出保证逐位可比对 (无十进制舍入歧义, -0.0/NaN 也可辨)。
// 输入取二进制精确值且除数非 0 (0x1.0p+2 类), 商亦二进制精确, 便于人工核对。

#include <cstdio>

extern "C" float xr_divss_s01(float a, float b);
extern "C" float xr_divss_s23(float a, float b, float* out_dst, float* out_src);
extern "C" float xr_divss_keep(float a, float b, void* slots);

int main() {
    // 1) 同 IR 读回: divss xmm0,xmm1 → 5.5f / 2.0f = 2.75f
    const float s01 = xr_divss_s01(5.5f, 2.0f);
    std::printf("[ctx_xmm0_s01]=%a\n", static_cast<double>(s01));

    // 2) 不同槽位探针: divss xmm2,xmm3 → 7.0f / 3.5f = 2.0f
    //    out_dst/out_src 必须是 16 字节缓冲 (asm 对两指针各做一次 128-bit
    //    movups store, 写 4 float): dst = ctx.xmm[2] 全槽位状态 (lane0 = 结果,
    //    lane1-3 = 未触碰高位), src = ctx.xmm[3] 全槽位状态 (必须 = 输入 b,
    //    handler 未越槽写)。
    alignas(16) float dst4[4] = {-1.0f, -1.0f, -1.0f, -1.0f};
    alignas(16) float src4[4] = {-1.0f, -1.0f, -1.0f, -1.0f};
    const float s23 = xr_divss_s23(7.0f, 3.5f, dst4, src4);
    std::printf("[ctx_xmm2_ret]=%a\n", static_cast<double>(s23));
    for (int l = 0; l < 4; ++l) {
        std::printf("[ctx_xmm2_dst_lane%d]=%a\n", l, static_cast<double>(dst4[l]));
    }
    for (int l = 0; l < 4; ++l) {
        std::printf("[ctx_xmm3_src_lane%d]=%a\n", l, static_cast<double>(src4[l]));
    }

    // 3) 槽位保持快照: divss xmm0,xmm1 → 9.0f / 4.0f = 2.25f;
    //    xmm1..xmm3 = 未触碰槽位 (VM 入口同步值), 4 槽 × 4 lane 全打。
    alignas(16) unsigned char slots[64] = {};
    const float sk = xr_divss_keep(9.0f, 4.0f, slots);
    const float* lane = reinterpret_cast<const float*>(slots);
    std::printf("[ctx_xmm0_keep_ret]=%a\n", static_cast<double>(sk));
    for (int r = 0; r < 4; ++r) {
        for (int l = 0; l < 4; ++l) {
            std::printf("[ctx_xmm%d_keep_lane%d]=%a\n", r, l,
                        static_cast<double>(lane[r * 4 + l]));
        }
    }
    return 0;
}
