// MIT-375 端到端主样本——区域内含 SSE 浮点传送 movss/movaps/movapd/movups/movupd
// (5 形式 REG-REG load 方向), 验证浮点传送支持后翻译成功、运行时走真 Movss/
// Movaps/Movapd/Movups/Movupd handler、行为与原生逐字节一致 (保护 → 运行 →
// stdout+退出码比对)。
//
// 设计要点:
//   - MSVC x64 不支持 inline asm, /Od 下 _mm_move_ss/_mm_load_ps/_mm_load_pd
//     会**融合 load+mov 为 MEM 形式** (movss xmm,[mem]), 与派活单限定 REG-REG
//     冲突 → 真 SSE 字节由 sse_mov_sample_asm.asm (MASM) 直接 emit
//     (F3 0F 10 / 0F 28 / 66 0F 28 / 0F 10 / 66 0F 10, mod=11)。沿用 MIT-373
//     sse_sub_sample 的 pitfall #35 模式。
//   - **mov 类指令必须用非平凡初值** (派活单 §E 验收 #5): 每个 helper 的 dst 槽
//     预置与 src 槽**完全不同**的值。若 handler 空转 (没搬), 读回 = dst 入口旧值
//     → 与原生 (dst = src) 必然不一致; "输出恰等于输入"的假阳性因此不成立。
//   - **movss 语义与另 4 条不同**: 寄存器形式只搬低 32 位, dst[127:32] 保持不
//     变 (本机实测; "高 96 位清零"是内存源形式的行为), 故 dst 预置 lane1-3 非零:
//     结果 lane1-3 必须仍是预置值 —— 这一条同时把"movss 被实现成全 128-bit 搬"
//     与"误按内存源形式清零高位"两种错法都区分开。
//   - **槽位分散**: 5 条分别用 xmm0/1、xmm2/3、xmm4/5、xmm6/7、xmm1/3 —— 只有非 0
//     槽能证明 handler 的 ctx.xmm 地址公式 0x140+(reg-24)*16 正确 (MIT-371 空转
//     bug 在 reg=26 上算成 0x40 落进 GPR 区, xmm0/xmm1 看不出来)。
//   - 每个 helper 额外回读 src 槽 (out_src): src **必须**保持入口值 —— 若 handler
//     把 dst/src 槽算反或越槽写, 这里立刻暴露。
//   - 区域只含白名单单指令 + 3 nop (凑 ≥5 字节让 stub_link 写 E9 跳转), 不含
//     rip-relative / printf / call (printf 在 main 区域外)。
//   - ctx.xmm 槽位级全量快照断言在影子样本 wvmp_sse_movss_xmm_readback_sample。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

extern "C" void sse_mov_ss(const float* dst4, const float* src4, float* out4,
                           float* out_src4);
extern "C" void sse_mov_aps(const float* dst4, const float* src4, float* out4,
                            float* out_src4);
extern "C" void sse_mov_apd(const double* dst2, const double* src2, double* out2,
                            double* out_src2);
extern "C" void sse_mov_ups(const float* dst4, const float* src4, float* out4,
                            float* out_src4);
extern "C" void sse_mov_upd(const double* dst2, const double* src2, double* out2,
                            double* out_src2);

int main() {
    // movss xmm0, xmm1 (寄存器形式): 只搬低 32 位 → 期望 [5.5, 2.25, -3.5, 4.75]
    //   (lane0 来自 src, lane1-3 **保持 dst 入口预置值不变**)。实测真值表见
    //   asmgen.cpp build_movss 注释: "高 96 位清零"只属于内存源形式 F3 0F 10
    //   (mod=00), 本单不支持; 若误按清零实现, 这一行会打印 [5.5,0,0,0]。
    const float ss_dst[4] = {-1.5f, 2.25f, -3.5f, 4.75f};
    const float ss_src[4] = {5.5f, -6.25f, 7.75f, -8.5f};
    float ss_out[4] = {};
    float ss_src_out[4] = {};
    sse_mov_ss(ss_dst, ss_src, ss_out, ss_src_out);

    // movaps xmm2, xmm3: 全 128-bit 搬 → 期望 [11, 22, 33, 44]
    const float aps_dst[4] = {1.5f, 2.5f, 3.5f, 4.5f};
    const float aps_src[4] = {11.0f, 22.0f, 33.0f, 44.0f};
    float aps_out[4] = {};
    float aps_src_out[4] = {};
    sse_mov_aps(aps_dst, aps_src, aps_out, aps_src_out);

    // movapd xmm4, xmm5: 全 128-bit 搬 (2×f64) → 期望 [12.5, 20.75]
    const double apd_dst[2] = {100.5, 200.25};
    const double apd_src[2] = {12.5, 20.75};
    double apd_out[2] = {};
    double apd_src_out[2] = {};
    sse_mov_apd(apd_dst, apd_src, apd_out, apd_src_out);

    // movups xmm6, xmm7: 全 128-bit 搬 → 期望 [7.5, 8.5, 9.5, 10.5]
    const float ups_dst[4] = {-0.5f, -1.5f, -2.5f, -3.5f};
    const float ups_src[4] = {7.5f, 8.5f, 9.5f, 10.5f};
    float ups_out[4] = {};
    float ups_src_out[4] = {};
    sse_mov_ups(ups_dst, ups_src, ups_out, ups_src_out);

    // movupd xmm1, xmm3: 全 128-bit 搬 (2×f64) → 期望 [3.25, 4.5]
    const double upd_dst[2] = {1000.0, 2000.0};
    const double upd_src[2] = {3.25, 4.5};
    double upd_out[2] = {};
    double upd_src_out[2] = {};
    sse_mov_upd(upd_dst, upd_src, upd_out, upd_src_out);

    std::printf("movss=[%g,%g,%g,%g] src=[%g,%g,%g,%g]\n",
                static_cast<double>(ss_out[0]), static_cast<double>(ss_out[1]),
                static_cast<double>(ss_out[2]), static_cast<double>(ss_out[3]),
                static_cast<double>(ss_src_out[0]), static_cast<double>(ss_src_out[1]),
                static_cast<double>(ss_src_out[2]), static_cast<double>(ss_src_out[3]));
    std::printf("movaps=[%g,%g,%g,%g] src=[%g,%g,%g,%g]\n",
                static_cast<double>(aps_out[0]), static_cast<double>(aps_out[1]),
                static_cast<double>(aps_out[2]), static_cast<double>(aps_out[3]),
                static_cast<double>(aps_src_out[0]), static_cast<double>(aps_src_out[1]),
                static_cast<double>(aps_src_out[2]), static_cast<double>(aps_src_out[3]));
    std::printf("movapd=[%g,%g] src=[%g,%g]\n", apd_out[0], apd_out[1], apd_src_out[0],
                apd_src_out[1]);
    std::printf("movups=[%g,%g,%g,%g] src=[%g,%g,%g,%g]\n",
                static_cast<double>(ups_out[0]), static_cast<double>(ups_out[1]),
                static_cast<double>(ups_out[2]), static_cast<double>(ups_out[3]),
                static_cast<double>(ups_src_out[0]), static_cast<double>(ups_src_out[1]),
                static_cast<double>(ups_src_out[2]), static_cast<double>(ups_src_out[3]));
    std::printf("movupd=[%g,%g] src=[%g,%g]\n", upd_out[0], upd_out[1], upd_src_out[0],
                upd_src_out[1]);
    return 0;
}
