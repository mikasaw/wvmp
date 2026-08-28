// MIT-375 影子样本 (WVmpVerifier 验收门 A.2 模式, 沿用 MIT-389
// sse_subss_xmm_readback_sample 设计) —— SSE 浮点传送 5 条新指令的 ctx.xmm
// 运行时读回断言, 与主样本 wvmp_sse_mov_sample 同 IR、独立 exe。
//
// 为什么需要影子样本 (MIT-371 空转教训): 主样本 stdout 只看"结果对不对", 而
// mov 类指令**空转时输出天然等于输入** (handler 若写错槽/根本没写, 只要 dst
// 初值恰好被下游当成结果消费, byte-exact 比对就可能假阳性)。本样本把
// VmContext.xmm[0..7] 全部 8 槽 × 4 lane 的 32-bit 原始位图案打印出来, 使
// "handler 是否真的更新了 ctx.xmm[dst] 且没污染别的槽" 变成显式断言:
//
//   虚拟化路径下区域代理解执行, xmm 状态全活在 VmContext.xmm[8] (@ +0x140,
//   stub 入口把物理 xmm0..7 同步进 ctx / HALT 出口恢复, 见 stub_gen.cpp)。
//   ctx 槽对样本唯一的可见出口 = 区域后的原生 store (值 = HALT 恢复后的物理
//   xmm, 即 ctx 读回状态)。handler 空转 (没写) → 读回 = 入口旧值;
//   handler 写错槽 (偏移公式坏) → dst 保持入口值 + 某无关槽被污染;
//   两种都与原生不一致 → 逐字节比对 FAIL。
//
// 5 个探针 (每条新指令 1 个, 1:1 配对):
//   xr_mov_ss  : movss  xmm0, xmm1 → dst 槽 = {src.lane0, dst.lane1, dst.lane2,
//                  dst.lane3} (寄存器形式只改低 32, 高位保持)
//   xr_mov_aps : movaps xmm2, xmm3 → dst 槽 = src 槽全 128-bit
//   xr_mov_apd : movapd xmm4, xmm5 → 同上 (非 0 槽 + REX 编码)
//   xr_mov_ups : movups xmm6, xmm7 → 同上 (xmm7 = VM 槽 31, reg 字段 5 位上界)
//   xr_mov_upd : movupd xmm1, xmm3 → 同上 (dst/src 交叉非相邻槽)
// 每次调用后 8 槽全部打印: dst 槽必须变成期望值, 其余 7 槽 (含 src 槽) 必须
// 逐位保持入口值。
//
// 输入图案: 8 槽 × 4 lane 全互不相同且非零 —— 任一"漏搬 / 多搬 / 搬反 / 越槽写 /
// 高位误清零"都至少改变一个可打印字。

#include <cstdio>
#include <cstring>

extern "C" void xr_mov_ss(const unsigned int* in_slots, unsigned int* out_slots);
extern "C" void xr_mov_aps(const unsigned int* in_slots, unsigned int* out_slots);
extern "C" void xr_mov_apd(const unsigned int* in_slots, unsigned int* out_slots);
extern "C" void xr_mov_ups(const unsigned int* in_slots, unsigned int* out_slots);
extern "C" void xr_mov_upd(const unsigned int* in_slots, unsigned int* out_slots);

namespace {

// 每槽每 lane 一个唯一非零图案 (0x31000000 起保证高位非零, 不与"清零"结果混淆)。
unsigned int pattern(int slot, int lane) {
    return 0x31000000u + static_cast<unsigned int>(slot + 1) * 0x00010100u +
           static_cast<unsigned int>(lane + 1) * 0x00000001u;
}

void fill(unsigned int* slots) {
    for (int s = 0; s < 8; ++s) {
        for (int l = 0; l < 4; ++l) slots[s * 4 + l] = pattern(s, l);
    }
}

// 跑一个探针: 重置 out (填 0xEE 哨兵, 使"helper 根本没写 out 区"也可分辨),
// 调 MASM helper, 打印 8 槽 × 4 lane 原始位图案。
void run_probe(const char* tag, void (*probe)(const unsigned int*, unsigned int*),
               const unsigned int* in8) {
    unsigned int out8[32];
    std::memset(out8, 0xEE, sizeof(out8));
    probe(in8, out8);
    for (int s = 0; s < 8; ++s) {
        std::printf("[%s s%d]=%08X %08X %08X %08X\n", tag, s, out8[s * 4 + 0],
                    out8[s * 4 + 1], out8[s * 4 + 2], out8[s * 4 + 3]);
    }
}

} // namespace

int main() {
    unsigned int in8[32];
    fill(in8);

    run_probe("movss", xr_mov_ss, in8);
    run_probe("movaps", xr_mov_aps, in8);
    run_probe("movapd", xr_mov_apd, in8);
    run_probe("movups", xr_mov_ups, in8);
    run_probe("movupd", xr_mov_upd, in8);
    return 0;
}
