// MIT-428 (G1d): SSE2 对齐传送 movdqa/movdqu 影子样本 — Movaps/Movups 既有
// handler 的 ctx.xmm 运行时读回断言 (与 wvmp_aligned_mov_sample 同能力面
// 配对、独立 exe, 沿用 MIT-389/408/411/425/426/427 影子样本模式)。
//
// 背景 (pitfall #79 纪律): 主样本 stdout 只断言传送语义值。本影子把 8 槽 ×
// 2×u64 全量打印: dst 槽 = 期望位图案 (16B 全宽 — movdqa/movdqu 无清零/
// 截断语义, 高位 = 源高位, 与 427 桥装入清零位级对照), 其余 7 槽必须 =
// 入口预载值 (误写无关槽即 FAIL); movups 通路对非对齐栈槽 ([rsp+8h]) 无
// 对齐校验 (D2 宽松语义位级钉)。本单零新 handler → 运行时走既有
// Movaps/Movups 注册表 (dump 门 SSE_HANDLERS 集合恒等 = 零新 VmOp 机器证明)。
//
// 全部输出 %016llx 逐位可比对。native run vs virtualized run 逐字节比对;
// handler 空转/槽位错/宽度错 → 与原生不一致 → FAIL。

#include <cstdio>
#include <cstdint>

extern "C" void ash_dqa_rr(const unsigned long long* in, unsigned long long* out);
extern "C" void ash_dqa_rr7(const unsigned long long* in, unsigned long long* out);
extern "C" void ash_dqu_rr(const unsigned long long* in, unsigned long long* out);
extern "C" void ash_dqa_stack(const unsigned long long* in, unsigned long long* out);
extern "C" void ash_dqu_stack_unal(const unsigned long long* in, unsigned long long* out);
extern "C" void ash_dqa_rip_load(const unsigned long long* in, unsigned long long* out);
extern "C" void ash_dqa_rip_store(const unsigned long long* in, unsigned long long* out);
extern "C" void ash_vdqa_rr(const unsigned long long* in, unsigned long long* out);
extern "C" void ash_vdqu_rr(const unsigned long long* in, unsigned long long* out);

// C 链接全局: MASM helper (aligned_mov_xmm_readback_sample_asm.asm)
// EXTERNDEF 直引符号 — rip mem 源 / store 目标 (16B 对齐)。
__declspec(align(16)) extern "C" unsigned long long g_ash_src[2] = {
    0x0123456789ABCDEFull, 0xFEDCBA9876543210ull};
__declspec(align(16)) extern "C" unsigned long long g_ash_out[2] = {0, 0};

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

// out: 16 × xmm 槽 u64 + 1 × rax 哨兵 (本族无 GP 方向)
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
    // ① movdqa reg-reg (6F): xmm0 = xmm1 预载全宽 — {4444..., 3333...}
    run_probe("dqa_rr", ash_dqa_rr);
    // ② movdqa reg-reg 7F 反写形: 与 ① 逐位一致 (probe 归一化)
    run_probe("dqa_rr7", ash_dqa_rr7);
    // ③ movdqu reg-reg: 与 ① 逐位一致 (全宽语义同构)
    run_probe("dqu_rr", ash_dqu_rr);
    // ④ movdqa 对齐栈槽: xmm0 = xmm4 预载图案 — {9999..., AAAA...}
    run_probe("dqa_stack", ash_dqa_stack);
    // ⑤ movdqu 非对齐栈槽: xmm0 = xmm5 预载图案 — {BBBB..., CCCC...}
    run_probe("dqu_stack_unal", ash_dqu_stack_unal);
    // ⑥ movdqa rip load: xmm0 = g_ash_src — {0123..., FEDC...}
    run_probe("dqa_rip_load", ash_dqa_rip_load);
    // ⑦ movdqa rip store: g_ash_out = xmm0 预载 — 区域后读回打印
    unsigned long long st[17];
    ash_dqa_rip_store(g_in, st);
    std::printf("[dqa_rip_store] out=%016llX,%016llX\n", g_ash_out[0], g_ash_out[1]);
    // ⑧⑨ VEX 镜像: vmovdqa/vmovdqu reg-reg — 与 ① 逐位一致
    run_probe("vdqa_rr", ash_vdqa_rr);
    run_probe("vdqu_rr", ash_vdqu_rr);
    return 0;
}
