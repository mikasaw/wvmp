// MIT-404 影子样本 (flags/dual-slot readback 断言, 派活单 §B.6 / §C D4.1) ——
// div/idiv 的 Rax/Rdx 双槽 + VM flags 运行时读回, 与主样本 wvmp_div_sample
// 同 IR 族、独立 exe (对齐 MIT-376 bwcmpss 影子样本模式)。
//
// 为什么需要影子样本 (MIT-371 空转教训): Div/Idiv handler 的正确性在
// Rax/Rdx 双结果槽 (商→Rax 槽, 余→Rdx 槽) 与 VM flags 槽。handler 若空转
// (decode+advance) 或写错槽, 主样本 stdout 虽然也能对上 (区域结果没被
// 消费) — 本样本把断言做成显式输出:
//   1. out[0]/out[1] = 商/余 (区域内存 store, 槽写错即不一致 → FAIL);
//   2. out[2..6] = setz/setc/seto/sets/setp 五探针 — Setcc handler 读
//      flags 管线写入的 VM flags 槽。MIT-494d 勘误: div/idiv 的 flags
//      为 SDM undefined, "同 CPU 同输入逐位一致"前提在高熵随机化下不
//      成立——asm 侧已改为除法后插 test 探测**有定义** flags（ZF/SF/
//      PF 由商决定, CF=OF=0），五探针照旧验证 flags 管线。
// native vs virtualized byte-exact; handler 空转 → 探针读 dispatch 残留
// flags / 槽与原生不符 → FAIL。ctx.xmm 无关 (整数除法族不触碰 xmm 槽)。

#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" void dfr_idiv64(int64_t a, int64_t b, uint64_t out[8]);
extern "C" void dfr_div32(uint32_t a, uint32_t b, uint64_t out[8]);
extern "C" void dfr_idiv32(int32_t a, int32_t b, uint64_t out[8]);

namespace {

// 打印一个探针的 商/余/五 flags 位 全部 7 槽 + 哨兵槽 (out 预填 0xEE,
// "helper 根本没写 out 区"可分辨)。
void print_probe(const char* tag, const uint64_t out[8]) {
    std::printf("[%s] q=%llx r=%llx ZF=%llx CF=%llx OF=%llx SF=%llx PF=%llx "
                "sent=%llx\n",
                tag,
                static_cast<unsigned long long>(out[0]),
                static_cast<unsigned long long>(out[1]),
                static_cast<unsigned long long>(out[2]),
                static_cast<unsigned long long>(out[3]),
                static_cast<unsigned long long>(out[4]),
                static_cast<unsigned long long>(out[5]),
                static_cast<unsigned long long>(out[6]),
                static_cast<unsigned long long>(out[7]));
}

} // namespace

int main() {
    uint64_t out[8];

    // idiv64: 正 / 负 (D3.1 截断向零) / 商为 0 (ZF 可观察) 三态。
    std::memset(out, 0xEE, sizeof(out));
    dfr_idiv64(100, 7, out);
    print_probe("idiv64_pos", out);

    std::memset(out, 0xEE, sizeof(out));
    dfr_idiv64(-7, 2, out);
    print_probe("idiv64_neg", out);

    std::memset(out, 0xEE, sizeof(out));
    dfr_idiv64(3, 8, out);
    print_probe("idiv64_zeroq", out);

    // div32: 正 INT_MAX (cdq → edx=0, 商 32 位内) / 正小值。
    // ⚠️ div 配负 a 必商溢出 #DE (0xC0000095, cdq 扩 0xFFFFFFFF 高位) —
    // 负数语义属 idiv, div32 探针只用正 a。
    std::memset(out, 0xEE, sizeof(out));
    dfr_div32(0x7FFFFFFFu, 7u, out);
    print_probe("div32_max", out);

    std::memset(out, 0xEE, sizeof(out));
    dfr_div32(1000000u, 7u, out);
    print_probe("div32_pos", out);

    // idiv32 MEM 形式负数组合: -7/2 → q=-3 r=-1。
    std::memset(out, 0xEE, sizeof(out));
    dfr_idiv32(-7, 2, out);
    print_probe("idiv32_neg", out);
    return 0;
}
