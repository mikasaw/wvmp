// MIT-376: 端到端主样本——区域内含 SSE 浮点位运算 xorps/orps/andps +
// 浮点比较 ucomiss/ucomisd (5 形式 REG-REG), 验证 5 条新指令支持后翻译成功、
// 运行时走真 Xorps/Orps/Andps/Ucomiss/Ucomisd handler、行为与原生逐字节一致
// (保护 → 运行 → stdout+退出码比对)。
//
// 设计要点:
//   - MSVC x64 **不支持 inline asm**, /Od 下位运算/比较 intrinsic 会融合
//     load+op 为 MEM 形式, 与派活单限定 REG-REG only 冲突。故 SSE 字节由
//     sse_bwcmp_sample_asm.asm (MASM) 直接 emit 真 REG-REG 字节 (0F 57 / 0F 56
//     / 0F 54 / 0F 2E / 66 0F 2E, mod=11), 链接进本 sample (pitfall #35)。
//   - 位运算 3 条 (xorps/orps/andps): 输入取互不相同的非零 32-bit 位图案,
//     结果以 %08X 原始位图案打印 (位运算不解释浮点值, 按 lane 打印才二进制
//     精确)。xorps 空转 → 输出=输入 a ≠ 期望, 与原生不一致 → FAIL。
//   - 比较类断言 (派活单 §C 6): ucomiss/ucomisd 后**紧跟 seta**, 且 seta 在
//     marker 区域**内** (虚拟化路径下由 VmOp::Setcc handler 读 VmOp::Ucomiss
//     handler 写的 VM flags 槽, 证明 flags 真参与运行时, 非 stdout 盲区)。
//     seta 结果经 movzx+store 在区域内保存 (pitfall #36 rax 跨 SDK 调用
//     clobber), 返回值落到 main 的 printf。
//   - ucomiss 覆盖 greater/less/equal/unordered(NaN) 四态 (Intel SDM 真值表
//     ZF/CF 全组合), ucomisd 覆盖 greater/less 两态; NaN → unordered →
//     ZF=PF=CF=1 → seta=0 (D1.1 决策)。
//   - 区域**只含白名单**: SSE 位运算/比较 + setcc/movzx/store, 不含
//     rip-relative / printf / call (printf 在 main 区域外)。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>
#include <limits>

extern "C" unsigned int bw_xorps(unsigned int a, unsigned int b);
extern "C" unsigned int bw_orps(unsigned int a, unsigned int b);
extern "C" unsigned int bw_andps(unsigned int a, unsigned int b);
extern "C" int ucmp_ss_gt(float a, float b);
extern "C" int ucmp_ss_lt(float a, float b);
extern "C" int ucmp_ss_eq(float a, float b);
extern "C" int ucmp_ss_nan(float a, float b);
extern "C" int ucmp_sd_gt(double a, double b);
extern "C" int ucmp_sd_lt(double a, double b);

int main() {
    // 位运算三件套: 位图案输入, 结果二进制精确 (按位, 不经浮点舍入)。
    //   xorps: 0x0F0F0F0F ^ 0x33CC33CC = 0x3CC33CC3
    //   orps : 0xF0F0F0F0 | 0x0F0F0F0F = 0xFFFFFFFF
    //   andps: 0xFF00FF00 & 0xFFFF0000 = 0xFF000000
    const unsigned int x = bw_xorps(0x0F0F0F0Fu, 0x33CC33CCu);
    const unsigned int o = bw_orps(0xF0F0F0F0u, 0x0F0F0F0Fu);
    const unsigned int a = bw_andps(0xFF00FF00u, 0xFFFF0000u);

    // ucomiss + seta 四态 (a > b → seta=1; less/equal/unordered → seta=0):
    //   gt  = (2.5, 1.5)  → CF=0 ZF=0 → 1
    //   lt  = (0.5, 1.5)  → CF=1 ZF=0 → 0
    //   eq  = (1.5, 1.5)  → CF=0 ZF=1 → 0
    //   nan = (qNaN, 1.0) → unordered, ZF=PF=CF=1 → 0
    const float qnan = std::numeric_limits<float>::quiet_NaN();
    const int gt = ucmp_ss_gt(2.5f, 1.5f);
    const int lt = ucmp_ss_lt(0.5f, 1.5f);
    const int eq = ucmp_ss_eq(1.5f, 1.5f);
    const int nan_uc = ucmp_ss_nan(qnan, 1.0f);

    // ucomisd + seta 两态:
    //   gt = (7.25, 3.5) → 1 / lt = (1.5, 7.25) → 0
    const int dgt = ucmp_sd_gt(7.25, 3.5);
    const int dlt = ucmp_sd_lt(1.5, 7.25);

    std::printf("xorps=%08X orps=%08X andps=%08X\n", x, o, a);
    std::printf("ucomiss gt=%d lt=%d eq=%d nan=%d\n", gt, lt, eq, nan_uc);
    std::printf("ucomisd gt=%d lt=%d\n", dgt, dlt);
    return 0;
}
