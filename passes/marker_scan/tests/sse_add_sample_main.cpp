// MIT-371: 端到端正路径样本——区域内含 SSE 浮点加 addss/addps/addpd
// (3 形式 REG-REG), 验证 SSE 浮点加修复后翻译成功、运行时走真 Addss/
// Addps/Addpd handler、行为与原生逐字节一致（保护 → 运行 → stdout+退出码
// 比对）。
//
// 设计要点:
//   - MSVC x64 **不支持 inline asm**, 高 level C++ 在 /Od 下对 _mm_add_ss/
//     _mm_add_ps/_mm_add_pd 内部函数会**融合 load+add 为 MEM 形式**
//     (addss xmm, [mem] / addps xmm, [mem] / addpd xmm, [mem]), 与派活单
//     限定 REG-REG only 冲突. 故 SSE 字节由 sse_add_sample_asm.asm (MASM)
//     直接 emit 真 REG-REG addss/addps/addpd 字节 (F3 0F 58 / 0F 58 /
//     66 0F 58, mod=11), 链接进本 sample. 沿用 cmpxchg_sample_asm.asm 模式
//     (pitfall #35 MASM helper 强制 codegen).
//   - 区域**只含白名单** ALU/SSE: mov/xmm add REG-REG, 不含 rip-relative /
//     printf / call (printf 在 main 区域外).
//   - 测试用例覆盖典型 SSE 浮点加语义:
//     - addss: scalar 单精度 (xmm0.low 32-bit f32 += xmm1.low 32-bit f32)
//     - addps: 4xf32 packed 同时加 (4 lane 并行)
//     - addpd: 2xf64 packed 同时加 (2 lane 并行)
//   - 运算结果有具体期望值（依赖 codegen 与 intrinsic 形态），E2E 通过字节级
//     stdout + 退出码比对保证行为一致。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

extern "C" float sse_addss(float a, float b);
extern "C" void sse_addps(const float* a, const float* b, float* out);
extern "C" void sse_addpd(const double* a, const double* b, double* out);

int main() {
    // addss: 1.5f + 2.5f = 4.0f (scalar single)
    const float s1 = sse_addss(1.5f, 2.5f);    // = 4.0f

    // addps: 4xf32 packed parallel
    //   a = {1.0, 2.0, 3.0, 4.0}
    //   b = {10.0, 20.0, 30.0, 40.0}
    //   result = {11.0, 22.0, 33.0, 44.0}
    float ps_a[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float ps_b[4] = {10.0f, 20.0f, 30.0f, 40.0f};
    float ps_out[4] = {};
    sse_addps(ps_a, ps_b, ps_out);

    // addpd: 2xf64 packed parallel
    //   a = {1.5, 2.5}
    //   b = {10.5, 20.25}
    //   result = {12.0, 22.75}
    double pd_a[2] = {1.5, 2.5};
    double pd_b[2] = {10.5, 20.25};
    double pd_out[2] = {};
    sse_addpd(pd_a, pd_b, pd_out);

    std::printf("addss=%g addps=[%g,%g,%g,%g] addpd=[%g,%g]\n",
                static_cast<double>(s1),
                static_cast<double>(ps_out[0]), static_cast<double>(ps_out[1]),
                static_cast<double>(ps_out[2]), static_cast<double>(ps_out[3]),
                pd_out[0], pd_out[1]);
    return 0;
}