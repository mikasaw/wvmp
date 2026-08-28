// MIT-373: 端到端正路径样本——区域内含 SSE 浮点减 subss/subps/subpd
// (3 形式 REG-REG), 验证 SSE 浮点减支持后翻译成功、运行时走真 Subss/
// Subps/Subpd handler、行为与原生逐字节一致（保护 → 运行 → stdout+退出码
// 比对）。
//
// 设计要点:
//   - MSVC x64 **不支持 inline asm**, 高 level C++ 在 /Od 下对 _mm_sub_ss/
//     _mm_sub_ps/_mm_sub_pd 内部函数会**融合 load+sub 为 MEM 形式**
//     (subss xmm, [mem] / subps xmm, [mem] / subpd xmm, [mem]), 与派活单
//     限定 REG-REG only 冲突. 故 SSE 字节由 sse_sub_sample_asm.asm (MASM)
//     直接 emit 真 REG-REG subss/subps/subpd 字节 (F3 0F 5C / 0F 5C /
//     66 0F 5C, mod=11), 链接进本 sample. 沿用 sse_add_sample_asm.asm 模式
//     (pitfall #35 MASM helper 强制 codegen).
//   - 区域**只含白名单** ALU/SSE: xmm sub REG-REG, 不含 rip-relative /
//     printf / call (printf 在 main 区域外).
//   - 测试用例覆盖典型 SSE 浮点减语义:
//     - subss: scalar 单精度 (xmm0.low 32-bit f32 -= xmm1.low 32-bit f32)
//     - subps: 4xf32 packed 同时减 (4 lane 并行)
//     - subpd: 2xf64 packed 同时减 (2 lane 并行)
//   - 运算结果有具体期望值（依赖 codegen 与 intrinsic 形态），E2E 通过字节级
//     stdout + 退出码比对保证行为一致。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

extern "C" float sse_subss(float a, float b);
extern "C" void sse_subps(const float* a, const float* b, float* out);
extern "C" void sse_subpd(const double* a, const double* b, double* out);

int main() {
    // subss: 5.5f - 2.0f = 3.5f (scalar single)
    const float s1 = sse_subss(5.5f, 2.0f);    // = 3.5f

    // subps: 4xf32 packed parallel
    //   a = {10.0, 20.0, 30.0, 40.0}
    //   b = {1.0, 2.0, 3.0, 4.0}
    //   result = {9.0, 18.0, 27.0, 36.0}
    float ps_a[4] = {10.0f, 20.0f, 30.0f, 40.0f};
    float ps_b[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float ps_out[4] = {};
    sse_subps(ps_a, ps_b, ps_out);

    // subpd: 2xf64 packed parallel
    //   a = {12.5, 20.75}
    //   b = {10.5, 20.25}
    //   result = {2.0, 0.5}
    double pd_a[2] = {12.5, 20.75};
    double pd_b[2] = {10.5, 20.25};
    double pd_out[2] = {};
    sse_subpd(pd_a, pd_b, pd_out);

    std::printf("subss=%g subps=[%g,%g,%g,%g] subpd=[%g,%g]\n",
                static_cast<double>(s1),
                static_cast<double>(ps_out[0]), static_cast<double>(ps_out[1]),
                static_cast<double>(ps_out[2]), static_cast<double>(ps_out[3]),
                pd_out[0], pd_out[1]);
    return 0;
}
