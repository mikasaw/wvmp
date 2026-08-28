// MIT-374: 端到端正路径样本——区域内含 SSE 浮点除 divss/divps/divpd
// (3 形式 REG-REG), 验证 SSE 浮点除支持后翻译成功、运行时走真 Divss/
// Divps/Divpd handler、行为与原生逐字节一致（保护 → 运行 → stdout+退出码
// 比对）。
//
// 设计要点:
//   - MSVC x64 **不支持 inline asm**, 高 level C++ 在 /Od 下对 _mm_div_ss/
//     _mm_div_ps/_mm_div_pd 内部函数会**融合 load+div 为 MEM 形式**
//     (divss xmm, [mem] / divps xmm, [mem] / divpd xmm, [mem]), 与派活单
//     限定 REG-REG only 冲突. 故 SSE 字节由 sse_div_sample_asm.asm (MASM)
//     直接 emit 真 REG-REG divss/divps/divpd 字节 (F3 0F 5E / 0F 5E /
//     66 0F 5E, mod=11), 链接进本 sample. 沿用 sse_add_sample_asm.asm /
//     sse_sub_sample_asm.asm 模式 (pitfall #35 MASM helper 强制 codegen).
//   - 区域**只含白名单** ALU/SSE: xmm div REG-REG, 不含 rip-relative /
//     printf / call (printf 在 main 区域外).
//   - 测试用例覆盖典型 SSE 浮点除语义 (输入全部取二进制精确值, 商也二进制
//     精确, 避免十进制舍入歧义; 除数一律非 0, v1 不追踪 MXCSR 异常):
//     - divss: scalar 单精度 (xmm0.low 32-bit f32 /= xmm1.low 32-bit f32)
//     - divps: 4xf32 packed 同时除 (4 lane 并行)
//     - divpd: 2xf64 packed 同时除 (2 lane 并行)
//   - 运算结果有具体期望值（依赖 codegen 与 intrinsic 形态），E2E 通过字节级
//     stdout + 退出码比对保证行为一致。

#include "wvmp/sdk/markers.hpp"

#include <cstdio>

extern "C" float sse_divss(float a, float b);
extern "C" void sse_divps(const float* a, const float* b, float* out);
extern "C" void sse_divpd(const double* a, const double* b, double* out);

int main() {
    // divss: 5.5f / 2.0f = 2.75f (scalar single)
    const float s1 = sse_divss(5.5f, 2.0f);    // = 2.75f

    // divps: 4xf32 packed parallel
    //   a = {1024.0, 512.0, 256.0, 128.0}
    //   b = {1.0, 2.0, 4.0, 8.0}
    //   result = {1024.0, 256.0, 64.0, 16.0}
    float ps_a[4] = {1024.0f, 512.0f, 256.0f, 128.0f};
    float ps_b[4] = {1.0f, 2.0f, 4.0f, 8.0f};
    float ps_out[4] = {};
    sse_divps(ps_a, ps_b, ps_out);

    // divpd: 2xf64 packed parallel
    //   a = {12.5, 20.75}
    //   b = {0.5, 0.25}
    //   result = {25.0, 83.0}
    double pd_a[2] = {12.5, 20.75};
    double pd_b[2] = {0.5, 0.25};
    double pd_out[2] = {};
    sse_divpd(pd_a, pd_b, pd_out);

    std::printf("divss=%g divps=[%g,%g,%g,%g] divpd=[%g,%g]\n",
                static_cast<double>(s1),
                static_cast<double>(ps_out[0]), static_cast<double>(ps_out[1]),
                static_cast<double>(ps_out[2]), static_cast<double>(ps_out[3]),
                pd_out[0], pd_out[1]);
    return 0;
}
