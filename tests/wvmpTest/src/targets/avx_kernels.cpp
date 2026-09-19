// targets/avx_kernels.cpp - MIT-520 (T72): x64 专属 AVX 语料批实现。
//
// 编译约束（build.bat x64 分支单独编译本 TU）：
//   cl /c /arch:AVX /Od /utf-8 avx_kernels.cpp
// #pragma optimize("", off) 防止 marker_end 尾调用化（E8 消失）——与
// kernels.cpp 同款纪律；/arch:AVX 使 __m256 运算逐条对映 VEX.256 编码。
#include "avx_kernels.h"

#if defined(_MSC_VER) && defined(_WIN64)

#include "wvmp_protect.h"

#include <immintrin.h>

#pragma optimize("", off)

WV_TARGET_NOINLINE void wv_avx_add8(const float* a, const float* b, float* out) {
    PROTECT_BEGIN("wv_avx_add8");
    __m256 va = _mm256_loadu_ps(a);
    __m256 vb = _mm256_loadu_ps(b);
    __m256 vr = _mm256_add_ps(va, vb);
    _mm256_storeu_ps(out, vr);
    PROTECT_END();
}

WV_TARGET_NOINLINE void wv_avx_fma8(const float* a, const float* b,
                                    float* out) {
    PROTECT_BEGIN("wv_avx_fma8");
    __m256 va = _mm256_loadu_ps(a);
    __m256 vb = _mm256_loadu_ps(b);
    __m256 vr = _mm256_add_ps(_mm256_mul_ps(va, va), vb);
    _mm256_storeu_ps(out, vr);
    PROTECT_END();
}

// MIT-519 验收 F1 教训：float 标量归约在 /Od 下生成 addss（legacy SSE 词）
// 会与本文件 ymm 词同函数共存 → 混排 gate。归约移驱动侧，kernel 纯 ymm。
WV_TARGET_NOINLINE void wv_avx_mul8(const float* a, const float* b, float* out) {
    PROTECT_BEGIN("wv_avx_mul8");
    __m256 va = _mm256_loadu_ps(a);
    __m256 vb = _mm256_loadu_ps(b);
    __m256 prod = _mm256_mul_ps(va, vb);
    _mm256_storeu_ps(out, prod);
    PROTECT_END();
}

#pragma optimize("", on)

#endif  // _MSC_VER && _WIN64
