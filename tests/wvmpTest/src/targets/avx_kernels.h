// targets/avx_kernels.h - MIT-520 (T72): x64 专属 AVX 语料批。
//
// 入选标准同 kernels.h（纯计算/确定性/extern "C"/noinline），另加：
//   * 仅 x64 构建编入（build.bat x64 分支单独 /arch:AVX 编译本文件；
//     x86 构建完全不含本 TU —— MSVC x86 默认无 AVX 且 wvmpTest x86
//     词面无需 ymm）。
//   * 全部使用 <immintrin.h> intrinsic 保证 ymm 词流确定性（自动向量
//     化依赖编译器版本， intrinsic 逐条对映 VEX 编码，回归稳定）。
//   * 区域内只允许 VEX 词（__m256 运算）—— legacy SSE 混排会触发保护
//     器的混排 gate（MIT-512），那是负例面（vex128_sample 的职责），
//     本批全部正例。
//
// 读回方式：驱动不假设 ymm 跨调用存活（MSVC x64 ABI 中 ymm 上半是
// volatile），内核把结果写回内存缓冲；物理 ymm0 出口回写的观测面由
// 主仓 ymm_data_sample ⑥ 承担。
#pragma once

#include <stdint.h>

#if defined(_MSC_VER) && defined(_WIN64)

// 与 kernels.h 同款 noinline 宏（本头自包含，不依赖 kernels.h）。
#if defined(_MSC_VER)
#  define WV_TARGET_NOINLINE __declspec(noinline)
#else
#  define WV_TARGET_NOINLINE __attribute__((noinline))
#endif

#if defined(__cplusplus)
extern "C" {
#endif

// 8-lane 逐元素加：out[i] = a[i] + b[i]（_mm256_add_ps）。
WV_TARGET_NOINLINE void wv_avx_add8(const float* a, const float* b, float* out);

// 8-lane 逐元素乘加：out[i] = a[i] * k + b[i]（_mm256_mul_ps + add_ps）。
WV_TARGET_NOINLINE void wv_avx_fma8(const float* a, const float* b,
                                    float* out);

// 8-lane 逐元素乘：out[i] = a[i] * b[i]（_mm256_mul_ps；归约留驱动侧——
// kernel 内 float 标量归约会生成 addss legacy-SSE 词触发混排 gate）。
WV_TARGET_NOINLINE void wv_avx_mul8(const float* a, const float* b,
                                    float* out);

#if defined(__cplusplus)
}
#endif

#endif  // _MSC_VER && _WIN64
