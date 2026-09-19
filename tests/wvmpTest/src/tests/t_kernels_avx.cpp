// t_kernels_avx.cpp - MIT-520 (T72): AVX 语料批验证驱动（x64 专属）。
//
// 非 x64 编译为空 TU（kernavx 组不存在 → SKIP 语义由组缺席自然表达）。
// 对拍策略：小整数初值（2 的幂附近）保证 float 全程精确，驱动与内核
// 同序计算位精确对拍。
#include "../common.h"
#include "../testfw.h"

#if defined(_MSC_VER) && defined(_WIN64)

#include "../targets/avx_kernels.h"

#include <cstring>

using namespace wv;

namespace {
alignas(32) float g_a[8];
alignas(32) float g_b[8];
alignas(32) float g_out[8];

void fill_f(float* p, float base) {
    for (int i = 0; i < 8; ++i) p[i] = base + static_cast<float>(i);
}
}  // namespace

TEST(kernavx, add8_fma8_dot8) {
    fill_f(g_a, 1.0f);
    fill_f(g_b, 100.0f);

    // ① add8
    std::memset(g_out, 0, sizeof(g_out));
    wv_avx_add8(g_a, g_b, g_out);
    for (int i = 0; i < 8; ++i) {
        float want = g_a[i] + g_b[i];
        uint32_t gb, wb;
        std::memcpy(&gb, &g_out[i], 4);
        std::memcpy(&wb, &want, 4);
        CHECK_EQ(gb, wb);
    }

    // ② fma8（a*a + b：平方加——白名单内 mul/add 词，无 broadcast）
    fill_f(g_a, 3.0f);
    std::memset(g_out, 0, sizeof(g_out));
    wv_avx_fma8(g_a, g_b, g_out);
    for (int i = 0; i < 8; ++i) {
        float want = g_a[i] * g_a[i] + g_b[i];
        uint32_t gb, wb;
        std::memcpy(&gb, &g_out[i], 4);
        std::memcpy(&wb, &want, 4);
        CHECK_EQ(gb, wb);
    }

    // ③ mul8（1..8 × 常数 1）+ 驱动侧归约（1..8 积和 = 精确整数 36）。
    // 归约不放 kernel 内：float 标量加在 /Od 下生成 addss（legacy SSE 词），
    // 与 ymm 词同函数触发混排 gate。
    fill_f(g_a, 1.0f);
    for (int i = 0; i < 8; ++i) g_a[i] = static_cast<float>(i + 1);
    fill_f(g_b, 0.0f);
    for (int i = 0; i < 8; ++i) g_b[i] = 1.0f;
    wv_avx_mul8(g_a, g_b, g_out);
    float acc = 0.0f;
    for (int i = 0; i < 8; ++i) acc += g_out[i];
    uint32_t gb, wb;
    std::memcpy(&gb, &acc, 4);
    const float want = 36.0f;
    std::memcpy(&wb, &want, 4);
    CHECK_EQ(gb, wb);
}

#endif  // _MSC_VER && _WIN64
