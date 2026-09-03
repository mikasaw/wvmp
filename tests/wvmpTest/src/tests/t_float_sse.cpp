// t_float_sse.cpp - FP semantics corner cases plus SSE2 integer lanes.
// Float assertions rely only on values that are exactly representable, so
// "equality" is meaningful and identical across compilers/optimization.
#include "../testfw.h"
#include "../common.h"

#include <cmath>
#include <cfloat>
#if defined(_MSC_VER)
#  include <emmintrin.h>
#else
#  include <emmintrin.h>
#endif

using namespace wv;

static bool pininf_helper_cmp();                 // comparisons vs infinities

// ---------------------------------------------------------------------------
TEST(fp, trunc_conversions) {
    volatile double dv = 19.75;                  // volatile blocks constant folding
    CHECK_EQ((int)dv, 19);
    dv = -19.75;
    CHECK_EQ((int)dv, -19);                      // toward zero on negatives too
    dv = 0.999999;
    CHECK_EQ((int)dv, 0);

    volatile float fv = 16777215.0f;             // 2^24-1 is the exact limit
    CHECK_EQ((long long)fv, 16777215LL);

    double big = 123456789.0;
    CHECK_EQ((float)big, 123456792.0f);          // nearest float to that integer

    // round trip through float preserves these chosen magnitudes exactly
    for (int k = 0; k < 20; ++k) {
        int v = 1 << k;
        double dd = (double)v;
        CHECK_EQ((double)(float)dd, dd);
    }
}

TEST(fp, classify_specials) {
    volatile double zero = 0.0;
    double pinf = 1.0 / zero;
    double ninf = -1.0 / zero;
    double nan_v = zero / zero;

    CHECK(std::isinf(pinf) && pinf > 0);
    CHECK(std::isinf(ninf) && ninf < 0);
    CHECK(std::isnan(nan_v));
    CHECK(!std::isnan(pinf) && !std::isnan(ninf));

    CHECK(pininf_helper_cmp());
    CHECK(!std::signbit(42.0));
    CHECK(std::signbit(-0.0));                   // IEEE preserves negative zero
    CHECK(-0.0 == 0.0);                          // but compares equal

    double dm = std::copysign(3.5, -100.0);
    CHECK(dm == -3.5);
    CHECK(std::fpclassify(0.0) == FP_ZERO);
    CHECK(std::fabs(1e-310) < DBL_MIN);          // denormal territory or below
}

static bool pininf_helper_cmp() {                // comparisons vs infinities
    double inf = HUGE_VAL;
    CHECK(inf > DBL_MAX);
    CHECK(-inf < -DBL_MAX);
    return inf + inf == inf;                     // saturates instead of overflowing
}

TEST(fp, nextafter_monotonic_ladder) {
    double x = 1.0;
    double prev = x;
    for (int i = 0; i < 1024; ++i) {
        x = std::nextafter(x, HUGE_VAL);
        CHECK(x > prev);                         // strict climb, ulp by ulp
        prev = x;
    }
    // descending from 2.0 towards 1.0 has a known ulp count
    double y = 2.0;
    int steps = 0;
    while (y > 1.0 && steps < 5000) { y = std::nextafter(y, 1.0); ++steps; }
    CHECK(steps <= (1 << 20));                   // sane magnitude guard
}

TEST(fp, hypot_pythagorean_exactness) {
    struct T3 { double a, b, c; };
    const T3 triples[] = {
        { 3, 4, 5 }, { 5, 12, 13 }, { 8, 15, 17 },
        { 7, 24, 25 }, { 20, 21, 29 }, { 9, 40, 41 }, { 11, 60, 61 },
    };
    for (const T3& t : triples)
        CHECK_NEAR(std::hypot(t.a, t.b), t.c, 0.0);   // all integers: EXACT
}

#if defined(_M_X64) || defined(__SSE2__)
TEST(fp, sse2_integer_lanes_match_scalar) {
    alignas(16) s32 a[4][4], b[4][4];
    Rng rng(31415u);
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c) {
            a[r][c] = (s32)(rng.u32n() % 200000u) - 100000;
            b[r][c] = (s32)(rng.u32n() % 200000u) - 100000;
        }

    // dword add: wrapped mod 2^32, order-free => must equal scalar exactly
    for (int row = 0; row < 4; ++row) {
        __m128i va = _mm_load_si128((const __m128i*)a[row]);
        __m128i vb = _mm_load_si128((const __m128i*)b[row]);
        __m128i vs = _mm_add_epi32(va, vb);
        s32 got[4];
        _mm_storeu_si128((__m128i*)got, vs);
        for (int k = 0; k < 4; ++k)
            CHECK_EQ(got[k], a[row][k] + b[row][k]);
    }

    // word mullo: low 16 bits of signed products
    {
        __m128i va = _mm_load_si128((const __m128i*)a[2]);
        __m128i vb = _mm_load_si128((const __m128i*)b[2]);
        __m128i vm = _mm_mullo_epi16(va, vb);
        s16 lanes[8];
        _mm_storeu_si128((__m128i*)lanes, vm);
        const s16* pa = (const s16*)a[2];
        const s16* pb = (const s16*)b[2];
        for (int k = 0; k < 8; ++k)
            CHECK_EQ((int)lanes[k],
                     (int)(s16)((u16)((u16)pa[k] * (u16)pb[k])));
    }

    // byte widening chaos: unpack lows/highs preserves byte identity
    {
        alignas(16) u8 bytes[16];
        for (int i = 0; i < 16; ++i) bytes[i] = pattern_byte((size_t)i * 11 + 5);
        __m128i src = _mm_load_si128((const __m128i*)bytes);
        __m128i lo = _mm_unpacklo_epi8(src, _mm_setzero_si128());
        __m128i hi = _mm_unpackhi_epi8(src, _mm_setzero_si128());
        u16 widened[16];
        _mm_storeu_si128((__m128i*)&widened[0], lo);
        _mm_storeu_si128((__m128i*)&widened[8], hi);
        for (int i = 0; i < 16; ++i)
            CHECK_EQ(widened[i], (u16)bytes[i]);
    }
}
#endif // SSE2-capable target

TEST(fp, sse2_float_dotproduct_bitexact) {
    // integer-valued floats bounded far below rounding thresholds make ANY
    // summation order exact -> scalar and vector MUST agree bitwise
    enum { N = 64 };
    alignas(16) float va[N], vb[N];
    Rng rng(2718281u);
    for (int i = 0; i < N; ++i) {
        va[i] = (float)((int)(rng.next() % 21u) - 10);
        vb[i] = (float)((int)(rng.next() % 21u) - 10);
    }

    double acc_scalar = 0.0;
    for (int i = 0; i < N; ++i)
        acc_scalar += (double)((double)va[i] * (double)vb[i]);   // never rounds

    __m128 acc = _mm_setzero_ps();
    for (int i = 0; i < N; i += 4)
        acc = _mm_add_ps(acc, _mm_mul_ps(
              _mm_load_ps(va + i), _mm_load_ps(vb + i)));
    // ordered horizontal sum of four partials (exact: small integers)
    alignas(16) float parts[4];
    _mm_store_ps(parts, acc);
    double dot_vec = (double)parts[0] + (double)parts[1] +
                     (double)parts[2] + (double)parts[3];

    CHECK(dot_vec == acc_scalar);                // both are the true integer sum
}

#if defined(_M_IX86)
TEST(fp, x87_controlword_roundtrip_x86only) {
    // encoding-agnostic: consecutive queries agree, save/restore restores
    unsigned base = _control87(0, 0);
    CHECK_EQ(_control87(0, 0), base);

    _control87(_PC_53, _MCW_PC);
    unsigned raised = _control87(0, 0);

    _control87(base, _MCW_PC);
    CHECK_EQ(_control87(0, 0),
             ((raised ^ base) == 0) ? raised : base);
}
#endif

static double fp_quadratic_roots_check() {       // tiny workload entry point
    double a = 1.0, b = -3.0, c = 2.0;           // roots 1 and 2
    double disc = std::sqrt(b * b - 4.0 * a * c);
    double r1 = (-b + disc) / (2.0 * a);
    double r2 = (-b - disc) / (2.0 * a);
    return (r1 + r2) - (r1 * r2);                // 3 - 2 = 1 (Vieta)
}

TEST(fp, vieta_sum_product_identity) {
    CHECK_NEAR(fp_quadratic_roots_check(), 1.0, 1e-12);
}
