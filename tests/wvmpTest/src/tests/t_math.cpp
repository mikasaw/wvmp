// t_math.cpp - integer semantics, bit tricks, number theory basics.
// All inputs are seeded-deterministic; every assertion has a closed-form,
// platform-independent expected result.
#include "../testfw.h"
#include "../common.h"

using namespace wv;

// ---------------------------------------------------------------------------
// small helper algorithms (plain, easy-to-virtualize leaf functions)
// ---------------------------------------------------------------------------
static unsigned popcnt_loop(u32 v) { unsigned c = 0; while (v) { v &= v - 1; ++c; } return c; }

static unsigned clz_manual(u32 v) {
    unsigned n = 0;
    if (v == 0) return 32;
    while (!(v & 0x80000000u)) { v <<= 1; ++n; }
    return n;
}

static unsigned ctz_manual(u32 v) {
    if (v == 0) return 32;
    unsigned n = 0;
    while (!(v & 1u)) { v >>= 1; ++n; }
    return n;
}

static u32 rotl32(u32 v, unsigned c) { c &= 31; return (v << c) | (v >> ((32 - c) & 31)); }
static u32 rotr32(u32 v, unsigned c) { c &= 31; return (v >> c) | (v << ((32 - c) & 31)); }

static u32 reverse_bits32(u32 v) {
    u32 r = 0;
    for (int i = 0; i < 32; ++i) { r = (r << 1) | (v & 1u); v >>= 1; }
    return r;
}

static unsigned parity(u32 v) { return popcnt_loop(v) & 1u; }

static u32 add_sat_u32(u32 a, u32 b) { u32 r = a + b; return (r < a) ? 0xFFFFFFFFu : r; }
static u32 sub_sat_u32(u32 a, u32 b) { u32 r = a - b; return (r > a) ? 0u : r; }

static u64 mul64hi(u64 a, u64 b) {              // portable 64x64->128 high word
    u64 alo = (u32)a, ahi = a >> 32;
    u64 blo = (u32)b, bhi = b >> 32;
    u64 ll = alo * blo;
    u64 lh = alo * bhi;
    u64 hl = ahi * blo;
    u64 hh = ahi * bhi;
    u64 mid = (ll >> 32) + (u32)lh + (u32)hl;
    return hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}

static u64 gcd_u64(u64 a, u64 b) { while (b) { u64 t = a % b; a = b; b = t; } return a; }

// ---------------------------------------------------------------------------
TEST(math, int_wraparound) {
    u32 a = 0xFFFFFFFFu;
    CHECK_EQ(a + 1u, 0u);
    CHECK_EQ(a + 2u, 1u);
    CHECK_EQ(0u - 1u, 0xFFFFFFFFu);

    // integer promotions and truncation of 8-bit lanes
    u8 x = 200, y = 100;
    CHECK_EQ((int)x + (int)y, 300);
    CHECK_EQ((int)(u8)(x + y), 44);              // 300 & 0xFF
    CHECK_EQ((int)(s8)200, -56);                 // two's complement view

    // signed wraparound observed through casts, avoiding signed-overflow UB
    int sd = (int)((u32)2147483647u + 1u);       // INT_MAX + 1
    CHECK_EQ(sd, (int)0x80000000);               // == INT_MIN on this ABI
    CHECK_EQ(sd < 0, true);

    u16 mix = 60000;
    CHECK_EQ((int)(s16)mix, -5536);
}

TEST(math, div_mod_signs) {
    CHECK_EQ(-7 / 2, -3);    CHECK_EQ(-7 % 2, -1);   // truncation toward zero
    CHECK_EQ(7 / -2, -3);    CHECK_EQ(7 % -2, 1);
    CHECK_EQ(-7 / -2, 3);    CHECK_EQ(-7 % -2, -1);

    for (int d = 1; d <= 4; ++d) {
        CHECK_EQ(0 / d, 0);   CHECK_EQ(0 % d, 0);
        CHECK_EQ(0 / -d, 0);  CHECK_EQ(0 % -d, 0);
    }
    // Truncating division: quotient rounds toward zero and the remainder
    // takes the SIGN OF THE DIVIDEND (C99/C++11 rule).
    for (int q = -100; q <= 100; ++q) {
        int r7 = q % 7;
        int rr = q % -7;
        CHECK_MSG(r7 >= -6 && r7 <= 6, "|r| < |d|");
        if (q > 0) CHECK_MSG(r7 >= 0, "positive dividend -> non-negative r");
        if (q < 0 && r7 != 0) CHECK_MSG(r7 < 0, "negative dividend -> negative r");
        CHECK_EQ((q / 7) * 7 + r7, q);
        CHECK_EQ((q / -7) * -7 + rr, q);
        CHECK_EQ(rr, r7);                        // divisor sign never matters
    }
}

TEST(math, shift_rotate) {
    CHECK_EQ(-16 >> 2, -4);                      // arithmetic shift, negatives
    CHECK_EQ(0x80000000u >> 31, 1u);             // logical shift, unsigned
    CHECK_EQ(0x80000001u << 1, 2u);              // shifted-out bits discarded
    CHECK_EQ(1 << 30, (int)0x40000000);

    CHECK_EQ(rotl32(0xDEADBEEFu, 0), 0xDEADBEEFu);
    CHECK_EQ(rotr32(0xDEADBEEFu, 4), 0xFDEADBEEu);
    CHECK_EQ(rotl32(1u, 31), 0x80000000u);
    CHECK_EQ(rotr32(1u, 31), 2u);

    Rng rng(101);
    for (int i = 0; i < 500; ++i) {
        u32 v = rng.u32n();
        unsigned c = rng.irange(0, 63);
        CHECK_EQ(rotl32(rotl32(v, c), 32 - (c & 31)), v);
#if defined(WV_MSVC)
        CHECK_MSG(_rotr(v, c) == rotr32(v, c), "intrinsic vs portable rotate");
#endif
    }
}

TEST(math, mul_wide) {
    u64 mx = ~0ull;
    CHECK_EQ(mx * mx, 1ull);                     // (2^64-1)^2 mod 2^64
    CHECK_EQ(mul64hi(mx, mx), mx - 1);           // high word 0xFF..FE

    CHECK_EQ(mul64hi(1, 1), 0);
    CHECK_EQ(0xFFFFFFFFull * 0xFFFFFFFFull, 0xFFFFFFFE00000001ull);
    CHECK_EQ(mul64hi(0xFFFFFFFFull, 0xFFFFFFFFull), 0ull);

    CHECK_EQ(mul64hi(0x100000000ull, mx), 0xFFFFFFFFull); // 2^32*(2^64-1)
    CHECK_EQ(mul64hi(mx, 2), 1ull);              // 2^65-2 -> high word 1

    Rng rng(202);
    for (int i = 0; i < 400; ++i) {
        u64 a = rng.next(), b = rng.next();
        CHECK_EQ(mul64hi(a, b), mul64hi(b, a));      // commutative in the ring

        // no-wrap subset lets division truly invert multiplication
        u64 sa = rng.next() % 1000000ull, sb = rng.next() % 1000000ull;
        CHECK_EQ(sa * sb / sb, sa);
    }
}

TEST(math, bit_tricks) {
    Rng rng(303);
    for (int i = 0; i < 800; ++i) {
        u32 v = rng.u32n();
        unsigned pc = popcnt_loop(v);
#if defined(WV_MSVC)
        CHECK_EQ(__popcnt(v), pc);
        CHECK_EQ(__popcnt(v) & 1u, parity(v));
#endif
        // splits must stay consistent
        CHECK_EQ(popcnt_loop(v >> 16) + popcnt_loop(v & 0xFFFFu), pc);

        u32 rv = reverse_bits32(v);
        CHECK_EQ(reverse_bits32(rv), v);
        CHECK_EQ(popcnt_loop(rv), pc);

        if (v) {
            CHECK(clz_manual(v) < 32);
            // ctz(v) == clz(bit-reverse(v)): trailing zeros become leading
            CHECK_EQ(ctz_manual(v), clz_manual(rv));
        } else {
            CHECK_EQ(clz_manual(v), 32u);
        }
    }
    // pinned corner values
    CHECK_EQ(clz_manual(0x80000000u), 0u);
    CHECK_EQ(clz_manual(1u), 31u);
    CHECK_EQ(ctz_manual(0x80000000u), 31u);
    CHECK_EQ(ctz_manual(1u), 0u);
    CHECK_EQ(reverse_bits32(0x00000080u), 0x01000000u);

    u32 bs = 0x12345678u;
    u32 mbs = ((bs & 0xFFu) << 24) | ((bs & 0xFF00u) << 8) |
              ((bs >> 8) & 0xFF00u) | (bs >> 24);
    CHECK_EQ(mbs, 0x78563412u);
#if defined(WV_MSVC)
    CHECK_EQ(_byteswap_ulong(bs), mbs);
#endif
}

TEST(math, saturating_clamp) {
    CHECK_EQ(clampv(5, 0, 10), 5);
    CHECK_EQ(clampv(-3, 0, 10), 0);
    CHECK_EQ(clampv(99, 0, 10), 10);
    CHECK_EQ(clampv(0, 0, 0), 0);
    CHECK_NEAR(clampv(1.5, 0.0, 1.0), 1.0, 1e-12);
    CHECK_NEAR(clampv(-1.5, 0.0, 1.0), 0.0, 1e-12);

    CHECK_EQ(add_sat_u32(10u, 20u), 30u);
    CHECK_EQ(add_sat_u32(0xFFFFFFFFu, 1u), 0xFFFFFFFFu);
    CHECK_EQ(add_sat_u32(0xFFFFFFFFu, 0xFFFFFFFFu), 0xFFFFFFFFu);
    CHECK_EQ(sub_sat_u32(5u, 9u), 0u);
    CHECK_EQ(sub_sat_u32(9u, 5u), 4u);
}

TEST(math, gcd_lcm_prime_sieve) {
    struct GC { u64 a, b, g; };
    const GC tab[] = {
        { 48, 18, 6 }, { 17, 5, 1 }, { 270, 192, 6 },
        { 1071, 462, 21 }, { 0, 7, 7 }, { 7, 0, 7 }, { 13, 13, 13 },
    };
    for (const GC& t : tab)
        CHECK_EQ(gcd_u64(t.a, t.b), t.g);

    // sieve below 10000 must contain exactly 1229 primes (classic count)
    const int N = 10000;
    static bool comp[N + 1];
    int cnt = 0;
    for (int i = 2; i <= N; ++i) {
        if (!comp[i]) {
            ++cnt;
            for (long long j = (long long)i * i; j <= N; j += i) comp[j] = true;
        }
    }
    CHECK_EQ(cnt, 1229);

    auto is_prime_td = [](int n) {
        if (n < 2) return false;
        for (int d = 2; (long long)d * d <= n; ++d)
            if (n % d == 0) return false;
        return true;
    };
    int probes[] = { 0, 1, 2, 3, 4, 5, 7919, 7917, 9999, 9973 };
    for (int p : probes)
        CHECK_EQ(is_prime_td(p), !comp[p] && p >= 2);
}

static void to_base(char* buf, size_t cap, u64 v, int radix) {
    static const char* dig = "0123456789abcdefghijklmnopqrstuvwxyz";
    size_t n = 0;
    if (v == 0) buf[n++] = '0';
    while (v && n + 1 < cap) { buf[n++] = dig[v % (u64)radix]; v /= (u64)radix; }
    buf[n] = 0;
    for (size_t i = 0; i < n / 2; ++i) std::swap(buf[i], buf[n - 1 - i]);
}

static u64 from_base(const char* s, int radix) {
    u64 v = 0;
    for (; *s; ++s) {
        int d;
        if (*s >= '0' && *s <= '9') d = *s - '0';
        else if (*s >= 'a' && *s <= 'z') d = *s - 'a' + 10;
        else break;
        v = v * (u64)radix + (u64)d;
    }
    return v;
}

TEST(math, base_conversion_roundtrip) {
    char buf[72];

    to_base(buf, sizeof(buf), 0, 2);      CHECK_MSG(strcmp(buf, "0") == 0, "zero");
    to_base(buf, sizeof(buf), 255, 16);   CHECK_MSG(strcmp(buf, "ff") == 0, "ff");
    to_base(buf, sizeof(buf), 35, 36);    CHECK_MSG(strcmp(buf, "z") == 0, "z");
    to_base(buf, sizeof(buf), 2026, 16);  CHECK_MSG(strcmp(buf, "7ea") == 0, "7ea");
    to_base(buf, sizeof(buf), 5, 2);      CHECK_MSG(strcmp(buf, "101") == 0, "101");

    Rng rng(404);
    for (int i = 0; i < 500; ++i) {
        u64 v = rng.next() >> rng.irange(0, 40);
        int radix = rng.irange(2, 36);
        to_base(buf, sizeof(buf), v, radix);
        CHECK_EQ(from_base(buf, radix), v);

        // decimal printf must match to_base(radix 10)
        to_base(buf, sizeof(buf), v, 10);
        char ref[32];
        std::snprintf(ref, sizeof(ref), "%llu", (unsigned long long)v);
        CHECK_MSG(strcmp(buf, ref) == 0, "base10 matches printf");
    }
}

TEST(math, fixed_point_q16) {
    // Q16.16 helpers over safely-bounded magnitudes
    auto qmul = [](s32 a, s32 b) -> s32 { return (s32)(((s64)a * b) >> 16); };

    s32 one = 1 << 16;
    CHECK_EQ(qmul(one, one), one);                 // 1.0 * 1.0 == 1.0
    CHECK_EQ(qmul(one << 1, one), one << 1);       // 2.0 * 1.0 == 2.0
    CHECK_EQ(qmul(one / 2, one / 2), one / 4);     // 0.5 * 0.5 == 0.25

    // inverse round trips: floor() of the reciprocal loses up to x/2^16
    // quantization steps when multiplied back and shifted, so the tolerance
    // scales with x - derived from the division theorem, compiler-independent
    Rng rng(505);
    for (int i = 0; i < 300; ++i) {
        s32 x = 257 + (s32)(rng.next() % 4000000ull);
        s32 inv = (s32)(((u64)1 << 32) / (u64)x);
        CHECK(inv > 0);
        s32 back = qmul(x, inv);
        int tol = (int)((u32)x >> 16) + 2;
        CHECK_MSG(back >= one - tol && back <= one,
                  "q16 inverse stays within floor-shift bound");
    }
}
