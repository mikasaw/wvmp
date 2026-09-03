// common.h - shared utilities for the functional test target.
//
// Deterministic PRNG so every test has fully reproducible runtime data
// (prevents the optimizer from folding everything into constants, yet keeps
// PASS/FAIL meaningful and identical across packed/unpacked builds).
#pragma once

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#endif

#if defined(_MSC_VER)
#  include <intrin.h>
#  define WV_MSVC 1
#endif

namespace wv {

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

// ---------------------------------------------------------------------------
// splitmix64 - tiny, fast, deterministic; zero global state.
// ---------------------------------------------------------------------------
struct Rng {
    u64 s;
    explicit Rng(u64 seed = 0x243F6A8885A308D3ull) : s(seed) { next(); }

    u64 next() {
        u64 z = (s += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    u32 u32n()      { return (u32)(next() >> 32); }
    int irange(int lo, int hi) {          // inclusive
        return lo + (int)(next() % (u64)(hi - lo + 1));
    }
    double d01()    { return (double)(next() >> 11) * (1.0 / 9007199254740992.0); }
};

// ---------------------------------------------------------------------------
// misc helpers used by several test groups
// ---------------------------------------------------------------------------
inline u32 fnv1a32_buf(const void* p, size_t n) {
    const u8* b = (const u8*)p;
    u32 h = 0x811C9DC5u;
    for (size_t i = 0; i < n; ++i) { h ^= b[i]; h *= 0x01000193u; }
    return h;
}

inline std::string hex32(u32 v) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%08x", (unsigned)v);
    return buf;
}
inline std::string hex64(u64 v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)v);
    return buf;
}

// Default pattern used everywhere a big buffer must be filled/verified.
inline u8 pattern_byte(size_t i) { return (u8)((i * 131 + 17) & 0xFF); }

template <class T> inline T clampv(T v, T lo, T hi) { return v < lo ? lo : (v > hi ? hi : v); }

} // namespace wv
