// targets/kernels.cpp - 打标靶内核实现。
//
// ============ 你的保护工具标记示例位置（伪代码）============
//   void wv_xtea_encipher(...)
//   {
//       /* 你的标记系统可能是：
//            PROTECT_BEGIN("wv_xtea_encipher");
//            ... 函数体 ...
//            PROTECT_END();      // <- 函数收尾处
//          也可能是行级插入或从 } 前向上划定范围。
//          本工程刻意不含任何工具特定宏，按需自行包裹。 */
//   }
// =========================================================
//
// 所有算法均与 tests/ 内已验证的实现逐式一致（转写而非调用，
// 以保证被圈选的代码自包含、不依赖测试框架符号）。
#include "kernels.h"
#include "wvmp_protect.h"

#include <stdint.h>
#include <string.h>
#include <math.h>

// ---------------------------------------------------------------------------
// 文件内部助手（不出符号，保持朴素以便任何引擎处理）
// ---------------------------------------------------------------------------
static double wvsin(double x) { return sin(x); }
static double wvfabs(double x) { return fabs(x); }
static double wvpow13(double x) { return pow(x, 1.0 / 3.0); }

static uint32_t rot_left(uint32_t x, int c) {
    return c ? ((x << c) | (x >> (32 - c))) : x;
}
static uint32_t rot_right(uint32_t x, int c) {
    return c ? ((x >> c) | (x << (32 - c))) : x;
}

static uint32_t frac_sqrt_prime(uint32_t p) {
    // H 常数 = sqrt(质数) 的小数部分 * 2^32
    double v = sqrt((double)p);
    v -= floor(v);
    return (uint32_t)(v * 4294967296.0);
}
static uint32_t frac_cbrt_prime(uint32_t p) {
    // K 常数 = 质数立方根的小数部分 * 2^32
    double v = wvpow13((double)p);
    v -= floor(v);
    return (uint32_t)(v * 4294967296.0);
}
static unsigned is_small_prime(uint32_t n) {
    if (n < 2) return 0;
    for (uint32_t d = 2; d * d <= n; ++d)
        if (n % d == 0) return 0;
    return 1;
}

static const char B64_ALPHA[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static const uint32_t* md5_T(void) {
    static uint32_t T[64];
    static int ready = 0;
    if (!ready) {
        // T[i] = floor(abs(sin(i+1)) * 2^32)：启动期推导，避免手抄表出错
        for (int i = 0; i < 64; ++i)
            T[i] = (uint32_t)(wvfabs(wvsin((double)i + 1.0)) * 4294967296.0);
        ready = 1;
    }
    return T;
}

static const uint32_t* sha256_h0(void) {
    static uint32_t H[8];
    static int ready = 0;
    if (!ready) {
        int i = 0;
        for (uint32_t p = 2; i < 8; ++p)
            if (is_small_prime(p))
                H[i++] = frac_sqrt_prime(p);
        ready = 1;
    }
    return H;
}
static const uint32_t* sha256_K(void) {
    static uint32_t K[64];
    static int ready = 0;
    if (!ready) {
        int i = 0;
        for (uint32_t p = 2; i < 64; ++p)
            if (is_small_prime(p))
                K[i++] = frac_cbrt_prime(p);
        ready = 1;
    }
    return K;
}

// MIT-379：含 WVMP 标记的翻译单元按 SDK 建议关闭优化——/O2 可能把收尾处
// marker_end() 尾调用成 jmp（E8 消失、marker_scan 配对失败）。本 pragma 自
// 出现点后的首个函数定义起生效，上方文件内助手保持 /O2 不受影响。
#pragma optimize("", off)

#ifdef __cplusplus
extern "C" {
#endif

// ===========================================================================
// [位算术 / 整数语义]
// ===========================================================================
WV_TARGET_NOINLINE uint64_t wv_mul64hi(uint64_t a, uint64_t b) {
    PROTECT_BEGIN("wv_mul64hi");
    uint64_t alo = (uint32_t)a, ahi = a >> 32;
    uint64_t blo = (uint32_t)b, bhi = b >> 32;
    uint64_t ll = alo * blo;
    uint64_t lh = alo * bhi;
    uint64_t hl = ahi * blo;
    uint64_t hh = ahi * bhi;
    uint64_t mid = (ll >> 32) + (uint32_t)lh + (uint32_t)hl;
    PROTECT_END();
    return hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}

WV_TARGET_NOINLINE void wv_duff_copy(uint8_t* to, const uint8_t* from,
                                     uint32_t count) {
    PROTECT_BEGIN("wv_duff_copy");
    uint32_t batches = (count + 7) / 8;
    switch (count % 8) {
        case 0: do { *to++ = *from++;
        case 7:      *to++ = *from++;
        case 6:      *to++ = *from++;
        case 5:      *to++ = *from++;
        case 4:      *to++ = *from++;
        case 3:      *to++ = *from++;
        case 2:      *to++ = *from++;
        case 1:      *to++ = *from++;
                } while (--batches > 0);
    }
    PROTECT_END();
}

WV_TARGET_NOINLINE int32_t wv_bsearch_i32(const int32_t* a, int32_t n,
                                          int32_t key) {
    PROTECT_BEGIN("wv_bsearch_i32");
    int32_t lo = 0, hi = n - 1;
    while (lo <= hi) {
        int32_t mid = lo + ((hi - lo) >> 1);
        if (a[mid] == key) return mid;
        if (a[mid] < key) lo = mid + 1; else hi = mid - 1;
    }
    PROTECT_END();
    return -1;
}

WV_TARGET_NOINLINE void wv_insertion_sort(int32_t* v, int32_t n) {
    PROTECT_BEGIN("wv_insertion_sort");
    for (int32_t i = 1; i < n; ++i) {
        int32_t key = v[i];
        int32_t j = i - 1;
        while (j >= 0 && v[j] > key) { v[j + 1] = v[j]; --j; }
        v[j + 1] = key;
    }
    PROTECT_END();
}

WV_TARGET_NOINLINE int32_t wv_ackermann(int32_t m, int32_t n) {
    PROTECT_BEGIN("wv_ackermann");
    if (m == 0) return n + 1;
    if (n == 0) return wv_ackermann(m - 1, 1);
    PROTECT_END();
    return wv_ackermann(m - 1, wv_ackermann(m, n - 1));
}

// ===========================================================================
// [哈希 / 密码学 —— 块级核心]
// ===========================================================================
WV_TARGET_NOINLINE void wv_md5_compress(uint32_t st[4],
                                        const uint8_t block[64]) {
    PROTECT_BEGIN("wv_md5_compress");
    uint32_t m[16];
    for (int i = 0; i < 16; ++i)
        m[i] = (uint32_t)block[4*i] | ((uint32_t)block[4*i+1] << 8) |
               ((uint32_t)block[4*i+2] << 16) | ((uint32_t)block[4*i+3] << 24);
    const uint32_t* T = md5_T();
    static const int S[4][4] = {
        { 7, 12, 17, 22 }, { 5, 9, 14, 20 },
        { 4, 11, 16, 23 }, { 6, 10, 15, 21 },
    };
    uint32_t A = st[0], B = st[1], C = st[2], D = st[3];
    for (int i = 0; i < 64; ++i) {
        uint32_t F; int g, s;
        if (i < 16)      { F = (B & C) | (~B & D);  g = i;              s = S[0][i & 3]; }
        else if (i < 32) { F = (D & B) | (~D & C);  g = (5*i + 1) % 16; s = S[1][i & 3]; }
        else if (i < 48) { F = B ^ C ^ D;           g = (3*i + 5) % 16; s = S[2][i & 3]; }
        else             { F = C ^ (B | ~D);        g = (7*i) % 16;     s = S[3][i & 3]; }
        uint32_t tmp = D;
        D = C;
        C = B;
        B = B + rot_left(A + F + T[i] + m[g], s);
        A = tmp;
    }
    PROTECT_END();
    st[0] += A; st[1] += B; st[2] += C; st[3] += D;
}

WV_TARGET_NOINLINE void wv_sha256_compress(uint32_t h[8],
                                           const uint8_t block[64]) {
    PROTECT_BEGIN("wv_sha256_compress");
    static const uint32_t* K = NULL;
    if (!K) K = sha256_K();
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = ((uint32_t)block[4*i] << 24) | ((uint32_t)block[4*i+1] << 16) |
               ((uint32_t)block[4*i+2] << 8) | (uint32_t)block[4*i+3];
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rot_right(w[i-15], 7) ^ rot_right(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rot_right(w[i-2], 17) ^ rot_right(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rot_right(e, 6) ^ rot_right(e, 11) ^ rot_right(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        uint32_t S0 = rot_right(a, 2) ^ rot_right(a, 13) ^ rot_right(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1;
        d=c;  c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
    h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    PROTECT_END();
}

// 暴露 H0 初始向量（驱动侧组装消息用）
const uint32_t* wv_sha256_h0(void) { return sha256_h0(); }

WV_TARGET_NOINLINE uint32_t wv_crc32_update(uint32_t crc, const uint8_t* p,
                                            uint32_t n) {
    PROTECT_BEGIN("wv_crc32_update");
    static uint32_t t[256];
    static int ready = 0;
    if (!ready) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        ready = 1;
    }
    while (n--) crc = t[(crc ^ *p++) & 0xFFu] ^ (crc >> 8);
    PROTECT_END();
    return crc;
}

// ===========================================================================
// [流密码]
// ===========================================================================
WV_TARGET_NOINLINE void wv_rc4_ksa(wv_rc4_state* st, const uint8_t* key,
                                   uint32_t klen) {
    PROTECT_BEGIN("wv_rc4_ksa");
    for (int i = 0; i < 256; ++i) st->S[i] = (uint8_t)i;
    uint32_t j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + st->S[i] + key[i % klen]) & 0xFFu;
        uint8_t tmp = st->S[i]; st->S[i] = st->S[j]; st->S[j] = tmp;
    }
    PROTECT_END();
    st->i = 0;
    st->j = 0;
}

WV_TARGET_NOINLINE void wv_rc4_crypt(wv_rc4_state* st, uint8_t* buf,
                                     uint32_t n) {
    PROTECT_BEGIN("wv_rc4_crypt");
    uint32_t I = st->i, J = st->j;
    for (uint32_t k = 0; k < n; ++k) {
        I = (I + 1) & 0xFFu;
        J = (J + st->S[I]) & 0xFFu;
        uint8_t tmp = st->S[I]; st->S[I] = st->S[J]; st->S[J] = tmp;
        buf[k] ^= st->S[(st->S[I] + st->S[J]) & 0xFFu];
    }
    PROTECT_END();
    st->i = I;
    st->j = J;
}

// ===========================================================================
// [XTEA 单块]
// ===========================================================================
WV_TARGET_NOINLINE void wv_xtea_encipher(uint32_t v[2], const uint32_t k[4]) {
    PROTECT_BEGIN("wv_xtea_encipher");
    uint32_t v0 = v[0], v1 = v[1], sum = 0;
    const uint32_t delta = 0x9E3779B9u;
    for (int i = 0; i < 32; ++i) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
    }
    PROTECT_END();
    v[0] = v0;
    v[1] = v1;
}

WV_TARGET_NOINLINE void wv_xtea_decipher(uint32_t v[2], const uint32_t k[4]) {
    PROTECT_BEGIN("wv_xtea_decipher");
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0xC6EF3720u;
    const uint32_t delta = 0x9E3779B9u;
    for (int i = 0; i < 32; ++i) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }
    PROTECT_END();
    v[0] = v0;
    v[1] = v1;
}

// ===========================================================================
// [Base64]
// ===========================================================================
WV_TARGET_NOINLINE int32_t wv_b64_encode(const uint8_t* src, uint32_t n,
                                         char* dst) {
    PROTECT_BEGIN("wv_b64_encode");
    int32_t o = 0;
    uint32_t i = 0;
    for (; i + 2 < n; i += 3) {
        uint32_t grp = ((uint32_t)src[i] << 16) | ((uint32_t)src[i+1] << 8) |
                       src[i+2];
        dst[o++] = B64_ALPHA[(grp >> 18) & 63];
        dst[o++] = B64_ALPHA[(grp >> 12) & 63];
        dst[o++] = B64_ALPHA[(grp >> 6) & 63];
        dst[o++] = B64_ALPHA[grp & 63];
    }
    if (i + 1 == n) {
        uint32_t grp = (uint32_t)src[i] << 16;
        dst[o++] = B64_ALPHA[(grp >> 18) & 63];
        dst[o++] = B64_ALPHA[(grp >> 12) & 63];
        dst[o++] = '=';
        dst[o++] = '=';
    } else if (i + 2 == n) {
        uint32_t grp = ((uint32_t)src[i] << 16) | ((uint32_t)src[i+1] << 8);
        dst[o++] = B64_ALPHA[(grp >> 18) & 63];
        dst[o++] = B64_ALPHA[(grp >> 12) & 63];
        dst[o++] = B64_ALPHA[(grp >> 6) & 63];
        dst[o++] = '=';
    }
    PROTECT_END();
    dst[o] = 0;
    return o;
}

WV_TARGET_NOINLINE int32_t wv_b64_decode(const char* s, uint32_t len,
                                         uint8_t* dst) {
    PROTECT_BEGIN("wv_b64_decode");
    int32_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (uint32_t i = 0; i < len; ++i) {
        char c = s[i];
        if (c == '=') continue;
        int d = b64_val(c);
        if (d < 0) return -1;
        acc = (acc << 6) | (uint32_t)d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            dst[o++] = (uint8_t)((acc >> bits) & 0xFFu);
        }
    }
    PROTECT_END();
    return o;
}

} // extern "C"
