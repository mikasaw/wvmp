// MIT-517 (T69) AVX 真实 codegen 词流频率画像 — 算法集。
// 编译变体：/arch:AVX（实验组）与 /arch:SSE2（对照组）；/O2 开自动向量化。
// 全部确定性、无系统调用；运行仅用于防止常量折叠（画像只看 .text 静态形态）。
#include <cstdint>
#include <cstring>
#include <cstdio>

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

volatile uint64_t g_sink = 0;

// ① 字节拷贝循环（memcpy 自动向量化主力形态）
void k_copy(u8* dst, const u8* src, unsigned n) {
    for (unsigned i = 0; i < n; ++i) dst[i] = src[i];
}

// ② float 点积（256 元素，归约）
float k_dot(const float* a, const float* b, unsigned n) {
    float s = 0.f;
    for (unsigned i = 0; i < n; ++i) s += a[i] * b[i];
    return s;
}

// ③ axpy：y[i] = a*x[i] + y[i]（流式三元）
void k_axpy(float a, const float* x, float* y, unsigned n) {
    for (unsigned i = 0; i < n; ++i) y[i] = a * x[i] + y[i];
}

// ④ RGBX → 灰度（u8 整数向量化的典型面）
void k_grey(const u8* px, u8* out, unsigned n) {
    for (unsigned i = 0; i < n; ++i)
        out[i] = (u8)((px[i * 4 + 0] * 30 + px[i * 4 + 1] * 59 + px[i * 4 + 2] * 11) / 100);
}

// ⑤ s16 饱和钳位（媒体处理典型面）
void k_clamp16(short* v, unsigned n, short lo, short hi) {
    for (unsigned i = 0; i < n; ++i) {
        short x = v[i];
        if (x < lo) x = lo;
        if (x > hi) x = hi;
        v[i] = x;
    }
}

// ⑥ 表驱动 CRC32（串行对照面：不可向量化，看标量浮点/整型词占比）
uint32_t k_crc32(const u8* p, unsigned n) {
    static uint32_t tab[256];
    static int init = 0;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            tab[i] = c;
        }
        init = 1;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (unsigned i = 0; i < n; ++i) crc = tab[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

// ⑦ u64 累加归约（64 位面对照）
uint64_t k_sum64(const uint64_t* v, unsigned n) {
    uint64_t s = 0;
    for (unsigned i = 0; i < n; ++i) s += v[i];
    return s;
}

// ⑧ 结构体数组字段整理（AoS 字段搬运：部分向量化形态）
void k_normalise(u32* recs, unsigned n) {
    for (unsigned i = 0; i < n; ++i) {
        u32 a = recs[4 * i + 0], b = recs[4 * i + 1];
        u32 c = recs[4 * i + 2];
        recs[4 * i + 3] = (a ^ (b << 3)) + (c >> 2);
    }
}

int main() {
    static float fa[256], fb[256], fy[256];
    static u8 src[4096], dst[4096], grey[1024];
    static short cl[512];
    static u64 q[512];
    static u32 recs[1024];
    for (unsigned i = 0; i < 256; ++i) { fa[i] = (float)i * 0.5f; fb[i] = (float)(i % 7); fy[i] = 1.f; }
    for (unsigned i = 0; i < 4096; ++i) src[i] = (u8)(i * 13);
    for (unsigned i = 0; i < 512; ++i) { cl[i] = (short)(i * 61 - 3000); q[i] = (uint64_t)i * 0x9E3779B97F4A7C15ull; }
    for (unsigned i = 0; i < 256; ++i) recs[4 * i] = i;

    k_copy(dst, src, 4096);
    k_axpy(2.0f, fa, fy, 256);
    k_grey(src, grey, 1024);
    k_clamp16(cl, 512, -1000, 1000);
    k_normalise(recs, 256);

    uint64_t sink = g_sink;
    sink += (uint64_t)k_dot(fa, fb, 256);
    sink += k_crc32(src, 4096);
    sink += k_sum64(q, 512);
    for (unsigned i = 0; i < 1024; ++i) sink += grey[i];
    for (unsigned i = 0; i < 512; ++i) sink += (uint64_t)cl[i];
    for (unsigned i = 0; i < 1024; ++i) sink += recs[i];
    for (unsigned i = 0; i < 4096; ++i) sink += dst[i];
    g_sink = sink;
    std::printf("done sink=%llu\n", (unsigned long long)(sink & 0xFFFF));
    return 0;
}
