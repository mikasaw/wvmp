// MIT-512 (T64 · 档B wave2①): ymm 数据通路样本 main — 32B 逐位行为对拍。
// 正例区真虚拟化 (stub ≥1, ymm 同步变体); 负例混排函数整函数原生 (可调用,
// 行为 byte-exact — native 执行无混排问题)。REQUIRE_REAL: 正例区域真虚拟
// 化 (stub ≥1); gate 证据 = protect 日志 Note。
#include <cstdio>
#include <cstring>

extern "C" unsigned int      ymm_copy32(void* dst, const void* src);      // ①
extern "C" unsigned int      ymm_chain32(void* dst, const void* src);     // ②
extern "C" unsigned int      ymm_vzero_mix(void* dst, const void* src);   // ③
extern "C" unsigned int      ymm_mix_neg(void* dst, const void* src);     // ④ gate

namespace {
alignas(32) unsigned char g_src[64];
alignas(32) unsigned char g_dst[64];

bool check32(const unsigned char* got, const unsigned char* want) {
    return std::memcmp(got, want, 32) == 0;
}
void fill(unsigned char* p, unsigned seed) {
    for (int i = 0; i < 64; ++i) p[i] = static_cast<unsigned char>(seed + i * 7);
}
}  // namespace

int main() {
    int fails = 0;

    // ① copy32: 32B 逐位拷贝; [32..64) 不得被多写 (store 恰 32B)
    fill(g_src, 0x10);
    std::memset(g_dst, 0, sizeof(g_dst));
    const unsigned int r1 = ymm_copy32(g_dst, g_src);
    if (!check32(g_dst, g_src)) { std::printf("FAIL copy32 32B\n"); ++fails; }
    for (int i = 32; i < 64; ++i)
        if (g_dst[i] != 0) { std::printf("FAIL copy32 越界写 @%d\n", i); ++fails; break; }

    // ② chain32: load→mov(aps)→mov(dqa)→store 链
    fill(g_src, 0x80);
    std::memset(g_dst, 0, sizeof(g_dst));
    const unsigned int r2 = ymm_chain32(g_dst, g_src);
    if (!check32(g_dst, g_src)) { std::printf("FAIL chain32\n"); ++fails; }

    // ③ vzeroupper + ymm 词共存 (非混排)
    fill(g_src, 0xC0);
    std::memset(g_dst, 0, sizeof(g_dst));
    const unsigned int r3 = ymm_vzero_mix(g_dst, g_src);
    if (!check32(g_dst, g_src)) { std::printf("FAIL vzero_mix\n"); ++fails; }

    // ④ 混排负例: 整函数原生 (ymm+legacy SSE 同区), 行为 byte-exact —
    // vmovups 32B 拷贝 + addps xmm0,xmm0 (xmm0 结果弃置)。
    fill(g_src, 0xE0);
    std::memset(g_dst, 0, sizeof(g_dst));
    const unsigned int r4 = ymm_mix_neg(g_dst, g_src);
    if (!check32(g_dst, g_src)) { std::printf("FAIL mix_neg (native)\n"); ++fails; }

    std::printf("ymm_data r1=%u r2=%u r3=%u r4=%u fails=%d\n",
                r1, r2, r3, r4, fails);
    return fails == 0 ? 0 : 1;
}
