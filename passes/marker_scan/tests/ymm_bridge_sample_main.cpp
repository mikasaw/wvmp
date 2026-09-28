// MIT-533 (wave2 桥): vextractf128/vinsertf128 样本 main — 逐位行为对拍。
// 正例区真虚拟化 (stub ≥1, ymm 同步变体); 负例混排函数整函数原生 (行为
// byte-exact)。REQUIRE_REAL: 正例区域真虚拟化; gate 证据 = protect 日志 Note。
#include <cstdio>
#include <cstring>

extern "C" unsigned int ymm_swap_hi(void* dst, const void* src);       // ①
extern "C" unsigned int ymm_bridge_mem(void* dst, const void* src);    // ②
extern "C" unsigned int ymm_bridge_mix_neg(void* dst, const void* src);// ③ gate

namespace {
alignas(32) unsigned char g_src[64];
alignas(32) unsigned char g_dst[64];

void fill(unsigned char* p, unsigned seed) {
    for (int i = 0; i < 64; ++i) p[i] = static_cast<unsigned char>(seed + i * 7);
}
}  // namespace

int main() {
    int fails = 0;

    // ① swap_hi: dst[0..32) = (src_hi, src_hi); [32..64) 不被触碰
    fill(g_src, 0x30);
    std::memset(g_dst, 0, sizeof(g_dst));
    const unsigned int r1 = ymm_swap_hi(g_dst, g_src);
    if (std::memcmp(g_dst, g_src + 16, 16) != 0 ||
        std::memcmp(g_dst + 16, g_src + 16, 16) != 0) {
        std::printf("FAIL swap_hi 车道\n"); ++fails;
    }
    for (int i = 32; i < 64; ++i)
        if (g_dst[i] != 0) { std::printf("FAIL swap_hi 越界写 @%d\n", i); ++fails; break; }

    // ② bridge_mem: dst[0..16) = src[16..32); dst[16..32) = src[16..32);
    //    dst[32..48) = src[16..32); [48..64) 不被触碰
    fill(g_src, 0x90);
    std::memset(g_dst, 0, sizeof(g_dst));
    const unsigned int r2 = ymm_bridge_mem(g_dst, g_src);
    for (int k = 0; k < 3; ++k)
        if (std::memcmp(g_dst + 16 * k, g_src + 16, 16) != 0) {
            std::printf("FAIL bridge_mem 块 %d\n", k); ++fails;
        }
    for (int i = 48; i < 64; ++i)
        if (g_dst[i] != 0) { std::printf("FAIL bridge_mem 越界写 @%d\n", i); ++fails; break; }

    // ③ 混排负例: 整函数原生, 32B 拷贝 byte-exact
    fill(g_src, 0xD0);
    std::memset(g_dst, 0, sizeof(g_dst));
    const unsigned int r3 = ymm_bridge_mix_neg(g_dst, g_src);
    if (std::memcmp(g_dst, g_src, 32) != 0) { std::printf("FAIL mix_neg (native)\n"); ++fails; }

    if (fails == 0) std::printf("ALL OK\n");
    return fails;
}
