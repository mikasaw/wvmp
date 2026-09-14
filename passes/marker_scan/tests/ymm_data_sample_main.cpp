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
extern "C" unsigned int      ymm_arith(void* dst, const void* src);       // ③' MIT-513
extern "C" void*            ymm_pass_through(const void* src);           // ⑥ MIT-514 读回 (src=rcx)
extern "C" unsigned int      ymm_mix_arith_neg(void* dst, const void* src); // ⑦ gate
extern "C" void             read_ymm0(void* dst);                        // ymm0 捕获 thunk

namespace {
alignas(32) unsigned char g_src[64];
alignas(32) unsigned char g_dst[64];
alignas(32) float g_want[8];  // MIT-513: 全局 — /RTC1 栈帧检查与手写 asm 交互隔离

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
    // vmovups 32B 拷贝 + addps xmm0,xmm0 (store 在前, addps 结果不落盘)。
    fill(g_src, 0xE0);
    std::memset(g_dst, 0, sizeof(g_dst));
    const unsigned int r4 = ymm_mix_neg(g_dst, g_src);
    if (!check32(g_dst, g_src)) { std::printf("FAIL mix_neg (native)\n"); ++fails; }
    // ③' packed 算术链: [rcx] = 2×src 逐 f32 lane (翻倍, d 独立三地址折叠)
    fill(g_src, 0x40);
    std::memset(g_dst, 0, sizeof(g_dst));
    const unsigned int r5 = ymm_arith(g_dst, g_src);
    {
        for (int i = 0; i < 8; ++i) {
            float v;
            std::memcpy(&v, &g_src[i * 4], 4);
            v = v + v;  // vaddps ymm0,ymm0,ymm0
            std::memcpy(&g_want[i], &v, 4);  // g_want 是 float[8]: 按 float 索引
        }
        if (!check32(g_dst, reinterpret_cast<const unsigned char*>(g_want))) {
            std::printf("FAIL arith 2x\n");
            std::printf("  bytes:");
            for (int i = 0; i < 32; ++i)
                std::printf(" %02X/%02X", g_dst[i], reinterpret_cast<const unsigned char*>(g_want)[i]);
            std::printf("\n");
            ++fails;
        }
    }


    // ⑥ ymm 读回 (MIT-513 F1/T64 F4): 虚拟化函数经物理 ymm0 返回 32B —
    // stub 出口 ymm 回写行为级钉住 (disp32 正确性真值面)。
    fill(g_src, 0x90);
    std::memset(g_dst, 0, sizeof(g_dst));
    ymm_pass_through(g_src);
    read_ymm0(g_dst);
    if (!check32(g_dst, g_src)) { std::printf("FAIL ymm readback\n"); ++fails; }

    // ⑦ 混排算术负例: ymm 算术 + legacy SSE 同区 → 整函数原生 gate,
    // 输出 = 翻倍值 (native byte-exact)。
    fill(g_src, 0xD0);
    std::memset(g_dst, 0, sizeof(g_dst));
    const unsigned int r6 = ymm_mix_arith_neg(g_dst, g_src);
        for (int i = 0; i < 8; ++i) {
            float v;
            std::memcpy(&v, &g_src[i * 4], 4);
            v = v + v;
            std::memcpy(&g_want[i], &v, 4);
        }
        if (!check32(g_dst, reinterpret_cast<const unsigned char*>(g_want))) {
            std::printf("FAIL mix_arith_neg\n"); ++fails;
        }

    std::printf("ymm_data r1=%u r2=%u r3=%u r4=%u r5=%u r6=%u fails=%d\n",
                r1, r2, r3, r4, r5, r6, fails);
    return fails == 0 ? 0 : 1;
}
